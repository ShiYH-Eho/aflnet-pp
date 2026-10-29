#!/usr/bin/env python3
"""cscan -- heuristic scanner that proposes "state variable" candidates.

This module is deliberately dependency free (stdlib only) and *heuristic*: it is
not a compiler.  Its single job is to produce a short, ranked list of variables /
struct fields that plausibly encode the state of the program under test, so that
a downstream consumer (an LLM, or a human) can decide which of them really are
protocol/application state variables.

Ranking signals, strongest first:

1. AFLNet++'s own annotation, which is exactly what ``AFL_LLVM_STATEVAR=1``
   instruments::

       __attribute__((annotate("__AFL_STATE_VAR__")))

2. "state-like predicate" usage: comparisons against constants
   (``if (x == 0x42)``), ``switch (x)``, digit parsing (``atoi(x)``) and
   string comparisons (``strcmp(x, "PASS")``).
3. Assignment / occurrence counts and the declaration's storage class
   (``static`` globals and struct members outrank automatic locals).

The scanner never claims correctness; every candidate carries the raw counters
used to rank it so the caller can re-rank or filter.
"""

from __future__ import print_function

import ast
import os
import re
import sys

C_EXTENSIONS = ('.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx', '.c++', '.h++')
PY_EXTENSIONS = ('.py',)
DEFAULT_EXTENSIONS = C_EXTENSIONS + PY_EXTENSIONS

SKIP_DIRS = {
    '.git', '.svn', '.hg', '.bzr', '.tox', '.eggs', '__pycache__', 'node_modules',
    'build', 'cmake-build-debug', 'cmake-build-release', 'autom4te.cache',
    'dist', 'target', '.cache', '.idea', '.vscode', 'CMakeFiles',
}

# Directories whose code is usually *not* the target under test.  Candidates
# found there are kept but demoted: a lot of fuzzing targets ship their own test
# programs and vendored libraries.
LOW_PRIORITY_DIRS = {'test', 'tests', 'testing', 'example', 'examples', 'sample',
                     'samples', 'demo', 'demos', 'benchmark', 'benchmarks',
                     'vendor', 'third_party', 'thirdparty', 'external', 'deps',
                     'doc', 'docs', 'fuzz', 'fuzzing', 'unittests', 'unit-test',
                     'regress', 'regression'}

# Trees that are almost never compiled for a Linux fuzzing target (usually a
# stale platform port of the very same code).  Their names would otherwise
# duplicate every real finding at a nearly identical score.
DEAD_DIRS = {'deprecated', 'windows', 'win32', 'wince', 'msvc', 'old', 'attic'}

TYPE_QUALIFIERS = {
    'static', 'extern', 'const', 'volatile', 'register', 'inline', 'auto',
    'typedef', 'restrict', '_Thread_local', '_Atomic', 'mutable', 'virtual',
    'explicit', 'friend', 'constexpr', '__inline', '__inline__', '__restrict',
    '__restrict__', '__const', '__volatile__', '__extension__', '__signed__',
    '__forceinline', '_Noreturn', 'signed', 'unsigned',
}

BASE_TYPES = {
    'void', 'char', 'short', 'int', 'long', 'float', 'double', 'signed',
    'unsigned', '_Bool', 'bool', 'size_t', 'ssize_t', 'wchar_t', 'uint8_t',
    'uint16_t', 'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 'int32_t',
    'int64_t', 'u8', 'u16', 'u32', 'u64', 's8', 's16', 's32', 's64', '__u8',
    '__u16', '__u32', '__u64', 'FILE', 'pid_t', 'time_t', 'off_t', 'intptr_t',
    'uintptr_t', 'ptrdiff_t', 'intmax_t', 'ssize_t', 'va_list', 'jmp_buf',
}

RESERVED = {
    'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default', 'break',
    'continue', 'return', 'goto', 'sizeof', 'struct', 'union', 'enum',
    'typedef', 'static', 'extern', 'const', 'volatile', 'register', 'inline',
    'void', 'char', 'short', 'int', 'long', 'float', 'double', 'signed',
    'unsigned', 'class', 'public', 'private', 'protected', 'new', 'delete',
    'this', 'try', 'catch', 'throw', 'namespace', 'using', 'template',
    'typename', 'operator', 'true', 'false', 'nullptr', 'NULL',
}

# Names that carry almost no information as "state".  They are not dropped
# (they may still be annotated) but they are heavily demoted when they are not.
GENERIC_NAMES = {
    'i', 'j', 'k', 'n', 'm', 'c', 'p', 'q', 'r', 's', 't', 'x', 'y', 'z', 'a',
    'b', 'ch', 'len', 'l', 'ret', 'rc', 'res', 'resu', 'result', 'tmp', 'temp',
    'buf', 'buffer', 'idx', 'index', 'count', 'cnt', 'num', 'size', 'siz',
    'val', 'value', 'ptr', 'addr', 'off', 'offset', 'arg', 'args', 'argv',
    'argc', 'err', 'error', 'fd', 'fp', 'line', 'next', 'prev', 'head', 'tail',
    'it', 'iter', 'pos', 'end', 'start', 'str', 'data', 'name', 'key',
}

ANNOTATION_MARKER = '__AFL_STATE_VAR__'

# --- regexes used on the *cleaned* (comments/strings blanked) text -----------

ANNOTATE_RE = re.compile(r'annotate\s*\(\s*"' + ANNOTATION_MARKER + r'"\s*\)')

DEFINE_RE = re.compile(r'(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]*(.*)$')


def find_annotation_macros(original):
    """Return macro names that alias the ``__AFL_STATE_VAR__`` annotation.

    Almost every real target hides the attribute behind a macro (AFLNet++'s own
    tests use ``#define STATE_VAR __attribute__((annotate("__AFL_STATE_VAR__")))``),
    so a scanner that only looks for the literal spelling misses them all.
    """
    flat = original.replace('\\\n', '')
    macros = set()
    for m in DEFINE_RE.finditer(flat):
        body = m.group(2)
        if ANNOTATION_MARKER in body or ANNOTATE_RE.search(body):
            macros.add(m.group(1))
    return macros


def blank_tokens(text, names):
    """Replace whole-word occurrences of ``names`` with spaces (length kept)."""
    if not names:
        return text
    pat = re.compile(r'\b(?:' + '|'.join(re.escape(n) for n in sorted(names)) + r')\b')
    return pat.sub(lambda m: ' ' * (m.end() - m.start()), text)


STMT_BOUNDARY = ';{}'

ASSIGN_RE = re.compile(r'(\+\+|--|(?:[+\-*/%&|^]|<<|>>)?=(?!=))')
COMPARE_RE = re.compile(r'(?:==|!=|<=|>=|<|>)')

STRING_FN_RE = re.compile(r'\b(strcmp|strncmp|strcasecmp|strncasecmp|strstr|strchr|memcmp|strcoll)\b')
PARSE_FN_RE = re.compile(r'\b(atoi|atol|atoll|strtol|strtoul|strtoll|strtoull|sscanf|strtod)\b')
SWITCH_RE = re.compile(r'\bswitch\s*\(')

NOISE_START_RE = re.compile(r'[/"\']')


def _name_regex(name):
    return re.compile(r'\b' + re.escape(name) + r'\b')


# ---------------------------------------------------------------------------
# C / C++ scanning
# ---------------------------------------------------------------------------

def strip_noise(text, keep_strings=False):
    """Blank out comments, string/char literal bodies and preprocessor lines.

    The returned string has exactly the same length and line structure as the
    input, so byte offsets and line numbers stay valid.  ``//`` inside a string
    or a literal inside a comment can therefore never confuse the scanners
    below.

    ``keep_strings`` keeps the *contents* of string/char literals while still
    blanking comments: the annotation the pass looks for is spelled inside a
    literal (``annotate("__AFL_STATE_VAR__")``), so that is the view of the file
    in which it can be recognised.
    """
    # Remove preprocessor lines first (with backslash line continuations), so a
    # '#define FOO 1' never merges with the next real statement.
    def blank_pp(match):
        return re.sub(r'[^\n]', ' ', match.group(0))

    text = re.sub(r'(?m)^[ \t]*#(?:[^\n]*\\\n)*(?:[^\n]*)', blank_pp, text)

    out = []
    i = 0
    n = len(text)
    state = 'code'
    while i < n:
        if state == 'code':
            # Plain code is the common case: jump straight to the next
            # character that can start a comment or a literal instead of
            # walking the text one byte at a time (matters on 30 MB trees).
            m = NOISE_START_RE.search(text, i)
            if m is None:
                out.append(text[i:])
                break
            j = m.start()
            if j > i:
                out.append(text[i:j])
            c = text[j]
            nxt = text[j + 1] if j + 1 < n else ''
            if c == '/' and nxt == '/':
                state = 'line'; out.append('  '); i = j + 2; continue
            if c == '/' and nxt == '*':
                state = 'block'; out.append('  '); i = j + 2; continue
            if c == '"':
                state = 'str'; out.append('"'); i = j + 1; continue
            if c == "'":
                state = 'chr'; out.append("'"); i = j + 1; continue
            out.append(c); i = j + 1; continue
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if state == 'line':
            out.append('\n' if c == '\n' else ' ')
            if c == '\n':
                state = 'code'
            i += 1; continue
        if state == 'block':
            if c == '*' and nxt == '/':
                out.append('  '); i += 2; state = 'code'; continue
            out.append('\n' if c == '\n' else ' ')
            i += 1; continue
        if state == 'str':
            if c == '\\':
                pair = text[i:i + 2].ljust(2)
                out.append(pair if keep_strings else '  ')
                i += 2; continue
            if c == '"':
                out.append('"'); i += 1; state = 'code'; continue
            out.append(c if keep_strings else ('\n' if c == '\n' else ' '))
            i += 1; continue
        # state == 'chr'
        if c == '\\':
            pair = text[i:i + 2].ljust(2)
            out.append(pair if keep_strings else '  ')
            i += 2; continue
        if c == "'":
            out.append("'"); i += 1; state = 'code'; continue
        out.append(c if keep_strings else ('\n' if c == '\n' else ' '))
        i += 1
    return ''.join(out)


def strip_attributes(text):
    """Replace ``__attribute__((...))`` / ``__declspec(...)`` with spaces.

    Length (and therefore every offset) is preserved.  Parentheses are matched
    so nested forms like ``__attribute__((annotate("x")))`` are fully removed.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        a = text.find('__attribute__', i)
        d = text.find('__declspec', i)
        if a == -1 or (d != -1 and d < a):
            a = d
        if a == -1:
            out.append(text[i:])
            break
        out.append(text[i:a])
        k = text.find('(', a)
        if k == -1:
            out.append(text[a:])
            break
        depth = 0
        m = k
        while m < n:
            if text[m] == '(':
                depth += 1
            elif text[m] == ')':
                depth -= 1
                if depth == 0:
                    break
            m += 1
        out.append(' ' * (m + 1 - a))
        i = m + 1
    return ''.join(out)


def compute_scope(text):
    """Return (depth, in_aggregate, agg_tag) arrays, one entry per character.

    ``depth`` is the brace nesting level.  ``in_aggregate`` is True when the
    innermost enclosing braces belong to a ``struct``/``union``/``enum`` body
    (detected by looking back at the tokens preceding the ``{``), which is how
    struct members are told apart from ordinary locals.  ``agg_tag`` holds the
    name of the enclosing aggregate (``''`` for anonymous ones).
    """
    depth = [0] * len(text)
    in_agg = [False] * len(text)
    agg_tag = [''] * len(text)
    stack = []  # ('agg', tag) or ('block', '')
    for i, c in enumerate(text):
        if c == '{':
            j = i - 1
            buf = []
            while j >= 0 and len(buf) < 400 and text[j] not in '{};':
                buf.append(text[j])
                j -= 1
            head = ''.join(reversed(buf))
            kind = 'block'
            tag = ''
            # The aggregate body must be the *last* thing before the brace and
            # must not look like a call/return type (`struct x f(void) {`) nor an
            # initializer list (`= {1, 2, 3}`).
            last = None
            for mm in re.finditer(r'\b(?:struct|union|enum)\b', head):
                last = mm
            if last is not None:
                tail = head[last.start():]
                if '(' not in tail and '=' not in tail:
                    kind = 'agg'
                    mt = re.search(r'([A-Za-z_]\w*)\s*$', tail)
                    tag = mt.group(1) if mt else ''
            stack.append((kind, tag))
        elif c == '}':
            if stack:
                stack.pop()
        depth[i] = len(stack)
        if stack:
            top_kind, top_tag = stack[-1]
            in_agg[i] = top_kind == 'agg'
            agg_tag[i] = top_tag if top_kind == 'agg' else ''
    return depth, in_agg, agg_tag


def split_statements(text):
    """Split source text into statements delimited by top-level ``;`` ``{`` ``}``.

    Delimiters nested in parentheses/brackets are ignored, so
    ``__attribute__((annotate("x")))`` and ``int a[2] = {1, 2}`` behave sanely.
    Returns a list of ``(start, end, delimiter, segment)`` tuples.
    """
    stmts = []
    paren = 0
    brack = 0
    start = 0
    for i, c in enumerate(text):
        if c == '(':
            paren += 1
        elif c == ')':
            paren = max(0, paren - 1)
        elif c == '[':
            brack += 1
        elif c == ']':
            brack = max(0, brack - 1)
        elif paren == 0 and brack == 0 and c in STMT_BOUNDARY:
            seg = text[start:i]
            stmts.append((start, i, c, seg))
            start = i + 1
    if start < len(text):
        seg = text[start:]
        if seg.strip():
            stmts.append((start, len(text), None, seg))
    return stmts


def _is_type_word(word):
    if word in BASE_TYPES or word in TYPE_QUALIFIERS:
        return True
    if re.match(r'^[A-Za-z_]\w*(?:_t|_T|_H|_h)$', word):
        return True
    if word[:1].isupper():
        return True
    return False


def parse_decl(seg, type_aliases):
    """Parse one statement as a declaration.

    Returns ``None`` when the segment is not a declaration (expression, call,
    function definition, control statement...).  Otherwise a dict with the
    declared name, the rendered type, and a few flags.  Only the *first*
    declarator is returned; comma lists are handled by the caller via
    ``split_commas``.
    """
    s = seg.strip()
    if not s:
        return None
    if '(' in s or ')' in s:
        return None
    if '&&' in s or '||' in s or '->' in s:
        return None

    # Drop a trailing top-level initializer: `= ...`
    eq = _find_top_level(s, '=')
    has_init = eq != -1
    head = s[:eq] if has_init else s
    head = head.strip()
    if not head:
        return None

    # Array declarator: keep the fact, drop it for parsing.
    is_array = False
    arr = re.search(r'\[[^\]]*\]\s*$', head)
    if arr:
        is_array = True
        head = head[:arr.start()].strip()

    # Bitfields (`unsigned a : 3`) are members but carry no useful type.
    head = re.sub(r'\s*:\s*\d+\s*$', '', head).strip()

    toks = re.findall(r'::|[A-Za-z_]\w*|\*+|&+', head)
    if not toks:
        return None
    name = toks[-1]
    if not re.match(r'^[A-Za-z_]\w*$', name):
        return None
    if name in RESERVED:
        return None
    specs = toks[:-1]
    if not specs:
        return None

    # Everything before the name must be a qualifier / known type / tag name.
    expect_tag = False
    saw_type = False
    for w in specs:
        if w in ('*', '&', '::') or re.match(r'^[&*]+$', w):
            continue
        if expect_tag:
            expect_tag = False
            saw_type = True
            continue
        if w in ('struct', 'union', 'enum', 'class'):
            expect_tag = True
            saw_type = True
            continue
        if w in TYPE_QUALIFIERS:
            continue
        if w in BASE_TYPES or w in type_aliases or _is_type_word(w):
            saw_type = True
            continue
        return None
    if expect_tag:  # trailing 'struct' with no tag
        return None
    if not saw_type:
        return None

    # Re-render a readable type (drop storage-class noise that does not help).
    type_str = ' '.join(w for w in specs if w != 'typedef')
    type_str = re.sub(r'\s+', ' ', type_str).replace(' *', '*').replace(' &', '&')
    is_pointer = any(re.match(r'^[&*]+$', w) for w in specs)
    return {
        'name': name,
        'type': type_str or '<unknown>',
        'has_init': has_init,
        'is_array': is_array,
        'is_pointer': is_pointer,
        'storage': 'static' if 'static' in specs else ('extern' if 'extern' in specs else ''),
    }


def _find_top_level(s, ch):
    """Index of the first ``ch`` at nesting depth 0 (parens/brackets/braces)."""
    depth = 0
    for i, c in enumerate(s):
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth = max(0, depth - 1)
        elif c == ch and depth == 0:
            return i
    return -1


def split_commas(s):
    """Split a declarator list on top-level commas."""
    parts = []
    depth = 0
    cur = []
    for c in s:
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth = max(0, depth - 1)
        if c == ',' and depth == 0:
            parts.append(''.join(cur))
            cur = []
            continue
        cur.append(c)
    parts.append(''.join(cur))
    return parts


def _find_name_offset(seg, name, start=0):
    m = re.compile(r'\b' + re.escape(name) + r'\b').search(seg, start)
    if m:
        return m.start(), m.end()
    return -1, start


def line_of(text, offset):
    return text.count('\n', 0, offset) + 1


def _snippet(original_lines, line, span=3):
    lo = max(0, line - 1 - span)
    hi = min(len(original_lines), line + span)
    return '\n'.join(original_lines[lo:hi])


_LEADING_COMMENT_RE = re.compile(r'\s*(?://[^\n]*\n|/\*.*?\*/)', re.S)


def statement_snippet(original, start, end):
    """The statement as written, without the leading comment noise.

    Statements are split on ``;``/``{``/``}`` of the *cleaned* text, so the
    original slice may start with blank lines and comment blocks that were
    blanked out for the parser.  Those would otherwise be handed to the model
    (or printed) as if they were part of the declaration.
    """
    seg = original[start:end]
    while seg:
        m = _LEADING_COMMENT_RE.match(seg)
        if m and m.end() > 0:
            seg = seg[m.end():]
            continue
        stripped = seg.lstrip()
        if stripped.startswith('#'):
            # Preprocessor lines contain no ';', so they stick to the statement
            # that follows them.  Drop the whole directive, continuations too.
            i = 0
            while True:
                nl = stripped.find('\n', i)
                if nl == -1:
                    return ''
                if stripped[nl - 1:nl] != '\\':
                    break
                i = nl + 1
            seg = stripped[nl + 1:]
            continue
        break
    return seg.rstrip()


def scan_c_file(path, rel, type_aliases):
    """Scan a C/C++ file and return (declarations, prepared_text, raw_clean_text).

    ``prepared_text`` is the text the declaration parser works on (comments,
    strings, preprocessor lines and attributes blanked, annotation macros
    blanked too), while ``raw_clean_text`` keeps the macro spellings so that
    annotation sites aliased through a ``#define`` can be recognised.  Both have
    the same length as the original file, so offsets and line numbers are
    directly comparable.
    """
    with open(path, 'r', errors='replace') as fh:
        original = fh.read()

    raw_clean = strip_noise(original)
    macros = find_annotation_macros(original)
    prepared = strip_attributes(blank_tokens(raw_clean, macros))
    # The literal spelling of the annotation lives inside a string literal,
    # which is exactly what raw_clean blanks out, so the annotation test runs on
    # a view that keeps literal bodies.  Only files that mention the marker pay
    # for that second pass.
    annotate_src = (strip_noise(original, keep_strings=True)
                    if ANNOTATION_MARKER in original else raw_clean)

    depth, in_agg, agg_tag = compute_scope(prepared)
    decls = []

    for start, end, delim, seg in split_statements(prepared):
        if not seg.strip():
            continue
        if delim is None and not seg.rstrip().endswith(';'):
            continue
        d = depth[start] if start < len(depth) else 0
        agg = in_agg[start] if start < len(in_agg) else False
        tag = agg_tag[start] if start < len(agg_tag) else ''

        if agg:
            kind = 'struct-member'
        elif d == 0:
            kind = 'global'
        else:
            kind = 'local'

        # Comma-separated declarator lists: parse `type a, b;` once for the head,
        # then reuse the same specifiers for each name.
        pieces = split_commas(seg)
        parsed = parse_decl(pieces[0], type_aliases)
        if parsed is None:
            continue
        names = [parsed]
        for extra in pieces[1:]:
            # The extra declarators lose their specifiers; re-attach them.
            p2 = parse_decl(parsed['type'] + ' ' + extra, type_aliases)
            if p2 is not None:
                names.append(p2)

        seg_raw = raw_clean[start:end]
        annotated = bool(ANNOTATE_RE.search(annotate_src[start:end])) \
            or blank_tokens(seg_raw, macros).strip() != seg_raw.strip()

        cursor = 0
        for parsed_decl in names:
            off, cursor = _find_name_offset(seg, parsed_decl['name'], cursor)
            # The declaration is reported at the *name*, not at the statement
            # start: a segment may begin after a blanked `#include` block.
            line = line_of(prepared, start + off) if off >= 0 else line_of(prepared, start)
            decls.append({
                'name': parsed_decl['name'],
                'type': parsed_decl['type'],
                'kind': kind,
                'agg': tag if agg else '',
                'file': rel,
                'line': line,
                'end_line': line + (seg[off:].count('\n') if off >= 0 else seg.count('\n')),
                'storage': parsed_decl['storage'],
                'is_pointer': parsed_decl['is_pointer'],
                'is_array': parsed_decl['is_array'],
                'annotated': annotated,
                'snippet': statement_snippet(original, start, end),
            })

        if parsed['name'] and seg.lstrip().startswith('typedef'):
            type_aliases.add(parsed['name'])

    return decls, prepared, raw_clean


def scan_enum_constants(cleaned, rel, original, raw_clean=None):
    """Extract enum constants, which are frequently the protocol's state ids."""
    out = []
    raw = raw_clean if raw_clean is not None else cleaned
    for m in re.finditer(r'\benum\b[^;{}]*\{', cleaned):
        start = m.end()
        depth = 1
        i = start
        while i < len(cleaned) and depth:
            if cleaned[i] == '{':
                depth += 1
            elif cleaned[i] == '}':
                depth -= 1
            i += 1
        body = cleaned[start:i - 1]
        raw_body = raw[start:i - 1]
        tag = cleaned[m.start():m.end() - 1].strip()
        line = line_of(cleaned, m.start())
        for piece in split_commas(body):
            piece = piece.strip()
            if not piece:
                continue
            name_m = re.match(r'([A-Za-z_]\w*)', piece)
            if not name_m:
                continue
            nm = name_m.group(1)
            if nm in RESERVED:
                continue
            out.append({
                'name': nm,
                'type': tag or 'enum',
                'kind': 'enum-constant',
                'file': rel,
                'line': line,
                'end_line': line,
                'storage': '',
                'is_pointer': False,
                'is_array': False,
                'annotated': ANNOTATION_MARKER in raw_body,
                'snippet': statement_snippet(original, start, i - 1),
            })
    return out


PY_ATTR_RE = re.compile(r'^\s*self\.([A-Za-z_]\w*)\s*=')


def scan_python_file(path, rel):
    """Scan a Python file with :mod:`ast` and return its state-ish attributes."""
    with open(path, 'r', errors='replace') as fh:
        source = fh.read()
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return []

    lines = source.splitlines()
    decls = []

    def add(name, kind, line):
        decls.append({
            'name': name,
            'type': '<py>',
            'kind': kind,
            'file': rel,
            'line': line,
            'end_line': line,
            'storage': '',
            'is_pointer': False,
            'is_array': False,
            'annotated': False,
            'snippet': _snippet(lines, line),
        })

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    add(t.id, 'python-global', t.lineno)
                elif isinstance(t, ast.Attribute):
                    add(t.attr, 'python-attribute', t.lineno)
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, ast.FunctionDef) and sub.name == '__init__':
                    for inner in ast.walk(sub):
                        if isinstance(inner, (ast.Assign, ast.AnnAssign)):
                            tgts = inner.targets if isinstance(inner, ast.Assign) else [inner.target]
                            for t in tgts:
                                if isinstance(t, ast.Attribute):
                                    add(t.attr, 'python-attribute', t.lineno)
    return decls


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------

NUM_LITERAL_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|\d+|'.*'|\".*\")$")

STRING_FN_NAMES = ('strcmp', 'strncmp', 'strcasecmp', 'strncasecmp', 'strstr',
                   'strcoll', 'memcmp')
STRING_FN_CALL_RE = re.compile(r'\b(?:' + '|'.join(STRING_FN_NAMES) + r')\s*\(\s*$')
PARSE_CALL_RE = re.compile(r'\b(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull'
                           r'|strtod|sscanf)\s*\(\s*$')
ASSIGN_TAIL_RE = re.compile(r'(?:\+\+|--|[+\-*/%&|^]?=(?!=))')


def _empty_counts():
    return {'const_comparisons': 0, 'var_comparisons': 0, 'switch_statements': 0,
            'switch_cases': 0, 'string_comparisons': 0, 'parse_calls': 0,
            'assignments': 0, 'occurrences': 0}


IDENT_SCAN_RE = re.compile(r'[A-Za-z_]\w*')

# Counting is driven by a full identifier scan, so every hook below runs once
# per occurrence of a candidate name -- several per source line.  Cheap string
# probes keep the regexes off the hot path; they cannot change the result, only
# skip windows that provably contain no operator/functions of interest.
AFTER_COMPARE_RE = re.compile(r'\s*(?:==|!=|<=|>=|<|>)\s*([^\s(),;]+)')
BEFORE_COMPARE_RE = re.compile(r'([^\s(),;]+)\s*(?:==|!=|<=|>=|<|>)\s*$')
SWITCH_BEFORE_RE = re.compile(r'\bswitch\s*\(\s*$')


def _has_cmp(window):
    return '=' in window or '<' in window or '>' in window or '!' in window


def count_usage_multi(texts, names):
    """Measure how each name in ``names`` is used across ``texts``.

    Only the operand *immediately* adjacent to a comparison operator is
    inspected.  The obvious implementation -- regex the name, then look at a
    48-character window -- attributes every unrelated comparison in the
    neighbourhood to the variable and swamps the ranking.

    ``texts`` is a list of cleaned sources (see :func:`strip_noise`), which lets
    a caller count a struct member declared in a header over the whole tree
    instead of over the header where it is never mentioned again.
    """
    out = dict((n, _empty_counts()) for n in names)
    if not names:
        return out
    # Scanning every identifier and looking it up in a set is much cheaper than
    # compiling one alternation of ten thousand names -- on a 30 MB tree with
    # Kamailio's symbol count the regex alone takes minutes.
    nameset = set(names)

    for text in texts:
        for m in IDENT_SCAN_RE.finditer(text):
            c = out.get(m.group(0))
            if c is None:
                continue
            c['occurrences'] += 1
            before = text[max(0, m.start() - 64):m.start()]
            after = text[m.end():m.end() + 64]

            others = []
            if _has_cmp(after):
                others.append(AFTER_COMPARE_RE.match(after))
            if _has_cmp(before):
                others.append(BEFORE_COMPARE_RE.search(before))
            for other in others:
                if other is None:
                    continue
                if NUM_LITERAL_RE.match(other.group(1)):
                    c['const_comparisons'] += 1
                else:
                    c['var_comparisons'] += 1

            if 'switch' in before and SWITCH_BEFORE_RE.search(before):
                c['switch_statements'] += 1
                head = re.match(r'\s*\)\s*\{', text[m.end():m.end() + 8])
                if head:
                    i = m.end() + head.end() - 1  # the '{' of the body
                    depth = 0
                    j = i
                    while j < len(text):
                        if text[j] == '{':
                            depth += 1
                        elif text[j] == '}':
                            depth -= 1
                            if depth == 0:
                                break
                        j += 1
                    c['switch_cases'] += len(re.findall(r'\bcase\b', text[i:j]))

            if ('str' in before or 'memcmp' in before) and STRING_FN_CALL_RE.search(before):
                c['string_comparisons'] += 1
            if ('ato' in before or 'strto' in before or 'sscanf' in before) \
                    and PARSE_CALL_RE.search(before):
                c['parse_calls'] += 1
            if ASSIGN_TAIL_RE.match(after.lstrip()):
                c['assignments'] += 1
    return out


def _looks_like_constant(name):
    return bool(re.match(r'^[A-Z0-9_]{3,}$', name))


def score_candidate(cand):
    score = 0.0
    if cand['annotated']:
        score += 1000.0
    score += 3.0 * min(cand['const_comparisons'], 40)
    score += 4.0 * min(cand['switch_statements'], 8)
    score += 1.0 * min(cand['switch_cases'], 40)
    score += 3.0 * min(cand['string_comparisons'], 40)
    score += 1.5 * min(cand['parse_calls'], 10)
    score += 1.0 * min(cand['assignments'], 30)
    score += 0.5 * min(cand['var_comparisons'], 40)
    score += 0.1 * min(cand['occurrences'], 100)
    if cand['const_comparisons'] and cand['assignments']:
        score += 5.0  # compared *and* written: the shape of a state machine
    if cand['kind'] == 'struct-member':
        score += 2.0
    elif cand['kind'] == 'global':
        score += 1.0
    elif cand['kind'] == 'enum-constant':
        score -= 1.0
    if cand['storage'] == 'static':
        score += 1.5
    if cand['is_pointer'] or cand['is_array']:
        score -= 0.5
    if (cand['name'].lower() in GENERIC_NAMES or len(cand['name']) <= 2) \
            and not cand['annotated']:
        # Short names ('i', 'e', 'tmp') are scratch space with near-zero
        # information -- unless explicitly annotated.
        score *= 0.15
    if cand.get('generic_member') and not cand['annotated']:
        # The same member name declared in three unrelated structs ('op',
        # 'next', 'data') is a vocabulary word, not one protocol state: its
        # usage counts are an aggregate over unrelated variables.
        score *= 0.1
    if cand.get('sites', 1) > 1 and not cand['annotated']:
        # Usage is counted by name over the whole tree.  When the same name is
        # declared in several places (one global per module, one `type` member
        # per struct) those counts stitch several unrelated variables together,
        # so the evidence has to be discounted by how many variables it covers.
        score /= (1.0 + 0.5 * (cand['sites'] - 1))
    if cand['kind'] == 'local':
        # A name declared N times in one file is a scratch buffer, not state.
        score *= 0.5 / (1.0 + 0.5 * max(0, cand['declarations'] - 1))
    if _looks_like_constant(cand['name']):
        score *= 0.5
    score *= cand['path_weight']
    return score


def iter_source_files(root, extensions):
    if os.path.isfile(root):
        if root.endswith(extensions):
            yield root, os.path.basename(root)
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if fn.endswith(extensions):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, root)
                yield full, rel


def _path_weight(rel):
    parts = set(rel.lower().replace('\\', '/').split('/')[:-1])
    if parts & DEAD_DIRS:
        return 0.08
    if parts & LOW_PRIORITY_DIRS:
        return 0.4
    return 1.0


def collect_candidates(root, extensions=DEFAULT_EXTENSIONS, max_candidates=200,
                       include_enums=True, max_corpus_bytes=64 * 1024 * 1024,
                       max_per_name=3, progress=None):
    """Scan ``root`` and return ``(top, ranked)`` candidates by descending score.

    Each candidate is a plain dict, safe to JSON-serialize.

    Usage statistics are computed over the whole tree for globals / struct
    members (they are usually declared in a header and used everywhere else) and
    per file for locals.  ``max_corpus_bytes`` bounds how much cleaned source is
    kept in memory for that; a bigger tree silently degrades to per-file counts.

    ``max_per_name`` caps how many declarations of the same ``(name, kind)``
    survive into ``ranked`` (annotated ones are always kept), which keeps a
    common name from filling the whole list.

    ``progress``, if given, is called as ``progress(files_seen, rel)`` while the
    tree is walked -- a large repository takes a minute to scan.
    """
    root = os.path.abspath(root)
    files = []           # (rel, kind of scanner, decls)
    texts = {}           # rel -> cleaned text
    total = 0
    type_aliases = set()

    for seen, (full, rel) in enumerate(iter_source_files(root, extensions), 1):
        try:
            if rel.endswith(PY_EXTENSIONS):
                decls = scan_python_file(full, rel)
                with open(full, 'r', errors='replace') as fh:
                    cleaned = strip_noise(fh.read())
            else:
                decls, prepared, cleaned = scan_c_file(full, rel, type_aliases)
                if include_enums:
                    with open(full, 'r', errors='replace') as fh:
                        original = fh.read()
                    decls.extend(scan_enum_constants(prepared, rel, original, cleaned))
        except (OSError, UnicodeDecodeError):
            continue
        if progress is not None:
            progress(seen, rel)
        files.append((rel, decls))
        texts[rel] = cleaned
        total += len(cleaned)

    repo_wide = total <= max_corpus_bytes
    all_texts = list(texts.values()) if repo_wide else []

    def names_of(kinds):
        seen = set()
        for _, decls in files:
            for d in decls:
                if d['kind'] in kinds:
                    seen.add(d['name'])
        return sorted(seen)

    shared_counts = count_usage_multi(all_texts, names_of(
        {'global', 'struct-member', 'enum-constant', 'python-global'})) if repo_wide else {}

    # A member name declared in several unrelated aggregates ('op', 'next',
    # 'data') is a vocabulary word shared by unrelated variables, so its
    # repo-wide usage counts are meaningless as evidence of one state.
    member_tags = {}
    for _, decls in files:
        for d in decls:
            if d['kind'] == 'struct-member' and d.get('agg'):
                member_tags.setdefault(d['name'], set()).add(d['agg'])
    generic_members = set(n for n, tags in member_tags.items() if len(tags) >= 3)

    # How many distinct objects share each name: for a member it is the number
    # of aggregates declaring it, for a global the number of files declaring it.
    site_keys = {}
    for _, decls in files:
        for d in decls:
            if d['kind'] in ('local', 'python-attribute'):
                continue
            key = (d.get('agg') or d['file']) if d['kind'] == 'struct-member' else d['file']
            site_keys.setdefault(d['name'], set()).add(key)

    by_key = {}
    for rel, decls in files:
        cleaned = texts[rel]
        weight = _path_weight(rel)
        local_names = sorted(set(d['name'] for d in decls if d['kind'] in
                                 ('local', 'python-attribute')))
        local_counts = count_usage_multi([cleaned], local_names)
        decl_count = {}

        for d in decls:
            is_local = d['kind'] in ('local', 'python-attribute')
            if is_local and not d['annotated'] and len(d['name']) <= 2:
                continue
            if is_local:
                decl_count[d['name']] = decl_count.get(d['name'], 0) + 1
                key = ('local', rel, d['name'])
                counts = local_counts[d['name']]
            else:
                key = (d['kind'], rel, d['line'], d['name'])
                counts = shared_counts.get(d['name']) or count_usage_multi(
                    [cleaned], [d['name']])[d['name']]
            cand = {
                'name': d['name'],
                'type': d['type'],
                'kind': d['kind'],
                'file': rel,
                'line': d['line'],
                'end_line': d.get('end_line', d['line']),
                'location': '%s:%d' % (rel, d['line']),
                'storage': d['storage'],
                'is_pointer': d['is_pointer'],
                'is_array': d['is_array'],
                'annotated': d['annotated'],
                'agg': d.get('agg', ''),
                'generic_member': d['kind'] == 'struct-member'
                                  and d['name'] in generic_members,
                'sites': len(site_keys.get(d['name'], ())) or 1,
                'declarations': 1,
                'path_weight': weight,
                'low_priority_path': weight < 1.0,
                'snippet': d['snippet'],
            }
            cand.update(counts)
            cand['score'] = round(score_candidate(cand), 2)
            prev = by_key.get(key)
            if prev is None or cand['score'] > prev['score']:
                by_key[key] = cand

        # Locals are keyed by name, so a scratch buffer declared twenty times in
        # one file collapses to a single (heavily demoted) candidate.
        for key, cand in list(by_key.items()):
            if key[0] != 'local' or key[1] != rel:
                continue
            n = decl_count.get(cand['name'], 1)
            if n > 1:
                cand['declarations'] = n
                cand['score'] = round(score_candidate(cand), 2)

    ranked = sorted(by_key.values(), key=lambda c: (-c['score'], c['file'], c['line']))
    if max_per_name > 0:
        # The same member name shows up once per file that re-declares it; the
        # long tail of those copies tells the caller nothing new.  Annotated
        # declarations are ground truth and are never dropped.
        kept, per_name = [], {}
        for cand in ranked:
            if cand['annotated']:
                kept.append(cand)
                continue
            k = (cand['name'], cand['kind'])
            if per_name.get(k, 0) >= max_per_name:
                continue
            per_name[k] = per_name.get(k, 0) + 1
            kept.append(cand)
        ranked = kept
    return ranked[:max_candidates], ranked


def main(argv=None):
    import argparse
    import json

    ap = argparse.ArgumentParser(description='scan a source tree for state-variable candidates')
    ap.add_argument('repo')
    ap.add_argument('--top', type=int, default=40, help='print only the top N candidates')
    ap.add_argument('--json', action='store_true', help='emit JSON instead of a table')
    args = ap.parse_args(argv)

    top, all_c = collect_candidates(args.repo, max_candidates=args.top)
    if args.json:
        print(json.dumps(top, indent=2, ensure_ascii=False))
        return 0

    print('%-26s %-13s %-16s %5s %5s %5s %5s %7s  %s' %
          ('name', 'kind', 'type', 'cmp', 'case', 'asg', 'occ', 'score', 'location'))
    for c in top:
        print('%-26s %-13s %-16s %5d %5d %5d %5d %7.1f  %s' % (
            c['name'][:26], c['kind'][:13], c['type'][:16],
            c['const_comparisons'] + c['var_comparisons'], c['switch_cases'],
            c['assignments'], c['occurrences'], c['score'], c['location']))
    print('\n[~] %d candidate(s) shown, %d found in total' % (len(top), len(all_c)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
