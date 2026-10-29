#!/usr/bin/env python3
"""Annotate the definitions listed in an identify.py JSON file.

    python3 utils/AI-agent/statevar/annotate.py <statevars.json> [--repo DIR]

The JSON is the list ``identify.py`` writes, one object per state variable with
an exact definition site::

    [{"name": "Access", "description": "...",
      "location": "Source/ftpserv.h:92", "type": "int"}]

Because the location is exact, this tool does not search for anything: it opens
that file, goes to that line, finds the variable on it and inserts

    __attribute__((annotate("__AFL_STATE_VAR__")))

directly after the declarator (past an array suffix) -- the position clang and
gcc both accept for a global, a struct member, a parameter and an automatic
local.  A line that already carries the annotation (spelled out, or through a
``#define`` alias in the same file) is left alone, so re-running is safe.

Exit codes: 0 success, 1 unreadable input or --check with a pending change,
2 argument error.
"""

from __future__ import print_function

import argparse
import difflib
import json
import os
import re
import sys

ATTRIBUTE = '__attribute__((annotate("__AFL_STATE_VAR__")))'
MARKER = '__AFL_STATE_VAR__'

#: A file is annotatable when it is C or C++.
C_SUFFIXES = ('.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx',
              '.c++', '.h++')

#: ``#define STATE_VAR __attribute__((annotate("__AFL_STATE_VAR__")))``
DEFINE_RE = re.compile(r'(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[^\n]*'
                       + re.escape(MARKER))


def one_line(text, width=120):
    text = re.sub(r'\s+', ' ', (text or '')).strip()
    return text if len(text) <= width else text[:width - 3] + '...'


def bare_name(name):
    """``context->Mode`` / ``Foo::bar`` / ``self.state`` -> the declared name."""
    return re.split(r'->|::|\.', str(name))[-1].strip() or str(name)


def find_declarator(line, name):
    """The occurrence of ``name`` that ends a declarator, or ``None``.

    A line can name its type as well (``struct foo foo;``), so the occurrence
    followed by ``[``/``=``/``;``/``,``/``)``/``{`` or the end of the line is the
    variable; the first occurrence is the fallback for an unusual spelling.
    """
    pattern = re.compile(r'(?<![\w$])' + re.escape(name) + r'(?![\w$])')
    first = None
    for match in pattern.finditer(line):
        if first is None:
            first = match
        rest = line[match.end():].lstrip(' \t')
        if not rest or rest[0] in '[=;,){':
            return match
    return first


def skip_arrays(line, index):
    """Move ``index`` past any ``[..]`` declarator suffix."""
    length = len(line)
    while True:
        i = index
        while i < length and line[i] in ' \t':
            i += 1
        if i >= length or line[i] != '[':
            return index
        depth = 0
        while i < length:
            if line[i] == '[':
                depth += 1
            elif line[i] == ']':
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        index = i


def is_annotated(line, macros):
    """The line already carries the annotation (literally or through a macro)."""
    if MARKER in line:
        return True
    for macro in macros:
        if re.search(r'(?<![\w$])' + re.escape(macro) + r'(?![\w$])', line):
            return True
    return False


def declarator_span(line, start, end):
    """The part of ``line`` that belongs to the declarator ``[start, end)``.

    Two variables can share a line (``int a, b;``): the "already annotated"
    test has to look at this declarator only, not at the whole line.
    """
    depth = 0
    left = 0
    for i in range(start - 1, -1, -1):
        char = line[i]
        if char in ')]}':
            depth += 1
        elif char in '([{':
            if depth:
                depth -= 1
            elif char == '{':
                left = i + 1
                break
        elif depth == 0 and char in ',;':
            left = i + 1
            break
    depth = 0
    right = len(line)
    for i in range(end, len(line)):
        char = line[i]
        if char in '([{':
            depth += 1
        elif char in ')]}':
            if depth:
                depth -= 1
            else:
                right = i
                break
        elif depth == 0 and char in ',;':
            right = i + 1
            break
    return line[left:right]


# ---------------------------------------------------------------------------
# input
# ---------------------------------------------------------------------------

def read_entries(path):
    """The ``{name, location}`` entries of the JSON list."""
    with open(path, 'r', errors='replace') as handle:
        payload = json.load(handle)
    if isinstance(payload, dict):
        payload = payload.get('state_variables') or []
    if not isinstance(payload, list):
        raise ValueError('expected a JSON list of state variables')
    entries, problems = [], []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get('name') or '').strip()
        location = str(item.get('location') or '').strip()
        file_name, separator, line_text = location.rpartition(':')
        if not name or not separator or not line_text.isdigit():
            problems.append('%s: no usable "file:line" location' % (name or '?'))
            continue
        entries.append({'name': name, 'location': location,
                        'file': file_name.strip(), 'line': int(line_text)})
    return entries, problems


def resolve(path, repo):
    return path if os.path.isabs(path) else os.path.join(repo, path)


# ---------------------------------------------------------------------------
# the edit
# ---------------------------------------------------------------------------

def annotate_file(path, rel, entries, options, log):
    """Annotate one file; return the per-entry results."""
    with open(path, 'rb') as handle:
        text = handle.read().decode('latin-1')
    lines = text.splitlines(True)
    macros = set(DEFINE_RE.findall(text))
    by_line = {}
    for entry in entries:
        by_line.setdefault(entry['line'], []).append(entry)

    results = []
    for line_number in sorted(by_line):
        if not 1 <= line_number <= len(lines):
            for entry in by_line[line_number]:
                results.append({'name': entry['name'], 'file': rel,
                                'line': line_number, 'status': 'not-found',
                                'reason': 'line %d is past the end of the file '
                                          '(%d line(s))' % (line_number, len(lines))})
            continue
        line = lines[line_number - 1]
        for entry in by_line[line_number]:
            result = {'name': entry['name'], 'file': rel, 'line': line_number}
            match = find_declarator(line, bare_name(entry['name']))
            if match is None:
                result['status'] = 'not-found'
                result['reason'] = 'name not found on line %d' % line_number
                results.append(result)
                continue
            if is_annotated(declarator_span(line, match.start(), match.end()),
                            macros):
                result['status'] = 'already-annotated'
                results.append(result)
                continue
            if line[match.end():].lstrip(' \t').startswith(':'):
                result['status'] = 'unsupported'
                result['reason'] = 'bit-field cannot take the annotation'
                results.append(result)
                continue
            end = skip_arrays(line, match.end())
            line = line[:end] + ' ' + ATTRIBUTE + line[end:]
            result['status'] = 'annotated'
            results.append(result)
        lines[line_number - 1] = line

    new_text = ''.join(lines)
    if new_text == text:
        return results, False
    if options.dry_run:
        sys.stdout.writelines(difflib.unified_diff(
            text.splitlines(True), new_text.splitlines(True),
            fromfile='a/' + rel, tofile='b/' + rel))
    if options.dry_run or options.check:
        return results, True
    if options.backup:
        with open(path + '.bak', 'wb') as handle:
            handle.write(text.encode('latin-1'))
    with open(path, 'wb') as handle:
        handle.write(new_text.encode('latin-1'))
    log('[+] %s: %d annotation(s)' % (rel, len(
        [r for r in results if r['status'] == 'annotated'])))
    return results, True


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------

def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog='annotate.py',
        description='Insert __AFL_STATE_VAR__ at the definition sites listed in '
                    'an identify.py JSON file (a list of name/location).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  python3 utils/AI-agent/statevar/annotate.py statevars.json '
               '--repo ~/src/foo --dry-run\n'
               '  python3 utils/AI-agent/statevar/annotate.py statevars.json '
               '--repo ~/src/foo --backup\n'
               '  python3 utils/AI-agent/statevar/annotate.py statevars.json '
               '--check\n')
    ap.add_argument('statevars', help='JSON list written by identify.py')
    ap.add_argument('--repo',
                    help='root the relative locations are based on '
                         '(default: the current directory)')
    ap.add_argument('--dry-run', action='store_true',
                    help='print a unified diff and write nothing')
    ap.add_argument('--check', action='store_true',
                    help='exit 1 when an annotation is still pending')
    ap.add_argument('--backup', action='store_true',
                    help='keep a .bak copy of every file that is modified')
    ap.add_argument('--quiet', action='store_true', help='no progress on stderr')
    return ap.parse_args(argv)


def main(argv=None):
    options = parse_args(argv)

    def log(message):
        if not options.quiet:
            print(message, file=sys.stderr)

    if not os.path.isfile(options.statevars):
        print('[!] no such JSON file: %s' % options.statevars, file=sys.stderr)
        return 1
    try:
        entries, problems = read_entries(options.statevars)
    except (OSError, ValueError) as exc:
        print('[!] cannot read %s: %s' % (options.statevars, exc), file=sys.stderr)
        return 1
    repo = os.path.abspath(options.repo or os.getcwd())
    log('[~] %d entr(ies) from %s, locations relative to %s'
        % (len(entries), options.statevars, repo))

    results = [{'name': '?', 'file': '', 'line': 0, 'status': 'bad-entry',
                'reason': problem} for problem in problems]
    by_file = {}
    for entry in entries:
        path = resolve(entry['file'], repo)
        rel = entry['file']
        if not os.path.isfile(path):
            results.append({'name': entry['name'], 'file': rel,
                            'line': entry['line'], 'status': 'file-missing',
                            'reason': 'no such file: %s (pass --repo if the '
                                      'locations are relative to another tree)'
                                      % path})
            continue
        if not rel.lower().endswith(C_SUFFIXES):
            results.append({'name': entry['name'], 'file': rel,
                            'line': entry['line'], 'status': 'unsupported',
                            'reason': 'not a C/C++ source'})
            continue
        by_file.setdefault((path, rel), []).append(entry)

    changed_files = 0
    for (path, rel), file_entries in sorted(by_file.items(), key=lambda kv: kv[0][1]):
        file_results, changed = annotate_file(path, rel, file_entries, options, log)
        results.extend(file_results)
        changed_files += 1 if changed else 0

    counts = {}
    for result in results:
        counts[result['status']] = counts.get(result['status'], 0) + 1
    for status in sorted(counts):
        log('[~] %-18s %d' % (status, counts[status]))
    for result in results:
        if result['status'] in ('bad-entry', 'file-missing', 'not-found',
                                'unsupported'):
            log('[!] %s:%s: %s -- %s' % (result['file'], result['line'],
                                         result['name'], result.get('reason', '')))

    pending = counts.get('annotated', 0)
    if options.check:
        log('[~] %d annotation(s) pending' % pending)
        return 1 if pending else 0
    if options.dry_run:
        log('[~] %d annotation(s) pending in %d file(s)'
            % (pending, changed_files))
    else:
        log('[+] %d annotation(s) written in %d file(s)'
            % (pending, changed_files))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
