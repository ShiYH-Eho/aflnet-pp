#!/usr/bin/env python3
"""Enrich an AFLNet++ seed corpus with LLM-written message sequences.

    python3 utils/AI-agent/corpus-enrich/enrich_corpus.py \
        <corpus-dir> <output-dir> <protocol> [options]

One seed of an AFLNet(++) corpus is *one whole message sequence* -- a chain of
client requests such as ``USER x\\r\\nPASS y\\r\\n...`` -- which the fuzzer replays
message by message.  Whatever the initial corpus does not contain, the fuzzer has
to rediscover from scratch, and for a stateful protocol that is the expensive
part.  This tool rewrites that starting point with a model's help, aiming at the
three kinds of coverage AFLNet++ reacts to:

* **service coverage** -- this task always runs.  A service is a coherent client
  workflow such as login, directory listing, upload or retrieval.  If
  ``--services`` names them, one job is planned per service; otherwise the model
  discovers the protocol's services at runtime;
* **message type coverage** -- enabled by ``--grammar`` (or an explicit
  ``--types`` list).  Every client request type should appear somewhere in the
  pool;
* **state variable coverage** -- for every state variable reported by
  ``utils/AI-agent/statevar/identify.py`` (or by the ChatState ``state.json`` /
  ``query.json`` this tree already uses), some seed should drive it to each value
  it can take and through each branch it controls (``context->Mode`` reaching
  ``MODE_PASSIVE``, ``Access`` reaching ``FTP_ACCESS_NOLOGIN``,
  ``DataProtectionLevel`` reaching ``PROT_P`` ...).

The three enrichment tasks are additive, not mutually exclusive.  ``--root`` is
also optional: when supplied it exposes the project repository, server
configuration and related files through ``list_dir``, ``read_file`` and
``search_text``.  Without ``--root`` the model has no local tool access.

```text
utils/AI-agent/corpus-enrich/
├── enrich_corpus.py   # the tool (this file)
├── llmclient.py       # lazy shim around utils/AI-agent/statevar/llmclient.py
├── selftest.py        # offline regression test, needs no network
├── ../agent.py        # the shared JSON tool agent (also used by statevar,
│                      #   pro-template)
└── ../localtools.py   # list_dir / read_file / search_text, shared with statevar
```

What it writes: the original seeds (copied) plus one new file per generated
sequence, named for the service, type or state-variable task that produced it.
A run also writes ``<output>/.enrich.json`` with the task set, coverage
information, local tool calls and the model's rationale.

Every input except the corpus is optional: without ``--statevars`` the run does
message type coverage only, without ``--types``/``--grammar``/``--services`` the
type universe is asked from the model once, and without an endpoint
``--dump-prompt``/``--from-answer`` keep the whole pipeline usable from any chat
UI.

Exit codes: 0 success, 1 error (bad corpus, endpoint failure, nothing usable
with ``--strict``), 2 argument error.
"""

from __future__ import print_function

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
SHARED = os.path.dirname(HERE)          # utils/AI-agent: localtools.py lives there
if SHARED not in sys.path:
    sys.path.insert(0, SHARED)

import agent  # noqa: E402
import formats  # noqa: E402  (shared with pro-template)
import llmclient  # noqa: E402  (shim next to this file)
import localtools  # noqa: E402

VERSION = '1.1'
META_NAME = '.enrich.json'
ENRICHED_PREFIX = 'enriched'
STATEVAR_PREFIX = 'enriched_sv'
#: what a final answer looks like, for the agent's retry hint
FINAL_HINT = '{"action":"final","seed":{...}}'

#: Default message terminator, written the way it is typed on the command line.
DEFAULT_TERMINATOR = '\\r\\n'
#: ChatState's MAX_ENRICHMENT_MESSAGE_TYPES: how many missing types one request
#: asks for.  More than a couple and the model starts dropping one of them.
DEFAULT_TYPES_PER_JOB = 2
DEFAULT_MAX_JOBS_PER_SEED = 5
DEFAULT_MAX_JOBS = 60
DEFAULT_MAX_STEPS = 12
DEFAULT_MAX_MESSAGES = 64
DEFAULT_MAX_MESSAGE_BYTES = 4096
DEFAULT_PROMPT_MESSAGES = 40
DEFAULT_ROUNDS = 2

LANGUAGES = {
    'en': 'Write the "rationale" field in English, at most two sentences.',
    'zh': 'Write the "rationale" field in Simplified Chinese (简体中文)，最多两句话。',
}

#: Where a request header ends -- ChatState splits message types on the same set.
HEADER_STOPS = (' ', '\t', '\r', '\n', '\\')

#: A plausible protocol request type name (chat message / HTTP method / verb).
TYPE_RE = re.compile(r'^[A-Z0-9][A-Z0-9_.+-]*$')


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def shorten(text, width=72):
    text = re.sub(r'\s+', ' ', (text or '')).strip()
    return text if len(text) <= width else text[:width - 3] + '...'


def decode_escapes(text, binary=False):
    """Decode the literal escapes a model writes in an answer.

    Text mode deliberately keeps its historical behaviour.  Binary mode also
    accepts ``\\xNN`` so a model can spell arbitrary frame bytes in JSON.
    """
    table = {'\\r': '\r', '\\n': '\n', '\\t': '\t', '\\0': '\0', '\\\\': '\\'}
    out = []
    i = 0
    while i < len(text):
        pair = text[i:i + 2]
        if pair in table:
            out.append(table[pair])
            i += 2
            continue
        if binary and pair in ('\\x', '\\X') and i + 3 < len(text):
            try:
                out.append(chr(int(text[i + 2:i + 4], 16)))
            except ValueError:
                pass
            else:
                i += 4
                continue
        out.append(text[i])
        i += 1
    return ''.join(out)


def escape_terminator(terminator):
    return terminator.replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')


def escape_binary_message(message):
    """Render one latin-1 message as an unambiguous escaped byte string."""
    out = []
    for char in message:
        value = ord(char)
        if char == '\\':
            out.append('\\\\')
        elif 0x20 <= value <= 0x7e:
            out.append(char)
        else:
            out.append('\\x%02x' % value)
    return ''.join(out)


def read_bytes(path, limit=1 << 20):
    try:
        with open(path, 'rb') as handle:
            return handle.read(limit)
    except OSError:
        return None


def write_bytes(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, 'wb') as handle:
        handle.write(data)


def read_text(path):
    """Read a text file: UTF-8 when valid, else latin-1 (lossless for any byte)."""
    data = read_bytes(path, limit=4 << 20)
    if data is None:
        return None
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.decode('latin-1')


def sanitize(name):
    return re.sub(r'[^A-Za-z0-9._-]+', '_', str(name)).strip('_') or 'seed'


def chunks(items, size):
    size = max(1, int(size))
    return [items[i:i + size] for i in range(0, len(items), size)]


def seed_files(directory, skip_enriched=True):
    files = []
    if not os.path.isdir(directory):
        return files
    for name in sorted(os.listdir(directory)):
        if name.startswith('.'):
            continue                      # .enrich.json and friends are not seeds
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        if skip_enriched and ENRICHED_PREFIX in name:
            continue
        files.append((name, path))
    return files


# ---------------------------------------------------------------------------
# protocol message model
# ---------------------------------------------------------------------------

def header_token(message):
    """The leading token of a request (ChatState's message type for line protocols)."""
    out = []
    for ch in message:
        if ch in HEADER_STOPS:
            break
        out.append(ch)
    return ''.join(out).strip().upper()


def split_messages(data, terminator, max_messages=DEFAULT_MAX_MESSAGES):
    """Split one seed file into its messages, without the terminators."""
    text = (data or b'').decode('latin-1')
    parts = text.split(terminator)
    messages = [p.rstrip('\r\n') for p in parts if p.strip()]
    if len(messages) <= 1 and terminator != '\n' and '\n' in text:
        # a corpus captured with plain LF still has to be usable
        messages = [p.rstrip('\r\n') for p in text.split('\n') if p.strip()]
    if max_messages and len(messages) > max_messages:
        messages = messages[:max_messages]
    return messages


def join_messages(messages, terminator, binary=False):
    """Serialize messages; binary frames are already complete and get no CRLF."""
    if binary:
        return ''.join(messages).encode('latin-1')
    return (terminator.join(messages) + terminator).encode('latin-1')


def pcre_to_re(pattern):
    """Translate the PCRE2-isms of a pro-template header into Python ``re``."""
    text = pattern
    text = text.replace('\\r', '\r').replace('\\n', '\n').replace('\\t', '\t')
    text = re.sub(r'\(\?<([A-Za-z_][A-Za-z0-9_]*)>', r'(?P<\1>', text)
    text = re.sub(r"\(\?'([A-Za-z_][A-Za-z0-9_]*)'", r'(?P<\1>', text)
    text = re.sub(r'\\k<([A-Za-z_][A-Za-z0-9_]*)>', r'(?P=\1)', text)
    return text


def read_grammar(directory):
    """Read a pro-template directory: one file per type, line 1 is the header.

    Only the header pattern is used here (to tell which message *is* which type),
    so a template Python ``re`` cannot compile is kept with ``compiled = None``
    and the type simply never matches instead of failing the run.
    """
    templates, problems = [], []
    if not os.path.isdir(directory):
        return templates, ['%s is not a directory' % directory]
    for name in sorted(os.listdir(directory)):
        if name.startswith('.'):
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        text = read_text(path)
        if text is None:
            problems.append('%s: cannot read' % name)
            continue
        newline = text.find('\n')
        header = (text[:newline] if newline >= 0 else text).strip()
        if not header:
            problems.append('%s: empty header pattern' % name)
            continue
        try:
            compiled = re.compile(pcre_to_re(header))
        except re.error as exc:
            compiled = None
            problems.append('%s: Python re cannot compile the header (%s)' % (name, exc))
        templates.append({'type': name, 'header': header, 'compiled': compiled})
    return templates, problems


def classify(message, templates, terminator, formats_data=None):
    """Message type of ``message``: probe, grammar template, or its first verb."""
    if formats_data:
        # binary protocol: the probe table is the authority; an unknown type is
        # reported as unknown instead of a junk "verb" from binary bytes
        return formats.classify(message.encode('latin-1', 'replace'), formats_data)
    if templates:
        for template in templates:
            if template['compiled'] is None:
                continue
            if template['compiled'].match(message + terminator) \
                    or template['compiled'].match(message):
                return template['type']
    return header_token(message) or None


def explicit_types(spec):
    """``--types`` -- a comma separated list of names, or a file holding them."""
    if not spec:
        return set()
    if os.path.isfile(spec):
        spec = read_text(spec) or ''
    return set(t.strip().upper() for t in re.split(r'[\s,]+', spec)
               if t.strip() and TYPE_RE.match(t.strip().upper()))


# ---------------------------------------------------------------------------
# state variables
# ---------------------------------------------------------------------------

def _statevar_record(name, value, repository):
    """One state variable from any of the JSON shapes this tree produces."""
    record = {'name': name, 'description': '', 'type': '', 'kind': '',
              'locations': [], 'cond_snippets': [], 'store_snippets': [],
              'default': None}
    if isinstance(value, str):
        record['locations'] = [_resolve_location(value, repository)] \
            if ':' in value else []
        record['description'] = '' if record['locations'] else value
        return record
    if not isinstance(value, dict):
        return record
    record['description'] = str(value.get('description') or value.get('meaning') or '')
    record['type'] = str(value.get('type') or '')
    record['kind'] = str(value.get('kind') or '')
    if value.get('default_value') is not None:
        record['default'] = value.get('default_value')
    for key in ('location', 'cond_insts', 'store_insts'):
        raw = value.get(key)
        if isinstance(raw, str):
            raw = [raw]
        if isinstance(raw, list):
            for item in raw:
                location = _resolve_location(str(item), repository)
                if location and location not in record['locations']:
                    record['locations'].append(location)
    if value.get('file'):
        # identify.py carries file and line side by side: keep them together so
        # the prompt and the report show one location per variable.
        location = _resolve_location('%s:%s' % (value['file'], value['line']),
                                     repository) if value.get('line') is not None \
            else _resolve_location(value['file'], repository)
        if location and location not in record['locations']:
            record['locations'].insert(0, location)
    for key, target in (('cond_codes', 'cond_snippets'), ('store_codes', 'store_snippets'),
                        ('related_codes', 'store_snippets')):
        raw = value.get(key)
        if isinstance(raw, list):
            record[target].extend(str(item) for item in raw if item)
        elif isinstance(raw, str) and raw:
            record[target].append(raw)
    return record


def _resolve_location(location, repository):
    """Absolute ``file:line`` for a location, relative to the JSON's repository."""
    text = (location or '').strip()
    if not text:
        return ''
    # ChatState's cond_insts/store_insts spell it file:line:column.
    detailed = re.match(r'^(.*):(\d+):(\d+)$', text)
    if detailed:
        path, line = detailed.group(1), detailed.group(2)
    else:
        head, sep, tail = text.rpartition(':')
        if sep and tail.strip().isdigit():
            path, line = head, tail.strip()
        else:
            path, line = text, ''
    if not os.path.isabs(path):
        path = os.path.join(repository or '', path)
    path = os.path.normpath(path)
    return '%s:%s' % (path, line) if line else path


def load_statevars(path, log):
    """Read identify.py output, ChatState ``state.json`` or ``query.json``."""
    text = read_text(path)
    if text is None:
        raise ValueError('cannot read %s' % path)
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise ValueError('%s is not JSON: %s' % (path, exc))

    repository = ''
    if isinstance(payload, dict):
        repository = payload.get('repository') or ''
    records = []
    if isinstance(payload, dict) and isinstance(payload.get('state_variables'), list):
        for entry in payload['state_variables']:
            if isinstance(entry, dict):
                records.append(_statevar_record(str(entry.get('name') or '?'),
                                                entry, repository))
    elif isinstance(payload, list):
        for entry in payload:
            if isinstance(entry, dict):
                records.append(_statevar_record(str(entry.get('name') or '?'),
                                                entry, repository))
            elif isinstance(entry, str):
                records.append(_statevar_record(entry, {}, repository))
    elif isinstance(payload, dict):
        for name in sorted(payload):
            if name in ('tool', 'version', 'repository', 'generated_at', 'mode',
                        'model', 'base_url', 'statistics', 'warnings'):
                continue
            records.append(_statevar_record(name, payload[name], repository))
    records = [r for r in records if r['name'] and r['name'] != '?']
    if not records:
        raise ValueError('%s holds no usable state variable' % path)
    log('[~] %d state variable(s) read from %s' % (len(records), path))
    return records


def statevar_brief(record, workspace, width=68):
    """Render one state variable for the prompt."""
    lines = ['name: %s' % record['name']]
    if record['description']:
        lines.append('  description: %s' % shorten(record['description'], 160))
    if record['type'] or record['kind']:
        lines.append('  declared as: %s %s' % (record['type'] or '?', record['kind'] or ''))
    if record['default'] is not None:
        lines.append('  default value: %s' % record['default'])
    for location in record['locations'][:3]:
        lines.append('  defined/used at: %s' % display_location(location, workspace))
    for snippet in record['store_snippets'][:1]:
        lines.append('  code that assigns it:\n%s' % indent(shorten(snippet, 400), '    '))
    for snippet in record['cond_snippets'][:1]:
        lines.append('  branch it controls:\n%s' % indent(shorten(snippet, 400), '    '))
    return '\n'.join(lines)


def indent(text, prefix):
    return '\n'.join(prefix + line for line in (text or '').splitlines())


def display_location(location, workspace):
    """``file:line`` as the model should read it: relative to the workspace."""
    if not location:
        return location
    path, sep, line = location.rpartition(':')
    if not sep or not line.isdigit():
        path, line = location, ''
    if workspace is not None and os.path.isabs(path):
        try:
            rel = os.path.relpath(path, workspace.root)
            if not rel.startswith(os.pardir):
                path = rel
        except ValueError:
            pass
    return '%s:%s' % (path, line) if line else path


def load_service_catalog(path, log):
    """Read protocol services while keeping their names and request chains."""
    text = read_text(path)
    if text is None:
        raise ValueError('cannot read %s' % path)
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise ValueError('%s is not JSON: %s' % (path, exc))

    types, chains, overview, services = set(), [], [], []
    if isinstance(payload, dict):
        for feature in sorted(payload):
            value = payload[feature]
            service = {'name': str(feature), 'description': '',
                       'chains': [], 'symbols': []}
            if isinstance(value, str):
                service['description'] = value
                overview.append('%s: %s' % (feature, shorten(value, 140)))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, list) and item:
                        chain = [str(step) for step in item if str(step).strip()]
                        if chain:
                            chains.append(chain)
                            service['chains'].append(chain)
                            for step in chain:
                                token = step.split()[0].upper()
                                if TYPE_RE.match(token):
                                    types.add(token)
                    elif isinstance(item, str) and item.strip():
                        symbol = item.strip()
                        service['symbols'].append(symbol)
            if service['chains'] or service['symbols'] or service['description']:
                services.append(service)
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, str) and item.strip():
                chain = [item.strip()]
                chains.append(chain)
                token = chain[0].split()[0].upper()
                if TYPE_RE.match(token):
                    types.add(token)
        if chains:
            services.append({'name': 'protocol services', 'description': '',
                             'chains': chains, 'symbols': []})
    log('[~] services: %d request type(s), %d known chain(s), %d description(s)'
        % (len(types), len(chains), len(overview)))
    return services, types, chains, overview


def load_services(path, log):
    """Compatibility view of :func:`load_service_catalog`."""
    _services, types, chains, overview = load_service_catalog(path, log)
    return types, chains, overview


# ---------------------------------------------------------------------------
# the corpus
# ---------------------------------------------------------------------------

class Corpus(object):
    """The seeds read from disk (or the ones already generated this run)."""

    def __init__(self, terminator, templates, formats_data=None):
        self.terminator = terminator
        self.templates = templates
        self.formats = formats_data
        self.framing = formats.framing_of(formats_data) if formats_data else None
        self.files = {}      # name -> [message]
        self.types = {}      # name -> {type}
        self.origin = {}     # name -> 'original' | 'generated'

    def add(self, name, messages, origin='generated'):
        self.files[name] = list(messages)
        self.types[name] = set(t for t in
                               (classify(m, self.templates, self.terminator,
                                         self.formats)
                                for m in messages) if t)
        self.origin[name] = origin

    def load_dir(self, directory, skip_enriched=True,
                 max_messages=DEFAULT_MAX_MESSAGES, warnings=None):
        count = 0
        for name, path in seed_files(directory, skip_enriched=skip_enriched):
            data = read_bytes(path)
            if data is None:
                continue
            if self.formats:
                # a formats table without a framing spec means one message per
                # seed (datagram protocols); never CRLF-split binary bytes
                frames, rest = formats.split_frames(data, self.framing)
                messages = [frame.decode('latin-1') for frame in frames]
                if max_messages and len(messages) > max_messages:
                    messages = messages[:max_messages]
                if rest and warnings is not None:
                    warnings.append('%s: %d trailing byte(s) do not form a frame'
                                    % (name, rest))
            else:
                messages = split_messages(data, self.terminator, max_messages)
            self.add(name, messages, origin='original')
            count += 1
        return count

    @property
    def observed_types(self):
        types = set()
        for values in self.types.values():
            types |= values
        return types

    def missing_in(self, name, universe):
        return sorted(set(universe) - self.types.get(name, set()))

    def richest_seed(self, universe=None):
        if not self.files:
            return None

        def score(name):
            known = set(universe or ())
            typed = self.types[name] & known if known else self.types[name]
            return (len(typed), len(self.files[name]))

        return sorted(self.files, key=score, reverse=True)[0]

    def summary(self):
        return '%d seed(s), %d message(s), %d message type(s)' % (
            len(self.files), self.message_count, len(self.observed_types))

    @property
    def message_count(self):
        return sum(len(v) for v in self.files.values())


# ---------------------------------------------------------------------------
# prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = '''\
You are a network protocol expert building the seed corpus of an AFLNet++ fuzzing
campaign for a {protocol} server.  A seed is one complete sequence of client
requests, exactly what a single client session would send.

You are asked for the *next client message sequence*, guided by
  (1) service coverage: the sequence should exercise a real client workflow of
      the {protocol} server,
  (2) message type coverage: every client request type of the {protocol}
      protocol must appear somewhere in the corpus, and
  (3) state variable coverage: the server's state variables must be driven to
      the values and branches the current corpus does not reach.

{workspace_note}

{tools}

{lang}

Answer with exactly ONE JSON object per turn -- no prose, no code fences:
{tool_turn}
  * to deliver the sequence:
    {{"action":"final","seed":{{"messages":["USER anonymous","PASS ubuntu"],"rationale":"..."}}}}

Rules for "messages": one element per client request, written the way the client
puts it on the wire but WITHOUT its line terminator -- the tool appends the
"{terminator}" terminator itself.  A payload that spans several lines becomes
several elements.  Keep every message of the base sequence byte-identical unless
the task requires a change, and never invent a request type the protocol does not
define.
'''

BINARY_WIRE_RULES = '''\
Rules for "messages": one element per COMPLETE client protocol message, including
its fixed header, length field and checksum.  Spell arbitrary bytes with \\xNN
escapes (in a JSON answer write the backslash as \\\\xNN).  Do not append or strip a
line terminator, and do not split one frame merely because its payload contains
CR, LF or other non-printable bytes.  Keep every message of the base sequence
byte-identical unless the task requires a change, and make every generated frame
valid for the {protocol} framing and message type you target.
'''


def build_system_prompt(protocol, args, binary=False, tools=False):
    tools_help = localtools.TOOLS_HELP if tools else (
        'No workspace tools are available for this run; rely on the material '
        'in the task.  The protocol itself is still the authority.')
    workspace_note = (
        'The target repository, configuration files and corpus are available '
        'in the workspace below; read them whenever the answer depends on a '
        'constant, a keyword, a default or accepted input.'
        if tools else
        'No workspace was supplied.  Use the protocol definition, the task '
        'material and the base corpus; do not claim to have read repository files.')
    tool_turn = (
        '  * to inspect the workspace:\n'
        '    {"action":"tool","tool":"read_file","args":'
        '{"path":"Source/ftpserv.c","start_line":200,"end_line":320}}\n'
        if tools else '')
    prompt = SYSTEM_PROMPT.format(
        protocol=protocol, tools=tools_help,
        workspace_note=workspace_note, tool_turn=tool_turn,
        lang=LANGUAGES.get(args.lang, LANGUAGES['en']),
        terminator=escape_terminator(args.terminator))
    if binary:
        # Binary runs replace the line-oriented wire rules at the end.
        marker = 'Rules for "messages":'
        prompt = prompt[:prompt.index(marker)] + BINARY_WIRE_RULES.format(
            protocol=protocol)
    return prompt


def render_sequence(messages, terminator, limit=DEFAULT_PROMPT_MESSAGES,
                    binary=False):
    marker = '' if binary else escape_terminator(terminator)
    lines = []
    for index, message in enumerate(messages):
        if limit and index >= limit:
            lines.append('... (%d more message(s))' % (len(messages) - limit))
            break
        shown = escape_binary_message(message) if binary else message
        lines.append('%d: %s%s' % (
            index + 1, shown, marker if message else marker))
    return '\n'.join(lines)


def render_binary_formats(formats_data, limit=40):
    """The probe/framing facts the model needs to construct valid frames."""
    if not formats_data:
        return ''
    lines = []
    framing = formats.framing_of(formats_data)
    if framing:
        lines.append('framing: %s' % json.dumps(framing, sort_keys=True))
    else:
        lines.append('framing: one complete message per seed (no stream framing)')
    for name in sorted(formats.types_of(formats_data))[:limit]:
        entry = formats.types_of(formats_data)[name]
        if not isinstance(entry, dict):
            lines.append('%s: (no details)' % name)
            continue
        facts = []
        for key in ('probe', 'layout', 'example_hex', 'frame'):
            if entry.get(key) is not None:
                facts.append('%s=%s' % (key, json.dumps(entry[key], ensure_ascii=False,
                                                        sort_keys=True)))
        lines.append('%s: %s' % (name, '; '.join(facts) or '(no details)'))
    if len(formats.types_of(formats_data)) > limit:
        lines.append('... (%d more type(s))'
                     % (len(formats.types_of(formats_data)) - limit))
    return '\n'.join(lines)


def build_service_prompt(ctx, job):
    """Prompt for the always-on service coverage task."""
    service = job['service']
    base = ctx.corpus.files[job['base']]
    binary = bool(ctx.formats)
    parts = [
        'Task: service coverage (job %s, round %d).' % (job['id'], job['round']),
        'Target service: %s.' % service['name'],
    ]
    if service.get('description'):
        parts.append('Service description: %s' % service['description'])
    if service.get('chains'):
        parts.append('Known request chains for this service:\n%s'
                     % '\n'.join(' / '.join(chain)
                                 for chain in service['chains'][:12]))
    if service.get('symbols'):
        parts.append('Server-side handlers associated with this service: %s'
                     % ', '.join(service['symbols'][:16]))
    if not ctx.service_catalog:
        parts.append('No service catalogue was supplied.  Determine the services '
                     'the %s server actually implements%s, then generate a client '
                     'sequence that exercises as many of them as possible.  Put '
                     'the concrete service names in "services_covered".'
                     % (ctx.protocol,
                        ' by inspecting the workspace' if ctx.workspace else
                        ' from the protocol definition and corpus'))
    else:
        parts.append('Generate one complete client session sequence that exercises '
                     'this service through its normal request flow.  Include the '
                     'authentication or setup requests it requires, and put the '
                     'concrete actions reached in "services_covered".')
    parts.append('Base corpus sequence (use only as session context):\n\n```\n%s\n```'
                 % render_sequence(base, ctx.terminator, binary=binary))
    if binary:
        parts.append('Binary message types and framing:\n%s'
                     % render_binary_formats(ctx.formats))
    parts.append('Answer with {"action":"final","seed":{"messages":[...],'
                 '"service":"%s","services_covered":["..."],"rationale":"..."}}.'
                 % service['name'])
    return '\n\n'.join(parts)


def build_type_prompt(ctx, job):
    base = ctx.corpus.files[job['base']]
    binary = bool(ctx.formats)
    parts = [
        'Task: message type coverage (job %s, round %d).' % (job['id'], job['round']),
        'The base seed "%s" is this client message sequence:\n\n```\n%s\n```'
        % (job['base'], render_sequence(base, ctx.terminator, binary=binary)),
        'It does not contain these client message type(s): %s.'
        % ', '.join(job['missing_types']),
        ('Add complete, correctly framed messages of those types at positions a '
         'real client would use, together with any earlier setup they require.  '
         'The result is one complete client session sequence the server accepts.')
        if binary else
        ('Add them at the positions a real client would use, together with whatever '
         'earlier request makes them valid (authentication, data channel setup, a '
         'prior SELECT/REST/RNFR, ...).  The result is one complete session sequence '
         'that the server accepts.'),
        'Message types present in this seed: %s.'
        % (', '.join(sorted(ctx.corpus.types[job['base']])) or 'none'),
    ]
    if binary:
        parts.append('Binary message types and framing:\n%s'
                     % render_binary_formats(ctx.formats))
    if ctx.universe:
        parts.append('Request types of the protocol: %s.' % ', '.join(sorted(ctx.universe)))
    if ctx.known_chains:
        parts.append('Known good chains: %s'
                     % ' | '.join(' / '.join(c) for c in ctx.known_chains[:10]))
    if binary:
        parts.append('Every requested type must match its probe bytes, and every '
                     'length/checksum field must describe the bytes in that same '
                     'message.  Everything you add must be valid for a %s server.'
                     % ctx.protocol)
    else:
        parts.append('Every requested type must appear as the first token of one of '
                     'the messages.  Everything you add must be valid for a %s server.'
                     % ctx.protocol)
    parts.append('Answer with {"action":"final","seed":{"messages":[...],'
                 '"types_added":%s,"rationale":"..."}}.' % json.dumps(job['missing_types']))
    return '\n\n'.join(parts)


def build_statevar_prompt(ctx, job):
    record = job['record']
    base = ctx.corpus.files[job['base']]
    binary = bool(ctx.formats)
    parts = [
        'Task: state variable coverage (job %s).' % job['id'],
        'State variable to cover:\n%s' % statevar_brief(record, ctx.workspace),
        'Read the implementation (and any configuration file it uses) to find out '
        'which values "%s" can take -- assignments, #define/enum constants, '
        'configuration defaults -- and which code branches it controls.'
        % record['name'],
        'Then write ONE client request sequence that drives "%s" to a value and '
        'through a branch that the current corpus does not cover.'
        % record['name'],
        'Base sequence (the session context to extend or adapt):\n\n```\n%s\n```'
        % render_sequence(base, ctx.terminator, binary=binary),
    ]
    if binary:
        parts.append('Binary message types and framing:\n%s'
                     % render_binary_formats(ctx.formats))
    previous = ctx.sv_history.get(record['name']) or []
    if previous:
        parts.append('Previous answers already cover: %s.  This time cover a '
                     '*different* value or branch (variant %d of %d).'
                     % ('; '.join(previous[-3:]), job['variant'] + 1, job['variants']))
    if ctx.workspace:
        parts.append('Use the workspace tools before answering if the values or the '
                     'branch conditions are not spelled out above; cite the file '
                     'and line you relied on.')
    else:
        parts.append('No workspace was supplied, so use the code snippets above and '
                     'cite any file/line they provide.')
    parts.append('Answer with {"action":"final","seed":{"messages":[...],'
                 '"state_var":"%s","values_targeted":["..."],"locations":["file:line"],'
                 '"rationale":"..."}}.' % record['name'])
    return '\n\n'.join(parts)


# ---------------------------------------------------------------------------
# talking to the model
# ---------------------------------------------------------------------------

def make_client(args, log):
    if not llmclient.available():
        raise RuntimeError(llmclient.hint())
    # The shared client resolves LLM_BASE_URL / LLM_API_KEY / LLM_MODEL (and the
    # OPENAI_* fallbacks), the same names every AI-agent tool uses.
    client = llmclient.ChatClient(model=args.model, base_url=args.base_url,
                                  api_key=args.api_key,
                                  timeout=args.timeout, retries=args.retries,
                                  temperature=args.temperature,
                                  json_mode=args.json_mode, verbose=args.verbose)
    if not client.api_key:
        log('[!] no API key in LLM_API_KEY / OPENAI_API_KEY; the endpoint will '
            'likely reject the request')
    return client


def is_final(payload):
    """Answer shapes this task accepts as the final turn."""
    if isinstance(payload, list):
        return True
    if not isinstance(payload, dict):
        return False
    action = str(payload.get('action') or '').lower()
    if action == 'final':
        return True
    if action == 'tool':
        return False
    return any(key in payload for key in ('seed', 'messages', 'sequence', 'types',
                                          'state_var'))


def answer_messages(payload, raw, args, warnings, binary=False):
    """Pull the message list out of a final answer, however it was spelled."""
    candidate = payload
    if isinstance(candidate, dict):
        seed = candidate.get('seed')
        candidate = seed if isinstance(seed, (dict, list)) else candidate
    messages = None
    if isinstance(candidate, list):
        messages = candidate
    elif isinstance(candidate, dict):
        for key in ('messages', 'sequence', 'requests', 'client_requests'):
            value = candidate.get(key)
            if isinstance(value, list):
                messages = value
                break
            if isinstance(value, str) and value.strip():
                messages = [value]
                break
    if messages is None:
        block = agent.fenced_block(raw)
        if block is not None:
            messages = block.splitlines()
        elif raw and '{' not in raw and '[' not in raw:
            # a plain answer that just lists the requests, one per line
            messages = raw.splitlines()
        else:
            warnings.append('answer carried no message sequence')
            return []

    out = []
    for item in messages:
        if not isinstance(item, str):
            continue
        if binary:
            # One answer element is exactly one complete frame.  In particular,
            # never split on CR/LF that belongs to the binary payload.
            part = decode_escapes(item, binary=True)
            if not part:
                continue
            try:
                part.encode('latin-1')
            except UnicodeEncodeError:
                warnings.append('binary message contains a non-byte Unicode '
                                'character (use \\xNN escapes)')
                continue
            if len(part) > args.max_message_bytes:
                warnings.append('binary message exceeded the %d-byte limit and was '
                                'dropped' % args.max_message_bytes)
                continue
            out.append(part)
            continue

        for part in decode_escapes(item).replace('\r\n', '\n').split('\n'):
            part = part.strip('\r').strip()
            if not part or set(part) <= set('-`'):
                continue
            if len(part) > args.max_message_bytes:
                part = part[:args.max_message_bytes]
            out.append(part)
    if len(out) > args.max_messages:
        warnings.append('answer had %d messages, kept the first %d'
                        % (len(out), args.max_messages))
        out = out[:args.max_messages]
    return out


def validate_binary_messages(messages, formats_data, log):
    """Reject sequences whose elements are not complete framed messages."""
    if not formats_data:
        return messages
    framing = formats.framing_of(formats_data)
    valid = []
    for index, message in enumerate(messages):
        data = message.encode('latin-1')
        if framing:
            frames, rest = formats.split_frames(data, framing)
            if frames != [data] or rest:
                log('[!] binary message %d is not one complete frame; dropped'
                    % (index + 1))
                continue
        if formats.classify(data, formats_data) is None:
            # Unknown probes are allowed only when the classifier has no table
            # entry for the intended type; still make the miss visible.
            log('[!] binary message %d matches no type probe' % (index + 1))
        valid.append(message)
    return valid


# ---------------------------------------------------------------------------
# job planning
# ---------------------------------------------------------------------------

def plan_jobs(ctx, args, round_no):
    """Deterministic job list for one round (the same inputs give the same jobs)."""
    corpus = ctx.corpus
    jobs = []
    if round_no == 1:
        services = ctx.service_catalog or [{
            'name': 'protocol services', 'description': '',
            'chains': [], 'symbols': [],
        }]
        base = args.base_seed if args.base_seed in corpus.files \
            else corpus.richest_seed(ctx.universe)
        if base:
            for index, service in enumerate(services):
                jobs.append({'id': 'services-r1-%d' % index, 'kind': 'services',
                             'round': round_no, 'base': base,
                             'service': service})

    if 'types' in args.task_list:
        if round_no == 1:
            for name in sorted(corpus.files):
                missing = [t for t in corpus.missing_in(name, ctx.universe)
                           if t not in args.ignore_types]
                if not missing:
                    continue
                if args.max_missing_types:
                    missing = missing[:args.max_missing_types]
                for index, group in enumerate(chunks(missing, args.types_per_job)):
                    if index >= args.max_jobs_per_seed:
                        break
                    jobs.append({'id': 'types-r1-%s-%d' % (sanitize(name), index),
                                 'kind': 'types', 'round': round_no, 'base': name,
                                 'chunk': index, 'missing_types': group})
        else:
            pool_missing = [t for t in sorted(ctx.universe - corpus.observed_types)
                            if t not in args.ignore_types]
            base = args.base_seed if args.base_seed in corpus.files \
                else corpus.richest_seed(ctx.universe)
            if pool_missing and base:
                for index, group in enumerate(chunks(pool_missing, args.types_per_job)):
                    if index >= args.max_jobs_per_seed:
                        break
                    jobs.append({'id': 'types-r%d-%d' % (round_no, index),
                                 'kind': 'types', 'round': round_no, 'base': base,
                                 'chunk': index, 'missing_types': group})

    if 'statevars' in args.task_list and round_no == 1 and ctx.statevars:
        base = args.base_seed if args.base_seed in corpus.files \
            else corpus.richest_seed(ctx.universe)
        for index, record in enumerate(ctx.statevars):
            if args.only_vars and record['name'] not in args.only_vars:
                continue
            for variant in range(max(1, args.sv_variants)):
                jobs.append({'id': 'sv-%d-%d' % (index, variant), 'kind': 'statevar',
                             'round': round_no, 'base': base, 'record': record,
                             'variant': variant, 'variants': max(1, args.sv_variants)})
    return jobs[:args.max_jobs]


# ---------------------------------------------------------------------------
# running one job
# ---------------------------------------------------------------------------

def seed_name_for(job, base_name):
    if job['kind'] == 'statevar':
        return '%s_%s_%d_%s' % (STATEVAR_PREFIX, sanitize(job['record']['name']),
                                job['variant'], base_name)
    if job['kind'] == 'services':
        return '%s_service_%s_r%d_%s' % (
            ENRICHED_PREFIX, sanitize(job['service']['name']),
            job['round'], base_name)
    return '%s_r%d-%d_%s' % (ENRICHED_PREFIX, job['round'], job.get('chunk', 0), base_name)


def execute_job(client, job, ctx, args, warnings):
    """Ask the model for one sequence and turn the answer into a seed."""
    if job['base'] not in ctx.corpus.files:
        job['base'] = ctx.corpus.richest_seed(ctx.universe)
    if job['base'] is None:
        warnings.append('job %s has no base seed' % job['id'])
        return None
    if job['kind'] == 'services':
        user = build_service_prompt(ctx, job)
    elif job['kind'] == 'types':
        user = build_type_prompt(ctx, job)
    else:
        user = build_statevar_prompt(ctx, job)
    payload, raw, _calls = ctx.agent.run(ctx.system_prompt, user, is_final=is_final,
                                         final_hint=FINAL_HINT)
    if payload is None:
        return None
    binary = bool(ctx.formats)
    messages = answer_messages(payload, raw, args, warnings, binary=binary)
    if binary:
        messages = validate_binary_messages(messages, ctx.formats, ctx.log)
    if not messages:
        return None
    produced = set(t for t in (classify(m, ctx.templates, ctx.terminator,
                                        ctx.formats)
                               for m in messages) if t)
    requested = set(job.get('missing_types', []))
    result = {
        'job': job['id'], 'kind': job['kind'], 'round': job['round'],
        'base': job['base'], 'messages': len(messages),
        'produced_types': sorted(produced),
        'types_added': sorted(requested & produced),
        'missing_after': sorted(requested - produced),
        'rationale': shorten(str(answer_field(payload, 'rationale') or ''), 300),
        'source': 'llm',
    }
    if job['kind'] == 'services':
        covered = answer_field(payload, 'services_covered')
        result['service'] = job['service']['name']
        result['services_covered'] = [str(v) for v in covered] \
            if isinstance(covered, list) else []
    elif job['kind'] == 'statevar':
        record = job['record']
        values = answer_field(payload, 'values_targeted')
        locations = answer_field(payload, 'locations')
        result['state_var'] = record['name']
        result['values_targeted'] = [str(v) for v in values] if isinstance(values, list) else []
        result['locations'] = [str(v) for v in locations] if isinstance(locations, list) else []
        result['locations_ok'] = check_locations(ctx, result['locations'])
        ctx.sv_history.setdefault(record['name'], []).append(
            '%s (%s)' % (result['values_targeted'] or 'unstated value',
                         result['rationale'] or 'no rationale'))
        ctx.sv_results.setdefault(record['name'], []).append(result)
    return {'messages': messages, 'result': result}


def answer_field(payload, key):
    """Read ``key`` from a final answer, looking inside ``seed`` as well."""
    if not isinstance(payload, dict):
        return None
    if payload.get(key) is not None:
        return payload[key]
    seed = payload.get('seed')
    if isinstance(seed, dict):
        return seed.get(key)
    return None


def check_locations(ctx, locations):
    """Do the files the model cited exist in the workspace?"""
    if not locations or ctx.workspace is None:
        return None
    found, missing = 0, 0
    for location in locations:
        path = str(location).rsplit(':', 1)[0]
        try:
            target = ctx.workspace.safe(path)
        except ValueError:
            missing += 1
            continue
        if os.path.isfile(target):
            found += 1
        else:
            missing += 1
    if not found and not missing:
        return None
    return missing == 0


def write_seed(out_dir, name, messages, terminator, binary=False):
    path = os.path.join(out_dir, name)
    write_bytes(path, join_messages(messages, terminator, binary=binary))
    return path


def copy_originals(corpus_dir, out_dir, log):
    copied = 0
    for name, path in seed_files(corpus_dir, skip_enriched=True):
        target = os.path.join(out_dir, name)
        if os.path.exists(target):
            continue
        shutil.copyfile(path, target)
        copied += 1
    return copied


def digest(payload):
    return hashlib.sha1(payload).hexdigest()


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def coverage_snapshot(corpus, universe):
    missing = sorted(set(universe) - corpus.observed_types)
    per_seed = dict((name, sorted(types)) for name, types in sorted(corpus.types.items()))
    return {'seeds': len(corpus.files), 'messages': corpus.message_count,
            'observed_types': sorted(corpus.observed_types),
            'missing_types': missing, 'per_seed': per_seed}


def print_snapshot(label, snapshot, log):
    log('[~] %s: %d seed(s), %d message(s), %d/%d message type(s)'
        % (label, snapshot['seeds'], snapshot['messages'],
           len(snapshot['observed_types']),
           len(snapshot['observed_types']) + len(snapshot['missing_types'])))
    if snapshot['missing_types']:
        log('[!] still missing: %s' % ', '.join(snapshot['missing_types']))


def write_report(path, payload, log):
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, 'w') as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write('\n')
    log('[~] report written to %s' % path)


def check_corpus(ctx, args, log):
    """--check: describe the coverage of a corpus, contact nobody."""
    snapshot = coverage_snapshot(ctx.corpus, ctx.universe)
    log('[~] corpus %s: %d seed(s), %d message(s)'
        % (ctx.corpus_dir, snapshot['seeds'], snapshot['messages']))
    for name in sorted(ctx.corpus.files):
        types = sorted(ctx.corpus.types[name])
        log('    %-42s %2d message(s)  %s'
            % (name, len(ctx.corpus.files[name]),
               ', '.join(types) if types else '(no known type)'))
    observed, missing = snapshot['observed_types'], snapshot['missing_types']
    log('[~] %d message type(s) observed%s'
        % (len(observed), ': ' + ', '.join(observed) if observed else ''))
    if missing:
        log('[!] %d known %s type(s) are in no seed: %s'
            % (len(missing), ctx.protocol, ', '.join(missing)))
    else:
        log('[+] every known %s message type appears in the corpus' % ctx.protocol)
    for record in ctx.statevars:
        log('[~] state variable %s (%s)'
            % (record['name'],
               ', '.join(display_location(l, ctx.workspace)
                         for l in record['locations']) or 'no location known'))
    if args.report:
        write_report(args.report, {
            'tool': 'aflnet-pp/utils/AI-agent/corpus-enrich', 'version': VERSION,
            'corpus': os.path.abspath(ctx.corpus_dir), 'protocol': ctx.protocol,
            'generated_at': datetime.datetime.now().isoformat(timespec='seconds'),
            'mode': 'check', 'terminator': escape_terminator(ctx.terminator),
            'binary': {'enabled': bool(ctx.formats),
                       'framing': ctx.framing},
            'tasks': sorted(args.task_list),
            'service_catalog': [service['name'] for service in ctx.service_catalog],
            'coverage': snapshot,
            'state_variables': [{'name': r['name'],
                                 'locations': [display_location(l, ctx.workspace)
                                               for l in r['locations']]}
                                for r in ctx.statevars],
            'warnings': [],
        }, log)
    return 0


# ---------------------------------------------------------------------------
# context and command line
# ---------------------------------------------------------------------------

class Context(object):
    def __init__(self, args, log):
        self.args = args
        self.log = log
        self.corpus_dir = os.path.abspath(args.corpus)
        self.out_dir = os.path.abspath(args.output)
        self.protocol = args.protocol.strip().lower()
        self.terminator = decode_escapes(args.terminator)
        self.templates = []
        self.formats = None
        self.framing = None
        self.universe = set()
        self.service_catalog = []
        self.known_chains = []
        self.overview = []
        self.statevars = []
        self.corpus = Corpus(self.terminator, self.templates)
        self.workspace = None
        self.agent = None
        self.system_prompt = ''
        self.sv_history = {}
        self.sv_results = {}
        self.stats = {'tool_calls': 0, 'jobs': 0, 'generated': 0, 'rounds': 0}


def build_parser():
    ap = argparse.ArgumentParser(
        prog='enrich_corpus.py',
        description='Enrich an AFLNet++ seed corpus.  Service coverage is always '
                    'performed; --grammar enables message-type enrichment and '
                    '--statevars enables state-variable enrichment.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  python3 utils/AI-agent/corpus-enrich/enrich_corpus.py \\\n'
               '      profuzzbench/subjects/FTP/LightFTP/in-ftp /tmp/in-ftp-enriched FTP \\\n'
               '      --grammar grammars/ftp --statevars lftp-statevars.json \\\n'
               '      --services services.json --root profuzzbench/subjects/FTP/LightFTP/repo\n'
               '  python3 utils/AI-agent/corpus-enrich/enrich_corpus.py \\\n'
               '      in-ftp out-ftp FTP --check\n'
               '\nEndpoint: LLM_BASE_URL, LLM_API_KEY, LLM_MODEL (the OPENAI_* / '
               'AZURE_OPENAI_* names work as fallbacks).\n')
    ap.add_argument('corpus', help='seed corpus to read (one file per message sequence)')
    ap.add_argument('output', help='directory for the enriched corpus')
    ap.add_argument('protocol', help='protocol name, for example FTP, MQTT or RTSP')

    g = ap.add_argument_group('inputs')
    g.add_argument('--types', help='client request types to cover: a comma separated '
                                   'list, or a file with one type per line; explicitly '
                                   'supplying this also enables type enrichment')
    g.add_argument('--grammar', help='protocol grammar template directory '
                                     '(utils/AI-agent/pro-template output) used to '
                                     'enable and classify message type enrichment')
    g.add_argument('--formats', help='binary formats file written by '
                                     'pro-template --mode binary '
                                     '(.binary-formats.json); with --grammar the '
                                     'file inside that directory is used by default')
    g.add_argument('--services', help='optional services.json / service.json; without '
                                      'it the model discovers services at runtime')
    g.add_argument('--statevars', help='state variable JSON: identify.py output, a '
                                       'ChatState state.json (name -> file:line) or a '
                                       'query.json')
    g.add_argument('--root', help='optional project/config/server directory exposed '
                                  'to the model as read-only workspace tools')
    g.add_argument('--terminator', default=DEFAULT_TERMINATOR,
                   help='message terminator, escapes allowed (default: \\r\\n)')

    g2 = ap.add_argument_group('what to generate')
    g2.add_argument('--rounds', type=int, default=DEFAULT_ROUNDS,
                    help='enrichment rounds (default: %d)' % DEFAULT_ROUNDS)
    g2.add_argument('--sv-variants', type=int, default=1,
                    help='sequences asked per state variable (default: 1)')
    g2.add_argument('--types-per-job', type=int, default=DEFAULT_TYPES_PER_JOB,
                    help='missing message types per request (default: %d)'
                         % DEFAULT_TYPES_PER_JOB)
    g2.add_argument('--max-missing-types', type=int, default=10,
                    help='ignore a seed needing more than N missing types (default: 10)')
    g2.add_argument('--max-jobs-per-seed', type=int, default=DEFAULT_MAX_JOBS_PER_SEED,
                    help='cap the requests derived from one seed (default: %d)'
                         % DEFAULT_MAX_JOBS_PER_SEED)
    g2.add_argument('--max-jobs', type=int, default=DEFAULT_MAX_JOBS,
                    help='cap the requests of the whole run (default: %d)' % DEFAULT_MAX_JOBS)
    g2.add_argument('--only-vars', help='comma separated state variables to work on')
    g2.add_argument('--ignore-types', help='comma separated types never to generate')
    g2.add_argument('--base-seed', help='seed used as the base of the state variable tasks')
    g2.add_argument('--max-messages', type=int, default=DEFAULT_MAX_MESSAGES,
                    help='never write a sequence longer than this (default: %d)'
                         % DEFAULT_MAX_MESSAGES)
    g2.add_argument('--max-message-bytes', type=int, default=DEFAULT_MAX_MESSAGE_BYTES,
                    help='per message cap in bytes (default: %d)' % DEFAULT_MAX_MESSAGE_BYTES)

    g3 = ap.add_argument_group('model')
    g3.add_argument('--base-url', help='OpenAI-compatible base URL')
    g3.add_argument('--api-key', help='bearer token (prefer the env vars)')
    g3.add_argument('--model', help='model name')
    g3.add_argument('--temperature', type=float, default=0.5)
    g3.add_argument('--timeout', type=float, default=120.0)
    g3.add_argument('--retries', type=int, default=2)
    g3.add_argument('--json-mode', action='store_true',
                    help='also send response_format={"type":"json_object"}')
    g3.add_argument('--max-steps', type=int, default=DEFAULT_MAX_STEPS,
                    help='tool-use turns per job (default: %d)' % DEFAULT_MAX_STEPS)
    g3.add_argument('--lang', choices=sorted(LANGUAGES), default='zh',
                    help='language of the rationale field (default: zh)')

    g4 = ap.add_argument_group('offline and inspection')
    g4.add_argument('--check', action='store_true',
                    help='report the coverage of a corpus and exit (no model)')
    g4.add_argument('--dump-prompt', metavar='DIR',
                    help='write one prompt per planned job to this directory and exit')
    g4.add_argument('--from-answer', action='append', metavar='FILE', default=None,
                    help='replay captured answers (one per job, in order; "-" reads '
                         'stdin) instead of calling the model')
    g4.add_argument('--offline', action='store_true',
                    help='never contact the endpoint (needs --from-answer)')
    g4.add_argument('--report', help='JSON report path (default: <output>/.enrich.json)')

    g5 = ap.add_argument_group('output control')
    g5.add_argument('--in-place', action='store_true',
                    help='write the new seeds into the corpus directory itself')
    g5.add_argument('--no-copy', dest='copy', action='store_false',
                    help='do not copy the original seeds into the output directory')
    g5.add_argument('--force', action='store_true',
                    help='write into a directory that already holds files')
    g5.add_argument('--strict', action='store_true',
                    help='fail when the endpoint errors or an answer is unusable')
    g5.add_argument('--quiet', action='store_true', help='no progress output on stderr')
    g5.add_argument('--verbose', action='store_true', help='show every tool call')
    g5.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    ap.set_defaults(copy=True)
    return ap


def parse_args(argv):
    ap = build_parser()
    args = ap.parse_args(argv)
    args.protocol = args.protocol.strip().lower()
    args.task_list = set(['services'])
    if args.grammar or args.types:
        args.task_list.add('types')
    if args.statevars:
        args.task_list.add('statevars')
    args.only_vars = set(v.strip() for v in (args.only_vars or '').split(',') if v.strip())
    args.ignore_types = set(v.strip().upper() for v in
                            (args.ignore_types or '').split(',') if v.strip())
    args.answers = list(args.from_answer or [])
    return args


def setup(args, log):
    ctx = Context(args, log)
    if not os.path.isdir(ctx.corpus_dir):
        raise ValueError('no such corpus directory: %s' % ctx.corpus_dir)

    if args.grammar:
        ctx.templates, problems = read_grammar(args.grammar)
        for problem in problems:
            log('[!] grammar: %s' % problem)
        ctx.universe |= set(t['type'] for t in ctx.templates)
        log('[~] grammar: %d template(s) from %s' % (len(ctx.templates), args.grammar))

    try:
        ctx.formats = formats.load_formats(args.formats or args.grammar)
    except formats.FormatError as exc:
        raise ValueError(str(exc))
    ctx.framing = formats.framing_of(ctx.formats) if ctx.formats else None
    ctx.corpus = Corpus(ctx.terminator, ctx.templates, ctx.formats)
    if ctx.formats:
        ctx.universe |= set(formats.types_of(ctx.formats))
        log('[~] binary formats: %d type(s)%s'
            % (len(formats.types_of(ctx.formats)),
               ', length-field framing' if ctx.framing else ', one message per seed'))

    ctx.universe |= explicit_types(args.types)
    if args.services:
        ctx.service_catalog, service_types, chains, overview = \
            load_service_catalog(args.services, log)
        ctx.universe |= service_types
        ctx.known_chains = chains
        ctx.overview = overview
    skip_enriched = not args.check
    seed_warnings = []
    count = ctx.corpus.load_dir(ctx.corpus_dir, skip_enriched=skip_enriched,
                               max_messages=args.max_messages,
                               warnings=seed_warnings)
    for warning in seed_warnings:
        log('[!] %s' % warning)
    log('[~] %d seed(s) read from %s (%s)' % (count, ctx.corpus_dir, ctx.corpus.summary()))
    if not ctx.corpus.files:
        raise ValueError('no seed file under %s' % ctx.corpus_dir)
    ctx.universe |= ctx.corpus.observed_types

    if args.statevars:
        ctx.statevars = load_statevars(args.statevars, log)

    if args.root:
        root = os.path.abspath(args.root)
        if not os.path.isdir(root):
            raise ValueError('--root is not a directory: %s' % root)
        ctx.workspace = localtools.Workspace(root)
        log('[~] model workspace tools enabled at %s' % root)
    else:
        log('[~] no --root supplied: workspace tools disabled')
    ctx.system_prompt = build_system_prompt(ctx.protocol, args,
                                            binary=bool(ctx.formats),
                                            tools=bool(ctx.workspace))
    return ctx


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def dump_prompts(ctx, jobs, args, log):
    directory = os.path.abspath(args.dump_prompt)
    if not os.path.isdir(directory):
        os.makedirs(directory)
    index = []
    for number, job in enumerate(jobs):
        if job['kind'] == 'services':
            user = build_service_prompt(ctx, job)
        elif job['kind'] == 'types':
            user = build_type_prompt(ctx, job)
        else:
            user = build_statevar_prompt(ctx, job)
        name = 'job-%02d-%s.txt' % (number, sanitize(job['id']))
        with open(os.path.join(directory, name), 'w') as handle:
            handle.write('===== SYSTEM (%s) =====\n%s\n\n===== USER =====\n%s\n'
                         % (ctx.protocol, ctx.system_prompt, user))
        index.append({'index': number, 'id': job['id'], 'kind': job['kind'],
                      'base': job['base'], 'prompt': name,
                      'missing_types': job.get('missing_types'),
                      'service': job.get('service', {}).get('name')
                      if job['kind'] == 'services' else None,
                      'state_var': job.get('record', {}).get('name') if job['kind'] == 'statevar' else None})
    with open(os.path.join(directory, 'jobs.json'), 'w') as handle:
        json.dump({'protocol': ctx.protocol, 'jobs': index}, handle, indent=2,
                  ensure_ascii=False)
        handle.write('\n')
    log('[~] wrote %d prompt(s) to %s (jobs.json lists them in order)'
        % (len(jobs), directory))
    return 0


class AnswerPool(object):
    """Captured answers for ``--from-answer``: a JSON map by job id, or in order."""

    def __init__(self, specs, job_ids, log, warnings):
        self.mapping = {}
        self.ordered = []
        self.cursor = 0
        for spec in specs or []:
            text = sys.stdin.read() if spec == '-' else read_text(spec)
            if text is None:
                warnings.append('cannot read answer file %s' % spec)
                continue
            payload = None
            try:
                payload = json.loads(text)
            except ValueError:
                payload = None
            if isinstance(payload, dict) and set(payload) & set(job_ids):
                # A map: keep every key, not just the ones this round planned --
                # a later round asks for the job ids that are still missing.
                for key, value in payload.items():
                    self.mapping[key] = value if isinstance(value, str) \
                        else json.dumps(value)
                continue
            self.ordered.append(text)
        if self.mapping or self.ordered:
            log('[~] %d captured answer(s): %d keyed by job id, %d in order'
                % (len(self.mapping) + len(self.ordered), len(self.mapping),
                   len(self.ordered)))

    def get(self, job_id):
        if job_id in self.mapping:
            return self.mapping[job_id]
        if self.cursor < len(self.ordered):
            answer = self.ordered[self.cursor]
            self.cursor += 1
            return answer
        return None


def execute_replay(job, answer, ctx, args, warnings):
    """Turn one captured answer into a result, without any endpoint."""
    payload = agent.parse_turn(answer)
    binary = bool(ctx.formats)
    messages = answer_messages(payload, answer, args, warnings, binary=binary)
    if binary:
        messages = validate_binary_messages(messages, ctx.formats, ctx.log)
    if not messages:
        return None
    produced = set(t for t in (classify(m, ctx.templates, ctx.terminator,
                                        ctx.formats)
                               for m in messages) if t)
    requested = set(job.get('missing_types', []))
    result = {'job': job['id'], 'kind': job['kind'], 'round': job['round'],
              'base': job['base'], 'messages': len(messages),
              'produced_types': sorted(produced),
              'types_added': sorted(requested & produced),
              'missing_after': sorted(requested - produced),
              'rationale': shorten(str(answer_field(payload, 'rationale') or ''), 300),
              'source': 'captured'}
    if job['kind'] == 'services':
        covered = answer_field(payload, 'services_covered')
        result['service'] = job['service']['name']
        result['services_covered'] = [str(v) for v in covered] \
            if isinstance(covered, list) else []
    elif job['kind'] == 'statevar':
        record = job['record']
        values = answer_field(payload, 'values_targeted')
        locations = answer_field(payload, 'locations')
        result['state_var'] = record['name']
        result['values_targeted'] = [str(v) for v in values] if isinstance(values, list) else []
        result['locations'] = [str(v) for v in locations] if isinstance(locations, list) else []
        result['locations_ok'] = check_locations(ctx, result['locations'])
        ctx.sv_results.setdefault(record['name'], []).append(result)
    return {'messages': messages, 'result': result}


def main(argv=None):
    args = parse_args(argv)

    def log(message):
        if not args.quiet:
            print(message, file=sys.stderr)

    warnings = []
    try:
        ctx = setup(args, log)
    except ValueError as exc:
        print('[!] %s' % exc, file=sys.stderr)
        return 1

    if args.check:
        return check_corpus(ctx, args, log)

    if args.offline and not args.answers and args.dump_prompt is None:
        print('[!] --offline needs --from-answer (or use --dump-prompt)',
              file=sys.stderr)
        return 1

    replay = bool(args.answers) or args.offline
    client = None
    if not replay and not args.dump_prompt:
        try:
            client = make_client(args, log)
        except RuntimeError as exc:
            print('[!] %s' % exc, file=sys.stderr)
            return 1
        ctx.agent = agent.Agent(client,
                                ctx.workspace,
                                max_steps=args.max_steps, verbose=args.verbose,
                                log=log, warnings=warnings)
        log('[~] asking %s with model %s' % (client.base_url, client.model))

    before = coverage_snapshot(ctx.corpus, ctx.universe)
    log('[~] protocol %s, %d message type(s) known'
        % (ctx.protocol, len(ctx.universe)))
    print_snapshot('corpus before', before, log)

    jobs = plan_jobs(ctx, args, 1)
    if args.dump_prompt:
        return dump_prompts(ctx, jobs, args, log)
    if not jobs:
        log('[+] nothing to do: the corpus already covers every known message type')
        return 0

    out_dir = ctx.corpus_dir if args.in_place else ctx.out_dir
    if not args.in_place and os.path.isdir(out_dir) and os.listdir(out_dir) \
            and not args.force:
        print('[!] %s is not empty; use --force or --in-place' % out_dir, file=sys.stderr)
        return 1
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    if not args.in_place and args.copy:
        copied = copy_originals(ctx.corpus_dir, out_dir, log)
        log('[~] copied %d original seed(s) to %s' % (copied, out_dir))

    pool = AnswerPool(args.answers, set(job['id'] for job in jobs), log, warnings)
    known = {}
    for name in sorted(os.listdir(out_dir)):
        path = os.path.join(out_dir, name)
        if os.path.isfile(path):
            data = read_bytes(path)
            if data is not None:
                known[digest(data)] = name

    report = {
        'tool': 'aflnet-pp/utils/AI-agent/corpus-enrich', 'version': VERSION,
        'protocol': ctx.protocol, 'corpus': ctx.corpus_dir, 'output': out_dir,
        'generated_at': datetime.datetime.now().isoformat(timespec='seconds'),
        'mode': ('llm' if client is not None else ('replay' if args.answers else 'prompt')),
        'model': (client.model if client is not None else None),
        'base_url': (client.base_url if client is not None else None),
        'terminator': escape_terminator(ctx.terminator),
        'binary': {'enabled': bool(ctx.formats), 'framing': ctx.framing},
        'tasks': sorted(args.task_list),
        'service_catalog': [service['name'] for service in ctx.service_catalog],
        'message_types': {'universe': sorted(ctx.universe)},
        'coverage_before': before, 'seeds': [], 'state_variables': [],
        'statistics': {}, 'warnings': warnings,
    }

    produced = 0
    endpoint_failed = False
    for round_no in range(1, max(1, args.rounds) + 1):
        if round_no > 1:
            jobs = plan_jobs(ctx, args, round_no)
            if not jobs:
                break
        log('[~] round %d: %d job(s)' % (round_no, len(jobs)))
        ctx.stats['rounds'] = round_no
        endpoint_failed = False
        for job in jobs:
            ctx.stats['jobs'] += 1
            if client is None:
                if not args.answers:
                    warnings.append('no --from-answer given: job %s skipped' % job['id'])
                    continue
                answer = pool.get(job['id'])
                if answer is None:
                    warnings.append('no captured answer for job %s' % job['id'])
                    if args.strict:
                        print('[!] no captured answer for job %s' % job['id'],
                              file=sys.stderr)
                        return 1
                    continue
                outcome = execute_replay(job, answer, ctx, args, warnings)
            else:
                try:
                    outcome = execute_job(client, job, ctx, args, warnings)
                except RuntimeError as exc:
                    warnings.append(str(exc))
                    print('[!] %s' % exc, file=sys.stderr)
                    if args.strict:
                        return 1
                    endpoint_failed = True
                    break
            if outcome is None:
                warnings.append('job %s produced no usable sequence' % job['id'])
                if args.strict:
                    print('[!] job %s produced no usable sequence' % job['id'],
                          file=sys.stderr)
                    return 1
                continue
            messages, result = outcome['messages'], outcome['result']
            binary = bool(ctx.formats)
            data = join_messages(messages, ctx.terminator, binary=binary)
            key = digest(data)
            if key in known:
                warnings.append('job %s produced a duplicate of %s (dropped)'
                                % (job['id'], known[key]))
                continue
            name = seed_name_for(job, os.path.basename(job['base']))
            if os.path.exists(os.path.join(out_dir, name)):
                name = '%s-r%d' % (name, round_no)
            write_seed(out_dir, name, messages, ctx.terminator, binary=binary)
            known[key] = name
            ctx.corpus.add(name, messages, origin='generated')
            result['seed'] = name
            produced += 1
            ctx.stats['generated'] = produced
            report['seeds'].append(result)
            log('[+] %s: %d message(s)%s%s'
                % (name, len(messages),
                   ' (+%s)' % ','.join(result['types_added']) if result['types_added'] else '',
                   ' -- still missing %s' % ','.join(result['missing_after'])
                   if result['missing_after'] else ''))
        snapshot = coverage_snapshot(ctx.corpus, ctx.universe)
        print_snapshot('coverage after round %d' % round_no, snapshot, log)
        if endpoint_failed or not snapshot['missing_types']:
            break

    report['coverage_after'] = coverage_snapshot(ctx.corpus, ctx.universe)
    for record in ctx.statevars:
        entries = ctx.sv_results.get(record['name'], [])
        report['state_variables'].append({
            'name': record['name'],
            'description': record['description'],
            'locations': [display_location(l, ctx.workspace) for l in record['locations']],
            'seeds': [e.get('seed') for e in entries if e.get('seed')],
            'values_targeted': [v for e in entries for v in e.get('values_targeted', [])],
            'locations_cited': [v for e in entries for v in e.get('locations', [])],
            'rationales': [e.get('rationale') for e in entries if e.get('rationale')],
        })
    if ctx.agent is not None:
        ctx.stats['tool_calls'] = ctx.agent.tool_calls
    report['statistics'] = dict(ctx.stats)
    report['statistics']['seeds_written'] = produced
    report['statistics']['by_task'] = {
        label: sum(1 for entry in report['seeds'] if entry['kind'] == kind)
        for kind, label in (('services', 'services'), ('types', 'types'),
                            ('statevar', 'statevars'))
    }
    write_report(args.report or os.path.join(out_dir, META_NAME), report, log)

    if not produced:
        if endpoint_failed:
            log('[!] the endpoint failed and no seed could be written')
            return 1
        log('[!] no enriched seed was written (%d warning(s))' % len(warnings))
        return 0
    log('[+] %d enriched seed(s) in %s (%d job(s), %d tool call(s))'
        % (produced, out_dir, ctx.stats['jobs'], ctx.stats['tool_calls']))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)


