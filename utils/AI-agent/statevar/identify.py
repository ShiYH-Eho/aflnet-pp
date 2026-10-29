#!/usr/bin/env python3
"""Identify a project's protocol state variables with an LLM agent.

    python3 utils/AI-agent/statevar/identify.py <repository-dir> <output.json>

One small agent, the same shape as ChatState's ``ai-agent/query.py``: the model
is told the three characteristics a protocol state variable must satisfy, gets
three read-only tools over the repository --

  * ``list_dir``    -- directory inspection
  * ``read_file``   -- a file with line numbers
  * ``search_text`` -- literal or regex search across the tree

-- and answers with the variables it found and where they are defined.  There is
no heuristic pre-ranking and no candidate list: whenever the answer depends on
the code, the model reads the code.  The loop itself is ``../agent.py`` and the
workspace tools are ``../localtools.py`` -- both shared with ``pro-template`` and
``corpus-enrich`` -- so every read stays inside the repository and bounded.

The exported JSON is a list, one object per state variable, four fields each::

    [{"name": "Access", "description": "...",
      "location": "Source/ftpserv.h:92", "type": "int"}, ...]

``location`` is ``file:line`` relative to the scanned repository, so a consumer
that opens the files needs to be pointed at that tree (``annotate.py --repo``).

Without an endpoint, ``--dump-prompt`` writes the exact prompt (paste it into a
chat UI) and ``--from-answer`` converts the captured answer, so the tool works
offline.  Exit codes: 0 success, 1 error (bad repository, endpoint failure, or an
empty result with ``--strict``), 2 argument error.
"""

from __future__ import print_function

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)          # utils/AI-agent: localtools.py lives there
for path in (PARENT, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

import agent  # noqa: E402
import localtools  # noqa: E402
from llmclient import ChatClient  # noqa: E402

VERSION = '2.0'
DEFAULT_MAX_STEPS = agent.DEFAULT_MAX_STEPS

LANGUAGES = {
    'zh': 'Write the "description" values in Simplified Chinese (简体中文), one '
          'sentence each.',
    'en': 'Write the "description" values in English, one sentence each.',
}

#: Directories whose name says nothing about the protocol under test.
GENERIC_DIRS = ('repo', 'src', 'source', 'code', 'project', 'build', 'release',
                'debug')

STATE_PROMPT = """\
State variables in the source code of this %(protocol)s protocol project must \
satisfy all three of:
1. They implement the network protocol server states or server modes defined in \
the RFC.
2. They persist across multiple client requests during runtime.
3. Client requests can change them, and their value influences the server \
behaviour triggered by later client requests.

Analyze this %(protocol)s project: find which state variables are implemented \
and where they are defined in the source code. Read the code you need with the \
tools instead of guessing from names.

Workspace root: %(root)s

Return the state variables in the final answer as:
{"action":"final","answer":{"state_variables":[
  {"name":"<variable or struct member>",
   "description":"<one sentence: which protocol state it carries>",
   "location":"<file relative to the workspace root>:<line>",
   "type":"<declared C type, e.g. int or static struct session *>"}
]}}
Only report variables that satisfy all three characteristics, and report the \
definition site, not every use.

%(lang)s"""


# ---------------------------------------------------------------------------
# prompts
# ---------------------------------------------------------------------------

def guess_protocol(root):
    """A human readable protocol/project name for the prompt."""
    base = os.path.basename(os.path.normpath(root))
    if base.lower() in GENERIC_DIRS:
        parent = os.path.basename(os.path.dirname(os.path.normpath(root)))
        if parent:
            base = parent
    return base or 'network'


ANSWER_HINT = '{"action":"final","answer":{"state_variables":[...]}}'


def build_system_prompt():
    """The shared agent prompt, with the workspace tools of this task."""
    return agent.build_system_prompt(localtools.tools_help(ANSWER_HINT))


def build_state_prompt(protocol, root, lang):
    return STATE_PROMPT % {'protocol': protocol, 'root': root,
                           'lang': LANGUAGES.get(lang, LANGUAGES['en'])}


# ---------------------------------------------------------------------------
# answer acceptance
# ---------------------------------------------------------------------------

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
    if any(key in payload for key in ('state_variables', 'variables',
                                      'state_vars', 'answer', 'result')):
        return True
    # query.py's documented answer is a bare {name: "file:line"} mapping
    return bool(payload) and all(isinstance(v, (str, dict))
                                 for v in payload.values())


# ---------------------------------------------------------------------------
# the exported list
# ---------------------------------------------------------------------------

def resolve_location(name, item, root):
    """``file:line`` (relative to ``root``) for one answer entry, or a problem."""
    text = str(item.get('location') or '').strip()
    if not text and item.get('file'):
        text = '%s:%s' % (item.get('file'), item.get('line') or '')
    if not text:
        return '', 'no location given'
    detailed = re.match(r'^(.*):(\d+):(\d+)$', text)   # file:line:column
    if detailed:
        path, line = detailed.group(1), detailed.group(2)
    else:
        path, sep, line = text.rpartition(':')
        if not (sep and line.strip().isdigit()):
            return '', 'location %r has no line number' % agent.one_line(text, 60)
        line = line.strip()
    path = path.strip()
    if not path:
        return '', 'location %r has no file name' % agent.one_line(text, 60)
    if os.path.isabs(path):
        try:
            rel = os.path.relpath(path, root)
        except ValueError:
            rel = path
        if not rel.startswith(os.pardir):
            path = rel
    else:
        path = os.path.normpath(path)
    full = path if os.path.isabs(path) else os.path.join(root, path)
    if not os.path.isfile(full):
        return '', 'location %r does not exist under the repository' \
            % agent.one_line(text, 60)
    try:
        with open(full, 'r', errors='replace') as handle:
            lines = handle.read().splitlines()
    except OSError:
        lines = []
    if lines and int(line) > len(lines):
        return '', 'location %r is past the end of %s (%d line(s))' \
            % (agent.one_line(text, 60), path, len(lines))
    if lines:
        # the answer names a state variable, so its last name component has to
        # occur in the file it points at (``context->Mode`` -> ``Mode``)
        leaf = re.split(r'->|::|\.', name)[-1].strip() or name
        pattern = re.compile(r'(?<![\w$])' + re.escape(leaf) + r'(?![\w$])')
        if not any(pattern.search(source_line) for source_line in lines):
            return '', 'the name does not appear in %s' % path
    return '%s:%s' % (path, line), ''


def normalize_answer(payload, root, warnings):
    """The four-field list from whatever shape the model answered with.

    Accepted: ``{"state_variables": [...]}`` (and a few synonyms), a bare list,
    a single object, and query.py's ``{name: "file:line"}`` mapping.  Entries
    whose file does not exist or whose location has no line number are dropped
    with a warning; duplicates of ``(name, location)`` are collapsed.
    """
    value = payload
    for _depth in range(3):
        if not isinstance(value, dict):
            break
        nested = None
        for key in ('state_variables', 'variables', 'state_vars', 'answer',
                    'result'):
            if isinstance(value.get(key), (dict, list)):
                nested = value[key]
                break
        if nested is None:
            break
        value = nested
    if isinstance(value, list):
        items = value
    elif isinstance(value, dict) and 'name' in value:
        items = [value]
    elif isinstance(value, dict):
        items = []
        for name in value:
            item = value[name]
            if isinstance(item, str):
                items.append({'name': name, 'location': item})
            elif isinstance(item, dict):
                item = dict(item)
                item.setdefault('name', name)
                items.append(item)
    else:
        items = []

    records, seen = [], set()
    for item in items:
        if not isinstance(item, dict):
            continue
        name = agent.one_line(str(item.get('name') or ''), 120)
        if not name:
            continue
        location, problem = resolve_location(name, item, root)
        if problem:
            warnings.append('%s: %s' % (name, problem))
            continue
        key = (name, location)
        if key in seen:
            continue
        seen.add(key)
        records.append({
            'name': name,
            'description': agent.one_line(str(item.get('description') or ''), 300),
            'location': location,
            'type': agent.one_line(str(item.get('type') or ''), 80),
        })
    return records


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------

def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog='identify.py',
        description='Identify protocol state variables with a source-reading LLM '
                    'agent (the same shape as ChatState ai-agent/query.py).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Environment: LLM_BASE_URL, LLM_API_KEY, LLM_MODEL (the OPENAI_* / '
               'AZURE_OPENAI_* names work as fallbacks).\n'
               'Examples:\n'
               '  python3 utils/AI-agent/statevar/identify.py '
               'profuzzbench/subjects/FTP/LightFTP/repo lftp-statevars.json\n'
               '  python3 utils/AI-agent/statevar/identify.py ~/src/foo foo.json '
               '--protocol ftp --dump-prompt prompt.txt\n'
               '  python3 utils/AI-agent/statevar/identify.py ~/src/foo foo.json '
               '--from-answer answer.txt\n')
    ap.add_argument('repo', help='repository to analyse (the workspace root)')
    ap.add_argument('output', help='JSON list of state variables to write')
    ap.add_argument('--protocol', help='protocol/project name used in the prompt '
                                       '(default: derived from the repository path)')

    g = ap.add_argument_group('endpoint')
    g.add_argument('--base-url', help='OpenAI-compatible base URL')
    g.add_argument('--api-key', help='bearer token (prefer the environment)')
    g.add_argument('--model', help='model name (default: gpt-4o-mini)')
    g.add_argument('--temperature', type=float, default=0.0)
    g.add_argument('--timeout', type=float, default=120.0)
    g.add_argument('--retries', type=int, default=2)
    g.add_argument('--json-mode', action='store_true',
                   help='also send response_format={"type":"json_object"}')

    g2 = ap.add_argument_group('agent')
    g2.add_argument('--max-steps', type=int, default=DEFAULT_MAX_STEPS,
                    help='tool-use turns before giving up (default: %d)'
                         % DEFAULT_MAX_STEPS)
    g2.add_argument('--lang', choices=sorted(LANGUAGES), default='en',
                    help='language of the description field (default: en)')

    g3 = ap.add_argument_group('offline')
    g3.add_argument('--dump-prompt', metavar='FILE',
                    help='write the exact system+user prompt to this file and exit')
    g3.add_argument('--from-answer', metavar='FILE',
                    help='convert a captured answer instead of calling the model '
                         '("-" reads stdin)')
    g3.add_argument('--strict', action='store_true',
                    help='exit 1 when no state variable could be identified')
    g3.add_argument('--quiet', action='store_true', help='no progress on stderr')
    g3.add_argument('--verbose', action='store_true', help='show every tool call')
    g3.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    return ap.parse_args(argv)


def read_answer(path):
    if path == '-':
        return sys.stdin.read()
    try:
        with open(path, 'r', errors='replace') as handle:
            return handle.read()
    except OSError:
        return None


def write_json(path, payload):
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, 'w') as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write('\n')


def main(argv=None):
    args = parse_args(argv)

    def log(message):
        if not args.quiet:
            print(message, file=sys.stderr)

    root = os.path.abspath(args.repo)
    if not os.path.isdir(root):
        print('[!] no such repository: %s' % args.repo, file=sys.stderr)
        return 1
    if args.max_steps < 1:
        print('[!] --max-steps must be >= 1', file=sys.stderr)
        return 1

    protocol = args.protocol or guess_protocol(root)
    workspace = localtools.Workspace(root)
    system = build_system_prompt()
    user = build_state_prompt(protocol, root, args.lang)

    if args.dump_prompt:
        with open(args.dump_prompt, 'w') as handle:
            handle.write('===== SYSTEM =====\n%s\n\n===== USER =====\n%s\n'
                         % (system, user))
        log('[~] wrote the prompt to %s' % args.dump_prompt)
        return 0

    warnings = []
    tool_calls = 0
    if args.from_answer:
        text = read_answer(args.from_answer)
        if text is None:
            print('[!] cannot read %s' % args.from_answer, file=sys.stderr)
            return 1
        payload = agent.parse_turn(text)
        if payload is None:
            warnings.append('the answer file holds no JSON object')
    else:
        client = ChatClient(model=args.model, base_url=args.base_url,
                            api_key=args.api_key, timeout=args.timeout,
                            retries=args.retries, temperature=args.temperature,
                            json_mode=args.json_mode, verbose=args.verbose)
        if not client.api_key:
            log('[!] no API key in LLM_API_KEY / OPENAI_API_KEY; the endpoint will '
                'likely reject the request')
        log('[~] asking %s with model %s (workspace %s)'
            % (client.base_url, client.model, root))
        runner = agent.Agent(client, workspace, max_steps=args.max_steps,
                             verbose=args.verbose, log=log, warnings=warnings)
        try:
            payload, _raw, tool_calls = runner.run(system, user,
                                                   is_final=is_final,
                                                   final_hint=ANSWER_HINT)
        except agent.AgentError as exc:
            print('[!] %s' % exc, file=sys.stderr)
            return 1

    records = normalize_answer(payload, root, warnings) if payload is not None else []
    write_json(args.output, records)
    for warning in warnings:
        log('[!] %s' % warning)
    log('[+] %d state variable(s) written to %s (%d tool call(s))'
        % (len(records), args.output, tool_calls))
    for record in records[:10]:
        log('    %-28s %s  %s' % (record['name'], record['location'],
                                  agent.one_line(record['description'], 70)))
    if len(records) > 10:
        log('    ... %d more' % (len(records) - 10))
    if not records and args.strict:
        log('[!] no state variable identified')
        return 1
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
