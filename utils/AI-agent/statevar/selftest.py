#!/usr/bin/env python3
"""Offline regression test for the statevar tools.

    python3 utils/AI-agent/statevar/selftest.py

``identify.py`` is an LLM agent, so its two paths are checked without a
network: a stub client drives the tool loop (tool call -> tool result -> final
answer), and ``--dump-prompt``/``--from-answer`` drive the prompt and the answer
conversion.  The scanner ``annotate.py`` uses is checked against
``test/test-statevar.c`` (the annotated fixture of ``test/test-statevar.sh``),
and ``annotate.py`` is driven over a throw-away fixture, including the
``identify.py -> annotate.py`` pipeline.  Nothing is written outside a temporary
directory.

Exits non-zero on the first failed expectation.
"""

from __future__ import print_function

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)          # utils/AI-agent: localtools.py lives there
for path in (PARENT, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

import cscan  # noqa: E402
import identify  # noqa: E402
import annotate  # noqa: E402
import localtools  # noqa: E402
import llmclient  # noqa: E402

# Every object annotated with __AFL_STATE_VAR__ in test/test-statevar.c.
ANNOTATED = ['g_counter', 'a', 'g_ptr', 'g_blobptr', 'g_dblptr', 'g_byteptr',
             'g_fallbackptr', 'local']
# Annotated declarations that must never be reported.
NOT_ANNOTATED = ['g_plain', 'g_fallback']

FAILED = []


def check(ok, label, detail=''):
    print('%s %s%s' % ('[+]' if ok else '[!]', label, (' -- ' + detail) if detail else ''))
    sys.stdout.flush()
    if not ok:
        FAILED.append(label)
    return ok


def find_repo_root():
    d = HERE
    for _ in range(6):
        if os.path.exists(os.path.join(d, 'test', 'test-statevar.c')):
            return d
        d = os.path.dirname(d)
    return None


def run(argv):
    """Call identify.main() with its progress output captured."""
    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        rc = identify.main(argv)
    return rc, captured.getvalue()


def run_annotate(argv):
    """Call annotate.main() with its progress output captured."""
    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        rc = annotate.main(argv)
    return rc, captured.getvalue()


# The source annotate.py is driven over.  Every declaration shape the tool has
# to place an attribute on appears once: global, struct member, array member,
# parameter, automatic local and a bit-field (the one it must refuse).
FIXTURE = '''\
#include <string.h>

struct ctx {
  int access;
  unsigned flags : 3;
  char dir[64];
};

static struct ctx g_ctx;
static int g_rounds = 0;

static int pick(int choice) {
  int local = choice;
  return local;
}

int run(void) {
  g_ctx.access = pick(g_rounds);
  return g_ctx.access;
}
'''


def write_fixture(path):
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, 'w') as handle:
        handle.write(FIXTURE)
    return FIXTURE.splitlines().index('  int access;') + 1


# ---------------------------------------------------------------------------
# 1. the scanner annotate.py uses
# ---------------------------------------------------------------------------

def check_scanner(tmpdir, root):
    fixture = os.path.join(root, 'test', 'test-statevar.c')
    candidates = cscan.collect_candidates(fixture, max_candidates=50)[1]
    by_name = {}
    for cand in candidates:
        by_name.setdefault(cand['name'], []).append(cand)
    missing = [n for n in ANNOTATED if n not in by_name]
    check(not missing, 'scanner finds every annotated variable',
          'missing: %s' % missing if missing else '%d candidates' % len(candidates))
    low = [n for n in ANNOTATED
           if max(c['score'] for c in by_name.get(n, [{'score': 0}])) < 500]
    check(not low, 'annotated variables outrank everything else', str(low))
    annotated_flag = [n for n in ANNOTATED
                      if not any(c['annotated'] for c in by_name.get(n, []))]
    check(not annotated_flag, 'annotation attribute is recognised', str(annotated_flag))
    literal = os.path.join(tmpdir, 'literal.c')
    with open(literal, 'w') as fh:
        fh.write('static int g_lit '
                 '__attribute__((annotate("__AFL_STATE_VAR__")));\n')
    literal_cands = cscan.collect_candidates(literal, max_candidates=5)[1]
    check(any(c['name'] == 'g_lit' and c['annotated'] for c in literal_cands),
          'the literal annotate() spelling is recognised without a #define')
    false_positive = [n for n in NOT_ANNOTATED
                      if any(c['annotated'] for c in by_name.get(n, []))]
    check(not false_positive, 'unannotated variables are not flagged as annotated',
          str(false_positive))
    lines = [c['line'] for c in by_name['g_counter'][0:1]]
    check(lines == [36], 'definition line is the position of the name', str(lines))
    snippet = by_name['g_counter'][0]['snippet']
    check('#include' not in snippet and 'annotate' not in snippet.split('STATE_VAR')[0],
          'declaration snippet has no preprocessor/comment noise',
          snippet.strip()[:60])


# ---------------------------------------------------------------------------
# 2. prompts
# ---------------------------------------------------------------------------

def check_prompts(tmpdir, repo):
    prompt_file = os.path.join(tmpdir, 'prompt.txt')
    rc, err = run([repo, os.path.join(tmpdir, 'unused.json'),
                   '--dump-prompt', prompt_file, '--quiet'])
    text = open(prompt_file).read()
    check(rc == 0 and '===== SYSTEM =====' in text and '===== USER =====' in text,
          '--dump-prompt writes a system and a user prompt')
    criteria = [text.count('implement the network protocol server states'),
                text.count('persist across multiple client requests'),
                text.count('influences the server')]
    check(all(criteria), 'the prompt carries the three state variable criteria',
          str(criteria))
    check('read_file' in text and 'search_text' in text and 'list_dir' in text,
          'the prompt offers the three workspace tools')
    check('Workspace root: %s' % os.path.abspath(repo) in text,
          'the prompt names the workspace root')
    check('"name"' in text and '"description"' in text and '"location"' in text
          and '"type"' in text,
          'the prompt asks for name/description/location/type')
    rc, _err = run([repo, os.path.join(tmpdir, 'unused.json'), '--dump-prompt',
                    prompt_file, '--lang', 'en', '--quiet'])
    check(rc == 0 and 'in English' in open(prompt_file).read(),
          '--lang en changes the description language')


# ---------------------------------------------------------------------------
# 3. answer parsing and normalisation
# ---------------------------------------------------------------------------

def check_answers(tmpdir, root):
    access_line = FIXTURE.splitlines().index('  int access;') + 1
    location = 'target.c:%d' % access_line

    def normalize(answer):
        warnings = []
        records = identify.normalize_answer(answer, root, warnings)
        return records, warnings

    records, _ = normalize({'state_variables': [
        {'name': 'access', 'description': 'd', 'location': location, 'type': 'int'}]})
    check(len(records) == 1 and records[0]['location'] == location,
          '{"state_variables": [...]} is accepted')
    records, _ = normalize({'action': 'final', 'answer': {'state_variables': [
        {'name': 'access', 'description': 'd', 'location': location, 'type': 'int'}]}})
    check(len(records) == 1, 'the query.py {"action":"final","answer":...} shape is accepted')
    records, _ = normalize({'access': location})
    check(len(records) == 1 and records[0]['name'] == 'access',
          'query.py\'s {name: "file:line"} mapping is accepted')
    records, _ = normalize([{'name': 'access', 'location': location}])
    check(len(records) == 1 and records[0]['description'] == ''
          and records[0]['type'] == '',
          'a bare list is accepted and missing fields become empty')
    absolute = os.path.join(root, location.rsplit(':', 1)[0]) + ':' + location.rsplit(':', 1)[1]
    records, _ = normalize([{'name': 'access', 'location': absolute}])
    check(len(records) == 1 and records[0]['location'] == location,
          'an absolute location inside the root becomes relative',
          records[0]['location'] if records else '')
    records, warnings = normalize([
        {'name': 'access', 'location': location},
        {'name': 'access', 'location': location},
        {'name': 'ghost', 'location': 'target.c:3'},
        {'name': 'nolines', 'location': 'target.c'},
        {'name': 'toolong', 'location': 'target.c:9999'},
        {'name': 'access', 'location': 'nope.c:3'}])
    check(len(records) == 1, 'duplicates are collapsed and bad locations dropped',
          str([r['name'] for r in records]))
    check(all(any(k in w for w in warnings) for k in
              ('does not appear', 'no line number', 'past the end', 'does not exist')),
          'every dropped entry is explained', ' | '.join(warnings)[:100])
    records, _ = normalize({'action': 'final', 'answer': {
        'state_variables': [{'name': 'access', 'description': '中文描述',
                             'location': location, 'type': 'int'}]}})
    check(records[0]['description'] == '中文描述',
          'a non-ASCII description survives unchanged')


class StubClient(object):
    """A fake endpoint: one tool call, then the final answer."""

    model = 'stub-model'
    base_url = 'http://stub.invalid/v1'
    api_key = 'stub'

    def __init__(self, location, final=None):
        self.location = location
        self.final = final
        self.calls = []

    def chat(self, system, user):
        self.calls.append(user)
        if 'tool result for read_file' in user:
            if self.final is not None:
                return json.dumps(self.final)
            return json.dumps({'action': 'final', 'answer': {'state_variables': [
                {'name': 'access', 'description': 'session access level',
                 'location': self.location, 'type': 'int'}]}})
        return json.dumps({'action': 'tool', 'tool': 'read_file',
                           'args': {'path': 'target.c', 'start_line': 1,
                                    'end_line': 12}})


def check_environment():
    """The unified LLM_* names win, the OPENAI_* names still work."""
    names = ('LLM_API_KEY', 'OPENAI_API_KEY', 'AZURE_OPENAI_API_KEY',
             'LLM_BASE_URL', 'OPENAI_BASE_URL', 'AZURE_OPENAI_BASE_URL',
             'LLM_MODEL', 'OPENAI_MODEL')
    saved = dict((name, os.environ.get(name)) for name in names)
    try:
        os.environ.update({'LLM_API_KEY': 'llm-key', 'OPENAI_API_KEY': 'oa-key',
                           'LLM_BASE_URL': 'http://llm/v1',
                           'OPENAI_BASE_URL': 'http://oa/v1',
                           'LLM_MODEL': 'llm-model', 'OPENAI_MODEL': 'oa-model'})
        client = llmclient.ChatClient()
        check((client.api_key, client.base_url, client.model)
              == ('llm-key', 'http://llm/v1', 'llm-model'),
              'LLM_API_KEY / LLM_BASE_URL / LLM_MODEL are the primary names')
        for name in ('LLM_API_KEY', 'LLM_BASE_URL', 'LLM_MODEL'):
            os.environ.pop(name, None)
        client = llmclient.ChatClient()
        check((client.api_key, client.base_url, client.model)
              == ('oa-key', 'http://oa/v1', 'oa-model'),
              'the OPENAI_* names still work as fallbacks')
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def check_agent_loop(tmpdir, repo):
    location = 'target.c:%d' % (FIXTURE.splitlines().index('  int access;') + 1)
    stub = StubClient(location)
    original = identify.ChatClient
    identify.ChatClient = lambda **kwargs: stub
    try:
        out = os.path.join(tmpdir, 'agent.json')
        rc, err = run([repo, out, '--quiet'])
    finally:
        identify.ChatClient = original
    records = json.load(open(out))
    check(rc == 0 and [r['name'] for r in records] == ['access'],
          'the agent path writes the answer as the list', 'rc=%d' % rc)
    check(any('tool result for read_file' in call for call in stub.calls),
          'the tool result is fed back to the model')
    check(any('int access;' in call for call in stub.calls),
          'the model actually saw the file it asked for')
    check(records[0]['location'] == location and records[0]['type'] == 'int',
          'the answer keeps the location and the type')

    # a model that follows query.py's documented shape: a bare name -> file:line map
    stub = StubClient(location, final={'access': location})
    identify.ChatClient = lambda **kwargs: stub
    try:
        out = os.path.join(tmpdir, 'agent-map.json')
        rc, _err = run([repo, out, '--quiet'])
    finally:
        identify.ChatClient = original
    records = json.load(open(out))
    check(rc == 0 and len(records) == 1 and records[0]['name'] == 'access',
          'a bare {name: "file:line"} answer ends the loop', 'rc=%d' % rc)


# ---------------------------------------------------------------------------
# 4. offline runs and the command line
# ---------------------------------------------------------------------------

def check_offline(tmpdir, root):
    answer = os.path.join(tmpdir, 'answer.json')
    with open(answer, 'w') as fh:
        json.dump({'action': 'final', 'answer': {'state_variables': [
            {'name': 'access', 'description': 'access level',
             'location': 'target.c:%d' % (FIXTURE.splitlines().index('  int access;') + 1),
             'type': 'int'}]}}, fh)
    out = os.path.join(tmpdir, 'from-answer.json')
    rc, _err = run([root, out, '--from-answer', answer, '--quiet'])
    records = json.load(open(out))
    check(rc == 0 and len(records) == 1 and records[0]['name'] == 'access',
          '--from-answer converts a captured answer without a network')

    out_empty = os.path.join(tmpdir, 'empty.json')
    rc, _err = run([root, out_empty, '--from-answer', answer, '--strict',
                    '--quiet', '--protocol', 'ftp'])
    check(rc == 0, '--strict passes when something was found', 'rc=%d' % rc)
    empty = os.path.join(tmpdir, 'nothing.json')
    with open(empty, 'w') as fh:
        fh.write('{"action":"final","answer":{"state_variables":[]}}')
    rc, _err = run([root, out_empty, '--from-answer', empty, '--strict', '--quiet'])
    check(rc == 1 and json.load(open(out_empty)) == [],
          '--strict fails on an empty result', 'rc=%d' % rc)

    rc, _err = run([os.path.join(tmpdir, 'nope'), os.path.join(tmpdir, 'x.json'),
                    '--quiet'])
    check(rc == 1, 'a missing repository exits 1', 'rc=%d' % rc)
    rc, _err = run([root, os.path.join(tmpdir, 'x.json'), '--from-answer',
                    os.path.join(tmpdir, 'missing-answer.txt'), '--quiet'])
    check(rc == 1, 'an unreadable answer file exits 1', 'rc=%d' % rc)


# ---------------------------------------------------------------------------
# 5. annotate.py
# ---------------------------------------------------------------------------

def check_annotate(tmpdir):
    directory = os.path.join(tmpdir, 'annot')
    source = os.path.join(directory, 'target.c')
    write_fixture(source)
    original = open(source).read()
    lines = FIXTURE.splitlines()

    def line_of(text):
        return lines.index(text) + 1

    def entry(name, line):
        return {'name': name, 'location': 'target.c:%d' % line}

    entries = [
        entry('access', line_of('  int access;')),
        entry('dir', line_of('  char dir[64];')),
        entry('g_ctx', line_of('static struct ctx g_ctx;')),
        entry('g_rounds', line_of('static int g_rounds = 0;')),
        entry('local', line_of('  int local = choice;')),
        entry('choice', line_of('static int pick(int choice) {')),
        entry('access', line_of('  int access;')),        # duplicate
        entry('flags', line_of('  unsigned flags : 3;')),  # bit-field
        entry('access', line_of('  return local;')),       # wrong line
        {'name': 'gone', 'location': 'missing.c:1'},
    ]
    statevars = os.path.join(directory, 'statevars.json')
    with open(statevars, 'w') as fh:
        json.dump(entries, fh)

    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        rc, _err = run_annotate([statevars, '--repo', directory, '--dry-run',
                                 '--quiet'])
    check(rc == 0 and open(source).read() == original
          and '  int access __attribute__((annotate(' in captured.getvalue(),
          'annotate.py --dry-run shows the change and writes nothing')
    rc, _err = run_annotate([statevars, '--repo', directory, '--check', '--quiet'])
    check(rc == 1 and open(source).read() == original,
          'annotate.py --check reports pending changes and writes nothing',
          'rc=%d' % rc)

    rc, err = run_annotate([statevars, '--repo', directory, '--backup'])
    text = open(source).read()
    marker = '__attribute__((annotate("__AFL_STATE_VAR__")))'
    wanted = [
        '  int access %s;' % marker,
        '  char dir[64] %s;' % marker,
        'static struct ctx g_ctx %s;' % marker,
        'static int g_rounds %s = 0;' % marker,
        'static int pick(int choice %s) {' % marker,
        '  int local %s = choice;' % marker,
    ]
    missing = [w for w in wanted if w not in text]
    check(rc == 0 and not missing,
          'the attribute lands on the variable at the given location',
          'missing: %s' % missing)
    check('  unsigned flags : 3;' in text, 'a bit-field is left alone')
    check(os.path.exists(source + '.bak'), '--backup keeps the original copy')
    check('not-found' in err and 'unsupported' in err and 'file-missing' in err,
          'bad locations are reported', ' '.join(err.split())[:120])
    rc, _err = run_annotate([statevars, '--repo', directory, '--check', '--quiet'])
    check(rc == 0 and open(source).read() == text,
          'a second run is a no-op and --check passes')

    clang = shutil.which('clang')
    if clang:
        obj = os.path.join(directory, 'target.o')
        proc = subprocess.run([clang, '-c', source, '-o', obj],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        check(proc.returncode == 0, 'the annotated source compiles',
              proc.stderr.decode('utf-8', 'replace')[:200])
        proc = subprocess.run([clang, '-S', '-emit-llvm', source, '-o', '-'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ir = proc.stdout.decode('utf-8', 'replace')
        check('llvm.global.annotations' in ir and 'llvm.ptr.annotation' in ir,
              'clang emits the annotation records the pass consumes')

    # an already annotated declaration is recognised through its macro
    macro_source = os.path.join(directory, 'macro.c')
    with open(macro_source, 'w') as fh:
        fh.write('#define STATE_VAR __attribute__((annotate("__AFL_STATE_VAR__")))\n'
                 'static int counter STATE_VAR;\n')
    macro_statevars = os.path.join(directory, 'macro.json')
    with open(macro_statevars, 'w') as fh:
        json.dump([{'name': 'counter', 'location': 'macro.c:2'}], fh)
    rc, _err = run_annotate([macro_statevars, '--repo', directory, '--quiet'])
    macro_text = open(macro_source).read()
    check(rc == 0 and macro_text.count('annotate(') == 1,
          'a declaration annotated through a macro is left alone')

    multi_source = os.path.join(directory, 'multi.c')
    with open(multi_source, 'w') as fh:
        fh.write('static int a, b;\nint use(void){return a+b;}\n')
    multi_json = os.path.join(directory, 'multi.json')
    with open(multi_json, 'w') as fh:
        json.dump([{'name': 'a', 'location': 'multi.c:1'},
                   {'name': 'b', 'location': 'multi.c:1'}], fh)
    rc, _err = run_annotate([multi_json, '--repo', directory, '--quiet'])
    check(rc == 0
          and open(multi_source).read().count('annotate("__AFL_STATE_VAR__")') == 2,
          'two variables on one line each get their own annotation')

    rc, _err = run_annotate([os.path.join(directory, 'nope.json'), '--quiet'])
    check(rc == 1, 'a missing JSON file exits 1', 'rc=%d' % rc)


# ---------------------------------------------------------------------------
# 6. identify.py -> annotate.py
# ---------------------------------------------------------------------------

def check_pipeline(tmpdir):
    directory = os.path.join(tmpdir, 'pipeline')
    source = os.path.join(directory, 'target.c')
    access_line = write_fixture(source)
    answer = os.path.join(directory, 'answer.json')
    with open(answer, 'w') as fh:
        json.dump({'action': 'final', 'answer': {'state_variables': [
            {'name': 'access', 'description': 'access level',
             'location': 'target.c:%d' % access_line, 'type': 'int'},
            {'name': 'g_rounds', 'description': 'login retries',
             'location': 'target.c:%d'
             % (FIXTURE.splitlines().index('static int g_rounds = 0;') + 1),
             'type': 'static int'}]}}, fh)
    out = os.path.join(directory, 'statevars.json')
    rc, _err = run([directory, out, '--from-answer', answer, '--quiet'])
    payload = json.load(open(out))
    check(rc == 0 and isinstance(payload, list) and len(payload) == 2,
          'the pipeline input is the exported list', 'rc=%d' % rc)
    check(all(set(v) == set(('name', 'description', 'location', 'type'))
              for v in payload),
          'every entry is name/description/location/type')
    rc = annotate.main([out, '--repo', directory, '--quiet'])
    text = open(source).read()
    check(rc == 0 and 'int access __attribute__((annotate(' in text
          and 'static int g_rounds __attribute__((annotate(' in text,
          'annotate.py consumes the exported list with --repo', 'rc=%d' % rc)


def main():
    root = find_repo_root()
    if root is None:
        print('[!] cannot locate test/test-statevar.c above %s' % HERE)
        return 1
    tmpdir = tempfile.mkdtemp(prefix='statevar-selftest-')
    try:
        print('[*] scanner (used by annotate.py)')
        check_scanner(tmpdir, root)

        repo = os.path.join(tmpdir, 'repo')
        source = os.path.join(repo, 'target.c')
        write_fixture(source)
        print('[*] prompts')
        check_prompts(tmpdir, repo)
        print('[*] answers')
        check_answers(tmpdir, repo)
        print('[*] environment')
        check_environment()
        print('[*] agent loop')
        check_agent_loop(tmpdir, repo)
        print('[*] offline runs and the command line')
        check_offline(tmpdir, repo)
        print('[*] annotate.py')
        check_annotate(tmpdir)
        print('[*] identify.py -> annotate.py')
        check_pipeline(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if FAILED:
        print('\n[!] %d expectation(s) failed:' % len(FAILED))
        for label in FAILED:
            print('[!]   %s' % label)
        return 1
    print('\n[+] statevar tools look correct')
    return 0


if __name__ == '__main__':
    sys.exit(main())
