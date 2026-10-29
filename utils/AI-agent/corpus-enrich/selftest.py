#!/usr/bin/env python3
"""Offline regression test for the corpus enrichment tool.

    python3 utils/AI-agent/corpus-enrich/selftest.py

Builds a throw-away protocol tree (corpus, source, state variable JSON, services
JSON, grammar templates), drives ``enrich_corpus.py`` over it and checks the
offline pipeline end to end: prompt dumping, answer replay, the two coverage
goals, the report, the local workspace tools, the tolerant answer parser and the
CLI contract.  No network, no third-party package, only a temporary directory.
Exits non-zero on the first failed expectation.
"""

from __future__ import print_function

import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
SHARED = os.path.dirname(HERE)
if SHARED not in sys.path:
    sys.path.insert(0, SHARED)

import agent  # noqa: E402
import enrich_corpus as ec  # noqa: E402
import formats  # noqa: E402
import localtools  # noqa: E402

FAILED = []

SEED_A = b'USER ubuntu\r\nPASS ubuntu\r\nLIST\r\nQUIT\r\n'
SEED_B = b'USER anonymous\r\nPASS x\r\nPWD\r\nQUIT\r\n'
TYPES = ['USER', 'PASS', 'LIST', 'PWD', 'QUIT', 'ACCT', 'SMNT', 'REST', 'STOR', 'MDTM']

FTP_SOURCE = """\
#define MODE_NORMAL 0
#define MODE_PASSIVE 1
#define FTP_ACCESS_NOLOGIN 0
#define FTP_ACCESS_LOGIN 1

int create_datasocket(PFTPCONTEXT context) {
  switch (context->Mode) {
    case MODE_NORMAL:  /* PORT */
      break;
    case MODE_PASSIVE: /* PASV */
      break;
  }
  return 0;
}
"""


def check(ok, label, detail=''):
    print('%s %s%s' % ('[+]' if ok else '[!]', label, (' -- ' + detail) if detail else ''))
    sys.stdout.flush()
    if not ok:
        FAILED.append(label)
    return ok


def write_bytes(path, data):
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, 'wb') as handle:
        handle.write(data if isinstance(data, bytes) else data.encode('utf-8'))


def read_bytes(path):
    with open(path, 'rb') as handle:
        return handle.read()


def run(args):
    """Call main() with stderr captured; return (rc, stderr)."""
    args = list(args) + ['ftp']
    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        rc = ec.main(args)
    return rc, captured.getvalue()


def build_tree(tmp):
    """A miniature FTP tree: corpus, source, state variables, services, grammar."""
    paths = {'corpus': os.path.join(tmp, 'in-ftp'),
             'out': os.path.join(tmp, 'out-ftp'),
             'prompts': os.path.join(tmp, 'prompts'),
             'repo': os.path.join(tmp, 'repo'),
             'grammar': os.path.join(tmp, 'grammar')}
    write_bytes(os.path.join(paths['corpus'], 'seed_a.raw'), SEED_A)
    write_bytes(os.path.join(paths['corpus'], 'seed_b.raw'), SEED_B)
    source = os.path.join(paths['repo'], 'Source', 'ftpserv.c')
    write_bytes(source, FTP_SOURCE)

    # ChatState state.json: name -> absolute file:line
    write_bytes(os.path.join(tmp, 'state.json'), json.dumps({
        'Mode': '%s:5' % source, 'Access': '%s:7' % source}))
    # ChatState query.json: descriptions and the code around each variable
    write_bytes(os.path.join(tmp, 'query.json'), json.dumps([
        {'name': 'context->Mode', 'description': 'Active or passive data transfer.',
         'default_value': 0, 'store_insts': ['%s:11' % source],
         'store_codes': ['context->Mode = MODE_PASSIVE;'],
         'cond_codes': ['switch (context->Mode) { case MODE_NORMAL: ... }']},
        {'name': 'Access', 'description': 'Session access level.',
         'cond_codes': ['if (context->Access == FTP_ACCESS_NOLOGIN) ...']}]))
    # ChatState services.json: feature -> known request chains
    write_bytes(os.path.join(tmp, 'services.json'), json.dumps({
        'Login': [['USER', 'PASS'], ['AUTH', 'USER', 'PASS']],
        'Transfer': [['PORT', 'STOR'], ['PASV', 'RETR']]}))
    write_bytes(os.path.join(tmp, 'service.json'), json.dumps({
        'User authentication and login': 'Authenticates users and opens a session.',
        'Directory listing': 'Returns a listing of the current directory.'}))
    # A pro-template grammar directory
    write_bytes(os.path.join(paths['grammar'], 'USER'),
                b'^(?:USER (.*)\\r\\n)$\n(.+)')
    write_bytes(os.path.join(paths['grammar'], 'PASS'),
                b'^(?:PASS (.*)\\r\\n)$\n(.+)')
    return paths, source


# ---------------------------------------------------------------------------
# sections
# ---------------------------------------------------------------------------

def section_localtools(paths):
    """1. the tools the model may call."""
    workspace = localtools.Workspace(paths['repo'])
    listing = workspace.list_dir('.')
    check('Source/' in listing, 'list_dir shows the workspace', listing.splitlines()[0])
    body = workspace.read_file('Source/ftpserv.c', 1, 4)
    check('MODE_NORMAL' in body and '\n    1: ' in body,
          'read_file numbers the lines it returns')
    hits = workspace.search_text('MODE_PASSIVE')
    check('ftpserv.c:2:' in hits and 'MODE_PASSIVE' in hits,
          'search_text finds a literal', hits.splitlines()[-1])
    regex = workspace.search_text(r'MODE_\w+', include='*.c', is_regex=True)
    check(regex.count('ftpserv.c:') >= 4, 'search_text honours a regex and a glob')
    escaped = workspace.dispatch('read_file', {'path': '../../../etc/passwd'})
    check('escapes the workspace root' in escaped,
          'a path outside the root is refused', escaped)
    unknown = workspace.dispatch('nope', {})
    check(unknown.startswith('unknown tool'), 'an unknown tool is reported, not raised')
    missing = workspace.dispatch('read_file', {'path': 'Source/nope.c'})
    check('file not found' in missing, 'a missing file is reported to the model')


def section_message_model(tmp, paths):
    """2. splitting, joining and typing messages."""
    messages = ec.split_messages(SEED_A, '\r\n')
    check(messages == ['USER ubuntu', 'PASS ubuntu', 'LIST', 'QUIT'],
          'a seed splits into its messages', str(messages))
    check(ec.join_messages(messages, '\r\n') == SEED_A,
          'the messages join back into the same bytes')
    little_endian = b'HELO x\nMAIL FROM:<a@b>\nQUIT\n'
    check(ec.split_messages(little_endian, '\r\n') == ['HELO x', 'MAIL FROM:<a@b>', 'QUIT'],
          'an LF corpus is still usable')
    check(ec.header_token('USER anonymous') == 'USER'
          and ec.header_token('MAIL FROM:<a@b>') == 'MAIL',
          'the header token is the request verb')
    check(ec.decode_escapes('USER x\\r\\n') == 'USER x\r\n',
          'literal \\r\\n escapes are decoded')

    templates, problems = ec.read_grammar(paths['grammar'])
    check(len(templates) == 2 and not problems, 'the grammar directory reads', str(problems))
    check(ec.classify('USER bob', templates, '\r\n') == 'USER'
          and ec.classify('PASS x', templates, '\r\n') == 'PASS',
          'a message is typed by its template')
    check(ec.classify('STOR f', templates, '\r\n') == 'STOR',
          'a message without a template falls back to its verb')
    corpus = ec.Corpus('\r\n', templates)
    corpus.load_dir(paths['corpus'])
    check(corpus.observed_types == set(['USER', 'PASS', 'LIST', 'PWD', 'QUIT']),
          'the corpus reports the types it holds', str(sorted(corpus.observed_types)))
    check(corpus.missing_in('seed_a.raw', set(TYPES)) ==
          ['ACCT', 'MDTM', 'PWD', 'REST', 'SMNT', 'STOR'],
          'the missing types of one seed are listed',
          str(corpus.missing_in('seed_a.raw', set(TYPES))))
    check(corpus.richest_seed(set(TYPES)) in corpus.files,
          'a base seed can be picked')


def section_statevars(tmp, paths):
    """3. the state variable JSON shapes and the workspace root."""
    statevars = ec.load_statevars(os.path.join(tmp, 'state.json'), lambda _m: None)
    check(sorted(r['name'] for r in statevars) == ['Access', 'Mode'],
          'a ChatState state.json reads')
    check(os.path.isabs(statevars[0]['locations'][0].rsplit(':', 1)[0]),
          'its file:line locations are resolved to absolute paths')
    check(ec._resolve_location('Source/ftpserv.c:268:258', paths['repo'])
          == '%s:268' % os.path.join(paths['repo'], 'Source', 'ftpserv.c'),
          'a file:line:column location keeps the line, not the column')
    query = ec.load_statevars(os.path.join(tmp, 'query.json'), lambda _m: None)
    by_name = dict((r['name'], r) for r in query)
    check('Active or passive' in by_name['context->Mode']['description']
          and by_name['context->Mode']['cond_snippets'],
          'a query.json keeps descriptions and code snippets')
    identify = os.path.join(tmp, 'identify.json')
    write_bytes(identify, json.dumps({
        'tool': 'aflnet-pp/utils/AI-agent/statevar', 'repository': paths['repo'],
        'state_variables': [{'name': 'Access', 'description': 'level',
                             'file': 'Source/ftpserv.c', 'line': 7,
                             'type': 'int', 'kind': 'struct-member'}]}))
    identify_records = ec.load_statevars(identify, lambda _m: None)
    check(identify_records[0]['locations'] == ['%s:7' % os.path.join(paths['repo'],
                                                                     'Source/ftpserv.c')],
          'an identify.py JSON resolves against its repository')
    brief = ec.statevar_brief(by_name['context->Mode'], localtools.Workspace(paths['repo']))
    check('Source/ftpserv.c' in brief and 'assigns it' in brief,
          'the prompt renders a state variable with its code')


def section_services(tmp, paths):
    """4. the pre-scripts services.json."""
    types, chains, overview = ec.load_services(os.path.join(tmp, 'services.json'),
                                              lambda _m: None)
    check(types == set(['USER', 'PASS', 'AUTH', 'PORT', 'STOR', 'PASV', 'RETR']),
          'services.json gives the request vocabulary', str(sorted(types)))
    check(['PORT', 'STOR'] in chains and not overview,
          'services.json gives known good chains')
    services, _, _, _ = ec.load_service_catalog(
        os.path.join(tmp, 'services.json'), lambda _m: None)
    check([s['name'] for s in services] == ['Login', 'Transfer']
          and services[0]['chains'],
          'services.json keeps each named service for job planning')
    types, chains, overview = ec.load_services(os.path.join(tmp, 'service.json'),
                                              lambda _m: None)
    check(not types and len(overview) == 2
          and any('Authenticates users' in line for line in overview),
          'service.json (descriptions only) is understood too', str(overview)[:60])


def section_answer_parsing():
    """5. tolerant parsing of what a model sends back."""
    payload = agent.parse_turn('{"action":"final","seed":{"messages":["USER x","PASS y"],'
                            '"values_targeted":["MODE_PASSIVE"],"rationale":"why"}}')
    check(isinstance(payload, dict) and payload.get('action') == 'final',
          'the whole answer object is parsed, not its first array')
    check(ec.answer_field(payload, 'rationale') == 'why'
          and ec.answer_field(payload, 'messages') == ['USER x', 'PASS y'],
          'fields are readable at the top level and inside "seed"')
    tool = agent.parse_turn('```json\n{"action":"tool","tool":"read_file",'
                         '"args":{"path":"a.c"}}\n```')
    check(isinstance(tool, dict) and tool.get('tool') == 'read_file',
          'a fenced tool call is parsed')
    check(agent.parse_turn('no json at all') is None, 'prose without JSON gives None')

    args = type('A', (), {'max_messages': 64, 'max_message_bytes': 4096})()
    warnings = []
    messages = ec.answer_messages({'seed': {'messages': ['USER x\\r\\n', 'PASS y']}},
                                  '', args, warnings)
    check(messages == ['USER x', 'PASS y'], 'escapes and terminators are stripped',
          str(messages))
    messages = ec.answer_messages(None, '```\nUSER x\nPASS y\n```', args, warnings)
    check(messages == ['USER x', 'PASS y'], 'a fenced raw sequence is accepted')
    messages = ec.answer_messages(None, 'USER x\nPASS y\n', args, warnings)
    check(messages == ['USER x', 'PASS y'], 'a plain line list is accepted')
    messages = ec.answer_messages({'seed': {'messages': ['A', 'B']}}, '', args, warnings)
    check(messages == ['A', 'B'], 'a bare message list is accepted')


def answers_for(jobs, location='Source/ftpserv.c:5'):
    """One plausible answer per job, adding the first requested type."""
    answers = {}
    for job in jobs:
        if job['kind'] == 'services':
            messages = ['USER ubuntu', 'PASS ubuntu', 'PASV',
                        'LIST', 'QUIT']
            answers[job['id']] = json.dumps({'action': 'final', 'seed': {
                'messages': messages, 'service': job['service'],
                'services_covered': [job['service']],
                'rationale': 'exercises %s' % job['service']}})
        elif job['kind'] == 'types':
            base = ['USER ubuntu', 'PASS ubuntu'] if 'seed_a' in job['base'] \
                else ['USER anonymous', 'PASS x']
            messages = base + [job['missing_types'][0]] + ['QUIT']
            answers[job['id']] = json.dumps({'action': 'final', 'seed': {
                'messages': messages, 'types_added': job['missing_types'][:1],
                'rationale': 'added %s' % job['missing_types'][0]}})
        else:
            answers[job['id']] = json.dumps({'action': 'final', 'seed': {
                'messages': ['USER ubuntu', 'PASS ubuntu', 'QUIT'],
                'state_var': job['state_var'],
                'values_targeted': ['VALUE_FOR_%s' % job['state_var']],
                'locations': [location],
                'rationale': 'drives %s' % job['state_var']}})
    return answers


def section_end_to_end(tmp, paths, source):
    """6. dump the prompts, replay answers, check the corpus that comes out."""
    answers = None

    # --- prompts ---------------------------------------------------------
    rc, _err = run([paths['corpus'], paths['out'], '--dump-prompt', paths['prompts'],
                    '--types', ','.join(TYPES), '--rounds', '1',
                    '--quiet'])
    jobs_file = os.path.join(paths['prompts'], 'jobs.json')
    check(rc == 0 and os.path.exists(jobs_file), '--dump-prompt writes a job list')
    jobs = json.load(open(jobs_file))['jobs']
    service_jobs = [j for j in jobs if j['kind'] == 'services']
    type_jobs = [j for j in jobs if j['kind'] == 'types']
    check(len(service_jobs) == 1 and len(type_jobs) == 6,
          'service enrichment is always planned; type jobs follow --types',
          str([(j['kind'], j.get('service')) for j in jobs]))
    service_prompt = open(os.path.join(paths['prompts'],
                                       service_jobs[0]['prompt'])).read()
    check('Target service: protocol services' in service_prompt,
          'the service prompt is generated at runtime without a service file')
    prompt = open(os.path.join(paths['prompts'], type_jobs[0]['prompt'])).read()
    check('USER ubuntu' in prompt and type_jobs[0]['missing_types'][0] in prompt
          and 'No workspace was supplied' in prompt and 'read_file' not in prompt,
          'without --root the prompt carries no local tool contract')

    # --- replay ----------------------------------------------------------
    answers = answers_for(jobs)
    answer_file = os.path.join(tmp, 'answers.json')
    write_bytes(answer_file, json.dumps(answers))
    rc, err = run([paths['corpus'], paths['out'], '--from-answer', answer_file,
                   '--types', ','.join(TYPES), '--rounds', '1',
                   '--quiet'])
    check(rc == 0, 'the replay run exits 0', 'rc=%d' % rc)
    names = sorted(os.listdir(paths['out']))
    check('seed_a.raw' in names and 'seed_b.raw' in names,
          'the original seeds are copied into the output corpus')
    enriched = [n for n in names if n.startswith('enriched_')]
    check(len(enriched) == 7, 'service and type seeds were written', str(len(enriched)))
    produced = read_bytes(os.path.join(paths['out'], 'enriched_r1-0_seed_a.raw'))
    check(produced.endswith(b'\r\n') and b'USER ubuntu\r\n' in produced,
          'an enriched seed is CRLF terminated like the corpus')
    report = json.load(open(os.path.join(paths['out'], ec.META_NAME)))
    stats = report['statistics']
    check(stats['seeds_written'] == 7 and stats['jobs'] == 7,
          'the report counts the seeds written', json.dumps(stats))
    check('ACCT' in report['coverage_after']['observed_types']
          and len(report['coverage_after']['missing_types'])
          < len(report['coverage_before']['missing_types']),
          'the coverage improved',
          'before=%s after=%s' % (len(report['coverage_before']['missing_types']),
                                   len(report['coverage_after']['missing_types'])))
    type_seeds = [s for s in report['seeds'] if s['kind'] == 'types']
    check(type_seeds and type_seeds[0]['types_added'] and type_seeds[0]['seed'],
          'each generated seed records what it added')
    service_seeds = [s for s in report['seeds'] if s['kind'] == 'services']
    check(service_seeds and service_seeds[0]['service'] == 'protocol services'
          and service_seeds[0]['services_covered'] == ['protocol services']
          and report['tasks'] == ['services', 'types'],
          'the mandatory service task is recorded alongside explicit type tasks',
          json.dumps(service_seeds[:1]))
    check(any('MDTM' in s['missing_after'] for s in report['seeds']),
          'a partially covered job reports what is still missing')

    # --- round 2 closes the pool level gap -------------------------------
    answers = dict(answers)
    answers['types-r2-0'] = json.dumps({'action': 'final', 'seed': {
        'messages': ['USER ubuntu', 'PASS ubuntu', 'REST 0', 'STOR f', 'MDTM f.txt',
                     'QUIT'],
        'types_added': ['MDTM', 'REST', 'STOR'], 'rationale': 'pool level gaps'}})
    answers2 = os.path.join(tmp, 'answers2.json')
    write_bytes(answers2, json.dumps(answers))
    out2 = os.path.join(tmp, 'out-ftp2')
    rc, _err = run([paths['corpus'], out2, '--from-answer', answers2,
                    '--types', ','.join(TYPES), '--rounds', '2',
                    '--quiet'])
    report2 = json.load(open(os.path.join(out2, ec.META_NAME)))
    check(rc == 0 and not report2['coverage_after']['missing_types'],
          'a second round fills the gaps left at the pool level',
          str(report2['coverage_after']['missing_types']))
    check(report2['statistics']['rounds'] == 2, 'the report names the round that ran')

    # --- duplicates and re-runs ------------------------------------------
    duplicates = dict(answers)
    keys = [j['id'] for j in jobs]
    duplicates[keys[1]] = duplicates[keys[0]]
    dup_file = os.path.join(tmp, 'answers-dup.json')
    write_bytes(dup_file, json.dumps(duplicates))
    out3 = os.path.join(tmp, 'out-ftp3')
    rc, _err = run([paths['corpus'], out3, '--from-answer', dup_file,
                    '--types', ','.join(TYPES), '--rounds', '1',
                    '--quiet'])
    report3 = json.load(open(os.path.join(out3, ec.META_NAME)))
    check(rc == 0 and report3['statistics']['seeds_written'] == 6
          and any('duplicate' in w for w in report3['warnings']),
          'an identical answer is dropped as a duplicate',
          json.dumps(report3['statistics']))
    rc, _err = run([paths['corpus'], out3, '--force', '--from-answer', dup_file,
                    '--types', ','.join(TYPES), '--rounds', '1',
                    '--quiet'])
    report3b = json.load(open(os.path.join(out3, ec.META_NAME)))
    check(rc == 0 and report3b['statistics']['seeds_written'] == 0,
          're-running the same answers adds nothing')

    # --- state variable task ---------------------------------------------
    answers = answers_for([])
    sv_prompts = os.path.join(tmp, 'prompts-sv')
    rc, _err = run([paths['corpus'], os.path.join(tmp, 'out-sv'),
                    '--statevars', os.path.join(tmp, 'query.json'),
                    '--dump-prompt', sv_prompts, '--quiet'])
    sv_jobs = json.load(open(os.path.join(sv_prompts, 'jobs.json')))['jobs']
    sv_only = [j for j in sv_jobs if j['kind'] == 'statevar']
    check(rc == 0 and len(sv_only) == 2 and sv_only[0]['state_var'],
          'one state variable job per variable; service stays enabled', str(sv_jobs))
    sv_prompt = open(os.path.join(sv_prompts, sv_only[0]['prompt'])).read()
    check('state variable' in sv_prompt.lower() and 'assigns it' in sv_prompt,
          'the state variable prompt carries the code from query.json')
    sv_answers = answers_for(sv_only, location='Source/nope.c:1')
    for job in sv_jobs:
        if job['kind'] == 'services':
            sv_answers[job['id']] = answers_for([job])[job['id']]
    sv_file = os.path.join(tmp, 'answers-sv.json')
    write_bytes(sv_file, json.dumps(sv_answers))
    out_sv = os.path.join(tmp, 'out-sv')
    rc, _err = run([paths['corpus'], out_sv,
                    '--statevars', os.path.join(tmp, 'query.json'),
                    '--root', paths['repo'],
                    '--from-answer', sv_file, '--rounds', '1', '--quiet'])
    sv_report = json.load(open(os.path.join(out_sv, ec.META_NAME)))
    entry = sv_report['state_variables'][0]
    check(rc == 0 and entry['seeds'] and entry['values_targeted'],
          'the report links the generated seeds to the state variable they drive',
          json.dumps(entry, ensure_ascii=False))
    check(entry['locations'] == ['Source/ftpserv.c:5'] or entry['locations'],
          'the definition site is carried into the report')
    located = [s for s in sv_report['seeds'] if s.get('state_var')]
    check(located and located[0]['locations_ok'] is False,
          'a cited file the workspace does not have is flagged',
          json.dumps([s.get('locations_ok') for s in located]))
    check(located[0]['locations'] == ['Source/nope.c:1'],
          'the cited locations are carried into the report')

    # --- in place ---------------------------------------------------------
    in_place = os.path.join(tmp, 'in-place')
    shutil.copytree(paths['corpus'], in_place)
    rc, _err = run([in_place, in_place, '--in-place', '--from-answer', dup_file,
                    '--types', ','.join(TYPES), '--rounds', '1',
                    '--quiet'])
    after = sorted(n for n in os.listdir(in_place) if n.startswith('enriched_'))
    check(rc == 0 and len(after) == 6, '--in-place writes into the corpus itself',
          str(len(after)))
    rc, _err = run([in_place, in_place, '--in-place', '--from-answer', dup_file,
                    '--types', ','.join(TYPES), '--rounds', '1',
                    '--quiet'])
    check(sorted(n for n in os.listdir(in_place) if n.startswith('enriched_')) == after,
          'an in-place re-run does not treat enriched seeds as new inputs')

    # --- check mode -------------------------------------------------------
    check_report = os.path.join(tmp, 'check.json')
    rc, err = run(['--check', paths['out'], paths['out'],
                   '--types', ','.join(TYPES),
                   '--report', check_report, '--quiet'])
    payload = json.load(open(check_report))
    check(rc == 0 and payload['coverage']['seeds'] == 9,
          '--check counts the seeds of an enriched corpus',
          str(payload['coverage']['seeds']))
    check(payload['mode'] == 'check' and payload['protocol'] == 'ftp',
          '--check identifies corpus and protocol')


def section_binary_formats(tmp):
    """9. binary framing + probe classification through --formats/--grammar."""
    corpus = os.path.join(tmp, 'bin-corpus')
    os.makedirs(corpus)

    def frame(magic, payload):
        return bytes([magic, len(payload)]) + payload

    first = frame(0xA1, b'one')
    second = frame(0xA2, b'two-two')
    write_bytes(os.path.join(corpus, 'two.bin'), first + second)
    write_bytes(os.path.join(corpus, 'one.bin'), first)

    table = {'format_version': 1,
             'framing': {'length_offset': 1, 'length_size': 1,
                         'payload_offset': 2, 'length_includes': 'payload'},
             'types': {'MSG_A': {'probe': [{'offset': 0, 'value': '0xA1'}]},
                       'MSG_B': {'probe': [{'offset': 0, 'value': '0xA2'}]}}}
    formats_dir = os.path.join(tmp, 'bin-formats')
    write_bytes(os.path.join(formats_dir, formats.FORMATS_NAME),
                json.dumps(table))
    report = os.path.join(tmp, 'bin-report.json')
    rc, err = run(['--check', corpus, corpus, '--formats',
                   os.path.join(formats_dir, formats.FORMATS_NAME),
                   '--report', report, '--quiet'])
    payload = json.load(open(report))
    coverage = payload['coverage']
    check(rc == 0 and coverage['seeds'] == 2 and coverage['messages'] == 3,
          'binary seeds are split by the length field', json.dumps(
              {k: coverage[k] for k in ('seeds', 'messages')}))
    check(set(coverage['observed_types']) == set(['MSG_A', 'MSG_B']),
          'the probe table classifies every binary message',
          str(coverage['observed_types']))

    rc, _err = run(['--check', corpus, corpus, '--grammar', formats_dir,
                    '--report', report, '--quiet'])
    payload = json.load(open(report))
    check(rc == 0 and payload['coverage']['messages'] == 3,
          'the formats file is found next to the grammar directory')

    datagram = dict(table)
    datagram.pop('framing')
    datagram_path = os.path.join(tmp, 'datagram-formats.json')
    write_bytes(datagram_path, json.dumps(datagram))
    datagram_corpus = os.path.join(tmp, 'datagram-corpus')
    os.makedirs(datagram_corpus)
    write_bytes(os.path.join(datagram_corpus, 'a.bin'), first)
    write_bytes(os.path.join(datagram_corpus, 'b.bin'), second)
    rc, _err = run(['--check', datagram_corpus, datagram_corpus,
                    '--formats', datagram_path,
                    '--report', report, '--quiet'])
    payload = json.load(open(report))
    check(rc == 0 and payload['coverage']['messages'] == 2
          and set(payload['coverage']['observed_types']) == set(['MSG_A', 'MSG_B']),
          'without framing one seed is one message (datagram protocols)',
          str(payload['coverage']['messages']))

    check(formats.framing_of(table) is not None
          and formats.classify(first, table) == 'MSG_A'
          and formats.classify(second, table) == 'MSG_B',
          'the shared formats module classifies frames')
    frames, rest = formats.split_frames(first + second, table['framing'])
    check(frames == [first, second] and rest == 0,
          'the shared framing splitter returns whole frames')
    long_payload = b'x' * 129
    long_frame = b'\xa1\x81\x01' + long_payload
    varint_table = dict(table)
    varint_table['framing'] = {'length_offset': 1, 'length_size': 'varint',
                               'payload_offset': 2,
                               'length_includes': 'payload'}
    frames, rest = formats.split_frames(long_frame + long_frame,
                                        varint_table['framing'])
    check(frames == [long_frame, long_frame] and rest == 0,
          'a multi-byte varint moves the payload start on the wire')

    args = type('A', (), {'max_messages': 64, 'max_message_bytes': 4096,
                          'tools': True, 'lang': 'en',
                          'terminator': '\r\n'})()
    warnings = []
    messages = ec.answer_messages(
        {'seed': {'messages': ['\\xA1\\x03one', '\\xA2\\x07two-two']}},
        '', args, warnings, binary=True)
    check(messages == ['\xa1\x03one', '\xa2\x07two-two'],
          'binary answer escapes are decoded as raw bytes', repr(messages))
    messages_with_crlf = ec.answer_messages(
        {'seed': {'messages': ['\\xA1\\x02\\r\\n']}},
        '', args, warnings, binary=True)
    check(messages_with_crlf == ['\xa1\x02\r\n'],
          'binary answer parsing preserves embedded CRLF bytes')
    binary_prompt = ec.build_system_prompt('binary-test', args, binary=True)
    text_prompt = ec.build_system_prompt('binary-test', args)
    check('Do not append or strip' in binary_prompt
          and 'one element per COMPLETE client protocol message' in binary_prompt
          and 'Do not append or strip' not in text_prompt,
          'the binary prompt asks for complete framed messages')

    reply_corpus = os.path.join(tmp, 'reply-corpus')
    os.makedirs(reply_corpus)
    write_bytes(os.path.join(reply_corpus, 'one.bin'), first)
    answer_path = os.path.join(tmp, 'binary-answer.json')
    write_bytes(answer_path,
                '{"action":"final","seed":{"messages":'
                '["\\\\xA1\\\\x03one","\\\\xA2\\\\x07two-two"],'
                '"rationale":"cover the second type"}}')
    reply_out = os.path.join(tmp, 'reply-out')
    rc, err = run([reply_corpus, reply_out, '--formats',
                   os.path.join(formats_dir, formats.FORMATS_NAME),
                   '--from-answer', answer_path, '--rounds', '1',
                   '--max-jobs', '1', '--no-copy', '--quiet'])
    generated = [name for name in os.listdir(reply_out)
                 if not name.startswith('.')] if os.path.isdir(reply_out) else []
    written = read_bytes(os.path.join(reply_out, generated[0])) if generated else b''
    check(rc == 0 and written == first + second,
          'binary replay writes complete frames without injecting CRLF',
          '%d file(s), %r' % (len(generated), written))


def section_live_loop(tmp, paths):
    """9. the agent loop, driven by a stub endpoint (no network)."""

    class StubClient(object):
        model = 'stub-model'
        base_url = 'http://stub.invalid/v1'

        def __init__(self):
            self.calls = []

        def chat(self, system, user):
            self.calls.append(user)
            match = re.search(r'\(job ([^,)]+)', user)
            job = match.group(1) if match else 'job-unknown'
            if 'tool result for' in user:
                return json.dumps({'action': 'final', 'seed': {
                    'messages': ['USER %s' % job, 'PASS ubuntu', 'MDTM f.txt', 'QUIT'],
                    'types_added': ['MDTM'], 'state_var': 'Mode',
                    'values_targeted': ['MODE_PASSIVE'],
                    'locations': ['Source/ftpserv.c:5'],
                    'rationale': 'read the code and used MDTM'}})
            if 'message type inventory' in user:
                return json.dumps({'action': 'final',
                                   'types': ['USER', 'PASS', 'ACCT', 'MDTM']})
            return json.dumps({'action': 'tool', 'tool': 'search_text',
                               'args': {'query': 'MODE_PASSIVE'}})

    stub = StubClient()
    original = ec.make_client
    ec.make_client = lambda args, log: stub
    try:
        out = os.path.join(tmp, 'out-live')
        rc, err = run([paths['corpus'], out, '--statevars',
                       os.path.join(tmp, 'query.json'), '--types',
                       'USER,PASS,ACCT,MDTM', '--root', paths['repo'],
                       '--rounds', '1',
                       '--quiet'])
        report = json.load(open(os.path.join(out, ec.META_NAME)))
        check(rc == 0 and report['mode'] == 'llm' and report['model'] == 'stub-model',
              'the live path records the model it used', 'rc=%d' % rc)
        check(report['statistics']['tool_calls'] > 0,
              'the model got its local tool results',
              json.dumps(report['statistics']))
        check(any('tool result for search_text' in call for call in stub.calls),
              'the tool output is fed back to the model')
        check('ACCT' in report['message_types']['universe']
              and 'MDTM' in report['message_types']['universe'],
              'explicit and observed types bound the type universe')
        check(report['seeds'] and all(s['job'] for s in report['seeds']),
              'every generated seed names the job it came from')
        check(any(s.get('values_targeted') for s in report['seeds']),
              'the state variable task records the values the model targeted')
        cited = [s for s in report['seeds'] if s.get('locations')]
        check(cited and all(s['locations_ok'] for s in cited),
              'a cited file inside the workspace is accepted',
              json.dumps([s.get('locations_ok') for s in cited]))
        check(report['statistics']['generated'] == report['statistics']['jobs']
              and report['seeds'][-1]['kind'] == 'statevar',
              'every job of the live path produced its own seed',
              json.dumps(report['statistics']))
        check(report['statistics']['by_task']['services'] == 1
              and report['statistics']['by_task']['statevars'] == 2,
              'the report separates service and state-variable seeds',
              json.dumps(report['statistics']['by_task']))
    finally:
        ec.make_client = original


def section_cli(tmp, paths):
    """7. the command line contract."""
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            ec.parse_args([paths['corpus'], paths['out']])
        except SystemExit as exc:
            missing_protocol = exc.code == 2
        else:
            missing_protocol = False
    check(missing_protocol, 'corpus, output and protocol are all required')
    args = ec.parse_args([paths['corpus'], paths['out'], 'FTP',
                          '--grammar', paths['grammar'],
                          '--statevars', os.path.join(tmp, 'query.json')])
    check(args.protocol == 'ftp'
          and args.task_list == set(['services', 'types', 'statevars']),
          'grammar and statevars enable additive service/type/statevar tasks',
          str(sorted(args.task_list)))
    rc, err = run([os.path.join(tmp, 'nope'), os.path.join(tmp, 'x')])
    check(rc == 1 and 'no such corpus' in err, 'a missing corpus exits 1', 'rc=%d' % rc)
    rc, err = run([paths['corpus'], paths['out'], '--offline', '--types', 'USER'])
    check(rc == 1 and '--offline needs --from-answer' in err,
          '--offline without answers exits 1', 'rc=%d' % rc)
    rc, err = run([paths['corpus'], paths['out'], '--types', 'USER', '--rounds', '1'])
    check(rc == 1 and 'is not empty' in err,
          'a populated output directory needs --force', 'rc=%d' % rc)
    rc, err = run([paths['corpus'], paths['out'], '--from-answer',
                   os.path.join(tmp, 'answers.json'), '--types', 'USER,PASS,ACCT',
                   '--rounds', '1', '--strict', '--quiet'])
    check(rc == 1, '--strict fails on a job without an answer', 'rc=%d' % rc)
    rc, err = run([paths['corpus'], os.path.join(tmp, 'out-none'),
                   '--types', 'USER,PASS', '--from-answer',
                   os.path.join(tmp, 'answers.json'), '--rounds', '1', '--quiet'])
    check(rc == 0, 'an unanswered optional job warns but non-strict exits 0',
          'rc=%d' % rc)
    rc, err = run([paths['corpus'], os.path.join(tmp, 'out-llm'),
                   '--types', 'USER,PASS,ACCT', '--rounds', '1',
                   '--base-url', 'http://127.0.0.1:1/v1', '--api-key', 'x',
                   '--timeout', '1', '--retries', '0', '--quiet'])
    check(rc == 1 and 'endpoint' in err, 'an unreachable endpoint exits 1',
          err.strip().splitlines()[-1][:60] if err.strip() else '')


def section_grammar_and_services_inputs(tmp, paths):
    """8. --grammar and --services feed the type universe."""
    prompts = os.path.join(tmp, 'prompts2')
    rc, err = run([paths['corpus'], os.path.join(tmp, 'out-g'),
                   '--grammar', paths['grammar'],
                   '--services', os.path.join(tmp, 'services.json'),
                   '--root', paths['repo'],
                   '--dump-prompt', prompts, '--rounds', '1',
                   '--quiet'])
    jobs = json.load(open(os.path.join(prompts, 'jobs.json')))['jobs']
    type_jobs = [job for job in jobs if job['kind'] == 'types']
    service_jobs = [job for job in jobs if job['kind'] == 'services']
    missing = set(t for job in type_jobs for t in (job['missing_types'] or []))
    check(rc == 0 and 'AUTH' in missing and 'RETR' in missing,
          'the type universe comes from the grammar and the services file',
          str(sorted(missing))[:80])
    check(len(service_jobs) == 2,
          'services.json creates one mandatory service job per service',
          str([j.get('service') for j in service_jobs]))
    prompt = open(os.path.join(prompts, type_jobs[0]['prompt'])).read()
    check('Known good chains' in prompt and 'USER / PASS' in prompt
          and 'read_file' in prompt,
          '--root enables tools and the prompt shows known request chains')


def main():
    tmp = tempfile.mkdtemp(prefix='corpus-enrich-selftest-')
    try:
        paths, source = build_tree(tmp)
        section_localtools(paths)
        section_message_model(tmp, paths)
        section_statevars(tmp, paths)
        section_services(tmp, paths)
        section_answer_parsing()
        section_end_to_end(tmp, paths, source)
        section_grammar_and_services_inputs(tmp, paths)
        section_binary_formats(tmp)
        section_live_loop(tmp, paths)
        section_cli(tmp, paths)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if FAILED:
        print('\n[!] %d check(s) failed: %s' % (len(FAILED), ', '.join(FAILED)))
        return 1
    print('\n[+] corpus enrichment tool looks correct')
    return 0


if __name__ == '__main__':
    sys.exit(main())
