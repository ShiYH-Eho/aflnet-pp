#!/usr/bin/env python3
"""Offline regression test for the grammar template generator.

    python3 utils/AI-agent/pro-template/selftest.py

Needs neither network nor any third party package: the endpoint is never
contacted, every answer is replayed from a literal that mimics the models this
tool talks to.  Exits non-zero on the first failed group of expectations.
"""

from __future__ import print_function

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gen_templates as gt  # noqa: E402

# Byte identical to ChatState's reference template
# (prompt-test/sv_data/protocol-grammars/USER), so the two generators can be
# mixed in one AFLNET_GRAMMAR directory.
REFERENCE_USER = '^(?:USER (.*)\\r\\n)$\n(.+)'

FAILED = []


def check(ok, label, detail=''):
    print('%s %s%s' % ('[+]' if ok else '[!]', label,
                       (' -- ' + detail) if detail else ''))
    sys.stdout.flush()
    if not ok:
        FAILED.append(label)
    return ok


def record_for(entry, protocol='ftp', keep_static=False):
    warnings = []
    record, reason = gt.build_record(entry, warnings, keep_static=keep_static,
                                     protocol=protocol)
    return record, reason, warnings


def test_text_helpers():
    check(gt.normalize_escapes('USER x\\r\\n') == 'USER x\r\n',
          'escapes of a model answer become real CR LF bytes')
    check(gt.escape_literal('a.b*c\r\n') == 'a\\.b\\*c\\r\\n',
          'literal protocol bytes are escaped for PCRE2')
    segs, marked, balanced = gt.marker_segments('USER <<NAME>>\r\n')
    check(marked and balanced and [k for k, _ in segs] == ['lit', 'var', 'lit'],
          '<<...>> placeholders are split out of a request')
    segs, _, balanced = gt.marker_segments('USER {{NAME}}')
    check(balanced and [k for k, _ in segs] == ['lit', 'var'],
          '{{...}} placeholders are accepted as well')


def test_header_shapes():
    record, reason, _ = record_for(
        {'type': 'USER', 'request': 'USER <<USERNAME>>\\r\\n',
         'placeholders': [{'name': 'USERNAME', 'example': 'anonymous',
                           'description': 'login name'}],
         'description': 'login user name'})
    check(reason is None, 'a marked request becomes a template', str(reason))
    check(gt.template_text(record) == REFERENCE_USER,
          'the template is byte identical to the reference corpus',
          repr(gt.template_text(record)))
    check(record['verified'] is True,
          'the generated example matches its own header pattern')
    check(record['example'] == 'USER anonymous\r\n' and record['type'] == 'USER',
          'the example is built from the placeholder examples')

    record, _, _ = record_for(
        {'type': 'USER', 'request': 'USER <<USERNAME>>',
         'placeholders': [{'name': 'USERNAME', 'example': 'anonymous'}]})
    check(gt.template_text(record) == REFERENCE_USER,
          'a missing CRLF terminator is added for a line protocol')

    record, _, _ = record_for(
        {'type': 'CONNECT', 'request': 'CONNECT <<ID>>'},
        protocol='mqtt')
    check(record['header'] == '^(?:CONNECT (.*))',
          'a binary protocol keeps the prefix matching layout',
          record['header'])

    record, _, _ = record_for(
        {'type': 'USER', 'request': '^USER ([^ ]+)$'}, protocol='ftp')
    check(record['header'] == '^(?:USER (.*)\\r\\n)$' and record['example'] is None,
          'a request written as a regex is converted too', record['header'])

    record, _, _ = record_for({'type': 'PORT',
                               'request': 'PORT <<H1>>,<<H2>>,<<P1>>,<<P2>>'})
    check(record['header'] == '^(?:PORT (.*),(.*),(.*),(.*)\\r\\n)$',
          'every placeholder becomes one capture group', record['header'])

    record, _, _ = record_for({'type': 'RETR', 'request': 'RETR <<PATH>>'},
                              keep_static=True)
    check(record['header'] == '^(?:RETR (.*)\\r\\n)$', 'plain marker request')

    record, reason, _ = record_for({'type': 'NOOP', 'request': 'NOOP\\r\\n'})
    check(record is None and 'static' in (reason or ''),
          'a request without a mutable field is rejected', str(reason))
    record, reason, _ = record_for({'type': 'NOOP', 'request': 'NOOP\\r\\n'},
                                   keep_static=True)
    check(record is not None and record['header'] == '^(?:NOOP\\r\\n)$',
          '--keep-static keeps such a template', str(reason))

    record, _, _ = record_for({'type': 'X', 'request': 'USER <<A>>',
                               'field_pattern': '.+?(.*)'})
    check(record['fields'] == '.+?(.*)', 'a model supplied field pattern is kept')

    check(gt.sanitize_type('../../etc/passwd') == 'etcpasswd',
          'a message type can never escape the output directory',
          str(gt.sanitize_type('../../etc/passwd')))
    check(gt.sanitize_type('..') is None and gt.sanitize_type('') is None,
          'a useless message type is rejected')


def test_multiline_requests():
    """A request line plus headers: line 1 is the head, the rest is the field."""
    setup = {'type': 'SETUP',
             'request': 'SETUP <<URI>> RTSP/1.0\\r\\nCSeq: <<CSEQ>>\\r\\n'
                        'User-Agent: <<UA>>\\r\\n\\r\\n',
             'placeholders': [{'name': 'URI', 'example': 'rtsp://127.0.0.1:8554/a'},
                              {'name': 'CSEQ', 'example': '2'},
                              {'name': 'UA', 'example': 'TestRTSPClient'}],
             'description': 'set up a session'}
    record, reason, _ = record_for(setup, protocol='rtsp')
    check(reason is None, 'a request with headers becomes a template', str(reason))
    check(record['header'] == '^(?:SETUP (.*) RTSP/1\\.0\\r\\n)',
          'the line that names the message type becomes the header pattern',
          record['header'])
    check(record['fields'] == '(?|(?:CSeq: (.*)\\r\\n)|(?:User-Agent: (.*)\\r\\n)'
                              '|(?:\\r\\n))',
          'the other lines become the alternatives of the field pattern',
          record['fields'])
    check('$' not in record['header'],
          'the header pattern stops at the request line so the fields are scanned')
    check(record['verified'] is True,
          'the header pattern matches the example of its own template')
    check(record['example'] == 'SETUP rtsp://127.0.0.1:8554/a RTSP/1.0\r\n'
                               'CSeq: 2\r\nUser-Agent: TestRTSPClient\r\n\r\n',
          'the example keeps the empty line that closes the headers',
          repr(record['example']))

    # a JSON answer carries real CR LF bytes, not the "\\r\\n" spelling
    real = dict(setup)
    real['request'] = setup['request'].replace('\\r\\n', '\r\n')
    record, reason, _ = record_for(real, protocol='rtsp')
    check(record is not None and record['fields'] ==
          '(?|(?:CSeq: (.*)\\r\\n)|(?:User-Agent: (.*)\\r\\n)|(?:\\r\\n))',
          'real line breaks split the same way as the escaped spelling',
          record['fields'] if record else reason)

    # only a header line is marked: the template still has a mutable field
    minimal = {'type': 'SETUP',
               'request': 'SETUP rtsp://127.0.0.1:8554/a RTSP/1.0\\r\\n'
                          'CSeq: <<CSEQ>>\\r\\n\\r\\n',
               'placeholders': [{'name': 'CSEQ', 'example': '2'}]}
    record, reason, _ = record_for(minimal, protocol='rtsp')
    check(record is not None and record['fields'] == '(?|(?:CSeq: (.*)\\r\\n)'
                                                   '|(?:\\r\\n))',
          'a placeholder in a header line keeps the template',
          str(reason) if record is None else record['fields'])

    # a regex that spells out both lines is split as well
    record, reason, _ = record_for({'type': 'PLAY',
                                    'request': '^PLAY (.*)\\r\\nCSeq: (.*)\\r\\n$'},
                                   protocol='rtsp')
    check(record is not None and record['header'] == '^(?:PLAY (.*)\\r\\n)'
          and record['fields'] == '(?:CSeq: (.*)\\r\\n)',
          'a multi line answer written as a regex is split too',
          record['fields'] if record else reason)

    # single line commands keep the reference layout, and a lone trailing
    # terminator is not mistaken for a header block
    record, _, _ = record_for({'type': 'USER', 'request': 'USER <<NAME>>\\r\\n'})
    check(gt.template_text(record) == REFERENCE_USER,
          'a single line command is still byte identical to the reference corpus')
    record, _, _ = record_for({'type': 'USER', 'request': 'USER <<NAME>>\\r\\n',
                               'placeholders': [{'name': 'NAME', 'example': 'a'}]},
                              protocol='ftp')
    check(record['fields'] == '(.+)',
          'a single line command keeps the default field pattern', record['fields'])


def test_answer_parsers():
    json_answer = json.dumps({'templates': [
        {'type': 'USER', 'request': 'USER <<USERNAME>>\\r\\n',
         'placeholders': [{'name': 'USERNAME', 'example': 'anonymous'}]},
        {'type': 'PASS', 'request': 'PASS <<PASSWORD>>\\r\\n',
         'placeholders': [{'name': 'PASSWORD', 'example': 'secret'}]}]})
    entries = gt.parse_answer('```json\n%s\n```' % json_answer)
    check([gt.entry_type(e) for e in entries] == ['USER', 'PASS'],
          'a fenced JSON object is parsed', repr(entries)[:80])

    entries = gt.parse_answer(json.dumps({'types': {
        'USER': {'syntax': 'USER x', 'description': 'd'},
        'PORT': {'syntax': 'PORT 1,2,3,4,5,6'}}}))
    check(len(entries) == 2 and gt.entry_type(entries[1]) == 'PORT',
          'a "types" map of objects is parsed', repr(entries)[:80])

    entries = gt.parse_answer('USER: ["USER anonymous\\r\\n"]\n'
                              'PASS: ["PASS secret\\r\\n"]\n')
    check([e.get('request') for e in entries] == ['USER anonymous\r\n',
                                                  'PASS secret\r\n'],
          'the ChatState list-of-lines form is parsed', repr(entries)[:80])

    entries = gt.parse_answer('type: RETR\nrequest: RETR <<PATH>>\r\n'
                              'description: download a file\n'
                              '\n'
                              'name: STOR\nrequest: STOR <<PATH>>\r\n')
    check([gt.entry_type(e) for e in entries] == ['RETR', 'STOR']
          and entries[0].get('request') == 'RETR <<PATH>>'
          and entries[0].get('description') == 'download a file',
          'a plain metadata/detail answer is parsed', repr(entries)[:120])
    record, _, _ = record_for(entries[0])
    check(record['header'] == '^(?:RETR (.*)\\r\\n)$',
          'the terminator a line based answer lost is added back',
          record['header'])

    entries = gt.parse_answer('TYPE: A\r\n\nPASV: PASV\r\n')
    check([gt.entry_type(e) for e in entries] == ['TYPE', 'PASV']
          and entries[0].get('request') == 'A',
          'an upper case key stays a message type (FTP TYPE is not metadata)',
          repr(entries)[:120])

    check(gt.parse_answer('I cannot help with that.') == [],
          'an answer without a template yields nothing')


def test_prompt():
    system, user = gt.build_prompt('ftp', 'English', 1, [], None, 40)
    check('JSON' in system and 'CRLF' in user and 'USER' in user,
          'the first prompt asks for every request type and uses the FTP hint')
    system, user = gt.build_prompt('ftp', 'English', 2, ['USER'], ['PASS'], 40)
    check('USER' in user and 'still missing' in user and 'PASS' in user,
          'the second prompt lists the known types and asks for the rest')
    check('UNKNOWN-PROTO' in gt.build_prompt('unknown-proto', 'English', 1, [], None,
                                             40)[1],
          'an unknown protocol is still described in the prompt')
    check('at most 3' in gt.build_prompt('ftp', 'English', 1, [], None, 3)[1],
          'the type limit reaches the prompt')
    system, user = gt.build_prompt('ftp', 'English', 1, [], None, 40,
                                   root='/tmp/some-repo')
    check('read_file' in system and 'Workspace root' not in system
          and '/tmp/some-repo' in user,
          '--root offers the tools and names the workspace in the task')


def test_agent_round(tmpdir):
    """--root drives the shared agent: a tool call is answered, then the answer."""
    root = os.path.join(tmpdir, 'agent-root')
    os.makedirs(root)
    with open(os.path.join(root, 'target.c'), 'w') as fh:
        fh.write('int login_state;\n')

    class Stub(object):
        model = 'stub-model'
        base_url = 'http://stub.invalid/v1'

        def __init__(self):
            self.calls = []

        def chat(self, system, user):
            self.calls.append(user)
            if 'tool result for read_file' in user:
                return json.dumps({'templates': [
                    {'type': 'USER', 'request': 'USER <<NAME>>\\r\\n',
                     'placeholders': [{'name': 'NAME', 'example': 'anonymous'}],
                     'description': 'login name'}]})
            return json.dumps({'action': 'tool', 'tool': 'read_file',
                               'args': {'path': 'target.c', 'start_line': 1,
                                        'end_line': 5}})

    stub = Stub()
    original = gt.make_client
    gt.make_client = lambda args, log: stub
    out = os.path.join(tmpdir, 'agent-grammar')
    try:
        rc = gt.main(['ftp', out, '--root', root, '--rounds', '1', '--quiet'])
    finally:
        gt.make_client = original
    check(rc == 0 and os.path.exists(os.path.join(out, 'USER')),
          '--root runs the shared agent and writes the template', 'rc=%d' % rc)
    check(any('tool result for read_file' in call for call in stub.calls)
          and any('int login_state;' in call for call in stub.calls),
          'the agent saw the file it asked for')
    check(any('Target workspace root: %s' % root in call for call in stub.calls),
          'the task prompt names the workspace root')


def test_binary_mode(tmpdir):
    """--mode binary: \\xNN bytes, byte-class windows, layout-derived templates."""
    check(gt.normalize_escapes('\\x41\\x00') == '\\x41\\x00',
          'text mode keeps \\xNN spellings untouched')
    check(gt.normalize_escapes('\\x41\\x00', binary=True) == 'A\x00',
          'binary mode decodes \\xNN to bytes')

    warnings = []
    record, reason = gt.build_record(
        {'type': 'MQTT_CONNECT',
         'request': '\\x10<<RL>>\\x00\\x04MQTT\\x04\\x02\\x00<<KA>>',
         'placeholders': [{'name': 'RL', 'example': '\\x0c'},
                          {'name': 'KA', 'example': '\\x3c'}]},
        warnings, protocol='mqtt', binary=True)
    check(record is not None and record['example'].startswith('\x10'),
          'a binary request example is decoded to bytes', reason or '')
    check(record is not None and '$' not in record['header']
          and '\\x00-\\xff' in record['header'],
          'binary windows use the byte class and stay prefix anchored',
          record['header'] if record else reason)
    check(record is not None and record['fields'] == '([\\x00-\\xff]+)',
          'the binary field pattern covers any tail',
          record['fields'] if record else reason)
    check(record is not None and record['verified'] is True,
          'the decoded example matches its binary header')

    layout = [
        {'name': 'fixed_header', 'offset': 0, 'size': 1, 'kind': 'const',
         'value': '0x10', 'mutable': False},
        {'name': 'remaining_length', 'offset': 1, 'size': 1, 'kind': 'length',
         'mutable': False},
        {'name': 'protocol_name_len', 'offset': 2, 'size': 2, 'kind': 'const',
         'value': '0x0004', 'mutable': False},
        {'name': 'protocol_name', 'offset': 4, 'size': 4, 'kind': 'const',
         'value': 'MQTT', 'mutable': False},
        {'name': 'protocol_level', 'offset': 8, 'size': 1, 'kind': 'const',
         'value': '0x04', 'mutable': False},
        {'name': 'connect_flags', 'offset': 9, 'size': 1, 'kind': 'bitfield',
         'mutable': True},
        {'name': 'keepalive', 'offset': 10, 'size': 2, 'kind': 'uint16',
         'mutable': True},
    ]
    entry = {'type': 'MQTT_CONNECT',
             'probe': [{'offset': 0, 'value': '0x10'}],
             'example': '\\x10\\x0a\\x00\\x04MQTT\\x04\\x02\\x00\\x3c',
             'layout': layout,
             'frame': {'length_offset': 1, 'length_size': 'varint',
                       'length_includes': 'payload'},
             'description': 'MQTT CONNECT'}
    warnings = []
    record, reason = gt.build_record(dict(entry), warnings, protocol='mqtt',
                                     binary=True)
    check(record is not None and not warnings,
          'a consistent binary layout becomes a template', str(warnings))
    expected = ('^(?:\\x10(?:[\\x00-\\xff]{1})\\x00\\x04MQTT\\x04'
                '([\\x00-\\xff]{1})([\\x00-\\xff]{2}))')
    check(record is not None and record['header'] == expected,
          'mutable layout fields become captures, framing stays non-capturing',
          record['header'] if record else reason)
    check(record is not None and record.get('probe') == entry['probe']
          and len(record.get('layout') or []) == len(layout),
          'probe and layout are kept for the meta file')

    varint_layout = [
        {'name': 'type', 'offset': 0, 'size': 1, 'kind': 'const',
         'value': '0x10', 'mutable': False},
        {'name': 'remaining_length', 'offset': 1, 'size': 'varint',
         'kind': 'length', 'mutable': False},
        {'name': 'payload', 'offset': 2, 'size': 3, 'kind': 'bytes',
         'mutable': True},
    ]
    warnings = []
    derived = gt.layout_to_template('\x10\x03abc', varint_layout, warnings, 'V')
    varint_header = derived['header'] if derived else ''
    warnings_multi = []
    derived_multi = gt.layout_to_template('\x10\x83\x01abc', varint_layout,
                                          warnings_multi, 'V')
    varint_multi_header = derived_multi['header'] if derived_multi else ''
    check(not warnings and '(?:[\\x80-\\xff]*[\\x00-\\x7f])' in varint_header,
          'size=varint becomes a LEB128 pattern instead of being skipped',
          varint_header or str(warnings))
    check('\\x03' not in varint_header,
          'the example varint bytes are not duplicated as a fixed gap',
          varint_header)
    check(not warnings_multi and varint_multi_header == varint_header
          and '\\x83' not in varint_multi_header,
          'a multi-byte example varint is not hard-coded in the template',
          varint_multi_header or str(warnings_multi))
    compiled, error = gt.compile_pattern(varint_header)
    check(compiled is not None and compiled.match('\x10\x03abc') is not None
          and compiled.match('\x10\x83\x01abc') is not None,
          'one-byte and multi-byte varints match the same generated template',
          error or varint_header)

    bad = [dict(field) for field in layout]
    bad[3]['value'] = 'NOPE'
    warnings = []
    gt.build_record({'type': 'MQTT_CONNECT', 'example': entry['example'],
                     'layout': bad}, warnings, protocol='mqtt', binary=True)
    check(any('does not match the example' in warning for warning in warnings),
          'a layout const that disagrees with the example is reported',
          ' | '.join(warnings)[:80])

    text_prompt = gt.build_prompt('mqtt', 'English', 1, [], None, 40)[1]
    binary_prompt = gt.build_prompt('mqtt', 'English', 1, [], None, 40,
                                    binary=True)[1]
    check('BINARY protocol' not in text_prompt
          and 'BINARY protocol' in binary_prompt
          and '"layout"' in binary_prompt and '"probe"' in binary_prompt,
          'only binary mode asks for the layout/probe contract')
    check('"request"' in text_prompt and '<<PLACEHOLDER_NAME>>' in text_prompt,
          'the text contract is unchanged')

    answer = os.path.join(tmpdir, 'mqtt-answer.json')
    with open(answer, 'w') as handle:
        json.dump({'templates': [entry]}, handle)
    out = os.path.join(tmpdir, 'mqtt-grammar')
    rc = gt.main(['mqtt', out, '--mode', 'binary', '--from-answer', answer,
                  '--quiet'])
    written = os.path.join(out, 'MQTT_CONNECT')
    check(rc == 0 and os.path.isfile(written)
          and open(written).read() == expected + '\n([\\x00-\\xff]+)',
          '--mode binary writes the derived template', 'rc=%d' % rc)
    meta = json.load(open(os.path.join(out, '.templates.json')))
    template = meta['templates'][0] if meta.get('templates') else {}
    check(template.get('probe') == entry['probe']
          and len(template.get('layout') or []) == len(layout),
          'the meta file records probe and layout')
    formats_path = os.path.join(out, '.binary-formats.json')
    check(os.path.isfile(formats_path),
          '--mode binary writes the shared .binary-formats.json')
    binary_formats = json.load(open(formats_path))
    check(binary_formats.get('framing', {}).get('length_offset') == 1
          and 'MQTT_CONNECT' in binary_formats.get('types', {}),
          'the formats file carries the framing and the type table')
    rc = gt.main(['--check', out, '--quiet'])
    check(rc == 0, '--check validates the binary formats against the template',
          'rc=%d' % rc)
    binary_formats['types']['MQTT_CONNECT']['example_hex'] = '100a0004585154540402003c'
    with open(formats_path, 'w') as handle:
        json.dump(binary_formats, handle)
    rc = gt.main(['--check', out, '--quiet'])
    check(rc == 1, '--check reports a layout that disagrees with the example',
          'rc=%d' % rc)


def test_check_flow(tmpdir):
    answer = os.path.join(tmpdir, 'answer.txt')
    with open(answer, 'w') as handle:
        handle.write(json.dumps({'templates': [
            {'type': 'USER', 'request': 'USER <<USERNAME>>\\r\\n',
             'placeholders': [{'name': 'USERNAME', 'example': 'anonymous'}]},
            {'type': 'PORT', 'request': 'PORT <<H1>>,<<H2>>,<<P1>>,<<P2>>'},
            {'type': 'NOOP', 'request': 'NOOP\\r\\n'}]}))
    out = os.path.join(tmpdir, 'ftp')
    code = gt.main(['ftp', out, '--from-answer', answer, '--quiet'])
    check(code == 0, 'generating from a captured answer exits 0', str(code))
    written = sorted(name for name in os.listdir(out) if not name.startswith('.'))
    check(written == ['PORT', 'USER'],
          'one file per message type is written, the static one skipped',
          repr(written))
    with open(os.path.join(out, 'USER')) as handle:
        check(handle.read() == REFERENCE_USER, 'the written file matches the format')

    seeds = os.path.join(tmpdir, 'seeds')
    os.makedirs(seeds)
    with open(os.path.join(seeds, 'seed_1.raw'), 'wb') as handle:
        handle.write(b'USER ubuntu\r\nPASS ubuntu\r\n')
    with open(os.path.join(seeds, 'seed_2.raw'), 'wb') as handle:
        handle.write(b'PORT 127,0,0,1,1,2\r\n')
    with open(os.path.join(seeds, 'seed_3.raw'), 'wb') as handle:
        handle.write(b'USER anonymous\r\nNOOP\r\n')

    code = gt.main(['--check', out, '--quiet'])
    check(code == 0, 'a directory written by this tool passes --check', str(code))

    code = gt.main(['--check', out, '--seeds', seeds, '--offline', '--quiet'])
    check(code == 0, 'the templates match a corpus that carries them', str(code))
    with open(os.path.join(out, '.check.json')) as handle:
        report = json.load(handle)
    check(report.get('USER', {}).get('matched') == 2
          and report.get('PORT', {}).get('matched') == 1
          and report.get('USER', {}).get('seeds') == 3,
          'the report counts the seeds of every message type', repr(report)[:120])

    extracted = os.path.join(tmpdir, 'per-type')
    code = gt.main(['--check', out, '--seeds', seeds, '--extract-seeds', seeds,
                    '--out-seeds', extracted, '--offline', '--quiet'])
    check(code == 0, 'the per type corpus extraction succeeds', str(code))
    user_dir = os.path.join(extracted, 'USER')
    check(os.path.isdir(user_dir) and len(os.listdir(user_dir)) == 2,
          'one extracted message per matching seed',
          repr(os.listdir(user_dir) if os.path.isdir(user_dir) else None))
    with open(os.path.join(user_dir, sorted(os.listdir(user_dir))[0]), 'rb') as handle:
        check(handle.read().endswith(b'\r\n'), 'the extracted message keeps its CRLF')

    foreign = os.path.join(tmpdir, 'foreign')
    os.makedirs(foreign)
    with open(os.path.join(foreign, 'USER'), 'w') as handle:
        handle.write('^(?:USER (.*))')
    code = gt.main(['ftp', foreign, '--from-answer', answer, '--quiet'])
    check(code == 1, 'files this tool did not write are protected', str(code))
    code = gt.main(['ftp', foreign, '--from-answer', answer, '--force', '--quiet'])
    check(code == 0, '--force overwrites them', str(code))

    empty = os.path.join(tmpdir, 'mismatch')
    code = gt.main(['--check', out, '--seeds', seeds, '--offline', '--quiet',
                    '--strict'])
    check(code == 0, '--strict still accepts a clean run', str(code))


def test_cli(tmpdir):
    tool = os.path.join(HERE, 'gen_templates.py')
    env = dict(os.environ)
    for name in ('LLM_API_KEY', 'OPENAI_API_KEY', 'AZURE_OPENAI_API_KEY'):
        env.pop(name, None)

    proc = subprocess.Popen([sys.executable, tool, '--dump-prompt', 'ftp', 'out',
                             '--lang', 'en'], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)
    out, _ = proc.communicate()
    out = out.decode('utf-8', 'replace')
    check(proc.returncode == 0 and 'system (round 1)' in out and 'USER' in out,
          '--dump-prompt prints the prompt without contacting the endpoint',
          str(proc.returncode))

    proc = subprocess.Popen([sys.executable, tool, 'ftp', 'out', '--offline'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    proc.communicate()
    check(proc.returncode == 2, '--offline without --from-answer is an argument '
          'error', str(proc.returncode))

    proc = subprocess.Popen([sys.executable, tool, 'ftp'], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)
    proc.communicate()
    check(proc.returncode == 2, 'a missing output directory is an argument error',
          str(proc.returncode))

    proc = subprocess.Popen([sys.executable, tool, '--version'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    out, _ = proc.communicate()
    check(proc.returncode == 0 and out.decode().strip() == gt.VERSION,
          '--version prints the version')


def test_llmclient_shim(tmpdir):
    """The shim must forward, never delegate to itself (regression guard)."""
    sibling = os.path.join(os.path.dirname(HERE), 'statevar', 'llmclient.py')
    probe = os.path.join(tmpdir, 'shim_probe.py')
    if os.path.isfile(sibling):
        source = (
            'import sys\n'
            'sys.path.insert(0, %r)\n'   # mirrors `python3 <tool>/gen_templates.py`
            'import llmclient\n'
            'print("available", llmclient.available())\n'
            'print("selfloop", llmclient._shared is llmclient)\n'
            'print("client", llmclient.ChatClient.__name__)\n' % HERE)
        expect_available = True
    else:
        # Same shim, but with no sibling: SHARED then points at a missing dir.
        lonely = os.path.join(tmpdir, 'lonely')
        os.mkdir(lonely)
        with open(os.path.join(HERE, 'llmclient.py')) as src:
            text = src.read()
        with open(os.path.join(lonely, 'llmclient.py'), 'w') as dst:
            dst.write(text)
        source = (
            'import sys\n'
            'sys.path.insert(0, %r)\n'
            'import llmclient\n'
            'print("available", llmclient.available())\n'
            'print("hint", len(llmclient.hint()) > 0)\n'
            'try:\n'
            '    llmclient.ChatClient()\n'
            'except RuntimeError:\n'
            '    print("explains", True)\n' % lonely)
        expect_available = False
    with open(probe, 'w') as handle:
        handle.write(source)
    proc = subprocess.Popen([sys.executable, probe], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate()
    out = out.decode('utf-8', 'replace')
    tail = err.decode('utf-8', 'replace').strip().splitlines()[-1:]
    detail = tail[0] if tail else ''

    if expect_available:
        check(proc.returncode == 0, 'the shim imports without recursing', detail)
        check('available True' in out, 'the shared chat client is reachable',
              out.strip())
        check('selfloop False' in out,
              'the shim forwards to utils/AI-agent/statevar, not to itself', out.strip())
        check('client ChatClient' in out,
              'llmclient.ChatClient resolves to the shared class', out.strip())
    else:
        check(proc.returncode == 0,
              'the shim still imports when utils/AI-agent/statevar is missing', detail)
        check('available False' in out and 'hint True' in out and
              'explains True' in out,
              'a missing utils/AI-agent/statevar gives a hint instead of a crash',
              out.strip())


def main():
    tmpdir = tempfile.mkdtemp(prefix='pro-template-selftest-')
    try:
        print('[*] text helpers and request conversion')
        test_text_helpers()
        test_header_shapes()
        test_multiline_requests()
        print('[*] model answer parsers')
        test_answer_parsers()
        print('[*] prompts')
        test_prompt()
        print('[*] agent (--root)')
        test_agent_round(tmpdir)
        print('[*] binary mode')
        test_binary_mode(tmpdir)
        print('[*] generating and checking a directory')
        test_check_flow(tmpdir)
        print('[*] command line')
        test_cli(tmpdir)
        print('[*] shared chat client')
        test_llmclient_shim(tmpdir)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    if FAILED:
        print('[!] %d expectation(s) failed:' % len(FAILED))
        for label in FAILED:
            print('[!]   %s' % label)
        return 1
    print('[+] grammar template generator looks correct')
    return 0


if __name__ == '__main__':
    sys.exit(main())
