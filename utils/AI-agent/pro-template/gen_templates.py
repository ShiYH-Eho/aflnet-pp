#!/usr/bin/env python3
"""Extract protocol grammar templates with an LLM (AFLNet++ ``AFLNET_GRAMMAR``).

The tool asks an OpenAI-compatible chat model for one description per *client
request type* of a protocol, converts every answer into the two line template
format consumed by ``src/aflnet/utils/grammar.c`` and writes one file per
message type into a directory that the fuzzer can use directly::

    python3 utils/AI-agent/pro-template/gen_templates.py ftp  grammars/ftp
    python3 utils/AI-agent/pro-template/gen_templates.py imap grammars/imap --types APPEND
    AFLNET_GRAMMAR=grammars/ftp ./afl-fuzz -N tcp://127.0.0.1/2200 ...

Template file format (file name = message type, no comments, no blank lines)::

    ^(?:SETUP (.*)\r\n)
    (?|(?:CSeq: (.*)\r\n)|(?:User-Agent: (.*)\r\n)|(?:\r\n)|(?:Transport: (.*)\r\n))

  * line 1 is a PCRE2 pattern matched against the message region from offset 0;
    every capture group is a mutable field;
  * line 2 (and everything after it) is one PCRE2 pattern used to find further
    mutable fields; ``(.+)`` is the default.

A request that spans several lines -- a request line followed by headers, as
RTSP, SIP and HTTP write them -- is split the way the example above is split:
the first line, the one that carries the message type, becomes line 1 and the
other lines become the alternatives of line 2, so the header match ends with the
request line and the fields are found from there on (``template_collect_fields()``
in ``src/aflnet/utils/grammar.c``).

Two offline entry points are available as well::

    # re-check / inspect a directory that was written earlier
    python3 utils/AI-agent/pro-template/gen_templates.py --check grammars/ftp

    # convert an already captured model answer, no network involved
    python3 utils/AI-agent/pro-template/gen_templates.py ftp grammars/ftp --from-answer a.txt

``--check`` also compares every template against a corpus of seeds
(``--seeds DIR``, default ``profuzzbench/aflnet-pp/bin-corpus`` when present) and
can derive a per type seed corpus with ``--extract-seeds DIR``.

Exit codes: 0 success, 1 error (endpoint, no template at all), 2 argument error.
"""

from __future__ import print_function

import argparse
import json
import os
import re
import shutil
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
SHARED = os.path.dirname(HERE)          # utils/AI-agent: agent.py/localtools.py
if SHARED not in sys.path:
    sys.path.insert(0, SHARED)

import agent  # noqa: E402
import formats  # noqa: E402  (shared with corpus-enrich)
import llmclient  # noqa: E402  (shim next to this file, re-exports utils/AI-agent/statevar)
import localtools  # noqa: E402

VERSION = '1.0.0'

DEFAULT_FIELD_PATTERN = '(.+)'
#: line 2 of a binary template: a capture group (so the tail becomes a window)
#: that matches every remaining byte, including NUL and newline bytes.
BINARY_FIELD_PATTERN = '([\\x00-\\xff]+)'
BYTE_CLASS = '[\\x00-\\xff]'
VARINT_BODY = '[\\x80-\\xff]*[\\x00-\\x7f]'
REQUEST_KEYS = ('request', 'message', 'template', 'syntax', 'shape', 'example',
                'request_template', 'pattern')
#: ``size``/``kind`` spellings a binary layout may use.
LAYOUT_SIZES = {
    'byte': 1, 'char': 1, 'u8': 1, 'uint8': 1, 'int8': 1, 'i8': 1,
    'bool': 1, 'boolean': 1, 'octet': 1,
    'u16': 2, 'uint16': 2, 'int16': 2, 'i16': 2, 'short': 2, 'word': 2,
    'u32': 4, 'uint32': 4, 'int32': 4, 'i32': 4, 'dword': 4, 'float': 4,
    'u64': 8, 'uint64': 8, 'int64': 8, 'i64': 8, 'double': 8,
}
VARIABLE_LAYOUT_KINDS = ('varint', 'length_prefixed', 'bytes', 'string', 'blob',
                         'tlv', 'repeat', 'payload')
CONST_LAYOUT_KINDS = ('const', 'magic', 'literal')
DEFAULT_BASE_URL = 'https://api.deepseek.com'
DEFAULT_MODEL = 'deepseek-flash'
DEFAULT_MAX_TYPES = 40
META_NAME = '.templates.json'
DISPLAY_WIDTH = 68
TYPE_TOKEN = re.compile(r'[A-Za-z0-9_]+')

LANGUAGES = {
    'en': 'English',
    'zh': 'Simplified Chinese',
    'de': 'German',
    'fr': 'French',
    'ja': 'Japanese',
    'ko': 'Korean',
    'es': 'Spanish',
    'ru': 'Russian',
    'pt': 'Portuguese',
    'it': 'Italian',
}

# Grounding hints for the protocols AFLNet++ ships a request parser for.  The
# list is intentionally incomplete: anything unknown is still accepted, the
# hint only makes the prompt more precise.
PROTOCOL_NOTES = {
    'ftp': 'Client commands are CRLF terminated lines: a 3-4 letter verb with '
           'optional arguments, e.g. USER, PASS, ACCT, CWD, CDUP, QUIT, PORT, '
           'PASV, TYPE, STRU, MODE, RETR, STOR, STOU, APPE, ALLO, REST, RNFR, '
           'RNTO, ABOR, DELE, RMD, MKD, PWD, LIST, NLST, SITE, SYST, STAT, '
           'HELP, NOOP, FEAT, OPTS, SIZE, MDTM, EPRT, EPSV, AUTH, PBSZ, PROT, '
           'MLSD, MLST.',
    'smtp': 'Client commands are CRLF terminated: HELO, EHLO, MAIL FROM:<...>, '
            'RCPT TO:<...>, DATA (followed by the message body and a lone "." '
            'line), RSET, VRFY, EXPN, HELP, NOOP, QUIT, AUTH, STARTTLS.',
    'rtsp': 'Requests are "METHOD URI RTSP/1.0" CRLF lines with headers: '
            'OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER, '
            'SET_PARAMETER, ANNOUNCE, RECORD, REDIRECT.',
    'sip': 'Requests are "METHOD sip:uri SIP/2.0" CRLF lines with headers: '
           'INVITE, ACK, CANCEL, BYE, REGISTER, OPTIONS, SUBSCRIBE, NOTIFY, '
           'REFER, INFO, PRACK, MESSAGE, UPDATE.',
    'http': 'Requests are "METHOD SP request-target SP HTTP/1.1" CRLF lines '
            'with headers and an optional body: GET, HEAD, POST, PUT, DELETE, '
            'OPTIONS, TRACE, CONNECT, PATCH.',
    'imap': 'Commands are CRLF terminated lines that start with a tag: '
            'CAPABILITY, NOOP, LOGOUT, STARTTLS, AUTHENTICATE, LOGIN, SELECT, '
            'EXAMINE, CREATE, DELETE, RENAME, SUBSCRIBE, UNSUBSCRIBE, LIST, '
            'LSUB, STATUS, APPEND, CHECK, CLOSE, EXPUNGE, SEARCH, FETCH, '
            'STORE, COPY, UID.',
    'pop3': 'Commands are CRLF terminated keywords: USER, PASS, APOP, STAT, '
            'LIST, RETR, DELE, NOOP, RSET, QUIT, TOP, UIDL, CAPA, AUTH.',
    'tls': 'TLS records are a 5 byte record header (content type, version, '
           'length) followed by the body; client records are ClientHello, '
           'ClientKeyExchange, ChangeCipherSpec and ApplicationData.',
    'dns': 'Messages are a 12 byte header (id, flags, counts) followed by the '
           'question and resource record sections; names are length prefixed '
           'labels.',
    'dhcp': 'Messages are a 236 byte BOOTP header (op, htype, hlen, hops, xid, '
            'secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file), '
            'the magic cookie 0x63825363 and a TLV options list (53 = type).',
    'mqtt': 'Binary packets: a 1 byte fixed header (packet type in the high '
            'nibble, remaining length varint) then the variable header and '
            'payload; client packets are CONNECT, PUBLISH, PUBACK, PUBREC, '
            'PUBREL, PUBCOMP, SUBSCRIBE, UNSUBSCRIBE, PINGREQ, DISCONNECT.',
    'ssh': 'A version line such as "SSH-2.0-libssh_0.9.6\\r\\n" followed by '
           'binary packets: 4 byte packet length, 1 byte padding length, '
           'payload, padding, MAC; client payloads are KEXINIT, KEXDH_INIT, '
           'SERVICE_REQUEST, USERAUTH_REQUEST, CHANNEL_OPEN, CHANNEL_REQUEST.',
    'snmp': 'BER/DER encoded messages: a sequence with the version, the '
            'community string and a PDU (GetRequest, GetNextRequest, '
            'GetBulkRequest, SetRequest, InformRequest, Trap, Report).',
    'dicom': 'Upper layer PDUs: a 1 byte type, 1 reserved byte, a 4 byte '
             'length and the body: A-ASSOCIATE-RQ, P-DATA-TF, A-RELEASE-RQ, '
             'A-ABORT.',
    'modbus': 'TCP frames: a 7 byte MBAP header (transaction id, protocol id, '
              'length, unit id), a 1 byte function code and data: 1 read '
              'coils, 2 read discrete inputs, 3 read holding registers, '
              '4 read input registers, 5 write single coil, 6 write single '
              'register, 15/16 write multiple.',
    'smpp': 'PDUs: a 4 byte length, 4 byte command id, 4 byte status, 4 byte '
            'sequence number then the body: bind_transmitter, bind_receiver, '
            'bind_transceiver, submit_sm, deliver_sm, enquire_link, unbind, '
            'cancel_sm, replace_sm, query_sm.',
}

# Protocols whose request messages are CRLF terminated lines.  When the model
# forgets the terminator it is appended, exactly like the reference templates
# shipped with ChatState (``^(?:SETUP (.*)\r\n)``): the mutable capture then
# stops before CR LF instead of swallowing the CR.
CRLF_PROTOCOLS = frozenset((
    'ftp', 'smtp', 'imap', 'pop3', 'nntp', 'irc', 'rtsp', 'sip', 'telnet',
    'finger', 'gopher',
))


# ---------------------------------------------------------------------------
# text helpers
# ---------------------------------------------------------------------------

SPECIAL_CHARS = '\\^$.|?*+()[]{}'
HEX_DIGITS = '0123456789abcdefABCDEF'
_VAR_MARKER = re.compile(r'<<([^<>]*)>>')
_VAR_BRACE = re.compile(r'\{\{([^{}]*)\}\}')


def shorten(text, width=DISPLAY_WIDTH):
    text = str(text)
    return text if len(text) <= width else text[:width - 3] + '...'


def normalize_escapes(text, regex_style=False, binary=False):
    """Turn literal backslash escapes of a model answer into real characters.

    A chat model writes protocol bytes as "\\r\\n" (four characters), so those
    have to become CR LF before the pattern is built.  ``regex_style`` also
    accepts the escapes a regular expression author would use (``\\x0d``,
    ``\\.`` for a literal dot).  ``binary`` accepts ``\\xNN`` without the other
    regex-author conveniences, which is what a binary protocol answer needs;
    text mode keeps the historical behaviour so its templates do not change.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch != '\\' or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt == 'r':
            out.append('\r')
            i += 2
        elif nxt == 'n':
            out.append('\n')
            i += 2
        elif nxt == 't':
            out.append('\t')
            i += 2
        elif nxt == '0':
            out.append('\0')
            i += 2
        elif nxt == '\\':
            out.append('\\')
            i += 2
        elif (regex_style or binary) and nxt == 'x' and i + 4 <= n and \
                all(c in HEX_DIGITS for c in text[i + 2:i + 4]):
            out.append(chr(int(text[i + 2:i + 4], 16)))
            i += 4
        elif regex_style and not nxt.isalnum():
            out.append(nxt)
            i += 2
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def escape_literal(text):
    """Escape protocol bytes for a single line PCRE2 pattern."""
    out = []
    for ch in text:
        if ch in SPECIAL_CHARS:
            out.append('\\' + ch)
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\t':
            out.append('\\t')
        elif 0x20 <= ord(ch) <= 0x7e:
            out.append(ch)
        else:
            out.append('\\x%02x' % ord(ch))
    return ''.join(out)


def to_single_line(pattern):
    """Keep a model supplied pattern on one line (the fuzzer splits at '\\n')."""
    pattern = pattern.replace('\r\n', '\\r\\n')
    pattern = pattern.replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')
    return pattern.strip()


def marker_segments(request):
    """Split a template request on <<placeholders>> / {{placeholders}}."""
    request = _VAR_BRACE.sub(lambda m: '<<%s>>' % m.group(1), request)
    marked = '<<' in request
    segs = []
    pos = 0
    found = 0
    for match in _VAR_MARKER.finditer(request):
        if match.start() > pos:
            segs.append(('lit', request[pos:match.start()]))
        segs.append(('var', match.group(1).strip()))
        pos = match.end()
        found += 1
    if pos < len(request):
        segs.append(('lit', request[pos:]))
    balanced = True
    if marked:
        leftover = ''.join(value for kind, value in segs if kind == 'lit')
        balanced = found > 0 and '<<' not in leftover and '>>' not in leftover
    return segs, marked, balanced


def matching_paren(text, start):
    """Index of the ')' closing the '(' at ``start``, or -1."""
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch == '\\':
            i += 2
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def strip_outer_noncapture(text):
    """``(?:X)`` -> ``X`` when that group wraps the whole pattern."""
    if not text.startswith('(?:'):
        return None
    end = matching_paren(text, 0)
    if end != len(text) - 1:
        return None
    return text[4:end]


def scan_groups(text):
    """Split a pattern into literal and capture group segments, or None."""
    segs = []
    pos = 0
    depth = 0
    start = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '\\':
            i += 2
            continue
        if ch == '(':
            if depth == 0:
                if i > pos:
                    segs.append(('lit', text[pos:i]))
                start = i
            depth += 1
        elif ch == ')':
            if depth == 0:
                return None
            depth -= 1
            if depth == 0:
                body = text[start + 1:i]
                if not body.strip():
                    return None
                segs.append(('var', body))
                pos = i + 1
        i += 1
    if depth:
        return None
    if pos < n:
        segs.append(('lit', text[pos:]))
    return segs


def regex_segments(request):
    """Read a model answer written as a regular expression, or None."""
    text = request.strip()
    if text.startswith('^'):
        text = text[1:]
    if text.endswith('$'):
        text = text[:-1]
    inner = strip_outer_noncapture(text)
    if inner is not None:
        text = inner
    if '(' not in text or '|' in text or '(?:' in text:
        return None
    segs = scan_groups(text)
    if segs is None:
        return None
    if not any(kind == 'var' for kind, _ in segs):
        return None
    return segs


# ---------------------------------------------------------------------------
# request description -> (header pattern, example message)
# ---------------------------------------------------------------------------

def sanitize_type(name):
    """Make a message type safe to use as a file name."""
    if name is None:
        return None
    text = re.sub(r'\s+', '_', str(name).strip().strip('\'"`'))
    if re.match(r'^[A-Z][A-Z0-9_+.-]{0,31}$', text):
        return text
    text = re.sub(r'[^A-Za-z0-9.+_-]', '', text).strip('._-+')
    if not text or len(text) > 64:
        return None
    return text


def collect_placeholders(entry):
    """Normalize the placeholder list of an entry."""
    for key in ('placeholders', 'variables', 'vars', 'arguments', 'args',
                'parameters', 'params', 'fields'):
        value = entry.get(key)
        if not isinstance(value, list) or not value:
            continue
        out = []
        for item in value:
            if isinstance(item, dict):
                out.append(item)
            elif isinstance(item, str) and item.strip():
                out.append({'name': item.strip()})
        if out:
            return out
    return []


def first_str(entry, keys, keep_newlines=False):
    """First non-empty string of ``keys``.

    ``keep_newlines`` keeps the line breaks of the value (bar the leading and
    trailing whitespace noise): the trailing ``\\r\\n`` of a request is what tells
    a command (``USER x\\r\\n``) from a request with a header block
    (``SETUP x\\r\\nCSeq: 2\\r\\n\\r\\n``), which decides whether the message type
    line becomes the header pattern and the other lines the field pattern.
    """
    for key in keys:
        value = entry.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        if keep_newlines:
            return value.lstrip(' \t\r\n').rstrip(' \t')
        return value.strip()
    return None


def first_raw(entry, keys):
    """First non-empty string of ``keys`` without stripping its edges.

    Binary examples may legitimately start or end with whitespace bytes, so
    ``build_record`` cannot trim them the way it trims a textual request.
    """
    for key in keys:
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def decode_byte_value(value):
    """Bytes described by a layout ``value`` (``"0x10"``, ``"\\x10"``, ``"MQTT"``)."""
    if isinstance(value, bool) or isinstance(value, int):
        return None                      # the field's size carries an integer
    if isinstance(value, (list, tuple)):
        try:
            return bytes(int(item) & 0xff for item in value)
        except (TypeError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.lower().startswith('0x') and len(text) > 2:
        digits = text[2:]
        if not all(c in HEX_DIGITS for c in digits):
            return None
        return int(digits, 16).to_bytes((len(digits) + 1) // 2, 'big')
    if '\\x' in text or '\\0' in text:
        return normalize_escapes(text, binary=True).encode('latin-1', 'replace')
    return text.encode('latin-1', 'replace')


def layout_size(field):
    """Byte width of a layout field, or ``None`` for a variable size."""
    size = field.get('size')
    if isinstance(size, bool):
        size = None
    if isinstance(size, int):
        return size if size > 0 else None
    if isinstance(size, str):
        text = size.strip().lower()
        if text.isdigit():
            return int(text)
        if text in LAYOUT_SIZES:
            return LAYOUT_SIZES[text]
    kind = str(field.get('kind') or '').strip().lower()
    if kind in LAYOUT_SIZES:
        return LAYOUT_SIZES[kind]
    if kind in CONST_LAYOUT_KINDS:
        data = decode_byte_value(field.get('value'))
        if data:
            return len(data)
    return None


def layout_is_varint(field):
    """True when ``size`` or ``kind`` marks a LEB128-encoded varint."""
    size = field.get('size')
    size_text = size.strip().lower() if isinstance(size, str) else ''
    kind = str(field.get('kind') or '').strip().lower()
    return size_text in ('varint', 'leb128') or kind in ('varint', 'leb128')


def layout_to_template(example, layout, warnings, type_name):
    """Derive a binary header pattern from a byte example + field layout.

    Fields are emitted in byte order.  ``mutable`` fields become capture groups
    (the fuzzer may change them), ``const``/``magic`` fields become literals,
    and every other field (version, length, checksum, padding, ...) becomes a
    non-capturing byte class: it has to be present but is not turned into a
    mutation window.  Bytes after the last described field belong to the field
    pattern (line 2), which is where a variable payload goes.
    """
    if not isinstance(example, str) or not example:
        return None
    if not isinstance(layout, list) or not layout:
        return None
    label = type_name or '?'
    fields, cursor = [], 0
    for index, item in enumerate(layout):
        if not isinstance(item, dict):
            continue
        offset = item.get('offset')
        if isinstance(offset, str) and offset.strip().isdigit():
            offset = int(offset.strip())
        if not isinstance(offset, int) or offset < 0:
            offset = cursor
        size = layout_size(item)
        kind = str(item.get('kind') or '').strip().lower()
        varint = layout_is_varint(item)
        variable = varint or (size is None and kind in VARIABLE_LAYOUT_KINDS)
        if size is None and not variable:
            warnings.append('%s: layout field %r has no size, skipped'
                            % (label, item.get('name') or index))
            continue
        mutable = item.get('mutable')
        if isinstance(mutable, str):
            mutable = mutable.strip().lower() in ('true', '1', 'yes', 'y')
        fields.append({'name': str(item.get('name') or 'field%d' % index),
                       'offset': offset, 'size': size, 'kind': kind,
                       'mutable': bool(mutable), 'variable': variable,
                       'varint': varint, 'value': item.get('value')})
        cursor = offset + (size or 0)
    if not fields:
        return None

    fields.sort(key=lambda field: field['offset'])
    parts, cursor, variables, gaps = [], 0, 0, 0
    covered_by_variable = False
    limit = len(example)
    for field in fields:
        offset = field['offset']
        if offset > limit:
            warnings.append('%s: layout field %r starts past the example '
                            '(offset %d)' % (label, field['name'], offset))
            continue
        if offset < cursor:
            warnings.append('%s: layout field %r overlaps the previous field'
                            % (label, field['name']))
            continue
        if offset > cursor and not covered_by_variable:
            parts.append(escape_literal(example[cursor:offset]))
            gaps += offset - cursor
        if field['variable']:
            body = VARINT_BODY if field['varint'] else BYTE_CLASS + '+'
            if field['mutable']:
                parts.append('(%s)' % body)
                variables += 1
            else:
                parts.append('(?:%s)' % body)
            cursor = offset             # the encoded length is unknown
            covered_by_variable = True
            continue
        size = int(field['size'])
        if offset + size > limit:
            warnings.append('%s: layout field %r runs past the example'
                            % (label, field['name']))
            continue
        raw = example[offset:offset + size]
        expected = decode_byte_value(field.get('value'))
        if expected is not None and expected != raw.encode('latin-1', 'replace'):
            warnings.append('%s: layout value of %r does not match the example'
                            % (label, field['name']))
        if field['mutable']:
            parts.append('(%s{%d})' % (BYTE_CLASS, size))
            variables += 1
        elif field['kind'] in CONST_LAYOUT_KINDS:
            parts.append(escape_literal(raw))
        else:
            parts.append('(?:%s{%d})' % (BYTE_CLASS, size))
        cursor = offset + size
        covered_by_variable = False
    if not parts:
        return None
    header = '^(?:%s)' % ''.join(parts)
    notes = ['binary layout: %d field(s), %d mutable'
             % (len(fields), variables)]
    if gaps:
        notes.append('%d byte(s) not described by the layout stayed literal' % gaps)
    return {'header': header, 'fields': None, 'example': example,
            'variables': variables, 'notes': notes}


def substitute_example(segs, placeholders, binary=False):
    """Build a concrete message from the request template and the placeholders."""
    named = {}
    ordered = []
    for item in placeholders or []:
        if isinstance(item, dict):
            name = item.get('name') or item.get('placeholder') or item.get('var')
            example = item.get('example') or item.get('value') or item.get('sample')
            if name:
                named[str(name).strip().lower()] = example
        else:
            ordered.append(str(item))
    parts = []
    index = 0
    for kind, value in segs:
        if kind == 'lit':
            parts.append(normalize_escapes(value, binary=binary))
            continue
        example = named.get(value.lower()) if value else None
        if example is None and index < len(ordered):
            example = ordered[index]
        index += 1
        if example:
            parts.append(normalize_escapes(str(example), binary=True)
                         if binary else str(example))
        else:
            parts.append('x')
    return ''.join(parts)


def apply_terminator(header, example, protocol, binary=False):
    """Shape ``^BODY`` into the reference layout ``^(?:BODY<CRLF>)$``.

    A CRLF protocol gets its terminator appended when the model omitted it, so
    the last mutable capture ends before CR LF.  ``$`` is only added when the
    pattern is known to cover the whole message (terminator present); an
    unfinished description such as an HTTP request line without its headers
    keeps matching as a prefix instead of being rejected outright.  A binary
    message never gets a terminator or ``$``: it is matched as a prefix.
    """
    body = header[1:] if header.startswith('^') else header
    if binary:
        return '^(?:%s)' % body, example
    term = '\\r\\n' if (protocol or '').strip().lower() in CRLF_PROTOCOLS else None
    complete = body.endswith('\\n')
    if term and not complete:
        body += term
        complete = True
        if example is not None and not example.endswith(('\r\n', '\n')):
            example += '\r\n'
    return '^(?:%s)%s' % (body, '$' if complete else ''), example


def request_lines(segs, regex_style, binary=False):
    """Split the segments of a request on the line breaks inside its literals.

    Returns one token list per line -- ``('lit', text)`` / ``('var', name)`` --
    with the line breaks themselves dropped: they are put back as the terminator
    of the pattern line built from that list, and the terminator of the last line
    is dropped with it (``apply_terminator``/the multi line builder re-add it).
    """
    if binary:
        # a binary payload may contain 0x0d/0x0a as data: never split it
        return [[(kind, normalize_escapes(value, binary=True) if kind == 'lit'
                  else value) for kind, value in segs]]
    lines = [[]]
    for kind, value in segs:
        if kind != 'lit':
            lines[-1].append((kind, value))
            continue
        parts = re.split(r'\r\n|\n',
                         normalize_escapes(value, regex_style=regex_style))
        for index, part in enumerate(parts):
            if index:
                lines.append([])
            if part:
                lines[-1].append(('lit', part))
    if len(lines) > 1 and not lines[-1]:
        lines.pop()
    return lines


def line_pattern(line, binary=False):
    """PCRE2 body of one request line: literals escaped, placeholders captured."""
    wildcard = '([\\x00-\\xff]+)' if binary else '(.*)'
    return ''.join(escape_literal(value) if kind == 'lit' else wildcard
                   for kind, value in line)


def segments_to_template(segs, example, protocol, regex_style, notes, binary=False):
    """Build (header pattern, field pattern, example, variables, notes).

    A request that spans several lines -- a request line followed by headers, as
    RTSP, SIP, HTTP and the mail protocols write them -- is split the way the
    reference templates of ChatState are split: the *first* line, the one that
    carries the message type, becomes the header pattern and every remaining line
    becomes an alternative of the field pattern::

        ^(?:SETUP (.*)\\r\\n)
        (?|(?:CSeq: (.*)\\r\\n)|(?:User-Agent: (.*)\\r\\n)|(?:\\r\\n)|(?:Transport: (.*)\\r\\n))

    so the header match ends with the request line and
    ``template_collect_fields()`` finds the fields from there on.  A single line
    request keeps the one line layout of the reference corpus, ``^(?:BODY\\r\\n)$``
    with the default ``(.+)`` field pattern.
    """
    if binary:
        lines = request_lines(segs, regex_style, binary=True)
        body = line_pattern(lines[0] if lines else [], binary=True)
        header, example = apply_terminator('^' + body, example, protocol,
                                           binary=True)
        variables = sum(1 for kind, _ in segs if kind == 'var')
        return header, None, example, variables, notes
    lines = request_lines(segs, regex_style)
    crlf = (protocol or '').strip().lower() in CRLF_PROTOCOLS
    term = '\\r\\n' if crlf else '\\n'
    variables = sum(1 for kind, _ in segs if kind == 'var')
    if len(lines) <= 1:
        body = line_pattern(lines[0]) if lines else ''
        header, example = apply_terminator('^' + body, example, protocol)
        return header, None, example, variables, notes
    if crlf and example is not None:
        # a model that wrote real line breaks loses the trailing ones to the
        # strip() above, so make sure the last header line is terminated
        example = example.replace('\r\n', '\n').replace('\n', '\r\n')
        if not example.endswith('\r\n'):
            example += '\r\n'
    header = '^(?:%s%s)' % (line_pattern(lines[0]), term)
    alternatives = ['(?:%s%s)' % (line_pattern(line), term) for line in lines[1:]]
    fields = '|'.join(alternatives)
    if len(alternatives) > 1:
        fields = '(?|%s)' % fields
    notes = list(notes)
    notes.append('the request has %d lines: line 1 is the header pattern, the '
                 'other %d became the field pattern'
                 % (len(lines), len(lines) - 1))
    return header, fields, example, variables, notes


def request_to_header(request, placeholders, warnings, type_name, protocol=None,
                      binary=False):
    """Convert one request description into a pattern + field pattern + example."""
    # Trailing line breaks are kept: they are what tells a multi line request
    # (request line + headers + empty line) from a single line command.
    request = (request or '').lstrip(' \t\r\n').rstrip(' \t')
    if not request:
        return None
    label = type_name or '?'
    segs, marked, balanced = marker_segments(request)
    if marked and not balanced:
        warnings.append('%s: unbalanced <<...>> placeholder markers, treating the '
                        'request as a regular expression' % label)
    elif marked:
        header, fields, example, variables, notes = segments_to_template(
            segs, substitute_example(segs, placeholders, binary=binary),
            protocol, False, [], binary=binary)
        return {
            'header': header,
            'fields': fields,
            'example': example,
            'variables': variables,
            'notes': notes,
        }
    segs = regex_segments(request)
    if segs is not None:
        header, fields, _example, variables, notes = segments_to_template(
            segs, None, protocol, True,
            ['converted from a regular expression; the example message and the '
             'field values could not be verified'], binary=binary)
        return {
            'header': header,
            'fields': fields,
            'example': None,
            'variables': variables,
            'notes': notes,
        }
    if '(' in request or request.startswith('^'):
        warnings.append('%s: could not convert the request expression, treating it '
                        'as a literal message' % label)
    header, _ = apply_terminator('^' + escape_literal(normalize_escapes(request,
                                                                       regex_style=True,
                                                                       binary=binary)),
                                 None, protocol, binary=binary)
    return {
        'header': header,
        'fields': None,
        'example': None,
        'variables': 0,
        'notes': ['no variable field found; the template is static'],
    }


def pattern_to_regex(pattern):
    """Translate a PCRE2 template pattern into something Python re accepts.

    Python never sees the templates (``grammar.c`` compiles them with PCRE2);
    this is only used to report obviously broken answers to the user.
    """
    text = pattern
    text = text.replace('\\r', '\r').replace('\\n', '\n').replace('\\t', '\t')
    text = re.sub(r'\(\?<([A-Za-z_][A-Za-z0-9_]*)>', r'(?P<\1>', text)
    text = re.sub(r'\(\?P<([A-Za-z_][A-Za-z0-9_]*)>', r'(?P<\1>', text)
    text = re.sub(r"\(\?'([A-Za-z_][A-Za-z0-9_]*)'", r'(?P<\1>', text)
    text = re.sub(r'\\k<([A-Za-z_][A-Za-z0-9_]*)>', r'(?P=\1)', text)
    text = re.sub(r'\\k\'([A-Za-z_][A-Za-z0-9_]*)\'', r'(?P=\1)', text)
    text = re.sub(r'\\x\{([0-9A-Fa-f]+)\}', lambda m: chr(int(m.group(1), 16)), text)
    return text


def compile_pattern(pattern):
    """Return (compiled, error); ``compiled`` is None when the pattern is bad."""
    translated = pattern_to_regex(pattern)
    try:
        return re.compile(translated), None
    except Exception as exc:  # re.error, ValueError, ...
        return None, str(exc)


# ---------------------------------------------------------------------------
# tolerant parsing of the model answer
# ---------------------------------------------------------------------------

FENCE_RE = re.compile(r'^\s*```[A-Za-z0-9_+-]*\s*$')
LINE_ENTRY_RE = re.compile(
    r'^\s*(?:[-*+]\s*)?(?:\*\*)?([A-Za-z][A-Za-z0-9_+.-]{0,31})(?:\*\*)?\s*[:=]\s*(.*)$')
ENTRY_KEYS = {
    'header', 'header_pattern', 'request_pattern', 'request', 'request_template',
    'message', 'template', 'syntax', 'shape', 'example', 'fields', 'field_pattern',
    'fields_pattern', 'tail_pattern', 'placeholders', 'variables', 'vars',
    'arguments', 'args', 'parameters', 'description', 'meaning', 'purpose',
    'notes', 'type', 'name', 'message_type', 'command', 'method',
}
WRAPPER_KEYS = ('templates', 'grammar_templates', 'requests', 'commands',
                'message_types', 'types', 'messages', 'type_templates', 'grammars',
                'grammar', 'results', 'result', 'data', 'answer')
# Lower case keys that name the message type of the entry that follows them.
META_KEYS = frozenset(('type', 'name', 'msg_type', 'message_type', 'command',
                       'method'))


def strip_code_fences(text):
    lines = []
    for line in (text or '').splitlines():
        if FENCE_RE.match(line):
            continue
        lines.append(line)
    return '\n'.join(lines)


def json_blocks(text):
    """Yield the balanced [...] / {...} blocks of a text."""
    for opener, closer in (('[', ']'), ('{', '}')):
        pos = 0
        while True:
            start = text.find(opener, pos)
            if start < 0:
                break
            depth = 0
            in_string = False
            escaped = False
            for i in range(start, len(text)):
                ch = text[i]
                if in_string:
                    if escaped:
                        escaped = False
                    elif ch == '\\':
                        escaped = True
                    elif ch == '"':
                        in_string = False
                    continue
                if ch == '"':
                    in_string = True
                elif ch == opener:
                    depth += 1
                elif ch == closer:
                    depth -= 1
                    if depth == 0:
                        yield text[start:i + 1]
                        break
            pos = start + 1


def loads_loose(text):
    """json.loads with a trailing comma repair, or None."""
    if not text:
        return None
    candidates = [text, re.sub(r',(\s*[}\]])', r'\1', text)]
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except Exception:
            continue
    return None


def entry_from_named(name, value):
    """Build one entry from a ``"TYPE": <value>`` pair."""
    if not name:
        return None
    if isinstance(value, dict):
        entry = dict(value)
        if not any(k in entry for k in ('type', 'name', 'message_type', 'command')):
            entry['type'] = name
        return entry
    if isinstance(value, list):
        lines = [item for item in value if isinstance(item, str)]
    elif isinstance(value, str):
        lines = [value]
    else:
        return None
    if not lines:
        return None
    return {'type': name, 'request': ''.join(lines)}


def entries_from_obj(obj):
    """Normalize a JSON answer into a list of raw entries."""
    if isinstance(obj, list):
        out = []
        for item in obj:
            out.extend(entries_from_obj(item))
        return out
    if isinstance(obj, dict):
        for key in WRAPPER_KEYS:
            if key in obj:
                nested = entries_from_obj(obj[key])
                if nested:
                    return nested
        if any(k in obj for k in ('type', 'name', 'message_type', 'command', 'method')):
            return [obj]
        if obj and all(isinstance(v, (list, str, dict)) for v in obj.values()):
            out = []
            for key, value in obj.items():
                entry = entry_from_named(key, value)
                if entry:
                    out.append(entry)
            return out
    return []


def entries_from_lines(text):
    """Fallback parser for answers that are not JSON.

    Accepts ChatState's ``USER: ["USER <<VALUE>>\\r\\n"]`` as well as a plain
    ``TYPE: <request>`` line followed by indented continuation lines and
    ``key: value`` detail lines (``header:``, ``fields:``, ``description:``).
    A lower case metadata key (``type: RETR``, ``name: RETR``) opens a new
    entry, while an upper case one (``TYPE: A``, FTP's transfer type) stays a
    message type of its own.
    """
    entries = []
    current = None
    for raw_line in (text or '').splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        match = LINE_ENTRY_RE.match(line)
        if match:
            name = match.group(1)
            rest = match.group(2).strip()
            if current is not None and name.lower() in ENTRY_KEYS \
                    and name not in META_KEYS:
                if rest:
                    current[name.lower()] = rest
                continue
            if name in META_KEYS and rest and rest[:1] not in ('[', '{'):
                current = {'type': rest}
                entries.append(current)
                continue
            if rest[:1] in ('[', '{'):
                obj = loads_loose(rest)
                entry = entry_from_named(name, obj) if obj is not None else None
                if entry is None:
                    entry = {'type': name, 'request': rest.strip('[]')}
                entries.append(entry)
                current = None
                continue
            entry = {'type': name, 'request': rest}
            entries.append(entry)
            current = entry
            continue
        if current is not None:
            current['request'] = (current.get('request', '') + '\n' + line.strip()).strip()
    return entries


def parse_answer(answer):
    """Parse a model answer into a list of raw entries (possibly empty)."""
    text = strip_code_fences(answer)
    for candidate in [text.strip()] + list(json_blocks(text)):
        obj = loads_loose(candidate)
        if obj is None:
            continue
        entries = entries_from_obj(obj)
        if entries:
            return entries
    return entries_from_lines(text)


# ---------------------------------------------------------------------------
# prompting
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    'You extract protocol request grammars for the AFLNet++ grey-box fuzzer. '
    'You answer with one JSON object and nothing else: no explanation, no '
    'comment, no markdown fence.')


def build_system_prompt(root=None):
    """The system prompt; with a root the model may inspect the implementation."""
    prompt = SYSTEM_PROMPT
    if root:
        prompt += ('\nRead the target implementation in the workspace below before '
                   'answering, and only report request types it really implements.\n\n'
                   + localtools.tools_help('{"templates":[...]}'))
    return prompt


def protocol_hint(protocol):
    hint = PROTOCOL_NOTES.get(protocol.strip().lower())
    if hint:
        return hint
    return ('Describe the client side requests of the %s protocol using the '
            'message type names as they appear on the wire.' % protocol.upper())


def build_prompt(protocol, lang_name, round_no, seen_types, want_types, max_types,
                 root=None, binary=False):
    """Build the (system, user) pair for one extraction round."""
    lines = []
    if round_no <= 1:
        lines.append('List every distinct client request type of the %s protocol.'
                     % protocol.upper())
    else:
        lines.append('A previous answer listed these client request types of the '
                     '%s protocol: %s.' % (protocol.upper(), ', '.join(seen_types)))
        lines.append('List every client request type of the %s protocol that is '
                     'still missing from that list, and nothing else.'
                     % protocol.upper())
    lines.append('')
    lines.append('Protocol notes: %s' % protocol_hint(protocol))
    if root:
        lines.append('Target workspace root: %s (inspect it with the tools).' % root)
    if want_types:
        lines.append('These request types must be included: %s.'
                     % ', '.join(want_types))
    lines.append('')
    if binary:
        lines.append('This is a BINARY protocol: a request is a byte string with '
                     'a framing, opcode and length structure, not a text line.')
        lines.append('For every request type return an object with these fields:')
        lines.append('  "type": a file-safe name, e.g. "MQTT_CONNECT" or '
                     '"TLS_HANDSHAKE_CLIENT_HELLO".')
        lines.append('  "probe": how to recognise the type in a message, a list of '
                     '{"offset": <byte offset>, "value": "0x..", "mask": "0x.."}; '
                     'mask is optional. Nested types use one probe per level, e.g. '
                     'TLS record content type at offset 0 and handshake type at 5.')
        lines.append('  "example": ONE complete request message. Write every '
                     'non-printable byte as a \\xNN escape (in JSON escape the '
                     'backslash, e.g. "\\\\x10"); printable ASCII may stay. Do not '
                     'add a terminator or a raw line break that is not part of the '
                     'message.')
        lines.append('  "layout": the byte structure of that example, in order: '
                     '{"name": "...", "offset": <byte offset>, '
                     '"size": <bytes | u8 | u16 | u32 | u64 | varint>, '
                     '"kind": "const|magic|enum|uint|int|bool|bitfield|bytes|'
                     'varint|length|checksum|padding", '
                     '"value": "0x.." or text for const fields, '
                     '"mutable": true|false}.')
        lines.append('  "frame": (optional) how consecutive messages are delimited '
                     'on a stream: {"length_offset": <where the length field '
                     'starts>, "length_size": <1|2|4|varint>, '
                     '"endian": "big|little", "payload_offset": <where the '
                     'counted bytes start; omit for "just after the length '
                     'field"; for a varint this is the one-byte baseline>, '
                     '"payload_offset_extra": <optional fixed bytes between a '
                     'varint and the payload>, '
                     '"length_includes": "payload"|"message"}. Omit it '
                     'for datagram protocols (DNS, DICOM, ...).')
        lines.append('  "description": one sentence that explains the request, in '
                     '%s.' % lang_name)
        lines.append('')
        lines.append('Rules:')
        lines.append('  - "example" and the layout ranges must describe the same '
                     'bytes; the layout covers the message from its first to its '
                     'last described field.')
        lines.append('  - mark "mutable": true ONLY for value fields the fuzzer may '
                     'change (payload values, identifiers, flags the protocol '
                     'accepts). Magic, version, length, checksum, padding and '
                     'offsets are mutable: false: they stay non-capturing in the '
                     'generated pattern and are never mutated.')
        lines.append('  - use exact byte offsets and sizes; a varint/length-prefixed '
                     'field uses "size": "varint" (or "kind": "length_prefixed").')
        lines.append('  - do not write a regular expression; the tool derives the '
                     'PCRE2 template from example + layout.')
        lines.append('  - one entry per request type, no duplicates, at most %d '
                     'entries ordered from the most to the least common.'
                     % max_types)
        lines.append('  - if nothing is missing, answer with an empty list.')
        lines.append('')
        lines.append('Answer format: {"templates": [{"type": "...", '
                     '"probe": [{"offset": 0, "value": "0x.."}], '
                     '"example": "\\\\x10\\\\x00...", "layout": [{"name": "...", '
                     '"offset": 0, "size": 1, "kind": "const", '
                     '"value": "0x..", "mutable": false}], '
                     '"frame": {"length_offset": 0, "length_size": 2, '
                     '"endian": "big", "length_includes": "payload"}, '
                     '"description": "..."}]}')
        return build_system_prompt(root), '\n'.join(lines)
    lines.append('For every request type return an object with these fields:')
    lines.append('  "type": the request name as it appears on the wire, upper case, '
                 'for example "SETUP" or "GET".')
    lines.append('  "request": the exact bytes of one complete request message, as '
                 'a single string. Mark every value the client may choose '
                 '(argument, identifier, number, flag) with <<PLACEHOLDER_NAME>>. '
                 'Write non printable bytes as the escapes \\r, \\n, \\t and '
                 '\\xNN, for example "SETUP <<URI>> RTSP/1.0\\r\\n'
                 'CSeq: <<CSEQ>>\\r\\n\\r\\n".')
    lines.append('  "placeholders": a list of {"name": "...", "example": "...", '
                 '"description": "..."} with a realistic example value for each '
                 'placeholder.')
    lines.append('  "description": one sentence that explains the request, in %s.'
                 % lang_name)
    lines.append('')
    lines.append('Rules:')
    lines.append('  - "request" is the message itself, not a description of it and '
                 'not a regular expression; use <<NAME>> for the values.')
    lines.append('  - write a request that carries a header block (RTSP, SIP, HTTP, '
                 'IMAP, SMTP DATA, ...) exactly as it goes on the wire, headers '
                 'included: the generator puts the request line (the one that names '
                 'the message type) in the header pattern and the remaining lines in '
                 'the field pattern, so mark the value of every header the client '
                 'may choose with <<NAME>>.')
    lines.append('  - one entry per request type, no duplicates, at most %d entries '
                 'ordered from the most to the least common.' % max_types)
    lines.append('  - if a request type has no argument, "request" is just the '
                 'command, for example "QUIT\\r\\n".')
    lines.append('  - if nothing is missing, answer with an empty list.')
    lines.append('')
    lines.append('Answer format: {"templates": [{"type": "...", "request": "...", '
                 '"placeholders": [{"name": "...", "example": "...", '
                 '"description": "..."}], "description": "..."}]}')
    return build_system_prompt(root), '\n'.join(lines)


# ---------------------------------------------------------------------------
# template records
# ---------------------------------------------------------------------------

def type_token(header):
    """First literal token of a header pattern, used for the seeds report."""
    for match in TYPE_TOKEN.finditer(header):
        token = match.group(0)
        if token not in ('r', 'n', 't', 'x', 'd', 'w', 's', 'b', 'P'):
            return token
    return None


def build_record(entry, warnings, keep_static=False, anchor=True, protocol=None,
                 binary=False):
    """Convert one raw entry into a template record, or None with a reason."""
    placeholders = collect_placeholders(entry)
    header_in = first_str(entry, ('header', 'header_pattern', 'request_pattern'))
    request = (first_raw(entry, REQUEST_KEYS) if binary
               else first_str(entry, REQUEST_KEYS, keep_newlines=True))
    layout = entry.get('layout')
    if not isinstance(layout, list) and isinstance(entry.get('fields'), list):
        layout = entry.get('fields')
    if not isinstance(layout, list):
        layout = None
    probe = entry.get('probe') if isinstance(entry.get('probe'), list) else None
    frame = entry.get('frame') if isinstance(entry.get('frame'), dict) else None
    if frame is None and isinstance(entry.get('framing'), dict):
        frame = entry.get('framing')
    field_pattern = first_str(entry, ('field_pattern', 'fields_pattern',
                                      'tail_pattern', 'fields'))
    description = first_str(entry, ('description', 'meaning', 'purpose', 'notes'))
    name = sanitize_type(first_str(entry, ('type', 'name', 'message_type', 'msg_type',
                                           'command', 'method', 'id')))
    example = None
    notes = []
    converted = None
    derived_header = False
    if header_in:
        header = to_single_line(header_in)
        if request:
            converted = request_to_header(request, placeholders, warnings, name,
                                          protocol, binary=binary)
            if converted:
                example = converted['example']
                notes.extend(converted['notes'])
    elif binary and layout and request:
        converted = layout_to_template(normalize_escapes(request, binary=True),
                                       layout, warnings, name)
        if converted is None:
            converted = request_to_header(request, placeholders, warnings, name,
                                          protocol, binary=True)
        if converted is None:
            return None, 'empty request'
        header = converted['header']
        example = converted['example']
        notes.extend(converted['notes'])
        derived_header = True
    elif request:
        converted = request_to_header(request, placeholders, warnings, name,
                                      protocol, binary=binary)
        if not converted:
            return None, 'empty request'
        header = converted['header']
        example = converted['example']
        notes.extend(converted['notes'])
        derived_header = True
    else:
        if header_in is None:
            return None, 'no request and no header pattern'
        header = ''
    if not header:
        return None, 'empty header pattern'
    if header.lower().startswith('^?'):
        header = header[1:]
    if anchor and not header.startswith('^'):
        header = '^' + header
        notes.append('header was not anchored with ^, anchoring it at offset 0')
    compiled, error = compile_pattern(header)
    variables = compiled.groups if compiled is not None else header.count('(')
    if not variables and derived_header and converted and converted.get('variables'):
        # the header pattern is the request line only, so a request whose fields
        # are all in its remaining lines still has mutable windows (line 2)
        variables = converted['variables']
    if variables == 0 and not keep_static:
        return None, 'no variable field (use --keep-static to keep it)'
    if field_pattern:
        fields = to_single_line(field_pattern)
    elif derived_header and converted and converted.get('fields'):
        fields = converted['fields']
    else:
        fields = None
    fields = fields or (BINARY_FIELD_PATTERN if binary else DEFAULT_FIELD_PATTERN)
    notes.append('field pattern: %s' % fields)
    record = {
        'type': name,
        'header': header,
        'fields': fields,
        'description': description or '',
        'placeholders': placeholders,
        'example': example,
        'verified': None,
        'notes': notes,
    }
    if probe is not None:
        record['probe'] = probe
    if binary and layout:
        record['layout'] = layout
    if frame:
        record['frame'] = frame
    if compiled is None:
        notes.append('Python re cannot compile the pattern: %s' % error)
    elif example:
        match = compiled.match(example)
        record['verified'] = bool(match)
        if not match:
            notes.append('the example message %s does not match the header'
                         % shorten(repr(example), 48))
    record['type'] = record['type'] or type_token(header) or 'TEMPLATE'
    return record, None


def template_text(record):
    """Render one template exactly like the reference corpus.

    ChatState's ``protocol-grammars`` files carry no trailing newline;
    ``template_add()`` tolerates one either way.
    """
    return '%s\n%s' % (record['header'], record['fields'])


def parse_template_text(text):
    """Split a template file into (header, fields), or (None, reason)."""
    newline = text.find('\n')
    if newline < 0:
        return None, 'no field pattern line'
    header = text[:newline].strip()
    fields = text[newline + 1:].strip('\r\n').strip()
    if not header:
        return None, 'empty header pattern'
    if not fields:
        return None, 'empty field pattern'
    return (header, fields), None


# ---------------------------------------------------------------------------
# talking to the model
# ---------------------------------------------------------------------------

def read_text(path):
    if path == '-':
        return sys.stdin.read()
    try:
        with open(path, 'r', errors='replace') as handle:
            return handle.read()
    except Exception:
        return None


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
    log('[*] endpoint %s, model %s%s' % (client.base_url, client.model,
                                         '' if client.api_key else ', no api key'))
    return client


def entry_type(entry):
    return sanitize_type(first_str(entry, ('type', 'name', 'message_type', 'msg_type',
                                           'command', 'method', 'id')))


def query_llm(args, log, warnings, stats):
    client = make_client(args, log)
    stats['model'] = client.model
    workspace = localtools.Workspace(args.root) if args.root else None
    runner = agent.Agent(client, workspace, max_steps=args.max_steps,
                         verbose=args.verbose, log=log, warnings=warnings)
    raw_entries = []
    seen = []
    rounds = max(1, args.rounds)
    for round_no in range(1, rounds + 1):
        system, user = build_prompt(args.protocol, LANGUAGES.get(args.lang, args.lang),
                                    round_no, seen, args.types, args.max_types,
                                    root=args.root, binary=args.binary)
        if args.verbose:
            log('[debug] round %d prompt:\n%s' % (round_no, user))
        try:
            _payload, answer, _calls = runner.run(
                system, user, final_hint='{"templates":[...]}')
        except agent.AgentError as exc:
            message = 'round %d: the request failed (%s)' % (round_no, exc)
            if args.strict:
                raise RuntimeError(message)
            warnings.append(message)
            break
        entries = parse_answer(answer)
        if not entries:
            warnings.append('round %d: no template found in the model answer'
                            % round_no)
            break
        new_types = 0
        for entry in entries:
            name = entry_type(entry)
            if name and name.lower() not in [item.lower() for item in seen]:
                seen.append(name)
                new_types += 1
            raw_entries.append((entry, 'llm round %d' % round_no, round_no))
        log('[+] round %d: %d template(s), %d new message type(s)'
            % (round_no, len(entries), new_types))
        if round_no >= 2 and new_types == 0:
            log('[~] nothing new in round %d, stopping' % round_no)
            break
    stats['rounds'] = rounds
    return raw_entries


# ---------------------------------------------------------------------------
# records and output
# ---------------------------------------------------------------------------

def describe_entry(entry):
    for key in ('type', 'name', 'message_type', 'command', 'request', 'header'):
        value = first_str(entry, (key,))
        if value:
            return shorten(value, 32)
    return shorten(json.dumps(entry, ensure_ascii=True), 32)


def merge_records(raw_entries, args, warnings):
    """Convert raw entries into unique template records."""
    records = []
    by_type = {}
    skipped = []
    for entry, source, round_no in raw_entries:
        record, reason = build_record(entry, warnings, keep_static=args.keep_static,
                                      protocol=args.protocol, binary=args.binary)
        if record is None:
            skipped.append((describe_entry(entry), reason))
            continue
        key = record['type'].lower()
        if key in by_type:
            if template_text(record) != template_text(by_type[key]):
                warnings.append('%s: a second and different description was '
                                'returned by %s, keeping the first one'
                                % (record['type'], source))
            continue
        record['source'] = source
        record['round'] = round_no
        by_type[key] = record
        records.append(record)
    for wanted in args.types or []:
        if wanted.lower() not in by_type:
            warnings.append('the requested message type %s was not returned'
                            % wanted)
    return records, skipped


def guard_output_dir(out_dir, args, log):
    """Refuse to clobber files this tool did not write, return previous types."""
    meta_path = os.path.join(out_dir, META_NAME)
    if not os.path.isdir(out_dir):
        return []
    previous = []
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, 'r', errors='replace') as handle:
                meta = json.load(handle)
            previous = [item.get('type') for item in meta.get('templates', [])
                        if item.get('type')]
        except Exception:
            previous = []
    clashes = []
    for name in sorted(os.listdir(out_dir)):
        if name.startswith('.'):
            continue
        if not os.path.isfile(os.path.join(out_dir, name)):
            continue
        if name not in previous and not args.force:
            clashes.append(name)
    if clashes:
        log('[!] %s already holds files this tool did not write (%s)'
            % (out_dir, ', '.join(clashes[:5])))
        log('[!] pass --force to overwrite them, or choose another directory')
        return None
    return previous


def write_templates(out_dir, args, records, warnings, skipped, stats, previous):
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    written = []
    for record in records:
        path = os.path.join(out_dir, record['type'])
        with open(path, 'w') as handle:
            handle.write(template_text(record))
        written.append(record['type'])
    stale = [name for name in previous if name not in written]
    for name in stale:
        path = os.path.join(out_dir, name)
        if os.path.isfile(path):
            os.remove(path)
    binary_types = {}
    frames = []
    for record in records:
        probe = record.get('probe')
        layout = record.get('layout')
        frame = record.get('frame')
        if not probe and not layout and not frame:
            continue
        entry = {'probe': probe or [], 'layout': layout or []}
        if record.get('example'):
            entry['example_hex'] = record['example'].encode('latin-1').hex()
        if frame:
            entry['frame'] = frame
            frames.append(frame)
        binary_types[record['type']] = entry
    formats_path = os.path.join(out_dir, formats.FORMATS_NAME)
    if binary_types:
        framing = frames[0] if frames and all(frame == frames[0]
                                             for frame in frames) else None
        with open(formats_path, 'w') as handle:
            handle.write(json.dumps({
                'format_version': formats.FORMAT_VERSION,
                'tool': 'utils/AI-agent/pro-template/gen_templates.py',
                'protocol': args.protocol,
                'framing': framing,
                'types': binary_types,
            }, indent=2, sort_keys=True, ensure_ascii=True) + '\n')
    elif os.path.exists(formats_path):
        os.remove(formats_path)          # stale binary table in a directory we own
    meta = {
        'tool': 'utils/AI-agent/pro-template/gen_templates.py',
        'version': VERSION,
        'protocol': args.protocol,
        'source': stats.get('source'),
        'model': stats.get('model'),
        'rounds': stats.get('rounds'),
        'language': args.lang,
        'template_format': ('line 1: PCRE2 header pattern, its capture groups are '
                            'the mutable fields; line 2: PCRE2 field pattern'),
        'usage': 'AFLNET_GRAMMAR=%s ./afl-fuzz -N tcp://127.0.0.1/PORT ...' % out_dir,
        'binary_formats': formats.FORMATS_NAME if binary_types else None,
        'templates': records,
        'removed_from_previous_run': stale,
        'skipped': [{'entry': name, 'reason': reason} for name, reason in skipped],
        'warnings': warnings,
    }
    with open(os.path.join(out_dir, META_NAME), 'w') as handle:
        handle.write(json.dumps(meta, indent=2, ensure_ascii=True) + '\n')
    return written


# ---------------------------------------------------------------------------
# checking an existing template directory
# ---------------------------------------------------------------------------

SEED_DIRS = (
    os.path.join('profuzzbench', 'aflnet-pp', 'bin-corpus'),
    os.path.join('profuzzbench', 'bin-corpus'),
)


def repo_root():
    return os.path.abspath(os.path.join(HERE, os.pardir, os.pardir))


def default_seed_dir(protocol):
    """Guess the profuzzbench seed corpus of a protocol, or None."""
    root = repo_root()
    candidates = [os.path.join(root, relative) for relative in SEED_DIRS]
    name = (protocol or '').strip().lower().rsplit('/', 1)[-1]
    subjects = os.path.join(root, 'profuzzbench', 'subjects', name.upper())
    if name and os.path.isdir(subjects):
        for subject in sorted(os.listdir(subjects)):
            candidates.append(os.path.join(subjects, subject, 'in-' + name))
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return None


def scan_templates(directory):
    """Read a template directory, return (templates, problems)."""
    templates = []
    problems = []
    if not os.path.isdir(directory):
        return [], ['%s is not a directory' % directory]
    for name in sorted(os.listdir(directory)):
        if name.startswith('.'):
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        text = read_text(path)
        if text is None:
            problems.append('%s: cannot read the file' % name)
            continue
        parsed, reason = parse_template_text(text)
        if parsed is None:
            problems.append('%s: %s' % (name, reason))
            continue
        header, fields = parsed
        notes = []
        if not header.startswith('^'):
            notes.append('not anchored with ^')
        compiled, error = compile_pattern(header)
        if compiled is None:
            notes.append('Python re cannot compile it (%s)' % error)
            groups = -1
        else:
            groups = compiled.groups
            if groups == 0:
                notes.append('no capture group, so no mutable field')
        for pattern in (header, fields):
            if any(ord(ch) > 126 for ch in pattern):
                notes.append('non ASCII byte in the pattern')
                break
        extra = [line for line in text.split('\n')[2:] if line.strip()]
        if extra:
            notes.append('%d extra line(s) are part of the field pattern'
                         % len(extra))
        templates.append({'type': name, 'header': header, 'fields': fields,
                          'groups': groups, 'notes': notes})
    return templates, problems


def read_bytes(path, limit=1 << 20):
    try:
        with open(path, 'rb') as handle:
            return handle.read(limit)
    except Exception:
        return b''


def seed_files(directory):
    files = []
    if not os.path.isdir(directory):
        return files
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            files.append(path)
    return files


def seed_messages(data):
    """Candidate single message slices of one seed.

    profuzzbench seeds are whole request chains (``USER x\\r\\nPASS y\\r\\n``),
    while a template describes exactly one message, so the seed itself and every
    line of it are tried.  ``latin-1`` keeps the byte values unchanged for the
    regex engine.
    """
    text = data.decode('latin-1')
    yield text
    if '\r\n' in text:
        separator = '\r\n'
    elif '\n' in text:
        separator = '\n'
    else:
        return
    for line in text.split(separator):
        if line:
            yield line + separator


def matching_messages(template, files):
    """The (path, message) pairs of a corpus that this template accepts."""
    compiled, _ = compile_pattern(template['header'])
    if compiled is None:
        return []
    hits = []
    for path in files:
        for message in seed_messages(read_bytes(path)):
            if compiled.match(message):
                hits.append((path, message))
                break
    return hits


def seeds_report(templates, directory, log):
    """Report how many seeds carry each message type, return the report."""
    files = seed_files(directory)
    report = {}
    if not files:
        log('[!] no seed file under %s' % directory)
        return report
    for template in templates:
        hits = matching_messages(template, files)
        report[template['type']] = {'seeds': len(files), 'matched': len(hits),
                                    'how': 'header pattern'}
        if hits:
            example = hits[0][1].strip()
            log('[+] %-16s %d/%d seed(s) match, e.g. %s'
                % (template['type'], len(hits), len(files),
                   shorten(repr(example), 40)))
        else:
            log('[!] %-16s no seed matched its header pattern'
                % template['type'])
    if report and not any(item['matched'] for item in report.values()):
        log('[!] no template matched any seed under %s' % directory)
        log('[!] is this the seed corpus of the protocol you asked for?')
    return report


def extract_seeds(templates, seed_dir, out_dir, log):
    """Write the messages a template accepts into one directory per type."""
    files = seed_files(seed_dir)
    if not files:
        log('[!] no seed file under %s' % seed_dir)
        return 1
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    empty = []
    total = 0
    written = 0
    for template in templates:
        hits = matching_messages(template, files)
        if not hits:
            empty.append(template['type'])
            continue
        target = os.path.join(out_dir, template['type'])
        if not os.path.isdir(target):
            os.makedirs(target)
        for index, (path, message) in enumerate(hits, 1):
            name = '%s-%s-%03d' % (template['type'],
                                   os.path.basename(path).replace('/', '_'), index)
            with open(os.path.join(target, name), 'wb') as handle:
                handle.write(message.encode('latin-1'))
            written += 1
        total += len(hits)
    log('[+] %d message(s) of %d seed(s) split into %d type director(ies) under %s'
        % (written, len(files), len(templates) - len(empty), out_dir))
    if empty:
        log('[!] %d template(s) would get an empty corpus and were skipped: %s'
            % (len(empty), ', '.join(sorted(empty))))
        return 1
    return 0


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog='gen_templates.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=('Ask an LLM for the client request types of a protocol and '
                     'write one AFLNet++ grammar template per message type.'),
        epilog=('examples:\n'
                '  gen_templates.py ftp grammars/ftp\n'
                '  gen_templates.py imap grammars/imap --types APPEND --rounds 2\n'
                '  gen_templates.py --check grammars/ftp --seeds profuzzbench/'
                'subjects/FTP/BFTPD/in-ftp\n'
                '  gen_templates.py ftp grammars/ftp --from-answer answer.txt\n'
                '\nEndpoint: LLM_BASE_URL, LLM_API_KEY, LLM_MODEL (the OPENAI_* / '
                'AZURE_OPENAI_* names work as fallbacks).\n'))
    parser.add_argument('protocol', nargs='?',
                        help='protocol name (ftp, smtp, rtsp, sip, http, imap, '
                             'pop3, tls, dns, ...); with --check this is the '
                             'template directory instead')
    parser.add_argument('output', nargs='?', help='output directory')
    mode = parser.add_argument_group('mode')
    mode.add_argument('--check', action='store_true',
                      help='inspect an existing template directory instead of '
                           'asking the model')
    mode.add_argument('--seeds', metavar='DIR',
                      help='score the templates against a seed corpus')
    mode.add_argument('--extract-seeds', metavar='DIR',
                      help='copy the matching seeds of every template into '
                           '--out-seeds')
    mode.add_argument('--out-seeds', metavar='DIR',
                      help='destination of --extract-seeds (one directory per type)')
    mode.add_argument('--from-answer', metavar='FILE', nargs='+',
                      help='convert an already captured model answer instead of '
                           'calling the endpoint ("-" reads stdin)')
    mode.add_argument('--offline', action='store_true',
                      help='never contact the endpoint (needs --from-answer or '
                           '--check)')
    mode.add_argument('--dump-prompt', action='store_true',
                      help='print the prompt of every round and exit')
    endpoint = parser.add_argument_group('endpoint')
    endpoint.add_argument('--base-url', help='OpenAI compatible base URL')
    endpoint.add_argument('--api-key', help='API key (prefer the environment)')
    endpoint.add_argument('--model', help='model name')
    endpoint.add_argument('--temperature', type=float, default=0.2)
    endpoint.add_argument('--timeout', type=float, default=120.0)
    endpoint.add_argument('--retries', type=int, default=2)
    endpoint.add_argument('--rounds', type=int, default=2,
                          help='number of extraction rounds (default 2)')
    endpoint.add_argument('--json-mode', action='store_true',
                          help='ask the endpoint for a JSON object response')
    prompt = parser.add_argument_group('prompt')
    prompt.add_argument('--root', metavar='DIR',
                        help='target repository the model may inspect with '
                             'list_dir/read_file/search_text while it answers')
    prompt.add_argument('--max-steps', type=int, default=16,
                        help='tool-use turns per round (default 16)')
    prompt.add_argument('--mode', choices=('text', 'binary'), default='text',
                        help='text protocol templates (default, unchanged) or '
                             'binary byte-layout templates')
    prompt.add_argument('--lang', default='zh',
                        help='language of the "description" fields (%s)'
                             % '/'.join(sorted(LANGUAGES)))
    prompt.add_argument('--types', nargs='+', metavar='TYPE',
                        help='message types that must be covered')
    prompt.add_argument('--max-types', type=int, default=DEFAULT_MAX_TYPES,
                        help='maximum number of request types per round')
    conversion = parser.add_argument_group('conversion')
    conversion.add_argument('--keep-static', action='store_true',
                            help='keep templates that have no mutable field')
    conversion.add_argument('--strict', action='store_true',
                            help='fail on endpoint errors and on warnings')
    output = parser.add_argument_group('output')
    output.add_argument('--force', action='store_true',
                        help='overwrite files this tool did not write')
    output.add_argument('--quiet', action='store_true')
    output.add_argument('--verbose', action='store_true')
    output.add_argument('--version', action='store_true')
    return parser


def show_prompts(args, log):
    seen = []
    for round_no in range(1, max(1, args.rounds) + 1):
        system, user = build_prompt(args.protocol, LANGUAGES.get(args.lang, args.lang),
                                    round_no, seen, args.types, args.max_types,
                                    root=args.root, binary=args.binary)
        print('==== system (round %d) ====' % round_no)
        print(system)
        print('==== user (round %d) ====' % round_no)
        print(user)
        print('')
        seen = list(args.types or [])


def check_binary_formats(directory, templates, log):
    """Validate ``.binary-formats.json`` against the template files."""
    try:
        payload = formats.load_formats(directory)
    except formats.FormatError as exc:
        log('[!] %s' % exc)
        return [str(exc)], None
    if not payload:
        return [], None
    by_type = dict((template['type'], template) for template in templates)
    types = formats.types_of(payload)
    problems = []
    for name in sorted(types):
        entry = types[name]
        if not isinstance(entry, dict):
            problems.append('%s: entry is not an object' % name)
            continue
        template = by_type.get(name)
        if template is None:
            problems.append('%s: no template file for this type' % name)
            continue
        example_hex = str(entry.get('example_hex') or '').strip()
        if not example_hex:
            problems.append('%s: no example_hex to validate against' % name)
            continue
        try:
            example = bytes.fromhex(example_hex)
        except ValueError:
            problems.append('%s: example_hex is not valid hex' % name)
            continue
        issues = []
        probes = entry.get('probe') or []
        if probes and not formats.probe_match(example, probes):
            issues.append('probe does not match the example')
        layout = entry.get('layout') or []
        if layout:
            layout_warnings = []
            derived = layout_to_template(example.decode('latin-1'), layout,
                                         layout_warnings, name)
            issues.extend(layout_warnings)
            if derived is None:
                issues.append('the layout does not derive a template')
            elif derived['header'] != template['header']:
                issues.append('layout-derived header differs from the template')
        frame = entry.get('frame') or payload.get('framing')
        if frame:
            frames, rest = formats.split_frames(example, frame)
            if frames != [example] or rest:
                issues.append('the framing does not reproduce the example')
        if issues:
            problems.extend('%s: %s' % (name, issue) for issue in issues)
        else:
            log('[+] %-20s probe/layout/example OK' % name)
    return problems, {'types': len(types),
                      'framing': formats.framing_of(payload)}


def run_check(args, log):
    directory = os.path.abspath(args.output or args.protocol)
    templates, problems = scan_templates(directory)
    binary_problems, binary_info = check_binary_formats(directory, templates, log)
    problems.extend(binary_problems)
    for problem in problems:
        log('[!] %s' % problem)
    notes = 0
    for template in templates:
        notes += len(template['notes'])
    print('[*] %s: %d template(s), %d problem(s), %d note(s)'
          % (directory, len(templates), len(problems), notes))
    print('%-20s %-6s %s' % ('type', 'groups', 'header'))
    for template in templates:
        groups = '?' if template['groups'] < 0 else str(template['groups'])
        print('%-20s %-6s %s' % (template['type'], groups, template['header']))
        if template['fields'] != DEFAULT_FIELD_PATTERN:
            # the fields pattern holds the mutable fields of a multi line
            # request, so show it next to the header pattern
            print('%-27s   fields: %s' % ('', template['fields']))
        for note in template['notes']:
            print('%-27s - %s' % ('', note))
    failed = bool(problems)
    report = {}
    if not args.seeds and templates:
        guessed = default_seed_dir(args.protocol or
                                   os.path.basename(directory.rstrip(os.sep)))
        if guessed:
            log('[+] using the seed corpus %s (override with --seeds)' % guessed)
    seed_dir = args.seeds or default_seed_dir(args.protocol or
                                              os.path.basename(directory.rstrip(os.sep)))
    if seed_dir:
        report = seeds_report(templates, seed_dir, log)
        if templates and not any(item['matched'] for item in report.values()):
            failed = True
    if args.extract_seeds:
        if not args.out_seeds:
            log('[!] --extract-seeds needs --out-seeds')
            return 2
        if not templates:
            log('[!] no template to extract seeds for')
            return 1
        if extract_seeds(templates, args.extract_seeds, args.out_seeds, log):
            failed = True
    if notes and args.strict:
        failed = True
    if not templates:
        failed = True
    report['problems'] = problems
    report['directory'] = directory
    if binary_info is not None:
        report['binary_formats'] = binary_info
    if seed_dir:
        report['seed_dir'] = seed_dir
    try:
        with open(os.path.join(directory, '.check.json'), 'w') as handle:
            handle.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    except Exception as exc:
        log('[~] cannot write %s: %s' % (os.path.join(directory, '.check.json'), exc))
    print('[%s] check finished (report: %s)'
          % ('-' if failed else '+', os.path.join(directory, '.check.json')))
    return 1 if failed else 0


def summarize(args, out_dir, records, warnings, skipped, log):
    ok = [r for r in records if r['verified'] is True]
    bad = [r for r in records if r['verified'] is False]
    unknown = [r for r in records if r['verified'] is None]
    print('[*] protocol %s: %d template(s) written to %s'
          % (args.protocol, len(records), out_dir))
    print('[*] %d example(s) verified against their header pattern, %d mismatched, '
          '%d without an example' % (len(ok), len(bad), len(unknown)))
    print('%-18s %-6s %s' % ('type', 'state', 'header'))
    for record in records:
        if record['verified'] is True:
            state = 'ok'
        elif record['verified'] is False:
            state = 'CHECK'
        else:
            state = '-'
        print('%-18s %-6s %s' % (record['type'], state, record['header']))
    for name, reason in skipped:
        log('[~] skipped %s: %s' % (name, reason))
    for warning in warnings:
        log('[!] %s' % warning)
    if bad:
        log('[!] %d template(s) do not match their own example message, look at '
            'the "CHECK" rows' % len(bad))
    print('[*] meta: %s' % os.path.join(out_dir, META_NAME))
    print('[*] use it with: AFLNET_GRAMMAR=%s ./afl-fuzz -N tcp://127.0.0.1/PORT ...'
          % out_dir)
    print('[*] inspect or score it again with: %s --check %s [--seeds DIR]'
          % (os.path.join('utils', 'pro-template', 'gen_templates.py'), out_dir))
    if not records:
        return 1
    if args.strict and (warnings or bad or skipped):
        return 1
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.binary = args.mode == 'binary'
    if args.version:
        print(VERSION)
        return 0
    if args.quiet:
        def log(message):
            pass
    else:
        def log(message):
            print(message, file=sys.stderr)
    if args.check:
        if args.protocol and args.output:
            log('[!] --check takes one directory: gen_templates.py DIR --check')
            return 2
        return run_check(args, log)
    if not args.protocol:
        log('[!] the protocol name is required (or use --check DIR)')
        return 2
    if not args.output:
        log('[!] the output directory is required')
        return 2
    if getattr(args, 'root', None) and not os.path.isdir(args.root):
        log('[!] --root is not a directory: %s' % args.root)
        return 2
    if args.dump_prompt:
        show_prompts(args, log)
        return 0
    out_dir = os.path.abspath(args.output)
    previous = guard_output_dir(out_dir, args, log)
    if previous is None:
        return 1
    warnings = []
    skipped = []
    stats = {'source': None, 'model': None, 'rounds': args.rounds}
    if args.from_answer:
        raw_entries = []
        for path in args.from_answer:
            text = read_text(path)
            if text is None:
                log('[!] cannot read %s' % path)
                return 1
            entries = parse_answer(text)
            log('[+] %s: %d template(s) parsed' % (path, len(entries)))
            for entry in entries:
                raw_entries.append((entry, 'answer %s' % path, 0))
        stats['source'] = 'answer: %s' % ', '.join(args.from_answer)
    else:
        if args.offline:
            log('[!] --offline needs --from-answer, or use --check')
            return 2
        try:
            raw_entries = query_llm(args, log, warnings, stats)
        except Exception as exc:
            log('[!] %s' % exc)
            return 1
        stats['source'] = 'llm'
    records, skipped = merge_records(raw_entries, args, warnings)
    if not records:
        log('[!] no usable template was produced')
    write_templates(out_dir, args, records, warnings, skipped, stats, previous)
    code = summarize(args, out_dir, records, warnings, skipped, log)
    if args.seeds:
        seeds_report(records, args.seeds, log)
    if args.extract_seeds:
        if not args.out_seeds:
            log('[!] --extract-seeds needs --out-seeds')
            return 2
        seed_dir = args.seeds or default_seed_dir(args.protocol)
        if not seed_dir:
            log('[!] --extract-seeds needs --seeds DIR (no default corpus found)')
            return 2
        if extract_seeds(records, seed_dir, args.out_seeds, log):
            code = 1
    return code


if __name__ == '__main__':
    sys.exit(main())
