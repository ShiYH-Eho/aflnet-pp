#!/usr/bin/env python3
"""Binary message types and framing, shared by pro-template and corpus-enrich.

``pro-template --mode binary`` writes ``.binary-formats.json`` next to the
two-line PCRE2 templates.  That file is small on purpose: it carries the
message-type discriminator (``probe``), the byte layout of the example and,
when the protocol has one, how a length field delimits a message on the wire.
The fuzzer loads it alongside the grammar directory and uses its probes to
select the matching binary template before falling back to regex matching.
``corpus-enrich`` also uses it to split binary seeds into messages and to
classify them by type.

Example::

    {
      "format_version": 1,
      "protocol": "mqtt",
      "framing": {"length_offset": 1, "length_size": "varint",
                  "payload_offset": 2, "length_includes": "payload"},
      "types": {
        "MQTT_CONNECT": {
          "probe": [{"offset": 0, "value": "0x10"}],
          "layout": [...],
          "example_hex": "100c00044d5154540402003c"
        }
      }
    }

Nothing here needs a third-party package; the module is deliberately tolerant
about the JSON shapes so a hand-written file works as well as a generated one.
"""

from __future__ import print_function

import json
import os

FORMATS_NAME = '.binary-formats.json'
FORMAT_VERSION = 1


class FormatError(ValueError):
    """A formats file exists but cannot be used."""


def _fixed_bytes(value, allow_text=True):
    """Bytes described by ``0x10`` / ``\\x10`` / ``10`` / a text constant."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return bytes([value & 0xff])
    if isinstance(value, (list, tuple)):
        try:
            return bytes(int(item) & 0xff for item in value)
        except (TypeError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.lower().startswith('0x'):
        digits = text[2:]
        try:
            number = int(digits, 16)
        except ValueError:
            return None
        return number.to_bytes((len(digits) + 1) // 2, 'big')
    if '\\x' in text:
        out = bytearray()
        i = 0
        while i < len(text):
            if text[i] == '\\' and i + 3 < len(text) and text[i + 1] in 'xX':
                try:
                    out.append(int(text[i + 2:i + 4], 16))
                except ValueError:
                    return None
                i += 4
                continue
            out.extend(text[i].encode('latin-1', 'replace'))
            i += 1
        return bytes(out)
    return text.encode('latin-1', 'replace') if allow_text else None


def load_formats(path):
    """Read a formats file, or ``DIR/.binary-formats.json``; ``None`` if absent."""
    if not path:
        return None
    if os.path.isdir(path):
        path = os.path.join(path, FORMATS_NAME)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, 'r', errors='replace') as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        raise FormatError('cannot read %s: %s' % (path, exc))
    if not isinstance(payload, dict) or not isinstance(payload.get('types'), dict):
        raise FormatError('%s has no "types" object' % path)
    return payload


def types_of(formats):
    return formats.get('types') if formats else {}


def framing_of(formats):
    """The protocol framing: the top-level one, else the first per-type one."""
    if not formats:
        return None
    framing = formats.get('framing')
    if isinstance(framing, dict) and framing:
        return framing
    for name in sorted(types_of(formats)):
        entry = types_of(formats)[name]
        if isinstance(entry, dict) and isinstance(entry.get('frame'), dict) \
                and entry['frame']:
            return entry['frame']
    return None


def probe_match(message, probes):
    """True when every probe (offset + value/mask) matches ``message``."""
    if not probes:
        return False
    for probe in probes:
        if not isinstance(probe, dict):
            return False
        try:
            offset = int(probe.get('offset', 0))
        except (TypeError, ValueError):
            return False
        value = _fixed_bytes(probe.get('value'))
        if value is None:
            return False
        mask = _fixed_bytes(probe.get('mask'), allow_text=False) \
            if probe.get('mask') is not None else None
        if mask is not None and len(mask) != len(value):
            return False
        if offset < 0 or offset + len(value) > len(message):
            return False
        chunk = message[offset:offset + len(value)]
        if mask is None:
            if chunk != value:
                return False
        elif any((byte & m) != (want & m)
                 for byte, m, want in zip(chunk, mask, value)):
            return False
    return True


def classify(message, formats):
    """The type whose probe matches ``message``, or ``None``."""
    if not formats or not isinstance(message, (bytes, bytearray)):
        return None
    for name in sorted(types_of(formats)):
        entry = types_of(formats)[name]
        probes = entry.get('probe') if isinstance(entry, dict) else None
        if probe_match(bytes(message), probes):
            return name
    return None


def read_length(data, pos, size, endian='big'):
    """Read a 1/2/4/8-byte or LEB128 varint length; ``(value, used)`` or None."""
    if pos < 0 or pos >= len(data):
        return None, 0
    if isinstance(size, str) and size.strip().lower() in ('varint', 'leb128'):
        value, used = 0, 0
        for index in range(10):
            if pos + index >= len(data):
                return None, 0
            byte = data[pos + index]
            used += 1
            value |= (byte & 0x7f) << (7 * index)
            if not (byte & 0x80):
                return value, used
        return None, 0
    try:
        width = int(size)
    except (TypeError, ValueError):
        return None, 0
    if width not in (1, 2, 4, 8) or pos + width > len(data):
        return None, 0
    order = 'little' if str(endian).lower().startswith('little') else 'big'
    return int.from_bytes(data[pos:pos + width], order), width


def split_frames(data, framing):
    """Split a binary stream into messages; return ``(frames, leftover_bytes)``.

    ``framing`` describes how to find the end of a message::

        {"length_offset": 1, "length_size": "varint",
         "payload_offset": 2, "length_includes": "payload"}

    ``length_includes`` is ``"payload"`` (default: frame end is
    ``payload_offset + length``; ``payload_offset`` defaults to just after the
    length field) or ``"message"`` (frame end is ``length`` bytes from the start
    of the message, e.g. protocols whose length covers the whole frame).  For a
    varint length the payload starts after the encoded varint, so a supplied
    ``payload_offset`` is treated as its one-byte baseline; use
    ``payload_offset_extra`` for any fixed bytes between the varint and payload.
    Without a framing spec the whole input is one message.
    """
    data = bytes(data or b'')
    if not framing:
        return ([data] if data else []), 0
    try:
        length_offset = int(framing.get('length_offset', 0))
    except (TypeError, ValueError):
        return [], len(data)
    size = framing.get('length_size', 1)
    endian = framing.get('endian', 'big')
    includes = str(framing.get('length_includes', 'payload')).strip().lower()
    payload_offset = framing.get('payload_offset')
    payload_extra = framing.get('payload_offset_extra')
    varint = isinstance(size, str) and size.strip().lower() in ('varint', 'leb128')
    frames, offset = [], 0
    while offset < len(data):
        length, used = read_length(data, offset + length_offset, size, endian)
        if length is None:
            break
        if includes == 'message':
            end = offset + length
        else:
            if varint:
                # A varint is 1..N bytes on the wire.  ``payload_offset`` in a
                # generated table is usually the position for the one-byte
                # example, so keep its fixed gap but not its width.
                if isinstance(payload_extra, int) and payload_extra >= 0:
                    extra = payload_extra
                elif isinstance(payload_offset, int) and payload_offset >= 0:
                    extra = max(0, payload_offset - (length_offset + 1))
                else:
                    extra = 0
                base = length_offset + used + extra
            else:
                base = payload_offset if isinstance(payload_offset, int) \
                    and payload_offset >= 0 else length_offset + used
            end = offset + base + length
        if end <= offset or end > len(data):
            break
        frames.append(data[offset:end])
        offset = end
    return frames, len(data) - offset
