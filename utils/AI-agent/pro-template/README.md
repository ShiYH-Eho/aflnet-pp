# utils/AI-agent/pro-template — LLM-assisted protocol grammar templates

AFLNet++ can narrow the mutation of a state-relevant message down to one field of
that message when it knows the *shape* of the protocol (see `AFLNET_GRAMMAR` in
`docs/env_variables.md` and `src/aflnet/utils/grammar.c`). Writing one template
per client request type by hand is the slow part — for FTP that is 48 files, for
SIP it is more than a hundred.

This directory contains a small tool that asks an LLM for the client request
types of a protocol and writes **one template file per message type**, in the
exact format the fuzzer consumes.

```text
utils/AI-agent/pro-template/
├── gen_templates.py   # the tool: <protocol> <output-dir>
├── llmclient.py       # lazy shim around utils/AI-agent/statevar/llmclient.py
├── selftest.py        # offline regression test, needs no network
├── ../agent.py        # the shared JSON tool agent (also used by statevar,
│                      #   corpus-enrich)
└── ../localtools.py   # list_dir / read_file / search_text over the workspace
```

Everything is Python 3.8+ with **no third-party dependency**, so the same files
work inside the AFLNet++ pre-image container. The LLM client is shared with
`utils/AI-agent/statevar` and speaks any OpenAI-compatible endpoint (OpenAI, Azure,
vLLM, Ollama, llama.cpp ...). The agent loop and the workspace tools are shared
with the other two tools of `utils/AI-agent`: with `--root DIR` the model may
read the target implementation (`list_dir`, `read_file`, `search_text`) while it
proposes the request types, instead of working from protocol knowledge alone.

## Template format (what is written)

One file per message type, **file name = message type name**, two lines:

```
^(?:USER (.*)\r\n)$
(.+)
```

* line 1 — a PCRE2 **header pattern**, anchored at offset 0, which must match a
  whole message. Its capture groups are the *variable fields* of the message.
* line 2 — a PCRE2 **field pattern** used to find further mutable fields in the
  bytes *after* the header match (`template_collect_fields()` also adds the byte
  gaps between its matches as windows).

A request that spans several lines is split the same way the ChatState reference
templates are split: the **first** line, the one that carries the message type,
becomes line 1 and the remaining lines become the alternatives of line 2, so the
header match ends with the request line and the fields are found from there on.
`SETUP <<URI>> RTSP/1.0\r\nCSeq: <<CSEQ>>\r\n\r\n` becomes

```
^(?:SETUP (.*) RTSP/1\.0\r\n)
(?|(?:CSeq: (.*)\r\n)|(?:\r\n))
```

The alternatives are a PCRE2 branch reset (`(?|...)`) so every alternative
numbers its capture groups the same way, and the empty line that closes a header
block stays an alternative of its own. A *single* line command (`USER x\r\n`)
keeps the one line layout above, with the header anchored at both ends.

`src/aflnet/utils/grammar.c` splits each file at the first `\n` and trims a
trailing `\r\n`, so a file may end with a newline or not. The generator writes no
trailing newline, which makes its output byte identical to the reference corpus
shipped with ChatState (`prompt-test/sv_data/protocol-grammars/`) — a round trip
over those 48 FTP templates reproduces every file byte for byte, so both
generators can share one `AFLNET_GRAMMAR` directory.

### Binary protocols (`--mode binary`)

Text mode is the default and its templates stay byte-identical. A binary
protocol has no request line to key on, so `--mode binary` asks the model for a
byte example plus a field layout instead of a marked text message:

```json
{"templates": [{
  "type": "MQTT_CONNECT",
  "probe": [{"offset": 0, "value": "0x10"}],
  "example": "\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c",
  "layout": [
    {"name": "fixed_header", "offset": 0, "size": 1, "kind": "const",
     "value": "0x10", "mutable": false},
    {"name": "remaining_length", "offset": 1, "size": "varint", "kind": "length",
     "mutable": false},
    {"name": "protocol_name_len", "offset": 2, "size": 2, "kind": "const",
     "value": "0x0004", "mutable": false},
    {"name": "protocol_name", "offset": 4, "size": 4, "kind": "const",
     "value": "MQTT", "mutable": false},
    {"name": "protocol_level", "offset": 8, "size": 1, "kind": "const",
     "value": "0x04", "mutable": false},
    {"name": "connect_flags", "offset": 9, "size": 1, "kind": "bitfield",
     "mutable": true},
    {"name": "keepalive", "offset": 10, "size": 2, "kind": "uint16",
     "mutable": true}
  ],
  "description": "MQTT CONNECT handshake"
}]}
```

The tool derives the two-line template mechanically:

```
^(?:\x10(?:[\x80-\xff]*[\x00-\x7f])\x00\x04MQTT\x04([\x00-\xff]{1})([\x00-\xff]{2}))
([\x00-\xff]+)
```

* `mutable: true` fields become capture groups — they are the fuzzer's mutation
  windows;
* `const`/`magic` fields become literal bytes (`\x10`, `MQTT`, ...);
* version/length/checksum/padding fields become **non-capturing** byte classes:
  they must be present but are never mutated (the grammar layer reassembles
  bytes and cannot recompute a length or checksum);
* a field with `"size": "varint"` (or `"kind": "varint"`) becomes
  `[\x80-\xff]*[\x00-\x7f]`, so the same template accepts one-byte and
  multi-byte LEB128 values without hard-coding the example's length byte;
* bytes not covered by the layout are kept literal, and everything after the
  last described field is matched by line 2, `([\x00-\xff]+)`, so a variable
  payload is still a window;
* binary head patterns are prefix-anchored (no `$`) and `\xNN` escapes are
  decoded to bytes — only in this mode. Text mode keeps the historical `\xNN`
  behaviour so existing templates do not change.

`probe` is the message-type discriminator (fixed offset + value/mask, possibly
one per nesting level, e.g. TLS record content type at 0 and handshake type at
5). Both `probe` and `layout` are kept in `.templates.json` so a corpus
classifier can be derived from the same data.

If the target has to mutate a length or checksum field, add a postprocessor
(`AFL_POST_LIBRARY`) that recomputes it after mutation; the template itself only
freezes it.

The generator also writes `.binary-formats.json` next to the templates: the
per-type `probe`, `layout` and `example_hex`, plus the stream framing when the
answer carried one. The fuzzer loads this file at grammar initialisation and
uses the probes to choose the message type before applying its header regex;
this prevents a broad binary template from winning merely because its filename
sorts first. `--check` validates the file against the templates (probe vs
example, layout consts/ranges, the layout-derived header, and that the framing
reproduces the example) and reports `binary_formats` in `.check.json`.
`corpus-enrich --formats <dir>/.binary-formats.json` (or `--grammar <dir>`, which
finds the file automatically) uses the same table to split binary seeds into
messages and to classify them by type.

When the template matches the AFLNet mutation target (region M2), M2 is narrowed
to one randomly picked mutable window and reassembled afterwards, so the
protocol structure outside the variable fields is preserved.

## Quick start

```sh
# 1. Ask an endpoint (OpenAI or any compatible server):
export LLM_API_KEY=sk-...
python3 utils/AI-agent/pro-template/gen_templates.py ftp grammars/ftp

# 2. Local model (vLLM / Ollama / llama.cpp speak the same API):
python3 utils/AI-agent/pro-template/gen_templates.py ftp grammars/ftp \
    --base-url http://localhost:11434/v1 --model qwen2.5:14b --api-key ollama

# 3. No endpoint handy? Capture the prompt, paste it into a chat UI yourself,
#    save the answer and convert it offline:
python3 utils/AI-agent/pro-template/gen_templates.py ftp grammars/ftp --dump-prompt > prompt.txt
python3 utils/AI-agent/pro-template/gen_templates.py ftp grammars/ftp --from-answer answer.txt

# 4. Inspect and score a directory that already exists (no endpoint):
python3 utils/AI-agent/pro-template/gen_templates.py --check grammars/ftp \
    --seeds profuzzbench/subjects/FTP/BFTPD/in-ftp

# 5. Use it:
AFLNET_GRAMMAR=$PWD/grammars/ftp ./afl-fuzz -N tcp://127.0.0.1/2200 -i in -o out -- ./bftpd

# 6. Binary protocol (byte example + field layout -> two-line template):
python3 utils/AI-agent/pro-template/gen_templates.py mqtt grammars/mqtt --mode binary
```

## Command line

```
python3 utils/AI-agent/pro-template/gen_templates.py <protocol> <output-dir> [options]
python3 utils/AI-agent/pro-template/gen_templates.py --check <template-dir> [options]
```

| Option | Meaning |
|---|---|
| `--check` | inspect an existing directory instead of asking the model |
| `--seeds DIR` | score the templates against a seed corpus (one match report per type) |
| `--extract-seeds DIR` `--out-seeds DIR` | copy the matching seed of every type into `--out-seeds/<TYPE>/` |
| `--from-answer FILE [...]` | convert an already captured answer (`-` reads stdin) instead of calling the endpoint |
| `--offline` | never contact the endpoint (needs `--from-answer` or `--check`) |
| `--dump-prompt` | print the prompt of every round and exit |
| `--base-url`, `--api-key`, `--model` | endpoint configuration |
| `--temperature`, `--timeout`, `--retries` | request tuning (default `0.2`, `120 s`, `2`) |
| `--rounds N` | extraction rounds (default `2`): round 2 asks for the types still missing |
| `--mode text\|binary` | text protocol (default, unchanged) or binary byte-layout templates |
| `--root DIR` | target repository the model may inspect while it answers (enables the shared agent's `list_dir`/`read_file`/`search_text`) |
| `--max-steps N` | tool-use turns per round (default `16`) |
| `--json-mode` | also send `response_format={"type":"json_object"}` |
| `--types A B ...` | message types that must be covered |
| `--max-types N` | maximum number of request types per round (default `40`) |
| `--lang zh\|en` | language of the `description` fields (default `zh`) |
| `--keep-static` | keep templates without a mutable field |
| `--strict` | fail on endpoint errors and on warnings (exit 2) |
| `--force` | overwrite files this tool did not write (`.templates.json` is the marker) |
| `--quiet`, `--verbose`, `--version` | output control |

Exit codes: `0` success, `1` bad arguments / nothing usable, `2` endpoint failure
with `--strict`.

Endpoint configuration is read from the environment. All three AI-agent tools
use the same names, in this order:

```
LLM_BASE_URL   OPENAI_BASE_URL  AZURE_OPENAI_BASE_URL
LLM_API_KEY    OPENAI_API_KEY   AZURE_OPENAI_API_KEY
LLM_MODEL      OPENAI_MODEL
```

(`llmclient.py` is a PEP-562 shim: it loads `utils/AI-agent/statevar/llmclient.py` by path
into a private module and forwards attribute access to it, so the two tools
share one HTTP client. The load is lazy, which keeps `--check`, `--dump-prompt`
and `--from-answer` working even when the sibling directory is not present — in
that case the shim reports `available() == False` and `hint()` explains why
instead of raising an `ImportError`.)

## How it works

1. **Prompt.** A protocol-specific hint (the known request verbs of FTP, SMTP,
   RTSP, SIP, HTTP, IMAP, POP3, TLS, DNS, DHCP, MQTT, SSH, SNMP, DICOM, Modbus,
   SMPP) is combined with a strict output contract: a JSON list of
   `{type, request, description}` where `request` is one *example* message with
   `<<PLACEHOLDER>>` markers for the variable parts. Round 2 lists the types that
   were collected and asks for the ones still missing. In `--mode binary` the
   contract is a byte `example` plus a `layout` and a `probe` (see above). With
   `--root DIR` the
   request goes through the shared JSON agent (`../agent.py`) instead of a single
   call: the model may read the implementation first and its tool calls are
   answered from the workspace (`../localtools.py`), which keeps the proposed
   request types to the ones the target really implements.
2. **Parse.** The answer is parsed tolerantly: JSON (with code fences, trailing
   commas, or a `types`/`templates`/`requests` wrapper), a `TYPE: [ ... ]` map as
   used by ChatState, or plain `<TYPE>: <request>` lines with `key: value` detail
   lines.
3. **Convert.** The *model never writes a regex*. The example request is escaped
   and every `<<PLACEHOLDER>>` becomes a capture group (in binary mode the
   layout's mutable fields become the groups and its framing fields stay
   non-capturing):
   `USER <<USERNAME>>\r\n` → `^(?:USER (.*)\r\n)$`. A request that spans several
   lines is split: the request line becomes the *header* pattern and the other
   lines the alternatives of the *field* pattern (see above), which is what keeps
   a header block out of line 1. The terminator is re-added for the CRLF
   protocols when the answer lost it, and the pattern is only anchored with `$`
   when it is known complete (a multi line header pattern is not, the field scan
   continues after it). Templates without any capture group are dropped
   (`--keep-static` keeps them; `grammar.c` then treats the whole message as
   mutable).
4. **Verify.** Every generated header pattern is compiled with `re` (or the
   example is at least escaped consistently when a PCRE2-only construct is used)
   and matched against its own example; a mismatch is reported as a warning and
   fails the run under `--strict`.
5. **Write.** `<output>/<TYPE>` for every type plus `<output>/.templates.json`
   with the description, the header, the field pattern, warnings and the exact
   `AFLNET_GRAMMAR=` line to use. Types removed by a re-run are listed in the
   meta file instead of being deleted silently.

## Checking and scoring

`--check` re-reads a directory, prints one row per template (capture groups,
header) and, with `--seeds`, tries to match every message of a seed corpus
against every template:

```
$ python3 utils/AI-agent/pro-template/gen_templates.py --check grammars/ftp \
      --seeds profuzzbench/subjects/FTP/BFTPD/in-ftp
[+] APPE             1/13 seed(s) match, e.g. 'APPE teste.txt'
[+] CWD              1/13 seed(s) match, e.g. 'CWD test'
[!] LIST             no seed matched its header pattern
```

A seed corpus is a set of files that contain whole request chains
(`USER ubuntu\r\nPASS ubuntu\r\nTYPE A\r\n`), so the checker also tries every
individual line of a file; a template that matches *no* seed is flagged, which is
usually either a verb the target does not implement or a wrong terminator.

`--extract-seeds DIR --out-seeds DIR2` copies, for every template, the first
message that matched it into `DIR2/<TYPE>/`, which is a quick way to build a
per-type corpus to look at.

The report is written to `<template-dir>/.check.json`.

## Accuracy notes

* the model proposes the *vocabulary*, the tool derives the *syntax*: an
  unusable or invented regex cannot enter a template, and a wrong placeholder is
  at worst a slightly too narrow or too wide mutable window;
* greedy `(.*)` groups mean several placeholders in one message can be merged
  (`PORT (.*),(.*),(.*),(.*)` still exposes the address as a field — the split
  is just not the one a human would draw);
* verbs the target does not implement (or that only appear in responses) are
  harmless extra files: an unused template simply never matches;
* a protocol with binary framing (`MQTT`, `TLS`) gets prefix patterns without
  `$`, so the template still matches a longer message;
* the reference corpus of ChatState matches 30 of its own 48 FTP templates on
  the BFTPD seeds, which is a good order of magnitude for what to expect.

## Requirements

* `libpcre2-dev` **to build** the fuzzer with grammar support (`AFLNET_GRAMMAR`
  is compiled out without it) — the generator itself does **not** need PCRE2, it
  only needs a Python `re`-compatible pattern and warns when it is not;
* Python 3.8+; no `pip` packages;
* the templates must be readable at fuzzer startup: `AFLNET_GRAMMAR` is imported
  once and the importer reports `Imported N protocol grammar template(s)`.

## Testing

```sh
python3 utils/AI-agent/pro-template/selftest.py      # offline, no network, temp dirs only
./test/test-pro-template.sh                 # same checks, skipped without python3
```

The selftest covers the text helpers, the header shapes (terminator handling,
placeholders, static messages, binary protocols), the head/field split of a
multi line request (escaped and real line breaks, a placeholder that only appears
in a header, a regex answer that spells both lines out), all three answer
formats, the prompt builder, the `--from-answer`/`--check`/`--extract-seeds`
flows, the CLI contract (exit codes, `--dump-prompt`, `--offline` with no answer)
and the shared chat client (that it forwards to `utils/AI-agent/statevar` instead of
looping back into itself, and that a missing sibling degrades to a hint).

## Note on the reference path

The request mentioned `~/ChatState/benchmark/subjects/*/grammar` as the format
reference; that path does not exist on this machine. The corpus that was used to
match the byte-for-byte layout is
`~/ChatState/prompt-test/sv_data/protocol-grammars/` (48 FTP files, e.g.
`USER` = `^(?:USER (.*)\r\n)$` + `(.+)`, no trailing newline). A round trip over
that corpus reproduces all 48 files byte for byte.
