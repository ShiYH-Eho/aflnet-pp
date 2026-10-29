# utils/AI-agent/corpus-enrich — LLM-assisted seed corpus enrichment

One seed of an AFLNet(++) corpus is *one whole message sequence*: a chain of
client requests such as

```
USER ubuntu\r\nPASS ubuntu\r\nSYST\r\nPORT 127,0,0,1,132,209\r\nLIST\r\nQUIT\r\n
```

which the fuzzer replays message by message and mutates. Everything the initial
corpus does **not** contain, the fuzzer has to rediscover from scratch — and for
a stateful protocol that is the expensive part: a verb it has never seen, an
argument it has never seen, or a state it can only reach after a specific chain
of requests.

This directory contains a tool that rewrites that starting point with a model's
help. Service enrichment always runs; type and state-variable enrichment are
enabled independently by their optional inputs:

* **service coverage** — named protocol services such as authentication,
  directory listing and file transfer always receive enrichment jobs. When no
  service catalogue is supplied, the model discovers the protocol's services
  while solving the service task;
* **message type coverage** — every client request type the protocol defines
  should appear somewhere in the pool when ``--grammar`` is supplied. An
  explicit ``--types`` list also enables this task;
* **state variable coverage** — for every state variable of the target, some seed
  should drive it to each value it can take and through each branch it controls
  when ``--statevars`` is supplied.

The tasks are additive. ``--root`` optionally exposes a directory containing the
project repository, server configuration and other useful files through the
read-only ``list_dir``, ``read_file`` and ``search_text`` tools. Without
``--root`` the model receives no local tool access.

```text
utils/AI-agent/corpus-enrich/
├── enrich_corpus.py   # the tool: <corpus-dir> <output-dir> <protocol>
├── llmclient.py       # lazy shim around utils/AI-agent/statevar/llmclient.py
├── selftest.py        # offline regression test, needs no network
├── ../agent.py        # the shared JSON tool agent (also used by statevar,
│                      #   pro-template)
└── ../localtools.py   # list_dir / read_file / search_text, shared with statevar
```

Everything is Python 3.8+ with **no third-party dependency**, so the same files
work inside the AFLNet++ pre-image container. The chat client is the one shipped
with `utils/AI-agent/statevar` and speaks any OpenAI-compatible endpoint (OpenAI,
Azure, vLLM, Ollama, llama.cpp, LiteLLM ...).

## Quick start

```sh
# 1. Ask an endpoint. Services always run; grammar and statevars add the two
#    optional tasks. --root enables repository/config lookup:
export LLM_API_KEY=sk-...
python3 utils/AI-agent/corpus-enrich/enrich_corpus.py \
    profuzzbench/subjects/FTP/LightFTP/in-ftp /tmp/in-ftp-enriched FTP \
    --grammar grammars/ftp \
    --statevars lftp-statevars.json \
    --services ~/pre-scripts/FTP/services.json \
    --root profuzzbench/subjects/FTP/LightFTP/repo

# 2. Local model (vLLM / Ollama / llama.cpp speak the same API):
python3 utils/AI-agent/corpus-enrich/enrich_corpus.py in-ftp out-ftp FTP \
    --base-url http://localhost:11434/v1 --model qwen2.5:14b --api-key ollama

# 3. No endpoint handy: capture the prompts, answer them in a chat UI, replay the
#    answers offline (no network at all):
python3 utils/AI-agent/corpus-enrich/enrich_corpus.py \
    in-ftp out-ftp FTP --dump-prompt prompts/
python3 utils/AI-agent/corpus-enrich/enrich_corpus.py \
    in-ftp out-ftp FTP --from-answer answers/*.txt

# 4. Inspect what a corpus covers (no endpoint, no edits):
python3 utils/AI-agent/corpus-enrich/enrich_corpus.py \
    /tmp/in-ftp-enriched /tmp/in-ftp-enriched FTP --check \
    --types USER,PASS,ACCT,SMNT,REST,STOR,MDTM

# 5. Use the enriched corpus:
./afl-fuzz -N tcp://127.0.0.1/2200 -i /tmp/in-ftp-enriched -o out -- ./lightftp
```

## What it writes

The output directory is a complete corpus, ready to pass to `-i`: the original
seeds (copied, unless `--in-place`) plus one new file per generated sequence.

| file | produced by |
|---|---|
| `<original>` | copied unchanged |
| `enriched_service_<service>_r<round>_<seed>` | always-on service coverage |
| `enriched_r<round>-<n>_<seed>` | message type coverage |
| `enriched_sv_<variable>_<n>_<seed>` | state variable coverage |

`<seed>` is the base sequence the job started from, so a file can always be
traced back to its job; the machine-readable report names the same seed in its
`seeds[]` entries. Enriched files are ignored when the tool reads a corpus again
(like the ChatState fuzzer does), so `--in-place` is safe to re-run.

`<output>/.enrich.json` records the requested tasks and service catalogue, the
message type universe, coverage before and after, every generated service/type/
state-variable seed, the state variable values and code locations the model
claimed to target, per-task seed counts, tool calls, and every warning.

## Command line

```
python3 utils/AI-agent/corpus-enrich/enrich_corpus.py \
    <corpus-dir> <output-dir> <protocol> [options]
```

`corpus`, `output` and `protocol` are three required positional arguments.
`--check` looks like this:

```sh
python3 utils/AI-agent/corpus-enrich/enrich_corpus.py \
    <corpus-dir> <corpus-dir> <protocol> --check
```

| Option | Meaning |
|---|---|
| `--types LIST\|FILE` | explicit request types; also enables type enrichment |
| `--grammar DIR` | pro-template directory; enables message-type enrichment and supplies its classifier |
| `--formats FILE` | binary formats table from `pro-template --mode binary`; with `--grammar` the `.binary-formats.json` inside that directory is used by default |
| `--services FILE` | optional `services.json` / `service.json`; without it services are discovered at runtime |
| `--statevars FILE` | enables state-variable enrichment; accepts `identify.py` output, ChatState `state.json`, or `query.json` |
| `--root DIR` | optional project/config/server tree exposed to the model as read-only tools |
| `--terminator STR` | message terminator, escapes allowed (default `\r\n`) |
| `--rounds N` | enrichment rounds (default 2) |
| `--sv-variants N` | sequences asked per state variable (default 1) |
| `--types-per-job N` | missing types per request (default 2, ChatState's value) |
| `--max-missing-types N` | ignore a seed that is missing more than N types (default 10) |
| `--max-jobs-per-seed N` | cap the requests derived from one seed (default 5) |
| `--max-jobs N` | cap the requests of the whole run (default 60) |
| `--only-vars A,B` / `--ignore-types A,B` | narrow the work |
| `--base-seed NAME` | base sequence for the state variable tasks (default: the richest seed) |
| `--max-messages N` / `--max-message-bytes N` | caps on what is written (default 64 / 4096) |
| `--base-url`, `--api-key`, `--model`, `--temperature`, `--timeout`, `--retries`, `--json-mode` | endpoint configuration |
| `--max-steps N` | tool-use turns per job (default 12) |
| `--lang zh\|en` | language of the `rationale` field (default `zh`) |
| `--check` | report the coverage of a corpus and exit (no model, reads enriched seeds too) |
| `--dump-prompt DIR` | write one prompt per planned job to this directory and exit |
| `--from-answer FILE` | replay captured answers: a JSON object keyed by job id, or one answer per job in order (`-` reads stdin) |
| `--offline` | never contact the endpoint (needs `--from-answer`) |
| `--report FILE` | report path (default: `<output>/.enrich.json`) |
| `--in-place` | write the new seeds into the corpus directory itself |
| `--no-copy` | do not copy the original seeds into the output directory |
| `--force` | write into a non-empty output directory |
| `--strict` | fail (exit 1) on an endpoint error or a job without an answer/sequence |
| `--quiet`, `--verbose`, `--version` | output control |

Exit codes: `0` success; `1` a missing corpus, an unreachable endpoint that
produced nothing, a populated output directory without `--force`, `--offline`
without `--from-answer`, or a `--strict` failure; `2` a bad command line.

Endpoint configuration is read from the environment. All three AI-agent tools
use the same names, in this order:

```
LLM_BASE_URL   OPENAI_BASE_URL  AZURE_OPENAI_BASE_URL
LLM_API_KEY    OPENAI_API_KEY   AZURE_OPENAI_API_KEY
LLM_MODEL      OPENAI_MODEL
```

## How it works

1. **Read the corpus.** Every file becomes a list of messages, split on
   `--terminator` (a corpus that was captured with plain `\n` still works). For
   a binary protocol pass `--formats` (or a `--grammar` directory that carries
   `.binary-formats.json`): messages are then split with the framing table's
   length field (varint / 1/2/4 bytes, "payload" or "message" semantics), or
   one seed is one message when the protocol is a datagram one. A file name
   containing `enriched` is skipped when the corpus is read, so re-running over
   an enriched directory never treats generated seeds as input.
2. **Type every message.** With a binary formats table, each message's `probe`
   (offset + value/mask, one probe per nesting level) decides the type; with
   `--grammar` the templates of `utils/AI-agent/pro-template` decide (line 1 of
   each template is matched against the message); without either, the message
   *header* — the bytes up to the first space/CR/LF — is the type, which is how
   ChatState splits message types for line protocols. The type universe is the
   union of `--types`, grammar/formats type names, service-chain vocabulary and
   the types observed in the corpus.
3. **Select tasks.** `services` is always present. `--grammar` adds `types`;
   `--statevars` adds `statevars`. These conditions are independent and their
   jobs are combined in one run.
4. **Plan jobs.** Service jobs come first. With `--services`, every named
   service becomes one job; without it, one runtime-discovery job covers the
   protocol's services. Type jobs then fill per-seed gaps in round 1 and
   pool-level gaps in later rounds. State-variable jobs cover each variable and
   its requested variants. `--max-jobs*` caps the combined cost.
5. **Ask.** Each job is one prompt (system + task + the base sequence) and a
   small agent loop: the model answers with one JSON object per turn, either a
   tool call to inspect the workspace or the finished sequence. The tool
   contract is included only when `--root` is supplied. Text messages are
   rendered with visible `\r\n` markers. Binary messages are rendered as
   complete escaped frames plus their probe, layout and framing facts. Tool
   output is bounded and confined to `--root`.
6. **Write and check.** In text mode the answer is split back into messages and
   terminated with `--terminator`. In binary mode each answer element must be
   exactly one complete framed message: `\xNN` escapes are decoded, embedded
   CR/LF bytes are preserved, framing is validated, and frames are concatenated
   without a line terminator. Duplicate seeds are dropped with a warning. The
   corpus model is updated immediately. The report separates seeds by service,
   type and state-variable task.

## The prompt contract

```
{"action":"tool","tool":"read_file","args":{"path":"Source/ftpserv.c","start_line":200,"end_line":320}}
{"action":"tool","tool":"search_text","args":{"query":"MODE_PASSIVE","include":"*.c"}}
{"action":"final","seed":{"messages":["USER ubuntu","PASS ubuntu"],"rationale":"..."}}
```

The two tool-call lines are available only with `--root`. A service answer also
contains `"service"` and `"services_covered"`.

For a binary formats table, the same field holds one complete frame per element,
for example `"messages":["\\x10\\x0a\\x00\\x04MQTT..."]`. The JSON answer uses
`\\xNN` (two source backslashes), which decodes to byte `NN`.

For a state variable job the final answer also carries
`"state_var"`, `"values_targeted"` and `"locations"`, which the report keeps (a
cited file that is not in the workspace is flagged as `locations_ok: false`). The
tolerant answer parser accepts a bare list of messages, a fenced raw sequence and
a plain line-per-message answer as well, so a model that ignores the JSON
contract is not wasted work.

The prompts deliberately mirror the seed enrichment ChatState already performs
inside the fuzzer (`construct_store_code_prompt_stall`,
`construct_cond_code_prompt_stall`, `enrich_sequence` in `chat-llm.c`): the
consumer of this tool is the same state variable model, the difference is that
here the enrichment happens *before* the campaign, from a corpus, with the source
tree on disk to read and without a live server.

## Accuracy notes

The tool generates and organises seeds; it does not run the target.

* **service coverage is planned, not measured** — the service jobs and the
  model's `services_covered` claims are recorded, but only running the server
  can prove that a workflow completed successfully;
* **message type coverage is verified** — every generated sequence is re-typed
  after parsing, so `types_added`/`missing_after` in the report are facts about
  the bytes written, not claims by the model;
* **state variable coverage is planned, not measured** — without executing the
  server nobody can say that a sequence really reaches `MODE_PASSIVE`, so the
  report stores what the model targeted (`values_targeted`, the code locations it
  cited) together with its rationale. Measure the real thing after fuzzing with
  `AFLNET_STATE_MODE=2` (`docs/env_variables.md`);
* **the model can still be wrong** — a sequence that is valid FTP may still be
  rejected by a specific server (an `ACCT` after an anonymous login, a `REST`
  before `RETR` without a data channel). The base sequence is always carried
  over, so a bad addition costs one queue entry, not the session;
* **the type universe bounds the goal** — type enrichment is enabled by
  `--grammar` or `--types`, and its universe is the union of configured type
  names, service vocabulary and observed types;
* **cost** — one request (plus tool calls) per job, so `--max-jobs`,
  `--max-jobs-per-seed`, `--max-missing-types` and `--types-per-job` are the
  knobs that keep a big tree affordable.

## Requirements

* Python 3.8+, no `pip` packages;
* an OpenAI-compatible endpoint for the live path (not needed for `--check`,
  `--dump-prompt` or `--from-answer`);
* the sibling `utils/AI-agent/statevar` for the shared chat client (the shim
  reports a hint instead of crashing when it is missing, and the offline modes
  keep working without it).

## Testing

```sh
python3 utils/AI-agent/corpus-enrich/selftest.py     # offline, no network, temp dirs only
./test/test-corpus-enrich.sh                         # same checks, skipped without python3
```

The selftest builds a throw-away protocol tree (corpus, source, `state.json`,
`query.json`, `services.json`, grammar templates) and drives the whole offline
pipeline: the local tools with their sandbox, the message model, the three state
variable JSON shapes, the tolerant answer parser, `--dump-prompt` →
`--from-answer` → report, the second round that closes the pool level gaps,
duplicate detection, `--in-place`, `--check` and the exit codes.
