# utils/AI-agent/statevar — LLM-assisted state-variable identification and annotation

AFLNet++ gets its best results when the *state variables* of the target are
known: the server state or mode a request handler implements, which persists
across client requests and whose value — changed by one request — decides how a
later request is served. They can be tagged with
`__attribute__((annotate("__AFL_STATE_VAR__")))` and fed to the fuzzer through
the state-variable backend (`AFLNET_STATE_MODE=2`, see
`instrumentation/afl-llvm-statevar-pass.so.cc` and `src/aflnet/utils/AI-agent/statevar.c`).

This directory holds two small tools:

* **identify.py** — one LLM agent, the same shape as ChatState's
  `ai-agent/query.py`: it is told the three characteristics a state variable
  must satisfy, reads the repository with three read-only tools and returns the
  variables it found with their definition sites;
* **annotate.py** — writes the annotation into the sources at those sites.

```text
utils/AI-agent/statevar/
├── identify.py     # identification: <repository-dir> <output.json>
├── annotate.py     # annotation: <output.json> edits the sources in place
├── cscan.py        # standalone heuristic candidate scanner (not used by the tools)
├── llmclient.py    # stdlib-only client for any OpenAI-compatible endpoint
└── selftest.py     # offline regression test, needs no network
                ../agent.py        # the shared JSON tool agent
                ../localtools.py   # list_dir / read_file / search_text, shared
```

Everything is Python 3.8+ with **no third-party dependency**, so the same files
work inside the AFLNet++ pre-image container. The chat client and the workspace
tools are shared with `utils/AI-agent/corpus-enrich`.

## Quick start

```sh
# 1. Ask an endpoint (OpenAI or any compatible server):
export LLM_API_KEY=sk-...
python3 utils/AI-agent/statevar/identify.py \
    profuzzbench/subjects/FTP/LightFTP/repo lftp-statevars.json

# 2. Local model (vLLM / Ollama / llama.cpp speak the same API):
python3 utils/AI-agent/statevar/identify.py ~/src/foo foo-statevars.json \
    --protocol ftp --base-url http://localhost:11434/v1 --model qwen2.5:14b \
    --api-key ollama

# 3. No endpoint handy: dump the prompt, answer it in a chat UI, convert:
python3 utils/AI-agent/statevar/identify.py ~/src/foo foo-statevars.json \
    --dump-prompt prompt.txt
python3 utils/AI-agent/statevar/identify.py ~/src/foo foo-statevars.json \
    --from-answer answer.txt

# 4. Close the loop: write __AFL_STATE_VAR__ into the sources:
python3 utils/AI-agent/statevar/annotate.py foo-statevars.json --repo ~/src/foo --dry-run
python3 utils/AI-agent/statevar/annotate.py foo-statevars.json --repo ~/src/foo
```

## What a state variable is

The prompt uses the definition of the ChatState state analysis
(`ai-agent/query.py`, `build_state_prompt`): a variable must satisfy **all
three** of

1. it implements a network protocol server state or server mode defined in the
   RFC;
2. it persists across multiple client requests at runtime;
3. client requests can change it, and its value influences the server behaviour
   triggered by later client requests.

## Output format

```json
[
  {
    "name": "Access",
    "description": "当前会话的访问级别；LOGIN 成功后由 FTP_ACCESS_NOLOGIN 提升，决定哪些命令被允许。",
    "location": "Source/ftpserv.h:92",
    "type": "int"
  }
]
```

The file is a list, one object per variable, with exactly four fields:

| field | meaning |
|---|---|
| `name` | the variable or struct member name (a qualified name such as `context->Mode` is kept) |
| `description` | one sentence that says which protocol state it carries |
| `location` | definition site as `file:line`, **relative to the scanned repository** |
| `type` | the declared C type |

The answer is validated before it is written: the file has to exist under the
repository, the line has to be inside it, and the name has to occur in the file
(`context->Mode` is checked as `Mode`). Entries that fail are dropped with a
warning on stderr, and duplicates of `(name, location)` are collapsed.

Because the list does not name the repository it was produced from, a consumer
that opens the files has to be pointed at that tree: `annotate.py` takes
`--repo DIR` (or run it from the repository root), `corpus-enrich` derives the
root from the corpus location or its own `--root`.

## How it works

1. **Prompt.** The system prompt is the one of ChatState's `query.py` agent
   (concise source-code analysis, one JSON object per turn, tools; see
   `../localtools.py`). The user prompt carries the three criteria, the
   workspace root and the answer contract above.
2. **Tool loop.** The model answers with
   `{"action":"tool","tool":"read_file","args":{...}}` until it has enough
   evidence (at most `--max-steps` turns); every tool result is fed back. The
   tools are read-only, keep every path inside the repository and bound each
   answer (lines, entries, search hits), so a large tree is explored in small
   targeted reads.
3. **Answer.** The final turn is `{"action":"final","answer":{...}}`. The answer
   parser is tolerant: `{"state_variables":[...]}`, a bare list, a single
   object, or query.py's `{name: "file:line"}` mapping all work, with or without
   a markdown fence.
4. **Export.** The entries are validated (file, line range, name occurrence),
   deduplicated and written as the four-field list. Nothing is inferred beyond
   what the model read.
5. **Annotate.** `annotate.py` opens the ``file:line`` of every entry, finds the
   variable on that line and inserts the attribute after the declarator (see
   below).

## Command line

```
python3 utils/AI-agent/statevar/identify.py <repository-dir> <output.json> [options]
```

| Option | Meaning |
|---|---|
| `--protocol NAME` | protocol/project name used in the prompt (default: derived from the repository path) |
| `--max-steps N` | tool-use turns before giving up (default 32) |
| `--base-url`, `--api-key`, `--model`, `--temperature`, `--timeout`, `--retries`, `--json-mode` | endpoint configuration |
| `--lang zh\|en` | language of the descriptions (default `zh`) |
| `--dump-prompt FILE` | write the exact system+user prompt and exit (no endpoint) |
| `--from-answer FILE` | convert a captured answer instead of calling the model (`-` reads stdin) |
| `--strict` | exit 1 when no state variable was identified |
| `--quiet`, `--verbose`, `--version` | output control |

Endpoint configuration is read from the environment. All three AI-agent tools
use the same names, in this order:

```
LLM_BASE_URL   OPENAI_BASE_URL  AZURE_OPENAI_BASE_URL
LLM_API_KEY    OPENAI_API_KEY   AZURE_OPENAI_API_KEY
LLM_MODEL      OPENAI_MODEL
```

Exit codes: `0` success, `1` bad repository / endpoint failure / an empty result
with `--strict`, `2` argument error.

## Writing the result back (`annotate.py`)

```sh
python3 utils/AI-agent/statevar/annotate.py foo-statevars.json --repo <repo> --dry-run
python3 utils/AI-agent/statevar/annotate.py foo-statevars.json --repo <repo>
```

It inserts the attribute the pass looks for at every declaration the list points
at:

```c
static unsigned int g_counter __attribute__((annotate("__AFL_STATE_VAR__"))) = 0;

struct FTPCONTEXT {
  int  Access     __attribute__((annotate("__AFL_STATE_VAR__")));  /* ftpserv.h:92 */
  char CurrentDir[PATH_MAX] __attribute__((annotate("__AFL_STATE_VAR__")));
  ...
};
```

The attribute goes *after* the declarator, past any array suffix, the position
clang and gcc both accept for a global, a struct member, a parameter and an
automatic local. The list already carries the exact definition site, so the tool
does not search for anything: it goes to that line, picks the variable on it
(``context->Mode`` is looked up as ``Mode``) and inserts the attribute. It is
byte-exact (line endings included) and idempotent: a line that already carries
the annotation -- spelled out or through a ``#define`` alias in the same file --
is left alone. A line whose variable is not there, a bit-field, a non-C source or
a missing file is reported instead of being guessed at.

| Option | Meaning |
|---|---|
| `--repo DIR` | repository root for the relative locations (default: the current directory) |
| `--dry-run` / `--check` | show the diff / exit 1 when a change is pending (both write nothing) |
| `--backup` | keep a `.bak` copy before editing |
| `--quiet` | no progress on stderr |

## cscan.py — a standalone candidate scanner

Neither tool needs the scanner any more (the agent reads the code and the
annotator trusts the JSON), but `cscan.py` is still a fast, dependency-free
*ranking* of state-variable candidates for browsing a tree by hand:

```sh
python3 utils/AI-agent/statevar/cscan.py profuzzbench/subjects/FTP/LightFTP/repo --top 30
python3 utils/AI-agent/statevar/cscan.py profuzzbench/subjects/FTP/LightFTP/repo --json
```

It blanks comments/strings length-preservingly, parses declarations, and counts
state-like usage (constant comparisons, `switch` cases, assignments, references).
That ranking is **not** used by `identify.py` any more — it is a quick way to
browse a tree by hand.

## Accuracy notes

* the model decides; there is no heuristic pre-ranking that can hide a variable
  from it or promote a scratch buffer into the list. Give it a model that can
  follow tool calls and read C;
* every exported location is checked (file exists, line in range, name appears);
  what remains is "the model picked this variable and this site", which is what
  the `description` is for;
* there are no confidence scores: audit by re-running with `--dump-prompt` and a
  different model, or by reading the listed declarations;
* one run is one agent conversation: `--max-steps` bounds it, and stderr shows
  every tool call with `--verbose`.

## Testing

```sh
python3 utils/AI-agent/statevar/selftest.py
```

runs fully offline: the scanner against `test/test-statevar.c`, the prompt
contract, the answer normalisation (list / mapping / `answer` wrappers, absolute
paths, duplicates, dropped locations), the agent loop against a stub client
(tool call → tool result → final answer), `--dump-prompt`/`--from-answer`, and
`annotate.py` — including the `identify.py` → `annotate.py` pipeline and, when
clang is installed, that the annotated source compiles and emits the annotation
records the pass reads. Nothing is written outside a temporary directory.
