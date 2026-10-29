#!/bin/bash
# test/test-corpus-enrich.sh — offline test for
# utils/AI-agent/corpus-enrich/enrich_corpus.py
#
# The tool is pure Python: it reads a corpus of message sequences and asks an
# LLM for sequences that cover the protocol's message types and the target's
# state variables.  This test never contacts an endpoint and never needs a
# build; it drives the --dump-prompt/--from-answer/--check paths, which are the
# only ones that touch the files the fuzzer consumes, and skips when python3 is
# not available.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TOOL_DIR="$AFL_DIR/utils/AI-agent/corpus-enrich"
TOOL="$TOOL_DIR/enrich_corpus.py"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[-] python3 not available; skipping"
  exit 0
fi
if [ ! -f "$TOOL" ]; then
  echo "[-] $TOOL not found; skipping"
  exit 0
fi

PY=python3
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

echo "[*] Testing: utils/AI-agent/corpus-enrich/enrich_corpus.py"

# --- 1. the tool's own regression test ------------------------------------
$PY "$TOOL_DIR/selftest.py" >"$TMP/selftest.log" 2>&1 || {
  echo "[-] selftest.py failed:"
  cat "$TMP/selftest.log"
  exit 1
}
TOTAL=$(grep -c '^\[+\]' "$TMP/selftest.log" || true)
echo "[+] python3 selftest.py: $TOTAL check(s) passed"

# --- 2. a corpus with missing message types -------------------------------
IN="$TMP/in-ftp"
mkdir -p "$IN"
printf 'USER ubuntu\r\nPASS ubuntu\r\nLIST\r\nQUIT\r\n' >"$IN/seed_a.raw"
printf 'USER anonymous\r\nPASS x\r\nPWD\r\nQUIT\r\n' >"$IN/seed_b.raw"
TYPES="USER,PASS,LIST,PWD,QUIT,ACCT,SMNT,REST,STOR,MDTM"

$PY "$TOOL" --check "$IN" "$IN" FTP --types "$TYPES" --report "$TMP/before.json" \
    >"$TMP/check-before.log" 2>&1 || {
  echo "[-] --check failed:"
  cat "$TMP/check-before.log"
  exit 1
}
$PY - "$TMP/before.json" <<'PYX'
import json, sys
report = json.load(open(sys.argv[1]))
missing = report['coverage']['missing_types']
assert len(missing) == 5, 'the bare corpus must miss 5 types: %r' % missing
print('the corpus misses %s' % ', '.join(missing))
PYX
echo "[+] --check reports the message types a corpus does not cover"

# --- 3. capture the prompts, answer them, replay --------------------------
PROMPTS="$TMP/prompts"
OUT="$TMP/out-ftp"
$PY "$TOOL" "$IN" "$OUT" FTP --dump-prompt "$PROMPTS" --types "$TYPES" \
    --rounds 1 --quiet >"$TMP/dump.log" 2>&1 || {
  echo "[-] --dump-prompt failed:"
  cat "$TMP/dump.log"
  exit 1
}
if [ ! -f "$PROMPTS/jobs.json" ]; then
  echo "[-] --dump-prompt wrote no job list"
  exit 1
fi
JOBS=$(ls "$PROMPTS" | grep -c '^job-.*\.txt$')
echo "[+] --dump-prompt wrote $JOBS prompt(s) plus jobs.json"

# Answer every job with a sequence that adds the first type it asked for; the
# answers are keyed by job id, which is how a chat UI round trip is replayed.
# The user line carries the job name so that two seeds answering the same gap
# with the same sequence do not collapse into one (that is what the tool
# deduplicates, and the selftest covers it separately).
$PY - "$PROMPTS/jobs.json" "$TMP/answers.json" <<'PY'
import json, sys
jobs = json.load(open(sys.argv[1]))['jobs']
answers = {}
for job in jobs:
    want = (job['missing_types'] or ['NOOP'])[0]
    answers[job['id']] = json.dumps({'action': 'final', 'seed': {
        'messages': ['USER %s' % job['id'].replace('-', '_'), 'PASS ubuntu',
                     want, 'QUIT'],
        'types_added': [want], 'rationale': 'covers %s' % want}})
json.dump(answers, open(sys.argv[2], 'w'))
print('%d answers written' % len(answers))
PY

$PY "$TOOL" "$IN" "$OUT" FTP --from-answer "$TMP/answers.json" --types "$TYPES" \
    --rounds 2 --quiet >"$TMP/replay.log" 2>&1 || {
  echo "[-] --from-answer failed:"
  cat "$TMP/replay.log"
  exit 1
}
for f in seed_a.raw seed_b.raw; do
  if [ ! -f "$OUT/$f" ]; then
    echo "[-] the original seed $f was not copied"
    exit 1
  fi
done
ENRICHED=$(ls "$OUT" | grep -c '^enriched_')
if [ "$ENRICHED" -lt 6 ]; then
  echo "[-] too few enriched seeds: $ENRICHED"
  ls "$OUT"
  exit 1
fi
echo "[+] the output corpus holds the originals plus $ENRICHED enriched seed(s)"

# the enriched files must be terminated exactly like the input corpus
$PY - "$OUT" <<'PYX'
import os, sys
out = sys.argv[1]
seed = open(os.path.join(out, 'seed_a.raw'), 'rb').read()
assert seed == b'USER ubuntu\r\nPASS ubuntu\r\nLIST\r\nQUIT\r\n'
for name in sorted(os.listdir(out)):
    if not name.startswith('enriched_'):
        continue
    data = open(os.path.join(out, name), 'rb').read()
    assert data.endswith(b'\r\n'), '%s is not CRLF terminated' % name
    assert b'\n\n' not in data, '%s has a blank line' % name
report = None
import json
report = json.load(open(os.path.join(out, '.enrich.json')))
stats = report['statistics']
assert stats['seeds_written'] >= 6, stats
assert report['coverage_after']['observed_types'], 'no coverage recorded'
print('report: %d seed(s) written, %d type(s) after'
      % (stats['seeds_written'], len(report['coverage_after']['observed_types'])))
PYX
echo "[+] the report accounts for every written seed"

# --- 4. the enriched corpus scores better than the input ------------------
$PY "$TOOL" --check "$OUT" "$OUT" FTP --types "$TYPES" --report "$TMP/after.json" \
    --quiet >"$TMP/check-after.log" 2>&1 || {
  echo "[-] --check on the enriched corpus failed:"
  cat "$TMP/check-after.log"
  exit 1
}
$PY - "$TMP/before.json" "$TMP/after.json" <<'PYX'
import json, sys
before = json.load(open(sys.argv[1]))['coverage']['missing_types']
after = json.load(open(sys.argv[2]))['coverage']['missing_types']
assert len(after) < len(before), 'coverage did not improve: %r -> %r' % (before, after)
print('missing types %d -> %d' % (len(before), len(after)))
PYX
echo "[+] the enriched corpus covers more message types than the input"

# --- 5. an in-place run keeps the corpus usable ---------------------------
$PY "$TOOL" "$IN" "$IN" FTP --in-place --from-answer "$TMP/answers.json" \
    --types "$TYPES" --rounds 1 --quiet >"$TMP/inplace.log" 2>&1 || {
  echo "[-] --in-place failed:"
  cat "$TMP/inplace.log"
  exit 1
}
BEFORE_COUNT=$(ls "$IN" | grep -c '^enriched_')
$PY "$TOOL" "$IN" "$IN" FTP --in-place --from-answer "$TMP/answers.json" \
    --types "$TYPES" --rounds 1 --quiet >"$TMP/inplace2.log" 2>&1 || {
  echo "[-] the second --in-place run failed:"
  cat "$TMP/inplace2.log"
  exit 1
}
AFTER_COUNT=$(ls "$IN" | grep -c '^enriched_')
if [ "$BEFORE_COUNT" != "$AFTER_COUNT" ] || [ "$AFTER_COUNT" -eq 0 ]; then
  echo "[-] an in-place re-run changed the corpus ($BEFORE_COUNT -> $AFTER_COUNT)"
  exit 1
fi
echo "[+] --in-place enriches the corpus and a re-run is idempotent"

# --- 6. the offline contract ----------------------------------------------
if $PY "$TOOL" "$IN" "$TMP/nope" FTP --offline >/dev/null 2>&1; then
  echo "[-] --offline without --from-answer must fail"
  exit 1
fi
if $PY "$TOOL" "$TMP/does-not-exist" "$TMP/out" FTP >/dev/null 2>&1; then
  echo "[-] a missing corpus must fail"
  exit 1
fi
$PY "$TOOL" --help >/dev/null 2>&1
$PY "$TOOL" --version | grep -qE '[0-9]+\.[0-9]+'
echo "[+] --offline refuses to contact an endpoint, --help/--version work"

echo "[+] utils/AI-agent/corpus-enrich looks correct"
