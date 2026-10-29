#!/bin/bash
# test/test-pro-template.sh — offline test for
# utils/AI-agent/pro-template/gen_templates.py
#
# The generator is a pure Python tool: it asks an LLM for the message types of a
# protocol and writes one AFLNet++ grammar template per type.  This test never
# contacts an endpoint and never needs a build; it drives the --from-answer and
# --check paths, which are the ones the fuzzer consumes, and only runs when
# python3 is available.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TOOL_DIR="$AFL_DIR/utils/AI-agent/pro-template"
GEN="$TOOL_DIR/gen_templates.py"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[-] python3 not available; skipping"
  exit 0
fi
if [ ! -f "$GEN" ]; then
  echo "[-] $GEN not found; skipping"
  exit 0
fi

PY=python3
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

echo "[*] Testing: utils/AI-agent/pro-template/gen_templates.py"

# --- 1. the tool's own regression test -------------------------------------
$PY "$TOOL_DIR/selftest.py" >"$TMP/selftest.log" 2>&1 || {
  echo "[-] selftest.py failed:"
  cat "$TMP/selftest.log"
  exit 1
}
TOTAL=$(grep -c '^\[+\]' "$TMP/selftest.log" || true)
echo "[+] python3 selftest.py: $TOTAL check(s) passed"

# --- 2. an answer becomes one template per message type --------------------
ANSWER="$TMP/answer.json"
cat >"$ANSWER" <<'JSON'
{"templates": [
  {"type": "USER", "request": "USER <<USERNAME>>\r\n", "description": "login name"},
  {"type": "PASS", "request": "PASS <<PASSWORD>>\r\n", "description": "login password"},
  {"type": "PORT", "request": "PORT <<H1>>,<<H2>>,<<H3>>,<<H4>>,<<P1>>,<<P2>>\r\n",
   "description": "data address"},
  {"type": "SYST", "request": "SYST\r\n", "description": "static, no field"}
]}
JSON

OUT="$TMP/grammar"
$PY "$GEN" ftp "$OUT" --from-answer "$ANSWER" >"$TMP/gen.log" 2>&1 || {
  echo "[-] --from-answer failed:"
  cat "$TMP/gen.log"
  exit 1
}

for t in USER PASS PORT; do
  if [ ! -f "$OUT/$t" ]; then
    echo "[-] template $t was not written"
    cat "$TMP/gen.log"
    exit 1
  fi
done
if [ -e "$OUT/SYST" ]; then
  echo "[-] a template without a mutable field must be dropped by default"
  exit 1
fi
echo "[+] one file per message type: $(ls "$OUT" | grep -vc '^\.') written, static type dropped"

# the file must be exactly "header\nfield" with no trailing newline, like the
# reference corpus in ChatState (prompt-test/sv_data/protocol-grammars)
FIRST=$($PY - "$OUT/USER" <<'PY'
import sys
raw = open(sys.argv[1], 'rb').read()
want = b'^(?:USER (.*)\\r\\n)$\n(.+)'
print('ok' if raw == want else repr(raw))
PY
)
if [ "$FIRST" != "ok" ]; then
  echo "[-] unexpected USER template layout: $FIRST"
  exit 1
fi
echo "[+] template layout is byte identical to the reference corpus (no trailing newline)"

# the CRLF terminator the JSON answer escaped must survive the conversion
if ! grep -qF '^(?:PASS (.*)\r\n)$' "$OUT/PASS"; then
  echo "[-] the CRLF terminator was lost"
  exit 1
fi
echo "[+] CRLF terminators survive the answer conversion"

# --- 3. an answer can also be plain lines ---------------------------------
$PY - >"$TMP/plain.txt" <<'PY'
print('type: APPE')
print('request: APPE <<PATH>>')
print('description: append to a file')
print('')
print('type: DELE')
print('request: DELE <<PATH>>')
PY
PLAIN="$TMP/grammar-plain"
$PY "$GEN" ftp "$PLAIN" --from-answer "$TMP/plain.txt" >"$TMP/plain.log" 2>&1 || {
  echo "[-] a plain line answer was not converted:"
  cat "$TMP/plain.log"
  exit 1
}
if [ ! -f "$PLAIN/APPE" ] || [ ! -f "$PLAIN/DELE" ]; then
  echo "[-] a plain line answer produced the wrong files: $(ls "$PLAIN")"
  exit 1
fi
if [ "$(head -1 "$PLAIN/APPE")" != '^(?:APPE (.*)\r\n)$' ]; then
  echo "[-] unexpected APPE header: $(head -1 "$PLAIN/APPE")"
  exit 1
fi
echo "[+] a plain '<type>: <request>' answer is converted too"

# --- 4. --check inspects a directory and scores it against seeds ----------
SEEDS="$TMP/seeds"
mkdir -p "$SEEDS"
printf 'USER anonymous\r\nPASS secret\r\n' >"$SEEDS/seed_1.raw"
printf 'USER anonymous\r\n' >"$SEEDS/seed_2.raw"
printf 'PORT 127,0,0,1,1,2\r\n' >"$SEEDS/seed_3.raw"

$PY "$GEN" --check "$OUT" --seeds "$SEEDS" >"$TMP/check.log" 2>&1 || {
  echo "[-] --check failed:"
  cat "$TMP/check.log"
  exit 1
}
if [ ! -f "$OUT/.check.json" ]; then
  echo "[-] --check wrote no report"
  exit 1
fi
$PY - "$OUT/.check.json" <<'PYX'
import json, sys
report = json.load(open(sys.argv[1]))
user = report.get('USER') or {}
assert user.get('matched') == 2, 'USER must match both seeds: %r' % (user,)
assert user.get('seeds') == 3, 'USER must be scored against all seeds'
assert report.get('PORT', {}).get('matched') == 1, 'PORT matches its seed'
assert report.get('PASS', {}).get('matched') == 1, 'PASS matches its seed'
assert 'SYST' not in report, 'SYST is not a template'
print('USER matched %d/%d seed(s)' % (user['matched'], user['seeds']))
PYX
echo "[+] --check scores the templates against a seed corpus"

# --- 5. --extract-seeds copies the matching message of every type ----------
EXTRACT="$TMP/extract"
$PY "$GEN" --check "$OUT" --seeds "$SEEDS" --extract-seeds "$SEEDS" \
    --out-seeds "$EXTRACT" >"$TMP/extract.log" 2>&1 || {
  echo "[-] --extract-seeds failed:"
  cat "$TMP/extract.log"
  exit 1
}
if [ ! -d "$EXTRACT/USER" ] || [ -z "$(ls -A "$EXTRACT/USER")" ]; then
  echo "[-] no USER message was extracted: $(ls -R "$EXTRACT" 2>&1)"
  exit 1
fi
echo "[+] --extract-seeds writes one directory per message type"

# --- 6. the offline contract ----------------------------------------------
if $PY "$GEN" ftp "$TMP/nope" --offline >/dev/null 2>&1; then
  echo "[-] --offline without --from-answer must be an argument error"
  exit 1
fi
$PY "$GEN" --help >/dev/null 2>&1
$PY "$GEN" --version | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'
echo "[+] --offline refuses to contact an endpoint, --help/--version work"

# --- 7. the generated templates are valid PCRE2 patterns ------------------
if pkg-config --exists libpcre2-8 2>/dev/null; then
  cat >"$TMP/pcre.c" <<'EOC'
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* usage: pcre <template> <message> <window_start> <window_len> [<concat>]
 *   - the template's first line must compile and match <message> exactly
 *   - its first capture group must cover [window_start, window_start+len)
 *   - when <concat> is given, the pattern must not match it
 */
static char *slurp(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f) { return NULL; }
  char *buf = malloc(1 << 20);
  *len = fread(buf, 1, 1 << 20, f);
  fclose(f);
  return buf;
}

int main(int argc, char **argv) {
  if (argc < 5) { return 2; }
  size_t tlen, mlen; PCRE2_SIZE off;
  char *tpl = slurp(argv[1], &tlen);
  char *msg = slurp(argv[2], &mlen);
  if (!tpl || !msg) { return 2; }
  char *nl = memchr(tpl, '\n', tlen);
  if (!nl) { return 2; }
  *nl = 0;
  int err;
  pcre2_code *re = pcre2_compile((PCRE2_SPTR)tpl, PCRE2_ZERO_TERMINATED, 0,
                                 &err, &off, NULL);
  if (!re) { return 3; }
  pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, NULL);
  int rc = pcre2_match(re, (PCRE2_SPTR)msg, mlen, 0, 0, md, NULL);
  if (rc <= 1) { return 4; }
  PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
  size_t want = (size_t)atoi(argv[3]);
  size_t wlen = (size_t)atoi(argv[4]);
  if (ov[2] != want || ov[3] != want + wlen) {
    fprintf(stderr, "group is [%lu,%lu), want [%lu,%lu)\n",
            (unsigned long)ov[2], (unsigned long)ov[3],
            (unsigned long)want, (unsigned long)(want + wlen));
    return 5;
  }
  if (argc > 5) {
    size_t clen;
    char *concat = slurp(argv[5], &clen);
    if (!concat) { return 2; }
    if (pcre2_match(re, (PCRE2_SPTR)concat, clen, 0, 0, md, NULL) > 0) {
      fprintf(stderr, "the pattern also matched the concatenated messages\n");
      return 6;
    }
  }
  return 0;
}
EOC
  if cc -O1 $(pkg-config --cflags libpcre2-8) -o "$TMP/pcre" "$TMP/pcre.c" \
      $(pkg-config --libs libpcre2-8) 2>"$TMP/pcre.log"; then
    printf 'USER anonymous\r\n' >"$TMP/one.msg"
    printf 'USER anonymous\r\nUSER anonymous\r\n' >"$TMP/two.msg"
    if ! "$TMP/pcre" "$OUT/USER" "$TMP/one.msg" 5 9 "$TMP/two.msg"; then
      echo "[-] the USER template does not match exactly one message"
      exit 1
    fi
    echo "[+] the generated pattern is valid PCRE2 and matches exactly one message"
  else
    echo "[~] libpcre2-8 not usable, skipping the PCRE2 check"
  fi
else
  echo "[~] libpcre2-8 not installed, skipping the PCRE2 check"
fi

# --- 8. a request with a header block is split into head and fields --------
MULTI="$TMP/grammar-multi"
cat >"$TMP/multi.json" <<'JSON'
{"templates": [{"type": "SETUP",
  "request": "SETUP <<URI>> RTSP/1.0\r\nCSeq: <<CSEQ>>\r\n\r\n",
  "placeholders": [{"name": "URI", "example": "rtsp://127.0.0.1:8554/a"},
                   {"name": "CSEQ", "example": "2"}],
  "description": "set up a session"}]}
JSON
$PY "$GEN" rtsp "$MULTI" --from-answer "$TMP/multi.json" >"$TMP/multi.log" 2>&1 || {
  echo "[-] a request with a header block was not converted:"
  cat "$TMP/multi.log"
  exit 1
}
if [ "$(head -1 "$MULTI/SETUP")" != '^(?:SETUP (.*) RTSP/1\.0\r\n)' ]; then
  echo "[-] the request line is not the header pattern: $(head -1 "$MULTI/SETUP")"
  exit 1
fi
if [ "$(sed -n 2p "$MULTI/SETUP")" != '(?|(?:CSeq: (.*)\r\n)|(?:\r\n))' ]; then
  echo "[-] the other lines are not the field pattern: $(sed -n 2p "$MULTI/SETUP")"
  exit 1
fi
echo "[+] the message type line becomes the head, the other lines the fields"

# the header pattern must stop at the request line (no $) so that the fields of
# a real message are reachable, and the field pattern must be valid PCRE2
if [ -x "$TMP/pcre" ]; then
  printf 'SETUP rtsp://127.0.0.1:8554/a RTSP/1.0\r\nCSeq: 2\r\n\r\n' >"$TMP/setup.msg"
  if ! "$TMP/pcre" "$MULTI/SETUP" "$TMP/setup.msg" 6 23; then
    echo "[-] the SETUP header pattern does not match its own message"
    exit 1
  fi
  if sed -n 2p "$MULTI/SETUP" | grep -q '\$'; then
    echo "[-] the field pattern must not be anchored"
    exit 1
  fi
  echo "[+] the head matches the request line and the fields stay reachable"
fi

echo "[+] utils/AI-agent/pro-template looks correct"
