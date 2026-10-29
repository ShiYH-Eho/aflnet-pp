#!/bin/sh
# test-defer-stale.sh - regression test for the deferred forkserver's shared
# accept queue (utils/sockhook/sockhook.c).
#
# In deferred mode the forkserver parent owns the listening socket and every
# per-run child inherits it.  A connection that a run never accepts (here
# forced once: the target exits for one run before its accept()) therefore
# stays queued, already closed by the fuzzer.  Without the stale-connection
# filter in accept() every following child would serve that dead connection
# instead of its own - silently, for the rest of the campaign, because the
# fuzzer opens exactly one connection per run.
#
# The target logs per accepted connection whether the peer had already gone
# (TCP_CLOSE_WAIT); the test fails when the runs answer leftovers instead of
# their own session.
#
# Run from the repo root:  ./test/test-defer-stale.sh
# Requires: an AFL++ compiler whose runtime exports __afl_manual_init (the
# repo's afl-cc does), and afl-fuzz.  Skips cleanly when neither is usable.

set -u

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO" || exit 1

PORT=${AFLNET_TEST_PORT:-8098}
TMP=${TMPDIR:-/tmp}/aflnet-defer-stale.$$

if ! mkdir -p "$TMP"; then

  echo "[!] cannot create $TMP"
  exit 1

fi

BIN=$TMP/server

# --- an AFL++ compiler whose target exports __afl_manual_init --------------
# The deferred forkserver is started through dlsym("__afl_manual_init"), so
# the symbol has to be in the target's dynamic symbol table.  afl-cc adds
# AFL++'s dynamic_list.txt itself; do it by hand for a compiler that does not
# (and for an afl-cc that cannot instrument here at all).

exports_manual_init() {

  [ -x "$BIN" ] && nm -D "$BIN" 2>/dev/null | grep -q __afl_manual_init

}

try_cc() {

  rm -f "$BIN"
  "$1" -O1 -o "$BIN" test/test-defer-stale-server.c >/dev/null 2>&1
  exports_manual_init && return 0

  "$1" -O1 -Wl,--dynamic-list="$REPO/dynamic_list.txt" \
      -o "$BIN" test/test-defer-stale-server.c >/dev/null 2>&1
  exports_manual_init

}

CC_BIN=${AFL_CC:-}
CANDIDATES="${CC_BIN:-./afl-cc ./afl-clang-fast afl-cc afl-clang-fast}"
for c in $CANDIDATES; do

  if [ -n "${CC_BIN:-}" ] ||
     [ -x "$c" ] ||
     command -v "$c" >/dev/null 2>&1; then

    if try_cc "$c"; then CC_BIN=$c; break; fi
    CC_BIN=""

  fi

done

if [ -z "$CC_BIN" ]; then

  echo "[!] no AFL++ compiler exporting __afl_manual_init found - skipping"
  exit 0

fi

echo "[*] built the target with $CC_BIN"

# --- build the preload library under test ----------------------------------

echo "[*] building sockhook.so"
if ! make -C utils/sockhook >/dev/null 2>&1; then

  echo "[!] sockhook build failed"
  exit 1

fi

# --- one campaign, with exactly one run that does not accept ---------------

mkdir -p "$TMP/in"
printf 'HELO defer\r\n' > "$TMP/in/seed"
: > "$TMP/server.log"
touch "$TMP/boom"

echo "[*] running afl-fuzz (sock_mode=1, deferred forkserver)"
AFL_PATH=$REPO \
AFL_NO_UI=1 \
AFL_SKIP_CPUFREQ=1 \
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
AFLNET_URL=127.0.0.1:$PORT \
AFLNET_PROTOCOL=ftp \
AFLNET_SOCK_MODE=1 \
AFLNET_DEFER_FORKSRV=1 \
AFLNET_TERMINATE_CHILD=1 \
timeout 30 ./afl-fuzz -i "$TMP/in" -o "$TMP/out" -V 10 -m none -t 2000+ \
    -- "$BIN" $PORT "$TMP/server.log" "$TMP/boom" > "$TMP/fuzz.log" 2>&1

served=$(grep -c '^served' "$TMP/server.log" 2>/dev/null)
stale=$(grep -c '^stale' "$TMP/server.log" 2>/dev/null)
total=$((served + stale))

if [ "$total" -lt 20 ]; then

  echo "[-] only $total connections accepted - the campaign did not run"
  echo "    (logs kept in $TMP)"
  tail -5 "$TMP/fuzz.log"
  exit 1

fi

# the forcing run itself is dropped (and on a loaded machine the fuzzer may
# give a run up before the child accepts), so a small number is normal; a
# desynchronised campaign answers a leftover in essentially every run
if [ "$stale" -gt $((total / 20)) ]; then

  echo "[-] FAIL: $stale of $total runs served an already-closed leftover"
  echo "    connection instead of their own session (logs in $TMP)"
  exit 1

fi

echo "[+] OK: $stale of $total runs served a leftover connection"
rm -rf "$TMP"

exit 0
