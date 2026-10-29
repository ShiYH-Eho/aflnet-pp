#!/bin/sh
# test-defer-alarm.sh - deferred forkserver vs. a target's own alarm() timer.
#
# proftpd arms a wall-clock alarm() while it starts up, i.e. before the
# deferred forkserver exists.  In deferred mode that timer belongs to the
# process which becomes the forkserver parent; when it expires there, the
# interrupted read()/waitpid() comes back with EINTR and the AFL runtime treats
# that as "the fuzzer is gone" (write_error() + _exit(1)) - the forkserver
# disappears and afl-fuzz aborts with "Unable to communicate with fork
# server".  The preloaded library has to park the timer across the forkserver
# start and give it back to the per-test children.
#
# Run from the repo root:  ./test/test-defer-alarm.sh

set -u

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO" || exit 1

PORT=${AFLNET_TEST_PORT:-8090}
TMP=${TMPDIR:-/tmp}/aflnet-defer-alarm.$$

if ! mkdir -p "$TMP"; then

  echo "[!] cannot create $TMP"
  exit 1

fi

BIN=$TMP/server

# --- an AFL++ compiler whose target exports __afl_manual_init --------------
# (same lookup as test-defer-stale.sh: the deferred start needs the runtime
# entry point in the target's dynamic symbol table)

exports_manual_init() {

  [ -x "$BIN" ] && nm -D "$BIN" 2>/dev/null | grep -q __afl_manual_init

}

try_cc() {

  rm -f "$BIN"
  "$1" -O1 -o "$BIN" test/test-defer-alarm-server.c >/dev/null 2>&1
  exports_manual_init && return 0

  "$1" -O1 -Wl,--dynamic-list="$REPO/dynamic_list.txt" \
      -o "$BIN" test/test-defer-alarm-server.c >/dev/null 2>&1
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

echo "[*] building sockhook.so"
if ! make -C utils/sockhook >/dev/null 2>&1; then

  echo "[!] sockhook build failed"
  exit 1

fi

mkdir -p "$TMP/in"
printf 'HELO alarm\r\n' > "$TMP/in/seed"
: > "$TMP/server.log"

echo "[*] running afl-fuzz (sock_mode=1, deferred forkserver, 1s target alarm)"
AFL_PATH=$REPO \
AFL_NO_UI=1 \
AFL_SKIP_CPUFREQ=1 \
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
AFLNET_URL=127.0.0.1:$PORT \
AFLNET_PROTOCOL=ftp \
AFLNET_SOCK_MODE=1 \
AFLNET_DEFER_FORKSRV=1 \
AFLNET_TERMINATE_CHILD=1 \
timeout 40 ./afl-fuzz -i "$TMP/in" -o "$TMP/out" -V 12 -m none -t 2000+ \
    -- "$BIN" $PORT "$TMP/server.log" > "$TMP/fuzz.log" 2>&1

execs=$(sed -n 's/^execs_done *: *\([0-9]*\).*/\1/p' "$TMP/out/default/fuzzer_stats" 2>/dev/null)

if grep -q "PROGRAM ABORT" "$TMP/fuzz.log"; then

  echo "[-] FAIL: the campaign aborted - the target's own alarm took the"
  echo "    forkserver parent down (logs kept in $TMP)"
  sed 's/\x1b\[[0-9;]*m//g' "$TMP/fuzz.log" | grep -A3 "PROGRAM ABORT" | head -5
  exit 1

fi

if [ "${execs:-0}" -lt 5 ]; then

  echo "[-] FAIL: only ${execs:-0} runs - the campaign did not get going"
  echo "    (logs kept in $TMP)"
  exit 1

fi

if ! grep -q "blocked=0 remaining=[1-9]" "$TMP/server.log"; then

  echo "[-] FAIL: no child reported an unblocked, re-armed alarm"
  echo "    (the preload must hand the target's timer back to the children)"
  cat "$TMP/server.log"
  exit 1

fi

echo "[+] OK: $execs runs, the forkserver survived the target's alarm and the"
echo "    children got their timer back"
rm -rf "$TMP"

exit 0
