#!/bin/sh
# test-defer-failfast.sh - the deferred-forkserver diagnostic must fire for
# the fuzz target only, never for helpers that inherited the environment.
#
# afl-fuzz exports __AFL_DEFER_FORKSRV to everything it starts.  For a target
# that cannot provide __afl_manual_init() the preloaded library fails fast
# (clear diagnostic + exit), which is what makes a misbuilt target obvious
# instead of a 10x-timeout.  Helpers inherit the same environment though - the
# AFLNET_CLEANUP_SCRIPT shell is started with system() - and they must keep the
# old, silent behaviour: killing them stops the per-run cleanup (and used to
# print one "exited with status 1" warning per run).
#
# The library tells the two apart by afl-fuzz's forkserver descriptors: the
# fuzzer wires fds 198/199 into the process it execs as the target, helpers do
# not have them.
#
# Run from the repo root:  ./test/test-defer-failfast.sh

set -u

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO" || exit 1

TMP=${TMPDIR:-/tmp}/sockhook-failfast.$$
if ! mkdir -p "$TMP"; then

  echo "[!] cannot create $TMP"
  exit 1

fi

CC_BIN=${CC:-cc}

echo "[*] building the target-like helper with $CC_BIN"
if ! "$CC_BIN" -O1 -o "$TMP/wire" test/test-defer-failfast-wire.c; then

  echo "[!] cannot build test/test-defer-failfast-wire.c"
  exit 1

fi

echo "[*] building sockhook.so"
if ! make -C utils/sockhook >/dev/null 2>&1; then

  echo "[!] sockhook build failed"
  exit 1

fi

LIB=${AFLNET_SOCKHOOK_PATH:-$REPO/utils/sockhook/sockhook.so}

if [ ! -x /bin/echo ]; then

  echo "[!] /bin/echo not available - skipping"
  exit 0

fi

# 1) helper-like: no forkserver descriptors -> plain preload, the command runs
out_helper=$(LD_PRELOAD="$LIB" __AFL_DEFER_FORKSRV=1 /bin/echo HELPER-RAN 2>&1)

# 2) target-like: the fuzzer's descriptors are wired -> still fail fast
out_target=$(__AFL_DEFER_FORKSRV=1 "$TMP/wire" "$LIB" /bin/echo TARGET-RAN 2>&1)

echo "    helper-like : $(printf '%s' "$out_helper" | tr '\n' ' ')"
echo "    target-like : $(printf '%s' "$out_target" | tr '\n' ' ' | cut -c1-100)..."

fail=0

case "$out_helper" in

  *HELPER-RAN*)
    ;;
  *)
    echo "[-] FAIL: a helper inheriting the environment must keep running"
    fail=1
    ;;

esac

case "$out_helper" in

  *"refusing to run"*)
    echo "[-] FAIL: the diagnostic must not fire for a helper"
    fail=1
    ;;

esac

case "$out_target" in

  *"refusing to run"*)
    ;;
  *)
    echo "[-] FAIL: a target-like process must still fail fast"
    fail=1
    ;;

esac

case "$out_target" in

  *TARGET-RAN*)
    echo "[-] FAIL: the fuzz target must not be allowed to continue"
    fail=1
    ;;

esac

if [ $fail -eq 0 ]; then

  echo "[+] OK: the fail-fast fires for the fuzz target only"
  rm -rf "$TMP"

fi

exit $fail
