#!/bin/sh
# test-sockhook-inert.sh - a process the preloaded library recognises as "not
# the fuzz target" must behave exactly like a process without the preload.
#
# afl-fuzz exports its environment to everything it starts, so the cleanup
# script (and any other helper) would otherwise load the library too.  The
# library tells them apart by AFL's forkserver descriptors: the fuzzer dup2()s
# 198/199 into the process it execs as the target, and only into that one.  A
# process started by afl-fuzz (__AFL_OUT_DIR) without them leaves
# sockhook_inited at 0, i.e. every hook takes its pass-through path.
#
# The probe binds to the target port and reports SO_REUSEPORT: only an active
# library sets it.  Bogus SHM ids are passed in the helper case, so a library
# that did initialise would _exit(1) instead of printing anything.
#
# Run from the repo root:  ./test/test-sockhook-inert.sh

set -u

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO" || exit 1

CC_BIN=${CC:-cc}
TMP=${TMPDIR:-/tmp}/sockhook-inert.$$

if ! mkdir -p "$TMP"; then

  echo "[!] cannot create $TMP"
  exit 1

fi

echo "[*] building helpers with $CC_BIN"
if ! "$CC_BIN" -O1 -o "$TMP/probe" test/test-sockhook-inert-probe.c ||
   ! "$CC_BIN" -O1 -o "$TMP/wire" test/test-defer-failfast-wire.c; then

  echo "[!] cannot build the test helpers"
  exit 1

fi

echo "[*] building sockhook.so"
if ! make -C utils/sockhook >/dev/null 2>&1; then

  echo "[!] sockhook build failed"
  exit 1

fi

LIB=${AFLNET_SOCKHOOK_PATH:-$REPO/utils/sockhook/sockhook.so}

fail=0

check() {   # label, expected "reuseport=N", probe output

  label=$1
  want=$2
  out=$3

  printf '    %-46s: %s\n' "$label" "$(printf '%s' "$out" | tr '\n' ' ')"

  case "$out" in

    *"$want"*)
      ;;
    *)
      echo "[-] FAIL: $label (expected $want)"
      fail=1
      ;;

  esac

}

# 1) helper of afl-fuzz: fuzzer environment, no forkserver descriptors
out=$(env __AFL_OUT_DIR=/tmp __AFL_NETPORT=8091 __AFL_SOCK_MODE=2 \
          __AFL_SHM_MSG_ID=9999999 __AFL_SHM_CHECK_ID=9999999 \
          LD_PRELOAD="$LIB" "$TMP/probe" 8091 2>&1)
check "helper of afl-fuzz (inert)" "reuseport=0" "$out"

# 2) the target: same environment, forkserver descriptors wired by the fuzzer
out=$(env __AFL_OUT_DIR=/tmp __AFL_NETPORT=8092 \
          "$TMP/wire" "$LIB" "$TMP/probe" 8092 2>&1)
check "target (active)" "reuseport=1" "$out"

# 3) standalone/manual preload: documented behaviour is kept
out=$(env __AFL_NETPORT=8093 LD_PRELOAD="$LIB" "$TMP/probe" 8093 2>&1)
check "standalone/manual (active)" "reuseport=1" "$out"

# 4) the escape hatch forces initialisation in a helper-looking process
out=$(env AFLNET_SOCKHOOK_FORCE_ACTIVE=1 __AFL_OUT_DIR=/tmp __AFL_NETPORT=8094 \
          LD_PRELOAD="$LIB" "$TMP/probe" 8094 2>&1)
check "escape hatch (active)" "reuseport=1" "$out"

if [ $fail -eq 0 ]; then

  echo "[+] OK: only targets (and manual runs) initialise the library"
  rm -rf "$TMP"

fi

exit $fail
