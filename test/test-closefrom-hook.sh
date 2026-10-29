#!/bin/sh
# test-closefrom-hook.sh - regression test for sockhook's descriptor guard.
#
# OpenSSH's sshd sanitises its descriptors early in main() and reaches its
# deferred __AFL_INIT() only later (to skip config parsing and host key loading
# per run).  With glibc >= 2.34 its closefrom(3) call goes to libc, which
# closes AFL's forkserver descriptors 198/199 as well - afl-fuzz then aborts
# with "Fork server crashed with signal 9" (the SIGKILL in that message is the
# fuzzer's own cleanup).  The same happens to targets that close their
# descriptors one by one.  The preloaded library therefore has to keep those
# two descriptors until the handshake happened, and behave exactly like libc
# everywhere else.
#
# Run from the repo root:  ./test/test-closefrom-hook.sh

set -u

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO" || exit 1

TMP=${TMPDIR:-/tmp}/sockhook-closefrom.$$
if ! mkdir -p "$TMP"; then

  echo "[!] cannot create $TMP"
  exit 1

fi

CC_BIN=${CC:-cc}

echo "[*] building the helper with $CC_BIN"
if ! "$CC_BIN" -O1 -rdynamic -o "$TMP/closefrom" test/test-closefrom.c; then

  echo "[!] cannot build test/test-closefrom.c"
  exit 1

fi

echo "[*] building sockhook.so"
if ! make -C utils/sockhook >/dev/null 2>&1; then

  echo "[!] sockhook build failed"
  exit 1

fi

LIB=$REPO/utils/sockhook/sockhook.so

fail=0

ALL_CLOSED='*fd7=closed*fd198=closed*fd199=closed*'
PROTECTED='*fd7=closed*fd198=alive*fd199=alive*'

check() {   # label, mode, connected, preload, defer, accepted pattern ...

  label=$1
  mode=$2
  conn=$3
  preload=$4
  defer=$5
  shift 5

  args=$mode
  if [ "$conn" = "connected" ]; then args="$args connected"; fi

  if [ -n "$preload" ] && [ -n "$defer" ]; then

    out=$(LD_PRELOAD="$preload" __AFL_DEFER_FORKSRV=1 "$TMP/closefrom" $args 2>&1)

  elif [ -n "$preload" ]; then

    out=$(LD_PRELOAD="$preload" "$TMP/closefrom" $args 2>&1)

  else

    out=$("$TMP/closefrom" $args 2>&1)

  fi

  printf '    %-40s: %s\n' "$label" "$(printf '%s' "$out" | tr '\n' ' ')"

  ok=0
  for want in "$@"; do

    case "$out" in
      $want) ok=1 ;;
    esac

  done

  if [ $ok -eq 0 ]; then

    echo "[-] FAIL: $label (expected: $*)"
    fail=1

  fi

}

# baseline: plain libc closes everything (the closefrom() variant is skipped on
# libc < 2.34, where there is no closefrom() at all)
check "no preload, close loop"        closeloop "" "" ""    "$ALL_CLOSED"
check "no preload, closefrom()"       closefrom "" "" ""    "$ALL_CLOSED" \
                                                            '*closefrom-unavailable*'

# with the preload but no deferred forkserver: exactly libc semantics
check "preload, deferred off, loop"   closeloop "" "$LIB" "" "$ALL_CLOSED"
check "preload, deferred off, cfrom"  closefrom "" "$LIB" "" "$ALL_CLOSED"

# deferred, handshake still pending: the forkserver descriptors survive
check "preload, deferred on, loop"    closeloop "" "$LIB" 1 "$PROTECTED"
check "preload, deferred on, cfrom"   closefrom "" "$LIB" 1 "$PROTECTED"

# deferred, handshake already done (the forked child): no protection any more,
# so AFL's own close() of the two descriptors is left alone
check "preload, deferred on, connected, loop" closeloop connected "$LIB" 1 \
                                              "$ALL_CLOSED"

if [ $fail -eq 0 ]; then

  echo "[+] OK: 198/199 are kept only until the deferred handshake happened"
  rm -rf "$TMP"

fi

exit $fail
