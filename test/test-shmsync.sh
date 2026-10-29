#!/bin/bash
# test/test-shmsync.sh — standalone SMH rendezvous of utils/sockhook
# (sock_mode=1 + AFLNET_SHM_SYNC=1).
#
# The library must be usable *without* sock2shm: with __AFL_SHMSYNC=1 and no
# segments the target still speaks over the real socket, but it publishes its
# readiness from accept() and waits for the fuzzer's turn at recv(), so the
# request cannot be read before it was sent and a session end is noticed
# instead of waiting for the transfer to time out.  test/test-shmsync.c plays
# the fuzzer side and asserts that contract, plus that the default
# configuration (no sync, no segments) stays completely inert.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."

SRC="$SCRIPT_DIR/test-shmsync.c"
BIN="$SCRIPT_DIR/test-shmsync"
TARGET="$SCRIPT_DIR/test-echo-server"
SOCKHOOK="$AFL_DIR/sockhook.so"

if [ ! -e "$AFL_DIR/src/aflnet/utils/sock2shm.c" ]; then
  echo "[-] not an aflnet-pp tree; skipping"
  exit 0
fi

CC_BIN="${CC:-cc}"

echo "[*] Testing: sockhook standalone SHM sync (AFLNET_SHM_SYNC)"

# the library the fuzzer preloads must be the freshly built one
make -s -C "$AFL_DIR/utils/sockhook" >/dev/null 2>&1 || {
  echo "[-] cannot build utils/sockhook/sockhook.so; skipping"
  exit 0
}
cp -f "$AFL_DIR/utils/sockhook/sockhook.so" "$SOCKHOOK"

echo "[*] building test-echo-server with $CC_BIN"
$CC_BIN -O1 -o "$TARGET" "$SCRIPT_DIR/test-echo-server.c"

echo "[*] building test-shmsync with $CC_BIN"
$CC_BIN -O1 -I "$AFL_DIR/include" -I "$AFL_DIR/utils/sockhook" \
  -o "$BIN" "$SRC"

rc=0
for mode in sync plain; do

  args=""
  [ "$mode" = sync ] && args="sync"

  echo "[*] case: $mode"
  ( cd "$AFL_DIR" && "$BIN" $args ) || rc=1

done

rm -f "$BIN" "$TARGET"

if [ $rc -ne 0 ]; then
  echo "[-] sockhook standalone SHM sync failed"
  exit 1
fi

echo "[+] sockhook standalone SHM sync looks correct"
