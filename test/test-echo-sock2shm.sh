#!/bin/sh
# test-echo-sock2shm.sh - smoke test for the aflpp-net network interaction
# backends using test-echo-server.c.
#
# Builds the echo target, then runs a short afl-fuzz session in each of:
#   sock_mode=0 (libaflppdesock)     sock_mode=1 (default AFLNet socket)
#   sock_mode=2 (sock2shm)           sock_mode=2 + AFLNET_SOCK2SHM_FORK=1
#
# The AFLNET_* variables are read by the fuzzer from ITS OWN environment, so
# they are exported here before afl-fuzz is started (AFL_TARGET_ENV would only
# reach the target process).
#
# Run from the repo root:  ./test/test-echo-sock2shm.sh
# Requires: afl-cc (AFL++ compiler, for coverage) and the target built.  If
# afl-cc is not available the server is built with plain cc (still works, but
# without coverage feedback).

set -u

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO" || exit 1

CC_BIN=${AFL_CC:-}
if [ -z "$CC_BIN" ]; then
  for c in ./afl-cc ./afl-clang-fast afl-cc afl-clang-fast; do
    if [ -x "$c" ]; then CC_BIN=$c; break; fi
  done
fi
if [ -z "$CC_BIN" ]; then
  echo "[!] afl-cc not found; building target uninstrumented (no coverage)"
  CC_BIN=cc
fi

echo "[*] building test-echo-server with $CC_BIN"
$CC_BIN -o test/test-echo-server test/test-echo-server.c || exit 1

echo "[*] building sock2shm.so"
make -C utils/sock2shm >/dev/null 2>&1 || { echo "[!] sock2shm build failed"; exit 1; }

# seed inputs (line-based so the ftp/smtp-style extractors split them cleanly)
mkdir -p /tmp/echo_in
printf 'hello\r\n'   > /tmp/echo_in/hello
printf 'PING\r\n'    > /tmp/echo_in/ping
printf 'STATUS\r\n'  > /tmp/echo_in/status

# --- common AFLNet env (protocol + URL) ---
export AFLNET_URL=127.0.0.1:8080
export AFLNET_PROTOCOL=ftp

run_mode() {
  local tag=$1 secs=$2
  rm -rf /tmp/echo_out
  echo "===== $tag ====="
  timeout "$secs" ./afl-fuzz -i /tmp/echo_in -o /tmp/echo_out \
      -V "$secs" -m none -t 3000+ -- test/test-echo-server 8080 \
      > "/tmp/echo_${tag}.log" 2>&1
  echo "exit=$?"
  if [ -f /tmp/echo_out/fuzzer_stats ]; then
    grep -E "execs_done|unique_crashes|last_find|run_time" /tmp/echo_out/fuzzer_stats
  else
    tail -5 "/tmp/echo_${tag}.log"
  fi
}

# --- sock_mode=2 (sock2shm), forkserver off ---
export AFLNET_SOCK_MODE=2
export AFLNET_SOCK2SHM_PATH=$REPO/sock2shm.so
unset AFLNET_SOCK2SHM_FORK
run_mode s2s 8

# --- sock_mode=2 + forkserver enabled (the new mechanism) ---
export AFLNET_SOCK2SHM_FORK=1
run_mode s2s_fork 8

# --- sock_mode=1 (default AFLNet real-socket) ---
unset AFLNET_SOCK2SHM_FORK
export AFLNET_SOCK_MODE=1
run_mode sock1 8

# --- sock_mode=0 (libaflppdesock, testcase via stdin) ---
export AFLNET_SOCK_MODE=0
export AFLNET_DESOCK_PATH=$REPO/utils/libaflppdesock/libaflppdesock.so
run_mode desock 8

echo "[*] done - logs in /tmp/echo_*.log"
