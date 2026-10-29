#!/bin/bash
# test/test-statevar.sh — instrumentation and runtime self-test for the AFLNet
# state-variable feedback pass (AFL_LLVM_STATEVAR=1,
# instrumentation/afl-llvm-statevar-pass.so.cc).
#
# A. pass level: the generated IR must contain one __afl_statevar_record call
#    per annotated object (at least - a variable assigned in both arms of a
#    conditional is stored twice) over exactly one slot each, at -O0 and -O2,
#    and no call at all when the pass is not enabled.
# B. runtime level: the values must land in the 8-byte slots of the SHM region
#    the fuzzer exports, with the documented encoding (integers zero-extended,
#    integer pointers dereferenced, other pointers reduced to their nullity,
#    NULL pointers recorded as 0), without recording unannotated variables or
#    ever reading a non-integer pointee, reproducibly (no ASLR address in the
#    state), and different variable values must produce a different SHM image -
#    the assumption state-mode-2 feedback is built on.
#    test/test-statevar-harness.c owns the SHM and does the checking.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

CC="$AFL_DIR/afl-clang-fast"
LEGACY_CC="$AFL_DIR/afl-clang"
PLUGIN="$AFL_DIR/afl-llvm-statevar-pass.so"
RT="$AFL_DIR/afl-statevar-rt.o"
SRC="$SCRIPT_DIR/test-statevar.c"
HARNESS_SRC="$SCRIPT_DIR/test-statevar-harness.c"

if [ ! -x "$CC" ] || [ ! -x "$LEGACY_CC" ] || [ ! -e "$PLUGIN" ] ||
  [ ! -e "$RT" ]; then
  echo "[-] afl-clang-fast, afl-clang, afl-llvm-statevar-pass.so or" \
    "afl-statevar-rt.o not built; skipping"
  exit 0
fi

unset AFL_LLVM_STATEVAR AFL_DEBUG AFL_QUIET AFL_LLVM_LTO
unset AFL_CMPLOG AFL_LLVM_CMPLOG AFL_LLVM_ALLOWLIST AFL_LLVM_DENYLIST

# test-statevar.c prints one REC line per annotated object (whole global, struct
# member, int pointer, struct pointer, double pointer, char pointer, malloc'ed
# pointer, parameter, automatic local): one SHM slot each.
NVARS=$(grep -c 'printf("REC ' "$SRC")

echo "[*] Testing: afl-llvm-statevar-pass.so (AFL_LLVM_STATEVAR)"

# --- A. pass level ---------------------------------------------------------
for opt in 0 2; do

  AFL_QUIET=1 AFL_LLVM_STATEVAR=1 "$CC" "-O$opt" -S -emit-llvm "$SRC" \
    -o "$TMP/target.O$opt.ll"

  calls=$(grep -c 'call void @__afl_statevar_record' \
    "$TMP/target.O$opt.ll" || true)
  words=$(grep -oE '@__afl_statevar_record(_ptr)?\(i64 [0-9]+' \
    "$TMP/target.O$opt.ll" |
    awk '{print $2}' | sort -n -u | wc -l)

  # One slot per annotated object, but possibly more than one call: a variable
  # assigned in both arms of an if/ternary is stored (and recorded) twice.
  if [ "$words" != "$NVARS" ] || [ "$calls" -lt "$NVARS" ]; then
    echo "[!] -O$opt: expected >= $NVARS record call(s) over $NVARS slot(s)," \
      "got $calls over $words"
    exit 1
  fi

  echo "[+] -O$opt: $calls record call(s) over $words distinct slot(s) ==" \
    "$NVARS annotated object(s)"

done

# negative control: without AFL_LLVM_STATEVAR=1 the pass is not loaded at all
AFL_QUIET=1 "$CC" -O2 -S -emit-llvm "$SRC" -o "$TMP/nopass.ll"
calls=$(grep -c 'call void @__afl_statevar_record' "$TMP/nopass.ll" || true)

if [ "$calls" != "0" ]; then
  echo "[!] the pass ran without AFL_LLVM_STATEVAR=1 ($calls record call(s))"
  exit 1
fi

echo "[+] without AFL_LLVM_STATEVAR=1: 0 record call(s), pass not loaded"

# pass statistics (afl-llvm-statevar-pass.so prints them with AFL_DEBUG=1)
AFL_QUIET=1 AFL_LLVM_STATEVAR=1 AFL_DEBUG=1 "$CC" -O2 -S -emit-llvm "$SRC" \
  -o "$TMP/dbg.ll" 2>"$TMP/dbg.err"

stats=$(grep -m1 'statevar pass: .* annotated variable(s)' "$TMP/dbg.err" || true)
nann=$(echo "$stats" | sed -n 's/.*: \([0-9]*\) annotated.*/\1/p')
ninstr=$(echo "$stats" | sed -n 's/.*, \([0-9]*\) store(s) instrumented.*/\1/p')

if [ "$nann" != "$NVARS" ] || [ -z "$ninstr" ] || [ "$ninstr" -lt "$NVARS" ] ||
  ! echo "$stats" | grep -q '0 store(s) skipped'; then
  echo "[!] unexpected pass statistics:"
  cat "$TMP/dbg.err" | grep "statevar pass:" || true
  exit 1
fi

if ! echo "$stats" | grep -qE '\([0-9]+ recorded pointer nullity\)'; then
  echo "[!] the pass does not report how many pointer stores were recorded as" \
    "nullity:"
  echo "$stats"
  exit 1
fi

echo "[+] pass statistics: $nann annotated variable(s), $ninstr store(s)" \
  "instrumented, $(echo "$stats" | sed -n 's/.*(\([0-9]*\) recorded.*/\1/p')" \
  "recorded as pointer nullity"

if grep -q "Mistyped AFL environment variable" "$TMP/dbg.err"; then
  echo "[!] afl-cc does not know AFL_LLVM_STATEVAR (see include/envs.h)"
  exit 1
fi

echo "[+] AFL_LLVM_STATEVAR is a known afl-cc setting"

# The statevar pass is independent from the coverage backend and must also be
# loaded by the legacy assembler instrumentation path.
AFL_QUIET=1 AFL_LLVM_STATEVAR=1 "$LEGACY_CC" -gdwarf-4 -O2 -S -emit-llvm "$SRC" \
  -o "$TMP/legacy.ll"
legacy_calls=$(grep -c 'call void @__afl_statevar_record' \
  "$TMP/legacy.ll" || true)

if [ "$legacy_calls" -lt "$NVARS" ]; then
  echo "[!] afl-clang did not load the statevar pass ($legacy_calls call(s))"
  exit 1
fi

echo "[+] legacy afl-clang loaded the statevar pass ($legacy_calls call(s))"

# --- B. runtime level ------------------------------------------------------
PLAIN_CC=$(command -v cc || command -v gcc || command -v clang)

# the harness must create the SHM region the same way the AFL runtime reads it
HARNESS_FLAGS=""
HARNESS_LIBS=""
if [ -e "$RT" ] && nm "$RT" 2>/dev/null | grep -q "shm_open"; then
  HARNESS_FLAGS="-DUSEMMAP"
  HARNESS_LIBS="-lrt"
fi

# shellcheck disable=SC2086
"$PLAIN_CC" -O1 -Wall $HARNESS_FLAGS -o "$TMP/harness" "$HARNESS_SRC" \
  $HARNESS_LIBS
AFL_QUIET=1 AFL_LLVM_STATEVAR=1 "$CC" -O2 -o "$TMP/target" "$SRC"

# $1 = case name, rest = target arguments
run_case() {

  log="$TMP/run-$1.log"
  shift

  if ! "$TMP/harness" "$TMP/target" "$@" >"$log" 2>&1; then
    echo "[!] state-variable SHM check failed for target arguments '$*':"
    cat "$log"
    exit 1
  fi

  echo "[+] $*: $(grep -m1 '^\[' "$log")"

}

run_case d7 --delta 7
run_case d9 --delta 9
run_case dm5 --delta -5
run_case null --delta 7 --nullptr
run_case allnull --delta 7 --nullptr --blobptr-null
run_case d7b --delta 7

# -O2 must not have changed what is recorded: the words of the target build are
# the exact values it printed, and an unannotated variable would have failed
# above.  Check the zero-extension of signed values explicitly, and the 1-byte
# read of the char pointer (a wider read would have picked up the canary).
if ! grep -q " 0000000000000015" "$TMP/run-d7.log" ||
  ! grep -q " 00000000fffffff1" "$TMP/run-dm5.log" ||
  ! grep -q " 000000000000005a" "$TMP/run-d7.log"; then
  echo "[!] the SHM words are not the zero-extended annotated values:"
  grep '^SHM-SET' "$TMP"/run-*.log
  exit 1
fi

echo "[+] 32-bit values are zero-extended (7*3 -> 0x15, -5*3 ->" \
  "0x00000000fffffff1) and the char pointer only read one byte (0x5a)"

# Pointer variables: non-integer pointees (struct / double) are recorded as
# nullity only, so the SHM must hold 1 twice (both non-NULL) in the default
# run, never the pointee bytes (0x0cafed00d from the struct tag or the double).
ones_d7=$(grep -o ' 0000000000000001\b' "$TMP/run-d7.log" | wc -l)
if [ "$ones_d7" != "2" ]; then
  echo "[!] expected 2 non-integer pointers recorded as 1, got $ones_d7"
  exit 1
fi

if grep -q "0cafed00d" "$TMP/run-d7.log"; then
  echo "[!] the pointee of a non-integer pointer was dereferenced:"
  grep '^SHM-SET' "$TMP/run-d7.log"
  exit 1
fi

echo "[+] struct/double pointers are recorded as nullity (1), their pointees" \
  "are never read"

# NULL pointers of both kinds must still be recorded, as 0: with --nullptr
# --blobptr-null nothing in the SHM can be 1 any more, yet every annotated
# variable must still have written its slot (the harness checks the count).
d7_ones=$(grep -o ' 0000000000000001\b' "$TMP/run-null.log" | wc -l)
allnull_ones=$(grep -o ' 0000000000000001\b' "$TMP/run-allnull.log" | wc -l)

if [ "$allnull_ones" != "0" ] || [ "$d7_ones" != "1" ]; then
  echo "[!] NULL pointers were not recorded as 0 (expected 1/0 non-integer" \
    "pointers to read 1, got $d7_ones/$allnull_ones)"
  exit 1
fi

echo "[+] NULL pointers are recorded as 0 (integer and non-integer pointees" \
  "alike), not skipped"

# Every run must have written the same slots: the slot of a variable depends on
# its identity only, never on its value.
slots_d7=$(grep '^SHM-SLOTS' "$TMP/run-d7.log")
for f in d9 dm5 null allnull; do

  if [ "$(grep '^SHM-SLOTS' "$TMP/run-$f.log")" != "$slots_d7" ]; then
    echo "[!] the set of written slots depends on the values:"
    grep '^SHM-SLOTS' "$TMP"/run-*.log
    exit 1
  fi

done

nslots=$(echo "$slots_d7" | wc -w)
nslots=$((nslots - 1))

if [ "$nslots" != "$NVARS" ]; then
  echo "[!] $nslots slot(s) written for $NVARS annotated object(s)"
  exit 1
fi

echo "[+] every run wrote the same $nslots slot(s), one per annotated object," \
  "independent of the values"

# Two runs with the same arguments must produce the same image: the recorded
# pointers are dereferenced/classified in the target, so no ASLR address can
# leak into the state (a raw pointer would differ between the runs).
h_d7=$(awk '/^SHM-HASH/{print $2}' "$TMP/run-d7.log")
h_d7b=$(awk '/^SHM-HASH/{print $2}' "$TMP/run-d7b.log")

if [ "$h_d7" != "$h_d7b" ]; then
  echo "[!] the SHM image is not reproducible ($h_d7 vs $h_d7b): a pointer" \
    "address may have been recorded"
  exit 1
fi

echo "[+] the same run twice produces the same SHM image ($h_d7), no pointer" \
  "address is recorded"

# and different state-variable values must produce different images
h_d9=$(awk '/^SHM-HASH/{print $2}' "$TMP/run-d9.log")
h_dm5=$(awk '/^SHM-HASH/{print $2}' "$TMP/run-dm5.log")
h_null=$(awk '/^SHM-HASH/{print $2}' "$TMP/run-null.log")
h_allnull=$(awk '/^SHM-HASH/{print $2}' "$TMP/run-allnull.log")

if [ "$h_d7" != "$h_d9" ] && [ "$h_d7" != "$h_dm5" ] &&
  [ "$h_d7" != "$h_null" ] && [ "$h_d7" != "$h_allnull" ] &&
  [ "$h_d9" != "$h_dm5" ] && [ "$h_d9" != "$h_null" ] &&
  [ "$h_dm5" != "$h_null" ] && [ "$h_null" != "$h_allnull" ]; then
  echo "[+] different state-variable values produce different SHM images" \
    "(distinct hashes: $h_d7 / $h_d9 / $h_dm5 / $h_null / $h_allnull)"
else
  echo "[!] the SHM image does not depend on the state variables:"
  grep '^SHM-SET\|^SHM-HASH' "$TMP"/run-*.log
  exit 1
fi

echo "[*] Testing legacy afl-clang assembler coverage + statevar runtime"

AFL_QUIET=1 AFL_LLVM_STATEVAR=1 "$LEGACY_CC" -gdwarf-4 -O2 -o "$TMP/target-legacy" \
  "$SRC"

if ! nm "$TMP/target-legacy" | grep -q '__afl_maybe_log' ||
  ! nm "$TMP/target-legacy" | grep -q '__afl_statevar_record'; then
  echo "[!] legacy afl-clang target is missing coverage or statevar runtime"
  exit 1
fi

if ! "$TMP/harness" "$TMP/target-legacy" --delta 7 \
  >"$TMP/run-legacy.log" 2>&1; then
  echo "[!] legacy afl-clang statevar runtime check failed:"
  cat "$TMP/run-legacy.log"
  exit 1
fi

echo "[+] legacy afl-clang uses afl-as coverage and the statevar runtime"

echo "[+] state-variable instrumentation looks correct"
