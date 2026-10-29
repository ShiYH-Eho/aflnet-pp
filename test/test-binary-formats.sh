#!/bin/sh
# Standalone test for the fuzzer-side .binary-formats.json probe loader.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

CC=${CC:-cc}
"$CC" -std=gnu11 -Wall -Wextra -Werror \
  -I"$ROOT/include" -I"$ROOT/src/aflnet/utils" \
  "$SCRIPT_DIR/test-binary-formats.c" \
  "$ROOT/src/aflnet/utils/binary_formats.c" \
  -o "$TMP/test-binary-formats"

"$TMP/test-binary-formats" "$TMP"
