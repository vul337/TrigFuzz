#!/usr/bin/env bash
# build.sh <source_dir> <output_binary>
#
# Compiles the PUT with the compiler and flags selected by the driver. This
# lets the same script serve afl-gcc, AFLGo preprocessing, and the final
# control-flow-distance build.
set -euo pipefail
SRC="$1"
OUT="$2"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CC_BIN="${CC:-gcc}"
read -r -a USER_CFLAGS <<< "${CFLAGS:-}"
"$CC_BIN" "${USER_CFLAGS[@]}" -O1 -g -I"$ROOT" -o "$OUT" "$SRC/main.c"
