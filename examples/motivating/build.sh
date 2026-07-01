#!/usr/bin/env bash
# build.sh <source_dir> <output_binary>
#
# Compiles the PUT with the TrigFuzz runtime header.  In a real setup
# this would also link in AFL's coverage instrumentation; for the
# prototype we just compile with gcc and rely on the shm header alone.
set -euo pipefail
SRC="$1"
OUT="$2"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
gcc -O1 -g -I"$ROOT" -o "$OUT" "$SRC/main.c"
