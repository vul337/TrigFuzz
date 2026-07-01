# Selective AFL++ Based TrigFuzz

This option ports TrigFuzz feedback to AFL++ and adds conservative SelectFuzz-style selective instrumentation.

It is intended as a performance-oriented path:

- AFL++ remains the fuzzing base;
- TrigFuzz uses a dedicated shared-memory region for TCU distances;
- `+trig` inputs are saved when triggering distance improves;
- scheduling adds a bounded distance-aware multiplier;
- selective instrumentation instruments only listed source locations, while keeping unknown debug locations instrumented for soundness.

## Build

```sh
cd /root/TrigFuzz/engines/aflplusplus-selective
make source-only
```

The optional Nyx component requires Rust. If Rust is not installed, AFL++ can
still finish the source-instrumentation build and report Nyx as optional.

## Selective Instrumentation

Enable the selective pass while compiling the target:

```sh
export AFL_TRIGFUZZ_SELECTIVE=selectfuzz-like
export AFL_TRIGFUZZ_SELECTIVE_FILE=/path/to/selective-keep.txt
```

The keep-list format is one source location per line:

```text
parser.c:120
parser.c:121
decoder.c:88
```

The pass canonicalizes entries as `basename:line`. Empty lines and `#` comments are ignored.

Soundness policy:

- listed source locations are instrumented;
- source locations not listed are skipped;
- blocks without usable debug locations are still instrumented, because skipping unknown code can silently drop relevant behavior.

Compile a target:

```sh
cd /root/TrigFuzz/engines/aflplusplus-selective
./afl-clang-fast -Iinclude -O1 -g -o target target.c
```

## Target-Side TCU Calls

Include:

```c
#include "trigfuzz-distance.h"
```

Insert:

```c
distance_instrument(distance_expr, save_index, seq, conj, weight);
```

Use helper expressions:

```c
tf_gt(tf_sub_num((double)nstrips, 1.0), (double)limit)
tf_bool(ptr != NULL)
```

## Run

```sh
AFL_TRIGFUZZ_ENABLE=1 \
AFL_TRIGFUZZ_INS_NUM=64 \
AFL_TRIGFUZZ_SEQ_NUM=64 \
/root/TrigFuzz/engines/aflplusplus-selective/afl-fuzz \
  -i seeds \
  -o out \
  -m none \
  -t 5000 \
  -d \
  -- ./target @@
```

Diagnostics:

```sh
export AFL_TRIGFUZZ_DEBUG=1
```

With `AFL_TRIGFUZZ_ENABLE` unset, the fuzzer should behave like normal AFL++.
