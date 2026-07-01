# TrigFuzz on AFL++

This tree contains an AFL++ `v5.01c` port of TrigFuzz's default feedback
model: trigger-distance reporting, `+trig` queue discovery,
trigger-distance-aware seed scheduling, and conservative selective
instrumentation.

Triggering-byte mutation is intentionally not part of this AFL++ v1 port.

## Building Targets

Instrument target code with AFL++ as usual, and include:

```c
#include "trigfuzz-distance.h"
```

At each LLM-selected triggering-condition unit, insert:

```c
distance_instrument(distance_expr, loc, seq, conj, weight);
```

`distance_expr` is emitted directly by the LLM or TCU author. Do not provide
old `cond`-only metadata and rely on automatic condition lowering.

Use the helper functions from `trigfuzz-distance.h` for safe branch-distance
expressions, for example:

```c
tf_gt(tf_sub_num((double)nstrips, 1.0), (double)limit)
tf_bool(ptr != NULL)
```

## Selective Instrumentation

Enable the SelectFuzz-style pass while compiling:

```sh
export AFL_TRIGFUZZ_SELECTIVE=selectfuzz-like
export AFL_TRIGFUZZ_SELECTIVE_FILE=/path/to/selective-keep.txt
```

The keep list contains one canonical `basename:line` entry per line:

```text
parser.c:120
decoder.c:88
```

The pass instruments listed source locations. Basic blocks without usable
debug locations remain instrumented so unknown code is not silently dropped.

## Running

Enable TrigFuzz in `afl-fuzz` with:

```sh
AFL_TRIGFUZZ_ENABLE=1 \
AFL_TRIGFUZZ_INS_NUM=64 \
AFL_TRIGFUZZ_SEQ_NUM=64 \
./afl-fuzz -i seeds -o out -- ./target @@
```

`AFL_TRIGFUZZ_INS_NUM` is the number of TCU slots available to
`distance_instrument()`. `AFL_TRIGFUZZ_SEQ_NUM` is the number of sequence
levels used by the triggering-distance aggregation.

If these are omitted, both default to `64`.

Optional diagnostics:

```sh
AFL_TRIGFUZZ_DEBUG=1
```

## Behavior

When TrigFuzz is enabled, AFL++ creates a dedicated TrigFuzz shared-memory
region and exports it to the target using `__AFL_TRIGFUZZ_SHM_ID`.

After each primary target execution, AFL++ aggregates the recorded TCU
distances. A lower aggregate distance is better; distance `0` means the
triggering condition has been reached.

Inputs are saved when they either:

- increase normal AFL++ coverage, or
- improve the best known triggering distance.

Inputs saved because of triggering-distance progress are tagged `+trig` in
normal queue filenames. With `AFL_SHA1_FILENAMES=1`, the metadata is stored on
the queue entry even though the filename cannot show the suffix.

Scheduling keeps normal AFL++ coverage behavior and adds a bounded
trigger-distance multiplier. Seeds with better measured triggering distance get
more energy, capped at `3x`. Seeds without TrigFuzz distance are not penalized.

## Notes

- TrigFuzz is opt-in. With `AFL_TRIGFUZZ_ENABLE` unset, AFL++ behavior should
  remain unchanged.
- Imported `+trig` seeds are recognized from filename metadata, but scheduling
  only uses their trigger distance after local calibration remeasures them.
- The shared-memory layout is separate from AFL++'s coverage map. Do not append
  TrigFuzz records after `trace_bits`.
