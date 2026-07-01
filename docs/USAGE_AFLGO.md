# AFLGo Based TrigFuzz

This option is the paper-aligned implementation path. It uses AFLGo as the directed-fuzzing base and adds TrigFuzz triggering-distance feedback:

- target-side `distance_instrument(...)` calls write TCU distance records;
- `afl-fuzz` aggregates distances after each run;
- inputs that improve triggering distance are saved with `+trig`;
- seed scheduling incorporates triggering distance.

The release default is triggering-distance scheduling. Triggering byte-aware mutation is available as an explicit opt-in experiment.

## Build

```sh
cd /root/TrigFuzz/engines/aflgo-trigfuzz/afl-2.57b
make clean all
```

The Python driver uses these binaries by default:

```text
engines/aflgo-trigfuzz/afl-2.57b/afl-fuzz
engines/aflgo-trigfuzz/afl-2.57b/afl-gcc
```

Override them if needed:

```sh
export TRIGFUZZ_AFL=/path/to/afl-fuzz
export TRIGFUZZ_AFL_GCC=/path/to/afl-gcc
```

## Target Instrumentation

Include the runtime header:

```c
#include "distance.h"
```

At each TCU location, insert:

```c
distance_instrument(distance_expr, save_index, seq, conj, weight);
```

The Python instrumenter performs this insertion from `tcus.json`.

## Run

```sh
cd /root/TrigFuzz
python3 -B -m trigfuzz.driver examples/motivating \
  --skip-llm \
  --quick-dirty \
  --budget 60
```

Important defaults:

- `--quick-dirty` passes `-d`.
- `--aflgo-cutoff` defaults to `10m`, so the fuzzer receives `-z exp -c 10m`.
- The driver stops on the first crash with `AFL_BENCH_UNTIL_CRASH=1`.

Direct fuzzer invocation shape:

```sh
/root/TrigFuzz/engines/aflgo-trigfuzz/afl-2.57b/afl-fuzz \
  -i seeds \
  -o out \
  -m none \
  -t 5000 \
  -z exp \
  -c 10m \
  -d \
  -a INS_NUM \
  -s SEQ_NUM \
  -- ./target @@
```

Use `@@` for file-input targets. Omit it for stdin targets.

## Optional Byte-Aware Mutation

To add the byte-aware local mutation stage:

```sh
export AFL_TRIG_ENABLE_BYTE_AWARE_MUTATION=1
```

Optional strategy selector:

```sh
export AFL_TRIG_MUTATION_MODE=hybrid
```

Accepted values are:

- `diff`: mutate bytes that changed between source seed and `+trig` seed;
- `scan`: bounded sensitivity scan;
- `hybrid`: diff first, then scan if diff is not productive.
