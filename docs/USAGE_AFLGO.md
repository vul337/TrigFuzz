# AFLGo Based TrigFuzz

This option is the paper-aligned implementation path. It uses AFLGo as the directed-fuzzing base and adds TrigFuzz triggering-distance feedback:

- the optional two-pass build generates AFLGo control-flow distances to the
  report's target locations;
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

For control-flow distance, also build the LLVM instrumentation pass:

```sh
cd /root/TrigFuzz/engines/aflgo-trigfuzz/instrument
make clean all LLVM_CONFIG=llvm-config-14 CC=clang-14 CXX=clang++-14
```

This requires a compatible LLVM/Clang toolchain, plus AFLGo's Graphviz and
Python distance-generation dependencies.

The Python driver uses these binaries by default:

```text
engines/aflgo-trigfuzz/afl-2.57b/afl-fuzz
engines/aflgo-trigfuzz/afl-2.57b/afl-gcc
```

Override them if needed:

```sh
export TRIGFUZZ_AFL=/path/to/afl-fuzz
export TRIGFUZZ_AFL_GCC=/path/to/afl-gcc
export TRIGFUZZ_AFL_GXX=/path/to/afl-g++
export TRIGFUZZ_AFLGO_CLANG=/path/to/aflgo-clang
export TRIGFUZZ_AFLGO_CLANGXX=/path/to/aflgo-clang++
export TRIGFUZZ_AFLGO_CC=/path/to/clang-14
export TRIGFUZZ_AFLGO_CXX=/path/to/clang++-14
export TRIGFUZZ_AFLGO_OPT=/path/to/opt-14
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
  --aflgo-distance \
  --quick-dirty \
  --budget 60
```

The driver derives `BBtargets.txt` from `bug_report.json` entries such as
`"line 6 in main.c"`. Targets can instead be specified explicitly:

```json
{
  "type": "heap-buffer-overflow",
  "crash_points": ["line 6 in main.c"],
  "aflgo_targets": ["main.c:6"]
}
```

Or on the command line:

```sh
python3 -B -m trigfuzz.driver my-target \
  --skip-llm \
  --aflgo-distance \
  --aflgo-target parser.c:120
```

The two-pass artifacts and final distance file are written below
`my-target/work/aflgo-distance/`. Without `--aflgo-distance`, the driver uses
`afl-gcc`: coverage and TCU triggering distance remain enabled, but AFLGo's
control-flow-distance term is absent.

For a multi-file target, pass `--use-script`. Its `build.sh` must honor
`CC`, `CXX`, `CFLAGS`, and `CXXFLAGS`; the driver invokes it once with
`TRIGFUZZ_BUILD_PHASE=aflgo-preprocess` and once with
`TRIGFUZZ_BUILD_PHASE=aflgo-final`.

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
