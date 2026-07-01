# AFLGo instrumentation (LLVM-based)

The code in this directory allows you to instrument programs for AFLGo.
AFL's new *trace-pc-guard* mode is not supported currently.

## How to use

You need to have clang installed on your system.
You should also make sure that the `llvm-config` tool is in your path
(or pointed to via `LLVM_CONFIG` in the environment).

Unfortunately, some systems that do have clang come without llvm-config or the
LLVM development headers; one example of this is FreeBSD. FreeBSD users will
also run into problems with clang being built statically and not being able to
load modules (you'll see "Service unavailable" when loading `aflgo-pass.so`).

To solve all your problems, you can grab pre-built binaries for your OS from:

  http://llvm.org/releases/download.html

...and then put the `bin/` directory from the tarball at the beginning of your
`$PATH` when compiling the feature and building packages later on. You don't need
to be root for that.

To build the instrumentation itself, type `make`. This will generate binaries
called `aflgo-clang` and `aflgo-clang++` in current directory. For compatibility
there are also `afl-clang-fast` (symlink to `aflgo-clang`) and `afl-clang-fast++`
(symlink to `aflgo-clang++`).
Once this is done, you can instrument third-party code in a way similar to the standard
operating mode of AFL, e.g.:
```bash
CC=/path/to/aflgo-clang ./configure #[...options...]#
make
```
Be sure to also include CXX set to `aflgo-clang++` for C++ code.

The tool honors roughly the same environmental variables as afl-gcc (see
`afl-2.57b/docs/env_variables.txt`). This includes `AFL_INST_RATIO`, `AFL_USE_ASAN`,
`AFL_HARDEN`, and `AFL_DONT_OPTIMIZE`.

## Incomplete CG and CFGs

In some cases, the CG and CFGs are that LLVM produces are incomplete
due to register-indirect jumps or calls. In this case, we may need to
add edges manually.

Firstly, re-compile `aflgo-clang.c` with `AFLGO_TRACING=1`, e.g.
```bash
cd ./instrument
make clean all AFLGO_TRACING=1
```

Secondly, run target to trace the executed CG and CFG edges 
with environment variable `AFLGO_PROFILER_FILE` set, e.g.
```bash
export AFLGO_PROFILER_FILE="<your-file>"
```

Finally, add edges with `../distance/add_edges.py`.

## Feature #1: deferred instrumentation

AFL tries to optimize performance by executing the targeted binary just once,
stopping it just before `main()`, and then cloning this "master" process to get
a steady supply of targets to fuzz.

Although this approach eliminates much of the OS-, linker- and libc-level
costs of executing the program, it does not always help with binaries that
perform other time-consuming initialization steps - say, parsing a large config
file before getting to the fuzzed data.

In such cases, it's beneficial to initialize the forkserver a bit later, once
most of the initialization work is already done, but before the binary attempts
to read the fuzzed input and parse it; in some cases, this can offer a 10x+
performance gain. You can implement delayed initialization in LLVM mode in a
fairly simple way.

First, find a suitable location in the code where the delayed cloning can 
take place. This needs to be done with *extreme* care to avoid breaking the
binary. In particular, the program will probably malfunction if you select
a location after:

  - The creation of any vital threads or child processes - since the forkserver
    can't clone them easily.

  - The initialization of timers via `setitimer()` or equivalent calls.

  - The creation of temporary files, network sockets, offset-sensitive file
    descriptors, and similar shared-state resources - but only provided that
    their state meaningfully influences the behavior of the program later on.

  - Any access to the fuzzed input, including reading the metadata about its
    size.

With the location selected, add this code in the appropriate spot:

```c
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
```

You don't need the `#ifdef` guards, but including them ensures that the program will
keep working normally when compiled with a tool other than `aflgo-clang` / `afl-clang-fast`.

Finally, recompile the program with `aflgo-clang` - and you should be all set!

## Feature #2: persistent mode

Some libraries provide APIs that are stateless, or whose state can be reset in
between processing different input files. When such a reset is performed, a
single long-lived process can be reused to try out multiple test cases,
eliminating the need for repeated `fork()` calls and the associated OS overhead.

The basic structure of the program that does this would be:

```c
  while (__AFL_LOOP(1000)) {

    /* Read input data. */
    /* Call library code to be fuzzed. */
    /* Reset state. */

  }

  /* Exit normally */
```

The numerical value specified within the loop controls the maximum number
of iterations before AFL will restart the process from scratch. This minimizes
the impact of memory leaks and similar glitches; 1000 is a good starting point,
and going much higher increases the likelihood of hiccups without giving you
any real performance benefits.

A more detailed template is shown in `afl-2.57b/experimental/persistent_demo/`.
Similarly to the previous mode, the feature works only with `aflgo-clang` / `afl-clang-fast`;
`#ifdef` guards can be used to suppress it when using other compilers.

Note that as with the previous mode, the feature is easy to misuse; if you
do not fully reset the critical state, you may end up with false positives or
waste a whole lot of CPU power doing nothing useful at all. Be particularly
wary of memory leaks and of the state of file descriptors.

PS. Because there are task switches still involved, the mode isn't as fast as
"pure" in-process fuzzing offered, say, by LLVM's LibFuzzer; but it is a lot
faster than the normal `fork()` model, and compared to in-process fuzzing,
should be a lot more robust.
