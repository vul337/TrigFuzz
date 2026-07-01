"""TrigFuzz driver: orchestrates the patched AFLGo binary.

Pipeline per target:
    1. Load (or LLM-generate) k candidate TC sets.
    2. Assign disjoint save_index slots so a single v1 binary can monitor
       all candidates simultaneously.
    3. Instrument each v1/v2 source tree (instrument.py).
    4. Compile with afl-gcc -> AFL coverage instrumentation + distance.h
       runtime monitor in the same shm region.
    5. Spawn `afl-fuzz -a INS_NUM -s SEQ_NUM -i seeds -o out -- ./target`.
       This is the patched binary at $TRIGFUZZ_AFL or aflgo/afl-2.57b/afl-fuzz.
    6. (optional) Watch the queue for `+trig` files; when one appears,
       replay it on each v2 binary to drive the second validation step
       and pick the winning TC.  Once a winner is chosen we restart
       afl-fuzz with only that TC's slots active (the losers' weights are
       set so they cannot earn +trig).

Dependencies:
    - The patched afl-fuzz binary built from aflgo/afl-2.57b with our
      mutator changes applied.
    - afl-gcc on $PATH (or pointed to via $TRIGFUZZ_AFL_GCC).
    - distance.h (this repo).
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import resource
import shutil
import signal
import subprocess
import sys
import time

from .agent import sample_candidates
from .instrument import instrument_v1, instrument_v2
from .tcu import TCU, from_json, to_json
from .validation import Candidate, Validator


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

AFL_FUZZ = pathlib.Path(
    os.environ.get("TRIGFUZZ_AFL",
                   str(REPO_ROOT / "engines/aflgo-trigfuzz/afl-2.57b/afl-fuzz"))
)
AFL_GCC = os.environ.get("TRIGFUZZ_AFL_GCC",
                         str(REPO_ROOT / "engines/aflgo-trigfuzz/afl-2.57b/afl-gcc"))


def _load_candidate_sets(path: pathlib.Path) -> list[list[TCU]]:
    data = json.loads(path.read_text())
    if not data:
        return []
    if isinstance(data[0], dict):
        return [from_json(data)]
    return [from_json(candidate) for candidate in data]


# ---------------------------------------------------------------------------
# Build helpers
# ---------------------------------------------------------------------------

def _compile(src_dir: pathlib.Path, out_bin: pathlib.Path,
             *, sanitize: bool = False) -> None:
    """Compile a single-translation-unit C target with AFL coverage and
    the TrigFuzz runtime header.

    For multi-file projects the user supplies their own build.sh; we use
    it via `_compile_with_script` instead.  This helper is for the simple
    `<src_dir>/main.c` case that the example uses.
    """
    env = os.environ.copy()
    env.setdefault("AFL_PATH", str(pathlib.Path(AFL_GCC).resolve().parent))
    if sanitize:
        env["AFL_USE_ASAN"] = "1"

    src = src_dir / "main.c"
    cmd = [AFL_GCC, "-O1", "-g",
           "-I", str(REPO_ROOT),     # for distance.h
           "-o", str(out_bin), str(src), "-lm"]
    subprocess.run(cmd, check=True, env=env)


def _compile_with_script(target_dir: pathlib.Path,
                         src_dir: pathlib.Path,
                         out_bin: pathlib.Path,
                         *, sanitize: bool = False) -> None:
    """For non-trivial targets: invoke build.sh <src> <out> and let it
    set CC=afl-gcc etc.  We export the same env vars for consistency."""
    env = os.environ.copy()
    env.setdefault("AFL_PATH", str(pathlib.Path(AFL_GCC).resolve().parent))
    env["CC"] = AFL_GCC
    env["CFLAGS"] = (env.get("CFLAGS", "") + f" -I{REPO_ROOT}").strip()
    if sanitize:
        env["AFL_USE_ASAN"] = "1"
    subprocess.run(["bash", str(target_dir / "build.sh"),
                    str(src_dir), str(out_bin)], check=True, env=env)


# ---------------------------------------------------------------------------
# afl-fuzz invocation
# ---------------------------------------------------------------------------

def _spawn_afl(target: pathlib.Path, seeds: pathlib.Path,
               out: pathlib.Path, *, ins_num: int, seq_num: int,
               quick_dirty: bool, banner: str,
               aflgo_cutoff: str | None,
               extra_env: dict | None = None) -> subprocess.Popen:
    """Launch afl-fuzz as a child process and return immediately.

    The caller monitors `out/` for crashes and `out/queue/` for
    `+trig`-tagged seeds, then sends SIGINT when satisfied.
    """
    out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["AFL_SKIP_CPUFREQ"] = "1"
    env["AFL_NO_AFFINITY"] = "1"
    env["AFL_BENCH_UNTIL_CRASH"] = "1"   # exit afl-fuzz on first crash
    if extra_env:
        env.update(extra_env)

    cmd = [str(AFL_FUZZ),
           "-i", str(seeds),
           "-o", str(out),
           "-T", banner,
           "-a", str(ins_num),
           "-s", str(seq_num)]
    if aflgo_cutoff:
        cmd += ["-z", "exp", "-c", aflgo_cutoff]
    if quick_dirty:
        cmd.append("-d")
    cmd += ["--", str(target)]

    def prepare_child() -> None:
        # Detach into its own process group so we can kill the whole tree,
        # and suppress core files from expected crashing inputs.
        os.setsid()
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (AttributeError, ValueError, OSError):
            pass

    log = open(out / "afl.log", "w")
    return subprocess.Popen(cmd, env=env,
                            stdout=log, stderr=subprocess.STDOUT,
                            preexec_fn=prepare_child)


def _wait_for_outcome(afl: subprocess.Popen, out: pathlib.Path,
                      *, budget: float,
                      on_trig: callable | None = None) -> pathlib.Path | None:
    """Block until afl-fuzz exits, hits budget, or finds a crash.

    Returns the path to a triggering input if one is found, else None.
    `on_trig` is called once per newly-discovered `+trig`-tagged queue
    entry so the caller can drive v2 validation in parallel.
    """
    start = time.time()
    seen: set[str] = set()

    def _resolve():
        # AFL drops queue/ and crashes/ directly into `out` for single-
        # instance runs; under -M/-S they live under default/.  We resolve
        # both each iteration because the dirs are created lazily after
        # the dry run.
        for sub in ("", "default"):
            base = out / sub if sub else out
            if (base / "queue").exists():
                return base / "queue", base / "crashes"
        return None, None

    while time.time() - start < budget:
        queue_dir, crashes_dir = _resolve()
        if afl.poll() is not None:
            break
        # Crash short-circuit.
        if crashes_dir and crashes_dir.exists():
            crashes = [p for p in crashes_dir.iterdir()
                       if p.is_file() and not p.name.startswith("README")]
            if crashes:
                return crashes[0]
        # +trig hook.
        if on_trig and queue_dir and queue_dir.exists():
            for q in queue_dir.iterdir():
                if q.name in seen:
                    continue
                seen.add(q.name)
                if "+trig" in q.name:
                    on_trig(q)
        time.sleep(0.5)

    # Cleanup.
    try:
        os.killpg(afl.pid, signal.SIGINT)
        afl.wait(timeout=5)
    except Exception:
        try: os.killpg(afl.pid, signal.SIGKILL)
        except Exception: pass

    _, crashes_dir = _resolve()
    if crashes_dir and crashes_dir.exists():
        crashes = [p for p in crashes_dir.iterdir()
                   if p.is_file() and not p.name.startswith("README")]
        if crashes:
            return crashes[0]
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="trigfuzz")
    ap.add_argument("target_dir", type=pathlib.Path,
                    help="Directory holding source/, seeds/, bug_report.json")
    ap.add_argument("--budget", type=float, default=600.0)
    ap.add_argument("--k", type=int, default=1,
                    help="Number of LLM-sampled candidate TC sets.")
    ap.add_argument("--skip-llm", action="store_true",
                    help="Load tcus.json instead of calling the LLM.")
    ap.add_argument("--asan", action="store_true",
                    help="Build with AddressSanitizer.")
    ap.add_argument("--quick-dirty", action="store_true", default=False,
                    help="Pass -d to afl-fuzz (skip deterministic stage).")
    ap.add_argument("--aflgo-cutoff", default="10m",
                    help="AFLGo -c cutoff used with -z exp (default: 10m).")
    ap.add_argument("--use-script", action="store_true",
                    help="Use target_dir/build.sh instead of single-file gcc.")
    args = ap.parse_args(argv)

    d = args.target_dir.resolve()
    work = d / "work"; work.mkdir(exist_ok=True)
    report = json.loads((d / "bug_report.json").read_text())

    # 1. Get TC candidates -------------------------------------------------
    if args.skip_llm:
        cand_tcus = _load_candidate_sets(d / "tcus.json")
    else:
        funcs = json.loads((d / "funcs.json").read_text()) \
                if (d / "funcs.json").exists() else {}
        seed_src = {p.name: p.read_text()
                    for p in (d / "source").glob("*.[ch]")}
        cand_tcus = sample_candidates(
            k=args.k, report=report,
            seed_source=seed_src, func_dict=funcs,
        )
        tc_json = to_json(cand_tcus[0]) if len(cand_tcus) == 1 else [
            to_json(c) for c in cand_tcus
        ]
        (d / "tcus.json").write_text(json.dumps(tc_json, indent=2))

    # 2. Disjoint save_index slots across all candidates ------------------
    next_idx = 0
    for tcu_set in cand_tcus:
        for t in tcu_set:
            t.save_index = next_idx
            next_idx += 1

    union_tcus = [t for tcu_set in cand_tcus for t in tcu_set]
    if not union_tcus:
        print("[-] No TCUs available for fuzzing.", file=sys.stderr)
        return 2
    ins_num = len(union_tcus)
    seq_num = max((t.seq for t in union_tcus), default=0) + 1

    # 3. v1 instrumentation + build ---------------------------------------
    src_v1 = work / "source-v1"
    if src_v1.exists():
        shutil.rmtree(src_v1)
    shutil.copytree(d / "source", src_v1)
    instrument_v1(union_tcus, src_v1)

    bin_v1 = work / "target-v1"
    if args.use_script:
        _compile_with_script(d, src_v1, bin_v1, sanitize=args.asan)
    else:
        _compile(src_v1, bin_v1, sanitize=args.asan)

    # 4. v2 instrumentation + builds (one per candidate) ------------------
    cands: list[Candidate] = []
    for i, tcu_set in enumerate(cand_tcus):
        src_v2 = work / f"source-v2-{i}"
        bin_v2 = work / f"target-v2-{i}"
        if src_v2.exists():
            shutil.rmtree(src_v2)
        instrument_v2(tcu_set, d / "source", src_v2)
        try:
            if args.use_script:
                _compile_with_script(d, src_v2, bin_v2, sanitize=args.asan)
            else:
                _compile(src_v2, bin_v2, sanitize=args.asan)
            v2 = bin_v2
        except subprocess.CalledProcessError:
            print(f"[!] v2 build for candidate {i} failed; skipping.",
                  file=sys.stderr)
            v2 = None
        cands.append(Candidate(
            tcus=tcu_set,
            v1_indices=[t.save_index for t in tcu_set],
            v2_binary=v2,
        ))

    # 5. Fuzz with the patched AFLGo --------------------------------------
    out_dir = work / "afl-out"
    if out_dir.exists():
        shutil.rmtree(out_dir)

    validator = Validator(cands)

    def on_trig(q: pathlib.Path):
        # Each newly-tagged +trig input becomes a v2 probe.  The validator
        # is idempotent; re-probing with new inputs only sharpens its
        # opinion.  We DON'T restart afl-fuzz at this point - that's a
        # nice-to-have improvement worth doing in production.
        for c in cands:
            validator.attempt_v2(c, q.read_bytes())

    print(f"[+] Launching afl-fuzz: ins_num={ins_num} seq_num={seq_num} "
          f"budget={args.budget:.0f}s")
    afl = _spawn_afl(bin_v1, d / "seeds", out_dir,
                     ins_num=ins_num, seq_num=seq_num,
                     quick_dirty=args.quick_dirty, banner="trigfuzz",
                     aflgo_cutoff=args.aflgo_cutoff)
    poc = _wait_for_outcome(afl, out_dir, budget=args.budget,
                            on_trig=on_trig)

    # 6. Report ------------------------------------------------------------
    if poc:
        dst = d / "poc.bin"
        dst.write_bytes(poc.read_bytes())
        print(f"[+] Triggering input: {dst} ({dst.stat().st_size} B)")
        winner = validator.choose() if any(c.v2_ok is not None for c in cands) else cands[0]
        print(f"[+] Winning TC (validation score={winner.score}):")
        for t in winner.tcus:
            print(f"    <{t.cond}, {t.loc}, seq={t.seq}, conj={t.conj}>")
        return 0

    print("[-] No triggering input within budget.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
