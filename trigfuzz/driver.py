"""TrigFuzz driver: orchestrates the patched AFLGo binary.

Pipeline per target:
    1. Load (or LLM-generate) k candidate TC sets.
    2. Assign disjoint save_index slots so a single v1 binary can monitor
       all candidates simultaneously.
    3. Instrument each v1/v2 source tree (instrument.py).
    4. Compile either with afl-gcc (TCU-only mode), or perform AFLGo's
       preprocessing, distance generation, and final distance-instrumented
       build (``--aflgo-distance``).  Both modes retain distance.h feedback.
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
    - For ``--aflgo-distance``: the bundled AFLGo LLVM compiler pass,
      distance-generation dependencies, and a build script that honors
      CC/CXX/CFLAGS/CXXFLAGS.
    - distance.h (this repo).
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import resource
import re
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
AFL_GXX = os.environ.get(
    "TRIGFUZZ_AFL_GXX",
    str(REPO_ROOT / "engines/aflgo-trigfuzz/afl-2.57b/afl-g++"),
)
AFLGO_ROOT = pathlib.Path(
    os.environ.get(
        "TRIGFUZZ_AFLGO_ROOT",
        str(REPO_ROOT / "engines/aflgo-trigfuzz"),
    )
)
AFLGO_CLANG = os.environ.get(
    "TRIGFUZZ_AFLGO_CLANG",
    str(AFLGO_ROOT / "instrument/aflgo-clang"),
)
AFLGO_CLANGXX = os.environ.get(
    "TRIGFUZZ_AFLGO_CLANGXX",
    str(AFLGO_ROOT / "instrument/aflgo-clang++"),
)
AFLGO_CC = os.environ.get(
    "TRIGFUZZ_AFLGO_CC",
    shutil.which("clang-14") or shutil.which("clang") or "clang",
)
AFLGO_CXX = os.environ.get(
    "TRIGFUZZ_AFLGO_CXX",
    shutil.which("clang++-14") or shutil.which("clang++") or "clang++",
)
AFLGO_OPT = os.environ.get(
    "TRIGFUZZ_AFLGO_OPT",
    shutil.which("opt-14") or shutil.which("opt") or "opt",
)
AFLGO_DISTANCE_SCRIPT = pathlib.Path(
    os.environ.get(
        "TRIGFUZZ_AFLGO_DISTANCE_SCRIPT",
        str(AFLGO_ROOT / "distance/gen_distance_orig.sh"),
    )
)

_REPORT_LOC_RE = re.compile(r"line\s+(\d+)\s+in\s+([\w./-]+)", re.IGNORECASE)
_AFLGO_TARGET_RE = re.compile(r"^.+:\d+$")


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

def _append_flags(existing: str, flags: list[str]) -> str:
    return " ".join(part for part in [existing.strip(), *flags] if part)


def _compile(src_dir: pathlib.Path, out_bin: pathlib.Path,
             *, sanitize: bool = False,
             compiler: str = AFL_GCC,
             extra_flags: list[str] | None = None,
             extra_env: dict[str, str] | None = None) -> None:
    """Compile a single-translation-unit C target with AFL coverage and
    the TrigFuzz runtime header.

    For multi-file projects the user supplies their own build.sh; we use
    it via `_compile_with_script` instead.  This helper is for the simple
    `<src_dir>/main.c` case that the example uses.
    """
    env = os.environ.copy()
    env.setdefault("AFL_PATH", str(pathlib.Path(AFL_GCC).resolve().parent))
    if extra_env:
        env.update(extra_env)
    if sanitize:
        env["AFL_USE_ASAN"] = "1"

    src = src_dir / "main.c"
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    cmd = [compiler, "-O1", "-g",
           "-I", str(REPO_ROOT),     # for distance.h
           *(extra_flags or []),
           "-o", str(out_bin), str(src), "-lm"]
    subprocess.run(cmd, check=True, env=env)


def _compile_with_script(target_dir: pathlib.Path,
                         src_dir: pathlib.Path,
                         out_bin: pathlib.Path,
                         *, sanitize: bool = False,
                         compiler: str = AFL_GCC,
                         cxx_compiler: str | None = None,
                         extra_flags: list[str] | None = None,
                         extra_env: dict[str, str] | None = None,
                         build_phase: str = "final") -> None:
    """For non-trivial targets: invoke build.sh <src> <out> and let it
    set CC=afl-gcc etc.  We export the same env vars for consistency."""
    env = os.environ.copy()
    env.setdefault("AFL_PATH", str(pathlib.Path(AFL_GCC).resolve().parent))
    env["CC"] = compiler
    env["CXX"] = cxx_compiler or (AFL_GXX if compiler == AFL_GCC else compiler)
    build_flags = [f"-I{REPO_ROOT}", *(extra_flags or [])]
    env["CFLAGS"] = _append_flags(env.get("CFLAGS", ""), build_flags)
    env["CXXFLAGS"] = _append_flags(env.get("CXXFLAGS", ""), build_flags)
    env["TRIGFUZZ_BUILD_PHASE"] = build_phase
    if extra_env:
        env.update(extra_env)
    if sanitize:
        env["AFL_USE_ASAN"] = "1"
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["bash", str(target_dir / "build.sh"),
                    str(src_dir), str(out_bin)], check=True, env=env)


def _aflgo_targets(report: dict, overrides: list[str] | None = None) -> list[str]:
    """Return AFLGo ``file:line`` targets from CLI overrides or a report."""
    raw_targets = overrides or report.get("aflgo_targets") or []
    if isinstance(raw_targets, str):
        raw_targets = [raw_targets]

    targets: list[str] = []
    for raw in raw_targets:
        value = str(raw).strip()
        if not _AFLGO_TARGET_RE.match(value):
            raise ValueError(
                f"invalid AFLGo target {value!r}; expected FILE:LINE"
            )
        if value not in targets:
            targets.append(value)

    if targets:
        return targets

    for point in report.get("crash_points", []):
        match = _REPORT_LOC_RE.search(str(point))
        if not match:
            continue
        value = f"{match.group(2)}:{match.group(1)}"
        if value not in targets:
            targets.append(value)
    return targets


def _normalize_aflgo_metadata(temp_dir: pathlib.Path) -> None:
    """Deduplicate metadata appended by parallel compiler invocations."""
    for name in ("BBnames.txt", "BBcalls.txt", "Fnames.txt", "Ftargets.txt",
                 "BBtargets.resolved.txt"):
        path = temp_dir / name
        if not path.exists():
            continue
        rows = sorted({line.strip() for line in path.read_text().splitlines()
                       if line.strip()})
        path.write_text("".join(f"{row}\n" for row in rows))


def _use_resolved_aflgo_targets(temp_dir: pathlib.Path) -> None:
    """Replace source-line targets with their containing LLVM BB names."""
    resolved = temp_dir / "BBtargets.resolved.txt"
    rows = resolved.read_text().splitlines() if resolved.exists() else []
    rows = sorted({row.strip() for row in rows if row.strip()})
    if not rows:
        requested = (temp_dir / "BBtargets.txt").read_text().splitlines()
        raise RuntimeError(
            "AFLGo could not match any target to an instrumented source "
            f"location (requested: {', '.join(requested)})"
        )
    (temp_dir / "BBtargets.txt").write_text(
        "".join(f"{row}\n" for row in rows)
    )


def _aflgo_preprocess_flags(targets_file: pathlib.Path,
                            temp_dir: pathlib.Path) -> list[str]:
    return [
        f"-targets={targets_file}",
        f"-outdir={temp_dir}",
        "-flto",
        "-fuse-ld=gold",
        "-Wl,-plugin-opt=save-temps",
    ]


def _build_v1_with_aflgo_distance(
    *,
    target_dir: pathlib.Path,
    src_dir: pathlib.Path,
    out_bin: pathlib.Path,
    work_dir: pathlib.Path,
    report: dict,
    target_overrides: list[str] | None,
    use_script: bool,
    sanitize: bool,
) -> pathlib.Path:
    """Perform AFLGo preprocessing, distance generation, and final build."""
    targets = _aflgo_targets(report, target_overrides)
    if not targets:
        raise ValueError(
            "--aflgo-distance needs crash_points in 'line N in file.c' "
            "form, bug_report.json aflgo_targets, or --aflgo-target FILE:LINE"
        )

    aflgo_work = work_dir / "aflgo-distance"
    if aflgo_work.exists():
        shutil.rmtree(aflgo_work)
    temp_dir = aflgo_work / "temp"
    binary_dir = aflgo_work / "binaries"
    temp_dir.mkdir(parents=True)
    binary_dir.mkdir(parents=True)

    targets_file = temp_dir / "BBtargets.txt"
    targets_file.write_text("".join(f"{target}\n" for target in targets))
    preprocess_bin = binary_dir / "target-v1-preprocess"
    preprocess_flags = _aflgo_preprocess_flags(targets_file, temp_dir)
    aflgo_env = {
        "AFLGO": str(AFLGO_ROOT),
        "AFL_CC": AFLGO_CC,
        "AFL_CXX": AFLGO_CXX,
        "OPT": AFLGO_OPT,
    }

    print(f"[+] AFLGo preprocessing targets: {', '.join(targets)}")
    if use_script:
        _compile_with_script(
            target_dir, src_dir, preprocess_bin,
            compiler=AFLGO_CLANG,
            cxx_compiler=AFLGO_CLANGXX,
            extra_flags=preprocess_flags,
            extra_env=aflgo_env,
            build_phase="aflgo-preprocess",
        )
    else:
        _compile(
            src_dir, preprocess_bin,
            compiler=AFLGO_CLANG,
            extra_flags=preprocess_flags,
            extra_env=aflgo_env,
        )

    _normalize_aflgo_metadata(temp_dir)
    required = [temp_dir / name for name in
                ("BBnames.txt", "BBcalls.txt", "Fnames.txt", "Ftargets.txt",
                 "BBtargets.resolved.txt")]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise RuntimeError(
            "AFLGo preprocessing did not produce required metadata: "
            + ", ".join(missing)
        )
    _use_resolved_aflgo_targets(temp_dir)

    subprocess.run(
        ["bash", str(AFLGO_DISTANCE_SCRIPT), str(binary_dir), str(temp_dir),
         preprocess_bin.name],
        check=True,
        env={**os.environ, **aflgo_env},
    )
    distance_file = temp_dir / "distance.cfg.txt"
    if not distance_file.is_file() or distance_file.stat().st_size == 0:
        raise RuntimeError(
            f"AFLGo produced no control-flow distances: {distance_file}"
        )

    final_flags = [f"-distance={distance_file}"]
    if use_script:
        _compile_with_script(
            target_dir, src_dir, out_bin,
            sanitize=sanitize,
            compiler=AFLGO_CLANG,
            cxx_compiler=AFLGO_CLANGXX,
            extra_flags=final_flags,
            extra_env=aflgo_env,
            build_phase="aflgo-final",
        )
    else:
        _compile(
            src_dir, out_bin,
            sanitize=sanitize,
            compiler=AFLGO_CLANG,
            extra_flags=final_flags,
            extra_env=aflgo_env,
        )
    return distance_file


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
    ap.add_argument("--aflgo-distance", action="store_true",
                    help="Generate AFLGo control-flow distances with a "
                         "preprocessing build, then combine them with TCU "
                         "triggering distance in the final binary.")
    ap.add_argument("--aflgo-target", action="append", default=None,
                    metavar="FILE:LINE",
                    help="Override an AFLGo target location. May be repeated. "
                         "Defaults to bug_report.json aflgo_targets or "
                         "parseable crash_points.")
    ap.add_argument("--use-script", action="store_true",
                    help="Use target_dir/build.sh instead of the built-in "
                         "single-file compiler. The script must honor "
                         "CC/CXX/CFLAGS/CXXFLAGS.")
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
    instrument_v1(
        union_tcus, src_v1, preserve_locations=args.aflgo_distance
    )

    bin_v1 = work / "target-v1"
    if args.aflgo_distance:
        try:
            distance_file = _build_v1_with_aflgo_distance(
                target_dir=d,
                src_dir=src_v1,
                out_bin=bin_v1,
                work_dir=work,
                report=report,
                target_overrides=args.aflgo_target,
                use_script=args.use_script,
                sanitize=args.asan,
            )
        except (ValueError, RuntimeError) as exc:
            print(f"[-] AFLGo distance build failed: {exc}", file=sys.stderr)
            return 2
        print(f"[+] AFLGo control-flow distance: {distance_file}")
    elif args.use_script:
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
