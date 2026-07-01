#!/usr/bin/env python3
"""Run deterministic end-to-end TrigFuzz smoke checks.

The checks require +trig queue entries as well as final crashing inputs:

* source_diff_magic uses the paper-default source-diff triggering-byte mode.
* two_byte_magic uses AFL_TRIG_ALL_BYTES=1 to exercise the broader fallback.
"""

from __future__ import annotations

import argparse
import os
import resource
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=float, default=30.0)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="trigfuzz-dynamic-"))
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (AttributeError, ValueError, OSError):
        pass

    checks = [
        ("source_diff_magic", b"YMAG", {}),
        ("two_byte_magic", b"Z!", {"AFL_TRIG_ALL_BYTES": "1"}),
    ]

    for name, expected, extra_env in checks:
        rc = run_one(tmp, name, expected, args.budget, extra_env)
        if rc:
            if not args.keep:
                shutil.rmtree(tmp)
            return rc

    if args.keep:
        print(f"[dynamic] kept workdir: {tmp}")
    else:
        shutil.rmtree(tmp)
    return 0


def run_one(
    tmp: Path,
    name: str,
    expected_prefix: bytes,
    budget: float,
    extra_env: dict[str, str],
) -> int:
    target = tmp / name
    shutil.copytree(ROOT / "examples" / name, target)
    cmd = [
        sys.executable,
        "-B",
        "-m",
        "trigfuzz.driver",
        str(target),
        "--skip-llm",
        "--budget",
        str(budget),
    ]
    env = None
    if extra_env:
        env = {**os.environ, **extra_env}
    print(f"[dynamic] running {name}:", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, env=env)
    print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    if proc.returncode != 0:
        print(f"[dynamic] driver failed with exit {proc.returncode}", file=sys.stderr)
        return proc.returncode

    poc = target / "poc.bin"
    if not poc.exists() or poc.read_bytes()[: len(expected_prefix)] != expected_prefix:
        print(
            f"[dynamic] expected {name} poc.bin to start with {expected_prefix!r}",
            file=sys.stderr,
        )
        return 1

    queue = target / "work" / "afl-out" / "queue"
    trig = sorted(p for p in queue.iterdir() if "+trig" in p.name)
    if not trig:
        print("[dynamic] no +trig queue entry produced", file=sys.stderr)
        return 1

    print(f"[dynamic] {name} +trig entries: {len(trig)}")
    print(
        f"[dynamic] {name} first +trig: "
        f"{trig[0].name} -> {trig[0].read_bytes()[:len(expected_prefix)]!r}"
    )
    print(
        f"[dynamic] {name} poc: "
        f"{poc} -> {poc.read_bytes()[:len(expected_prefix)]!r}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
