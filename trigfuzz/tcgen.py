"""Standalone TC generation CLI.

The full driver can generate TCUs before fuzzing, but release users often
want a separate reviewable step:

    bug_report.json + source/ -> tcus.json

This module runs the progressive LLM agent and writes candidate TCU sets in
the release `distance_expr` JSON format.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .agent import sample_candidates
from .llm_client import LLMClient
from .tcu import TCU, to_json


SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
}


def _number_source(path: pathlib.Path, root: pathlib.Path) -> tuple[str, str]:
    rel = path.relative_to(root).as_posix()
    lines = path.read_text(errors="replace").splitlines()
    width = max(1, len(str(len(lines))))
    numbered = "\n".join(f"{i:>{width}} {line}" for i, line in enumerate(lines, 1))
    return rel, numbered


def collect_source_slices(
    source_root: pathlib.Path, selected: list[str] | None = None
) -> dict[str, str]:
    """Load numbered source snippets for the initial LLM prompt."""
    if selected:
        paths = [source_root / item for item in selected]
    else:
        paths = [
            p for p in sorted(source_root.rglob("*"))
            if p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES
        ]

    out: dict[str, str] = {}
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"source file not found: {path}")
        rel, body = _number_source(path, source_root)
        out[rel] = body
    return out


def load_func_dict(target_dir: pathlib.Path) -> dict[str, str]:
    path = target_dir / "funcs.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("funcs.json must be an object mapping function names to source")
    return {str(k): str(v) for k, v in data.items()}


def serialize_candidates(candidates: list[list[TCU]]) -> list[dict] | list[list[dict]]:
    if len(candidates) == 1:
        return to_json(candidates[0])
    return [to_json(candidate) for candidate in candidates]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="trigfuzz-tcgen")
    ap.add_argument("target_dir", type=pathlib.Path,
                    help="Directory containing bug_report.json and source/")
    ap.add_argument("--k", type=int, default=3,
                    help="Number of independent TCU candidate sets to sample")
    ap.add_argument("--out", type=pathlib.Path,
                    help="Output JSON path, default: target_dir/tcus.json")
    ap.add_argument("--source", action="append", default=None,
                    help="Initial source file relative to target_dir/source/. "
                         "May be repeated. Defaults to all C/C++ files.")
    ap.add_argument("--model", default=None,
                    help="OpenAI model name; defaults to OPENAI_MODEL or gpt-5.5")
    args = ap.parse_args(argv)

    if args.k <= 0:
        print("[-] --k must be positive", file=sys.stderr)
        return 2

    target_dir = args.target_dir.resolve()
    report_path = target_dir / "bug_report.json"
    source_root = target_dir / "source"
    out_path = args.out or (target_dir / "tcus.json")

    if not report_path.exists():
        print(f"[-] Missing {report_path}", file=sys.stderr)
        return 2
    if not source_root.is_dir():
        print(f"[-] Missing source directory: {source_root}", file=sys.stderr)
        return 2

    report = json.loads(report_path.read_text())
    seed_source = collect_source_slices(source_root, args.source)
    if not seed_source:
        print(f"[-] No source files found under {source_root}", file=sys.stderr)
        return 2

    llm = LLMClient(model=args.model) if args.model else None
    try:
        candidates = sample_candidates(
            k=args.k,
            report=report,
            seed_source=seed_source,
            func_dict=load_func_dict(target_dir),
            llm=llm,
        )
    except Exception as exc:
        print(f"[-] TC generation failed: {exc}", file=sys.stderr)
        return 1
    if not any(candidates):
        print("[-] TC generation returned no TCUs", file=sys.stderr)
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(serialize_candidates(candidates), indent=2) + "\n")
    total = sum(len(candidate) for candidate in candidates)
    print(f"[+] Wrote {len(candidates)} candidate set(s), {total} TCU(s): {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
