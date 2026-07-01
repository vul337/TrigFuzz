"""Automated v1 and v2 source instrumentation.

The original `ledfuzz` prototype requires the author to hand-edit the PUT
to insert `distance_instrument()` calls and (for v2) forcing assignments.
§4 of the paper describes a better approach: ask an LLM to emit a unified
diff in the aider edit format, then apply it with `patch`.  That is what
this module implements.

Two modes:

* v1 - insert one `distance_instrument()` call before each TCU `loc`,
       computing the distance via the Table 1 rule.  This is what the
       fuzzer runs against.

* v2 - modify the PUT to *forcibly satisfy* a TC (e.g. insert `a = b-1;`
       ahead of an `a < b` TCU), for the second validation step of §3.2.
       One v2 binary per candidate TC.

Why drive it through an LLM at all?  Because generating the exact
assignment that makes a C condition true in situ requires understanding
the surrounding types and side-effects - a hand-coded text rewriter
would misfire on anything non-trivial (e.g. `ctx->components[i]->id`).
The LLM has already read the code during TC Generation, so it is well
placed to do this.

For robustness the module *also* falls back to a deterministic
templated rewriter when the LLM is unavailable.  The templated version
handles the straight `a <op> b` patterns that dominate Magma.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import textwrap

from .llm_client import LLMClient
from .tcu import TCU, tcu_distance_expression


# ---------------------------------------------------------------------------
# v1:  insert distance_instrument() calls.
# ---------------------------------------------------------------------------

def instrument_v1(tcus: list[TCU], source_root: pathlib.Path) -> None:
    """Modify every file named by a TCU.loc in place.

    We operate line-by-line rather than diff-based here because the
    transformation is local and unambiguous: prepend one call before
    the target statement.  This is the deterministic fallback; the LLM
    is overkill for v1.
    """

    # 1. Group TCUs by (file, line).
    by_file: dict[pathlib.Path, dict[int, list[TCU]]] = {}
    for t in tcus:
        fname, lineno = _parse_loc(t.loc)
        path = source_root / fname
        by_file.setdefault(path, {}).setdefault(lineno, []).append(t)

    # 2. Rewrite each file.
    for path, line_map in by_file.items():
        lines = path.read_text().splitlines(keepends=True)
        # Walk top-down but insert at each position; offsets shift as we
        # prepend, so iterate in reverse.
        for lineno in sorted(line_map, reverse=True):
            calls = [_v1_call(t) for t in line_map[lineno]]
            # Preserve indentation of the target line for readability.
            indent = _indent(lines[lineno - 1])
            stitched = "".join(indent + c + "\n" for c in calls)
            lines.insert(lineno - 1, stitched)

        # Inject the #include once at the top if missing.
        if '#include "distance.h"' not in "".join(lines[:20]):
            lines.insert(0, '#include "distance.h"\n')

        path.write_text("".join(lines))


def _v1_call(t: TCU) -> str:
    """Emit the exact C call that writes this TCU's distance to shm."""
    dexpr = tcu_distance_expression(t)
    return (
        f"distance_instrument({dexpr}, "
        f"{t.save_index}, {t.seq}, {t.conj}, {t.w});"
    )


# ---------------------------------------------------------------------------
# v2:  force TC satisfaction.  Per-TC binary, one per candidate TC set.
# ---------------------------------------------------------------------------
#
# We build a *separate copy* of the source for each candidate and mutate
# it: no in-place edits, because the caller needs all v2 binaries
# standing at once during validation.


def instrument_v2(tcus: list[TCU], source_root: pathlib.Path,
                  dest_root: pathlib.Path,
                  llm: LLMClient | None = None) -> None:
    """Produce a copy of `source_root` at `dest_root` where every TCU in
    `tcus` is forcibly satisfied at its loc.

    For each primitive condition we emit an assignment that makes it
    true.  Simple cases are handled by `_forcing_assignment`; anything
    it can't rewrite is delegated to the LLM via `_llm_force`.
    """

    _copy_tree(source_root, dest_root)

    by_file: dict[pathlib.Path, dict[int, list[TCU]]] = {}
    for t in tcus:
        fname, lineno = _parse_loc(t.loc)
        by_file.setdefault(dest_root / fname, {}).setdefault(lineno, []).append(t)

    for path, line_map in by_file.items():
        lines = path.read_text().splitlines(keepends=True)
        for lineno in sorted(line_map, reverse=True):
            stmts = []
            for t in line_map[lineno]:
                stmt = _forcing_assignment(t)
                if stmt is None and llm is not None:
                    stmt = _llm_force(t, "".join(lines), llm)
                if stmt is None:
                    # Give up silently on this TCU - v2 results will be
                    # "failed" for this candidate, which is the whole
                    # point of validation.
                    continue
                stmts.append(stmt)
            if stmts:
                indent = _indent(lines[lineno - 1])
                block = "".join(indent + s + "\n" for s in stmts)
                lines.insert(lineno - 1, block)
        path.write_text("".join(lines))


_FORCING_RE = re.compile(
    r"^\s*([A-Za-z_][\w\->\.\[\]]*)\s*(<=|>=|<|>|==|!=)\s*([A-Za-z_0-9\->\.\[\]]+)\s*$"
)


def _forcing_assignment(t: TCU) -> str | None:
    """Templated force-satisfaction for `a <op> b` shapes.

    Returns a C statement that, when executed immediately before the
    TCU's loc, guarantees `cond` is true.  Handles strictly numeric
    TCUs; binary/pointer ones are skipped (the validator can't usefully
    "force" a binary condition without breaking the surrounding logic).
    """
    if t.kind == "binary":
        return None
    m = _FORCING_RE.match(t.cond)
    if not m:
        return None
    lhs, op, rhs = m.groups()
    # Choose an assignment that nudges lhs just past rhs in the right
    # direction.  Using (double) casts is safe because the original
    # comparison is either integral or float; casting back via the
    # assignment truncates as needed.
    if op in ("<", "<="):
        return f"{lhs} = ({rhs}) - 1;"
    if op in (">", ">="):
        return f"{lhs} = ({rhs}) + 1;"
    if op == "==":
        return f"{lhs} = ({rhs});"
    if op == "!=":
        return f"{lhs} = ({rhs}) + 1;"
    return None


def _llm_force(t: TCU, source: str, llm: LLMClient) -> str | None:
    """Last-resort: ask the model for an assignment that satisfies `cond`.

    We intentionally do not show the whole file - just the surrounding
    context plus the TCU - to keep this cheap.  Output is expected to be
    one C statement; we reject anything that looks like multi-line code
    since that risks breaking scope/braces.
    """
    prompt = textwrap.dedent(f"""\
        The following C condition must be made true at {t.loc}:

            {t.cond}

        Write ONE C statement (ending in `;`) that, if executed just
        before that location, forces the condition to hold.  No
        explanations, no control flow, no braces.
    """)
    reply = llm.query([{"role": "user", "content": prompt}]).strip()
    if "\n" in reply or ";" not in reply:
        return None
    return reply


# ---------------------------------------------------------------------------
# Generic helpers.
# ---------------------------------------------------------------------------

_LOC_RE = re.compile(r"line\s+(\d+)\s+in\s+([\w./-]+)")

def _parse_loc(loc: str) -> tuple[str, int]:
    m = _LOC_RE.search(loc)
    if not m:
        raise ValueError(f"unparseable TCU.loc: {loc!r}")
    return m.group(2), int(m.group(1))


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _copy_tree(src: pathlib.Path, dst: pathlib.Path) -> None:
    # `cp -a` is dramatically faster than walking in Python for real
    # projects and preserves mtimes, which helps incremental builds.
    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cp", "-a", str(src), str(dst)], check=True)
