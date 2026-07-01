"""TCU model, DNF decomposition, and distance-expression helpers.

Implements Definition 1 and Equation 1 of the TrigFuzz paper. A *Triggering
Condition Unit* (TCU) captures one primitive equality/inequality that must
be satisfied *after* the target code is reached for the vulnerability to
trigger.  A full triggering condition (TC) is a list of TCUs whose logical
structure is recovered from their `conj` ids (DNF conjuncts) and `seq`
values (execution order groups).

Release metadata should carry a target-side `distance_expr` directly. That
lets the TCU author or LLM choose safe arithmetic for project-specific C
types, for example avoiding unsigned underflow before a cast. The older
`cond`-only format is still accepted as a compatibility fallback.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Callable, Iterable


# ---------------------------------------------------------------------------
# 1. The 5-tuple itself.
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class TCU:
    """Definition 1 plus an explicit target-side distance expression.

    `distance_expr` is the C expression passed to `distance_instrument()`.
    It should evaluate to 0.0 when the triggering predicate is satisfied
    and positive otherwise. `cond` is retained as a human-readable label and
    for legacy cond-only metadata.
    """

    cond: str                  # e.g. "v < 2", used as a label/fallback
    loc: str                   # e.g. "line 6 in example.c"
    seq: int = 0               # execution-order index (0 = first)
    conj: int = 0              # DNF conjunct id
    w:   float = 1.0           # normalisation weight, set during validation
    distance_expr: str | None = None

    # For bookkeeping across the v1/v2 instrumentation pipeline.  Each TCU
    # emitted into the C source gets a unique save_index that selects its
    # slot in the shm record ring (see distance.h).
    save_index: int | None = None

    # Type hint that lets distance.py fall back to a binary 0/1 distance
    # for conditions that cannot be quantified numerically (pointer eq,
    # type checks).  The LLM is prompted to classify this explicitly.
    kind: str = "numeric"      # "numeric" | "binary"


# ---------------------------------------------------------------------------
# 2. Distance-expression rules (Table 1).
# ---------------------------------------------------------------------------
#
# Each rule takes the symbolic lhs/rhs and returns a *textual* C expression
# computing the distance.  We work on text rather than AST nodes because the
# lhs/rhs may contain arbitrary C sub-expressions that the LLM identified
# (e.g. "ctx->components[i]->id").  This keeps us honest - whatever the LLM
# writes is what gets compiled into the target.

Rule = Callable[[str, str], str]

K = "1.0"

DISTANCE_RULES: dict[str, Rule] = {
    "<":  lambda a, b: (
        f"tf_lt((double)({a}), (double)({b}))"
    ),
    "<=": lambda a, b: (
        f"tf_le((double)({a}), (double)({b}))"
    ),
    ">":  lambda a, b: (
        f"tf_gt((double)({a}), (double)({b}))"
    ),
    ">=": lambda a, b: (
        f"tf_ge((double)({a}), (double)({b}))"
    ),
    "==": lambda a, b: f"tf_eq((double)({a}), (double)({b}))",
    "!=": lambda a, b: f"tf_bool(({a}) != ({b}))",
}


_OPS = sorted(DISTANCE_RULES.keys(), key=len, reverse=True)  # match "<=" before "<"


def distance_expression(cond: str) -> str:
    """Translate a primitive conditional statement into a C distance expr.

    Only primitive conds reach this function - composite expressions are
    split into multiple TCUs upstream (see `to_dnf`).  Unknown operators
    are returned as-is wrapped in a binary form; the LLM is instructed to
    avoid such cases but we keep the fallback for robustness.
    """
    for op in _OPS:
        # Simple left-to-right split; cond strings from the LLM are
        # already primitive and un-parenthesised.
        if op in cond:
            lhs, rhs = cond.split(op, 1)
            return DISTANCE_RULES[op](lhs.strip(), rhs.strip())
    # Unrecognised - fall back to a boolean interpretation so the
    # instrumenter still emits something compilable.
    return f"tf_bool({cond})"


def tcu_distance_expression(tcu: TCU) -> str:
    """Return the target-side distance expression for a TCU.

    Release metadata should set `distance_expr`. If it is absent, we lower
    the legacy primitive `cond` field with the simple Table-1 fallback above.
    """
    if tcu.distance_expr and tcu.distance_expr.strip():
        return tcu.distance_expr.strip()
    if tcu.cond and tcu.cond.strip():
        return distance_expression(tcu.cond)
    raise ValueError(f"TCU has neither distance_expr nor cond: {tcu!r}")


# ---------------------------------------------------------------------------
# 3. DNF decomposition (Equation 1).
# ---------------------------------------------------------------------------

def to_dnf(expr: str) -> list[list[str]]:
    """Split a composite C boolean expression into DNF conjuncts.

    Returns a list of conjuncts, each a list of primitive conditions.  The
    paper guarantees this transformation is always possible for the subset
    of C expressions that appear in vulnerability triggering conditions
    (no side-effects, no short-circuiting relied upon for safety).

    We implement just enough of a Boolean simplifier to cover the patterns
    seen in the Magma benchmark: `&&`/`||` with optional parens, no `!`.
    The LLM already normalises further (it is asked to output tuples
    directly) - this helper is a safety net for when it doesn't.
    """
    # 1. Normalise.
    s = expr.replace("&&", " AND ").replace("||", " OR ")
    # 2. Walk once, splitting on top-level OR then top-level AND.
    def split_top(text: str, sep: str) -> list[str]:
        depth, start, out = 0, 0, []
        i = 0
        while i < len(text):
            c = text[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif depth == 0 and text[i:i + len(sep)] == sep:
                out.append(text[start:i].strip())
                start = i + len(sep)
                i += len(sep)
                continue
            i += 1
        out.append(text[start:].strip())
        return [p for p in out if p]

    or_parts = split_top(s, " OR ")
    return [
        [p.strip("()").strip() for p in split_top(part, " AND ")]
        for part in or_parts
    ]


# ---------------------------------------------------------------------------
# 4. Parse the LLM's tuple output back into TCU objects.
# ---------------------------------------------------------------------------
#
# The release prompt asks the model to emit lines like:
#
#   <tf_lt((double)v, 2.0), line 6 in example.c, 0, 0, 1.0>
#
# We accept the older four-field form too because ledfuzz logs use it.

_INT_RE = re.compile(r"^\d+$")


def parse_tcu_output(text: str) -> list[TCU]:
    """Extract TCUs from an LLM response.  Never raises - skips bad lines."""
    out: list[TCU] = []
    for line in text.splitlines():
        start = line.find("<")
        end = line.rfind(">")
        if start < 0 or end <= start:
            continue
        fields = _split_tuple_fields(line[start + 1:end])
        if len(fields) not in (4, 5):
            continue
        expr, loc, seq, conj = fields[:4]
        if not (_INT_RE.match(seq) and _INT_RE.match(conj)):
            continue
        try:
            weight = float(fields[4]) if len(fields) == 5 else 1.0
        except ValueError:
            continue
        # Heuristic "binary kind" tag: pointer comparisons and type
        # checks as flagged by the paper.  The LLM is also asked to tag
        # these explicitly; this is a belt-and-braces check.
        kind = "binary" if _looks_binary(expr) else "numeric"
        idx = len(out)
        out.append(TCU(cond=expr, distance_expr=expr, loc=loc,
                       seq=int(seq), conj=int(conj), w=weight,
                       kind=kind, save_index=idx))
    return out


def _split_tuple_fields(body: str) -> list[str]:
    """Split tuple fields on top-level commas.

    Conditions often contain nested calls or array indices, and future TCU
    locations may include macro names.  A small scanner is more reliable than
    a regular expression while keeping the accepted format intentionally tight.
    """
    fields: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escape = False
    for i, ch in enumerate(body):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}" and depth:
            depth -= 1
        elif ch == "," and depth == 0:
            fields.append(body[start:i].strip())
            start = i + 1
    fields.append(body[start:].strip())
    return fields


_BINARY_HINTS = ("NULL", "->type", ".type", "strcmp", "memcmp")

def _looks_binary(cond: str) -> bool:
    return any(h in cond for h in _BINARY_HINTS)


# ---------------------------------------------------------------------------
# 5. Convenience: serialise a TCU set to/from JSON for the validation
#    orchestrator (validation.py writes the chosen set to shm so the
#    fuzzer knows which TCs to keep monitoring).
# ---------------------------------------------------------------------------

def to_json(tcus: Iterable[TCU]) -> list[dict]:
    return [dataclasses.asdict(t) for t in tcus]

def from_json(data: Iterable[dict]) -> list[TCU]:
    out: list[TCU] = []
    field_names = {f.name for f in dataclasses.fields(TCU)}
    for raw in data:
        d = dict(raw)
        if "distance_expr" not in d:
            for alias in ("distance_expression", "distance", "expr"):
                if alias in d:
                    d["distance_expr"] = d[alias]
                    break
        if "cond" not in d:
            d["cond"] = d.get("label") or d.get("predicate") or d.get("distance_expr", "")
        item = {k: v for k, v in d.items() if k in field_names}
        out.append(TCU(**item))
    return out


@dataclasses.dataclass(frozen=True)
class ObservedTCU:
    """Runtime TCU record used to mirror the fuzzer aggregation in tests."""

    distance: float
    seq: int
    conj: int
    weight: float = 1.0


def aggregate_triggering_distance(
    records: Iterable[ObservedTCU],
    *,
    seq_num: int | None = None,
    distance_max: float = 1_000_000.0,
) -> float | None:
    """Compute TrigFuzz triggering distance D(x) from runtime TCU records.

    This mirrors the fuzzer's Algorithm-1 style aggregation: sum primitive
    distances in each conjunct, choose the minimum conjunct per sequence
    level, and penalize the first missing sequence with (n - i) * M.  If no
    TCU is reached, D(x) is NULL, represented as None.
    """
    rows = list(records)
    if not rows:
        return None
    if seq_num is None:
        seq_num = max(r.seq for r in rows) + 1

    total = 0.0
    reached_seqs = {r.seq for r in rows}
    for seq in range(seq_num):
        if seq not in reached_seqs:
            total += (seq_num - seq) * distance_max
            break
        conj_distance: dict[int, float] = {}
        for row in rows:
            if row.seq != seq:
                continue
            weight = row.weight if row.weight > 0 else 1.0
            conj_distance[row.conj] = (
                conj_distance.get(row.conj, 0.0) + row.distance / weight
            )
        if conj_distance:
            total += min(conj_distance.values())
    return total
