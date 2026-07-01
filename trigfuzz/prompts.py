"""Prompt template (Figure 2) + Appendix-A few-shot CoT examples.

The template is assembled in three parts:

  (a) Fixed instructions describing the task and the 5-tuple output format.
  (b) The vulnerability report (mandatory fields + any optional ones).
  (c) The relevant source code, appended iteratively by the agent as the
      model requests more function bodies (progressive prompting, §3.1).

Keeping (a) as a constant string makes the TC generation instructions stable
across the 3 sampling rounds used by TC Validation (§3.2).
"""

from __future__ import annotations

import json
import textwrap

# ---------------------------------------------------------------------------
# (a) Fixed task instructions.  Do NOT splice user data in here - it must
#     remain identical across all calls for the prompt cache to hit.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = textwrap.dedent("""\
    You are a vulnerability-triggering-condition analyst.  The user will
    give you a vulnerability report and the relevant source code of a
    C/C++ program.  Your task is to produce a formal set of *Triggering
    Condition Units* (TCUs) describing the constraints that must hold
    AFTER the target code is reached for the vulnerability to actually
    trigger.  Path constraints leading up to the target are out of scope.

    Each TCU is a 5-tuple:

        <distance_expr, loc, seq, conj, weight>

      distance_expr - a C expression that evaluates to 0.0 when the
              triggering predicate is satisfied and a positive distance
              otherwise. Prefer the helper functions from distance.h:
              tf_lt, tf_le, tf_gt, tf_ge, tf_eq, tf_bool, tf_add_num,
              tf_sub_num, tf_mul_num, and tf_min2.
      loc   - "line N in file.c", pointing at the statement where the
              triggering predicate must already hold when execution reaches it
      seq   - integer, execution order group.  0 = must fire first.
      conj  - integer, DNF conjunct id.  TCUs sharing (seq, conj) are
              ANDed; conjuncts with the same seq but different conj are
              ORed.
      weight - positive numeric normalization weight. Use 1.0 unless
              runtime validation provides a more precise scale.

    Rules:

    * Prefer numerically-valued predicates over pointer/type checks,
      because the former yield informative distances.  If the condition
      is genuinely binary (e.g. `p == NULL`), use `tf_bool(p == NULL)`
      but also try to express a precondition that influences the binary
      choice.
    * Do not output a raw condition like `x < y` as `distance_expr`.
      Lower it to a distance expression such as
      `tf_lt((double)x, (double)y)`.
    * Preserve C arithmetic semantics intentionally. If an expression can
      underflow or overflow before conversion, rewrite it with helper
      arithmetic, for example use
      `tf_gt(tf_sub_num((double)nstrips, 1.0), (double)limit)` instead of
      `(double)(nstrips - 1) > (double)limit`.
    * If you need the body of a function you haven't been shown yet,
      reply with EXACTLY one line of the form
          Need the content of function(s): foo, bar
      and stop.  I will reply with the bodies and you will continue.
    * Do not assume definitions of project-specific functions.

    After reasoning step-by-step, output the final tuples on their own
    lines like so:
        <distance_expr, loc, seq, conj, weight>
        <distance_expr, loc, seq, conj, weight>
""")


# ---------------------------------------------------------------------------
# Few-shot examples.  These are the exact examples from Appendix A of the
# paper; they carry a lot of weight (Finding 3) so we don't abbreviate.
# ---------------------------------------------------------------------------

FEW_SHOT_EXAMPLES = [
    {
        "report": {
            "type": "use-of-uninitialized-variable",
            "crash_points": ["line 6 in example.c"],
        },
        "source": textwrap.dedent("""\
            In example.c:
            1 #include <stdio.h>
            2
            3 void foo() {
            4   int a, b, c, d;
            5   int v = sscanf(input.field, "%d.%d.%d.%d", &a, &b, &c, &d);
            6   use(b);
            7 }
        """),
        "answer": textwrap.dedent("""\
            Reasoning: sscanf fills variables left to right; b is only
            initialised if the return value v is at least 2.  Therefore
            the use-of-uninitialised-b bug triggers iff v < 2 by the time
            line 6 executes.  Only one TCU, one conjunct, one seq level.

            <tf_lt((double)v, 2.0), line 6 in example.c, 0, 0, 1.0>
        """),
    },
    {
        "report": {
            "type": "null-pointer-dereference",
            "crash_points": ["line 62 in b.c"],
        },
        "source": "... (see Appendix A.2 - elided for brevity in this module)",
        "answer": textwrap.dedent("""\
            <tf_bool((ctx->comp_flags[i] & COMP_FLAG_SKIP) != 0), line 30 in a.c, 0, 0, 1.0>
            <tf_ge((double)ctx->components[i]->id, (double)ctx->skip_threshold), line 30 in a.c, 0, 0, 1.0>
            <tf_bool(record(i)), line 33 in a.c, 1, 0, 1.0>
            <tf_eq((double)offset, (double)record(i)), line 62 in b.c, 1, 0, 1.0>
            <tf_bool((ctx->comp_flags[offset] & COMP_FLAG_ACTIVE) != 0), line 62 in b.c, 1, 0, 1.0>
            <tf_eq((double)error_code, 0.0), line 62 in b.c, 1, 0, 1.0>
        """),
    },
]


# ---------------------------------------------------------------------------
# (b) + (c):  assemble per-target.
# ---------------------------------------------------------------------------

def build_user_turn(report: dict, source_slices: dict[str, str]) -> str:
    """Compose one user message from the report + whatever source has
    been gathered so far.

    `report` is a dict with at minimum keys `type` and `crash_points`;
    `optional` keys like `call_trace`, `patch` are included verbatim if
    present.  `source_slices` maps filename -> numbered source text.
    """

    lines = ["Vulnerability report:", json.dumps(report, indent=2), ""]
    lines.append("Relevant source code:")
    for fname, body in source_slices.items():
        lines.append(f"\n--- {fname} ---\n{body}")

    # A short worked example section.  Models benefit from seeing the
    # reasoning trace in the same turn rather than as a separate prior
    # exchange (the "in-turn few-shot" pattern).
    lines.append("\nWorked examples:")
    for ex in FEW_SHOT_EXAMPLES:
        lines.append(f"Report: {json.dumps(ex['report'])}")
        lines.append(f"Source:\n{ex['source']}")
        lines.append(f"Answer:\n{ex['answer']}")
        lines.append("")

    lines.append(
        "Now analyse the target above and output the TCUs on their own "
        "lines.  If you need more function bodies, reply with the "
        '"Need the content of function(s): ..." line instead.'
    )
    return "\n".join(lines)
