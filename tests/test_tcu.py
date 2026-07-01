from __future__ import annotations

import math
import subprocess
from pathlib import Path

from trigfuzz.tcu import (
    ObservedTCU,
    aggregate_triggering_distance,
    distance_expression,
    from_json,
    parse_tcu_output,
    tcu_distance_expression,
)


ROOT = Path(__file__).resolve().parents[1]


def _eval_c_expr(tmp_path, expr: str, a: float, b: float) -> float:
    src = tmp_path / "eval.c"
    exe = tmp_path / "eval"
    src.write_text(
        "#include \"distance.h\"\n"
        "#include <math.h>\n"
        "#include <stdio.h>\n"
        "int main(void) {\n"
        f"  double a = {a!r};\n"
        f"  double b = {b!r};\n"
        f"  printf(\"%.9f\\n\", (double)({expr}));\n"
        "  return 0;\n"
        "}\n"
    )
    subprocess.run(["gcc", "-I", str(ROOT), str(src), "-lm", "-o", str(exe)], check=True)
    return float(subprocess.check_output([str(exe)], text=True).strip())


def test_table_1_distance_expressions(tmp_path):
    cases = [
        ("a < b", 1, 2, 0),
        ("a < b", 2, 2, 1),
        ("a <= b", 2, 2, 0),
        ("a <= b", 4, 2, 2),
        ("a > b", 3, 2, 0),
        ("a > b", 2, 2, 1),
        ("a >= b", 2, 2, 0),
        ("a >= b", 1, 4, 3),
        ("a == b", 7, 3, 4),
        ("a != b", 7, 3, 0),
        ("a != b", 3, 3, 1),
    ]
    for cond, a, b, expected in cases:
        got = _eval_c_expr(tmp_path, distance_expression(cond), a, b)
        assert math.isclose(got, expected, abs_tol=1e-9), cond


def test_parse_weighted_and_legacy_tcus():
    text = """
    reasoning...
    <tf_gt((double)num, (double)max_palette_length), line 992 in pngrutil.c, 0, 0, 32.0>
    <tf_lt((double)v, 2.0), line 6 in example.c, 1, 2>
    """
    tcus = parse_tcu_output(text)
    assert len(tcus) == 2
    assert tcus[0].cond == "tf_gt((double)num, (double)max_palette_length)"
    assert tcus[0].distance_expr == "tf_gt((double)num, (double)max_palette_length)"
    assert tcus[0].w == 32.0
    assert tcus[1].cond == "tf_lt((double)v, 2.0)"
    assert tcus[1].distance_expr == "tf_lt((double)v, 2.0)"
    assert tcus[1].w == 1.0
    assert [t.save_index for t in tcus] == [0, 1]


def test_json_prefers_direct_distance_expr():
    tcus = from_json([
        {
            "cond": "nstrips - 1 > limit",
            "distance_expr": "tf_gt(tf_sub_num((double)nstrips, 1.0), (double)limit)",
            "loc": "line 10 in tif.c",
            "seq": 0,
            "conj": 0,
            "w": 1.0,
        }
    ])
    assert tcu_distance_expression(tcus[0]) == (
        "tf_gt(tf_sub_num((double)nstrips, 1.0), (double)limit)"
    )


def test_json_legacy_cond_fallback():
    tcus = from_json([
        {"cond": "v < 2", "loc": "line 6 in example.c", "seq": 0, "conj": 0}
    ])
    assert tcu_distance_expression(tcus[0]) == "tf_lt((double)(v), (double)(2))"


def test_aggregate_triggering_distance_dnf_and_sequence_penalty():
    records = [
        ObservedTCU(distance=8, seq=0, conj=0, weight=2),
        ObservedTCU(distance=3, seq=0, conj=0, weight=1),
        ObservedTCU(distance=9, seq=0, conj=1, weight=1),
        ObservedTCU(distance=5, seq=2, conj=0, weight=1),
    ]
    # seq 0 chooses min(conj0=7, conj1=9), then seq 1 is missing.
    assert aggregate_triggering_distance(records, seq_num=3, distance_max=100) == 207
    assert aggregate_triggering_distance([]) is None
