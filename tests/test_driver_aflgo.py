from __future__ import annotations

from pathlib import Path

import pytest

from trigfuzz import driver
from trigfuzz.instrument import instrument_v1
from trigfuzz.tcu import TCU


def test_aflgo_targets_prefers_overrides_and_derives_crash_points():
    report = {
        "crash_points": [
            "line 5973 in libtiff/tif_dirread.c",
            "not a source location",
            "line 5973 in libtiff/tif_dirread.c",
        ]
    }
    assert driver._aflgo_targets(report) == ["libtiff/tif_dirread.c:5973"]
    assert driver._aflgo_targets(
        report, ["parser.c:10", "parser.c:10", "decode.c:22"]
    ) == ["parser.c:10", "decode.c:22"]


def test_aflgo_targets_accepts_report_override_and_rejects_bad_values():
    assert driver._aflgo_targets({"aflgo_targets": "parser.c:12"}) == [
        "parser.c:12"
    ]
    with pytest.raises(ValueError, match="expected FILE:LINE"):
        driver._aflgo_targets({}, ["line 12 in parser.c"])


def test_build_v1_with_aflgo_distance_runs_two_compiler_phases(
    tmp_path, monkeypatch
):
    target_dir = tmp_path / "target"
    src_dir = target_dir / "source-v1"
    src_dir.mkdir(parents=True)
    (src_dir / "main.c").write_text("int main(void) { return 0; }\n")
    out_bin = target_dir / "work" / "target-v1"
    compile_calls = []

    def fake_compile(src, out, **kwargs):
        compile_calls.append((src, out, kwargs))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"binary")
        flags = kwargs.get("extra_flags") or []
        outdir_flag = next(
            (flag for flag in flags if flag.startswith("-outdir=")), None
        )
        if outdir_flag:
            metadata_dir = Path(outdir_flag.split("=", 1)[1])
            metadata_dir.mkdir(parents=True, exist_ok=True)
            for name in ("BBnames.txt", "BBcalls.txt", "Fnames.txt", "Ftargets.txt"):
                (metadata_dir / name).write_text("main.c:1\n")
            (metadata_dir / "BBtargets.resolved.txt").write_text("main.c:1\n")

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["bash", str(driver.AFLGO_DISTANCE_SCRIPT)]
        temp_dir = Path(cmd[3])
        (temp_dir / "distance.cfg.txt").write_text("main.c:1,0\n")

    monkeypatch.setattr(driver, "_compile", fake_compile)
    monkeypatch.setattr(driver.subprocess, "run", fake_run)

    distance_file = driver._build_v1_with_aflgo_distance(
        target_dir=target_dir,
        src_dir=src_dir,
        out_bin=out_bin,
        work_dir=target_dir / "work",
        report={"crash_points": ["line 1 in main.c"]},
        target_overrides=None,
        use_script=False,
        sanitize=False,
    )

    assert distance_file.read_text() == "main.c:1,0\n"
    assert len(compile_calls) == 2
    preprocess = compile_calls[0][2]
    final = compile_calls[1][2]
    assert preprocess["compiler"] == driver.AFLGO_CLANG
    assert any(flag.startswith("-targets=") for flag in preprocess["extra_flags"])
    assert "-flto" in preprocess["extra_flags"]
    assert final["compiler"] == driver.AFLGO_CLANG
    assert final["extra_flags"] == [f"-distance={distance_file}"]
    assert out_bin.read_bytes() == b"binary"


def test_aflgo_instrumentation_preserves_original_source_lines(tmp_path):
    source = tmp_path / "main.c"
    source.write_text(
        "int main(void) {\n"
        "  int v = 3;\n"
        "  return v;\n"
        "}\n"
    )
    tcu = TCU(
        cond="v < 2",
        distance_expr="tf_lt((double)v, 2.0)",
        loc="line 3 in main.c",
        seq=0,
        conj=0,
        w=1.0,
        save_index=0,
        kind="numeric",
    )

    instrument_v1([tcu], tmp_path, preserve_locations=True)

    rewritten = source.read_text()
    assert '#line 1 "main.c"' in rewritten
    assert '#line 3 "main.c"\n  return v;' in rewritten
