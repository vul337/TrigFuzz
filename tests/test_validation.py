from __future__ import annotations

import subprocess
from pathlib import Path

from trigfuzz.validation import validate_original_patched


ROOT = Path(__file__).resolve().parents[1]


def _compile(tmp_path, name: str, body: str):
    src = tmp_path / f"{name}.c"
    exe = tmp_path / name
    src.write_text(body)
    subprocess.run(
        ["gcc", "-I", str(ROOT), str(src), "-lm", "-o", str(exe)],
        check=True,
    )
    return exe


def test_original_patched_tcu_validation(tmp_path):
    common_prefix = """
    #include "distance.h"
    #include <math.h>
    #include <stdio.h>
    #include <stdlib.h>
    int main(void) {
      unsigned char b = 0;
      if (fread(&b, 1, 1, stdin) != 1) return 0;
      unsigned int v = b;
    """
    original = _compile(
        tmp_path,
        "original",
        common_prefix
        + """
      distance_instrument(fabs((double)v - 89.0), 0, 0, 0, 1.0);
      if (v == 89) abort();
      return 0;
    }
    """,
    )
    patched = _compile(
        tmp_path,
        "patched",
        common_prefix
        + """
      if (v == 89) v = 0;
      distance_instrument(fabs((double)v - 89.0), 0, 0, 0, 1.0);
      if (v == 89) abort();
      return 0;
    }
    """,
    )

    result = validate_original_patched(
        original,
        patched,
        b"Y",
        ins_num=1,
        seq_num=1,
    )

    assert result.valid
    assert result.patch_blocks_crash
    assert result.original.triggered
    assert result.original.crashed
    assert result.original.distance == 0.0
    assert not result.patched.triggered
    assert not result.patched.crashed
