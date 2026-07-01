"""TC validation helpers (§3.2).

There are two validation paths here:

* `validate_original_patched()` implements the paper-style check for a
  known crashing input: run instrumented original and patched binaries under
  the TrigFuzz shared-memory monitor and require the TCU set to trigger in
  the original but not in the patched version.
* `Validator` is the fuzzing-time manifestation helper used by the driver:
  replay newly-discovered `+trig` inputs on force-satisfied v2 binaries and
  rank candidate TC sets by observed crash manifestation.
"""

from __future__ import annotations

import ctypes
import dataclasses
import os
import random
import resource
import struct
import subprocess
from pathlib import Path

from .tcu import ObservedTCU, TCU, aggregate_triggering_distance


MAP_SIZE = 1 << 16
TF_MAX_TCUS = 64
TF_MAX_SEQS = 64
TF_REACH_BASE = MAP_SIZE + 16
TF_SEQ_BASE = TF_REACH_BASE + TF_MAX_TCUS
TF_TCU_BASE = TF_SEQ_BASE + TF_MAX_SEQS
TF_TCU_STRIDE = 18
TF_SHM_SIZE = TF_TCU_BASE + TF_MAX_TCUS * TF_TCU_STRIDE

IPC_PRIVATE = 0
IPC_CREAT = 0o1000
IPC_EXCL = 0o2000
IPC_RMID = 0

_libc = ctypes.CDLL(None, use_errno=True)
_libc.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
_libc.shmget.restype = ctypes.c_int
_libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
_libc.shmat.restype = ctypes.c_void_p
_libc.shmdt.argtypes = [ctypes.c_void_p]
_libc.shmdt.restype = ctypes.c_int
_libc.shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
_libc.shmctl.restype = ctypes.c_int


@dataclasses.dataclass
class Candidate:
    tcus: list[TCU]
    v1_indices: list[int]
    v2_binary: Path | None
    v2_ok: bool | None = None    # None = not yet probed.
    v2_attempts: int = 0

    @property
    def score(self) -> int:
        """Crude rank used for tie-breaking in `Validator.choose()`.
        +1 for v2 manifestation observed, +0 otherwise; v2-not-built
        candidates score 0 and lose ties."""
        return int(bool(self.v2_ok))


class Validator:
    def __init__(self, candidates: list[Candidate]):
        self.candidates = candidates

    def attempt_v2(self, cand: Candidate, reachable_input: bytes) -> None:
        """Run one input through the v2 binary, look for a crash signal.

        We accept multiple attempts per candidate (each call increments
        `v2_attempts`) - re-probing with newly-discovered reachable
        inputs only sharpens the verdict.  Once a v2 manifests, we
        latch v2_ok=True and stop bothering it.
        """
        if cand.v2_binary is None or cand.v2_ok:
            return
        cand.v2_attempts += 1
        try:
            r = subprocess.run(
                [str(cand.v2_binary)], input=reachable_input,
                capture_output=True, timeout=5,
            )
        except subprocess.TimeoutExpired:
            return
        if r.returncode != 0 or b"AddressSanitizer" in (r.stderr or b""):
            cand.v2_ok = True

    def choose(self) -> Candidate:
        best = max(self.candidates, key=lambda c: c.score)
        winners = [c for c in self.candidates if c.score == best.score]
        return random.choice(winners)


@dataclasses.dataclass
class MonitorRun:
    """One execution under the TrigFuzz runtime monitor."""

    returncode: int
    stderr: bytes
    records: list[ObservedTCU]
    distance: float | None

    @property
    def crashed(self) -> bool:
        return self.returncode != 0 or b"AddressSanitizer" in self.stderr

    @property
    def triggered(self) -> bool:
        return self.distance == 0.0


@dataclasses.dataclass
class PatchValidationResult:
    """Paper-style check: original triggers; patched does not."""

    original: MonitorRun
    patched: MonitorRun

    @property
    def valid(self) -> bool:
        return self.original.triggered and not self.patched.triggered

    @property
    def patch_blocks_crash(self) -> bool:
        return self.original.crashed and not self.patched.crashed


def run_with_monitor(
    binary: Path,
    input_bytes: bytes,
    *,
    ins_num: int,
    seq_num: int,
    timeout: float = 5.0,
) -> MonitorRun:
    """Run an instrumented binary once and collect reached TCU records."""

    if ins_num < 0 or ins_num > TF_MAX_TCUS:
        raise ValueError(f"ins_num must be in [0, {TF_MAX_TCUS}]")
    if seq_num < 0 or seq_num > TF_MAX_SEQS:
        raise ValueError(f"seq_num must be in [0, {TF_MAX_SEQS}]")

    shm_id = _libc.shmget(
        IPC_PRIVATE, TF_SHM_SIZE, IPC_CREAT | IPC_EXCL | 0o600
    )
    if shm_id < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))

    addr = _libc.shmat(shm_id, None, 0)
    if addr in (0, ctypes.c_void_p(-1).value):
        err = ctypes.get_errno()
        _libc.shmctl(shm_id, IPC_RMID, None)
        raise OSError(err, os.strerror(err))

    try:
        env = os.environ.copy()
        env["__AFL_SHM_ID"] = str(shm_id)

        def prepare_child() -> None:
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except (AttributeError, ValueError, OSError):
                pass

        proc = subprocess.run(
            [str(binary)],
            input=input_bytes,
            capture_output=True,
            timeout=timeout,
            env=env,
            preexec_fn=prepare_child,
        )
        raw = ctypes.string_at(addr, TF_SHM_SIZE)
    finally:
        _libc.shmdt(addr)
        _libc.shmctl(shm_id, IPC_RMID, None)

    records = _read_records(raw, ins_num)
    return MonitorRun(
        returncode=proc.returncode,
        stderr=proc.stderr or b"",
        records=records,
        distance=aggregate_triggering_distance(records, seq_num=seq_num),
    )


def validate_original_patched(
    original_binary: Path,
    patched_binary: Path,
    crashing_input: bytes,
    *,
    ins_num: int,
    seq_num: int,
    timeout: float = 5.0,
) -> PatchValidationResult:
    """Validate TCUs with the paper's original-vs-patched check."""

    original = run_with_monitor(
        original_binary,
        crashing_input,
        ins_num=ins_num,
        seq_num=seq_num,
        timeout=timeout,
    )
    patched = run_with_monitor(
        patched_binary,
        crashing_input,
        ins_num=ins_num,
        seq_num=seq_num,
        timeout=timeout,
    )
    return PatchValidationResult(original=original, patched=patched)


def _read_records(raw: bytes, ins_num: int) -> list[ObservedTCU]:
    records: list[ObservedTCU] = []
    for i in range(ins_num):
        if raw[TF_REACH_BASE + i] == 0:
            continue
        off = TF_TCU_BASE + i * TF_TCU_STRIDE
        distance = struct.unpack_from("d", raw, off)[0]
        seq = raw[off + 8]
        conj = raw[off + 9]
        weight = struct.unpack_from("d", raw, off + 10)[0]
        records.append(
            ObservedTCU(distance=distance, seq=seq, conj=conj, weight=weight)
        )
    return records
