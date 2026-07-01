# AFLGo `afl-fuzz.c` TrigFuzz Patch Notes

The release copy is:

```text
engines/aflgo-trigfuzz/afl-2.57b/afl-fuzz.c
```

The patch starts from ledfuzz's TrigFuzz changes, then adds the updates below.

## 1. Shared-memory ABI made explicit

`distance.h` and `afl-fuzz.c` now share the same logical layout:

```c
#define TF_MAX_TCUS   64
#define TF_MAX_SEQS   64
#define TF_MAX_CONJS  64
#define TF_REACH_BASE (MAP_SIZE + 16)
#define TF_SEQ_BASE   (TF_REACH_BASE + TF_MAX_TCUS)
#define TF_TCU_BASE   (TF_SEQ_BASE + TF_MAX_SEQS)
#define TF_TCU_STRIDE 18
```

This replaces the original fixed 8-slot layout and adds `-a/-s` bounds
checks so oversized TCU sets fail clearly.

## 2. Triggering-distance scheduling is the release default

The release default keeps:

- triggering-distance aggregation;
- `+trig` queue tagging;
- triggering-distance-aware seed scheduling.

The triggering byte-aware mutation stage is available as an explicit config:

```sh
export AFL_TRIG_ENABLE_BYTE_AWARE_MUTATION=1
```

When enabled, the byte-aware stage can use the paper's source-diff strategy:
recover the source seed from the AFL filename's `src:NNNNNN` field, diff that
source seed against the new `+trig` seed, and probe bytes that changed while
reducing triggering distance.

Strategy selector:

```sh
export AFL_TRIG_MUTATION_MODE=hybrid
```

Accepted values are `diff`, `scan`, and `hybrid`. `AFL_TRIG_ALL_BYTES=1`
remains a backward-compatible alias for scan mode.

## 3. Optional byte-aware length-change probes restored

ledfuzz had the *insert* and *delete* probes commented out because the
in-place `memmove` + `ck_realloc` dance corrupted `out_buf` between
loop iterations. We rewrote them to use a **scratch buffer per probe**:

```c
if (len > 1) {
  u8* scratch = ck_alloc_nozero(len - 1);
  memcpy(scratch, out_buf, t_byte);
  memcpy(scratch + t_byte, out_buf + t_byte + 1, len - t_byte - 1);
  if (common_fuzz_stuff(argv, scratch, len - 1)) { ck_free(scratch); goto abandon_entry; }
  ck_free(scratch);
  if (triggering_distance != queue_cur->trig_distance && triggering_distance > -DBL_MAX)
    is_t_byte += 2;
}
```

Symmetric block for the *insert* probe sets `is_t_byte += 4`. The
outer `out_buf` and `len` are left intact so the next offset in the
loop sees a clean parent.

## 4. Optional systematic length-change stages restored

Whenever a probe lifts `is_t_byte & 2` (delete worked) or `& 4`
(insert worked), the original code intended to follow up with
progressively larger length-changing mutations. Both branches were
commented out for the same reason as above. Replacement:

```c
if (is_t_byte & 2) {
  u32 sizes[] = { 1, 2, 4, 8, 16, 32 };
  for (size in sizes) {
    if (t_byte + size >= len) break;
    /* scratch-buffered delete of `size` bytes at offset t_byte */
  }
}
if (is_t_byte & 4) {
  u32 sizes[] = { 1, 2, 4, 8, 16, 32 };
  for (size in sizes) {
    if (len + size >= MAX_FILE) break;
    /* scratch-buffered insert of `size` bytes (random or cloned) */
  }
}
```

The geometric progression matches the paper's §3.3 description and
keeps the worst-case cost per critical offset bounded at ~12 extra
executions (6 deletes + 6 inserts).

## What we did NOT change

- The shm layout, Algorithm 1 implementation in `has_new_bits()`, the
  `+cov`/`+trig` queue tagging, and the two-term power schedule are
  reused as-is.
- The strict-inequality semantics (distance > 0 must hold for "not
  triggered") match Table 1 of the paper.
- AFLGo's control-flow distance code path is untouched; if present it
  composes with TrigFuzz, if absent the corresponding term in the
  power schedule drops out.

## How to reproduce the patch from scratch

```bash
git clone https://github.com/aflgo/aflgo.git
cp ledfuzz/afl-fuzz.c aflgo/afl-2.57b/afl-fuzz.c
# apply the TrigFuzz patch from this repository
cd aflgo/afl-2.57b && make
```
