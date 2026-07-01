/*
 * distance.h  -  TrigFuzz v1 runtime triggering-distance monitor.
 *
 * This header is dropped into the program under test (PUT) at the code
 * locations named by TCUs (Triggering Condition Units).  Each call writes
 * one TCU's live distance into a shared-memory region that the fuzzer
 * reads after the target exits.  The design mirrors AFL's trace_bits
 * layout (64 KiB coverage map) and simply appends a TCU section behind it,
 * so AFLGo-compatible fuzzers can still use the map unchanged.
 *
 * Shared-memory layout (offsets relative to trace_bits base):
 *
 *   [0, MAP_SIZE)              - AFL edge-coverage bitmap (unchanged)
 *   [MAP_SIZE,       +16)      - AFLGo target-distance fields / reserved
 *   [TF_REACH_BASE,  +N)       - reach_flag[save_index]      (uint8 x N)
 *   [TF_SEQ_BASE,    +S)       - seq_bitmap[exec_sequence]   (uint8 x S)
 *   [TF_TCU_BASE, +N*18)       - TCU records:
 *         per record (18 bytes):
 *             double  min_distance        (8)
 *             uint8   exec_sequence       (1)
 *             uint8   conjunct            (1)
 *             double  weight              (8)
 *
 * The TCU record format matches Definition 1 in the paper: <cond, loc,
 * seq, conj, w>.  The {cond, loc} pair is baked into the compiled-in call
 * site, while {distance, seq, conj, w} are streamed out at runtime.
 *
 * Defaults: 64 TCUs, 64 execution-order levels, 64 conjunct IDs. Keep these
 * constants in sync with the patched afl-fuzz.c.
 */

#ifndef TRIGFUZZ_DISTANCE_H
#define TRIGFUZZ_DISTANCE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>

#ifndef MAP_SIZE
#define MAP_SIZE        (1U << 16)
#endif
#ifndef TF_MAX_TCUS
#define TF_MAX_TCUS     64
#endif
#ifndef TF_MAX_SEQS
#define TF_MAX_SEQS     64
#endif
#ifndef TF_MAX_CONJS
#define TF_MAX_CONJS    64
#endif

#define TF_REACH_BASE   (MAP_SIZE + 16)
#define TF_SEQ_BASE     (TF_REACH_BASE + TF_MAX_TCUS)
#define TF_TCU_BASE     (TF_SEQ_BASE + TF_MAX_SEQS)
#define TF_TCU_STRIDE   18
#define TF_SHM_SIZE     (TF_TCU_BASE + TF_MAX_TCUS * TF_TCU_STRIDE)

#ifndef TF_DIST_MAX
#define TF_DIST_MAX     1000000000000.0
#endif

static inline double tf_num(double value)
{
    if (value != value) return TF_DIST_MAX;
    if (value > TF_DIST_MAX) return TF_DIST_MAX;
    if (value < -TF_DIST_MAX) return -TF_DIST_MAX;
    return value;
}

static inline double tf_dist(double value)
{
    if (value != value || value < 0.0) return TF_DIST_MAX;
    if (value > TF_DIST_MAX) return TF_DIST_MAX;
    return value;
}

static inline double tf_add_num(double a, double b)
{
    return tf_num(tf_num(a) + tf_num(b));
}

static inline double tf_sub_num(double a, double b)
{
    return tf_num(tf_num(a) - tf_num(b));
}

static inline double tf_mul_num(double a, double b)
{
    return tf_num(tf_num(a) * tf_num(b));
}

static inline double tf_min2(double a, double b)
{
    a = tf_dist(a);
    b = tf_dist(b);
    return a < b ? a : b;
}

static inline double tf_bool(int condition)
{
    return condition ? 0.0 : 1.0;
}

static inline double tf_lt(double a, double b)
{
    if (a != a || b != b) return TF_DIST_MAX;
    a = tf_num(a);
    b = tf_num(b);
    return tf_dist(a < b ? 0.0 : a - b + 1.0);
}

static inline double tf_le(double a, double b)
{
    if (a != a || b != b) return TF_DIST_MAX;
    a = tf_num(a);
    b = tf_num(b);
    return tf_dist(a <= b ? 0.0 : a - b);
}

static inline double tf_gt(double a, double b)
{
    if (a != a || b != b) return TF_DIST_MAX;
    a = tf_num(a);
    b = tf_num(b);
    return tf_dist(a > b ? 0.0 : b - a + 1.0);
}

static inline double tf_ge(double a, double b)
{
    if (a != a || b != b) return TF_DIST_MAX;
    a = tf_num(a);
    b = tf_num(b);
    return tf_dist(a >= b ? 0.0 : b - a);
}

static inline double tf_eq(double a, double b)
{
    if (a != a || b != b) return TF_DIST_MAX;
    a = tf_num(a);
    b = tf_num(b);
    return tf_dist(a >= b ? a - b : b - a);
}

static inline double tf_ptr_lt(uintptr_t a, uintptr_t b)
{
    return tf_dist(a < b ? 0.0 : (double)(a - b) + 1.0);
}

static inline double tf_ptr_ge(uintptr_t a, uintptr_t b)
{
    return tf_dist(a >= b ? 0.0 : (double)(b - a));
}

/*
 * distance_instrument()  -  one call per TCU at its `loc`.
 *
 *   distance       numeric distance derived from `cond` using Table 1.
 *                  0 means the condition is met.
 *   save_index     unique per-TCU slot in the shm ring (author-picked).
 *   exec_sequence  TCU.seq - execution order index.
 *   conjunct       TCU.conj - DNF conjunct this TCU belongs to.
 *   weight         TCU.w    - normalisation weight (set by validation).
 *
 * The function is static-inline so a PUT can include this header
 * everywhere without linker conflicts.  We attach only to the shm
 * segment; AFL's forkserver keeps it mapped across executions.
 */
static inline void distance_instrument(double distance,
                                       uint16_t save_index,
                                       uint8_t exec_sequence,
                                       uint8_t conjunct,
                                       double  weight)
{
    /* Resolve the AFL trace_bits base once per process.  When the target
     * is run standalone (no fuzzer), __AFL_SHM_ID is unset and we no-op,
     * which makes instrumented binaries still executable for debugging. */
    static uint8_t *trace_bits = NULL;
    static int      resolved   = 0;
    if (!resolved) {
        const char *env = getenv("__AFL_SHM_ID");
        if (env) {
            int shm_id = atoi(env);
            trace_bits = (uint8_t *)shmat(shm_id, NULL, 0);
            if (trace_bits == (void *)-1) trace_bits = NULL;
        }
        resolved = 1;
    }
    if (!trace_bits) return;
    if (save_index >= TF_MAX_TCUS ||
        exec_sequence >= TF_MAX_SEQS ||
        conjunct >= TF_MAX_CONJS ||
        weight != weight ||
        weight <= 0.0) {
        return;
    }
    distance = tf_dist(distance);
    weight = tf_dist(weight);

    /* Execution-order bitmap.  A given seq level is "reached in order"
     * only if every lower level has already fired during this execution.
     * This is what lets us tell which of {free, use} came first in a
     * use-after-free - CAFL cannot. */
    uint8_t *seq = trace_bits + TF_SEQ_BASE + exec_sequence;
    if (exec_sequence == 0 || seq[-1] == 1) *seq = 1;

    /* TCU record.  On repeated visits (e.g. buffer access inside a loop)
     * we keep the *minimum* observed distance - the access closest to
     * the boundary dominates, as argued in §3.3. */
    uint8_t *rec  = trace_bits + TF_TCU_BASE + save_index * TF_TCU_STRIDE;
    uint8_t *reach = trace_bits + TF_REACH_BASE + save_index;

    if (!*reach) {
        memcpy(rec, &distance, sizeof(distance));
    } else {
        double old_distance;
        memcpy(&old_distance, rec, sizeof(old_distance));
        old_distance = tf_dist(old_distance);
        if (distance < old_distance) memcpy(rec, &distance, sizeof(distance));
    }
    *reach = 1;

    rec[8]  = exec_sequence;
    rec[9]  = conjunct;
    memcpy(rec + 10, &weight, sizeof(weight));
}

#endif /* TRIGFUZZ_DISTANCE_H */
