/*
   TrigFuzz shared constants for AFL++ integration.

   This header contains only the shared-memory ABI used between afl-fuzz and
   instrumented targets. The target-side runtime lives in trigfuzz-distance.h.
 */

#ifndef AFL_TRIGFUZZ_H
#define AFL_TRIGFUZZ_H

#include <stdint.h>
#include <stddef.h>

#define TRIGFUZZ_SHM_ENV_VAR "__AFL_TRIGFUZZ_SHM_ID"
#define TRIGFUZZ_MAP_SIZE_ENV_VAR "__AFL_TRIGFUZZ_MAP_SIZE"

#define TRIGFUZZ_MAGIC 0x54524746U
#define TRIGFUZZ_DEFAULT_INS_NUM 64U
#define TRIGFUZZ_DEFAULT_SEQ_NUM 64U
#define TRIGFUZZ_MAX_CONJS 64U
#define TRIGFUZZ_TCU_STRIDE 18U
#define TRIGFUZZ_HEADER_SIZE 16U

#define TRIGFUZZ_DISTANCE_CAP 1000000000000.0

static inline size_t trigfuzz_reach_base(void) {

  return TRIGFUZZ_HEADER_SIZE;

}

static inline size_t trigfuzz_seq_base(uint32_t ins_num) {

  return trigfuzz_reach_base() + (size_t)ins_num;

}

static inline size_t trigfuzz_tcu_base(uint32_t ins_num, uint32_t seq_num) {

  return trigfuzz_seq_base(ins_num) + (size_t)seq_num;

}

static inline size_t trigfuzz_map_size_for(uint32_t ins_num,
                                           uint32_t seq_num) {

  return trigfuzz_tcu_base(ins_num, seq_num) +
         (size_t)ins_num * TRIGFUZZ_TCU_STRIDE;

}

#endif
