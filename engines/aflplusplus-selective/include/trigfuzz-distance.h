/*
   Target-side TrigFuzz distance runtime for AFL++.

   Instrumented targets include this header and call distance_instrument() at
   LLM-selected triggering-condition units. The fuzzer provides a dedicated
   shared-memory region through __AFL_TRIGFUZZ_SHM_ID.
 */

#ifndef AFL_TRIGFUZZ_DISTANCE_H
#define AFL_TRIGFUZZ_DISTANCE_H

#include "trigfuzz.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>

static inline double tf_num(double value) {

  if (value != value) return TRIGFUZZ_DISTANCE_CAP;
  if (value > TRIGFUZZ_DISTANCE_CAP) return TRIGFUZZ_DISTANCE_CAP;
  if (value < -TRIGFUZZ_DISTANCE_CAP) return -TRIGFUZZ_DISTANCE_CAP;
  return value;

}

static inline double tf_dist(double value) {

  if (value != value || value < 0.0) return TRIGFUZZ_DISTANCE_CAP;
  if (value > TRIGFUZZ_DISTANCE_CAP) return TRIGFUZZ_DISTANCE_CAP;
  return value;

}

static inline double tf_add_num(double a, double b) {

  return tf_num(tf_num(a) + tf_num(b));

}

static inline double tf_sub_num(double a, double b) {

  return tf_num(tf_num(a) - tf_num(b));

}

static inline double tf_mul_num(double a, double b) {

  return tf_num(tf_num(a) * tf_num(b));

}

static inline double tf_min2(double a, double b) {

  a = tf_dist(a);
  b = tf_dist(b);
  return a < b ? a : b;

}

static inline double tf_bool(int condition) {

  return condition ? 0.0 : 1.0;

}

static inline double tf_lt(double a, double b) {

  if (a != a || b != b) return TRIGFUZZ_DISTANCE_CAP;
  a = tf_num(a);
  b = tf_num(b);
  return tf_dist(a < b ? 0.0 : a - b + 1.0);

}

static inline double tf_le(double a, double b) {

  if (a != a || b != b) return TRIGFUZZ_DISTANCE_CAP;
  a = tf_num(a);
  b = tf_num(b);
  return tf_dist(a <= b ? 0.0 : a - b);

}

static inline double tf_gt(double a, double b) {

  if (a != a || b != b) return TRIGFUZZ_DISTANCE_CAP;
  a = tf_num(a);
  b = tf_num(b);
  return tf_dist(a > b ? 0.0 : b - a + 1.0);

}

static inline double tf_ge(double a, double b) {

  if (a != a || b != b) return TRIGFUZZ_DISTANCE_CAP;
  a = tf_num(a);
  b = tf_num(b);
  return tf_dist(a >= b ? 0.0 : b - a);

}

static inline double tf_eq(double a, double b) {

  if (a != a || b != b) return TRIGFUZZ_DISTANCE_CAP;
  a = tf_num(a);
  b = tf_num(b);
  return tf_dist(a >= b ? a - b : b - a);

}

static inline double tf_ptr_lt(uintptr_t a, uintptr_t b) {

  return tf_dist(a < b ? 0.0 : (double)(a - b) + 1.0);

}

static inline double tf_ptr_ge(uintptr_t a, uintptr_t b) {

  return tf_dist(a >= b ? 0.0 : (double)(b - a));

}

static inline uint8_t *trigfuzz_map_shm(size_t *map_size_out) {

  static uint8_t *map = NULL;
  static size_t   map_size = 0;
  static int      resolved = 0;

  if (resolved) {

    if (map_size_out) *map_size_out = map_size;
    return map;

  }

  resolved = 1;

  const char *id_env = getenv(TRIGFUZZ_SHM_ENV_VAR);
  const char *sz_env = getenv(TRIGFUZZ_MAP_SIZE_ENV_VAR);
  if (!id_env || !sz_env) return NULL;

  char *endptr = NULL;
  errno = 0;
  unsigned long parsed_size = strtoul(sz_env, &endptr, 10);
  if (errno || !parsed_size || !endptr || *endptr) return NULL;

  map_size = (size_t)parsed_size;

  if (id_env[0] == '/') {

    int fd = shm_open(id_env, O_RDWR, 0600);
    if (fd < 0) return NULL;
    void *mapped = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                        0);
    close(fd);
    if (mapped == MAP_FAILED) {

      map = NULL;
      map_size = 0;
      return NULL;

    }

    map = (uint8_t *)mapped;

  } else {

    int   shm_id = atoi(id_env);
    void *mapped = shmat(shm_id, NULL, 0);
    if (mapped == (void *)-1) {

      map = NULL;
      map_size = 0;
      return NULL;

    }

    map = (uint8_t *)mapped;

  }

  if (map_size_out) *map_size_out = map_size;
  return map;

}

static inline void distance_instrument(double distance, uint16_t save_index,
                                       uint8_t exec_sequence,
                                       uint8_t conjunct, double weight) {

  size_t   map_size = 0;
  uint8_t *map = trigfuzz_map_shm(&map_size);
  if (!map || map_size < TRIGFUZZ_HEADER_SIZE) return;

  uint32_t magic = 0, ins_num = 0, seq_num = 0;
  memcpy(&magic, map, sizeof(magic));
  memcpy(&ins_num, map + 4, sizeof(ins_num));
  memcpy(&seq_num, map + 8, sizeof(seq_num));

  if (magic != TRIGFUZZ_MAGIC || !ins_num || !seq_num) return;
  if (save_index >= ins_num || exec_sequence >= seq_num ||
      conjunct >= TRIGFUZZ_MAX_CONJS || weight != weight || weight <= 0.0) {

    return;

  }

  size_t expected = trigfuzz_map_size_for(ins_num, seq_num);
  if (expected > map_size) return;

  distance = tf_dist(distance);
  weight = tf_dist(weight);

  size_t reach_base = trigfuzz_reach_base();
  size_t seq_base = trigfuzz_seq_base(ins_num);
  size_t tcu_base = trigfuzz_tcu_base(ins_num, seq_num);

  uint8_t *seq = map + seq_base + exec_sequence;
  if (exec_sequence == 0 || seq[-1] == 1) *seq = 1;

  uint8_t *reach = map + reach_base + save_index;
  uint8_t *rec = map + tcu_base + (size_t)save_index * TRIGFUZZ_TCU_STRIDE;

  if (!*reach) {

    memcpy(rec, &distance, sizeof(distance));

  } else {

    double old_distance;
    memcpy(&old_distance, rec, sizeof(old_distance));
    old_distance = tf_dist(old_distance);
    if (distance < old_distance) memcpy(rec, &distance, sizeof(distance));

  }

  *reach = 1;
  rec[8] = exec_sequence;
  rec[9] = conjunct;
  memcpy(rec + 10, &weight, sizeof(weight));

}

#endif
