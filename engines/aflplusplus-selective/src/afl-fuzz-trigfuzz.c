/*
   TrigFuzz feedback integration for AFL++.
 */

#include "afl-fuzz.h"
#include "trigfuzz.h"

#include <float.h>
#include <math.h>

#define TRIGFUZZ_EPSILON 1e-9

static double trigfuzz_sanitize_distance(double distance) {

  if (distance != distance || distance < 0.0) return TRIGFUZZ_DISTANCE_CAP;
  if (distance > TRIGFUZZ_DISTANCE_CAP) return TRIGFUZZ_DISTANCE_CAP;
  return distance;

}

static double trigfuzz_add_distance(double a, double b) {

  a = trigfuzz_sanitize_distance(a);
  b = trigfuzz_sanitize_distance(b);
  if (a >= TRIGFUZZ_DISTANCE_CAP || b >= TRIGFUZZ_DISTANCE_CAP)
    return TRIGFUZZ_DISTANCE_CAP;
  if (a > TRIGFUZZ_DISTANCE_CAP - b) return TRIGFUZZ_DISTANCE_CAP;
  return a + b;

}

static u32 trigfuzz_parse_u32_env(char *name, u32 default_value) {

  char *env = getenv(name);
  if (!env || !*env) return default_value;

  char *endptr = NULL;
  errno = 0;
  unsigned long value = strtoul(env, &endptr, 10);
  if (errno || !endptr || *endptr || value == 0 || value > 1000000UL) {

    FATAL("Invalid %s value: %s", name, env);

  }

  return (u32)value;

}

static void trigfuzz_write_header(afl_state_t *afl) {

  if (!afl->trigfuzz_map) return;

  u32 magic = TRIGFUZZ_MAGIC;
  memcpy(afl->trigfuzz_map, &magic, sizeof(magic));
  memcpy(afl->trigfuzz_map + 4, &afl->trigfuzz_ins_num,
         sizeof(afl->trigfuzz_ins_num));
  memcpy(afl->trigfuzz_map + 8, &afl->trigfuzz_seq_num,
         sizeof(afl->trigfuzz_seq_num));

}

void trigfuzz_init(afl_state_t *afl) {

  char *enabled = getenv("AFL_TRIGFUZZ_ENABLE");
  if (!enabled || !*enabled || !strcmp(enabled, "0")) return;

  afl->trigfuzz_enabled = 1;
  afl->trigfuzz_debug = !!getenv("AFL_TRIGFUZZ_DEBUG");
  afl->trigfuzz_ins_num =
      trigfuzz_parse_u32_env("AFL_TRIGFUZZ_INS_NUM",
                             TRIGFUZZ_DEFAULT_INS_NUM);
  afl->trigfuzz_seq_num =
      trigfuzz_parse_u32_env("AFL_TRIGFUZZ_SEQ_NUM",
                             TRIGFUZZ_DEFAULT_SEQ_NUM);

  afl->trigfuzz_map_size =
      trigfuzz_map_size_for(afl->trigfuzz_ins_num, afl->trigfuzz_seq_num);

  if (afl->trigfuzz_map_size > (1U << 28)) {

    FATAL("TrigFuzz shm is too large: %zu bytes", afl->trigfuzz_map_size);

  }

  afl->trigfuzz_map =
      afl_shm_init(&afl->trigfuzz_shm, afl->trigfuzz_map_size, 1, afl->perm,
                   afl->chown_needed ? afl->fsrv.gid : -1);
  if (!afl->trigfuzz_map) { FATAL("Could not initialize TrigFuzz shm"); }

#ifdef USEMMAP
  setenv(TRIGFUZZ_SHM_ENV_VAR, afl->trigfuzz_shm.g_shm_file_path, 1);
#else
  u8 *shm_str = alloc_printf("%d", afl->trigfuzz_shm.shm_id);
  setenv(TRIGFUZZ_SHM_ENV_VAR, shm_str, 1);
  ck_free(shm_str);
#endif

  u8 *map_size_str = alloc_printf("%zu", afl->trigfuzz_map_size);
  setenv(TRIGFUZZ_MAP_SIZE_ENV_VAR, map_size_str, 1);
  ck_free(map_size_str);

  trigfuzz_reset(afl);

  if (afl->trigfuzz_debug) {

    ACTF("TrigFuzz enabled: ins=%u seq=%u shm=%zu bytes",
         afl->trigfuzz_ins_num, afl->trigfuzz_seq_num,
         afl->trigfuzz_map_size);

  }

}

void trigfuzz_deinit(afl_state_t *afl) {

  if (!afl->trigfuzz_enabled || !afl->trigfuzz_map) return;

  afl_shm_deinit(&afl->trigfuzz_shm);
  afl->trigfuzz_map = NULL;
  afl->trigfuzz_enabled = 0;
  unsetenv(TRIGFUZZ_SHM_ENV_VAR);
  unsetenv(TRIGFUZZ_MAP_SIZE_ENV_VAR);

}

void trigfuzz_reset(afl_state_t *afl) {

  if (!afl->trigfuzz_enabled || !afl->trigfuzz_map) return;

  memset(afl->trigfuzz_map, 0, afl->trigfuzz_map_size);
  trigfuzz_write_header(afl);
  afl->trigfuzz_cur_distance_valid = 0;
  afl->trigfuzz_cur_plus = 0;
  afl->trigfuzz_save_plus_trig = 0;

}

void trigfuzz_after_run(afl_state_t *afl) {

  if (!afl->trigfuzz_enabled || !afl->trigfuzz_map) return;

  u32 magic = 0, ins_num = 0, seq_num = 0;
  memcpy(&magic, afl->trigfuzz_map, sizeof(magic));
  memcpy(&ins_num, afl->trigfuzz_map + 4, sizeof(ins_num));
  memcpy(&seq_num, afl->trigfuzz_map + 8, sizeof(seq_num));
  if (magic != TRIGFUZZ_MAGIC || ins_num != afl->trigfuzz_ins_num ||
      seq_num != afl->trigfuzz_seq_num) {

    afl->trigfuzz_cur_distance_valid = 0;
    return;

  }

  u8    *reach = afl->trigfuzz_map + trigfuzz_reach_base();
  u8    *seq = afl->trigfuzz_map + trigfuzz_seq_base(ins_num);
  u8    *records = afl->trigfuzz_map + trigfuzz_tcu_base(ins_num, seq_num);
  double distance = 0.0;
  u8     any_reached = 0;

  for (u32 i = 0; i < ins_num; ++i) {

    if (reach[i]) {

      any_reached = 1;
      break;

    }

  }

  if (!any_reached) {

    afl->trigfuzz_cur_distance_valid = 0;
    return;

  }

  double conj_cal[TRIGFUZZ_MAX_CONJS];

  for (u32 cur_seq = 0; cur_seq < seq_num; ++cur_seq) {

    if (!seq[cur_seq]) {

      distance = trigfuzz_add_distance(
          distance, (double)(seq_num - cur_seq) * TRIGFUZZ_DISTANCE_CAP);
      break;

    }

    for (u32 conj = 0; conj < TRIGFUZZ_MAX_CONJS; ++conj) {

      conj_cal[conj] = -1.0;

    }

    for (u32 site = 0; site < ins_num; ++site) {

      if (!reach[site]) continue;

      u8 *rec = records + (size_t)site * TRIGFUZZ_TCU_STRIDE;
      if (rec[8] != cur_seq || rec[9] >= TRIGFUZZ_MAX_CONJS) continue;

      double rec_dist = 0.0, weight = 1.0;
      memcpy(&rec_dist, rec, sizeof(rec_dist));
      memcpy(&weight, rec + 10, sizeof(weight));
      rec_dist = trigfuzz_sanitize_distance(rec_dist);
      if (weight != weight || weight <= 0.0) weight = 1.0;
      weight = trigfuzz_sanitize_distance(weight);
      if (weight <= 0.0 || weight >= TRIGFUZZ_DISTANCE_CAP) weight = 1.0;

      double weighted = trigfuzz_sanitize_distance(rec_dist / weight);
      if (conj_cal[rec[9]] < 0.0) {

        conj_cal[rec[9]] = weighted;

      } else {

        conj_cal[rec[9]] = trigfuzz_add_distance(conj_cal[rec[9]], weighted);

      }

    }

    double min_conj = -1.0;
    for (u32 conj = 0; conj < TRIGFUZZ_MAX_CONJS; ++conj) {

      if (conj_cal[conj] >= 0.0 &&
          (min_conj < 0.0 || conj_cal[conj] < min_conj)) {

        min_conj = conj_cal[conj];

      }

    }

    if (min_conj >= 0.0) { distance = trigfuzz_add_distance(distance, min_conj); }

  }

  afl->trigfuzz_cur_distance = trigfuzz_sanitize_distance(distance);
  afl->trigfuzz_cur_distance_valid = 1;

  if (afl->trigfuzz_debug) {

    DEBUGF("TrigFuzz current distance: %.6f\n", afl->trigfuzz_cur_distance);

  }

}

u8 trigfuzz_current_is_interesting(afl_state_t *afl) {

  if (!afl->trigfuzz_enabled || !afl->trigfuzz_cur_distance_valid) return 0;

  return !afl->trigfuzz_best_distance_valid ||
         afl->trigfuzz_cur_distance + TRIGFUZZ_EPSILON <
             afl->trigfuzz_best_distance;

}

static void trigfuzz_update_distance_range(afl_state_t *afl, double distance) {

  distance = trigfuzz_sanitize_distance(distance);
  if (!afl->trigfuzz_distance_range_valid) {

    afl->trigfuzz_min_distance = distance;
    afl->trigfuzz_max_distance = distance;
    afl->trigfuzz_distance_range_valid = 1;
    return;

  }

  if (distance < afl->trigfuzz_min_distance) afl->trigfuzz_min_distance = distance;
  if (distance > afl->trigfuzz_max_distance) afl->trigfuzz_max_distance = distance;

}

void trigfuzz_update_queue_entry(afl_state_t *afl, struct queue_entry *q,
                                 u8 mark_plus) {

  if (!afl->trigfuzz_enabled || !q || !afl->trigfuzz_cur_distance_valid) return;

  q->trig_distance = afl->trigfuzz_cur_distance;
  q->trig_distance_valid = 1;
  trigfuzz_update_distance_range(afl, q->trig_distance);

  if (!afl->trigfuzz_best_distance_valid ||
      q->trig_distance + TRIGFUZZ_EPSILON < afl->trigfuzz_best_distance) {

    afl->trigfuzz_best_distance = q->trig_distance;
    afl->trigfuzz_best_distance_valid = 1;

  }

  if (mark_plus) {

    q->plus_trig = 1;
    q->trig_novel_cycle = afl->queue_cycle;
    afl->trigfuzz_saved_plus_trig++;
    afl->score_changed = 1;

  }

}

void trigfuzz_note_queue_filename(afl_state_t *afl, struct queue_entry *q) {

  if (!afl->trigfuzz_enabled || !q || !q->fname) return;

  const char *name = strrchr((const char *)q->fname, '/');
  name = name ? name + 1 : (const char *)q->fname;
  if (strstr(name, "+trig")) {

    q->plus_trig = 1;
    q->trig_novel_cycle = afl->queue_cycle;

  }

}

u8 trigfuzz_queue_is_favored(afl_state_t *afl, struct queue_entry *q) {

  if (!afl->trigfuzz_enabled || !q || !q->plus_trig ||
      !q->trig_distance_valid) {

    return 0;

  }

  if (afl->queue_cycle - q->trig_novel_cycle >= 3) {

    q->plus_trig = 0;
    q->trig_novel_cycle = 0;
    return 0;

  }

  return 1;

}

double trigfuzz_perf_multiplier(afl_state_t *afl, struct queue_entry *q) {

  if (!afl->trigfuzz_enabled || !q || !q->trig_distance_valid ||
      !afl->trigfuzz_distance_range_valid) {

    return 1.0;

  }

  if (afl->trigfuzz_max_distance <= afl->trigfuzz_min_distance) return 1.5;

  double norm = (q->trig_distance - afl->trigfuzz_min_distance) /
                (afl->trigfuzz_max_distance - afl->trigfuzz_min_distance);
  if (norm < 0.0) norm = 0.0;
  if (norm > 1.0) norm = 1.0;

  return 1.0 + (1.0 - norm) * 2.0;

}
