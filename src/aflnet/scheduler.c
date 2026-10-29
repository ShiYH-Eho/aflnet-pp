/* aflnet/scheduler.c - AFLNet state-aware (IPSM) seed selection.

   Moved out of src/afl-fuzz-aflnet.c into the src/aflnet/ module tree:

     - aflnet_choose_target_state(): pick the next state to target (state
       selection algorithm).
     - aflnet_choose_seed(): pick a seed reaching the target state (seed
       selection algorithm).
     - aflnet_select_next_seed(): public entry point used by the core
       (afl-main.c afl_fuzz_queue) to pick the next queue entry.

   The per-state data (state table, seed lists) lives in state.c; the
   get_state_index() helper is shared via aflnet-internal.h. */

#include <math.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "common.h"
#include "afl-fuzz.h"
#include "aflnet.h"
#include "aflnet-internal.h"

/* Decide whether the state-aware (IPSM) scheduler should pick the next seed
   on this iteration.  Mirrors original AFLNet seed_schedule_type:
     - CODE_AWARE: never (always the normal selection);
     - HYBRID: original probability UR(100) < (now - last_path_time) / time_gap
       (the longer since the last new path was found, the more likely the
       state-aware scheduler is used);
     - IPSM: always (default). */
u8 aflnet_use_state_scheduler(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (!afl->afl_env.aflnet_mode || !an) { return 0; }
  if (!an->state_mode) { return 0; }

  switch (an->seed_schedule_type) {

    case AFLNET_CODE_AWARE_SCHEDULE:

      return 0;

    case AFLNET_HYBRID_SCHEDULE: {

      u64 now = get_cur_time();
      if (an->last_path_time == 0) { an->last_path_time = now; }
      if (!an->time_gap) { an->time_gap = 600; }

      u64 elapsed = now - an->last_path_time;
      return rand_below(afl, 100) < (u32)(elapsed / an->time_gap) ? 1 : 0;

    }

    case AFLNET_IPSM_SCHEDULE:
    default:

      return 1;

  }

}

/* index of the first prefix-sum bucket containing val */
static u32 aflnet_index_search(u32 *A, u32 n, u32 val) {

  u32 index = 0;
  for (index = 0; index < n; index++) {

    if (val <= A[index]) { break; }

  }

  return (index >= n) ? n - 1 : index;

}

/* Recompute the per-state scores and weighted-select the next state.
   Mirrors original AFLNet update_scores_and_select_next_state(FAVOR):

     score = ceil(1000 * 2^(-log10(log10(fuzzs+1) * selected_times + 1))
                       * 2^(log(paths_discovered+1)))

   A state is then picked with probability proportional to its score. */
static u32 aflnet_update_scores_and_select_next_state(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;
  u32             i;

  if (!an->state_ids_count) { return 0; }

  u32 *state_scores = (u32 *)ck_alloc(an->state_ids_count * sizeof(u32));
  if (!state_scores) { PFATAL("Cannot allocate memory for state_scores"); }

  for (i = 0; i < an->state_ids_count; i++) {

    u32          state_id = an->state_ids[i];
    u32          sidx = aflnet_get_state_index(an, state_id);
    state_info_t *state = (sidx != (u32)-1) ? an->states[sidx] : NULL;
    if (!state) { continue; }

    double inv =
        -log10(log10((double)state->fuzzs + 1.0) *
                   (double)state->selected_times +
               1.0);
    double cov = log((double)state->paths_discovered + 1.0);
    state->score = (u32)ceil(1000.0 * pow(2.0, inv) * pow(2.0, cov));

    if (i == 0) {

      state_scores[i] = state->score;

    } else {

      state_scores[i] = state_scores[i - 1] + state->score;

    }

  }

  u32 total = state_scores[an->state_ids_count - 1];
  u32 result;
  if (!total) {

    result = an->state_ids[rand_below(afl, an->state_ids_count)];

  } else {

    u32 randV = rand_below(afl, total);
    u32 idx = aflnet_index_search(state_scores, an->state_ids_count, randV);
    result = an->state_ids[idx];

  }

  ck_free(state_scores);
  return result;

}

/* Pick the next state to target. */

static u32 aflnet_choose_target_state(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;
  u32             result = 0;

  if (!an->state_ids_count) { return 0; }

  switch (an->state_selection_algo) {

    case AFLNET_RANDOM_SELECTION:

      an->selected_state_index = rand_below(afl, an->state_ids_count);
      result = an->state_ids[an->selected_state_index];
      break;

    case AFLNET_FAVOR:

      /* round-robin for the first few cycles to gather enough statistics,
         then score-based weighted selection (mirrors original AFLNet) */
      if (an->state_cycles < 5) {

        result = an->state_ids[an->selected_state_index];
        an->selected_state_index++;
        if (an->selected_state_index == an->state_ids_count) {

          an->selected_state_index = 0;
          an->state_cycles++;

        }

        break;

      }

      result = aflnet_update_scores_and_select_next_state(afl);
      break;

    case AFLNET_ROUND_ROBIN:
    default:

      result = an->state_ids[an->selected_state_index];
      an->selected_state_index++;
      if (an->selected_state_index == an->state_ids_count) {

        an->selected_state_index = 0;
        an->state_cycles++;

      }

      break;

  }

  return result;

}

/* Pick a seed from the target state's seed list. */

static struct queue_entry *aflnet_choose_seed(afl_state_t *afl,
                                              u32 target_state_id) {

  aflnet_state_t *an = afl->aflnet;
  u32             sidx = aflnet_get_state_index(an, target_state_id);

  if (sidx == (u32)-1) { return NULL; }

  state_info_t *s = an->states[sidx];
  if (!s->seeds_count) { return NULL; }

  switch (an->seed_selection_algo) {

    case AFLNET_ROUND_ROBIN: {

      struct queue_entry *r =
          (struct queue_entry *)s->seeds[s->selected_seed_index];
      s->selected_seed_index++;
      if (s->selected_seed_index == s->seeds_count) {

        s->selected_seed_index = 0;

      }

      return r;

    }

    case AFLNET_FAVOR: {

      /* Mirror original AFLNet choose_seed(FAVOR): walk the state's seed list
         for up to 5 full cycles, skipping (with high probability) seeds that
         are neither initial seeds nor were generated while the current target
         state was targeted, and preferring seeds not yet fuzzed for the target
         state (was_fuzzed_map).  Falls back to round-robin when the list is
         small or the heuristic scan produces no survivor. */

      if (s->seeds_count <= 10) {

        struct queue_entry *r =
            (struct queue_entry *)s->seeds[s->selected_seed_index];
        s->selected_seed_index++;
        if (s->selected_seed_index == s->seeds_count) {

          s->selected_seed_index = 0;

        }

        return r;

      }

      u32                 passed_cycles = 0;
      struct queue_entry *result = NULL;

      while (passed_cycles < 5) {

        result = (struct queue_entry *)s->seeds[s->selected_seed_index];
        if (s->selected_seed_index + 1 == s->seeds_count) {

          s->selected_seed_index = 0;
          passed_cycles++;

        } else {

          s->selected_seed_index++;

        }

        if (!result || result->disabled) { continue; }

        /* skip seeds that do not reach the target state */
        if (result->generating_state_id != target_state_id &&
            !result->is_initial_seed && rand_below(afl, 100) < 90) {

          continue;

        }

        u8 fuzzed =
            (result->id < an->fuzzed_map_qentries)
                ? an->was_fuzzed_map[sidx][result->id]
                : 0;

        if (afl->pending_favored) {

          /* with pending favourites, skip already-fuzzed or non-favoured
             seeds with high probability (SKIP_TO_NEW_PROB) */
          if ((fuzzed == 1 || !result->favored) &&
              rand_below(afl, 100) < SKIP_TO_NEW_PROB) {

            continue;

          }

          break;

        } else if (!result->favored && afl->queued_items > 10) {

          /* no pending favourites: skip non-favoured seeds, more often when
             already fuzzed for this state (mirrors AFL's skip heuristics) */
          if (afl->queue_cycle > 1 && fuzzed == 0) {

            if (rand_below(afl, 100) < SKIP_NFAV_NEW_PROB) { continue; }

          } else {

            if (rand_below(afl, 100) < SKIP_NFAV_OLD_PROB) { continue; }

          }

          break;

        }
        /* favoured seed (or small queue): keep scanning */

      }

      if (result && !result->disabled) { return result; }

      /* no survivor: fall back to round-robin */
      struct queue_entry *r =
          (struct queue_entry *)s->seeds[s->selected_seed_index];
      s->selected_seed_index++;
      if (s->selected_seed_index == s->seeds_count) {

        s->selected_seed_index = 0;

      }

      return r;

    }

    case AFLNET_RANDOM_SELECTION:
    default:

      s->selected_seed_index = rand_below(afl, s->seeds_count);
      return (struct queue_entry *)s->seeds[s->selected_seed_index];

  }

}

/* Public: pick the next seed, guided by the IPSM.  Sets queue_cur /
   current_entry on success and returns 1; returns 0 when the state-aware
   scheduler is disabled or there is not enough state info yet (caller then
   falls back to the normal selection). */

u8 aflnet_select_next_seed(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (!afl->afl_env.aflnet_mode || !an->state_mode) { return 0; }
  if (!an->state_ids_count) { return 0; }  /* not enough info yet */

  struct queue_entry *selected = NULL;
  u32                 guard = 0;

  while (!selected && guard++ < 100) {

    an->target_state_id = aflnet_choose_target_state(afl);

    /* update favourites based on the selected state */
    cull_queue(afl);

    u32 sidx = aflnet_get_state_index(an, an->target_state_id);
    if (sidx != (u32)-1) { an->states[sidx]->selected_times++; }

    selected = aflnet_choose_seed(afl, an->target_state_id);

    /* never hand a disabled (redundant) seed to the core */
    if (selected && selected->disabled) { selected = NULL; }

  }

  if (!selected) { return 0; }

  afl->queue_cur = selected;
  afl->current_entry = selected->id;
  return 1;

}
