/* aflnet/feedback.c - AFLNet IPSM update and per-run state feedback.

   Moved out of src/afl-fuzz-aflnet.c into the src/aflnet/ module tree:

     - aflnet_update_ipsm(): update the IPSM with the state sequence of the
       most recent run (path novelty, state table, per-state paths, seed
       registration).
     - aflnet_update_state_feedback(): fold the per-run state transitions
       into the coverage bitmap (called from the module's post_run hook).

   The state-table core helpers (ensure_state / get_state_index / path
   hashing / register_seed) live in state.c. */

#include "config.h"
#include "types.h"
#include "debug.h"
#include "common.h"
#include "afl-fuzz.h"
#include "aflnet.h"
#include "aflnet-internal.h"

/* Update the IPSM with the state sequence of the most recent run. */

void aflnet_update_ipsm(afl_state_t *afl, struct queue_entry *q) {

  aflnet_state_t *an = afl->aflnet;

  if (!an->state_sequence || !an->state_count) { return; }

  u32 states_before = an->state_ids_count;

  /* Preserve every distinct transition from this path.  Edges are recorded
     on every IPSM update so a later state discovery publishes the complete
     graph observed up to that point. */
  aflnet_record_sequence_edges(an, an->state_sequence, an->state_count);

  /* state sequence novelty (IPSM path discovery) */
  u32 h = aflnet_state_seq_hash(an->state_sequence, an->state_count);
  if (!aflnet_is_path_seen(an, h)) { aflnet_mark_path_seen(an, h); }

  /* make sure all visited states exist */
  for (u32 i = 0; i < an->state_count; i++) {

    aflnet_ensure_state(an, an->state_sequence[i]);

  }

  /* count paths that traverse each state */
  for (u32 i = 0; i < an->state_count; i++) {

    u32 sidx = aflnet_get_state_index(an, an->state_sequence[i]);
    if (sidx != (u32)-1) { an->states[sidx]->paths++; }

  }

  /* register the seed that produced this sequence */
  if (q) { aflnet_register_seed(afl, q); }

  /* mirror original AFLNet update_state_aware_variables(): on non-dry-run
     registrations (i.e. fuzz-generated seeds, is_initial_seed == 0), count a
     newly discovered path for the current target state (feeds the FAVOR
     state score in scheduler.c). */
  if (q && !q->is_initial_seed) {

    u32 sidx = aflnet_get_state_index(an, an->target_state_id);
    if (sidx != (u32)-1) { an->states[sidx]->paths_discovered++; }

  }

  if (an->state_ids_count > states_before) { aflnet_write_ipsm_json(afl); }

}

/* Per-run state feedback: fold the state sequence into the coverage
   bitmap. */

void aflnet_update_state_feedback(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (!afl->afl_env.aflnet_mode || !an->state_mode) { return; }
  if (!an->state_backend) { return; }

  /* 1. make the per-run state sequence current.  The bound backend decides
        how:
          - response-code backend: clears any stale sequence (so a run
            without a server response never reuses old state data) and
            extracts the whole sequence from response_buf.
          - state-variable backend: the sequence was already built
            incrementally by begin/on_recv/end during aflnet_send_over_network, so
            finalize is a no-op and the data is preserved. */
  an->state_backend->finalize(afl);

  if (!an->state_sequence || !an->state_count) { return; }

  /* 1b. mirror original AFLNet's update_fuzzs(): count the states visited by
        this run, no matter whether the generated test case is interesting. */
  aflnet_update_fuzzs(afl);

  /* 2. state feedback: fold state transitions into the coverage bitmap so
        new transitions are treated as interesting by the existing machinery.
        Mirrors original AFLNet's update_state_bitmap(): both STATE_FEEDBACK
        and CODE_STATE_FEEDBACK fold the transitions into trace_bits. */
  if (an->feedback_type == AFLNET_STATE_FEEDBACK ||
      an->feedback_type == AFLNET_CODE_STATE_FEEDBACK) {

    u32 prev_state = 0;
    for (u32 i = 0; i < an->state_count; i++) {

      u32 cur_state = an->state_sequence[i];
      u32 map_ptr_idx = (prev_state * STATE_SIZE + cur_state) % SHIFT_SIZE;
      if (map_ptr_idx < afl->fsrv.map_size) {

        afl->fsrv.trace_bits[map_ptr_idx]++;

      }

      prev_state = cur_state;

    }

  }

  /* 3. update the IPSM (annotates the current queue entry's regions and
        registers it with the discovered states) */
  // aflnet_update_ipsm(afl, q);

}
