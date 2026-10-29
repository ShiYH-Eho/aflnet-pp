#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "hash.h"
#include "common.h"
#include "afl-fuzz.h"
#include "aflnet.h"
#include "../aflnet-internal.h"
#include "alloc-inl.h" 
/* ------------------------------------------------------------------ */
/* public: init / deinit                                              */
/* ------------------------------------------------------------------ */

/* State variable feedback (state_mode == AFLNET_STATE_VAR_MODE): create a dedicated shared
   memory region that the instrumented target writes its current state-
   variable values into.  The SHM id/path is exported via the environment
   variable AFLNET_STATEVAR_SHM_ENV_VAR so the target can pick it up. */

void aflnet_statevar_shm_init(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (an->statevar_shm_ready) { return; }

  u8 *map = afl_shm_init(&an->statevar_shm, AFLNET_STATEVAR_SHM_SIZE, 1,
                         afl->perm, afl->chown_needed ? afl->fsrv.gid : -1);

  if (!map) { FATAL("aflnet_statevar_shm_init: zero return from afl_shm_init"); }

  memset(an->statevar_shm.map, 0, AFLNET_STATEVAR_SHM_SIZE);

#ifdef USEMMAP
  setenv(AFLNET_STATEVAR_SHM_ENV_VAR, an->statevar_shm.g_shm_file_path, 1);
  OKF("AFLNet state-variable SHM ready at %s",
      an->statevar_shm.g_shm_file_path);
#else
  {

    u8 *shm_str = alloc_printf("%d", an->statevar_shm.shm_id);
    setenv(AFLNET_STATEVAR_SHM_ENV_VAR, shm_str, 1);
    ck_free(shm_str);
    OKF("AFLNet state-variable SHM ready with ID %d", an->statevar_shm.shm_id);

  }
#endif

  an->statevar_shm_ready = 1;

}
void aflnet_statevar_shm_deinit(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (!an->statevar_shm_ready) { return; }

  unsetenv(AFLNET_STATEVAR_SHM_ENV_VAR);
  afl_shm_deinit(&an->statevar_shm);
  an->statevar_shm_ready = 0;

}
/* Hash the current contents of the state-variable SHM region to derive a
   state id.  The target writes state-variable values into the SHM during
   execution; after each recv we hash the region to capture the current
   "state snapshot". */

static u32 aflnet_statevar_hash(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (!an->statevar_shm_ready || !an->statevar_shm.map) { return 0; }

  return hash32(an->statevar_shm.map, AFLNET_STATEVAR_SHM_SIZE, HASH_CONST);

}
/* Append a state id to the real-time state sequence.  This sequence is
   built incrementally during aflnet_send_over_network (one entry per recv) when
   state_mode == AFLNET_STATE_VAR_MODE, and is later consumed by aflnet_update_state_feedback.
   It reuses the same state_sequence / state_count fields that state_mode
   == 1 populates from response codes, so the rest of the IPSM machinery
   works uniformly. */

static void aflnet_statevar_append(afl_state_t *afl, u32 state_id) {

  aflnet_state_t *an = afl->aflnet;

  an->state_sequence = (u32 *)ck_realloc(
      an->state_sequence,
      (an->state_count + 1) * sizeof(u32));

  an->state_sequence[an->state_count++] = state_id;

}

/* ------------------------------------------------------------------ */
/* state-variable state-sequence backend                              */
/* (state_mode == AFLNET_STATE_VAR_MODE)                              */
/* ------------------------------------------------------------------ */

/* Start of a run: drop the previous run's state sequence and zero the
   state-variable SHM so stale values cannot bleed into the first state id
   of this run. */

static void aflnet_statevar_reset(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (an->state_sequence) {

    ck_free(an->state_sequence);
    an->state_sequence = NULL;

  }

  an->state_count = 0;

  if (an->statevar_shm_ready && an->statevar_shm.map) {

    memset(an->statevar_shm.map, 0, AFLNET_STATEVAR_SHM_SIZE);

  }

}

/* The exchange always starts from the initial state id 0. */

static void aflnet_statevar_begin(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (an->statevar_shm_ready) { aflnet_statevar_append(afl, 0); }

}

/* After each server response: hash the state-variable SHM to derive the
   current state id and append it to the real-time state sequence. */

static void aflnet_statevar_on_recv(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (!an->statevar_shm_ready) { return; }

  u32 sid = aflnet_statevar_hash(afl);
  aflnet_statevar_append(afl, sid);

}

/* After the last response of the exchange: capture the terminal state.  The
   draining recv in HANDLE_RESPONSES mirrors the response-code backend, whose
   finalize() re-extracts the codes from the whole (drained) response buffer,
   so the terminal state does belong to the sequence.  Only append it when
   that recv really advanced the state: re-appending an unchanged id would
   duplicate the last on_recv entry and add a bogus self-transition when the
   sequence is folded into state transitions. */

static void aflnet_statevar_end(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (!an->statevar_shm_ready) { return; }

  u32 sid = aflnet_statevar_hash(afl);

  if (an->state_count && an->state_sequence[an->state_count - 1] == sid) {

    return;

  }

  aflnet_statevar_append(afl, sid);

}

/* The sequence is already complete: begin/on_recv/end built it - and
   de-duplicated its terminal entry - in real time. */

static void aflnet_statevar_finalize(afl_state_t *afl) { (void)afl; }

/* state_sequence = [0 (initial), s0, s1, ...], where entry 0 is the synthetic
   pre-exchange state, entry 1 is the state reached by the initial recv (the
   server greeting) and entry i+2 is the state reached by the response to
   message i.  Like the response-code backend, region i's cumulative
   subsequence therefore ends with the state reached by the response to its own
   message: state_sequence[0..i+2]. */

static unsigned int *aflnet_statevar_region_states(afl_state_t *afl,
                                                   u32 region_idx,
                                                   u32 *count) {

  aflnet_state_t *an = afl->aflnet;

  if (!an->state_sequence || region_idx >= an->state_count) { return NULL; }

  /* state_sequence[0] is the synthetic initial state, state_sequence[i + 1] the
     state reached after the response to message i, so region i's cumulative
     prefix is state_sequence[0..i + 1] (same end point as the response-code
     backend's [0, code(greeting), code(response to message 0), ...]).  The
     entry is missing when that response never arrived (failed send/recv made
     the exchange stop right there); clamp instead of returning NULL, which
     would make aflnet_annotate_regions leave the region unannotated and
     region.c drop the whole seed from M2 inference. */
  u32 cnt = region_idx + 2;
  if (cnt > an->state_count) { cnt = an->state_count; }
  unsigned int *seq = (unsigned int *)ck_alloc(cnt * sizeof(unsigned int));
  memcpy(seq, an->state_sequence, cnt * sizeof(unsigned int));

  *count = cnt;
  return seq;

}

const aflnet_state_backend_t aflnet_statevar_backend = {

    .reset                = aflnet_statevar_reset,
    .begin                = aflnet_statevar_begin,
    .on_recv              = aflnet_statevar_on_recv,
    .end                  = aflnet_statevar_end,
    .finalize             = aflnet_statevar_finalize,
    .region_states        = aflnet_statevar_region_states,

};