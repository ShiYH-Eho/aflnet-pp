/* aflnet/module.c - AFLNet exposed as a native AFL++ custom-mutator module.

   This is the modularization layer that lets the AFLNet machinery run through
   the stock AFL++ extension points instead of scattered core edits.  It is
   registered by aflnet_register_module() from afl_setup_environment()
   (afl-fuzz.c) right after setup_custom_mutators(), so it coexists with
   user-supplied custom mutators.  When AFLNET_* is not requested the
   registration is a no-op and the module stays inactive.

   Native hook mapping:

     - afl_custom_fuzz_send       -> the per-run network exchange.  Because the
                                     module sets AFL_CUSTOM_MUTATOR_LATE_SEND,
                                     the stock setup binds this to
                                     fsrv.late_send, so it runs at exactly the
                                     point in the forkserver where the target
                                     child is ready for the session.
     - afl_custom_post_run        -> per-run state feedback (fold the state
                                     transitions into the coverage bitmap and
                                     update the IPSM).
     - afl_custom_queue_new_entry -> register a newly saved seed with the IPSM
                                     and write its replayable copy.
     - afl_custom_havoc_mutation  -> layer the AFLNet region-level mutations
                                     (original havoc cases 17-20) into the
                                     core havoc stacking loop.  fuzz_one()
                                     (afl-fuzz-one.c) runs the standard
                                     mutation pipeline directly on the M2
                                     region and reassembles M1+M2+M3 in
                                     common_fuzz_stuff().
     - afl_custom_init / afl_custom_deinit -> module lifecycle (data ptr). */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "common.h"
#include "afl-fuzz.h"
#include "aflnet.h"
#include "aflnet-internal.h"
#include "alloc-inl.h"

typedef struct aflnet_module_ctx {

  afl_state_t *afl;             /* the fuzzer instance this module serves */

  /* scratch buffer for the region-level havoc mutation (afl_custom_havoc_*) */
  u8 *havoc_scratch;

} aflnet_module_ctx_t;

/* ------------------------------------------------------------------ */
/* module hooks                                                       */
/* ------------------------------------------------------------------ */

static void *aflnet_module_init(afl_state_t *afl, unsigned int seed) {

  (void)seed;

  aflnet_module_ctx_t *ctx = (aflnet_module_ctx_t *)ck_alloc(sizeof(*ctx));
  ctx->afl = afl;
  return ctx;

}

static void aflnet_module_deinit(void *data) {

  aflnet_module_ctx_t *ctx = (aflnet_module_ctx_t *)data;
  if (ctx) {

    if (ctx->havoc_scratch) { afl_free(ctx->havoc_scratch); }
    ck_free(ctx);

  }

}

/* post-fuzz: called by fuzz_run_target() after every target execution.
   Two things happen here, in this order:

     1. the shared sockhook session is re-armed for the NEXT run.  post_run()
        is the last hook the core calls after an execution and before the
        next fork, so the rendezvous state (turn token, is_end,
        connection_state, message lengths, futex) is clean again by the time
        the next child looks at it - and, unlike late_send
        (aflnet_module_fuzz_send -> aflnet_send_over_network), it does not
        race a child that has already armed the session.  This is the fuzzer
        half of the per-run reset that the target's own session_init() cannot
        perform for a process that serves more than one session without
        re-arming (a persistent target looping on accept()).

     2. the per-run state feedback: fold the state sequence into the coverage
        bitmap and update the IPSM.  Like every afl_custom_post_run this
        fires for any forkserver run, INCLUDING the optional SAN forkservers.
        Only the main forkserver run performs a network exchange (the module's
        late_send -> aflnet_send_over_network sets feedback_pending); SAN runs
        re-execute the target with the same input but no exchange, so
        feedback_pending is 0 there and we skip the feedback - otherwise they
        would re-derive the stale response and double-count fuzzs / re-fold
        state transitions into trace_bits.  The reset in step 1 runs for
        those runs as well: re-arming an idle session is idempotent, and it
        also cleans up whatever a SAN child may have armed. */
static void aflnet_module_post_run(void *data) {

  aflnet_module_ctx_t *ctx = (aflnet_module_ctx_t *)data;
  afl_state_t         *afl = ctx->afl;

  if (!afl->afl_env.aflnet_mode) { return; }

  /* re-arm the shared session for the next run.  The function pointer is
     assigned in config.c for the two shm-sync configurations and is NULL for
     sock_mode=0; aflnet_sock2shm_init_session() itself no-ops unless the
     segment rendezvous is armed.  It also resets the token/connection_state
     left behind by a timed-out run, which is why the (never wired)
     aflnet_sock2shm_notify_timeout() is not needed. */
  if (afl->aflnet && afl->aflnet->aflnet_init_session) {

    (void)afl->aflnet->aflnet_init_session(afl);

  }

  /* skip runs without a fresh network exchange (e.g. SAN forkservers) */
  if (!afl->aflnet->feedback_pending) { return; }
  afl->aflnet->feedback_pending = 0;

  aflnet_update_state_feedback(afl);

}

/* send the full message chain to the target.  Bound to fsrv.late_send by the
   stock AFL_CUSTOM_MUTATOR_LATE_SEND machinery, so custom_data_ptr points at
   this module's context (not at the afl_state_t directly). */
static void aflnet_module_fuzz_send(void *data, const u8 *buf, size_t buf_size) {

  aflnet_module_ctx_t *ctx = (aflnet_module_ctx_t *)data;

  aflnet_send_over_network(ctx->afl, buf, buf_size);

}

/* post-save: a new queue entry was saved (add_to_queue).  Register it with the
   IPSM using the run that produced it and write the replayable copy.  For
   seeds loaded before any run (initial corpus / dry run) there is no state
   sequence yet, so this is a no-op; those are handled by the dry-run path. */
static u8 aflnet_module_queue_new_entry(void *data, const u8 *fname,
                                        const u8 *mother_fname) {

  aflnet_module_ctx_t *ctx = (aflnet_module_ctx_t *)data;
  afl_state_t         *afl = ctx->afl;
  (void)mother_fname;

  if (!afl->afl_env.aflnet_mode) { return 0; }

  aflnet_state_t *an = afl->aflnet;
  if (!an || !an->state_sequence || !an->state_count) { return 0; }
  if (!afl->queue_top) { return 0; }

  /* register the seed that produced this run's state sequence */
  aflnet_update_ipsm(afl, afl->queue_top);

  /* write the replayable copy of the new test case (only when the run
     actually exchanged messages, i.e. messages_sent > 0) */
  if (an->messages_sent && fname) {

    FILE *fp = fopen((char *)fname, "rb");
    if (fp) {

      fseek(fp, 0, SEEK_END);
      long sz = ftell(fp);
      fseek(fp, 0, SEEK_SET);
      if (sz > 0) {

        u8 *buf = (u8 *)ck_alloc((u32)sz);
        if (fread(buf, 1, (size_t)sz, fp) == (size_t)sz) {

          u8 *fn_replay = alloc_printf("%s/replayable-queue/%s", afl->out_dir,
                                       basename((char *)fname));
          aflnet_save_testcase_to_file(afl, buf, (u32)sz, fn_replay, 1,
                                       an->messages_sent);
          ck_free(fn_replay);

        }

        ck_free(buf);

      }

      fclose(fp);

    }

  }

  return 1;

}

/* ------------------------------------------------------------------ */
/* region-level mutation (afl_custom_fuzz)                            */
/* ------------------------------------------------------------------ */

/* Pick a random region from a random queue seed (for the AFLNet
   region-level mutations, original havoc cases 17-20).  Returns a freshly
   allocated buffer (caller frees with ck_free) or NULL if no region is
   available. */
static u8 *aflnet_choose_source_region(afl_state_t *afl, u32 *out_len) {

  *out_len = 0;
  if (!afl->queued_items) { return NULL; }

  struct queue_entry *q = afl->queue_buf[rand_below(afl, afl->queued_items)];
  if (!q || !q->regions || !q->region_count) { return NULL; }

  u32 reg_index = rand_below(afl, q->region_count);
  u32 len = (u32)(q->regions[reg_index].end_byte -
                  q->regions[reg_index].start_byte + 1);
  if (!len || len > MAX_FILE) { return NULL; }

  u8 *src = queue_testcase_get(afl, q);
  u8 *out = (u8 *)ck_alloc(len);
  memcpy(out, src + q->regions[reg_index].start_byte, len);
  *out_len = len;
  return out;

}

/* Apply ONE AFLNet region-level mutation (original havoc cases 17-20) to the
   input buffer: replace / insert-begin / insert-end / duplicate with a random
   region pulled from a random queue seed.  The result is built into *scratch
   (grown up to max_len) and its length is returned (0 = nothing was applied,
   e.g. no source region available). */
static u32 aflnet_build_region_mutation(afl_state_t *afl, u8 **scratch,
                                        const u8 *in, u32 in_len,
                                        u32 max_len) {

  u32 src_len = 0;
  u8 *src = aflnet_choose_source_region(afl, &src_len);
  if (!src || !src_len) {

    if (src) { ck_free(src); }
    return 0;

  }

  u8 *out;
  u32 out_len;

  switch (rand_below(afl, 4)) {

    /* case 17: replace the current region with a random region */
    case 0:

      out_len = src_len;
      if (out_len > max_len) { ck_free(src); return 0; }
      out = (u8 *)afl_realloc((void **)scratch, out_len ? out_len : 1);
      memcpy(out, src, src_len);
      break;

    /* case 18: insert a random region at the beginning */
    case 1:

      out_len = src_len + in_len;
      if (out_len > max_len) { ck_free(src); return 0; }
      out = (u8 *)afl_realloc((void **)scratch, out_len ? out_len : 1);
      memcpy(out, src, src_len);
      memcpy(out + src_len, in, in_len);
      break;

    /* case 19: insert a random region at the end */
    case 2:

      out_len = in_len + src_len;
      if (out_len > max_len) { ck_free(src); return 0; }
      out = (u8 *)afl_realloc((void **)scratch, out_len ? out_len : 1);
      memcpy(out, in, in_len);
      memcpy(out + in_len, src, src_len);
      break;

    /* case 20: duplicate the current region */
    default:

      if (!in_len || in_len * 2 > max_len) { ck_free(src); return 0; }
      out_len = in_len * 2;
      out = (u8 *)afl_realloc((void **)scratch, out_len ? out_len : 1);
      memcpy(out, in, in_len);
      memcpy(out + in_len, in, in_len);
      break;

  }

  ck_free(src);
  return out_len;

}

/* stacked-havoc hook: called from fuzz_one()'s havoc_stage stacking loop.
   With the configured probability it replaces one stacked step with an
   AFLNet region-level mutation of the M2 region (buf).  Always returns a
   valid buffer so the core never sees a NULL out_buf. */
static size_t aflnet_module_havoc_mutation(void *data, u8 *buf, size_t buf_size,
                                           u8 **out_buf, size_t max_len) {

  aflnet_module_ctx_t *ctx = (aflnet_module_ctx_t *)data;
  afl_state_t         *afl = ctx->afl;

  if (!afl->afl_env.aflnet_mode || !afl->aflnet->state_mode ||
      !afl->aflnet->region_mode) {

    *out_buf = buf;
    return buf_size;

  }

  u32 new_len = aflnet_build_region_mutation(afl, &ctx->havoc_scratch, buf,
                                             (u32)buf_size, (u32)max_len);

  if (!new_len) {

    /* no source region available: return the input unchanged */
    ctx->havoc_scratch = (u8 *)afl_realloc((void **)&ctx->havoc_scratch,
                                           buf_size ? buf_size : 1);
    memcpy(ctx->havoc_scratch, buf, buf_size);
    *out_buf = ctx->havoc_scratch;
    return buf_size;

  }

  *out_buf = ctx->havoc_scratch;
  return new_len;

}

/* probability (in percent) that a havoc stacking step becomes an AFLNet
   region-level mutation (mirrors the old ~25% region-op mix) */
static u8 aflnet_module_havoc_mutation_probability(void *data) {

  (void)data;
  return 25;

}



/* ------------------------------------------------------------------ */
/* registration                                                       */
/* ------------------------------------------------------------------ */

/* Register the AFLNet module as a custom mutator.  Called from
   afl_setup_environment() (afl-fuzz.c) after setup_custom_mutators() and
   before the native late_send binding.  Returns the mutator (or NULL when
   AFLNet mode is not configured). */
struct custom_mutator *aflnet_register_module(afl_state_t *afl) {

  if (!afl->afl_env.aflnet_mode) { return NULL; }

  aflnet_module_ctx_t *ctx = (aflnet_module_ctx_t *)ck_alloc(sizeof(*ctx));
  ctx->afl = afl;

  struct custom_mutator *m = (struct custom_mutator *)ck_alloc(sizeof(*m));
  m->name                   = "aflnet";
  m->name_short             = strdup("aflnet"); /* freed by destroy_custom_mutators() */
  m->data                   = ctx;
  m->afl_custom_init        = aflnet_module_init;
  m->afl_custom_deinit      = aflnet_module_deinit;
  m->afl_custom_post_run    = aflnet_module_post_run;
  m->afl_custom_fuzz_send   = aflnet_module_fuzz_send;
  m->afl_custom_queue_new_entry = aflnet_module_queue_new_entry;

  /* let the stock AFL_CUSTOM_MUTATOR_LATE_SEND machinery pick up
     afl_custom_fuzz_send as fsrv.late_send (see afl_setup_environment()) */
  afl->afl_env.afl_custom_mutator_late_send = 1;

  /* register the IPSM state-aware scheduler on the core's generic
     custom_next_queue_entry hook (afl-main.c afl_fuzz_queue) */
  // afl->custom_next_queue_entry = aflnet_select_next_seed;

  /* state-aware mode: the core's fuzz_one() runs the whole mutation pipeline
     (deterministic + havoc + splice) directly on the M2 region (see
     afl-fuzz-one.c) and common_fuzz_stuff() reassembles M1+M2+M3.  The
     module only layers the AFLNet region-level mutations (original havoc
     cases 17-20) into havoc's stacking loop. */
  if (afl->aflnet && afl->aflnet->state_mode) {

    m->afl_custom_havoc_mutation = aflnet_module_havoc_mutation;
    m->afl_custom_havoc_mutation_probability =
        aflnet_module_havoc_mutation_probability;
    m->stacked_custom = 1;

  }

  list_append(&afl->custom_mutator_list, m);
  ++afl->custom_mutators_count;

  OKF("AFLNet module registered as a custom mutator");

  return m;

}
