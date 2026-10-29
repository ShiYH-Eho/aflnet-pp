/* aflnet/state.c - AFLNet inferred protocol state machine (IPSM) core.

   Split out of src/afl-fuzz-aflnet.c.  Maintains the discovered state
   table, per-state seed lists, the per-state/per-seed fuzzed map, the set
   of seen state sequences, plus the state-variable SHM used by
   state_mode == AFLNET_STATE_VAR_MODE. */

#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "hash.h"
#include "common.h"
#include "afl-fuzz.h"
#include "aflnet.h"
#include "aflnet-internal.h"
#include "alloc-inl.h" 

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */

u32 aflnet_get_state_index(aflnet_state_t *an, u32 state_id) {

  for (u32 i = 0; i < an->state_ids_count; i++) {

    if (an->state_ids[i] == state_id) { return i; }

  }

  return (u32)-1;

}
/* Grow the per-state/per-seed fuzzed map. New cells are marked -1
   (unreachable). The map is always kept at least 1x1 so that it is never a
   NULL/zero-size allocation. */

void aflnet_expand_was_fuzzed_map(aflnet_state_t *an, u32 new_states,
                                         u32 new_qentries) {

  u32 old_states = an->fuzzed_map_states;
  u32 old_q = an->fuzzed_map_qentries;

  if (!new_states && !new_qentries) { return; }

  u32 new_state_count = MAX(1U, old_states + new_states);
  u32 new_q_count = MAX(1U, old_q + new_qentries);

  an->was_fuzzed_map = (u8 **)ck_realloc(an->was_fuzzed_map,
                                         new_state_count * sizeof(u8 *));

  /* ck_realloc() does not zero the memory it hands out (it is plain
      realloc()), so the row pointers added by this growth have to be
      initialised before they are reallocated below -- reading them as-is
      would pass a garbage pointer to realloc(). */
  for (u32 i = old_states; i < new_state_count; i++) {

    an->was_fuzzed_map[i] = NULL;

  }

  for (u32 i = 0; i < new_state_count; i++) {

    an->was_fuzzed_map[i] =
        (u8 *)ck_realloc(an->was_fuzzed_map[i], new_q_count * sizeof(u8));

  }

  for (u32 i = 0; i < new_state_count; i++) {

    for (u32 j = 0; j < new_q_count; j++) {

      if (i >= old_states || j >= old_q) { an->was_fuzzed_map[i][j] = (u8)-1; }

    }

  }

  an->fuzzed_map_states = new_state_count;
  an->fuzzed_map_qentries = new_q_count;

}
/* Make sure a state id exists in the IPSM state table. */

void aflnet_ensure_state(aflnet_state_t *an, u32 state_id) {

  if (aflnet_get_state_index(an, state_id) != (u32)-1) { return; }

  if (an->state_ids_count >= an->state_ids_alloc) {

    u32 new_alloc = an->state_ids_alloc ? an->state_ids_alloc * 2 : 16;
    an->state_ids = (u32 *)ck_realloc(an->state_ids,
                                      new_alloc * sizeof(u32));
    an->states = (state_info_t **)ck_realloc(an->states,
                                             new_alloc * sizeof(state_info_t *));
    an->state_ids_alloc = new_alloc;

  }

  state_info_t *s = (state_info_t *)ck_alloc(sizeof(state_info_t));
  s->id = state_id;
  s->is_covered = 1;
  s->score = 1;

  an->state_ids[an->state_ids_count] = state_id;
  an->states[an->state_ids_count] = s;
  an->state_ids_count++;

  /* give every state (including the initial state 0) a row in the fuzzed map */
  aflnet_expand_was_fuzzed_map(an, 1, 0);

}
/* Add a seed to the seed list of a state (deduplicated). */

void aflnet_state_add_seed(aflnet_state_t *an, u32 state_id,
                                  struct queue_entry *q) {

  u32 sidx = aflnet_get_state_index(an, state_id);
  if (sidx == (u32)-1) { return; }

  state_info_t *s = an->states[sidx];
  for (u32 i = 0; i < s->seeds_count; i++) {

    if (s->seeds[i] == q) { return; }

  }

  s->seeds = (void **)ck_realloc(s->seeds,
                                 (s->seeds_count + 1) * sizeof(void *));
  s->seeds[s->seeds_count++] = (void *)q;

}
/* Trim a state sequence (drop consecutive repetitions) and hash it. */

u32 aflnet_state_seq_hash(u32 *seq, u32 count) {

  u32 *trimmed = NULL;
  u32  tcount = 0;

  for (u32 i = 0; i < count; i++) {

    if (i >= 2 && seq[i] == seq[i - 1] && seq[i] == seq[i - 2]) { continue; }

    trimmed = (u32 *)ck_realloc(trimmed, (tcount + 1) * sizeof(u32));
    trimmed[tcount++] = seq[i];

  }

  u32 h = hash32((u8 *)trimmed, tcount * sizeof(u32), 0);
  if (trimmed) { ck_free(trimmed); }
  return h;

}
u8 aflnet_is_path_seen(aflnet_state_t *an, u32 hash) {

  for (u32 i = 0; i < an->path_hash_count; i++) {

    if (an->path_hashes[i] == hash) { return 1; }

  }

  return 0;

}
void aflnet_mark_path_seen(aflnet_state_t *an, u32 hash) {

  if (an->path_hash_count >= an->path_hash_alloc) {

    u32 new_alloc = an->path_hash_alloc ? an->path_hash_alloc * 2 : 64;
    an->path_hashes =
        (u32 *)ck_realloc(an->path_hashes, new_alloc * sizeof(u32));
    an->path_hash_alloc = new_alloc;

  }

  an->path_hashes[an->path_hash_count++] = hash;

}

static void aflnet_record_edge(aflnet_state_t *an, u32 from, u32 to) {

  for (u32 i = 0; i < an->ipsm_edge_count; i++) {

    if (an->ipsm_edges[i].from == from && an->ipsm_edges[i].to == to) {

      return;

    }

  }

  if (an->ipsm_edge_count >= an->ipsm_edge_alloc) {

    u32 new_alloc = an->ipsm_edge_alloc ? an->ipsm_edge_alloc * 2 : 64;
    an->ipsm_edges = (aflnet_edge_t *)ck_realloc(
        an->ipsm_edges, new_alloc * sizeof(aflnet_edge_t));
    an->ipsm_edge_alloc = new_alloc;

  }

  an->ipsm_edges[an->ipsm_edge_count].from = from;
  an->ipsm_edges[an->ipsm_edge_count].to = to;
  an->ipsm_edge_count++;

}

void aflnet_record_sequence_edges(aflnet_state_t *an, u32 *sequence,
                                  u32 count) {

  for (u32 i = 1; i < count; i++) {

    aflnet_record_edge(an, sequence[i - 1], sequence[i]);

  }

}

/* Publish the current IPSM without exposing a partially written file to
   readers.  The temporary file is renamed over ipsm.json only after the
   complete JSON document has been flushed. */
void aflnet_write_ipsm_json(afl_state_t *afl) {

  if (!afl || !afl->aflnet || !afl->out_dir) { return; }

  aflnet_state_t *an = afl->aflnet;
  u8 *tmp = alloc_printf("%s/ipsm.json.tmp", afl->out_dir);
  u8 *dst = alloc_printf("%s/ipsm.json", afl->out_dir);
  FILE *fp = fopen((char *)tmp, "w");

  if (!fp) {

    WARNF("Unable to create IPSM snapshot '%s'", tmp);
    ck_free(tmp);
    ck_free(dst);
    return;

  }

  fputs("{\n  \"states\": [\n", fp);

  for (u32 i = 0; i < an->state_ids_count; i++) {

    state_info_t *state = an->states[i];

    fprintf(fp,
            "    {\"id\": %u, \"covered\": %s, \"paths\": %u, "
            "\"paths_discovered\": %u, \"selected_times\": %u, "
            "\"fuzzs\": %u, \"score\": %u, \"seeds\": %u}%s\n",
            state->id, state->is_covered ? "true" : "false", state->paths,
            state->paths_discovered, state->selected_times, state->fuzzs,
            state->score, state->seeds_count,
            i + 1 < an->state_ids_count ? "," : "");

  }

  fputs("  ],\n  \"edges\": [\n", fp);

  for (u32 i = 0; i < an->ipsm_edge_count; i++) {

    fprintf(fp, "    {\"from\": %u, \"to\": %u}%s\n",
            an->ipsm_edges[i].from, an->ipsm_edges[i].to,
            i + 1 < an->ipsm_edge_count ? "," : "");

  }

  fputs("  ]\n}\n", fp);

  u8 write_failed = ferror(fp);
  if (fclose(fp)) { write_failed = 1; }

  if (write_failed || rename((char *)tmp, (char *)dst)) {

    WARNF("Unable to update IPSM snapshot '%s'", dst);
    unlink((char *)tmp);

  }

  ck_free(tmp);
  ck_free(dst);

}

/* ------------------------------------------------------------------ */
/* state-sequence backends                                            */
/* ------------------------------------------------------------------ */

/* Response-code backend (state_mode == AFLNET_RESP_CODE_MODE): the whole
   state sequence is extracted from the accumulated response bytes in one
   batch at feedback time (aflnet_update_state_feedback -> finalize), and
   each region is annotated by re-extracting from the cumulative response
   bytes up to that message. */

static void aflnet_respcode_reset(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (an->state_sequence) {

    ck_free(an->state_sequence);
    an->state_sequence = NULL;

  }

  an->state_count = 0;

}

/* batch backend: nothing to capture during the message exchange */
static void aflnet_respcode_begin(afl_state_t *afl) { (void)afl; }
static void aflnet_respcode_on_recv(afl_state_t *afl) { (void)afl; }
static void aflnet_respcode_end(afl_state_t *afl) { (void)afl; }

static void aflnet_respcode_finalize(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  /* drop any stale sequence (e.g. a run that produced no server response)
     so a response-less run never reuses old state data */
  aflnet_respcode_reset(afl);

  if (!afl->aflnet->aflnet_extract_response_codes) { return; }
  if (!an->response_buf || an->response_buf_size <= 0) { return; }

  /* extract the state sequence from the whole response */
  an->state_sequence = afl->aflnet->aflnet_extract_response_codes(
      (unsigned char *)an->response_buf,
      (unsigned int)an->response_buf_size, &an->state_count);

}

static unsigned int *aflnet_respcode_region_states(afl_state_t *afl,
                                                   u32 region_idx,
                                                   u32 *count) {

  aflnet_state_t *an = afl->aflnet;

  if (!an->response_buf || !an->response_bytes) { return NULL; }
  if (!afl->aflnet->aflnet_extract_response_codes) { return NULL; }

  u32 acc = an->response_bytes[region_idx];
  u32 prev_acc = (region_idx > 0) ? an->response_bytes[region_idx - 1] : 0;

  if (acc == 0 || (acc - prev_acc) == 0) { return NULL; }

  unsigned int cnt = 0;
  unsigned int *seq = afl->aflnet->aflnet_extract_response_codes(
      (unsigned char *)an->response_buf, acc, &cnt);

  *count = cnt;
  return seq;

}

const aflnet_state_backend_t aflnet_respcode_backend = {

    .reset                = aflnet_respcode_reset,
    .begin                = aflnet_respcode_begin,
    .on_recv              = aflnet_respcode_on_recv,
    .end                  = aflnet_respcode_end,
    .finalize             = aflnet_respcode_finalize,
    .region_states        = aflnet_respcode_region_states,

};

/* Bind the state-sequence backend from the current state_mode.  Call
   whenever state_mode is (re)set. */
void aflnet_state_bind_backend(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (!an) { return; }

  switch (an->state_mode) {

    case AFLNET_RESP_CODE_MODE:

      an->state_backend = &aflnet_respcode_backend;
      break;

    case AFLNET_STATE_VAR_MODE:

      an->state_backend = &aflnet_statevar_backend;
      break;

    default:

      an->state_backend = NULL;
      break;

  }

}

/* ------------------------------------------------------------------ */
/* IPSM update                                                        */
/* ------------------------------------------------------------------ */

/* Annotate the regions of q with per-region cumulative state subsequences.
   Both state_mode == AFLNET_RESP_CODE_MODE and state_mode == AFLNET_STATE_VAR_MODE produce the same structure: for
   region i the annotation is the cumulative subsequence of all state ids
   observed up to and including message i's response.  The only difference is
   the source of the state ids:
     - state_mode == AFLNET_RESP_CODE_MODE: extracted from response_buf via extract_response_codes
     - state_mode == AFLNET_STATE_VAR_MODE: taken from state_sequence (one entry per recv, built
                        in real time by aflnet_send_over_network) */

static void aflnet_annotate_regions(afl_state_t *afl, struct queue_entry *q) {

  aflnet_state_t *an = afl->aflnet;

  if (!q || !q->regions || !q->region_count) { return; }
  if (!an->messages_sent) { return; }

  u32 sent = MIN(an->messages_sent, q->region_count);

  for (u32 i = 0; i < sent; i++) {

    /* free previous annotation */
    if (q->regions[i].state_sequence) {

      ck_free(q->regions[i].state_sequence);
      q->regions[i].state_sequence = NULL;
      q->regions[i].state_count = 0;

    }

    /* ask the bound backend for region i's cumulative state subsequence:
       - response-code backend: extract from the cumulative response bytes
       - state-variable backend: copy state_sequence[0..i] */
    if (an->state_backend && an->state_backend->region_states) {

      unsigned int cnt = 0;
      q->regions[i].state_sequence =
          an->state_backend->region_states(afl, i, &cnt);
      q->regions[i].state_count = cnt;

    }

  }

}

/* Count the states visited by the latest run.  A state is counted once per
   run even when the sequence revisits it. */
void aflnet_update_fuzzs(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;
  if (!an || !an->state_sequence) { return; }

  for (u32 i = 0; i < an->state_count; i++) {

    u8 seen = 0;
    for (u32 j = 0; j < i; j++) {

      if (an->state_sequence[j] == an->state_sequence[i]) {

        seen = 1;
        break;

      }

    }

    if (seen) { continue; }

    u32 sidx = aflnet_get_state_index(an, an->state_sequence[i]);
    if (sidx != (u32)-1) { an->states[sidx]->fuzzs++; }

  }

}

/* Register a seed (and its region annotations) with the IPSM. */

void aflnet_register_seed(afl_state_t *afl, struct queue_entry *q) {

  aflnet_state_t *an = afl->aflnet;

  if (!afl->afl_env.aflnet_mode || !q) { return; }

  if (!an->state_sequence) { return; }

  /* annotate the seed's regions from the most recent run's state
     sequence (both modes use the same annotation path; the per-mode
     differences are handled inside aflnet_annotate_regions) */
  aflnet_annotate_regions(afl, q);

  /* every seed reaches the initial state */
  aflnet_ensure_state(an, 0);

  if (q->id >= an->fuzzed_map_qentries) {

    aflnet_expand_was_fuzzed_map(an, 0,
                                 q->id + 1 - an->fuzzed_map_qentries);

  }

  aflnet_state_add_seed(an, 0, q);
  an->was_fuzzed_map[aflnet_get_state_index(an, 0)][q->id] = 0;

  /* register per-region reachability */
  for (u32 i = 0; i < q->region_count; i++) {

    if (q->regions[i].state_count > 0) {

      u32 reachable =
          q->regions[i].state_sequence[q->regions[i].state_count - 1];

      aflnet_ensure_state(an, reachable);
      aflnet_state_add_seed(an, reachable, q);

      u32 sidx = aflnet_get_state_index(an, reachable);
      if (sidx != (u32)-1) { an->was_fuzzed_map[sidx][q->id] = 0; }

    }

  }

}

/* Record that q has been fuzzed for the currently targeted state.  The map
   is sparse and may lag behind queue IDs imported from another instance. */
void aflnet_mark_seed_fuzzed(afl_state_t *afl, struct queue_entry *q) {

  if (!afl || !afl->afl_env.aflnet_mode || !afl->aflnet || !q) { return; }

  aflnet_state_t *an = afl->aflnet;
  if (!an->state_mode) { return; }

  u32 sidx = aflnet_get_state_index(an, an->target_state_id);
  if (sidx == (u32)-1) { return; }

  if (q->id >= an->fuzzed_map_qentries) {

    aflnet_expand_was_fuzzed_map(an, 0,
                                 q->id + 1 - an->fuzzed_map_qentries);

  }

  an->was_fuzzed_map[sidx][q->id] = 1;

}

/* Whether q has already been fuzzed for the currently targeted state. */
u8 aflnet_is_seed_fuzzed(afl_state_t *afl, struct queue_entry *q) {

  if (!afl || !afl->afl_env.aflnet_mode || !afl->aflnet || !q) { return 0; }

  aflnet_state_t *an = afl->aflnet;
  if (!an->state_mode) { return 0; }

  u32 sidx = aflnet_get_state_index(an, an->target_state_id);
  if (sidx == (u32)-1 || q->id >= an->fuzzed_map_qentries) { return 0; }

  return an->was_fuzzed_map[sidx][q->id] == 1;

}

/* Save the first max_count messages of a test case.  In replay mode each
   message gets the native 4-byte length prefix consumed by aflnet-replay;
   otherwise the selected messages are concatenated unchanged. */
u32 aflnet_save_testcase_to_file(afl_state_t *afl, u8 *mem, u32 len,
                                 u8 *fname, u8 replay_enabled, u32 max_count) {

  if (!afl || !afl->aflnet || !afl->aflnet->aflnet_extract_requests || !mem ||
      !len || !fname || !max_count) {

    return 0;

  }

  unsigned int region_count = 0;
  region_t    *regions = afl->aflnet->aflnet_extract_requests(
      mem, len, &region_count);

  if (!regions || !region_count) {

    if (regions) { ck_free(regions); }
    return 0;

  }

  u32 write_count = MIN(region_count, max_count);
  int fd = open((char *)fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) {

    ck_free(regions);
    PFATAL("Unable to create '%s'", fname);

  }

  u32 bytes_written = 0;

  for (u32 i = 0; i < write_count; i++) {

    if (regions[i].start_byte < 0 || regions[i].end_byte <
                                          regions[i].start_byte ||
        (u32)regions[i].end_byte >= len) {

      continue;

    }

    u32 msg_len = (u32)regions[i].end_byte -
                  (u32)regions[i].start_byte + 1;

    if (replay_enabled) {

      ck_write(fd, &msg_len, sizeof(msg_len), fname);
      bytes_written += sizeof(msg_len);

    }

    ck_write(fd, mem + regions[i].start_byte, msg_len, fname);
    bytes_written += msg_len;

  }

  close(fd);
  ck_free(regions);
  return bytes_written;

}

void aflnet_save_replayable_fault(afl_state_t *afl, u8 *mem, u32 len,
                                  const u8 *raw_fname, u8 is_crash) {

  if (!afl || !afl->afl_env.aflnet_mode || !afl->aflnet || !mem || !len ||
      !raw_fname || !afl->aflnet->messages_sent) {

    return;

  }

  const char *raw_name = strrchr((const char *)raw_fname, '/');
  raw_name = raw_name ? raw_name + 1 : (const char *)raw_fname;

  u8 *replay_fname =
      alloc_printf("%s/%s/%s", afl->out_dir,
                   is_crash ? "replayable-crashes" : "replayable-hangs",
                   raw_name);
  aflnet_save_testcase_to_file(afl, mem, len, replay_fname, 1,
                               afl->aflnet->messages_sent);
  ck_free(replay_fname);

}

/* aflnet_update_ipsm() and aflnet_update_state_feedback() are the public
   IPSM entry points used by the rest of the fuzzer; they live in
   src/afl-fuzz-aflnet.c and call back into the helpers above. */
