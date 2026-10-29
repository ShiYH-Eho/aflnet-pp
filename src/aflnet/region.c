/* aflnet/region.c - AFLNet region-level (M1/M2/M3) mutation support.

   Moved out of src/afl-fuzz-aflnet.c into the src/aflnet/ module tree:

     - aflnet_prepare_region_fuzz(): identify M1 (prefix), M2 (target
       subsequence) and M3 (suffix) of the current testcase based on the
       targeted state, build the M2 buffer and remember M1/M3.  With
       protocol grammar templates enabled (AFLNET_GRAMMAR) M2 is then
       narrowed further down to one mutable field of the template that
       matches it, see the grammar block in aflnet_prepare_region_fuzz().
     - aflnet_reassemble_region(): reassemble the full message chain
       (M1 + mutated M2 + M3).

   Used by the custom-mutator module (module.c) via afl_custom_fuzz_count /
   afl_custom_fuzz, and by fuzz_one() (afl-fuzz-one.c) through
   aflnet_prepare_region_fuzz_or_whole() so the whole mutation pipeline runs
   on M2 only. */

#include <string.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "common.h"
#include "afl-fuzz.h"
#include "aflnet.h"
#include "aflnet-internal.h"
#include "alloc-inl.h"

/* Identify M1 (prefix), M2 (target subsequence) and M3 (suffix) of the
   current testcase based on the targeted state, build the M2 buffer and
   remember M1/M3 so that common_fuzz_stuff() can reassemble the full
   message chain. Returns 0 on success, 1 if the seed has to be skipped. */

u8 aflnet_prepare_region_fuzz(afl_state_t *afl, u8 *in_buf, u32 in_len,
                              u8 **out_buf, u32 *out_len) {

  aflnet_state_t   *an = afl->aflnet;
  struct queue_entry *q = afl->queue_cur;
  u32                M2_start_region_ID = 0, M2_region_count = 0;
  u32                i;

  if (!q || !q->regions || !q->region_count) { return 1; }
  if (!in_buf || !in_len) { return 1; }

  if (an->target_state_id == 0) {

    /* M1 is empty: M2 is the longest prefix of regions with the same
       annotation as the first region */
    M2_start_region_ID = 0;
    for (i = 0; i < q->region_count; i++) {

      if (q->regions[i].state_count != q->regions[0].state_count) { break; }
      M2_region_count++;

    }

    if (M2_region_count == 0) { M2_region_count = 1; }

  } else {

    /* locate the first region whose reachable state equals the target */
    for (i = 0; i < q->region_count; i++) {

      u32 rsc = q->regions[i].state_count;
      if (rsc > 0) {

        u32 reachable = q->regions[i].state_sequence[rsc - 1];
        M2_start_region_ID++;
        if (reachable == an->target_state_id) { break; }

      } else {

        /* unannotated region: cannot safely determine M2 */
        return 1;

      }

    }

    if (M2_start_region_ID >= q->region_count) { return 1; }

    /* M2 covers all consecutive regions with the same annotation */
    for (i = M2_start_region_ID; i < q->region_count; i++) {

      if (q->regions[i].state_count !=
          q->regions[M2_start_region_ID].state_count) {

        break;

      }

      M2_region_count++;

    }

  }

  if (M2_region_count == 0) { return 1; }
  if (M2_start_region_ID + M2_region_count > q->region_count) {

    M2_region_count = q->region_count - M2_start_region_ID;

  }

  /* compute region byte lengths */
  u32 m1_len = 0, m2_len = 0, m3_len = 0;
  for (i = 0; i < M2_start_region_ID; i++) {

    m1_len += (u32)(q->regions[i].end_byte - q->regions[i].start_byte + 1);

  }

  for (i = M2_start_region_ID; i < M2_start_region_ID + M2_region_count; i++) {

    m2_len += (u32)(q->regions[i].end_byte - q->regions[i].start_byte + 1);

  }

  for (i = M2_start_region_ID + M2_region_count; i < q->region_count; i++) {

    m3_len += (u32)(q->regions[i].end_byte - q->regions[i].start_byte + 1);

  }

  /* M1 */
  an->region_m1 =
      (u8 *)afl_realloc((void **)&an->region_m1, m1_len ? m1_len : 1);
  if (unlikely(!an->region_m1)) { return 1; PFATAL("alloc region_m1"); }
  u32 off = 0;
  for (i = 0; i < M2_start_region_ID; i++) {

    u32 rl = (u32)(q->regions[i].end_byte - q->regions[i].start_byte + 1);
    memcpy(an->region_m1 + off, in_buf + q->regions[i].start_byte, rl);
    off += rl;

  }

  an->region_m1_len = m1_len;

  /* M3 */
  an->region_m3 =
      (u8 *)afl_realloc((void **)&an->region_m3, m3_len ? m3_len : 1);
  if (unlikely(!an->region_m3)) { return 1; PFATAL("alloc region_m3"); }
  off = 0;
  for (i = M2_start_region_ID + M2_region_count; i < q->region_count; i++) {

    u32 rl = (u32)(q->regions[i].end_byte - q->regions[i].start_byte + 1);
    memcpy(an->region_m3 + off, in_buf + q->regions[i].start_byte, rl);
    off += rl;

  }

  an->region_m3_len = m3_len;

  /* M2 (the mutation target) */
  an->region_m2 =
      (u8 *)afl_realloc((void **)&an->region_m2, m2_len ? m2_len : 1);
  if (unlikely(!an->region_m2)) { return 1; PFATAL("alloc region_m2"); }
  off = 0;
  for (i = M2_start_region_ID; i < M2_start_region_ID + M2_region_count; i++) {

    u32 rl = (u32)(q->regions[i].end_byte - q->regions[i].start_byte + 1);
    memcpy(an->region_m2 + off, in_buf + q->regions[i].start_byte, rl);
    off += rl;

  }

  /* Protocol grammar template guided mutation (AFLNET_GRAMMAR): when a
     template matches the mutation target M2, narrow M2 down to one of the
     mutable fields that the template describes, by folding the bytes before
     and after that field into M1/M3.  The whole mutation pipeline
     (deterministic stages, custom mutators, havoc, splicing) then only ever
     sees the field, and aflnet_reassemble_region() rebuilds the message, so
     the grammar only has to be plugged into the AFLNet module - the core
     fuzzer (src/afl-fuzz-one.c) is not involved.  This mirrors ChatState's
     parse_buffer() + havoc-exploit ranges; without a matching template (or
     when the exploration roll fails) M2 stays the whole message. */
  if (grammar_templates_enabled() && grammar_roll_guided(afl) &&
      grammar_stage_begin(an->region_m2, m2_len)) {

    u32 win_start = 0, win_len = 0;

    if (grammar_stage_window(afl, &win_start, &win_len) && win_len &&
        win_start + win_len <= m2_len) {

      u32 suffix_len = m2_len - win_start - win_len;
      u8 *field;
      u8 *tmp;

      /* the field is copied out first: M1/M2/M3 are realloc'ed below */
      field = ck_alloc(win_len);
      memcpy(field, an->region_m2 + win_start, win_len);

      /* M1 = M1 + the part of M2 that stays in front of the field */
      tmp = (u8 *)afl_realloc((void **)&an->region_m1,
                              (m1_len + win_start) ? (m1_len + win_start) : 1);
      if (unlikely(!tmp)) { PFATAL("alloc region_m1"); }
      an->region_m1 = tmp;
      memcpy(an->region_m1 + m1_len, an->region_m2, win_start);
      an->region_m1_len = m1_len + win_start;

      /* M3 = the part of M2 behind the field + M3 */
      tmp = (u8 *)afl_realloc((void **)&an->region_m3,
                              (m3_len + suffix_len) ? (m3_len + suffix_len) : 1);
      if (unlikely(!tmp)) { PFATAL("alloc region_m3"); }
      an->region_m3 = tmp;
      memmove(an->region_m3 + suffix_len, an->region_m3, m3_len);
      memcpy(an->region_m3, an->region_m2 + win_start + win_len, suffix_len);
      an->region_m3_len = m3_len + suffix_len;

      /* M2 = the mutable field itself */
      tmp = (u8 *)afl_realloc((void **)&an->region_m2, win_len);
      if (unlikely(!tmp)) { PFATAL("alloc region_m2"); }
      an->region_m2 = tmp;
      memcpy(an->region_m2, field, win_len);
      ck_free(field);

      m2_len = win_len;

      ACTF(
          "Grammar template '%s' matched M2: mutating field [%u,%u) of %u "
          "mutable window(s)",
          grammar_stage_template(), win_start, win_start + win_len,
          grammar_stage_count());

    }

  }

  an->region_m2_len = m2_len;
  *out_buf = an->region_m2;
  *out_len = m2_len;

  /* entering M2 mode: common_fuzz_stuff() reassembles M1+M2+M3 while the
     mutation pipeline runs on M2 */
  an->region_mode = 1;

  /* remember M2's first region id for the sock2shm send path (is_M2 gate) */
  an->M2_start_region_ID = M2_start_region_ID;

  return 0;

}

/* Like aflnet_prepare_region_fuzz, but never fails on "cannot determine M2":
   if the seed cannot be split (unannotated region, target state only reached
   at the very last region, or no regions at all), clear region_mode so the
   caller falls back to mutating the whole input with the ORIGINAL (full
   message chain) mutation pipeline instead of dropping the seed.  Returns 0
   on success (region_mode==1 -> M2 mode with the out buffers set;
   region_mode==0 -> full-chain mode), 1 only for empty/unreadable input.
   Used by fuzz_one() (afl-fuzz-one.c). */
u8 aflnet_prepare_region_fuzz_or_whole(afl_state_t *afl, u8 *in_buf,
                                       u32 in_len, u8 **out_buf,
                                       u32 *out_len) {

  aflnet_state_t *an = afl->aflnet;

  if (!an || !in_buf || !in_len) { return 1; }

  if (!aflnet_prepare_region_fuzz(afl, in_buf, in_len, out_buf, out_len)) {

    /* M2 split OK: region_mode is 1, caller runs the pipeline on M2 */
    return 0;

  }

  /* cannot split: fall back to the original full-chain mutation path */
  an->region_mode = 0;
  *out_buf = NULL;
  *out_len = 0;
  return 0;

}

/* Reassemble the full message chain (M1 + mutated M2 + M3) and return it.
   Called by common_fuzz_stuff() (afl-fuzz-run.c) when region_mode is active,
   so both the network send (late_send) and the saved queue entry see the
   full message chain. */

u8 *aflnet_reassemble_region(afl_state_t *afl, u8 *m2_buf, u32 m2_len,
                             u32 *full_len) {

  aflnet_state_t *an = afl->aflnet;
  u32             len = an->region_m1_len + m2_len + an->region_m3_len;
  u8             *full = afl_realloc((void **)&an->region_full, len ? len : 1);

  memcpy(full, an->region_m1, an->region_m1_len);
  memcpy(full + an->region_m1_len, m2_buf, m2_len);
  memcpy(full + an->region_m1_len + m2_len, an->region_m3, an->region_m3_len);

  *full_len = len;
  return full;

}
