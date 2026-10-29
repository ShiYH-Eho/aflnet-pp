/* aflnet-internal.h - declarations shared between the aflnet implementation
   translation units under src/aflnet/.

   These are internal to the AFLNet module and are NOT part of the public
   API declared in include/aflnet.h. */

#ifndef AFLNET_INTERNAL_H
#define AFLNET_INTERNAL_H

#include "types.h"
#include "config.h"
#include "aflnet.h"

#ifdef __cplusplus
extern "C" {
#endif

/* initial capacity of the message-code map (response_codes.c) */
#define AFLNET_CODE_MAP_INIT_CAP 128U

/* DTLS 1.2 record content types and message markers (shared by
   protocols.c and response_codes.c) */
#define CCS_CONTENT_TYPE 0x14
#define ALERT_CONTENT_TYPE 0x15
#define HS_CONTENT_TYPE 0x16
#define APPLICATION_CONTENT_TYPE 0x17
#define HEARTBEAT_CONTENT_TYPE 0x18

#define UNKNOWN_CONTENT_TYPE 0xFF
#define UNKNOWN_MESSAGE_TYPE 0xFF
#define MALFORMED_MESSAGE_TYPE 0xFE

extern unsigned char dtls12_version[2];

/* ---- state machine core helpers (state.c) ---- */
u32 aflnet_get_state_index(aflnet_state_t *an, u32 state_id);
void aflnet_expand_was_fuzzed_map(aflnet_state_t *an, u32 new_states,
                                  u32 new_qentries);
void aflnet_ensure_state(aflnet_state_t *an, u32 state_id);
void aflnet_state_add_seed(aflnet_state_t *an, u32 state_id,
                           struct queue_entry *q);
u32 aflnet_state_seq_hash(u32 *seq, u32 count);
u8 aflnet_is_path_seen(aflnet_state_t *an, u32 hash);
void aflnet_mark_path_seen(aflnet_state_t *an, u32 hash);
void aflnet_record_sequence_edges(aflnet_state_t *an, u32 *sequence,
                                  u32 count);

/* Increment the per-state fuzz counter for each distinct state visited by the
   most recent run's state sequence.  Called from feedback.c after every run;
   feeds the FAVOR state score. */
void aflnet_update_fuzzs(struct afl_state *afl);

/* State-sequence backends (aflnet_state_backend_t).  The response-code
   backend lives in state.c, the state-variable backend in statevar.c.
   Bound to aflnet_state_t.state_backend from state_mode by
   aflnet_state_bind_backend(); all callers go through the vtable, never
   through these instances directly. */
extern const aflnet_state_backend_t aflnet_respcode_backend;
extern const aflnet_state_backend_t aflnet_statevar_backend;

/* Bind aflnet_state_t.state_backend from the current state_mode
   (NULL for AFLNET_NO_STATE_MODE).  Call whenever state_mode is (re)set,
   i.e. in aflnet_state_init and after parsing AFLNET_STATE_MODE. */
void aflnet_state_bind_backend(struct afl_state *afl);

/* Initialize / destroy the state-variable SHM (called from state init/deinit). */
void aflnet_statevar_shm_init(struct afl_state *afl);
void aflnet_statevar_shm_deinit(struct afl_state *afl);

/* ---- real-socket per-message dispatch (net.c), used by config.c ---- */
int aflnet_sock_init_session(struct afl_state *afl);
int aflnet_sock_send_msg(struct afl_state *afl, const u8 *mem,
                         unsigned int len);
int aflnet_sock_recv_msg(struct afl_state *afl, char **response_buf,
                         unsigned int *response_buf_size);

/* AFLNET_CLEANUP_SCRIPT: run the user-supplied cleanup script in the fuzzer
   process before each target execution.  Called from net.c
   (aflnet_send_over_network) before the message exchange. */
void aflnet_run_cleanup(struct afl_state *afl);


/* sock_mode == AFLNET_SOCK2SHM: create the msg/check SHM segments, export the
   __AFL_SHM_MSG_ID / __AFL_SHM_CHECK_ID env vars and attach them so the
   preloaded sockhook engages the shared-SHM exchange.  The target port /
   protocol type (ENV_NETPORT / ENV_PROTOCOL_TYPE) and the sockhook.so
   preload itself are handled by aflnet_sockhook_preload() (which runs for
   every mode).  Called from aflnet_configure_from_env. */
void aflnet_sock2shm_setup(struct afl_state *afl);

/* AFLNET_SHM_SYNC=1 on top of sock_mode == AFLNET_SOCK: create the same
   msg/check SHM segments as sock2shm but leave the message exchange on the
   real socket.  The preloaded sockhook then only arms its rendezvous, so the
   target can tell the fuzzer when it has accepted the client and when it is
   ready for the next request.  Called from aflnet_configure_from_env. */
void aflnet_sock_shm_sync_setup(struct afl_state *afl);

/* The standalone sockhook rendezvous (sock_mode == 1 + AFLNET_SHM_SYNC=1).
   aflnet_configure_from_env() installs it in aflnet_state_t.sync_ops for that
   configuration and leaves sync_ops NULL everywhere else, so net.c only has to
   call through the table. */
extern const aflnet_sync_ops_t aflnet_shm_sync_ops;

/* Preload sockhook.so into the target for every server mode and export the
   default target-facing configuration the preloaded library needs: ENV_NETPORT
   (the port parsed from AFLNET_URL) and ENV_PROTOCOL_TYPE (TCP/UDP derived
   from AFLNET_PROTOCOL).  sock_mode == AFLNET_SOCK2SHM additionally attaches
   the msg/check segments (aflnet_sock2shm_setup) which makes the library
   redirect the session I/O through shared SHM; every other mode keeps it
   inert (plain real-socket server).  Used for both AFLNET_SOCK and
   AFLNET_SOCK2SHM; AFLNET_LIBDESOCK preloads libaflppdesock.so instead. */
void aflnet_sockhook_preload(struct afl_state *afl);

/* Reset the shared msg segment before each target run, for sock_mode ==
   AFLNET_SOCK2SHM and for the standalone sync (sock_mode=1 +
   AFLNET_SHM_SYNC=1, which shares the same segments).  It runs in the
   module's afl_custom_post_run() (src/aflnet/module.c), i.e. after the
   previous run finished and before the forkserver spawns the next child. */
int aflnet_sock2shm_init_session(struct afl_state *afl);

/* sock_mode == AFLNET_SOCK2SHM: connect to the server and exchange the
   request messages through the shared msg SHM, capturing responses.
   Called from aflnet_send_over_network. */
void aflnet_sock2shm_send(struct afl_state *afl, const u8 *mem, size_t len);

/* sock_mode == AFLNET_SOCK2SHM: per-message send/recv implementations used
   as aflnet_state_t.aflnet_send / aflnet_recv.  send_msg applies the M2
   gating then writes the message into data1 (returns bytes written or -1);
   recv_msg reads one response from data2 (returns 0 ok, 1 wait timeout,
   -1 no response available). */
int aflnet_sock2shm_send_msg(struct afl_state *afl, const u8 *mem,
                             unsigned int len);
int aflnet_sock2shm_recv_msg(struct afl_state *afl, char **response_buf,
                             unsigned int *response_buf_size);

/* sock_mode == AFLNET_SOCK2SHM: detach / destroy the shared segments. */
void aflnet_sock2shm_deinit(struct afl_state *afl);

/* sock_mode == AFLNET_LIBDESOCK: set DESOCK_PORT and preload
   libaflppdesock.so into the target.  Called from aflnet_configure_from_env. */
void aflnet_desock_setup(struct afl_state *afl);

/* sock_mode == AFLNET_SOCK2SHM or standalone sync: notify a still-running
   server that the fuzzer timed out (is_end=3, notify SERVER to release a
   target parked on CLIENT). */
void aflnet_sock2shm_notify_timeout(struct afl_state *afl);

/* sock_mode == AFLNET_SOCK2SHM: normal end of the exchange (is_end=1 and
   SERVER, which releases a target parked on CLIENT).  sock_mode=2 implies the
   SHM rendezvous, so its cleanup uses this even though its wait ops live in
   the s2s message helpers rather than in aflnet_state_t.sync_ops. */
void aflnet_sock2shm_notify_end(struct afl_state *afl);

/* 1 if this run exchanges messages through sock2shm (sock_mode=2 and the SHM
   segments exist); used to skip the physical testcase file/stdin write. */
int aflnet_sock2shm_active(struct afl_state *afl);

/* ---- protocol grammar templates (utils/grammar.c) ----

   Optional module: inactive unless the AFLNET_GRAMMAR option provides a
   template path.  A template that matches the mutation target M2 makes the
   region selection (region.c) narrow M2 to one of the mutable fields the
   template describes; see the header comment of utils/grammar.c for the
   template file format and the environment variables.  If the grammar
   directory contains .binary-formats.json, its probes select the binary
   message type before regex fallback. */
#define GRAMMAR_DEFAULT_EXPLORE_PROB 50

/* Import the templates from the AFLNET_GRAMMAR option (directory or single
   file), read AFLNET_GRAMMAR_EXPLORE_PROB and derive afl->input_mode (text /
   binary) from the AFLNet protocol type.  Returns 1 when at least one
   template could be used, 0 when the feature stays disabled (no option given,
   no usable template, or the binary was built without PCRE2).  Called from
   aflnet_configure_from_env (config.c). */
u8   grammar_templates_init(struct afl_state *afl, const char *protocol);

/* Release all templates (not required at process exit, useful for tests). */
void grammar_templates_deinit(void);

/* Number of imported templates. */
u32 grammar_templates_count(void);

/* 1 when grammar guided mutation is available (templates imported). */
u8 grammar_templates_enabled(void);

/* Random roll: 1 = this fuzz iteration narrows M2 to a template field, 0 =
   keep M2 as it is (whole-message mutation, "exploration").  Always 0 when
   the feature is disabled. */
u8 grammar_roll_guided(struct afl_state *afl);

/* Decompose the mutation target (M2) with the first matching template.
   Returns 1 when a template matched and at least one mutable window is
   available, 0 otherwise (callers then keep mutating the whole M2). */
u8 grammar_stage_begin(const u8 *seed, u32 len);

/* Number of mutable windows of the mutation target prepared by
   grammar_stage_begin(). */
u32 grammar_stage_count(void);

/* Name (file name) of the template that matched, NULL when none did. */
const char *grammar_stage_template(void);

/* Pick a random mutable window of the prepared mutation target.  Returns 1
   and fills start/len on success, 0 when there is no usable window. */
u8 grammar_stage_window(struct afl_state *afl, u32 *start, u32 *len);

/* Drop the prepared decomposition. */
void grammar_stage_end(void);

#ifdef __cplusplus
}
#endif

#endif /* AFLNET_INTERNAL_H */
