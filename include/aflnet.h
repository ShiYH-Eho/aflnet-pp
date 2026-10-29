#ifndef AFLNET_H
#define AFLNET_H

#include "types.h"
#include "config.h"
#include "sharedmem.h"
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations to break the circular dependency with afl-fuzz.h
   (afl-fuzz.h includes this header and defines afl_state_t and queue_entry
   afterwards).  The struct-tag form is used so the declarations match the
   `afl_state_t` typedef in afl-fuzz.h without needing a typedef here. */
struct afl_state;
struct queue_entry;
struct custom_mutator;


/* ------------------------------------------------------------------ */
/* AFLNet state-aware fuzzing                                         */
/* ------------------------------------------------------------------ */

typedef struct {
  int           start_byte;
  int           end_byte;
  char          modifiable;
  unsigned int *state_sequence;
  unsigned int  state_count;
} region_t;

typedef region_t *(*aflnet_extract_requests_fn)(unsigned char *buf,
                                                unsigned int  buf_size,
                                                unsigned int *region_count_ref);

typedef unsigned int *(*aflnet_extract_response_codes_fn)(unsigned char *buf,
                                                          unsigned int  buf_size,
                                                          unsigned int *state_count_ref);

/* per-message send/recv dispatch: how one request message is delivered to
   the target and how the corresponding response is captured.  Assigned in
   aflnet_configure_from_env() from sock_mode:
     - AFLNET_SOCK      -> aflnet_sock_send / aflnet_sock_recv (real socket)
     - AFLNET_SOCK2SHM  -> aflnet_sock2shm_send_msg / aflnet_sock2shm_recv_msg
     - AFLNET_LIBDESOCK -> NULL / NULL (testcase delivered via stdin)      */
typedef int (*aflnet_send_fn)(struct afl_state *afl, const u8 *mem,
                              unsigned int len);
typedef int (*aflnet_recv_fn)(struct afl_state *afl, char **response_buf,
                              unsigned int *response_buf_size);
typedef int (*aflnet_init_session_fn)(struct afl_state *afl);

/* Optional client/server rendezvous used by the real-socket mode with
   AFLNET_SHM_SYNC=1.  A NULL sync_ops pointer keeps the plain socket path. */
typedef struct aflnet_sync_ops {

  /* Wait (bounded) until the target yields the turn (CLIENT), i.e. until it
     has entered recv and is ready for the next request.  The fuzzer must not
     send before this succeeds; SERVER owns the session by default and CLIENT
     is the explicit hand-over edge.  Returns 1 when the turn arrived. */
  int (*wait_request_turn)(struct afl_state *afl);

  /* Wait (bounded) until the target has finished its current output and
     yielded the turn (CLIENT), i.e. it is back in recv.  Used before the
     real-socket response read.  A timeout is not fatal: the response bytes
     may already be on the wire, so the caller proceeds to read anyway. */
  int (*wait_response_ready)(struct afl_state *afl);

  int (*wait_ready)(struct afl_state *afl);
  void (*notify_request)(struct afl_state *afl);
  void (*notify_end)(struct afl_state *afl);

} aflnet_sync_ops_t;

/* State-sequence backend: abstracts the two ways the IPSM learns the
   per-run state sequence so the rest of the machinery (aflnet_late_send,
   sock2shm, aflnet_update_state_feedback, region annotation) is
   mode-agnostic:

     - response-code backend (state_mode == AFLNET_RESP_CODE_MODE): the
       whole state sequence is extracted from the accumulated response
       bytes in one batch at feedback time.
     - state-variable backend (state_mode == AFLNET_STATE_VAR_MODE): a state
       id is derived (hash of the state-variable SHM) after each recv and
       appended to the sequence incrementally during the exchange.

   The ops take the fuzzer state; a backend carries no per-instance data
   (everything it operates on lives in aflnet_state_t).  The instance
   bound from state_mode is stored in aflnet_state_t.state_backend. */

typedef struct aflnet_state_backend {

  /* start of a run: drop per-run state from the previous run (state
     sequence; the state-variable backend also zeroes its SHM). */
  void (*reset)(struct afl_state *afl);

  /* before the first request is sent: capture the initial state. */
  void (*begin)(struct afl_state *afl);

  /* after each server response: capture the current state.  No-op for the
     batch (response-code) backend. */
  void (*on_recv)(struct afl_state *afl);

  /* after the last response of the run: capture the terminal state. */
  void (*end)(struct afl_state *afl);

  /* after the whole exchange: make state_sequence/state_count hold the
     complete per-run state sequence.  The response-code backend clears any
     stale sequence and extracts the codes from response_buf here; the
     state-variable backend is a no-op (on_recv already built it). */
  void (*finalize)(struct afl_state *afl);

  /* per-region cumulative state subsequence for region annotation.
     Returns a freshly allocated array (caller frees with ck_free) and sets
     *count, or returns NULL if the region cannot be annotated. */
  unsigned int *(*region_states)(struct afl_state *afl, u32 region_idx,
                                 u32 *count);

} aflnet_state_backend_t;

/* Per-state statistics used by the inferred protocol state machine (IPSM) */
typedef struct state_info {

  u32 id;                       /* state id (mapped response code)         */
  u8  is_covered;               /* has this state been covered            */
  u32 paths;                    /* # paths exercising this state          */
  u32 paths_discovered;         /* # new paths discovered here            */
  u32 selected_times;           /* # times targeted for fuzzing           */
  u32 fuzzs;                    /* # inputs generated for this state      */
  u32 score;                    /* current score of the state             */
  u32 selected_seed_index;      /* recently selected seed index           */
  void **seeds;                 /* seeds reaching this state (queue_entry*)*/
  u32 seeds_count;              /* size of the seeds array                */

} state_info_t;

/* Directed transition discovered in an IPSM state sequence. */
typedef struct aflnet_edge {

  u32 from;
  u32 to;

} aflnet_edge_t;

/* State mode */
enum{
   AFLNET_NO_STATE_MODE=0,      /* state-aware mode disabled               */
   AFLNET_RESP_CODE_MODE=1,       /* state-aware mode enabled                */
   AFLNET_STATE_VAR_MODE=2       /* state variable feedback (state_mode==2) */
};

/* sock_mode: how the fuzzer exchanges network messages with the target */
enum{
   AFLNET_LIBDESOCK=0,          /* target preloaded with libaflppdesock: the
                                   testcase is delivered through stdin       */
   AFLNET_SOCK=1,               /* default AFLNet: real-socket I/O in
                                   aflnet_late_send                         */
   AFLNET_SOCK2SHM=2            /* target preloaded with sock2shm.so: message
                                   exchange through a shared msg SHM         */
};
/* State-aware selection / feedback algorithms (mirrors AFLNet) */
enum {

  /* 00 */ AFLNET_INVALID_SELECTION,
  /* 01 */ AFLNET_RANDOM_SELECTION,
  /* 02 */ AFLNET_ROUND_ROBIN,
  /* 03 */ AFLNET_FAVOR

};

enum {

  /* 00 */ AFLNET_INVALID_FEEDBACK,
  /* 01 */ AFLNET_CODE_FEEDBACK,        /* only code coverage feedback      */
  /* 02 */ AFLNET_STATE_FEEDBACK,       /* only state feedback              */
  /* 03 */ AFLNET_CODE_STATE_FEEDBACK   /* code + state feedback            */

};

/* Seed scheduling policy (AFLNET_SCHEDULE). */
enum {

  /* 00 */ AFLNET_CODE_AWARE_SCHEDULE,
  /* 01 */ AFLNET_HYBRID_SCHEDULE,
  /* 02 */ AFLNET_IPSM_SCHEDULE

};

typedef struct aflnet_state {

  u8 *aflnet_url, *aflnet_protocol;
  u8 *cleanup_script;           /* AFLNET_CLEANUP_SCRIPT: script run before each
                                   target execution to keep fuzzing deterministic */

  aflnet_extract_requests_fn       aflnet_extract_requests;
  aflnet_extract_response_codes_fn aflnet_extract_response_codes;

  u8 sock_mode;
  u8 shm_sync;                    /* use sockhook SHM rendezvous          */
  aflnet_init_session_fn aflnet_init_session;

  /* per-message send/recv dispatch (assigned from sock_mode at init) */
  aflnet_send_fn aflnet_send;
  aflnet_recv_fn aflnet_recv;
  const aflnet_sync_ops_t *sync_ops;

  /* persistent socket used by the send/recv dispatch functions for the
     current run (-1 while closed) */
  int sockfd;

  u8 state_mode;                   /* state-aware mode active                */
  u8 state_selection_algo;      /* AFLNET_*_SELECTION                    */
  u8 seed_selection_algo;       /* AFLNET_*_SELECTION                    */
  u8 feedback_type;             /* AFLNET_*_FEEDBACK                     */

  /* state-sequence backend bound from state_mode at init (NULL when
     state-aware mode is disabled).  All per-run state-sequence compute /
     update / region-annotation goes through this vtable, hiding the
     response-code vs. state-variable differences from the callers. */
  const aflnet_state_backend_t *state_backend;

  /* discovered states */
  u32         *state_ids;       /* state ids in discovery order          */
  u32          state_ids_count;
  u32          state_ids_alloc;
  state_info_t **states;        /* parallel to state_ids                  */

  /* all distinct IPSM transitions discovered so far */
  aflnet_edge_t *ipsm_edges;
  u32            ipsm_edge_count;
  u32            ipsm_edge_alloc;

  u32 target_state_id;          /* state currently targeted              */
  u32 selected_state_index;     /* round-robin state cursor              */
  u32 state_cycles;             /* # round-robin cycles                  */
  u8  seed_schedule_type;       /* AFLNET_*_SCHEDULE                     */
  u32 time_gap;                 /* hybrid schedule time gap (seconds)    */
  u64 last_path_time;           /* last new path time                    */
  u32 poll_wait_msecs;          /* response poll timeout                 */
  u32 socket_timeout_usecs;     /* per-send/recv socket timeout          */
  u8  terminate_child;          /* terminate target after each exchange  */
  u32 server_wait_usecs;        /* startup wait for the server           */
  u32 local_port;               /* fixed local source port, 0 = disabled */
  u8  code_aware_schedule;      /* normal AFL++ scheduler is active      */

  /* per-state-per-seed fuzzed status: -1 unreachable, 0 not fuzzed, 1 fuzzed */
  u8  **was_fuzzed_map;
  u32    fuzzed_map_states;
  u32    fuzzed_map_qentries;

  /* set of seen state sequences (IPSM path novelty) */
  u32 *path_hashes;
  u32  path_hash_count;
  u32  path_hash_alloc;

  /* per-run response capture (filled by aflnet_late_send) */
  char *response_buf;           /* accumulated response bytes             */
  int   response_buf_size;
  u32  *response_bytes;         /* accumulated response size after msg i  */
  u32   messages_sent;
  u8    feedback_pending;       /* a network exchange needs feedback      */

  /* extracted state sequence from the whole response */
  u32 *state_sequence;
  u32  state_count;

  /* state variable feedback (state_mode == AFLNET_STATE_VAR_MODE): a dedicated shared memory
     region that the instrumented target writes its current state-variable
     values into.  After each recv the fuzzer hashes the region to derive a
     state id and appends it to state_sequence in real time (reusing the
     same field that state_mode == AFLNET_RESP_CODE_MODE populates from response codes). */
  sharedmem_t statevar_shm;     /* SHM handle (owns the map)              */
  u8          statevar_shm_ready; /* 1 once the SHM has been created      */

  /* region-level mutation state: M1 (prefix) + M2 (target) + M3 (suffix) */
  u8   region_mode;             /* 1 while mutating only M2              */
  u8  *region_m1;
  u32  region_m1_len;
  u8  *region_m2;
  u32  region_m2_len;
  u8  *region_m3;
  u32  region_m3_len;
  u8  *region_full;             /* scratch for reassembled message chain  */

  /* first region index of M2 (set by aflnet_prepare_region_fuzz); used by
     the sock2shm send path to gate response capture on the M2 region */
  u32 M2_start_region_ID;

} aflnet_state_t;

void aflnet_set_protocol_handlers(struct afl_state *afl,
                                         const char  *protocol);

void aflnet_configure_from_env(struct afl_state *afl);

/* fuzzer-side network mode dispatch (sock_mode): defined in
   src/aflnet/sock2shm.c, Linux only.  Stubs are provided for
   non-Linux builds. */
int aflnet_protocol_to_socket_type(const char *protocol);

unsigned int *extract_response_codes_smtp(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref);
unsigned int *extract_response_codes_ssh(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref);
unsigned int *extract_response_codes_tls(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref);
unsigned int *extract_response_codes_dicom(unsigned char *buf,
                                           unsigned int  buf_size,
                                           unsigned int *state_count_ref);
unsigned int *extract_response_codes_dns(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref);
unsigned int *extract_response_codes_ftp(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref);
unsigned int *extract_response_codes_mqtt(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref);
unsigned int *extract_response_codes_rtsp(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref);
unsigned int *extract_response_codes_dtls12(unsigned char *buf,
                                            unsigned int  buf_size,
                                            unsigned int *state_count_ref);
unsigned int *extract_response_codes_sip(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref);
unsigned int *extract_response_codes_http(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref);
unsigned int *extract_response_codes_ipp(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref);
unsigned int *extract_response_codes_dhcp(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref);
unsigned int *extract_response_codes_tftp(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref);
unsigned int *extract_response_codes_SNTP(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref);
unsigned int *extract_response_codes_NTP(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref);
unsigned int *extract_response_codes_SNMP(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref);

region_t *extract_requests_smtp(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref);
region_t *extract_requests_ssh(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref);
region_t *extract_requests_tls(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref);
region_t *extract_requests_dicom(unsigned char *buf, unsigned int buf_size,
                                 unsigned int *region_count_ref);
region_t *extract_requests_dns(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref);
region_t *extract_requests_ftp(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref);
region_t *extract_requests_mqtt(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref);
region_t *extract_requests_rtsp(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref);
region_t *extract_requests_dtls12(unsigned char *buf, unsigned int buf_size,
                                  unsigned int *region_count_ref);
region_t *extract_requests_sip(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref);
region_t *extract_requests_http(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref);
region_t *extract_requests_ipp(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref);
region_t *extract_requests_tftp(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref);
region_t *extract_requests_dhcp(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref);
region_t *extract_requests_SNTP(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref);
region_t *extract_requests_NTP(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref);
region_t *extract_requests_SNMP(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref);

u32 read_bytes_to_uint32(unsigned char *buf, unsigned int offset,
                         int num_bytes);

void init_message_code_map(void);
void destroy_message_code_map(void);

void aflnet_send_over_network(void *data, const u8 *mem, size_t len);

/* AFLNet state-aware (IPSM) support.  The scheduling / region / feedback
   entry points are implemented in src/afl-fuzz-aflnet.c (the single
   external entry point into the AFLNet module); the state-table core
   helpers live in src/aflnet/state.c and src/aflnet/statevar.c. */
void aflnet_state_init(struct afl_state *afl);
void aflnet_state_deinit(struct afl_state *afl);
void aflnet_update_state_feedback(struct afl_state *afl);
void aflnet_register_seed(struct afl_state *afl, struct queue_entry *q);
u8   aflnet_is_seed_fuzzed(struct afl_state *afl, struct queue_entry *q);
void aflnet_mark_seed_fuzzed(struct afl_state *afl, struct queue_entry *q);
u8   aflnet_use_state_scheduler(struct afl_state *afl);
u8   aflnet_select_next_seed(struct afl_state *afl);
u8   aflnet_prepare_region_fuzz(struct afl_state *afl, u8 *in_buf, u32 in_len,
                                u8 **out_buf, u32 *out_len);
u8   aflnet_prepare_region_fuzz_or_whole(struct afl_state *afl, u8 *in_buf,
                                         u32 in_len, u8 **out_buf,
                                         u32 *out_len);
u8  *aflnet_reassemble_region(struct afl_state *afl, u8 *m2_buf, u32 m2_len,
                              u32 *full_len);
void aflnet_update_ipsm(struct afl_state *afl, struct queue_entry *q);
void aflnet_write_ipsm_json(struct afl_state *afl);
struct custom_mutator *aflnet_register_module(struct afl_state *afl);

/* Save a full message chain (test case) to a file, optionally in replayable
   mode (4-byte length prefix + payload per message).  Equivalent of the
   original AFLNet save_kl_messages_to_file(); replay_enabled == 0 writes the
   raw concatenated messages, == 1 writes the aflnet-replay format.  max_count
   caps the number of messages written (pass messages_sent to mirror the
   original semantics).  Returns the number of bytes written. */
u32  aflnet_save_testcase_to_file(struct afl_state *afl, u8 *mem, u32 len,
                                  u8 *fname, u8 replay_enabled, u32 max_count);

/* Save the replayable counterpart of a crash or hang entry.  raw_fname is
   the path of the raw crashes/hangs file; the replayable copy keeps its
   basename under replayable-crashes/ or replayable-hangs/. */
void aflnet_save_replayable_fault(struct afl_state *afl, u8 *mem, u32 len,
                                  const u8 *raw_fname, u8 is_crash);

/* Parse an AFLNET_URL of the form [scheme://]host:port into its
   components.  scheme may be empty if no scheme prefix is present. */
void aflnet_parse_url(const char *url, char *scheme, size_t scheme_len,
                      char *host, size_t host_len, u32 *port);

#ifdef __cplusplus
}
#endif

#endif
