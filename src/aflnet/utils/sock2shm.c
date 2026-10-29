/* aflnet/sock2shm.c - fuzzer side of the sock2shm (HNPFuzzer-style) SHM
   network interaction, plus the libaflppdesock (sock_mode=0) setup.

   sock_mode (aflnet_state_t.sock_mode):
     0 = AFLNET_LIBDESOCK : target preloaded with libaflppdesock.so, the
         testcase is delivered through stdin, no late-send network I/O.
     1 = AFLNET_SOCK      : default AFLNet real-socket interaction
         (implemented in src/aflnet/net.c).
     2 = AFLNET_SOCK2SHM  : target preloaded with sock2shm.so; request
         messages are exchanged through a shared msg SHM segment and the
         responses are read back from the same segment.

   The protocol mirrors HNPFuzzer's fuzzer side: the fuzzer still opens a
   real socket + connect() so that the target's accept() completes, then all
   send/recv on the session fd are redirected through the SHM by the
   preloaded library.

   Linux only (System V shm + futex based protocol). */

#include "config.h"
#include "types.h"
#include "debug.h"
#include "afl-fuzz.h"
#include "aflnet.h"
#include "alloc-inl.h"
#include "common.h"
#include "../aflnet-internal.h"

#ifdef __linux__

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <limits.h>

#include "../../../utils/sockhook/sock2shm_utils.h"

/* ------------------------------------------------------------------ */
/* shared segment handles                                             */
/* ------------------------------------------------------------------ */

msg *session_msg = NULL;          /* DATA plane: shared message buffers
                                     (msg segment, sock2shm_utils.h).  Only
                                     the SHM redirection creates/uses it;
                                     with the standalone rendezvous
                                     (AFLNET_SHM_SYNC) it stays NULL. */
shm_sig *sign_ptr = NULL;         /* CONTROL plane: shared rendezvous state
                                     (check segment, sock2shm_utils.h) -
                                     turn token, session flags, futex and
                                     connection_state.  Created for BOTH the
                                     redirection and the rendezvous-only
                                     configuration, because it is what the
                                     target's sockhook uses to arm a session,
                                     publish its readiness and hand the turn
                                     over.  The per-process target config
                                     (netport, SHM on/off) is carried through
                                     the environment + a local struct in the
                                     preloaded sockhook library, NOT here. */

static int  shm_msg_id = -1;
static int  shm_check_id = -1;

int  waiting_time = WAITING_TIME; /* futex wait timeout (ms)              */

/* ------------------------------------------------------------------ */
/* minimal futex helpers (same semantics as sock2shm_utils.c)         */
/* ------------------------------------------------------------------ */

static u64 s2s_cur_time_ms(void) {

  struct timeval tv;
  gettimeofday(&tv, NULL);

  return (u64)(tv.tv_sec * 1000ULL) + (u64)(tv.tv_usec / 1000);

}

int shm_wait(atomic_int *state, int val, int timeout) {

  u64 deadline = 0;

  if (atomic_load(state) != val) { return 0; }

  if (timeout > 0) { deadline = s2s_cur_time_ms() + (u64)timeout; }

  for (;;) {

    struct timespec         ts;
    struct timespec        *tsp = NULL;

    if (atomic_load(state) != val) { return 0; }

    if (timeout > 0) {

      u64 now = s2s_cur_time_ms();
      u64 remain;

      if (now >= deadline) { break; }

      remain = deadline - now;
      ts.tv_sec = (time_t)(remain / 1000);
      ts.tv_nsec = (long)((remain % 1000) * 1000000ULL);
      tsp = &ts;

    }

    if (futex_wait((int *)state, val, tsp) == -1) {

      if (errno == EAGAIN || errno == EINTR) { continue; }
      if (errno == ETIMEDOUT) { break; }
      /* unexpected futex error: do not fall back to a tight spin */
      usleep(1000);

    }

  }

  return atomic_load(state) == val;

}

void shm_notify(atomic_int *state, int val) {

  atomic_store(state, val);
  /* wake every process parked on this token (shared SysV mapping) */
  futex_wake((int *)state, INT_MAX);

}

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static int s2s_port_from_url(afl_state_t *afl, u32 *port) {

  char scheme[16];
  char host[256];

  if (!afl->aflnet || !afl->aflnet->aflnet_url) { return -1; }

  aflnet_parse_url((const char *)afl->aflnet->aflnet_url, scheme,
                   sizeof(scheme), host, sizeof(host), port);

  return 0;

}

/* ------------------------------------------------------------------ */
/* sock_mode = 0: libaflppdesock setup                                  */
/* ------------------------------------------------------------------ */

void aflnet_desock_setup(afl_state_t *afl) {

  const char *path = getenv("AFLNET_DESOCK_PATH");
  u32         port = 0;
  char        port_str[16];
  struct stat st;

  if (!path || !path[0]) { path = "utils/libaflppdesock/libaflppdesock.so"; }

  if (stat(path, &st) != 0) {

    WARNF("AFLNET_DESOCK_PATH '%s' not found; is libaflppdesock built?",
          path);

  }

  if (s2s_port_from_url(afl, &port) != 0) {

    FATAL("AFLNET_URL is required for sock_mode=0 (libaflppdesock)");

  }

  snprintf(port_str, sizeof(port_str), "%u", port);
  setenv("DESOCK_PORT", port_str, 1);
  setenv("DESOCK_CLOSE_EXIT", "1", 1);

  OKF("libaflppdesock enabled: target reads the testcase from stdin "
      "(DESOCK_PORT=%u, preload=%s)", port, path);

}

/* ------------------------------------------------------------------ */
/* sock_mode = 2: sock2shm fuzzer side                                  */
/* ------------------------------------------------------------------ */

static void s2s_remove_shm(void) {

  if (session_msg && session_msg != (msg *)-1) { shmdt(session_msg); }
  if (sign_ptr && (void *)sign_ptr != (void *)-1) { shmdt(sign_ptr); }

  if (shm_msg_id >= 0) { shmctl(shm_msg_id, IPC_RMID, NULL); }
  if (shm_check_id >= 0) { shmctl(shm_check_id, IPC_RMID, NULL); }

  session_msg = NULL;
  sign_ptr = NULL;

}

static void sock_shm_segments_setup(const char *what, int with_data) {

  char shm_msg_str[32];
  char shm_check_str[32];
  const char *wt;

  /* Two System V segments (trace-bits SHM is managed by the regular AFL++
     machinery):
       - the "check" segment (CONTROL plane, shm_sig) is created whenever a
         session can be armed - the redirection and the standalone rendezvous
         both drive their turn-taking through it;
       - the "msg" segment (DATA plane, msg) is created only for the SHM
         redirection (with_data): the rendezvous keeps its messages on the
         real socket, so the target never attaches it.
     The target port / protocol type are not exported here any more:
     aflnet_sockhook_preload() (config.c) already exports ENV_NETPORT /
     ENV_PROTOCOL_TYPE by default for every server mode, and preloads
     sockhook.so. */
  shm_check_id =
      shmget(IPC_PRIVATE, sizeof(shm_sig), IPC_CREAT | IPC_EXCL | 0600);

  if (with_data) {

    shm_msg_id = shmget(IPC_PRIVATE, sizeof(msg), IPC_CREAT | IPC_EXCL | 0600);

  }

  if (shm_check_id < 0 || (with_data && shm_msg_id < 0)) {

    PFATAL("shmget() failed for sock2shm segments");

  }

  snprintf(shm_check_str, sizeof(shm_check_str), "%d", shm_check_id);
  setenv(SHM_ENV_CHECK_VAR, shm_check_str, 1);

  if (with_data) {

    snprintf(shm_msg_str, sizeof(shm_msg_str), "%d", shm_msg_id);
    setenv(SHM_ENV_MSG_VAR, shm_msg_str, 1);
    session_msg = (msg *)shmat(shm_msg_id, NULL, 0);

  }

  sign_ptr = (shm_sig *)shmat(shm_check_id, NULL, 0);

  if ((with_data && session_msg == (msg *)-1) ||
      (void *)sign_ptr == (void *)-1) {

    PFATAL("shmat() failed for sock2shm segments");

  }

  /* init the per-session fields of the check segment (the shared shm_sig).
     Zero is NOT a neutral state: connection_state == 0 is ENDING and a zero
     futex avail looks locked.  Start from the same state the target's
     session_init() will use, so the first run's readiness wait really waits
     for the target instead of being satisfied by the zero fill. */
  memset(sign_ptr, 0, sizeof(*sign_ptr));
  /* both modes start with the server's turn (see sockhook's session_init) */
  shm_notify(&sign_ptr->state, SERVER);
  shm_notify(&sign_ptr->connection_state,UNINITIALIZED);
  sign_ptr->mx.avail = 1;
  sign_ptr->mx.waiters = 0;

  /* optional wait-time override (HNPFuzzer's -L option) */
  wt = getenv("AFLNET_SOCK2SHM_WAIT_TIME");
  if (wt && atoi(wt) > 0) {

    waiting_time = atoi(wt);

  }

  atexit(s2s_remove_shm);

  /* the segment ids reach the preloaded library, which was already added to
     AFL_PRELOAD and given its netport/protocol config by
     aflnet_sockhook_preload() in config.c; whether it actually redirects the
     exchange or only arms the handshake is decided by the __AFL_SHMSYNC /
     __AFL_SOCK_MODE envs the caller exported. */
  if (with_data) {

    OKF("%s engaged: shm msg=%d check=%d waiting_time=%d", what, shm_msg_id,
        shm_check_id, waiting_time);

  } else {

    OKF("%s engaged: shm check=%d waiting_time=%d (no data segment, the "
        "messages stay on the real socket)",
        what, shm_check_id, waiting_time);

  }

}

/* sock_mode == 2: the preloaded sockhook redirects the whole exchange, so
   both segments are created (control + data) */
void aflnet_sock2shm_setup(afl_state_t *afl) {

  (void)afl;
  sock_shm_segments_setup("sock2shm", 1);

}

/* sock_mode == 1 + AFLNET_SHM_SYNC=1: only the CONTROL segment is created,
   because the messages keep travelling over the real socket.
   __AFL_SHMSYNC arms just the rendezvous in the preloaded library (the
   target publishes its readiness on accept and hands the turn back on every
   recv), so the fuzzer can drive the session handshake without the SHM
   message redirection. */
void aflnet_sock_shm_sync_setup(afl_state_t *afl) {

  (void)afl;
  setenv(ENV_SHMSYNC, "1", 1);
  sock_shm_segments_setup("shmsync", 0);

}

/* 1 when the sockhook rendezvous is armed for this run: sock_mode=2, or
   sock_mode=1 with AFLNET_SHM_SYNC=1 and the control segment in place (the
   data segment is optional - the rendezvous never uses it).  Used by
   aflnet_sock2shm_init_session() to gate the per-run reset; the
   sock_mode=1 driver itself is selected through aflnet_state_t.sync_ops. */
static int aflnet_shm_sync_armed(afl_state_t *afl) {

  return afl->afl_env.aflnet_mode && afl->aflnet && afl->aflnet->shm_sync &&
         sign_ptr != NULL;

}

/* Wait (bounded) for the target to yield the turn (CLIENT).  In the unified
   ownership model the SERVER owns the session by default; CLIENT is published
   only when the target enters recv and waits for the client's input.  The
   fuzzer must not send before this edge.  On timeout the session is marked
   failed and a parked target is released, so the run ends instead of
   blocking. */
static int aflnet_shm_sync_wait_request_turn(afl_state_t *afl) {

  static u8 warned = 0;

  (void)afl;

  if (!sign_ptr) { return 0; }

  if (!shm_wait(&sign_ptr->state, SERVER, waiting_time)) { return 1; }

  if (!warned) {

    warned = 1;
    WARNF("standalone sockhook sync: target did not enter recv (CLIENT) "
          "within %d ms; marking the session failed",
          waiting_time);

  }

  sign_ptr->is_end = 3;
  /* release a target that may already be parked on CLIENT */
  shm_notify(&sign_ptr->state, SERVER);

  return 0;

}

/* Wait (bounded) for the target to finish its current output and return to
   recv (CLIENT).  This is a soft gate before the real-socket response read:
   on timeout the bytes may already be on the wire, so the caller reads
   anyway. */
static int aflnet_shm_sync_wait_response_ready(afl_state_t *afl) {

  (void)afl;

  if (!sign_ptr) { return 0; }

  return !shm_wait(&sign_ptr->state, SERVER, waiting_time);

}

/* Wait for the target to reach accept() (it publishes RUNNING on the check
   segment before it blocks in accept).  Returns 1 when the target signalled
   that it is ready for connections, 0 when the sync is off or the signal did
   not arrive within waiting_time - the caller then keeps the plain connect
   retry behaviour.  Installed as sync_ops->wait_ready for sock_mode=1 +
   AFLNET_SHM_SYNC=1 (see config.c); a no-op when the segment is gone. */
static int aflnet_shm_sync_wait_ready(afl_state_t *afl) {

  (void)afl;   /* the state lives in the shared segment, not in afl_state_t */

  if (!sign_ptr) { return 0; }

  return !shm_wait(&sign_ptr->connection_state, UNINITIALIZED, waiting_time);

}

/* Hand the next request over: the target's real-socket recv waits for this
   before it reads (it mirrors the data1 handover of sock_mode=2). */
static void aflnet_shm_sync_notify_request(afl_state_t *afl) {

  (void)afl;

  if (!sign_ptr) { return; }

  shm_notify(&sign_ptr->state, SERVER);

}

/* End the session from the client side (called once the exchange is over,
   before the socket is closed): the target's recv() hook returns without
   reading instead of waiting for the TCP close / the run timeout.
   aflnet_sock2shm_init_session() clears is_end again before the next child is
   spawned, so this only affects the run being finished. */
static void aflnet_shm_sync_notify_end(afl_state_t *afl) {

  (void)afl;

  if (!sign_ptr) { return; }

  sign_ptr->is_end = 1;

  /* release the target's turn-taking wait (it is parked on CLIENT) */
  shm_notify(&sign_ptr->state, SERVER);

}

void aflnet_sock2shm_deinit(afl_state_t *afl) {

  (void)afl;
  s2s_remove_shm();

}

/* reset the shared state before each target run.  Called from
   fuzz_run_target() before the forkserver spawns the child, so the freshly
   spawned child starts from a clean session: the turn token, the session-end
   code, the message lengths and the connection state are shared, and the
   child may reach bind()/accept() the moment it is forked.  (The target's
   own "session armed" flag is per-process now - see
   global_session_mark.session_inited - and is deliberately not part of this
   reset.)
   Also used by the standalone shmsync (sock_mode=1 + AFLNET_SHM_SYNC), where
   the connection_state arm is what the target's accept() waits for. */
int aflnet_sock2shm_init_session(afl_state_t *afl) {

  if (!aflnet_shm_sync_armed(afl)) {

    return 0;

  }

  /* CONTROL plane (check segment): the shared rendezvous state.  The target's
     "session armed" flag is NOT here anymore - every target process keeps its
     own mark (global_session_mark.session_inited in utils/sockhook), which a
     fork copies like the rest of the memory image, so the fuzzer only has to
     reset the state that is really shared across processes.  Both modes start
     with the server's turn: the target may publish a banner, then its first
     recv yields CLIENT and waits for the fuzzer's request (see the target's
     session_init()/recv_state_trans()). */
  shm_notify(&sign_ptr->state, SERVER);
  sign_ptr->is_end = 0;
  /* sign_ptr->is_init is RESERVED (ABI only): the target no longer reads it */
  sign_ptr->mx.avail = 1;
  sign_ptr->mx.waiters = 0;

  /* DATA plane (msg segment): only the SHM redirection has one - the
     rendezvous-only configuration does not even create the segment. */
  if (afl->aflnet->sock_mode == AFLNET_SOCK2SHM && session_msg) {

    session_msg->len1 = 0;
    session_msg->len2 = 0;
    session_msg->buf_size = 0;

  }

  /* per-run resets so the freshly spawned target starts a clean session:
     - connection_state must not be ENDING (the target's accept() would
       otherwise call suspend()/SIGSTOP on its very first connection and
       never reach shm_read -> run timeout);
     - proc_ref_cnt is balanced (accept -> +1, close -> -1); resetting it
       here keeps it from accumulating across fork(). */
  if (sign_ptr) {

    shm_notify(&sign_ptr->connection_state,UNINITIALIZED);
    sign_ptr->proc_ref_cnt = 0;

  }

  return 0;

}

/* Normal end of a sock2shm exchange (sock_mode=2 implies shmsync).  The
   target may be parked in shm_read()/shm_write() on CLIENT; publish the end
   flag and hand SERVER back so the futex wait is released and the target
   closes/exits instead of waiting for the run timeout. */
void aflnet_sock2shm_notify_end(afl_state_t *afl) {

  if (!aflnet_shm_sync_armed(afl)) {

    return;

  }

  sign_ptr->is_end = 1;
  shm_notify(&sign_ptr->state, SERVER);

}

/* notify the server that the fuzzer timed out (is_end=3).  Called after
   FSRV_RUN_TMOUT so a still-running server ends its session cleanly. */
void aflnet_sock2shm_notify_timeout(afl_state_t *afl) {

  if (!aflnet_shm_sync_armed(afl)) {

    return;

  }

  /* The target waits while state == CLIENT, so hand SERVER back together with
     the end flag; writing CLIENT here would leave a parked recv() asleep. */
  sign_ptr->is_end = 3;
  shm_notify(&sign_ptr->state, SERVER);

}

/* read a response from data2 (fuzzer side, mirrors HNPFuzzer shm_read).
   Return convention matches the real-socket read (aflnet_net_recv, used by
   the AFLNET_SOCK dispatch): 0 means OK - either response bytes were copied
   into *response_buf, or there is no response data available yet (the
   target is idle / waiting for the next request), which is NOT an error.
   1 is reserved for a genuine error.  This keeps net.c's call sites
   mode-agnostic: a nonzero return from aflnet_recv is a hard failure there
   (it would abort the whole run at the banner read, or stop sending more
   regions), exactly as with the real-socket dispatch. */
static int s2s_shm_read(char **response_buf, int *response_buf_size) {

  int remain;
  static u8 warned_stall = 0;

  /* The target did not hand the response turn back within waiting_time.  A
     request-driven server may legitimately not reply yet, so this stays "no
     data" - but a session that is already marked ended is a hard error, and
     the stall is reported once instead of being silently indistinguishable
     from an empty response. */
  if (shm_wait(&sign_ptr->state, SERVER, waiting_time)) {

    if (!warned_stall) {

      warned_stall = 1;
      WARNF("sock2shm: target did not hand the response turn back within %d "
            "ms (request-driven target or stalled session?)",
            waiting_time);

    }

    return sign_ptr->is_end ? 1 : 0;

  }

  /* the target signalled CLIENT but has no bytes queued (e.g. it is idle,
     waiting for the next request): again no data, not an error, unless the
     session is known to be over. */
  if (session_msg->len2 == 0) { return sign_ptr->is_end ? 1 : 0; }

  /* len2 > 0: drain it even when is_end was set - the target's close path
     flushes the pending response before it publishes the end. */

  *response_buf =
      (char *)ck_realloc(*response_buf, *response_buf_size + session_msg->len2);

  for (remain = session_msg->len2; remain > 0;) {

    if (remain < MAX_MSG_SIZE) {

      memcpy(*response_buf + *response_buf_size, session_msg->data2, remain);
      *response_buf_size += remain;
      remain = 0;
      session_msg->len2 = 0;

    } else {

      memcpy(*response_buf + *response_buf_size, session_msg->data2,
             MAX_MSG_SIZE);
      remain -= MAX_MSG_SIZE;
      session_msg->len2 -= MAX_MSG_SIZE;
      *response_buf_size += MAX_MSG_SIZE;
      shm_notify(&sign_ptr->state, SERVER);

      if (shm_wait(&sign_ptr->state, SERVER, waiting_time)) {

        /* the target never took the previous chunk: do not keep reading the
           shared buffer as if the transfer were still healthy */
        sign_ptr->is_end = 3;
        shm_notify(&sign_ptr->state, SERVER);

        if (!warned_stall) {

          warned_stall = 1;
          WARNF("sock2shm: target stalled while draining a response chunk "
                "(waiting_time=%d ms)",
                waiting_time);

        }

        return 1;

      }

    }

  }

  return 0;

}

/* write a request message into data1 (fuzzer side, mirrors HNPFuzzer
   shm_write).  Returns len on success, -1 on error. */
static int s2s_shm_write(char *mem, unsigned int len) {

  int remain;
  int p;
  static u8 warned_stall = 0;

  /* Wait for the write floor: the target must have drained the previous
     request and signalled readiness (state != SERVER) before we may touch
     data1/len1/buf_size.  shm_wait() does NOT set errno - it returns 1
     when state is still SERVER after waiting_time, so the old
     'if (errno == ETIMEDOUT)' never fired and we overwrote data1 while the
     target was still reading it.  On a real timeout do not write: bail out
     with 0 bytes so the caller stops this exchange instead of corrupting
     the shared buffer. */
  if (shm_wait(&sign_ptr->state, SERVER, waiting_time)) {

    /* We cannot write the request at all.  Returning 0 used to look like a
       normal short send and the whole run was silently discarded; mark the
       session dead (releasing the target) and report the stall once. */
    sign_ptr->is_end = 8;
    shm_notify(&sign_ptr->state, SERVER);

    if (!warned_stall) {

      warned_stall = 1;
      WARNF("sock2shm: target did not take the request turn within %d ms; "
            "marking the session failed",
            waiting_time);

    }

    return -1;

  }
  if (sign_ptr->is_end) { return -1; }

  session_msg->len1 = len;

  for (remain = (int)len, p = 0; remain > 0;) {

    if (remain < MAX_MSG_SIZE) {

      memcpy(session_msg->data1, mem + p, remain);
      session_msg->buf_size = remain;
      remain = 0;

    } else {

      memcpy(session_msg->data1, mem + p, MAX_MSG_SIZE);
      remain -= MAX_MSG_SIZE;
      session_msg->buf_size = MAX_MSG_SIZE;
      p += MAX_MSG_SIZE;

    }

    do {                          /* wait until the buffer data is cleared */

      shm_notify(&sign_ptr->state, SERVER);

      if (shm_wait(&sign_ptr->state, SERVER, waiting_time)) {

        sign_ptr->is_end = 8;
        shm_notify(&sign_ptr->state, SERVER);
        return -1;

      }

      if (sign_ptr->is_end) { return -1; }

    } while (session_msg->buf_size > 0);

  }

  return (int)len;

}

/* sock_mode == AFLNET_SOCK2SHM: per-message send implementation used as
   aflnet_state_t.aflnet_send.  Writes one request message into data1.
   Returns bytes written or -1 on error. */
int aflnet_sock2shm_send_msg(afl_state_t *afl, const u8 *mem,
                             unsigned int len) {

  (void)afl;
  int n;

  if (!session_msg) { return -1; }

  n = s2s_shm_write((char *)mem, len);

  return n;

}

/* sock_mode == AFLNET_SOCK2SHM: per-message recv implementation used as
   aflnet_state_t.aflnet_recv.  Reads one response from data2.
   Return convention is the same as the socket read (aflnet_sock_recv_msg ->
   aflnet_net_recv): 0 on success OR when no response data is available yet
   (not an error), 1 only on a genuine transport error (no SHM session). */
int aflnet_sock2shm_recv_msg(afl_state_t *afl, char **response_buf,
                             unsigned int *response_buf_size) {

  (void)afl;

  if (!session_msg) { return 1; }

  return s2s_shm_read(response_buf, (int *)response_buf_size);

}

/* connect to the server and exchange the request messages through the
   shared msg SHM, capturing the responses.  Called from aflnet_send_over_network
   for sock_mode == AFLNET_SOCK2SHM.  The per-message send/recv calls are
   routed through aflnet_sock2shm_send_msg / aflnet_sock2shm_recv_msg (the
   same functions bound to aflnet_state_t.aflnet_send / aflnet_recv). */
// void aflnet_sock2shm_send(afl_state_t *afl, const u8 *mem, size_t len) {

//   aflnet_state_t   *an = afl->aflnet;
//   char              scheme[16];
//   char              host[256];
//   u32               port = 0;
//   int               sock_type;
//   int               sockfd = -1;
//   int               n;
//   struct sockaddr_in serv_addr;
//   region_t         *regions = NULL;
//   unsigned int      region_count = 0;
//   char             *response_buf = NULL;
//   unsigned int      response_buf_size = 0;

//   if (!session_msg) { return; }

//   an->messages_sent = 0;

//   aflnet_parse_url((const char *)an->aflnet_url, scheme, sizeof(scheme), host,
//                    sizeof(host), &port);
//   sock_type =
//       aflnet_protocol_to_socket_type((const char *)an->aflnet_protocol);

//   /* extract the request messages from the testcase */
//   regions =
//       an->aflnet_extract_requests((unsigned char *)mem, (unsigned int)len,
//                                   &region_count);
//   if (!regions || !region_count) { return; }

//   /* create a TCP/UDP socket and connect so the server's accept() completes */
//   sockfd = socket(AF_INET, sock_type, 0);
//   if (sockfd < 0) {

//     PFATAL("Cannot create a socket");

//   }

//   an->sockfd = sockfd;

//   memset(&serv_addr, 0, sizeof(serv_addr));
//   serv_addr.sin_family = AF_INET;
//   serv_addr.sin_port = htons((u16)port);
//   if (inet_pton(AF_INET, host, &serv_addr.sin_addr) != 1) {

//     close(sockfd);
//     an->sockfd = -1;
//     FATAL("AFLNET_URL host is not a valid IPv4 address: %s", host);

//   }

//   if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {

//     for (n = 0; n < 1000; ++n) {

//       if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
//           0) {

//         break;

//       }

//       usleep(1000);

//     }

//     if (n == 1000) {

//       close(sockfd);
//       an->sockfd = -1;
//       ck_free(regions);
//       return;

//     }

//   }

//   /* retrieve an early server response if needed */
//   if (aflnet_sock2shm_recv_msg(afl, &response_buf, &response_buf_size) > 0) {

//     goto HANDLE_RESPONSES;

//   }

//   /* write the request messages */
//   for (unsigned int i = 0; i < region_count; ++i) {

//     unsigned int region_len =
//         (unsigned int)regions[i].end_byte - (unsigned int)regions[i].start_byte +
//         1;

//     n = aflnet_sock2shm_send_msg(afl, (const u8 *)mem + regions[i].start_byte,
//                                  region_len);

//     an->response_bytes =
//         (u32 *)ck_realloc(an->response_bytes, an->messages_sent * sizeof(u32));

//     /* jump out if something went wrong leading to an incomplete message */
//     if (n != (int)region_len) {

//       goto HANDLE_RESPONSES;

//     }

//     /* retrieve the server response */
//     if (aflnet_sock2shm_recv_msg(afl, &response_buf, &response_buf_size) > 0) {

//       goto HANDLE_RESPONSES;

//     }

//     an->response_bytes[an->messages_sent - 1] = (u32)response_buf_size;

//     /* capture the state reached after this response through the bound
//        state-sequence backend (state-variable backend hashes the SHM and
//        appends; response-code backend is a no-op). */
//     if (an->state_backend) { an->state_backend->on_recv(afl); }

//   }

//   close(sockfd);
//   sockfd = -1;
//   an->sockfd = -1;
//   /* don't clobber a crash report (is_end==9) written by the persistent
//      forkserver parent */
//   if (session_msg->is_end != 9) {

//     session_msg->is_end = 2;
//     shm_notify(&session_msg->state, SERVER);

//   }

// HANDLE_RESPONSES:
//   /* latch a crash reported by the persistent forkserver parent before we
//      may overwrite is_end below */
//   s2s_record_crash();

//   if (session_msg->len2 > 0) {

//     response_buf =
//         (char *)ck_realloc(response_buf, response_buf_size + session_msg->len2);
//     memcpy(response_buf + response_buf_size, session_msg->data2,
//            session_msg->len2);
//     response_buf_size += (unsigned int)session_msg->len2;
//     session_msg->len2 = 0;

//   }

//   if (sockfd >= 0) {

//     close(sockfd);
//     an->sockfd = -1;
//     if (session_msg->is_end != 9) {

//       session_msg->is_end = 7;
//       shm_notify(&session_msg->state, SERVER);

//     }

//   }

//   if (an->messages_sent > 0 && an->response_bytes) {

//     an->response_bytes[an->messages_sent - 1] = (u32)response_buf_size;

//   }

//   /* publish the captured response for state feedback */
//   an->response_buf = response_buf;
//   an->response_buf_size = (int)response_buf_size;

//   if (regions) { ck_free(regions); }

// }

/* 1 if the current run should exchange messages through sock2shm (used to
   skip writing the testcase to stdin/file for sock_mode=2). */
int aflnet_sock2shm_active(afl_state_t *afl) {

  return afl->afl_env.aflnet_mode && afl->aflnet &&
         afl->aflnet->sock_mode == AFLNET_SOCK2SHM && session_msg != NULL;

}

#else /* !__linux__ */

/* non-Linux: the sock2shm mechanism is not supported */

void aflnet_desock_setup(afl_state_t *afl) {

  FATAL("sock_mode=0 (libaflppdesock) is only supported on Linux");

}

void aflnet_sock2shm_setup(afl_state_t *afl) {

  FATAL("sock_mode=2 (sock2shm) is only supported on Linux");

}

void aflnet_sock_shm_sync_setup(afl_state_t *afl) {

  FATAL("AFLNET_SHM_SYNC (standalone sockhook sync) is only supported on "
        "Linux");

}

static int aflnet_shm_sync_wait_request_turn(afl_state_t *afl) { (void)afl; return 0; }

static int aflnet_shm_sync_wait_response_ready(afl_state_t *afl) { (void)afl; return 0; }

static int aflnet_shm_sync_wait_ready(afl_state_t *afl) { (void)afl; return 0; }

static void aflnet_shm_sync_notify_request(afl_state_t *afl) { (void)afl; }

static void aflnet_shm_sync_notify_end(afl_state_t *afl) { (void)afl; }

void aflnet_sock2shm_deinit(afl_state_t *afl) { }

int aflnet_sock2shm_init_session(afl_state_t *afl) { return 0; }

void aflnet_sock2shm_notify_end(afl_state_t *afl) { }

void aflnet_sock2shm_notify_timeout(afl_state_t *afl) { }

// void aflnet_sock2shm_send(afl_state_t *afl, const u8 *mem, size_t len) { }

int aflnet_sock2shm_send_msg(afl_state_t *afl, const u8 *mem,
                             unsigned int len) {

  (void)afl;
  (void)mem;
  (void)len;
  return -1;

}

int aflnet_sock2shm_recv_msg(afl_state_t *afl, char **response_buf,
                             unsigned int *response_buf_size) {

  (void)afl;
  (void)response_buf;
  (void)response_buf_size;
  return 1;

}

int aflnet_sock2shm_active(afl_state_t *afl) { return 0; }

#endif /* __linux__ */

/* The standalone sockhook rendezvous, installed in aflnet_state_t.sync_ops by
   aflnet_configure_from_env() for sock_mode=1 + AFLNET_SHM_SYNC=1.  On
   non-Linux the functions above are inert stubs, so the table is harmless. */
const aflnet_sync_ops_t aflnet_shm_sync_ops = {

    .wait_request_turn = aflnet_shm_sync_wait_request_turn,
    .wait_response_ready = aflnet_shm_sync_wait_response_ready,
    .wait_ready = aflnet_shm_sync_wait_ready,
    .notify_request = aflnet_shm_sync_notify_request,
    .notify_end = aflnet_shm_sync_notify_end,

};
