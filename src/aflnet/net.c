/* aflnet/net.c - AFLNet network transport: URL parsing, socket I/O and the
   per-run message exchange (forkserver late-send callback).

   Moved out of src/afl-fuzz-aflnet.c into the src/aflnet/ module tree:

     - aflnet_protocol_to_socket_type() / aflnet_parse_url(): URL/socket
       helpers shared with sock2shm.c.
     - aflnet_net_send() / aflnet_net_recv(): low-level poll-based send/recv.
     - aflnet_sock_send_msg() / aflnet_sock_recv_msg(): per-message dispatch
       bound to aflnet_state_t.aflnet_send / aflnet_recv (AFLNET_SOCK).
     - aflnet_run_cleanup(): AFLNET_CLEANUP_SCRIPT hook.
     - aflnet_send_over_network(): the per-run exchange, bound to
       fsrv.late_send through the custom-mutator module (module.c). */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "common.h"
#include "afl-fuzz.h"
#include "aflnet.h"
#include "aflnet-internal.h"
#include "alloc-inl.h"

/* Map an application protocol name to a socket type (SOCK_STREAM/SOCK_DGRAM).
   Shared by net.c (late-send) and sock2shm.c. */

int aflnet_protocol_to_socket_type(const char *protocol) {

  char normalized[16];
  size_t protocol_len = protocol ? strlen(protocol) : 0;

  if (!protocol_len) { return SOCK_STREAM; }

  if (protocol_len >= sizeof(normalized)) { return SOCK_STREAM; }

  for (size_t i = 0; i < protocol_len; ++i) {
    normalized[i] = (char)tolower((unsigned char)protocol[i]);
  }
  normalized[protocol_len] = 0;

  if (!strcmp(normalized, "dns") || !strcmp(normalized, "dhcp") ||
      !strcmp(normalized, "tftp") || !strcmp(normalized, "sntp") ||
      !strcmp(normalized, "ntp") || !strcmp(normalized, "snmp") ||
      !strcmp(normalized, "dtls12") || !strcmp(normalized, "dtls") ||
      !strcmp(normalized, "sip")) {

    return SOCK_DGRAM;

  }

  return SOCK_STREAM;

}

/* Parse an AFLNET_URL.  Accepted forms (the AFLNet classic one first):
     <protocol>://<host>/<port>     e.g. tcp://127.0.0.1/8554
     <protocol>://<host>:<port>     e.g. tcp://127.0.0.1:8554
     <host>:<port>                  e.g. 127.0.0.1:8554
   Shared by net.c, config.c (sockhook preload) and sock2shm.c. */

void aflnet_parse_url(const char *url, char *scheme, size_t scheme_len,
                             char *host, size_t host_len, u32 *port) {

  const char *scheme_end = strstr(url, "://");
  const char *host_start = url;
  const char *port_start = NULL;

  if (scheme_end && scheme_end > url) {
    size_t url_scheme_len = (size_t)(scheme_end - url);
    if (url_scheme_len >= scheme_len) {
      FATAL("AFLNET_URL scheme is too long: %s", url);
    }
    for (size_t i = 0; i < url_scheme_len; ++i) {
      scheme[i] = (char)tolower((unsigned char)url[i]);
    }
    scheme[url_scheme_len] = 0;
    host_start = scheme_end + 3;
  } else {
    scheme[0] = 0;
  }

  /* Port separator.  AFLNet's classic form is "<protocol>://<host>/<port>"
     (e.g. tcp://127.0.0.1/8554), while "<protocol>://<host>:<port>" and
     "<host>:<port>" use ':'.  Accept both: the last ':' or '/' inside the
     host part wins.  Bracketed IPv6 literals ("[::1]") are skipped so their
     colons are not mistaken for the port separator. */
  for (const char *p = host_start; *p; ++p) {

    if (*p == '[') {

      const char *closing = strchr(p, ']');
      if (!closing) { break; }
      p = closing;

    } else if (*p == ':' || *p == '/') {

      port_start = p;

    }

  }

  if (!port_start || port_start == host_start || !port_start[1]) {

    FATAL(
        "AFLNET_URL must look like protocol://host:port, protocol://host/port "
        "or host:port");

  }

  size_t host_part_len = (size_t)(port_start - host_start);
  if (host_part_len >= host_len) {
    FATAL("AFLNET_URL host is too long: %s", url);
  }

  memcpy(host, host_start, host_part_len);
  host[host_part_len] = 0;

  errno = 0;
  unsigned long parsed_port = strtoul(port_start + 1, NULL, 10);
  if (errno || !parsed_port || parsed_port > 65535) {
    FATAL("AFLNET_URL has an invalid port: %s", url);
  }

  *port = (u32)parsed_port;

}

/* ------------------------------------------------------------------ */
/* low-level send / recv                                              */
/* ------------------------------------------------------------------ */

static int aflnet_net_send(int sockfd, struct timeval timeout, char *mem,
                           unsigned int len) {

  unsigned int byte_count = 0;
  int n;
  struct pollfd pfd[1];
  pfd[0].fd = sockfd;
  pfd[0].events = POLLOUT;
  int rv = poll(pfd, 1, 1);

  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
             sizeof(timeout));
  if (rv > 0) {
    if (pfd[0].revents & POLLOUT) {
      while (byte_count < len) {
        usleep(10);
        n = send(sockfd, &mem[byte_count], len - byte_count, MSG_NOSIGNAL);
        if (n == 0) return byte_count;
        if (n == -1) return -1;
        byte_count += n;
      }
    }
  }
  return byte_count;

}

static int aflnet_net_recv(int sockfd, struct timeval timeout, int poll_w,
                           char **response_buf, unsigned int *len) {

  char temp_buf[1000];
  int n;
  struct pollfd pfd[1];
  pfd[0].fd = sockfd;
  pfd[0].events = POLLIN;
  int rv = poll(pfd, 1, poll_w);

  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
             sizeof(timeout));
  if (rv > 0) {
    if (pfd[0].revents & POLLIN) {
      n = recv(sockfd, temp_buf, sizeof(temp_buf), 0);
      if ((n < 0) && (errno != EAGAIN)) { return 1; }
      while (n > 0) {
        usleep(10);
        *response_buf = (unsigned char *)ck_realloc(*response_buf, *len + n + 1);
        memcpy(&(*response_buf)[*len], temp_buf, n);
        (*response_buf)[(*len) + n] = '\0';
        *len = *len + n;
        n = recv(sockfd, temp_buf, sizeof(temp_buf), 0);
        if ((n < 0) && (errno != EAGAIN)) { return 1; }
      }
    }
  } else if (rv < 0) {
    return 1;
  }

  return 0;

}

/* per-message send/recv dispatch for the default real-socket sock_mode
   (AFLNET_SOCK).  Bound to aflnet_state_t.aflnet_send / aflnet_recv in
   aflnet_configure_from_env(); operate on the persistent socket stored in
   aflnet_state_t.sockfd. */

int aflnet_sock_init_session(afl_state_t *afl){
    (void)afl;   /* no per-run session state to reset for the plain socket */
    return 0;
}

int aflnet_sock_send_msg(afl_state_t *afl, const u8 *mem,
                                unsigned int len) {

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = (suseconds_t)afl->aflnet->socket_timeout_usecs;

  return aflnet_net_send(afl->aflnet->sockfd, timeout, (char *)mem, len);

}

int aflnet_sock_recv_msg(afl_state_t *afl, char **response_buf,
                                unsigned int *response_buf_size) {

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = (suseconds_t)afl->aflnet->socket_timeout_usecs;

  return aflnet_net_recv(afl->aflnet->sockfd, timeout,
                         (int)afl->aflnet->poll_wait_msecs, response_buf,
                         response_buf_size);

}

/* ------------------------------------------------------------------ */
/* cleanup script (AFLNET_CLEANUP_SCRIPT)                             */
/* ------------------------------------------------------------------ */

/* Run the user-supplied cleanup script in the fuzzer process before every
   target execution.  This gives the server a clean environment so that
   network fuzzing is deterministic -- mirrors original AFLNet's
   send_over_network(), which calls system(cleanup_script).  The script is
   only run when AFLNET_CLEANUP_SCRIPT is set. */

void aflnet_run_cleanup(afl_state_t *afl) {

  int rc;

  if (!afl || !afl->aflnet || !afl->aflnet->cleanup_script) { return; }

  rc = system((const char *)afl->aflnet->cleanup_script);

  if (rc == -1) {

    WARNF("AFLNET_CLEANUP_SCRIPT '%s' could not be executed (%s)",
          afl->aflnet->cleanup_script, strerror(errno));

  } else if (rc != 0) {

    if (WIFEXITED(rc)) {

      WARNF("AFLNET_CLEANUP_SCRIPT '%s' exited with status %d",
            afl->aflnet->cleanup_script, WEXITSTATUS(rc));

    } else if (WIFSIGNALED(rc)) {

      WARNF("AFLNET_CLEANUP_SCRIPT '%s' terminated by signal %d",
            afl->aflnet->cleanup_script, WTERMSIG(rc));

    }

  }

}

/* ------------------------------------------------------------------ */
/* standalone sockhook sync (sock_mode=1 + AFLNET_SHM_SYNC=1)          */
/* ------------------------------------------------------------------ */

/* The preloaded sockhook serialises the exchange from the target side: it
   publishes "listening, ready to accept" from accept() and hands the turn
   back from every recv().  The helpers below perform the matching
   client-side steps through aflnet_state_t.sync_ops, which
   aflnet_configure_from_env() fills with the implementation of the configured
   sock mode (NULL when the mode has no rendezvous), so sock_mode=0/1 without
   AFLNET_SHM_SYNC and sock_mode=2 keep their exact behaviour. */

/* wait (bounded) for the target to publish its readiness before dialling.
   A target that is slow to start is not an error here: the plain connect
   retry loop below still covers it. */
static void net_sync_wait_server(afl_state_t *afl) {

  static u8 warned = 0;

  /* Only the standalone rendezvous has a readiness handshake.  sock_mode=2
     leaves sync_ops NULL (its readiness is implicit in the SHM turn-taking),
     so nothing is waited for and nothing is warned about there. */
  if (!afl->aflnet || !afl->aflnet->sync_ops) { return; }

  if (!afl->aflnet->sync_ops->wait_ready(afl) && !warned) {

    warned = 1;
    WARNF("standalone sockhook sync: the target did not signal readiness in "
          "time, relying on the connect retry");

  }

}

/* Tell the target-side recv() that a request is on the wire.  It is called
   AFTER the bytes are handed to the socket on purpose: the target's recv hook
   waits for this before it looks at the socket, so the ordering guarantees
   that its first (non-blocking) probe already sees the request - otherwise
   the target would poll an empty socket, hand the turn straight back and the
   fuzzer would record an empty response for a message that is still in
   flight. */
static void net_sync_hand_over(afl_state_t *afl) {

  if (afl->aflnet && afl->aflnet->sync_ops) {

    afl->aflnet->sync_ops->notify_request(afl);

  }

}

/* Wait (bounded) for the target to yield the turn (CLIENT): in the unified
   ownership model the fuzzer may send only after the target has entered recv
   and published CLIENT.  Returns 1 when the turn is available (also when the
   configured mode has no rendezvous), 0 when the wait timed out (the session
   has then been marked failed by the implementation). */
static int net_sync_wait_turn(afl_state_t *afl) {

  if (!afl->aflnet || !afl->aflnet->sync_ops) { return 1; }

  return afl->aflnet->sync_ops->wait_request_turn(afl);

}

/* Soft pre-read gate (sync-only): wait until the target has finished its
   current output and returned to recv (CLIENT).  Unlike wait_request_turn(),
   a timeout is not an error - the response bytes may already be on the
   wire - so the caller always proceeds to the real recv.  In mode 2 the
   sync_ops table is NULL: s2s_shm_read() performs the wait and the data copy
   together. */
static void net_sync_wait_response_ready(afl_state_t *afl) {

  if (afl->aflnet && afl->aflnet->sync_ops) {

    (void)afl->aflnet->sync_ops->wait_response_ready(afl);

  }

}

/* ------------------------------------------------------------------ */
/* public: forkserver late-send callback                              */
/* ------------------------------------------------------------------ */

/* Send the full message chain to the target over the network.  Bound to
   fsrv.late_send by the custom-mutator module (module.c), so data points at
   the module context, from which the afl_state_t is recovered. */

void aflnet_send_over_network(void *data, const u8 *mem, size_t len) {

  afl_state_t *afl = (afl_state_t *)data;
  const char   *url;
  const char   *protocol;
  char          scheme[16];
  char          host[256];
  u32           port = 0;
  int           sock_type;
  int           sockfd;
  int           n;
  struct sockaddr_in serv_addr;
  struct sockaddr_in local_serv_addr;
  struct timeval timeout;
  region_t     *regions = NULL;
  unsigned int  region_count = 0;
  aflnet_state_t *an = afl->aflnet;

  if (!afl || !afl->afl_env.aflnet_mode || !mem || !len) { return; }

  if (!afl->aflnet->aflnet_extract_requests) {
    FATAL("AFLNET mode needs a request extractor");
  }

  /* this run performs a real network exchange: tell the module's post_run
     that state feedback must be processed (SAN forkserver runs have no
     late_send and therefore never reach here, keeping feedback_pending 0) */
  an->feedback_pending = 1;

  if (afl->aflnet->cleanup_script){
    aflnet_run_cleanup(afl);
  }

  /* wait a bit for the server to finish initializing before the first send
     (mirror original AFLNet -D, AFLNET_SERVER_WAIT_USECS) */
  if (an->server_wait_usecs && !afl->deferred_mode && !afl->aflnet->shm_sync) { usleep(an->server_wait_usecs); }

  /* reset per-run response capture */
  if (an->response_buf) {

    ck_free(an->response_buf);
    an->response_buf = NULL;

  }

  if (an->response_bytes) {

    ck_free(an->response_bytes);
    an->response_bytes = NULL;

  }

  /* reset the per-run state sequence through the bound state-sequence
     backend: drops stale state_sequence/state_count, and (state-variable
     backend) zeroes the state-variable SHM so values from the previous run
     cannot bleed into this run's first state id. */
  if (an->state_backend) { an->state_backend->reset(afl); }

  /* NOTE: the per-run session reset (an->aflnet_init_session) deliberately
     does NOT run here - this function is reached only AFTER the forkserver
     has spawned the target child (and the child may already have run
     bind()/accept()).  Clearing the shared state at this point would hit a
     session the child has already armed.
     The reset runs in the module's afl_custom_post_run() instead
     (src/aflnet/module.c), i.e. after the previous run finished and before
     the next fork - the same serialisation point the core would provide in
     fuzz_run_target() (src/afl-fuzz-run.c), without a core edit. */

  an->response_buf_size = 0;
  an->messages_sent = 0;

  an->sockfd = -1;

  url = (const char *)afl->aflnet->aflnet_url;
  protocol = (const char *)afl->aflnet->aflnet_protocol;
  if (!url) { FATAL("AFLNET_URL is required in AFLNET mode"); }

  aflnet_parse_url(url, scheme, sizeof(scheme), host, sizeof(host), &port);

  sock_type = aflnet_protocol_to_socket_type(protocol);
  sockfd = socket(AF_INET, sock_type, 0);
  if (sockfd < 0) { PFATAL("Cannot create a socket"); }

  timeout.tv_sec = 0;
  timeout.tv_usec = 1000;
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
             sizeof(timeout));
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons((u16)port);
  if (inet_pton(AF_INET, host, &serv_addr.sin_addr) != 1) {
    close(sockfd);
    FATAL("AFLNET_URL host is not a valid IPv4 address: %s", host);
  }

  /* bind to a fixed local source port before connecting (mirror original
     AFLNet -l, AFLNET_LOCAL_PORT) - needed for targets like Kamailio SIP
     that reply to a specific source port */
  if (an->local_port > 0) {

    memset(&local_serv_addr, 0, sizeof(local_serv_addr));
    local_serv_addr.sin_family = AF_INET;
    local_serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_serv_addr.sin_port = htons((u16)an->local_port);
    local_serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(sockfd, (struct sockaddr *)&local_serv_addr,
             sizeof(struct sockaddr_in))) {

      close(sockfd);
      FATAL("Unable to bind socket on local source port %u", an->local_port);

    }

  }

  /* standalone sockhook sync: give the target the chance to reach accept()
     and publish its readiness before dialling (the retry loop below stays as
     the fallback for a target that is slower than the bounded wait). */
  net_sync_wait_server(afl);

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    for (n = 0; n < 1000; ++n) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0)
        break;
      usleep(1000);
    }
    if (n == 1000) {
      close(sockfd);
      return;
    }
  }

  /* hand the socket to the per-message dispatch helpers.  The per-run
     session reset (an->aflnet_init_session) deliberately does NOT happen
     here: it runs in the module's post_run for the *next* run (see the note
     above).  Resetting the shared session state at this point would hit a
     child that already armed its session. */
  an->sockfd = sockfd;

  /* capture the initial state of the exchange through the bound
     state-sequence backend */
  if (an->state_backend) { an->state_backend->begin(afl); }

  /* The greeting is unprompted (the target writes it right after accept).
     Wait for the target's CLIENT yield when a rendezvous is armed so the
     greeting has been fully written, then read it off the real socket. */
  net_sync_wait_response_ready(afl);
  if (an->aflnet_recv(afl, &an->response_buf, &an->response_buf_size)) {
    goto cleanup;
  }

  regions = afl->aflnet->aflnet_extract_requests((unsigned char *)mem,
                                                (unsigned int)len,
                                                &region_count);
  for (unsigned int i = 0; i < region_count; ++i) {
    unsigned int region_len = (unsigned int)regions[i].end_byte -
                              (unsigned int)regions[i].start_byte + 1;

    if (!region_len) { continue; }

    if (!net_sync_wait_turn(afl)) { goto HANDLE_RESPONSES; }

    n = an->aflnet_send(afl, mem + regions[i].start_byte, region_len);
    an->messages_sent++;

    /* remember the accumulated response size after this message for
       state feedback / region annotation */
    an->response_bytes = (u32 *)ck_realloc(an->response_bytes,
                                           an->messages_sent * sizeof(u32));

    if (n != (int)region_len) { 
      goto HANDLE_RESPONSES; 
    }

    /* the request is in the socket: release the target's recv(), wait for it
       to finish the response and return to recv (soft, bounded), then read */
    net_sync_hand_over(afl);
    net_sync_wait_response_ready(afl);
    if (an->aflnet_recv(afl, &an->response_buf, &an->response_buf_size)) {
      goto HANDLE_RESPONSES;
    }

    an->response_bytes[an->messages_sent - 1] = an->response_buf_size;

    /* capture the state reached after this response through the bound
       state-sequence backend (state-variable backend hashes the SHM and
       appends; response-code backend is a no-op). */
    if (an->state_backend) { an->state_backend->on_recv(afl); }
  }

HANDLE_RESPONSES:

  net_sync_wait_response_ready(afl);
  (void)an->aflnet_recv(afl, &an->response_buf, &an->response_buf_size);

  if (an->messages_sent > 0 && an->response_bytes) {

    an->response_bytes[an->messages_sent - 1] = an->response_buf_size;

  }

  /* capture the terminal state of the exchange through the bound
     state-sequence backend */
  if (an->state_backend) { an->state_backend->end(afl); }

cleanup:
  if (regions) { ck_free(regions); }

  /* End the session before closing the socket so a target parked on the SHM
     turn-taking returns immediately instead of waiting for the TCP close (or
     the run timeout).  sock_mode=2 implies shmsync but keeps its wait ops in
     the s2s helpers, so its normal end notification is a separate call. */
  if (an->sync_ops) {

    an->sync_ops->notify_end(afl);

  } else if (an->sock_mode == AFLNET_SOCK2SHM) {

    aflnet_sock2shm_notify_end(afl);

  }

  close(sockfd);
  an->sockfd = -1;

  /* mirror original AFLNet -K: optionally terminate the target child after
     each exchange so stateful servers (FTP sessions etc.) start fresh on
     the next run.  Bounded wait so a stubborn target cannot hang the
     fuzzer. */
  if (an->terminate_child && afl->fsrv.child_pid > 0) {

    /* Mark the SIGTERM as *ours* so the forkserver's result classification
       treats the child's death as a normal run (AFLNet's FAULT_NONE) instead
       of a crash - see classify_result() in src/afl-forkserver.c.  Only when
       the signal was really delivered: if the child was already gone
       (ESRCH), leave the flag clear so a real crash that happened during the
       exchange is not masked. */
    if (kill(afl->fsrv.child_pid, SIGTERM) == 0) {

      afl->fsrv.child_killed_by_fuzzer = 1;

    }

    for (u32 i = 0; i < 2000; i++) {

      if (kill(afl->fsrv.child_pid, 0) != 0 && errno == ESRCH) { break; }
      usleep(1000);

    }

  }

}
