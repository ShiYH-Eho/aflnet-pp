/* aflnet/config.c - AFLNet mode configuration, protocol handler setup and
   IPSM lifecycle.

   Moved out of src/afl-fuzz-aflnet.c into the src/aflnet/ module tree:

     - aflnet_set_protocol_handlers(): bind the protocol-specific request
       and response-code extractors to the protocol name from
       AFLNET_PROTOCOL.
     - aflnet_state_init() / aflnet_state_deinit(): IPSM lifecycle.
     - aflnet_configure_from_env(): read the AFLNET_* environment variables,
       initialise the AFLNet (IPSM) machinery and bind the per-message
       send/recv dispatch based on sock_mode.

   The public API is declared in include/aflnet.h; internal helpers it needs
   (state-sequence backend binding, sock2shm / statevar setup, message code
   map) come from aflnet-internal.h, state.c and utils/. */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "common.h"
#include "afl-fuzz.h"
#include "aflnet.h"
#include "aflnet-internal.h"
#include "alloc-inl.h"

#ifdef __linux__
  #include <sys/socket.h>                            /* SOCK_DGRAM        */
  #include "../../utils/sockhook/sock2shm_utils.h"  /* ENV_NETPORT, ENV_PROTOCOL_TYPE */
#endif

/* Bind the protocol-specific request and response-code extractors. */

void aflnet_set_protocol_handlers(afl_state_t *afl,
                                         const char  *protocol) {

  char  normalized[16];
  size_t protocol_len = protocol ? strlen(protocol) : 0;

  if (!protocol_len) { return; }

  if (protocol_len >= sizeof(normalized)) {
    FATAL("AFLNET protocol name '%s' is too long", protocol);
  }

  for (size_t i = 0; i < protocol_len; ++i) {
    normalized[i] = (char)tolower((unsigned char)protocol[i]);
  }
  normalized[protocol_len] = 0;

  if (!strcmp(normalized, "smtp")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_smtp;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_smtp;
  } else if (!strcmp(normalized, "ssh")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_ssh;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_ssh;
  } else if (!strcmp(normalized, "tls")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_tls;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_tls;
  } else if (!strcmp(normalized, "dicom")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_dicom;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_dicom;
  } else if (!strcmp(normalized, "dns")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_dns;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_dns;
  } else if (!strcmp(normalized, "ftp")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_ftp;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_ftp;
  } else if (!strcmp(normalized, "mqtt")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_mqtt;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_mqtt;
  } else if (!strcmp(normalized, "rtsp")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_rtsp;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_rtsp;
  } else if (!strcmp(normalized, "dtls12") || !strcmp(normalized, "dtls")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_dtls12;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_dtls12;
  } else if (!strcmp(normalized, "sip")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_sip;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_sip;
  } else if (!strcmp(normalized, "http")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_http;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_http;
  } else if (!strcmp(normalized, "ipp")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_ipp;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_ipp;
  } else if (!strcmp(normalized, "dhcp")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_dhcp;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_dhcp;
  } else if (!strcmp(normalized, "tftp")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_tftp;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_tftp;
  } else if (!strcmp(normalized, "sntp")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_SNTP;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_SNTP;
  } else if (!strcmp(normalized, "ntp")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_NTP;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_NTP;
  } else if (!strcmp(normalized, "snmp")) {
    afl->aflnet->aflnet_extract_requests = extract_requests_SNMP;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_SNMP;
  } else {
    WARNF("Unsupported AFLNet protocol '%s', defaulting to FTP handlers", protocol);
    afl->aflnet->aflnet_extract_requests = extract_requests_ftp;
    afl->aflnet->aflnet_extract_response_codes = extract_response_codes_ftp;
    // FATAL("Unsupported AFLNet protocol '%s'", protocol);
  }

}

/* Initialise the AFLNet IPSM machinery to its defaults. */

void aflnet_state_init(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  if (!an) { return; }

  memset(an, 0, sizeof(aflnet_state_t));
  an->sock_mode = AFLNET_SOCK;
  an->state_mode = AFLNET_RESP_CODE_MODE;
  an->state_selection_algo = AFLNET_ROUND_ROBIN;
  an->seed_selection_algo = AFLNET_RANDOM_SELECTION;
  an->feedback_type = AFLNET_CODE_FEEDBACK;
  an->seed_schedule_type = AFLNET_IPSM_SCHEDULE;  /* original AFLNet default */
  an->time_gap = 600;                             /* original AFLNet default */
  an->last_path_time = 0;
  an->poll_wait_msecs = 1;                        /* original AFLNet default (-W) */
  an->socket_timeout_usecs = 1000;                /* original AFLNet default (-w) */
  an->terminate_child = 0;                        /* original AFLNet default (-K off) */
  an->server_wait_usecs = 10000;                  /* original AFLNet default (-D) */
  an->local_port = 0;                             /* original AFLNet default (-l off) */

  /* bind the state-sequence backend matching the default state mode */
  aflnet_state_bind_backend(afl);

  /* reset the protocol message-code map for a fresh per-run mapping */
  init_message_code_map();

  /* state variable feedback (state_mode == AFLNET_STATE_VAR_MODE): the SHM is created lazily
     in read_afl_environment after state_mode has been parsed from the
     environment, so that it is only allocated when actually needed. */

}

/* Release the AFLNet IPSM machinery. */

void aflnet_state_deinit(afl_state_t *afl) {

  aflnet_state_t *an = afl->aflnet;

  /* release the sock2shm shared memory segments (if sock_mode == AFLNET_SOCK2SHM) */
  aflnet_sock2shm_deinit(afl);

  if (an->state_ids) {

    for (u32 i = 0; i < an->state_ids_count; i++) {

      if (an->states[i]) {

        if (an->states[i]->seeds) { ck_free(an->states[i]->seeds); }
        ck_free(an->states[i]);

      }

    }

    ck_free(an->state_ids);
    ck_free(an->states);

  }

  if (an->was_fuzzed_map) {

    for (u32 i = 0; i < an->fuzzed_map_states; i++) {

      if (an->was_fuzzed_map[i]) { ck_free(an->was_fuzzed_map[i]); }

    }

    ck_free(an->was_fuzzed_map);

  }

  if (an->path_hashes) { ck_free(an->path_hashes); }
  if (an->ipsm_edges) { ck_free(an->ipsm_edges); }
  if (an->response_buf) { ck_free(an->response_buf); }
  if (an->response_bytes) { ck_free(an->response_bytes); }
  if (an->state_sequence) { ck_free(an->state_sequence); }
  if (an->region_m1) { afl_free(an->region_m1); }
  if (an->region_m2) { afl_free(an->region_m2); }
  if (an->region_m3) { afl_free(an->region_m3); }
  if (an->region_full) { afl_free(an->region_full); }

  aflnet_statevar_shm_deinit(afl);

  destroy_message_code_map();
  ck_free(an); 
  afl->aflnet = NULL;

}

/* Read the AFLNET_* environment variables and bring up the AFLNet mode. */

void aflnet_configure_from_env(afl_state_t *afl) {

  if (get_afl_env("AFLNET_URL") && get_afl_env("AFLNET_PROTOCOL")) {

    afl->afl_env.aflnet_mode = 1;

  } else {

    afl->afl_env.aflnet_mode = 0;

  }

  if (!afl->afl_env.aflnet_mode)
    return;

  OKF("AFLNet mode enabled.");

  afl->aflnet->aflnet_extract_requests = NULL;
  afl->aflnet->aflnet_extract_response_codes = NULL;

/* initialize the AFLNet state-aware (IPSM) machinery */

  aflnet_state_init(afl);

  /* NOTE: aflnet_state_init() memsets the whole struct, so the URL and
     protocol pointers must be (re-)assigned AFTER it, otherwise they end
     up NULL and the run aborts. */
  afl->aflnet->aflnet_url = (u8 *)get_afl_env("AFLNET_URL");
  afl->aflnet->aflnet_protocol = (u8 *)get_afl_env("AFLNET_PROTOCOL");

  if (!afl->aflnet->aflnet_url || !afl->aflnet->aflnet_protocol){

    FATAL("AFLNET_URL and AFLNET_PROTOCOL are required");

  }

  aflnet_set_protocol_handlers(afl, afl->aflnet->aflnet_protocol);

  /* Protocol grammar templates (AFLNET_GRAMMAR=<path>): import them once at
     startup and align the mutation strategies with the protocol type
     (text/binary).  They are used by the AFLNet region selection
     (src/aflnet/region.c), which narrows the mutation target M2 to one of
     the mutable fields a matching template describes.  Without
     AFLNET_GRAMMAR this is a no-op and the input mode is left untouched. */
  grammar_templates_init(afl, (const char *)afl->aflnet->aflnet_protocol);

  /* state-aware scheduling is on by default; disable with AFLNET_STATE_MODE=0 */
  const char *sa = get_afl_env("AFLNET_STATE_MODE");
  if (sa) { 

    int v = atoi(sa);
    if (v >= AFLNET_NO_STATE_MODE && v <= AFLNET_STATE_VAR_MODE) {

      afl->aflnet->state_mode = atoi(sa); 

    }

  }

  /* bind the state-sequence backend matching the final state mode */
  aflnet_state_bind_backend(afl);

  /* state variable feedback (state_mode == AFLNET_STATE_VAR_MODE): create the dedicated SHM
      that the instrumented target writes state-variable values into.
      Must happen before the forkserver starts so the child inherits it. */
  if (afl->aflnet->state_mode == AFLNET_STATE_VAR_MODE) { aflnet_statevar_shm_init(afl); }

  const char *ss = get_afl_env("AFLNET_STATE_SELECTION");
  if (ss) {

    int v = atoi(ss);
    if (v >= AFLNET_RANDOM_SELECTION && v <= AFLNET_FAVOR) {

      afl->aflnet->state_selection_algo = (u8)v;

    }

  }

  const char *se = get_afl_env("AFLNET_SEED_SELECTION");
  if (se) {

    int v = atoi(se);
    if (v >= AFLNET_RANDOM_SELECTION && v <= AFLNET_FAVOR) {

      afl->aflnet->seed_selection_algo = (u8)v;

    }

  }

  const char *fb = get_afl_env("AFLNET_FEEDBACK");
  if (fb) {

    int v = atoi(fb);
    if (v >= AFLNET_CODE_FEEDBACK && v <= AFLNET_CODE_STATE_FEEDBACK) {

      afl->aflnet->feedback_type = (u8)v;

    }

  }

  /* seed schedule type (mirrors original AFLNet -h):
       0 = code-aware (always normal seed selection)
       1 = hybrid (probabilistic switch to the IPSM scheduler)
       2 = ipSm (always state-aware; default) */
  const char *sc = get_afl_env("AFLNET_SCHEDULE");
  if (sc) {

    int v = atoi(sc);
    if (v >= AFLNET_CODE_AWARE_SCHEDULE && v <= AFLNET_IPSM_SCHEDULE) {

      afl->aflnet->seed_schedule_type = (u8)v;

    } else {

      WARNF("Invalid AFLNET_SCHEDULE '%s' (expected 0..2), using 2 (IPSM)",
            sc);

    }

  }

  /* time gap for the hybrid schedule (mirrors original AFLNet TIME_GAP env,
     default 600 seconds): the longer since a new path was found, the more
     likely the state-aware scheduler is used. */
  const char *tg = get_afl_env("AFLNET_TIME_GAP");
  if (tg) {

    int v = atoi(tg);
    if (v > 0) { afl->aflnet->time_gap = (u32)v; }

  }

  /* network timing (mirror original AFLNet -W / -w): poll_wait_msecs is the
     max time waited for a response before concluding no more responses are
     coming, socket_timeout_usecs is the per-send/recv socket timeout. */
  const char *pw = get_afl_env("AFLNET_POLL_WAIT_MSECS");
  if (pw) {

    int v = atoi(pw);
    if (v > 0) { afl->aflnet->poll_wait_msecs = (u32)v; }

  }

  const char *st = get_afl_env("AFLNET_SOCKET_TIMEOUT_USECS");
  if (st) {

    int v = atoi(st);
    if (v > 0) { afl->aflnet->socket_timeout_usecs = (u32)v; }

  }

  /* kill the target child after every network exchange so stateful servers
     start fresh on the next run (mirror original AFLNet -K). */
  const char *tc = get_afl_env("AFLNET_TERMINATE_CHILD");
  if (tc) { afl->aflnet->terminate_child = (atoi(tc) != 0); }

  /* wait after the socket is connected before the first send so the server
     finishes initializing (mirror original AFLNet -D). */
  const char *sw = get_afl_env("AFLNET_SERVER_WAIT_USECS");
  if (sw) {

    int v = atoi(sw);
    if (v > 0) { afl->aflnet->server_wait_usecs = (u32)v; }

  }

  /* bind the socket to a fixed local source port before connecting (mirror
     original AFLNet -l; needed for targets like Kamailio SIP that reply to
     a specific source port). */
  const char *lp = get_afl_env("AFLNET_LOCAL_PORT");
  if (lp) {

    int v = atoi(lp);
    if (v >= 1024 && v <= 65535) {

      afl->aflnet->local_port = (u32)v;

    } else {

      WARNF("Invalid AFLNET_LOCAL_PORT '%s' (expected 1024..65535), ignored",
            lp);

    }

  }

  /* AFLNET_CLEANUP_SCRIPT: optional script that cleans the server environment
     before each target execution (e.g., clear the FTP share directory) so that
     network fuzzing stays deterministic.  Mirrors original AFLNet's -c option. */
  const char *cs = get_afl_env("AFLNET_CLEANUP_SCRIPT");
  if (cs && cs[0]) {

    afl->aflnet->cleanup_script = (u8 *)cs;

  }

  /* sock_mode: how the fuzzer interacts with the target network socket
     0 = libaflppdesock (testcase via stdin, no late-send network I/O)
     1 = default AFLNet real-socket interaction
     2 = sock2shm (shared SHM message exchange) */

  const char *nf = get_afl_env("AFLNET_SOCK_MODE");
  if (nf) {

    int v = atoi(nf);
    if (v >= AFLNET_LIBDESOCK && v <= AFLNET_SOCK2SHM) {

      afl->aflnet->sock_mode = (u8)v;

      char mode_str[8];

      snprintf(mode_str, sizeof(mode_str), "%u", afl->aflnet->sock_mode);
      setenv(ENV_SOCK_MODE, mode_str, 1);

    } else {

      WARNF("Invalid AFLNET_SOCK_MODE '%s' (expected 0..2), using 1 (default "
            "AFLNet socket interaction)", nf);

    }

  }

  /* default real-socket interaction: still preload sockhook.so, which stays
       inert for sock_mode=1 (the server runs over plain sockets) unless the
       standalone SHM rendezvous below is requested */
  aflnet_sockhook_preload(afl);

  /* AFLNET_SHM_SYNC=1: arm the sockhook SHM rendezvous on top of the
     default real-socket interaction, so the target can tell the fuzzer when
     it is ready to accept the client and when it has handed the turn back.
     sock_mode=2 always implies it (the whole exchange goes through SHM). */
  const char *sync_env = get_afl_env("AFLNET_SHM_SYNC");
  if (sync_env && sync_env[0] && atoi(sync_env) > 0) {

    afl->aflnet->shm_sync = 1;

  }

  if (afl->aflnet->sock_mode == AFLNET_SOCK2SHM) {

    /* preloads sockhook.so and exports the SHM envs (sockhook engages) */
    afl->aflnet->shm_sync = 1;
    aflnet_sock2shm_setup(afl);

  } else if (afl->aflnet->sock_mode == AFLNET_LIBDESOCK) {

    // aflnet_desock_setup(afl);

  } else {

    if (afl->aflnet->shm_sync) {

      /* the fuzzer forwards its user-facing mode to the target as well, so
         the preloaded sockhook knows the messages stay on the real socket
         and only the handshake is armed */
      if (!getenv(ENV_SOCK_MODE)) { setenv(ENV_SOCK_MODE, "1", 1); }
      aflnet_sock_shm_sync_setup(afl);

    }

  }

  /* bind the per-message send/recv dispatch based on sock_mode:
     - AFLNET_SOCK      -> real-socket helpers (aflnet_sock_send_msg/recv_msg)
     - AFLNET_SOCK2SHM  -> shared-SHM helpers (aflnet_sock2shm_send_msg/recv_msg)
     - AFLNET_LIBDESOCK -> NULL/NULL: the testcase is delivered through stdin
                           by libaflppdesock, there is no late-send I/O. */
  if (afl->aflnet->sock_mode == AFLNET_SOCK) {

    /* standalone sockhook sync (sock_mode=1 + AFLNET_SHM_SYNC=1): the same
       per-run session arming as sock_mode=2 (state turn + is_end +
       connection_state), because the messages keep travelling over the real
       socket and only the rendezvous is shared.  Without the sync the plain
       (empty) socket session reset is the right thing. */
    afl->aflnet->aflnet_init_session = afl->aflnet->shm_sync
                                          ? aflnet_sock2shm_init_session
                                          : aflnet_sock_init_session;
    afl->aflnet->aflnet_send = aflnet_sock_send_msg;
    afl->aflnet->aflnet_recv = aflnet_sock_recv_msg;

  } else if (afl->aflnet->sock_mode == AFLNET_SOCK2SHM) {

    afl->aflnet->aflnet_init_session = aflnet_sock2shm_init_session;
    afl->aflnet->aflnet_send = aflnet_sock2shm_send_msg;
    afl->aflnet->aflnet_recv = aflnet_sock2shm_recv_msg;

  } else {

    // afl->aflnet->aflnet_init_session = aflnet_sock_init_session;    
    // afl->aflnet->aflnet_send = aflnet_sock_send_msg;
    // afl->aflnet->aflnet_recv = aflnet_sock_recv_msg;

  }

  /* session synchronisation for this run: pick the implementation of the
     configured sock mode.  Only the standalone rendezvous on top of the plain
     real-socket interaction needs the client-side driver; the SHM redirection
     (sock_mode=2) keeps its handshake inside the SHM message helpers, so it
     leaves sync_ops NULL and net.c drives nothing there. */
  if (afl->aflnet->sock_mode == AFLNET_SOCK && afl->aflnet->shm_sync) {

    afl->aflnet->sync_ops = &aflnet_shm_sync_ops;

  } else {

    afl->aflnet->sync_ops = NULL;

  }

  /* no persistent socket yet */
  afl->aflnet->sockfd = -1;

}

/* Resolve and preload sockhook.so into the target and export the default
   target-facing configuration the preloaded library needs in every server
   mode (ENV_NETPORT from AFLNET_URL, ENV_PROTOCOL_TYPE from AFLNET_PROTOCOL).
   sock_mode == AFLNET_SOCK2SHM additionally attaches the msg/check segments
   (aflnet_sock2shm_setup) which makes the library redirect the session I/O
   through the shared msg SHM; every other value keeps it inert (plain
   real-socket server), which is what makes the sockhook preload uniform. */
void aflnet_sockhook_preload(afl_state_t *afl) {

  const char *path;
  struct stat st;
#ifdef __linux__
  char        scheme[16];
  char        host[256];
  char        port_str[16];
  u32         port = 0;
  const char *proto_type = "TCP";
#endif

  /* Default target-facing configuration for the preloaded sockhook library,
     exported in every server mode (not just sock2shm): the port it matches
     bind()/SO_REUSEPORT against (ENV_NETPORT) and whether the protocol is a
     datagram one (ENV_PROTOCOL_TYPE -> SOCK_DGRAM).  Derived from the
     AFLNET_URL / AFLNET_PROTOCOL config that aflnet_configure_from_env() has
     already validated and stored. */
#ifdef __linux__
  if (afl->aflnet && afl->aflnet->aflnet_url) {

    aflnet_parse_url((const char *)afl->aflnet->aflnet_url, scheme,
                     sizeof(scheme), host, sizeof(host), &port);

    snprintf(port_str, sizeof(port_str), "%u", port);
    setenv(ENV_NETPORT, port_str, 1);

    if (aflnet_protocol_to_socket_type(
            (const char *)afl->aflnet->aflnet_protocol) == SOCK_DGRAM) {

      proto_type = "UDP";

    }

    setenv(ENV_PROTOCOL_TYPE, proto_type, 1);

  }

#endif

  path = getenv("AFLNET_SOCKHOOK_PATH");
  if (!path || !path[0]) {
    
    path = afl->afl_env.afl_path
               ? (const char *)alloc_printf("%s/utils/sockhook/sockhook.so",
                                            afl->afl_env.afl_path)
               : "sockhook.so";

    // if (stat("sockhook.so", &st) == 0) {

    //   path = "sockhook.so";

    // } else if (stat("utils/sockhook/sockhook.so", &st) == 0) {

    //   path = "utils/sockhook/sockhook.so";

    // } else {

    //   // path = "sockhook.so";
    //   path = afl->afl_env.afl_path ? alloc_printf("%s/utils/sockhook/sockhook.so",
    //                                          afl->afl_env.afl_path)
    //                              : "sockhook.so";

    // }

  }

  if (stat(path, &st) != 0) {

    WARNF("sockhook preload library '%s' not found; build it with "
          "'make -C utils/sockhook'", path);

  }

  const char *cur = getenv("AFL_PRELOAD");
  u8         *combined;

  if (cur && cur[0]) {

    combined = alloc_printf("%s:%s", cur, path);

  } else {

    combined = ck_strdup((u8 *)path);

  }

  setenv("AFL_PRELOAD", (const char *)combined, 1);
  ck_free(combined);

  /* read_afl_environment() cached afl->afl_env.afl_preload *before* this
     function appended sockhook.so to AFL_PRELOAD, so afl_check_environment()
     would otherwise skip copying AFL_PRELOAD -> LD_PRELOAD and the library
     would never actually be preloaded into the target.  Refresh the cached
     copy so the default preload (scenario: target always loads sockhook.so)
     really happens. */
  afl->afl_env.afl_preload = (u8 *)getenv("AFL_PRELOAD");

}
