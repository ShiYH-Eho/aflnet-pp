/* replay-net.h - shared helpers for the AFLNet standalone replayers.

   Ported from the original AFLNet repository (aflnet-replay.c / afl-replay.c
   and the net_send()/net_recv() helpers in aflnet.c) into aflnet-pp.

   The replayers are small client programs that connect to a server under
   test, replay a recorded test case, and report the response codes the server
   produced.  They are used by ProFuzzBench's crash_script / cov_script.sh
   (aflnet-replay for the structured "replayable-*" corpus, afl-replay for the
   raw "queue"/"crashes" corpus).

   The protocol parsers (extract_response_codes_*) are NOT duplicated here:
   the replayers link ../../src/aflnet/protocols.c, the very same file the
   fuzzer uses, so both stay in sync automatically. */

#ifndef AFLNET_REPLAY_NET_H
#define AFLNET_REPLAY_NET_H

#include <sys/time.h>

#include "types.h"
#include "aflnet.h"

/* Default delay (us) before the first connect attempt.  The server may still
   be starting up, so the original AFLNet replayers sleep 10 ms first. */
#define REPLAY_SERVER_WAIT_USECS 10000

/* Number of connect retries (1 ms apart) while the server comes up. */
#define REPLAY_CONNECT_RETRIES 1000

/* Read a whole file into a ck_alloc()'d buffer and store its size in *size.
   Exits with an error message when the file cannot be read. */
u8 *replay_load_file(const char *path, unsigned int *size);

/* Case-insensitive protocol name -> response-code extractor.  Returns NULL
   when the protocol is not supported (the caller prints the error). */
aflnet_extract_response_codes_fn replay_response_code_extractor(
    const char *protocol);

/* SOCK_STREAM / SOCK_DGRAM for a protocol, mirroring the fuzzer's
   aflnet_protocol_to_socket_type() so the replayers speak the same transport
   as afl-fuzz does. */
int replay_socket_type(const char *protocol);

/* Connect to 127.0.0.1:<port> with the upstream retry loop.  Returns a
   connected fd, or -1 when the server never came up. */
int replay_connect(const char *protocol, int port, int socket_timeout_usecs);

/* Low-level poll()-based send/recv, a faithful port of AFLNet's
   net_send()/net_recv().  Both return 0 on success and non-zero on a
   transport error (send returns the number of bytes written). */
int replay_net_send(int sockfd, struct timeval timeout, const char *mem,
                    unsigned int len);
int replay_net_recv(int sockfd, struct timeval timeout, int poll_w,
                    char **response_buf, unsigned int *len);

/* Print the extracted state sequence plus the raw response bytes to stderr,
   in the exact format the original aflnet-replay/afl-replay used. */
void replay_print_results(const unsigned int *state_sequence,
                          unsigned int        state_count,
                          const char         *response_buf,
                          unsigned int        response_buf_size);

#endif /* AFLNET_REPLAY_NET_H */
