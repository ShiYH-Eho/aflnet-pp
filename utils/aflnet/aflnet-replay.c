/* aflnet-replay.c - replay a structured AFLNet test case against a server.

   Ported from the original AFLNet repository (aflnet-replay.c) into
   aflnet-pp.  It reads a test case in AFLNet's "replayable" format, i.e. a
   sequence of [4-byte message size (host byte order)][message bytes] chunks
   (exactly what aflnet_save_testcase_to_file() writes when replay_enabled is
   set, and what ProFuzzBench keeps in the "replayable-*" folders), then sends
   the messages one by one and prints the response codes the server returned.

   Usage:
     aflnet-replay <packet_file> <protocol> <port> \
                   [first_resp_timeout(ms)] [follow-up_resp_timeout(us)]

   The protocol parsers are shared with the fuzzer (src/aflnet/protocols.c). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "alloc-inl.h"
#include "replay-net.h"

static void usage(const char *prog) {

  fprintf(stderr,
          "Usage: %s packet_file protocol port "
          "[first_resp_timeout(ms) [follow-up_resp_timeout(us)]]\n"
          "\n"
          "Replays a structured AFLNet test case (sequence of\n"
          "length-prefixed messages) against a server listening on "
          "127.0.0.1:<port>\n"
          "and prints the response codes extracted from the server's "
          "answers.\n"
          "\n"
          "  packet_file             replayable test case to send\n"
          "  protocol                e.g. FTP, RTSP, SMTP, SSH, TLS, DNS, "
          "SIP, ...\n"
          "  port                    server port\n"
          "  first_resp_timeout      poll() timeout in ms (default 1)\n"
          "  follow-up_resp_timeout  socket timeout in us (default 1000)\n",
          prog);

}

int main(int argc, char *argv[]) {

  if ((argc == 2) && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {

    usage(argv[0]);
    return 0;

  }

  if (argc < 4) {

    usage(argv[0]);
    return 1;

  }

  const char *packet_file = argv[1];
  const char *protocol = argv[2];
  int         port = atoi(argv[3]);

  /* Same defaults and argument order as the original aflnet-replay. */
  unsigned int poll_timeout = 1;       /* argv[4], poll() timeout in ms   */
  unsigned int socket_timeout = 1000;  /* argv[5], socket timeout in us   */

  if (argc > 4) {

    poll_timeout = (unsigned int)atoi(argv[4]);
    if (argc > 5) { socket_timeout = (unsigned int)atoi(argv[5]); }

  }

  aflnet_extract_response_codes_fn extract_response_codes =
      replay_response_code_extractor(protocol);

  if (!extract_response_codes) {

    fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n",
            protocol);
    return 1;

  }

  unsigned int fsize = 0;
  u8          *data = replay_load_file(packet_file, &fsize);

  /* Give the server time to finish its own start up. */
  usleep(REPLAY_SERVER_WAIT_USECS);

  int sockfd = replay_connect(protocol, port, (int)socket_timeout);

  if (sockfd < 0) {

    fprintf(stderr, "[AFLNet-replay] Cannot connect to 127.0.0.1:%d\n", port);
    ck_free(data);
    return 1;

  }

  char         *response_buf = NULL;
  unsigned int  response_buf_size = 0;
  unsigned int  offset = 0;
  unsigned int  packet_count = 0;

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout;

  /* Send the requests one by one and keep all server responses.  The recv
     before each send drains whatever the server sent on its own (e.g. the FTP
     banner), exactly like the original replayer. */
  while (offset + 4 <= fsize) {

    unsigned int size;
    memcpy(&size, data + offset, sizeof(size));
    offset += 4;

    /* `size > fsize - offset` (rather than `offset + size > fsize`) avoids an
       unsigned overflow on a corrupt/truncated 4-byte length field, which
       would otherwise let an absurd size through and read out of bounds. */
    if (!size || size > fsize - offset) {

      fprintf(stderr,
              "[AFLNet-replay] Warning: invalid/truncated message (%u bytes) "
              "at offset %u, stopping\n",
              size, offset - 4);
      break;

    }

    packet_count++;
    fprintf(stderr, "\nSize of the current packet %u is  %u\n", packet_count,
            size);

    if (replay_net_recv(sockfd, timeout, (int)poll_timeout, &response_buf,
                        &response_buf_size)) {

      break;

    }

    int n = replay_net_send(sockfd, timeout, (char *)data + offset, size);
    if (n < 0 || (unsigned int)n != size) { break; }

    if (replay_net_recv(sockfd, timeout, (int)poll_timeout, &response_buf,
                        &response_buf_size)) {

      break;

    }

    offset += size;

  }

  close(sockfd);
  ck_free(data);

  /* Extract and report the response codes. */
  unsigned int  state_count = 0;
  unsigned int *state_sequence =
      extract_response_codes((unsigned char *)response_buf, response_buf_size,
                             &state_count);

  replay_print_results(state_sequence, state_count, response_buf,
                       response_buf_size);

  if (state_sequence) { ck_free(state_sequence); }
  if (response_buf) { ck_free(response_buf); }

  return 0;

}
