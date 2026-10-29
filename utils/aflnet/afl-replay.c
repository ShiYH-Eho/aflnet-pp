/* afl-replay.c - replay a raw AFLNet test case against a server.

   Ported from the original AFLNet repository (afl-replay.c) into aflnet-pp.
   Unlike aflnet-replay, this tool does not know about message boundaries: it
   sends the whole test case as one blob and then collects the server
   responses.  It is used for the raw corpus (ProFuzzBench's "queue"/"crashes"
   folders) where the concatenated messages are not length-prefixed.

   Usage:
     afl-replay <packet_file> <protocol> <port> \
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
          "Replays a raw (concatenated) AFLNet test case against a server\n"
          "listening on 127.0.0.1:<port> and prints the response codes\n"
          "extracted from the server's answers.\n"
          "\n"
          "  packet_file             raw test case to send\n"
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

  /* Same defaults and argument order as the original afl-replay. */
  unsigned int poll_timeout = 1;       /* argv[4], poll() timeout in ms   */
  unsigned int socket_timeout = 1000;  /* argv[5], socket timeout in us   */

  if (argc > 4) {

    poll_timeout = (unsigned int)atoi(argv[4]);
    if (argc > 5) { socket_timeout = (unsigned int)atoi(argv[5]); }

  }

  aflnet_extract_response_codes_fn extract_response_codes =
      replay_response_code_extractor(protocol);

  if (!extract_response_codes) {

    fprintf(stderr, "[AFL-replay] Protocol %s has not been supported yet!\n",
            protocol);
    return 1;

  }

  unsigned int fsize = 0;
  u8          *data = replay_load_file(packet_file, &fsize);

  /* Give the server time to finish its own start up. */
  usleep(REPLAY_SERVER_WAIT_USECS);

  int sockfd = replay_connect(protocol, port, (int)socket_timeout);

  if (sockfd < 0) {

    fprintf(stderr, "[AFL-replay] Cannot connect to 127.0.0.1:%d\n", port);
    ck_free(data);
    return 1;

  }

  char         *response_buf = NULL;
  unsigned int  response_buf_size = 0;

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout;

  /* Write the whole test case at once, then collect the responses. */
  replay_net_send(sockfd, timeout, (char *)data, fsize);
  replay_net_recv(sockfd, timeout, (int)poll_timeout, &response_buf,
                  &response_buf_size);

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
