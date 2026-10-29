/* replay-net.c - shared helpers for the AFLNet standalone replayers.

   See replay-net.h for the overview.  The transport helpers are a faithful
   port of net_send()/net_recv() from the original AFLNet's aflnet.c, the
   protocol dispatch mirrors src/aflnet/net.c and src/aflnet/config.c. */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "alloc-inl.h"
#include "replay-net.h"

#ifndef MSG_NOSIGNAL
  #define MSG_NOSIGNAL 0
#endif

/* ------------------------------------------------------------------ */
/* protocol dispatch                                                  */
/* ------------------------------------------------------------------ */

/* Case-insensitive comparison so that both the canonical AFLNet spelling
   ("FTP", "DTLS12", "SNTP") and the lower-case fuzzer spelling ("ftp") work. */

static int replay_str_ieq(const char *a, const char *b) {

  while (*a && *b) {

    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) { return 0; }
    ++a;
    ++b;

  }

  return *a == *b;

}

aflnet_extract_response_codes_fn replay_response_code_extractor(
    const char *protocol) {

  if (!protocol) { return NULL; }

  /* The order matters: check "sntp" before "ntp" is not required because the
     comparison is on the whole string, but keep the list aligned with the
     declarations in include/aflnet.h and the dispatch in src/aflnet/config.c. */

  if (replay_str_ieq(protocol, "SMTP")) { return extract_response_codes_smtp; }
  if (replay_str_ieq(protocol, "SSH")) { return extract_response_codes_ssh; }
  if (replay_str_ieq(protocol, "TLS")) { return extract_response_codes_tls; }
  if (replay_str_ieq(protocol, "DICOM")) { return extract_response_codes_dicom; }
  if (replay_str_ieq(protocol, "DNS")) { return extract_response_codes_dns; }
  if (replay_str_ieq(protocol, "FTP")) { return extract_response_codes_ftp; }
  if (replay_str_ieq(protocol, "MQTT")) { return extract_response_codes_mqtt; }
  if (replay_str_ieq(protocol, "RTSP")) { return extract_response_codes_rtsp; }
  if (replay_str_ieq(protocol, "DTLS12") || replay_str_ieq(protocol, "DTLS")) {

    return extract_response_codes_dtls12;

  }

  if (replay_str_ieq(protocol, "SIP")) { return extract_response_codes_sip; }
  if (replay_str_ieq(protocol, "HTTP")) { return extract_response_codes_http; }
  if (replay_str_ieq(protocol, "IPP")) { return extract_response_codes_ipp; }
  if (replay_str_ieq(protocol, "DHCP")) { return extract_response_codes_dhcp; }
  if (replay_str_ieq(protocol, "TFTP")) { return extract_response_codes_tftp; }
  if (replay_str_ieq(protocol, "SNTP")) { return extract_response_codes_SNTP; }
  if (replay_str_ieq(protocol, "NTP")) { return extract_response_codes_NTP; }
  if (replay_str_ieq(protocol, "SNMP")) { return extract_response_codes_SNMP; }

  return NULL;

}

int replay_socket_type(const char *protocol) {

  if (!protocol) { return SOCK_STREAM; }

  /* Datagram transports, mirroring aflnet_protocol_to_socket_type(). */
  if (replay_str_ieq(protocol, "DNS") || replay_str_ieq(protocol, "DHCP") ||
      replay_str_ieq(protocol, "TFTP") || replay_str_ieq(protocol, "SNTP") ||
      replay_str_ieq(protocol, "NTP") || replay_str_ieq(protocol, "SNMP") ||
      replay_str_ieq(protocol, "DTLS12") || replay_str_ieq(protocol, "DTLS") ||
      replay_str_ieq(protocol, "SIP")) {

    return SOCK_DGRAM;

  }

  return SOCK_STREAM;

}

/* ------------------------------------------------------------------ */
/* test case loading                                                  */
/* ------------------------------------------------------------------ */

u8 *replay_load_file(const char *path, unsigned int *size) {

  FILE *fp = fopen(path, "rb");

  if (!fp) {

    fprintf(stderr, "[AFLNet-replay] Error opening file %s\n", path);
    exit(1);

  }

  if (fseek(fp, 0, SEEK_END) != 0) { PFATAL("fseek() failed on %s", path); }

  long fsize = ftell(fp);
  if (fsize < 0) { PFATAL("ftell() failed on %s", path); }

  rewind(fp);

  /* ck_alloc(0) is not well defined for all allocators, so always request at
     least one byte; *size still reports the real length. */
  u8 *buf = (u8 *)ck_alloc(fsize > 0 ? (u32)fsize : 1);

  if (fsize > 0 && fread(buf, (size_t)fsize, 1, fp) != 1) {

    PFATAL("fread() failed on %s", path);

  }

  fclose(fp);

  *size = (unsigned int)fsize;
  return buf;

}

/* ------------------------------------------------------------------ */
/* connection setup                                                   */
/* ------------------------------------------------------------------ */

int replay_connect(const char *protocol, int port, int socket_timeout_usecs) {

  int sockfd = socket(AF_INET, replay_socket_type(protocol), 0);

  if (sockfd < 0) { PFATAL("Cannot create a socket"); }

  /* Otherwise a send/recv can block for a long time when the server stays
     alive after processing all requests. */
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout_usecs;
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
             sizeof(timeout));

  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons((unsigned short)port);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {

    /* The server's startup time varies, so retry for up to ~1 second. */
    int n;
    for (n = 0; n < REPLAY_CONNECT_RETRIES; n++) {

      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
          0) {

        break;

      }

      usleep(1000);

    }

    if (n == REPLAY_CONNECT_RETRIES) {

      close(sockfd);
      return -1;

    }

  }

  return sockfd;

}

/* ------------------------------------------------------------------ */
/* transport (faithful port of AFLNet's net_send/net_recv)             */
/* ------------------------------------------------------------------ */

int replay_net_send(int sockfd, struct timeval timeout, const char *mem,
                    unsigned int len) {

  unsigned int  byte_count = 0;
  int           n;
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

        if (n == 0) { return (int)byte_count; }
        if (n == -1) { return -1; }

        byte_count += (unsigned int)n;

      }

    }

  }

  return (int)byte_count;

}

int replay_net_recv(int sockfd, struct timeval timeout, int poll_w,
                    char **response_buf, unsigned int *len) {

  char          temp_buf[1000];
  int           n;
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
        *response_buf =
            (char *)ck_realloc(*response_buf, *len + (unsigned int)n + 1);
        memcpy(&(*response_buf)[*len], temp_buf, (size_t)n);
        (*response_buf)[(*len) + (unsigned int)n] = '\0';
        *len = *len + (unsigned int)n;

        n = recv(sockfd, temp_buf, sizeof(temp_buf), 0);
        if ((n < 0) && (errno != EAGAIN)) { return 1; }

      }

    }

  } else if (rv < 0) {

    return 1;

  }

  /* rv == 0 (poll timeout) or all pending data has been drained. */
  return 0;

}

/* ------------------------------------------------------------------ */
/* result reporting                                                   */
/* ------------------------------------------------------------------ */

void replay_print_results(const unsigned int *state_sequence,
                          unsigned int        state_count,
                          const char         *response_buf,
                          unsigned int        response_buf_size) {

  unsigned int i;

  fprintf(stderr, "\n--------------------------------");
  fprintf(stderr, "\nResponses from server: ");

  for (i = 0; i < state_count; i++) {

    fprintf(stderr, "%d-", state_sequence ? state_sequence[i] : 0);

  }

  fprintf(stderr, "\n++++++++++++++++++++++++++++++++\nResponses in details:\n");

  for (i = 0; i < response_buf_size; i++) {

    fprintf(stderr, "%c", response_buf[i]);

  }

  fprintf(stderr, "\n--------------------------------\n");

}
