/*
   test-defer-stale-server.c - target for test-defer-stale.sh.

   A minimal one-session TCP server (accept, echo until EOF, exit) used to
   exercise the accept queue the deferred forkserver's children inherit.

   usage: <port> <log> [boom-flag]

   If the flag file exists the server unlinks it and exits before accept(),
   i.e. it leaves the connection the fuzzer has just opened queued in the
   listening socket - the situation the deferred forkserver must survive.

   The log records, once per accepted connection, whether the peer had
   already closed when the connection was accepted (TCP_CLOSE_WAIT / reset):
   such a connection is a leftover of an earlier run, not the run's session.

   Build (instrumented, the deferred forkserver needs the AFL++ runtime):
     afl-cc -o test-defer-stale-server test-defer-stale-server.c
*/

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFSZ 4096

static const char *log_path;

static void note(const char *what) {

  int  fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  char buf[128];
  int  n;

  if (fd < 0) { return; }

  n = snprintf(buf, sizeof(buf), "%s pid=%d\n", what, (int)getpid());
  if (write(fd, buf, (size_t)n) < 0) { /* not fatal for the test */ }
  close(fd);

}

int main(int argc, char **argv) {

  int                listen_fd, conn_fd, opt = 1, n;
  int                port = (argc > 1) ? atoi(argv[1]) : 8098;
  struct sockaddr_in addr;
  struct tcp_info    info;
  socklen_t          info_len = sizeof(info);
  char               buf[BUFSZ];

  if (argc < 3) {

    fprintf(stderr, "usage: %s <port> <log> [boom-flag]\n", argv[0]);
    return 2;

  }

  log_path = argv[2];

  listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0) { perror("socket"); return 1; }

  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)port);

  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {

    perror("bind");
    return 1;

  }

  if (listen(listen_fd, 32) < 0) { perror("listen"); return 1; }

  /* leave the fuzzer's connection queued exactly once */
  if (argc > 3 && access(argv[3], F_OK) == 0) {

    unlink(argv[3]);
    note("oneshot-exit-before-accept");
    return 0;

  }

  conn_fd = accept(listen_fd, NULL, NULL);
  if (conn_fd < 0) { return 1; }

  if (getsockopt(conn_fd, IPPROTO_TCP, TCP_INFO, &info, &info_len) == 0 &&
      (info.tcpi_state == TCP_CLOSE_WAIT || info.tcpi_state == TCP_CLOSE)) {

    note("stale");

  } else {

    note("served");

  }

  while ((n = (int)recv(conn_fd, buf, sizeof(buf), 0)) > 0) {

    send(conn_fd, buf, (size_t)n, 0);

  }

  close(conn_fd);

  return 0;

}
