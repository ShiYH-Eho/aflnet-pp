/*
   test-echo-server.c - minimal TCP echo server used to exercise aflpp-net's
   network interaction backends:

     sock_mode=0 (libaflppdesock): target is preloaded with libaflppdesock.so,
         the testcase is delivered through stdin (recv on the session socket
         is redirected to FD 0), and the process exits after the session
         (DESOCK_CLOSE_EXIT=1).
     sock_mode=1 (default AFLNet): the fuzzer connects a real socket and
         exchanges request/response over the network stack.
     sock_mode=2 (sock2shm): target is preloaded with sock2shm.so; the fuzzer
         still opens a real socket so accept() completes, but send/recv on the
         session fd are redirected through the shared msg SHM segment.

   The server simply echoes back everything it receives.  A request containing
   the magic string "CRASH!" triggers abort(), giving the fuzzer a crash to
   find.

   Build (instrumented, for coverage; afl-cc from AFL++):
     afl-cc -o test-echo-server test-echo-server.c

   Run it manually with sock2shm:
     LD_PRELOAD=./sock2shm.so ./test-echo-server 8080

   See test-echo-sock2shm.sh for a full afl-fuzz smoke test of all three
   sock_modes plus the sock2shm forkserver (AFLNET_SOCK2SHM_FORK=1).
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAGIC_CRASH "CRASH!"
#define BUFSZ 4096

int main(int argc, char **argv) {

  int  listen_fd, conn_fd, opt = 1, n;
  int  port = (argc > 1) ? atoi(argv[1]) : 8080;
  struct sockaddr_in addr;
  char buf[BUFSZ];

  listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0) { perror("socket"); return 1; }

  /* SO_REUSEPORT lets a freshly forked/restarted server rebind the port
     (sock2shm uses it too). */
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);

  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {

    perror("bind");
    return 1;

  }

  if (listen(listen_fd, 32) < 0) {

    perror("listen");
    return 1;

  }

  fprintf(stderr, "echo server listening on port %d\n", port);

  for (;;) {

    conn_fd = accept(listen_fd, NULL, NULL);
    if (conn_fd < 0) { perror("accept"); continue; }

    while ((n = (int)recv(conn_fd, buf, sizeof(buf), 0)) > 0) {

      if (memmem(buf, (size_t)n, MAGIC_CRASH, sizeof(MAGIC_CRASH) - 1)) {

        abort();

      }

      send(conn_fd, buf, (size_t)n, 0);

    }

    close(conn_fd);

  }

  return 0;

}
