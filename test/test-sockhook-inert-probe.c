/*
   test-sockhook-inert-probe.c - helper for test-sockhook-inert.sh.

   Binds to the AFLNet target port and reports whether the preloaded library
   treated this process as the fuzz target: only then does its bind() hook set
   SO_REUSEPORT on the target-port socket.  A process the library recognises as
   a plain helper must come out with reuseport=0 - and must still run at all:
   with the bogus SHM ids the test passes in that configuration, an active
   library would _exit(1) in setup_shm().

   usage: <port>   (or __AFL_NETPORT in the environment)
*/

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {

  int                fd, port = (argc > 1) ? atoi(argv[1]) : 8091;
  int                reuse = -1;
  socklen_t          rlen = sizeof(reuse);
  const char        *np = getenv("__AFL_NETPORT");
  struct sockaddr_in a;

  if (np) { port = atoi(np); }

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { perror("socket"); return 2; }

  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons((uint16_t)port);

  if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {

    printf("bind=fail errno=%d reuseport=?\n", errno);
    return 0;

  }

  if (getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, &rlen) < 0) {

    printf("bind=ok reuseport=?\n");
    return 0;

  }

  printf("bind=ok reuseport=%d\n", reuse != 0);
  close(fd);
  return 0;

}
