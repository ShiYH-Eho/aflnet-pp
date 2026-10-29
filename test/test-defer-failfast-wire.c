/*
   test-defer-failfast-wire.c - helper for test-defer-failfast.sh.

   Mimics what afl-fuzz does to the process it execs as the target: it wires
   its forkserver pipes to the fixed descriptors FORKSRV_FD/FORKSRV_FD + 1
   (198/199 here) *before* the exec, and then execs the target.  A preloaded
   library can use that to tell a real target from a helper that merely
   inherited its environment (the AFLNET_CLEANUP_SCRIPT shell, for example).

   Only the exec'd program gets the preload, so the wiring itself is not
   affected by it.

   usage: test-defer-failfast-wire <preload> <program> [args ...]
*/

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define WIRE_FD 198

int main(int argc, char **argv) {

  int nullfd;

  if (argc < 3) {

    fprintf(stderr, "usage: %s <preload> <program> [args ...]\n", argv[0]);
    return 2;

  }

  nullfd = open("/dev/null", O_RDWR);
  if (nullfd < 0) { perror("open"); return 2; }

  if (dup2(nullfd, WIRE_FD) < 0 || dup2(nullfd, WIRE_FD + 1) < 0) {

    perror("dup2");
    return 2;

  }

  if (nullfd != WIRE_FD && nullfd != WIRE_FD + 1) { close(nullfd); }

  setenv("LD_PRELOAD", argv[1], 1);
  execv(argv[2], &argv[2]);

  perror("execv");
  return 2;

}
