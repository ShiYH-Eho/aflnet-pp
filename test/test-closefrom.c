/*
   test-closefrom.c - helper for test-closefrom-hook.sh.

   Reports, in one machine-readable line, what a target's descriptor
   sanitisation leaves behind: an ordinary descriptor (7) and AFL's forkserver
   descriptors (198/199).  The preloaded sockhook has to keep the two
   forkserver descriptors alive while a deferred forkserver is still waiting
   for its handshake, and behave exactly like libc otherwise.

   Build with -rdynamic: with __AFL_DEFER_FORKSRV in the environment the
   preloaded library insists on resolving __afl_manual_init() (this helper is
   not an AFL target, hence the stand-in below).

   usage: test-closefrom <closefrom|closeloop> [connected]
     closefrom  sanitise through closefrom(3) (needs libc or the preload to
                provide it)
     closeloop  close the descriptors one by one, like a target that does its
                own fd cleanup instead of calling closefrom()
     connected  pretend the forkserver handshake already happened
                (__afl_connected = 1), i.e. the forked per-test child

   output, one line on stdout:
     closefrom-unavailable                        (no libc closefrom(), no preload)
     fd7=closed fd198=closed fd199=closed
     fd7=closed fd198=alive  fd199=alive
*/

#define _GNU_SOURCE

#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* weak: libc before 2.34 has no closefrom(); the call is then only possible
   when the preloaded library provides the symbol */
extern void closefrom(int lowfd) __attribute__((weak));

/* stand-in for the AFL++ runtime entry point (see the file comment) */
void __afl_manual_init(void) { }

/* stand-in for the AFL++ runtime's "forkserver already started" flag */
unsigned int __afl_connected = 0;

static const char *state(int fd) {

  return (fcntl(fd, F_GETFD) >= 0) ? "alive" : "closed";

}

int main(int argc, char **argv) {

  int         nullfd, fd;
  int         via_closefrom = 1;

  if (argc > 1 && strcmp(argv[1], "closeloop") == 0) { via_closefrom = 0; }
  if (argc > 2 && strcmp(argv[2], "connected") == 0) { __afl_connected = 1; }

  if (via_closefrom && !closefrom) {

    printf("closefrom-unavailable\n");
    return 0;

  }

  nullfd = open("/dev/null", O_RDWR);
  if (nullfd < 0) { return 2; }

  dup2(nullfd, 7);
  dup2(nullfd, 198);
  dup2(nullfd, 199);
  if (nullfd != 7 && nullfd != 198 && nullfd != 199) { close(nullfd); }

  if (via_closefrom) {

    closefrom(3);

  } else {

    /* a target closing its inherited descriptors one by one */
    for (fd = 3; fd < 512; fd++) { close(fd); }

  }

  printf("fd7=%s fd198=%s fd199=%s\n", state(7), state(198), state(199));
  return 0;

}
