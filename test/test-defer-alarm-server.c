/*
   test-defer-alarm-server.c - helper for test-defer-alarm.sh.

   A minimal TCP echo server that mimics proftpd's timer behaviour: it arms a
   wall-clock alarm() during startup (i.e. *before* anything starts the
   deferred forkserver) and its SIGALRM handler terminates the process.  In
   deferred mode that timer belongs to the process which becomes the
   forkserver parent, where the signal would take the whole forkserver down
   ("Unable to communicate with fork server").  The preloaded library has to
   park it across the forkserver start and hand it back to the children.

   usage: <port> <logfile>
   The log records, once per per-test child, whether SIGALRM was unblocked and
   how much time was left on the alarm, i.e. whether the child got its timer
   back.
*/

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFSZ 4096

static const char *log_path;

static void note(const char *fmt, ...) {

  char    buf[256];
  va_list ap;
  int     fd, n;

  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (n <= 0) { return; }

  fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) { return; }

  if (write(fd, buf, (size_t)n) < 0) { /* not fatal for the test */ }
  close(fd);

}

static void on_alarm(int sig) {

  (void)sig;
  note("alarm-fired pid=%d\n", (int)getpid());
  _exit(3);

}

int main(int argc, char **argv) {

  int                listen_fd, conn_fd, opt = 1, n;
  int                port = (argc > 1) ? atoi(argv[1]) : 8090;
  struct sockaddr_in addr;
  sigset_t           cur;
  unsigned int       remaining;
  char               buf[BUFSZ];

  log_path = (argc > 2) ? argv[2] : "/dev/null";

  /* the timer proftpd-style: armed before the deferred forkserver exists */
  signal(SIGALRM, on_alarm);
  alarm(1);

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

  note("parent pid=%d about to listen\n", (int)getpid());

  /* in deferred mode the forkserver starts inside this call; only the
     per-test children return from it */
  if (listen(listen_fd, 32) < 0) { perror("listen"); return 1; }

  /* report what the preload left us: the mask must be restored and the
     alarm re-armed (reading it cancels it, fine for the test) */
  sigemptyset(&cur);
  sigprocmask(SIG_SETMASK, NULL, &cur);
  remaining = alarm(0);
  note("child pid=%d blocked=%d remaining=%u\n", (int)getpid(),
       sigismember(&cur, SIGALRM), remaining);

  for (;;) {

    conn_fd = accept(listen_fd, NULL, NULL);
    if (conn_fd < 0) { continue; }

    while ((n = (int)recv(conn_fd, buf, sizeof(buf), 0)) > 0) {

      send(conn_fd, buf, (size_t)n, 0);

    }

    close(conn_fd);

  }

  return 0;

}
