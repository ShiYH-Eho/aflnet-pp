/* test-shmsync.c - deterministic test of the standalone sockhook SHM
   rendezvous (sock_mode=1 + AFLNET_SHM_SYNC=1).

   Unlike test-echo-sock2shm.sh this does not need afl-fuzz: it plays the
   fuzzer's client side itself, so the contract the preloaded library has to
   honour can be asserted exactly:

     case A (sync armed, __AFL_SHMSYNC=1 + __AFL_SOCK_MODE=1)
       1. the target publishes RUNNING on the check segment from accept(), so
          the fuzzer knows the server is ready to be dialled;
       2. the target does NOT read the request before the fuzzer hands the
          turn over (state CLIENT -> SERVER), so the request cannot be lost;
       3. after the handover the response is on the real socket;
       4. is_end + handover makes the parked target end the session, so the
          fuzzer does not have to wait for the TCP close.

     case B (no segments, __AFL_SOCK_MODE=1 only) - the default real-socket
       configuration: the library stays inert and the exchange needs no
       handshake at all.

   Build: cc -O1 -I include -I utils/sockhook -o test/test-shmsync \
              test/test-shmsync.c
   Run from the repo root: ./test/test-shmsync.sh                        */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sock2shm_utils.h"

static int failures = 0;

static void check(int cond, const char *msg) {

  printf("%s %s\n", cond ? "[+]" : "[!]", msg);
  if (!cond) { failures++; }

}

static long now_ms(void) {

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;

}

/* wait until cond() holds, at most budget_ms; returns 1 on success */
#define WAIT_FOR(expr, budget_ms, out_ms)                                     \
  ({                                                                          \
    long _t0 = now_ms();                                                      \
    int  _ok = 0;                                                             \
    while (now_ms() - _t0 < (budget_ms)) {                                    \
      if (expr) { _ok = 1; break; }                                           \
      usleep(1000);                                                           \
    }                                                                         \
    if (out_ms) { *(out_ms) = now_ms() - _t0; }                               \
    _ok;                                                                      \
  })

/* an unused local TCP port (bind 0, read it back, close) */
static int free_port(void) {

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a;
  socklen_t len = sizeof(a);

  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
      getsockname(fd, (struct sockaddr *)&a, &len) != 0) {

    close(fd);
    return 0;

  }

  int port = ntohs(a.sin_port);
  close(fd);
  return port;

}

static pid_t spawn_target(int port, int login_ignore) {

  (void)login_ignore;
  pid_t pid = fork();

  if (pid == 0) {

    char p[16];
    int  devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }
    snprintf(p, sizeof(p), "%d", port);
    execl("./test/test-echo-server", "test-echo-server", p, (char *)NULL);
    _exit(127);

  }

  return pid;

}

static int connect_to(int port) {

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a;
  struct timeval tv = {.tv_sec = 0, .tv_usec = 1000};

  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons((unsigned short)port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {

    close(fd);
    return -1;

  }

  return fd;

}

/* read whatever arrives within budget_ms (like aflnet_net_recv: poll, then
   drain with a short SO_RCVTIMEO); returns the byte count, -1 if the peer
   closed the connection */
static int read_response(int fd, char *buf, size_t bufsz, int budget_ms) {

  struct pollfd pfd = {.fd = fd, .events = POLLIN};
  int           total = 0;

  long t0 = now_ms();
  while (now_ms() - t0 < budget_ms) {

    if (poll(&pfd, 1, 1) > 0) {

      ssize_t n = recv(fd, buf + total, bufsz - 1 - total, 0);
      if (n == 0) { return -1; }
      if (n < 0) {
        if (errno == EAGAIN) { break; }
        return -1;
      }
      total += (int)n;
      t0 = now_ms();

    }

  }

  buf[total] = 0;
  return total;

}

int main(int argc, char **argv) {

  int   sync_case = (argc > 1 && strcmp(argv[1], "sync") == 0);
  int   port = free_port();
  msg     *smsg = NULL;
  shm_sig *ssig = NULL;
  int      msg_id = -1, chk_id = -1;
  char     id[32];
  pid_t    pid;
  int      fd, n;
  char     buf[512];
  long     waited = 0;

  if (!port) { printf("[!] no free port\n"); return 1; }

  if (access("./sockhook.so", R_OK) != 0) {
    printf("[!] ./sockhook.so is missing (run make -C utils/sockhook)\n");
    return 1;
  }

  if (access("./test/test-echo-server", X_OK) != 0) {
    printf("[!] ./test/test-echo-server is missing\n");
    return 1;
  }

  if (sync_case) {

    msg_id = shmget(IPC_PRIVATE, sizeof(msg), IPC_CREAT | IPC_EXCL | 0600);
    chk_id = shmget(IPC_PRIVATE, sizeof(shm_sig), IPC_CREAT | IPC_EXCL | 0600);
    if (msg_id < 0 || chk_id < 0) { printf("[!] shmget failed\n"); return 1; }

    smsg = shmat(msg_id, NULL, 0);
    ssig = shmat(chk_id, NULL, 0);
    memset(smsg, 0, sizeof(msg));
    memset(ssig, 0, sizeof(shm_sig));

    /* the fuzzer-side per-run arming (aflnet_sock2shm_init_session) */
    smsg->state = CLIENT;
    smsg->is_end = 0;
    smsg->is_init = 0;
    smsg->mx.avail = 1;
    ssig->connection_state = UNINITIALIZED;

    snprintf(id, sizeof(id), "%d", msg_id);
    setenv(SHM_ENV_MSG_VAR, id, 1);
    snprintf(id, sizeof(id), "%d", chk_id);
    setenv(SHM_ENV_CHECK_VAR, id, 1);
    setenv(ENV_SHMSYNC, "1", 1);

  }

  /* exported by the fuzzer in every server mode */
  setenv(ENV_SOCK_MODE, "1", 1);
  snprintf(id, sizeof(id), "%d", port);
  setenv(ENV_NETPORT, id, 1);
  setenv(ENV_PROTOCOL_TYPE, "TCP", 1);
  setenv("LD_PRELOAD", "./sockhook.so", 1);

  pid = spawn_target(port, 0);
  if (pid < 0) { printf("[!] fork failed\n"); return 1; }

  /* the readiness notification the accept() hook publishes */
  if (sync_case) {

    check(WAIT_FOR(atomic_load(&ssig->connection_state) != UNINITIALIZED, 2000,
                   &waited),
          "target publishes its readiness (accept) before the fuzzer dials");
    printf("    (RUNNING observed after %ld ms, connection_state=%d)\n",
           waited, atomic_load(&ssig->connection_state));

  } else {

    usleep(200000); /* let an inert library bind/listen */

  }

  fd = connect_to(port);
  check(fd >= 0, sync_case ? "connected to the synchronised target"
                           : "connected to the plain real-socket target");
  if (fd < 0) { kill(pid, SIGKILL); return 1; }

  /* the request is on the wire before the target is allowed to read it */
  n = (int)send(fd, "hello\r\n", 7, 0);
  check(n == 7, "request sent over the real socket");

  if (sync_case) {

    n = read_response(fd, buf, sizeof(buf), 300);
    check(n == 0, "no response before the handover: the target waits for the "
                  "fuzzer at recv()");
    check(atomic_load(&smsg->state) == CLIENT,
          "the target is parked on the SHM turn (state == CLIENT)");

    smsg->state = SERVER; /* hand the turn over */

    n = read_response(fd, buf, sizeof(buf), 1000);
    check(n == 7 && memcmp(buf, "hello\r\n", 7) == 0,
          "the echoed response arrives on the real socket after the handover");
    printf("    (handover -> %d byte(s): \"%s\")\n", n, n > 0 ? buf : "");

    /* end of the session: the parked target must stop waiting */
    smsg->is_end = 1;
    smsg->state = SERVER;
    n = read_response(fd, buf, sizeof(buf), 1000);
    check(n == -1, "is_end + handover ends the session without waiting for "
                   "the TCP close (read returns EOF)");

  } else {

    n = read_response(fd, buf, sizeof(buf), 1000);
    check(n == 7 && memcmp(buf, "hello\r\n", 7) == 0,
          "inert (default) configuration echoes without any handshake");

  }

  close(fd);
  kill(pid, SIGKILL);
  waitpid(pid, NULL, 0);

  if (msg_id >= 0) { shmctl(msg_id, IPC_RMID, NULL); }
  if (chk_id >= 0) { shmctl(chk_id, IPC_RMID, NULL); }

  if (failures) {
    printf("[!] %d check(s) failed\n", failures);
    return 1;
  }

  printf("[+] %s checks passed\n", sync_case ? "standalone shmsync"
                                             : "default real-socket mode");
  return 0;

}
