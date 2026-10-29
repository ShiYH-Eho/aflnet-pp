// test/test-statevar-harness.c
// Owner of the state-variable shared memory region and verifier used by
// test-statevar.sh.
//
// The instrumented target (test-statevar.c) records the value of every
// variable annotated __AFL_STATE_VAR__ into one 8-byte slot of a 16 KB SHM
// region whose id/path the fuzzer normally exports through
// __AFL_AFLNET_STATEVAR_SHM_ID (see include/config.h).  The region must exist
// before the target is started, because the statevar runtime attaches to it
// from an early constructor (afl-statevar-rt.o.c), so
// this harness creates it first and only then fork+execs the target.
//
// It then checks, against the values the target printed:
//   * every annotated variable landed in a slot, with the exact 64-bit value
//     the pass records (integers zero-extended; integer pointers dereferenced
//     to the pointed-to integer; pointers to anything else reduced to their
//     nullity, 0 or 1)
//   * one slot per annotated variable (no variable recorded twice, and even
//     the ones recorded as 0 did write - the region is poisoned rather than
//     zeroed, see POISON_WORD)
//   * no unannotated variable (the SKIP controls) leaked into the region
// and prints SHM-HASH (FNV-1a over the whole region), SHM-SLOTS (the slots the
// target wrote, deterministic per binary) and SHM-SET (the sorted non-zero
// words), so the driver can tell two different states apart.
//
// Build: cc [-DUSEMMAP] -o harness test-statevar-harness.c [-lrt]
//        -DUSEMMAP iff afl-statevar-rt.o was built with USEMMAP (i.e. it
//        references shm_open instead of shmat).
// Run:   ./harness <instrumented-target> [target args...]
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Keep in sync with include/config.h
#define STATEVAR_ENV_VAR "__AFL_AFLNET_STATEVAR_SHM_ID"
#define SHM_SIZE         (1U << 14)  // AFLNET_STATEVAR_SHM_SIZE
#define SLOT_SIZE        8U

// A real fuzzer hands the target a zeroed region, but then a slot holding 0
// (a variable whose recorded value is 0: a NULL pointer, an integer assigned
// zero, ...) is indistinguishable from a slot the target never wrote.  To be
// able to verify that such a variable is still recorded, the region is
// poisoned instead: every slot the target did not write keeps POISON_WORD,
// so "written as 0" and "not written at all" can be told apart.
#define POISON_BYTE 0x5a
#define POISON_WORD 0x5a5a5a5a5a5a5a5aULL

#define MAX_WORDS 4096
#define MAX_VARS  32

struct var {

  char     name[32];
  char     type[8];
  uint64_t val;

};

static unsigned char *shm;
static char           shm_name[64];
static int            sysv_id = -1;
static struct var     recs[MAX_VARS];    // annotated variables (must be recorded)
static struct var     skips[MAX_VARS];   // controls (must not be recorded)
static int            nrecs;
static int            nskips;

static void die(const char *fmt, ...) {

  va_list ap;

  fputs("[-] test-statevar-harness: ", stderr);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);

  exit(1);

}

static void shm_create(void) {

#ifdef USEMMAP

  snprintf(shm_name, sizeof(shm_name), "/aflnet-statevar-test-%d",
           (int)getpid());

  int fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (fd < 0 && errno == EEXIST) {

    shm_unlink(shm_name);
    fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);

  }

  if (fd < 0) die("shm_open(%s): %s", shm_name, strerror(errno));
  if (ftruncate(fd, SHM_SIZE) != 0) die("ftruncate: %s", strerror(errno));

  void *p = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (p == MAP_FAILED) die("mmap: %s", strerror(errno));

  close(fd);
  shm = p;

#else

  sysv_id = shmget(IPC_PRIVATE, SHM_SIZE, IPC_CREAT | IPC_EXCL | 0600);
  if (sysv_id < 0) die("shmget: %s", strerror(errno));

  void *p = shmat(sysv_id, NULL, 0);
  if (p == (void *)-1) die("shmat: %s", strerror(errno));

  shm = p;
  snprintf(shm_name, sizeof(shm_name), "%d", sysv_id);

#endif

  memset(shm, POISON_BYTE, SHM_SIZE);

  // exactly what aflnet_statevar_shm_init() exports to the target
  setenv(STATEVAR_ENV_VAR, shm_name, 1);

}

static void shm_destroy(void) {

#ifdef USEMMAP

  if (shm) {

    munmap(shm, SHM_SIZE);
    shm = NULL;

  }

  if (shm_name[0]) {

    shm_unlink(shm_name);
    shm_name[0] = '\0';

  }

#else

  if (shm) {

    shmdt(shm);
    shm = NULL;

  }

  if (sysv_id >= 0) {

    shmctl(sysv_id, IPC_RMID, NULL);
    sysv_id = -1;

  }

#endif

}

// The pass records integers zero-extended (int -3 -> 0x00000000fffffffd),
// dereferences integer pointers and reduces other pointers to their nullity
// (so the target prints *p for integer pointers and 0/1 for the rest), so the
// printed values map onto the words as follows: u32/i32 -> zero-extended
// 32-bit, u64/i64/ptr -> as printed.
static uint64_t parse_value(const char *type, const char *text) {

  if (!strcmp(type, "u32")) return (uint64_t)(uint32_t)strtoull(text, NULL, 0);

  if (!strcmp(type, "i32"))
    return (uint64_t)(uint32_t)(int32_t)strtoll(text, NULL, 0);

  if (!strcmp(type, "u64") || !strcmp(type, "i64") || !strcmp(type, "ptr"))
    return (uint64_t)strtoull(text, NULL, 0);

  die("unknown value type '%s'", type);
  return 0;

}

static void parse_line(char *line) {

  char *save = NULL;
  char *kind = strtok_r(line, " \t\r\n", &save);

  if (!kind) return;

  if (!strcmp(kind, "REC") || !strcmp(kind, "SKIP")) {

    int         is_rec = !strcmp(kind, "REC");
    char       *name = strtok_r(NULL, " \t\r\n", &save);
    char       *type = strtok_r(NULL, " \t\r\n", &save);
    char       *text = strtok_r(NULL, " \t\r\n", &save);
    struct var *tab = is_rec ? recs : skips;
    int        *n = is_rec ? &nrecs : &nskips;

    if (!name) die("malformed %s line", kind);
    if (*n >= MAX_VARS) die("too many %s lines", kind);

    if (is_rec) {

      if (!type || !text) die("malformed REC line");

    } else {

      // SKIP lines carry "<name> <value>": the control is a plain integer
      if (!type) die("malformed SKIP line");

      text = type;
      type = "u32";

    }

    snprintf(tab[*n].name, sizeof(tab[*n].name), "%s", name);
    snprintf(tab[*n].type, sizeof(tab[*n].type), "%s", type);
    tab[*n].val = parse_value(type, text);
    (*n)++;

  }

}

static void run_target(char *const *argv) {

  int pfd[2];

  if (pipe(pfd) != 0) die("pipe: %s", strerror(errno));

  pid_t pid = fork();
  if (pid < 0) die("fork: %s", strerror(errno));

  if (pid == 0) {

    if (dup2(pfd[1], STDOUT_FILENO) < 0) _exit(127);
    close(pfd[0]);
    close(pfd[1]);

    execvp(argv[0], argv);
    fprintf(stderr, "[-] execvp(%s): %s\n", argv[0], strerror(errno));
    _exit(127);

  }

  close(pfd[1]);

  FILE *out = fdopen(pfd[0], "r");
  if (!out) die("fdopen: %s", strerror(errno));

  char   *line = NULL;
  size_t  cap = 0;

  while (getline(&line, &cap, out) > 0)
    parse_line(line);

  free(line);
  fclose(out);  // also closes pfd[0]

  int status = 0;

  if (waitpid(pid, &status, 0) < 0) die("waitpid: %s", strerror(errno));
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    die("target did not exit cleanly (status %#x)", status);

  if (!nrecs) die("target printed no REC line");

}

static uint64_t hash_shm(void) {

  uint64_t h = 0xcbf29ce484222325ULL;  // FNV-1a

  for (size_t i = 0; i < SHM_SIZE; i++) {

    h ^= (uint64_t)shm[i];
    h *= 0x100000001b3ULL;

  }

  return h;

}

static void verify(void) {

  uint64_t *slot = (uint64_t *)shm;
  size_t    nslots = SHM_SIZE / SLOT_SIZE;
  uint64_t  found[MAX_WORDS];
  uint64_t  written[MAX_WORDS];
  char      used[MAX_WORDS];
  uint64_t  expect[MAX_VARS];
  int       nfound = 0, nwritten = 0, nexp = 0, missing = 0, extra = 0;
  int       leaked = 0, unwritten = 0;

  // A slot still holding the poison was never written by the target; any
  // other slot was written, with the value the runtime recorded (possibly 0).
  for (size_t i = 0; i < nslots; i++) {

    if (slot[i] == POISON_WORD) continue;

    if (nwritten >= MAX_WORDS) die("too many written slots");
    written[nwritten++] = i;

    if (slot[i]) {

      if (nfound >= MAX_WORDS) die("too many non-zero slots");
      found[nfound++] = slot[i];

    }

  }

  memset(used, 0, sizeof(used));

  for (int i = 0; i < nrecs; i++)
    if (recs[i].val) expect[nexp++] = recs[i].val;

  if (getenv("STATEVAR_DUMP")) {

    for (int w = 0; w < nwritten; w++)
      printf("SLOT %llu 0x%016llx\n", (unsigned long long)written[w],
             (unsigned long long)slot[written[w]]);

  }

  // Every annotated variable must have written its own slot, exactly once,
  // including the ones whose recorded value is 0 (a NULL pointer, an integer
  // assigned 0): the map holds one slot per annotated object, so the number
  // of written slots must equal the number of annotated objects.
  if (nwritten != nrecs) {

    printf("[-] %d slot(s) written for %d annotated variable(s): a variable "
           "was recorded twice or not at all\n",
           nwritten, nrecs);
    unwritten = 1;

  }

  // every expected value must be present exactly as often as it is expected
  for (int e = 0; e < nexp; e++) {

    int matched = 0;

    for (int f = 0; f < nfound; f++) {

      if (!used[f] && found[f] == expect[e]) {

        used[f] = 1;
        matched = 1;
        break;

      }

    }

    if (!matched) {

      printf("[-] no SHM word for annotated value 0x%016llx\n",
             (unsigned long long)expect[e]);
      missing++;

    }

  }

  for (int f = 0; f < nfound; f++) {

    if (!used[f]) {

      printf("[-] unexpected SHM word 0x%016llx\n",
             (unsigned long long)found[f]);
      extra++;

    }

  }

  // the negative controls must not have been recorded (unless the value is
  // indistinguishable from an annotated one, which would not prove anything)
  for (int s = 0; s < nskips; s++) {

    int is_expected = 0;

    for (int i = 0; i < nrecs; i++)
      if (recs[i].val && recs[i].val == skips[s].val) is_expected = 1;

    if (is_expected) continue;

    for (int f = 0; f < nfound; f++) {

      if (found[f] == skips[s].val) {

        printf("[-] unannotated '%s' was recorded (0x%016llx)\n",
               skips[s].name, (unsigned long long)skips[s].val);
        leaked++;
        break;

      }

    }

  }

  printf("[*] %d annotated variable(s) (%d with a non-zero value), SHM: %d "
         "written slot(s), %d non-zero, of %zu\n",
         nrecs, nexp, nwritten, nfound, nslots);

  if (missing || extra || leaked || unwritten) {

    printf("[-] state-variable instrumentation is wrong: %d missing, %d "
           "unexpected, %d leaked, %d unwritten/duplicated\n",
           missing, extra, leaked, unwritten);
    exit(1);

  }

  printf("[+] every annotated variable wrote exactly one slot (zero-valued "
         "ones included), no unannotated value leaked\n");

  // canonical rendering for the driver: whole-image hash (noise-free across
  // runs of the same delta as long as ASLR does not move the pointer) and the
  // sorted set of non-zero words (deterministic per delta)
  printf("SHM-HASH %016llx\n", (unsigned long long)hash_shm());

  printf("SHM-SLOTS");

  for (int w = 0; w < nwritten; w++)
    printf(" %llu", (unsigned long long)written[w]);

  printf("\n");

  for (int a = 1; a < nfound; a++) {

    uint64_t v = found[a];
    int      b = a - 1;

    while (b >= 0 && found[b] > v) {

      found[b + 1] = found[b];
      b--;

    }

    found[b + 1] = v;

  }

  printf("SHM-SET");

  for (int f = 0; f < nfound; f++)
    printf(" %016llx", (unsigned long long)found[f]);

  printf("\n");

}

int main(int argc, char **argv) {

  if (argc < 2) {

    fprintf(stderr, "usage: %s <instrumented-target> [target args...]\n",
            argv[0]);
    return 1;

  }

  shm_create();
  atexit(shm_destroy);

  run_target(&argv[1]);
  verify();

  return 0;

}
