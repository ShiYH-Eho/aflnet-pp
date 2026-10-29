// test/test-statevar.c
// Instrumentation target for the AFLNet state-variable pass
// (instrumentation/afl-llvm-statevar-pass.so.cc, enabled with
// AFL_LLVM_STATEVAR=1).  It covers every annotation source the pass knows
// about plus the negative controls that must NOT be recorded:
//
//   1. a whole annotated global            -> llvm.global.annotations
//   2. an annotated struct member          -> llvm.ptr.annotation
//   3. an annotated int pointer global     -> dereferenced integer value
//   4. an annotated parameter              -> llvm.var.annotation (alloca)
//   5. an annotated automatic local        -> llvm.var.annotation (alloca)
//   6. a pointer to a NON-integer type     -> only nullity (1), never the
//      (struct pointer, double pointer)      pointee and never the address
//   7. a pointer to a narrow integer       -> only that many bytes are read
//      (unsigned char, behind a canary)
//   8. a pointer whose pointee cannot be   -> sizeof(int) fallback, the
//      inferred (call result)                 pointed-to int is recorded
//   9. NULL pointers of both kinds         -> recorded as 0 (with --nullptr)
//   -  an unannotated global and an        -> never recorded
//      unannotated struct member
//
// Each annotated value is printed as "REC <name> <type> <value>" and each
// negative control as "SKIP <name> <value>", so that
// test-statevar-harness.c can derive the expected 8-byte words the target
// must have written into the state-variable SHM.
//
// Usage: test-statevar [--delta N] [--nullptr] [--blobptr-null]
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STATE_VAR __attribute__((annotate("__AFL_STATE_VAR__")))

// 1. whole annotated global
static unsigned int g_counter STATE_VAR = 0;

// 2. annotated struct member (b must not be recorded)
struct box {

  STATE_VAR int a;
  int           b;

};

static struct box g_box = {0, 0};

// 3. annotated pointer to an integer global (recorded dereferenced)
static int *g_ptr STATE_VAR = NULL;

// 6. annotated pointers to NON-integer types: only nullity may be recorded.
// The pointed-to objects hold recognisable bytes so that a wrongly
// dereferenced pointee shows up as an unexpected SHM word.
struct blob {

  int    tag;
  double weight;

};

static struct blob  g_blob = {0x0CAFED00D, 3.25};
static struct blob *g_blobptr STATE_VAR = NULL;

static double  g_dbl = 1.5;
static double *g_dblptr STATE_VAR = NULL;

// 7. annotated pointer to a narrow integer located behind a canary: reading
// more than one byte (or the struct itself) would leak the canary.
struct narrow {

  unsigned int  pad;
  unsigned char v;
  unsigned char canary[3];

};

static struct narrow  g_narrow = {0x11111111u, 0x5A, {0xAA, 0xBB, 0xCC}};
static unsigned char *g_byteptr STATE_VAR = NULL;

// 8. annotated pointer whose pointee cannot be inferred: the address comes
// from a call, so the pass falls back to sizeof(int) and the runtime records
// the pointed-to int (filled before the pointer is assigned)
static int g_fallback = 0;

__attribute__((noinline)) static int *point_at_fallback(int v) {

  g_fallback = v;
  return &g_fallback;

}

static int *g_fallbackptr STATE_VAR = NULL;

// negative control: unannotated global
static unsigned int g_plain = 0;

// 4. annotated parameter and 5. annotated automatic local (clang demotes both
// to an alloca and records them with llvm.var.annotation)
static void step(int delta STATE_VAR, int null_ptrs, int null_blobptr) {

  int local STATE_VAR = delta * 3;

  g_counter = 0x11223344u;
  g_box.a = -3;             // int store: recorded zero-extended
  g_box.b = 0x0BEEFu;       // not annotated: must not reach the SHM
  g_plain = 0x0BADF00Du;    // not annotated: must not reach the SHM
  g_ptr = null_ptrs ? NULL : (int *)&g_counter;

  // non-integer pointees: the harness expects 1 (non-NULL) or 0 (NULL)
  g_blobptr = null_blobptr ? NULL : &g_blob;
  g_dblptr = null_ptrs ? NULL : &g_dbl;

  g_byteptr = &g_narrow.v;  // 1-byte pointee, the canary must not be read

  g_fallbackptr = null_ptrs ? NULL : point_at_fallback(0x0D15EA5E);

  // The harness parses these into the expected SHM word multiset.  The REC
  // values are the zero-extended 64-bit words the pass writes into a slot.
  // Annotated integer pointers record the pointed-to integer (*g_ptr), not
  // the pointer value; non-integer pointers record only nullity (0 or 1).
  printf("REC counter u32 %u\n", (unsigned int)g_counter);
  printf("REC boxa i32 %d\n", g_box.a);
  printf("REC ptr i32 %d\n", g_ptr ? *g_ptr : 0);
  printf("REC blobptr u32 %u\n", g_blobptr ? 1u : 0u);
  printf("REC dblptr u32 %u\n", g_dblptr ? 1u : 0u);
  printf("REC byteptr u32 %u\n", (unsigned int)*g_byteptr);
  printf("REC fallbackptr i32 %d\n", g_fallbackptr ? *g_fallbackptr : 0);
  printf("REC delta i32 %d\n", delta);
  printf("REC local i32 %d\n", local);
  printf("SKIP boxb %u\n", (unsigned int)g_box.b);
  printf("SKIP plain %u\n", g_plain);

  fflush(stdout);

}

int main(int argc, char **argv) {

  int delta = 7;
  int null_ptrs = 0;
  int null_blobptr = 0;

  for (int i = 1; i < argc; i++) {

    if (!strcmp(argv[i], "--delta") && i + 1 < argc) delta = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--nullptr")) null_ptrs = 1;
    else if (!strcmp(argv[i], "--blobptr-null")) null_blobptr = 1;
    else {

      fprintf(stderr, "usage: %s [--delta N] [--nullptr] [--blobptr-null]\n",
              argv[0]);
      return 1;

    }

  }

  step(delta, null_ptrs, null_blobptr);
  return 0;

}
