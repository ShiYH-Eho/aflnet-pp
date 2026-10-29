/*
   american fuzzy lop++ (aflnet-pp) - state-variable runtime
   ---------------------------------------------------------

   Runtime support for afl-llvm-statevar-pass.so.

   This object is independent from afl-compiler-rt.o and from any coverage
   backend.  It only attaches the AFLNet state-variable shared-memory region
   exported by afl-fuzz and provides the helpers called by the LLVM pass:

     __afl_statevar_record(slot, value)
     __afl_statevar_record_ptr(slot, ptr, width)

   Keeping this separate lets the assembler, PCGUARD and LTO instrumentation
   modes use the same state-variable pass without pulling in another coverage
   runtime or forkserver.

 */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE 1
#endif

#include "config.h"
#include "types.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/mman.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#endif

/* Owned by this object.  The pass only calls the record helpers, so the map
   pointer does not need to be exported. */
static u8 *__afl_statevar_map;
static u8  __afl_statevar_attach_attempted;

/* Attach the dedicated state SHM once.  Missing or invalid state is not an
   error: targets compiled with the statevar pass must still run normally
   outside a state-mode-2 afl-fuzz session. */
static void __afl_statevar_attach(void) {

  if (__afl_statevar_map || __afl_statevar_attach_attempted) { return; }
  __afl_statevar_attach_attempted = 1;

  const char *id_str = getenv(AFLNET_STATEVAR_SHM_ENV_VAR);
  if (!id_str || !*id_str) { return; }

  void *base = NULL;

#ifdef USEMMAP

  int shm_fd = shm_open(id_str, O_RDWR, 0);
  if (shm_fd == -1) { return; }

  base = mmap(NULL, AFLNET_STATEVAR_SHM_SIZE, PROT_READ | PROT_WRITE,
              MAP_SHARED, shm_fd, 0);
  close(shm_fd);

#else

  /* Validate the integer id instead of treating 0 as failure: on a fresh IPC
     namespace, zero is a valid SysV shared-memory id. */
  char *end = NULL;
  long  shm_id = strtol(id_str, &end, 10);
  if (end == id_str || *end != '\0' || shm_id < 0) { return; }

  base = shmat((int)shm_id, NULL, 0);

#endif

  if (base == NULL || base == (void *)-1) { return; }
  __afl_statevar_map = (u8 *)base;

}

/* Run as early as possible so ordinary user constructors observe an attached
   map.  The record helpers also retry lazily in case a loader or a dynamic
   library invokes instrumented code before this constructor. */
__attribute__((constructor(101))) static void __afl_statevar_rt_init(void) {

  __afl_statevar_attach();

}

static inline void __afl_statevar_ensure_map(void) {

  if (unlikely(!__afl_statevar_map && !__afl_statevar_attach_attempted)) {
    __afl_statevar_attach();
  }

}

__attribute__((noinline, visibility("default"))) void __afl_statevar_record(
    u64 slot, u64 value) {

  __afl_statevar_ensure_map();

  u8 *m = __afl_statevar_map;
  if (likely(m)) {

    ((u64 *)m)[slot & (u64)((AFLNET_STATEVAR_SHM_SIZE / 8U) - 1U)] = value;

  }

}

/* Pointer stores record the state behind the pointer, never a raw address:

     width != 0  pointee is an integer of 1/2/4/8 bytes;
     width == 0  pointee is not an integer, record only 0/1 for NULL/non-NULL.

   The copy avoids alignment assumptions for the pointee. */
__attribute__((noinline, visibility("default"))) void
__afl_statevar_record_ptr(u64 word, const void *p, u64 width) {

  __afl_statevar_ensure_map();

  u8 *m = __afl_statevar_map;
  if (likely(m)) {

    u64 v = 0;

    if (width == 0) {

      v = (p != NULL);

    } else if (p != NULL) {

      switch (width) {

        case 1:
        case 2:
        case 4:
        case 8:
          memcpy(&v, p, (size_t)width);
          break;

        default:
          return;

      }

    }

    ((u64 *)m)[word & (u64)((AFLNET_STATEVAR_SHM_SIZE / 8U) - 1U)] = v;

  }

}
