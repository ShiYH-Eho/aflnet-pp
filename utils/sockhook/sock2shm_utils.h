#ifndef SOCK2SHM_UTILS_H
#define SOCK2SHM_UTILS_H

#include <linux/futex.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>

#include "types.h"

#define MAX_MSG_SIZE 0x4000
#define WAITING_TIME 100
#define SHM_ENV_MSG_VAR "__AFL_SHM_MSG_ID"
// #define ENV_NETPORT_VAR "__AFL_SHM_NETPORT_ID"
#define ENV_NETPORT "__AFL_NETPORT"
#define SHM_ENV_CHECK_VAR "__AFL_SHM_CHECK_ID"
#define ENV_PROTOCOL_TYPE "__AFL_PROTOCOL_TYPE"
#define ENV_IS_KILL "__AFL_KILL_ON"
/* All env vars consumed by the preloaded sockhook library use the "__"
   internal prefix (like afl's __AFL_* runtime vars) to mark them as
   target-facing protocol knobs, distinct from the user-facing AFLNET_*
   config vars the fuzzer reads (e.g. AFLNET_SOCK_MODE, which
   aflnet_sockhook_preload forwards here as __AFL_SOCK_MODE). */
#define ENV_SOCK_MODE "__AFL_SOCK_MODE"
#define SOCK_MODE_SOCK2SHM 2     /* AFLNET_SOCK2SHM: shared-SHM exchange */
/* __AFL_SHMSYNC=1 engages the handshake on its own: the session data still
   travels over the real socket (sock_mode 1) and only the SHM rendezvous is
   armed, so the target can tell the fuzzer that it is listening, that it is
   ready to be spoken to and that the session is over - without any SHM
   message I/O (data1/data2 and the shared send buffer stay unused).  It also
   takes precedence over the legacy "__AFL_SHM_* ids only" engage rule, so a
   manual run can arm the rendezvous while still exporting the segment ids.
   0/absent = off; sock_mode 2 always implies it. */
#define ENV_SHMSYNC "__AFL_SHMSYNC"
/* 1 once this process was recognised as the fuzz target: set by the target's
   own constructor and inherited by everything it forks or execs, so the
   target's descendants stay active even when they no longer have the
   forkserver descriptors. */
#define ENV_SOCKHOOK_ACTIVE "__AFL_SOCKHOOK_ACTIVE"
/* user-facing escape hatch: force the library to initialise even in a process
   that looks like a helper of afl-fuzz (no forkserver descriptors) - for
   setups the detection cannot see, e.g. AFL_NO_FORKSRV=1. */
#define ENV_SOCKHOOK_FORCE  "AFLNET_SOCKHOOK_FORCE_ACTIVE"
#define gettidv() (syscall(__NR_gettid))
#define futex_wait(addr,val,timeout) (syscall(SYS_futex,addr,FUTEX_WAIT,val,timeout,NULL,0))
#define futex_wake(addr,val) (syscall(SYS_futex,addr,FUTEX_WAKE,val,NULL,NULL,0))
enum session_state { SERVER, CLIENT };
enum connection_state { UNINITIALIZED=-1, ENDING, RUNNING };

typedef struct fu_semaphore {
  int avail;
  int waiters;
}fsemaphore;

/* ------------------------------ DATA plane ------------------------------
   SysV "msg" segment (__AFL_SHM_MSG_ID): ONLY the message buffers and their
   bookkeeping.  It is attached just for the SHM redirection (enable_shm);
   the rendezvous-only configuration (enable_shmsync alone) never maps it.
   Field order is the cross-process ABI and MUST stay:

     len1      bytes available in data1 (client -> server)
     len2      bytes available in data2 (server -> client)
     buf_size  bytes of the chunk currently being drained             */
typedef struct msg_struct {
  int len1; // client writes and server reads
  int len2; // client reads and server writes
  int buf_size;
  u8 data1[MAX_MSG_SIZE];
  u8 data2[MAX_MSG_SIZE];
}msg;

/* ----------------------------- CONTROL plane ----------------------------
   SysV "check" segment (__AFL_SHM_CHECK_ID): every field that synchronises
   the two processes - the turn token, the session lifecycle flags, the futex
   mutex and the connection state.  It is attached whenever either half is
   engaged (enable_shmsync, implied by enable_shm), so the rendezvous needs
   nothing else and the redirection finds its sync state here as well.
   Field order is the cross-process ABI and MUST stay:

     [0] state                 [1] connection_state  [2] mx (futex, 2 ints)
     [3] is_init (RESERVED)    [4] is_end            [5] proc_ref_cnt
     [6] is_mem_leaked         [7] is_global_val_written                */
typedef struct shm_sig {
  atomic_int  state;                /* [0] SERVER / CLIENT turn token        */
  atomic_int  connection_state;     /* [1] UNINITIALIZED / ENDING / RUNNING  */
  fsemaphore  mx;                   /* [2] futex mutex over the session      */
  int         is_init;              /* [3] RESERVED: the per-process
                                         global_session_mark.session_inited
                                         replaced it, the shared field is kept
                                         only so the ABI stays stable */
  int         is_end;               /* [4] 0 running, 1 client ended, 3 tmo,
                                             6 closed, 7/8/9 errors         */
  int         proc_ref_cnt;         /* [5] # holders of the session fd(s)    */
  int         is_mem_leaked;        /* [6] long-term data / leaks detected   */
  int         is_global_val_written;/* [7] global data written this run      */
} shm_sig;

typedef struct global_session_mark {
  int netport;
  int socket_type;
  int enable_shm;
  int enable_shmsync;
  /* 1 when __AFL_DEFER_FORKSRV is exported to this process: the deferred
     forkserver switch is fixed for the process lifetime, so it is read once
     (see init_sockhook) instead of getenv()ing it in every bind()/listen().
     It applies in EVERY mode, also when neither SHM half is engaged. */
  int deferred_fs_wanted;
  /* 1 once THIS process has a session context: session_init() ran here, or in
     the parent this process was forked from (fork copies it like the rest of
     the memory image).  Deliberately process-local, not shared: everything it
     gates - fd_map, session_fd/server_fd, max_fd, read_p - is process-local
     too, so the fuzzer does not have to disarm it across processes (a fresh
     child starts from 0 and re-arms on its own bind()/accept()). */
  int session_inited;
} global_session_mark;

// _Static_assert(sizeof(shm_sig) == 10 * sizeof(int),
//                "shm_sig layout must match the 10-int sign[] ABI");

int shm_wait(atomic_int *state,int val,int timeout);
void shm_notify(atomic_int *state,int val);
void lock(fsemaphore* who);
void unlock(fsemaphore* who);
void thread_block_signal(sigset_t *oldset);
void thread_unblock_signal(sigset_t *sigset);

extern msg *session_msg;          /* DATA plane  (msg segment)   */
extern shm_sig *session_shm_sig;  /* CONTROL plane (check segment) */

#endif
