/*
   sock2shm - LD_PRELOAD library that replaces per-connection network I/O
   with shared-memory based message exchange.

   Ported from HNPFuzzer (https://github.com/HNPFuzzer/HNPFuzzer)
   into aflpp-net. The mechanism:

     - the fuzzer allocates 2 System V shared memory segments (msg / check),
       exports their ids through __AFL_SHM_MSG_ID / __AFL_SHM_CHECK_ID and
       the target port through __AFL_SHM_NETPORT;
     - the target (server) is preloaded with this library, which attaches the
       segments and intercepts the socket calls;
     - once a client connects (the fuzzer still opens a real socket and
       connects so that accept() completes), all send/recv on the session
       socket are redirected to the shared msg segment, avoiding the network
       stack entirely.

   Only the ck_* alloc helpers from alloc-inl.h are used here (the original
   also pulled in llvm_mode/containers.h for the klib iterators, which are
   only needed on the fuzzer side and are therefore not included here).
*/

#define _GNU_SOURCE

#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stddef.h>   /* offsetof() */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <signal.h>
#include <netdb.h>
#include <pthread.h>
#include <poll.h>
#include <execinfo.h>
#include <dirent.h>        /* closefrom(): /proc/self/fd iteration */

#include <sys/epoll.h>
#include <sys/resource.h>  /* closefrom(): RLIMIT_NOFILE fallback */
#include <sys/socket.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <linux/kcmp.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>   /* TCP_INFO: stale-connection filter, see accept() */

#include "sock2shm_utils.h"
#include "alloc-inl.h"

//#define DEBUG_MODE
#define LOG_FILE_NAME "sockhook.log"
#define REGION_FOR_FORK "/sockhook_region"
//#define session_fd 400
#define MAX_FD 64
#define MAX_LOOP 3
/* Upper bound (ms) on a session turn-taking wait.  The two sides normally
   hand the token over within milliseconds, so this never fires in a healthy
   run; it exists so a target cannot spin forever on a token that neither
   moves nor gets an is_end notification (e.g. the fuzzer vanished before the
   next request).  On expiry the waiting hook treats the session as over
   (session_end()) and lets the target exit on its own. */
#define SESSION_STALL_TIMEOUT 30000
#define kcmp_fd(pid1,pid2,fd1,fd2) (syscall(__NR_kcmp,pid1,pid2,KCMP_FILE,fd1,fd2))

#if defined(DEBUG_MODE)
  static FILE * __log_fd=NULL;
  #define DO_LOG(...) original_fprintf(__log_fd, __VA_ARGS__); fflush(__log_fd);
#else
  #define DO_LOG(...) do {} while (0)
#endif

msg* session_msg;
shm_sig *session_shm_sig;                       /* "check" SHM segment (see shm_sig)  */
global_session_mark *global_session_mark_ptr;                 /* local session config (see global_session_mark)  */
static int sockhook_inited;                     /* set by init_sockhook() once the config
                                                   globals above (and the inert fallbacks)
                                                   are published; every hook passes straight
                                                   through to libc while this is 0 */
static msg no_sock_msg;                         /* inert msg/sig fallbacks installed when */
static shm_sig no_sock_sig;                    /* disabled, so hooks never deref NULL   */

int *fd_map=NULL;

static s32 shm_send_buf_size_id;
char* send_buf;
int shared_fd_for_fork,max_send_buf_size=0x1000;
int *send_buf_size;

atomic_int has_recv_msg;

/* Standalone-rendezvous ownership bookkeeping, process-local (one session per
   process).  sync_yielded: the target published CLIENT and waits for the
   fuzzer's send; sync_handover: SERVER was observed for that yield and the
   request bytes may still be in flight. */
static int sync_yielded=0;
static int sync_handover=0;

int is_kill,is_child=0;

int max_fd,read_p,epoll_event_op=EPOLLOUT;
int select_loop_cnt,poll_loop_cnt,epoll_loop_cnt;
int server_fd=-403,epoll_session_fd=-402,epoll_server_fd=-401,session_fd=-400;
struct timeval select_timeout = {.tv_sec = 0, .tv_usec = 0};
enum fd_type {OTHER,SESSION_FD,SERVER_FD=2,E_SESSION_FD=4,E_SERVER_FD=8};

/* one-shot marker for the deferred forkserver, shared by the bind (UDP) and
   listen (TCP) hooks (see maybe_start_deferred_fs below). */
static int deferred_fs_started = 0;
/* 1 once AFL++'s runtime entry point was really resolved and invoked: only
   then does a forkserver parent exist whose listening socket (and accept
   queue) the per-run children inherit - see the stale-connection filter in
   accept()/accept4().  It is armed before the runtime is entered so that the
   children forked inside it inherit the mark. */
static int deferred_fs_live = 0;
/* the target-port listener whose accept queue the forkserver parent shares
   with its children; -1 until the deferred forkserver starts. */
static int deferred_listen_fd = -1;
/* AFL++'s runtime entry point the deferred forkserver is started with,
   resolved once in init_sockhook().  It is non-NULL whenever
   deferred_fs_wanted is set: a target that cannot provide it is a
   configuration error and init_sockhook() refuses to run (see there). */
static void (*deferred_init_fn)(void) = NULL;
static void maybe_start_deferred_fs(void);
static int is_netport_listener(int fd);
static int sockaddr_port(const struct sockaddr *addr, socklen_t addrlen);
static void warn_deferred_unavailable(void);

/* 1 when both of AFL's forkserver descriptors are open.  afl-fuzz wires them
   (dup2 to FORKSRV_FD / FORKSRV_FD + 1) into the process it execs as the
   target, and only into that one - see the target detection in
   init_sockhook(). */
static int forkserver_fds_present(void) {

  return fcntl(FORKSRV_FD, F_GETFD) != -1 &&
         fcntl(FORKSRV_FD + 1, F_GETFD) != -1;

}

/* 1 when this process was started by afl-fuzz at all - the fuzzer exports
   __AFL_OUT_DIR (afl-fuzz.c) to the target and to every helper it spawns; a
   standalone/manual preload has none of that and keeps its documented
   behaviour. */
static int started_by_afl_fuzz(void) {

  return getenv("__AFL_OUT_DIR") != NULL;

}

__attribute__((noreturn)) void (*original__exit)(int status)=NULL;
__attribute__((noreturn)) void (*original_exit)(int status)=NULL;
pid_t (*original_fork)()=NULL;
int (*original_execve)(const char *pathname, char *const argv[], char *const envp[])=NULL;
int (*original_dup)(int oldfd)=NULL;
int (*original_dup2)(int oldfd, int newfd)=NULL;
int (*original_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
int (*original_epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event);
int (*original_epoll_wait)(int epfd, struct epoll_event *events,
                      int maxevents, int timeout);
int (*original_select)(int nfds, fd_set *restrict readfds,
                  fd_set *restrict writefds, fd_set *restrict exceptfds,
                  struct timeval *restrict timeout)=NULL;
int (*original_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen)=NULL;
int (*original_listen)(int sockfd, int backlog)=NULL;
int (*original_accept)(int, struct sockaddr*, socklen_t*)=NULL;
int (*original_accept4)(int sockfd, struct sockaddr *addr,  socklen_t *addrlen, int flags)=NULL;
ssize_t (*original_send)(int sockfd, const void *buf, size_t len, int flags)=NULL;
ssize_t (*original_sendto)(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)=NULL;
ssize_t (*original_sendmsg)(int sockfd, const struct msghdr *msg, int flags)=NULL;
ssize_t (*original_recv)(int sockfd, void *buf, size_t len, int flags)=NULL;
ssize_t (*original_recvfrom)(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)=NULL;
ssize_t (*original_recvmsg)(int sockfd, struct msghdr *msg, int flags)=NULL;
int (*original_close)(int fd)=NULL;
int (*original_fclose)(FILE* stream)=NULL;
ssize_t (*original_read)(int fd, void *buf, size_t count)=NULL;
ssize_t (*original_write)(int fd, const void *buf, size_t count)=NULL;
ssize_t (*original_readv)(int fd, const struct iovec *iov, int iovcnt)=NULL;
ssize_t (*original_writev)(int fd, const struct iovec *iov, int iovcnt)=NULL;
int (*original_fprintf)(FILE *restrict stream, const char *restrict format, ...)=NULL;
char* (*original_fgets)(char *restrict s, int n, FILE *restrict stream)=NULL;
int (*original_fputs)(const char *restrict s, FILE *restrict stream)=NULL;
int (*original_fputc)(int c, FILE *stream)=NULL;
size_t (*original_fread)(void *restrict ptr, size_t size, size_t nmemb,
                    FILE *restrict stream)=NULL;
size_t (*original_fwrite)(const void *restrict ptr, size_t size, size_t nmemb,
                    FILE *restrict stream)=NULL;

static void setup_shm(){
  char *id_str = 0;
  if (global_session_mark_ptr->enable_shm){
    id_str = getenv(SHM_ENV_MSG_VAR);

    if(id_str) {
      u32 shm_msg_id = atoi(id_str);
      session_msg = (msg*)shmat(shm_msg_id, NULL ,0);
      if(session_msg == (void *)-1)
        _exit(1);
    }
    else
      _exit(1);

    /* 2-int bookkeeping of the shared send buffer (present size / capacity).
       Allocated in both configurations so the session logs (check_before_close
       prints it) and the teardown stay uniform; only the buffer itself is a
       redirection-only resource. */
    shm_send_buf_size_id=shmget(IPC_PRIVATE, sizeof(int)*2, IPC_CREAT | IPC_EXCL | 0600);
    if(shm_send_buf_size_id<0)
      _exit(1);
    send_buf_size=(int *)shmat(shm_send_buf_size_id, NULL, 0);
  
    /* The shared send buffer only backs the msg redirection (shm_write /
       shm_write_buf, all gated on enable_shm): with enable_shmsync alone the
       target keeps writing to the real socket, so it is never mapped.
       The region used to have one fixed name for every process on the host,
       which let parallel fuzzing instances truncate each other's buffer.
       Give it a per-process name, then unlink it immediately: the fd (and the
       mapping its forks inherit) keeps the object alive, while no other
       instance - or a later instance reusing the pid - can open it. */
    char region_name[64];
    snprintf(region_name,sizeof(region_name),"%s.%d",REGION_FOR_FORK,(int)getpid());
    shared_fd_for_fork = shm_open(region_name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if(shared_fd_for_fork == -1){
      /* stale object from a crash with the same pid: drop it and retry */
      shm_unlink(region_name);
      shared_fd_for_fork = shm_open(region_name, O_CREAT | O_EXCL | O_RDWR, 0600);
    }
    if (shared_fd_for_fork == -1 || ftruncate(shared_fd_for_fork, max_send_buf_size) == -1){
      if(shared_fd_for_fork != -1)
        close(shared_fd_for_fork);
      shm_unlink(region_name);
      _exit(1);
    }
    shm_unlink(region_name);

    send_buf = mmap(0, max_send_buf_size, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd_for_fork, 0);
    if (send_buf == MAP_FAILED){
      _exit(1);
    }
  }
  if (global_session_mark_ptr->enable_shmsync){
    id_str=getenv(SHM_ENV_CHECK_VAR);
    if(id_str){
      u32 shm_check_id=atoi(id_str);
      session_shm_sig=shmat(shm_check_id,NULL,0);
      if (session_shm_sig==(void *)-1)
        _exit(1);
    }
    else
      _exit(1);
  }
}

/* 1 if the SHM rendezvous should be engaged on its own (__AFL_SHMSYNC=1).
   The session data keeps flowing through the real socket; only the accept /
   send / recv turn-taking (shm_sig's state and connection_state) is armed, so
   the target can signal the fuzzer when it is
   listening, when it has accepted the client and when it is ready for the
   next request. */
static int shmsync_wanted(void){
  char *id_str=getenv(ENV_SHMSYNC);

  return id_str!=NULL && atoi(id_str)>0;
}

/* go inert: no shared memory is attached; the config flags force every hook
   onto the real-socket path and the inert msg/sig fallbacks keep the
   unconditional hooks (e.g. accept) from dereferencing NULL. */
static void sock2shm_disable(void){
  global_session_mark_ptr->enable_shm=0;
  global_session_mark_ptr->enable_shmsync=0;
  session_msg=&no_sock_msg;
  session_shm_sig=&no_sock_sig;
}

/* 1 if this preloaded copy should engage the sock2shm SHM redirection.  The
   fuzzer always forwards its user-facing AFLNET_SOCK_MODE here as
   __AFL_SOCK_MODE, so when that variable is present it is authoritative:
   only 2 (SOCK_MODE_SOCK2SHM) engages and any other mode (0/1) keeps the
   library inert - no shared memory is attached and every hook falls back to
   the real network path.  Standalone/manual runs that export the __AFL_SHM_*
   ids without the mode variable still engage, preserving the legacy
   behaviour - unless __AFL_SHMSYNC asks for the rendezvous only, which must
   stay rendezvous only (the messages keep using the real socket). */
static int sock2shm_wanted(void){
  const char *sm;

  sm = getenv(ENV_SOCK_MODE);
  if(sm)
    return atoi(sm) == SOCK_MODE_SOCK2SHM;

  // return getenv(SHM_ENV_MSG_VAR) && getenv(SHM_ENV_CHECK_VAR) &&
  //        getenv(ENV_NETPORT);
  return 0;
}

__attribute__((constructor)) void init_sockhook(){
  const char *netport_env;
  char *protocol_type;

  global_session_mark_ptr = ck_alloc(sizeof(global_session_mark));
  global_session_mark_ptr->netport = 0;
  global_session_mark_ptr->enable_shm = 0;
  global_session_mark_ptr->enable_shmsync = 0;
  global_session_mark_ptr->deferred_fs_wanted = 0;
  global_session_mark_ptr->session_inited = 0;
  session_msg=&no_sock_msg;
  session_shm_sig=&no_sock_sig;

  /* Is this the process afl-fuzz exec'd as the target, or one of the helpers
     it spawns - the AFLNET_CLEANUP_SCRIPT shell, a tool, a wrapper - that
     merely inherited the environment?  afl-fuzz dup2()s its forkserver
     descriptors into the target child before the exec, so those descriptors
     are the discriminator, and this constructor is the only moment they can
     be used: the runtime closes them again in the per-run children
     (afl-compiler-rt.o.c), and __afl_connected is still 0 here.

     A process started by afl-fuzz (__AFL_OUT_DIR) without those descriptors
     is not a target: leave sockhook_inited at 0, so every hook - they cannot
     be uninstalled once the loader resolved them - takes its pass-through
     path to libc, and touch neither the configuration nor any shared segment
     nor a forkserver.  Descendants of the target (the marker this library
     exports below) as well as standalone/manual preloads (no __AFL_OUT_DIR)
     keep their normal initialisation. */
  if (!getenv(ENV_SOCKHOOK_ACTIVE) &&
      !getenv(ENV_SOCKHOOK_FORCE) &&
      started_by_afl_fuzz() &&
      !forkserver_fds_present()) {

    return;

  }

  /* remember for everything the target forks or execs that it belongs to the
     target (exec survives only through the environment) */
  setenv(ENV_SOCKHOOK_ACTIVE, "1", 1);

  /* From here on the hooks may safely dereference the config globals.  Until
     this point they must pass straight through to the real libc functions:
     the library is loaded before the executable, so a hook can fire (from the
     dynamic loader, another library's constructor or AFL++'s own runtime
     constructor) while global_session_mark_ptr is still NULL.  Note that the
     enable_* flags are still 0 here, so even a hook triggered from within this
     constructor (e.g. via the debug log's fopen) only takes the inert path. */
  sockhook_inited=1;

  #ifdef DEBUG_MODE
    /* Open the debug log here rather than lazily in session_init(): the hooks
       that run BEFORE any session exists (listen/bind of the deferred
       forkserver) and the inert mode (where session_init() never runs at all)
       must be loggable too, otherwise the log stays empty and the listen()
       port check cannot be inspected.  Append, not truncate: every exec of
       the target opens its own copy and truncating would leave only the
       activity of the last process. */
    original_fprintf=dlsym(RTLD_NEXT,"fprintf");
    if(!__log_fd){
      chmod(LOG_FILE_NAME,0666);
      __log_fd=fopen(LOG_FILE_NAME,"a");
    }
  #endif

  /* Per-target config the hooks need in EVERY mode is parsed here, regardless
     of whether the sock2shm SHM redirection engages: the deferred forkserver
     hooks (bind for UDP / listen for TCP) and the netport SO_REUSEPORT only
     need the lightweight __AFL_NETPORT / __AFL_PROTOCOL_TYPE envs that the
     fuzzer exports for every server mode. */
  netport_env = getenv(ENV_NETPORT);
  if(netport_env)
    global_session_mark_ptr->netport = atoi(netport_env);

  protocol_type = getenv(ENV_PROTOCOL_TYPE);
  if(!protocol_type || strcmp(protocol_type,"UDP")){
    global_session_mark_ptr->socket_type=SOCK_STREAM;
  }
  else{
    global_session_mark_ptr->socket_type=SOCK_DGRAM;
  }

  if(getenv(ENV_IS_KILL))
    is_kill=1;
  else
    is_kill=0;

  if (getenv(DEFER_ENV_VAR))
    global_session_mark_ptr->deferred_fs_wanted = atoi(getenv(DEFER_ENV_VAR)) != 0;

  /* A deferred forkserver is started through AFL++'s __afl_manual_init(); a
     target that does not export it cannot provide one, so afl-fuzz would only
     report "Timeout while initializing fork server" after exec_timeout x 10 ms
     of waiting, with nothing pointing at the build.  Resolve the entry point
     here, once, and refuse to run when it is missing - that is a
     build/configuration error, not something to degrade around silently.
     This is safe for the modes that get the entry point from another
     preloaded library: afl-fuzz's FRIDA runtime links afl-compiler-rt.o into
     afl-frida-trace.so, so the symbol resolves from there, and QEMU mode
     never preloads this library at all.  (Note that the check applies to
     every process that loads the library with __AFL_DEFER_FORKSRV set, so a
     non-instrumented helper the target exec()s will refuse to start as well;
     without a deferred forkserver it is not loaded for that reason at all.) */
  if (global_session_mark_ptr->deferred_fs_wanted) {

    deferred_init_fn = (void (*)(void))dlsym(RTLD_DEFAULT, "__afl_manual_init");

    if (!deferred_init_fn) {

      /* Stop only a process that afl-fuzz really exec'd as the target: the
         fuzzer wires its forkserver pipes into that child (dup2 to
         FORKSRV_FD / FORKSRV_FD + 1) before the exec, so a process without
         them is a helper that merely inherited the environment - the
         AFLNET_CLEANUP_SCRIPT shell, or something the target exec()s.  Those
         keep the old, silent preload behaviour instead of being killed before
         they can do their work (a cleanup script dying per run also produces
         a "exited with status 1" warning on every single run). */
      if (forkserver_fds_present()) {

        warn_deferred_unavailable();
        _exit(1);

      }

    }

  }

  /* __AFL_SHMSYNC=1 arms the handshake without the SHM redirection: the
     session data keeps flowing through the real socket and only the
     rendezvous (accept / send / recv turn-taking) is engaged. */
  if(!sock2shm_wanted()){
    if(!shmsync_wanted()){
      sock2shm_disable();
      return;
    }

    global_session_mark_ptr->enable_shm = 0;
    global_session_mark_ptr->enable_shmsync = 1;
  }
  else{
    /* sock2shm SHM redirection engaged: attach the msg/check segments and
     allocate the shared send buffer (only now - when disabled, none of the
     sock2shm machinery is set up). */
    global_session_mark_ptr->enable_shm = 1;
    global_session_mark_ptr->enable_shmsync = 1;
  }

  #ifdef DEBUG_MODE
    original_fprintf=dlsym(RTLD_NEXT,"fprintf");
  #endif

  max_fd=MAX_FD;
  setup_shm();
}

/* Make sure fd_map has an entry for fd.  Every direct fd_map[] access and
   every loop bounded by a caller-supplied fd count has to call this first:
   the map starts at MAX_FD, while an accepted connection, an epoll fd or a
   select() bound can easily be larger. */
static void grow_fd_map(int fd){
  int old_max_fd;

  if(fd<0)
    return;

  if(!fd_map)
    fd_map=ck_alloc(sizeof(int)*max_fd);

  while(fd>=max_fd){
    old_max_fd=max_fd;
    max_fd<<=1;
    fd_map=ck_realloc(fd_map,max_fd*sizeof(int));
    memset(&fd_map[old_max_fd],0,(max_fd-old_max_fd)*sizeof(int));
  }
}

static int check_fd(int fd,int target){
  if(fd<0 || !global_session_mark_ptr->session_inited)
    return 0;

  grow_fd_map(fd);

  return fd_map[fd]&target;
}

/* 1 when the descriptor is in non-blocking mode.  Per-call MSG_DONTWAIT is
   checked by the recv*() hooks separately. */
static int fd_is_nonblocking(int fd){
  int flags=fcntl(fd,F_GETFL,0);

  return flags!=-1 && (flags&O_NONBLOCK);
}

static int next_dup_fd(int target){
  int i;

  if(fd_map && global_session_mark_ptr->session_inited)
    for(i=0;i<max_fd;i++){
      if(fd_map[i]&target)
        return i;
    }

  return -400;
}

static void clr_dup_fd(int start,int target){
  int i;

  if(fd_map && global_session_mark_ptr->session_inited)
    for(i=start;i<max_fd;i++){
      fd_map[i]&=~target;
    }
}


static void reset_loop_cnt(){
  poll_loop_cnt=0;
  epoll_loop_cnt=0;
  select_loop_cnt=0;
}

void session_init(){
  /* the flag is per-process: a fresh child (non-deferred forkserver model)
     starts with 0 and arms its own session, while a child forked from an
     already-initialized parent inherits 1 and reuses the inherited context
     (fd_map with the server fd, server_fd, ...).  fd_map is checked as well
     so a state that claims to be initialized but has no map cannot happen. */
  if(global_session_mark_ptr->session_inited && fd_map){
    return;
  }

  #ifdef DEBUG_MODE
    if(!__log_fd){
      chmod(LOG_FILE_NAME,0666);
      __log_fd=fopen(LOG_FILE_NAME,"w");
    }
  #endif

  DO_LOG("%d start session %d %d %d %d %d\n",getpid(),session_shm_sig->is_end,session_fd,server_fd,next_dup_fd(SESSION_FD),session_shm_sig->proc_ref_cnt);
  reset_loop_cnt();

  /* CONTROL plane (check segment): the whole rendezvous state lives here and
     is reset unconditionally - the segment is attached in both
     configurations.  The futex has to be re-armed by hand, a zeroed avail
     would deadlock every lock() below. */
  session_shm_sig->is_end    = 0;
  session_shm_sig->mx.avail  = 1;
  session_shm_sig->mx.waiters = 0;
  session_shm_sig->proc_ref_cnt = 0;
  shm_notify(&session_shm_sig->connection_state,UNINITIALIZED);

  /* DATA plane (msg segment + shared send buffer): redirection-only, the
     rendezvous never maps it and keeps using the real socket instead. */
  if(global_session_mark_ptr->enable_shm){
    memset(session_msg,0,sizeof(struct msg_struct));
    send_buf_size[0]=0; // present send buf size
    send_buf_size[1]=max_send_buf_size; // max send buf size
    read_p=0; // shm_read()'s cursor into data1 (redirection only)
    /* long-term/global-write detection is a redirection feature as well: only
       check_global_state() consumes these two flags and it is reached from
       enable_shm paths (shm_read/shm_write, the ENDING branch of accept()) */
    session_shm_sig->is_mem_leaked         = 0;
    session_shm_sig->is_global_val_written = 0;
  }

  //epoll_event_op=EPOLLOUT;
  if(!fd_map){
    fd_map=ck_alloc(sizeof(int)*max_fd);
    DO_LOG("%d fd_map:%p\n",getpid(),fd_map);
  }

  atomic_store(&has_recv_msg, 0);
  memset(fd_map,0,sizeof(int)*max_fd);
  server_fd=-1;

  /* Both configurations start with the server's turn.  The server may emit an
     unprompted banner (mode 2: buffered and flushed into data2 by the first
     recv; sync-only: written straight to the socket), then, when it enters
     recv with no request in flight, publishes CLIENT ("I am in recv, the
     fuzzer may send") and waits for the request.  The logical order is
     therefore the same in both modes: server banner -> server yields ->
     client request -> server read. */
  shm_notify(&session_shm_sig->state,SERVER);

  sync_yielded=0;
  sync_handover=0;

  global_session_mark_ptr->session_inited=1;
}

int session_end(){
  DO_LOG("%d session end %d %d %d %d\n",getpid(),session_msg->buf_size,session_msg->len1,session_msg->len2,session_shm_sig->is_end);
  if(global_session_mark_ptr->socket_type==SOCK_DGRAM)
    exit(0);
  errno=ECONNRESET;

  return -1;
}

static void check_global_state(){
  int i;

  if(session_shm_sig->is_mem_leaked>0 || session_shm_sig->is_global_val_written>0){ // check if any long-term data is written or memory leaks occur
    if(!original_close)
      original_close = dlsym(RTLD_NEXT,"close");

    for(i=0;i<max_fd;i++){
      if(check_fd(i,SERVER_FD) || check_fd(i,SESSION_FD))
        original_close(i);
    }

    memset(fd_map,0,sizeof(int)*max_fd);
    session_fd=-400;
    server_fd=-400;
    epoll_server_fd=-400;
    epoll_session_fd=-400;
    DO_LOG("exit %d %d\n",session_shm_sig->is_mem_leaked,session_shm_sig->is_global_val_written);
    exit(0);
  }
}

void suspend(){
  reset_loop_cnt();
  if(!is_kill && global_session_mark_ptr->socket_type!=SOCK_DGRAM){  // Can't determine when to end a session in connectionless protocol udp
    raise(SIGSTOP);
  }
}

static void remap(int old_size,int new_size){
  char *new_send_buf;

  new_send_buf=mmap(0, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd_for_fork, 0);
  if (new_send_buf == MAP_FAILED){
    _exit(1);
  }

  memcpy(new_send_buf,send_buf,old_size);
  munmap(send_buf,old_size);
  send_buf=new_send_buf;
}

static int get_line_end(const void *buf,int size){
  void *line_end;

  line_end=memchr(buf,'\n',size);
  if(!line_end)
    return -1;

  return line_end-buf;
}

static int shm_read(int fd,char *buf,size_t size,int read_line,int nonblock){
  int result=0,line_end,buf_size;
  sigset_t sigset;

  /* read request bytes written by the fuzzer into data1 (s2s_shm_write on the
     fuzzer side).  Returns bytes copied, or 0 when there is no request yet, or
     -1/session_end() when the fuzzer already closed the session. */

  DO_LOG("%d %d shm_read() starts waiting\n",getpid(),gettidv());
  thread_block_signal(&sigset);
  lock(&session_shm_sig->mx);
  reset_loop_cnt();

  if(atomic_load(&session_shm_sig->connection_state)==ENDING || session_shm_sig->is_end){
    unlock(&session_shm_sig->mx);
    thread_unblock_signal(&sigset);
    return session_end();
  }

  if(nonblock){
    /* the fuzzer owns the turn: a non-blocking read reports EAGAIN instead
       of parking on the token */
    if(atomic_load(&session_shm_sig->state)==CLIENT){
      errno = EAGAIN;
      unlock(&session_shm_sig->mx);
      thread_unblock_signal(&sigset);
      return -1;
    }
  } else if(shm_wait(&session_shm_sig->state,CLIENT,SESSION_STALL_TIMEOUT)){
    /* the peer never handed the request over within the stall cap: treat the
       session as over instead of spinning on the token forever */
    unlock(&session_shm_sig->mx);
    thread_unblock_signal(&sigset);
    return session_end();
  }
  if(atomic_load(&session_shm_sig->connection_state)==ENDING || session_shm_sig->is_end){
    unlock(&session_shm_sig->mx);
    thread_unblock_signal(&sigset);
    return session_end();
  }
  else if(session_msg->len1==0){
    if(atomic_exchange(&has_recv_msg,0)){ // no more msg to read
      errno = EAGAIN;
      epoll_event_op = EPOLLOUT;
      unlock(&session_shm_sig->mx);
      thread_unblock_signal(&sigset);
      return -1;
    }
    else{ // waiting for client's msg
      shm_notify(&session_shm_sig->state,CLIENT);
      epoll_event_op = EPOLLIN;
      unlock(&session_shm_sig->mx);
      thread_unblock_signal(&sigset);
      if(nonblock){
        errno = EAGAIN;
        return -1;
      }
      return 0;
    }
  }
  else // during message receiving
    atomic_store(&has_recv_msg,1);

  do{
    if(read_line){
      buf_size=size<session_msg->buf_size?size:session_msg->buf_size;
      line_end=get_line_end(session_msg->data1+read_p,buf_size);
      if(line_end>=0)
        size=line_end+1;
    }

    if(session_msg->buf_size>size){
      memcpy(buf+result,session_msg->data1+read_p,size);
      result+=size;
      session_msg->buf_size-=size;
      session_msg->len1-=size;
      read_p+=size;
      size=0;
    }
    else{
      memcpy(buf+result,session_msg->data1+read_p,session_msg->buf_size);
      result+=session_msg->buf_size;
      session_msg->len1-=session_msg->buf_size;
      size-=session_msg->buf_size;
      session_msg->buf_size=0;
      read_p=0;
      if(session_msg->len1>0){
        shm_notify(&session_shm_sig->state,CLIENT);
        if(size){ // size > buf_size and size < len1
          if(nonblock){
            /* the rest of the request needs another data1 chunk; let the
               fuzzer refill and return what we have now */
            unlock(&session_shm_sig->mx);
            thread_unblock_signal(&sigset);
            return result;
          }
          if(shm_wait(&session_shm_sig->state,CLIENT,SESSION_STALL_TIMEOUT)){
            unlock(&session_shm_sig->mx);
            thread_unblock_signal(&sigset);
            return session_end();
          }
        }
      }
      else
        break;
        //epoll_event_op = EPOLLOUT;
      DO_LOG("\n%d read2 %d %d %d %s\n",fd,read_p,session_msg->len1,atomic_load(&session_shm_sig->state),buf);
    }
  }while(size);

  unlock(&session_shm_sig->mx);
  thread_unblock_signal(&sigset);
  DO_LOG("%d %d shm_read() finishes\n",getpid(),gettidv());

  return result;
}

/* Wait for the peer to hand the response turn over, but never past the end of
   the session.  A plain shm_wait(&state, CLIENT, -1) only watches the token,
   and the fuzzer's end-of-session paths do not always move it off CLIENT
   (notify_timeout() sets CLIENT, the close path leaves it there), so that wait
   can spin forever - inside recv() on the flush that precedes shm_read(), and
   worse inside the exit path, where it would turn a clean session end into a
   hang.  The wait is additionally bounded by SESSION_STALL_TIMEOUT so a token
   that never moves (and never gets an is_end either) cannot wedge the target.
   Returns 1 when the turn arrived, 0 when the session ended first or the
   stall cap expired (the pending bytes are undeliverable then). */
static int wait_peer_turn(){
  int timed_out = shm_wait(&session_shm_sig->state,CLIENT,SESSION_STALL_TIMEOUT);

  return !timed_out && !session_shm_sig->is_end;
}

/* Wait while connection_state == RUNNING, i.e. for the fuzzer to arm the next
   run (its post_run sets UNINITIALIZED).  The wait is bounded: if no re-arm
   arrives within SESSION_STALL_TIMEOUT (missing post_run, fuzzer gone), force
   the stale RUNNING back to UNINITIALIZED instead of parking the target
   forever.  This is used by the mode-2 accept/poll/select/epoll paths. */
static void wait_connection_arm(){
  if(shm_wait(&session_shm_sig->connection_state,RUNNING,SESSION_STALL_TIMEOUT))
    __sync_bool_compare_and_swap(&session_shm_sig->connection_state,RUNNING,UNINITIALIZED);
}

static int shm_write_buf(const char* buf,size_t len){
  DO_LOG("%d %d shm_write_buf() starts waiting\n",getpid(),gettidv());
  sigset_t sigset;

  thread_block_signal(&sigset);
  lock(&session_shm_sig->mx);
  reset_loop_cnt();

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d write buf %d %d %d %d %p %s\n",gettidv(),len,send_buf_size[0],send_buf_size[1],max_send_buf_size,send_buf,buf);
  #endif
  atomic_store(&has_recv_msg,0);

  if (send_buf_size[1] != max_send_buf_size) // Max send buf size is modified by other process
  {
    remap(max_send_buf_size,send_buf_size[1]);
    max_send_buf_size=send_buf_size[1];
  }

  if(send_buf_size[0]+len>max_send_buf_size){
    int old_size=max_send_buf_size;
    DO_LOG("%d start expanding %d %d %p\n",getpid(),send_buf_size[0]+len,max_send_buf_size,send_buf);
    do{
      max_send_buf_size<<=1;
    }while(send_buf_size[0]+len>max_send_buf_size);
    DO_LOG("%d finish expanding %d %d %p\n",getpid(),send_buf_size[0]+len,max_send_buf_size,send_buf);
    ftruncate(shared_fd_for_fork, max_send_buf_size);
    send_buf_size[1]=max_send_buf_size;
    remap(old_size,max_send_buf_size);
  }

  memcpy(send_buf+send_buf_size[0],buf,len);
  send_buf_size[0]+=len;
  epoll_event_op=EPOLLIN;
  unlock(&session_shm_sig->mx);
  thread_unblock_signal(&sigset);
  DO_LOG("%d %d shm_write_buf() finishes\n",getpid(),gettidv());

  return len;
}

static int shm_write(int is_lock){
  int remain=0,p=0;
  sigset_t sigset;

  thread_block_signal(&sigset);
  if(is_lock)
    lock(&session_shm_sig->mx);
  reset_loop_cnt();
  atomic_store(&has_recv_msg,0);

  if(send_buf_size[0]>0 && session_msg->len1==0){
    if(!wait_peer_turn()){
      /* the session is already over: nobody will read the response, drop the
         pending bytes instead of waiting for a turn that never comes */
      send_buf_size[0]=0;
    }
    else{
      session_msg->len2=send_buf_size[0];

      for(remain=send_buf_size[0],p=0;remain>0;){
        if(remain<=MAX_MSG_SIZE){
          memcpy(session_msg->data2,send_buf+p,remain);
          p+=remain;
          remain=0;
          shm_notify(&session_shm_sig->state,CLIENT);
        }
        else{
          memcpy(session_msg->data2,send_buf+p,MAX_MSG_SIZE);
          remain-=MAX_MSG_SIZE;
          p+=MAX_MSG_SIZE;
          shm_notify(&session_shm_sig->state,CLIENT);
          if(!wait_peer_turn()){ /* session ended while draining data2 */
            session_msg->len2=p;
            break;
          }
        }
      }
      send_buf_size[0]=0;
    }
  }

  if(is_lock)
    unlock(&session_shm_sig->mx);
  thread_unblock_signal(&sigset);

  return p;
}

/* Non-blocking flush of the pending response: publish one data2 chunk only if
   the server owns the turn (state == SERVER).  Used by non-blocking recv
   paths; the event loop retries until send_buf is fully drained.  Returns 1
   when a chunk was published, 0 when there is nothing to flush or the turn is
   not available. */
static int shm_write_nonblock(void){
  sigset_t sigset;
  int n;

  if(!session_msg || !send_buf_size)
    return 0;
  if(send_buf_size[0]<=0 || session_msg->len1!=0)
    return 0;
  if(atomic_load(&session_shm_sig->state)!=SERVER)
    return 0;

  thread_block_signal(&sigset);
  lock(&session_shm_sig->mx);
  reset_loop_cnt();
  atomic_store(&has_recv_msg,0);

  if(send_buf_size[0]>0 && session_msg->len1==0 &&
     atomic_load(&session_shm_sig->state)==SERVER){
    n=send_buf_size[0];
    if(n>MAX_MSG_SIZE)
      n=MAX_MSG_SIZE;
    session_msg->len2=n;
    memcpy(session_msg->data2,send_buf,n);
    if(send_buf_size[0]>n)
      memmove(send_buf,send_buf+n,send_buf_size[0]-n);
    send_buf_size[0]-=n;
    shm_notify(&session_shm_sig->state,CLIENT);
  }
  else
    n=0;

  unlock(&session_shm_sig->mx);
  thread_unblock_signal(&sigset);

  return n>0;
}

/* A send by the server does not change ownership: SERVER keeps it until it
   enters recv and yields CLIENT (the only hand-over point in the unified
   model).  Only reset the per-message bookkeeping here. */
static void send_state_trans(){
  reset_loop_cnt();
  atomic_store(&has_recv_msg,0);
}

static u64 sockhook_now_ms(void){
  struct timeval tv;

  gettimeofday(&tv,NULL);
  return (u64)(tv.tv_sec*1000ULL)+(u64)(tv.tv_usec/1000);
}

/* Standalone rendezvous (real socket) under the unified ownership model:

     SERVER owns the session by default (including while it sends a banner or
     a response).  When it enters recv at the start of a message and has no
     request, it publishes CLIENT and parks on the token; only the fuzzer's
     send (which itself waits for CLIENT) publishes SERVER again.  After that
     hand-over the target must not yield again: the request bytes may still be
     in flight, so they are awaited in short poll slices while is_end/ENDING
     stay reachable. */
static int recv_state_trans(int fd,int nonblock){
  struct pollfd pfd[1];
  u64 start=0;
  int rv;

  reset_loop_cnt();
  pfd[0].fd = fd;
  pfd[0].events = POLLIN;
  if(!original_poll)
    original_poll=dlsym(RTLD_NEXT,"poll");

  for(;;){

    if(session_shm_sig->is_end || atomic_load(&session_shm_sig->connection_state)==ENDING)
      return session_end();

    /* CLIENT: the fuzzer owns the turn.  Park on the token (bounded) until it
       has sent the request and handed SERVER back. */
    if(atomic_load(&session_shm_sig->state)==CLIENT){
      sync_yielded=1;
      if(nonblock){
        errno=EAGAIN;
        return -1;
      }
      if(shm_wait(&session_shm_sig->state,CLIENT,SESSION_STALL_TIMEOUT))
        return session_end();
      sync_yielded=0;
      sync_handover=1;
      continue;
    }

    /* SERVER: our turn. */
    if(sync_yielded){
      /* the fuzzer answered our CLIENT yield */
      sync_yielded=0;
      sync_handover=1;
    }

    rv=original_poll(pfd,1,0);
    if(rv<0){
      if(errno==EINTR)
        continue;
      return -1;
    }
    if(rv>0){
      atomic_store(&has_recv_msg,1);
      sync_handover=0;
      return 0;
    }

    if(atomic_exchange(&has_recv_msg,0)){
      /* we already read part of this message and the socket is dry: message
         boundary, exactly as before */
      sync_handover=0;
      errno = EAGAIN;
      return -1;
    }

    if(sync_handover){
      /* the fuzzer handed the turn over after sending, but the bytes may
         still be in flight.  Do not yield the turn back. */
      if(nonblock){
        errno=EAGAIN;
        return -1;
      }
      if(!start)
        start=sockhook_now_ms();
      if(sockhook_now_ms()-start>=SESSION_STALL_TIMEOUT)
        return session_end();

      rv=original_poll(pfd,1,50);
      if(rv>0){
        atomic_store(&has_recv_msg,1);
        sync_handover=0;
        return 0;
      }
      if(rv<0 && errno!=EINTR)
        return -1;
      continue;
    }

    /* start of a message with no request: yield the turn; blocking callers
       loop to the CLIENT wait, non-blocking callers report EAGAIN */
    shm_notify(&session_shm_sig->state,CLIENT);
    sync_yielded=1;
    if(nonblock){
      errno=EAGAIN;
      return -1;
    }

  }
}

void check_before_close(int is_lock,int fd){
  sigset_t sigset;

  if(check_fd(fd,SESSION_FD)){
    thread_block_signal(&sigset);
    if(is_lock)
      lock(&session_shm_sig->mx);
    fd_map[fd]=OTHER;
    session_fd=next_dup_fd(SESSION_FD);
    DO_LOG("%d %d closed %d %d %d %d %d\n",getpid(),gettidv(),fd,session_fd,server_fd,send_buf_size?send_buf_size[0]:0,session_shm_sig->proc_ref_cnt);

    /* guard against an unbalanced close (e.g. a path that registered a
       session fd without counting it): never let the refcount go negative,
       otherwise the last-reference test below can never fire */
    if(session_fd<0 && session_shm_sig->proc_ref_cnt>0)
      __sync_fetch_and_sub(&session_shm_sig->proc_ref_cnt,1); // race condition here if no lock

    if(global_session_mark_ptr->session_inited && __sync_bool_compare_and_swap(&session_shm_sig->proc_ref_cnt,0,0)){
      /* flush the pending response (redirection only - sync-only never touches
         the message buffers); when the session is already over shm_write()
         drops the bytes instead of waiting for a turn nobody will give */
      if(global_session_mark_ptr->enable_shm)
        shm_write(0);
      session_fd=-402;
      atomic_store(&has_recv_msg,0);
      session_shm_sig->is_end=6;
      if(epoll_session_fd>=0)
        clr_dup_fd(0,E_SESSION_FD);
      shm_notify(&session_shm_sig->state,CLIENT);
      shm_notify(&session_shm_sig->connection_state,ENDING);
    }

    if(is_lock)
      unlock(&session_shm_sig->mx);
    thread_unblock_signal(&sigset);
  }
  else if(check_fd(fd,SERVER_FD)){ // It's likely that this happens in the child process
    fd_map[fd]=OTHER;
    server_fd=next_dup_fd(SERVER_FD);
    DO_LOG("%d %d server fd closed %d next: %d %d %d\n",getpid(),gettidv(),fd,server_fd,send_buf_size?send_buf_size[0]:0,session_shm_sig->proc_ref_cnt);
  }
}

__attribute__((noreturn)) void _exit(int status){
  sigset_t sigset;

  if(!original__exit)
    original__exit=dlsym(RTLD_NEXT,"_exit");

  /* nothing was set up / no config to consult yet: just exit */
  if(!sockhook_inited)
    original__exit(status);

  /* clean up only when this process actually set up a session (per-process
     mark); the CONTROL segment carries the shared rendezvous state and is
     attached whenever one of the two halves is engaged, so the
     rendezvous-only configuration reports the session end (is_end / ENDING)
     as well instead of only closing the socket.  During a setup_shm()
     failure nothing is attached, so there is nothing to clean up either. */
  if((global_session_mark_ptr->enable_shm || global_session_mark_ptr->enable_shmsync)
     && session_shm_sig 
     && global_session_mark_ptr->session_inited){
    #ifdef DEBUG_MODE
      if(__log_fd)
        DO_LOG("%d %d exit0:%d %d\n",getpid(),gettidv(),status,session_shm_sig->proc_ref_cnt);
    #endif
    thread_block_signal(&sigset);
    lock(&session_shm_sig->mx);
    if(fd_map){
      if(session_fd>=0 || (session_fd=next_dup_fd(SESSION_FD))>=0){
        memset(fd_map,0,max_fd*sizeof(int));
        fd_map[session_fd]=SESSION_FD;
        check_before_close(0,session_fd);
      }
      ck_free(fd_map);
      fd_map=NULL;
    }
    unlock(&session_shm_sig->mx);
    thread_unblock_signal(&sigset);
  }

  original__exit(status);
}

__attribute__((noreturn)) void exit(int status){
  sigset_t sigset;

  if(!original_exit)
    original_exit=dlsym(RTLD_NEXT,"exit");

  /* nothing was set up / no config to consult yet: just exit */
  if(!sockhook_inited)
    original_exit(status);

  /* clean up only when this process actually set up a session (per-process
     mark); the CONTROL segment carries the shared rendezvous state and is
     attached whenever one of the two halves is engaged, so the
     rendezvous-only configuration reports the session end (is_end / ENDING)
     as well instead of only closing the socket.  During a setup_shm()
     failure nothing is attached, so there is nothing to clean up either. */
  if((global_session_mark_ptr->enable_shm || global_session_mark_ptr->enable_shmsync)
     && session_shm_sig 
     && global_session_mark_ptr->session_inited){
    #ifdef DEBUG_MODE
      if(__log_fd)
        DO_LOG("%d %d exit1:%d %d %d %d\n",getpid(),gettidv(),status,session_shm_sig->proc_ref_cnt,session_fd,global_session_mark_ptr->session_inited);
    #endif
    thread_block_signal(&sigset);
    lock(&session_shm_sig->mx);
    if(fd_map){
      if(session_fd>=0 || (session_fd=next_dup_fd(SESSION_FD))>=0){
        memset(fd_map,0,max_fd*sizeof(int));
        fd_map[session_fd]=SESSION_FD;
        check_before_close(0,session_fd);
      }
      ck_free(fd_map);
      fd_map=NULL;
    }
    unlock(&session_shm_sig->mx);
    thread_unblock_signal(&sigset);
  }

  original_exit(status);
}

pid_t fork(){
  int ret_val;

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d do fork... %d\n",getpid(),session_shm_sig->proc_ref_cnt);
  #endif

  if(!original_fork)
    original_fork=dlsym(RTLD_NEXT,"fork");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_fork();

  if(session_fd>=0 || next_dup_fd(SESSION_FD)>=0)
    __sync_fetch_and_add(&session_shm_sig->proc_ref_cnt,1);

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d do fork2... %d %d\n",getpid(),session_shm_sig->proc_ref_cnt,next_dup_fd(SESSION_FD));
  #endif

  /* proc_ref_cnt is shared by both halves (it is how the close/exit path
     knows the last session reference is gone), but the fake-readiness loop
     counters belong to the redirection only. */
  if(global_session_mark_ptr->enable_shm)
    reset_loop_cnt();
  ret_val=original_fork();
  if(!ret_val){
    is_child=1;
    #ifdef DEBUG_MODE
      if(__log_fd)
        DO_LOG("%d fork child %d %d\n",getpid(),session_shm_sig->proc_ref_cnt,next_dup_fd(SESSION_FD));
    #endif
  }

  return ret_val;
}

int execve(const char *pathname, char *const argv[], char *const envp[]){
  if(!original_execve)
    original_execve=dlsym(RTLD_NEXT,"execve");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_execve(pathname,argv,envp);

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d execve: %d %s\n",getpid(),next_dup_fd(SESSION_FD),pathname);
  #endif

  int next_fd;
  if((next_fd=next_dup_fd(SESSION_FD))>=0){
    memset(fd_map,0,max_fd*sizeof(int));
    fd_map[next_fd]=SESSION_FD;
    check_before_close(1,next_fd);
  }

  return original_execve(pathname,argv,envp);
}

int dup(int oldfd){
  int ret_val;

  if(!original_dup)
    original_dup=dlsym(RTLD_NEXT,"dup");
  ret_val=original_dup(oldfd);
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return ret_val;

  if(global_session_mark_ptr->session_inited && ret_val>=0 && fd_map){
    check_fd(ret_val,OTHER); // just expand the fd_map if in need
    fd_map[ret_val]=fd_map[oldfd];
  }

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d dup:%d %d\n",getpid(),oldfd,ret_val);
  #endif

  return ret_val;
}

int dup2(int oldfd, int newfd){
  int ret_val;

  #ifdef DEBUG_MODE
    int log_fd;
    if(__log_fd){
      log_fd=fileno(__log_fd);
      if(newfd==log_fd){
        DO_LOG("log file dupped\n");
        fclose(__log_fd);
      }
    }
  #endif

  if(!original_dup2)
    original_dup2=dlsym(RTLD_NEXT,"dup2");
  ret_val=original_dup2(oldfd,newfd);
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return ret_val;

  if(global_session_mark_ptr->session_inited && ret_val>=0 && fd_map){
    check_fd(ret_val,OTHER);
    fd_map[ret_val]=fd_map[oldfd];
  }

  #ifdef DEBUG_MODE
    if(__log_fd && fd_map)
      DO_LOG("%d dup2:%d %d %d %d %d\n",getpid(),oldfd,newfd,ret_val,fd_map[oldfd],fd_map[newfd]);
  #endif

  return ret_val;
}

int __poll(struct pollfd *fds, nfds_t nfds, int timeout){
  return poll(fds,nfds,timeout);
}

/* Event-driven target: waiting in poll()/select()/epoll_wait() for the
   session fd is the non-blocking equivalent of entering recv().  Announce
   CLIENT once so the fuzzer's wait_request_turn can proceed; the real socket
   readiness wakes the target when the request bytes arrive. */
static void sync_ready_from_poll(int fd){
  if(!global_session_mark_ptr->enable_shmsync ||
     global_session_mark_ptr->enable_shm)
    return;
  if(!check_fd(fd,SESSION_FD))
    return;
  if(sync_handover || sync_yielded || atomic_load(&has_recv_msg))
    return;
  if(atomic_load(&session_shm_sig->state)!=SERVER)
    return;

  shm_notify(&session_shm_sig->state,CLIENT);
  sync_yielded=1;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout){
  int i,session_i=-1,server_i=-1,ret_val=0,tmp,tmp_session_fd=-1;

  if(!original_poll)
    original_poll=dlsym(RTLD_NEXT,"poll");
  /* redirection-only hook: the fake readiness and the ENDING parking below
     substitute for a session socket the target does not own.  With the
     rendezvous alone (enable_shmsync, enable_shm == 0) the target owns the
     real socket, so it must see the unmodified poll() - pass straight
     through instead of scanning every fd for session sockets. */
  if(!sockhook_inited)
    return original_poll(fds,nfds,timeout);

  if(!global_session_mark_ptr->enable_shm){
    if(global_session_mark_ptr->enable_shmsync)
      for(i=0;i<nfds;i++)
        sync_ready_from_poll(fds[i].fd);
    return original_poll(fds,nfds,timeout);
  }

  for(i=0;i<nfds;i++){
    if(check_fd(fds[i].fd,SESSION_FD)){ //&& (epoll_event_op==EPOLLIN || (fds[i].events&POLLIN)==0)){
      if(global_session_mark_ptr->enable_shm)   /* report a fake "ready" fd only when
                                            the target does not own the socket */
        ret_val++;
      session_i=i;
      tmp_session_fd=fds[i].fd;
    }
    else if(check_fd(fds[i].fd,SERVER_FD)){
      server_i=i;
    }
  }

  if((session_shm_sig->is_end || session_i<0) && server_i>=0
     && global_session_mark_ptr->enable_shm){
      wait_connection_arm();
      if(__sync_bool_compare_and_swap(&session_shm_sig->connection_state,ENDING,UNINITIALIZED)){
        check_global_state();
        suspend();
      }
  }

  #ifdef DEBUG_MODE
    if(__log_fd && original_fprintf)
      DO_LOG("poll:%d\n",session_i);
  #endif

  if(global_session_mark_ptr->enable_shm && session_i>=0 && poll_loop_cnt<MAX_LOOP){
    tmp=original_poll(fds,nfds,0);
    fds[session_i].fd=tmp_session_fd; // poll may modify the fd
    fds[session_i].revents=POLLIN | POLLOUT;
    poll_loop_cnt++;
    atomic_store(&has_recv_msg,0);
  }
  else
    tmp=original_poll(fds,nfds,timeout);

  if(tmp>=0 && poll_loop_cnt<MAX_LOOP)
    ret_val+=tmp;
  else
    ret_val=tmp;

  #ifdef DEBUG_MODE
    if(__log_fd && original_fprintf)
      DO_LOG("poll:%d %d %d %d\n",session_i,server_i,ret_val,tmp);
  #endif

  return ret_val;
}

/* Track which epoll instance watches the session/listener fd.  Used by the
   mode-2 fake readiness and, in sync-only, to publish CLIENT when an
   event-driven target starts waiting in epoll_wait(). */
static void epoll_track(int op,int epfd,int fd){
  if(op==EPOLL_CTL_ADD){
    if(check_fd(fd,SESSION_FD)){
      grow_fd_map(epfd);
      epoll_session_fd=epfd;
      fd_map[epfd]|=E_SESSION_FD;
    }
    else if(check_fd(fd,SERVER_FD)){
      grow_fd_map(epfd);
      epoll_server_fd=epfd;
      fd_map[epfd]|=E_SERVER_FD;
    }
  }
  else if(op==EPOLL_CTL_DEL){
    if(check_fd(fd,SESSION_FD)){
      grow_fd_map(epfd);
      //epoll_session_fd=-402;
      epoll_session_fd=next_dup_fd(E_SESSION_FD);
      fd_map[epfd]&=~E_SESSION_FD;
    }
    else if(check_fd(fd,SERVER_FD)){
      grow_fd_map(epfd);
      //epoll_server_fd=-401;
      epoll_server_fd=next_dup_fd(E_SERVER_FD);
      fd_map[epfd]&=~E_SERVER_FD;
    }
  }
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event){

  if(!original_epoll_ctl)
    original_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");

  if(!sockhook_inited)
    return original_epoll_ctl(epfd,op,fd,event);

  if(!global_session_mark_ptr->enable_shm){
    /* sync-only: remember the registration so epoll_wait() can yield */
    if(global_session_mark_ptr->enable_shmsync)
      epoll_track(op,epfd,fd);
    return original_epoll_ctl(epfd,op,fd,event);
  }

  epoll_track(op,epfd,fd);

  return original_epoll_ctl(epfd,op,fd,event);
}

int epoll_wait(int epfd, struct epoll_event *events, // Really naive implementation
                      int maxevents, int timeout){
  static struct epoll_event event;
  int ret_val;

  if(!original_epoll_wait)
    original_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
  if(!sockhook_inited)
    return original_epoll_wait(epfd,events,maxevents,timeout);

  if(!global_session_mark_ptr->enable_shm){
    /* sync-only: the target waits on the real socket; publish CLIENT once
       when it starts the epoll wait for the session fd */
    if(global_session_mark_ptr->enable_shmsync &&
       check_fd(epfd,E_SESSION_FD))
      sync_ready_from_poll(session_fd);
    return original_epoll_wait(epfd,events,maxevents,timeout);
  }

  if(check_fd(epfd,E_SESSION_FD) && !session_shm_sig->is_end && epoll_loop_cnt<MAX_LOOP){ // Watch session sockets and it has higher priority.
    if(!global_session_mark_ptr->enable_shm)
      return original_epoll_wait(epfd,events,maxevents,timeout);
    event.events = EPOLLOUT | EPOLLIN; //epoll_event_op;
    event.data.fd = session_fd;
    *events=event;
    epoll_loop_cnt++;
    atomic_store(&has_recv_msg,0);
    return 1;
  }
  else if(check_fd(epfd,E_SERVER_FD) && global_session_mark_ptr->enable_shm){
    wait_connection_arm();
    if(__sync_bool_compare_and_swap(&session_shm_sig->connection_state,ENDING,UNINITIALIZED)){
      check_global_state();
      suspend();
    }
  }

  ret_val=original_epoll_wait(epfd,events,maxevents,timeout);

  #ifdef DEBUG_MODE
    if(__log_fd){
      DO_LOG("%d %d %d epoll_wait:%d %d %d %d %d\n",getpid(),gettidv(),ret_val,epfd,check_fd(epfd,E_SESSION_FD),check_fd(epfd,E_SERVER_FD),check_fd(epfd,SESSION_FD),check_fd(epfd,SERVER_FD));
      if(ret_val>0)
        DO_LOG("%d epoll_wait2: %d %d %d\n",epfd,events->data.fd,events->events,fd_map[events->data.fd]);
    }
  #endif

  return ret_val;
}

static int extract_select_fd(int nfds,fd_set *restrict fds,int target){
  int i;

  if(!fd_map || nfds<=0)
    return -1;

  /* select()'s nfds is caller-controlled and may exceed the current map
     size; grow once so the loop below cannot read past fd_map. */
  grow_fd_map(nfds-1);

  for(i=0;i<nfds;i++){
    if(fd_map[i]&target && FD_ISSET(i,fds))
      return i;
  }

  return -1;
}

int select(int nfds, fd_set *restrict readfds,
                  fd_set *restrict writefds, fd_set *restrict exceptfds,
                  struct timeval *restrict timeout){
  int i,ret_val,tmp=0,extract_read,extract_write,server_extract_read=-1;

  if(!original_select)
    original_select=dlsym(RTLD_NEXT,"select");
  if(!sockhook_inited)
    return original_select(nfds,readfds,writefds,exceptfds,timeout);

  if(!global_session_mark_ptr->enable_shm){
    /* sync-only: real fd sets untouched, but publish CLIENT once when the
       target starts waiting for a session fd */
    if(global_session_mark_ptr->enable_shmsync && readfds)
      for(i=0;i<nfds && i<FD_SETSIZE;i++)
        if(FD_ISSET(i,readfds))
          sync_ready_from_poll(i);
    return original_select(nfds,readfds,writefds,exceptfds,timeout);
  }

  if(readfds){
    if(session_fd>=0 && FD_ISSET(session_fd,readfds)){
      if(global_session_mark_ptr->enable_shm)
        FD_CLR(session_fd,readfds);
      tmp|=1;
    }
    else if((extract_read=extract_select_fd(nfds,readfds,SESSION_FD))>=0){
      if(global_session_mark_ptr->enable_shm)
        FD_CLR(extract_read,readfds);
      tmp|=4;
    }
    if((server_fd>=0 && FD_ISSET(server_fd,readfds)) || (server_extract_read=extract_select_fd(nfds,readfds,SERVER_FD))>=0){
      if(global_session_mark_ptr->enable_shm && (tmp&5)==0){
        wait_connection_arm();
        if(__sync_bool_compare_and_swap(&session_shm_sig->connection_state,ENDING,UNINITIALIZED)){
          check_global_state();
          suspend();
        }
      }
      else if(global_session_mark_ptr->enable_shm) // accept() only creates 1 session
        FD_CLR(server_extract_read>=0?server_extract_read:server_fd,readfds);
    }
  }

  if(writefds && global_session_mark_ptr->enable_shm){
    if(session_fd>=0 && FD_ISSET(session_fd,writefds)){
      FD_CLR(session_fd,writefds);
      tmp|=2;
    }
    else if((extract_write=extract_select_fd(nfds,writefds,SESSION_FD))>=0){
      FD_CLR(extract_write,writefds);
      tmp|=8;
    }
  }

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d select:%d %d %d %d\n",getpid(),tmp,global_session_mark_ptr->socket_type,select_loop_cnt,tmp);
  #endif

  if(global_session_mark_ptr->enable_shm && tmp>0 && select_loop_cnt<MAX_LOOP){
    ret_val=original_select(nfds,readfds,writefds,exceptfds,&select_timeout); // always readable or writable
    ret_val=ret_val<0?0:ret_val;
    select_timeout.tv_sec=0; // select() may modify the timeout struct
    select_timeout.tv_usec=0;
    select_loop_cnt++;
  }
  else{
    ret_val=original_select(nfds,readfds,writefds,exceptfds,timeout);
  }

  if(global_session_mark_ptr->enable_shm && ret_val>=0 && select_loop_cnt<MAX_LOOP){
    if(tmp&1){
      FD_SET(session_fd,readfds);
      ret_val++;
      atomic_store(&has_recv_msg,0);
    }
    if(tmp&2){
      FD_SET(session_fd,writefds);
      ret_val++;
    }
    if(tmp&4){
      FD_SET(extract_read,readfds);
      ret_val++;
      atomic_store(&has_recv_msg,0);
    }
    if(tmp&8){
      FD_SET(extract_write,writefds);
      ret_val++;
    }
  }

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d select:%d %d %d %d %d\n",getpid(),session_fd,server_fd,FD_ISSET(server_fd,readfds),ret_val,errno);
  #endif

  return ret_val;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
  int ret_val,reuse=1;
  int type,length=sizeof(int);
  int is_netport;

  if(!original_bind)
    original_bind=dlsym(RTLD_NEXT, "bind");
  if (!original_bind) {

    errno = ENOSYS;
    return -1;

  }

  /* the library can be entered before init_sockhook() ran: stay a plain
     bind() then (this hook reads the config before doing anything else) */
  if(!sockhook_inited)
    return original_bind(sockfd,addr,addrlen);

  /* __AFL_NETPORT is the port the fuzzer dials, so a bind() to it is the
     AFLNet server socket - matching it is the only thing that identifies the
     target socket.  There is deliberately no "first bind wins" fallback for
     a missing port (netport <= 0, e.g. a standalone preload): without
     __AFL_NETPORT the target port is simply unknown, so the library stays an
     inert pass-through instead of arming a session on an arbitrary socket.
     Every afl-fuzz run gets the variable from aflnet_sockhook_preload()
     (config.c); a manual run has to export it itself. */
  is_netport = global_session_mark_ptr->netport > 0 &&
               sockaddr_port(addr,addrlen)==global_session_mark_ptr->netport;
  if(is_netport)
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse));
  ret_val=original_bind(sockfd,addr,addrlen);

  /* The session socket has to be the target port AND a datagram socket of the
     announced protocol: datagram targets only ever have this one socket and
     never call accept(), so bind() is both their session-arming point and
     their "listening" moment.  Stream targets arm at accept() instead - that
     way every test child arms its own session (the bind()/session_init() pair
     runs only once, in the deferred forkserver parent, and its child inherits
     the "armed" mark), and a bind() that happens before any session exists
     cannot register the listener in an fd_map that has not been allocated
     yet.  A failed getsockopt() leaves the type unknown, so the socket is
     treated as not-the-target one. */
  if(ret_val==0 && is_netport &&
     !getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &length) &&
     type == SOCK_DGRAM &&
     type == global_session_mark_ptr->socket_type){

    /* UDP deferred forkserver: connectionless (datagram) servers have no
       listen(), so start the deferred forkserver here, at the bind() of the
       target port, before serving.  TCP defers at listen() instead.  Only when
       __AFL_DEFER_FORKSRV enables deferred mode; maybe_start_deferred_fs()
       re-checks deferred_fs_wanted/deferred_fs_started, so a plain call is
       enough. */
    if(global_session_mark_ptr->deferred_fs_wanted)
      maybe_start_deferred_fs();

    if(global_session_mark_ptr->enable_shm || global_session_mark_ptr->enable_shmsync){
      session_init();
      session_fd = sockfd;
      grow_fd_map(sockfd);
      fd_map[sockfd] |= SESSION_FD;
      /* The bound datagram socket is itself the session fd and has no
         accept() to increment the refcount; count it here so the matching
         close decrements to zero and reports is_end=6/ENDING. */
      __sync_fetch_and_add(&session_shm_sig->proc_ref_cnt,1);
      if(global_session_mark_ptr->enable_shmsync && !global_session_mark_ptr->enable_shm)
        shm_notify(&session_shm_sig->connection_state,RUNNING);
    }
  }

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d bind:%d %d %d %d\n",getpid(),sockfd,server_fd,
             sockaddr_port(addr,addrlen),addr?(int)addr->sa_family:-1);
  #endif

  return ret_val;
}

/* Port carried by a socket address, or -1 when the address carries none:
   NULL, an address too short to hold the family and port fields, or a family
   that has no port there at all (AF_UNIX, AF_NETLINK, AF_PACKET, ...).
   Family and length are validated *before* the port is read: the hooks used
   to read the two bytes at offset 2 unconditionally, which dereferenced a
   NULL/short address and let an AF_UNIX sun_path (or any other family's
   payload) look like the AFLNet target port. */
static int sockaddr_port(const struct sockaddr *addr, socklen_t addrlen) {

  if (!addr ||
      addrlen < offsetof(struct sockaddr_in, sin_port) + sizeof(in_port_t))
    return -1;

  if (addr->sa_family == AF_INET)
    return ntohs(((const struct sockaddr_in *)addr)->sin_port);

  if (addr->sa_family == AF_INET6)
    return ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);

  return -1;

}

/* ------------- deferred forkserver: stale connections in the accept queue --

   In deferred mode the forkserver parent owns the listening socket, and with
   it its accept queue; every per-run child inherits that listener (see
   maybe_start_deferred_fs).  A connection that a run never got around to
   accepting - the child died or was killed before its accept(), or the
   fuzzer gave the run up - therefore is still queued when the next child
   runs, with the fuzzer's end of it already closed and the bytes it sent
   still buffered.  Without filtering, that child serves the dead session:
   its response goes nowhere, the fuzzer's own connection stays queued, and
   because the fuzzer opens exactly one connection per run the queue stays
   exactly one connection behind for the rest of the campaign - every run
   answering the previous run's socket, silently, without a crash or a
   timeout ever being reported.

   A child therefore drops accept()ed connections whose peer is already gone
   and accepts again.  The native (non-deferred) forkserver re-binds the port
   in every child, so its accept queue always starts empty and nothing has to
   be filtered there; the filter is consequently armed only for the deferred
   configuration, which is the only one that shares the listener. */
static int drop_stale_connection(int fd) {

#ifdef __linux__
  struct tcp_info info;
  socklen_t       len = sizeof(info);

  /* CLOSE_WAIT: the peer sent FIN and will never send more (the socket may
     still hold what it sent before).  CLOSE: the connection was reset.  A
     connection the fuzzer is still using is ESTABLISHED, so the connection
     being served is never dropped here. */
  if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) == 0 &&
      (info.tcpi_state == TCP_CLOSE_WAIT || info.tcpi_state == TCP_CLOSE))
    return 1;
#else
  /* without TCP_INFO only an already-drained closed connection is
     recognisable */
  char c;

  if (!original_recv) original_recv = dlsym(RTLD_NEXT, "recv");
  if (original_recv && original_recv(fd, &c, 1, MSG_PEEK | MSG_DONTWAIT) == 0)
    return 1;
#endif

  return 0;
}

/* 1 when accept() on this fd has to filter leftovers of the previous run:
   deferred mode is on, the AFL++ forkserver was really started, and the fd is
   the target-port listener whose queue the children inherit.  The recorded fd
   carries the common case without a syscall; a dup()/dup2() of the listener
   is recognised through the bound port.  Unrelated listeners (management
   port, unix socket, ...) are never touched, and in the inert non-deferred
   configuration no check is done at all. */
static int stale_filter_wanted(int sockfd) {

  if (!global_session_mark_ptr || !global_session_mark_ptr->deferred_fs_wanted ||
      !deferred_fs_live || sockfd < 0)
    return 0;

  if (sockfd == deferred_listen_fd) return 1;

  return global_session_mark_ptr->netport > 0 && is_netport_listener(sockfd);
}

/* real accept()/accept4(), minus the connections a previous run left in the
   inherited accept queue (see drop_stale_connection).  With the filter off
   this is exactly the libc call, so the non-deferred configurations keep
   their previous behaviour and cost. */
static int accept_one(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

  int fd;

  if (!stale_filter_wanted(sockfd)) return original_accept(sockfd, addr, addrlen);

  if (!original_close) original_close = dlsym(RTLD_NEXT, "close");

  while ((fd = original_accept(sockfd, addr, addrlen)) >= 0 &&
         drop_stale_connection(fd)) {

    DO_LOG("%d accept: dropping stale connection %d\n", getpid(), fd);
    if (original_close) original_close(fd);

  }

  return fd;
}

static int accept4_one(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
                       int flags) {

  int fd;

  if (!stale_filter_wanted(sockfd))
    return original_accept4(sockfd, addr, addrlen, flags);

  if (!original_close) original_close = dlsym(RTLD_NEXT, "close");

  while ((fd = original_accept4(sockfd, addr, addrlen, flags)) >= 0 &&
         drop_stale_connection(fd)) {

    DO_LOG("%d accept4: dropping stale connection %d\n", getpid(), fd);
    if (original_close) original_close(fd);

  }

  return fd;
}

int accept(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen){
  int ret_val;

  if(!original_accept)
    original_accept=dlsym(RTLD_NEXT,"accept");
  if(!sockhook_inited)
    return original_accept(sockfd,addr,addrlen);

  /* inert configuration (no segment attached): pass through, except for the
     stale connections the deferred forkserver's inherited listener may hold
     (see accept_one()) */
  if(!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync)
    return accept_one(sockfd,addr,addrlen);

  /* The session context is per-process.  A stream target arms its session
     here, at the accept() of the target-port listener: that is the first
     point of the session in this process for the native forkserver model
     (fresh child, un-armed mark) and for the deferred model too, because the
     forkserver parent only arms on a *datagram* bind() (see bind()) - its
     stream listener is never armed, so every child starts un-armed and arms
     its own session here.  Arming before the parking wait below is required:
     the wait releases on UNINITIALIZED, and the ENDING check that follows
     must not see the previous run's state.  The port check keeps an unrelated
     listener (a management port accepted first) from being taken for the
     session listener, and it is the only eligibility rule: only the listener
     bound to the configured target port arms a session, so without
     __AFL_NETPORT the target port is unknown and nothing is ever armed.  In
     the inert configuration (no segment attached) this is never reached.

     Arming and registering are two separate steps on purpose.  A session may
     already be armed in this process - bind() armed it for a datagram target,
     or a deferred-forkserver child inherited session_inited from the parent -
     and the accepted connection must STILL be registered as the session fd
     below.  Tying the registration to the "just armed" branch meant such a
     process never marked the listener SERVER_FD, so check_fd() rejected the
     session and the whole SHM redirection silently fell back to the real
     socket.  (check_fd() first makes the steady state - the listener already
     registered - skip the getsockname() in is_netport_listener().) */
  if((global_session_mark_ptr->enable_shm || global_session_mark_ptr->enable_shmsync)
     && (check_fd(sockfd,SERVER_FD) || is_netport_listener(sockfd))){

    if(!global_session_mark_ptr->session_inited)
      session_init();

    server_fd=sockfd;              /* the listener serving this session */
    check_fd(sockfd,OTHER);        /* grow fd_map when needed */
    if(fd_map)
      fd_map[sockfd]|=SERVER_FD;

  }

  /* mode 2 (SHM redirection): park until the fuzzer arms a fresh run
     (UNINITIALIZED).  Sync-only runs keep the native accept: the fuzzer
     bounds its own wait instead, so a target that serves several sessions
     per run never blocks here. */
  if(global_session_mark_ptr->enable_shm)
    wait_connection_arm();
  if(check_fd(sockfd,SERVER_FD)){
    if(global_session_mark_ptr->enable_shm &&
       atomic_load(&session_shm_sig->connection_state)==ENDING){
      check_global_state();
      suspend();
    }
    /* publish "the server is listening and about to accept": the fuzzer
       waits for this before it connects (sync-only) / before it reads the
       shared request (mode 2) */
    shm_notify(&session_shm_sig->connection_state,RUNNING);
  }

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d accept: %d %d\n",getpid(),sockfd,session_shm_sig->is_end);
  #endif

  ret_val=accept_one(sockfd,addr,addrlen);
  if(check_fd(sockfd,SERVER_FD) && ret_val>=0){
    session_fd=ret_val;
    grow_fd_map(ret_val);
    fd_map[ret_val]|=SESSION_FD;
    __sync_fetch_and_add(&session_shm_sig->proc_ref_cnt,1);
  }

  #ifdef DEBUG_MODE
    if(__log_fd){
      DO_LOG("%d accept:%d %d %d %d %d\n",getpid(),sockfd,server_fd,ret_val,session_fd,session_shm_sig->is_end);
      if(ret_val<0)
        DO_LOG("%d accept errno:%d\n",getpid(),errno);
    }
  #endif

  return ret_val;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags){
  int ret_val;

  if(!original_accept4)
    original_accept4=dlsym(RTLD_NEXT,"accept4");
  if(!sockhook_inited)
    return original_accept4(sockfd,addr,addrlen,flags);

  /* inert configuration: pass through, apart from the stale connections of
     the deferred forkserver's inherited listener (see accept4_one()) */
  if(!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync)
    return accept4_one(sockfd,addr,addrlen,flags);

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d %d accept4_1: %d %d\n",getpid(),gettidv(),sockfd,flags&O_NONBLOCK);
  #endif

  /* same per-process arming/registering as accept(): a stream target arms its
     session at the accept4() of the target-port listener, never in bind(), and
     registering the listener is a separate step so an already-armed session
     still gets its accepted connection recognised (see accept()) */
  if((global_session_mark_ptr->enable_shm || global_session_mark_ptr->enable_shmsync)
     && session_shm_sig 
     && (check_fd(sockfd,SERVER_FD) || is_netport_listener(sockfd))){

    if(!global_session_mark_ptr->session_inited)
      session_init();

    server_fd=sockfd;
    check_fd(sockfd,OTHER);
    if(fd_map)
      fd_map[sockfd]|=SERVER_FD;

  }

  /* the per-run parking wait belongs to the SHM redirection (mode 2); the
     sync-only and inert configurations keep the native accept4 semantics */
  if(global_session_mark_ptr->enable_shm && !(flags & O_NONBLOCK))
    wait_connection_arm();

  if(check_fd(sockfd,SERVER_FD) && atomic_load(&session_shm_sig->connection_state)<=ENDING){
    if(atomic_load(&session_shm_sig->connection_state)==ENDING){
      check_global_state();
      suspend();
    }
    shm_notify(&session_shm_sig->connection_state,RUNNING);
  }
  ret_val=accept4_one(sockfd,addr,addrlen,flags);

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d %d accept4_2: %d %d\n",getpid(),gettidv(),sockfd,ret_val);
  #endif

  if(check_fd(sockfd,SERVER_FD) && ret_val>=0){
    session_fd=ret_val;
    grow_fd_map(ret_val);
    fd_map[ret_val]|=SESSION_FD;
    __sync_fetch_and_add(&session_shm_sig->proc_ref_cnt,1);
  }

  return ret_val;
}

/* Start AFL++'s native forkserver at the first listen() -- the natural
   deferred-forkserver point for a network server, used for every aflnet-pp
   run (this library is the uniform preload for AFLNET_SOCK and AFLNET_SOCK2SHM
   alike).  The forkserver parent stays in its service loop; each per-test
   child returns from __afl_manual_init(), inherits the already bound +
   listening socket and serves one session, skipping the pre-listen setup.

   Deferred mode is the default in the profuzzbench run scripts, which export
   AFLNET_DEFER_FORKSRV=1; afl-fuzz translates that into __AFL_DEFER_FORKSRV
   for the target so AFL++'s auto-init constructor returns early instead of
   starting the forkserver at program entry.  This hook then starts it here,
   at the first listen().  If deferred mode is off (unset, or
   AFLNET_DEFER_FORKSRV=0), the constructor has already started the forkserver
   and __afl_manual_init() is a no-op (the runtime guards against double
   init), so the hook only proxies to the real listen().
   When the target is not running under afl-fuzz the runtime also returns
   immediately, so the server runs normally.  The runtime symbol is resolved
   once in init_sockhook(): with deferred mode requested and the symbol
   missing, no forkserver could ever come up, so the library refuses to start
   (see warn_deferred_unavailable()). */

/* __AFL_DEFER_FORKSRV is set (AFLNET_DEFER_FORKSRV=1) but the target does not
   export the runtime entry point the forkserver has to be started with: the
   deferred forkserver cannot come up, so init_sockhook() says why and exits
   instead of leaving afl-fuzz to time out with a message that points nowhere.
   (afl-fuzz redirects the target's stdout/stderr to /dev/null, so this is
   mostly for manual runs; under afl-fuzz the immediate "Fork server handshake
   failed" carries the hint - see afl_fsrv_start().)
   Raw write(2): this can run before/while stdio is usable and the library
   interposes the stdio functions itself. */
static void warn_deferred_unavailable(void) {

  static const char msg[] =
    "sockhook: __AFL_DEFER_FORKSRV is set, but __afl_manual_init() could not "
    "be\n"
    "sockhook: resolved in the target, so the deferred forkserver cannot "
    "start -\n"
    "sockhook: refusing to run.  Build the target so that the AFL++ runtime "
    "symbols\n"
    "sockhook: are exported (afl-cc does it through AFL++'s dynamic_list.txt; "
    "the\n"
    "sockhook: classic afl-gcc/afl-clang assembler modes do not), or run "
    "without\n"
    "sockhook: AFLNET_DEFER_FORKSRV.\n";

  if (write(2, msg, sizeof(msg) - 1) < 0) { /* best effort */ }

}

/* Start AFL++'s native (deferred) forkserver exactly once, from whichever
   socket hook is the natural point for the protocol: TCP servers call
   listen(), datagram (UDP) servers only bind(), so both hooks call this after
   the real syscall succeeds.  Gated on __AFL_DEFER_FORKSRV (translated by
   afl-fuzz from AFLNET_DEFER_FORKSRV): when it is not set, the runtime
   constructor has already started the forkserver at program entry and
   __afl_manual_init() is a no-op anyway (double-init guard), so calling it is
   harmless.  Not gated on enable_shm: sockhook is the uniform preload for
   every aflnet-pp run, so deferred forkserver applies to the real-socket
   (AFLNET_SOCK) mode too, not only sock2shm. */
static void maybe_start_deferred_fs(void) {

  pid_t        caller_pid;
  sigset_t     alarm_set, saved_set;
  unsigned int pending_alarm;

  if (deferred_fs_started || !global_session_mark_ptr->deferred_fs_wanted) return;

  /* a helper that inherited the environment has no runtime entry point (see
     init_sockhook): stay a plain preload, never call a NULL pointer */
  if (!deferred_init_fn) return;

  deferred_fs_started = 1;

  /* Park the target's own interval timers while the forkserver parent is
     resident.  A target that arms alarm() for its session timeouts arms it
     during the startup that runs *before* this hook - proftpd's timer system
     (src/timers.c) does exactly that - so in the deferred model the timer
     belongs to the process that is about to become the forkserver parent.
     When it expires there, the signal is delivered while the parent is parked
     in the runtime's read()/waitpid(); proftpd installs its handler with
     siginterrupt(SIGALRM, 1), so the syscall comes back with EINTR and the
     AFL runtime treats that as "the fuzzer is gone" (write_error() +
     _exit(1)) - the forkserver disappears and afl-fuzz aborts with
     "Unable to communicate with fork server".  The parent is not a session,
     so block the signal for it and hand the remaining time to the children,
     which do run sessions and keep the original semantics.
     (The mask is what guarantees the parent's survival - it also covers a
     setitimer(ITIMER_REAL) user, which alarm(0) would not cancel.  The
     unmask + re-arm below runs only in the children: the parent never
     returns from deferred_init_fn().  Note the mask is per thread: this
     assumes the deferred start point is still single threaded, which is the
     usual requirement for a forkserver anyway - forking a threaded process
     leaves a child with only the calling thread.) */
  sigemptyset(&alarm_set);
  sigaddset(&alarm_set, SIGALRM);
  pthread_sigmask(SIG_BLOCK, &alarm_set, &saved_set);
  pending_alarm = alarm(0);

  /* deferred_init_fn was resolved (and required) in init_sockhook().  Arm the
     accept()-queue filter *before* entering the runtime: the per-run children
     are forked inside that call and inherit the mark, which is what makes
     accept_one() drop the connections a previous run left queued in the
     listener they share with the forkserver parent */
  caller_pid = getpid();
  deferred_fs_live = 1;
  deferred_init_fn();

  /* back in a child (or in a process without a forkserver): undo the parking */
  pthread_sigmask(SIG_SETMASK, &saved_set, NULL);
  if (pending_alarm) alarm(pending_alarm);

  /* the runtime returned in this very process: there is no forkserver (not
     started by afl-fuzz, or the handshake failed), so this process is the
     server itself and must keep plain accept() semantics */
  if (getpid() == caller_pid) deferred_fs_live = 0;

}

/* Port fd is bound to, or -1 when fd is not a bound IP socket.  The *bound*
   address is queried with getsockname() instead of remembering bind() calls:
   that works in every mode (fd_map is only maintained while the sock2shm
   redirection is engaged) and survives any fd juggling (dup/dup2/fork) the
   target performs.  sockaddr_storage keeps the (v4/v6) result unclipped; the
   port decode and the family check live in sockaddr_port(). */
static int sock_local_port(int fd) {
  struct sockaddr_storage ss;
  socklen_t               len = sizeof(ss);

  if (getsockname(fd, (struct sockaddr *)&ss, &len)) return -1;

  return sockaddr_port((struct sockaddr *)&ss, len);
}

/* 1 if fd is a listener bound to the AFLNet target port (__AFL_NETPORT).
   Returns 0 when no target port is configured (netport <= 0). */
static int is_netport_listener(int fd) {

  return global_session_mark_ptr->netport > 0 &&
         sock_local_port(fd) == global_session_mark_ptr->netport;

}

int listen(int sockfd, int backlog) {

  int matched;

  if (!original_listen) { original_listen = dlsym(RTLD_NEXT, "listen"); }
  if (!original_listen) {

    errno = ENOSYS;
    return -1;

  }

  int retval = original_listen(sockfd, backlog);

  /* before init_sockhook() there is no config to consult (and no deferred
     forkserver to start) - behave like the plain libc listen() */
  if (!sockhook_inited) { return retval; }

  /* TCP: the deferred forkserver fires at the first listen() *of the AFLNet
     target port*, so a listener on some other socket (management port, unix
     socket, ...) created earlier cannot move the forkserver start point -
     matching __AFL_NETPORT (the same value bind() matches against) is the
     only thing that makes a listener the target one, and without it (netport
     <= 0) no forkserver is started at all.  UDP has no listen(); it fires at
     bind() instead (see bind()).
     The port check costs a getsockname() and only matters while a deferred
     forkserver start is still pending, so it is skipped once it cannot fire
     anymore (in the inert configuration every listen() of every socket would
     otherwise pay it). */
  matched = is_netport_listener(sockfd);
  if (retval == 0 && matched && global_session_mark_ptr->deferred_fs_wanted) {
      /* remember the listener: its accept queue is shared with every child
         forked by the deferred forkserver below (see accept_one()) */
    deferred_listen_fd = sockfd;
    maybe_start_deferred_fs();

  }

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d listen:%d fdport=%d netport=%d match=%d ret=%d "
             "defer_started=%d\n",getpid(),sockfd,sock_local_port(sockfd),
             global_session_mark_ptr->netport,matched,retval,deferred_fs_started);
  #endif

  return retval;

}

ssize_t send(int sockfd, const void *buf, size_t len, int flags){
  int ret_val;

  if(!original_send)
    original_send=dlsym(RTLD_NEXT, "send");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_send(sockfd,buf,len,flags);

  if(global_session_mark_ptr->enable_shm && check_fd(sockfd,SESSION_FD)){
    /* enable_shm: the bytes are buffered and flushed through data2 later */
    ret_val=shm_write_buf(buf,len);
  }
  else{
    /* sync-only (or an unrelated fd): real write, then hand the turn over */
    ret_val=original_send(sockfd,buf,len,flags);
    if(global_session_mark_ptr->enable_shmsync && check_fd(sockfd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen){
  int ret_val;

  if(!original_sendto)
    original_sendto=dlsym(RTLD_NEXT, "sendto");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_sendto(sockfd,buf,len,flags,dest_addr,addrlen);

  if(global_session_mark_ptr->enable_shm && check_fd(sockfd,SESSION_FD)){
    ret_val=shm_write_buf(buf,len);
  }
  else{
    ret_val=original_sendto(sockfd,buf,len,flags,dest_addr,addrlen);
    if(global_session_mark_ptr->enable_shmsync && check_fd(sockfd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags){
  int i,ret_val;

  if(!original_sendmsg)
    original_sendmsg=dlsym(RTLD_NEXT, "sendmsg");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_sendmsg(sockfd,msg,flags);

  if(global_session_mark_ptr->enable_shm && check_fd(sockfd,SESSION_FD)){
    for(i=0,ret_val=0;i<msg->msg_iovlen;i++){
      ret_val+=shm_write_buf(msg->msg_iov[i].iov_base,msg->msg_iov[i].iov_len);
    }
  }
  else{
    ret_val=original_sendmsg(sockfd,msg,flags);
    if(global_session_mark_ptr->enable_shmsync && check_fd(sockfd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags){
  int ret_val=0;
  int nonblock;

  if(!original_recv)
    original_recv=dlsym(RTLD_NEXT, "recv");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_recv(sockfd,buf,len,flags);

  /* A zero-length read returns 0 immediately.  It must not touch the SHM
     turn: shm_read() cannot make progress with size 0, so the
     while(!shm_read()) loop below would spin forever. */
  if(len==0 && check_fd(sockfd,SESSION_FD))
    return 0;

  nonblock = (flags & MSG_DONTWAIT) || fd_is_nonblocking(sockfd);

  if(global_session_mark_ptr->enable_shm && check_fd(sockfd,SESSION_FD)){
    /* enable_shm: flush the pending response, then read the request from data1 */
    if(nonblock){
      shm_write_nonblock();
      ret_val=shm_read(sockfd,buf,len,0,1);
    }
    else{
      shm_write(1);
      while(!(ret_val=shm_read(sockfd,buf,len,0,0)));
    }
  }
  else{
    /* sync-only (or an unrelated fd): wait for the fuzzer's turn, then the
       real receive (0 = parked in the kernel wait, -1 = nothing more for this
       message - the turn is handed back in that case) */
    if(global_session_mark_ptr->enable_shmsync && check_fd(sockfd,SESSION_FD))
      ret_val=recv_state_trans(sockfd,nonblock);
    if(ret_val>=0)
      ret_val=original_recv(sockfd,buf,len,flags);
  }

  return ret_val;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
  int ret_val=0;
  int nonblock;

  if(!original_recvfrom)
    original_recvfrom=dlsym(RTLD_NEXT, "recvfrom");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_recvfrom(sockfd,buf,len,flags,src_addr,addrlen);

  if(len==0 && check_fd(sockfd,SESSION_FD))
    return 0;

  nonblock = (flags & MSG_DONTWAIT) || fd_is_nonblocking(sockfd);

  if(global_session_mark_ptr->enable_shm && check_fd(sockfd,SESSION_FD)){
    if(nonblock){
      shm_write_nonblock();
      ret_val=shm_read(sockfd,buf,len,0,1);
    }
    else{
      shm_write(1);
      while(!(ret_val=shm_read(sockfd,buf,len,0,0)));
    }
    /* recvfrom(..., NULL, NULL) is legal on a connected/redirected socket;
       only fill the fake source address when the caller asked for it. */
    if(ret_val>0){
      if(addrlen)
        *addrlen=sizeof(struct sockaddr_in);
      if(src_addr){
        ((struct sockaddr_in*)src_addr)->sin_family=AF_INET;
        ((struct sockaddr_in*)src_addr)->sin_port=0x8383;
        ((struct sockaddr_in*)src_addr)->sin_addr.s_addr=0x100007f;
      }
    }
  }
  else{
    if(global_session_mark_ptr->enable_shmsync && check_fd(sockfd,SESSION_FD))
      ret_val=recv_state_trans(sockfd,nonblock);
    if(ret_val>=0)
      ret_val=original_recvfrom(sockfd,buf,len,flags,src_addr,addrlen);
  }

  return ret_val;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags){
  int i,tmp,ret_val=0;
  size_t total=0;
  int nonblock;

  if(!original_recvmsg)
      original_recvmsg=dlsym(RTLD_NEXT,"recvmsg");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_recvmsg(sockfd,msg,flags);

  /* all-zero iovecs are a zero-length read: return 0 without waiting for a
     turn (the per-iovec shm_read loop below cannot make progress on 0) */
  if(check_fd(sockfd,SESSION_FD)){
    for(i=0;i<msg->msg_iovlen;i++)
      total+=msg->msg_iov[i].iov_len;
    if(total==0)
      return 0;
  }

  nonblock = (flags & MSG_DONTWAIT) || fd_is_nonblocking(sockfd);

  if(global_session_mark_ptr->enable_shm && check_fd(sockfd,SESSION_FD)){
    if(nonblock){
      shm_write_nonblock();
    }
    else{
      shm_write(1);
    }
    for(i=0,ret_val=0;i<msg->msg_iovlen;i++){
      if(msg->msg_iov[i].iov_len==0)
        continue;
      if(nonblock){
        tmp=shm_read(sockfd,msg->msg_iov[i].iov_base,
                     msg->msg_iov[i].iov_len,0,1);
        if(tmp<0)
          return ret_val>0?ret_val:-1;
        ret_val+=tmp;
        continue;
      }
      do{
        tmp=shm_read(sockfd,msg->msg_iov[i].iov_base,
                     msg->msg_iov[i].iov_len,0,0);
        if(tmp<0)
          return -1;
      }while(tmp==0);
      ret_val+=tmp;
    }
  }
  else{
    if(global_session_mark_ptr->enable_shmsync && check_fd(sockfd,SESSION_FD))
      ret_val=recv_state_trans(sockfd,nonblock);
    if(ret_val>=0)
      ret_val=original_recvmsg(sockfd,msg,flags);
  }

  return ret_val;
}

ssize_t read(int fd, void * buf, size_t count) {
  int ret_val=0;
  int nonblock;

  if(!original_read)
      original_read=dlsym(RTLD_NEXT, "read");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_read(fd,buf,count);

  if(count==0 && check_fd(fd,SESSION_FD))
    return 0;

  nonblock=fd_is_nonblocking(fd);

  if(global_session_mark_ptr->enable_shm && check_fd(fd,SESSION_FD)){
    if(nonblock){
      shm_write_nonblock();
      ret_val=shm_read(fd,buf,count,0,1);
    }
    else{
      shm_write(1);
      while(!(ret_val=shm_read(fd,buf,count,0,0)));
    }
  }
  else{
    if(global_session_mark_ptr->enable_shmsync && check_fd(fd,SESSION_FD))
      ret_val=recv_state_trans(fd,nonblock);
    if(ret_val>=0)
      ret_val=original_read(fd,buf,count);
  }

  return ret_val;
}

ssize_t write(int fd, const void * buf, size_t count) {
  int ret_val;

  if(!original_write)
    original_write=dlsym(RTLD_NEXT, "write");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_write(fd,buf,count);

  if(global_session_mark_ptr->enable_shm && check_fd(fd,SESSION_FD)){
    ret_val=shm_write_buf(buf,count);
  }
  else{
    ret_val=original_write(fd,buf,count);
    if(global_session_mark_ptr->enable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt){
  int i,tmp,ret_val=0;
  size_t total=0;
  int nonblock;

  if(!original_readv)
      original_readv=dlsym(RTLD_NEXT,"readv");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_readv(fd,iov,iovcnt);

  if(check_fd(fd,SESSION_FD)){
    for(i=0;i<iovcnt;i++)
      total+=iov[i].iov_len;
    if(total==0)
      return 0;
  }

  nonblock=fd_is_nonblocking(fd);

  if(global_session_mark_ptr->enable_shm && check_fd(fd,SESSION_FD)){
    if(nonblock){
      shm_write_nonblock();
    }
    else{
      shm_write(1);
    }
    for(i=0,ret_val=0;i<iovcnt;i++){
      if(iov[i].iov_len==0)
        continue;
      if(nonblock){
        tmp=shm_read(fd,iov[i].iov_base,iov[i].iov_len,0,1);
        if(tmp<0)
          return ret_val>0?ret_val:-1;
        ret_val+=tmp;
        continue;
      }
      do{
        tmp=shm_read(fd,iov[i].iov_base,iov[i].iov_len,0,0);
        if(tmp<0)
          return -1;
      }while(tmp==0);
      ret_val+=tmp;
    }
  }
  else{
    if(global_session_mark_ptr->enable_shmsync && check_fd(fd,SESSION_FD))
      ret_val=recv_state_trans(fd,nonblock);
    if(ret_val>=0)
      ret_val=original_readv(fd,iov,iovcnt);
  }

  return ret_val;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt){
  int i,ret_val;

  if(!original_writev)
    original_writev=dlsym(RTLD_NEXT, "writev");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_writev(fd,iov,iovcnt);

  if(global_session_mark_ptr->enable_shm && check_fd(fd,SESSION_FD)){
    for(i=0,ret_val=0;i<iovcnt;i++){
      ret_val+=shm_write_buf(iov[i].iov_base,iov[i].iov_len);
    }
  }
  else{
    ret_val=original_writev(fd,iov,iovcnt);
    if(global_session_mark_ptr->enable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

int fprintf(FILE *restrict stream, const char *restrict format, ...) {
  va_list ap,ap2;
  int fd = fileno(stream),ret_val;
  char *buf;

  /* before init_sockhook() there is no session config to consult: behave
     exactly like libc's fprintf */
  if(!sockhook_inited){
    va_start(ap, format);
    ret_val=vfprintf(stream, format, ap);
    va_end(ap);
    return ret_val;
  }

  if(global_session_mark_ptr->enable_shm && check_fd(fd,SESSION_FD)){
    va_start(ap, format);
    va_copy(ap2, ap);
    ret_val = vsnprintf(NULL, 0, format, ap);
    buf=(char*)ck_alloc(ret_val+1);
    if(!buf)
      return -1;
    vsprintf(buf, format, ap2);
    va_end(ap);
    va_end(ap2);
    ret_val=shm_write_buf(buf, ret_val);
    ck_free(buf);
  }
  else{
    va_start(ap, format);
    ret_val=vfprintf(stream, format, ap);
    va_end(ap);
    if(global_session_mark_ptr->enable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

char* fgets(char *restrict s, int n, FILE *restrict stream){
  int fd = fileno(stream),ret_val=0;
  int nonblock;

  if(!original_fgets)
      original_fgets=dlsym(RTLD_NEXT, "fgets");

  if(!sockhook_inited)
    return original_fgets(s,n,stream);

  /* n <= 1 stores no bytes (glibc: n == 1 yields an empty string); let libc
     handle it instead of entering the SHM turn with a zero-length read */
  if(n<=1 && check_fd(fd,SESSION_FD))
    return original_fgets(s,n,stream);

  nonblock=fd_is_nonblocking(fd);

  if(global_session_mark_ptr->enable_shm && check_fd(fd,SESSION_FD)){
    if(nonblock){
      shm_write_nonblock();
      ret_val=shm_read(fd,s,n-1,1,1);
    }
    else{
      shm_write(1);
      while(!(ret_val=shm_read(fd,s,n-1,1,0)));
    }
    if(ret_val<0)
      return NULL;
    *(s+ret_val)='\0';
    return s;
  }
  else{
    if(global_session_mark_ptr->enable_shmsync && check_fd(fd,SESSION_FD))
      ret_val=recv_state_trans(fd,nonblock);
    if(ret_val>=0)
      return original_fgets(s,n,stream);
    else
      return NULL;
  }
}

int fputs(const char *restrict s, FILE *restrict stream){
  int fd = fileno(stream),ret_val;

  if(!original_fputs)
    original_fputs=dlsym(RTLD_NEXT, "fputs");

  if(!sockhook_inited)
    return original_fputs(s,stream);

  if(global_session_mark_ptr->enable_shm && check_fd(fd,SESSION_FD)){
    shm_write_buf(s,strlen(s));
    ret_val=0;
  }
  else{
    ret_val=original_fputs(s,stream);
    if(global_session_mark_ptr->enable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

int fputc(int c, FILE *stream){
  int fd = fileno(stream),ret_val;
  unsigned char ch=c;

  if(!original_fputc)
    original_fputc=dlsym(RTLD_NEXT, "fputc");

  if(!sockhook_inited)
    return original_fputc(c,stream);

  if(global_session_mark_ptr->enable_shm && check_fd(fd,SESSION_FD)){
    shm_write_buf(&ch,1);
    ret_val=c;
  }
  else{
    ret_val=original_fputc(c,stream);
    if(global_session_mark_ptr->enable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

size_t fread(void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream){
  int fd = fileno(stream),ret_val=0;
  int nonblock;

  if(!original_fread)
    original_fread=dlsym(RTLD_NEXT, "fread");

  if(!sockhook_inited)
    return original_fread(ptr,size,nmemb,stream);

  if((size==0 || nmemb==0) && check_fd(fd,SESSION_FD))
    return 0;

  nonblock=fd_is_nonblocking(fd);

  if(global_session_mark_ptr->enable_shm && check_fd(fd,SESSION_FD)){
    if(nonblock){
      shm_write_nonblock();
      ret_val=shm_read(fd,ptr,size*nmemb,0,1);
    }
    else{
      shm_write(1);
      while(!(ret_val=shm_read(fd,ptr,size*nmemb,0,0)));
    }
    if(ret_val<0)
      return 0;
  }
  else{
    if(global_session_mark_ptr->enable_shmsync && check_fd(fd,SESSION_FD))
      ret_val=recv_state_trans(fd,nonblock);
    if(ret_val<0)
      return 0;
    ret_val=original_fread(ptr,size,nmemb,stream);
  }

  return ret_val;
}

size_t fwrite(const void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream){
  int fd = fileno(stream),ret_val;

  if(!original_fwrite)
    original_fwrite=dlsym(RTLD_NEXT, "fwrite");

  if(!sockhook_inited)
    return original_fwrite(ptr,size,nmemb,stream);

  if(global_session_mark_ptr->enable_shm && check_fd(fd,SESSION_FD)){
    ret_val=shm_write_buf(ptr,size*nmemb);
  }
  else{
    ret_val=original_fwrite(ptr,size,nmemb,stream);
    if(global_session_mark_ptr->enable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

/* 1 when AFL's forkserver has already been started *in this process*.  The
   runtime flips __afl_connected right after the handshake and before it forks
   the per-test children, so a child inherits 1 - and AFL's own close() of the
   forkserver fds in that child is deliberately left alone.  It is 0 while the
   target is still running its own initialisation (i.e. before the deferred
   start point), and 0 when the target carries no AFL runtime at all. */
static int afl_forkserver_started(void) {

  static u32 *connected = NULL;
  static int  resolved = 0;

  if (!resolved) {

    resolved = 1;
    connected = (u32 *)dlsym(RTLD_DEFAULT, "__afl_connected");

  }

  return connected && *connected;

}

/* 1 when this close()/closefrom() call must leave fd alone: it is one of the
   deferred forkserver's pipes and the handshake still has to happen in this
   process.  Targets that sanitise their descriptors before reaching their
   deferred start point - OpenSSH's sshd calls closefrom(3) early in main()
   and only calls __AFL_INIT() after config parsing and host key loading -
   would otherwise take the handshake pipes with them, and afl-fuzz would
   report the misleading "Fork server crashed with signal 9" (its own cleanup
   SIGKILL) instead of the target ever coming up.

   In the native configuration nothing is protected: the handshake happened
   before main() and the forkserver parent owns its own copies, so the target
   closing its copies is harmless.  After the handshake the protection is off
   again for the same reason - and so that AFL's deliberate close() in the
   forked children (afl-compiler-rt.o.c) is not turned into an fd leak. */
static int forkserver_fd_protected(int fd) {

  if (fd != FORKSRV_FD && fd != FORKSRV_FD + 1) return 0;
  if (!sockhook_inited || !global_session_mark_ptr ||
      !global_session_mark_ptr->deferred_fs_wanted)
    return 0;

  return !afl_forkserver_started();

}

int close(int fd) {
  int ret_val;

  if(!original_close)
    original_close=dlsym(RTLD_NEXT, "close");

  /* deferred forkserver: a target that closes its descriptors one by one
     (rather than through closefrom()) must not lose the handshake pipes
     either - this has to come before the inert-configuration fast path
     below, the two fds matter exactly there */
  if(forkserver_fd_protected(fd))
    return 0;

  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_close(fd);

  #ifdef DEBUG_MODE
    int is_log_closed=0;
    if(__log_fd && fd==fileno(__log_fd)){
      DO_LOG("%d log closed\n",getpid());
      is_log_closed=1;
    }
    if(__log_fd)
      DO_LOG("%d close %d %d\n",getpid(),fd,check_fd(fd,SESSION_FD));
  #endif

  check_before_close(1,fd);
  ret_val=original_close(fd);

  #ifdef DEBUG_MODE
    if(is_log_closed){
      __log_fd=fopen(LOG_FILE_NAME,"a+");
      DO_LOG("%d log reopened successfully %d\n",getpid(),errno);
    }
  #endif

  return ret_val;
}

/* Close every descriptor >= lowfd, like libc's closefrom() - except for the
   deferred forkserver's pipes, which are kept until the handshake happened
   (see forkserver_fd_protected()).

   Targets that sanitise their descriptors (OpenSSH's sshd calls
   closefrom(3) early in main()) rely on this call to drop everything they
   inherited.  Since glibc 2.34 that call is libc's own implementation, which
   knows nothing about this preload, so a target whose deferred init point
   (__AFL_INIT()) sits *after* the sanitising call loses the handshake pipes.
   The profuzzbench OpenSSH fork places __AFL_INIT() after config parsing and
   host key loading on purpose (so every per-test child skips them) and does
   protect the two descriptors in its own openbsd-compat/bsd-closefrom.c - but
   that file is compiled out as soon as libc provides closefrom(), which is
   why the protection has to come from here.  See "Targets that close all file
   descriptors" in the README.

   This intercepts the closefrom() *call*; the close() calls libc makes
   internally are not interposable (which is why the plain close() hook alone
   cannot protect the pipes), and a target calling close_range() directly
   bypasses both - not the path the known targets take.

   Unlike the other hooks this one keeps working in a process the library
   decided is not a target (init_sockhook() leaves sockhook_inited 0 there):
   glibc before 2.34 has no closefrom() at all, so this symbol is then the only
   implementation the target's neighbours can reach, and for a non-target the
   loop below is exactly libc's semantics - every descriptor >= lowfd, no
   protection (forkserver_fd_protected() is off there as well). */
void closefrom(int lowfd) {

  int            dfd = -1;
  long           fd, maxfd;
  DIR           *dirp;
  struct dirent *dent;
  struct rlimit  rl;

  /* never recurse into our own close() hook (and its fd_map bookkeeping) */
  if (!original_close) original_close = dlsym(RTLD_NEXT, "close");
  if (!original_close) return;

  dirp = opendir("/proc/self/fd");
  if (dirp) {

    dfd = dirfd(dirp);
    while ((dent = readdir(dirp)) != NULL) {

      char *endp;

      fd = strtol(dent->d_name, &endp, 10);
      if (endp == dent->d_name || *endp != '\0' || fd < lowfd) continue;
      if (fd == dfd) continue;                  /* the directory handle itself */
      if (forkserver_fd_protected((int)fd)) continue;

      #ifdef DEBUG_MODE
        if (__log_fd && (int)fd == fileno(__log_fd)) __log_fd = NULL;
      #endif
      original_close((int)fd);

    }

    closedir(dirp);
    return;

  }

  /* no /proc (or it could not be read): fall back to the descriptor limit */
  maxfd = 1024;
  if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
    maxfd = (long)rl.rlim_cur;

  if (lowfd < 0) lowfd = 0;

  for (fd = lowfd; fd < maxfd; fd++) {

    if (forkserver_fd_protected((int)fd)) continue;

    #ifdef DEBUG_MODE
      if (__log_fd && (int)fd == fileno(__log_fd)) __log_fd = NULL;
    #endif
    original_close((int)fd);

  }

}

int fclose(FILE * stream) {
  int fd,ret_val;

  if(!original_fclose)
    original_fclose=dlsym(RTLD_NEXT, "fclose");
  if(!sockhook_inited ||
     (!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync))
    return original_fclose(stream);

  fd=fileno(stream);

  #ifdef DEBUG_MODE
    int is_log_closed=0;
    if(__log_fd && fd==fileno(__log_fd)){
      DO_LOG("%d log fclosed\n",getpid());
      is_log_closed=1;
    }
    if(__log_fd)
      DO_LOG("%d %d fclose %d\n",getpid(),gettidv(),fd);
  #endif

  check_before_close(1,fd);
  ret_val=original_fclose(stream);

  #ifdef DEBUG_MODE
    if(is_log_closed){
      __log_fd=fopen(LOG_FILE_NAME,"a+");
      DO_LOG("%d log reopened successfully\n",getpid());
    }
  #endif

  return ret_val;
}

static void detach_shm(){
  /*if(__sync_bool_compare_and_swap(&session_shm_sig->force_socket_path,0,0)){
    shmctl(shm_send_buf_size_id, IPC_RMID, NULL);
  }*/

  /* detach only what the respective plane actually attached: the msg segment
     + send-buffer counters belong to the redirection, the check segment to
     the rendezvous (implied by the redirection) */
  if(global_session_mark_ptr->enable_shm){
    shmdt(session_msg);
    shmdt(send_buf_size);
  }

  if(global_session_mark_ptr->enable_shmsync && session_shm_sig)
    shmdt(session_shm_sig);
}

__attribute__((destructor)) void fini_sock2shm(){
  if(!sockhook_inited)
    return;   /* init_sockhook() never published the config: nothing was attached */

  if(!global_session_mark_ptr->enable_shm && !global_session_mark_ptr->enable_shmsync)
    return;   /* inert: never attached/allocated anything */

  /* Close the session first: check_before_close() may flush a pending
     response through shm_write(), which reads send_buf/send_buf_size.  The
     buffer must still be mapped at that point (a target that returns from
     main() with an unflushed response used to hit a use-after-munmap here). */
  if(fd_map){
    if(session_fd>=0 || (session_fd=next_dup_fd(SESSION_FD))>=0){
      memset(fd_map,0,max_fd*sizeof(int));
      fd_map[session_fd]=SESSION_FD;
      check_before_close(1,session_fd);
    }
    ck_free(fd_map);
    fd_map=NULL;
  }

  if(global_session_mark_ptr->enable_shm){   /* sync-only never mapped it */
    munmap(send_buf,max_send_buf_size);
    close(shared_fd_for_fork);
  }

  #ifdef DEBUG_MODE
    if(__log_fd){
      DO_LOG("%d fini invoked %d\n",getpid(),session_shm_sig->proc_ref_cnt);
      if(!original_fclose)
        original_fclose=dlsym(RTLD_NEXT,"fclose");
      original_fclose(__log_fd);
    }
  #endif

  if(!is_child)
    detach_shm();
}
