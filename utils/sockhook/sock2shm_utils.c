#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include "sock2shm_utils.h"

static u64 get_cur_time(void) {

  struct timeval tv;
  gettimeofday(&tv, NULL);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* Wait until *state != val (or the timeout expires).  The token is a shared
   atomic_int in the SysV check segment, so a futex wait is used instead of a
   busy loop: between two messages the target may park here for a while and
   must not burn a CPU core.  Returns 1 when the value is still val after the
   wait, 0 when it changed. */
int shm_wait(atomic_int *state,int val,int timeout){
  u64 deadline = 0;

  if(atomic_load(state) != val)
    return 0;

  if(timeout > 0)
    deadline = get_cur_time() + (u64)timeout;

  for(;;){
    struct timespec ts;
    struct timespec *tsp = NULL;

    if(atomic_load(state) != val)
      return 0;

    if(timeout > 0){
      u64 now = get_cur_time();
      u64 remain;

      if(now >= deadline)
        break;

      remain = deadline - now;
      ts.tv_sec = (time_t)(remain / 1000);
      ts.tv_nsec = (long)((remain % 1000) * 1000000ULL);
      tsp = &ts;
    }

    if(futex_wait((int *)state, val, tsp) == -1){
      if(errno == EAGAIN || errno == EINTR)
        continue;
      if(errno == ETIMEDOUT)
        break;
      /* unexpected futex error: do not fall back to a tight spin */
      usleep(1000);
    }
  }

  return atomic_load(state) == val;
}

void shm_notify(atomic_int* state,int val) {
	atomic_store(state,val);
	/* wake every process parked on this token (shared SysV mapping) */
	futex_wake((int *)state, INT_MAX);
}

void lock(fsemaphore* who)
{
  //int val;
  if(!who)
    return;
  do {
   //val = who->avail;
   if(__sync_bool_compare_and_swap(&who->avail, 1, 0) )
      return;
    __sync_fetch_and_add(&who->waiters, 1);
    futex_wait(&who->avail,0,NULL);
    __sync_fetch_and_sub(&who->waiters, 1);
  } while(1);
}

void unlock(fsemaphore* who)
{
  //int nval;
  if(!who)
    return;
  __sync_bool_compare_and_swap(&who->avail, 0, 1);
  if( who->waiters > 0 )
  {
    futex_wake(&who->avail,1);
  }
}

void thread_block_signal(sigset_t *oldset){
  sigset_t set;
  sigfillset(&set);
  pthread_sigmask(SIG_SETMASK, &set, oldset);
}

void thread_unblock_signal(sigset_t *sigset){
  pthread_sigmask(SIG_SETMASK, sigset, NULL);
}
