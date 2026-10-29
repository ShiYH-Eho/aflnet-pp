# sockhook.so (sock2shm)

LD_PRELOAD library that replaces the server's per-connection network I/O with
a shared-memory (System V SHM + futex) message exchange.  Ported from
[HNPFuzzer](https://github.com/HNPFuzzer/HNPFuzzer).

## Build

    make            # -> sockhook.so (also copied to the repo root)

The fuzzer preloads `sockhook.so` into the target for the *server* socket
modes (1 = default real-socket AFLNet, 2 = sock2shm), see
`src/aflnet/config.c` / `src/aflnet/utils/sock2shm.c`.  The library is inert by
default and only engages the SHM redirection when the environment says so.

## Environment (consumed by the preloaded library)

| variable               | meaning                                          |
|------------------------|--------------------------------------------------|
| `__AFL_SOCK_MODE`      | interaction mode (the fuzzer forwards it, after reading the user-facing `AFLNET_SOCK_MODE`): **2** = engage the sock2shm SHM redirection; anything else (0/1/unset) = no redirection (a plain real-socket server, optionally with the rendezvous of `__AFL_SHMSYNC`) |
| `__AFL_SHMSYNC`        | **1** = arm the standalone rendezvous *without* the SHM redirection: the messages keep travelling over the real socket, but the target publishes its readiness (`accept()`, or `bind()` for datagram sockets) and waits for the fuzzer at `recv()` (see below).  Takes precedence over the legacy "`__AFL_SHM_*` ids only" rule |
| `__AFL_SHM_MSG_ID`     | System V id of the msg segment (fuzzer sets it)  |
| `__AFL_SHM_CHECK_ID`   | System V id of the check segment (fuzzer sets it)|
| `__AFL_NETPORT`        | target port, raw value (fuzzer sets it)         |
| `__AFL_PROTOCOL_TYPE`  | `TCP` or `UDP` (SOCK_STREAM / SOCK_DGRAM)        |
| `__AFL_SOCKHOOK_ACTIVE`| internal: set by the target itself and inherited by everything it forks or execs, so its descendants stay active even after they lost the forkserver descriptors (see "Which processes the library acts in") |
| `AFLNET_SOCKHOOK_FORCE_ACTIVE` | user-facing escape hatch: **1** = initialise even in a process that looks like a helper (no forkserver descriptors), for setups the detection cannot see |

## Enabling / configuration

The preloaded library configures itself from the environment at load time
(`enable_shm` and `enable_shmsync` in the local `session_mark` are set
independently):

  - `__AFL_SOCK_MODE` is exported by the fuzzer from the user-facing
    `AFLNET_SOCK_MODE` config and is authoritative when present:
    **2** = the SHM redirection is **engaged** (`enable_shm = 1`,
    `enable_shmsync = 1`), **0/1** = no redirection.
  - `__AFL_SHMSYNC=1` (set by the fuzzer for `AFLNET_SHM_SYNC=1` with
    `AFLNET_SOCK_MODE=1`) engages **only the rendezvous**
    (`enable_shm = 0`, `enable_shmsync = 1`), so the same library can be used
    as a plain real-socket server *with* a synchronised session.
  - the two flags are independent, but `enable_shm = 1` always implies
    `enable_shmsync = 1` (the redirection needs the rendezvous).
  - the target socket is identified *only* by `__AFL_NETPORT`: `bind()`,
    `listen()` and `accept()` arm/arm-start the session for the socket bound
    to that port and for nothing else.  There is no "first bind / first
    listen / every accept" fallback for a missing port any more - without
    `__AFL_NETPORT` the target port is unknown, so a standalone/manual preload
    stays an inert pass-through even when the segment ids are exported (a
    manual run that wants the redirection has to export `__AFL_NETPORT` too).
    An explicit `__AFL_SHMSYNC=1` request is never upgraded to the full
    redirection this way: the run stays at the rendezvous-only level and keeps
    using the real socket.
  - when both are off, no shared memory is attached and every hooked call
    (send/recv/read/write/poll/select/epoll/accept/bind) falls back to the
    real network path, so the target runs as a plain server.

### Which processes the library acts in

afl-fuzz exports its environment to everything it starts, so the cleanup
script (`AFLNET_CLEANUP_SCRIPT`, run through `system()`) and any other helper
would load the preloaded library as well.  The library tells them apart in its
constructor, the only moment at which the difference is visible:

  - afl-fuzz `dup2()`s its forkserver descriptors (198/199) into the process it
    execs as the target - and only into that one;
  - the runtime closes them again inside the per-run children
    (`afl-compiler-rt.o.c`), and `__afl_connected` is still 0 while the library
    loads, so neither can be used for this later on.

A process started by afl-fuzz (`__AFL_OUT_DIR`) that does not have those
descriptors is not a target: `init_sockhook()` leaves `sockhook_inited` at 0.
Every hook - the loader has already resolved them, they cannot be uninstalled -
then takes its pass-through path straight back to libc, and nothing is parsed,
attached or started.  `closefrom()` is the one exception: it keeps working,
because glibc before 2.34 has no such symbol at all (this may be the only
implementation the process can reach), and for a non-target its loop is exactly
libc's semantics.

The decision is remembered for the target's own descendants
(`__AFL_SOCKHOOK_ACTIVE`), so a target that `exec()`s a helper keeps the library
active there; standalone/manual preloads (no `__AFL_OUT_DIR`) keep their
documented behaviour.  `AFLNET_SOCKHOOK_FORCE_ACTIVE=1` forces initialisation
in a process that looks like a helper, for setups the detection cannot see (for
instance `AFL_NO_FORKSRV=1`).  `test/test-sockhook-inert.sh` is the regression
test: a helper must be able to bind the target port *without* the library's
`SO_REUSEPORT`.

### Inert fast path

With `enable_shm == enable_shmsync == 0` (the local `global_session_mark`
fields, as set by `init_sockhook()`) each of the 22 interposed entry points
starts with

    if(!global_session_mark_ptr->enable_shm &&
       !global_session_mark_ptr->enable_shmsync)
      return original_xxx(...);

so the target's `poll()`/`select()`/`epoll_wait()` never walk their fd lists
looking for session sockets, `fork()`/`dup()`/`close()` never touch the
session reference counters, `execve()` never scans the fd map and the port
check behind `listen()` (a `getsockname()` syscall) is skipped as well - it
only runs while a deferred forkserver start is still pending, in every mode.
The deferred switch itself is read once into
`global_session_mark.deferred_fs_wanted` (`__AFL_DEFER_FORKSRV` is fixed for
the process lifetime), so `bind()`/`listen()` do not `getenv()` per call.
The only thing that stays enabled in the inert configuration is what is not
just bookkeeping:

  - `bind()` still sets `SO_REUSEPORT` on `__AFL_NETPORT`, so a target that
does not set `SO_REUSEADDR` itself can re-bind the port on every run (the
non-deferred forkserver model forks a fresh child per run);
  - `listen()`/`bind()` still start AFL++'s **deferred** forkserver
(`__afl_manual_init()`), which is what `AFLNET_DEFER_FORKSRV=1` relies on.
  - `accept()`/`accept4()` still drop the connections a previous run left in
the listener the deferred forkserver's children inherit (see "The inherited
accept queue" below).  Only the deferred configuration pays the `TCP_INFO`
check for that: without a deferred forkserver the two hooks are exactly libc.
  - `closefrom()` and `close()` are interposed as well: a target that closes
every descriptor above its own - through `closefrom()` (OpenSSH's sshd calls
`closefrom(3)` early in `main()`) or one by one - would otherwise take the
deferred forkserver's pipes down with it before its `__AFL_INIT()` (see
"Targets that close all file descriptors" below).  The two hooks keep
`FORKSRV_FD`/`FORKSRV_FD + 1` only until the handshake happened, and only in
the deferred configuration; everywhere else they are exactly libc.

Measured on a trivial target (ns/call, `LD_PRELOAD` vs. no preload vs. the
same build forced onto the old always-run path):

| call | native | inert (fast path) | inert, forced engaged |
|----------------------|--------|-------------------|-----------------------|
| `poll(64 fds, 0)` | 882 | 926 | 1013 |
| `select(4 nfds)` | 283 | 292 | 353 |
| `read(/dev/null)` | 145 | 148 | 186 |
| `fork()` | 68790 | 91225 | 109408 |

This makes the preload uniform: the same `sockhook.so` is loaded for
`sock_mode=1` and `sock_mode=2`, and the target behaves as a plain server
(mode 1), a plain server with a synchronised session
(`AFLNET_SOCK_MODE=1` + `AFLNET_SHM_SYNC=1`), or a SHM-exchanging server
(mode 2) depending only on the exported env vars.

## Standalone rendezvous (`__AFL_SHMSYNC`, no SHM redirection)

With `enable_shmsync` alone only the **check** segment is attached: the turn
token (`state`), `is_end`, `connection_state`, the `mx` futex and the session
refcount all live there.  The msg/data plane and the shared send buffer belong
to the redirection and stay unmapped.  The hooks therefore become
notifications instead of redirections:

| hook                | behaviour with `enable_shm = 0, enable_shmsync = 1` |
|---------------------|-----------------------------------------------------|
| `bind()`            | match the listener against `__AFL_NETPORT` and initialise the session (as in mode 2).  For a datagram socket this is also the readiness point: `connection_state = RUNNING` is published right after a successful bind, because there is no `accept()` to publish from |
| `accept()`          | publish `connection_state = RUNNING` **before** the real accept, i.e. "the server is listening, dial me" - the fuzzer waits for this instead of racing the listener.  No `suspend()`/`SIGSTOP` parking and no fake readiness: `poll()`/`select()`/`epoll_wait()` use the real socket |
| first `recv()`      | the session starts on the server's turn (`state = SERVER`); at the start of a message, with no request in flight, the target publishes `CLIENT` ("I am in recv, the fuzzer may send") and parks on the token until a send has handed `SERVER` back |
| `send*()`           | perform the real write; ownership stays with the server (it yields only when it enters `recv`), so a banner/response does not hand the turn over by itself |
| `recv*()`           | while a message is being read, `SERVER` keeps probing the real socket: readable -> real receive, dry -> `EAGAIN` (message boundary); at the start of the next message it publishes `CLIENT` and parks again.  The fuzzer waits for that `CLIENT` before it sends and hands `SERVER` back. |
| `is_end = 1`        | release the parked `recv()` and end the session, so the fuzzer does not have to wait for the TCP close (session teardown instead of a run timeout) |
| `_exit()`/`exit()`  | session teardown, including the explicit end notification (`is_end = 6`, `connection_state = ENDING`) so the fuzzer learns about the end of the session from SHM as well |

In this configuration the library performs **no SHM message I/O at all**: the
shared send buffer is never mapped (`setup_shm()` opens `REGION_FOR_FORK`
only for `enable_shm`), the send-buffer counters are left alone by
`session_init()` and the close path does not call `shm_write()`.  Only the
rendezvous fields are touched - the check segment's `state`, `is_end`,
`connection_state` and `proc_ref_cnt` (the msg segment itself is never
mapped).

The turn-taking waits are bounded by `SESSION_STALL_TIMEOUT` (30 s): the two
sides normally hand the token over within milliseconds, so the cap never
fires in a healthy run, but a token that neither moves nor gets an `is_end`
(e.g. the fuzzer vanished) ends the session instead of wedging the target.
At the start of a message the target parks on the token, so `is_end` /
`ENDING` can release it directly; after a `SERVER` hand-over the request bytes
may still be in flight, so they are awaited in short poll slices (which keep
the end notification reachable) instead of a blocking kernel `recv()`.

### Which hook does what in each configuration

The three configurations do not share one code path per hook: each of them is
split at the point where the work stops being shared.

| hook | inert (both off) | rendezvous only (`enable_shmsync`) | redirection (`enable_shm`) |
|------|------------------|------------------------------------|----------------------------|
| `send*`/`write*`/stdio write | pass-through | real write; ownership stays with `SERVER` (no token change) | `shm_write_buf()` into the shared send buffer |
| `recv*`/`read*`/stdio read | pass-through | `recv_state_trans()`: at message start publish `CLIENT` and park; after `SERVER`, probe the real socket and receive | `shm_write(1)` flush + `shm_read()` from `data1` |
| `poll`/`select`/`epoll_ctl`/`epoll_wait` | pass-through | pass-through - the target owns the real socket | fake readiness for the session fd, `MAX_LOOP` re-probe, ENDING -> `suspend()` |
| `bind`/`listen` | `SO_REUSEPORT` on `__AFL_NETPORT` + deferred forkserver | same, plus `session_init()` + the port match (datagram: publish `RUNNING`) | same, plus the session-fd registration in `fd_map` |
| `accept`/`accept4` | pass-through, except for the previous run's leftovers in deferred mode (see below) | per-session re-arm + publish `RUNNING` (never parks) | per-session re-arm + publish `RUNNING` + park while a previous run is still armed |
| `fork` | pass-through | `proc_ref_cnt` accounting + `is_child` | plus the fake-readiness loop counters |
| `execve`/`close`/`fclose` | pass-through | fd classification and the session-end report | plus the flush of the pending response |
| `exit`/`_exit` | pass-through | lock + session-end report (`is_end = 6`, `ENDING`) | plus the flush of the pending response |

So the non-socket hooks are *not* dead weight in the rendezvous-only mode:
`proc_ref_cnt` (`fork`/`accept`/`close`) is what tells the target when the last
session reference is gone, `fd_map` classification (`dup`/`dup2`/`execve`) is
what makes `check_fd()` recognise the session socket for the turn-taking, and
the session-end report (`close`/`execve`/`exit`) is what saves the fuzzer the
wait for the TCP close.  What the rendezvous does *not* need - and therefore
skips - is everything that only exists to serve a session socket the target
does not write to itself: the fake `poll()`/`select()`/`epoll_wait()`
readiness, the ENDING `suspend()` parking and the response flush.

Split of the two halves in `setup_shm()` / `session_init()`:

| resource                                       | `enable_shm` | `enable_shmsync` alone |
|------------------------------------------------|--------------|------------------------|
| msg (session) segment: `state`/`is_end`/`mx`/header | attach   | attach (needed for the hand-over) |
| msg segment `data1`/`data2` + send buffer      | used         | never touched          |
| `send_buf_size` counters                       | written      | allocated but not written |
| check segment: `proc_ref_cnt`, `connection_state` | used      | used                   |
| check segment: `is_mem_leaked`/`is_global_val_written` | reset (read by `check_global_state()`) | not touched (no reader in this mode) |

The fuzzer side of the same contract lives in
`src/aflnet/utils/sock2shm.c` as the `aflnet_sync_ops_t` table
(`aflnet_shm_sync_wait_request_turn()`, `aflnet_shm_sync_wait_response_ready()`,
`aflnet_shm_sync_wait_ready()`, `aflnet_shm_sync_notify_request()`,
`aflnet_shm_sync_notify_end()`) and is driven from `src/aflnet/net.c`; the
fuzzer arms a clean session per run through
`aflnet_sock2shm_init_session()`.  `wait_request_turn()` is the hard gate
before sending; `wait_response_ready()` is a soft (bounded, non-fatal) gate
before the real-socket response read.  Mode 2 has no separate pre-read gate:
`s2s_shm_read()` performs the CLIENT wait and the `data2` copy together.  Its
exchange cleanup still sends the normal end notification directly
(`aflnet_sock2shm_notify_end()`: `is_end` + `SERVER`), because sock_mode=2
implies the rendezvous but keeps its wait ops inside the s2s helpers rather
than in `aflnet_state_t.sync_ops`.

## check segment

`shm_sig` (sock2shm_utils.h) is the CONTROL plane over the "check" segment:

    [0] state                          turn token (SERVER / CLIENT)
    [1] connection_state               UNINITIALIZED / ENDING / RUNNING
    [2] mx (fsemaphore)                futex mutex over the session
    [3] is_init                        RESERVED (ABI only, see below)
    [4] is_end                         0 running, 1 client ended, 3 timeout, 6 closed, 8 write timeout
    [5] proc_ref_cnt                   holders of the session fd(s)
    [6] is_mem_leaked                  long-term data / leak detected
    [7] is_global_val_written          global data written this run

The third entry was the shared "session armed" flag (`is_init`).  It is no
longer read by the target: every target process keeps its own mark
(`global_session_mark.session_inited`), which a `fork()` copies like the rest
of the memory image, so a fresh child starts un-armed and arms on its own
`bind()`/`accept()` while a deferred-forkserver child inherits the armed flag
of the forkserver parent.  The shared field is kept (and written as 0 by the
fuzzer's session reset) only so the segment ABI stays stable.

The old 10-int `sign[]` layout (force_socket_path / disable_shm /
disable_shmsync / fsrv_mark) and the snapshot "forkserver" (`fsrv_mark`) have
been removed; the per-process config now lives in the local
`global_session_mark` (netport, socket_type, enable_shm, enable_shmsync,
deferred_fs_wanted, session_inited) instead of the shared segment.

## Native forkserver at listen() (deferred mode)

`listen()` is also hooked.  On the first call it starts AFL++'s **native**
forkserver via `__afl_manual_init()`.  The forkserver parent then stays in its
service loop, and each per-test child resumes right after that `listen()` -
the parent already ran the real call - and serves one session on the inherited
listener.

`__afl_manual_init()` is resolved once, in the library's constructor
(`init_sockhook()`).  With `__AFL_DEFER_FORKSRV` set and the symbol missing -
the target does not export the AFL++ runtime symbols (the classic
afl-gcc/afl-clang assembler modes do not, and neither does a build without
AFL++'s `dynamic_list.txt`) - the deferred forkserver can never come up, so the
library prints a `sockhook:` diagnostic and **exits** instead of letting
afl-fuzz wait `exec_timeout x 10` ms for a forkserver that will not appear.
That check applies to the process afl-fuzz exec'd as the target only: the
fuzzer wires its forkserver descriptors (198/199) into that child before the
exec, so a process without them is a helper that merely inherited the
environment - the `AFLNET_CLEANUP_SCRIPT` shell, or something the target
`exec()`s.  Helpers keep the plain-preload behaviour and run normally;
otherwise every run would print a diagnostic and kill the cleanup script
("AFLNET_CLEANUP_SCRIPT ... exited with status 1" once per run).
afl-fuzz redirects the target's stderr to /dev/null, so its own "terminated
before we could complete a handshake" and "Timeout while initializing fork
server" messages carry the same hint.  Modes that obtain the entry point from
another preloaded library are unaffected: afl-fuzz's FRIDA runtime links
`afl-compiler-rt.o` into `afl-frida-trace.so`, and QEMU mode never preloads
this library at all.

The hook only fires for a listener bound to the AFLNet target port: the bound
address is read back with `getsockname()` and compared against `__AFL_NETPORT`
(the same value `bind()` matches), so an unrelated listener created earlier
(management port, unix socket, ...) cannot move the forkserver start point.
With no target port configured (`__AFL_NETPORT` unset) no listener is the
target one, so the deferred forkserver is not started at all.

Note: the `profuzzbench` run scripts default to `AFLNET_DEFER_FORKSRV=0`
(native constructor forkserver, as in original AFLNet); pass
`AFLNET_DEFER_FORKSRV=1` through `AFLNET_ENV` to opt in.

This is only *active* when the target is started with
`AFLNET_DEFER_FORKSRV=1` (the fuzzer translates it into the internal
`__AFL_DEFER_FORKSRV` for the target) so AFL++'s auto-init constructor does
not start the forkserver at program entry.  Otherwise (default, non-deferred)
`__afl_manual_init()` is a no-op (the runtime guards against double init) and
the hook simply proxies to the real `listen()`.  Running without an afl-fuzz
parent is also a no-op (the runtime returns immediately), so standalone
servers are unaffected.  Datagram targets have no `listen()`: for them the
deferred forkserver is started at the `bind()` of the configured netport
instead.

Notes when enabling deferred mode together with sock2shm:

  - the forkserver parent persists inside the deferred start (`listen()` for a
    stream target, `bind()` for a datagram one), and the per-run children
    resume from there *before* the session is armed: a stream `bind()` never
    arms (only a datagram bind does - see `bind()`), and the datagram
    `session_init()` sits after the deferred start inside `bind()`.  Each
    child therefore inherits an un-armed mark and arms - and resets the shared
    session state - itself, at its `accept()` (stream) or in its `bind()`
    (datagram).  `accept()` arms and registers independently of that mark, so
    an inherited "already armed" state can no longer make it silently fall
    back to the real socket.

    The fuzzer-side per-run reset (`aflnet_init_session`, assigned in
    `src/aflnet/config.c`) runs in the module's `afl_custom_post_run()`
    (`src/aflnet/module.c`): after the previous run finished and before the
    forkserver spawns the next child, which is the serialisation point the
    core would otherwise have to provide in `fuzz_run_target()`.  With the
    arming described above it is not needed for a freshly forked child, but
    it is the safety net for a process that serves more than one session
    without re-arming (a persistent target looping on `accept()`), where the
    previous session's `connection_state` / `is_end` / turn token would
    otherwise carry over - and it also cleans up after a run that timed out
    before the target could report its own session end.

### The inherited accept queue

Because the listener is inherited, its accept queue is inherited too.  A
connection that a run never gets around to accepting - the child dies or is
killed before its `accept()`, or the fuzzer gives the run up - therefore stays
queued, with the fuzzer's end of it already closed.  The next child would
serve that dead session: its response goes nowhere and the fuzzer's own
connection stays queued.  Since the fuzzer opens exactly one connection per
run, the queue would then stay exactly one connection behind for the rest of
the campaign - every run answering the previous run's socket, silently,
without a crash or a timeout ever being reported.

`accept()`/`accept4()` in a child therefore drop connections whose peer is
already gone (`TCP_CLOSE_WAIT` or reset, read through `TCP_INFO`) and accept
again, which recovers in a single run.  The filter is armed only when a
deferred forkserver really forked the process (a standalone preload keeps
plain `accept()` semantics, and so do the non-deferred configurations) and
only for the target-port listener the children share - unrelated listeners
are never touched.  Datagram targets have no `accept()` and no accept queue,
so they are unaffected.  `test/test-defer-stale.sh` is the regression test.

### Targets that close all file descriptors

Targets that sanitise their descriptors before reaching the deferred start
point would close the forkserver's pipes.  OpenSSH's `sshd` does exactly that:
`closefrom(3)` runs early in `main()`, while the profuzzbench fork places
`__AFL_INIT()` after config parsing and host key loading (on purpose - so every
per-test child skips them).  Since glibc 2.34 that `closefrom()` call is the
libc implementation, which knows nothing about the preload and closes
`FORKSRV_FD`/`FORKSRV_FD + 1` as well; afl-fuzz then sees EOF on the status
pipe and aborts with the misleading
`Fork server crashed with signal 9` - the SIGKILL in that message is the
fuzzer's own cleanup, not a target crash.  (The same fork's
`openbsd-compat/bsd-closefrom.c` does protect those two descriptors, but that
file is compiled out as soon as libc provides `closefrom()`.)

The library therefore interposes both ways a target can drop the descriptors:

  - `closefrom()` implements the usual semantics (everything `>= lowfd`,
    `/proc/self/fd` with a `getrlimit()` based fallback), and
  - `close()` leaves `FORKSRV_FD`/`FORKSRV_FD + 1` alone, for targets (or
    libraries) that close their inherited descriptors one by one instead of
    calling `closefrom()`.

Both keep the two descriptors **only until the handshake happened in this
process**, which is exactly the window in which the target's own sanitisation
runs: the AFL runtime sets `__afl_connected` right after the handshake and
before it forks the per-test children, so a child inherits `1` and AFL's own
`close()` of the two descriptors in that child is left alone (no fd leak into
the target).  Without deferred mode, and before `init_sockhook()` runs, the
hooks behave exactly like libc's.
`test/test-closefrom-hook.sh` is the regression test: it runs the matrix
(no preload / preload with deferred off / preload with deferred on / the
connected child) for both the `closefrom()` and the one-by-one path and checks
that an ordinary descriptor is always closed while 198/199 only survive while
the deferred handshake is still pending.

### Targets that keep wall-clock timers

A target can also arm an `alarm()` for its session timeouts during the startup
that runs *before* the deferred start point.  In deferred mode that timer then
belongs to the process which becomes the forkserver parent - and the parent is
not a session.  proftpd (`src/timers.c`) does exactly this: it arms a
wall-clock alarm early and installs its handler with
`siginterrupt(SIGALRM, 1)`, so when the timer expires in the parked parent the
runtime's `read()`/`waitpid()` comes back with `EINTR`; the AFL runtime treats
that as "the fuzzer is gone" (`write_error()` then `_exit(1)`) and afl-fuzz
aborts with `Unable to communicate with fork server`.  The whole campaign dies
5 s after startup with proftpd's 5 s timer.

The library therefore parks the timer across the forkserver start: it blocks
`SIGALRM` for the parent and cancels a pending `alarm()` before entering the
runtime (`alarm(0)` also returns the remaining seconds).  The children - the
parent never returns from the runtime - restore the signal mask and re-arm the
remaining time, so their own session timeouts keep working.  The mask is what
makes the parent safe even for a `setitimer(ITIMER_REAL)` user, which
`alarm(0)` would not cancel (it is per thread, so this assumes the deferred
start point is still single threaded - the usual forkserver requirement).
This only affects the deferred start driven by this library; targets that call
`__AFL_INIT()` themselves are untouched.
`test/test-defer-alarm.sh` is the regression test (a target that arms `alarm(1)`
and exits from its SIGALRM handler must not take the forkserver with it).

### Testing

    # deterministic contract test of the standalone rendezvous (readiness,
    # turn-taking at recv, session end, inert default) - no afl-fuzz needed
    ./test/test-shmsync.sh

    # deferred forkserver: a run that never accepted its connection must not
    # leave the following runs serving that dead connection
    ./test/test-defer-stale.sh

    # deferred forkserver: a target that arms alarm() during its startup must
    # not lose the forkserver parent to its own timer (and keeps the timer in
    # its per-test children)
    ./test/test-defer-alarm.sh

    # the "cannot resolve __afl_manual_init" diagnostic fires for the fuzz
    # target only, not for helpers that inherited the environment
    ./test/test-defer-failfast.sh

    # a process the library does not recognise as the fuzz target must behave
    # exactly like one without the preload (and manual runs must not)
    ./test/test-sockhook-inert.sh

    # deferred forkserver: a target calling closefrom(3) must not lose the
    # forkserver descriptors before __AFL_INIT()
    ./test/test-closefrom-hook.sh

    # afl-fuzz smoke run against a live server.  AFLNET_TERMINATE_CHILD=1 is
    # required for test/test-echo-server: it is a *stateful* server that keeps
    # serving after the exchange, so without it every seed is reported as a
    # timeout during the dry run.
    AFLNET_URL=127.0.0.1:8080 AFLNET_PROTOCOL=ftp AFLNET_SOCK_MODE=1 \
      AFLNET_SHM_SYNC=1 AFLNET_TERMINATE_CHILD=1 \
      ./afl-fuzz -i in -o out -V 10 -m none -t 3000+ \
      -- test/test-echo-server 8080
