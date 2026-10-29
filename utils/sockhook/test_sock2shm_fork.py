#!/usr/bin/env python3
"""Standalone smoke test for the sock2shm forkserver (mark==1) mechanism.

Mimics the fuzzer side of the SHM protocol (see src/aflnet/sock2shm.c):

  1. create the msg / netport / sign SHM segments and export their ids
  2. spawn the echo server with sock2shm.so preloaded (LD_PRELOAD)
  3. with AFLNET_SOCK2SHM_FORK=1: the server forks at its first shm_read,
     the parent stalls and exits propagating the child's status, while the
     child reads the request from data1, echoes it into data2 and exits.
  4. verify the echoed response and the parent's exit status.

Run from the repo root:
    python3 utils/sock2shm/test_sock2shm_fork.py
"""

import ctypes
import os
import signal
import socket
import struct
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOCK2SHM = os.path.join(REPO, "sock2shm.so")
SERVER = os.path.join(REPO, "test", "test-echo-server")
PORT = 8080
MAX_MSG_SIZE = 0x4000

# --- msg struct layout (must match sock2shm_utils.h) ---
class FuSemaphore(ctypes.Structure):
    _fields_ = [("avail", ctypes.c_int), ("waiters", ctypes.c_int)]

class Msg(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_int),
        ("is_init", ctypes.c_int),
        ("is_end", ctypes.c_int),
        ("len1", ctypes.c_int),
        ("len2", ctypes.c_int),
        ("buf_size", ctypes.c_int),
        ("mx", FuSemaphore),
        ("data1", ctypes.c_ubyte * MAX_MSG_SIZE),
        ("data2", ctypes.c_ubyte * MAX_MSG_SIZE),
    ]

SERVER_ST = 0  # enum session_state { SERVER, CLIENT }
CLIENT_ST = 1
UNINIT = -1    # enum connection_state { UNINITIALIZED=-1, ENDING, RUNNING }
RUNNING = 1

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.shmat.restype = ctypes.c_void_p
libc.shmdt.argtypes = [ctypes.c_void_p]


def shm_create(size):
    # IPC_PRIVATE: each call returns a brand-new segment
    flags = 0o600 | 0o1000 | 0o2000   # perms | IPC_CREAT | IPC_EXCL
    shmid = libc.shmget(0, size, flags)
    if shmid < 0:
        raise OSError("shmget failed: %d" % shmid)
    addr = libc.shmat(shmid, None, 0)
    if addr == ctypes.c_void_p(-1).value:
        raise OSError("shmat failed")
    return shmid, ctypes.c_void_p(addr)


def shm_free(shmid, addr):
    libc.shmdt(addr)
    libc.shmctl(shmid, 0, None)  # IPC_RMID


def spin_wait(addr, val, timeout_ms):
    """mirror shm_wait: spin while *addr == val, up to timeout_ms."""
    start = time.time()
    while ctypes.c_int.from_address(addr).value == val:
        if (time.time() - start) * 1000 >= timeout_ms:
            return True  # still == val after timeout
    return False  # changed


def run_fork_test(fork, req=b"hello\r\n"):
    """Exercise one exchange with the echo server.
    Returns (echo_ok, exit_code); a crash request ("CRASH!") makes the
    server child abort() and checks the parent propagates the signal."""

    shm_msg, a_msg = shm_create(ctypes.sizeof(Msg))
    shm_net, a_net = shm_create(ctypes.sizeof(ctypes.c_int))
    shm_sig, a_sign = shm_create(ctypes.sizeof(ctypes.c_int) * 10)

    # attach views
    msg = Msg.from_address(a_msg.value)
    netport = ctypes.c_int.from_address(a_net.value)
    sign = (ctypes.c_int * 10).from_address(a_sign.value)

    # initialise shared state (like aflnet_sock2shm_setup + init_session)
    netport.value = PORT
    for i in range(10):
        sign[i] = 0
    sign[2] = UNINIT      # connection_state
    sign[9] = 1 if fork else 0   # fsrv_mark
    msg.state = SERVER_ST
    msg.is_init = 0
    msg.is_end = 0
    msg.len1 = 0
    msg.len2 = 0
    msg.buf_size = 0
    msg.mx.avail = 1
    msg.mx.waiters = 0

    env = os.environ.copy()
    env["__AFL_SHM_MSG_ID"] = str(shm_msg)
    env["__AFL_SHM_NETPORT_ID"] = str(shm_net)
    env["__AFL_SHM_CHECK_ID"] = str(shm_sig)
    env["__AFL_PROTOCOL_TYPE"] = "TCP"
    env["LD_PRELOAD"] = SOCK2SHM
    if fork:
        env["AFLNET_SOCK2SHM_FORK"] = "1"
    env.pop("AFLNET_SOCK2SHM_FORK", None) if not fork else None

    proc = subprocess.Popen([SERVER, str(PORT)], env=env,
                            stderr=subprocess.DEVNULL)

    exit_code = None
    echo_ok = False
    def dump(tag):
        print("    [%s] state=%d is_end=%d len1=%d len2=%d buf=%d" % (
            tag, msg.state, msg.is_end, msg.len1, msg.len2, msg.buf_size))

    try:
        # connect so the server's accept() completes
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        deadline = time.time() + 5
        while True:
            try:
                sock.connect(("127.0.0.1", PORT))
                break
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(0.02)
        dump("connected")

        # --- early recv (server's first shm_read notifies CLIENT) ---
        spin_wait(a_msg.value, SERVER_ST, 300)        # wait while state==SERVER
        dump("early-recv")

        # --- send request ---
        msg.len1 = len(req)
        for i, b in enumerate(req):
            msg.data1[i] = b
        msg.buf_size = len(req)
        # do { notify SERVER; wait while SERVER } while buf_size>0
        while msg.buf_size > 0:
            msg.state = SERVER_ST
            if spin_wait(a_msg.value, SERVER_ST, 300):
                break
        dump("after-write")
        if msg.is_end:
            raise RuntimeError("server marked session end during write")

        # --- recv response ---
        if spin_wait(a_msg.value, SERVER_ST, 300):    # wait while state==SERVER
            dump("recv-timeout")
            raise RuntimeError("timeout waiting for response")
        dump("after-recv-wait")
        if msg.len2 > 0:
            resp = bytes(msg.data2[: msg.len2])
            echo_ok = (resp == req)

        # --- finish (fuzzer marks session done) ---
        msg.is_end = 2
        msg.state = SERVER_ST
        sock.close()
    except Exception as e:
        print("  exchange error: %r" % (e,))
    finally:
        # wait for the target to exit (forkserver parent exits after child)
        try:
            proc.wait(timeout=6)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            exit_code = None

    shm_free(shm_msg, a_msg)
    shm_free(shm_net, a_net)
    shm_free(shm_sig, a_sign)
    return echo_ok, exit_code


def main():
    os.system("cc -o %s %s" % (SERVER, SERVER + ".c"))

    print("[*] fork=%d (mark==1)" % 1)
    ok, code = run_fork_test(True)
    print("    echo_ok=%s exit_code=%s" % (ok, code))
    if not ok or code is None:
        print("[FAIL] forkserver echo mismatch or target did not exit")
        return 1

    print("[*] fork=%d (mark==0, no fork; process stays alive)" % 0)
    ok, code = run_fork_test(False)
    print("    echo_ok=%s (expected True; exit_code=%s target killed by harness)"
          % (ok, code))
    if not ok:
        print("[FAIL] non-fork echo mismatch")
        return 1

    print("[*] fork=%d crash propagation (child abort -> parent dies by SIGABRT)" % 1)
    ok, code = run_fork_test(True, req=b"CRASH!\r\n")
    print("    echo_ok=%s exit_code=%s (expected <0 = killed by signal)" % (ok, code))
    if code is None or code >= 0:
        print("[FAIL] crash was not propagated to the parent")
        return 1

    print("[PASS] sock2shm forkserver smoke test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
