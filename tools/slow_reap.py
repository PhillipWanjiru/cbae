#!/usr/bin/env python3
"""Run a program so that every thread that exits stays listed in /proc/<pid>/task for a while after it has gone (Linux).

A joined thread is not removed from /proc/<pid>/task until the kernel has finished with it, normally a few microseconds after
pthread_join returns. On a loaded or virtual machine that step can take much longer. This runs the program under ptrace, which
makes the kernel keep an exited thread as a zombie until the tracer collects it, and collects it DELAY_MS after the thread has
gone. A test that counts threads straight after a join then meets the slowest teardown it can meet.

usage: slow_reap.py DELAY_MS PROGRAM [ARGS...]

Exit status: the program's; 77 when this system does not allow tracing (the caller may count that as skipped).
A leak checker that works by tracing (LeakSanitizer) cannot run inside this: set ASAN_OPTIONS=detect_leaks=0 for such a program.
"""
import ctypes
import os
import signal
import sys
import time

WALL = 0x40000000                                     # __WALL: wait for threads as well as processes
PTRACE_TRACEME, PTRACE_CONT, PTRACE_SETOPTIONS, PTRACE_GETEVENTMSG = 0, 7, 0x4200, 0x4201
PTRACE_O_TRACECLONE, PTRACE_O_EXITKILL, PTRACE_EVENT_CLONE = 0x8, 0x100000, 3

libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]


def ptrace(request, pid, data=None):
    if libc.ptrace(request, pid, None, data) == -1:
        err = ctypes.get_errno()
        if err:
            raise OSError(err, "ptrace(%d) on %d: %s" % (request, pid, os.strerror(err)))


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    delay = float(sys.argv[1]) / 1000.0
    argv = sys.argv[2:]
    child = os.fork()
    if child == 0:
        if libc.ptrace(PTRACE_TRACEME, 0, None, None) == -1:
            os._exit(77)                              # tracing is not allowed here
        try:
            os.execvp(argv[0], argv)
        finally:
            os._exit(127)
    _, st = os.waitpid(child, WALL)                   # the stop at exec
    if not os.WIFSTOPPED(st):
        return os.waitstatus_to_exitcode(st)
    try:
        ptrace(PTRACE_SETOPTIONS, child, ctypes.c_void_p(PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL))
    except OSError:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, WALL)
        return 77
    ptrace(PTRACE_CONT, child, None)

    tids = {child}
    gone = {}                                         # tid -> when it was first seen to have exited
    result = 0
    while tids:
        busy = False
        for tid in list(tids):
            if tid in gone:
                if time.monotonic() - gone[tid] >= delay:
                    _, st = os.waitpid(tid, WALL)     # collected: the task leaves /proc now
                    tids.discard(tid)
                    del gone[tid]
                    busy = True
                    if tid == child:
                        result = os.waitstatus_to_exitcode(st)
                continue
            # a traced task that is merely stopped is reported here too, so look at what was reported
            info = os.waitid(os.P_PID, tid, os.WEXITED | os.WNOHANG | os.WNOWAIT | WALL)
            if info is not None and info.si_pid == tid and info.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED):
                gone[tid] = time.monotonic()
                busy = True
                continue
            pid, st = os.waitpid(tid, os.WNOHANG | WALL)
            if pid == 0:
                continue
            busy = True
            if not os.WIFSTOPPED(st):                 # it exited in the instant between the two calls: nothing is left to hold
                tids.discard(tid)
                if tid == child:
                    result = os.waitstatus_to_exitcode(st)
                continue
            sig = os.WSTOPSIG(st)
            if st >> 16 == PTRACE_EVENT_CLONE:
                new = ctypes.c_ulong(0)
                ptrace(PTRACE_GETEVENTMSG, tid, ctypes.byref(new))
                tids.add(new.value)
                sig = 0
            elif sig in (signal.SIGTRAP, signal.SIGSTOP):
                sig = 0
            ptrace(PTRACE_CONT, tid, ctypes.c_void_p(sig))
        if not busy:
            time.sleep(0.0002)
    return result


if __name__ == "__main__":
    sys.exit(main())
