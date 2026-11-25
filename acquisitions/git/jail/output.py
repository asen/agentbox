"""Bounded writes to this process's own output descriptors (the `git` shim's
stdout and stderr), which a reader may never drain. Never a blocking write
and never a change to the descriptor's shared status flags, which its other
holders see:

  regular file           written as is (no reader to wait for)
  socket                 send with MSG_DONTWAIT
  pipe, FIFO, tty, ...   a private reopening through /proc/self/fd, O_NONBLOCK
  none of these works    dropped

No thread. What cannot be written in time is dropped, never queued without
bound."""

import os
import select
import socket
import stat
import time


class Sink:
    def __init__(self, fd):
        self._fd = None
        self._own = False
        self._socket = None
        try:
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode):
                self._fd = fd
            elif stat.S_ISSOCK(info.st_mode):
                self._socket = socket.socket(fileno=os.dup(fd))
            else:
                self._fd = os.open("/proc/self/fd/%d" % fd,
                                   os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
                self._own = True
        except OSError:
            self.close()

    def fileno(self):
        """The descriptor to wait on for writability; None when nothing waits (direct or dropped)."""
        if self._socket is not None:
            return self._socket.fileno()
        return self._fd if self._own else None

    def write(self, data):
        """Bytes taken now: 0 when it would block; all of them when dropped."""
        try:
            if self._socket is not None:
                return self._socket.send(data, socket.MSG_DONTWAIT)
            if self._fd is not None:
                return os.write(self._fd, data)
        except (BlockingIOError, InterruptedError):
            return 0
        except OSError:
            self.close()
        return len(data)

    def write_all(self, data, timeout):
        """`data` within `timeout` seconds, the rest dropped; whether all of it went."""
        until = time.monotonic() + timeout
        view = memoryview(data)
        while view:
            view = view[self.write(view):]
            remaining = until - time.monotonic()
            if view and (remaining <= 0 or self.fileno() is None):
                return False
            if view:
                poll = select.poll()
                poll.register(self.fileno(), select.POLLOUT)
                poll.poll(remaining * 1000)
        return True

    def close(self):
        if self._socket is not None:
            self._socket.close()
        elif self._own and self._fd is not None:
            os.close(self._fd)
        self._fd = self._socket = None
        self._own = False


# A final report line's bound.
REPORT_TIMEOUT_MS = 2000


def report_line(line, fd=2):
    """One line to `fd` within REPORT_TIMEOUT_MS, else dropped."""
    sink = Sink(fd)
    try:
        sink.write_all((line + "\n").encode("utf-8", "surrogateescape"), REPORT_TIMEOUT_MS / 1000)
    finally:
        sink.close()
