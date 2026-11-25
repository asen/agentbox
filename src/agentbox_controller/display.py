"""Live display of guest output, the final report line and the controller's
own input (the Rust CLI's output.rs and stdin.rs, simplified).

Output is rendered inert: printable text, newline and tab as is, every
other control character, bidirectional control and invalid UTF-8 byte as an
escape, so guest bytes never drive the terminal. Writes never block the
loop: a pipe or terminal is reopened as a private nonblocking description,
a regular file written as is; anything else is unsupported. A bounded
queue (`MAX_PENDING`) per stream: past it the display is incomplete, said
so in the result, never claimed shown.
"""
import codecs
import os
import select
import selectors
import socket
import stat
import time

from .host import read_some, write_some

MAX_PENDING = 1 << 20
FINAL_TIMEOUT = 1.0
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}


def render(text):
    out = []
    for ch in text:
        code = ord(ch)
        if ch in "\n\t" or (ch.isprintable() and code not in _BIDI):
            out.append(ch)
        elif code < 0x100:
            out.append(f"\\x{code:02x}")
        else:
            out.append(f"\\u{{{code:x}}}")
    return "".join(out)


def _escape_errors(error):
    bad = error.object[error.start:error.end]
    return "".join(f"\\x{b:02x}" for b in bad), error.end


codecs.register_error("agentbox_escape", _escape_errors)


class Surface:
    """One of the controller's own output streams."""

    def __init__(self, loop, fd):
        self.loop = loop
        self.pending = bytearray()
        self.incomplete = None
        self.fd = None
        self.own = False
        # The last byte actually written, for the final line's own line.
        self.tail = None
        try:
            st = os.fstat(fd)
            if stat.S_ISFIFO(st.st_mode) or stat.S_ISCHR(st.st_mode):
                self.fd = os.open(f"/proc/self/fd/{fd}", os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC
                                  | os.O_NOCTTY)
                self.own = True
            elif stat.S_ISREG(st.st_mode):
                self.fd, self.own = fd, False
        except OSError:
            self.fd = None
        if self.fd is None:
            self.incomplete = "output_unsupported"
        self.decoder = codecs.getincrementaldecoder("utf-8")("agentbox_escape")

    def show(self, data):
        """Guest bytes, rendered inert, queued."""
        text = self.decoder.decode(data)
        self.write(render(text).encode())

    def write(self, data):
        if self.fd is None or self.incomplete is not None:
            return
        if len(self.pending) + len(data) > MAX_PENDING:
            self.incomplete = "output_behind"
            return
        self.pending += data
        self._flush(None)

    def _flush(self, _mask):
        while self.pending:
            written = write_some(self.fd, bytes(self.pending[:65536]))
            if written is None:
                self.pending.clear()
                self.incomplete = "output_lost"
                break
            if written == 0:
                self.loop.watch(self.fd, selectors.EVENT_WRITE, self._flush)
                return
            self.tail = self.pending[written - 1]
            del self.pending[:written]
        if self.fd is not None:
            self.loop.unwatch(self.fd)

    def finish(self, deadline):
        """Whatever is still queued, by `deadline`; then the result."""
        tail = self.decoder.decode(b"", final=True)
        if tail:
            self.write(render(tail).encode())
        self.loop.run(lambda: not self.pending or self.incomplete is not None, deadline)
        if self.pending and self.incomplete is None:
            self.incomplete = "output_behind"
        if self.fd is not None:
            self.loop.unwatch(self.fd)
            if self.own:
                os.close(self.fd)
            self.fd = None
        return self.incomplete


def emit(fd, data, timeout=FINAL_TIMEOUT):
    """A short report on one of the controller's own streams, best effort
    and bounded: never a blocking write, given up (False) at `timeout` when
    the reader stopped reading. A pipe or terminal through a private
    nonblocking description, a socket with MSG_DONTWAIT, a regular file as
    is."""
    deadline = time.monotonic() + timeout
    try:
        st = os.fstat(fd)
        if stat.S_ISREG(st.st_mode):
            while data:
                data = data[os.write(fd, data):]
            return True
        if stat.S_ISSOCK(st.st_mode):
            stream = socket.socket(fileno=os.dup(fd))
            send = lambda chunk: stream.send(chunk, socket.MSG_DONTWAIT)  # noqa: E731
            target = stream.fileno()
        elif stat.S_ISFIFO(st.st_mode) or stat.S_ISCHR(st.st_mode):
            target = os.open(f"/proc/self/fd/{fd}", os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY)
            stream = None
            send = lambda chunk: os.write(target, chunk)  # noqa: E731
        else:
            return False
    except OSError:
        return False
    poller = select.poll()
    poller.register(target, select.POLLOUT)
    try:
        while data:
            try:
                data = data[send(data):]
                continue
            except BlockingIOError:
                pass
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            poller.poll(left * 1000)
        return True
    except OSError:
        return False
    finally:
        if stream is not None:
            stream.close()
        else:
            os.close(target)


class Input:
    """The controller's own stdin as the task's (`--stdin`), read only on
    demand, one chunk per guest credit; never changing the inherited
    description."""

    CHUNK = 2048

    def __init__(self, fd=0):
        self.fd = None
        self.eof = False
        self.failed = False
        try:
            st = os.fstat(fd)
            if stat.S_ISFIFO(st.st_mode) or stat.S_ISCHR(st.st_mode) or stat.S_ISSOCK(st.st_mode):
                self.fd = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
                                  | os.O_NOCTTY)
            elif stat.S_ISREG(st.st_mode):
                self.fd = os.dup(fd)
        except OSError:
            self.fd = None
        if self.fd is None:
            self.failed = True

    def read(self):
        """One chunk, b"" at its end, None when nothing is ready."""
        if self.fd is None or self.eof:
            return b""
        data = read_some(self.fd, self.CHUNK)
        if data == b"":
            self.eof = True
        return data

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
