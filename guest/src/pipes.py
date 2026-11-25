"""Non-blocking descriptor streams on the running asyncio loop: a reader with
pause/resume and a writer with backpressure, flush callbacks and an optional
watch for its reader's close. Plain descriptors, not asyncio pipe
transports: the helper's stdin and stdout may be one socket (sshd's
socketpair), which a pipe transport would misread as closed.

Callbacks run on the loop, never re-entrantly from the call that caused
them; `close` comes once, after `end`, `error` or `destroy`."""

import asyncio
import errno
import os

CHUNK_BYTES = 65536


class FdReader:
    def __init__(self, fd, data, end=None, error=None, close=None, own=True):
        self.loop = asyncio.get_running_loop()
        self.fd = fd
        self.own = own
        self._data = data
        self._end = end
        self._error = error
        self._close = close
        self.paused = False
        self.ended = False
        self.destroyed = False
        self._registered = False
        self._closed = False
        os.set_blocking(fd, False)
        self._register()

    def _register(self):
        if not self._registered and not self.paused and not self.destroyed and not self.ended:
            self.loop.add_reader(self.fd, self._ready)
            self._registered = True

    def _unregister(self):
        if self._registered:
            self.loop.remove_reader(self.fd)
            self._registered = False

    def _ready(self):
        if self.destroyed or self.ended or self.paused:
            return
        try:
            chunk = os.read(self.fd, CHUNK_BYTES)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._finish(self._error)
            return
        if not chunk:
            self._finish(self._end)
            return
        self._data(chunk)

    def _finish(self, callback):
        self.ended = True
        self._unregister()
        self._release()
        if callback is not None:
            callback()
        self._closing()

    def _release(self):
        if self.own and self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1

    def _closing(self):
        if not self._closed:
            self._closed = True
            if self._close is not None:
                self.loop.call_soon(self._close)

    def pause(self):
        self.paused = True
        self._unregister()

    def resume(self):
        self.paused = False
        self._register()

    def destroy(self):
        if self.destroyed:
            return
        self.destroyed = True
        self._unregister()
        self._release()
        self._closing()


class FdWriter:
    """`write(data)` returns False once `high_water` bytes or more wait in this
    process; `drain` runs once the buffer is empty again after such a False.
    `flushed(callback)`, one waiter at a time: `callback(True)` once
    everything written so far left this process, `callback(False)` if it is
    destroyed first. `gone` runs once on a write failure or, with `watch`, the
    reader's close."""

    def __init__(self, fd, drain=None, gone=None, watch=False, own=True, high_water=1):
        self.loop = asyncio.get_running_loop()
        self.fd = fd
        self.own = own
        self._drain = drain
        self._gone = gone
        self.buffer = bytearray()
        self._waiter = None
        self.ended = False
        self.destroyed = False
        self._writing = False
        self._watching = False
        self._close_after = False
        self._high_water = high_water
        self._need_drain = False
        os.set_blocking(fd, False)
        if watch:
            # A pipe's write end reports an error once its reader closed.
            self.loop.add_reader(fd, self._hangup)
            self._watching = True

    @property
    def pending(self):
        return len(self.buffer)

    def write(self, data):
        if self.destroyed or self.ended:
            return False
        self.buffer += data
        self._flush()
        if self.destroyed or len(self.buffer) >= self._high_water:
            self._need_drain = True
            return False
        return True

    def flushed(self, callback):
        if self.destroyed:
            self.loop.call_soon(callback, False)
        elif not self.buffer:
            self.loop.call_soon(callback, True)
        else:
            self._waiter = callback

    def end(self, data=b""):
        """Writes `data`, then closes once everything left."""
        if self.destroyed or self.ended:
            return
        self.write(data)
        self.ended = True
        self._close_after = True
        if not self.destroyed and not self.buffer:
            self._finish_end()

    def _flush(self):
        while self.buffer and not self.destroyed:
            try:
                count = os.write(self.fd, self.buffer)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                self._fail()
                return
            del self.buffer[:count]
        if self.destroyed:
            return
        if not self.buffer and self._waiter is not None:
            waiter, self._waiter = self._waiter, None
            self.loop.call_soon(waiter, True)
        if self.buffer and not self._writing:
            self.loop.add_writer(self.fd, self._writable)
            self._writing = True
        elif not self.buffer and self._writing:
            self.loop.remove_writer(self.fd)
            self._writing = False
            if self._need_drain:
                self._need_drain = False
                if self._drain is not None:
                    self.loop.call_soon(self._drain)

    def _writable(self):
        self._flush()
        if not self.buffer and self._close_after and not self.destroyed:
            self._finish_end()

    def _finish_end(self):
        self._close_after = False
        self._release()

    def _hangup(self):
        self._fail()

    def _fail(self):
        if self.destroyed:
            return
        gone = self._gone
        self.destroy()
        if gone is not None:
            self.loop.call_soon(gone)

    def _release(self):
        if self._writing:
            self.loop.remove_writer(self.fd)
            self._writing = False
        if self._watching:
            self.loop.remove_reader(self.fd)
            self._watching = False
        if self.own and self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1

    def destroy(self):
        """Drops whatever waits; a waiting `flushed` gets False."""
        if self.destroyed:
            return
        self.destroyed = True
        self.buffer = bytearray()
        waiter, self._waiter = self._waiter, None
        if waiter is not None:
            self.loop.call_soon(waiter, False)
        self._release()


def pipe():
    """A close-on-exec pipe: (read, write)."""
    return os.pipe2(os.O_CLOEXEC)


def close_quietly(*fds):
    for fd in fds:
        if fd is not None and fd >= 0:
            try:
                os.close(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    pass
