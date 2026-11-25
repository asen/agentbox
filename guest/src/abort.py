"""A sticky abort, like the web's AbortController and AbortSignal in one:
`aborted` once `abort()` ran; listeners run once, in order, at that call.
Listeners added later never run. Single-threaded: the event loop's or a
signal handler's caller only."""

import signal

# The terminal signals a request client gives up on.
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class Abort:
    def __init__(self):
        self.aborted = False
        self._listeners = []

    def abort(self):
        if self.aborted:
            return
        self.aborted = True
        listeners, self._listeners = self._listeners, []
        for listener in listeners:
            listener()

    def add_listener(self, listener):
        if not self.aborted:
            self._listeners.append(listener)

    def remove_listener(self, listener):
        if listener in self._listeners:
            self._listeners.remove(listener)


def signalled(loop):
    """A fresh abort of the terminal signals on `loop`; returns (abort, done),
    `done` restoring the default dispositions."""
    abort = Abort()
    for number in SIGNALS:
        loop.add_signal_handler(number, abort.abort)

    def done():
        for number in SIGNALS:
            loop.remove_signal_handler(number)

    return abort, done
