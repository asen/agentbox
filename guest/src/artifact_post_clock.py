"""A request's original cutoff, captured once before anything else.

One clock, `time.monotonic_ns()`, serves both the request's cutoff (`until_ns`)
and local work's (`local_until`, the same instant in `time.monotonic()`
seconds, floored to the millisecond, so local work's bound can only
shorten)."""

import time

from guest.src.artifact_post_protocol import REQUEST_TIMEOUT_MS

MS_NS = 1_000_000


class RequestDeadline:
    __slots__ = ("started_ns", "until_ns", "local_until")

    def __init__(self, started_ns, until_ns, local_until):
        self.started_ns = started_ns
        self.until_ns = until_ns
        self.local_until = local_until


def capture_request_deadline(milliseconds=REQUEST_TIMEOUT_MS):
    """Samples the clock first; a broken sample is already expired."""
    started_ns = time.monotonic_ns()
    until_ns = started_ns + milliseconds * MS_NS
    now = time.monotonic_ns()
    remaining = until_ns - now
    if now < started_ns or remaining <= 0:
        return RequestDeadline(started_ns, started_ns, 0.0)
    return RequestDeadline(started_ns, until_ns, (now + (remaining // MS_NS) * MS_NS) / 1e9)
