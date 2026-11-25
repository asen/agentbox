"""The contract of a handler's jail module (`acquisitions/<id>/jail/<id>.py` in
the worker bundle), the file its manifest's `jail.entry` names
(acquisitions/contracts/handlers/v1). A module is the program of its manifest's shims,
the commands the host generates in the installation's `bin/`:

    SHIM ARGS...  (bin/SHIM) --> PYTHON entry shim SHIM ARGS... --> status

Each shim owns its command's semantics: its arguments, its submissions, the
application of what is delivered and its reports. `agentbox-request` knows
no handler (request_main.py); nothing routes to a module but its own shims.
`operation_shim` serves the common `SHIM OPERATION [ARGS_JSON]` form with
arguments checked as the POST carries them. Modules are jail convenience,
never authority: the host authorizes every submission under the handler's
policy.
"""

import asyncio
import json
import math
import os
import sys

from guest.src.abort import signalled
from guest.src.artifact_post_context import context_from_environment
from guest.src.artifact_post_protocol import MAX_DEPTH, canonical_value, is_word, keys_valid
from guest.src.protocol import MAX_SAFE_INTEGER
from guest.src.request_status import CLIENT_USAGE

# The longest argument object, as canonical JSON (the host's ceiling,
# handlers.rs MAX_ARGS_BYTES).
MAX_ARGS_BYTES = 61440


class _Unsafe:
    """A number JavaScript would not hold as a non-negative safe integer."""


_UNSAFE = _Unsafe()


def _js_number(token):
    # JSON.parse's double, then the POST contract's integers only.
    try:
        value = float(token)
    except (ValueError, OverflowError):
        return _UNSAFE
    if not math.isfinite(value) or not value.is_integer() or value < 0 or value > MAX_SAFE_INTEGER:
        return _UNSAFE
    if value == 0 and math.copysign(1.0, value) < 0:
        return _UNSAFE
    return int(value)


def _reject(_name):
    raise ValueError("not JSON")


def _depth(value):
    if isinstance(value, dict):
        return 1 + max([0] + [_depth(item) for item in value.values()])
    if isinstance(value, list):
        return 1 + max([0] + [_depth(item) for item in value])
    return 0


def _numbers_valid(value):
    """Non-negative safe integers only, as the POST contract."""
    if value is _UNSAFE:
        return False
    if isinstance(value, dict):
        return all(_numbers_valid(item) for item in value.values())
    if isinstance(value, list):
        return all(_numbers_valid(item) for item in value)
    return True


def args_of(text):
    """One JSON object within the POST's own bounds; None otherwise."""
    try:
        value = json.loads(text, parse_constant=_reject, parse_int=_js_number, parse_float=_js_number)
    except (ValueError, RecursionError):
        return None
    if not isinstance(value, dict) or not keys_valid(value) or _depth(value) > MAX_DEPTH - 2:
        return None
    if not _numbers_valid(value):
        return None
    return value if len(canonical_value(value).encode("utf-8", "surrogatepass")) <= MAX_ARGS_BYTES else None


def say(line):
    """One report line to standard output."""
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


class RequestInput:
    """One handler submission: its operation, the checked arguments, the
    task's request context (None without one), a sticky abort of SIGINT,
    SIGTERM or SIGHUP, and `print`, one report line to stdout."""

    def __init__(self, operation, args, context, abort, print_line):
        self.operation = operation
        self.args = args
        self.context = context
        self.abort = abort
        self.print = print_line


def operation_shim(name, request):
    """The shim `NAME OPERATION [ARGS_JSON]` (default `{}`): one submission
    of `request(input)` with the arguments checked, the context read once
    and the terminal signals as its abort."""

    async def shim(argv):
        args = args_of(argv[1] if len(argv) == 2 else "{}") if len(argv) in (1, 2) else None
        if args is None or not is_word(argv[0]):
            sys.stderr.write("usage: %s OPERATION [ARGS_JSON]\n"
                             "ARGS_JSON: one JSON object of at most 60 KiB\n" % name)
            return CLIENT_USAGE
        abort, done = signalled(asyncio.get_running_loop())
        try:
            return await request(RequestInput(argv[0], args, context_from_environment(os.environ), abort, say))
        finally:
            done()

    return shim


def serve(argv, shims):
    """Runs the shim `argv` names (`shim NAME ARGS...`) to its end; returns
    its status. Each `shims[name](args)` is a coroutine."""
    mode = argv[0] if argv else None
    name = argv[1] if len(argv) > 1 else ""
    if mode == "shim" and name in shims:
        return asyncio.run(shims[name](argv[2:]))
    sys.stderr.write("usage: SHIM ARGS...\n")
    return CLIENT_USAGE
