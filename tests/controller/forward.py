"""Test-only front (`PYTHON -I -S -B -X utf8 forward.py ENTRY ARG...`) of the
production `agentbox-request` command and handler shims, run unmodified as
the bootstrap's wrappers name them (ssh_standin.py rewrites only their
interpreter line). The guest port 18080 is never bound here: the session's
reverse forward is emulated on an ephemeral port (HOME/.agentbox-test-forward).
A connection to exactly 127.0.0.1:18080 goes there; each module child the
command starts (runtime.python_argv) runs behind this front too."""

import asyncio
import os
import re
import runpy
import sys

ENTRY = re.compile(r"(/.+?)/(?:guest/src|acquisitions/[a-z0-9-]+/jail)/[^/]+\.py")
HERE = os.path.abspath(__file__)

entry = sys.argv[1]
root = ENTRY.fullmatch(entry).group(1)
sys.path.insert(0, root)

import guest.src.runtime as runtime  # noqa: E402

original_argv = runtime.python_argv
runtime.python_argv = lambda script, *args: original_argv(HERE, script, *args)
original_connect = asyncio.base_events.BaseEventLoop.create_connection


async def create_connection(self, factory, host=None, port=None, **options):
    if host == "127.0.0.1" and port == 18080:
        with open(os.path.join(os.environ.get("HOME", ""), ".agentbox-test-forward")) as stream:
            port = int(stream.read())
    return await original_connect(self, factory, host, port, **options)


asyncio.base_events.BaseEventLoop.create_connection = create_connection
sys.argv = sys.argv[1:]
runpy.run_path(entry, run_name="__main__")
