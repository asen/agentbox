"""The process side of the supported Git command interface: the `git` shim
(git.py) runs it. The real Git for local pass-through is the fixed
/usr/bin/git, with this process's own standard streams, environment and
working directory: it is the guest's ordinary local Git, not intercepted and
not a security claim. SIGINT, SIGTERM or SIGHUP cancel a clone, fetch or
pull request (bytes already applied stay; a pull's own process group is
signalled); a local Git gets terminal signals itself and is awaited."""

import asyncio
import os

from acquisitions.git.jail.dispatch import run_git_command
from acquisitions.git.jail.output import report_line
from guest.src.abort import signalled
from guest.src.artifact_post_context import context_from_environment

# The fixed real Git; never looked up on PATH, which may hold the wrapper.
REAL_GIT = "/usr/bin/git"


async def pass_through(args):
    """The real Git with exactly `args`; its status, 128 + the signal's number when killed."""
    try:
        child = await asyncio.create_subprocess_exec(REAL_GIT, *args)
    except OSError:
        return 127
    code = await child.wait()
    return 128 - code if code < 0 else code


async def git_main(args):
    """One Git command with the request context of this process's
    environment, read once; awaited to its end, the handlers stay until it
    settled."""
    abort, done = signalled(asyncio.get_running_loop())
    try:
        # The report line is bounded: an unread stderr cannot hold this process.
        return await run_git_command(list(args), os.getcwd(), context_from_environment(os.environ), report_line,
                                     pass_through, abort, os.environ)
    finally:
        done()
