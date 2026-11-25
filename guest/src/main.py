"""The guest helper's entrypoint, as the launcher runs it (`PYTHON -I -S -B -X utf8
main.py ...`; /usr/local/bin/agentbox-guest in the QEMU image).

Without arguments, as the host's SSH session always runs it: one protocol
session on stdin/stdout in the fixed working directory; SIGTERM or SIGHUP
count as the loss of the host's input and end the running command first.
With `persistence-marker write|check TOKEN`, as a guest command: the marker
diagnostic in the fixed state directory.
With `supplied-session-v3 HOME WORK WRAPPER_BIN`, as a supplied jail's or a
managed image's launcher runs it (worker_profile.py): the same session with
those explicit paths. With `... shell TERM SESSION [ARG...]`, as `agentbox
shell`'s SSH login (and an interactive agent's) runs it: no protocol
session, the command (else the account's own shell, interactive, not a
login shell) replaces this process, with the serving owner's request
context. Nothing else is accepted.
"""

if __name__ == "__main__":
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
import os
import signal
import sys

from guest.src.abort import Abort
from guest.src.artifact_post_context import request_context
from guest.src.execution import (
    GUEST_HOME, WORK_DIR, SessionOptions, command_environment, prepare_work_dir, run_session, session_argv,
)
from guest.src.persistence_marker import MARKER_DIR, marker_main
from guest.src.worker_profile import is_plain_absolute, shell_session, supplied_session

# The fallback of an account without a usable shell.
DEFAULT_SHELL = "/bin/sh"


async def _session(work_dir, home, wrapper_bin=None, mount=None):
    loop = asyncio.get_running_loop()
    abort = Abort()
    for number in (signal.SIGTERM, signal.SIGHUP):
        loop.add_signal_handler(number, abort.abort)
    return await run_session(SessionOptions(0, 1, work_dir, home, wrapper_bin=wrapper_bin, abort=abort,
                                            mount=mount))


def account_shell():
    """The account's own shell: its passwd entry's, if plain absolute."""
    import pwd

    try:
        login = pwd.getpwuid(os.getuid()).pw_shell
    except KeyError:
        return DEFAULT_SHELL
    return login if is_plain_absolute(login) else DEFAULT_SHELL


def shell(profile, execvpe=None):
    """The interactive form: a task's fixed environment (wrappers, system,
    then HOME/.local/bin; the broker's proxy; the request context of the
    serving owner's session nonce, the launcher's WORK and MOUNT) with the
    host's terminal type, in the private working directory; nothing of the
    SSH login's is kept. Then ARG..., else the account's shell with `-i`,
    replaces this process (behind the installation's session wrapper, if
    any: execution.py `session_argv`), with Python's ignored signals
    restored. Returns only on failure."""
    context = request_context(profile["session"], profile["work_dir"], profile["mount"])
    if context is None:
        print("agentbox-shell: request context refused", file=sys.stderr)
        return 1
    env = command_environment(profile["home"], context, profile["wrapper_bin"])
    env["TERM"] = profile["term"]
    if not prepare_work_dir(profile["work_dir"], profile["home"], profile["mount"]):
        print("agentbox-shell: working directory refused", file=sys.stderr)
        return 1
    os.chdir(profile["work_dir"])
    argv = session_argv(profile["wrapper_bin"], profile["argv"] or [account_shell(), "-i"], env,
                        profile["work_dir"])
    for number in (signal.SIGPIPE, signal.SIGXFSZ):
        signal.signal(number, signal.SIG_DFL)
    try:
        (execvpe or os.execvpe)(argv[0], argv, env)
    except OSError:
        print("agentbox-shell: command not run", file=sys.stderr)
        return 127
    return 127


def main(args):
    interactive = shell_session(args)
    if interactive is not None:
        return shell(interactive)
    supplied = supplied_session(args)
    if supplied is not None:
        return asyncio.run(_session(supplied["work_dir"], supplied["home"], supplied["wrapper_bin"],
                                    supplied["mount"]))
    if not args:
        return asyncio.run(_session(WORK_DIR, GUEST_HOME))
    if args[0] == "persistence-marker":
        return marker_main(args[1:], MARKER_DIR, lambda line: print(line, flush=True))
    return 2


if __name__ == "__main__":
    # As any program: an interrupt ends it by the signal.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    sys.exit(main(sys.argv[1:]))
