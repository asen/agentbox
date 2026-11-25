"""The supplied-jail worker profile (docs/ssh-worker.md): how the launcher the
host's bootstrap writes (crates/agentbox/src/runtime/bootstrap.rs) invokes
this helper. Pure: parsing only, no file or process access.

    launcher -> PYTHON -I -S -B -X utf8 main.py supplied-session-v3 HOME WORK WRAPPER_BIN
    shell    -> ... supplied-session-v3 HOME WORK WRAPPER_BIN shell TERM SESSION [ARG...]
    mounted  -> ... supplied-mounted-v1 HOME WORK WRAPPER_BIN MOUNT [shell TERM SESSION [ARG...]]

Exactly the profile word and three distinct plain absolute paths: the command
environment's HOME, the private working directory and the installation's
directory of host-generated wrappers. Any other argument count or path is
refused. The mounted form adds MOUNT, the root of the host mount holding
the working directory (WORK equal to or beneath it, strictly beneath HOME):
there the working directory's checks admit the host's ordinary modes
(execution.py `prepare_work_dir`). The interactive form (`agentbox shell`, an
ordinary SSH login with a PTY; an interactive agent's staging, terminal and
unstaging) adds the word `shell`, the host's terminal type, the serving
owner's current session nonce (its request context with WORK and MOUNT,
artifact_post_context.py; a correlation id, no secret or grant) and the
command, if any. The worker's modules need not live in the installation (an image
bakes them, read-only, at /opt/agentbox/worker), so the directory is the
host's explicit argument, never derived from a module's path. The session
then runs as the QEMU one does; the jail's lifecycle is the operator's. No
coding agent, credential, interpreter or other directory is discovered here.
"""

import re

from guest.src.artifact_post_protocol import is_session

# The launcher's fixed profile argument.
SUPPLIED_SESSION = "supplied-session-v3"
# Its form with a host mount's root (crates/agentbox/src/runtime/bootstrap.rs).
SUPPLIED_MOUNTED = "supplied-mounted-v1"
# The interactive form's word after the paths.
SHELL = "shell"
# The longest path accepted, as the host's transport paths.
MAX_PATH_BYTES = 4096

_PLAIN = re.compile(r"[A-Za-z0-9._/-]+")
# A terminal type as the host validates it (crates/agentbox/src/shell.rs).
_TERM = re.compile(r"[A-Za-z0-9._+-]{1,64}")


def is_plain_absolute(path):
    """Absolute and normalized, `[A-Za-z0-9._/-]` only, not the root."""
    if not isinstance(path, str) or len(path) > MAX_PATH_BYTES or _PLAIN.fullmatch(path) is None:
        return False
    if not path.startswith("/"):
        return False
    return all(part not in ("", ".", "..") for part in path[1:].split("/"))


def within(inner, outer):
    """Whether path `inner` is `outer` or beneath it, by component."""
    return inner == outer or inner.startswith(outer + "/")


def _arity(args):
    """The profile's argument count, its word included; None for no profile."""
    if args and args[0] == SUPPLIED_SESSION:
        return 4
    if args and args[0] == SUPPLIED_MOUNTED:
        return 5
    return None


def supplied_session(args):
    """The supplied profile's paths {home, work_dir, wrapper_bin, mount}, or
    None for any other invocation. `wrapper_bin` is the installation's
    `bin/`: the host-generated wrappers (`agentbox-request`, and a handler's
    shims only where the host enabled them), first on the command's PATH.
    `mount` is the mounted form's MOUNT, else None."""
    if _arity(args) is None or len(args) != _arity(args):
        return None
    paths = list(args[1:4])
    if not all(is_plain_absolute(path) for path in paths) or len(set(paths)) != len(paths):
        return None
    home, work_dir, wrapper_bin = paths
    mount = args[4] if len(args) == 5 else None
    if mount is not None and not (is_plain_absolute(mount) and mount != home and within(mount, home)
                                  and within(work_dir, mount) and not within(wrapper_bin, mount)):
        return None
    return {"home": home, "work_dir": work_dir, "wrapper_bin": wrapper_bin, "mount": mount}


def shell_session(args):
    """The interactive form's {home, work_dir, wrapper_bin, mount, term,
    session, argv}, or None for any other invocation. `argv` is empty for
    the account's own shell."""
    count = _arity(args)
    if count is None or len(args) < count + 3 or args[count] != SHELL \
            or _TERM.fullmatch(args[count + 1]) is None or not is_session(args[count + 2]):
        return None
    paths = supplied_session(args[:count])
    if paths is None:
        return None
    return dict(paths, term=args[count + 1], session=args[count + 2], argv=list(args[count + 3:]))
