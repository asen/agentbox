"""A guest-local persistence marker: a diagnostic for the later stop/reboot
acceptance of a run's disk. `write` durably records a host-chosen token in a
fixed file of the guest user's private state directory; `check`, after a
reboot or resume, reports whether the same token is still there. It reads and
writes nothing else, and is run only as a guest command."""

import os
import stat

from guest.src.protocol import is_id

# The guest user's private Agentbox state directory.
MARKER_DIR = "/home/agentbox/.agentbox"
MARKER_FILE = "persistence-marker"
MARKER_SCHEMA = "agentbox.persistence-marker.v1"
MAX_MARKER_BYTES = 256


def _contents(token):
    return "%s %s\n" % (MARKER_SCHEMA, token)


def write_marker(directory, token):
    """Writes the token durably: a private temporary file, fsync, rename, fsync."""
    if not is_id(token):
        raise ValueError("invalid_token")
    os.makedirs(directory, 0o700, exist_ok=True)
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or (info.st_mode & 0o077) != 0:
        raise ValueError("marker_dir_invalid")
    temporary = os.path.join(directory, MARKER_FILE + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        data = _contents(token).encode("ascii")
        while data:
            data = data[os.write(fd, data):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(temporary, os.path.join(directory, MARKER_FILE))
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def check_marker(directory, token):
    """`present`, `absent` or `mismatch`; never follows a symlink."""
    if not is_id(token):
        raise ValueError("invalid_token")
    try:
        fd = os.open(os.path.join(directory, MARKER_FILE), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "mismatch"
    try:
        data = os.pread(fd, MAX_MARKER_BYTES + 1, 0)
    except OSError:
        return "mismatch"
    finally:
        os.close(fd)
    return "present" if data == _contents(token).encode("ascii") else "mismatch"


def marker_main(args, directory, say):
    """`write TOKEN` or `check TOKEN` against `directory`; prints one fixed
    status word and returns the exit status: 0 written or present, 1 absent or
    mismatch, 2 usage or failure."""
    if len(args) != 2 or not is_id(args[1]):
        say("persistence-marker: usage")
        return 2
    action, token = args
    try:
        if action == "write":
            write_marker(directory, token)
            say("persistence-marker: written")
            return 0
        if action == "check":
            state = check_marker(directory, token)
            say("persistence-marker: " + state)
            return 0 if state == "present" else 1
    except Exception:
        say("persistence-marker: failed")
        return 2
    say("persistence-marker: usage")
    return 2
