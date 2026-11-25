"""Copied-input setup (the host's crates/agentbox/src/inputs.rs). The host
uploads one tar archive its trusted worker made (inputs/stage.py) to a path
derived from its execution id alone, then sends `inputs_setup`. This adapter
has the guest's own tar extract it, with fixed arguments and environment,
into fresh private staging, then publishes each numbered slot at its planned
home-relative destination. It never runs archive contents and parses no
archive format itself. Nothing occupied is ever overwritten; an empty
directory is only rmdir'ed. Done means extracted and renamed, not synced:
disk durability is the ordinary disk lifecycle's. Nothing is retried; what a
failure leaves stays.

    staging/{plan, slots/0 .. slots/N-1}
    plan: "agentbox-inputs-v2\\n" then "d DEST\\n", "f DEST\\n" or "l DEST\\n"
          per slot: a directory tree, a regular file, or a symlink (its own
          text, never followed here or by the host)

The plan is checked whole (bounded, strict UTF-8, valid unreserved disjoint
destinations, exactly the staged slots of its kinds), then every destination
before anything is published: existing parents must be real directories
(never symlinks), a directory slot needs a missing or empty destination, a
file or link slot a missing one. Then each slot in plan order: missing
parents are created (shared by siblings, never replaced), a directory is
renamed into place, a file or link hard-linked (link(2) never follows a
symlink and never overwrites) and unlinked from staging. A directory is never
merged into occupied state. These pathname checks guard against mistakes,
not against this guest's own processes, which own the home anyway.
"""

import asyncio
import errno
import os
import stat

# The guest's own trusted tar, fixed.
TAR = "/usr/bin/tar"
TAR_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
# The archive's only top-level entries, sorted.
ROOTS = ("plan", "slots")
PLAN_HEADER = "agentbox-inputs-v2\n"
MAX_COPIES = 32
MAX_DESTINATION_BYTES = 1024
MAX_COMPONENT_BYTES = 255
MAX_PLAN_BYTES = len(PLAN_HEADER) + MAX_COPIES * (2 + MAX_DESTINATION_BYTES + 1)
# The setup's own names under the home: never a destination.
RESERVED_PREFIX = ".agentbox-inputs-"
# How often a running extraction checks that the session still wants it.
LIVE_POLL_S = 0.05


def archive_path(home, execution_id):
    """The uploaded archive, from the host's execution id alone (protocol id)."""
    return os.path.join(home, "%s%s.tar" % (RESERVED_PREFIX, execution_id))


def staging_path(home, execution_id):
    """Fresh private staging beside it; never reused."""
    return os.path.join(home, "%s%s.d" % (RESERVED_PREFIX, execution_id))


def tar_args(archive):
    """Extract only, into staging, owned by this user, permissions by umask."""
    return ["--extract", "--file", archive, "--no-same-owner", "--no-same-permissions", "--no-overwrite-dir"]


class _Child:
    def __init__(self, process):
        self.process = process

    async def wait(self):
        return await self.process.wait()

    def kill(self):
        try:
            self.process.kill()
        except ProcessLookupError:
            pass


async def spawn_tar(command, args, cwd, env):
    """The production extraction: a child whose `wait()` is its exit status
    (negative when signalled) and `kill()` its SIGKILL. Tests pass a double."""
    process = await asyncio.create_subprocess_exec(command, *args, cwd=cwd, env=env, stdin=asyncio.subprocess.DEVNULL,
                                                   stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    return _Child(process)


def _owned(uid):
    return uid == os.geteuid()


def _bytes(text):
    return len(text.encode("utf-8", "surrogatepass"))


def _control(text):
    """Control characters, as the host's `char::is_control` (Unicode Cc)."""
    return any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in text)


def valid_destination(text):
    """The host's `inputs::destination`: relative, bounded, unreserved."""
    if len(text) == 0 or _bytes(text) > MAX_DESTINATION_BYTES:
        return False
    valid = all(len(part) > 0 and part not in (".", "..") and _bytes(part) <= MAX_COMPONENT_BYTES and not _control(part)
                for part in text.split("/"))
    return valid and not text.startswith(RESERVED_PREFIX)


def _overlap(a, b):
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def parse_plan(plan):
    """The plan's slots in order, (destination, kind) pairs, or None for anything else."""
    if len(plan) > MAX_PLAN_BYTES:
        return None
    try:
        text = bytes(plan).decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.startswith(PLAN_HEADER) or not text.endswith("\n"):
        return None
    lines = text[len(PLAN_HEADER):-1].split("\n")
    if len(text) == len(PLAN_HEADER) or len(lines) > MAX_COPIES:
        return None
    slots = []
    for line in lines:
        kind, destination = line[:2], line[2:]
        if kind not in ("d ", "f ", "l ") or not valid_destination(destination):
            return None
        if any(_overlap(existing, destination) for existing, _ in slots):
            return None
        slots.append((destination, kind[0]))
    return slots


async def setup_inputs(home, execution_id, live, spawn=spawn_tar):
    """True once every slot is published; False on any refusal or failure.
    `live()` turns False once the session no longer wants the setup."""
    try:
        return await _setup(home, execution_id, live, spawn)
    except Exception:
        return False


async def _setup(home, execution_id, live, spawn):
    archive = archive_path(home, execution_id)
    staging = staging_path(home, execution_id)
    upload = os.lstat(archive)
    if not stat.S_ISREG(upload.st_mode) or not _owned(upload.st_uid):
        return False
    os.mkdir(staging, 0o700)
    if not live() or not await _extract(spawn, archive, staging, live) or not live():
        return False
    if sorted(os.listdir(staging)) != list(ROOTS):
        return False
    slots = _staged_slots(staging)
    if slots is None:
        return False
    # Every destination checked before anything is published.
    for slot in slots:
        if not _available(home, slot):
            return False
    for index, slot in enumerate(slots):
        if not live():
            return False
        _publish(os.path.join(staging, "slots", str(index)), home, slot)
    os.rmdir(os.path.join(staging, "slots"))
    os.unlink(os.path.join(staging, "plan"))
    os.rmdir(staging)
    try:
        os.unlink(archive)
    except OSError:
        pass
    return live()


def _staged_slots(staging):
    """The staged plan, checked against exactly the staged slots."""
    plan_path = os.path.join(staging, "plan")
    plan = os.lstat(plan_path)
    if not stat.S_ISREG(plan.st_mode) or not _owned(plan.st_uid) or plan.st_size > MAX_PLAN_BYTES:
        return None
    with open(plan_path, "rb") as stream:
        slots = parse_plan(stream.read(MAX_PLAN_BYTES + 1))
    slots_dir = os.lstat(os.path.join(staging, "slots"))
    if slots is None or not stat.S_ISDIR(slots_dir.st_mode) or not _owned(slots_dir.st_uid):
        return None
    if sorted(os.listdir(os.path.join(staging, "slots"))) != sorted(str(index) for index in range(len(slots))):
        return None
    for index, (_destination, kind) in enumerate(slots):
        staged = os.lstat(os.path.join(staging, "slots", str(index)))
        shaped = {"d": stat.S_ISDIR, "f": stat.S_ISREG, "l": stat.S_ISLNK}[kind](staged.st_mode)
        if not _owned(staged.st_uid) or not shaped:
            return None
    return slots


def _available(home, slot):
    """Existing parents are real directories; the destination is free for its kind."""
    destination, kind = slot
    path = home
    for part in destination.split("/")[:-1]:
        path = os.path.join(path, part)
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return True
        if not stat.S_ISDIR(info.st_mode):
            return False
    state = _vacant(os.path.join(home, destination))
    return state is not False if kind == "d" else state == "missing"


def _publish(staged, home, slot):
    """Creates missing parents, then publishes without replacing anything."""
    destination, kind = slot
    path = home
    for part in destination.split("/")[:-1]:
        path = os.path.join(path, part)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            raise OSError(errno.ENOTDIR, "parent")
    target = os.path.join(home, destination)
    if kind != "d":
        # Fails if anything is there, unlike rename; a symlink is linked
        # itself, never its target.
        os.link(staged, target, follow_symlinks=False)
        os.unlink(staged)
        return
    state = _vacant(target)
    if state is False:
        raise OSError(errno.EEXIST, "occupied")
    if state == "empty":
        os.rmdir(target)
    # Fails onto anything but a missing or empty directory: never a merge.
    os.rename(staged, target)


def _vacant(path):
    """`missing`, or `empty` (an empty directory of this user); False for anything occupied."""
    try:
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or not _owned(info.st_uid):
            return False
        return "empty" if not os.listdir(path) else False
    except FileNotFoundError:
        return "missing"
    except OSError:
        return False


async def _extract(spawn, archive, staging, live):
    """Runs tar to its exit; killed and reaped if the session stops wanting it."""
    try:
        child = await spawn(TAR, tar_args(archive), staging, dict(TAR_ENV))
    except Exception:
        return False
    lost = False
    waiting = asyncio.ensure_future(child.wait())
    try:
        while True:
            done, _ = await asyncio.wait({waiting}, timeout=LIVE_POLL_S)
            if done:
                break
            if not live() and not lost:
                lost = True
                child.kill()
        try:
            code = waiting.result()
        except Exception:
            return False
    finally:
        if not waiting.done():
            child.kill()
            await asyncio.shield(waiting)
    return code == 0 and not lost
