"""The pip handler's jail module: its session wrapper, which the guest
puts before every command of an execution or shell that enables the
handler (`bin/agentbox-session`, acquisitions/contracts/handlers/v1):

    agentbox-session [--status=FD] ARGV...
      without a request context, or inside another session
      (AGENTBOX_PIP_INDEX set): ARGV as is, nothing more
      otherwise: one loopback index (index.py) in a detached sidecar, then
        ARGV replaces this process with the environment it was given plus
          PIP_INDEX_URL=http://127.0.0.1:PORT/simple/  PIP_RETRIES=0
          PIP_TIMEOUT=1860  no_proxy, NO_PROXY += 127.0.0.1,localhost
          AGENTBOX_PIP_INDEX=http://127.0.0.1:PORT/

Every pip of the command and its children (an activated or bare venv's
`pip`, `python -m pip`, pip's own isolated build environments) reads its
index from that environment; pip resolves, builds source distributions and
runs their build hooks in the jail as it always does. Defaults, not a
boundary: a command line or configuration naming another index reaches past
the adapter to the broker, whose policy applies as to any guest process.

The command keeps this process: its pid, argv, descriptors, terminal,
process group and session, signal dispositions (SIGPIPE and SIGXFSZ back
to their defaults, as for any spawned command) and exit status. Its
environment is the one this process received (/proc/self/environ: nothing
of Python's own start-up), plus the variables above. The sidecar is a
double-forked process in a session of its own, with no terminal and
/dev/null for its standard descriptors, holding nothing of the command's;
it serves until the command's process ends (its pidfd), then aborts an
active host request, closes its batches and exits; their files are
unnamed (index.py), so a sidecar killed first (its container removed)
leaves nothing. An index that cannot start leaves the command to run
without it, after one line on stderr.

`--status=FD` (the guest's anchor, acquisitions/contracts/handlers/v1): `r` on FD just
before the exec, `f` if it fails; FD is close-on-exec, so the command never
holds it. A failed exec is then the anchor's failed start, and nothing is
printed. Without it (the interactive form), a failed exec prints one line
and exits 127, as the guest's own `command not run` does."""

if __name__ == "__main__":
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import asyncio
import os
import re
import select
import signal
import sys
import time

from acquisitions.pip.jail.index import KEY_WAIT, Adapter, fetch_batch
from guest.src.artifact_post_context import context_from_environment

ADAPTER_ENV = "AGENTBOX_PIP_INDEX"
SESSION = "session"
# pip's socket timeout, past the adapter's KEY_WAIT: the adapter answers first.
TIMEOUT_SECONDS = int(KEY_WAIT) + 60
LOOPBACK = ("127.0.0.1", "localhost")
# The sidecar's port line, at most this long after the fork.
START_TIMEOUT = 10
# Without a pidfd: how often the sidecar looks for the command.
POLL_SECONDS = 0.5
USAGE = 2
NOT_RUN = 127
STATUS = re.compile(r"--status=([1-9][0-9]{0,6})")


def report(line):
    try:
        os.write(2, ("agentbox-session: %s\n" % line).encode())
    except OSError:
        pass


def initial_environment():
    """The environment this process was started with, as the kernel holds
    it; os.environ if that cannot be read."""
    try:
        with open("/proc/self/environ", "rb") as stream:
            data = stream.read()
    except OSError:
        return dict(os.environ)
    env = {}
    for item in data.split(b"\0"):
        name, sep, value = item.partition(b"=")
        if sep and name:
            env.setdefault(os.fsdecode(name), os.fsdecode(value))
    return env


def session_environment(env, url):
    """`env` with the index's variables (module documentation)."""
    child = dict(env)
    child.update({"PIP_INDEX_URL": url + "simple/", "PIP_RETRIES": "0", "PIP_TIMEOUT": str(TIMEOUT_SECONDS),
                  ADAPTER_ENV: url})
    for name in ("no_proxy", "NO_PROXY"):
        hosts = [host for host in child.get(name, "").split(",") if host.strip()]
        child[name] = ",".join(hosts + [host for host in LOOPBACK if host not in hosts])
    return child


def tell(status, word):
    if status is not None:
        try:
            os.write(status, word)
        except OSError:
            pass


def run(argv, env, status=None):
    """ARGV replaces this process; returns only on failure."""
    tell(status, b"r")
    for number in (signal.SIGPIPE, signal.SIGXFSZ):
        signal.signal(number, signal.SIG_DFL)
    try:
        os.execvpe(argv[0], argv, env)
    except OSError:
        pass
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    if status is None:
        report("command not run")
    tell(status, b"f")
    return NOT_RUN


# The sidecar.

async def serve(port_fd, target, context):
    """The index until `target` (the command's pid) ends; the port, once
    listening, on `port_fd`."""
    loop = asyncio.get_running_loop()
    adapter = Adapter(lambda operation, args, abort: fetch_batch(context, adapter.spool, operation, args, abort))
    done = loop.create_future()

    def end():
        if not done.done():
            done.set_result(None)

    watch = None
    try:
        await adapter.start()
        try:
            watch = os.pidfd_open(target)
            loop.add_reader(watch, end)
        except (AttributeError, OSError):
            watch = None
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            loop.add_signal_handler(number, end)
        os.write(port_fd, b"%d\n" % adapter.port)
        os.close(port_fd)
        if watch is not None:
            await done
        while watch is None and not done.done():
            try:
                os.kill(target, 0)
            except ProcessLookupError:
                break
            except OSError:
                pass
            await asyncio.wait([done], timeout=POLL_SECONDS)
    finally:
        if watch is not None:
            loop.remove_reader(watch)
            os.close(watch)
        await adapter.close()


def sidecar(port_fd, target, context):
    """The grandchild: no terminal, no descriptor of the command's."""
    null = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(null, fd)
    keep = {0, 1, 2, port_fd}
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd not in keep:
            try:
                os.close(fd)
            except OSError:
                pass
    asyncio.run(serve(port_fd, target, context))


def start(context):
    """The sidecar's index URL, or None."""
    target = os.getpid()
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        status = 1
        try:
            os.close(read_end)
            os.setsid()
            if os.fork() == 0:
                sidecar(write_end, target, context)
            status = 0
        except BaseException:
            pass
        finally:
            os._exit(status)
    os.close(write_end)
    try:
        os.waitpid(pid, 0)
        data, until = b"", time.monotonic() + START_TIMEOUT
        while b"\n" not in data and len(data) < 16:
            left = until - time.monotonic()
            if left <= 0 or not select.select([read_end], [], [], left)[0]:
                break
            chunk = os.read(read_end, 16)
            if not chunk:
                break
            data += chunk
    finally:
        os.close(read_end)
    port = data[:-1] if data.endswith(b"\n") else b""
    if not port.isdigit() or not 0 < int(port) < 65536:
        return None
    return "http://127.0.0.1:%d/" % int(port)


def session(argv):
    status = None
    found = STATUS.fullmatch(argv[0]) if argv else None
    if found is not None:
        status, argv = int(found.group(1)), argv[1:]
        try:
            os.set_inheritable(status, False)
        except OSError:
            status = None
    if not argv:
        sys.stderr.write("usage: agentbox-session ARGV...\n")
        return USAGE
    env = initial_environment()
    context = context_from_environment(env)
    if context is not None and not env.get(ADAPTER_ENV):
        url = start(context)
        if url is None:
            report("pip index unavailable")
        else:
            env = session_environment(env, url)
    return run(argv, env, status)


def main(argv):
    if argv and argv[0] == SESSION:
        return session(argv[1:])
    sys.stderr.write("usage: %s ARGV...\n" % SESSION)
    return USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
