"""Test-only handler `fake` (controller tests; never packaged): an `http`
metered worker reading nothing upstream, its behavior chosen by its args.

    fetch {"size": N, "acquired": N[, "mode": M][, "packages": N]}
      ok        the artifact: N bytes; `acquired` counted on the meter
      error     a worker denial `fake_denied`, `acquired` counted
      crash     no line (exit 7)
      sleep     never answers (killed at its deadline or a cancel)
      overclaim a line claiming more than its allowance
      perms     the artifact left 0644 (not private)
      wrongsize a size one byte off
      linked    a second link to the artifact
      spawn     a background child left in its own session, then ok
      metadata  metadata of N bytes (`size` used as its length)
      fds       the metadata counts its own open descriptors above 2
      exit7     ok's valid line (and packages), then exit 7
      killed    ok's valid line (and packages), then SIGKILL of itself
      pinned    a file left in its stage, the stage made 0500 (its removal
                fails), then a denial `fake_denied`
"""

import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "lib"))

import agentbox_handler as handler  # noqa: E402
from agentbox_handler import ARTIFACT_FILE, RESULT_SCHEMA, Refused  # noqa: E402


# Set by `exit7` and `killed`: how the process ends after its line.
AFTER = []


def fetch(request):
    args = request.args
    mode = args.get("mode", "ok")
    if mode in ("exit7", "killed"):
        AFTER.append(mode)
    acquired = args.get("acquired", 0)
    room = request.meter.room(acquired)
    request.meter.take(room)
    if mode == "error":
        raise Refused("fake_denied")
    if mode == "crash":
        os._exit(7)
    if mode == "pinned":
        stage = handler.open_stage(request)
        os.close(handler.create(stage, "pin"))
        os.fchmod(stage, 0o500)
        os.close(stage)
        raise Refused("fake_denied")
    if mode == "sleep":
        time.sleep(1000)
    if mode == "overclaim":
        handler.emit([("outcome", "error"), ("code", "fake_denied"),
                      ("acquired", request.meter.allowance + 1)])
        os._exit(0)
    if mode == "spawn":
        subprocess.Popen(["sleep", "1000"], start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    size = args.get("size", 1)
    data = b"f" * size
    stage = handler.open_stage(request)
    try:
        fd = handler.create(stage, ARTIFACT_FILE)
        try:
            sink = handler.Sink(fd)
            sink.write(data)
            size, sha256 = sink.finish()
        finally:
            os.close(fd)
        if mode == "perms":
            os.chmod(ARTIFACT_FILE, 0o644, dir_fd=stage)
        if mode == "linked":
            os.link(ARTIFACT_FILE, "second", src_dir_fd=stage, dst_dir_fd=stage)
    finally:
        os.close(stage)
    if mode == "wrongsize":
        size += 1
    metadata = {"length": size}
    if mode == "metadata":
        metadata = {"pad": "x" * args.get("size", 1)}
    if mode == "fds":
        metadata = {"fds": len([fd for fd in os.listdir("/proc/self/fd") if int(fd) > 2]) - 1}
    packages = [{"name": f"pkg-{i}", "version": "1.0.0", "integrity": "sha512-" + "A" * 86 + "=="}
                for i in range(args.get("packages", 0))]
    return (size, sha256, metadata, packages) if packages else (size, sha256, metadata)


if __name__ == "__main__":
    assert RESULT_SCHEMA
    code = handler.main({"fetch": fetch, "denied-op": fetch})
    if AFTER == ["exit7"]:
        os._exit(7)
    if AFTER == ["killed"]:
        os.kill(os.getpid(), signal.SIGKILL)
    sys.exit(code)
