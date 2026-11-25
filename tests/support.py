"""What both host suites share (never packaged): the checkout's paths, SRC
on the path (`agentbox_controller`, `agentbox_server`), the built
agentbox-relay and a private copy of the transport server."""
import atexit
import os
import shutil
import sys
import tempfile

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
SRC = os.path.join(REPO, "src")
BUILT_RELAY = os.path.join(REPO, "target", "debug", "agentbox-relay")

if SRC not in sys.path:
    sys.path.insert(0, SRC)

_SERVER = {}


def server():
    """A private copy of the transport server, once per process (0700,
    removed at exit), laid out as packaged: the `agentbox-server` launcher
    and the built `agentbox-relay` (0755) beside its `agentbox_server`
    package. A checkout is group writable under umask 002, which the
    controller refuses."""
    if "path" not in _SERVER:
        directory = tempfile.mkdtemp(prefix="abs-")
        atexit.register(shutil.rmtree, directory, True)
        shutil.copyfile(os.path.join(SRC, "agentbox-server"), os.path.join(directory, "agentbox-server"))
        shutil.copytree(os.path.join(SRC, "agentbox_server"), os.path.join(directory, "agentbox_server"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copyfile(relay(), os.path.join(directory, "agentbox-relay"))
        for name in ("agentbox-server", "agentbox-relay"):
            os.chmod(os.path.join(directory, name), 0o755)
        _SERVER["path"] = os.path.join(directory, "agentbox-server")
    return _SERVER["path"]


def relay():
    """The built agentbox-relay, used in place: its launcher checks nothing
    of its file."""
    if not os.path.exists(BUILT_RELAY):
        raise RuntimeError("target/debug/agentbox-relay missing: cargo build --bin agentbox-relay")
    return BUILT_RELAY
