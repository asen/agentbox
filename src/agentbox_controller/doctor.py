"""`doctor`: local prerequisite presence checks (the old CLI's doctor.rs).

```text
platform     linux on x86_64                              required
python       this interpreter >= 3.12                    required
             (the host code's: PEP 701 f-strings, hashlib.file_digest)
ssh ssh-keygen scp sftp   on the captured PATH            required
cgroup2      /sys/fs/cgroup/cgroup.controllers a file     managed runs only
server       the configured (or packaged) agentbox-server: ok, missing,
             untrusted or unconfigured (a source tree without one)   required
```

Presence only: file metadata through the same PATH lookup every command
uses; nothing is executed, so versions, delegation, providers, images and
targets are not checked. cgroup2 is reported but fails nothing: attached
runs need no delegation. Exit 0 when every required check is ok.
"""
import os
import platform
import sys

from .config import check_server, config_path, load_controller
from .host import HostError, find_tool

TOOLS = ("ssh", "ssh-keygen", "scp", "sftp")
CGROUP2_CONTROLLERS = "/sys/fs/cgroup/cgroup.controllers"
MIN_PYTHON = (3, 12)


def facts(config=None, environ=None, find=find_tool, controllers=CGROUP2_CONTROLLERS, prefix=None):
    """[(name, status, required)]: status ok, missing or unsupported."""
    def present(name):
        try:
            find(name)
            return "ok"
        except HostError:
            return "missing"

    checks = [("platform", "ok" if sys.platform.startswith("linux") and platform.machine() == "x86_64"
               else "unsupported", True),
              ("python", "ok" if sys.version_info[:2] >= MIN_PYTHON else "unsupported", True)]
    checks += [(name.replace("-", "_"), present(name), True) for name in TOOLS]
    checks.append(("cgroup2", "ok" if os.path.isfile(controllers) else "missing", False))
    if environ is not None:
        try:
            path, explicit = config_path(config, environ)
            check_server(load_controller(path, environ, prefix, explicit)["server"])
            status = "ok"
        except HostError as error:
            status = {"server_unconfigured": "unconfigured", "server_untrusted": "untrusted"}.get(
                error.code, "missing" if error.code == "server_missing" else "config_invalid")
        checks.append(("server", status, True))
    return checks


def main(config, environ, say, prefix=None):
    checks = facts(config, environ, prefix=prefix)
    for name, status, required in checks:
        say(f"{name}: {status}" + ("" if required else " (managed runs only)") + "\n")
    say("note: presence only; delegation, providers, images and targets are not checked\n")
    return 0 if all(status == "ok" for _, status, required in checks if required) else 1
