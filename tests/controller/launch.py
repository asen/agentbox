"""The controller's CLI with test seams, for subprocess tests:

  python3 -I -B launch.py SPEC.json ARG...

SPEC: {"dir": fake cgroup directory, "tools": {name: path},
       "faults": {FakeCgroups flag: value}, "overrides": {"module.NAME": value}}

The controller's own entry words (`jail shell-transport`'s ProxyCommand)
become this launcher and SPEC, so a transport runs with the same seams.
"""
import importlib
import json
import os
import sys

if __name__ == "__main__":
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path[:0] = [os.path.join(repo, "src"), repo]
    sys.dont_write_bytecode = True
    from agentbox_controller import cli, execute, shell
    from tests.controller.fakes import FakeCgroups

    shell.ENTRY = (os.path.abspath(__file__), os.path.abspath(sys.argv[1]))

    with open(sys.argv[1]) as stream:
        spec = json.load(stream)
    for name, value in spec.get("overrides", {}).items():
        module, attribute = name.rsplit(".", 1)
        setattr(importlib.import_module(f"agentbox_controller.{module}"), attribute, value)
    host = FakeCgroups(spec["dir"])
    for flag, value in spec.get("faults", {}).items():
        setattr(host, flag, value)
    sys.exit(cli.main(sys.argv[2:], system=execute.System(host, dict(spec["tools"]))))
