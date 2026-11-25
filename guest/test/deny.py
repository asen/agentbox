"""Process denial for in-process library tests: while installed, every child
this process would start is refused unless `allow(program)` says otherwise;
counted, raised before anything runs. asyncio children go through the same
Popen. One module's guard: installed in its setUpModule, released in its
tearDownModule."""

import os
import subprocess

_original = subprocess.Popen._execute_child


class ProcessDenial:
    def __init__(self, allow):
        self.allow = allow
        self.denied = 0

    def release(self):
        """Restores process creation; returns the denials counted."""
        subprocess.Popen._execute_child = _original
        return self.denied


def deny_processes(allow=None):
    """Installs a fresh denial, replacing any other; `allow` none by default."""
    guard = ProcessDenial(allow or (lambda program: False))

    def guarded(popen, args, executable, *rest, **kwargs):
        program = os.fsdecode(executable or (args[0] if isinstance(args, (list, tuple)) else args))
        if not guard.allow(program):
            guard.denied += 1
            raise PermissionError("process creation denied by the test guard")
        return _original(popen, args, executable, *rest, **kwargs)

    subprocess.Popen._execute_child = guarded
    return guard
