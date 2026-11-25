"""The jail's Python, as this process was started: every module child the
worker starts (the group anchor, a handler's jail module) runs on this same
interpreter, isolated, with no site, user or environment search and no
bytecode written. The interpreter is the launcher's choice (an attached
target's explicit `python`, else `python3` on the controlled PATH); nothing
here looks for another or checks its version."""

import sys

# Isolated (no environment, user site or script directory on the path), no
# `site` (no system site-packages or .pth files), no bytecode written, UTF-8
# mode: the launcher's own flags (runtime/bootstrap.rs PYTHON_FLAGS).
FLAGS = ("-I", "-S", "-B", "-X", "utf8")


def python_argv(script, *args):
    """This interpreter on `script` with `args`; ValueError without one."""
    if not sys.executable:
        raise ValueError("no interpreter")
    return [sys.executable, *FLAGS, script, *args]
