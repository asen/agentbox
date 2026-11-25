"""Fixture-only exec shim, always beneath git_fixture_server.py own.

Redirect Git's data/diagnostics into exclusive, file-backed captures. The
owner's line relay is not a binary/data channel. No fork, subprocess, thread,
listener or background work: exec preserves the owner's anchored leader.
Captures may grow without bound; only their inspection has bounded state.
"""
import os
import sys

out, err, *args = sys.argv[1:]
if not args or args[0] != "/usr/bin/git":
    raise SystemExit(2)
for target, path in [(1, out), (2, err)]:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.dup2(fd, target)
    if fd != target:
        os.close(fd)
os.execve(args[0], args, os.environ)
