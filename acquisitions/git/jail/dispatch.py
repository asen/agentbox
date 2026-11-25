"""The supported Git command interface (acquisitions/git/contract/v1): the `git` shim
(git.py) an enabled git handler's manifest names. The items after `git` are
classified by the frozen G0 table (`classify_git_command`), never as shell
text:

  local       the real Git runs them as given, here and now; not intercepted
  push        refused at once with a fixed code: no host is contacted,
              whether or not a request context exists
  refused     unsupported remote forms and options: a fixed code, and never
              a fallback to network Git
  clone       `[-C DIR] clone [--branch NAME] [FLAG...] URL [DEST]`: the
              canonical repository (and selector) goes to the host; the
              destination and pip's flags (command.py CLONE_FLAGS) stay
              guest-local
  fetch       `[-C DIR] fetch [REMOTE]`: only with the task's request
              context, the remote's one configured URL is read guest-locally
              (G3's `resolve_remote`, staging in the context's Git upload
              directory) and only its canonical repository goes to the host
  pull        `[-C DIR] pull [--ff-only | --rebase | --no-rebase]`: as a
              fetch of the current branch's upstream remote
              (`resolve_upstream`), then stock `git pull` from the verified
              delivery (pull.py); Git's own exit status

A clone, fetch or pull is one git handler submission (request_client.py; a
pull submits the host's `fetch`) and one G3 application of its delivery. No host path, argv, environment, URL, remote
name or ref reaches the host. Classification is usability, not a security
boundary: aliases, scripts and `/usr/bin/git` bypass it and gain no route.
"""

import os

from acquisitions.git.jail.application import resolve_remote, resolve_upstream
from acquisitions.git.jail.command import classify_git_command
from acquisitions.git.jail.request_client import git_layout, run_git_client
from guest.src.artifact_post_clock import capture_request_deadline
from guest.src.artifact_post_context import prepare_upload_dir
from guest.src.protocol import js_json

# A refused form: no request was formed.
EXIT_REFUSED = 1
# No request context, or the local preparation failed: nothing was sent.
EXIT_UNAVAILABLE = 3


class DispatchSeams:
    """Library tests only: the request client and the remote and upstream resolutions."""

    def __init__(self, client, resolve, upstream=resolve_upstream):
        self.client = client
        self.resolve = resolve
        self.upstream = upstream


PRODUCTION = DispatchSeams(run_git_client, resolve_remote)


def git_report_line(report):
    """One compact local line of the four fixed fields; no path, URL, ref or diagnostic."""
    fields = {"ok": report["ok"], "code": report["code"]}
    if "reason" in report:
        fields["reason"] = report["reason"]
    fields["changes"] = report["changes"]
    fields["cleanup"] = report["cleanup"]
    return "agentbox-request: git " + js_json(fields)


def _refusal(code):
    return {"ok": False, "code": code, "changes": "none", "cleanup": "observed"}


async def run_git_command(args, cwd, context, report, pass_through, abort=None, environ=None):
    """Runs one Git command; returns its exit status. `report` gets one
    compact line; `pass_through(args)` runs the real Git with exactly these
    items and returns its status. `environ` locates a pull's global Git
    configuration (HOME, XDG_CONFIG_HOME, GIT_CONFIG_GLOBAL) and nothing else."""
    return await run_git_command_with(PRODUCTION, args, cwd, context, report, pass_through, abort, environ)


async def run_git_command_with(seams, args, cwd, context, report, pass_through, abort=None, environ=None):
    command = classify_git_command(args)
    if command["kind"] == "local":
        return await pass_through(args)

    def say(outcome):
        report(git_report_line(outcome))

    if command["kind"] == "refused":
        say(_refusal(command["code"]))
        return EXIT_REFUSED
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        say(_refusal("git_client_invalid"))
        return EXIT_UNAVAILABLE
    # The request's original clock, before any lookup or local read.
    deadline = capture_request_deadline()
    base = os.path.normpath(os.path.join(cwd, command.get("cwd", ".")))
    common = {"context": context, "report": say, "deadline": deadline, "abort": abort}
    if command["kind"] == "clone":
        return await seams.client(operation="clone", repository=command["repository"], selector=command.get("selector"),
                                  local={"operation": "clone",
                                         "destination": os.path.normpath(os.path.join(base, command["directory"]))},
                                  **common)
    # A fetch or pull reads its local repository only with a request context, staging in its prepared upload directory.
    if context is None or prepare_upload_dir(context) is None:
        say(_refusal("git_client_unavailable"))
        return EXIT_UNAVAILABLE
    if command["kind"] == "fetch":
        resolved = await seams.resolve(base, command["remote"], deadline.local_until, abort, git_layout(context))
        local = {"operation": "fetch", "directory": base, "remote": command["remote"]}
    else:
        resolved = await seams.upstream(base, deadline.local_until, abort, git_layout(context), environ or {})
        local = {"operation": "pull", "directory": base, "remote": resolved.get("remote"),
                 "branch": resolved.get("branch"), "flag": command.get("flag"), "global": resolved.get("global")}
    if not resolved["ok"]:
        say({"ok": False, "code": resolved["code"], "changes": "none", "cleanup": resolved["cleanup"]})
        return EXIT_UNAVAILABLE
    return await seams.client(operation="fetch", repository=resolved["repository"], local=local, **common)
