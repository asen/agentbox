"""Trusted host worker of the `git` handler (acquisitions/git/contract/v1).

Operations `clone` and `fetch`, the same acquisition: the guest names one
public GitHub repository and an optional branch or tag selector,

    {"repository": "owner/name" [, "selector": NAME]}

and the operator's policy grants public read of GitHub, optionally only
listed repositories:

    {"schema":"agentbox.git.request-policy.v1","grant":"github-public-read-v1"
     [, "repositories":["owner/name",...]]}   (sorted, unique, <= 256)

A repository the policy does not list is `git_repository_denied`. The
worker derives the HTTPS URL from the validated identity only. The host
resolves `git` (manifest `tools`) and passes its path in the request.

Everything this worker writes stays beneath the request directory:

    stage/cwd home tmp       git's working directory, HOME, TMPDIR (empty)
    stage/repository.git     the bare clone (never checked out)
    stage/artifact           a stock Git bundle, or the empty marker

Steps: `git version --build-options` (Git 2.53+, libcurl 8.4+); one bare
clone over HTTPS with the fixed configuration below, the host's own
resolver and the system trust (no redirect, proxy, credential, cookie,
rewrite, bundle URI, promisor, submodule or other transport; nothing of a
system, global or repository template configuration; received objects
checked); the clone's usable HEAD and the selector, by local plumbing;
then, if it has any branch or tag, one self-contained v2 bundle of every
branch and tag (`git -c core.warnAmbiguousRefs=false bundle create
--version=2 - --glob=refs/heads/* --glob=refs/tags/*`) streamed into the
artifact, whose `list-heads` must equal the clone's own ref inventory byte
for byte (should Git omit a ref: refused, never delivered short). A repository without
refs is the fixed EMPTY marker. The clone tree is then removed best
effort.

    metadata  {"format": "bundle" [, "head": "refs/heads/X"]} | {"format": "empty"}

Tool output is bounded and discarded: no code carries a path, URL, address,
argument or tool text. Every `git` runs in this process's group (never a
new session or group), with exactly the given environment, `/dev/null`
stdin and no inherited descriptor; each is waited for before the next step,
and killed and waited for on any failure or this worker's own deadline.

The request's `test` seam (the host's test build only) is
{"endpoint": "localhost:PORT", "ca_file": ABS}: the clone's source is
`https://localhost:PORT/owner/name.git`, trusting only that CA.
"""

import hashlib
import os
import re
import selectors
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "lib"))

import agentbox_handler as handler  # noqa: E402
from agentbox_handler import ARTIFACT_FILE, Refused  # noqa: E402

POLICY_SCHEMA = "agentbox.git.request-policy.v1"
GRANT = "github-public-read-v1"
MAX_REPOSITORIES = 256

# The supported profile.
MIN_VERSION = (2, 53, 0)
MIN_LIBCURL = (8, 4, 0)
MAX_PROFILE_BYTES = 4096
MAX_PROFILE_LINES = 32
MAX_PROFILE_LINE = 256
PROFILE_TIMEOUT = 5.0
# A call's captured diagnostics, at most; more fails it. Not a repository
# size bound: no repository, pack, object, ref or bundle size is limited.
MAX_DIAGNOSTIC_BYTES = 65536
MAX_HEAD_BYTES = 512
MAX_REF_BYTES = 256
OID_HEX = 40
CHUNK = 1 << 20

# The fixed configuration, as literal `-c` items, in this order.
CONFIG = (
    # One transport: HTTPS; Git's v2 wire protocol.
    "protocol.allow=never",
    "protocol.https.allow=always",
    "protocol.version=2",
    # No redirect (including a treated-as-redirect http-alternates), proxy,
    # cookie or proactive credential.
    "http.followRedirects=false",
    "http.proxy=",
    "http.emptyAuth=false",
    "http.proactiveAuth=none",
    "http.cookieFile=",
    "http.saveCookies=false",
    "http.sslVerify=true",
    # No credential source and no prompt (`GIT_TERMINAL_PROMPT=0` too).
    "credential.helper=",
    "credential.interactive=false",
    "core.askPass=",
    # Nothing of a repository or template runs or is copied.
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "init.templateDir=",
    # No other source: bundle URIs, promisor remotes, submodules; packfile
    # URIs need `fetch.uriProtocols`, which stays unset.
    "transfer.bundleURI=false",
    "promisor.acceptFromServer=none",
    "fetch.recurseSubmodules=false",
    "submodule.recurse=false",
    # Malformed objects refuse; a shallow source refuses.
    "transfer.fsckObjects=true",
    "clone.rejectShallow=true",
    # No background or follow-up work.
    "fetch.writeCommitGraph=false",
    "maintenance.auto=false",
    "gc.auto=0",
)
CLONE_OPTIONS = ("clone", "--bare", "--no-local", "--template=", "--quiet")
# A local plumbing call's: no transport at all, so no network fallback.
LOCAL_CONFIG = (
    "protocol.allow=never",
    "credential.helper=",
    "credential.interactive=false",
    "core.askPass=",
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "core.alternateRefsCommand=",
    "fetch.writeCommitGraph=false",
    "maintenance.auto=false",
    "gc.auto=0",
)
# The clone's inventory and the bundle's: the same `<oid> SP <name> LF`
# lines, branches then tags, each in ref order.
REFS = ("for-each-ref", "--format=%(objectname) %(refname)", "refs/heads/", "refs/tags/")
# Full ref names (`--branches`/`--tags` pass short ones, and Git omits a
# short name a branch and a tag share). Without `warnAmbiguousRefs` Git
# still omits a full name that another ref's short form also matches
# (refs/heads/x beside refs/heads/refs/heads/x); with it off, the exact
# name is taken and every ref is bundled.
BUNDLE_CONFIG = ("core.warnAmbiguousRefs=false",)
BUNDLE = ("bundle", "create", "--version=2", "--quiet", "-", "--glob=refs/heads/*",
          "--glob=refs/tags/*")
LIST_HEADS = ("bundle", "list-heads")
# Git's environment beside PATH and the private HOME/TMPDIR: nothing else is
# inherited.
GIT_ENV = (
    ("LC_ALL", "C"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_PROTOCOL_FROM_USER", "0"),
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    ("GIT_NO_LAZY_FETCH", "1"),
    ("GIT_ADVICE", "0"),
)

# The request directory's fixed entries.
CWD, HOME, TMP = "cwd", "home", "tmp"
REPOSITORY = "repository.git"

# The delivery (contract.json `delivery`).
FORMAT_BUNDLE = "bundle"
FORMAT_EMPTY = "empty"
EMPTY = b"agentbox.git.empty.v1\n"

# The worker's own codes (the shared runtime adds its generic ones).
CODES = (
    "git_profile_malformed",
    "git_profile_unsupported",
    "git_clone_failed",
    "git_diagnostic_limit",
    "git_repository_inconsistent",
    "git_selector_not_acquired",
    "git_bundle_failed",
    "git_staging_unsafe",
    "git_staging_failed",
    "git_acquisition_expired",
    "git_tool_failed",
    "git_args_invalid",
    "git_policy_invalid",
    "git_repository_denied",
    "git_test_seam_invalid",
)

HEX = re.compile(r"[0-9a-f]+")
OWNER = re.compile(r"[a-z0-9]([a-z0-9-]{0,37}[a-z0-9])?")
NAME = re.compile(r"[a-z0-9._][a-z0-9._-]{0,99}")


# Grammar (the shared repository fixtures).

def is_short_ref(text):
    return (text != ""
            and all(0x21 <= ord(c) < 0x7f and c not in "~^:?*[\\" for c in text)
            and ".." not in text and "@{" not in text and text != "@" and not text.endswith(".")
            and all(part and not part.startswith(".") and not part.endswith(".lock")
                    for part in text.split("/")))


def is_ref(text):
    return len(text) <= MAX_REF_BYTES and any(
        text.startswith(prefix) and is_short_ref(text[len(prefix):])
        for prefix in ("refs/heads/", "refs/tags/"))


def is_selector(text):
    return (len(text) <= MAX_REF_BYTES - len("refs/heads/") and is_short_ref(text)
            and not text.startswith("-") and text != "HEAD")


def is_oid(text):
    return len(text) == OID_HEX and HEX.fullmatch(text) is not None and set(text) != {"0"}


def is_repository(text):
    owner, _, name = text.partition("/")
    return (OWNER.fullmatch(owner) is not None and NAME.fullmatch(name) is not None
            and name not in (".", "..") and not name.endswith(".git"))


# The request.

ENDPOINT = re.compile(r"localhost:([1-9][0-9]{0,4})")


def policy_permits(policy, repository):
    """The operator's grant; raises `git_policy_invalid`."""
    invalid = Refused("git_policy_invalid")
    if not handler.exact(policy, {"schema", "grant"}, {"repositories"}) \
            or policy["schema"] != POLICY_SCHEMA or policy["grant"] != GRANT:
        raise invalid
    if "repositories" not in policy:
        return True
    listed = policy["repositories"]
    if (not isinstance(listed, list) or not 0 < len(listed) <= MAX_REPOSITORIES
            or not all(isinstance(item, str) and is_repository(item) for item in listed)
            or any(a >= b for a, b in zip(listed, listed[1:]))):
        raise invalid
    return repository in listed


def job(request):
    """The acquisition's fixed inputs from the request, its policy and its
    guest arguments."""
    args = request.args
    if not handler.exact(args, {"repository"}, {"selector"}):
        raise Refused("git_args_invalid")
    repository = args["repository"]
    if not isinstance(repository, str) or not is_repository(repository):
        raise Refused("git_args_invalid")
    selector = args.get("selector")
    if "selector" in args and not (isinstance(selector, str) and is_selector(selector)):
        raise Refused("git_args_invalid")
    if not policy_permits(request.policy, repository):
        raise Refused("git_repository_denied")
    git = request.tools.get("git")
    if not handler.plain_path(git):
        raise Refused("git_tool_failed")
    url = "https://github.com/%s.git" % repository
    work = {"git": git, "stage": request.stage, "source": url, "url": url,
            "repository": repository, "session": request.ids["session"],
            "request": request.ids["request"], "request_sha256": request.ids["request_sha256"],
            "remaining_ms": request.value["remaining_ms"]}
    if selector is not None:
        work["selector"] = selector
    if request.test is not None:
        endpoint, ca_file = request.test.get("endpoint"), request.test.get("ca_file")
        match = ENDPOINT.fullmatch(endpoint) if isinstance(endpoint, str) else None
        if match is None or int(match.group(1)) > 65535 or not handler.plain_path(ca_file):
            raise Refused("git_test_seam_invalid")
        work["source"] = "https://%s/%s.git" % (endpoint, repository)
        work["ca_file"] = ca_file
    return work


# Processes.

class Clock:
    def __init__(self, remaining_ms):
        self.deadline = time.monotonic() + remaining_ms / 1000.0

    def left(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise Refused("git_acquisition_expired")
        return left


def run(argv, env, cwd, clock, stdout=None, cap=MAX_DIAGNOSTIC_BYTES, merge=True,
        timeout=None):
    """Runs `argv` in this group with exactly `env`, `/dev/null` stdin, no
    inherited descriptor; waits for it. Output: `stdout(chunk)` gets the
    data stream (stderr bounded and discarded apart), else stdout (and with
    `merge` stderr) is collected up to `cap` bytes (`git_diagnostic_limit`
    beyond). Returns (exit code, collected bytes). Any failure or the
    deadline kills it and waits before raising."""
    try:
        process = subprocess.Popen(
            list(argv), env=dict(env), cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge and stdout is None else subprocess.PIPE,
            close_fds=True)
    except OSError:
        raise Refused("git_tool_failed") from None
    collected = bytearray()
    diagnostics = 0
    # One cutoff, computed once, for the output and the exit alike.
    limit = None if timeout is None else time.monotonic() + timeout

    def left():
        remaining = clock.left()
        if limit is not None:
            remaining = min(remaining, limit - time.monotonic())
            if remaining <= 0:
                raise Refused("git_profile_malformed")
        return remaining

    selector = selectors.DefaultSelector()
    try:
        streams = {process.stdout.fileno(): "out"}
        if process.stderr is not None:
            streams[process.stderr.fileno()] = "err"
        for fd, kind in streams.items():
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_READ, kind)
        while streams:
            for key, _ in selector.select(left()):
                try:
                    data = os.read(key.fd, CHUNK)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fd)
                    del streams[key.fd]
                elif key.data == "out" and stdout is not None:
                    stdout(data)
                elif key.data == "out":
                    collected += data
                    if len(collected) > cap:
                        raise Refused("git_diagnostic_limit")
                else:
                    diagnostics += len(data)
                    if diagnostics > MAX_DIAGNOSTIC_BYTES:
                        raise Refused("git_diagnostic_limit")
        # Its pipes at EOF are not its exit: the same cutoff bounds the wait.
        while True:
            try:
                code = process.wait(timeout=max(0.001, left()))
                break
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
    return code, bytes(collected)


def git_env(path, home, tmp, ceiling):
    env = [("PATH", path)] + list(GIT_ENV)
    env += [("HOME", home), ("XDG_CONFIG_HOME", home + "/.config"), ("TMPDIR", tmp),
            ("GIT_CEILING_DIRECTORIES", ceiling)]
    return env


# The version profile.

def triple(text):
    parts = text.split(".")
    if len(parts) != 3 or not all(1 <= len(p) <= 4 and p.isdigit() and p.isascii()
                                  and not (len(p) > 1 and p.startswith("0")) for p in parts):
        raise Refused("git_profile_malformed")
    return tuple(int(p) for p in parts)


def check_profile(output):
    """`git version --build-options`: Git MIN_VERSION or later, built with
    libcurl MIN_LIBCURL or later; bounded ASCII, each key at most once."""
    if len(output) > MAX_PROFILE_BYTES or not output.isascii():
        raise Refused("git_profile_malformed")
    lines = output.decode("ascii").splitlines()
    if not lines or len(lines) > MAX_PROFILE_LINES or any(len(l) > MAX_PROFILE_LINE for l in lines):
        raise Refused("git_profile_malformed")
    if not lines[0].startswith("git version "):
        raise Refused("git_profile_malformed")
    version = triple(lines[0][len("git version "):])
    found = [line[len("libcurl: "):] for line in lines[1:] if line.startswith("libcurl: ")]
    if len(found) > 1:
        raise Refused("git_profile_malformed")
    if not found:
        raise Refused("git_profile_unsupported")
    libcurl = triple(found[0])
    if version < MIN_VERSION or libcurl < MIN_LIBCURL:
        raise Refused("git_profile_unsupported")
    return version, libcurl


def symbolic_head(output):
    """`symbolic-ref -q HEAD`'s target if a branch of the grammar, else None
    (detached or unusable)."""
    try:
        text = output.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not text.endswith("\n") or "\n" in text[:-1]:
        return None
    target = text[:-1]
    return target if target.startswith("refs/heads/") and is_ref(target) else None


class Inventory:
    """A ref listing as it streams: its byte count and SHA-256; constant
    memory, nothing parsed."""

    def __init__(self):
        self.size = 0
        self.digest = hashlib.sha256()

    def feed(self, data):
        self.size += len(data)
        self.digest.update(data)

    def value(self):
        return self.size, self.digest.hexdigest()


# The acquisition.

def open_stage(request):
    """The host's fresh request directory (agentbox_handler.open_stage); its
    fixed private working directory, HOME and TMPDIR made."""
    fd = handler.open_stage(request, "git_staging_unsafe")
    try:
        for name in (CWD, HOME, TMP):
            os.mkdir(name, 0o700, dir_fd=fd)
    except OSError:
        os.close(fd)
        raise Refused("git_staging_failed") from None
    return fd


def acquire(request):
    work = job(request)
    clock = Clock(work["remaining_ms"])
    path = os.environ.get("PATH", "")
    stage_fd = open_stage(request)
    try:
        return acquire_in(work, clock, work["git"], work["stage"], stage_fd, path)
    finally:
        os.close(stage_fd)


def acquire_in(request, clock, git, stage, stage_fd, path):
    home, tmp, cwd = (os.path.join(stage, name) for name in (HOME, TMP, CWD))
    # The version profile: no home, configuration or repository discovery.
    profile_env = [("PATH", path)] + list(GIT_ENV) + [("HOME", "/nonexistent"),
                                                      ("GIT_CEILING_DIRECTORIES", "/")]
    code, output = run((git, "version", "--build-options"), profile_env, "/", clock,
                       cap=MAX_PROFILE_BYTES, merge=False, timeout=PROFILE_TIMEOUT)
    if code != 0:
        raise Refused("git_profile_malformed")
    check_profile(output)

    env = git_env(path, home, tmp, stage)
    repository = os.path.join(stage, REPOSITORY)
    argv = [git]
    for item in CONFIG:
        argv += ["-c", item]
    if "ca_file" in request:
        argv += ["-c", "http.sslCAInfo=" + request["ca_file"]]
    argv += list(CLONE_OPTIONS) + ["--", request["source"], repository]
    code, _ = run(argv, env, cwd, clock)
    if code != 0:
        raise Refused("git_clone_failed")

    local = [git]
    for item in LOCAL_CONFIG:
        local += ["-c", item]
    local.append("--git-dir=" + repository)

    def exists(ref):
        code, _ = run(local + ["show-ref", "--verify", "--quiet", ref], env, cwd, clock)
        if code not in (0, 1):
            raise Refused("git_repository_inconsistent")
        return code == 0

    selector = request.get("selector")
    if selector and not (exists("refs/heads/" + selector) or exists("refs/tags/" + selector)):
        raise Refused("git_selector_not_acquired")
    code, output = run(local + ["symbolic-ref", "-q", "HEAD"], env, cwd, clock,
                       cap=MAX_HEAD_BYTES, merge=False)
    if code not in (0, 1):
        raise Refused("git_repository_inconsistent")
    head = symbolic_head(output) if code == 0 else None
    if head is not None and not exists(head):
        head = None

    refs = Inventory()
    code, _ = run(local + list(REFS), env, cwd, clock, stdout=refs.feed, merge=False)
    if code != 0:
        raise Refused("git_repository_inconsistent")
    artifact = handler.create(stage_fd, ARTIFACT_FILE, "git_staging_failed")
    try:
        sink = handler.Sink(artifact, "git_staging_failed")
        if refs.size == 0:
            sink.write(EMPTY)
            metadata = {"format": FORMAT_EMPTY}
        else:
            bundle = list(local)
            for item in BUNDLE_CONFIG:
                bundle += ["-c", item]
            code, _ = run(bundle + list(BUNDLE), env, cwd, clock, stdout=sink.write, merge=False)
            if code != 0:
                raise Refused("git_bundle_failed")
            metadata = {"format": FORMAT_BUNDLE}
            if head is not None:
                metadata["head"] = head
        size, sha256 = sink.finish()
    finally:
        os.close(artifact)
    if refs.size:
        # Every branch and tag of the clone, exactly: none omitted or added.
        heads = Inventory()
        code, _ = run(local + list(LIST_HEADS) + [os.path.join(stage, ARTIFACT_FILE)], env, cwd,
                      clock, stdout=heads.feed, merge=False)
        if code != 0 or heads.value() != refs.value():
            raise Refused("git_bundle_failed")
    # The clone and scratch are no longer needed; the host removes the rest.
    for name in (REPOSITORY, HOME, TMP, CWD):
        shutil.rmtree(name, ignore_errors=True, dir_fd=stage_fd)
    return size, sha256, metadata


if __name__ == "__main__":
    sys.exit(handler.main({"clone": acquire, "fetch": acquire}))
