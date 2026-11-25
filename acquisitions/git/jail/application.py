"""A single-use, guest-local application of one bound delivery (G3). No relay,
wrapper, network fallback, image capability or host authority."""

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile

from acquisitions.git.jail.command import PULL_FLAGS, is_remote_name
from acquisitions.git.jail.local import (
    APPLICATION_CODES, CHUNK_BYTES, Clock, Failed, LocalGit, Records, below, directory, fail, open_regular, regular,
    repository_tree, same, text_input,
)
from acquisitions.git.jail.pull import (
    effective_settings, global_settings, pull_invocation, run_pull, stage_helper,
)
from acquisitions.git.jail.repository import is_oid, is_selector, parse_repository, parse_repository_url, repository_id
from acquisitions.git.jail.semantics import SEMANTICS_CODES, InvalidInput, is_branch, is_local_ref, plan_clone, plan_fetch
from guest.src.artifact_post_context import upload_name
from guest.src.protocol import is_safe_integer, is_sha256

BUNDLE_SIGNATURE = b"# v2 git bundle\n"
EMPTY_MARKER = b"agentbox.git.empty.v1\n"
UNBORN_HEAD = "refs/heads/main"
ZERO = "0" * 40
WORK_CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
# Fixed code vocabulary for tests and consumers; no Git diagnostic is returned.
LOCAL_RESULT_CODES = APPLICATION_CODES + SEMANTICS_CODES + (
    "git_semantics_input_invalid", "git_applied", "git_pull_failed", "git_pull_unsupported")

_REF_LINE = re.compile(r"([0-9a-f]{40}) (\S+) (.*)", re.S)
_OBJECT_LINE = re.compile(r"([0-9a-f]{40}) (commit|tree|blob)")
_VERSION = re.compile(r"git version (\d+)\.(\d+)\.(\d+)(?:[. -].*)?\n", re.S)
_ALLOWED = (re.compile(r"(user|alias|color|filter|credential)\..*", re.S),
            re.compile(r"remote\..+\.(url|pushurl|fetch)", re.S),
            re.compile(r"branch\..+\.(remote|merge|rebase|description|pushremote)", re.S),
            re.compile(r"core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|"
                       r"quotepath|autocrlf|eol|safecrlf|symlinks|hookspath|fsmonitor|untrackedcache)"))
# A pull's strategy keys besides; and no filter, which its checkout would run.
_PULL_ALLOWED = re.compile(r"pull\.(ff|rebase)", re.S)
_FILTER = re.compile(r"filter\..*", re.S)
# The jail user's global values a pull imports, by key.
MAX_GLOBAL_KEYS = 64


def delivery(metadata):
    """The host worker's metadata as a delivery: {format: bundle, head?} (a
    stock v2 bundle of every branch and tag and the source's usable HEAD
    branch, if any) or {format: empty}; None for anything else."""
    keys = sorted(metadata)
    if metadata.get("format") == "empty" and keys == ["format"]:
        return {"format": "empty"}
    if metadata.get("format") != "bundle":
        return None
    if keys == ["format"]:
        return {"format": "bundle"}
    head = metadata.get("head")
    return {"format": "bundle", "head": head} if keys == ["format", "head"] and is_branch(head) else None


def _is_delivery(value):
    return isinstance(value, dict) and delivery(value) is not None


class Layout:
    """Production callers pass the request context's upload directory
    (request_client.py `git_layout`); library tests an owned scratch root."""

    def __init__(self, root, uploads):
        self.root = root
        self.uploads = uploads


class _PlanRefused(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _code_of(error):
    if isinstance(error, (Failed, InvalidInput, _PlanRefused)):
        return error.code
    return "git_application_failed"


def _stat_maybe(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _utf8(data):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        fail("git_repository_unsupported")


def _write_all(fd, data, clock):
    at = 0
    while at < len(data):
        clock.check()
        count = os.write(fd, data[at:at + 65536])
        clock.check()
        if count == 0:
            fail("git_application_failed")
        at += count


async def _refs(git, prefix):
    found = []
    previous = [""]

    def accept(line):
        match = _REF_LINE.fullmatch(_utf8(line))
        if (match is None or not is_oid(match.group(1)) or not is_local_ref(match.group(2))
                or match.group(2) <= previous[0] or (match.group(3) != "" and not is_local_ref(match.group(3)))):
            fail("git_repository_inconsistent")
        previous[0] = match.group(2)
        found.append({"oid": match.group(1), "name": match.group(2), "symbolic": match.group(3)})

    records = Records(10, 40 + 2 + 2 * 1024, accept)
    await git.run([*prefix, "for-each-ref", "--sort=refname", "--format=%(objectname) %(refname) %(symref)"],
                  data=records.push, reject_stderr=True)
    records.finish()
    return found


async def _import_delivery(git, upload, upload_path, source, given):
    """The delivery imported by stock Git into a fresh bare `source`: a v2
    bundle (no prerequisite can resolve in an empty repository; no network
    transport) or nothing for the empty marker. HEAD as the host's clone had it."""
    # The host's whole file, as the `ready` announced it; then its kind.
    is_bundle = given["delivery"]["format"] == "bundle"
    expected = BUNDLE_SIGNATURE if is_bundle else EMPTY_MARKER
    digest = hashlib.sha256()
    at = 0
    first = b""
    while at < given["size"]:
        git.clock.check()
        chunk = os.pread(upload, min(CHUNK_BYTES, given["size"] - at), at)
        git.clock.check()
        if not chunk:
            fail("git_bundle_invalid")
        if at == 0:
            first = chunk[:len(expected)]
        digest.update(chunk)
        at += len(chunk)
    if (digest.hexdigest() != given["sha256"] or first != expected
            or (not is_bundle and given["size"] != len(expected))):
        fail("git_bundle_invalid")
    await git.run(["init", "--quiet", "--bare", "--template=", "--object-format=sha1", source])
    prefix = ["--git-dir=" + source]
    if is_bundle:
        try:
            await git.run([*prefix, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--no-auto-maintenance",
                           "--no-write-fetch-head", "--no-write-commit-graph", "--no-prune", "--refmap=", "--",
                           upload_path, "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"])
        except Failed as error:
            if error.code == "git_process_failed":
                fail("git_bundle_invalid")
            raise
    head = given["delivery"].get("head", UNBORN_HEAD) if is_bundle else UNBORN_HEAD
    await git.run([*prefix, "symbolic-ref", "HEAD", head])


async def _verify_source(git, source, given, repository):
    prefix = ["--git-dir=" + source]
    await git.run([*prefix, "fsck", "--full", "--strict", "--no-reflogs", "--no-dangling"])
    local = await _refs(git, prefix)
    if any(ref["symbolic"] != "" or not (ref["name"].startswith("refs/heads/") or ref["name"].startswith("refs/tags/"))
           for ref in local):
        fail("git_repository_inconsistent")
    # Batch-peel every distinct raw id; annotated and nested tags are not
    # guessed from their first tag header or a server-supplied peeled value.
    ids = list(dict.fromkeys(ref["oid"] for ref in local))
    peeled = {}

    def accept(line):
        match = _OBJECT_LINE.fullmatch(_utf8(line))
        if match is None or not is_oid(match.group(1)) or len(peeled) == len(ids):
            fail("git_repository_inconsistent")
        peeled[ids[len(peeled)]] = {"oid": match.group(1), "type": match.group(2)}

    objects = Records(10, 80, accept)
    await git.run([*prefix, "cat-file", "--batch-check=%(objectname) %(objecttype)"],
                  input=text_input(identifier + "^{}\n" for identifier in ids), data=objects.push)
    objects.finish()
    if len(peeled) != len(ids):
        fail("git_repository_inconsistent")
    acquired = {"repository": repository}
    # The host's HEAD only when it names an acquired branch.
    head = given["delivery"].get("head")
    if head is not None and any(ref["name"] == head for ref in local):
        acquired["head"] = head
    acquired["refs"] = [{"name": ref["name"], "oid": ref["oid"], "peeled": {"type": peeled[ref["oid"]]["type"],
                                                                             "oid": peeled[ref["oid"]]["oid"]}}
                        for ref in local]
    return acquired


async def _config(git, git_dir, pull=False):
    """Refuse config indirection before Git discovers this repository. config
    --file --no-includes runs from private staging, with no ambient
    repository. The small first subset intentionally refuses unsupported
    repository config; aliases, filters and credentials are inert here (fixed
    builtins, no checkout on fetch, file transport only). They are never
    copied into a working clone. A `pull` also accepts pull.ff and
    pull.rebase, and refuses any filter: its merge or rebase checks out."""
    values = {}

    def accept(data):
        text = _utf8(data)
        split = text.find("\n")
        key = text if split < 0 else text[:split]
        value = "true" if split < 0 else text[split + 1:]
        allowed = any(pattern.fullmatch(key) for pattern in _ALLOWED)
        if pull:
            allowed = (allowed and _FILTER.fullmatch(key) is None) or _PULL_ALLOWED.fullmatch(key) is not None
        if not allowed:
            fail("git_repository_unsupported")
        values.setdefault(key, []).append(value)

    records = Records(0, 65536, accept)
    await git.run(["config", "--file", os.path.join(git_dir, "config"), "--no-includes", "--null", "--list"],
                  data=records.push)
    records.finish()
    if values.get("core.repositoryformatversion") != ["0"] or \
            values.get("core.bare") not in (None, ["false"], ["0"], ["no"], ["off"]):
        fail("git_repository_unsupported")
    return values


def _self_contained(git_dir, clock):
    repository_tree(git_dir, clock)
    for path in ("commondir", "gitdir", "config.worktree", "shallow", "info/grafts", "objects/info/alternates",
                 "objects/info/http-alternates"):
        clock.check()
        if _stat_maybe(os.path.join(git_dir, path)) is not None:
            fail("git_repository_unsupported")
    for name in os.listdir(os.path.join(git_dir, "objects/pack")):
        if name.endswith(".promisor"):
            fail("git_repository_unsupported")
    clock.check()


def _working_root(root, path, clock):
    """The working repository at or above `path`. As a clone's destination,
    its ancestors may be sticky (`directory`); it, and any directory between
    it and `path`, may not."""
    directory(root, path, clock, sticky=path)
    current = path
    while True:
        clock.check()
        dot = _stat_maybe(os.path.join(current, ".git"))
        if dot is not None:
            if not stat.S_ISDIR(dot.st_mode) or dot.st_uid != os.geteuid():
                fail("git_repository_unsupported")
            directory(root, path, clock, sticky=None if current == root else os.path.dirname(current))
            return current
        if current == root:
            fail("git_repository_unsupported")
        current = os.path.dirname(current)


async def _normalize_clone(git, path, plan):
    prefix = ["-C", path]
    git_dir = os.path.join(path, ".git")
    # Local clone's temporary origin and inferred default branch never reach
    # the published destination, even on selector or unborn-head paths.
    fd = os.open(os.path.join(git_dir, "config"), os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not regular(os.fstat(fd)):
            fail("git_work_unsafe")
        _write_all(fd, WORK_CONFIG, git.clock)
    finally:
        os.close(fd)
    current = await _refs(git, prefix)
    desired = {ref["name"]: ref["oid"] for ref in plan["refs"]}
    checkout = plan["checkout"]
    if checkout["kind"] == "branch":
        desired[checkout["branch"]] = checkout["commit"]
    existing = {ref["name"]: ref["oid"] for ref in current}
    lines = ["start\n", "option no-deref\n"]
    for ref in current:
        if ref["symbolic"] != "":
            if ref["name"] != "refs/remotes/origin/HEAD":
                fail("git_repository_inconsistent")
            await git.run([*prefix, "symbolic-ref", "--delete", ref["name"]])
        elif ref["name"] not in desired:
            lines.append("delete %s %s\n" % (json.dumps(ref["name"]), ref["oid"]))
    for name, oid in desired.items():
        old = existing.get(name, ZERO)
        if old != oid:
            lines.append("update %s %s %s\n" % (json.dumps(name), oid, old))
    lines += ["prepare\n", "commit\n"]
    await git.run([*prefix, "update-ref", "--stdin"], input=text_input(lines))
    for key, value in plan["config"]:
        await git.run([*prefix, "config", "--local", "--add", key, value])
    remote_head = plan.get("remote_head")
    if remote_head is not None:
        await git.run([*prefix, "symbolic-ref", "refs/remotes/origin/HEAD", remote_head])
    if checkout["kind"] == "detached":
        await git.run([*prefix, "update-ref", "--no-deref", "HEAD", checkout["commit"]])
    else:
        await git.run([*prefix, "symbolic-ref", "HEAD",
                       checkout["branch"] if checkout["kind"] == "branch" else checkout["unborn"]])
    if checkout["kind"] != "none":
        await git.run([*prefix, "reset", "--hard", checkout["commit"], "--"])
    _self_contained(git_dir, git.clock)
    actual = await _refs(git, prefix)
    if remote_head is not None:
        desired["refs/remotes/origin/HEAD"] = desired[remote_head]
    if len(actual) != len(desired) or any(
            desired.get(ref["name"]) != ref["oid"]
            or ref["symbolic"] != ((remote_head or "") if ref["name"] == "refs/remotes/origin/HEAD" else "")
            for ref in actual):
        fail("git_repository_inconsistent")


def _fetch_line(entry, url):
    branch = entry["ref"].startswith("refs/heads/")
    name = entry["ref"][len("refs/heads/" if branch else "refs/tags/"):]
    return ("%s\t%s\t%s '%s' of %s\n" % (entry["oid"], "" if entry["merge"] else "not-for-merge",
                                         "branch" if branch else "tag", name, url)).encode()


def _valid_input(given):
    local = given.get("local")
    if not isinstance(local, dict):
        return False
    name = upload_name(given.get("session"), given.get("request"))
    # A pull's delivery is the host's fetch.
    submitted = "fetch" if local.get("operation") == "pull" else local.get("operation")
    if (name is None or not is_sha256(given.get("request_sha256")) or not _is_delivery(given.get("delivery"))
            or not is_sha256(given.get("sha256")) or not is_safe_integer(given.get("size")) or given["size"] <= 0
            or given.get("operation") != submitted):
        return False
    if "selector" in given and (given["operation"] != "clone" or not isinstance(given["selector"], str)
                                or not is_selector(given["selector"])):
        return False
    expected = {"clone": ["destination", "operation"], "fetch": ["directory", "operation", "remote"],
                "pull": ["branch", "directory", "flag", "global", "operation", "remote"]}.get(local.get("operation"))
    if sorted(local) != expected:
        return False
    if local["operation"] == "clone":
        return isinstance(local["destination"], str)
    if local["operation"] == "pull" and not (
            is_branch(local["branch"]) and (local["flag"] is None or local["flag"] in PULL_FLAGS)
            and _is_global(local["global"])):
        return False
    return isinstance(local["directory"], str) and is_remote_name(local["remote"])


def _is_global(value):
    return (isinstance(value, dict) and len(value) <= MAX_GLOBAL_KEYS
            and all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()))


class Application:
    """A new instance consumes its immutable input once. The request lane owns
    cross-instance and session replay prevention; this is not saved host
    authority. `given` is one submission and the host's `ready` for it
    (request_client.py): session, request, request_sha256, operation,
    repository, selector?, delivery, size, sha256 and the guest-local `local`
    operation ({operation: clone, destination}, {operation: fetch,
    directory, remote} or, for a submitted fetch, {operation: pull,
    directory, remote, branch, flag, global}: `resolve_upstream`'s)."""

    def __init__(self, given):
        self._input = dict(given, local=dict(given.get("local") or {}))
        self._used = False

    async def run(self, deadline, signal, layout):
        """{ok, code, changes, cleanup}: `changes` the working repository's, not
        temporary delivery staging; `cleanup` owned descriptors, direct
        children, pipes, request staging and a clone's private directory
        beside its destination only. Failures retain staging rather than
        guess. A pull's also has Git's `exit`; a nonzero one is
        `git_pull_failed`, its staging removed after a normal end."""
        state = {"changes": "none", "cleanup": "observed"}

        def failed(code):
            return {"ok": False, "code": code, "changes": state["changes"], "cleanup": state["cleanup"]}

        if self._used:
            return failed("git_application_used")
        self._used = True
        try:
            result = await self._apply(deadline, signal, layout, state, failed)
        except Exception as error:
            result = failed(_code_of(error))
        finally:
            for fd in (state.get("upload"), state.get("stage_pin"), state.get("side_pin")):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        state["cleanup"] = "retained"
        # A failed close cannot be hidden by a previously constructed result.
        if state["cleanup"] != result["cleanup"]:
            return failed("git_cleanup_incomplete")
        return result

    async def _apply(self, deadline, signal, layout, state, failed):
        clock = Clock(deadline, signal)
        clock.check()
        given = self._input
        local = given["local"]
        if not _valid_input(given):
            fail("git_application_invalid")
        repository = parse_repository(given["repository"]) if isinstance(given.get("repository"), str) else None
        if repository is None:
            fail("git_application_invalid")
        directory(layout.root, layout.uploads, clock)
        uploads = os.lstat(layout.uploads)
        if uploads.st_uid != os.geteuid() or (uploads.st_mode & 0o077) != 0:
            fail("git_work_unsafe")
        upload_path = os.path.join(layout.uploads, upload_name(given["session"], given["request"]))
        state["upload"] = open_regular(upload_path)
        before = os.fstat(state["upload"])
        if before.st_size != given["size"]:
            fail("git_bundle_invalid")
        clock.check()
        # Debt precedes creation; every failure keeps it.
        state["cleanup"] = "retained"
        stage = tempfile.mkdtemp(prefix=".apply-", dir=layout.uploads)
        state["stage_pin"] = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stage_identity = os.fstat(state["stage_pin"])
        if (not stat.S_ISDIR(stage_identity.st_mode) or stage_identity.st_uid != os.geteuid()
                or (stage_identity.st_mode & 0o777) != 0o700):
            fail("git_work_unsafe")
        for name in ("home", "tmp"):
            clock.check()
            os.mkdir(os.path.join(stage, name), 0o700)
        source = os.path.join(stage, "source")
        git = LocalGit(stage, clock)
        version = _VERSION.fullmatch(_utf8(await git.run(["--version"], diagnostics=4096)))
        if version is None or int(version.group(1)) < 2 or (int(version.group(1)) == 2 and int(version.group(2)) < 53):
            fail("git_repository_unsupported")
        await _import_delivery(git, state["upload"], upload_path, source, given)
        after = os.fstat(state["upload"])
        if (not same(before, after) or after.st_size != before.st_size or after.st_ctime_ns != before.st_ctime_ns
                or not regular(after) or not same(after, os.lstat(upload_path))):
            fail("git_work_changed")
        acquired = await _verify_source(git, source, given, repository_id(repository))
        exit = None
        if local["operation"] == "clone":
            await self._clone(git, layout, local["destination"], acquired, given, source, state, clock)
        elif local["operation"] == "fetch":
            await self._fetch(git, layout, local, acquired, source, state, clock)
        else:
            exit = await self._pull(git, layout, local, acquired, stage, source, state, clock)
        clock.check()
        # Positive detachment of held original descriptors, not a claim of
        # atomic inode-conditional unlink or protection against same-UID races.
        if not same(stage_identity, os.lstat(stage)):
            fail("git_work_changed")
        shutil.rmtree(stage)
        if os.fstat(state["stage_pin"]).st_nlink != 0:
            fail("git_cleanup_incomplete")
        if not same(before, os.lstat(upload_path)):
            fail("git_work_changed")
        os.unlink(upload_path)
        if os.fstat(state["upload"]).st_nlink != 0:
            fail("git_cleanup_incomplete")
        os.close(state.pop("stage_pin"))
        os.close(state.pop("upload"))
        state["cleanup"] = "observed"
        clock.check()
        if exit is None:
            return {"ok": True, "code": "git_applied", "changes": state["changes"], "cleanup": state["cleanup"]}
        return {"ok": exit == 0, "code": "git_applied" if exit == 0 else "git_pull_failed",
                "changes": state["changes"], "cleanup": state["cleanup"], "exit": exit}

    async def _clone(self, git, layout, destination, acquired, given, source, state, clock):
        if not below(layout.root, destination) or destination == layout.root or below(layout.uploads, destination):
            fail("git_work_unsafe")
        parent = os.path.dirname(destination)
        directory(layout.root, parent, clock, sticky=parent)
        old = _stat_maybe(destination)
        if old is None:
            kind = "missing"
        elif stat.S_ISDIR(old.st_mode) and not os.listdir(destination):
            kind = "empty"
        else:
            kind = "nonempty"
        planned = {"acquired": acquired, "destination": kind}
        if "selector" in given:
            planned["selector"] = given["selector"]
        plan = plan_clone(planned)
        if not plan["ok"]:
            raise _PlanRefused(plan["code"])
        if old is not None and (old.st_uid != os.geteuid() or (old.st_mode & 0o002) != 0):
            fail("git_work_unsafe")
        # The working clone is made beside its destination, in a private
        # directory of its own, so publication is one rename within the
        # destination's directory whichever filesystem holds the staging.
        clock.check()
        side = tempfile.mkdtemp(prefix=".agentbox-clone-", dir=parent)
        state["side_pin"] = os.open(side, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        side_identity = os.fstat(state["side_pin"])
        if (not stat.S_ISDIR(side_identity.st_mode) or side_identity.st_uid != os.geteuid()
                or (side_identity.st_mode & 0o777) != 0o700):
            fail("git_work_unsafe")
        work = os.path.join(side, "worktree")
        await git.run(["clone", "--quiet", "--local", "--no-hardlinks", "--no-checkout", "--template=", "--", source,
                       work])
        await _normalize_clone(git, work, plan)
        directory(layout.root, parent, clock, sticky=parent)
        if not same(side_identity, os.lstat(side)):
            fail("git_work_changed")
        now = _stat_maybe(destination)
        if old is None:
            changed = now is not None
        else:
            changed = (now is None or not same(old, now) or not stat.S_ISDIR(now.st_mode)
                       or len(os.listdir(destination)) != 0)
        if changed:
            fail("git_work_changed")
        clock.check()
        state["changes"] = "possible"
        os.rename(work, destination)
        if not same(side_identity, os.lstat(side)):
            fail("git_work_changed")
        os.rmdir(side)
        if os.fstat(state["side_pin"]).st_nlink != 0:
            fail("git_cleanup_incomplete")
        os.close(state.pop("side_pin"))

    async def _fetch(self, git, layout, local, acquired, source, state, clock):
        work, git_dir, config, original, plan = await _fetch_plan(git, layout, local, acquired, clock)
        remote = local["remote"]
        prefix = ["-C", work]
        # No live URL rewrite. An explicit local source and explicit refspecs;
        # no automatic refmap, pruning, tag forcing or FETCH_HEAD generation.
        clock.check()
        state["changes"] = "possible"
        await git.run([*prefix, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--no-auto-maintenance",
                       "--no-write-fetch-head", "--no-write-commit-graph", "--no-prune", "--refmap=", "--", source,
                       "+refs/heads/*:refs/remotes/%s/*" % remote, "refs/tags/*:refs/tags/*"])
        _self_contained(git_dir, clock)
        actual = await _refs(git, prefix)
        desired = {ref["name"]: ref["oid"] for ref in original}
        for update in plan["updates"]:
            desired[update["ref"]] = update["new"]
        symbolic = {ref["name"]: ref["symbolic"] for ref in original if ref["symbolic"] != ""}
        if len(actual) != len(desired) or any(
                (ref["symbolic"] != symbolic[ref["name"]]) if ref["name"] in symbolic
                else (ref["symbolic"] != "" or ref["oid"] != desired.get(ref["name"])) for ref in actual):
            fail("git_repository_inconsistent")
        if list((await _config(git, git_dir)).items()) != list(config.items()):
            fail("git_work_changed")
        fetch_head = os.path.join(git_dir, "FETCH_HEAD")
        previous = _stat_maybe(fetch_head)
        if previous is not None and not regular(previous):
            fail("git_work_unsafe")
        lock = fetch_head + ".lock"
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            for entry in plan["fetch_head"]:
                _write_all(fd, _fetch_line(entry, plan["url"]), clock)
        finally:
            os.close(fd)
        clock.check()
        os.rename(lock, fetch_head)

    async def _pull(self, git, layout, local, acquired, stage, source, state, clock):
        """Stock `git pull` on the current branch, its fetch served from
        `source` (pull.py); the same checks as a fetch first, the plan a
        precondition only: stock fetch moves the refs, then merges or
        rebases. Git's exit status; a merge or rebase it leaves stays."""
        work, git_dir, config, _, plan = await _fetch_plan(git, layout, local, acquired, clock, pull=True)
        if plan["current"] != local["branch"]:
            fail("git_work_changed")
        settings = effective_settings(config, local["global"], local["branch"][len("refs/heads/"):])
        remote = local["remote"]
        stage_helper(stage)
        argv, env = pull_invocation(stage, work, remote, config["remote.%s.url" % remote][0], source, local["flag"],
                                    settings)
        clock.check()
        state["changes"] = "possible"
        exit = await run_pull(argv, env, clock)
        if list((await _config(git, git_dir, pull=True)).items()) != list(config.items()):
            fail("git_work_changed")
        return exit


async def _fetch_plan(git, layout, local, acquired, clock, pull=False):
    """A fetch's checks of the working repository and its plan: (work,
    git_dir, config, original refs, plan). A pull's needs its current
    branch's upstream on this remote (plan `current`)."""
    work = _working_root(layout.root, local["directory"], clock)
    git_dir = os.path.join(work, ".git")
    if below(layout.uploads, work):
        fail("git_work_unsafe")
    _self_contained(git_dir, clock)
    config = await _config(git, git_dir, pull)
    prefix = ["-C", work]
    await git.run([*prefix, "fsck", "--full", "--strict", "--no-reflogs", "--no-dangling"])
    original = await _refs(git, prefix)
    branch = _utf8(await git.run([*prefix, "symbolic-ref", "-q", "HEAD"], exits=(0, 1))).rstrip()
    current = None
    if branch != "":
        if not is_branch(branch):
            fail("git_repository_unsupported")
        short = branch[len("refs/heads/"):]
        remotes = config.get("branch.%s.remote" % short, [])
        merges = config.get("branch.%s.merge" % short, [])
        if (remotes or merges) and (len(remotes) != 1 or len(merges) != 1
                                    or not (remotes[0] == "." or is_remote_name(remotes[0]))
                                    or not is_branch(merges[0])):
            fail("git_repository_unsupported")
        current = {"branch": branch}
        if not any(ref["name"] == branch for ref in original):
            current["unborn"] = True
        if remotes:
            current["upstream"] = {"remote": remotes[0], "merge": merges[0]}
    remote = local["remote"]
    planned = {"acquired": acquired, "remote": remote, "urls": config.get("remote.%s.url" % remote, []),
               "fetch": config.get("remote.%s.fetch" % remote, []),
               "local": [{"name": ref["name"], "oid": ref["oid"]} for ref in original]}
    if current is not None:
        planned["current"] = current
    plan = plan_fetch(planned)
    if not plan["ok"]:
        raise _PlanRefused(plan["code"])
    targets = {update["ref"] for update in plan["updates"]} | set(plan["unchanged"])
    if any(ref["symbolic"] != "" and ref["name"] in targets for ref in original):
        fail("git_repository_unsupported")
    if pull:
        upstream = (current or {}).get("upstream")
        # As resolved; an upstream branch absent from the delivery is stock Git's to report.
        if upstream is None or upstream["remote"] != remote:
            fail("git_work_changed")
        plan = dict(plan, current=current["branch"])
    return work, git_dir, config, original, plan


async def resolve_remote(start, remote, deadline, signal, layout):
    """The canonical `owner/name` of `remote`'s one configured URL in the
    ordinary working repository at or above `start`, so a fetch can be
    submitted without passing a path, URL or argv to the host. The same
    cooperative checks and no-include configuration read from private staging
    as `Application`'s fetch (which later verifies the URL and refspec again
    against the delivery); nothing is fetched, written or repaired, and there
    is no network fallback. Staging is removed only once observed detached.
    {ok: True, repository} or {ok: False, code, cleanup}."""
    if not is_remote_name(remote):
        return {"ok": False, "code": "git_application_invalid", "cleanup": "observed"}

    async def read(git, git_dir, values):
        return {"remote": remote}

    found = await _resolve(start, deadline, signal, layout, False, read)
    if found["ok"]:
        del found["remote"]
    return found


async def resolve_upstream(start, deadline, signal, layout, environ):
    """`resolve_remote` for a pull: the current branch's one configured
    upstream on a named remote, the remote's repository, and the jail user's
    global values of the keys a pull imports (pull.py `global_settings`,
    `environ` locating them), the effective strategy already checked. No
    upstream, a local one or a detached HEAD is `git_remote_unsupported`.
    {ok: True, repository, remote, branch, global} or {ok: False, code, cleanup}."""

    async def read(git, git_dir, values):
        head = _utf8(await git.run(["--git-dir=" + git_dir, "symbolic-ref", "-q", "HEAD"], exits=(0, 1))).rstrip()
        if not is_branch(head):
            raise _PlanRefused("git_remote_unsupported")
        short = head[len("refs/heads/"):]
        remotes = values.get("branch.%s.remote" % short, [])
        merges = values.get("branch.%s.merge" % short, [])
        if len(remotes) != 1 or len(merges) != 1 or not is_remote_name(remotes[0]) or not is_branch(merges[0]):
            raise _PlanRefused("git_remote_unsupported")
        found = await global_settings(git.stage, git.clock, environ)
        if len(found) > MAX_GLOBAL_KEYS:
            fail("git_pull_unsupported")
        effective_settings(values, found, short)
        return {"remote": remotes[0], "branch": head, "global": found}

    return await _resolve(start, deadline, signal, layout, True, read)


async def _resolve(start, deadline, signal, layout, pull, read):
    cleanup = "observed"
    pin = None
    found = None
    code = None
    try:
        clock = Clock(deadline, signal)
        clock.check()
        if not isinstance(start, str):
            fail("git_application_invalid")
        work = _working_root(layout.root, start, clock)
        git_dir = os.path.join(work, ".git")
        if below(layout.uploads, work):
            fail("git_work_unsafe")
        _self_contained(git_dir, clock)
        directory(layout.root, layout.uploads, clock)
        uploads = os.lstat(layout.uploads)
        if uploads.st_uid != os.geteuid() or (uploads.st_mode & 0o077) != 0:
            fail("git_work_unsafe")
        cleanup = "retained"
        stage = tempfile.mkdtemp(prefix=".resolve-", dir=layout.uploads)
        pin = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        identity = os.fstat(pin)
        if (not stat.S_ISDIR(identity.st_mode) or identity.st_uid != os.geteuid()
                or (identity.st_mode & 0o777) != 0o700):
            fail("git_work_unsafe")
        for name in ("home", "tmp"):
            clock.check()
            os.mkdir(os.path.join(stage, name), 0o700)
        git = LocalGit(stage, clock)
        # Configuration refused while reading it: retained, as G3 retains a failure's.
        values = await _config(git, git_dir, pull)
        refusal = None
        try:
            found = await read(git, git_dir, values)
            urls = values.get("remote.%s.url" % found["remote"], [])
            parsed = parse_repository_url(urls[0]) if len(urls) == 1 else None
            if parsed is None:
                raise _PlanRefused("git_remote_unsupported")
            found["repository"] = repository_id(parsed)
        except (_PlanRefused, Failed) as error:
            if isinstance(error, Failed) and error.code != "git_pull_unsupported":
                raise
            # A refusal: staging is removed first.
            refusal, found = error, None
        if not same(identity, os.lstat(stage)):
            fail("git_work_changed")
        shutil.rmtree(stage)
        if os.fstat(pin).st_nlink != 0:
            fail("git_cleanup_incomplete")
        os.close(pin)
        pin = None
        cleanup = "observed"
        if refusal is not None:
            raise refusal
    except Exception as error:
        code = _code_of(error)
    finally:
        if pin is not None:
            try:
                os.close(pin)
            except OSError:
                cleanup = "retained"
    if code is not None or found is None:
        return {"ok": False, "code": code or "git_application_failed", "cleanup": cleanup}
    return dict(found, ok=True)
