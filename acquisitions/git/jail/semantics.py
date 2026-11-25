"""Pure expected-operation plans for guest clone and fetch application of
acquisitions/git/contract/v1. No I/O, Git invocation, file or lane dispatch: the
application (application.py) applies these plans with real local Git and must
reproduce them; the shared semantics-fixtures.json freezes their expected
outcomes.

Inputs describe the delivered copy and guest-local state. Each acquired ref
carries its raw value and the fully peeled object it reaches; both are facts
the application must verify locally in the delivered repository, never server
claims. A plan only checks their consistency; it does not verify the object
graph. Plans never contain a staging path, alternate or temporary URL: the
canonical public URL is the only remote URL ever planned, and fetch never
rewrites it. Refusals are fixed codes; malformed or contradictory inputs raise
one fixed `InvalidInput` and echo nothing. Inputs and plans are plain dicts
and lists, as the fixtures' JSON."""

from acquisitions.git.jail.command import is_remote_name
from acquisitions.git.jail.repository import (
    is_oid, is_ref, is_selector, is_short_ref, parse_repository, parse_repository_url, repository_id, repository_url,
)

SEMANTICS_CODES = (
    "git_destination_not_empty", "git_selector_not_found", "git_selector_not_checkoutable", "git_ref_unsupported",
    "git_ref_conflict", "git_remote_unsupported", "git_refspec_unsupported", "git_tag_conflict",
)

CLONE_REMOTE = "origin"
# A fixed guest branch for an unborn HEAD; never host or ambient config.
UNBORN_BRANCH = "refs/heads/main"
# The type of a fully peeled object: never a tag.
PEELED_TYPES = ("commit", "tree", "blob")
# The upstream remote Git uses for a branch tracking a local branch.
LOCAL_UPSTREAM = "."
# Bound on one guest-local ref name; longer than acquired refs, as tracking refs add their remote prefix.
MAX_LOCAL_REF_BYTES = 1024
# The reserved branch name `refs/remotes/<remote>/HEAD` would collide with;
# a branch below it (`refs/heads/HEAD/X`) would map below that symref.
RESERVED_BRANCH = "refs/heads/HEAD"


def default_refspec(remote):
    return "+refs/heads/*:refs/remotes/%s/*" % remote


class InvalidInput(Exception):
    """One fixed refusal for malformed or contradictory input; nothing is echoed."""

    code = "git_semantics_input_invalid"

    def __init__(self):
        super().__init__("git_semantics_input_invalid")


def _invalid():
    raise InvalidInput()


def _exact(value, required, optional=()):
    """A plain object with exactly the required keys and only the optional ones besides."""
    if not isinstance(value, dict):
        _invalid()
    if any(key not in required and key not in optional for key in value):
        _invalid()
    if any(key not in value for key in required):
        _invalid()
    return value


def _dense(value):
    if not isinstance(value, list):
        _invalid()
    return value


def _strings(value):
    items = _dense(value)
    if any(not isinstance(item, str) for item in items):
        _invalid()
    return items


def namespace_conflict(names):
    """Whether any name is a path ancestor of another (`a/b` and `a/b/c`): Git's
    ordinary ref storage cannot hold both. String prefixes such as `a/b` and
    `a/bc` do not conflict."""
    names = set(names)
    for name in names:
        at = name.find("/", len("refs/"))
        while at >= 0:
            if name[:at] in names:
                return True
            at = name.find("/", at + 1)
    return False


def _check_acquired(value):
    acquired = _exact(value, ("repository", "refs"), ("head",))
    repository = parse_repository(acquired["repository"]) if isinstance(acquired["repository"], str) else None
    if repository is None:
        _invalid()
    refs = _dense(acquired["refs"])
    previous = ""
    for item in refs:
        ref = _exact(item, ("name", "oid", "peeled"))
        peeled = _exact(ref["peeled"], ("type", "oid"))
        if (not isinstance(ref["name"], str) or not isinstance(ref["oid"], str) or not isinstance(peeled["oid"], str)
                or not is_ref(ref["name"]) or not is_oid(ref["oid"]) or not is_oid(peeled["oid"])
                or peeled["type"] not in PEELED_TYPES or ref["name"] <= previous):
            _invalid()
        # A branch is a direct commit; only a tag may name a distinct tag object.
        if ref["name"].startswith("refs/heads/") and (peeled["type"] != "commit" or peeled["oid"] != ref["oid"]):
            _invalid()
        previous = ref["name"]
    head = acquired.get("head")
    if "head" in acquired and (not isinstance(head, str) or not head.startswith("refs/heads/")
                               or not any(ref["name"] == head for ref in refs)):
        _invalid()
    # No ordinary repository holds both `a` and `a/b`: contradictory input.
    if namespace_conflict(ref["name"] for ref in refs):
        _invalid()
    return repository_url(repository)


def is_local_ref(text):
    """Any fully qualified local ref: `refs/` and check-ref-format, bounded."""
    return len(text) <= MAX_LOCAL_REF_BYTES and text.startswith("refs/") and is_short_ref(text[len("refs/"):])


def is_branch(text):
    """A real local branch name: `refs/heads/X`, not the reserved `refs/heads/HEAD`."""
    return isinstance(text, str) and is_local_ref(text) and text.startswith("refs/heads/") and text != RESERVED_BRANCH


def _check_local(value):
    refs = {}
    for item in _dense(value):
        ref = _exact(item, ("name", "oid"))
        if (not isinstance(ref["name"], str) or not isinstance(ref["oid"], str) or not is_local_ref(ref["name"])
                or not is_oid(ref["oid"])):
            _invalid()
        # Duplicates are ambiguous, identical or not.
        if ref["name"] in refs:
            _invalid()
        refs[ref["name"]] = ref["oid"]
    if namespace_conflict(refs):
        _invalid()
    return refs


def _check_current(value, local):
    current = _exact(value, ("branch",), ("unborn", "upstream"))
    branch = current["branch"]
    if not is_branch(branch):
        _invalid()
    if "unborn" in current and current["unborn"] is not True:
        _invalid()
    unborn = current.get("unborn") is True
    if (branch in local) == unborn:
        _invalid()
    # An unborn branch must be creatable beside the existing refs.
    if unborn and namespace_conflict([*local, branch]):
        _invalid()
    result = {"branch": branch}
    if unborn:
        result["unborn"] = True
    if "upstream" in current:
        upstream = _exact(current["upstream"], ("remote", "merge"))
        if (not isinstance(upstream["remote"], str) or not isinstance(upstream["merge"], str)
                or not (upstream["remote"] == LOCAL_UPSTREAM or is_remote_name(upstream["remote"]))
                or not is_branch(upstream["merge"])):
            _invalid()
        result["upstream"] = {"remote": upstream["remote"], "merge": upstream["merge"]}
    return result


def _short(name, prefix):
    return name[len(prefix):]


def _heads(refs):
    return [ref for ref in refs if ref["name"].startswith("refs/heads/")]


def _tags(refs):
    return [ref for ref in refs if ref["name"].startswith("refs/tags/")]


def _reserved(refs):
    return any(ref["name"] == RESERVED_BRANCH or ref["name"].startswith(RESERVED_BRANCH + "/") for ref in refs)


def plan_clone(given):
    """Clone into a missing or empty destination. Heads become `origin`'s
    tracking refs and tags are created, with their raw ids; `origin` is the
    canonical URL with the default refspec. An acquired `refs/heads/HEAD` would
    map onto `refs/remotes/origin/HEAD` and is refused. A selector names an
    exact branch, else an equal-named tag whose peeled object must be a
    commit. Without one, the advertised HEAD branch is checked out; without a
    usable HEAD nothing is checked out and HEAD is the unborn fixed branch. The
    checkout target is always the peeled commit. No fallback."""
    obj = _exact(given, ("acquired", "destination"), ("selector",))
    url = _check_acquired(obj["acquired"])
    if "selector" in obj and (not isinstance(obj["selector"], str) or not is_selector(obj["selector"])):
        _invalid()
    if obj["destination"] not in ("missing", "empty", "nonempty"):
        _invalid()
    if obj["destination"] == "nonempty":
        return {"ok": False, "code": "git_destination_not_empty"}
    refs = obj["acquired"]["refs"]
    if _reserved(refs):
        return {"ok": False, "code": "git_ref_unsupported"}
    remote = CLONE_REMOTE
    local = ([{"name": "refs/remotes/%s/%s" % (remote, _short(ref["name"], "refs/heads/")), "oid": ref["oid"]}
              for ref in _heads(refs)]
             + [{"name": ref["name"], "oid": ref["oid"]} for ref in _tags(refs)])
    config = [["remote.%s.url" % remote, url], ["remote.%s.fetch" % remote, default_refspec(remote)]]
    head = obj["acquired"].get("head")
    selector = obj.get("selector")
    if selector is not None:
        chosen = (next((ref for ref in refs if ref["name"] == "refs/heads/" + selector), None)
                  or next((ref for ref in refs if ref["name"] == "refs/tags/" + selector), None))
        if chosen is None:
            return {"ok": False, "code": "git_selector_not_found"}
        if chosen["peeled"]["type"] != "commit":
            return {"ok": False, "code": "git_selector_not_checkoutable"}
        checkout = _checkout_of(chosen, remote, config)
    else:
        chosen = next((ref for ref in refs if ref["name"] == head), None)
        checkout = {"kind": "none", "unborn": UNBORN_BRANCH} if chosen is None else _checkout_of(chosen, remote, config)
    # The complete resulting namespace: created refs, the remote HEAD symref
    # and the checked-out branch.
    resulting = ([ref["name"] for ref in local] + ([] if head is None else ["refs/remotes/%s/HEAD" % remote])
                 + ([checkout["branch"]] if checkout["kind"] == "branch" else []))
    if namespace_conflict(resulting):
        return {"ok": False, "code": "git_ref_conflict"}
    plan = {"ok": True, "remote": remote, "url": url, "config": config, "refs": local}
    if head is not None:
        plan["remote_head"] = "refs/remotes/%s/%s" % (remote, _short(head, "refs/heads/"))
    plan["checkout"] = checkout
    return plan


def _checkout_of(ref, remote, config):
    if ref["name"].startswith("refs/tags/"):
        return {"kind": "detached", "ref": ref["name"], "commit": ref["peeled"]["oid"]}
    name = _short(ref["name"], "refs/heads/")
    config.extend([["branch.%s.remote" % name, remote], ["branch.%s.merge" % name, ref["name"]]])
    return {"kind": "branch", "branch": ref["name"], "commit": ref["peeled"]["oid"], "upstream": ref["name"]}


def plan_fetch(given):
    """Fetch for one configured remote with exactly one canonical URL and only
    the default refspec. An acquired `refs/heads/HEAD` is refused. Tracking
    refs are created or moved to the acquired raw id (the refspec is forced);
    tracking refs of branches absent upstream are retained, never pruned.
    Local branches, the index, the worktree, `refs/remotes/<remote>/HEAD` and
    the remote URL are never planned to change. Absent tags are created,
    identical ones left; any differing existing tag fails the whole plan
    before any update. FETCH_HEAD lists every fetched head, then tag, with raw
    ids; only the current branch's configured upstream, when its remote is
    this remote and it was fetched, is eligible for merge, first."""
    obj = _exact(given, ("remote", "urls", "fetch", "local", "acquired"), ("current",))
    url = _check_acquired(obj["acquired"])
    if not isinstance(obj["remote"], str) or not is_remote_name(obj["remote"]):
        _invalid()
    urls = _strings(obj["urls"])
    refspecs = _strings(obj["fetch"])
    existing = _check_local(obj["local"])
    current = _check_current(obj["current"], existing) if "current" in obj else None
    if len(urls) != 1:
        return {"ok": False, "code": "git_remote_unsupported"}
    configured = parse_repository_url(urls[0])
    if configured is None or repository_id(configured) != obj["acquired"]["repository"]:
        return {"ok": False, "code": "git_remote_unsupported"}
    if len(refspecs) != 1 or refspecs[0] != default_refspec(obj["remote"]):
        return {"ok": False, "code": "git_refspec_unsupported"}
    refs = obj["acquired"]["refs"]
    if _reserved(refs):
        return {"ok": False, "code": "git_ref_unsupported"}
    fetched_tags = _tags(refs)
    if any(ref["name"] in existing and existing[ref["name"]] != ref["oid"] for ref in fetched_tags):
        return {"ok": False, "code": "git_tag_conflict"}
    tracking = "refs/remotes/%s/" % obj["remote"]
    planned = ([(tracking + _short(ref["name"], "refs/heads/"), ref["oid"]) for ref in _heads(refs)]
               + [(ref["name"], ref["oid"]) for ref in fetched_tags])
    updates = []
    unchanged = []
    for ref, oid in planned:
        old = existing.get(ref)
        if old == oid:
            unchanged.append(ref)
        else:
            update = {"ref": ref}
            if old is not None:
                update["old"] = old
            update["new"] = oid
            updates.append(update)
    if namespace_conflict([*existing, *(ref for ref, _ in planned)]):
        return {"ok": False, "code": "git_ref_conflict"}
    fetched_tracking = {ref for ref, _ in planned}
    retained = sorted(name for name in existing
                      if name.startswith(tracking) and name != tracking + "HEAD" and name not in fetched_tracking)
    upstream = (current or {}).get("upstream")
    merge_ref = upstream["merge"] if upstream is not None and upstream["remote"] == obj["remote"] else None
    entries = [{"ref": ref["name"], "oid": ref["oid"], "merge": ref["name"] == merge_ref}
               for ref in _heads(refs) + fetched_tags]
    fetch_head = [entry for entry in entries if entry["merge"]] + [entry for entry in entries if not entry["merge"]]
    return {"ok": True, "url": url, "updates": updates, "unchanged": unchanged, "retained": retained,
            "fetch_head": fetch_head}
