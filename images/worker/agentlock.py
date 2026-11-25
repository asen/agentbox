"""The coding agents' npm locks checked (images/agents/README.md). Stdlib
only, nothing imported from the builder: stage.py checks the tracked locks
with it (QEMU), the Podman recipe runs it on the locks resolved in its
build (`agents-check` stage, without network, before `npm ci`) and the
Podman provider on the locks baked into the image it measured.

  python3 -I -B agentlock.py check --registry REGISTRY DIR

DIR holds exactly one directory per agent (AGENTS), each exactly
package.json and package-lock.json: a private project of exactly one exact
dependency (with `check`: the agent's own package, PACKAGES) and a
lockfile v3 of registry tarballs only (no link, bundle, dev or other
source), each exactly at REGISTRY/NAME/-/BASE-VERSION.tgz with a sha512
integrity. Exit 0, or 1 with `agentlock refused: CODE` on stderr.
"""
import json
import os
import re
import stat
import sys

AGENTS = ("pi", "codex", "claude")
# Each agent's npm package (agents/AGENT/adapter.py PACKAGE; resolve.sh).
PACKAGES = {"pi": "@earendil-works/pi-coding-agent", "codex": "@openai/codex",
            "claude": "@anthropic-ai/claude-code"}
REGISTRY = "https://registry.npmjs.org/"
LOCK_FILES = ("package.json", "package-lock.json")
# The image's platform, as npm matches an optional package's os/cpu/libc.
PLATFORM = {"os": "linux", "cpu": "x64", "libc": "glibc"}
MAX_PROJECT_BYTES = 64 << 10
MAX_LOCK_BYTES = 1 << 20
NPM_NAME = r"(?:@[a-z0-9][a-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*"
LOCK_KEY = re.compile(r"node_modules/%s(?:/node_modules/%s)*" % (NPM_NAME, NPM_NAME))
NPM_VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z.-]{1,64})?")
INTEGRITY = re.compile(r"sha512-[A-Za-z0-9+/]{86}==")
FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}")


class Refused(Exception):
    """A fixed refusal code."""


def read(path, limit):
    """`path`'s bytes, a single-link regular file opened without following
    a final link, at most `limit`."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        raise Refused("agent_lock") from None
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise Refused("agent_lock")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise Refused("agent_lock")
    return data


def platform(entry):
    """Whether npm installs `entry` on PLATFORM (`!x` excludes x)."""
    for key, value in PLATFORM.items():
        wanted = entry.get(key)
        if wanted is None:
            continue
        if not isinstance(wanted, list) or not all(isinstance(w, str) and w for w in wanted):
            raise Refused("agent_lock")
        allowed = [w for w in wanted if not w.startswith("!")]
        if "!" + value in wanted or (allowed and value not in allowed):
            return False
    return True


def check(project, lock, registry=REGISTRY, package=None):
    """One agent's package.json and package-lock.json bytes checked (with
    `package`, its one dependency must be that). Returns ((name, version),
    [{name, version, resolved, integrity, file}]) of the tarballs npm
    installs on PLATFORM."""
    try:
        project, lock = json.loads(project), json.loads(lock)
    except ValueError:
        raise Refused("agent_lock") from None
    deps = project.get("dependencies") if isinstance(project, dict) else None
    if not isinstance(deps, dict) or len(deps) != 1 or project.get("private") is not True \
            or not set(project) <= {"name", "version", "private", "dependencies"}:
        raise Refused("agent_lock")
    (top, version), = deps.items()
    packages = lock.get("packages") if isinstance(lock, dict) else None
    if re.fullmatch(NPM_NAME, top) is None or (package is not None and top != package) \
            or not isinstance(version, str) \
            or NPM_VERSION.fullmatch(version) is None or lock.get("lockfileVersion") != 3 \
            or not isinstance(packages, dict) or not isinstance(packages.get(""), dict) \
            or packages[""].get("dependencies") != deps \
            or not isinstance(packages.get("node_modules/" + top), dict) \
            or packages["node_modules/" + top].get("version") != version:
        raise Refused("agent_lock")
    tarballs = []
    for key, entry in packages.items():
        if key == "":
            continue
        if LOCK_KEY.fullmatch(key) is None or not isinstance(entry, dict) \
                or any(entry.get(flag) for flag in ("link", "inBundle", "dev", "devOptional", "extraneous")):
            raise Refused("agent_lock")
        name = entry.get("name", key.rsplit("node_modules/", 1)[1])
        number = entry.get("version")
        if not isinstance(name, str) or re.fullmatch(NPM_NAME, name) is None or not isinstance(number, str) \
                or NPM_VERSION.fullmatch(number) is None \
                or entry.get("resolved") != f"{registry}{name}/-/{name.rsplit('/', 1)[-1]}-{number}.tgz" \
                or not isinstance(entry.get("integrity"), str) or INTEGRITY.fullmatch(entry["integrity"]) is None:
            raise Refused("agent_lock")
        if not platform(entry):
            if entry.get("optional") is not True:
                raise Refused("agent_lock")
            continue
        file = f"{name.lstrip('@').replace('/', '-')}-{number}.tgz"
        if FILE.fullmatch(file) is None:
            raise Refused("agent_lock")
        tarballs.append({"name": name, "version": number, "resolved": entry["resolved"],
                         "integrity": entry["integrity"], "file": file})
    return (top, version), tarballs


def check_dir(base, registry=REGISTRY, package=None):
    """`check` of base/package.json and base/package-lock.json."""
    return check(read(os.path.join(base, "package.json"), MAX_PROJECT_BYTES),
                 read(os.path.join(base, "package-lock.json"), MAX_LOCK_BYTES), registry, package)


def check_tree(root, registry=REGISTRY):
    """`root`/AGENT for every agent, nothing else, each exactly its two
    files, each the agent's own package: {agent: version}."""
    try:
        if sorted(os.listdir(root)) != sorted(AGENTS):
            raise Refused("agent_lock")
        for agent in AGENTS:
            path = os.path.join(root, agent)
            if not stat.S_ISDIR(os.lstat(path).st_mode) or sorted(os.listdir(path)) != sorted(LOCK_FILES):
                raise Refused("agent_lock")
    except OSError:
        raise Refused("agent_lock") from None
    return {agent: check_dir(os.path.join(root, agent), registry, PACKAGES[agent])[0][1] for agent in AGENTS}


def main(argv):
    if len(argv) != 4 or argv[:2] != ["check", "--registry"] or not argv[2].endswith("/"):
        raise Refused("usage")
    check_tree(argv[3], argv[2])


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Refused as error:
        print(f"agentlock refused: {error}", file=sys.stderr)
        sys.exit(1)
