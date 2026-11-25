"""The Agentbox worker: one layout (layout.json here), assembled from source
inside an image builder, then installed and sealed at its fixed path. Stdlib
only; it runs, imports and compiles nothing it bundles. Shared by the Podman
and QEMU recipes (README.md here).

  worker.py build --sources DIR --out DIR [--counterparts DIR]
      DIR/worker/                the bundle (agentbox.worker-bundle.v3)
      DIR/worker-metadata.json   build metadata, kept apart from the bundle
  worker.py validate ROOT [--metadata FILE]
  worker.py install --from DIR      copy DIR/worker to the install root, seal
  worker.py seal                    validate and seal in place (root only)

`build` takes explicitly staged sources only (stage.py), laid out as in the
repository: the guest's regular packages (`guest/__init__.py`,
`guest/src/*.py`), `acquisitions/__init__.py` and, for each shipped handler
with a jail tree, `acquisitions/ID/__init__.py` and
`acquisitions/ID/jail/*.py`. The bundle is those exact files, source only:
no interpreter, bytecode, cache or test. The jail's Python is the image's
or the operator's, chosen independently of this build; nothing here probes
it. Every entrypoint adds only the bundle root to its isolated interpreter's
path and imports by absolute name (`guest.src.X`, `acquisitions.ID.jail.Y`).

`--counterparts DIR` adds handlers' ready jail modules: DIR holds only
regular files `ID.py` (ID a handler id), each placed at
`acquisitions/ID/jail/ID.py` (a jail manifest's `jail.entry`). Each runs as
an entry script, so it may import only the bundle's own modules and the
standard library. A path the sources already provide is refused. The
operator vouches for these files as for the asset tree; the bundle is still
only the jail's convenience, never host authority.

The manifest records actual sizes and digests; its `revision` is the staged
sources' digest. Nothing here admits or names an image candidate.

Every byte of a bundle is readable by the workload: never put secrets in
one. Errors are fixed codes (`Refused`), never file content.
"""
import hashlib
import json
import os
import re
import shutil
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_layout():
    with open(os.path.join(HERE, "layout.json"), "rb") as stream:
        return json.loads(stream.read())


LAYOUT = _load_layout()
BUNDLE = LAYOUT["bundle"]
LIMITS = BUNDLE["limits"]
MANIFEST = BUNDLE["manifest"]
REQUIRED = tuple(BUNDLE["required"])
ENTRYPOINTS = tuple(LAYOUT["entrypoints"])
INSTALL_ROOT = LAYOUT["install_root"]
METADATA = LAYOUT["metadata"]
SOURCES = LAYOUT["sources"]
KEYS = ("schema", "platform", "protocol", "guest_version", "revision", "files")

NAME = re.compile(r"[A-Za-z0-9._-]+")
DIGEST = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
PROTECTED = "human.md"
COUNTERPART = re.compile(r"[a-z][a-z0-9-]{0,31}\.py")
HANDLER_ID = re.compile(r"[a-z][a-z0-9-]{0,31}")
JAIL_ENTRY = re.compile(r"acquisitions/([a-z][a-z0-9-]{0,31})/jail/\1\.py")
MODULE = re.compile(r"[a-z_][a-z0-9_]*\.py")


class Refused(Exception):
    """A fixed refusal code."""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


# ---------------------------------------------------------------------------
# Bundle rules (worker_bundle.rs): manifest, paths, tree, digests.

def plain(path):
    """A listed path: beneath a top dir, 2 to max depth components of
    [A-Za-z0-9._-], none starting with '.' or '-', none HUMAN.md in any
    case."""
    parts = path.split("/")
    return (len(path.encode()) <= LIMITS["max_path_bytes"]
            and 2 <= len(parts) <= LIMITS["max_path_depth"]
            and parts[0] in BUNDLE["top_dirs"]
            and all(NAME.fullmatch(p) is not None and len(p) <= LIMITS["max_name_bytes"]
                    and not p.startswith((".", "-")) and p.lower() != PROTECTED for p in parts))


def listing(data):
    """The closed manifest's files, {path: (size, sha256)}; refuses anything else."""
    if len(data) > LIMITS["max_manifest_bytes"]:
        raise Refused("manifest")
    try:
        manifest = json.loads(data)
    except ValueError:
        raise Refused("manifest") from None
    if not isinstance(manifest, dict) or set(manifest) != set(KEYS):
        raise Refused("manifest")
    revision = manifest["revision"]
    if (manifest["schema"] != BUNDLE["schema"] or manifest["platform"] != BUNDLE["platform"]
            or type(manifest["protocol"]) is not int or manifest["protocol"] != BUNDLE["protocol"]
            or manifest["guest_version"] != BUNDLE["guest_version"]
            or not isinstance(revision, str) or REVISION.fullmatch(revision) is None
            or not isinstance(manifest["files"], list)):
        raise Refused("manifest")
    if not 0 < len(manifest["files"]) <= LIMITS["max_files"]:
        raise Refused("limit")
    files, previous, total = {}, "", 0
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise Refused("manifest")
        path, size, digest = entry["path"], entry["size"], entry["sha256"]
        if not isinstance(path, str) or not plain(path) or path <= previous:
            raise Refused("path")
        if type(size) is not int or size < 0:
            raise Refused("manifest")
        total += size
        if size > LIMITS["max_file_bytes"] or total > LIMITS["max_total_bytes"]:
            raise Refused("limit")
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            raise Refused("manifest")
        files[path] = (size, digest)
        previous = path
    if any(other.startswith(path + "/") for path in files for other in files):
        raise Refused("path")
    if not all(path in files for path in REQUIRED):
        raise Refused("required")
    return files


def directories(files):
    found = {""}
    for path in files:
        parts = path.split("/")
        found.update("/".join(parts[:i]) for i in range(1, len(parts)))
    return found


def classify(entries, files):
    """Exactly the listing's directories, its files and the manifest; every
    file regular with one link; nothing else."""
    dirs, regular = set(), set()
    for rel, kind, links in entries:
        if kind == "dir":
            dirs.add(rel)
        elif kind == "file" and links == 1:
            regular.add(rel)
        else:
            raise Refused("entry")
    if dirs != directories(files) or regular != set(files) | {MANIFEST}:
        raise Refused("entry")


def scan(root):
    """Every entry beneath `root` by `lstat` alone: (rel, kind, links, stat)."""
    entries = []

    def walk(rel, depth):
        if depth > LIMITS["max_path_depth"]:
            raise Refused("entry")
        full = os.path.join(root, rel) if rel else root
        st = os.lstat(full)
        kind = "dir" if stat.S_ISDIR(st.st_mode) else "file" if stat.S_ISREG(st.st_mode) else "other"
        entries.append((rel, kind, st.st_nlink, st))
        if kind == "dir":
            for name in sorted(os.listdir(full)):
                walk(f"{rel}/{name}" if rel else name, depth + 1)

    walk("", 0)
    return entries


def opened(path, directory=False, dir_fd=None):
    """`path` opened without following a final link; a directory, or a
    regular file with one link."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if directory else os.O_NONBLOCK)
    try:
        fd = os.open(path, flags, dir_fd=dir_fd)
    except OSError:
        raise Refused("entry") from None
    st = os.fstat(fd)
    if not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode) and st.st_nlink == 1):
        os.close(fd)
        raise Refused("entry")
    return fd


def measured(path):
    """A regular single-link file's (size, sha256)."""
    with os.fdopen(opened(path), "rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        return os.fstat(stream.fileno()).st_size, digest


def read_small(path, limit):
    with os.fdopen(opened(path), "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise Refused("limit")
    return data


def validate(root):
    """The bundle at `root`, exactly: (release, files). The root is opened
    first; the manifest beneath its descriptor; then the tree and every
    digest."""
    root_fd = opened(root, directory=True)
    try:
        fd = opened(MANIFEST, dir_fd=root_fd)
    finally:
        os.close(root_fd)
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(LIMITS["max_manifest_bytes"] + 1)
    files = listing(data)
    classify([(rel, kind, links) for rel, kind, links, _ in scan(root)], files)
    for path, expected in files.items():
        if measured(os.path.join(root, path)) != expected:
            raise Refused("digest")
    return sha256_bytes(data), files


def entrypoints(files):
    """The layout's entrypoints and every listed jail entry module,
    `acquisitions/ID/jail/ID.py`, sourced or added (`counterparts`)."""
    modules = [p for p in files if JAIL_ENTRY.fullmatch(p)]
    return tuple(sorted(set(ENTRYPOINTS) | set(modules)))


def jail_entry(name):
    """A counterpart `ID.py`'s bundle path."""
    handler = name[:-len(".py")]
    return f"{SOURCES['handlers']}/{handler}/{SOURCES['jail']}/{name}"


def counterparts(source):
    """[(name, path)] of the ready jail modules in `source` (module doc);
    [] without one."""
    if source is None:
        return []
    found = []
    for rel, kind, links, _ in scan(source):
        if rel == "" and kind == "dir":
            continue
        if kind != "file" or links != 1 or "/" in rel or not COUNTERPART.fullmatch(rel):
            raise Refused("counterpart")
        found.append((rel, os.path.join(source, rel)))
    if len(found) > 32:
        raise Refused("counterpart")
    return sorted(found)


def mode(rel, kind):
    return 0o555 if kind == "dir" else 0o444


def seal(root, uid, gid):
    """Every entry owned uid:gid, files before directories, deepest first,
    each through its own no-follow descriptor; then checked again."""
    entries = scan(root)
    for rel, kind, _, _ in sorted(entries, key=lambda e: (e[1] == "dir", -e[0].count("/"), e[0])):
        fd = opened(os.path.join(root, rel) if rel else root, kind == "dir")
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode(rel, kind))
        finally:
            os.close(fd)
    for rel, kind, _, st in scan(root):
        if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, mode(rel, kind)):
            raise Refused("seal")


def parents_ok(path):
    """Every parent of `path`: a directory, not a link, root's, not
    group/other-writable."""
    parent = os.path.dirname(path)
    while True:
        st = os.lstat(parent)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused("parent")
        if parent == "/":
            return
        parent = os.path.dirname(parent)


# ---------------------------------------------------------------------------
# Sources: the allowlist below a repository (or a staged copy), measured.

def _regular(path):
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise Refused("source")
    return st


def _package(repo, top, paths):
    """The regular package `top` (relative to `repo`): its `__init__.py`
    (required) and every other module directly in it, into `paths`.
    Subdirectories are not part of it (a listed package is its own entry);
    the interpreter's own caches are skipped unopened. Any other entry, a
    link, a special file or a protected name is refused."""
    if not stat.S_ISDIR(os.lstat(os.path.join(repo, top)).st_mode):
        raise Refused("source")
    found = []
    for name in sorted(os.listdir(os.path.join(repo, top))):
        child = f"{top}/{name}"
        st = os.lstat(os.path.join(repo, child))
        if stat.S_ISDIR(st.st_mode):
            continue
        if name.lower() == PROTECTED or MODULE.fullmatch(name) is None or not stat.S_ISREG(st.st_mode) \
                or st.st_nlink != 1 or st.st_size > SOURCES["max_source_bytes"]:
            raise Refused("source")
        found.append(child)
    if f"{top}/{SOURCES['package']}" not in found:
        raise Refused("source")
    paths.extend(found)


def _directories(repo, top, allowed):
    """`top`'s subdirectories are exactly `allowed` and the interpreter's
    cache: a stray package is refused rather than silently dropped."""
    for name in sorted(os.listdir(os.path.join(repo, top))):
        st = os.lstat(os.path.join(repo, top, name))
        if stat.S_ISDIR(st.st_mode) and name != SOURCES["cache"] and name not in allowed:
            raise Refused("source")


def handler_jails(repo):
    """The shipped handlers with a jail source tree: each `ID` directly
    beneath `acquisitions/` (a handler id, not `lib` or `testing`) holding a
    `jail` directory. Other names (caches, tests, fixtures) are not
    sources and are never opened."""
    base = os.path.join(repo, SOURCES["handlers"])
    found = []
    for name in sorted(os.listdir(base)):
        if HANDLER_ID.fullmatch(name) is None or name in SOURCES["skip"]:
            continue
        if not stat.S_ISDIR(os.lstat(os.path.join(base, name)).st_mode):
            continue
        jail = os.path.join(base, name, SOURCES["jail"])
        if os.path.lexists(jail):
            found.append(name)
    return found


def source_paths(repo):
    """The allowlisted relative paths below `repo`: the package markers
    `guest/__init__.py` and `acquisitions/__init__.py`, the package
    `guest/src` and, for each shipped handler, `acquisitions/ID/__init__.py`
    and its package `acquisitions/ID/jail`. Anything else in those packages,
    a link, a special file or a protected name is refused; nothing outside
    the allowlist is ever read."""
    guest, src, handlers = SOURCES["packages"]
    marker = SOURCES["package"]
    paths = []
    for top in (guest, handlers):
        _regular(os.path.join(repo, top, marker))
        paths.append(f"{top}/{marker}")
    _package(repo, src, paths)
    _directories(repo, src, set())
    for name in handler_jails(repo):
        _regular(os.path.join(repo, handlers, name, marker))
        paths.append(f"{handlers}/{name}/{marker}")
        jail = f"{handlers}/{name}/{SOURCES['jail']}"
        _package(repo, jail, paths)
        _directories(repo, jail, set())
    return sorted(paths)


def source_files(repo):
    """[{path, size, sha256}] of the allowlisted sources, sorted."""
    out = []
    for path in source_paths(repo):
        size, digest = measured(os.path.join(repo, path))
        out.append({"path": path, "size": size, "sha256": digest})
    return out


def source_revision(files):
    """The sources' identity: SHA-256 of their canonical listing."""
    return sha256_bytes(canonical(files))


def stage_sources(repo, dest):
    """Copies exactly the allowlisted sources below `repo` into the new
    directory `dest`, same layout; returns their listing."""
    files = source_files(repo)
    os.mkdir(dest, 0o755)
    for entry in files:
        target = os.path.join(dest, entry["path"])
        os.makedirs(os.path.dirname(target), 0o755, exist_ok=True)
        _copy(os.path.join(repo, entry["path"]), target, 0o644)
    if source_files(dest) != files:
        raise Refused("source")
    return files


def _copy(source, target, perm):
    with os.fdopen(opened(source), "rb") as src:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, perm)
        with os.fdopen(fd, "wb") as dst:
            shutil.copyfileobj(src, dst)
    os.chmod(target, perm, follow_symlinks=False)


# ---------------------------------------------------------------------------
# Build.

def manifest_bytes(files, revision):
    manifest = {"schema": BUNDLE["schema"], "platform": BUNDLE["platform"], "protocol": BUNDLE["protocol"],
                "guest_version": BUNDLE["guest_version"], "revision": revision, "files": files}
    return (json.dumps(manifest, indent=2) + "\n").encode()


def assemble(sources, modules, added, revision, out):
    """The bundle at the new directory `out`: exactly `modules` from
    `sources` and the counterparts `added`, at their bundle paths."""
    os.mkdir(out, 0o755)
    entries = []

    def put(rel, source):
        target = os.path.join(out, rel)
        os.makedirs(os.path.dirname(target), 0o755, exist_ok=True)
        _copy(source, target, 0o644)
        size, digest = measured(target)
        entries.append({"path": rel, "size": size, "sha256": digest})

    for rel in modules:
        put(rel, os.path.join(sources, rel))
    for name, path in added:
        put(jail_entry(name), path)
    data = manifest_bytes(sorted(entries, key=lambda e: e["path"]), revision)
    fd = os.open(os.path.join(out, MANIFEST), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    return data


def layout_digest():
    return measured(os.path.join(HERE, "layout.json"))[1]


def build(sources, out, extra=None):
    """Assembles the bundle and its metadata into the new directory `out`
    from staged `sources`, with the ready jail modules of `extra`
    (`counterparts`); returns the metadata."""
    added = counterparts(extra)
    files = source_files(sources)
    if [f["path"] for f in files] != source_paths(sources) \
            or sorted(os.listdir(sources)) != sorted({SOURCES["packages"][0], SOURCES["handlers"]}) \
            or {rel for rel, kind, _, _ in scan(sources) if kind != "dir"} != {f["path"] for f in files}:
        raise Refused("source")
    listed = {f["path"] for f in files}
    if any(jail_entry(name) in listed for name, _ in added):
        raise Refused("counterpart")
    revision = source_revision(files)
    os.mkdir(out, 0o755)
    bundle = os.path.join(out, "worker")
    manifest = assemble(sources, sorted(listed), added, revision, bundle)
    release, contents = validate(bundle)
    if not set(entrypoints(contents)) <= set(contents):
        raise Refused("required")
    metadata = {
        "schema": METADATA["schema"],
        "release": release,
        "install_root": INSTALL_ROOT,
        "manifest": manifest.decode(),
        "files": len(contents),
        "bytes": sum(size for size, _ in contents.values()),
        "entrypoints": list(entrypoints(contents)),
        "counterparts": [{"path": jail_entry(name), "size": contents[jail_entry(name)][0],
                          "sha256": contents[jail_entry(name)][1]} for name, _ in added],
        "sources": {"revision": revision, "files": files},
        "builder": {"worker_py_sha256": measured(os.path.abspath(__file__))[1],
                    "layout_sha256": layout_digest()},
    }
    write_metadata(os.path.join(out, METADATA["file"]), metadata)
    return metadata


def write_metadata(path, metadata):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write((json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode())


def check_metadata(path, release):
    """Build metadata that names exactly this bundle's release and manifest."""
    try:
        metadata = json.loads(read_small(path, 1 << 20))
    except ValueError:
        raise Refused("metadata") from None
    if not isinstance(metadata, dict) or metadata.get("schema") != METADATA["schema"] \
            or metadata.get("release") != release or metadata.get("install_root") != INSTALL_ROOT \
            or not isinstance(metadata.get("manifest"), str) \
            or sha256_bytes(metadata["manifest"].encode()) != release:
        raise Refused("metadata")
    return metadata


# ---------------------------------------------------------------------------
# Installation at the fixed root.

def seal_installed(root=INSTALL_ROOT, metadata=METADATA["installed"]):
    """Validates the bundle and its metadata in place, then seals both
    root-owned and read-only. Root only."""
    if os.geteuid() != 0:
        raise Refused("root")
    parents_ok(root)
    release, _ = validate(root)
    check_metadata(metadata, release)
    seal(root, 0, 0)
    fd = opened(metadata)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o444)
    finally:
        os.close(fd)
    return release


def install(source, root=INSTALL_ROOT, metadata=METADATA["installed"]):
    """Copies a built output's bundle and metadata to their fixed paths
    (neither may exist), then `seal_installed`."""
    validate(os.path.join(source, "worker"))
    shutil.copytree(os.path.join(source, "worker"), root, symlinks=True)
    _copy(os.path.join(source, METADATA["file"]), metadata, 0o444)
    return seal_installed(root, metadata)


def main(argv):
    if argv[:1] == ["build"] and len(argv) in (5, 7) \
            and argv[1::2] == ["--sources", "--out", "--counterparts"][:len(argv) // 2]:
        metadata = build(argv[2], argv[4], argv[6] if len(argv) == 7 else None)
        print(f"agentbox-worker-built {metadata['release']}")
    elif argv[:1] == ["validate"] and len(argv) in (2, 4) and (len(argv) == 2 or argv[2] == "--metadata"):
        release, _ = validate(argv[1])
        if len(argv) == 4:
            check_metadata(argv[3], release)
        print(f"agentbox-worker-valid {release}")
    elif argv[:2] == ["install", "--from"] and len(argv) == 3:
        print(f"agentbox-worker-installed {install(argv[2])}")
    elif argv == ["seal"]:
        print(f"agentbox-worker-installed {seal_installed()}")
    else:
        raise Refused("usage")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (Refused, OSError) as error:
        code = error if isinstance(error, Refused) else type(error).__name__
        print(f"agentbox-worker refused: {code}", file=sys.stderr)
        sys.exit(1)
