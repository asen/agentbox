"""Agentbox's PEP 517 build backend (pyproject.toml, `backend-path`):
stdlib only, no build requirement, nothing downloaded by itself.

  sdist   agentbox-V.tar.gz: SDIST below plus package.py's asset allowlist,
          the launcher and PKG-INFO; no .git, tests, build output or docs
  wheel   agentbox-V-py3-none-linux_x86_64.whl: `cargo build --release
          --locked` of the relay child (cargo from PATH, its crates from
          cargo's own sources), then package.py stages PREFIX in private
          scratch, laid out as
            agentbox-V.data/scripts/{agentbox,agentbox-server,      0755
                                     agentbox-relay}
            agentbox-V.data/data/share/agentbox-assets/...        0644
            agentbox-V.dist-info/{METADATA,WHEEL,RECORD}

pip installs scripts beside the other scheme's `data`: bin/ and
share/agentbox-assets/ under one prefix (a venv, ~/.local, /usr/local),
as the launcher expects. The launcher's `#!/usr/bin/python3 -IB` is kept
(pip rewrites only `#!python`). File modes come from the installer's
umask (README.md here).

V is the relay crate's version (crates/agentbox-relay/Cargo.toml). The wheel is
a local Linux x86-64 build: it needs the glibc of the host that built it.
No editable install.
"""
import base64
import gzip
import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import package  # noqa: E402

NAME = "agentbox"
SUMMARY = "Runs commands, typically coding agents, inside isolated Linux jails"
# pip checks it against its own interpreter only; the launcher checks
# /usr/bin/python3 (doctor.MIN_PYTHON, the same minimum).
REQUIRES_PYTHON = ">=3.12"
TAG = "py3-none-linux_x86_64"
# The workspace's one crate, the relay child's.
CRATE = "crates/agentbox-relay"
CRATES = (CRATE,)
# The sdist beyond the asset allowlist and the launchers: the build itself
# and the crate's sources (every regular *.rs below each CRATES/src).
SDIST = ("pyproject.toml", "README.md", "LICENSE", "Cargo.toml", "Cargo.lock",
         *(f"{crate}/Cargo.toml" for crate in CRATES),
         "packaging/README.md", "packaging/package.py", "packaging/agentbox_build.py")
# Reproducible archives: SOURCE_DATE_EPOCH, else the zip epoch.
EPOCH = 315532800


class BuildRefused(SystemExit):
    def __init__(self, text):
        sys.stderr.write(f"agentbox build: {text}\n")
        super().__init__(1)


def _source():
    return os.path.realpath(os.getcwd())


def version(source):
    """The relay crate's `[package] version`."""
    with open(os.path.join(source, CRATE, "Cargo.toml"), encoding="utf-8") as stream:
        text = stream.read()
    found = re.search(r'^\[package\]\n(?:(?!\[).*\n)*?version = "([0-9]+\.[0-9]+\.[0-9]+)"$', text, re.M)
    if found is None:
        raise BuildRefused(f"no version in {CRATE}/Cargo.toml")
    return found.group(1)


def metadata(source):
    return (f"Metadata-Version: 2.1\nName: {NAME}\nVersion: {version(source)}\nSummary: {SUMMARY}\n"
            f"License: MIT\nRequires-Python: {REQUIRES_PYTHON}\n"
            f"Classifier: Operating System :: POSIX :: Linux\n").encode()


def _mtime():
    try:
        return max(EPOCH, int(os.environ["SOURCE_DATE_EPOCH"]))
    except (KeyError, ValueError):
        return EPOCH


def sdist_files(source):
    """Every sdist path below `source`, sorted; refused (package.py's
    codes) on a missing or linked one."""
    paths = set(SDIST) | {package.LAUNCHER_SOURCE, package.SERVER_SOURCE}
    try:
        paths |= set(package.allowlist(source))
    except package.Refused as error:
        raise BuildRefused(f"refused: {error}") from None
    for crate in CRATES:
        for parent, dirs, names in os.walk(os.path.join(source, crate, "src")):
            dirs.sort()
            for name in names:
                path = os.path.join(parent, name)
                if name.endswith(".rs") and stat.S_ISREG(os.lstat(path).st_mode):
                    paths.add(os.path.relpath(path, source))
    return sorted(paths)


def _read(src_fd, rel):
    try:
        fd = package.open_below(src_fd, rel)
    except package.Refused:
        raise BuildRefused(f"refused: source: {rel}") from None
    with os.fdopen(fd, "rb") as stream:
        return stream.read()


def build_sdist(sdist_directory, config_settings=None):
    source = _source()
    base = f"{NAME}-{version(source)}"
    name = f"{base}.tar.gz"
    mtime = _mtime()
    src_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        members = [(rel, _read(src_fd, rel)) for rel in sdist_files(source)]
    finally:
        os.close(src_fd)
    members.append(("PKG-INFO", metadata(source)))
    dirs = sorted({os.path.dirname(rel) for rel, _ in members} - {""})
    dirs = sorted({"/".join(d.split("/")[:i]) for d in dirs for i in range(1, d.count("/") + 2)})
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        def entry(rel, kind, size=0):
            info = tarfile.TarInfo(f"{base}/{rel}" if rel else base)
            info.type, info.size, info.mtime = kind, size, mtime
            info.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            return info
        tar.addfile(entry("", tarfile.DIRTYPE))
        for rel in dirs:
            tar.addfile(entry(rel, tarfile.DIRTYPE))
        for rel, data in sorted(members):
            tar.addfile(entry(rel, tarfile.REGTYPE, len(data)), io.BytesIO(data))
    # gzip's own header: the same time, no file name; reproducible bytes.
    with open(os.path.join(sdist_directory, name), "wb") as stream:
        with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=mtime) as compressed:
            compressed.write(raw.getvalue())
    return name


def _dist_info(source):
    return f"{NAME}-{version(source)}.dist-info"


def _wheel_file():
    return f"Wheel-Version: 1.0\nGenerator: agentbox_build\nRoot-Is-Purelib: false\nTag: {TAG}\n".encode()


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    source = _source()
    info = _dist_info(source)
    os.mkdir(os.path.join(metadata_directory, info))
    for name, data in (("METADATA", metadata(source)), ("WHEEL", _wheel_file())):
        with open(os.path.join(metadata_directory, info, name), "wb") as stream:
            stream.write(data)
    return info


def cargo(source):
    """`cargo build --release --locked` of SOURCE's workspace (the relay
    child) into SOURCE/target; the built relay's path."""
    found = shutil.which("cargo")
    if found is None:
        raise BuildRefused("cargo not found on PATH: the wheel builds agentbox-relay from source "
                           "(Rust, packaging/README.md)")
    target = os.path.join(source, "target")
    done = subprocess.run([found, "build", "--release", "--locked", "--target-dir", target], cwd=source,
                          stdin=subprocess.DEVNULL)
    if done.returncode != 0:
        raise BuildRefused(f"cargo build failed ({done.returncode})")
    return os.path.join(target, "release", "agentbox-relay")


def _record_line(path, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{path},sha256={digest},{len(data)}\n"


def wheel_entries(prefix, base):
    """[(archive path, file bytes, mode)] of a staged PREFIX, sorted."""
    entries = []
    for parent, dirs, names in os.walk(prefix):
        dirs.sort()
        for name in sorted(names):
            path = os.path.join(parent, name)
            rel = os.path.relpath(path, prefix)
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode):
                raise BuildRefused(f"refused: staged: {rel}")
            if rel.startswith("bin/"):
                target = f"{base}.data/scripts/{rel[len('bin/'):]}"
            elif rel.startswith(package.ASSETS + "/"):
                target = f"{base}.data/data/{rel}"
            else:
                raise BuildRefused(f"refused: staged: {rel}")
            with open(path, "rb") as stream:
                entries.append((target, stream.read(), stat.S_IMODE(st.st_mode)))
    return sorted(entries)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    source = _source()
    base = f"{NAME}-{version(source)}"
    info = _dist_info(source)
    relay = cargo(source)
    with tempfile.TemporaryDirectory(prefix="agentbox-wheel-") as scratch:
        prefix = os.path.join(os.path.realpath(scratch), "prefix")
        try:
            package.package(source, relay, prefix)
        except package.Refused as error:
            raise BuildRefused(f"refused: {error}") from None
        entries = wheel_entries(prefix, base)
    entries += [(f"{info}/METADATA", metadata(source), 0o644), (f"{info}/WHEEL", _wheel_file(), 0o644)]
    name = f"{base}-{TAG}.whl"
    stamp = time.gmtime(_mtime())[:6]
    record = "".join(_record_line(path, data) for path, data, _ in entries) + f"{info}/RECORD,,\n"
    path = os.path.join(wheel_directory, name)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for target, data, mode in entries + [(f"{info}/RECORD", record.encode(), 0o644)]:
            item = zipfile.ZipInfo(target, stamp)
            item.external_attr = (stat.S_IFREG | mode) << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, data)
    return name
