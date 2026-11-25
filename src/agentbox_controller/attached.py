"""Attached records: an operator's own Linux jail reached over SSH
(docs/ssh-worker.md), as a new-path run.

```text
main.py attach --config C --ssh-target T
  T  agentbox.ssh-target.v3 {schema, host, port, user, identity, host_key,
     remote_root[, python], bundle, revision}   the operator's file
  the bundle validated (images/worker/worker.py `validate`), its manifest's
  revision = T.revision; the record: T itself, its canonical SHA-256,
  retention `operator`, HOME REMOTE_ROOT/agentbox-worker-v1/home
  local state only: nothing is contacted
```

Each execution re-validates the bundle (release = the recorded one, else
`worker_mismatch`), pins `host_key` in the execution's own known_hosts,
uploads the bundle into a fresh installation (sftp batch) and verifies it
there. The jail is the operator's: no provider, domain or stop; nothing
of it is started, stopped, deleted or observed; its storage is retained.
`identity` is only ever named to ssh/scp/sftp, never opened here.
"""
import hashlib
import json
import os
import re

from .assets import provider_protocol, worker_layout
from .config import read_private, strict_json
from .host import HostError
from .ssh import LAYOUT_DIR, is_host, is_host_key

TARGET_SCHEMA = "agentbox.ssh-target.v3"
MAX_TARGET_BYTES = 16384
REQUIRED = ("schema", "host", "port", "user", "identity", "host_key", "remote_root", "bundle", "revision")
_PLAIN = re.compile(r"/[A-Za-z0-9._/-]*")


def _plain(path):
    return isinstance(path, str) and _PLAIN.fullmatch(path) is not None and provider_protocol.is_path(path) \
        and path != "/" and len(path) <= 1024


def check_target(value):
    """Every field's rules in a fixed order (supplied.rs `validate`)."""
    if not isinstance(value, dict) or value.get("schema") != TARGET_SCHEMA \
            or not set(REQUIRED) <= set(value) or not set(value) <= set(REQUIRED) | {"python"}:
        raise HostError("ssh_target_invalid")
    if not is_host(value["host"]):
        raise HostError("ssh_target_host_invalid")
    if type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
        raise HostError("ssh_target_port_invalid")
    if not provider_protocol.is_user(value["user"]):
        raise HostError("ssh_target_user_invalid")
    if not _plain(value["identity"]):
        raise HostError("ssh_target_identity_invalid")
    if not is_host_key(value["host_key"]):
        raise HostError("ssh_target_host_key_invalid")
    if not _plain(value["remote_root"]):
        raise HostError("ssh_target_remote_root_invalid")
    if "python" in value and not _plain(value["python"]):
        raise HostError("ssh_target_python_invalid")
    if not _plain(value["bundle"]) or value["bundle"] == value["identity"]:
        raise HostError("ssh_target_bundle_invalid")
    if not isinstance(value["revision"], str) or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value["revision"]) is None:
        raise HostError("ssh_target_revision_invalid")
    return value


def target_digest(target):
    return hashlib.sha256(json.dumps(target, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def home(target):
    return f"{target['remote_root']}/{LAYOUT_DIR}/home"


def bundle(target, release=None):
    """The local bundle validated now: (release, manifest bytes, files).
    Its manifest's `revision` must be the target's; `release`, if given,
    the recorded one."""
    try:
        found, files = worker_layout.validate(target["bundle"])
        fd = worker_layout.opened(os.path.join(target["bundle"], worker_layout.MANIFEST))
        with os.fdopen(fd, "rb") as stream:
            manifest = stream.read(worker_layout.LIMITS["max_manifest_bytes"] + 1)
    except (worker_layout.Refused, OSError):
        raise HostError("ssh_target_bundle_invalid") from None
    if hashlib.sha256(manifest).hexdigest() != found:
        raise HostError("ssh_target_bundle_invalid")
    try:
        revision = json.loads(manifest).get("revision")
    except ValueError:
        revision = None
    if revision != target["revision"]:
        raise HostError("ssh_target_revision_invalid")
    if release is not None and found != release:
        raise HostError("worker_mismatch")
    return found, manifest, files


def attach(store, path, name=None):
    """A new attached record for the target file at `path` (named `name`,
    if given); its run id."""
    target = check_target(strict_json(read_private(path, MAX_TARGET_BYTES, "ssh_target_unreadable"),
                                      "ssh_target_invalid"))
    _, manifest, _ = bundle(target)
    return store.create_attached(target, manifest, home(target), name=name)
