"""The image catalog: named tags over prepared provider images.

```text
DATA/images/             0700
  .lock                  0600 flock: held while a tag is published
  NAME                   0600 agentbox.image-tag.v1, replaced atomically
                         {schema, name, provider, image, worker_release,
                          recipe, profile: builtin | custom}
```

`provider` (config.check_recorded): a custom profile's configuration, a
snapshot, with its recipe's path; a built-in profile's identity and STATE
with its recipe relative to the asset tree, one of the provider's canonical
recipes (builtin.PRESETS: the tag's own preset), both resolved in the
running install at each use (builtin.resolve).

NAME: TAG (below). `default` is the tag when `-t`/`--image` is omitted.
A tag moves only once its prepare succeeded (temp file, fsync, rename):
a failed or cancelled prepare leaves the old one; concurrent prepares of
one tag: the last successful publication wins. Image bytes stay in the
provider's STATE; a run records its own copy of the tag's provider and
the image digest, so moving a tag never changes an existing run. Reading
never creates DATA or the catalog.
"""
import fcntl
import json
import os
import re
import secrets

from .assets import provider_protocol
from .config import check_recorded
from .host import HostError
from .store import _dump, _open_dir, _private_dir, _read, _write_new

TAG_SCHEMA = "agentbox.image-tag.v1"
DIR = "images"
LOCK = ".lock"
DEFAULT = "default"
TAG = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
MAX_TAG_BYTES = 16 * 1024
MAX_TAGS = 4096
PROFILES = ("builtin", "custom")
_SHA = re.compile(r"[0-9a-f]{64}")


def check_name(name):
    if not isinstance(name, str) or TAG.fullmatch(name) is None:
        raise HostError("image_name_invalid")
    return name


def _open_catalog(data, create=False):
    """DATA/images opened without following links, ours and 0700; None
    when absent (and not `create`)."""
    try:
        root = os.open(data, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        if create:
            raise HostError("store_unavailable") from None
        return None
    except OSError:
        raise HostError("store_unavailable") from None
    try:
        if not _private_dir(os.fstat(root)):
            raise HostError("store_invalid")
        if create:
            try:
                os.mkdir(DIR, 0o700, dir_fd=root)
            except FileExistsError:
                pass
        try:
            fd = _open_dir(DIR, root)
        except FileNotFoundError:
            return None
        except OSError:
            raise HostError("image_catalog_invalid") from None
    finally:
        os.close(root)
    if not _private_dir(os.fstat(fd)):
        os.close(fd)
        raise HostError("image_catalog_invalid")
    return fd


def check_tag(value, name):
    if not isinstance(value, dict) or set(value) != {"schema", "name", "provider", "image", "worker_release",
                                                     "recipe", "profile"} \
            or value["schema"] != TAG_SCHEMA or value["name"] != name or value["profile"] not in PROFILES \
            or not isinstance(value["image"], str) or _SHA.fullmatch(value["image"]) is None \
            or not isinstance(value["worker_release"], str) or _SHA.fullmatch(value["worker_release"]) is None \
            or not isinstance(value["recipe"], str):
        raise HostError("image_tag_invalid")
    try:
        check_recorded(value["provider"])
    except HostError:
        raise HostError("image_tag_invalid") from None
    from .builtin import canonical_recipes
    builtin = value["provider"].get("builtin")
    if (value["profile"] == "builtin") != (builtin is not None) \
            or (value["recipe"] not in canonical_recipes(builtin) if builtin
                else not provider_protocol.is_path(value["recipe"])):
        raise HostError("image_tag_invalid")
    return value


def _load(fd, name):
    try:
        raw = _read(fd, name, MAX_TAG_BYTES)
    except FileNotFoundError:
        return None
    except (OSError, HostError):
        raise HostError("image_tag_invalid") from None
    try:
        value = json.loads(raw)
    except ValueError:
        raise HostError("image_tag_invalid") from None
    return check_tag(value, name)


def read(data, name):
    """The tag `name`'s record, or None when it does not exist."""
    check_name(name)
    fd = _open_catalog(data)
    if fd is None:
        return None
    try:
        return _load(fd, name)
    finally:
        os.close(fd)


def resolve(data, name=None):
    """`--image NAME`, else `default`: the tag's record. Never prepares or
    guesses: a missing default says how to make one."""
    record = read(data, DEFAULT if name is None else name)
    if record is None:
        if name is None:
            error = HostError("default_image_missing")
            error.hint = "prepare one: agentbox image prepare podman (or qemu)"
        else:
            error = HostError("image_unknown")
            error.hint = "agentbox image list shows the prepared images"
        raise error
    return record


def entries(data):
    """[(name, record or None if invalid)], sorted by name."""
    fd = _open_catalog(data)
    if fd is None:
        return []
    try:
        names = sorted(n for n in os.listdir(fd) if TAG.fullmatch(n))[:MAX_TAGS]
        found = []
        for name in names:
            try:
                record = _load(fd, name)
            except HostError:
                record = None
            else:
                if record is None:
                    continue
            found.append((name, record))
        return found
    finally:
        os.close(fd)


def publish(data, name, config, image, release, recipe, profile):
    """The tag `name` now names `image` (atomically, under the catalog
    lock); the record written."""
    check_name(name)
    value = check_tag({"schema": TAG_SCHEMA, "name": name, "provider": config, "image": image,
                       "worker_release": release, "recipe": recipe, "profile": profile}, name)
    fd = _open_catalog(data, create=True)
    try:
        lock = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            temp = f".{name}.{secrets.token_hex(8)}"
            _write_new(fd, temp, _dump(value), 0o600)
            try:
                os.rename(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
            except OSError:
                os.unlink(temp, dir_fd=fd)
                raise
            os.fsync(fd)
        finally:
            os.close(lock)
    except OSError:
        raise HostError("image_publish_failed") from None
    finally:
        os.close(fd)
    return value
