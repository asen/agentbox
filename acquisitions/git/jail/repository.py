"""Pure public GitHub repository identity and Git ref grammar of
acquisitions/git/contract/v1. No I/O, lookup, fetch or authority.

The Rust host (git_repository.rs) implements the same rules; both test the
shared repository-fixtures.json. The HTTPS URL is derived from validated
components, never adopted. Names and refs are untrusted display data; they
are literal argv items or JSON strings, never shell text, and grant nothing.
A repository is an (owner, name) pair."""

import re

HOST = "github.com"
URL_PREFIX = "https://github.com/"
# Bound before any URL parsing.
MAX_URL_BYTES = 256
MAX_OWNER_BYTES = 39
MAX_NAME_BYTES = 100
# A full `refs/heads/` or `refs/tags/` name.
MAX_REF_BYTES = 256
# A short branch or tag name; it fits under both ref prefixes.
MAX_SELECTOR_BYTES = MAX_REF_BYTES - len("refs/heads/")
OBJECT_FORMAT = "sha1"
OID_HEX_BYTES = 40
REF_PREFIXES = ("refs/heads/", "refs/tags/")

_OWNER = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?")
_NAME = re.compile(r"[a-z0-9._][a-z0-9._-]{0,99}")
_OID = re.compile(r"[0-9a-f]{40}")
_NONZERO = re.compile(r"[1-9a-f]")
_PRINTABLE = re.compile(r"[\x21-\x7e]+")
_FORBIDDEN = re.compile(r"[~^:?*\[\\]")


def parse_repository(text):
    """The canonical `owner/name` form only: no normalization, no `.git`."""
    slash = text.find("/")
    if slash < 0:
        return None
    owner, name = text[:slash], text[slash + 1:]
    if (_OWNER.fullmatch(owner) is None or _NAME.fullmatch(name) is None or name in (".", "..")
            or name.endswith(".git")):
        return None
    return owner, name


def parse_repository_url(url):
    """Exactly `https://github.com/OWNER/REPO` or `.../REPO.git`, owner and name
    case-insensitive and lowercased, one lowercase `.git` removed. Anything
    else is refused."""
    if len(url.encode("utf-8", "surrogatepass")) > MAX_URL_BYTES or not url.startswith(URL_PREFIX):
        return None
    rest = url[len(URL_PREFIX):]
    slash = rest.find("/")
    if slash < 0:
        return None
    name = rest[slash + 1:]
    if name.endswith(".git"):
        name = name[:-4]
    return parse_repository("%s/%s" % (_ascii_lower(rest[:slash]), _ascii_lower(name)))


def repository_id(repository):
    return "%s/%s" % repository


def repository_url(repository):
    """The host-derived HTTPS URL."""
    return "%s%s/%s.git" % (URL_PREFIX, repository[0], repository[1])


def is_ref(text):
    """A full branch or tag ref under `git check-ref-format`, printable ASCII."""
    return len(text) <= MAX_REF_BYTES and any(text.startswith(prefix) and is_short_ref(text[len(prefix):])
                                              for prefix in REF_PREFIXES)


def is_selector(text):
    """A `clone --branch` selector: short branch or tag, not `-...` or `HEAD`."""
    return len(text) <= MAX_SELECTOR_BYTES and is_short_ref(text) and not text.startswith("-") and text != "HEAD"


def is_oid(text):
    """40 lowercase hex digits, not the null object id."""
    return isinstance(text, str) and _OID.fullmatch(text) is not None and _NONZERO.search(text) is not None


def is_short_ref(text):
    """`git check-ref-format` over printable ASCII, for the part after a ref namespace."""
    return (_PRINTABLE.fullmatch(text) is not None and _FORBIDDEN.search(text) is None and ".." not in text
            and "@{" not in text and text != "@" and not text.endswith(".")
            and all(len(part) > 0 and not part.startswith(".") and not part.endswith(".lock")
                    for part in text.split("/")))


def _ascii_lower(text):
    """ASCII-only lowercasing; other characters stay and then fail the grammar."""
    return re.sub(r"[A-Z]", lambda match: match.group().lower(), text)
