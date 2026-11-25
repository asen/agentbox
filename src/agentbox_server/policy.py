"""Model Only, Open and Custom network policies and their decisions (contracts/network/v1).

A decision has two steps around the broker's own resolver:

1. `Policy.admit` matches the CONNECT host and port before any lookup. A
   miss is final.
2. `Admission.validate` checks every candidate address, the resolver's
   answers or the IP literal itself. One unspecified candidate
   (`address.denied`) refuses the whole request; every other address is
   the policy's to allow, loopback, LAN, VPN, host-interface and metadata
   ones included. The result holds the numeric addresses to connect to, so
   nothing is resolved twice.

```text
CONNECT host:port -> rule match? -> resolve once (or the literal) -> any unspecified? -> dial numeric
                     no: destination_not_allowed            yes: address_unspecified
```

Through a configured CONNECT proxy step 2 is `Admission.proxied`: the
admitted authority is sent to the proxy as is, never resolved here; only
an unspecified literal is refused. The proxy chooses the address.

Grants (`with_grants`): a session's exact `host:port` endpoints, CONNECT
authorities, added to a Model Only or Custom policy's effective rules and
its identity; nothing under Open.
"""
import hashlib
import json

from . import strictjson
from .address import (AddressError, Authority, DnsName, authority_text, denied, ip_text, parse_authority,
                      parse_ip)

POLICY_SCHEMA = "agentbox.network-policy.v1"
IDENTITY_SCHEMA = "agentbox.network-policy-identity.v1"
MAX_POLICY_BYTES = 64 * 1024
MAX_PROVIDER_SETS = 8
MAX_DESTINATIONS = 256
MAX_PORTS = 32
MIN_SUBTREE_LABELS = 2
MAX_ANSWERS = 32
MAX_GRANTS = 32

# Code-owned, versioned provider sets: (name, version) -> (qualification,
# ((host, ports), ...)).
PROVIDER_SETS = {
    ("openai-codex", 1): ("pending", (("chatgpt.com", (443,)), ("auth.openai.com", (443,)))),
}
DEFAULT_MODEL_ONLY = (("openai-codex", 1),)


class PolicyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Denial(Exception):
    """`destination_not_allowed`, `dns_answers_*` or `address_unspecified`."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Rule:
    """kind `exact`, `subtree` (with `include_root`) or `address`."""

    __slots__ = ("kind", "name", "include_root", "address", "ports")

    def __init__(self, kind, ports, name=None, include_root=False, address=None):
        self.kind, self.ports = kind, ports
        self.name, self.include_root, self.address = name, include_root, address

    def matches(self, host):
        if self.kind == "exact":
            return host.name is not None and host.name == self.name
        if self.kind == "subtree":
            return host.name is not None and (host.name.is_strictly_within(self.name)
                                              or (self.include_root and host.name == self.name))
        return host.ip is not None and host.ip == self.address

    def text(self):
        return ip_text(self.address) if self.kind == "address" else self.name.text


def _ports(value):
    """serde `Vec<u16>`."""
    if not strictjson.is_array(value) or not all(strictjson.unsigned(port, 16) for port in value):
        raise PolicyError("policy_invalid")
    return list(value)


def _normalize_ports(ports):
    count = len(ports)
    unique = sorted(set(ports))
    if count == 0 or count > MAX_PORTS or len(unique) != count or unique[0] == 0:
        raise PolicyError("rule_ports_invalid")
    return unique


def _typed(value, fields, allowed_unknown=False):
    """A serde struct with `deny_unknown_fields`: its fields as a dict;
    unknown or duplicate keys refused."""
    if not isinstance(value, strictjson.Pairs):
        raise PolicyError("policy_invalid")
    seen = {}
    for key, item in value:
        if key not in fields:
            if allowed_unknown:
                continue
            raise PolicyError("policy_invalid")
        if key in seen:
            raise PolicyError("policy_invalid")
        seen[key] = item
    return seen


def _string(value):
    if not isinstance(value, str):
        raise PolicyError("policy_invalid")
    return value


def _present(fields, key, check):
    """An optional field that, when present, must not be null."""
    if key not in fields:
        return None
    if fields[key] is None:
        raise PolicyError("policy_invalid")
    return check(fields[key])


def _bool(value):
    if type(value) is not bool:
        raise PolicyError("policy_invalid")
    return value


def _list(check):
    def parse(value):
        if not strictjson.is_array(value):
            raise PolicyError("policy_invalid")
        return [check(item) for item in value]
    return parse


def _set_reference(value):
    fields = _typed(value, ("name", "version"))
    if "name" not in fields or "version" not in fields:
        raise PolicyError("policy_invalid")
    if not strictjson.unsigned(fields["version"], 32):
        raise PolicyError("policy_invalid")
    return (_string(fields["name"]), fields["version"])


def _destination(value):
    fields = _typed(value, ("exact", "subtree", "include_root", "address", "ports"))
    if "ports" not in fields:
        raise PolicyError("policy_invalid")
    exact = _present(fields, "exact", _string)
    subtree = _present(fields, "subtree", _string)
    include_root = _present(fields, "include_root", _bool)
    address = _present(fields, "address", _string)
    ports = _ports(fields["ports"])
    return (exact, subtree, include_root, address, ports)


def _normalized_name(text):
    try:
        name = DnsName.parse(text)
    except AddressError:
        raise PolicyError("rule_invalid") from None
    if name.text != text:
        raise PolicyError("rule_invalid")
    return name


def _rule(destination):
    exact, subtree, include_root, address, ports = destination
    if exact is not None and subtree is None and include_root is None and address is None:
        return Rule("exact", ports, name=_normalized_name(exact))
    if exact is None and subtree is not None and include_root is not None and address is None:
        return Rule("subtree", ports, name=_normalized_name(subtree), include_root=include_root)
    if exact is None and subtree is None and include_root is None and address is not None:
        try:
            return Rule("address", ports, address=parse_ip(address))
        except AddressError:
            raise PolicyError("rule_invalid") from None
    raise PolicyError("rule_invalid")


class Policy:
    """A validated, normalized policy: `mode` (`model_only`, `open`,
    `custom`), `replace_model_only`, its provider sets, rules, grants and
    identity."""

    def __init__(self, mode, replace, sets, rules, grants=()):
        wants_sets = mode == "model_only" or (mode == "custom" and not replace)
        custom = mode == "custom"
        if wants_sets == (not sets) or (not custom and rules):
            raise PolicyError("policy_fields_invalid")
        if len(sets) > MAX_PROVIDER_SETS:
            raise PolicyError("policy_too_many_rules")
        for reference in sets:
            if reference not in PROVIDER_SETS:
                raise PolicyError("provider_set_unknown")
        sets = sorted(sets, key=lambda reference: reference[0])
        if any(a[0] == b[0] for a, b in zip(sets, sets[1:])):
            raise PolicyError("provider_set_duplicate")
        if len(rules) > MAX_DESTINATIONS:
            raise PolicyError("policy_too_many_rules")
        for rule in rules:
            rule.ports = _normalize_ports(rule.ports)
            if rule.kind == "address" and denied(rule.address) is not None:
                raise PolicyError("rule_address_unspecified")
            if rule.kind == "subtree" and rule.name.labels() < MIN_SUBTREE_LABELS:
                raise PolicyError("rule_subtree_too_broad")
        rules = sorted(rules, key=lambda rule: (rule.kind, rule.text()))
        if any((a.kind, a.text()) == (b.kind, b.text()) for a, b in zip(rules, rules[1:])):
            raise PolicyError("rule_duplicate")
        # Open admits every endpoint: a grant adds nothing there.
        grants = [] if mode == "open" else _grants(grants)
        effective = []
        for reference in sets:
            for host, ports in PROVIDER_SETS[reference][1]:
                effective.append(Rule("exact", list(ports), name=DnsName.parse(host)))
        effective.extend(rules)
        effective.extend(_grant_rule(authority) for authority in grants)
        self.mode, self.replace = mode, mode == "custom" and replace
        self.sets, self.rules, self.grants = sets, rules, grants
        self.effective = effective
        self.identity = _identity(self)

    @classmethod
    def default_model_only(cls):
        return cls("model_only", False, list(DEFAULT_MODEL_ONLY), [])

    @classmethod
    def parse(cls, data):
        """Strictly parses a policy document's bytes."""
        if len(data) > MAX_POLICY_BYTES:
            raise PolicyError("policy_too_large")
        try:
            document = strictjson.loads_pairs(data)
        except strictjson.Invalid:
            raise PolicyError("policy_invalid") from None
        fields = _typed(document, ("schema", "mode", "provider_sets", "replace_model_only", "destinations"))
        if "schema" not in fields or "mode" not in fields:
            raise PolicyError("policy_invalid")
        schema = _string(fields["schema"])
        mode = fields["mode"]
        if mode not in ("model_only", "open", "custom"):
            raise PolicyError("policy_invalid")
        sets = _present(fields, "provider_sets", _list(_set_reference))
        replace = _present(fields, "replace_model_only", _bool)
        destinations = _present(fields, "destinations", _list(_destination))
        if schema != POLICY_SCHEMA:
            raise PolicyError("policy_schema_unsupported")
        if mode != "custom" and replace is not None:
            raise PolicyError("policy_fields_invalid")
        replace = bool(replace)
        custom = mode == "custom"
        wants_sets = mode == "model_only" or (custom and not replace)
        if (not custom and destinations is not None) or (not wants_sets and sets is not None):
            raise PolicyError("policy_fields_invalid")
        sets = sets or []
        if len(sets) > MAX_PROVIDER_SETS:
            raise PolicyError("policy_too_many_rules")
        for reference in sets:
            if reference not in PROVIDER_SETS:
                raise PolicyError("provider_set_unknown")
        destinations = destinations or []
        if len(destinations) > MAX_DESTINATIONS:
            raise PolicyError("policy_too_many_rules")
        rules = [_rule(destination) for destination in destinations]
        return cls(mode, replace, sets, rules)

    def with_grants(self, texts):
        """This policy with a session's grants: `host:port` CONNECT
        authorities (`[ipv6]:port`), at most MAX_GRANTS, duplicates
        merged; an unspecified literal refused."""
        if len(texts) > MAX_GRANTS:
            raise PolicyError("grants_too_many")
        return Policy(self.mode, self.replace, list(self.sets), self.rules, [parse_grant(text) for text in texts])

    def admit(self, authority):
        """Step 1: host and port only, before any lookup."""
        host, port = authority.host, authority.port
        allowed = self.mode == "open" or any(port in rule.ports and rule.matches(host) for rule in self.effective)
        if not allowed:
            raise Denial("destination_not_allowed")
        return Admission(self, host, port)


class Admission:
    """An admitted host and port, awaiting address validation."""

    def __init__(self, policy, host, port):
        self.policy, self.host, self.port = policy, host, port

    def resolver_query(self):
        """The absolute name to resolve; None for an IP literal."""
        return self.host.name.resolver_query() if self.host.name is not None else None

    def validate(self, answers):
        """Step 2: the numeric (ip, port) targets in resolver order without
        duplicates, every candidate checked before any is dialed."""
        if self.host.ip is not None:
            if answers:
                raise Denial("dns_answers_unexpected")
            candidates = [self.host.ip]
        elif not answers:
            raise Denial("dns_answers_empty")
        elif len(answers) > MAX_ANSWERS:
            raise Denial("dns_answers_too_many")
        else:
            candidates = answers
        addresses = []
        for ip in candidates:
            kind = denied(ip)
            if kind is not None:
                raise Denial("address_" + kind)
            target = (ip, self.port)
            if target not in addresses:
                addresses.append(target)
        return addresses

    def proxied(self):
        """Step 2 through a CONNECT proxy: the canonical authority it is
        asked for, never resolved here; an unspecified literal refused."""
        if self.host.ip is not None and denied(self.host.ip) is not None:
            raise Denial("address_unspecified")
        return authority_text(Authority(self.host, self.port))


def parse_grant(text):
    """One grant: a CONNECT authority, its host a name or a literal not
    unspecified. `grant_invalid` or `grant_unspecified`."""
    if not isinstance(text, str):
        raise PolicyError("grant_invalid")
    try:
        authority = parse_authority(text)
    except AddressError:
        raise PolicyError("grant_invalid") from None
    if authority.host.ip is not None and denied(authority.host.ip) is not None:
        raise PolicyError("grant_unspecified")
    return authority


def _grants(authorities):
    """Sorted by canonical text, duplicates merged."""
    unique = {}
    for authority in authorities:
        unique.setdefault(authority_text(authority), authority)
    return [unique[text] for text in sorted(unique)]


def _grant_rule(authority):
    host = authority.host
    if host.name is not None:
        return Rule("exact", [authority.port], name=host.name)
    return Rule("address", [authority.port], address=host.ip)


def _canonical_rule(kind, host, include_root, ports):
    return {"kind": kind, "host": host, "include_root": include_root, "ports": list(ports)}


def _identity(policy):
    """`sha256:` and the hex digest of the canonical validated policy, its
    field order the Rust structs'."""
    canonical = {
        "schema": IDENTITY_SCHEMA,
        "mode": policy.mode,
        "replace_model_only": policy.replace,
        "provider_sets": [
            {"name": name, "version": version, "qualification": PROVIDER_SETS[(name, version)][0],
             "destinations": [_canonical_rule("exact", host, False, ports)
                              for host, ports in PROVIDER_SETS[(name, version)][1]]}
            for name, version in policy.sets],
        "destinations": [_canonical_rule(rule.kind, rule.text(), rule.kind == "subtree" and rule.include_root,
                                         rule.ports) for rule in policy.rules],
        "grants": [authority_text(authority) for authority in policy.grants],
    }
    text = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()
