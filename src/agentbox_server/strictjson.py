"""Strict UTF-8 JSON: no NaN, Infinity or lone surrogates. Preserve object
pairs so typed structures can reject duplicate fields and maps can keep
the last value."""
import json
import re

_SURROGATE = re.compile("[\ud800-\udfff]")


class Invalid(ValueError):
    pass


class Pairs(list):
    """A JSON object as its (key, value) pairs, in order."""

    def last(self):
        """As a map: the last value of each key."""
        return dict(self)

    def keys_unique(self):
        keys = [key for key, _ in self]
        return len(keys) == len(set(keys))


# serde_json's own recursion limit: arrays and objects nested deeper fail.
MAX_NESTING = 127
_FLOAT_MAX = 1.7976931348623157e308


def _reject(_name):
    raise Invalid("constant")


def _float(token):
    value = float(token)
    if value in (float("inf"), float("-inf")):
        raise Invalid("number")
    return value


def _int(token):
    value = int(token)
    if abs(value) > _FLOAT_MAX:
        raise Invalid("number")
    return value


def nesting(text):
    """Bracket nesting outside strings."""
    depth = deepest = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif char in "]}":
            depth = max(0, depth - 1)
    return deepest


def _check(value):
    if isinstance(value, str):
        if _SURROGATE.search(value):
            raise Invalid("surrogate")
    elif isinstance(value, Pairs):
        for key, item in value:
            _check(key)
            _check(item)
    elif isinstance(value, list):
        for item in value:
            _check(item)


def loads_pairs(data):
    """`data` (bytes or str): its value, objects as `Pairs`, numbers as
    int or float; `Invalid` for anything serde_json refuses to parse."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        try:
            data = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            raise Invalid("encoding") from None
    if nesting(data) > MAX_NESTING:
        raise Invalid("depth")
    try:
        value = json.loads(data, object_pairs_hook=Pairs, parse_constant=_reject,
                           parse_float=_float, parse_int=_int)
    except (ValueError, RecursionError):
        raise Invalid("json") from None
    _check(value)
    return value


def as_map(value):
    """`Pairs` at any depth as dicts, last key wins (serde_json `Value`)."""
    if isinstance(value, Pairs):
        return {key: as_map(item) for key, item in value.last().items()}
    if type(value) is list:
        return [as_map(item) for item in value]
    return value


def is_array(value):
    """A JSON array, never an object's pairs."""
    return type(value) is list


def loads(data):
    """serde_json's `Value`: objects as dicts, the last duplicate kept."""
    return as_map(loads_pairs(data))


def is_u64(value):
    """serde_json `as_u64`: a JSON integer 0..2^64-1, never a bool or float."""
    return type(value) is int and 0 <= value < 1 << 64


def unsigned(value, bits):
    """A serde unsigned integer field of `bits` bits."""
    return type(value) is int and 0 <= value < 1 << bits


def dumps(value):
    """serde_json's compact encoding of a map-keyed value: keys sorted,
    minimal escapes, non-ASCII as UTF-8."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def json_str(text):
    """serde_json's encoding of one string."""
    return json.dumps(text, ensure_ascii=False)
