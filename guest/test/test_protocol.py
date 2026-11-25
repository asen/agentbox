"""The guest implementation against the shared files in contracts/v1."""

import base64
import json
import os
import unittest

from guest.src import protocol
from guest.src.protocol import (
    ERROR_CODES, FrameSplitter, Refused, decode_guest_frame, decode_host_frame, encode_guest_frame,
    encode_host_frame, validate_argv,
)

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONTRACTS = os.path.join(REPO, "contracts", "v1")


def contract(name):
    with open(os.path.join(CONTRACTS, name), encoding="utf-8") as stream:
        return json.load(stream)


FIXTURES = contract("protocol-fixtures.json")


def frame_bytes(fixture):
    if "frame_hex" in fixture:
        return bytes.fromhex(fixture["frame_hex"])
    frame = fixture["frame"]
    if isinstance(frame, str):
        return frame.encode("utf-8", "surrogatepass")
    return "".join(part if isinstance(part, str) else part["repeat"] * part["count"] for part in frame).encode()


def round_trip(fixture):
    """Decodes and re-encodes, as the Rust test does: bytes or the code."""
    data = frame_bytes(fixture)
    try:
        if fixture["direction"] == "host":
            return encode_host_frame(decode_host_frame(data))
        return encode_guest_frame(decode_guest_frame(data))
    except Refused as error:
        return error.code


def refused(call, *args):
    try:
        call(*args)
    except Refused as error:
        return error.code
    return None


class Contract(unittest.TestCase):
    def test_constants_match_the_contract(self):
        spec = contract("protocol.json")
        self.assertEqual(spec["protocol"], protocol.PROTOCOL)
        self.assertEqual(spec["version"], protocol.VERSION)
        self.assertEqual(spec["limits"], {
            "max_frame_bytes": protocol.MAX_FRAME_BYTES, "max_depth": protocol.MAX_DEPTH,
            "max_id_bytes": protocol.MAX_ID_BYTES, "max_guest_version_bytes": protocol.MAX_GUEST_VERSION_BYTES,
            "max_output_bytes": protocol.MAX_OUTPUT_BYTES, "max_output_text_bytes": protocol.MAX_OUTPUT_TEXT_BYTES,
            "max_argv_items": protocol.MAX_ARGV_ITEMS, "max_arg_bytes": protocol.MAX_ARG_BYTES,
            "max_argv_bytes": protocol.MAX_ARGV_BYTES, "max_exit_code": protocol.MAX_EXIT_CODE,
            "max_safe_integer": protocol.MAX_SAFE_INTEGER, "max_env_vars": protocol.MAX_ENV_VARS,
            "max_env_name_bytes": protocol.MAX_ENV_NAME_BYTES, "max_env_value_bytes": protocol.MAX_ENV_VALUE_BYTES,
            "max_env_bytes": protocol.MAX_ENV_BYTES, "max_stdin_bytes": protocol.MAX_STDIN_BYTES,
            "max_stdin_text_bytes": protocol.MAX_STDIN_TEXT_BYTES,
        })
        self.assertEqual(spec["reserved_env"], list(protocol.RESERVED_ENV))
        self.assertEqual(spec["host_types"], list(protocol.HOST_TYPES))
        self.assertEqual(spec["guest_types"], list(protocol.GUEST_TYPES))
        self.assertEqual(spec["error_codes"], list(ERROR_CODES))

    def test_valid_fixtures_decode_to_their_canonical_encoding(self):
        self.assertTrue(FIXTURES["valid"])
        for fixture in FIXTURES["valid"]:
            result = round_trip(fixture)
            self.assertIsInstance(result, bytes, fixture["name"])
            expected = fixture.get("canonical") or frame_bytes(fixture).decode("utf-8")
            self.assertEqual(result.decode("utf-8"), expected, fixture["name"])

    def test_invalid_fixtures_are_refused_with_their_code(self):
        self.assertTrue(FIXTURES["invalid"])
        for fixture in FIXTURES["invalid"]:
            self.assertEqual(round_trip(fixture), fixture["code"], fixture["name"])

    def test_every_decoder_code_has_an_invalid_fixture(self):
        used = {fixture["code"] for fixture in FIXTURES["invalid"]}
        for code in ERROR_CODES:
            # Only stream readers report a truncated frame.
            if code != "truncated_frame":
                self.assertIn(code, used)


class Codec(unittest.TestCase):
    def test_encoders_refuse_frames_the_peer_would_refuse(self):
        self.assertEqual(refused(encode_host_frame, {"v": 1, "type": "exec", "id": "r1", "argv": ["x"] * 65}),
                         "limit_exceeded")
        self.assertEqual(refused(encode_host_frame, {"v": 1, "type": "hello", "session": "bad id"}), "invalid_field")
        self.assertEqual(refused(encode_guest_frame, {"v": 1, "type": "output", "id": "r1", "stream": "stdout",
                                                      "data": ""}), "invalid_field")
        self.assertEqual(refused(encode_guest_frame, {"v": 1, "type": "exit", "id": "r1", "outcome": "exited",
                                                      "code": 256}), "invalid_field")

    def test_argv_validation_counts_utf8_bytes(self):
        self.assertIsNone(validate_argv(["é" * 2048]))
        self.assertEqual(validate_argv(["é" * 2049]), "limit_exceeded")
        self.assertEqual(validate_argv([]), "invalid_field")
        self.assertEqual(validate_argv(["a\0"]), "invalid_field")

    def test_splitter_yields_frames_across_chunk_boundaries(self):
        splitter = FrameSplitter()
        self.assertEqual(splitter.push(b'{"a":'), [])
        self.assertEqual(splitter.push(b'1}\n\n{"b"'), [b'{"a":1}', b""])
        self.assertEqual(refused(splitter.end), "truncated_frame")
        self.assertEqual(refused(splitter.push, b"\n"), "truncated_frame")

    def test_splitter_bounds_an_unfinished_frame(self):
        exact = FrameSplitter()
        frame = b"x" * protocol.MAX_FRAME_BYTES
        self.assertEqual(exact.push(frame[:7]), [])
        done = exact.push(frame[7:] + b"\n")
        self.assertEqual(len(done[0]), protocol.MAX_FRAME_BYTES)
        exact.end()
        over = FrameSplitter()
        self.assertEqual(over.push(frame), [])
        self.assertEqual(refused(over.push, b"x"), "frame_too_large")
        self.assertEqual(refused(over.end), "frame_too_large")

    def test_split_frames_decode_after_a_round_trip_through_the_wire(self):
        frame = {"v": 1, "type": "exec", "id": "r1", "argv": ["printf", "a\nb\r"]}
        wire = encode_host_frame(frame) + b"\n"
        self.assertEqual(wire.count(b"\n"), 1)
        [line] = FrameSplitter().push(wire)
        self.assertEqual(decode_host_frame(line), frame)

    def test_shutdown_is_no_frame(self):
        # No frame asks for a poweroff: a provider's `stop` ends an instance.
        for decode in (decode_host_frame, decode_guest_frame):
            self.assertEqual(refused(decode, b'{"v":1,"type":"shutdown"}'), "unknown_type")

    def test_exec_env_is_optional_canonical_by_name_and_refused_when_empty(self):
        generic = encode_host_frame({"v": 1, "type": "exec", "id": "r1", "argv": ["a"]})
        self.assertEqual(generic, b'{"v":1,"type":"exec","id":"r1","argv":["a"]}')
        self.assertEqual(encode_host_frame({"v": 1, "type": "exec", "id": "r1", "argv": ["a"], "env": ()}), generic)
        env = (("Z_FAKE", "fake-z"), ("__proto__", "fake-p"), ("A_FAKE", ""))
        encoded = encode_host_frame({"v": 1, "type": "exec", "id": "r1", "argv": ["a"], "env": env})
        self.assertEqual(encoded, b'{"v":1,"type":"exec","id":"r1","argv":["a"],'
                                  b'"env":{"A_FAKE":"","Z_FAKE":"fake-z","__proto__":"fake-p"}}')
        self.assertEqual(decode_host_frame(encoded)["env"],
                         (("A_FAKE", ""), ("Z_FAKE", "fake-z"), ("__proto__", "fake-p")))
        self.assertEqual(refused(encode_host_frame, {"v": 1, "type": "exec", "id": "r1", "argv": ["a"],
                                                     "env": (("PATH", "/x"),)}), "invalid_field")

    def test_the_anchor_config_is_the_env_object_again_strictly(self):
        config = protocol.encode_env_config((("B_FAKE", "fake-b\n\u0001"), ("A_FAKE", "")))
        self.assertEqual(config, b'{"A_FAKE":"","B_FAKE":"fake-b\\n\\u0001"}')
        self.assertEqual(protocol.decode_env_config(config), (("A_FAKE", ""), ("B_FAKE", "fake-b\n\u0001")))
        for bad in ("", "{}", "[]", '{"A":"x"', '{"HOME":"/x"}', '{"A":1}', '{"A-B":"x"}', '{"A":{"B":"x"}}',
                    # Refused like any frame: a duplicate key, even with equal values, an
                    # escaped lone surrogate in a value or a name, CR or LF bytes.
                    '{"A":"x","A":"y"}', '{"A":"x","A":"x"}', '{"A":"\\ud800"}', '{"A":"x\\udc00y"}',
                    '{"\\ud83dA":"x"}', '{"A":"x"}\n', '\r{"A":"x"}', '{"A":NaN}', '{"A":"x","B":-Infinity}'):
            self.assertIsNone(protocol.decode_env_config(bad.encode()), bad)
        # Truly invalid UTF-8: a lone 0xff, an encoded surrogate, a truncated sequence, an overlong NUL.
        for raw in (b"\xff", b'{"A":"\xff"}', b'{"A":"\xed\xa0\x80"}', b'{"A":"\xe2\x82"}', b'{"A":"\xc0\x80"}',
                    b"\xef\xbb\xbf" + b'{"A":"x"}'):
            self.assertIsNone(protocol.decode_env_config(raw), raw.hex())
        self.assertIsNone(protocol.decode_env_config(b" " * (protocol.MAX_FRAME_BYTES + 1)))
        # The bound is the frame's: whitespace alone up to it is still parsed.
        padded = b'{"A":"x"}' + b" " * (protocol.MAX_FRAME_BYTES - 9)
        self.assertEqual(protocol.decode_env_config(padded), (("A", "x"),))
        for env in ('{"A":"x","A":"y"}', '{"A":"\\ud800"}'):
            frame = '{"v":1,"type":"exec","id":"r1","argv":["a"],"env":%s}' % env
            self.assertIsNotNone(refused(decode_host_frame, frame.encode()), env)

    def test_stdin_frames_are_opt_in_canonical_bounded_and_directional(self):
        plain = encode_host_frame({"v": 1, "type": "exec", "id": "r1", "argv": ["cat"]})
        opted = encode_host_frame({"v": 1, "type": "exec", "id": "r1", "argv": ["cat"], "stdin": True})
        self.assertEqual(plain, b'{"v":1,"type":"exec","id":"r1","argv":["cat"]}')
        self.assertEqual(opted, b'{"v":1,"type":"exec","id":"r1","argv":["cat"],"stdin":true}')
        self.assertEqual(decode_host_frame(opted), {"v": 1, "type": "exec", "id": "r1", "argv": ["cat"], "stdin": True})
        self.assertNotIn("stdin", decode_host_frame(plain))
        # NUL, invalid UTF-8, CR/LF and a frame-like line are data only.
        raw = bytes([0, 0xFF, 0xFE, 0x0D, 0x0A]) + b'{"v":1}\nline\n'
        frame = {"v": 1, "type": "stdin", "id": "r1", "seq": 7, "data": base64.b64encode(raw).decode()}
        encoded = encode_host_frame(frame)
        self.assertNotIn(b"\n", encoded)
        self.assertEqual(base64.b64decode(decode_host_frame(encoded)["data"]), raw)
        self.assertEqual(refused(decode_guest_frame, encoded), "wrong_direction")
        # The longest frame with its LF fits one 4096-byte PIPE_BUF write.
        longest = encode_host_frame({"v": 1, "type": "stdin", "id": "e" * 64, "seq": protocol.MAX_SAFE_INTEGER,
                                     "data": base64.b64encode(b"\xff" * protocol.MAX_STDIN_BYTES).decode()})
        self.assertEqual(len(longest) + 1, 2860)
        self.assertEqual(refused(encode_host_frame, {
            "v": 1, "type": "stdin", "id": "r1", "seq": 0,
            "data": base64.b64encode(bytes(protocol.MAX_STDIN_BYTES + 1)).decode()}), "limit_exceeded")
        for guest, code in (({"v": 1, "type": "stdin_ready", "id": "r1", "seq": 0}, None),
                            ({"v": 1, "type": "stdin_closed", "id": "r1"}, None),
                            ({"v": 1, "type": "stdin_ready", "id": "r1", "seq": -1}, "invalid_number"),
                            ({"v": 1, "type": "stdin_ready", "id": "r1", "seq": 1.5}, "invalid_number"),
                            ({"v": 1, "type": "stdin_ready", "id": "r1", "seq": True}, "invalid_field")):
            if code is None:
                data = encode_guest_frame(guest)
                self.assertEqual(decode_guest_frame(data), guest)
                self.assertEqual(refused(decode_host_frame, data), "wrong_direction")
            else:
                self.assertEqual(refused(encode_guest_frame, guest), code)

    def test_json_literals_python_would_accept_are_refused(self):
        for text in ('{"v":1,"type":"cancel","id":"r1","x":NaN}', '{"v":1,"type":"cancel","id":Infinity}',
                     '{"v":-Infinity}', '﻿{"v":1,"type":"cancel","id":"r1"}'):
            self.assertEqual(refused(decode_host_frame, text.encode()), "invalid_json", text)
        # A huge integer is a bad number, never an interpreter limit.
        self.assertEqual(refused(decode_host_frame, ('{"v":1,"type":"stdin_eof","id":"r1","seq":%s}' % ("9" * 5000))
                                 .encode()), "invalid_number")
        # A boolean is never an integer.
        self.assertEqual(refused(decode_host_frame, b'{"v":true,"type":"cancel","id":"r1"}'), "invalid_version")


if __name__ == "__main__":
    unittest.main()
