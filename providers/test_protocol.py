"""Checks providers/protocol.py against contracts/provider/v1.

  python3 -I -m unittest discover -s providers -p 'test_*.py'
"""
import io
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import protocol  # noqa: E402

CONTRACT_DIR = os.path.join(HERE, "..", "contracts", "provider", "v1")


def load(name):
    with open(os.path.join(CONTRACT_DIR, name), "rb") as stream:
        return json.loads(stream.read())


CONTRACT = load("contract.json")
FIXTURES = load("fixtures.json")


def parts(items):
    out = b""
    for part in items:
        if isinstance(part, str):
            out += part.encode()
        else:
            out += (part["repeat"] * part["count"]).encode()
    return out


def frame_bytes(case):
    if "frame" in case:
        return case["frame"].encode()
    if "frame_hex" in case:
        return bytes.fromhex(case["frame_hex"])
    return parts(case["frame_parts"])


def decode(direction, data):
    if direction == "host":
        return protocol.decode_request(data)
    return protocol.decode_response(data)


class Constants(unittest.TestCase):
    def test_constants_match_the_contract(self):
        limits = CONTRACT["limits"]
        self.assertEqual(CONTRACT["protocol"], protocol.PROTOCOL)
        self.assertEqual(CONTRACT["version"], protocol.VERSION)
        self.assertEqual(limits["max_frame_bytes"], protocol.MAX_FRAME_BYTES)
        self.assertEqual(limits["max_depth"], protocol.MAX_DEPTH)
        self.assertEqual(limits["max_id_bytes"], protocol.MAX_ID_BYTES)
        self.assertEqual(limits["max_path_bytes"], protocol.MAX_PATH_BYTES)
        self.assertEqual(limits["max_provider_bytes"], protocol.MAX_PROVIDER_BYTES)
        self.assertEqual(limits["max_user_bytes"], protocol.MAX_USER_BYTES)
        self.assertEqual(limits["max_timeout_ms"], protocol.MAX_TIMEOUT_MS)
        self.assertEqual(limits["max_safe_integer"], protocol.MAX_SAFE_INTEGER)
        self.assertEqual(limits["max_diagnostic_bytes"], protocol.MAX_DIAGNOSTIC_BYTES)
        self.assertEqual(limits["cancel_grace_ms"], protocol.CANCEL_GRACE_MS)
        self.assertEqual(CONTRACT["argv"]["error"], protocol.ARGV_ERROR)
        ops = CONTRACT["operations"]
        self.assertEqual(tuple(ops["required"]), protocol.REQUIRED_OPERATIONS)
        self.assertEqual(tuple(ops["optional"]), protocol.OPTIONAL_OPERATIONS)
        self.assertEqual(tuple(CONTRACT["host_types"]), protocol.HOST_TYPES)
        self.assertEqual(tuple(CONTRACT["provider_types"]), protocol.PROVIDER_TYPES)
        self.assertEqual(CONTRACT["results"], protocol.RESULTS)
        self.assertEqual(tuple(CONTRACT["transports"]), protocol.TRANSPORTS)
        self.assertEqual(tuple(CONTRACT["tcp_hosts"]), protocol.TCP_HOSTS)
        self.assertEqual(tuple(CONTRACT["retention"]), protocol.RETENTION)
        self.assertEqual(tuple(CONTRACT["features"]), protocol.FEATURES)
        self.assertEqual(CONTRACT["default_user"], protocol.DEFAULT_USER)
        self.assertEqual(tuple(CONTRACT["agents"]), protocol.AGENTS)
        self.assertEqual({k: tuple(v) for k, v in CONTRACT["limit_ranges"].items()},
                         protocol.LIMIT_RANGES)
        self.assertEqual(list(CONTRACT["limit_ranges"]), list(protocol.LIMIT_RANGES))
        self.assertEqual(tuple(CONTRACT["settlement"]), protocol.SETTLEMENT)
        self.assertEqual(tuple(CONTRACT["durability"]), protocol.DURABILITY)
        self.assertEqual(tuple(CONTRACT["storage"]), protocol.STORAGE)
        self.assertEqual(tuple(CONTRACT["resource_states"]), protocol.RESOURCE_STATES)
        self.assertEqual(tuple(CONTRACT["instance_states"]), protocol.INSTANCE_STATES)
        self.assertEqual(tuple(CONTRACT["failure_codes"]), protocol.FAILURE_CODES)
        self.assertEqual(tuple(CONTRACT["lost_uncertain"]), protocol.LOST_UNCERTAIN)
        self.assertEqual(tuple(CONTRACT["frame_error_codes"]), protocol.FRAME_ERROR_CODES)
        self.assertEqual(tuple(CONTRACT["exchange_error_codes"]),
                         protocol.EXCHANGE_ERROR_CODES)

    def test_field_tables_match_the_contract(self):
        self.assertEqual(set(CONTRACT["fields"]), set(protocol.FIELDS))
        for kind, table in CONTRACT["fields"].items():
            required, optional, _ = protocol.FIELDS[kind]
            self.assertEqual(tuple(table["required"]), required, kind)
            self.assertEqual(tuple(table["optional"]), optional, kind)


class Frames(unittest.TestCase):
    def test_valid_frames_decode_and_encode_canonically(self):
        for case in FIXTURES["frames"]["valid"]:
            with self.subTest(case["name"]):
                frame = decode(case["direction"], frame_bytes(case))
                expected = case.get("canonical", case["frame"]).encode()
                self.assertEqual(protocol.encode(frame), expected)

    def test_invalid_frames_fail_with_their_code(self):
        codes = set()
        for case in FIXTURES["frames"]["invalid"]:
            with self.subTest(case["name"]):
                with self.assertRaises(protocol.ProtocolError) as caught:
                    decode(case["direction"], frame_bytes(case))
                self.assertEqual(caught.exception.code, case["error"])
                codes.add(case["error"])
        self.assertEqual(codes, set(protocol.FRAME_ERROR_CODES) - {"truncated_frame"})

    def test_every_type_has_a_valid_fixture(self):
        seen = {json.loads(c.get("canonical", c["frame"]))["type"]
                for c in FIXTURES["frames"]["valid"]}
        self.assertEqual(seen, set(protocol.HOST_TYPES + protocol.PROVIDER_TYPES))

    def test_encode_refuses_unknown_and_invalid_fields(self):
        cancel = {"v": 1, "type": "cancel", "operation": "op-1"}
        self.assertEqual(protocol.encode(cancel), b'{"v":1,"type":"cancel","operation":"op-1"}')
        for frame, code in [
            (dict(cancel, extra=1), "unknown_field"),
            (dict(cancel, operation="-x"), "invalid_field"),
            ({"type": "connect"}, "unknown_type"),
        ]:
            with self.assertRaises(protocol.ProtocolError) as caught:
                protocol.encode(frame)
            self.assertEqual(caught.exception.code, code)

    def valid(self, name):
        case = next(c for c in FIXTURES["frames"]["valid"] if c["name"] == name)
        return decode(case["direction"], frame_bytes(case)), case["frame"].encode()

    def test_encode_validates_nested_limits_before_canonicalizing(self):
        start, text = self.valid("start with every limit")
        reordered = dict(start, limits=dict(reversed(list(start["limits"].items()))))
        self.assertEqual(protocol.encode(reordered), text)
        for limits, code in [
            (dict(start["limits"], memory_mb=1), "unknown_field"),
            ({"cpus": 2, "network": 1}, "unknown_field"),
            ({"cpus": 0}, "invalid_field"),
            ({"cpus": True}, "invalid_field"),
            ({"cpus": 257}, "limit_exceeded"),
            ([2], "invalid_field"),
        ]:
            with self.subTest(limits=limits):
                with self.assertRaises(protocol.ProtocolError) as caught:
                    protocol.encode(dict(start, limits=limits))
                self.assertEqual(caught.exception.code, code)

    def test_encode_validates_nested_transport_before_canonicalizing(self):
        started, text = self.valid("started tcp ipv4")
        transport = started["transport"]
        reordered = dict(started, transport={"port": transport["port"], "host": transport["host"],
                                             "kind": "tcp"})
        self.assertEqual(protocol.encode(reordered), text)
        for value, code in [
            (dict(transport, socket="/run/x"), "unknown_field"),
            ({"kind": "stdio", "port": 22}, "unknown_field"),
            ({"kind": "stdio", "host": "::1"}, "unknown_field"),
            ({"kind": "tcp", "host": "::1"}, "missing_field"),
            ({"host": "::1", "port": 22}, "missing_field"),
            (dict(transport, host="0.0.0.0"), "invalid_field"),
            ("tcp", "invalid_field"),
        ]:
            with self.subTest(transport=value):
                with self.assertRaises(protocol.ProtocolError) as caught:
                    protocol.encode(dict(started, transport=value))
                self.assertEqual(caught.exception.code, code)

    def test_encode_refuses_invalid_response_fields(self):
        stopped, _ = self.valid("stopped retained")
        described, _ = self.valid("described qemu-like")
        ops = [op for op in described["operations"] if op != "discard"]
        for frame, code in [
            (dict(stopped, storage="unclean"), "invalid_field"),
            (dict(stopped, settlement="unknown"), "invalid_field"),
            (dict(stopped, run=""), "invalid_field"),
            (dict(described, operations=ops), "invalid_field"),
            (dict(described, limits=["cpus", "cpus"]), "invalid_field"),
            (dict(described, retention=[]), "invalid_field"),
            (dict(described, operation="o" * 65), "invalid_field"),
        ]:
            with self.assertRaises(protocol.ProtocolError) as caught:
                protocol.encode(frame)
            self.assertEqual(caught.exception.code, code)

    def test_encode_checks_the_version(self):
        cancel = {"type": "cancel", "operation": "op-1"}
        for version, code in [(2, "unsupported_version"), ("1", "invalid_version"),
                              (True, "invalid_version")]:
            with self.assertRaises(protocol.ProtocolError) as caught:
                protocol.encode(dict(cancel, v=version))
            self.assertEqual(caught.exception.code, code)

    def test_read_frame_is_bounded(self):
        largest = b"x" * protocol.MAX_FRAME_BYTES
        stream = io.BytesIO(b"a\n" + largest + b"\n")
        self.assertEqual(protocol.read_frame(stream), b"a")
        self.assertEqual(protocol.read_frame(stream), largest)
        self.assertIsNone(protocol.read_frame(stream))
        for data, code in [
            (largest + b"x\n", "frame_too_large"),
            (b"partial", "truncated_frame"),
        ]:
            with self.assertRaises(protocol.ProtocolError) as caught:
                protocol.read_frame(io.BytesIO(data))
            self.assertEqual(caught.exception.code, code)

    def test_write_frame_appends_lf(self):
        out = io.BytesIO()
        protocol.write_frame(out, {"type": "cancel", "operation": "op-1"})
        self.assertEqual(out.getvalue(), b'{"v":1,"type":"cancel","operation":"op-1"}\n')


class Argv(unittest.TestCase):
    def test_argv_fixtures(self):
        for case in FIXTURES["argv"]["valid"]:
            with self.subTest(case["name"]):
                self.assertEqual(list(protocol.parse_argv(case["argv"])), case["argv"])
        for case in FIXTURES["argv"]["invalid"]:
            with self.subTest(case["name"]):
                with self.assertRaises(protocol.ProtocolError) as caught:
                    protocol.parse_argv(case["argv"])
                self.assertEqual(caught.exception.code, protocol.ARGV_ERROR)

    def test_mount_destinations_may_be_hidden_projects_never(self):
        for text in (".pi", ".claude/x", ".ssh", "...", "a/.b", ".agentbox-root/x", "work"):
            self.assertTrue(protocol.is_mount_destination(text), text)
        for text in (".agentbox", ".agentbox-root", ".agentbox-inputs-e1.tar", ".agentboxx/y", ".", "..",
                     "./a", "a/../b", "/a", "a//b", "a/", "", "a b", None, "x" * 1025):
            self.assertFalse(protocol.is_mount_destination(text), text)
        for text in (".pi", ".ssh/x"):
            self.assertFalse(protocol.is_project(text), text)
        self.assertTrue(protocol.is_project(".agentbox-root/x"))

    def test_builders_validate(self):
        self.assertEqual(protocol.control_argv("/s"), ["control", "/s"])
        self.assertEqual(protocol.connect_argv("/s", "r", "e", "i"),
                         ["connect", "/s", "r", "e", "i"])
        with self.assertRaises(protocol.ProtocolError):
            protocol.connect_argv("/s", "r", "e", "i j")


def run_exchange(case):
    """Runs every step of one fixture exchange; returns (first error code or
    None, final outcome). A frame refused by its decoder is reported to the
    exchange; later steps still run."""
    described = None
    if "capabilities" in case:
        text = FIXTURES["described"][case["capabilities"]]
        described = protocol.decode_response(text.encode())
    exchange = None
    first = None
    for step in case["steps"]:
        decoded = False
        try:
            if "host" in step:
                frame = protocol.decode_request(step["host"].encode())
                decoded = True
                if exchange is None:
                    exchange = protocol.Exchange(frame, described, case.get("worker_sha256"))
                else:
                    exchange.host(frame)
            elif "provider" in step or "provider_parts" in step:
                data = (step["provider"].encode() if "provider" in step
                        else parts(step["provider_parts"]))
                frame = protocol.decode_response(data)
                decoded = True
                exchange.provider(frame)
            elif "exit" in step:
                exchange.exit()
            else:
                exchange.disconnect()
        except protocol.ProtocolError as err:
            if first is None:
                first = err.code
            if not decoded and exchange is not None:
                exchange.frame_error()
        if exchange is None:
            break
    return first, (exchange.outcome() if exchange is not None else None)


class Exchanges(unittest.TestCase):
    def test_exchange_fixtures(self):
        codes = set()
        for case in FIXTURES["exchanges"]:
            with self.subTest(case["name"]):
                error, outcome = run_exchange(case)
                self.assertEqual(error, case.get("error"))
                self.assertEqual(outcome, case["outcome"])
                codes.add(error)
        self.assertTrue(set(protocol.EXCHANGE_ERROR_CODES) <= codes)

    def started(self):
        case = next(c for c in FIXTURES["exchanges"] if c["name"] == "owner session retained")
        described = protocol.decode_response(FIXTURES["described"]["qemu"].encode())
        frames = [protocol.decode_request(case["steps"][0]["host"].encode()),
                  protocol.decode_response(case["steps"][1]["provider"].encode()),
                  protocol.decode_request(case["steps"][2]["host"].encode()),
                  protocol.decode_response(case["steps"][3]["provider"].encode())]
        exchange = protocol.Exchange(frames[0], described, "a" * 64)
        exchange.provider(frames[1])
        exchange.host(frames[2])
        exchange.provider(frames[3])
        self.assertEqual(exchange.outcome()["settlement"], "settled")
        return exchange, frames

    def test_errors_poison_a_settled_success(self):
        error = {"end": "error", "code": None, "settlement": "unknown",
                 "durability": "uncertain"}
        for name, act in [
            ("provider frame", lambda e, f: e.provider(f[3])),
            ("host frame", lambda e, f: e.host({"type": "cancel", "operation": "op-2"})),
            ("frame error", lambda e, f: e.frame_error()),
        ]:
            with self.subTest(name):
                exchange, frames = self.started()
                try:
                    act(exchange, frames)
                except protocol.ProtocolError as err:
                    self.assertEqual(err.code, "unexpected_frame")
                self.assertEqual(exchange.outcome(), error)
                exchange.exit()
                self.assertEqual(exchange.outcome(), error)
                with self.assertRaises(protocol.ProtocolError) as caught:
                    exchange.provider(frames[3])
                self.assertEqual(caught.exception.code, "unexpected_frame")
                self.assertEqual(exchange.outcome(), error)


if __name__ == "__main__":
    unittest.main()
