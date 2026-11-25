"""The transport server (agentbox_server), offline:

- its pure parts against the shared fixtures (contracts/network/v1, the
  reviewed answers; acquisitions/contracts/artifacts/post-v1) and contracts;
- its broker in process, on its own loop thread, with a fake resolver and
  a test-only dial map onto owned loopback upstreams, each tunnel relayed
  by the real agentbox-relay; and stepped by the test itself for stops and
  deadlines at each commit boundary;
- the real `agentbox-server` program, configured as the controller does
  with nothing on its PATH, tunnelling to an owned listener on this host's
  loopback (a session grant; Open), then killed.

  cargo build --locked --bin agentbox-relay
  python3 -I -B -W error::ResourceWarning -m unittest discover -s tests/server -t . -p test_broker.py

The black-box protocol suite is test_server_protocol.py.
"""
import ipaddress
import json
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest

from tests import support  # first: puts SRC on the path
from agentbox_server import address, broker, codec, ingress, main, policy, request, strictjson, tools, wire

REPO = support.REPO
WAIT = 5.0
NONCE = "0123456789abcdef0123456789abcdef"
ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"
POLICY = {"schema": "agentbox.network-policy.v1", "mode": "custom", "replace_model_only": True,
          "destinations": [{"exact": "api.example.com", "ports": [443]},
                           {"address": "93.184.216.34", "ports": [443]}]}


# Shared fixtures.

def _bytes(case, text, hexkey):
    return case[text].encode() if case.get(text) is not None else bytes.fromhex(case[hexkey])


def _authority(parsed):
    host = parsed.host
    return {"host": {"name": host.name.text} if host.name is not None else {"ip": address.ip_text(host.ip)},
            "port": parsed.port}


class SharedFixtures(unittest.TestCase):
    """Every reviewed answer of the shared fixtures, given here."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(REPO, "contracts", "network", "v1", "fixtures.json")) as stream:
            cls.network = json.load(stream)
        with open(os.path.join(REPO, "acquisitions", "contracts", "artifacts", "post-v1", "fixtures.json")) as stream:
            cls.post = json.load(stream)

    def test_authorities_and_denied_addresses(self):
        for case in self.network["authorities"]:
            try:
                got = _authority(address.parse_authority(case["text"]))
            except address.AddressError as error:
                got = {"code": error.code}
            self.assertEqual(got, case["expect"], case["text"])
        for case in self.network["denied"]:
            self.assertEqual({"denied": address.denied(address.parse_ip(case["ip"]))}, case["expect"], case["ip"])

    def test_policies(self):
        for case in self.network["policies"]:
            try:
                parsed = policy.Policy.parse(_bytes(case, "document", "document_hex"))
                if "grants" in case:
                    parsed = parsed.with_grants(case["grants"])
                got = {"identity": parsed.identity}
            except policy.PolicyError as error:
                got = {"code": error.code}
            self.assertEqual(got, case["expect"], case["name"])

    def test_decisions(self):
        for case in self.network["decisions"]:
            parsed = policy.Policy.parse(case["policy"].encode()).with_grants(case.get("grants", []))
            answers = [address.parse_ip(answer) for answer in case["answers"]]
            try:
                targets = parsed.admit(address.parse_authority(case["authority"])).validate(answers)
                got = {"targets": [f"[{address.ip_text(ip)}]:{port}" if ip.version == 6 else f"{ip}:{port}"
                                   for ip, port in targets]}
            except policy.Denial as denial:
                got = {"code": denial.code}
            self.assertEqual(got, case["expect"], case)

    def test_heads(self):
        limits = request.Limits(8192, 1024, 32)
        for case in self.network["heads"]:
            try:
                kind, value = request.parse_request_head(_bytes(case, "head", "head_hex"), limits)
                got = {"connect": _authority(value)} if kind == "connect" else {"post": value}
            except request.RequestError as error:
                got = {"code": error.code}
            self.assertEqual(got, case["expect"], case["name"])
        for case in self.post["heads"]["valid"]:
            self.assertEqual(request.parse_request_head(case["head"].encode(), limits), ("post", case["content_length"]))
        for case in self.post["heads"]["invalid"]:
            with self.assertRaises(request.RequestError) as raised:
                request.parse_request_head(case["head"].encode(), limits)
            self.assertEqual(raised.exception.code, case["code"], case["name"])

    def test_post_bodies(self):
        def body(case):
            if "body" in case:
                return case["body"].encode()
            if "body_hex" in case:
                return bytes.fromhex(case["body_hex"])
            return b"".join(part.encode() if isinstance(part, str) else part["repeat"].encode() * part["count"]
                            for part in case["body_parts"])
        for section, decode in (("requests", codec.decode_request), ("responses", codec.decode_response)):
            for case in self.post[section]["valid"]:
                decoded = decode(body(case))
                if section == "requests" and "request_sha256" in case:
                    self.assertEqual(codec.request_sha256(decoded["client"], decoded["handler"], decoded["operation"],
                                                          decoded["args"]), case["request_sha256"])
                encode = codec.encode_request if section == "requests" else codec.encode_response
                self.assertEqual(encode(decoded), body(case), case["name"])
            for case in self.post[section]["invalid"]:
                with self.assertRaises(codec.CodecError) as raised:
                    decode(body(case))
                self.assertEqual(raised.exception.code, case["code"], case["name"])


class Units(unittest.TestCase):
    def test_a_proxy_head_is_parsed_whole(self):
        limits = broker.Limits().head()
        for head, code in ((b"HTTP/1.1 200 Connection established\r\n\r\n", 200),
                           (b"HTTP/1.0 204 \r\nVia: 1.1 p\r\nX:\r\n\r\n", 204),
                           (b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 6\r\n\r\n", 407),
                           (b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 32 + b"\r\n", 200)):
            self.assertEqual(request.parse_proxy_head(head, limits), code, head[:40])
        for head in (b"HTTP/1.1 200\r\n\r\n", b"HTTP/1.1 200 OK\r\n", b"HTTP/1.1 20 OK\r\n\r\n",
                     b"http/1.1 200 OK\r\n\r\n", b"HTTP/1.1 200 OK\r\nX\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nX: \x7f\r\n\r\n", b"HTTP/1.1 200 OK\r\n\tX: y\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nX: y\n\r\n", b"HTTP/1.1 200 " + b"x" * 1100 + b"\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 33 + b"\r\n"):
            with self.assertRaises(request.RequestError, msg=head[:40]):
                request.parse_proxy_head(head, limits)

    def test_control_commands_follow_the_rust_rules(self):
        configure = {"type": "configure", "id": 1, "v": 1, "session": "s-1", "run_id": "r-" + NONCE,
                     "execution_id": "e-" + NONCE, "lifetime_ms": 1000, "policy": POLICY, "post": None}
        ident, kind, fields = wire.command(dict(configure), False, 0)
        self.assertEqual((ident, kind, fields["lifetime"]), (1, "configure", 1.0))
        self.assertEqual(fields["policy"].grants, [])
        _, _, granted = wire.command(dict(configure, grants=["nas.lan:445", "NAS.lan.:445", "[fd00::1]:22",
                                                             "127.0.0.1:22"]), False, 0)
        self.assertEqual([address.authority_text(a) for a in granted["policy"].grants],
                         ["127.0.0.1:22", "[fd00::1]:22", "nas.lan:445"])
        self.assertNotEqual(granted["policy"].identity, fields["policy"].identity)
        _, _, empty = wire.command(dict(configure, grants=[]), False, 0)
        self.assertEqual(empty["policy"].identity, fields["policy"].identity)
        self.assertIsNone(fields["connect_proxy"])
        _, _, proxied = wire.command(dict(configure, connect_proxy="Proxy.Corp:3128", grants=["nas.lan:445"]),
                                     False, 0)
        self.assertEqual(address.authority_text(proxied["connect_proxy"]), "proxy.corp:3128")
        # A route, not policy: the identity unchanged.
        _, _, plain = wire.command(dict(configure, grants=["nas.lan:445"]), False, 0)
        self.assertEqual(proxied["policy"].identity, plain["policy"].identity)
        cases = [
            (dict(configure, grants="nas.lan:445"), False, "control_malformed"),
            (dict(configure, grants=None), False, "control_malformed"),
            (dict(configure, grants=["[::ffff:0.0.0.0]:22"]), False, "configure_invalid"),
            (dict(configure, grants=["*.lan:22"]), False, "configure_invalid"),
            (dict(configure, grants=[f"h{i}.lan:1" for i in range(33)]), False, "configure_invalid"),
            (dict(configure, connect_proxy=None), False, "control_malformed"),
            (dict(configure, connect_proxy=3128), False, "control_malformed"),
            (dict(configure, connect_proxy="proxy.corp"), False, "configure_invalid"),
            (dict(configure, connect_proxy="[::]:3128"), False, "configure_invalid"),
            (dict(configure, connect_proxy="0.0.0.0:3128"), False, "configure_invalid"),
            (dict(configure, v=2), False, "control_version"),
            (dict(configure, extra=1), False, "control_malformed"),
            (dict(configure, id=0), False, "control_order"),
            (dict(configure, run_id="r-x"), False, "configure_invalid"),
            (dict(configure, policy={"schema": "x"}), False, "configure_invalid"),
            (dict(configure, lifetime_ms=0), False, "control_malformed"),
            (dict(configure, lifetime_ms=1.5), False, "control_malformed"),
            (dict(configure, lifetime_ms=True), False, "control_malformed"),
            (dict(configure, post={"nonce": "x", "delivery": None}), False, "configure_invalid"),
            ({"type": "revoke", "id": 2, "request": "q"}, False, "control_order"),
            ({"type": "shutdown", "id": 2}, True, "control_unknown"),
            ({"type": "revoke", "id": 2, "request": "../q"}, True, "control_malformed"),
            ({"type": "respond", "id": 2, "exchange": 1, "body": ""}, True, "control_malformed"),
            ({"type": "deliver", "id": 2, "exchange": 1, "request": "q", "deadline_ms": 1800001, "name": "n",
              "size": 1, "sha256": "a" * 64}, True, "control_malformed"),
            ({"type": "deliver", "id": 2, "exchange": 1, "request": "q", "deadline_ms": 1, "name": "n",
              "size": (2 << 30) + 1, "sha256": "a" * 64}, True, "control_malformed"),
        ]
        for value, configured, code in cases:
            with self.assertRaises(wire.Violation) as raised:
                wire.command(value, configured, 0 if not configured else 1)
            self.assertEqual(raised.exception.code, code, value)
        reader = wire.Reader()
        body = json.dumps({"type": "revoke"}).encode()
        frames = reader.feed(struct.pack(">I", len(body)) + body + b"\x00")
        self.assertEqual(frames, [{"type": "revoke"}])
        self.assertEqual(reader.end(), "control_truncated")
        surrogate = b'{"a":"\\ud800"}'
        for raw, code in ((b"\x00\x00\x00\x00", "control_oversize"), (b"\x7f\x00\x00\x00", "control_oversize"),
                          (b"\x00\x00\x00\x02[]", "control_malformed"),
                          (b"\x00\x00\x00\x03NaN", "control_malformed"),
                          (struct.pack(">I", len(surrogate)) + surrogate, "control_malformed")):
            with self.assertRaises(wire.Violation) as raised:
                wire.Reader().feed(raw)
            self.assertEqual(raised.exception.code, code, raw)

    def test_the_scp_profile_is_the_rust_one(self):
        from agentbox_server import transport
        from agentbox_controller import ssh
        self.assertEqual(transport.SCP_SSH_OPTIONS, ssh.TRANSFER_OPTIONS)
        self.assertEqual(transport.SCP_FLAGS, ssh.SCP_FLAGS)
        connection = transport.Connection(transport.Connection.endpoint("2001:db8::7", 2222), "agent", "/k/id",
                                          "/k/known", "jail")
        argv = connection.scp_argv("/usr/bin/scp", "/usr/bin/ssh", "/dev/fd/3", "/work/.agentbox-requests/x")
        self.assertEqual(argv[:8], ["/usr/bin/scp", "-q", "-B", "-s", "-F", "/dev/null", "-P", "2222"])
        self.assertEqual(argv[-3:], ["--", "/dev/fd/3", "[2001:db8::7]:/work/.agentbox-requests/x"])
        for host in ("0.0.0.0", "224.0.0.1", "::", "ff02::1", "[::1]", "fe80::1%eth0", "127.1", "Jail", "-V"):
            with self.assertRaises(transport.Invalid):
                transport.Connection.endpoint(host, 22)

    def test_strict_json_is_serdes(self):
        for text in ("NaN", '{"a":Infinity}', "[1e400]", "\ufeff{}", '"\\ud800"', "[" * 128 + "]" * 128, "{} x"):
            with self.assertRaises(strictjson.Invalid):
                strictjson.loads(text)
        self.assertEqual(strictjson.loads('{"a":1,"a":2}'), {"a": 2})
        self.assertIsInstance(strictjson.loads("[" * 127 + "]" * 127), list)


class ReferenceUnits(unittest.TestCase):
    """Request framing, control frames and host tool lookup."""

    def test_the_post_contract_is_the_codecs_and_framing(self):
        """acquisitions/contracts/artifacts/post-v1/contract.json: this server's codec
        constants, framing codes and statuses."""
        with open(os.path.join(REPO, "acquisitions", "contracts", "artifacts", "post-v1", "contract.json")) as stream:
            contract = json.load(stream)
        http, body = contract["http"], contract["body"]
        self.assertEqual((contract["version"], codec.VERSION), (1, 1))
        self.assertEqual((http["method"], http["path"], http["host"], http["content_type"], http["max_body_bytes"]),
                         (codec.METHOD, codec.PATH, codec.HOST, codec.CONTENT_TYPE, codec.MAX_BODY_BYTES))
        self.assertEqual((http["max_head_bytes"], http["max_request_line_bytes"], http["max_header_fields"]),
                         (broker.Limits().max_head_bytes, broker.Limits().max_line_bytes, broker.Limits().max_headers))
        self.assertEqual({int(status): phrase for status, phrase in http["response_statuses"].items()},
                         request._PHRASES)
        self.assertEqual((body["max_bytes"], body["max_depth"], body["session_hex_digits"],
                          body["max_ready_overhead_bytes"]),
                         (codec.MAX_BODY_BYTES, codec.MAX_DEPTH, codec.SESSION_HEX_DIGITS,
                          codec.MAX_READY_OVERHEAD_BYTES))
        self.assertEqual((tuple(body["request_types"]), tuple(body["response_types"])),
                         (codec.REQUEST_TYPES, codec.RESPONSE_TYPES))
        self.assertEqual(body["error"]["lane_codes"], {code: codec.fault_status(code) for code in codec.LANE_FAULTS})
        self.assertEqual(body["error"]["codec_status"], codec.fault_status("invalid_json"))
        # Every framing code with its status; the rest of STATUS are
        # transport refusals outside the contract.
        self.assertEqual(len(contract["framing_codes"]), 12)
        for code, status in contract["framing_codes"].items():
            self.assertEqual(request.STATUS[code], status, code)
            self.assertEqual(broker.status_of(code), status, code)

    def test_a_post_body_arrives_in_any_chunks_then_one_response_completes(self):
        exchange = request.PostExchange(5, b"ab")
        self.assertEqual(exchange.first, ("pending",))
        self.assertEqual((exchange.input(b"c"), exchange.input(b"de")), (("pending",), ("body", b"abcde")))
        self.assertEqual(exchange.input(b""), ("pending",))
        self.assertTrue(exchange.respond(b"0123456789"))
        self.assertFalse(exchange.respond(b"again"), "one response")
        self.assertEqual((exchange.output(), exchange.wrote(4)), (b"0123456789", False))
        self.assertEqual((exchange.output(), exchange.wrote(6)), (b"456789", True))
        self.assertEqual((exchange.input(b"late"), exchange.end(False)), (("ignored",), ("ignored",)))

    def test_post_bodies_end_or_overrun_with_fixed_steps(self):
        # Empty: complete at once.
        self.assertEqual(request.PostExchange(0, b"").first, ("body", b""))
        # An end before the whole body: incomplete, unanswered.
        exchange = request.PostExchange(4, b"ab")
        self.assertEqual(exchange.end(True), ("refused", "request_incomplete"))
        # Input past the length before dispatch: refused.
        self.assertEqual(request.PostExchange(2, b"abc").first, ("refused", "request_body_overrun"))
        exchange = request.PostExchange(2, b"a")
        self.assertEqual(exchange.input(b"bc"), ("refused", "request_body_overrun"))
        # Abandoned before its response completes: eof, reset, extra input.
        for end in ("eof", "reset", "extra_input"):
            exchange = request.PostExchange(1, b"x")
            exchange.respond(b"answer")
            exchange.wrote(2)
            step = exchange.input(b"y") if end == "extra_input" else exchange.end(end == "reset")
            self.assertEqual(step, ("abandoned", end))
            self.assertEqual(exchange.output(), b"")

    def test_responses_are_fixed_length_json_then_close_and_refusals_status_only(self):
        body = b'{"v":1,"type":"error","code":"not_active"}'
        response = request.post_response(409, body)
        self.assertEqual(response, b"HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        self.assertIsNone(request.post_response(418, body))
        self.assertIsNone(request.post_response(200, b"x" * (codec.MAX_BODY_BYTES + 1)))
        for code, status in (("post_unconfigured", 405), ("request_timeout", 408), ("request_body_too_large", 413),
                             ("post_capacity", 503), ("post_closed", 503), ("broker_stopping", 503),
                             ("destination_not_allowed", 403), ("dns_timeout", 504), ("connect_refused", 502)):
            self.assertEqual(broker.status_of(code), status, code)
            self.assertTrue(request.refusal(status).startswith(f"HTTP/1.1 {status} ".encode()), code)
            self.assertTrue(request.refusal(status).endswith(b"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))

    def test_a_maximal_legal_body_fits_one_frame_however_escaped(self):
        # Every byte of the largest body JSON-escaped to its longest form.
        body = "\u0001" * codec.MAX_BODY_BYTES
        message = wire.message("post.request", exchange=1, replay=False, bytes=codec.MAX_BODY_BYTES, body=body)
        data = wire.frame(message)
        self.assertIsNotNone(data)
        self.assertLessEqual(len(data) - 4, wire.MAX_FRAME_BYTES)

    def captured(self, path):
        """The tool PATH as captured from a host PATH of `path`."""
        saved = tools._CAPTURED
        self.addCleanup(setattr, tools, "_CAPTURED", saved)
        tools._CAPTURED = None
        tools.capture_host({"PATH": path, "HOME": "/h", "AGENTBOX_X": "1"})

    def scratch(self):
        root = tempfile.mkdtemp(prefix="abt-")
        self.addCleanup(shutil.rmtree, root, True)
        return root

    def tool_file(self, path, body, mode):
        with open(path, "w") as stream:
            stream.write(body)
        os.chmod(path, mode)

    def test_path_keeps_only_shell_inert_absolute_entries_in_order(self):
        self.assertEqual(tools.filter_path('/home/u/.local/bin::rel:/usr/bin:./x:/a b:/q"x:/usr/local/bin/:/a/../b:/bin'),
                         "/home/u/.local/bin:/usr/bin:/bin")
        self.assertEqual(tools.filter_path("/opt/\udcff/bin:/usr/bin"), "/usr/bin")
        for nothing in ("", ":", "rel:.:", "/a b", "/", None):
            self.assertIsNone(tools.filter_path(nothing), nothing)

    def test_the_host_environment_is_captured_once_with_its_path_filtered(self):
        self.captured("rel:/usr/bin:/a b")
        captured = tools.capture_host()
        self.assertEqual(captured, [("HOME", "/h"), ("PATH", "/usr/bin")])
        self.assertEqual(tools.capture_host({"PATH": "/elsewhere"}), captured, "captured once")
        self.assertEqual(tools.tool_env(), [("PATH", "/usr/bin"), ("LC_ALL", "C")])
        # No captured value: no PATH at all, never an empty one.
        self.captured("rel")
        self.assertEqual(tools.capture_host(), [("HOME", "/h")])
        self.assertEqual(tools.tool_env(), [("LC_ALL", "C")])

    def test_lookup_takes_the_first_executable_regular_file_in_order(self):
        root = self.scratch()
        dirs = {name: os.path.join(root, name) for name in ("plain", "dir", "user", "late")}
        for name, path in dirs.items():
            os.mkdir(path)
            os.chmod(path, 0o775 if name == "user" else 0o755)
        self.tool_file(os.path.join(dirs["plain"], "tool"), "#!/bin/sh\n", 0o644)
        os.mkdir(os.path.join(dirs["dir"], "tool"))
        self.tool_file(os.path.join(dirs["user"], "tool"), "#!/bin/sh\nexit 0\n", 0o775)
        self.tool_file(os.path.join(dirs["late"], "tool"), "#!/bin/sh\n", 0o755)
        self.captured(":".join(["relative", os.path.join(root, "absent"), dirs["plain"], dirs["dir"], dirs["user"],
                                dirs["late"]]))
        if os.geteuid() == 0:
            with self.assertRaises(tools.ToolError) as raised:
                tools.find_trusted("tool")
            self.assertEqual(raised.exception.code, "tool_untrusted")
            return
        # A user-owned script in a group-writable directory, as the shell
        # would run it.
        found = os.path.realpath(os.path.join(dirs["user"], "tool"))
        self.assertEqual((tools.find_trusted("tool"), tools.resolve("tool")), (found, found))
        for name in ("absent", "", ".", "..", "a/tool"):
            with self.assertRaises(tools.ToolError) as raised:
                tools.find_trusted(name)
            self.assertEqual(raised.exception.code, "tool_missing", name)
        self.captured("late")
        with self.assertRaises(tools.ToolError):
            tools.find_trusted("tool")

    def test_a_linked_tool_resolves_to_its_target_and_a_dangling_one_is_passed_over(self):
        if os.geteuid() == 0:
            self.skipTest("root needs a root-owned chain")
        root = self.scratch()
        for name in ("store", "bin", "dangling"):
            os.mkdir(os.path.join(root, name), 0o755)
        target = os.path.join(root, "store", "real-tool")
        self.tool_file(target, "#!/bin/sh\necho a\n", 0o555)
        os.symlink(target, os.path.join(root, "bin", "tool"))
        os.symlink(os.path.join(root, "nowhere"), os.path.join(root, "dangling", "tool"))
        self.captured(f"{root}/dangling:{root}/bin")
        self.assertEqual(tools.resolve("tool"), os.path.realpath(target))
        self.captured(f"{root}/dangling")
        with self.assertRaises(tools.ToolError) as raised:
            tools.find_trusted("tool")
        self.assertEqual(raised.exception.code, "tool_missing")

    def test_a_wrapper_finds_its_interpreter_only_through_the_tool_path(self):
        root = self.scratch()
        os.mkdir(os.path.join(root, "bin"), 0o755)
        os.symlink("/bin/sh", os.path.join(root, "bin", "agentbox-test-sh"))
        self.tool_file(os.path.join(root, "bin", "tool"), "#!/usr/bin/env agentbox-test-sh\necho wrapped\n", 0o755)
        self.captured(f"{root}/bin")
        tool = tools.find_trusted("tool")

        def ran(env):
            run = tools.Run(tool, [], env, time.monotonic() + 10, 64)
            self.addCleanup(run.close)
            while True:
                outcome = run.poll(time.monotonic())
                if outcome is not None:
                    return outcome
                select.select([run.fileno()], [], [], 0.05)
        self.assertEqual(ran(tools.tool_env()), ("ok", 0, b"wrapped\n"))
        outcome = ran([("LC_ALL", "C")])
        self.assertNotEqual(outcome[:2], ("ok", 0))

    def test_root_requires_a_root_owned_unwritable_chain(self):
        def owned(uid, mode):
            return tools._root_owned(types.SimpleNamespace(st_uid=uid, st_mode=mode))
        self.assertTrue(owned(0, 0o100755))
        self.assertTrue(owned(0, 0o40555))
        for uid, mode in ((1000, 0o100755), (0, 0o100775), (0, 0o100757), (0, 0o41777)):
            self.assertFalse(owned(uid, mode), (uid, oct(mode)))
        root = self.scratch()
        os.mkdir(os.path.join(root, "bin"), 0o755)
        self.tool_file(os.path.join(root, "bin", "tool"), "x", 0o755)
        if os.geteuid() != 0:
            self.assertFalse(tools._root_chain(os.path.join(root, "bin", "tool")))
        self.assertFalse(tools._root_chain(os.path.join(root, "absent")))
        # A root-owned, unwritable system chain passes (where the host has
        # one).
        chain = ("/", "/usr", "/usr/bin")
        if all(os.lstat(path).st_uid == 0 and not os.lstat(path).st_mode & 0o022 for path in chain):
            self.assertTrue(tools._root_chain("/usr/bin"))


class Ingress(unittest.TestCase):
    """POST ingress: slots, replay, answers, activation and ledger limits."""

    def submit(self, client):
        return codec.encode_request({"type": "submit", "session": NONCE, "client": client, "handler": "npm",
                                     "operation": "install", "args": {}})

    def test_slots_replay_and_answers(self):
        post = ingress.Ingress(0.0, None)
        self.assertEqual(post.permit(), "post_closed")
        post.arm(NONCE)
        with self.assertRaises(ValueError):
            post.arm(NONCE)
        self.assertIsNone(post.permit())
        self.assertIsNone(post.permit())
        self.assertEqual(post.permit(), "post_capacity")
        first = post.admit(self.submit("c-1"), 1.0)
        self.assertEqual(first[0], "dispatched")
        self.assertEqual(post.poll()[:4], ("request", first[1], codec.decode_request(self.submit("c-1")), False))
        # A second submit takes the control slot; a third has none.
        second = post.admit(self.submit("c-1"), 1.0)
        self.assertEqual(second[0], "dispatched")
        self.assertEqual(post.poll()[3], True)
        self.assertEqual(post.admit(self.submit("c-2"), 1.0), ("refused", "post_capacity"))
        self.assertEqual(post.activate(second[1], 100.0), "replay")
        # Codec and session errors are answered, charged, never seen.
        answer = post.admit(b"{}", 1.0)
        self.assertEqual((answer[0], answer[1]), ("answer", 400))
        self.assertEqual(json.loads(answer[2])["code"], "invalid_version")
        foreign = codec.encode_request({"type": "cancel", "session": "f" * 32, "client": "c-1"})
        self.assertEqual(post.admit(foreign, 1.0)[1], 403)
        token, cancel = post.activate(first[1], 100.0)
        self.assertEqual(post.activate(first[1], 100.0), "busy")
        digest = codec.request_sha256("c-1", "npm", "install", {})
        ready = {"type": "ready", "session": NONCE, "client": "c-1", "request": "q-1", "request_sha256": digest,
                 "handler": "npm", "operation": "install", "size": 1, "sha256": "a" * 64, "metadata": {}}
        self.assertEqual(post.respond(second[1], ready), "mismatch")
        self.assertIsNone(post.respond(first[1], ready))
        self.assertEqual(post.respond(first[1], ready), "stale")
        self.assertEqual(post.next_step(first[1])[0], "respond")
        self.assertEqual(post.finish(first[1], "written"), "written")
        self.assertEqual(post.poll(), ("ended", first[1], "written"))
        self.assertEqual(post.active["delivered"], ("q-1", digest, "a" * 64))
        # Peer loss of the replay's exchange cancels nothing of the active one.
        post.finish(second[1], "peer_eof")
        self.assertFalse(cancel.is_cancelled())
        post.retire(token)
        self.assertTrue(cancel.is_cancelled())
        post.stop()
        self.assertEqual(post.poll(), ("ended", second[1], "peer_eof"))
        self.assertEqual(post.poll(), ("closed", "stopped"))
        self.assertIsNone(post.poll())
        self.assertEqual(post.admit(self.submit("c-3"), 1.0), ("refused", "post_closed"))

    def test_the_ledger_ends_the_ingress_at_its_bound(self):
        post = ingress.Ingress(0.0, None)
        post.arm(NONCE)
        post.ledger.messages = ingress.MAX_MESSAGES - 3
        refused = post.admit(self.submit("c-1"), 1.0)
        self.assertEqual(refused, ("refused", "post_closed"))
        self.assertEqual(post.closure, "limit")
        self.assertEqual(post.poll(), ("closed", "limit"))
        cutoff = ingress.Ingress(0.0, 5.0)
        cutoff.arm(NONCE)
        self.assertEqual(cutoff.admit(self.submit("c-1"), 5.0), ("refused", "post_closed"))
        self.assertEqual(cutoff.bound(1.0), 5.0)


# The broker in process.

class Harness:
    """One broker on its own loop thread; the test thread only uses
    sockets and reads the records."""

    def __init__(self, relay=None, limits=None, post=None, policy_document=POLICY, names=None, loopback="127.0.0.1",
                 grants=(), mapped=(("93.184.216.34", 443),), proxy=None):
        self.loop = main.Loop()
        self.events = []
        self.mapped = mapped
        self.names = names or {"api.example.com.": ["93.184.216.34"]}
        self.lookups = []
        # Tests' own endpoints dialed as is (a closed port).
        self.direct = set()
        # The upstreams' loopback: an approved address is dialed there, by
        # its family (AF_INET6 for ::1).
        self.loopback = loopback
        self.upstream = socket.create_server((loopback, 0), family=socket.AF_INET6 if ":" in loopback
                                             else socket.AF_INET)
        self.upstream.settimeout(WAIT)
        self.failed = False
        self.calls = []
        self.broker = broker.Broker(
            self.loop, policy.Policy.parse(json.dumps(policy_document).encode()).with_grants(
                [grant.format(port=self.upstream.getsockname()[1]) for grant in grants]),
            limits or broker.Limits(head_timeout=1.0, dns_timeout=1.0, connect_timeout=1.0, idle_timeout=10.0),
            post, relay or support.relay(), self.record, self.fail, time.monotonic,
            lookup=self.lookup, dial_map=self.dial,
            proxy=None if proxy is None else policy.parse_grant(proxy.format(port=self.upstream.getsockname()[1])))
        self.address = self.broker.start(time.monotonic() + WAIT, lambda: False)
        self.report = None
        self.halt = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def record(self, event, deadline):
        self.events.append(event)
        return True

    def fail(self):
        self.failed = True

    def lookup(self, query):
        self.lookups.append(query)
        if query not in self.names:
            raise OSError("no such name")
        return [ipaddress.ip_address(answer) for answer in self.names[query]]

    def dial(self, target):
        """Only the mapped endpoints reach the owned upstream, and the owned
        upstream itself (its own loopback address, mapped forms included)
        is dialed as is; nothing is ever dialed elsewhere."""
        ip, port = target
        self.calls.append((str(ip), port))
        if (str(ip), port) in self.mapped:
            return ipaddress.ip_address(self.loopback), self.upstream.getsockname()[1]
        if (str(ip), port) in self.direct:
            return target
        plain = ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped is not None else ip
        if str(plain) == self.loopback and port == self.upstream.getsockname()[1]:
            return target
        return None

    def run(self):
        while not self.halt.is_set():
            self.loop.step(0.01)
            self.broker.tick()
        self.report = self.broker.stop_until(time.monotonic() + 5.0, self.loop.step)

    def stop(self):
        self.halt.set()
        self.thread.join(10)
        self.upstream.close()
        return self.report

    def client(self, head):
        sock = socket.create_connection(self.address, timeout=WAIT)
        sock.sendall(head)
        return sock

    def tunnel(self, authority="93.184.216.34:443", extra=b""):
        sock = self.client(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode() + extra)
        self.assertEqual(exact(sock, len(ESTABLISHED)), ESTABLISHED)
        upstream, _ = self.upstream.accept()
        upstream.settimeout(WAIT)
        return sock, upstream

    def assertEqual(self, a, b):
        assert a == b, (a, b)

    def of(self, kind):
        return [event for event in list(self.events) if event["event"] == kind]

    def wait_for(self, condition):
        end = time.monotonic() + WAIT
        while time.monotonic() < end:
            if condition():
                return True
            time.sleep(0.01)
        return condition()


def broker_model_only():
    return {"schema": "agentbox.network-policy.v1", "mode": "model_only",
            "provider_sets": [{"name": "openai-codex", "version": 1}]}


def ipv6_loopback():
    try:
        with socket.create_server(("::1", 0), family=socket.AF_INET6):
            return True
    except OSError:
        return False


def exact(sock, count):
    data = b""
    while len(data) < count:
        try:
            more = sock.recv(count - len(data))
        except ConnectionResetError:
            break
        if not more:
            break
        data += more
    return data


def read_all(sock):
    data = b""
    while True:
        try:
            more = sock.recv(65536)
        except (ConnectionResetError, TimeoutError):
            return data
        if not more:
            return data
        data += more


def status(sock):
    head = b""
    while not head.endswith(b"\r\n\r\n"):
        try:
            byte = sock.recv(1)
        except (ConnectionResetError, TimeoutError):
            return None
        if not byte:
            return None
        head += byte
    return int(head.split(b" ")[1])


class BrokerInProcess(unittest.TestCase):
    def harness(self, **kwargs):
        h = Harness(**kwargs)
        self.addCleanup(h.stop)
        return h

    def test_a_tunnel_through_a_relay_child_with_prefix_and_half_close(self):
        h = self.harness()
        for authority in ("93.184.216.34:443", "api.example.com:443"):
            client, upstream = h.tunnel(authority, extra=b"early")
            with client, upstream:
                self.assertEqual(exact(upstream, 5), b"early")
                client.sendall(b" more")
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(read_all(upstream), b" more")
                upstream.sendall(b"answer")
                upstream.shutdown(socket.SHUT_WR)
                self.assertEqual(read_all(client), b"answer")
        self.assertTrue(h.wait_for(lambda: len(h.of("broker.tunnel_closed")) == 2))
        for closed in h.of("broker.tunnel_closed"):
            self.assertEqual((closed["attributes"]["reason"], closed["attributes"]["bytes_up"],
                              closed["attributes"]["bytes_down"]), ("completed", 10, 6))
        allowed = h.of("broker.request")
        self.assertEqual([e["attributes"]["decision"] for e in allowed], ["tunnel", "tunnel"])
        self.assertEqual(allowed[1]["attributes"]["answers"], 1)
        self.assertEqual(h.lookups, ["api.example.com."])
        report = h.stop()
        self.assertTrue(report["clean"], report)
        self.assertEqual(report["counters"]["tunnels_opened"], 2)
        self.assertEqual((report["counters"]["bytes_up"], report["counters"]["bytes_down"]), (20, 12))
        self.assertEqual(h.of("broker.stopped")[0]["attributes"]["tunnels_opened"], 2)

    @unittest.skipUnless(socket.has_ipv6 and ipv6_loopback(), "no IPv6 loopback")
    def test_a_tunnel_dialed_over_ipv6_carries_binary_data_with_half_close(self):
        h = self.harness(loopback="::1")
        payload = bytes(range(256)) * 64
        client, upstream = h.tunnel(extra=b"\x00early")
        with client, upstream:
            # The broker's own dial: an AF_INET6 connection from ::1.
            self.assertEqual((upstream.family, upstream.getpeername()[0]), (socket.AF_INET6, "::1"))
            self.assertEqual(exact(upstream, 6), b"\x00early")
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(read_all(upstream), payload)
            upstream.sendall(payload[::-1])
            upstream.shutdown(socket.SHUT_WR)
            self.assertEqual(read_all(client), payload[::-1])
        self.assertTrue(h.wait_for(lambda: h.of("broker.tunnel_closed")))
        closed = h.of("broker.tunnel_closed")[0]["attributes"]
        self.assertEqual((closed["reason"], closed["bytes_up"], closed["bytes_down"]),
                         ("completed", 6 + len(payload), len(payload)))
        self.assertTrue(h.stop()["clean"])

    def test_denials_are_never_resolved_or_dialed(self):
        h = self.harness(names={"api.example.com.": ["93.184.216.34", "0.0.0.0"], "denied.example.": ["93.184.216.34"]})
        cases = [("denied.example:443", 403, "destination_not_allowed"), ("api.example.com:80", 403, "destination_not_allowed"),
                 ("api.example.com:443", 403, "address_unspecified"), ("127.0.0.1:443", 403, "destination_not_allowed"),
                 ("[::1]:443", 403, "destination_not_allowed"), ("example.com:0", 400, "port_invalid")]
        for authority, code, reason in cases:
            with h.client(f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode()) as sock:
                self.assertEqual(status(sock), code, authority)
            self.assertTrue(h.wait_for(lambda: len(h.of("broker.request")) == cases.index((authority, code, reason)) + 1))
            self.assertEqual(h.of("broker.request")[-1]["attributes"]["reason"], reason)
        self.assertEqual(h.lookups, ["api.example.com."])
        self.assertEqual(h.calls, [])
        h.upstream.settimeout(0.2)
        with self.assertRaises(TimeoutError):
            h.upstream.accept()

    def test_open_and_grants_admit_lan_and_loopback_endpoints_but_never_unspecified(self):
        # Owned upstreams only: each allowed LAN target is mapped to the
        # loopback listener, never dialed itself; the owned loopback
        # listener is dialed as is, through the address the client named.
        lan = (("192.168.1.20", 8080), ("10.0.0.5", 22), ("fd00::7", 22))
        names = {"nas.lan.": ["192.168.1.20"], "local.test.": ["127.0.0.1"],
                 "mixed.lan.": ["192.168.1.20", "0.0.0.0"], "zero.lan.": ["::ffff:0.0.0.0", "127.0.0.1"]}
        opened = self.harness(policy_document={"schema": "agentbox.network-policy.v1", "mode": "open"},
                              names=names, mapped=lan, grants=["10.0.0.9:1"])
        port = opened.upstream.getsockname()[1]
        for authority in ("192.168.1.20:8080", "10.0.0.5:22", "[fd00::7]:22", "nas.lan:8080", f"127.0.0.1:{port}",
                          f"[::ffff:127.0.0.1]:{port}", f"local.test:{port}"):
            client, upstream = opened.tunnel(authority)
            client.sendall(b"ping")
            self.assertEqual(exact(upstream, 4), b"ping", authority)
            client.close()
            upstream.close()
        self.assertIn(("127.0.0.1", port), opened.calls)
        self.assertIn(("::ffff:127.0.0.1", port), opened.calls)
        refused = [("0.0.0.0:22", "address_unspecified"), ("[::]:22", "address_unspecified"),
                   ("[::ffff:0.0.0.0]:22", "address_unspecified"), ("mixed.lan:8080", "address_unspecified"),
                   ("zero.lan:8080", "address_unspecified")]
        dialed = list(opened.calls)
        for authority, reason in refused:
            with opened.client(f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode()) as sock:
                self.assertEqual(status(sock), 403, authority)
            self.assertTrue(opened.wait_for(lambda: opened.of("broker.request")[-1]["attributes"]["reason"] == reason),
                            authority)
        self.assertEqual(opened.calls, dialed, "an unspecified candidate refuses before any dial")
        self.assertEqual(opened.of("broker.started")[0]["attributes"]["grants"], 0)

        granted = self.harness(policy_document=broker_model_only(), names=names, mapped=lan,
                               grants=["192.168.1.20:8080", "nas.lan:8080", "[fd00::7]:22", "nas.lan:8080",
                                       "127.0.0.1:{port}", "local.test:{port}"])
        port = granted.upstream.getsockname()[1]
        self.assertEqual(granted.of("broker.started")[0]["attributes"]["grants"], 5)
        for authority in ("192.168.1.20:8080", "nas.lan:8080", "[fd00::7]:22", f"127.0.0.1:{port}",
                          f"local.test:{port}"):
            client, upstream = granted.tunnel(authority)
            client.close()
            upstream.close()
        for authority, reason in (("10.0.0.5:22", "destination_not_allowed"),
                                  ("192.168.1.20:8081", "destination_not_allowed"),
                                  (f"[::1]:{port}", "destination_not_allowed"),
                                  (f"127.0.0.1:{port + 1}", "destination_not_allowed"),
                                  ("mixed.lan:8080", "destination_not_allowed")):
            with granted.client(f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode()) as sock:
                self.assertEqual(status(sock), 403, authority)
            self.assertTrue(granted.wait_for(lambda: granted.of("broker.request")[-1]["attributes"]["reason"] == reason),
                            authority)
        self.assertNotIn(("10.0.0.5", 22), granted.calls)
        self.assertNotIn(("127.0.0.1", port + 1), granted.calls)

    def test_malformed_and_slow_heads_are_bounded(self):
        h = self.harness()
        for head, code in ((b"GET / HTTP/1.1\r\n\r\n", 405), (b"CONNECT a HTTP/1.1\r\n\r\n", 400),
                           (b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n", 400),
                           (b"CONNECT " + b"a" * 2000, 414), (b"CONNECT x:1 HTTP/1.1\r\n" + b"X: y\r\n" * 2000, 431),
                           (b"POST /agentbox/v1/request HTTP/1.1\r\nHost: agentbox\r\nContent-Type: application/json"
                            b"\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}", 405)):
            with h.client(head) as sock:
                self.assertEqual(status(sock), code, head[:40])
        started = time.monotonic()
        with h.client(b"CONNECT 93.184") as sock:
            self.assertEqual(status(sock), 408)
        self.assertLess(time.monotonic() - started, 2.5)

    def test_a_tunnel_lives_on_without_any_refresh(self):
        h = self.harness(limits=broker.Limits(head_timeout=1.0, idle_timeout=10.0, max_lifetime=10.0))
        client, upstream = h.tunnel()
        with client, upstream:
            time.sleep(0.3)
            client.sendall(b"x")
            self.assertEqual(exact(upstream, 1), b"x")
            self.assertEqual(h.of("broker.tunnel_closed"), [])
        self.assertTrue(h.wait_for(lambda: h.of("broker.tunnel_closed")))
        self.assertEqual(h.of("broker.tunnel_closed")[0]["attributes"]["reason"], "completed")
        self.assertNotIn("snapshot", h.of("broker.started")[0]["attributes"])

    def test_capacity_and_a_failed_child(self):
        h = self.harness(limits=broker.Limits(max_tunnels=1, max_pending=1, head_timeout=1.0))
        client, upstream = h.tunnel()
        with client, upstream:
            with h.client(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n") as sock:
                self.assertEqual(status(sock), 503)
            self.assertTrue(h.wait_for(lambda: len(h.of("broker.request")) == 2))
            self.assertEqual(h.of("broker.request")[-1]["attributes"]["reason"], "tunnel_limit")
        h2 = self.harness(relay="/nonexistent/agentbox-relay")
        with h2.client(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n") as sock:
            self.assertEqual(status(sock), 503)
        self.assertTrue(h2.wait_for(lambda: h2.of("broker.tunnel_closed")))
        self.assertEqual(h2.of("broker.tunnel_closed")[0]["attributes"]["reason"], "relay_failed")

    def test_a_stop_revokes_stalled_tunnels_and_reaps_their_children(self):
        h = self.harness()
        pairs = [h.tunnel() for _ in range(3)]
        for client, upstream in pairs:
            client.setblocking(False)
            try:
                while True:
                    client.send(b"x" * 65536)
            except BlockingIOError:
                pass
        children = [t.relay.pid for t in list(h.broker.tunnels.values())]
        started = time.monotonic()
        report = h.stop()
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertTrue(report["clean"], report)
        for pid in children:
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)
        reasons = sorted(e["attributes"]["reason"] for e in h.of("broker.tunnel_closed"))
        self.assertEqual(reasons, ["broker_stopped"] * 3)
        for client, upstream in pairs:
            client.close()
            upstream.close()

    def test_post_exchanges_through_the_ingress(self):
        post = ingress.Ingress(time.monotonic(), None)
        post.arm(NONCE)
        h = self.harness(post=post)
        body = codec.encode_request({"type": "submit", "session": NONCE, "client": "c-1", "handler": "npm",
                                     "operation": "install", "args": {}})
        head = ("POST /agentbox/v1/request HTTP/1.1\r\nHost: agentbox\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        sock = h.client(head + body)
        self.assertTrue(h.wait_for(lambda: post.slots[0] is not None))
        events = []
        self.assertTrue(h.wait_for(lambda: events.append(post.poll()) or any(events)))
        kind, ident, decoded, replay, size, _ = next(e for e in events if e)
        self.assertEqual((kind, decoded["client"], replay, size), ("request", "c-1", False, len(body)))
        digest = codec.request_sha256("c-1", "npm", "install", {})
        closed = {"type": "closed", "session": NONCE, "client": "c-1", "request": "q-1", "request_sha256": digest,
                  "handler": "npm", "outcome": "denied", "reason": "delivery_failed"}
        self.assertIsNone(post.respond(ident, closed))
        answer = read_all(sock)
        sock.close()
        self.assertTrue(answer.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertTrue(answer.endswith(codec.encode_response(closed)))
        self.assertTrue(h.wait_for(lambda: h.of("broker.post")))
        self.assertEqual(h.of("broker.post")[0]["attributes"]["reason"], "written")
        # A third POST beyond the two permits is refused before its body.
        held = [h.client(head) for _ in range(2)]
        self.assertTrue(h.wait_for(lambda: post.permits == 2))
        with h.client(head) as sock:
            self.assertEqual(status(sock), 503)
        for sock in held:
            sock.close()
        report = h.stop()
        self.assertEqual(report["posts_outstanding"], 0)


def proxy_head(sock):
    """The CONNECT head a fake proxy received, read to its blank line."""
    head = b""
    while not head.endswith(b"\r\n\r\n"):
        more = sock.recv(1)
        if not more:
            break
        head += more
    return head


class BrokerProxy(unittest.TestCase):
    """A configured CONNECT proxy: the owned upstream listener plays it,
    then plays the destination behind its tunnel."""

    def harness(self, proxy="proxy.test:{port}", names=None, grants=("dest.invalid:443",), **kwargs):
        h = Harness(proxy=proxy, names=names or {"proxy.test.": ["127.0.0.1"]}, grants=grants,
                    policy_document=kwargs.pop("policy_document", broker_model_only()), **kwargs)
        self.addCleanup(h.stop)
        return h

    def proxied(self, h, authority="dest.invalid:443", extra=b""):
        """(client, proxy) once the proxy took the CONNECT it was sent."""
        client = h.client(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode() + extra)
        proxy, _ = h.upstream.accept()
        proxy.settimeout(WAIT)
        self.addCleanup(client.close)
        self.addCleanup(proxy.close)
        self.assertEqual(proxy_head(proxy),
                         f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        return client, proxy

    def reason(self, h):
        self.assertTrue(h.wait_for(lambda: h.of("broker.request")))
        return h.of("broker.request")[-1]["attributes"]["reason"]

    def nothing_accepted(self, h):
        h.upstream.settimeout(0.2)
        with self.assertRaises(TimeoutError):
            h.upstream.accept()

    def test_a_name_unresolvable_here_reaches_the_proxy_and_flows_both_ways(self):
        h = self.harness()
        client, proxy = self.proxied(h, extra=b"early")
        proxy.setblocking(False)
        # The client's early bytes wait for the proxy's 2xx.
        with self.assertRaises(BlockingIOError):
            proxy.recv(1)
        proxy.setblocking(True)
        proxy.settimeout(WAIT)
        # Its head and whatever follows in the same segment.
        proxy.sendall(b"HTTP/1.1 200 Connection established\r\nVia: 1.1 corp-proxy\r\n\r\nbanner")
        self.assertEqual(exact(client, len(ESTABLISHED)), ESTABLISHED)
        self.assertEqual(exact(client, 6), b"banner")
        self.assertEqual(exact(proxy, 5), b"early")
        client.sendall(b" more")
        client.shutdown(socket.SHUT_WR)
        self.assertEqual(read_all(proxy), b" more")
        proxy.sendall(b"answer")
        proxy.shutdown(socket.SHUT_WR)
        self.assertEqual(read_all(client), b"answer")
        self.assertTrue(h.wait_for(lambda: h.of("broker.tunnel_closed")))
        closed = h.of("broker.tunnel_closed")[0]["attributes"]
        self.assertEqual((closed["reason"], closed["bytes_up"], closed["bytes_down"]), ("completed", 10, 12))
        self.assertEqual(h.lookups, ["proxy.test."])
        request = h.of("broker.request")[0]["attributes"]
        self.assertEqual((request["decision"], request["attempts"], request["port"]), ("tunnel", 1, 443))
        self.assertNotIn("answers", request)
        self.assertEqual(h.of("broker.started")[0]["attributes"]["route"], "proxy")
        text = json.dumps(h.events)
        for leak in ("proxy.test", "dest.invalid", "corp-proxy", "127.0.0.1"):
            self.assertNotIn(leak, text)
        self.assertTrue(h.stop()["clean"])

    def test_a_fragmented_head_is_taken_exactly_without_spinning(self):
        h = self.harness()
        reads = []
        real = h.broker._proxy_read
        h.broker._proxy_read = lambda conn: reads.append(1) or real(conn)
        client, proxy = self.proxied(h)
        proxy.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # The blank line split across every read, the tunnel's first bytes
        # with its last piece.
        for piece in (b"HTTP/1.0 2", b"00 OK\r\nX: y\r", b"\n\r", b"\ntail"):
            proxy.sendall(piece)
            time.sleep(0.15)
        self.assertEqual(exact(client, len(ESTABLISHED)), ESTABLISHED)
        self.assertEqual(exact(client, 4), b"tail")
        self.assertLessEqual(len(reads), 8)
        client.sendall(b"up")
        self.assertEqual(exact(proxy, 2), b"up")

    def test_an_ip_literal_proxy_and_ipv6_authorities_are_never_resolved(self):
        h = self.harness(proxy="127.0.0.1:{port}", grants=("[2001:db8::1]:443",))
        client, proxy = self.proxied(h, "[2001:db8::1]:443")
        proxy.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        self.assertEqual(exact(client, len(ESTABLISHED)), ESTABLISHED)
        self.assertEqual(h.lookups, [])
        self.assertEqual(h.calls, [("127.0.0.1", h.upstream.getsockname()[1])])

    def test_denied_and_unspecified_targets_never_reach_the_proxy(self):
        h = self.harness(policy_document={"schema": "agentbox.network-policy.v1", "mode": "open"}, grants=())
        for authority in ("0.0.0.0:443", "[::]:443", "[::ffff:0.0.0.0]:443"):
            with h.client(f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode()) as sock:
                self.assertEqual(status(sock), 403, authority)
            self.assertEqual(self.reason(h), "address_unspecified")
        m = self.harness()
        with m.client(b"CONNECT other.invalid:443 HTTP/1.1\r\n\r\n") as sock:
            self.assertEqual(status(sock), 403)
        self.assertEqual(self.reason(m), "destination_not_allowed")
        for each in (h, m):
            self.assertEqual((each.lookups, each.calls), ([], []))
            self.nothing_accepted(each)

    def test_a_valid_head_with_an_empty_reason_and_value_opens_the_tunnel(self):
        h = self.harness()
        client, proxy = self.proxied(h)
        proxy.sendall(b"HTTP/1.1 200 \r\nVia: 1.1 p\r\nX-Empty:\r\nX-Tab:\tv \x80\r\n\r\nearly")
        self.assertEqual(exact(client, len(ESTABLISHED)), ESTABLISHED)
        self.assertEqual(exact(client, 5), b"early")

    def test_failures_close_both_ends_and_never_try_another_address(self):
        malformed = (b"HTTP/1.1 200\r\n\r\n", b"HTTP/1.1 200\tOK\r\n\r\n", b"HTTP/1.1 200 OK\r\nbadfield\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nX: a\x00b\r\n\r\n", b"HTTP/1.1 200 OK\r\n folded\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nX : y\r\n\r\n", b"HTTP/1.1 200 OK\r\n: y\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n", b"HTTP/1.1 200 O\x00K\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 33 + b"\r\n", b"HTTP/2 200 OK\r\n\r\n")
        cases = tuple((reply, 502, "proxy_malformed") for reply in malformed) + (
            (b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 6\r\n\r\nsecret", 502,
             "proxy_refused"),
            (b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", 502, "proxy_refused"),
            (b"SSH-2.0-OpenSSH\r\n\r\n", 502, "proxy_malformed"),
            (b"HTTP/1.1 200 " + b"x" * 2000, 502, "proxy_malformed"),
            (b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 2000, 502, "proxy_malformed"),
            (b"HTTP/1.1 200 OK\r\n", 502, "proxy_failed"),
            (None, 504, "proxy_timeout"))
        for reply, code, reason in cases:
            h = self.harness(names={"proxy.test.": ["127.0.0.1", "192.0.2.7"]})
            client, proxy = self.proxied(h)
            if reply is not None:
                try:
                    proxy.sendall(reply)
                except OSError:
                    pass
                if reason == "proxy_failed":
                    proxy.shutdown(socket.SHUT_WR)
            self.assertEqual(status(client), code, reason)
            self.assertEqual(self.reason(h), reason)
            self.assertEqual(read_all(client), b"")
            self.assertEqual(read_all(proxy), b"")
            self.assertEqual(h.calls, [("127.0.0.1", h.upstream.getsockname()[1])])
            self.assertEqual(h.of("broker.tunnel_closed"), [])
            self.assertNotIn("secret", json.dumps(h.events))
            self.assertTrue(h.stop()["clean"])

    def test_an_unreachable_proxy_never_falls_back_to_a_direct_dial(self):
        closed = socket.create_server(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        h = self.harness(proxy=f"127.0.0.1:{port}", grants=(), names={"api.example.com.": ["93.184.216.34"]},
                         policy_document=POLICY)
        h.direct.add(("127.0.0.1", port))
        for authority in ("93.184.216.34:443", "api.example.com:443"):
            with h.client(f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode()) as sock:
                self.assertEqual(status(sock), 502)
            self.assertEqual(self.reason(h), "connect_refused")
        self.assertEqual(h.lookups, [])
        self.assertEqual(h.calls, [("127.0.0.1", port)] * 2)
        self.nothing_accepted(h)

    def test_a_stop_during_the_handshake_closes_both_unanswered(self):
        h = self.harness()
        client, proxy = self.proxied(h)
        report = h.stop()
        self.assertFalse(read_all(client).startswith(b"HTTP/1.1 200"))
        self.assertEqual(read_all(proxy), b"")
        self.assertTrue(report["clean"], report)
        self.assertEqual(report["counters"]["tunnels_opened"], 0)
        self.assertEqual(h.of("broker.request")[-1]["attributes"]["reason"], "broker_stopping")


class Manual:
    """One broker stepped by the test thread itself, never swept (`tick`
    is not called, so each refusal below is the consuming step's own): a
    fake clock, lookups answered only once released, a server stop flag
    (main.py `stop_seen`) and a dial hook run just before each connect."""

    def __init__(self, names=None, post=None, on_record=None):
        self.now = 1000.0
        self.loop = main.Loop()
        self.stop = False
        self.events = []
        self.on_record = on_record
        self.names = names or {"api.example.com.": ["93.184.216.34"]}
        self.released = threading.Event()
        self.lookups = []
        self.dials = []
        self.on_dial = None
        self.report = None
        self.recording = True
        self.failures = 0
        self.upstream = socket.create_server(("127.0.0.1", 0))
        self.upstream.settimeout(0.2)
        refused = socket.create_server(("127.0.0.1", 0))
        self.closed_port = refused.getsockname()[1]
        refused.close()
        self.broker = broker.Broker(
            self.loop, policy.Policy.parse(json.dumps(POLICY).encode()),
            broker.Limits(head_timeout=1.0, dns_timeout=1.0, connect_timeout=1.0),
            post, support.relay(), self.record, self.failed, lambda: self.now,
            lookup=self.lookup, dial_map=self.dial, stopped=lambda: self.stop)
        self.address = self.broker.start(self.now + WAIT, lambda: False)

    def record(self, event, deadline):
        if not self.recording:
            return False
        self.events.append(event)
        if self.on_record is not None:
            self.on_record(self, event)
        return True

    def failed(self):
        self.failures += 1

    def lookup(self, query):
        self.lookups.append(query)
        self.released.wait(WAIT)
        return [ipaddress.ip_address(answer) for answer in self.names[query]]

    def dial(self, target):
        self.dials.append(str(target[0]))
        if self.on_dial is not None:
            return self.on_dial(self, target)
        return ipaddress.ip_address("127.0.0.1"), self.upstream.getsockname()[1]

    def step_until(self, condition):
        end = time.monotonic() + WAIT
        while not condition() and time.monotonic() < end:
            self.loop.step(0.01)
        return condition()

    def conn(self):
        return next(iter(self.broker.conns.values()), None)

    def answer(self, client):
        """What the client got: stepped until its answer and end are sent,
        then the client closed (ending a refusal's linger) and stepped
        until the request's record."""
        def readable():
            return bool(select.select([client], [], [], 0)[0])
        self.step_until(readable)
        got = answer(client)
        before = len(self.requests())
        client.close()
        self.step_until(lambda: len(self.requests()) > before)
        return got

    def requests(self):
        return [(e["attributes"]["decision"], e["attributes"]["reason"]) for e in self.events
                if e["event"] == "broker.request"]

    def close(self, release=True):
        """The broker's stop (once): its report. Lookups are released
        first, or (`release` false) only after it."""
        if self.report is None:
            if release:
                self.released.set()

            def pump(timeout):
                self.loop.step(0)
                self.now += 0.05
            self.report = self.broker.stop_until(self.now + 5.0, pump)
            self.released.set()
            self.upstream.close()
        return self.report


def answer(sock):
    """Everything the client got, until its end."""
    sock.settimeout(WAIT)
    return read_all(sock)


class Boundaries(unittest.TestCase):
    """A stop or a deadline seen where a result is taken: no admission,
    dial or commit after it, and no second answer to the client."""

    def manual(self, **kwargs):
        m = Manual(**kwargs)
        self.addCleanup(m.close)
        return m

    def assertNoUpstream(self, m):
        with self.assertRaises(TimeoutError):
            m.upstream.accept()

    def test_a_stop_seen_while_the_decision_is_recorded_prevents_the_commit(self):
        # The server learns of its end (input EOF, a signal) during the
        # required write of the `tunnel` record: the commit must refuse.
        def on_record(m, event):
            if event["event"] == "broker.request":
                m.stop = True
        m = self.manual(on_record=on_record)
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(m.step_until(lambda: m.broker.counters["tunnels_closed"] == 1))
            self.assertEqual(answer(client), b"")
        self.assertEqual(m.requests(), [("tunnel", "allowed")])
        closed = [e["attributes"]["reason"] for e in m.events if e["event"] == "broker.tunnel_closed"]
        self.assertEqual(closed, ["broker_stopped"])
        self.assertEqual(m.broker.counters["tunnels_opened"], 0)
        self.assertEqual(m.broker.tunnels, {})
        # The upstream was dialed, then closed unused.
        upstream, _ = m.upstream.accept()
        with upstream:
            upstream.settimeout(WAIT)
            self.assertEqual(read_all(upstream), b"")
        self.assertTrue(m.close()["clean"])

    def test_a_stop_seen_before_a_connect_completes_refuses_once(self):
        def on_dial(m, target):
            m.stop = True
            return ipaddress.ip_address("127.0.0.1"), m.upstream.getsockname()[1]
        m = self.manual()
        m.on_dial = on_dial
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n")
            got = m.answer(client)
        self.assertEqual(got.count(b"HTTP/1.1 "), 1)
        self.assertTrue(got.startswith(b"HTTP/1.1 503 "), got)
        self.assertEqual(m.requests(), [("refused", "broker_stopping")])
        self.assertEqual(m.broker.tunnels, {})
        self.assertTrue(m.close()["clean"])

    def test_a_stop_seen_before_answers_are_taken_dials_nothing(self):
        m = self.manual()
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(m.step_until(lambda: m.lookups))
            m.stop = True
            m.released.set()
            self.assertTrue(m.answer(client).startswith(b"HTTP/1.1 503 "))
        self.assertEqual(m.requests(), [("refused", "broker_stopping")])
        self.assertEqual(m.dials, [])
        self.assertNoUpstream(m)
        self.assertTrue(m.close()["clean"])

    def test_a_stop_refuses_new_clients_and_posts_before_any_work(self):
        post = ingress.Ingress(1000.0, None)
        post.arm(NONCE)
        m = self.manual(post=post)
        m.stop = True
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n")
            # Guarded (a POST ingress): after a stop, no status at all.
            self.assertEqual(m.answer(client), b"")
        body = b"{}"
        head = ("POST /agentbox/v1/request HTTP/1.1\r\nHost: agentbox\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        m.stop = False
        with socket.create_connection(m.address, timeout=WAIT) as client:
            # Accepted before the stop, its head read after it.
            self.assertTrue(m.step_until(lambda: m.broker.conns))
            m.stop = True
            client.sendall(head + body)
            self.assertEqual(m.answer(client), b"")
        self.assertEqual(m.requests(), [("refused", "broker_stopping")] * 2)
        self.assertEqual((m.lookups, m.dials, post.permits, m.broker.counters["posts"]), ([], [], 0, 0))

    def test_answers_after_the_lookup_deadline_are_a_timeout(self):
        m = self.manual()
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(m.step_until(lambda: m.lookups))
            m.now += 1.5
            m.released.set()
            self.assertTrue(m.answer(client).startswith(b"HTTP/1.1 504 "))
        self.assertEqual(m.requests(), [("refused", "dns_timeout")])
        self.assertEqual(m.dials, [])
        self.assertNoUpstream(m)

    def test_a_queued_lookup_past_its_deadline_never_starts(self):
        m = self.manual()
        m.broker.resolver.max = 1
        first = socket.create_connection(m.address, timeout=WAIT)
        second = socket.create_connection(m.address, timeout=WAIT)
        with first, second:
            first.sendall(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(m.step_until(lambda: m.lookups))
            second.sendall(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(m.step_until(lambda: len(m.broker.waiting) == 1))
            m.now += 1.5
            m.released.set()
            self.assertTrue(m.answer(second).startswith(b"HTTP/1.1 503 "))
            self.assertTrue(m.answer(first).startswith(b"HTTP/1.1 504 "))
        self.assertEqual(sorted(m.requests()), [("refused", "dns_timeout"), ("refused", "resolver_busy")])
        self.assertEqual(len(m.lookups), 1)

    def test_a_connect_completing_after_its_deadline_is_never_used(self):
        # Immediate or ready, the success is taken after the bound.
        def on_dial(m, target):
            m.now += 1.5
            return ipaddress.ip_address("127.0.0.1"), m.upstream.getsockname()[1]
        m = self.manual()
        m.on_dial = on_dial
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n")
            got = m.answer(client)
        self.assertEqual(got.count(b"HTTP/1.1 "), 1)
        self.assertTrue(got.startswith(b"HTTP/1.1 504 "), got)
        self.assertEqual(m.requests(), [("refused", "connect_timeout")])
        self.assertEqual((m.broker.tunnels, m.broker.counters["tunnels_opened"]), ({}, 0))

    def test_no_next_candidate_after_the_dial_deadline(self):
        def on_dial(m, target):
            m.now += 1.5
            return ipaddress.ip_address("127.0.0.1"), m.closed_port
        m = self.manual(names={"api.example.com.": ["93.184.216.34", "93.184.216.35"]})
        m.on_dial = on_dial
        m.released.set()
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(m.answer(client).startswith(b"HTTP/1.1 504 "))
        self.assertEqual(m.requests(), [("refused", "connect_timeout")])
        self.assertEqual(m.dials, ["93.184.216.34"])
        self.assertNoUpstream(m)

    def test_a_stop_during_a_lookup_reports_it_outstanding(self):
        m = self.manual()
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(m.step_until(lambda: m.lookups))
            report = m.close(release=False)
            self.assertEqual(answer(client), b"")
        self.assertEqual((report["resolutions_outstanding"], report["clean"]), (1, False))
        self.assertEqual(m.dials, [])

    def test_a_stop_during_a_dial_closes_the_client_unanswered(self):
        def on_dial(m, target):
            # The broker's own stop arrives while it dials.
            m.broker.halt()
            return ipaddress.ip_address("127.0.0.1"), m.upstream.getsockname()[1]
        m = self.manual()
        m.on_dial = on_dial
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(m.step_until(lambda: m.dials))
            report = m.close()
            self.assertFalse(answer(client).startswith(b"HTTP/1.1 200"))
        self.assertTrue(report["clean"], report)
        self.assertEqual((m.broker.tunnels, report["counters"]["tunnels_opened"]), ({}, 0))
        self.assertEqual(m.requests(), [("refused", "broker_stopping")])

    def test_a_failed_record_fails_closed_once(self):
        m = self.manual()
        m.recording = False
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(m.step_until(lambda: m.failures))
            self.assertFalse(answer(client).startswith(b"HTTP/1.1 200"))
        with self.assertRaises(OSError):
            for _ in range(3):
                socket.create_connection(m.address, timeout=WAIT).close()
                m.loop.step(0.01)
        self.assertEqual((m.failures, m.broker.phase), (1, "failed:recorder_failed"))
        self.assertEqual((m.broker.tunnels, m.broker.counters["tunnels_opened"]), ({}, 0))

    def test_refused_and_unmapped_upstreams_never_become_tunnels(self):
        for mapped, code, status in ((True, "connect_refused", 502), (False, "connect_failed", 502)):
            m = self.manual()
            m.on_dial = (lambda m, target: (ipaddress.ip_address("127.0.0.1"), m.closed_port)) if mapped \
                else (lambda m, target: None)
            with socket.create_connection(m.address, timeout=WAIT) as client:
                client.sendall(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n")
                got = m.answer(client)
            self.assertTrue(got.startswith(f"HTTP/1.1 {status} ".encode()), got)
            self.assertEqual(m.requests(), [("refused", code)])
            self.assertEqual((m.broker.tunnels, m.broker.counters["tunnels_opened"]), ({}, 0))

    # POST cutoff and shutdown.

    def posting(self, cutoff=None):
        post = ingress.Ingress(1000.0, cutoff)
        post.arm(NONCE)
        return self.manual(post=post), post

    def post_head(self, body):
        return ("POST /agentbox/v1/request HTTP/1.1\r\nHost: agentbox\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()

    def submit(self, client="c-1"):
        return codec.encode_request({"type": "submit", "session": NONCE, "client": client, "handler": "npm",
                                     "operation": "install", "args": {}})

    def posts(self, m):
        return [e["attributes"]["reason"] for e in m.events if e["event"] == "broker.post"]

    def waiting(self, m, post):
        """A submit admitted and seen by the loop: (client, exchange)."""
        body = self.submit()
        client = socket.create_connection(m.address, timeout=WAIT)
        self.addCleanup(client.close)
        client.sendall(self.post_head(body) + body)
        events = []
        self.assertTrue(m.step_until(lambda: events.append(post.poll()) or any(events)))
        event = next(e for e in events if e)
        self.assertEqual(event[0], "request")
        return client, event[1]

    def test_post_work_leaves_the_connect_allowances(self):
        m, post = self.posting()
        client, _ = self.waiting(m, post)
        self.assertEqual((m.broker.pending, m.broker.threads, m.broker.posts, post.permits), (0, 0, 1, 1))

    def test_a_body_completed_only_past_the_cutoff_is_never_dispatched(self):
        m, post = self.posting(cutoff=1000.5)
        body = self.submit()
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(self.post_head(body) + body[:5])
            self.assertTrue(m.step_until(lambda: m.conn() is not None and m.conn().state == "post_body"))
            m.now = 1000.5
            client.sendall(body[5:])
            self.assertTrue(m.step_until(lambda: self.posts(m)))
            # Past the cutoff: no status either.
            self.assertEqual(answer(client), b"")
        self.assertIsNone(post.poll())
        self.assertEqual(self.posts(m), ["request_timeout"])

    def test_a_response_taken_after_its_bound_is_never_written(self):
        m, post = self.posting()
        client, exchange = self.waiting(m, post)
        self.assertIsNone(post.respond(exchange, {"type": "error", "code": "not_active"}))
        m.now += ingress.EXCHANGE_CEILING
        m.broker.tick()
        self.assertEqual(answer(client), b"")
        self.assertEqual(post.poll(), ("ended", exchange, "exchange_expired"))

    def test_a_stop_ends_waiting_and_writing_with_nothing_written(self):
        m, post = self.posting()
        client, exchange = self.waiting(m, post)
        self.assertIsNone(post.respond(exchange, {"type": "error", "code": "not_active"}))
        m.stop = True
        m.broker.tick()
        self.assertEqual(answer(client), b"")
        self.assertEqual(post.poll(), ("ended", exchange, "post_stopped"))
        self.assertEqual(self.posts(m), ["post_stopped"])

    def test_peer_loss_while_waiting_cancels_the_accepted_request(self):
        m, post = self.posting()
        client, exchange = self.waiting(m, post)
        _, latch = post.activate(exchange, 2000.0)
        client.close()
        self.assertTrue(m.step_until(lambda: self.posts(m)))
        self.assertTrue(latch.is_cancelled())
        self.assertEqual(post.poll(), ("ended", exchange, "peer_eof"))

    def test_a_written_response_is_whole_then_closed(self):
        m, post = self.posting()
        client, exchange = self.waiting(m, post)
        body = codec.encode_response({"type": "error", "code": "not_active"})
        self.assertIsNone(post.respond(exchange, {"type": "error", "code": "not_active"}))
        m.broker.tick()
        self.assertEqual(answer(client), request.post_response(409, body))
        self.assertEqual(post.poll(), ("ended", exchange, "written"))

    def test_a_stop_seen_during_the_spawn_commits_no_200(self):
        """The commit again after the child's spawn: a stop latched while it
        spawned leaves the client unstarted, its child reaped."""
        spawned = []

        class Latching(broker.Relay):
            @classmethod
            def spawn(cls, binary, client, upstream):
                relay = super().spawn(binary, client, upstream)
                spawned.append(relay)
                m.stop = True
                return relay
        m = self.manual()
        saved = broker.Relay
        broker.Relay = Latching
        self.addCleanup(setattr, broker, "Relay", saved)
        with socket.create_connection(m.address, timeout=WAIT) as client:
            client.sendall(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(m.step_until(lambda: m.broker.counters["tunnels_closed"] == 1))
            self.assertEqual(answer(client), b"")
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].popen.returncode, "reaped")
        self.assertEqual(spawned[0].control.fileno(), -1)
        closed = [e["attributes"]["reason"] for e in m.events if e["event"] == "broker.tunnel_closed"]
        self.assertEqual(closed, ["broker_stopped"])
        self.assertEqual((m.broker.tunnels, m.broker.counters["tunnels_opened"]), ({}, 0))
        self.assertTrue(m.close()["clean"])

    def test_the_server_stop_is_what_the_broker_reads(self):
        server = main.Server.__new__(main.Server)
        server.cause, server.signalled, server.output_failed, server.broker_failed = None, False, False, False
        server.cutoff = None
        self.assertFalse(server.stop_seen())
        server.signalled = True
        self.assertTrue(server.stop_seen())
        server.signalled, server.cause = False, "control_eof"
        self.assertTrue(server.stop_seen())
        server.cause, server.output_failed = None, True
        self.assertTrue(server.stop_seen())


# The real program.

def cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as stream:
            return stream.read()
    except OSError:
        return b""


def private_address():
    """This host's first private IPv4 address, not loopback or link-local,
    if any: an owned listener binds it, nothing else is contacted."""
    out = subprocess.run(["ip", "-j", "-4", "addr", "show"], capture_output=True, check=False).stdout
    for link in json.loads(out or b"[]"):
        for info in link.get("addr_info", []):
            ip = ipaddress.ip_address(info["local"])
            if ip.is_private and address.denied(ip) is None and not ip.is_link_local:
                return str(ip)
    return None


def empty_path(test):
    """A private empty directory: the program's whole PATH."""
    test.dir = tempfile.mkdtemp(prefix="abt-")
    test.addCleanup(shutil.rmtree, test.dir, True)
    return test.dir


class Program(unittest.TestCase):
    """`agentbox-server` as the controller runs it, over its pipes."""

    def setUp(self):
        empty_path(self)

    def spawn(self, policy_document, grants=None):
        program = support.server()
        proc = subprocess.Popen([program], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env={"PATH": self.dir})
        configure = {"type": "configure", "id": 1, "v": 1, "session": "s-1", "run_id": "r-" + NONCE,
                     "execution_id": "e-" + NONCE, "lifetime_ms": 600000, "policy": policy_document, "post": None}
        if grants is not None:
            configure["grants"] = grants
        body = json.dumps(configure).encode()
        proc.stdin.write(struct.pack(">I", len(body)) + body)
        proc.stdin.flush()
        while True:
            message = self.message(proc)
            if message["type"] == "ready":
                return proc, message["broker"]["port"]

    def message(self, proc):
        prefix = proc.stdout.read(4)
        self.assertEqual(len(prefix), 4)
        return json.loads(proc.stdout.read(struct.unpack(">I", prefix)[0]))

    def test_a_tunnel_through_the_program_and_its_child_outlives_no_killed_broker(self):
        # An owned host-local listener, granted by its literal and dialed
        # for real (the program has no dial map).
        local = "127.0.0.1"
        with socket.create_server((local, 0)) as upstream_listener:
            upstream_listener.settimeout(WAIT)
            port = upstream_listener.getsockname()[1]
            proc, broker_port = self.spawn(broker_model_only(), [f"{local}:{port}"])
            with proc:
                client = socket.create_connection(("127.0.0.1", broker_port), timeout=WAIT)
                client.sendall(f"CONNECT {local}:{port} HTTP/1.1\r\n\r\n".encode())
                self.assertEqual(exact(client, len(ESTABLISHED)), ESTABLISHED)
                upstream, _ = upstream_listener.accept()
                upstream.settimeout(WAIT)
                client.sendall(b"ping")
                self.assertEqual(exact(upstream, 4), b"ping")
                children = [int(pid) for pid in subprocess.run(["pgrep", "-P", str(proc.pid)],
                                                                capture_output=True).stdout.split()]
                relays = [pid for pid in children if b"agentbox-relay" in cmdline(pid)]
                self.assertEqual(len(relays), 1)
                child = relays[0]
                # Both peers stall, then the broker dies: its child follows.
                for sock in (client, upstream):
                    sock.setblocking(False)
                    try:
                        while True:
                            sock.send(b"x" * 65536)
                    except BlockingIOError:
                        pass
                pidfd = os.pidfd_open(child)
                proc.kill()
                proc.wait()
                started = time.monotonic()
                self.assertTrue(select.select([pidfd], [], [], 1.0)[0])
                self.assertLess(time.monotonic() - started, 1.0)
                os.close(pidfd)
                for sock in (client, upstream):
                    sock.setblocking(True)
                    sock.settimeout(WAIT)
                    read_all(sock)
                    sock.close()

    def test_open_reaches_an_owned_host_local_listener_but_never_unspecified(self):
        with socket.create_server(("127.0.0.1", 0)) as upstream_listener:
            upstream_listener.settimeout(WAIT)
            port = upstream_listener.getsockname()[1]
            proc, broker_port = self.spawn({"schema": "agentbox.network-policy.v1", "mode": "open"})
            with proc:
                for target in (f"0.0.0.0:{port}", f"[::]:{port}", f"[::ffff:0.0.0.0]:{port}"):
                    with socket.create_connection(("127.0.0.1", broker_port), timeout=WAIT) as client:
                        client.sendall(f"CONNECT {target} HTTP/1.1\r\n\r\n".encode())
                        self.assertEqual(status(client), 403, target)
                upstream_listener.settimeout(0.2)
                with self.assertRaises(TimeoutError):
                    upstream_listener.accept()
                upstream_listener.settimeout(WAIT)
                with socket.create_connection(("127.0.0.1", broker_port), timeout=WAIT) as client:
                    client.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
                    self.assertEqual(exact(client, len(ESTABLISHED)), ESTABLISHED)
                    upstream, _ = upstream_listener.accept()
                    with upstream:
                        upstream.settimeout(WAIT)
                        client.sendall(b"ping")
                        self.assertEqual(exact(upstream, 4), b"ping")
                proc.stdin.close()
                self.assertEqual(proc.wait(10), 0)

    def test_a_policy_denial_and_a_clean_end_of_input(self):
        proc, broker_port = self.spawn(POLICY)
        with proc:
            with socket.create_connection(("127.0.0.1", broker_port), timeout=WAIT) as client:
                client.sendall(b"CONNECT 10.200.0.10:443 HTTP/1.1\r\n\r\n")
                self.assertEqual(status(client), 403)
            proc.stdin.close()
            while True:
                message = self.message(proc)
                if message["type"] == "stopped":
                    break
            self.assertEqual((message["reason"], message["clean"]), ("control_eof", True))
            self.assertEqual(proc.wait(10), 0)


@unittest.skipUnless(os.environ.get("AGENTBOX_BROKER_CAPACITY") == "1",
                     "opt-in measurement: AGENTBOX_BROKER_CAPACITY=1 (systemd user manager, ~20 s)")
class Capacity(unittest.TestCase):
    """The real program at its default full capacity, alone in a transient
    systemd user scope (its own cgroup; removed when it exits): 16 relayed
    tunnels (12 streaming both ways, 4 with a stalled client: their relay
    children's backpressure), both POST permits (one exchange awaiting its
    response, one body pending), the 8 pending heads, and the refusals past
    each limit. Samples the scope's memory and tasks, then reads its
    `memory.peak` and `pids.peak`; prints them. Local only: every upstream
    is a listener on this host's private address. Lookups are not loaded
    (no resolver without outside traffic)."""

    TUNNELS, ACTIVE, PENDING = 16, 12, 8
    HOLD = 3.5
    RUN = 8.0
    CHUNK = 64 * 1024

    def setUp(self):
        self.bin = empty_path(self)
        self.local = private_address()
        if self.local is None or shutil.which("systemd-run") is None:
            self.skipTest("needs a private IPv4 address and systemd-run")
        self.halt = threading.Event()
        self.addCleanup(self.halt.set)
        self.moved = [0, 0]
        self.lock = threading.Lock()
        self.messages = []

    def count(self, at, n):
        with self.lock:
            self.moved[at] += n

    def pump(self, sock, at, read, write):
        """Streams to and from `sock` until the halt; `write` without
        `read` stalls on its peer, as a client that stopped reading."""
        sock.setblocking(False)
        data = b"x" * self.CHUNK
        while not self.halt.is_set():
            readable, writable, _ = select.select([sock] if read else [], [sock] if write else [], [], 0.05)
            try:
                if readable:
                    got = sock.recv(self.CHUNK)
                    if not got:
                        return
                    self.count(at, len(got))
                if writable:
                    sock.send(data)
            except (BlockingIOError, InterruptedError):
                pass
            except OSError:
                return

    def serve(self, listener):
        """Each upstream streams down and reads until the halt."""
        listener.settimeout(0.1)
        while not self.halt.is_set():
            try:
                sock, _ = listener.accept()
            except TimeoutError:
                continue
            self.addCleanup(sock.close)
            threading.Thread(target=self.pump, args=(sock, 0, True, True), daemon=True).start()

    def read_messages(self, proc):
        while True:
            prefix = proc.stdout.read(4)
            if len(prefix) < 4:
                return
            body = proc.stdout.read(struct.unpack(">I", prefix)[0])
            with self.lock:
                self.messages.append(json.loads(body))

    def kinds(self, kind):
        with self.lock:
            return [m for m in self.messages if m.get("type") == kind or m.get("event") == kind]

    def wait(self, condition, limit=WAIT):
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if condition():
                return True
            time.sleep(0.01)
        return condition()

    def connect(self, port, head=b""):
        sock = socket.create_connection(("127.0.0.1", port), timeout=WAIT)
        self.addCleanup(sock.close)
        if head:
            sock.sendall(head)
        return sock

    def test_full_capacity_peak_memory_and_tasks(self):
        unit = f"abcap-{os.urandom(4).hex()}"
        listener = socket.create_server((self.local, 0), backlog=64)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        threading.Thread(target=self.serve, args=(listener,), daemon=True).start()
        env = {"PATH": f"{self.bin}:/usr/bin:/bin"}
        for name in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
            if name in os.environ:
                env[name] = os.environ[name]
        proc = subprocess.Popen(["systemd-run", "--user", "--scope", "--quiet", f"--unit={unit}", "--",
                                 support.server()], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env)
        self.addCleanup(proc.stdout.close)
        self.addCleanup(proc.wait, 10)
        self.addCleanup(proc.kill)
        policy_document = {"schema": "agentbox.network-policy.v1", "mode": "custom", "replace_model_only": True,
                           "destinations": [{"address": self.local, "ports": [port]}]}
        configure = {"type": "configure", "id": 1, "v": 1, "session": "s-1", "run_id": "r-" + NONCE,
                     "execution_id": "e-" + NONCE, "lifetime_ms": 600000, "policy": policy_document,
                     "post": {"nonce": NONCE, "delivery": None}}
        body = json.dumps(configure).encode()
        proc.stdin.write(struct.pack(">I", len(body)) + body)
        proc.stdin.flush()
        threading.Thread(target=self.read_messages, args=(proc,), daemon=True).start()
        self.assertTrue(self.wait(lambda: self.kinds("ready")))
        broker_port = self.kinds("ready")[0]["broker"]["port"]
        # The program's own cgroup: the scope.
        with open(f"/proc/{proc.pid}/cgroup") as stream:
            cgroup = "/sys/fs/cgroup" + stream.read().strip().split("::", 1)[1]
        self.assertTrue(cgroup.endswith(f"/{unit}.scope"), cgroup)

        def read(name):
            with open(f"{cgroup}/{name}") as stream:
                return stream.read()
        baseline = {"memory": int(read("memory.current")), "tasks": int(read("pids.current"))}
        began = time.monotonic()
        connect_head = f"CONNECT {self.local}:{port} HTTP/1.1\r\n\r\n".encode()
        clients = []
        for at in range(self.TUNNELS):
            sock = self.connect(broker_port, connect_head)
            self.assertEqual(exact(sock, len(ESTABLISHED)), ESTABLISHED, at)
            clients.append(sock)
        for at, sock in enumerate(clients):
            active = at < self.ACTIVE
            threading.Thread(target=self.pump, args=(sock, 1, active, active), daemon=True).start()
        with self.connect(broker_port, connect_head) as over:
            self.assertEqual(status(over), 503)
        submit = codec.encode_request({"type": "submit", "session": NONCE, "client": "c-1", "handler": "npm",
                                       "operation": "install", "args": {}})
        post_head = ("POST /agentbox/v1/request HTTP/1.1\r\nHost: agentbox\r\nContent-Type: application/json\r\n"
                     f"Content-Length: {len(submit)}\r\nConnection: close\r\n\r\n").encode()
        self.connect(broker_port, post_head + submit)
        self.assertTrue(self.wait(lambda: self.kinds("post.request")))
        self.connect(broker_port, post_head)
        time.sleep(0.2)
        with self.connect(broker_port, post_head) as over:
            self.assertEqual(status(over), 503)
        pending = [self.connect(broker_port) for _ in range(self.PENDING)]
        time.sleep(0.2)
        with self.connect(broker_port) as over:
            self.assertEqual(status(over), 503)
        full_at = time.monotonic() - began
        samples = []
        while time.monotonic() - began < self.RUN:
            samples.append((time.monotonic() - began, int(read("memory.current")), int(read("pids.current"))))
            time.sleep(0.1)
        stat = dict(line.split() for line in read("memory.stat").splitlines())
        peak = {"memory": int(read("memory.peak")), "tasks": int(read("pids.peak"))}
        with self.lock:
            moved = list(self.moved)
        held = [s for s in samples if s[0] <= full_at + self.HOLD]
        refusals = sorted(e["attributes"]["reason"] for e in self.kinds("broker.request")
                          if e["attributes"]["decision"] == "refused")
        self.halt.set()
        for sock in pending:
            sock.close()
        proc.stdin.close()
        self.assertTrue(self.wait(lambda: self.kinds("stopped"), 10))
        stopped = self.kinds("stopped")[0]
        self.assertEqual(proc.wait(10), 0)
        gone = self.wait(lambda: not os.path.exists(cgroup), 5)
        report = {
            "unit": unit, "baseline": baseline, "peak": peak,
            "full_capacity_after_s": round(full_at, 2),
            "during_hold": {"memory_max": max(s[1] for s in held), "tasks_max": max(s[2] for s in held)},
            "stat_at_end": {key: int(stat[key]) for key in ("anon", "file", "kernel", "sock") if key in stat},
            "bytes_upstream_read": moved[0], "bytes_client_read": moved[1],
            "refusals": refusals, "stopped": {key: stopped[key] for key in ("reason", "clean")},
            "broker_stopped": stopped["broker"], "scope_removed": gone}
        print("\nCAPACITY " + json.dumps(report), file=sys.stderr)
        self.assertIn("tunnel_limit", refusals)
        self.assertIn("pending_limit", refusals)
        self.assertTrue(stopped["clean"], stopped)
        self.assertTrue(gone)
        self.assertGreater(moved[0], 0)
        self.assertGreater(moved[1], 0)


if __name__ == "__main__":
    unittest.main()
