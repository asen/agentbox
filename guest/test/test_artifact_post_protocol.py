"""The guest POST codec and response reader against acquisitions/contracts/artifacts/post-v1."""

import json
import os
import re
import unittest

from guest.src import artifact_post_protocol as post
from guest.src.protocol import ERROR_CODES, Refused

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONTRACTS = os.path.join(REPO, "acquisitions", "contracts", "artifacts", "post-v1")

with open(os.path.join(CONTRACTS, "fixtures.json"), encoding="utf-8") as _stream:
    FIXTURES = json.load(_stream)
with open(os.path.join(CONTRACTS, "contract.json"), encoding="utf-8") as _stream:
    CONTRACT = json.load(_stream)


def body(fixture):
    if "body" in fixture:
        return fixture["body"].encode("utf-8", "surrogatepass")
    if "body_hex" in fixture:
        return bytes.fromhex(fixture["body_hex"])
    return "".join(part if isinstance(part, str) else part["repeat"] * part["count"]
                   for part in fixture.get("body_parts", [])).encode()


def code_of(call, *args):
    try:
        call(*args)
    except Refused as error:
        return error.code
    return None


def read(chunks, split):
    reader = post.ResponseReader()
    parts = []
    for chunk in chunks:
        data = chunk.encode("utf-8")
        parts += [data[at:at + split] for at in range(0, len(data), split)]
    for part in parts:
        state = reader.push(part)
        if state["state"] != "pending":
            return state
    return reader.end()


def push_all(reader, parts):
    state = post.PENDING
    for part in parts:
        state = reader.push(part)
        if state["state"] != "pending":
            break
    return state


OK_FIXTURE = FIXTURES["http_responses"]["valid"][0]
OK_BYTES = "".join(OK_FIXTURE["chunks"]).encode()
OK_BODY = OK_FIXTURE["body"].encode()


def declaring(length):
    return ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
            % length).encode()


class Codec(unittest.TestCase):
    def refused(self, reader, state, code):
        """Refused with `code`, holding nothing, and unchanged by anything later."""
        self.assertEqual(state, {"state": "failed", "code": code})
        self.assertEqual(reader.retained, 0)
        self.assertEqual(reader.push(b"x"), state)
        self.assertEqual(reader.push(bytes(1 << 20)), state)
        self.assertEqual(reader.end(), state)
        self.assertEqual(reader.retained, 0)

    def test_constants_match_the_contract(self):
        http, contract_body = CONTRACT["http"], CONTRACT["body"]
        self.assertEqual(CONTRACT["version"], post.CONTRACT_VERSION)
        self.assertEqual(http["method"], post.METHOD)
        self.assertEqual(http["path"], post.PATH)
        self.assertEqual(http["host"], post.HOST)
        self.assertEqual(http["content_type"], post.CONTENT_TYPE)
        self.assertEqual(http["max_body_bytes"], post.MAX_BODY_BYTES)
        self.assertEqual(http["max_response_head_bytes"], post.MAX_RESPONSE_HEAD_BYTES)
        self.assertEqual(http["response_statuses"], {str(key): value for key, value in post.RESPONSE_STATUSES.items()})
        self.assertEqual(contract_body["max_bytes"], post.MAX_BODY_BYTES)
        self.assertEqual(contract_body["max_depth"], post.MAX_DEPTH)
        self.assertEqual(contract_body["session_hex_digits"], post.SESSION_HEX_DIGITS)
        self.assertEqual(contract_body["max_ready_overhead_bytes"], post.MAX_READY_OVERHEAD_BYTES)
        self.assertEqual(contract_body["request_types"], list(post.REQUEST_TYPES))
        self.assertEqual(contract_body["response_types"], list(post.RESPONSE_TYPES))
        self.assertEqual(contract_body["closed"]["outcomes"], list(post.CLOSED_OUTCOMES))
        self.assertEqual(contract_body["rejected"]["codes"], list(post.REJECTED_CODES))
        self.assertEqual(contract_body["result"]["statuses"], list(post.RESULT_STATUSES))
        for code in contract_body["closed"]["lane_reasons"]:
            self.assertTrue(post.is_code(code), code)
        for pattern, valid in (("handler_pattern", post.is_word), ("operation_pattern", post.is_word),
                               ("key_pattern", post.is_key), ("code_pattern", post.is_code)):
            expected = re.compile(contract_body[pattern])
            for text in ("a", "a-b", "a_b", "A", "1a", "a.b", "a/b", "", "x" * 33, "x" * 65, "x" * 129, "a\n"):
                self.assertEqual(valid(text), expected.fullmatch(text) is not None, "%s %r" % (pattern, text))
        self.assertEqual(list(contract_body["error"]["lane_codes"]), list(post.LANE_CODES))
        self.assertEqual(CONTRACT["response_reader_codes"], list(post.READER_CODES))
        for code in post.LANE_CODES:
            self.assertEqual(post.response_status({"v": 1, "type": "error", "code": code}),
                             contract_body["error"]["lane_codes"][code])
        self.assertEqual(post.response_status({"v": 1, "type": "error", "code": "invalid_json"}),
                         contract_body["error"]["codec_status"])

    def test_valid_requests_decode_reencode_exactly_and_keep_their_handler_digests(self):
        for fixture in FIXTURES["requests"]["valid"]:
            data = body(fixture)
            request = post.decode_request(data)
            self.assertEqual(post.encode_request(request), data, fixture["name"])
            if request["type"] == "submit":
                submission = {key: request[key] for key in ("handler", "operation", "args")}
                self.assertEqual(post.request_sha256(request["client"], submission), fixture["request_sha256"])
            else:
                self.assertNotIn("request_sha256", fixture)
            self.assertEqual(code_of(post.decode_response, data), "wrong_direction")

    def test_invalid_requests_are_refused_with_their_codes(self):
        for fixture in FIXTURES["requests"]["invalid"]:
            self.assertIn(fixture["code"], ERROR_CODES)
            self.assertEqual(code_of(post.decode_request, body(fixture)), fixture["code"], fixture["name"])

    def test_valid_responses_decode_with_their_status(self):
        for fixture in FIXTURES["responses"]["valid"]:
            data = body(fixture)
            response = post.decode_response(data)
            self.assertEqual(post.encode_response(response), data, fixture["name"])
            self.assertEqual(post.response_status(response), fixture["status"], fixture["name"])
            self.assertEqual(code_of(post.decode_request, data), "wrong_direction")

    def test_invalid_responses_are_refused_with_their_codes(self):
        for fixture in FIXTURES["responses"]["invalid"]:
            self.assertEqual(code_of(post.decode_response, body(fixture)), fixture["code"], fixture["name"])

    def test_a_result_binds_the_delivered_request_and_artifact(self):
        session = FIXTURES["session"]
        submission = {"handler": "git", "operation": "clone",
                      "args": {"selector": "main", "repository": "octocat/hello-world"}}
        digest = post.request_sha256("c2", submission)
        ready = post.encode_response({
            "v": 1, "type": "ready", "session": session, "client": "c2", "request": "req-1",
            "request_sha256": digest, "handler": "git", "operation": "clone", "size": 7, "sha256": "2" * 64,
            "metadata": {"manifest_sha256": "1" * 64}})
        decoded = post.decode_response(ready)
        result = post.encode_request({
            "v": 1, "type": "result", "session": session, "client": "c2", "request": decoded["request"],
            "request_sha256": decoded["request_sha256"], "sha256": decoded["sha256"], "status": "applied"})
        self.assertEqual(post.decode_request(result), {
            "v": 1, "type": "result", "session": session, "client": "c2", "request": "req-1",
            "request_sha256": digest, "sha256": "2" * 64, "status": "applied"})

    def test_encoders_refuse_what_the_peer_would_refuse(self):
        session = "0" * 32
        self.assertEqual(code_of(post.encode_request, {"v": 1, "type": "cancel", "session": "S" * 32,
                                                       "client": "c1"}), "invalid_field")
        self.assertEqual(code_of(post.encode_request, {"v": 1, "type": "cancel", "session": session,
                                                       "client": "-c"}), "invalid_field")
        bound = {"v": 1, "session": session, "client": "c1", "request": "req-1", "request_sha256": "a" * 64}
        closed = dict(bound, type="closed", handler="git")
        self.assertEqual(code_of(post.encode_response, dict(closed, outcome="denied", reason="Nope")), "invalid_field")
        self.assertEqual(code_of(post.encode_response, dict(closed, outcome="cancelled", reason="nope")),
                         "invalid_field")
        self.assertIsNone(code_of(post.encode_response, dict(closed, outcome="denied", reason="git_repository_denied")))
        ready = dict(bound, type="ready", handler="echo", operation="say", size=1, sha256="a" * 64)
        self.assertEqual(code_of(post.encode_response, dict(ready, metadata={"bad key": 1})), "invalid_field")
        self.assertIsNotNone(code_of(post.encode_response, dict(ready, metadata={"n": -1})))
        self.assertEqual(code_of(post.encode_response, dict(ready, size=0, metadata={})), "invalid_field")
        self.assertIsNotNone(code_of(post.encode_response, dict(ready, metadata={"text": "x" * post.MAX_BODY_BYTES})))
        # Metadata keys travel sorted, whatever their order here.
        data = post.encode_response(dict(ready, metadata={"b": 1, "a": {"d": 2, "c": 3}}))
        self.assertTrue(data.endswith(b'"metadata":{"a":{"c":3,"d":2},"b":1}}'))
        self.assertEqual(code_of(post.encode_request, {"v": 1, "type": "submit", "session": session, "client": "c1",
                                                       "handler": "Echo", "operation": "say", "args": {}}),
                         "invalid_field")
        self.assertTrue(post.is_session("0123456789abcdef" * 2))
        for text in ("", "0" * 31, "0" * 33, "A" * 32, "s-1", "0" * 32 + "\n"):
            self.assertFalse(post.is_session(text), text)

    def test_the_request_head_is_the_exact_canonical_one(self):
        for length in (0, 1, 123, post.MAX_BODY_BYTES):
            data = b" " * length
            encoded = post.encode_http_request(data)
            head = FIXTURES["heads"]["canonical"].replace("{length}", str(length))
            self.assertEqual(encoded[:len(encoded) - length].decode("latin-1"), head)
            self.assertEqual(encoded[len(encoded) - length:], data)
        self.assertIsNone(post.encode_http_request(bytes(post.MAX_BODY_BYTES + 1)))


class Reader(unittest.TestCase):
    refused = Codec.refused

    def test_responses_are_read_to_the_servers_close_in_any_chunks(self):
        for fixture in FIXTURES["http_responses"]["valid"]:
            for split in (1, 7, 1 << 20):
                state = read(fixture["chunks"], split)
                self.assertEqual(state["state"], "complete", "%s %d" % (fixture["name"], split))
                self.assertEqual(state["status"], fixture["status"])
                self.assertEqual(state["body"].decode(), fixture["body"])
                post.decode_http_response(state["status"], state["body"])

    def test_malformed_oversized_truncated_and_trailing_responses_fail(self):
        for fixture in FIXTURES["http_responses"]["invalid"]:
            for split in (1, 1 << 20):
                state = read(fixture["chunks"], split)
                if state["state"] == "complete":
                    code = code_of(post.decode_http_response, state["status"], state["body"])
                    self.assertIsNotNone(code, fixture["name"])
                else:
                    self.assertEqual(state["state"], "failed", fixture["name"])
                    code = state["code"]
                self.assertEqual(code, fixture["code"], "%s %d" % (fixture["name"], split))
        # A failed reader stays failed.
        reader = post.ResponseReader()
        self.assertEqual(reader.end(), {"state": "failed", "code": "response_truncated"})
        self.assertEqual(reader.push(b"HTTP/1.1 200 OK\r\n"), {"state": "failed", "code": "response_truncated"})

    def test_the_hosts_exact_empty_503_is_a_refusal_of_its_own(self):
        head = post.REFUSAL_HEAD.encode()
        self.assertEqual(post.REFUSAL_HEAD,
                         "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        for split in (1, 7, 1 << 20):
            reader = post.ResponseReader()
            for at in range(0, len(head), split):
                self.assertEqual(reader.push(head[at:at + split]), {"state": "pending"})
            self.assertEqual(reader.retained, 0)
            self.assertEqual(reader.end(), {"state": "refused"})
            self.assertEqual(reader.push(b"x"), {"state": "refused"})
            self.assertEqual(reader.end(), {"state": "refused"})
        self.assertNotIn(503, post.RESPONSE_STATUSES)
        refusal = post.REFUSAL_HEAD
        cases = (
            (refusal + "x", "response_trailing"),
            (refusal.replace("503 Service Unavailable", "405 Method Not Allowed"), "response_malformed"),
            (refusal.replace("503 Service Unavailable", "400 Bad Request"), "response_malformed"),
            ("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "response_malformed"),
            ("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 00\r\n\r\n", "response_malformed"),
            ("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 0\r\n"
             "Connection: close\r\n\r\n", "response_malformed"),
            ("HTTP/1.1 503 service unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", "response_malformed"),
            ("﻿" + refusal, "response_malformed"),
            (refusal[:-1], "response_truncated"),
        )
        for text, code in cases:
            for split in (1, 1 << 20):
                self.assertEqual(read([text], split), {"state": "failed", "code": code}, repr(text))
        reader = post.ResponseReader()
        self.assertEqual(reader.push(head), {"state": "pending"})
        self.refused(reader, reader.push(b"H"), "response_trailing")

    def test_the_reader_bounds_what_it_holds_before_copying_a_chunk(self):
        huge = b"A" * (16 << 20)
        reader = post.ResponseReader()
        self.refused(reader, reader.push(huge), "response_malformed")
        reader = post.ResponseReader()
        self.assertEqual(reader.push(huge[:post.MAX_RESPONSE_HEAD_BYTES - 1]), {"state": "pending"})
        self.assertEqual(reader.push(huge[:1]), {"state": "pending"})
        self.assertEqual(reader.retained, post.MAX_RESPONSE_HEAD_BYTES)
        self.refused(reader, reader.push(huge[:1]), "response_malformed")
        reader = post.ResponseReader()
        self.assertEqual(reader.push(OK_BYTES), {"state": "pending"})
        self.assertEqual(reader.retained, len(OK_BODY))
        self.refused(reader, reader.push(huge), "response_trailing")
        reader = post.ResponseReader()
        self.refused(reader, reader.push(OK_BYTES + huge[:1 << 20]), "response_trailing")
        reader = post.ResponseReader()
        self.assertEqual(reader.push(declaring(10)), {"state": "pending"})
        self.assertEqual(reader.retained, 10)
        self.refused(reader, reader.push(huge[:11]), "response_trailing")
        reader = post.ResponseReader()
        self.assertEqual(push_all(reader, [declaring(10), huge[:5]]), {"state": "pending"})
        self.refused(reader, reader.push(huge[:6]), "response_trailing")
        reader = post.ResponseReader()
        whole = declaring(10) + huge[:10]
        self.assertEqual(push_all(reader, [whole[:-12], whole[-12:]]), {"state": "pending"})
        self.assertEqual(reader.end(), {"state": "complete", "status": 200, "body": huge[:10]})
        reader = post.ResponseReader()
        self.refused(reader, reader.push(declaring(post.MAX_BODY_BYTES + 1)), "response_too_large")
        reader = post.ResponseReader()
        self.assertEqual(reader.push(declaring(post.MAX_BODY_BYTES)), {"state": "pending"})
        self.assertEqual(reader.retained, post.MAX_BODY_BYTES)

    def test_a_bom_or_other_non_ascii_head_byte_is_refused(self):
        bom = b"\xef\xbb\xbf"
        for parts in ([bom + OK_BYTES], [bom[:1], bom[1:] + OK_BYTES], [bom[:2], bom[2:], OK_BYTES],
                      [OK_BYTES[:17], bom, OK_BYTES[17:]], [OK_BYTES[:17] + bom[:1], bom[1:] + OK_BYTES[17:]]):
            reader = post.ResponseReader()
            self.refused(reader, push_all(reader, parts), "response_malformed")
        reader = post.ResponseReader()
        self.refused(reader, reader.push(bom[:1]), "response_malformed")
        phrase = post.ResponseReader()
        self.refused(phrase, phrase.push(b"HTTP/1.1 200 O\x80" + OK_BYTES[15:]), "response_malformed")
        data = bom + OK_BODY
        framed = post.ResponseReader()
        self.assertEqual(framed.push(declaring(len(data)) + data), {"state": "pending"})
        state = framed.end()
        self.assertEqual(state["body"], data)
        self.assertEqual(code_of(post.decode_http_response, state["status"], state["body"]), "invalid_json")
        self.assertEqual(code_of(post.decode_response, data), "invalid_json")
        self.assertEqual(code_of(post.decode_request, bom + FIXTURES["requests"]["valid"][0]["body"].encode()),
                         "invalid_json")


if __name__ == "__main__":
    unittest.main()
