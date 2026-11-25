"""Test-only jail client (`python3 jail_poster.py SCENARIO`, run as the
guest command; never packaged): raw artifact POSTs to the session's
emulated forward (HOME/.agentbox-test-forward), canonical bodies, one JSON
line per response on stdout.

  limit N HANDLER     N submits of HANDLER, each answered before the next
  replay              the same client twice
  busy                a sleeping fake request, a second submit, a cancel
  peer_eof            a sleeping fake request, its write side shut at once
  binding             echo say, then a result of the wrong digest
  early_result        a result before any ready
  sleep               one sleeping fake request, waiting for its answer
"""
import json
import os
import socket
import sys
import time

SESSION = os.environ["AGENTBOX_REQUEST_SESSION"]
WORK = os.environ["AGENTBOX_WORK_ROOT"]
with open(os.path.join(os.environ["HOME"], ".agentbox-test-forward")) as stream:
    PORT = int(stream.read())


def body(kind, client, **fields):
    value = {"v": 1, "type": kind, "session": SESSION, "client": client}
    value.update(fields)
    if "args" in value:
        value["args"] = json.loads(json.dumps(value["args"], sort_keys=True))
    return json.dumps(value, separators=(",", ":")).encode()


def head(data):
    return (b"POST /agentbox/v1/request HTTP/1.1\r\nHost: agentbox\r\nContent-Type: application/json\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(data)) + data


def send(data):
    sock = socket.create_connection(("127.0.0.1", PORT))
    sock.sendall(head(data))
    return sock


def answer(sock):
    received = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        received += chunk
    sock.close()
    top, _, rest = received.partition(b"\r\n\r\n")
    status = top.split(b" ")[1].decode() if top else "none"
    try:
        value = json.loads(rest) if rest else {}
    except ValueError:
        value = {}
    return {"status": status, **value}


def post(data):
    return answer(send(data))


def say(value):
    print(json.dumps(value), flush=True)


def submit(client, handler, operation, args):
    return body("submit", client, handler=handler, operation=operation, args=args)


def main(argv):
    os.makedirs(os.path.join(WORK, ".agentbox-requests"), 0o700, exist_ok=True)
    scenario = argv[0]
    if scenario == "limit":
        count, handler = int(argv[1]), argv[2]
        tally = {}
        for index in range(count):
            reply = post(submit(f"c{index}", handler, "say", {}))
            key = reply.get("type", "none") + ":" + str(reply.get("reason") or reply.get("code") or "")
            tally[key] = tally.get(key, 0) + 1
        say(tally)
    elif scenario == "replay":
        say(post(submit("same", "echo", "say", {"text": "a"})))
        say(post(submit("same", "echo", "say", {"text": "a"})))
    elif scenario == "busy":
        first = send(submit("long", "fake", "fetch", {"mode": "sleep"}))
        time.sleep(1.0)
        say(post(submit("other", "echo", "say", {"text": "b"})))
        # The answered exchange's control slot frees once its worker ends.
        time.sleep(0.5)
        say(post(body("cancel", "long")))
        say(answer(first))
    elif scenario == "peer_eof":
        first = send(submit("gone", "fake", "fetch", {"mode": "sleep"}))
        time.sleep(1.0)
        first.shutdown(socket.SHUT_WR)
        say(answer(first))
        time.sleep(1.0)
    elif scenario == "binding":
        ready = post(submit("bind", "echo", "say", {"text": "c"}))
        say(ready)
        wrong = body("result", "bind", request=ready["request"], request_sha256=ready["request_sha256"],
                     sha256="0" * 64, status="applied")
        say(post(wrong))
    elif scenario == "early_result":
        say(post(body("result", "early", request="req-1", request_sha256="0" * 64, sha256="0" * 64,
                      status="applied")))
    elif scenario == "sleep":
        say(post(submit("sleeper", "fake", "fetch", {"mode": "sleep"})))
    else:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
