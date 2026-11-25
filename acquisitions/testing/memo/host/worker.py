"""Test-only handler `memo`: never packaged. Proves a handler with a jail
counterpart registers without a Rust or core guest rebuild: this worker and
manifest in the asset tree, its ready JavaScript counterpart
(../../counterparts/memo.js) added to the worker bundle at image build
(`worker.py build --counterparts`), and the operator's configuration.

    note  {"name": NAME, "text": STR}   the artifact is the policy's
                                        header line + STR (UTF-8); the
                                        metadata names the note and length

Policy: {"schema":"agentbox.memo.policy.v1","header":STR,"names":[NAME..]};
a name the policy does not list is the denial `memo_name_denied`.
"""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "lib"))

import agentbox_handler as handler  # noqa: E402
from agentbox_handler import ARTIFACT_FILE, Refused  # noqa: E402

POLICY_SCHEMA = "agentbox.memo.policy.v1"
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")


def policy(request):
    value = request.policy
    if not handler.exact(value, {"schema", "header", "names"}) \
            or value["schema"] != POLICY_SCHEMA or not isinstance(value["header"], str) \
            or not isinstance(value["names"], list) \
            or not all(isinstance(n, str) and NAME.fullmatch(n) for n in value["names"]):
        raise Refused("memo_policy_invalid")
    return value


def note(request):
    rules = policy(request)
    args = request.args
    if not handler.exact(args, {"name", "text"}) or not isinstance(args["name"], str) \
            or not NAME.fullmatch(args["name"]) or not isinstance(args["text"], str):
        raise Refused("memo_args_invalid")
    if args["name"] not in rules["names"]:
        raise Refused("memo_name_denied")
    data = (rules["header"] + "\n" + args["text"]).encode()
    stage = handler.open_stage(request)
    try:
        fd = handler.create(stage, ARTIFACT_FILE)
        try:
            sink = handler.Sink(fd)
            sink.write(data)
            size, sha256 = sink.finish()
        finally:
            os.close(fd)
    finally:
        os.close(stage)
    return size, sha256, {"name": args["name"], "length": size}


if __name__ == "__main__":
    sys.exit(handler.main({"note": note}))
