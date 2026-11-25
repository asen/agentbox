"""Test-only handler `echo`: never packaged. Proves a handler registers by
manifest, policy and configuration alone, with no Rust or guest rebuild.

    say     {"text": STR}   the artifact is the policy's prefix + STR (UTF-8);
                            the metadata echoes the operation and length
    refuse  {}              the policy's `code`, as a handler denial
    crash   {}              no result line (a malformed worker result)

Policy: {"schema":"agentbox.echo.policy.v1","prefix":STR,"code":CODE}.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "lib"))

import agentbox_handler as handler  # noqa: E402
from agentbox_handler import ARTIFACT_FILE, Refused  # noqa: E402

POLICY_SCHEMA = "agentbox.echo.policy.v1"


def policy(request):
    value = request.policy
    if not handler.exact(value, {"schema", "prefix", "code"}) \
            or value["schema"] != POLICY_SCHEMA or not isinstance(value["prefix"], str) \
            or not isinstance(value["code"], str) or not handler.CODE.fullmatch(value["code"]):
        raise Refused("echo_policy_invalid")
    return value


def say(request):
    prefix = policy(request)["prefix"]
    args = request.args
    if not handler.exact(args, {"text"}) or not isinstance(args["text"], str):
        raise Refused("echo_args_invalid")
    data = (prefix + args["text"]).encode()
    if not data:
        raise Refused("echo_empty")
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
    return size, sha256, {"operation": request.operation, "length": size}


def refuse(request):
    raise Refused(policy(request)["code"])


def crash(request):
    policy(request)
    os._exit(7)


if __name__ == "__main__":
    sys.exit(handler.main({"say": say, "refuse": refuse, "crash": crash}))
