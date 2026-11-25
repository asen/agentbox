"""Test-only `npm` host worker (never packaged): the real handler's
`metadata` contract with no network; the artifact is fixed bytes,
whatever the policy's registry says. Only the lane is exercised: the
stand-in jail npm (npm_standin.py) asks once and checks nothing more."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "lib"))

import agentbox_handler as handler  # noqa: E402
from agentbox_handler import ARTIFACT_FILE, Refused  # noqa: E402


def metadata(request):
    args = request.args
    if not handler.exact(args, {"names", "format"}) or not isinstance(args["names"], list):
        raise Refused("npm_args_invalid")
    data = json.dumps({"names": args["names"], "registry": request.policy.get("registry")}).encode()
    request.meter.take(request.meter.room(len(data)))
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
    return size, sha256, {"format": "agentbox.npm.batch.v1", "items": len(args["names"])}


if __name__ == "__main__":
    sys.exit(handler.main({"metadata": metadata}))
