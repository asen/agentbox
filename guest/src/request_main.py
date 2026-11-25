"""The installed `agentbox-request` command (bin/agentbox-request, a host
wrapper).

    agentbox-request HANDLER OPERATION [ARGS_JSON]
    agentbox-request --help

One artifact request: HANDLER's OPERATION with a JSON object of arguments
(default `{}`), whatever handlers the execution enables. The generic client
(artifact_save_client.py) saves what the host delivers under the working
root and claims `applied` for that copy only: it knows no handler and
applies nothing. Handlers with their own semantics bring their own commands
(their manifests' shims: `git`, `npm`, ...; pip's session index). The task's
request context is read once from the reserved environment the helper
session set (artifact_post_context.py); without it nothing is sent. SIGINT,
SIGTERM or SIGHUP give the request up, which cannot undo bytes already
written. A request is never cut short by a forced exit: it is awaited to
its own end.

Nothing here routes or authorizes: the host refuses a handler or operation
the execution does not enable, under the handler's own policy otherwise.
"""

if __name__ == "__main__":
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
import os
import sys

from guest.src.abort import signalled
from guest.src.artifact_post_context import context_from_environment
from guest.src.artifact_post_protocol import is_word
from guest.src.artifact_save_client import run_save_client
from guest.src.counterpart import args_of, say
from guest.src.protocol import js_json
from guest.src.request_status import CLIENT_USAGE

USAGE = "usage: agentbox-request HANDLER OPERATION [ARGS_JSON]\n       agentbox-request --help\n"

HELP = USAGE + """
Asks the host for one artifact from HANDLER's OPERATION with ARGS_JSON, a JSON
object of that handler's arguments (default {}). The host's handler decides
under its own policy; a submission is not an approval, and a handler or
operation this execution does not enable is refused by the host. The
delivered artifact is saved under the working root as is; one line reports
its path, size, SHA-256 and the host worker's metadata, or the outcome and,
for a denial, the host's reason. Nothing is installed or applied: a
handler's own commands (git, npm, ...) and pip's index do that.
"""


def main(argv):
    if argv == ["--help"]:
        sys.stdout.write(HELP)
        return 0
    if len(argv) < 2 or len(argv) > 3 or not is_word(argv[0]) or not is_word(argv[1]):
        sys.stderr.write(USAGE)
        return CLIENT_USAGE
    handler, operation = argv[0], argv[1]
    parsed = args_of(argv[2] if len(argv) == 3 else "{}")
    if parsed is None:
        sys.stderr.write("agentbox-request: ARGS_JSON must be one JSON object of at most 60 KiB\n")
        return CLIENT_USAGE
    context = context_from_environment(os.environ)

    async def generic():
        abort, done = signalled(asyncio.get_running_loop())
        try:
            return await run_save_client({"handler": handler, "operation": operation, "args": parsed}, context,
                                         lambda report: say("agentbox-request: %s %s" % (handler, js_json(report))),
                                         abort)
        finally:
            done()

    return asyncio.run(generic())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
