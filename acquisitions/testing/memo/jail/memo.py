"""Test-only jail counterpart of the `memo` handler (../host/worker.py),
source-only. `worker.py build --counterparts DIR` adds it to the worker
bundle as acquisitions/memo/jail/memo.py (its manifest's `jail.entry`); it
imports only the bundle's own modules and the standard library.

  memo NAME TEXT       (its shim: the note `{"name":NAME,"text":STR}`)

The delivered note is saved by the generic client, then applied: linked to
WORK/memos/NAME, never over an existing one. One JSON line reports it."""

if __name__ == "__main__":
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import asyncio
import os
import re
import shutil
import sys

from guest.src.abort import signalled
from guest.src.artifact_post_context import context_from_environment
from guest.src.artifact_save_client import run_save_client
from guest.src.counterpart import RequestInput, say, serve
from guest.src.protocol import js_json

NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")


async def request(given):
    def report(fields):
        given.print("memo: " + js_json(fields))

    args = given.args
    if (given.operation != "note" or sorted(args) != ["name", "text"] or not isinstance(args["name"], str)
            or NAME.fullmatch(args["name"]) is None or not isinstance(args["text"], str)):
        report({"ok": False, "code": "memo_client_invalid"})
        return 2
    saved = []
    status = await run_save_client({"handler": "memo", "operation": given.operation, "args": args}, given.context,
                                   saved.append, given.abort)
    if not saved or saved[0].get("ok") is not True or given.context is None:
        report(saved[0] if saved else {"ok": False, "code": "memo_client_failed"})
        return 1 if status == 0 else status
    note = saved[0]
    memos = os.path.join(given.context.work_root, "memos")
    target = os.path.join(memos, args["name"])
    try:
        os.makedirs(memos, 0o700, exist_ok=True)
        os.link(note["path"], target)
    except OSError:
        report({"ok": False, "code": "memo_apply_failed", "cleanup": note["cleanup"]})
        return 1
    shutil.rmtree(os.path.dirname(note["path"]), ignore_errors=True)
    report({"ok": True, "memo": target, "sha256": note["sha256"], "metadata": note["metadata"],
            "cleanup": note["cleanup"]})
    return 0


async def memo(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: memo NAME TEXT\n")
        return 2
    abort, done = signalled(asyncio.get_running_loop())
    try:
        return await request(RequestInput("note", {"name": argv[0], "text": argv[1]},
                                          context_from_environment(os.environ), abort, say))
    finally:
        done()


if __name__ == "__main__":
    sys.exit(serve(sys.argv[1:], {"memo": memo}))
