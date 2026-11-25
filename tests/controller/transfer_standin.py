"""Stand-in `scp` and `sftp` for controller tests (named by argv[0]), run
from a private copy beside `ssh.json`: the fixed profile checked, the argv
logged (transfer.log), then the copy made locally.

  scp   ... -- SOURCE HOST:DEST      SOURCE (a /dev/fd/N included) -> DEST
  sftp  ... -- HOST, batch on stdin  each `@put SRC DST` -> DST

`ssh.json` `fail`: "scp" | "sftp" (exit 1, nothing copied); `scp_sleep`:
seconds an scp waits first.
"""
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main(program, args):
    with open(os.path.join(HERE, "ssh.json")) as stream:
        conf = json.load(stream)
    entry = {"program": program, "argv": args}
    options = [args[i + 1] for i, word in enumerate(args) if word == "-o"]
    ok = "BatchMode=yes" in options and "ClearAllForwardings=yes" in options \
        and any(o.startswith("UserKnownHostsFile=") for o in options) and "--" in args
    entry["profile_ok"] = ok
    tail = args[args.index("--") + 1:] if "--" in args else []
    if program == "sftp":
        entry["batch"] = sys.stdin.read()
    entry["operands"] = tail
    with open(os.path.join(HERE, "transfer.log"), "a") as stream:
        stream.write(json.dumps(entry) + "\n")
    if not ok or conf.get("fail") == program:
        return 1
    if program == "scp":
        source, target = tail
        if conf.get("scp_sleep"):
            import time
            time.sleep(conf["scp_sleep"])
        destination = target.split(":", 1)[1]
        with open(source, "rb") as src, open(destination, "xb") as dst:
            shutil.copyfileobj(src, dst)
        return 0
    for line in entry["batch"].splitlines():
        words = line.split(" ")
        if len(words) != 3 or words[0] != "@put":
            return 1
        shutil.copyfile(words[1], words[2])
    return 0


if __name__ == "__main__":
    sys.exit(main(os.path.basename(sys.argv[0]), sys.argv[1:]))
