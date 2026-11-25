"""A stand-in coding agent (`pi`, `codex`, `claude`) for controller tests,
run in the stand-in jail from HOME/.local/bin (or an installed package):
logs what it got to HOME/agent-log.jsonl (argv, cwd, selected variables
(C2B_*, its request context AGENTBOX_*), the prompt, whether its credential file is there and its size; never a
credential's bytes), then:

  headless     the prompt from stdin: `agent NAME got: PROMPT`, exit 0
               (`exit:N` in the prompt: exit N; `sleep:S`: S seconds first)
  interactive  stdin a terminal: `agent-ready`, then bytes one at a time:
               \\x03 -> `ctrl-c`, `s` -> `size ROWSxCOLS`, `t` -> `tty
               raw|cooked`, \\x04 -> exit 0, `q` -> exit 3, `r` -> one
               `agentbox-request echo say` (`request ok|failed`); SIGWINCH ->
               `winch ROWSxCOLS`
"""
import json
import os
import signal
import sys
import termios

NAME = os.path.basename(sys.argv[0])
HOME = os.environ.get("HOME", "/")
CREDENTIALS = {"pi": ".pi/agent/auth.json", "codex": ".codex/auth.json", "claude": ".claude/.credentials.json"}


def size():
    cols, rows = os.get_terminal_size(0)
    return f"{rows}x{cols}"


def log(**fields):
    path = os.path.join(HOME, CREDENTIALS.get(NAME, ".none"))
    entry = {"name": NAME, "argv": sys.argv[1:], "cwd": os.getcwd(), "tty": os.isatty(0),
             "env": {k: v for k, v in os.environ.items() if k.startswith(("C2B_", "AGENTBOX_"))},
             "term": os.environ.get("TERM"), "auth": os.path.getsize(path) if os.path.isfile(path) else None}
    entry.update(fields)
    with open(os.path.join(HOME, "agent-log.jsonl"), "a") as stream:
        stream.write(json.dumps(entry) + "\n")


def say(text):
    os.write(1, (text + "\r\n").encode())


def main():
    if not os.isatty(0):
        prompt = sys.stdin.read()
        log(prompt=prompt)
        print(f"agent {NAME} got: {prompt}", flush=True)
        if prompt.startswith("exit:"):
            return int(prompt.split(":", 1)[1])
        if prompt.startswith("sleep:"):
            import time
            time.sleep(float(prompt.split(":", 1)[1]))
        return 0
    log(prompt=None)
    signal.signal(signal.SIGWINCH, lambda *_: say(f"winch {size()}"))
    say("agent-ready")
    while True:
        try:
            data = os.read(0, 1)
        except InterruptedError:
            continue
        if not data:
            return 0
        if data == b"\x03":
            say("ctrl-c")
        elif data == b"s":
            say(f"size {size()}")
        elif data == b"t":
            say("tty " + ("cooked" if termios.tcgetattr(0)[3] & termios.ICANON else "raw"))
        elif data == b"\x04":
            say("agent-eot")
            return 0
        elif data == b"q":
            return 3
        elif data == b"r":
            import subprocess
            done = subprocess.run(["agentbox-request", "echo", "say", '{"text":"i"}'], stdin=subprocess.DEVNULL,
                                  capture_output=True)
            say("request " + ("ok" if done.returncode == 0 and b'"ok":true' in done.stdout else "failed"))


if __name__ == "__main__":
    sys.exit(main())
