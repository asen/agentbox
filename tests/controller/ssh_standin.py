"""A stand-in `ssh` for controller tests, run from a private copy beside
its `ssh.json`: {log, payload, install_root, fail}. It checks the fixed
profile, logs argv and environment, then runs the remote side locally:

  /bin/sh -s   the host's bootstrap script, the baked payload path replaced
               by the local copy and `sealed` (root ownership) a no-op
  LAUNCHER     the written launcher, the payload path replaced: the real
               guest helper on this process's stdin/stdout, as a child;
               meanwhile `-R 127.0.0.1:18080:127.0.0.1:PORT` is emulated:
               an ephemeral listener relaying to PORT, its port written to
               HOME/.agentbox-test-forward (forward.py's)

The bootstrap's wrappers get one change: their interpreter line runs the
entry behind forward.py.

  LAUNCHER shell TERM 'ARG'...   the launcher's shell form, its words
               unquoted, as a child: with RequestTTY=force (`shell`, an
               agent's terminal SSH) this terminal set raw first, as ssh
               does, and restored at its end or on SIGTERM (its child
               ended too); `-T` (an agent's staging) plain pipes. `term`:
               "ignore" (SIGTERM ignored: only SIGKILL ends it, nothing
               restored)

A stdio route's ProxyCommand runs first, as ssh runs it: `%%` undone (any
other `%` token refused, `proxy_error`), `exec COMMAND` through /bin/sh on
pipes; the bridge's banner line read (`bridge`), one line echoed through
it (`echoed`), then ended as ssh ends it: its stdin closed (`proxy_end`
"eof", the default) or SIGHUP ("hup"); its pid and exit logged. `fail`:
"bootstrap" | "session" (exit 255 at once) | "hang" (session never answers)
| "hang_inputs" (the guest hello, then never `inputs_ready`; stderr noise
meanwhile) | "hang_bootstrap" (a bootstrap stage never answers). `export` (an export's
script): "hang" | "exit7" | "flood" (BYTES of x, then exit 0). `tamper` (a
directory): after a staging SSH, each file there replaced by a copy.
"""
import shlex
import select
import signal
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def main(args):
    with open(os.path.join(HERE, "ssh.json")) as stream:
        conf = json.load(stream)
    entry = {"argv": args, "env": dict(os.environ), "pid": os.getpid()}
    rest = list(args)
    interactive = rest[2:3] == ["-l"]
    head = rest[:4] if interactive else rest[:5]
    rest = rest[len(head):]
    ok = head[:3] == ["-F", "/dev/null", "-l"] if interactive else head[:4] == ["-F", "/dev/null", "-T", "-l"]
    port = forward = None
    if rest[:1] == ["-p"]:
        port, rest = rest[1], rest[2:]
    if rest[:1] == ["-R"]:
        forward, rest = rest[1], rest[2:]
    options = {}
    while rest[:1] == ["-o"]:
        key, _, value = rest[1].partition("=")
        options[key] = value
        rest = rest[2:]
    destination, remote = rest[0], rest[1:]
    entry.update(port=port, forward=forward, destination=destination, remote=remote, options=options)
    try:
        with open(options["UserKnownHostsFile"]) as stream:
            pinned = stream.read().split(" ")[0] == options["HostKeyAlias"]
        ok = ok and pinned and os.path.isfile(options["IdentityFile"]) and options["BatchMode"] == "yes" \
            and options["RequestTTY"] == ("force" if interactive else "no")
        with open(options["UserKnownHostsFile"]) as stream:
            entry["pinned"] = stream.read()
    except (KeyError, OSError):
        ok = False
    entry["profile_ok"] = ok
    if options.get("ProxyCommand", "none") != "none":
        entry.update(proxy(options["ProxyCommand"], conf.get("proxy_end", "eof")))
    bootstrap = remote == ["/bin/sh", "-s"]
    script = sys.stdin.read() if bootstrap else None
    shellform = len(remote) > 1 and remote[1] == "shell"
    entry["mode"] = ("export" if "agentbox-export" in script else "bootstrap") if bootstrap \
        else "shell" if interactive else "staging" if shellform else "session"
    with open(conf["log"], "a") as stream:
        stream.write(json.dumps(entry) + "\n")
    if not ok:
        return 255
    fail = conf.get("fail")
    root, payload = conf["install_root"], conf["payload"]
    if entry["mode"] == "export":
        mode = conf.get("export")
        if mode == "hang":
            time.sleep(1000)
        if mode == "exit7":
            return 7
        if mode == "flood":
            os.write(1, b"x" * int(conf["bytes"]))
            return 0
        os.execv("/bin/sh", ["/bin/sh", "-c", script])
    if bootstrap:
        if fail == "bootstrap":
            return 255
        if fail == "hang_bootstrap":
            time.sleep(1000)
            return 255
        script = script.replace(f"payload='{root}'", f"payload='{payload}'").replace(f"'{root}/", f"'{payload}/")
        script = re.sub(r"^sealed\(\) \{.*\}$", "sealed() { :; }", script, flags=re.M)
        front = os.path.join(conf["harness"], "forward.py")
        script = re.sub(r"-X utf8 '([^']+/(?:guest/src/request_main|acquisitions/[a-z0-9-]+/jail/[^/']+)\.py)'",
                        lambda m: f"-X utf8 '{front}' '{m.group(1)}'", script)
        os.execv("/bin/sh", ["/bin/sh", "-c", script])
    if fail == "session":
        return 255
    if fail == "hang":
        time.sleep(1000)
        return 255
    if fail == "hang_inputs":
        hello = json.loads(sys.stdin.buffer.readline())
        os.write(1, json.dumps({"v": 1, "type": "hello", "session": hello["session"],
                                "guest_version": "0.1.0"}).encode() + b"\n")
        for _ in range(5000):
            os.write(2, b"noise\n")
            time.sleep(0.2)
        return 255
    with open(remote[0]) as stream:
        text = stream.read().replace(f"'{root}/", f"'{payload}/")
    if interactive or shellform:
        code = shell_form(text, shlex.split(" ".join(remote[1:])), interactive, conf.get("term"))
        if conf.get("tamper") and not interactive and code == 0:
            tamper(conf["tamper"])
        return code
    home = re.search(r"'supplied-(?:session-v3|mounted-v1)' '([^']+)'", text).group(1)
    broker = int(forward.rsplit(":", 1)[1])
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    with open(os.path.join(home, ".agentbox-test-forward"), "w") as stream:
        stream.write(str(listener.getsockname()[1]))
    threading.Thread(target=relay, args=(listener, broker), daemon=True).start()
    child = subprocess.Popen(["/bin/sh", "-c", text, "sh"])
    return child.wait()


def shell_form(text, words, tty, term):
    import termios
    import tty as tty_mod
    saved = None
    if tty and os.isatty(0):
        saved = termios.tcgetattr(0)
        tty_mod.setraw(0)
    child = subprocess.Popen(["/bin/sh", "-c", text, "sh"] + words)

    def restore():
        if saved is not None:
            termios.tcsetattr(0, termios.TCSANOW, saved)

    flag = []
    signal.signal(signal.SIGTERM, signal.SIG_IGN if term == "ignore" else lambda *_: flag.append(1))
    while child.poll() is None:
        if flag:
            # The session's end: the runner forwards TERM to the agent.
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            restore()
            return 255
        time.sleep(0.02)
    restore()
    return child.returncode


def tamper(root):
    """Every staged file replaced by a byte-identical copy (a new inode)."""
    for directory, _, files in os.walk(root):
        for name in files:
            path = os.path.join(directory, name)
            with open(path, "rb") as stream:
                data = stream.read()
            copy = path + ".copy"
            fd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, data)
            os.close(fd)
            os.rename(copy, path)


def expand(command):
    """ssh's percent_expand of a ProxyCommand with no token used: `%%` is
    `%`; any other `%` sequence is ssh's fatal error (None)."""
    out, i = [], 0
    while i < len(command):
        if command[i] == "%":
            if command[i + 1:i + 2] != "%":
                return None
            out.append("%")
            i += 2
        else:
            out.append(command[i])
            i += 1
    return "".join(out)


def _line(fd, deadline):
    data = b""
    while not data.endswith(b"\n") and time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], max(0.0, deadline - time.monotonic()))
        if not ready:
            break
        chunk = os.read(fd, 1)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace").strip()


def proxy(command, end):
    """ssh's ProxyCommand on pipes: banner, one echoed line, then its end
    (stdin closed, or SIGHUP as ssh sends at its exit)."""
    expanded = expand(command)
    if expanded is None:
        return {"proxy_error": "percent"}
    proc = subprocess.Popen(["/bin/sh", "-c", "exec " + expanded], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    found = {"proxy_pid": proc.pid, "proxy_command": expanded}
    deadline = time.monotonic() + 20
    found["bridge"] = _line(proc.stdout.fileno(), deadline)
    if found["bridge"]:
        try:
            proc.stdin.write(b"ping\n")
            proc.stdin.flush()
        except OSError:
            pass
        found["echoed"] = _line(proc.stdout.fileno(), deadline)
    if end == "hup":
        try:
            proc.send_signal(signal.SIGHUP)
        except OSError:
            pass
    else:
        proc.stdin.close()
    try:
        found["proxy_exit"] = proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        found["proxy_exit"] = "timeout"
        proc.wait()
    found["proxy_stderr"] = proc.stderr.read().decode(errors="replace")[-400:]
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        try:
            stream.close()
        except OSError:
            pass
    return found


def pump(source, target):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            target.sendall(data)
    except OSError:
        pass
    for end in (source, target):
        try:
            end.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def relay(listener, broker):
    while True:
        client, _ = listener.accept()
        try:
            upstream = socket.create_connection(("127.0.0.1", broker))
        except OSError:
            client.close()
            continue
        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
