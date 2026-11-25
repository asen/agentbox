# The common jail runner of `agentbox run AGENT` (agents/AGENT/
# adapter.py chooses everything agent-specific): guest-only text, run by
# the jail's Python from argv chunks (`python3 -I -S -B -c LOADER
# CHUNK... MODE NONCE RECEIPT`). Untrusted automation in the jail, never
# host authority; best effort, and its own lines start with
# `agentbox-agent:` on stderr. No agent is named here.
#
#   headless - -  the prompt on the agent's stdin
#   stage N -     no prompt, HEADER.stage N, HEADER.env: the input to /dev/shm/
#                 agentbox-agent-UID/N (exclusive, 0600, a 0700 directory
#                 of this user); stdout DEV:INO:DIRDEV:DIRINO, the receipt
#   run N R       that file, only while still the receipt's, unlinked
#                 first (whatever keep); the agent on the terminal:
#                 INT/QUIT/TSTP its own, a stopped one continued
#   unstage N R   that file removed, the same checks
#
#   stdin  HEADER LF PROMPT CREDENTIAL   (agentbox.agent-input.v3, at most
#          MAX_INPUT; read whole before anything else)
#   env    staged only: {NAME: VALUE}, `--env` (names [A-Za-z_][A-Za-z0-9_]*,
#          values without NUL; the host's checks are the authority), over
#          this session's environment for the agent alone (run); headless
#          gets `--env` as any `jail exec` does
#   settings  {"argv": [PROGRAM, ARG...],
#              "auth": null | {"path": REL, "keep": BOOL},
#              "package": null | {"agent": NAME, "name": NPM_NAME, "bin": NAME,
#                  "install": null | {"version": null | VERSION}}}
#             literal strings, no interpolation or shell; the model, if
#             any, is in argv
#   AGENTS    ~/.local/share/agentbox-agents/AGENT: VERSION/ an npm prefix,
#             complete only with VERSION/.agentbox-installed (written last);
#             `current` -> VERSION, the last explicit install
#   [install] VERSION, else `npm view NAME@latest version`; complete: kept,
#             else any leftover removed and `npm install --global --prefix
#             AGENTS/VERSION NAME@VERSION` (npm and its scripts in the jail,
#             its output on stderr; the npm shim's lane), VERSION/bin/BIN
#             checked, the marker written; `current` repointed; BIN runs
#   [locate]  without: `current`'s BIN if complete, else PROGRAM (a bare
#             name: the first executable regular file of that name on the
#             task's PATH; an absolute path: itself)
#   [auth]    ~/REL created exclusively, 0600, without following links,
#             missing parents made 0700, existing ones real directories;
#             an existing file refuses and stays
#   PROGRAM-or-BIN ARG..., the prompt on its stdin
#   exit   the agent's status; TERM/INT/HUP forwarded to it (and to npm);
#          the credential this run created removed afterwards (not
#          keep), only while the same file in the same directory (an agent
#          may rewrite it in place); a replaced file or directory is left
#          with a warning, everything else (locks included) as found. Best
#          effort: the jail could copy it anyway.
#
# Failures before the agent exit 90-95 with a fixed code.


def _main():
    import sys
    import json
    import os
    import re
    import shutil
    import signal
    import stat
    import subprocess

    SCHEMA = "agentbox.agent-input.v3"
    MAX_INPUT = 1 << 20
    MAX_REPORT = 1 << 16
    EXIT = {"input": 90, "install": 91, "auth": 92, "missing": 93, "launch": 94, "stage": 95}
    MODE, NONCE, RECEIPT = sys.argv[-3:]
    SHM = "/dev/shm"
    HOME = os.environ.get("HOME", "")
    AGENTS = os.path.join(HOME, ".local", "share", "agentbox-agents")
    NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
    NPM = re.compile(r"(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*")
    VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z.-]{1,40})?")
    MARKER = ".agentbox-installed"
    STAGED = re.compile(r"[0-9a-f]{32}")
    VAR = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    state = {"keep": False, "current": None, "pid": None, "stopping": None, "auth": None,
             "label": None, "created": None, "staged": None, "finished": False}

    def say(text):
        try:
            os.write(2, ("agentbox-agent: %s\n" % text).encode())
        except OSError:
            pass  # Nothing left to report to.

    def same(info, identity):
        return (info.st_dev, info.st_ino) == identity

    def remove(path, ids):
        """`path` unlinked only while it and its directory are still `ids`
        (file, directory): None, else "gone" or why it stays."""
        file_id, dir_id = ids
        try:
            parent = os.lstat(os.path.dirname(path))
            if not stat.S_ISDIR(parent.st_mode) or not same(parent, dir_id):
                return "directory replaced"
            info = os.lstat(path)
        except FileNotFoundError:
            return "gone"
        except OSError:
            return "unreadable"
        if not stat.S_ISREG(info.st_mode) or not same(info, file_id):
            return "file replaced"
        try:
            os.unlink(path)
        except OSError:
            return "not removable"
        return None

    def cleanup():
        if state["staged"] is not None:
            remove(*state["staged"])
            state["staged"] = None
        created = state["created"]
        if created is None or state["keep"]:
            return
        state["created"] = None
        why = remove(state["auth"], created)
        if why is None:
            say("credential removed")
        elif why == "gone":
            say("credential already gone")
        else:
            say("warning: credential_left (%s): %s" % (why, state["label"]))

    def finish(status):
        if not state["finished"]:
            state["finished"] = True
            cleanup()
        os._exit(status)

    def fail(kind, code):
        say("error code=%s" % code)
        finish(EXIT[kind])

    def signalled():
        return 128 + (state["stopping"] or 0)

    def on_signal(number, _frame):
        if state["stopping"] is None:
            state["stopping"] = number
        child = state["current"]
        if state["pid"] is not None:
            try:
                os.kill(state["pid"], number)
            except OSError:
                pass  # Already gone: its wait ends this run.
        elif child is not None:
            try:
                child.send_signal(number)
            except OSError:
                pass  # Already gone: its close ends this run.
        else:
            finish(signalled())

    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, on_signal)

    def text(value):
        return isinstance(value, str) and value != "" and "\0" not in value

    def relative(path):
        """A plain path below HOME: no empty, `.` or `..` component."""
        return text(path) and all(part not in ("", ".", "..") for part in path.split("/"))

    def name(value):
        return isinstance(value, str) and NAME.fullmatch(value) is not None

    def version(value):
        return isinstance(value, str) and VERSION.fullmatch(value) is not None

    def valid_package(package):
        if package is None:
            return True
        if not isinstance(package, dict) or set(package) != {"agent", "name", "bin", "install"}:
            return False
        install = package["install"]
        return (name(package["agent"]) and name(package["bin"]) and isinstance(package["name"], str)
                and NPM.fullmatch(package["name"]) is not None
                and (install is None or (isinstance(install, dict) and set(install) == {"version"}
                                         and (install["version"] is None or version(install["version"])))))

    def valid(settings):
        if not isinstance(settings, dict) or set(settings) != {"argv", "auth", "package"}:
            return False
        argv, auth = settings["argv"], settings["auth"]
        if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) and "\0" not in arg
                                                            for arg in argv):
            return False
        program = argv[0]
        if not text(program) or ("/" in program and not os.path.isabs(program)):
            return False
        return valid_package(settings["package"]) and (
            auth is None or (isinstance(auth, dict) and set(auth) == {"path", "keep"}
                             and relative(auth["path"]) and isinstance(auth["keep"], bool)))

    def parse(data, staged):
        end = data.find(b"\n")
        if end < 0:
            return None
        try:
            header = json.loads(data[:end].decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return None

        def count(value):
            return type(value) is int and 0 <= value <= 2 ** 53 - 1

        keys = {"schema", "prompt_bytes", "credential_bytes", "settings"} | ({"stage", "env"} if staged else set())
        if (not isinstance(header, dict) or set(header) != keys
                or header["schema"] != SCHEMA or not count(header["prompt_bytes"])
                or not count(header["credential_bytes"])
                or not valid(header["settings"])
                or (header["credential_bytes"] == 0) != (header["settings"]["auth"] is None)
                or end + 1 + header["prompt_bytes"] + header["credential_bytes"] != len(data)
                or (staged and (header["stage"] != NONCE or header["prompt_bytes"] != 0
                                or (header["settings"]["package"] or {}).get("install") is not None
                                or not isinstance(header["env"], dict)
                                or not all(VAR.fullmatch(name) and isinstance(value, str) and "\0" not in value
                                           for name, value in header["env"].items())))):
            return None
        at = end + 1 + header["prompt_bytes"]
        return {"settings": header["settings"], "prompt": data[end + 1:at], "credential": data[at:],
                "env": header.get("env", {})}

    def is_file(path):
        try:
            return stat.S_ISREG(os.stat(path).st_mode)
        except OSError:
            return False

    def is_program(path):
        return is_file(path) and os.access(path, os.X_OK)

    def locate(program):
        if os.path.isabs(program):
            return program if is_program(program) else None
        for directory in os.environ.get("PATH", "").split(":"):
            if os.path.isabs(directory) and is_program(os.path.join(directory, program)):
                return os.path.join(directory, program)
        return None

    def run(argv, stdin=None, stdout=None, env=None, feed=None):
        """One child to its close: (returncode, stdout text) or None when it
        could not start; its stdout, when piped, bounded."""
        try:
            child = subprocess.Popen(argv, stdin=stdin, stdout=stdout, env=env, close_fds=True)
        except OSError:
            return None
        state["current"] = child
        kept = bytearray()
        try:
            if feed is not None:
                feed(child)
            if stdout is subprocess.PIPE:
                while True:
                    chunk = child.stdout.read(65536)
                    if not chunk:
                        break
                    if len(kept) < MAX_REPORT:
                        kept.extend(chunk)
                child.stdout.close()
            returncode = child.wait()
        finally:
            state["current"] = None
        return returncode, kept.decode("utf-8", "replace")

    def complete(directory, package):
        """`directory`'s BIN when its install completed, else None."""
        try:
            if not stat.S_ISREG(os.lstat(os.path.join(directory, MARKER)).st_mode):
                return None
        except OSError:
            return None
        found = os.path.join(directory, "bin", package["bin"])
        return found if is_program(found) else None

    def current(package):
        root = os.path.join(AGENTS, package["agent"])
        try:
            target = os.readlink(os.path.join(root, "current"))
        except OSError:
            return None
        return complete(os.path.join(root, target), package) if version(target) else None

    def npm(argv, out):
        found = locate("npm")
        if found is None:
            fail("install", "install_npm_missing")
        done = run([found] + argv, stdin=subprocess.DEVNULL, stdout=out)
        if state["stopping"] is not None:
            finish(signalled())
        return done

    def resolve(package):
        done = npm(["view", "--json", package["name"] + "@latest", "version"], subprocess.PIPE)
        try:
            found = json.loads(done[1]) if done and done[0] == 0 else None
        except (ValueError, RecursionError):
            found = None
        if not version(found):
            fail("install", "install_resolve_failed")
        return found

    def install(package):
        chosen = package["install"]["version"] or resolve(package)
        root = os.path.join(AGENTS, package["agent"])
        directory = os.path.join(root, chosen)
        try:
            os.makedirs(root, 0o700, exist_ok=True)
        except OSError:
            fail("install", "install_location_unusable")
        found = complete(directory, package)
        if found is not None:
            say("%s %s already installed" % (package["agent"], chosen))
        else:
            try:
                if os.path.isdir(directory) and not os.path.islink(directory):
                    shutil.rmtree(directory)
                elif os.path.lexists(directory):
                    os.unlink(directory)
                os.mkdir(directory, 0o700)
            except OSError:
                fail("install", "install_location_unusable")
            done = npm(["install", "--global", "--prefix", directory, "--no-audit", "--no-fund",
                        "%s@%s" % (package["name"], chosen)], 2)
            if done is None or done[0] != 0:
                fail("install", "install_failed")
            found = os.path.join(directory, "bin", package["bin"])
            if not is_program(found):
                fail("install", "install_incomplete")
            try:
                os.close(os.open(os.path.join(directory, MARKER),
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
            except OSError:
                fail("install", "install_location_unusable")
            say("%s %s installed" % (package["agent"], chosen))
        link = os.path.join(root, ".current-%d" % os.getpid())
        try:
            if os.path.lexists(link):
                os.unlink(link)
            os.symlink(chosen, link)
            os.replace(link, os.path.join(root, "current"))
        except OSError:
            fail("install", "install_location_unusable")
        return [found]

    def select(program, package):
        """The command before argv[1:]: an install, else `current`, else
        PROGRAM."""
        if package is not None and package["install"] is not None:
            return install(package)
        found = (package and current(package)) or locate(program)
        if found is None:
            fail("missing", "agent_not_installed")
        return [found]

    def place(path, credential):
        parts = path.split("/")
        directory = HOME
        for part in parts[:-1]:
            directory = os.path.join(directory, part)
            try:
                info = os.lstat(directory)
            except FileNotFoundError:
                info = None
            except OSError:
                fail("auth", "auth_location_unsafe")
            if info is None:
                try:
                    os.mkdir(directory, 0o700)
                except OSError:
                    fail("auth", "auth_location_unsafe")
            elif not stat.S_ISDIR(info.st_mode):
                fail("auth", "auth_location_unsafe")
        auth = state["auth"] = os.path.join(directory, parts[-1])
        try:
            fd = os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except FileExistsError:
            fail("auth", "auth_exists")
        except OSError:
            fail("auth", "auth_unwritable")
        try:
            created = os.fstat(fd)
            parent = os.lstat(directory)
            state["created"] = ((created.st_dev, created.st_ino), (parent.st_dev, parent.st_ino))
            view = memoryview(credential)
            while view:
                view = view[os.write(fd, view):]
            os.close(fd)
        except OSError:
            fail("auth", "auth_unwritable")

    def shm():
        return os.path.join(SHM, "agentbox-agent-%d" % os.getuid())

    def stage(data):
        """The staged payload: exclusive, 0600, its receipt on stdout."""
        directory = shm()
        path = os.path.join(directory, NONCE)
        for attempt in (0, 1):
            try:
                os.mkdir(directory, 0o700)
            except FileExistsError:
                pass
            except OSError:
                fail("stage", "staging_unavailable")
            try:
                parent = os.lstat(directory)
            except OSError:
                fail("stage", "staging_unavailable")
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                    or stat.S_IMODE(parent.st_mode) != 0o700):
                fail("stage", "staging_unsafe")
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                break
            except FileExistsError:
                fail("stage", "stage_exists")
            except FileNotFoundError:
                if attempt:  # The directory went meanwhile (another's end): once more.
                    fail("stage", "staging_unavailable")
            except OSError:
                fail("stage", "stage_unwritable")
        try:
            info = os.fstat(fd)
            ids = ((info.st_dev, info.st_ino), (parent.st_dev, parent.st_ino))
            state["staged"] = (path, ids)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.close(fd)
            os.write(1, ("%d:%d:%d:%d\n" % (ids[0] + ids[1])).encode())
        except OSError:
            fail("stage", "stage_unwritable")
        state["staged"] = None
        finish(0)

    def receipt():
        if not re.fullmatch(r"[0-9]{1,20}(:[0-9]{1,20}){3}", RECEIPT):
            fail("input", "input_invalid")
        numbers = [int(part) for part in RECEIPT.split(":")]
        return (tuple(numbers[:2]), tuple(numbers[2:]))

    def unstage():
        why = remove(os.path.join(shm(), NONCE), receipt())
        if why in (None, "gone"):
            say("staged payload removed" if why is None else "staged payload already gone")
            try:
                os.rmdir(shm())
            except OSError:
                pass  # Not empty, or gone.
            finish(0)
        say("warning: staging_left (%s)" % why)
        finish(EXIT["stage"])

    def consume():
        """The staged payload, unlinked: only the very file staged."""
        ids = receipt()
        path = os.path.join(shm(), NONCE)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except FileNotFoundError:
            fail("stage", "stage_missing")
        except OSError:
            fail("stage", "stage_mismatch")
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not same(info, ids[0]) or info.st_nlink != 1:
            fail("stage", "stage_mismatch")
        why = remove(path, ids)
        if why is not None:
            fail("stage", "stage_missing" if why == "gone" else "stage_mismatch")
        try:
            os.rmdir(shm())
        except OSError:
            pass
        data = os.read(fd, MAX_INPUT + 1)
        os.close(fd)
        return data

    def main(data):
        parsed = parse(data, MODE != "headless")
        if parsed is None:
            fail("input", "input_invalid")
        if MODE == "stage":
            stage(data)
        settings = parsed["settings"]
        argv, auth = settings["argv"], settings["auth"]
        if not os.path.isabs(HOME):
            fail("input", "home_invalid")
        program = select(argv[0], settings["package"])
        if state["stopping"] is not None:
            finish(signalled())
        if auth is not None:
            state["keep"], state["label"] = auth["keep"], "~/" + auth["path"]
            place(auth["path"], parsed["credential"])

        def feed(child):
            try:
                child.stdin.write(parsed["prompt"])
                child.stdin.close()
            except OSError:
                pass  # The agent's own business.

        if MODE == "run":
            # The terminal's: no prompt, nothing forwarded but TERM/HUP.
            for number in (signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP):
                signal.signal(number, lambda *_: None)
            try:
                # Held to the end: a dropped Popen would reap the agent itself.
                child = subprocess.Popen(program + argv[1:], close_fds=True,
                                         env={**os.environ, **parsed["env"]})
            except OSError:
                fail("launch", "agent_launch_failed")
            state["pid"] = child.pid
            while True:
                try:
                    _, status = os.waitpid(state["pid"], os.WUNTRACED)
                except ChildProcessError:
                    finish(EXIT["launch"])
                if not os.WIFSTOPPED(status):
                    break
                try:
                    os.kill(state["pid"], signal.SIGCONT)
                except OSError:
                    pass
            state["pid"] = None
            finish(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status))
        agent = run(program + argv[1:], stdin=subprocess.PIPE, feed=feed)
        if agent is None:
            fail("launch", "agent_launch_failed")
        code = agent[0]
        finish(code if code >= 0 else 128 - code)

    plain = NONCE == "-" and RECEIPT == "-"
    if not ((MODE == "headless" and plain)
            or (MODE in ("stage", "run", "unstage") and STAGED.fullmatch(NONCE)
                and (RECEIPT == "-") == (MODE == "stage"))):
        fail("input", "input_invalid")
    if MODE in ("run", "unstage"):
        try:
            unstage() if MODE == "unstage" else main(consume())
        except Exception:
            fail("launch", "agent_launch_failed")
    chunks = []
    size = 0
    try:
        while True:
            chunk = os.read(0, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_INPUT:
                fail("input", "input_too_large")
            chunks.append(chunk)
    except OSError:
        fail("input", "input_unreadable")
    try:
        main(b"".join(chunks))
    except Exception:
        fail("launch", "agent_launch_failed")


_main()
