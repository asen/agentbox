"""An interactive `run AGENT`'s session: the serving owner's in-process
client (execute.py `client`), one step per pass of the owner's loop (the
old CLI's cli_agent.rs `Session`).

```text
ready     the owner's guest ready, its profile known
staging   ssh -T (own process group): LAUNCHER shell TERM SESSION PY RUNNER stage N -
            stdin  <- one filled pipe: HEADER LF CREDENTIAL (agent.framed)
            stdout -> the runner's receipt DEV:INO:DIRDEV:DIRINO   <= 30 s
agent     ssh (PTY, RequestTTY=force): ... run N RECEIPT, this process's
          0/1/2 inherited, in this process's group (the terminal's
          foreground): its settings saved first, restored once at its end
unstaging ssh -T (own group): ... unstage N RECEIPT                 <= 30 s
done      the owner stops (cancelled), its teardown follows
```

Every SSH carries the serving owner's SESSION (shell.py): staging, the
agent and unstaging run in that owner's request context, its acquisition
lane (if configured) the one `agentbox shell` logins share.

No relay, filter or thread: the jail's bytes reach the terminal through
ssh alone, and nothing here writes the terminal while that ssh lives.
Ending this command's SSH: SIGTERM, 2 s, SIGKILL, 1 s (that child only;
never the jail). The terminal is restored immediately (TCSANOW) with
SIGTTOU blocked; a failure fails the command. The staged file is named by
its receipt: never removed without it, a removal not confirmed is
reported (`staging_left`). Through a stdio provider each SSH's
ProxyCommand is `jail shell-transport` of this same owner (shell.py): it
joins a slot of the owner's domain from this process's delegated unit (no
other entry) and counts against the owner's 32.
"""
import os
import signal
import termios
import time

from . import agent as agent_mod
from . import shell as shell_mod
from .host import Child, HostError, read_some

STAGE_WAIT = 30.0
SSH_GRACE = 2.0
KILL_WAIT = 1.0
MAX_RECEIPT_BYTES = 256


def foreground_terminal(stdin=0, stdout=1):
    """stdin and stdout terminals, this process in stdin's foreground
    process group."""
    try:
        return os.isatty(stdin) and os.isatty(stdout) and os.tcgetpgrp(stdin) == os.getpgrp()
    except OSError:
        return False


def settle(child, grace=SSH_GRACE):
    """This command's own child ended now, bounded: its own end
    ("exited"), else SIGTERM and `grace` ("terminated"), else SIGKILL and
    KILL_WAIT ("killed"), else "unsettled" (left, reported)."""
    if child.exited():
        child.finish()
        return "exited"
    child.signal(signal.SIGTERM)
    for state, wait in (("terminated", grace), ("killed", KILL_WAIT)):
        until = time.monotonic() + wait
        while time.monotonic() < until:
            if child.exited():
                child.finish()
                return state
            time.sleep(0.01)
        if state == "terminated":
            child.signal(signal.SIGKILL)
    return "unsettled"


class Session:
    def __init__(self, plan, nonce, payload, ssh_program, term, config, environ, tty=0):
        self.plan, self.nonce, self.payload = plan, nonce, payload
        self.ssh, self.term, self.config, self.environ = ssh_program, term, config, environ
        self.tty = tty
        self.owner = None
        self.step = "ready"
        self.child = None
        self.until = None
        self.receipt = None
        # The agent's end: ("ended", status) | ("stopped", code) | ("not_started", code)
        self.agent = ("not_started", "agent_not_started")
        self.staged = False
        self.unstaged = None
        self.staging_status = None
        self.saved = None
        self.unrestored = False

    def bind(self, owner):
        self.owner = owner

    # -- children --------------------------------------------------------

    def _spawn(self, mode, receipt, tty, stdin_fd=None):
        owner = self.owner
        profile = owner.profile
        transport = None
        if profile["endpoint"] is None:
            transport = shell_mod.transport_words(self.config, owner.run_id, owner.execution_id)
        words = list(owner.python_words) + agent_mod.runner_argv(self.plan, mode, self.nonce, receipt)
        argv = shell_mod.argv(self.ssh, profile, self.term, words, transport, tty=tty)
        env = shell_mod.environment(self.term, transport is not None)
        if tty:
            return Child(argv, env, stdin="inherit", stdout="inherit", stderr="inherit", session=False)
        if stdin_fd is not None:
            return Child(argv, env, stdin_fd=stdin_fd, stdout=True, stderr="inherit")
        return Child(argv, env, stdin=False, stdout=False, stderr="inherit")

    def _failed(self, code):
        self.agent = ("not_started", code)
        return "done"

    def _stage(self):
        try:
            self.plan.check_expiry()
        except HostError as error:
            return self._failed(error.code)
        payload, self.payload = self.payload, None
        if payload is None:
            return self._failed("agent_staging_failed")
        try:
            pipe = agent_mod.filled(payload)
        except HostError as error:
            return self._failed(error.code)
        try:
            self.child = self._spawn("stage", "-", False, stdin_fd=pipe)
        except HostError as error:
            return self._failed(error.code)
        finally:
            os.close(pipe)
        self.staged = True
        self.until = time.monotonic() + STAGE_WAIT
        return "staging"

    def _receipt(self):
        data = b""
        fd = self.child.popen.stdout.fileno()
        while len(data) <= MAX_RECEIPT_BYTES:
            chunk = read_some(fd, 4096)
            if not chunk:
                break
            data += chunk
        return agent_mod.receipt(data[:MAX_RECEIPT_BYTES + 1])

    def _save_terminal(self):
        try:
            self.saved = termios.tcgetattr(self.tty)
        except (termios.error, OSError):
            self.saved = None
        return self.saved is not None

    def _restore_terminal(self):
        """Once, immediately, never stopped by SIGTTOU."""
        saved, self.saved = self.saved, None
        if saved is None:
            return
        old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTTOU})
        try:
            termios.tcsetattr(self.tty, termios.TCSANOW, saved)
        except (termios.error, OSError):
            self.unrestored = True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old)

    def _launch(self):
        if not self._save_terminal():
            self.agent = ("not_started", "terminal_save_failed")
            return self._unstage()
        try:
            self.child = self._spawn("run", self.receipt, True)
        except HostError as error:
            self.saved = None
            self.agent = ("not_started", error.code)
            return self._unstage()
        return "agent"

    def _unstage(self):
        try:
            self.child = self._spawn("unstage", self.receipt, False)
        except HostError:
            self.unstaged = False
            return "done"
        self.until = time.monotonic() + STAGE_WAIT
        return "unstaging"

    def _stop_agent(self):
        state = settle(self.child)
        self._restore_terminal()
        if state == "exited":
            self.agent = ("ended", self.child.code)
        else:
            self.agent = ("stopped", {"terminated": "agent_session_stopped", "killed": "agent_session_killed"}
                          .get(state, "agent_session_unsettled"))
        self.child = None

    # -- the owner's pass -------------------------------------------------

    def turn(self, stopping):
        """One step; True once done."""
        step = self.step
        if step == "ready":
            step = self._failed("interrupted") if stopping else self._stage()
        elif step == "staging":
            child = self.child
            if child.exited():
                receipt = self._receipt()
                status = child.finish()
                self.child = None
                if receipt is not None and status == 0 and not stopping:
                    self.receipt = receipt
                    step = self._launch()
                elif receipt is not None:
                    self.receipt = receipt
                    self.staging_status = status
                    self.agent = ("not_started", "interrupted" if stopping else "agent_staging_failed")
                    step = self._unstage()
                else:
                    self.staging_status = status
                    step = self._failed("interrupted" if stopping else "agent_staging_failed")
            elif stopping or time.monotonic() >= self.until:
                settle(self.child)
                self.child = None
                step = self._failed("interrupted" if stopping else "agent_staging_timeout")
        elif step == "agent":
            child = self.child
            if child.exited():
                status = child.finish()
                self.child = None
                self._restore_terminal()
                self.agent = ("ended", status)
                step = "done" if stopping else self._unstage()
            elif stopping:
                self._stop_agent()
                step = "done"
        elif step == "unstaging":
            child = self.child
            if child.exited():
                self.unstaged = child.finish() == 0
                self.child = None
                step = "done"
            elif time.monotonic() >= self.until:
                settle(self.child)
                self.child = None
                self.unstaged = False
                step = "done"
        self.step = step
        return step == "done"

    def end(self):
        """Every SSH of this session still running ends now (bounded);
        idempotent."""
        step, self.step = self.step, "done"
        if step == "staging" and self.child is not None:
            settle(self.child)
            self.agent = ("not_started", "agent_staging_failed")
        elif step == "agent" and self.child is not None:
            self._stop_agent()
        elif step == "unstaging" and self.child is not None:
            settle(self.child)
            self.unstaged = False
        self.child = None

    # -- the report --------------------------------------------------------

    def report(self, say_out, say_err):
        """The agent's own line and the staging warning, after the owner's
        end; its exit status (terminal restoration's failure fails it)."""
        if self.staged and self.unstaged is not True:
            # Neither consumed nor removed for certain: only reported.
            say_err(f"agentbox: warning: the staged payload's removal is unconfirmed (staging_left): "
                    f"/dev/shm/agentbox-agent-UID/{self.nonce} in the jail may hold the copied credential "
                    f"and the forwarded --env values; a managed jail's stop clears it, an attached jail "
                    f"keeps it until removed\n")
        kind, value = self.agent
        code = 1
        if kind == "ended" and value == 0:
            say_out("agent: exit=0\n")
            code = 0
        elif kind == "ended":
            text = "exit=255 (the agent's or SSH's own failure)" if value == 255 else \
                (f"exit={value}" if value >= 0 else "exit=signal (SSH ended by a signal)")
            say_err(f"agentbox: agent: {text}\n")
        elif kind == "stopped":
            say_err(f"agentbox: agent run failed (code={value}); the agent's session was ended by this command\n")
        else:
            status = "" if self.staging_status is None or self.staging_status < 0 \
                else f" staging_exit={self.staging_status}"
            say_err(f"agentbox: agent run failed (code={value}{status}); the agent was not started\n")
        if self.unrestored:
            say_err("agentbox: agent run failed (code=terminal_restore_failed); the terminal's settings from "
                    "before the session could not be set back (stty sane resets them)\n")
            return 1
        return code
