"""`run [--image NAME | --jail JAIL] ... -- ARG...`: one command, no agent
and no shell (README.md, "One command"). Stdout carries only the
command's output, rendered inert as `jail exec`'s (display.py: control
bytes, bidirectional controls and invalid UTF-8 escaped, redirected too;
no binary passthrough); every line of agentbox's own goes to stderr.

```text
local checks   argv, --env values (before any effect)
--jail JAIL    jail exec of the existing run: never stopped or discarded
[--image NAME] jail create of the tag's image (else `default`), retention
               none, owned by this command -> jail exec -> jail discard
               once the execution settled; unsettled, or a pending create:
               kept, recovery printed
exit           the command's own code (`exited`), only with its output,
               capture, host cleanup and an owned run's discard all
               confirmed; any other end 125 (a signaled command too: the
               guest reports no number), usage 2
```

The numbers can coincide with the command's own (a command exiting 125
or 2). Owned: one interrupt list for the whole command
(host.share_signals); an interrupt stops the running step, and the
discard still runs, a fresh list counting only interrupts during it.
"""
from . import builtin, host, images, lifecycle
from .assets import guest_protocol, provider_protocol
from .display import emit
from .execute import Execution
from .host import HostError

FAILED = 125


def _say(stream, text):
    try:
        emit(stream.fileno(), text.encode())
    except (AttributeError, OSError, ValueError):
        stream.write(text)


class CommandRun:
    def __init__(self, system, controller, store, options, environ, err):
        self.system, self.controller, self.store = system, controller, store
        self.options, self.environ, self.err = options, environ, err

    def warn(self, text):
        _say(self.err, text)

    def run(self):
        from .cli import select_env
        options = self.options
        if guest_protocol.validate_argv(options["argv"]) is not None:
            raise HostError("argv_invalid")
        self.env = select_env(options["--env"], self.environ)
        # None: untimed once the guest is ready.
        self.timeout = int(options["--timeout"]) if "--timeout" in options else None
        if "--jail" in options:
            return self.execute(self.store.resolve(options["--jail"]), False)[0]
        tag = images.resolve(self.store.path, options.get("--image"))
        host.share_signals()
        run_id = self.create(tag)
        try:
            if host.SHARED:
                raise HostError("interrupted")
            code, settled = self.execute(run_id, True)
        except HostError as error:
            self.warn(f"agentbox: run failed (code={error.code}); the command was not started\n")
            return self.discard(run_id) or FAILED
        if not settled:
            self.warn(f"agentbox: the owned run {run_id} is kept: its execution is not confirmed settled; "
                      f"agentbox jail status {run_id}, agentbox jail stop {run_id}, then "
                      f"agentbox jail discard {run_id}\n")
            return FAILED
        return self.discard(run_id) or code

    def create(self, tag):
        try:
            run_id = lifecycle.create(self.system, self.store, tag["provider"], tag["image"], "none", {},
                                      provider_protocol.DEFAULT_USER, [], None, None)
        except HostError as error:
            run_id = getattr(error, "run_id", None)
            if run_id is None:
                raise
            # Nothing of the command in it: discarded (a pending one is
            # refused, reported).
            self.warn(f"agentbox: jail create failed (code={error.code})\n")
            self.discard(run_id)
            raise HostError("run_create_failed") from None
        self.warn(f"run: created id={run_id} kind=managed owned=true retention=none\n")
        return run_id

    def execute(self, run_id, owned):
        """(exit status, settled): the command's own code or FAILED."""
        lease = self.store.claim(run_id)
        try:
            execution = Execution(self.system, self.controller, self.store, lease, self.options["argv"], self.env,
                                  self.options.get("--stdin", False), self.timeout, report_err=True)
            try:
                execution.run()
            except HostError as error:
                if error.code == "storage_unclean" and not owned:
                    raise builtin.hinted("storage_unclean", f"check it with agentbox jail status {run_id}, then "
                                         f"agentbox jail exec {run_id} --allow-unclean GENERATION -- true") \
                        from None
                raise
            settled = lease.record["pending"] is None and execution.report.host_cleanup
        finally:
            lease.release()
        code = execution.report.exited()
        return (FAILED if code is None else code), settled

    def discard(self, run_id):
        """An owned run's discard, only an interrupt during it stopping it;
        0, else FAILED."""
        host.share_signals()
        try:
            lease = self.store.claim(run_id)
            try:
                result = lifecycle.discard(self.system, self.store, lease)
            finally:
                lease.release()
        except HostError as error:
            self.warn(f"agentbox: jail discard failed (code={error.code}); the owned run {run_id} remains: check "
                      f"agentbox jail status {run_id}, then agentbox jail stop {run_id} if an instance is pending, "
                      f"and agentbox jail discard {run_id}\n")
            return FAILED
        self.warn(f"discard: {run_id} {result}\n")
        return 0


def run(system, controller, store, options, environ, err):
    return CommandRun(system, controller, store, options, environ, err).run()
