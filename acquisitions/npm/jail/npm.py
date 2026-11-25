"""The npm handler's jail module and its `npm` and `npx` shims: ordinary
npm and npx, with this execution's host `npm` handler as their registry.

    npm ARGS... | npx ARGS...
      the real command: the first `npm`/`npx` on PATH outside Agentbox's
        command directories (a directory holding `agentbox-request`)
      inside an adapted npm (AGENTBOX_NPM_REGISTRY set: a lifecycle script,
        npm's own children) or without a request context: the real
        command as is, nothing more
      otherwise: one registry adapter for this process (registry.py), the
        real command its child with these defaults in its environment:
          npm_config_registry=ADAPTER  npm_config_replace_registry_host=always
          npm_config_noproxy=127.0.0.1,localhost  npm_config_audit=false
          npm_config_fund=false  npm_config_update_notifier=false
          npm_config_fetch_retries=0  npm_config_fetch_timeout=1860000
          AGENTBOX_NPM_REGISTRY=ADAPTER
        its status this command's; the adapter closed (an active host
        request cancelled, its spool removed) once the child ended

Defaults, not a boundary: a command line, `.npmrc` or lockfile naming
another registry reaches past the adapter to the broker, whose policy
applies as to any guest process. Lifecycle scripts run as npm runs them,
under the jail's general restrictions. SIGINT, SIGTERM and SIGHUP reach the
child; the adapter ends with it."""

if __name__ == "__main__":
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import asyncio
import os
import sys

from acquisitions.npm.jail.registry import KEY_WAIT, Adapter, fetch_batch
from guest.src.abort import SIGNALS
from guest.src.artifact_post_context import context_from_environment
from guest.src.counterpart import serve

ADAPTER_ENV = "AGENTBOX_NPM_REGISTRY"
# npm's own per-fetch timeout, past the adapter's KEY_WAIT: the adapter
# answers first (504), never npm's default 5 min while a host request runs.
FETCH_TIMEOUT_MS = int(KEY_WAIT * 1000) + 60000
# Agentbox's own command directories hold this one.
MARKER = "agentbox-request"
NOT_FOUND = 127


def real_command(name, path):
    """The first executable regular `name` in the PATH string `path`,
    skipping relative entries and Agentbox's command directories; None."""
    for directory in path.split(":"):
        if not directory.startswith("/") or os.path.lexists(os.path.join(directory, MARKER)):
            continue
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def adapted_environment(env, url):
    """The child's environment: `env` and the adapter's defaults."""
    child = dict(env)
    child.update({
        "npm_config_registry": url,
        "npm_config_replace_registry_host": "always",
        "npm_config_noproxy": "127.0.0.1,localhost",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_update_notifier": "false",
        "npm_config_fetch_retries": "0",
        "npm_config_fetch_timeout": str(FETCH_TIMEOUT_MS),
        ADAPTER_ENV: url,
    })
    return child


def report(line):
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


async def adapted(real, argv, env, context, fetch=fetch_batch, spool_parent=None):
    """The real command as the adapter's child (module documentation); its
    status, 128 + the signal's number when killed."""
    adapter = Adapter(lambda operation, args, abort: fetch(context, adapter.spool, operation, args, abort),
                      report, spool_parent)
    child = None
    loop = asyncio.get_running_loop()

    def forward(number):
        if child is not None and child.returncode is None:
            try:
                child.send_signal(number)
            except ProcessLookupError:
                pass

    for number in SIGNALS:
        loop.add_signal_handler(number, forward, number)
    try:
        await adapter.start()
        try:
            child = await asyncio.create_subprocess_exec(real, *argv, env=adapted_environment(env, adapter.url))
        except OSError:
            report("agentbox-npm: %s could not be started" % os.path.basename(real))
            return NOT_FOUND
        code = await child.wait()
        return 128 - code if code < 0 else code
    finally:
        for number in SIGNALS:
            loop.remove_signal_handler(number)
        await adapter.close()


def shim(name):
    async def run(argv):
        env = dict(os.environ)
        real = real_command(name, env.get("PATH", ""))
        if real is None:
            report("agentbox-npm: %s: command not found" % name)
            return NOT_FOUND
        context = context_from_environment(env)
        if env.get(ADAPTER_ENV) or context is None:
            # Nested in an adapted npm, or no request lane: the real command.
            os.execv(real, [real, *argv])
        return await adapted(real, argv, env, context)

    return run


if __name__ == "__main__":
    sys.exit(serve(sys.argv[1:], {"npm": shim("npm"), "npx": shim("npx")}))
