# Artifact requests

A jail can request an artifact without direct access to a registry or repository:

```text
guest request → host policy → trusted handler → verified file → SSH upload → guest applies
```

The host authorizes the handler, operation and arguments. A delivery proves transfer, not successful installation. Guest results are untrusted. Package names and repository selectors reach the upstream service from the host.

## Selection

`jail exec`, `jail serve`, interactive `run AGENT` and `dev` select a configuration once, before jail work. First match wins:

1. `--acquisition-config FILE`, then for `dev`, its configured `acquisition_config`.
2. `$XDG_CONFIG_HOME/agentbox/acquisition.json` (default `~/.config/agentbox/acquisition.json`).
3. If the default file is absent, packaged policies for npm, pip and public GitHub.

An explicit file must exist. Invalid configuration refuses the session; there is no fallback. Configuration **replaces** the defaults. For example, omit Git but keep both package indexes:

```json
{"schema":"agentbox.acquisition-config.v2","handlers":{"npm":{},"pip":{}}}
```

Use `"handlers":{}` to disable the lane, its shims and its spool reservation. Empty handler entries select packaged policies; custom asset trees need explicit policies. Each handler can restrict `operations`. See [examples](../examples/acquisition/README.md).

Headless `run AGENT` has no general lane. [`--install-agent`](agents.md#install---install-agent) enables npm alone. `run -- COMMAND` has no lane.

## pip

Ordinary pip uses a session-local index. The default policy permits `pypi.org/simple/` and distribution files from `files.pythonhosted.org/packages/`. Resolution, installation and source builds run in the jail. See [pip contract](../acquisitions/pip/contract/v1/README.md).

## npm

`npm` and `npx` shims use the configured registry (default `registry.npmjs.org`). The host supplies metadata and verified tarballs. Lifecycle scripts execute in the jail; this is not script approval. Alternate registry settings are subject to ordinary broker policy. See [npm contract](../acquisitions/npm/contract/v1/README.md).

## Git

The default policy allows anonymous clone and fetch from public GitHub repositories. No push, private credentials, submodules or LFS. See [Git operations](../acquisitions/git/contract/v1/README.md). `agentbox-request ID OP '{...}'` saves a delivered file without applying it.

## Host prerequisites

Handlers need Python 3.11+, SSH and SCP; npm and pip need TLS and system CA trust. Git needs host Git 2.53+ with libcurl 8.4+. Missing host Git refuses a session with Git enabled; omit that handler to proceed without it. Declare `DATA/controller-spool` in storage scopes. Enabled sessions reserve 2 GiB; Git's upstream transfer is unmetered.

## Jail prerequisites

Provide Git 2.53+ at `/usr/bin/git`, npm and npx behind the shims, or Python with venv and ensurepip, as appropriate. Package adapters need writable temporary space; source builds also need their build tools. Managed images supply the clients. Attached jails are the operator's responsibility.

## Interactive sessions

All logins and the agent share one serving execution's grant: 256 requests, 2 GiB, one active request. Reconnecting does not reset it. Individual requests remain timed (1800 s) even in an untimed session. Full capture closes the lane, not the execution. Stopping the owner revokes the grant; unconfirmed cleanup retains the spool reservation for `jail stop` to recover.

Wire and worker references: [POST](../acquisitions/contracts/artifacts/post-v1/README.md), [timing](../acquisitions/contracts/artifacts/v1/README.md), [handler interface](../acquisitions/contracts/handlers/v1/README.md).
