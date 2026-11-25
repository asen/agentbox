# Attach a jail over SSH

You provide confinement, resource limits, SSH access and cleanup. Agentbox pins the host key and uploads its worker. It does not provision the jail, prevent direct egress or lock the remote machine. Dedicate one jail to one run.

## Prerequisites

- Linux x86-64; Python 3.12+ with its standard library; POSIX `/bin/sh`; `uname`, `id`, `stat`, `mkdir`, `chmod`, `wc`, `sha256sum`, `cat`. Inputs and exports need `/usr/bin/tar` (GNU); export also needs `/usr/bin/env`.
- sshd with SFTP and reverse forwarding; permit a PTY for interactive shells. Restrict networking outside the jail, not with proxy variables.
- An existing directory writable by the SSH user, a [worker bundle](../packaging/README.md#attached-jails) and its source revision. Install task tools and any [handler prerequisites](artifact-requests.md#jail-prerequisites) in the jail.

## Target and first command

Replace the placeholders. `python` is optional: by default the worker uses `python3` on a fixed system PATH, not the login shell's PATH.

```json
{"schema":"agentbox.ssh-target.v3","host":"jail.example","port":22,
 "user":"agent","identity":"/absolute/path/to/unencrypted_ed25519_key",
 "host_key":"ssh-ed25519 <BASE64>","remote_root":"/existing/writable/directory",
 "python":"/usr/bin/python3","bundle":"/absolute/local/bundle",
 "revision":"<40 or 64 lowercase hex digits>"}
```

```sh
agentbox jail create --ssh-target target.json   # local record only; prints JAIL
agentbox jail exec JAIL -- /usr/bin/id
agentbox jail export JAIL --to result.tar
```

No trust on first use. The target selects the key, user and identity; no ambient SSH agent or config. `jail exec` passes argv without a shell. Use [`run AGENT`](agents.md) for a supported coding agent.

## What persists

Each execution uploads a fresh worker release. The task keeps `HOME` at `<remote_root>/agentbox-worker-v1/home` and works in `home/work`. Copied inputs are staged once. An interrupted input setup can block reuse (`inputs_setup_uncertain`).

`jail serve JAIL` followed by `agentbox shell JAIL` opens a PTY. A shell can outlive the serving execution, but its broker cannot. `jail discard` retires the local record, not remote files or processes. You remove prior releases, partial uploads and task data. No checkpoints or `--allow-unclean` on attached targets.

Export explicitly with `jail export` or during execution with `--export-to`. The host publishes an opaque archive without replacing an existing file; it never extracts it. See [storage and recovery](../src/README.md).
