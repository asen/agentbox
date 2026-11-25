# Host readiness

What the host must provide and what Agentbox does to it. Source:
`src/agentbox_controller/cgroups.py`, `host.py`, `doctor.py`.

## Prerequisites

- Linux x86-64, cgroup v2, a running systemd user manager on
  `/run/user/UID/bus` that supports scope `PIDFDs`, and `busctl`, `ssh`,
  `sftp`, `scp`, `ssh-keygen` in the host `PATH`. The host is trusted: a
  tool is the first executable regular file (links followed: a wrapper, a
  version manager's link) in the `PATH` the CLI started with, captured
  once. Only absolute, normalized, shell-inert entries count (no spaces,
  quotes, other bytes or trailing `/`); empty, relative and other entries
  are ignored, never the working directory; with none left nothing is
  found, and there is no fixed fallback. As root a tool and every directory
  above it must be root-owned and not group or world writable, and the tool
  not set-id or file-capable.
- Per provider: its own tools (QEMU/KVM, qemu-img, xorriso, Packer and its
  QEMU plugin; or rootless Podman, conmon, crun) as its README lists, found
  the same way; Python 3 for the provider itself (configured explicitly,
  never from `PATH`).
- Per artifact handler (pip, npm, Git): Python 3.11+ for its trusted worker
  (the acquisition configuration's `interpreter`, else `host.json`'s, else
  `/usr/bin/python3`; [selection](artifact-requests.md#selection)), with
  `ssl` and the system CA trust; Git also `git` 2.53+ from `PATH`
  ([artifact requests](artifact-requests.md#host-prerequisites)).
- `agentbox doctor` reports only platform, cgroup v2 and `ssh`/`ssh-keygen`
  presence, through the same lookup; it executes and opens nothing.

## Host environment

```text
CLI (captured once: env, PATH filtered, no AGENTBOX_*)
  -> controller (the holder), its workers  that environment
  -> provider control                      that + AGENTBOX_CUSTODY, _STORAGE_SCOPES
  -> ssh (stdio route) -> provider connect that - SHELL + LC_ALL=C + the two
  -> ssh (tcp route), scp, sftp            PATH + LC_ALL=C [or the proxy's, as above]
  -> host tools (ip busctl git ...)        PATH + LC_ALL=C [+ the tool's own fixed settings]
  -> packages worker (pip, npm)            LC_ALL=C only (runs no tool)
  -> guest / task                          nothing: its own explicit --env
```

`PATH` is the captured one wherever a host tool runs, so a wrapper found
there (a script, a version manager's shim) finds its own `#!/usr/bin/env`
interpreter as it would for the user.
The trusted provider receives the host's environment, proxies, credentials
and loader settings included, and decides what its own children get
(providers/README.md). Nothing of it is written to a record, log, event or
command line, and SSH forwards none of it (no `SendEnv`/`SetEnv`, agent
off). Variables that are not UTF-8 are not carried. A host whose
environment exceeds a launch's bounds (128 variables, 128 KiB with the
arguments) fails that launch.

No automatic `sudo`, firewall change, service installation or persistent
host reconfiguration.

## Launch context and custody

A managed execution or provider operation asks the user manager (`busctl`)
for one fresh transient `agentbox-launch-<hex>.scope` U (`Delegate=yes`,
`cpu memory pids`), moving the controller in by pidfd: fixed properties
only, no numeric-PID fallback. Attached runs and input staging use no
domain. No supervisor: the controller is the holder.

```text
agentbox-launch-<hex>.scope = U   transient, collected by systemd once empty
  controller/                     the holder, outside every limit
  agentbox-<hex>/ = D             custody domain: envelope limits, no process
    h-1 h-2 ...                   one leaf per child: provider owner,
                                  agentbox-server, each ssh, workers
    engine/ tool-*/ build/ ...    the provider's children
```

- Envelope defaults: 4 CPUs, 8192 MiB, 2048 PIDs (the provider
  configuration's `guard` or requested limits plus overhead replace a
  dimension). Written and read back, else refused; never weakened.
- D is killed only through `cgroup.kill`, settled once `cgroup.events`
  reads `populated 0`, never by PID or group. An empty D is host-cleanup
  evidence only, never provider settlement.
- A killed controller leaves U and D with whatever runs there; there is
  no automatic cleanup. A later explicit `jail stop` adopts D by its
  recorded path and identity only.
- Any manager absence, rejection, bad ownership, failed write or missing
  controller fails closed. Systemd delegation may enable controllers in
  shared ancestors; Agentbox manages only its own unit's subtree. Collection
  of the outer unit is systemd's and is not certified by any report.

## Crash collection: administrator hardening

Agentbox trusts the host kernel, hypervisor and administrator; ordinary
QEMU/KVM does not hide guest memory from them. Process-local defences:

- Every host target runs with `RLIMIT_CORE=0` (soft and hard) and an
  ignored `SIGXFSZ`.
- The QEMU provider sets `dump-guest-core=off`.

These do not promise zero crash artifacts: a piped `core_pattern` collector
(e.g. Apport) may ignore `RLIMIT_CORE` and keep reports outside Agentbox's
budgets and cleanup. Collector policy is the administrator's; it is not a
readiness gate, and Agentbox does not reconfigure it.

## Tests

The controller suite substitutes `FakeCgroups` over an owned directory
tree; it never touches the real user manager.
