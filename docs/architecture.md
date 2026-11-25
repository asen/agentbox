# Architecture

```text
trusted host                                      untrusted jail
controller ── provider ── create/start/stop       VM or container
     ├────── pinned SSH ────────────────────────► worker, command or agent
     └────── session server ◄── reverse forward ─ CONNECT or artifact request
```

The controller owns run records, leases and recovery. A trusted provider
owns the managed resource. For an [attached jail](ssh-worker.md), the
operator provides isolation, resource limits and cleanup. Guest reports
are not proof of isolation or settlement. No backend guarantees containment.

## One execution

1. The controller leases the run and starts the jail or connects to an attached target.
2. It starts a [session server](server-protocol.md), pins the SSH connection and stages requested inputs. A host adapter selects the invocation for `run AGENT`; the agent itself runs in the jail.
3. The command runs with the selected network policy. The controller captures output and records host and guest events separately. Guest output may contain secrets.
4. On exit or cancellation, the controller closes the session and settles the managed resource. An ambiguous stop blocks reuse. See [recovery](../src/README.md) before asserting a process has ended.

## Serve and shell

`jail serve` keeps a session open; `shell` joins it. Shells share the session's
network grants. Serve and interactive agent sessions have no runtime cutoff;
headless commands have a runtime limit only with `--timeout`. See [agent execution](agents.md).

## Host access

- A copied workspace is private to the jail. A mount is live. Read-only grants access to its contents; writable also grants authority to change host files. Podman resolves mount sources again on start. See [mount restrictions](../providers/README.md#shared-mounts).
- A credential selected with `--copy-auth` is readable by jail code. Neither deletion nor discard revokes it. A mounted credential directory may expose more than one account.
- The broker authorizes CONNECT destinations. Each approved tunnel uses a Rust relay. Filtering names and ports does not filter encrypted content or prevent exfiltration. Open policy includes host-local destinations. With `connect_proxy`, the upstream HTTP proxy resolves the approved name; there is no direct fallback.
- [Artifact requests](artifact-requests.md) use trusted host handlers. Policy selects what may be fetched. The guest receives the result, not a general host command or network socket.

## Storage and export

An owned disposable run is discarded. A retained jail restarts from storage,
not from a suspended process. Checkpoints, where supported, branch stopped
storage. Current-controller checkpoint create/restore lacks native qualification.
A storage admission threshold is not a filesystem quota.

Exports are explicit SSH reads: `jail export` for an attached jail, or
`--export-to` during a supported execution. The host treats the archive as
opaque, writes a private partial file, and publishes without overwriting.
It does not extract guest data. Failed cleanup may leave a partial and a
reservation. See [recovery](../src/README.md).
