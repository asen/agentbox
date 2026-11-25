# Provider contract v1

`src/agentbox_controller/provider.py` and `providers/protocol.py` implement framing, argv and exchange checks against shared fixtures. The controller manages custody and settlement; the [QEMU and Podman providers](../../../providers/README.md) implement the provider side of the lifecycle.

- [`contract.json`](contract.json): constants, field tables and value sets;
  each implementation asserts its constants match.
- [`fixtures.json`](fixtures.json): accepted/rejected frames, connect argv
  and whole exchanges with their expected outcome or error code.

A change to a rule below changes both implementations and the fixtures
together; an incompatible change is a new version.

## Roles

```text
 host (Python, trusted)               provider (Python, trusted, host-only)
   selects provider, entry, state  ->   one process per invocation
   stdin  : control frames  -------->   requests, stop, cancel
   stdout : control frames  <--------   one result per request
   stderr : diagnostics     <--------   bounded, never parsed
                                        launches and owns the jail

 ssh -> TCP loopback endpoint (tcp)  or  ProxyCommand: provider connect (stdio)
        raw SSH bytes only; never control frames
```

- The host selects the provider, its entry, its state directory and every
  request. Existing runs use the host's recorded provider binding, never a guest's selection or a provider's own claims. The jail cannot reach the
  control pipes, the state directory or the provider process.
- A provider is trusted host code. Its capability claims only let the host
  refuse requests early; they grant no artifact, network or policy authority
  and never relax a host check. The guest is untrusted; no guest byte reaches
  a control frame, argv or provider configuration.
- Control, task/bridge I/O and diagnostics stay on separate channels.
  Providers open no network listener except the loopback SSH endpoint of a
  `tcp` instance, and give the jail no route except that SSH transport (the
  host broker is reached over SSH's reverse forward). No guest engine socket, generic forward or direct egress. Host directory mounts require explicit grants and provider support.

## Invocation

The host runs `INTERPRETER -I ENTRY ARG...` with an absolute interpreter and
entry it selected, the host's environment (the CLI's, captured once: `PATH`
filtered to its usable entries, no inherited `AGENTBOX_*`) with the host's own
`AGENTBOX_*` variables set over it, stdin/stdout/stderr only (no other
inherited descriptor), inside the instance's or resource's custody domain
([Custody](#custody)). `ARG...` is exactly one of:

| argv after ENTRY | channel |
| --- | --- |
| `control STATE` | stdin/stdout: control frames |
| `connect STATE RUN EXECUTION INSTANCE` | stdin/stdout: raw SSH bytes |

`STATE` is an absolute path: `/`-separated components of
`[A-Za-z0-9._+-]`, none `.` or `..`, no empty component or trailing `/`,
at most 4096 bytes. `RUN`, `EXECUTION`, `INSTANCE` are ids. Every argument
is therefore shell-inert, as `ssh` runs a ProxyCommand through a shell.
Anything else is `invalid_argv`.

A `connect` invocation gets that environment through `ssh`, without
`SHELL` (so `/bin/sh` runs it) and with `LC_ALL=C`. A serving execution's
shell connection is the same
invocation as that shell's own `ssh` ProxyCommand: the host's `jail
shell-transport` entry, started by `ssh`, joins a fresh slot of the
domain (a direct leaf, at most 32 per execution), then replaces itself
with `connect` on ssh's pipes, its environment the shell caller's
captured one (no `SHELL`, no inherited `AGENTBOX_*`) with the owner's
`PATH` and the host's `AGENTBOX_*` set over it; `ssh` ends it (EOF,
`SIGHUP`), the owner's kill of the domain at the latest. Before E1 the
owner launched that bridge itself, a connected socket as its stdin and
stdout, handed to `ssh` (`ProxyUseFdpass`); the native results recorded
for that era are of that design. What a provider's own children inherit
is the provider's choice; none of it may reach a guest.

## Control framing

One UTF-8 JSON object per LF-terminated line, at most 16384 bytes without
the LF, nesting depth at most 3. Validation order and frame error codes are
those of [contracts/v1](../../v1/README.md#validation-order-and-error-codes)
steps 1-12 with these limits. `"v": 1`; another integer is
`unsupported_version`. Every field is listed below; there is no extension
field. Nested objects (`limits`, `transport`) follow steps 10-12 within
their field. Lists hold distinct known strings (`invalid_field` otherwise).
A partial line at end of stream is `truncated_frame`. Canonical encoding:
`v`, `type`, then table order, no whitespace.

Value grammar:

| name | rule |
| --- | --- |
| id | `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` |
| path | as `STATE` above |
| sha256 | 64 lowercase hex |
| timeout_ms | integer 1..86400000 (`limit_exceeded` above) |
| generation | safe integer >= 0 |
| ssh key | `ssh-ed25519 BASE64`, BASE64 the canonical 51-byte Ed25519 public blob |
| provider | `[a-z][a-z0-9-]{0,31}` |
| user | `[a-z_][a-z0-9_-]{0,31}` |

### Host to provider

Every request carries a fresh host-assigned `operation` id, never reused.
`run`, `resource`, `execution`, `instance` and `checkpoint` are
host-assigned handles, recorded by the host **before** the request is sent.

| type | fields (table order; `[]` optional) |
| --- | --- |
| `capabilities` | `operation`, `timeout_ms` |
| `prepare` | `operation`, `timeout_ms`, `recipe` path, `worker` path |
| `create` | `operation`, `timeout_ms`, `run`, `resource`, `image` sha256, `retention`, `user`, [`mounts`] |
| `start` | `operation`, `timeout_ms`, `run`, `resource`, `execution`, `instance`, `generation`, `accept_unclean` bool, `authorized_key` ssh key, `limits` |
| `status` | `operation`, `timeout_ms`, `run`, `resource`, [`execution`, `instance`] (both or neither) |
| `stop` | `operation`, `timeout_ms`, `run`, `resource`, `execution`, `instance`, `generation` |
| `discard` | `operation`, `timeout_ms`, `run`, `resource`, [`checkpoint`] |
| `checkpoint` | `operation`, `timeout_ms`, `run`, `resource`, `checkpoint`, `generation`, `accept_unclean` bool |
| `restore` | `operation`, `timeout_ms`, `run`, `resource`, `checkpoint`, `generation` |
| `cancel` | `operation` (the one in flight) |

`retention`: `none`, `home`, `home_tmp`, `disk`. `user`: the guest account
to provision, `[a-z_][a-z0-9_-]{0,31}` (`started.user`'s grammar);
`agentbox` (`default_user`) unless the provider declares `select_user`.
`mounts` (only with `host_mounts`, never with retention `none`): 1 to 8
objects of exactly `source` (path), `destination` (HOME-relative: plain
`[A-Za-z0-9._-]` components, no `.` or `..`; a hidden first one allowed,
`.pi` or `.ssh`, but one starting `.agentbox` only as `.agentbox-root/...`)
and `access` (`ro` or `rw`); each path at most 768
bytes; sources pairwise disjoint, destinations pairwise disjoint (neither
equal nor containing another). More than 8 is `limit_exceeded`. The
provider binds each source at `home/destination` from the next `start`
on, resolving the source path anew at every start; fixed for the
resource's life.
`limits`: an object of
optional `cpus` (1..256), `memory_mib` (64..1048576), `pids` (1..1048576),
`disk_mib` (1..16777216); 0 or below the minimum is `invalid_field`, above
the maximum `limit_exceeded`.

### Provider to host

| type | answers | fields |
| --- | --- | --- |
| `described` | capabilities | `operation`, `provider`, `operations`, `transport`, `retention`, `limits`, `features` |
| `prepared` | prepare | `operation`, `image` sha256, `worker_sha256`, [`agents`] |
| `created` | create | `operation`, `run`, `resource`, `retention`, `generation`, `user`, `home` path, [`volume`] |
| `started` | start | `operation`, `run`, `resource`, `execution`, `instance`, `generation`, `transport`, `user`, `host_key` ssh key, `worker_sha256`, `home` path, `control` path |
| `reported` | status | `operation`, `run`, `resource`, [`execution`, `instance`, `instance_state`] (all or none), `resource_state`, `generation` |
| `stopped` | stop | `operation`, `run`, `resource`, `execution`, `instance`, `settlement`, `durability`, `generation`, `storage` |
| `discarded` | discard | `operation`, `run`, `resource`, `settlement`, [`checkpoint`] |
| `checkpointed` | checkpoint | `operation`, `run`, `resource`, `checkpoint`, `generation`, `storage` |
| `restored` | restore | `operation`, `run`, `resource`, `checkpoint`, `generation`, `storage` |
| `failed` | any request | `operation`, `op`, `code`, `settlement`, `durability` |

- `described`: `operations` lists every required control operation
  (`capabilities`, `prepare`, `create`, `start`, `status`, `stop`,
  `discard`) and optionally both of `checkpoint`, `restore` (one alone is
  `invalid_field`). `transport` is `tcp` or `stdio`; `connect` works exactly
  for `stdio`. `retention` is a non-empty list; `limits` the enforceable
  limit names, possibly empty. `features`: distinct optional behaviours,
  possibly none, each independent of the others: `select_user` (`create`
  may name a user other than `agentbox`) and `project_layout` (the host
  may place an explicit workspace at its own HOME-relative project
  location, the working directory beneath `home`), `host_mounts`
  (`create` may carry `mounts`) and `explicit_retention` (retained storage
  lives outside the provider's STATE, e.g. Podman's shared store: a host
  creates it only on the operator's explicit request, never as a default
  or a preference fallback). They let the host refuse early and grant
  nothing.
- `prepared`: `agents` (optional) names the image's baked coding agents,
  exactly `pi`, `codex` and `claude`, each a plain npm version
  (`MAJOR.MINOR.PATCH[-PRERELEASE]`): what the provider measured in the
  image it built, for the operator's display; it grants nothing. A
  provider that knows none sends none.
- `created`: `user` is the request's (else `binding_mismatch`; a restored
  resource's request names its source's user), `home` its HOME. The host
  fixes both for the resource's life and requires every `started` to name
  exactly them. `volume` (optional, `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`):
  the engine's name of a retained HOME kept outside the provider's STATE,
  for the operator's display only; never a handle.
- `transport` in `started`: `{"kind":"tcp","host":"127.0.0.1"|"::1","port":1..65535}`
  or `{"kind":"stdio"}`.
- `home` and `control` in `started`: the session layout, engine-neutral.
  `home` is the guest user's HOME (copied inputs and the working directory
  beneath it: the run's project location, else `home/work`); `control` an
  existing directory, neither under
  nor above `home`, where the host's per-execution bootstrap installs its
  launcher (the host refuses any other pair). Neither grants anything.
- `stopped`: `settlement` is only `settled`; `durability` `retained` requires
  `storage` `clean`, `uncertain` requires `unclean`.
- `discarded`: `settlement` is only `settled`.
- `failed`: `op` is the request type; `code` one of `unsupported`,
  `not_found`, `binding_mismatch`, `exists`, `busy`, `generation_mismatch`,
  `unclean`, `partial`, `prerequisite`, `cancelled`, `timeout`, `failed`,
  `user_conflict` (`create`: the image already names the user; nothing
  made), or a `host_mounts` refusal of `create` or `start`:
  `mount_source_unavailable`, `mount_source_unsupported`,
  `mount_source_protected`, `mount_source_overlap`,
  `mount_destination_unsafe`, `mounts_need_memory`, or a shared engine
  store's (Podman `store` shared): `shared_store_uninitialized` (its helper
  not demonstrably running or not recognized; nothing ran),
  `shared_image_missing` (the prepared image is not in that store), `retained_home_missing` (`start`: the retained
  HOME is gone from that store; never made again). A code names a cause,
  never a path or value, and grants nothing; a `start`'s validated code is
  reported to the operator as `provider_code` (host: its `runtime_failed`
  final line and `jail status`'s last execution).

## Exchanges

One control invocation carries one request. `start` is the exception: its
invocation is the instance's **owner session**.

```text
host:      start ----------------------------> [cancel] --> stop ---> [cancel]
provider:        <- started (instance live) ..... waits ....  <- stopped | failed
                 <- failed (instead of started)
```

Host-side exchange checks, in both implementations, fail closed:

| check | error |
| --- | --- |
| request op not in `described.operations`; `discard` with `checkpoint` without the optional operations | `unsupported_operation` |
| `create.retention` not in `described.retention`, `create.user` other than `agentbox` without `select_user`, `create.mounts` without `host_mounts` or with retention `none`, a `start.limits` key not in `described.limits` | `unsupported_capability` |
| response `operation` differs, `failed.op` differs, or `stop`/`cancel` names the wrong operation | `operation_mismatch` |
| an echoed `run`/`resource`/`execution`/`instance`/`checkpoint`/`retention`/`user` differs, `discarded.checkpoint` present without the request's (or absent with it), `checkpointed` `unclean` without `accept_unclean`, or a `stop` binds another instance | `binding_mismatch` |
| `started.generation` != request; `created` != 0; `checkpointed` != request; `restored` != request + 1; `stopped` != request (`unchanged`) or request + 1 (otherwise); `stop.generation` != `start.generation` | `generation_mismatch` |
| `started.worker_sha256` != the prepared image's | `worker_mismatch` |
| `started.transport.kind` != `described.transport` | `capability_mismatch` |
| wrong result type, a frame after the terminal one, provider output while the owner session waits, a second cancel, a host frame out of turn | `unexpected_frame` |

Any frame error or exchange error is final and ends the exchange as
`error`: settlement `unknown`, durability by the lost rule below. It
**poisons** an earlier terminal frame: a valid `stopped` or `discarded`
followed by any further frame (well-formed or not) settles nothing. The host
ends the invocation and settles through fresh `status`, `stop` or `discard`
invocations. A request refused before it is sent has no outcome.

Encoders validate the frame as given, nested `limits` and `transport`
included, before canonicalizing; an unknown or invalid field is refused,
never dropped. An encoder never emits a frame its peer's decoder would
refuse (fields, nested values, size); refusal is a frame error code.

### Outcomes

Four facts stay separate:

| fact | who reports | established by |
| --- | --- | --- |
| command result | guest protocol | the guest `exit` frame; says nothing about resources |
| host cleanup | host | Agentbox's own processes, sockets and files gone |
| resource settlement | provider | `stopped`/`discarded` (`settled`), or `failed.settlement` |
| durability | provider | `stopped.durability`/`storage`, `failed.durability`, `reported` |

- `settlement`: `settled` (every process the operation or instance
  started, engines, bridges and tools included, is confirmed gone and its
  retained storage is in the state reported), `unsettled` (a possible
  writer or retained-storage effect remains; the handle needs `stop` or
  `discard`), `unknown`.
- Disposable state (engine stores, scratch, logs, cache staging) is
  cleaned up best effort once every writer is confirmed gone: a path is
  removed only while it is still the provider's pinned original, never a
  changed or foreign one; what is left is residue, reported by a fixed
  `warning:` diagnostic line, never `unsettled` and never a reuse block.
  Providers bound residue by capacity admission (`prerequisite` when free
  space or leftover entries are exhausted), not quotas. Caches are
  recoverable: entries are verified before use; a missing or invalid one
  invalidates the hit and is rebuilt; publication never replaces a name;
  an invalid entry is moved aside only when no provider record uses it,
  else it stays as it is (a base in use is never rebound).
- `durability` of the resource's retained storage: `unchanged`, `retained`
  (written and confirmed; generation advanced, `clean`), `uncertain`
  (possibly written, not confirmed; generation advanced, `unclean`).
- Provider exit status, EOF, a killed provider or process group, an empty
  custody domain, SSH disconnect, guest poweroff or the command's exit never
  establish settlement. An invocation
  ending without its terminal frame is **lost**: settlement `unknown`;
  durability `uncertain` for `create`, `start` (also after `started`),
  `stop`, `discard` and `restore`, else `unchanged`.
- `reported.instance_state` `settled` is the provider's settlement
  confirmation for a lost instance; `resource_state` and `generation` are its
  storage report.

### Reuse

The host keeps every handle whose last operation is not confirmed (pending,
lost, `error`, `unsettled`, `unknown`) in custody: no `start`, `create` on
the same run, `checkpoint` or `restore` until `status`, `stop` or `discard`
confirms it. Reuse and the end of `discard` need both a positive provider
settlement for the explicit handle and the host's positive settlement of
every process of that operation ([Custody](#custody)); neither alone
suffices. A provider refuses `start` on a resource with a live or unsettled
instance (`busy`), a partial resource (`partial`), a generation other than
its record (`generation_mismatch`) and, without `accept_unclean`, an unclean
one (`unclean`). Only `discard` applies to a partial resource.

`resource_state`: `absent` (no resource under the handle), `ready` (clean),
`unclean`, `busy` (live or unsettled instance), `partial` (incomplete
create/restore/discard). `instance_state`: `absent`, `live`, `settled`,
`unsettled`.

## Handles and ownership

- Handles are host-assigned and bound at creation: a resource to its run, an
  instance to its run, resource and execution, a checkpoint to its source
  run and resource (provenance; it does not share their lifetime).
  The provider names its private state by handle before any effect, so a
  partial `create` or `start` is found by the same handle. A handle with
  another binding is `binding_mismatch`, an unknown one `not_found`, a reused
  one `exists`. Process ids are never handles.
- **Owner session.** After `started` the start invocation keeps running as
  the instance's owner, inside the instance's custody domain, and the
  provider records the instance by handle. It writes nothing until the host's `stop` (or a
  `cancel` before `started`). The session ends with `stopped` or `failed`.
  A start's own `failed` before `started`, `settled` with durability
  `unchanged`, is the provider's settlement of that instance handle (it may
  never have been recorded, so a later `stop` answers `not_found`); the host
  still needs its own process settlement before reuse.
- **Cancellation.** `cancel` asks the in-flight request to stop; the
  provider still answers it (`failed` `cancelled`, or the result if it
  finished first). After `timeout_ms` the host cancels; 30000 ms later it
  kills the invocation's processes through its custody domain: that
  invocation is lost.
- **Host or worker loss.** EOF on the provider's stdin before the session
  ends is an unreported cancel: the provider force-stops what it started,
  records the result by handle and exits. Nothing it does then counts until
  a later `status`/`stop`/`discard` reports it.
- **Provider loss.** A provider gone without its terminal frame is lost. The
  host closes its SSH/SFTP processes while the custody domain is held, kills
  and reaps every process in it, and may run one standalone `stop` there.
  Any later settlement is a standalone `stop` (idempotent: an already
  settled instance answers `stopped`), `status` or `discard` using the
  recorded handles, in a fresh domain ([Custody](#custody)).
- **Connect.** A stdio `connect` serves raw SSH bytes for one live
  instance, verified by its run, execution and instance; it writes no
  control frame and its exit status is not authority. Several may run at
  once (session, SFTP, a serving execution's shell bridges), each in the
  instance's custody domain. The owner
  keeps the instance's private engine state alive until every one of them
  has ended and `stop` is processed.
- **Descendants.** The host's worker is a subreaper and confirms an
  instance's transports ended only when none of its children is outside
  the owner's session. A provider whose engine detaches processes keeps
  them as its own descendants (on Linux, each invocation a child
  subreaper). A `connect` that ends normally has itself reaped every
  descendant it adopted; a settled answer, the owner's included, is sent
  only once the provider positively confirmed every child it adopted
  reaped, else that answer is `unsettled`. An abrupt death (`SIGKILL`)
  confirms nothing: what that process adopted passes to the host, whose
  barrier then refuses and whose custody domain settles it.
- **Authentication.** The host generates a fresh client key per managed
  execution and sends only its public half (`authorized_key`). The provider
  installs it and a fresh guest host key before sshd starts, also on a
  retained or restored resource, keeps them outside retained HOME, and
  returns the host key's public half (`host_key`) for the host's pinned
  `known_hosts`. No private key crosses control. `worker_sha256` binds the
  baked worker of the prepared image; the guest protocol's hello still
  verifies the session.

## Custody

```text
host holder (the controller; outlives provider)
  holds custody domain D(instance)   <- created before start, released last
    start owner --- engine/VMM children --- daemonized engine helpers
    connect #1 (ssh session) --- podman exec / bridge descendants
    connect #N (sftp uploads) --- ...
    first fallback stop (after every earlier process is killed and reaped)
  kill D, reap all -> processes `settled` recorded -> D ends with its holder
later: standalone stop/status/discard in a fresh D, only after `settled`
```

- Each managed instance, and each resource operation that may leave
  processes (`prepare`, `create`, `discard`, `checkpoint`, `restore`), runs
  in one **custody domain** created and held by the host (the Python
  controller since D3; the old CLI's supervisor before): a container whose membership every descendant inherits and
  cannot leave by forking, daemonizing, `setsid`, double fork or
  reparenting to init or a subreaper (on Linux a supervisor-owned cgroup
  with delegation as the generic mechanism; never a process group or
  ancestry walk alone).
- One domain per instance covers the start owner, every engine/VMM child
  and helper, every concurrent `connect` invocation and all its bridge
  descendants, and standalone `stop`/`status` for that instance. The host
  starts each of them directly inside it (a shell's `connect`: the host's
  transport entry joins its leaf before it becomes `connect`).
- The domain is held by the host, not the provider, and stays live across
  provider death until the host has killed and reaped every process in it.
  It is temporary containment, never a resource's identity. A killed
  controller may leave it populated; only an explicit later recovery
  adopts it, by its recorded path and identity
  ([crash contract](../../../docs/server-protocol.md#crash-contract)). The host kills and reaps through the domain itself (all
  members), never by PID, process group or session.
- A provider must keep every process it starts inside its invocation's
  domain; engines must be configured so (for example no detached helper
  started outside it). This is the provider's backend knowledge; the host
  holds no engine-specific logic. If the host cannot establish a
  domain, the operation is refused.
- A killed, emptied, missing or reaped domain is **host cleanup** evidence
  only. It says nothing about state outside processes (disks, volumes,
  engine stores, checkpoints, private state) or anything the provider
  placed elsewhere. Reuse and discard completion need the provider's
  positive settlement for the explicit resource/instance handle **and** the
  host's process settlement below; process group kills, EOF, exit status or
  an empty domain alone prove nothing.
- **Host process settlement.** The host records, with each operation it
  sends and before its first effect, a process fact of that very operation
  (bound to its resource, instance where one exists, generation and
  operation handle; for a checkpoint-only operation its operation handle):
  `unknown`, and `settled` only once the domain's holder killed it, read it
  empty and reaped every process, the last helper's included, while still
  holding the object's lease. A new operation on the object replaces the
  fact with its own `unknown` before any effect; nothing infers it from an
  empty or missing domain, EOF or an exit. Missing or `unknown`, the object
  stays blocked for explicit operator recovery.
- **Standalone lifecycle cleanup (trusted host precondition).** The host
  sends a standalone `stop`, `status`, `discard`, `checkpoint` or `restore`
  for a handle in a fresh domain only once the previous operation's
  processes are recorded settled. A provider may therefore treat children
  it recorded with another domain as gone: it drops those records without
  signalling, removing or observing anything of them. It still strictly
  validates its current containment and its own children in the current
  domain, retained storage pins and native store identity, and never
  deletes a replaced or unowned retained path. Settling processes grants no
  reuse: that still needs the provider's confirmation of the resource.
- The live owner session settles its own live children normally (orderly
  shutdown included) in its own domain.
- Interface (Linux): D is a cgroup v2 directory delegated to the provider's
  user, `cpu memory pids` in its `cgroup.subtree_control`, no process of its
  own. The host starts each invocation in a fresh leaf directly under D and
  names D in the environment as `AGENTBOX_CUSTODY`. A provider
  verifies that its `/proc/self/cgroup` leaf is a child of D and creates
  further children of D for what it starts (limits written and read back
  first; every process joins before it runs), records each with D's
  identity before it exists, and kills and removes them by that record.
  In D, only removal of the very child (or its pinned directory found
  removed) settles it; a denied or ambiguous observation is `busy`
  `unsettled`. A child recorded with another D is settled by the host's
  precondition above. Status and capabilities need no domain; any other
  operation without one is `failed` `prerequisite`.
- Storage scopes: the environment also names the host's limits file as
  `AGENTBOX_STORAGE_SCOPES` (one absolute path, the operator's
  `run-limits.json`; storage configuration, never authority). Before any
  NEW allocation (`prepare`, `create`, `start`, `checkpoint`, `restore`) a
  provider reads it (no link, trusted ancestors, ours, 0600, bounded, the
  host's exact validity rule) and requires `STATE`, each directory it is
  about to make a new entry in and every external store root, as opened,
  to lie in a declared scope by actual filesystem membership (under a
  `filesystem` scope on its device; under a `tree` with every directory
  down to it on the tree's device or a measured filesystem's); absent, invalid or undeclared is `failed` `prerequisite` before
  any effect. Status, stop, discard and connect never read it: disposal
  uses the locations recorded when the data was made, never a later edit
  of the provider's inputs, and no capacity threshold refuses it. The host
  measures every declared scope itself; nothing of it is a quota.
- Host side: plan step 5 (custody domains, connect bridge membership,
  reaping, the process fact and settlement gating), fault tests in step 7.

## Optional operations

`checkpoint` and `restore` are stopped-storage operations, advertised
together or not at all (with them, `discard` of one checkpoint); the host
never sends an unadvertised operation and a provider answers one with
`failed` `unsupported`. Save and branch, not a universal snapshot API:

```text
checkpoint(R, C, g, accept_unclean)   R stopped at g -> C (copy, R untouched)
restore(R2, C, g2)                    R2 stopped at g2, same image as C
                                      -> R2 storage = C, generation g2 + 1
discard(R, checkpoint C)              C only; R = C's source binding
```

- `checkpoint` saves the storage of `generation` under a new handle, which
  records its source run, resource, generation and `storage`. Clean storage
  needs nothing; unclean storage needs `accept_unclean` (else `unclean`).
  `checkpointed.storage` is the saved state.
- A checkpoint is an independent provider object: discarding its source
  resource leaves it; only `discard` naming it removes it (also after the
  source is gone, settling nothing about the source).
- A `checkpoint` answered `failed`, `settled`, durability `unchanged` left
  nothing published under its handle. The host keeps that registration
  `failed` (never restorable); its `discard` answered `not_found`
  (`settled`) retires the registration only (metadata, no claim that any
  data was deleted). For any other checkpoint `not_found` settles nothing.
- A `create` answered `failed` `user_conflict`, `settled`, durability
  `unchanged` made nothing. The host keeps a new run's (not a restore's)
  partial and marked; its `discard` answered `not_found` (`settled`)
  retires the run only (metadata). For any other resource `not_found`
  settles nothing.
- `restore` replaces the storage of any resource without a live or
  unsettled instance whose image is the checkpoint's (`binding_mismatch`
  otherwise): its source (rollback) or a resource newly created for the
  branch (`create`, then `restore`). The result is `generation` + 1 with the
  checkpoint's `storage`: an unclean checkpoint restores unclean, and its
  `start` needs `accept_unclean`. The checkpoint and every other resource
  stay unchanged.

## Prepared image metadata

The one fixed file layout the host reads in `STATE`: after `prepared`,
`STATE/images/IMAGE/worker-metadata.json` (IMAGE the `image` digest) is the
baked worker's `agentbox.worker-build.v1` metadata
([images/worker](../../../images/worker/README.md)), a regular file of at
most 1 MiB reached without links. The host reads it once when a run is
created on IMAGE, requires `release` (= `worker_sha256`) to be the SHA-256
of its exact `manifest` text and that manifest to be a valid worker
manifest, and records both: `started.worker_sha256` must name that release,
and the bootstrap verifies the baked files in place against that manifest.
Nothing else in `STATE` is read by the host; no payload is duplicated on
the host and nothing in the file grants authority.

## Diagnostics

stderr is diagnostics only: the host keeps at most 65536 bytes per
invocation, drains and counts the rest, never parses it, never forwards it
to a jail and never bases a decision on it. Providers write no secret there.
Error codes never echo frame content.
