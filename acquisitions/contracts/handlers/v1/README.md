# Handlers v1

Trusted host acquisition handlers. The controller owns identity, permissions,
budgets, deadlines, cancellation, supervision, staging, upload and the one
terminal outcome; a handler's Python worker owns policy, argument and
content semantics. Bounds: [contract.json](contract.json).

```text
operator: --acquisition-config FILE
  {"schema":"agentbox.acquisition-config.v2","interpreter":ABS,"assets":ABS,
   "handlers":{"pip":{"policy":ABS},"git":{"policy":ABS,"operations":["clone"]}}}
      |
      v   preparation: config, each manifest, each listed file, all of lib,
      |   interpreter and tools trust-checked once (point in time); policy
      |   text snapshotted (strict JSON object, manifest bound)
ASSETS/acquisitions/
  lib/agentbox_handler.py ...       explicit trusted import dir
  ID/manifest.json                  id (never `lib`), version, entry, files,
                                    operations, metering, tools, limits,
                                    jail {entry, shims, session}
  ID/host/worker.py                 the trusted worker (entry)
  ID/jail/...                       its jail sources, worker bundle input only
      |
guest POST submit {handler, operation, args}  (acquisitions/contracts/artifacts/post-v1)
      |   lane: request grant (256, every attributable submission), busy,
      |   enabled, permitted, args bytes; `http` metering: acquired-byte
      |   allowance left, reserved whole for the worker
      v
STAGE = <root>/request-<hex>/   (0700, fresh)
  request.json  (0600, O_EXCL)  host-written, see below
  artifact      (0600, O_EXCL)  worker-written
INTERPRETER -I -B ENTRY acquire STAGE/request.json
  own process group; killed + reaped on stop, cancel, deadline
  stdout: exactly one result line
      |
      v   host: line grammar, artifact private regular file of stated size,
      |   metadata bounded, the allowance settled to `acquired`, provenance
      |   recorded; then one scp to WORK/.agentbox-requests/
      |   SESSION-REQUEST.artifact; ready {size, sha256, metadata}
guest: the handler's own shims (jail module) or the generic
`agentbox-request`, which saves the file
```

## Request file

```json
{"schema":"agentbox.handler-request.v1","handler":"pip","version":"1",
 "operation":"files","args":{"projects":["requests"]},"policy":{...},
 "ids":{"run":R,"execution":E,"session":S,"request":Q,"request_sha256":H},
 "stage":"/root/request-<hex>","artifact":"/root/request-<hex>/artifact",
 "remaining_ms":N,"tools":{"git":"/usr/bin/git"},
 "limits":{"metadata_bytes":N[,"acquire_bytes":N]}}
```

`args` are the guest's, admitted by grammar and size only. `policy` is the
operator's snapshot, never the guest's. `acquire_bytes`, exactly for an
`http`-metered handler: the upstream HTTP body bytes it may read. `test` (a
loopback endpoint and a CA) exists only in the host's test build.

## Result line

```json
{"schema":"agentbox.handler-result.v1","outcome":"ok","size":N,"sha256":HEX,"metadata":{...},
 "provenance":[{"name":N,"version":V,"integrity":"sha512-.."}],"acquired":N}
{"schema":"agentbox.handler-result.v1","outcome":"error","code":"pip_args_invalid","acquired":N}
```

An error code reaches the guest as `closed denied` with that `reason`,
attributed to the handler. `acquired` is required on every line of an
`http`-metered worker (`0..=acquire_bytes`) and absent otherwise.
`provenance`, `ok` only, at most 256 entries (`NAME` or `@SCOPE/NAME` at most
214 bytes, a version (pip: a file name) of `[0-9A-Za-z.+!_-]` at most 256,
`sha512-`/`sha256-`/`sha1-` base64): the packages the worker fetched, recorded by the host
(`host.handler.provenance`), never sent to the guest. Anything else (no
line, two lines, a bad grammar, a missing or wrong artifact) is a fixed
host failure; worker stderr, raw arguments and the policy never leave the
host. A line is at most 256 KiB.

## Limits

Each manifest may lower the ceilings (policy 128 KiB, args 60 KiB, metadata 62 KiB,
acquisition 600 s); absent ones are the ceilings. No per-handler request
or attempt allowance:

| bound | value | charged |
| --- | --- | --- |
| requests | 256 per execution, every handler's | every attributable submission: busy, refused, denied alike; each starts at most one worker (attempts are counted, not limited) |
| acquired bytes | 2 GiB per execution, `http` handlers' | upstream HTTP body bytes read: metadata, failed and partial bodies included |

Acquired bytes: a worker gets the whole remaining allowance, reserved and
charged at its start; its line's `acquired` settles the charge. No valid
line (killed, crashed, malformed, cut by a deadline or stop) keeps the
reservation charged; no worker started refunds it. With nothing left an
`http` handler is denied `byte_limit` before any worker; `none` handlers
(Git, test handlers) are outside the allowance and keep their own bounds.
Upload bytes (scp) are delivery, not acquisition. Nothing resets within an
execution.

## Trust

The interpreter, asset tree, `acquisitions`, every manifest and every
listed file are checked once at preparation as provider assets are (no
link, ours or root's, not group/world writable). So is everything in `lib`,
listed or not: workers put it before the standard library on `sys.path`,
so an unlisted `lib/json.py` would shadow `json`. Every entry there is a
trusted directory or regular file, never a link, FIFO or device, at most
256 entries 8 levels deep. This is a point-in-time check of a trusted
tree, not a sandbox: a worker may import anything its interpreter can,
and `lib` is the one directory the shipped workers add to `sys.path`.

## Jail counterparts

```text
bin/agentbox-request = PYTHON guest/src/request_main.py "$@"
bin/SHIM             = PYTHON ENTRY shim SHIM "$@"      (enabled handlers' shims)
bin/agentbox-session = PYTHON ENTRY session "$@"        (the one enabled
                                                         `jail.session` handler)
                       (PYTHON the jail's Python with -I -S -B -X utf8,
                        never bundled: docs/ssh-worker.md)

agentbox-request HANDLER OPERATION [ARGS_JSON]
  any handler, no local routing: ARGS_JSON one object, POST key grammar,
  numbers non-negative safe integers, depth <= 14, canonical <= 60 KiB;
  copy WORK/.agentbox-requests/S-R.artifact to
  WORK/agentbox-artifact-XXXXXX/artifact (0700/0600), size and SHA-256 of
  the ready; print path, size, digest, metadata; claim applied (the copy)
SHIM ARGS...         the handler's own command: git, npm, npx, memo (test);
                     its arguments, submissions and application
agentbox-session [--status=FD] ARGV...
                     before every command of the execution and every shell
                     (guest execution.py `session_argv`, main.py), when
                     ARGV[0] resolves: the module prepares the command's
                     environment (pip: a loopback index), then ARGV replaces
                     it, keeping its pid, argv, descriptors, terminal, group
                     and exit status. FD (exec only, from the anchor):
                     `r` just before the exec, `f` if it fails, close-on-exec;
                     a failed exec, or an end before `r`, is a failed start
                     (`outcome: failed`), never an exit 126/127. The shell
                     form has no FD: a failed exec exits 127, as before
```

There is no jail registry: a handler or operation the execution does not
enable is the host's refusal (`handler_unknown`, `operation_denied`), one
request spent. A manifest's `jail.entry` names a module of the worker
bundle beneath its own jail directory (`acquisitions/ID/jail/...py`, listed
by the bundle; a fourth handler's module needs a bundle that lists it, not
a controller change). It is the handler's `ID/jail/*.py` package bundled with the
guest, or a ready Python module joining the bundle at image build as
`acquisitions/ID/jail/ID.py` (`stage.py ... --counterparts DIR`, `worker.py
build --counterparts DIR`: images/worker/README.md). An entry script adds
only the bundle root to its path and imports the bundle's own modules by
absolute name (`guest.src.counterpart`'s `serve` and `operation_shim`,
`guest.src.artifact_save_client`, ...) and the standard library; `shims`
names the commands the host generates for it in the jail's `bin` (reserved
core names refused, `git`, `npm`, `npx` allowed, duplicates across handlers
refused); `session: true` makes the module the session wrapper (at most one
enabled handler, else `handler_session_conflict`). Modules and shims are guest convenience: they grant nothing, and
the host checks every submission under the handler's policy.
