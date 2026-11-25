# agentbox-server control protocol v1

One server serves one trusted controller session, in its own cgroup leaf for managed executions. Each approved CONNECT gets one relay child. Only the relay sends `200`; it exits when its control socket closes, even if the server was killed.

Without [enabled handlers](artifact-requests.md#selection), the controller sends `configure` with `post: null`, then EOF at shutdown. Enabled handlers add artifact delivery and response frames.

```text
controller (trusted)                    agentbox-server                    jail (untrusted)
  stdin  ---- frames ---------------->  reader -> loop                     guest POST/CONNECT
  stdout <--- frames -----------------  Output (whole frames, deadlines)        |
  stderr <--- fixed codes, best effort                                          | via the controller's
                                        broker 127.0.0.1:PORT <-----------------+ SSH -R
                                        delivery: spool fd -> scp /dev/fd/3 --> WORK/.agentbox-requests/
```

Source: [agentbox_server/](../src/agentbox_server/) (`main.py` the
loop and stops, `wire.py` the frames and commands, `broker.py`,
`ingress.py`, `relay.py`) and [agentbox-relay](../crates/agentbox-relay/).

## Process

- `agentbox-server` takes no arguments.
- stdin and stdout must be pipes or sockets. Otherwise it exits 2, as it
  also does when it cannot install its signal handlers.
- Inherited descriptors above 2 are made close-on-exec at startup.
- Children get `/dev/null` or their own pipes as stdio, never a control
  stream.
- Exit status: 0 after the end of input and a clean shutdown, otherwise 1.

## Framing

```text
frame = u32 big-endian length (1..=1 MiB) || one JSON object
```

| Bound | Value | Why |
| --- | --- | --- |
| Frame | 1 MiB | ≥ 6 × 64 KiB (`\u00XX` escaping of a maximal POST body) + 8 KiB envelope, and ≥ an escaped configuration (tested) |
| POST body | 65536 bytes | The post-v1 codec's `MAX_BODY_BYTES`, per body. (`REQUEST_BYTES` 133120 is per-request ledger accounting, not one body.) |
| Pending commands | 64 | Read but not yet taken. A 65th is a violation |
| Loop message write | 2 s | Waits for room and writes included. Then output is lost. A stop aborts the write earlier |
| Event write | 250 ms | The broker's `RECORD_WAIT`, waits included. A late event fails the broker closed |

Frames never interleave: the server's one loop writes each whole before
the next. One deadline covers a frame's waits for room and all its
writes; meanwhile the loop still reads the control input (an end or a
violation seen then is a stop at once). A frame counts as written only
once its last byte is out before any stop applies.

```text
deadline passed (waiting or writing)  -> output lost for good, the server stops
abort (a stop) before the 1st byte    -> frame dropped, stream intact
abort after any byte                  -> output lost
```

Only the final best-effort `stopped` uses an intact stream after a stop.
It may still not arrive.

## Controller → server

Each command has exactly its fields and an `id` greater than the previous
one. Anything else is fatal: an unknown type or field, a missing or
mistyped field, a stale `id`, a command before `configure`, or a second
`configure`. **End of input is the shutdown.** No shutdown command
exists.

| `type` | Fields | Effect |
| --- | --- | --- |
| `configure` | `v`=1, `session`, `run_id`, `execution_id`, `lifetime_ms`, `policy`, `post`[, `grants`][, `connect_proxy`] | Once, first. Starts the broker. Answered by `ready` |
| `deliver` | `exchange`, `request`, `deadline_ms`, `name`, `size`, `sha256` | Activates the seen submit `exchange` as the one active `request`, then uploads spool file `name`. One `result` when the upload ends |
| `respond` | `exchange`, `body` | Answers a seen exchange with one canonical post-v1 response body. `result` |
| `revoke` | `request` | Ends the active request and cancels its upload. `result`. The guest's waiting exchange still needs a `respond` (e.g. `closed`); otherwise it waits until its deadline |

`configure` fields:

- `session`: the control session id, echoed in `ready`.
- `run_id`: `r-` plus 32 hex digits. `execution_id`: `e-` plus 32 hex digits.
- `lifetime_ms`: 1 ms up to 366 days, anchored when `configure` is
  received; or `null` (the user's decision): no session cutoff, with or
  without `post` (`jail serve`, an interactive agent, an execution without
  `--timeout`). Missing, `0`, negative, fractional, a string or past 366
  days: `control_malformed`. Untimed is not a year-long cap and has no
  renewal or heartbeat: such a session ends on the controller's end of
  input, a signal, a violation or a failure, each through the bounded stop
  below; the startup (10 s), every query, transfer and the stop itself
  keep their own finite bounds. Every POST exchange waits at most 1800 s
  from its admission (its request's longest deadline), capped by the
  session's lifetime if any, and `activate` only tightens that; a codec
  or session answer is written within the same bound. An execution with
  `--timeout` sends its runtime plus a 60 s margin.
- `policy`: a network policy document (`agentbox.network-policy.v1`).
- `grants` (optional): at most 32 session endpoints, each a CONNECT
  authority (`host:port`, `[ipv6]:port`), duplicates merged, added to a
  Model Only or Custom policy and its identity; ignored under Open, which
  they never narrow. Loopback literals are allowed; an unspecified one
  (`0.0.0.0`, `::`, mapped forms) or a malformed one is
  `configure_invalid`. The controller's `--insecure-open` sends an Open
  `policy`; the server cannot tell it from a configured one.
- `connect_proxy` (optional): the controller config's upstream proxy, a
  CONNECT authority (a string; anything else `control_malformed`; an
  unspecified or malformed one `configure_invalid`). Each admitted CONNECT
  is then sent to it, never resolved or dialed directly: an unspecified
  literal target refused, the proxy's name resolved and validated like a
  destination, its `CONNECT` answered within `connect_timeout` by a head
  of at most 8 KiB (status line 1 KiB, 32 fields), its status line
  (`HTTP/1.x SP code SP [reason]`) and every field strictly parsed (no
  folding, no control bytes). Only a valid `2xx` opens the tunnel; else
  `502 proxy_refused`, `proxy_malformed`, `proxy_failed` or
  `504 proxy_timeout`. Not part of the policy identity;
  `broker.started` says `route` `direct` or `proxy`.
- `post`: `null` means POST is unconfigured, so a guest POST gets
  `405 post_unconfigured`. Otherwise
  `{nonce: 32 hex, delivery: null | {...}}`. `nonce` is the post-v1 session
  nonce. It is not the control session.
- `delivery`:
  - `route`: `{endpoint: {host, port}}` or `{proxy: {words, env}}`.
  - `user`, `identity`, `known_hosts` and `host_key_alias` must pass `src/agentbox_server/transport.py` validation.
  - `work_dir` is the jail's working directory.
  - `spool_root`: the controller's host directory, opened once without
    following a link.

`deadline_ms` (at most 1800000) counts from the exchange's admission and
is never renewed. The upload is bounded by the earliest of 60 s, that
deadline and the session's lifetime (if any).

## Server → controller

| `type` | Fields | Why it exists |
| --- | --- | --- |
| `ready` | `v`, `id`, `session`, `broker {host, port}`, `post`, `delivery` | The listener the controller's reverse forward targets |
| `post.request` | `exchange`, `replay`, `bytes`, `body` | An admitted guest body. The controller decides what it means |
| `post.ended` | `exchange`, `end` | The guest exchange's HTTP side ended (`written`, `peer_eof`, …), so its request may be cancelled |
| `result` | `id`, `ok`, `code` | The one answer to each command. `deliver`'s comes when its upload ends |
| `event` | `event`, `severity`, `attributes` | Broker records (fixed codes, counters, digests), and `post.closed` |
| `stopped` | `reason`, `clean`, `broker`, `delivery_outstanding` | The final report, best effort, within the cutoff |

Non-fatal `result` codes:

- `stale`, `busy`, `replay`, `cancelled`, `closed`, `not_active`
- `post_unconfigured`, `delivery_unconfigured`
- `response_invalid`, `mismatch`, `ready_unbound`, `request_ended`
- delivery failures: `source_missing`, `source_invalid`,
  `size_mismatch`, `timeout`, `transfer_failed`, `transfer_output`,
  `transfer_start_failed`, `target_invalid`

A `ready` is accepted only for the active request, after the upload this
server completed for it. Its `request`, `size` and `sha256` must equal
those of that request's `deliver`, and the request must not be cancelled.
The server does not hash content itself. The existing ingress then checks
session, client, handler and digest, and refuses any `ready` after its
latch.

## Delivery

```text
openat(root, NAME, O_NOFOLLOW|O_NONBLOCK)   NAME one [A-Za-z0-9][A-Za-z0-9._-]{0,63}
fstat: a regular file of SIZE bytes         SIZE ≤ 2 GiB (the HTTP acquisition ceiling)
scp -q -B -s -F /dev/null ... -- /dev/fd/3 HOST:WORK/.agentbox-requests/NONCE-REQUEST.artifact
```

- The `scp` and `ssh` options are a fixed profile: pinned host key, no configuration, agent or
  forwarding.
- fd 3 is the opened descriptor, given to the child alone. The name is
  never reopened, so a file renamed over it meanwhile is not what gets
  uploaded.
- The guest chooses nothing: not the root, the name, the target or the
  destination.
- Trust: the controller finalizes the artifact, supplies its size and
  SHA-256, and leaves it unchanged until the upload's `result`.
  - The server checks the type and size only. It makes no snapshot and no
    content check.
  - The guest's check of the advertised digest is content correctness,
    not a host boundary.
- Spool files are the controller's. The server deletes nothing.

## Stops

Every stop takes the same path, within one cutoff of 5 s that is never
renewed:

```text
cause: end of input | violation | SIGINT/SIGTERM/SIGHUP | lost output
       | broker failure | lifetime | startup failure
  -> latch: the loop's next step and every commit boundary of the broker
     (admission, lookup grant and answer, dial, connect, the relay child's
     spawn and each piece of its handoff up to START) see it at once
  -> active request cancelled, POST ingress ended, broker stopped (tunnels closed)
  -> delivery's scp group killed
  -> stopped (≤ 250 ms, never past the cutoff) -> exit
```

- The control input is read by the loop without blocking; nothing waits
  on it at exit. The only threads are the bounded lookups (`getaddrinfo`),
  never joined, so a stalled one does not delay exit.
- The overall ceiling from stop to exit is 10 s. Offline cases exit in
  milliseconds. A stalled output first waits out its 2 s write.
- Not covered:
  - **SIGKILL of the server.** Nothing runs. The broker's sockets close
    with the process. A running `scp` group loses its deadline,
    which lives in the server, and may run on indefinitely. SSH's connect
    and keepalive limits do not end a responsive but stalled transfer, and
    nothing cleans up automatically. This weaker contract is accepted.
  - Uninterruptible kernel I/O.
  - Host failure.

## Crash contract

Controller EOF makes the server revoke POST, close tunnels, stop its own copy processes
and exit. Server stdout EOF means transport loss to the controller. SIGKILL is not a
cleanup protocol: processes in the custody domain and detached jails can survive.
Handlers have their own limits. Use explicit `jail stop` and check settlement before
discard. Delegated systemd scopes support limits and explicit cleanup, not a watchdog.
