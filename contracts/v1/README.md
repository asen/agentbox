# Contracts v1

Shared, versioned contracts between the host (the Python controller,
`src/agentbox_controller/guest.py` and `capture.py`) and the
Python guest package (`guest/`). `host.supervisor` is a wire origin, not a process. Both implementations test against the
files in this directory:

- [`protocol.json`](protocol.json): protocol name, version, limits and error codes.
  Each implementation asserts that its constants match.
- [`protocol-fixtures.json`](protocol-fixtures.json): valid and invalid frames
  with their expected canonical encoding or error code.
- [`events.jsonl`](events.jsonl): host event records the controller's
  capture must produce for the inputs in its tests
  (`tests/controller/test_units.py` `EventContract`).

Changing any rule below is a protocol change: update both implementations and
the fixtures together, and use a new version for incompatible changes.

## Guest protocol `agentbox.guest` v1

The host starts one SSH session to the guest helper and exchanges frames over
its stdin/stdout. The host is the only authority. Guest frames are untrusted
reports: they cannot grant policy, name host paths or carry tool arguments, and
the host assigns all sequence numbers, origins and event types.

### Framing

- A frame is one JSON object encoded as UTF-8 and terminated by one LF.
- At most 65536 bytes per frame, excluding the LF. A longer line, or a partial
  line at end of stream, is fatal for the session.
- The frame must not contain CR or LF bytes. JSON space and tab are allowed.
- No byte-order mark, no invalid UTF-8, no lone surrogate escapes in any string,
  including one a duplicate key would replace.
- Nesting depth of objects and arrays is at most 8.
- Every number in the frame must be a plain non-negative integer
  (`0` or `[1-9][0-9]*`) no larger than 2^53 - 1. No sign, fraction or exponent.
- Object keys must be unique after unescaping. Values keep their JSON types:
  an object is never read as a number.

### Envelope

Every frame has `"v": 1` and a `"type"`. There is no negotiation in v1: a frame
whose `v` is an integer other than 1 is refused with `unsupported_version` and
the session ends. Fields not listed for a type are refused; this is how guest
attempts to supply `seq`, `origin`, `policy`, paths or `argv` are rejected.

Host to guest:

| type | fields |
| --- | --- |
| `hello` | `session`: id |
| `exec` | `id`: id; `argv`: guest-only argument vector; optional `env`: selected variables; optional `stdin`: exactly `true` |
| `cancel` | `id`: id of an earlier `exec` |
| `inputs_setup` | `execution_id`: id of this execution |
| `stdin` | `id`: the opted-in `exec`'s id; `seq`: the guest's latest credit; `data`: canonical padded standard base64 of 1 to 2048 bytes |
| `stdin_eof` | `id`; `seq`: the guest's latest credit |

`inputs_setup` asks, at most once, after `hello` and before `exec`, for the
copied-input setup of a run's first input execution
(src/agentbox_controller/inputs.py). The host has uploaded its own tar archive to
`/home/agentbox/.agentbox-inputs-EXECUTION_ID.tar`, from the id alone. The
guest's fixed adapter (guest/src/inputs.py) runs `/usr/bin/tar` with fixed
arguments into fresh staging, accepts exactly `work/` and `refs/`, and renames
them to `/home/agentbox/work` and `/home/agentbox/refs`, each only if missing
or an empty directory. It then sends `inputs_ready`; a failure gets the fixed
`invalid_field` error and ends the session. Any guest frame or data after
`hello` and before `inputs_setup`, and any other frame before `inputs_ready`,
is a protocol failure. `inputs_ready` reports setup only: not a
command, cleanup or disk durability. Ready runs get no `inputs_setup`.

Guest to host:

| type | fields |
| --- | --- |
| `hello` | `session`: the host's session id; `guest_version`: `[0-9A-Za-z][0-9A-Za-z.+-]{0,31}` |
| `output` | `id`; `stream`: `stdout` or `stderr`; `data`: canonical padded standard base64 of 1 to 16384 bytes |
| `exit` | `id`; `outcome`: `exited`, `signaled`, `cancelled` or `failed`; `code`: 0 to 255, required for `exited` and refused otherwise |
| `error` | `code`: one of the error codes below |
| `inputs_ready` | none: exactly `{"v":1,"type":"inputs_ready"}` |
| `stdin_ready` | `id`: the opted-in `exec`'s id; `seq`: the next task input frame's sequence |
| `stdin_closed` | `id` |

An id is `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. `argv` has 1 to 64 strings, each at
most 4096 UTF-8 bytes without NUL, at most 32768 bytes in total, and a
non-empty first item. `argv` is executed only inside the guest; the host never
interprets it as a host command or path. All size limits count UTF-8 bytes.

`env` is the host user's explicit `--env` selection
(src/agentbox_controller/cli.py): an object of 1 to 32 entries, absent
when none (so generic `exec` bytes are unchanged; an empty object is
refused). Names are `[A-Za-z_][A-Za-z0-9_]*` of at most 128 bytes and not in
`reserved_env` (the helper's fixed command variables, the request context's
`AGENTBOX_REQUEST_SESSION`, `AGENTBOX_WORK_ROOT` and `AGENTBOX_WORK_MOUNT`
included); values are strings of
at most 8192 bytes without NUL; names and values together at most 16384
bytes. The canonical encoding orders entries by name. The helper adds them to
the command's environment only (guest/src/execution.py, anchor.py). Helpers
older than this field refuse it (`unknown_field`); the host sends it only to
an exactly environment-capable image, and none is admitted yet.

`stdin: true` opts the command's standard input into task input
(guest/src/execution.py); absent, the default,
the command's input is the null device and the `exec` bytes are unchanged
(`false` is refused as non-canonical). Task input is data, never interpreted:
any bytes, NUL, invalid UTF-8 and LF included, travel as canonical base64.

```text
guest stdin_ready(id, 0)          after the command can start
host  stdin(id, 0, data)          one frame per credit, in order
guest stdin_ready(id, 1)          once that chunk was written to the command
host  stdin(id, 1, data) ...
host  stdin_eof(id, n)            on credit n; ends the command's input only
guest stdin_closed(id)            once, if the command's input closed early
```

A credit is a capacity hint for exactly the next sequence of this command,
never cumulative and never evidence of consumption or completion. A frame
without the outstanding credit, of another id, after `stdin_eof` or with a
repeated sequence is a protocol failure, as is a credit out of sequence, a
second `stdin_closed` or a credit after it. After a stop, the command's end
or `stdin_closed`, one frame already in flight on the outstanding credit is
dropped unwritten; the helper writes or reopens nothing. Neither side logs
input bytes; the host writes each `stdin` frame and its LF in one write of
at most 2860 bytes (`PIPE_BUF` holds it), so no other frame can interleave
with it. Helpers older than this field refuse it (`unknown_field`); the
host sends it only to an exactly stdin-capable image, and none is admitted
yet.

### Validation order and error codes

Validators report the first failing check, in this order, so both
implementations return the same code for the same bytes:

1. `frame_too_large`: more than 65536 bytes.
2. `invalid_framing`: contains CR or LF.
3. `invalid_encoding`: not valid UTF-8.
4. `invalid_json`: nesting deeper than 8, JSON syntax error or lone surrogate.
5. `invalid_number`: a number that is not a plain safe integer.
6. `duplicate_key`: a repeated object key.
7. `not_object`: the top-level value is not an object.
8. `invalid_version` (`v` missing or not an integer), then `unsupported_version`.
9. `missing_field` (`type` missing), `invalid_field` (`type` not a string),
   then `unknown_type`, or `wrong_direction` for a type of the other direction.
10. `unknown_field`: a field not listed for the type.
11. `missing_field`: a required field, in table order.
12. Each field in table order: `invalid_field` for a wrong type, pattern or
    value, `limit_exceeded` for a size or count limit. For `data`, more than
    21848 bytes of text is `limit_exceeded` before the base64 check; for `argv`,
    more than 64 items is checked before emptiness and items, and the total
    after the items. For `env`: not an object is `invalid_field`, more than 32
    entries `limit_exceeded`, none `invalid_field`; then each entry in name
    order: pattern, name length (`limit_exceeded`), reserved, value type,
    value length (`limit_exceeded`), NUL; then the total (`limit_exceeded`).
    For `stdin`'s `data`, more than 2732 bytes of text is `limit_exceeded`
    before the base64 check, and so is more than 2048 decoded bytes; `seq`
    is a safe integer (`invalid_field` for another type).

Stream readers also use `truncated_frame` for a partial line at end of stream.

## Event records `agentbox.event.v1`

The host writes one JSON object per line, shaped after OpenTelemetry log
records, with keys in sorted order:

| field | meaning |
| --- | --- |
| `schema` | `agentbox.event.v1` |
| `seq` | host-assigned, starts at 1 and increases by 1 per record of one execution |
| `time_unix_nano` | host observation time as a decimal string |
| `run_id`, `execution_id` | ids |
| `origin` | `host.cli`, `host.supervisor`, `host.broker` or `guest` |
| `event_type` | fixed by the host for each kind of event; never taken from guest data |
| `severity_number`, `severity_text` | OpenTelemetry severity: 5 `DEBUG`, 9 `INFO`, 13 `WARN`, 17 `ERROR` |
| `body`, `body_encoding` | optional; `utf8` text or `base64` bytes, such as guest output |
| `attributes` | object of fixed keys with string, integer or boolean values |

Records with origin `guest` hold guest-reported content and remain untrusted.
Host diagnostics use fixed codes and bounded metadata, never raw exception or
tool output, secrets, configuration or argument values.

An execution's records are written to `events.jsonl` in its private log
directory (`capture.py`). Event types:

| event_type | origin | meaning |
| --- | --- | --- |
| `host.execution.started`, `.qemu_started`, `.ssh_started`, `.guest_ready` | `host.supervisor` | lifecycle steps; `guest_ready` follows the matching guest hello |
| `host.execution.stopping` | `host.supervisor` | `reason`: a fixed supervision reason code, when the session ends by a stop or failure |
| `host.execution.finished` | `host.supervisor` | the precommit candidate, after the targets' teardown: `precommit` (always `true`), `reason` (the runtime's candidate, a fixed supervision reason code), `cleanup_reason` (the worker's reason as of the teardown), `cleanup_confirmed` (every target leader killed and reaped); never the outcome, which only the execution record and the supervisor's report together carry |
| `host.protocol.rejected` | `host.supervisor` | `code`: why a guest frame was refused; never its content |
| `host.inputs.attempted`, `.uploaded`, `.ready`, `.archive_retained` | `host.supervisor` | an input setup's steps: the synced attempt, the upload's clean exit, the published (logical) ready record, a host archive left charged |
| `host.inputs.ready_unsynced`, `.archive_removal_unsynced` | `host.supervisor` | warnings: the ready rename or archive unlink happened, then its directory sync failed |
| `host.bootstrap.started` | `host.supervisor` | an execution's bootstrap begins (src/agentbox_controller/execute.py): `release` (the worker bundle's manifest SHA-256) and `attempt` (the fresh 32-hex installation attempt) |
| `host.bootstrap.ready_claimed` | `host.supervisor` | the verify stage replied the exact ready line with exit 0: the guest's claim only, not verification, settlement or any authority; the execution session may start |
| `host.bootstrap.failed` | `host.supervisor` | the first failed stage, warning: `stage` (`prepare`, `custody`, `upload`, `verify`), `guest_reason` (a closed reason the guest claimed, or `none`) and `input_complete` (`false` when that stage's host-generated stdin was not taken whole); remote partial effects are unconfirmed and the operator's |
| `host.transport.stderr` | `host.supervisor` | `source`: `qemu`, `ssh`, `scp` (the input upload) or `sftp` (a supplied jail's bootstrap batch, stdout and stderr); host tool output bytes as untrusted base64 data |
| `host.capture.gap` | `host.supervisor` | last, when anything was not captured: `dropped_bytes` of console or tool streams, and `open_streams` still open when the capture closed |
| `broker.*` | `host.broker` | CONNECT broker records |
| `guest.hello`, `guest.output`, `guest.exit`, `guest.protocol_error`, `guest.inputs_ready` | `guest` | validated guest frames |
| `guest.console` | `guest` | serial console bytes as untrusted base64 data |
