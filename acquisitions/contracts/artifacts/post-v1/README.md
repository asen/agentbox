# Artifact request POST contract v1

The server accepts artifact POSTs on the existing broker forward and passes them to the controller's [enabled handlers](../../../../docs/artifact-requests.md#selection). With no ingress configured, a valid POST head gets status-only `405 post_unconfigured`. No relay fallback. Host and guest codecs share [constants](contract.json) and [fixtures](fixtures.json).

Changing any rule below is a protocol change: update both implementations and
the fixtures together.

## Shape

```text
guest client                         host broker (existing forward, numeric proxy)
------------                         -----------
POST /agentbox/v1/request  ------->  framing (request.py) -> ingress -> lane -> handler worker
  submit {session, client, handler, operation, args}
  keeps write side open ...          acquisition, scp upload
                           <-------  200 ready {bindings, size, sha256, metadata}  then close
applies locally
POST result {.. request, request_sha256, sha256, status}  ->  200 closed recorded, close
```

One POST, one response, then close. No polling, streaming, keep-alive,
pipelining, retry or resubmission. Artifact bytes travel by the host's upload,
never in a body.

## HTTP framing

Request head (the guest sends exactly this; the host accepts field names in any
case and order, and optional spaces/tabs around values):

```text
POST /agentbox/v1/request HTTP/1.1\r\n
Host: agentbox\r\n
Content-Type: application/json\r\n
Content-Length: <0 | [1-9][0-9]*, at most 65536>\r\n
Connection: close\r\n
\r\n
<exactly Content-Length body bytes>
```

- The broker's head ceilings apply unchanged: 8 KiB head, 1 KiB request line,
  32 fields; CRLF only; no obs-fold, bare CR/LF or whitespace before a colon.
- `Host` is the fixed literal `agentbox`, never resolved; the client dials the
  fixed numeric proxy endpoint. No other spelling.
- Exactly the four fields, each once. Anything else is refused:
  `Transfer-Encoding`, `Content-Encoding`, `Expect`, `Upgrade`, `TE`,
  `Trailer`, `Keep-Alive`, `Proxy-Connection` as framing; any other field
  (credentials included) as an unsupported header.
- Exact origin-form path: no absolute URL, query, dot segment, trailing slash
  or other path. `HTTP/1.1` only.
- A request line starting other than exactly `POST ` takes the unchanged
  CONNECT rules (which still refuse `Content-Length`/`Transfer-Encoding`).

Refusals before a dispatched body are status-only, as CONNECT's: `HTTP/1.1
<status> <phrase>`, `Connection: close`, `Content-Length: 0`, close.

| code | status | when |
| --- | --- | --- |
| `request_malformed` | 400 | syntax, version, spacing |
| `request_framing_invalid` | 400 | length missing/repeated/non-canonical, `Connection` not `close`, body-framing field |
| `request_header_invalid` | 400 | `Host`/`Content-Type` missing, repeated or not exact; any other field |
| `request_target_invalid` | 400 | not exactly `/agentbox/v1/request` |
| `request_body_overrun` | 400 | input past `Content-Length` before dispatch (pipelining) |
| `method_not_allowed` | 405 | CONNECT rules: another method |
| `post_unconfigured` | 405 | valid POST head, no POST ingress configured (no enabled handler) |
| `request_timeout` | 408 | head deadline, as CONNECT |
| `request_body_too_large` | 413 | `Content-Length` above 65536 |
| `request_line_too_long` | 414 | |
| `request_head_too_large`, `request_headers_too_many` | 431 | |

Check order: head size, line length, field count and every line's syntax;
request line; each field in order; then missing `Host`/`Content-Type`
(header), then missing length or `Connection` (framing).

Transport refusals (S4b), also status-only: none is seen by the execution,
nothing is queued or retried, and none but a slot refusal after its body
charges anything (S4d-2a, below). With
a POST ingress configured, every client connection of the broker, whatever
its head turns out to be (a malformed or partial head, a wrong path, a CONNECT
included), has two distinct bounds; both also end at the broker's stop or
the ingress's end:

- **Head bound**: the earlier of the broker's head deadline (from accept)
  and the execution's original cutoff. The head's wait, its admission after
  every readiness immediately before every read, and its completion check
  each reject **at or after** this bound: nothing more is read, and a head
  complete only at or after it is neither parsed nor classified. A POST body
  is read under the same rule against the earlier of that head deadline and
  the cutoff; a body complete only at or after it is not dispatched.
- **Refusal bound**: the execution's original cutoff alone, not the head
  bound. Every status-only refusal above (framing, timeout, capacity,
  closed, and CONNECT's own) is written by nonblocking writes with no wait,
  each only before that cutoff; its drain lasts at most 250 ms and ends
  before the cutoff. A refusal may therefore follow the head bound: with a
  5 s head deadline and a 1 h cutoff, a head timeout at 5 s still sends its
  `408` and drains for up to 250 ms. At or after the cutoff, or once a stop
  has come, the connection closes with no status.

Without an ingress, the broker's refusals are unchanged.
The two transport refusals below are not in `contract.json`. The guest's
reader (S4d) accepts exactly the empty 503 (`HTTP/1.1 503 Service
Unavailable`, `Connection: close`, `Content-Length: 0`, nothing after it, then
the server's close) as `refused`, a transport refusal apart from every logical
answer that its status cannot tell apart as capacity or closed; its client
fails closed and retries nothing. Any other status-only response stays
`response_malformed`.

| code | status | when |
| --- | --- | --- |
| `post_capacity` | 503 | both POST permits taken, before the body is read; or, after it, no slot of its class (one submit slot; one control slot for a cancel, a result or a submit while the submit slot is taken) |
| `post_closed` | 503 | the ingress is not armed yet (before the body is read, S4d-2a), ended (stop, or a body past the ledger) or the execution's cutoff passed |

Decoded logical refusals stay bodies (`error`, `rejected`, below): a codec
failure (400) or a session that is not the armed one (403) is answered by
the transport without effect, the body and the answer charged (S4d-2a; S4b
answered them uncharged, also before arming, when nothing is admitted now);
`busy`, `submission_limit` and a replayed `client` reach the execution loop,
which charges the submission.

Response (the host sends exactly this; the guest reader accepts nothing else):

```text
HTTP/1.1 <200 OK | 400 Bad Request | 403 Forbidden | 409 Conflict>\r\n
Content-Type: application/json\r\n
Content-Length: <n, at most 65536>\r\n
Connection: close\r\n
\r\n
<n body bytes>, then the server closes
```

The guest reader (`ResponseReader`) refuses a head over 1024 bytes or not
exactly that form (`response_malformed`), a length above 65536
(`response_too_large`), an end before the head or body is complete
(`response_truncated`), any byte after the body (`response_trailing`), and a
status that is not the body's (`response_status_mismatch`). Complete means the
whole body and then the server's close.

The reader bounds memory before copying: it examines and keeps at most 1024
head bytes of any chunk, allocates the body once at its declared length (at
most 65536), and refuses a chunk larger than the room left without copying
it. Head bytes are printable ASCII, CR and LF only, so a UTF-8 BOM (whole or
split across chunks) or any other byte is `response_malformed`, never decoded
away. A BOM in a body is kept and refused by the codec (`invalid_json`) on
both sides; canonical form compares raw bytes.

### Half-close and cancellation

```text
host: Body --complete--> Awaiting --respond--> Responding --written--> Complete
       | EOF/reset: incomplete, no response    | client EOF, reset or any   | later EOF/reset:
       | bytes past length: overrun refusal    | byte: Abandoned -> cancel  | ignored
```

The client keeps its write side open until it has the complete response. A
client half-close, reset or extra input before the response is completely
written abandons the exchange: the host cancels the request the POST is bound
to (a submit's new request; the active request named by a cancel or result's
client). Nothing resubmits or retries; bytes already uploaded stay. The
server's close after a complete response cancels nothing: a `ready` request's
application and later `result` POST go on. A lost response does not prove an
upload failed. Deadlines are the caller's: the body is read within the
broker's head deadline from accept; a response is awaited until the
execution's original cutoff, which the request's original deadline only
tightens once it is active, never a new frame timeout; and it is written
within the control write timeout (10 s) from its first write, never past that
bound; a codec or session `error` answer within the same, never past the
execution's cutoff or the ingress's end. Past the cutoff or after the end no
body is answered, a malformed one included (`post_closed`). The deadline and
the stop are read again after every readiness, before every write and after
the last one: a late, stopped, failed or zero write cancels and is never
delivered. Acquisition, upload and request bounds are the handler's
originals.

Host transport (S4b), between the broker's POST worker and the execution loop:

```text
worker: head -> permit (armed, 2) -> body -> admitted, charged: decode, session, slot -> ticket
loop:   poll: ends of seen exchanges first; no request while a response's
        write outcome is unknown -> activate (one) / respond -> written
latch:  peer loss, failed or late write, expiry: the request's latch, set
        before the mailbox; a written response cancels nothing
end:    stop or ledger limit: one shared atomic latch, first end wins, read by
        every request, ticket and permit; the stop takes no lock
permit: 2, each held until its worker's last record and count are released
```

The latches carry no time. A cancelled request's acquisition gets one cleanup
allowance: its cleanup-confirmation cutoff is the earlier of its original
deadline and the cleanup side's first observation of the cancellation plus the
cleanup reserve (250 ms), never reset. Delay between the cancellation and that
observation does not use up the allowance and never moves an original
deadline. The cutoff bounds the wait to confirm cleanup, not physical cleanup:
custody of anything not yet cleaned up continues until settled.

The control ledger counts request and response bodies, both directions,
once at their actual size; no head or artifact byte. Its bounds derive from
the execution's request grant (256, [handlers](../../handlers/v1/README.md#limits)):

```text
messages  4 x 256 + 64 = 1088      a submit, its answer, one terminal body
                                   (cancel or result) and its answer, per
                                   request; 64 stray bodies
bytes     256 x (64 KiB + 64 KiB + 2 x 1 KiB)    a full submit, a ready at
          + 2 x 3 x 64 KiB + 64 x 64 KiB          the metadata ceiling, a
          = 36.9 MiB (counters, nothing allocated) terminal and its answer;
                                                  two exchanges' held
                                                  credits; the slack
```

Terminal bodies and short answers (`cancel`, `result`, `closed`,
`rejected`, `error`) are at most 1 KiB by their grammar (tested). A submit holds its response's and its request's terminal
credits (one cancel or result body and its answer) from admission; a cancel
or result naming it takes them over; unused holds are released, nothing
spent is refunded; a request that does not fit ends the ingress. Each
submit's `client` is recorded once: a reused one is marked a replay for the
loop and can never be the active request.

Accounting. Every complete body admitted (armed, open, before the cutoff)
is charged once at its actual length whatever follows: malformed, foreign
session, unknown handler, no slot, busy or replay alike, never a
re-encoding or a guest's count. Nothing refused before admission (no permit,
unarmed, ended, past the cutoff) and no partial body is charged. Every
response body is charged once at its actual encoded length; an empty 503
has none. A body (and a codec or session answer) that does not fit ends the
ingress: the empty 503, uncharged. The ledger is the only control byte
bound; artifact bytes never count. The request grant is the lane's
([handlers](../../handlers/v1/README.md)): an attributable malformed, busy
or replayed submission spends one request; each request starts at most one
worker, a worker's denial included.

## Bodies

Strict JSON as [contracts v1](../../../../contracts/v1/README.md) steps 1-10 (UTF-8, no CR/LF,
non-negative safe integers only, no duplicate keys, an object with `"v": 1`
and a known `type`), at most 65536 bytes and nesting depth 16 (the envelope
included). Then the unknown and missing field checks (unknown first); then
each field in the order below; then **canonical form**: the body must be
byte-for-byte its message's encoding (keys in table order, no whitespace,
minimal escapes; `args` and `metadata` objects with their keys sorted at
every depth) or it is `invalid_field`. Codes are the shared v1 error codes;
nothing echoes content.

`session` is the execution session nonce: exactly 32 lowercase hex digits.
`client` is a guest correlation id (v1 id grammar), unique per submission; it
grants nothing. `request` is the host-assigned id. `handler` and
`operation` match `[a-z][a-z0-9-]{0,31}`; whether the handler is enabled
and the operation permitted is the lane's (a `closed denied` with a fixed
reason), never the codec's. An `args` or `metadata` key matches
`[A-Za-z0-9_.:@/+-]{1,128}` at every depth.

### Guest to host

| type | fields |
| --- | --- |
| `submit` | `session`, `client`, `handler`, `operation`, `args` (object) |
| `cancel` | `session`, `client` |
| `result` | `session`, `client`, `request`, `request_sha256`, `sha256`, `status` |

`request_sha256` of a submission is the SHA-256 of
`{"client":C,"handler":H,"operation":O,"args":A}` (keys in that order,
`args` canonical). Git's archive descriptor binds it as before.

`args` are untrusted: the lane checks only their canonical size against the
handler's `args_bytes`; the handler's worker interprets them under the
operator's policy, never as a path, URL or command of the host.

`cancel` ends the session's active request submitted by `client`, before or
after `ready`; no request id is needed before `ready`. `result` is an
untrusted claim (`applied` or `failed`) bound to the delivered request: its
`request`, `request_sha256` and the delivered artifact's `sha256` from
`ready`; the driver checks each against its own record and the transport's
record of the `ready` actually written.

### Host to guest

| type | status | fields |
| --- | --- | --- |
| `ready` | 200 | `session`, `client`, `request`, `request_sha256`, `handler`, `operation`, `size`, `sha256`, `metadata` |
| `rejected` | 200 | `session`, `client`, `code`: `busy` or `submission_limit` (no request id) |
| `closed` | 200 | `session`, `client`, `request`, `request_sha256`, `handler`, `outcome`; `reason` exactly for `denied` |
| `error` | 400/403/409 | `code` |

`ready` follows the host's completed upload of
`WORK/.agentbox-requests/SESSION-REQUEST.artifact`, never mere acceptance;
it does not mean installation or application. `size` is any positive safe
integer and `sha256` the worker's digest of the artifact; `metadata` is the
worker's object, within the handler's `metadata_bytes` (at most 62 KiB, so
it fits beside at most 2048 bytes of other `ready` fields in one 64 KiB body).

`closed` outcomes: `denied`, `cancelled`, `expired`, `recorded` (`recorded`
acknowledges a `result` claim only). A `denied` reason is a code of
`[a-z][a-z0-9_]{0,63}`: the lane's own (`handler_unknown`,
`operation_unknown`, `operation_denied`, `args_too_large`, `byte_limit`,
`delivery_stale`, `lost`), the host's fixed acquisition failures
(`worker_failed`, `upload_failed`, ...: contract.json) or the handler
worker's own code, attributed to `handler`. Before `ready`, `denied` also
answers a host failure to complete the delivery. It ends protocol work only:
it proves neither that no byte reached the guest nor that the host's
cleanup settled.

`error` codes: a shared codec code (status 400), `session_mismatch` (403),
`not_active` (409: no such active request of this client, or a `result`
before `ready`), `binding_mismatch` (409: a `result` not naming the delivered
request, digest and artifact).

## Gates

- Parsing or codec success enables nothing: no capability, listener, forward
  or URL is added. The POST shares the existing broker forward.
- One active request per execution, no queue, no retry; the handlers'
  request grant and acquired-byte allowance; the control ledger derived from
  the grant;
  the original acquisition, upload and request bounds and the cleanup
  reserve. A waiting POST must not block CONNECT.
- No image, provider capability or worker bundle makes an execution
  POST-capable: only the controller's lane selection does (the packaged
  defaults or the operator's configuration,
  [selection](../../../../docs/artifact-requests.md#selection)).
  Guest declarations grant no world authority.
