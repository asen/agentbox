# pip v1: an approved index for ordinary pip

Ordinary pip in the jail reads one operator-approved Python package index
(PEP 691 JSON Simple API) through the host. pip resolves, backtracks and
builds source distributions in the jail; the host lists, fetches and
verifies, nothing more.

```text
jail                                                     host
pip / python -m pip / pip's build env
  PIP_INDEX_URL=http://127.0.0.1:PORT/simple/
  -> loopback index (acquisitions/pip/jail/index.py)
       GET /simple/NAME/            -> POST pip files {projects}  -> GET INDEX/NAME/ (JSON)
       GET /files/NAME/SHA/FILE     -> POST pip fetch {files}     -> page again, its URL
       GET /files/NAME/SHA/FILE.metadata                             for that name + digest
  <- served as delivered            <- batch artifact (scp)       <- verified bytes
```

## Enablement

```json
{"schema": "agentbox.acquisition-config.v2", "interpreter": "/usr/bin/python3",
 "assets": "/opt/agentbox-0.1.0/share/agentbox-assets",
 "handlers": {"pip": {"policy": "/etc/agentbox/pip-policy.json"}}}
```

Policy (at most 4096 bytes):

```json
{"schema": "agentbox.pip.index-policy.v1",
 "index": "https://pypi.org/simple/",
 "files": ["https://files.pythonhosted.org/packages/"]}
```

- `index`, each `files` origin: `https://HOST/[SEGMENT/...]`, ending `/`; a
  lowercase multi-label host, no port, userinfo, query, fragment or escape.
  1..8 file origins, distinct. Anything else: `pip_policy_invalid`.
- Wheels and source distributions alike; no allowlist, no wheels-only
  switch (pip's own `--only-binary=:all:` refuses builds).

## Host operations (acquisitions/pip/host/worker.py)

| op | args | per item |
| --- | --- | --- |
| `files` | `{"projects":[NAME..<=64]}` (PEP 503 normalized, distinct) | GET `INDEX/NAME/`, `Accept: application/vnd.pypi.simple.v1+json`; 404 `missing`; else the rebuilt page |
| `fetch` | `{"files":[{project,filename,sha256}..<=64]}` | the project's page (once per batch); the entry of exactly that filename and digest, else `missing`; GET its URL; size (if listed) and SHA-256 checked. `FILE.metadata` with FILE's digest: GET URL.metadata against the page's core-metadata digest |

A page is kept only as these fields, per file, in page order; anything else
drops the file:

- `filename`: `[A-Za-z0-9][A-Za-z0-9._+!-]*` (<= 255), a wheel
  (`NAME-VER[-BUILD]-PY-ABI-PLAT.whl`) or `.tar.gz`/`.zip` whose name part
  normalizes to the project; the first of a name wins.
- `url`: resolved against the page's real URL; HTTPS, policy host grammar,
  no port, userinfo or query; plain or `%XX` segments (no escaped `.`, `/`,
  `\`, `%`; no `.`/`..`); last segment exactly the filename; under an
  approved file origin. Served as `/files/NAME/SHA256/FILENAME`.
- `hashes.sha256` (required), `requires-python` (printable, <= 1024),
  `yanked` (`true` or a reason), `core-metadata`/`dist-info-metadata`
  `{sha256}` (served as both), `size` (host bound only).

The page itself: `meta.api-version` `1.x`, `name` normalizing to the project.
The jail gets `{"meta":{"api-version":"1.0"},"name":NAME,"files":[...]}`:
no upstream URL reaches it.

```text
artifact  BODY... INDEX "\nagentbox.pip.batch.v1 " 20-DIGIT-LENGTH "\n"
INDEX     {"schema":"agentbox.pip.batch.v1","operation":OP,
           "items":[{"name","status":"ok"|"missing","bytes"[,"filename","sha256"]}]}
metadata  {"format":"agentbox.pip.batch.v1","items":N}
provenance  per fetched file {name: project, version: filename, integrity: sha256-BASE64}
```

HTTPS only, the host's resolver and system trust, TLS 1.2+, no redirect,
proxy, credential, cookie, retry or compression, one connection per GET.
Bounds: page 16 MiB, file 1 GiB, batch bodies 64 MiB (`files`) and 1.5 GiB
(`fetch`), the execution's acquired-byte allowance (2 GiB) and request
allowance (256 submissions), 600 s per request. Nothing is unpacked, built
or run on the host. Codes `pip_*` (`pip_policy_invalid`, `pip_args_invalid`,
`pip_page_invalid`, `pip_page_too_large`, `pip_file_mismatch`,
`pip_file_missing`, `pip_batch_too_large`, `pip_response_*`, `pip_fetch_failed`,
`pip_body_incomplete`, `pip_staging_*`), `acquire_limit`.

## Jail (acquisitions/pip/jail/)

`pip.py` is the session wrapper (`jail.session`, acquisitions/contracts/handlers/v1):
the guest runs every command of an enabling execution, and every
`agentbox shell` command, as `agentbox-session ARGV...`.

- With a request context, outside another session: a sidecar (double fork,
  own session, `/dev/null` stdio, none of the command's descriptors) serves
  the index; ARGV then replaces the wrapper with its received environment
  (`/proc/self/environ`) plus `PIP_INDEX_URL`, `PIP_RETRIES=0`,
  `PIP_TIMEOUT=1860`, `AGENTBOX_PIP_INDEX`, and `127.0.0.1,localhost`
  appended to `no_proxy`/`NO_PROXY` (pip would otherwise send loopback
  through the broker's `HTTP_PROXY`). pid, argv, descriptors, terminal,
  group, session, exit status: the command's.
- The sidecar ends when the command's process does (pidfd): an active host
  request cancelled, its batches closed. Descendants that outlive the
  command lose the index.
- Without a context, or nested: ARGV as is. A sidecar that cannot start:
  one stderr line, ARGV without the index.
- An exec that fails (a missing script interpreter, say): with the anchor's
  `--status=FD`, `f` there and nothing printed, so the guest reports a
  failed start as without the wrapper; a command's own exit 126/127 stays
  its exit. Without FD (the shell form): one stderr line, exit 127.

`index.py`: GET/HEAD only; a thread per connection (<= 32); keys queued
(<= 4096) and batched (50 ms window, <= 64, args <= 60 KiB), one host
request at a time; each delivered batch checked against its index; a key
waits at most 1800 s (then 504). A failed request answers its keys 424 with
`agentbox index request failed (CODE)` as the reason phrase (pip shows it;
it would retry 500/502/503); later keys get new requests; nothing is
retried. Each delivered batch is one unnamed file in `$TMPDIR`
(`tempfile.TemporaryFile`: `O_TMPFILE`; without it a fresh name unlinked
before any byte is written, so only a death in that instant leaves an
empty file), one descriptor each, open for the command's life; nothing
named stays when the sidecar is killed (its container removed at the
command's exit, say).

Defaults, not a boundary: `--index-url`, a config file's index or another
tool reaches past the adapter to the broker, under its own policy. pip runs
build hooks in the jail, also while resolving; compilers and headers are
the image's; a missing one fails the build and grants nothing.

## Limits not lifted here

- Each project page, metadata sidecar and file is usually its own host
  request (pip asks one at a time): about 2-3 per package against the
  execution's 256 submissions, shared with every handler.
- One request at a time per execution: a concurrent npm or Git request
  makes a pip key fail `request_busy`.
- PEP 691 JSON only: an HTML-only index fails `pip_page_invalid`. File
  origins must serve without redirects.

## Tests

`acquisitions/test_pip_index.py` (offline): the worker against a loopback
HTTPS fixture index; the jail index with the worker as its lane; the host's
real pip (25.x, Python 3.14 here) resolving
with backtracking, metadata sidecars, an sdist-only dynamic build
dependency, a source build and a C extension (setuptools wheel from
`/usr/share/python-wheels`, host `cc`), every proxy dead; the session
wrapper's argv, pid, status, signals, terminal and teardown; the guest's
exec (cancel included) and shell paths with the real wrapper.
