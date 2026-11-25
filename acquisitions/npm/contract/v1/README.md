# npm registry v1

Host worker: `acquisitions/npm/host/worker.py`. Jail adapter and shims:
`acquisitions/npm/jail/`. Consumers: the
default lane (its packaged policy) or an operator's acquisition
configuration ([selection](../../../../docs/artifact-requests.md#selection)),
and `run AGENT --install-agent` (the controller enables it with the
packaged `agents/npm-registry.json`,
[agents](../../../../docs/agents.md#install---install-agent)).

Native npm in the jail resolves; the host only reads one operator-approved
registry, on npm's behalf, in bounded batches over the
[artifact POST](../../../contracts/artifacts/post-v1/README.md).

```text
jail                                              host
----                                              ----
npm/npx shim (bin/, ahead of the system's)
  real npm/npx, child, env:
    npm_config_registry=http://127.0.0.1:PORT/
    replace-registry-host=always, noproxy=127.0.0.1,localhost,
    audit=false fund=false update-notifier=false fetch-retries=0
    fetch-timeout=1860000 (past the adapter's own wait)
  adapter (127.0.0.1:PORT, this npm's only)
    GET /NAME            -> metadata key ------ POST submit npm metadata
    GET .../NAME/-/F.tgz -> tarball key           {"names":[..],"format":..}
    batches: <=256 keys, args <=60 KiB,   ------ POST submit npm tarballs
      one host request at a time                  {"packages":[{name,version}..]}
                                                 worker: policy registry only
                                                   GET REGISTRY/NAME (opaque)
                                                   GET REGISTRY/NAME/VERSION
                                                     name, version, dist.tarball
                                                     == REGISTRY/NAME/-/BASE-VERSION.tgz
                                                   GET that tarball, integrity checked
  copy to spool (TMPDIR), verified <-- scp ---  batch artifact, provenance recorded
  serve slices; missing -> 404
```

## Policy

```json
{"schema":"agentbox.npm.registry-policy.v1","registry":"https://registry.npmjs.org/"}
```

`https://HOST/[SEGMENT/...]`: a lowercase multi-label DNS name, port 443, no
userinfo, port, query, fragment or escape, ending in `/`. One registry; no
package allowlist; no credentials (a private registry is reachable only
anonymously). The policy is the authorization: the host's normal DNS and
system trust, as pip's and Git's.

## Operations

| op | args | per item |
| --- | --- | --- |
| `metadata` | `{"names":[NAME..],"format":"abbreviated"\|"full"}` | `GET REGISTRY/NAME` (`@SCOPE%2fNAME`), `Accept` install-v1 or JSON; 404 `missing`; body opaque |
| `tarballs` | `{"packages":[{"name":NAME,"version":VERSION}..]}` | version document parsed (at most 4 MiB): exact name and version, `dist.tarball` exactly the derived URL; tarball checked against `dist.integrity` (sha512), else `dist.shasum` (sha1); 404 on the document `missing` |

- 1-256 unique items. `NAME`: `NAME` or `@SCOPE/NAME`, parts
  `[A-Za-z0-9][A-Za-z0-9._~-]*`, at most 214 bytes. `VERSION`: exact SemVer,
  at most 256 bytes. No ranges, tags, URLs, paths or VCS specs.
- Never a guest URL: the worker builds every URL from the policy and the
  validated name and version. No redirect, proxy, credential, cookie, retry
  or compression; one HTTPS connection per GET.
- Bodies: a metadata batch at most 64 MiB, a tarball batch 500 MiB; every
  body byte read (documents, failed and partial bodies) counts against the
  execution's acquired-byte allowance
  ([handlers](../../../contracts/handlers/v1/README.md#limits)).
- Codes `npm_*`, `acquire_limit`; no URL, body or address leaves the worker.

## Batch artifact

```text
BODY... INDEX "\nagentbox.npm.batch.v1 " DDDDDDDDDDDDDDDDDDDD "\n"
INDEX = canonical {"schema":"agentbox.npm.batch.v1","operation":OP,
                   "items":[{"name","status":"ok"|"missing","bytes"[,"version","integrity"]}]}
```

20 decimal digits: the index's length. Ok items' bodies in order. Metadata
(`ready`): `{"format":"agentbox.npm.batch.v1","items":N}`. The adapter checks
size and SHA-256 against `ready`, then the index against the keys it asked
and the bytes.

## Provenance

A `tarballs` result line carries `provenance`, each tarball fetched
`{name, version, integrity}`; the host records them
(`host.handler.provenance`, one line each). Fetched, not installed.

## Jail

- Shims `npm`, `npx`: the real command is the first on `PATH` outside a
  directory holding `agentbox-request`. Inside an adapted npm
  (`AGENTBOX_NPM_REGISTRY` set) or without a request context: the real
  command, nothing more.
- One adapter per outer npm process; nested npm (lifecycle scripts) reuse
  it. Python's `http.server`, 127.0.0.1 only, at most 32 connections, idle
  ones closed after 30 s. Best effort: it grants nothing a jail process
  could not submit itself; the host authorizes, meters and verifies.
- Documents served as delivered: tarball URLs stay upstream, so lockfiles
  do too; `replace-registry-host=always` routes every registry tarball to
  the adapter, which takes the name and version from the path (any prefix
  before the name ignored).
- Unsupported: other methods (`405`: publish, login), other paths (`404`:
  audit, search, ping), Git, URL and file-tarball dependencies.
- Nothing retried: the first failed host request is reported once
  (`agentbox-npm: registry request failed (code=..)`) and every later miss
  is `503` without a submission. A concurrent npm in the same execution
  gets the host's `busy`.
- Waits: reading a request or an idle connection, 30 s; a GET's wait for
  its key, its queue behind earlier batches included, at most the host's
  whole-request clock (1800 s, never renewed), then `504` (its batch goes
  on). npm's `fetch-timeout` is set past it, so the adapter answers first.
- At the child's end: the listener closed, an active request cancelled and
  awaited (at most 15 s), the spool (`TMPDIR/agentbox-npm-*`) removed.
- Defaults, not a boundary: `--registry`, `.npmrc` scoped registries or
  other hosts reach the broker, whose policy decides as for any process.

Exposure: package names and versions the jail asks for reach the registry
from the host. Lifecycle scripts run in the jail under its general network
policy.
