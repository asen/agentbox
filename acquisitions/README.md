# Acquisition handlers

Trusted Python workers fetch artifacts on the host. Untrusted clients apply them in the jail. Registration makes a handler available; only [session policy](../docs/artifact-requests.md#selection) enables it.

| Handler | Contract |
| --- | --- |
| pip | [Index metadata and distribution files](pip/contract/v1/README.md) |
| npm | [Registry metadata and verified tarballs](npm/contract/v1/README.md) |
| Git | [Read-only repositories](git/contract/v1/README.md) |

## Registering a handler

1. Add `ID/host/worker.py`. Dispatch operations with `agentbox_handler.main`. Write `STAGE/artifact`; report its size, SHA-256 and metadata. HTTP handlers must meter upstream bodies on success and failure.
2. Add `ID/manifest.json`. Declare the entry point, files, operations, metering, tools, limits and any jail module or shims. See the [handler contract](contracts/handlers/v1/README.md).
3. Enable it explicitly: `"handlers":{"ID":{"policy":"/abs/policy.json"}}`.

`agentbox-request` saves the delivered file. For guest-side application, bundle the handler's `jail/` package or add a module at [worker build](../images/worker/README.md) with `--counterparts`. `testing/echo` and `testing/memo` provide offline examples.

File and ownership checks do not sandbox the worker. Install only trusted interpreter, library and handler code.
