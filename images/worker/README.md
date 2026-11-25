# Worker bundle

`stage.py` stages sources for either image recipe. `worker.py` builds the same stdlib-only bundle for both. No interpreter, compilation or package install. The jail supplies Python 3.12+.

## Inputs

`guest/src/`, the guest and acquisition package markers, and each handler's `acquisitions/ID/jail/*.py`. Only allowlisted regular source files are copied. Optional `--counterparts DIR` adds a ready `ID.py` at `acquisitions/ID/jail/ID.py`; it cannot replace a bundled source. A counterpart runs in the guest and grants no host authority.

## Layout

```text
out/worker/manifest.json     version, revision and file digests
out/worker/{guest,acquisitions}/...
out/worker-metadata.json     manifest, entrypoints, source and builder identities
```

[layout.json](layout.json) defines the layout and limits. `revision` identifies the staged source listing; `release` is the manifest SHA-256. The metadata identifies the payload without containing it. Managed images install a root-owned, read-only bundle at `/opt/agentbox/worker`. For an [attached jail](../../docs/ssh-worker.md), export the bundle and supply the manifest's revision in the target file. SSH launchers are generated per execution.

Build examples: [Podman](../podman/README.md#build-and-export-user-invoked-needs-network), [QEMU](../qemu/README.md#manual-build).
