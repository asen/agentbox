# Podman image

```sh
agentbox image prepare podman                       # default recipe and tag
agentbox image prepare podman --preset dev -t dev   # development tools
agentbox run --image dev -- cargo --version
```

The recipe chooses software, not isolation. The [provider](../../providers/README.md#podman) controls mounts, networking, limits and retention. Prepare needs network access; start uses the measured image without pulling packages.

## Presets

Both recipes include Git, Python, venv, Node, the worker and coding agents. `default` has no compiler or Python headers. `dev` adds Python development headers (`python3-dev`), C/C++, make, pkg-config, Rust, Cargo, GDB, curl, SSH client and system pip. Use a venv for project packages. The running root is read-only; there is no runtime APT lane.

A private engine unpacks the image into tmpfs: allow space for the image **and** the workload. Typical unpack sizes are about 2.8 GiB (`default`) and 4.4 GiB (`dev`). `--preset` selects a packaged recipe; `-t` names its result. Do not combine `--preset` with `--recipe`.

## Accounts

Images leave UID/GID 1000 and `/home` free. The provider creates the selected workload account at 1000:1000 and binds its HOME at `/home/USER`. An account collision refuses creation. Keep machine credentials out of the image; SSH identities are per start.

## Agents

Each canonical build resolves Pi, Codex and Claude from the npm registry, checks locks, installs and verifies versions. Install scripts run during the trusted build. Integrity identifies bytes, not publishers. Failure does not move the tag. See [agent locks](../agents/README.md).

## Build and export (user-invoked; needs network)

Stage a fresh context; do not use the checkout as the build context. Use an empty output location for the worker export.

```sh
python3 -I images/worker/stage.py podman --repo . --out STAGE
podman build --squash-all -t localhost/agentbox-worker STAGE/context
podman save --format oci-archive -o image.oci.tar localhost/agentbox-worker
sha256sum image.oci.tar
podman image inspect --format '{{.Id}}' localhost/agentbox-worker
podman build --target worker-export --output type=local,dest=WORKER STAGE/context
```

`--squash-all` avoids copying intermediate layers into a private vfs store. For an attached SSH jail use the exported [worker bundle](../worker/README.md), not the OCI archive.
