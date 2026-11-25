# Jail providers

Providers are trusted host programs. The controller owns the run record, authorizes each operation and holds its custody domain. The provider owns the resource and reports its capabilities. Unsupported requests fail; they do not select a weaker backend. See the [wire contract](../contracts/provider/v1/README.md) and [host prerequisites](../docs/host-readiness.md).

| | QEMU/KVM | Rootless Podman |
| --- | --- | --- |
| Boundary | VM | Container; shares host kernel |
| SSH transport | Pinned SSH over a loopback port | Pinned SSH over provider stdio |
| Retention | None or disk | None or HOME; private store also supports `home_tmp` |
| Checkpoints | Stopped disk only | No |
| Host mounts | No | Explicit, retained HOME only |
| Limits | CPU, memory, pids, overlay file size | CPU, memory, pids; no disk quota |

## Lifecycle and recovery

`prepare` publishes an image. `create` binds the resource to it. Each `start` establishes fresh SSH identities and an owner session. `stop` must settle the instance before reuse. `discard` removes its resource, not the image or the controller's logs.

After interruption, inspect `jail status`; use `jail stop` to settle. A dead process is not proof that the resource is clean. Uncertain state blocks reuse. Never repair it by editing records, guessing a PID or deleting provider state. An unclean generation needs explicit acceptance. See [controller recovery](../src/README.md).

Admission measures declared storage scopes. It is not a filesystem quota. Images, failed work and retained resources can consume space after a command ends.

## QEMU

Requires KVM, `qemu-system-x86_64`, `qemu-img`, Packer and its QEMU plugin, `xorriso`, `ssh` and `ssh-keygen`. Use `packer plugins installed` to check discovery. See [image inputs and build](../images/qemu/README.md).

The canonical prepare verifies its base, builds a standalone QCOW2 image and check-boots it before publication. Custom recipes are not check-booted. The base stays read-only. Each VM has a private overlay, fresh seed and a restricted NIC with only a loopback SSH forward. The fixed account is `agentbox`.

Defaults: 2 CPUs, 4096 MiB guest memory, 512 pids. The default overlay file limit is the virtual disk size plus 1 GiB, not extra space inside the guest. A checkpoint captures stopped disk contents, not memory. Restore requires the same image; current-controller checkpoint and restore lack native qualification.

## Podman

Requires a non-root user, rootless Podman, `conmon`, `crun` and `ssh-keygen`. See the [image recipe](../images/podman/README.md). The container has no general network interface to the host. SSH uses the provider bridge. Each start replaces the container; only the requested storage persists.

`image prepare podman --store shared|private` overrides `podman_store` (default `shared`). Later operations use the resource's recorded store, not the current setting.

| Store | Behavior |
| --- | --- |
| Private | Fresh engine store on executable tmpfs. Size for image unpacking as well as the running container. Retained volume data is separate. |
| Shared | Uses your initialized rootless store. The measured image is loaded by ID without a tag. `shared_store_uninitialized`: initialize your rootless store outside Agentbox or use `private`. |

Shared HOME is the named volume `agentbox-home-RESOURCE`. Stop leaves it; discard removes it **by name**. Do not replace it manually. `podman volume prune` can destroy a stopped jail's HOME. `podman image prune` can remove the untagged image; prepare again. Store growth is outside Agentbox admission. Agentbox never prunes the user's store.

Defaults: 2 CPUs, 6144 MiB memory, 1024 pids. Memory includes the engine and its tmpfs. The minimum is 1024 MiB, or 1536 MiB for mounted runs; a particular image may need more. HOME has no size cap. `disk_mib` is refused, not silently ignored.

### Shared mounts

Create a jail with `--retention home`, then grant only the directories it needs with `--mount-ro` or `--mount-rw`. Use `--project` to choose the working directory. Read-only still exposes secrets. Writable changes survive discard, including hostile edits to code, hooks and agent settings later used on the host.

Sources are resolved again at start, not pinned. Destination checks run before workload binds. Mounted runs use keep-id; the first start may add mapped image layers to your store. A missing source can prevent start but not discard.

Agentbox rejects known engine, store and configuration paths. That list is **not exhaustive**. Never mount custom engine helpers, mount programs, hooks, seccomp profiles, registry credentials, additional image stores or writable parents of such dependencies. Agentbox trusts host configuration; it cannot discover everything a custom runtime reads. Shared-mode containment is not qualified.
