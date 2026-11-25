# QEMU image

`agentbox image prepare qemu` builds an Ubuntu 26.04 LTS amd64 image and check-boots it before publication. Requires KVM, QEMU, Packer with its QEMU plugin, `xorriso`, `gpgv` and OpenSSH. See the [provider](../../providers/README.md#qemu).

## Inputs

Each built-in prepare resolves the current Ubuntu cloud disk and Node 24 release. `default/inputs.lock.json` names the update channels and allowed signers, not fixed versions. The controller verifies signed manifests with the packaged Ubuntu and Node keyrings, then checks file size and SHA-256. Verified bytes can be reused. An unknown or expired signing key refuses the build; signature verification does not prove freshness.

A custom state needs `inputs/qemu-build-inputs.json` and the files it names: a standalone QCOW2 base and a stable Linux x64 Node tarball (24+), each with exact bytes and digest. Optional `git` and `packages` inputs belong to custom recipes. Nothing fetches these files for a custom state.

## In the builder guest

**The build is not a jail.** Its NAT network can reach the internet, host LAN and VPN, and host loopback services via `10.0.2.2`. Use trusted inputs. The canonical recipe uses APT, installs Node and the [agents](../agents/README.md), and bakes the [worker](../worker/README.md) into the image. The running jail instead gets the provider's restricted NIC.

## Manual build

```sh
python3 -I images/worker/stage.py qemu --repo . --inputs INPUTS.json --out STAGE
packer init images/qemu/default/agentbox.pkr.hcl  # explicitly install the plugin
packer build -var-file STAGE/agentbox.pkrvars.hcl images/qemu/default/agentbox.pkr.hcl
python3 -I images/worker/stage.py publish --stage STAGE --output STAGE/output
```

Manual publication validates the disk, worker metadata and system record; it is not the provider's check boot. The provider boots the canonical disk behind an overlay and checks SSH, kernel, worker and tools. Custom recipes do not receive that check.

## Storage

Every prepare rebuilds. Distinct published images remain in state and count toward admission. Allow roughly 7 GB per image, space for inputs, and 8 GiB free for scratch.
