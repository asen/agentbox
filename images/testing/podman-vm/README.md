# Podman test VM

A standalone Ubuntu 26.04 KVM fixture for rootless Podman. Not a provider or production jail. **Do not distribute the disk:** it contains test SSH identities. The outer VM has internet and LAN access; `passt --no-map-gw` removes gateway-to-host-loopback mapping, not general host reachability. No host directory is shared.

## Commands

```sh
python3 -I -B images/testing/podman-vm/vm.py build [--root ROOT]
python3 -I -B images/testing/podman-vm/vm.py start ROOT
python3 -I -B images/testing/podman-vm/vm.py ssh ROOT [--admin] [CMD...]
python3 -I -B images/testing/podman-vm/vm.py stop ROOT
python3 -I -B images/testing/podman-vm/vm.py smoke ROOT --archive OCI --sha256 HEX --image-id HEX
```

Build verifies the Ubuntu cloud disk, provisions a 20 GiB overlay (2 vCPU, 4096 MiB; needs 5120 MiB available), then produces a standalone disk. `vmadmin` has sudo; `abtest` (2001:3001) does not. `ROOT` holds the disk, keys, metadata, logs and instance state. Keep it private.

`start` boots the disk directly: changes persist. One VM per root. After interruption use `stop ROOT` to recover its recorded instance. `smoke` needs an idle root and uses a disposable overlay. It verifies the supplied OCI digest and tests keep-id and VM-local RO/RW binds. It does not exercise provider custody, retained HOME, the SSH bridge or agents.

Offline tests (no VM): `python3 -I -B -m unittest discover -s images/testing/podman-vm -p 'test_*.py'`.
