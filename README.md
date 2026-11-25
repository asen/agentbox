# Agentbox

Run a command or coding agent in a Linux jail. Use rootless Podman for a
container, QEMU/KVM for a VM, or supply a jail over SSH. The host controls
the network broker.

## First run: Podman

Use a Linux x86-64 host with `/usr/bin/python3` 3.12+, cgroup v2, a systemd
user manager and rootless Podman. Building from source needs Rust 1.99.
See [host prerequisites](docs/host-readiness.md) and the
[Podman recipe](images/podman/README.md) for the required tools.

From the checkout:

```sh
python3 -m venv ~/.local/agentbox
~/.local/agentbox/bin/pip install .
export PATH="$HOME/.local/agentbox/bin:$PATH"
agentbox doctor                      # basic host checks, not a provider test
agentbox image prepare podman        # build the default image; needs network
agentbox run -- git --version        # fresh jail; discarded on exit
```

The image remains. No project or credential is needed for this command.
`agentbox run pi` starts an interactive agent instead. See
[agent runs](docs/agents.md) for authentication, prompts and retained jails.

## Working on host files

`--workspace` copies files in; changes do not write back. A Podman
`--mount-ro` exposes live host files. `--mount-rw` lets jail code change
them. Discarding the jail does not undo host writes.

`dev` keeps the jail HOME and mounts the current project **writable**.
From the project directory:

```sh
agentbox image prepare podman --store shared --preset dev -t dev   # once
agentbox dev pi
```

Optional `dev setup --share-agent-dirs` grants new dev jails writable access
to host agent directories. That exposes credentials and lets jail code alter
settings used later on the host. Leave sharing off unless you need it.
`--copy-auth FILE` instead supplies an explicit credential to an agent run;
the jail can read it. Deletion is not revocation.

## Configuration

Start with the built-in profiles. For overrides use `--config FILE` or
`$XDG_CONFIG_HOME/agentbox/controller.json` (default `~/.config/agentbox/controller.json`).
Use `agentbox --help` for commands and flags.

- [Host setup](docs/host-readiness.md) · [Installation and configuration](packaging/README.md)
- [Podman and QEMU providers, storage and limits](providers/README.md) · [QEMU image](images/qemu/README.md) · [Attached SSH jail](docs/ssh-worker.md)
- [Lifecycle and recovery](src/README.md) · [Architecture and trust boundary](docs/architecture.md) · [Artifact requests](docs/artifact-requests.md)

## Tests

```sh
python3 -I -B tests/run.py fast   # before commit; also run change-specific tests
python3 -I -B tests/run.py full   # before push or release
```
