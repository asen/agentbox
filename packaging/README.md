# Packaging

The wheel ships the Python controller and server, the Rust relay and a trusted asset tree. Build on Linux x86-64 with Python 3.12+ and Rust 1.99. Installing a compatible wheel needs no Rust. The launchers use `/usr/bin/python3 -IB`, including inside a venv. Editable installs are unsupported.

```sh
python3 -m pip wheel --no-deps -w dist .
python3 -m pip install dist/agentbox-0.1.0-py3-none-linux_x86_64.whl
```

## Locations

| What | Default |
| --- | --- |
| Launchers and assets | `PREFIX/bin/`, `PREFIX/share/agentbox-assets/` |
| Controller and input-worker config | `$XDG_CONFIG_HOME/agentbox/{controller,host}.json` |
| Run records, image tags, logs | `$XDG_DATA_HOME/agentbox-controller` |
| Managed provider state | `$XDG_STATE_HOME/agentbox/{podman-shared,podman-private,qemu}` |
| Private Podman engine root | `$XDG_RUNTIME_DIR/agentbox-podman` |

Unset config, data and state roots default to `~/.config`, `~/.local/share` and `~/.local/state`. Uninstalling the package does not discard jails.

## Upgrades

Stop active commands before replacing files. Built-in runs use the running install's provider and their recorded state. Custom runs keep the exact interpreter, entry, assets and state paths recorded at prepare. Keep those paths available until the last dependent checkpoint or run is gone.

The image retains its baked worker; prepare a new image to change it. If recovery refuses `builtin_unavailable` or `provider_untrusted`, restore the trusted tree at the expected location and retry. No fallback or format migration.

## Stage without pip

```sh
cargo build --release --locked
python3 -I -B packaging/package.py --source "$PWD" \
  --relay-binary "$PWD/target/release/agentbox-relay" --out /opt/agentbox-0.1.0
```

Use absolute paths and a new output directory under a trusted writable parent. Failure can leave a private, incomplete tree; inspect and remove it yourself. Success prints the assets path. Move or copy the whole tree, not just `bin/`.

## Custom provider

```json
{"schema":"agentbox.provider-config.v1","provider":"qemu",
 "interpreter":"/usr/bin/python3",
 "entry":"/opt/agentbox-0.1.0/share/agentbox-assets/providers/qemu.py",
 "state":"/home/me/.local/state/agentbox-qemu",
 "assets":"/opt/agentbox-0.1.0/share/agentbox-assets"}
```

Use `agentbox image prepare qemu --provider-config CONFIG`. State and assets must be separate trees. Asset validation is not a sandbox; the provider is trusted host code.

Built-in profiles prepare their own inputs. For a custom profile, supply `STATE/inputs/qemu-build-inputs.json` and its named files, or `STATE/inputs/podman-inputs.json`. See the [QEMU](../images/qemu/README.md) and [Podman](../images/podman/README.md) recipes. For handler policies see [artifact selection](../docs/artifact-requests.md#selection).

## Attached jails

Build the bundle with the Podman recipe's `worker-export` target or the [source builder](../images/worker/README.md). It contains no interpreter; the jail needs Python 3.12+. See [SSH setup](../docs/ssh-worker.md).
