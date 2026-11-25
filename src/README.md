# Host controller and server

`agentbox_controller` owns the CLI, run records, provider lifecycle, SSH sessions and recovery. `agentbox_server` brokers network requests and uploads approved artifacts. Both ship under `PREFIX/share/agentbox-assets/controller/`. See [architecture](../docs/architecture.md) and the [server protocol](../docs/server-protocol.md).

```sh
python3 -I -B src/main.py --help
```

For execution from a checkout, configure a packaged server. Installed launchers resolve assets from their own prefix, not the current directory.

## Recovery

1. Inspect `agentbox jail status JAIL`. Do not infer settlement from a missing PID.
2. `agentbox jail stop JAIL` settles recorded local custody and asks the provider to stop. Lost creates or restores may be `partial`: discard, do not reuse. Unknown outcomes remain blocked.
3. If stop lists unproven local work, verify that exact operation has ended before using `--assert-local-ended ID`. This records **your assertion**, not proof of a kill. An input delivery marked `inputs_setup_uncertain` still blocks reuse; discard the record and create another. An attached jail's remote state is never cleaned this way.
4. An export assertion (`x-HEX`) releases its reservation but does not remove its partial file. The destination was not stored. Inspect its directory yourself.

## Entry points

| Concern | Modules in `agentbox_controller/` |
| --- | --- |
| CLI and defaults | `cli.py`, `config.py` |
| Managed resources | `lifecycle.py`, `provider.py`, `cgroups.py`, `states.py` |
| Commands, agents and shells | `execute.py`, `commandrun.py`, `agentrun.py`, `interactive.py`, `shell.py` |
| Data crossing the boundary | `inputs.py`, `mounts.py`, `export.py`, `acquisition.py`, `server.py` |

Run the [offline suites](../README.md#tests) from the repository root.
