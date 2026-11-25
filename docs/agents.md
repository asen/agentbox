# Coding agents

`agentbox run AGENT` runs `pi`, `codex` or `claude` inside a jail. The trusted host adapter selects arguments and credentials; the jail runner launches the agent. `agentbox run -- COMMAND` bypasses the adapter.

```sh
agentbox run pi --prompt 'Explain this project' --workspace .
agentbox run codex --jail work                  # interactive, existing jail
agentbox run codex --jail work -- resume --last # let Codex resume its session
```

Use `--prompt-file FILE` instead of a literal prompt. `--model` goes to the agent, not the network broker. Selecting a model does not grant access to its provider. `--env NAME` forwards the current value to the guest command; the agent may print or persist it.

## Work and retention

| Target | After the agent exits |
| --- | --- |
| New headless jail | Discarded. Copying a workspace in does not copy changes back. |
| New jail with `--export-to PATH` | Discarded after successful publication; kept if export fails. Retry with `jail exec JAIL --export-to PATH -- true`. |
| New interactive jail | Normally retained; `--discard` or a provider requiring explicit retention makes it disposable. |
| `--jail JAIL` | Run record and retained storage stay. The managed execution still stops. |
| `--ssh-target FILE` | The operator owns the jail; Agentbox never stops it. |

Shared Podman requires explicit retention. For persistent work, create a jail with `--retention home`, then use `--jail`. Writable mounts change the host immediately; discard cannot undo them. `--workspace` and `--copy` stage inputs only on a run without earlier inputs or executions.

If settlement fails, inspect `jail status`, then `jail stop` before reuse or discard. For an unclean generation, `jail exec JAIL --allow-unclean GENERATION -- true` grants one recovery attempt.

## Interactive

Without a prompt, the agent owns the terminal. Arguments after `--` go to the agent. Interactive runs have no runtime cutoff. A headless run takes `--timeout SECONDS`; `--export-to` needs time left for transfer. Interactive runs have no automatic export. For package access see [artifact requests](artifact-requests.md#selection).

## Credentials

`--copy-auth FILE` reads one explicitly named private JSON file, not the host's credential directories. Existing guest credential files are not overwritten.

| Agent | Guest file | What crosses |
| --- | --- | --- |
| Pi | `~/.pi/agent/auth.json` | One provider: the `--model` prefix or sole entry. A literal API key, or an `openai-codex` access token with at least ten minutes left. No OAuth refresh token or command-backed key. |
| Codex | `~/.codex/auth.json` | Whole file, including refresh credentials. |
| Claude | `~/.claude/.credentials.json` | Whole file, including refresh credentials. |

The runner attempts removal on exit unless `--keep-auth`. Interrupted sessions can leave files behind. Even successful removal does not revoke a credential or prevent the jail from copying it. Mounting an agent directory exposes its contents directly.

## Install (`--install-agent`)

The image supplies the agents. To override one, use `--install-agent` on a headless run: npm resolves `latest`, or `--agent-version V` selects an exact version. This grants registry-wide read access for that execution, independent of `acquisition.json`; install scripts run in the jail. No general network access is added.

A completed install under `~/.local/share/agentbox-agents/AGENT` takes precedence over the image on later runs using that HOME. A failed install does not replace the current version. Old versions and npm's cache consume retained space.
