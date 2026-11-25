# Image agents

Both canonical recipes resolve these npm packages at every prepare; the repository pins no agent version.

| Command | Package |
| --- | --- |
| `pi` | `@earendil-works/pi-coding-agent` |
| `codex` | `@openai/codex` |
| `claude` | `@anthropic-ai/claude-code` |

`resolve.sh` resolves `latest` with scripts disabled. [agentlock.py](../worker/agentlock.py) checks one exact dependency per agent, lockfile v3, registry tarball URLs and SHA-512 integrity. It rejects Git, file and link dependencies. Incompatible optional packages are skipped; incompatible required packages fail.

Install scripts run in the trusted image build, not on the host. QEMU fetches locked tarballs first, then installs offline. Integrity is not publisher authentication. The image records each package, version and lock digest and exposes `/usr/local/bin/AGENT`. Start does not refresh it. To override the image in a jail HOME, use [`--install-agent`](../../docs/agents.md#install---install-agent).
