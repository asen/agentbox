---
description: This file is for humans to edit. Do not edit unless explicitly asked.
---
# agentbox

A secure sandbox to unleash (potentially malicious) full-blown coding agents and arbitrary code within the jail.

Likely an overkill today, possibly - the way to do it in the future :)

Or, thinking about it from another perspective - we all freakout when some known software has a RCE bug,
yet we are willingly giving a bunch of providers pretty much full RCE capabilities to our laptops. And we
often also give them credentials to access a bunch of other systems from our daily life.

How could this possibly go wrong?

Agentbox tries to mitigate the RCE part by allowing restricted access only to the hosts the respective model
provider/harness requires to be able to coll the LLM API. And by default - nothing else external other than a copy
of a dir or two you may want the agent to modify. Yet it can be a fully featured development system, and even supports
installation of npm and pip packages and usable git clone/fetch/pull commands. These do NOT use outbound connections
though (more on that below). The jails are started with no networking other than their own localhost at all.

Relatively safe extraction of the results/modifications, reviewing and applying these are inherently risky operations.
Figuring out the right balance there is hard, and you can always mount host dirs in the jail yourself if you know
what you are doing. Currently - supported in "dev" mode.

You can open up from there - additional HTTP CONNECT hosts may be allowed and/or local dirs can be mounted.

Supports qemu and podman/docker isolations. A true futuristic AI would almost guaranteed to be able to
attack and bypass any in-jail protections, and then eventually attack your host kernel. I don't think
that current LLMs are there yet and I don't have access to an unrestricted SOTA model to try. Please try it
for me and let me know how it goes if you have access to any of these :)

## Ideas:

* no outbound networking, strict allowlist of LLM provider hosts
  * accessible through a dumbed down host-side rust CONNECT-only https (transparent) proxy
    * you can not inspect that (encrypted) traffic in agentbox, it's up to you to set up a separate MITM proxy if you want
  * opened via *inbound* ssh 127.0.0.1 by the jail, before agent is started. Still not trusted.
    * in docker/podman environment - using docker/podman exec directly, no TCP involved
* The same connect proxy implements a special (RPC) HTTP POST requests where the requests are specific enums (and typed json bodies)
  * there is no full http protocol support
* both of these can be implemented using something like nginx.
  * feel that allowing a potentially malicious agent should not be given access to a full host-side http proxy - too much surface
* The agent in the jail can still get access to specific public tools:
  * the jail has helpers (not trusted by the host) which can use the mentioned typed POST to request package bundles/git repositories
  * the host itself will download whatever package/bundles are required from the internet. locally.
  * then scp these to the jail, from where the jail helper can complete the request
  * these are installed in /usr/local/bin and are shadowing and wrapping the system versions of these tools
    * intercepting specific sub-commands which require package download
  * for now: pip, npm, git, apt (soon)
* the box is closed only from teh inside, you can open as much as you want using inbound ssh tunnels and proxies.
* Running the agentbox with an agent is likely NOT safe - your agent might be coerced by the jail agent to open the box

## Usage

* `agentbox image ...` # manage QEMU/Podman images
* `agentbox jail ...` # manage jails 
* `agentbox run ...` # run an agent/program in a jail - newly created for the task or existing one
* `agentbox dev ...` # syntactic sugar around agentbox run, for more conventent usage of agentbox for regular dev env

For daily development, prepare the Podman dev image, then start an agent from your project directory:

 ```sh
   agentbox doctor
   agentbox image prepare podman --store shared --preset dev -t dev
   cd /path/to/project
   agentbox dev pi                  # or: agentbox dev codex | agentbox dev claude
 ```

dev retains the jail HOME and mounts the project read-write. Edits change your host files immediately.

For a one-off task, run a command or give an agent a private copy:

 ```sh
   agentbox run --image dev -- python3 --version
   agentbox run pi --image dev --workspace . --prompt 'Explain this project'
 ```

--workspace . copies files in; changes do not write back.

For a named jail you can reuse:

 ```sh
   agentbox jail create -t work --image dev --retention home
   agentbox jail exec work -- python3 -m venv .venv
   agentbox jail exec work -- .venv/bin/pip install requests
   agentbox jail status work
   agentbox jail discard work       # deletes the retained HOME
 ```

Full CLI reference: agentbox --help, or from the checkout: python3 -I -B src/main.py --help.

## security boundaries

* host vs jail
  * host must be trusted, do NOT let an unrestricted LLM harness manage your agentbox, it can potentially be
    coerced to "open the box" and the game is over.
    * a limited UI helper with no tools other that reading and reporting state may be safe
      * not recommended for now, maybe implemented in the future, using dumber model with few tools.
  * jail is considered potentially compromised from the moment an agent is started for the first time
* QEMU/diff kernel
    * the host kernel is still subject to attack if/when the jail one is taken over
    * being able to break the jail kernel may already get you a high bounty and/or famous for about 3 days :)
    * for high-risk models, tasked to actually break the agentbox (That would be unrestricted SOTA models which I 
      don't have access to) use a relatively isolated from inbound traffic host, breaking a cloud provider
      virtualization is probably harder and might get you famous/rich and/or banned and/or in actual jail.
* podman/docker container - different (usually - lesser) guarantees.
* No unrestricted outbound network access.
* Inbound/Control ssh connections via ssh over the loopback address
    * Opens a simple CONNECT-only rust HTTP proxy allowing access to whitelist of hosts/IP/ports
        * By default - only explicitly required for the harness to function hosts (LLM providers)
            * This does allow codex web_search to work
    * Opens a Unix socket dedicated to agent requests, for now - used for package install requests.

### safe package installation

* support safe (for the host and the package repositories) package installs:
* overrides pip and npm (others - soon) commands
  * for now a pointer to agentbox-request alternatives, soon to become mostly transparent
  * the system-wide pip/npm/etc binaries are superseded via PATH with custom wrappers
* these wrappers recognize the specific commands which require remote package downloading
* the request is sent to the host via the Unix socket.
* the host will
    * recognize the respective command
    * download required files to temp files in the host (nothing gets executed)
    * upload through scp vail loopback form the host to the jail
    * notify the jail command (Unix socket client) that the files are now available in the jail
* once notified, the wrapper will use the now available package files and do the local install.

### MCP

* MCP: In theory - should work for https-based MCP servers via the CONNECT proxy, after whitelisted
    * WARNING: Use at your own risk. You are not whitelisting URLs, you are whitelisting DNS host names.
    * The more you open, the larger surface a potentially malicios agent will have to attack you from the OUTSIDE
        * e.g. a RCE in a MCP server would give it a platform to attack your otherwise trusted agentbox host from the internet.
* a slightly safer approach is to use ssh connection and bind it to a Unix socket in the jail.
  * the agent can be configured to use a local stdio based MCP proxy
  * have an actual proxy in the host which does the actual http(s) request to the MCP server and can intercept the content
  * you get to control the specific URL the agent connects to and the agent can not attempt HTTP-level protocol attacks on the MCP servers
  * TBD - support this in agentbox to make it easy to setup.

## TODOs
* scrutinized web fetch (?)
  * GET vs POST probably doesn't matter?
  * no direct connection - request through the Unix socket, response pushed via ssh
* safe extraction from qemu - libguestfs
* (half-done) support rust CONNECT proxy behind a host-side CONNECT proxy.
* cargo, uv, pnpm
