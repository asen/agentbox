# The `dev` preset of the canonical Agentbox Podman worker image
# (`agentbox image prepare podman --preset dev`; ../README.md#presets): the
# default recipe's base, runtime contract, worker and agents, plus Ubuntu's
# full development toolchain. Opt-in; the default recipe (../default/Dockerfile)
# installs none of it. An ordinary image recipe: it
# selects image bytes for a target; it approves nothing about host
# isolation, which is the provider's and the same for every image.
#
# Build context: the default recipe's (stage.py), unchanged. The build needs
# network access (base images, Ubuntu packages, the agents' npm metadata
# and tarballs); the worker's assembly, the agents' lock checks and their
# start checks run without network.

# Ubuntu 26.04 LTS (resolute), the newest stable LTS: the multi-arch index
# docker.io/library/ubuntu:26.04 resolved 2026-11-21 (also `resolute` and
# `latest` then), the default recipe's. Its packages come from the archive
# at build time.
ARG UBUNTU=docker.io/library/ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db
# The image's Node, for npm and agents, as the default recipe's: the
# official runtime, major 24 or later (Ubuntu's own is 22, never used).
ARG NODE=docker.io/library/node:24-bookworm-slim

# Node and npm, from the selected official image.
FROM ${NODE} AS node

# The worker, assembled from the staged sources without network with this
# release's python3 (3.14; the worker needs 3.12 or later).
FROM ${UBUNTU} AS worker
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
COPY worker/ /build/worker/
COPY worker-src/ /build/worker-src/
COPY worker-counterparts/ /build/worker-counterparts/
RUN --network=none /usr/bin/python3 -I -B /build/worker/worker.py build \
      --sources /build/worker-src --out /out --counterparts /build/worker-counterparts

# The coding agents' latest releases, resolved at every build (a prepare's
# build store is its own: nothing cached): each agent's exact tree locked
# from the registry's metadata, no tarball fetched, no package code run.
# Only /out/AGENT/package{,-lock}.json leaves this stage.
FROM ${NODE} AS agents-resolve
COPY agents/resolve.sh /build/resolve.sh
RUN sh /build/resolve.sh https://registry.npmjs.org/ /out

# The resolved locks checked without network before anything is installed
# from them (agentlock.py: the agents' own packages, registry tarballs at
# their exact URLs, sha512 integrity).
FROM worker AS agents-check
COPY agents/agentlock.py /build/agentlock.py
COPY --from=agents-resolve /out/ /checked/
RUN --network=none /usr/bin/python3 -I -B /build/agentlock.py check \
      --registry https://registry.npmjs.org/ /checked

# The coding agents, each its checked lock's exact tree: `npm ci` checks
# every tarball against the lock's integrity; install scripts run here, in
# the build. Only /opt/agentbox-agents leaves this stage, readable by
# everyone, writable by root only.
FROM ${NODE} AS agents
COPY --from=agents-check /checked/ /opt/agentbox-agents/
RUN set -eu; \
    for agent in pi codex claude; do \
      npm ci --prefix "/opt/agentbox-agents/$agent" --omit=dev --no-audit --no-fund \
        --no-update-notifier --registry=https://registry.npmjs.org/; \
    done; \
    chmod -R u=rwX,go=rX /opt/agentbox-agents

# The default recipe's runtime, from Ubuntu's own packages (Git, its full
# build: HTTPS, SSH; CA certificates; Python with venv), plus pip and the
# toolchain: C/C++ (build-essential), pkg-config, Rust and Cargo, GDB,
# curl and the SSH client. Ubuntu's default coreutils (uutils on 26.04)
# stay: the checks below probe exactly what the runtime runs with them.
FROM ${UBUNTU}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates cargo curl gdb git libstdc++6 openssh-client openssh-server \
      pkg-config python3 python3-dev python3-minimal python3-pip python3-venv rustc tini zlib1g \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
# The agents at the path they were installed at, each command on PATH.
COPY --from=agents --chown=0:0 /opt/agentbox-agents/ /opt/agentbox-agents/
RUN for agent in pi codex claude; do \
      ln -s "/opt/agentbox-agents/$agent/node_modules/.bin/$agent" "/usr/local/bin/$agent"; \
    done
# No workload account (the default recipe's rule): Ubuntu's own uid 1000
# user and its group go.
RUN if id ubuntu >/dev/null 2>&1; then userdel --remove ubuntu; fi \
 && if getent group ubuntu >/dev/null; then groupdel ubuntu; fi

# Build-time contract checks: the default recipe's (the toolchain
# required, not refused), and the runtime's own shell probes with this
# image's coreutils (the SSH bootstrap's stat, wc and sha256sum forms;
# the PID 1 sleep). They check the recipe's result, never the host.
RUN set -eu; \
    if getent passwd 1000 >/dev/null || getent group 1000 >/dev/null; then \
      echo "uid or gid 1000 is taken" >&2; exit 1; fi; \
    test -d /etc && test ! -L /etc && test -d /home && test ! -L /home && test -z "$(ls -A /home)"; \
    test -f /etc/passwd && test ! -L /etc/passwd && test -f /etc/group && test ! -L /etc/group; \
    for path in /usr/bin/tini /usr/bin/sleep /usr/sbin/sshd /bin/sh \
        /usr/bin/uname /usr/bin/id /usr/bin/stat /usr/bin/mkdir /usr/bin/chmod \
        /usr/bin/wc /usr/bin/sha256sum /usr/bin/cat /usr/bin/timeout \
        /usr/bin/python3 /usr/bin/git /usr/local/bin/node /usr/local/bin/npm \
        /usr/bin/cc /usr/bin/gcc /usr/bin/g++ /usr/bin/make /usr/bin/pkg-config /usr/bin/gdb \
        /usr/bin/rustc /usr/bin/cargo /usr/bin/curl /usr/bin/ssh; do \
      test -x "$path" || { echo "missing $path" >&2; exit 1; }; \
    done; \
    printf '#include <Python.h>\n' | /usr/bin/cc $(/usr/bin/python3-config --includes) -x c -fsyntax-only -; \
    /usr/bin/python3 -I -c 'import ensurepip, sys, venv; assert sys.version_info >= (3, 12)'; \
    /usr/bin/python3 -I -S -B -c 'import sys; assert sys.version_info >= (3, 12)'; \
    test "$(/usr/local/bin/node -p 'process.versions.node.split(".")[0]')" -ge 24; \
    /usr/local/bin/npm --version >/dev/null; \
    for agent in pi codex claude; do \
      test -x "/usr/local/bin/$agent" || { echo "missing agent $agent" >&2; exit 1; }; \
      /usr/local/bin/node -e 'const [d] = process.argv.slice(1); \
        const [[n, v]] = Object.entries(require(d + "/package.json").dependencies); \
        if (require(d + "/node_modules/" + n + "/package.json").version !== v) process.exit(1)' \
        "/opt/agentbox-agents/$agent" || { echo "agent $agent is not its locked version" >&2; exit 1; }; \
    done; \
    test -z "$(find /opt/agentbox-agents ! -type l \( ! -perm -o=r -o -type d ! -perm -o=x \) -print -quit)" \
      || { echo "agents not readable by the workload" >&2; exit 1; }; \
    set -- $(/usr/bin/git --version | sed -n 's/^git version \([0-9]*\)\.\([0-9]*\).*/\1 \2/p'); \
    test "$1" -gt 2 || { test "$1" -eq 2 && test "$2" -ge 53; }; \
    test -x "$(/usr/bin/git --exec-path)/git-remote-https"; \
    test -s /etc/ssl/certs/ca-certificates.crt; \
    tmp="$(mktemp -d)"; \
    git -C "$tmp" init -q src; \
    git -C "$tmp/src" -c user.name=check -c user.email=check@localhost commit -q --allow-empty -m check; \
    git -c protocol.allow=never -c protocol.file.allow=always clone -q "file://$tmp/src" "$tmp/dst"; \
    git -C "$tmp/dst" rev-parse --verify HEAD >/dev/null; \
    [ "$(uname -s)" = Linux ]; [ "$(uname -m)" = x86_64 ]; [ "$(id -u)" = 0 ]; \
    chmod 700 "$tmp"; \
    [ "$(stat -c %u -- "$tmp")" = 0 ]; [ $((0$(stat -c %a -- "$tmp") & 022)) -eq 0 ]; \
    [ "$(stat -c %a -- "$tmp")" = 700 ]; \
    printf abc > "$tmp/f"; \
    size=$(wc -c < "$tmp/f"); [ $size -eq 3 ]; \
    printf '%s  %s\n' ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad "$tmp/f" \
      | sha256sum -c --status -; \
    if printf '%s  %s\n' 0000000000000000000000000000000000000000000000000000000000000000 "$tmp/f" \
      | sha256sum -c --status - 2>/dev/null; then exit 1; fi; \
    chmod 444 "$tmp/f"; [ "$(stat -c %u -- "$tmp/f")" = 0 ]; \
    status=0; timeout 2 /usr/bin/sleep infinity || status=$?; [ $status -eq 124 ]; \
    rm -rf "$tmp"

# Each agent starts with no network and a scratch HOME, removed after: a
# release that does not is no image.
RUN --network=none set -eu; \
    scratch="$(mktemp -d)"; \
    for agent in pi codex claude; do \
      HOME="$scratch" TMPDIR="$scratch" timeout 120 "/usr/local/bin/$agent" --version </dev/null >/dev/null \
        || { echo "agent $agent does not start" >&2; exit 1; }; \
    done; \
    rm -rf "$scratch"

# The worker: only the worker stage's runtime output, copied to its fixed
# paths, then validated and sealed in place (root's; directories 0555, every
# file 0444) by the builder, mounted for this step only.
# No source, compiler or builder stays. Never secrets: the workload reads
# every byte, in every container of this image.
COPY --from=worker --chown=0:0 /out/worker/ /opt/agentbox/worker/
COPY --from=worker --chown=0:0 /out/worker-metadata.json /opt/agentbox/worker-metadata.json
RUN --network=none --mount=type=bind,from=worker,source=/build/worker,target=/run/agentbox-worker \
    /usr/bin/python3 -I -B /run/agentbox-worker/worker.py seal
