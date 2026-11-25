#!/bin/sh
# Each coding agent's npm `latest`, resolved into OUT/AGENT: package.json (a
# private project of that one exact version) and package-lock.json, from
# REGISTRY's metadata only (no tarball fetched, no package script run).
# The Podman recipe's `agents-resolve` stage, at every prepare; agentlock.py
# checks the result before anything is installed (README.md here).
#
#   sh resolve.sh REGISTRY OUT
set -eu
registry=$1
out=$2
umask 022
mkdir "$out"
while read -r agent package; do
  mkdir "$out/$agent"
  printf '{"private": true}\n' > "$out/$agent/package.json"
  (cd "$out/$agent" && npm install --package-lock-only --ignore-scripts --save-exact --no-audit --no-fund \
     --no-update-notifier --registry="$registry" "$package@latest" </dev/null)
done <<EOF
pi @earendil-works/pi-coding-agent
codex @openai/codex
claude @anthropic-ai/claude-code
EOF
