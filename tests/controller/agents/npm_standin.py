"""Test-only stand-in for the jail's npm (never packaged), called by the
common runner in place of `npm` (harness.py patches its runner copy, so
no real npm is ever found): each call logged to HOME/npm-log.jsonl;
`view` answers 9.9.9; `install --global --prefix DIR ... NAME@V` asks the
npm lane once (`agentbox-request npm metadata`), then lays DIR out as npm
does, every agent's command a relative link to the stand-in agent."""

import json
import os
import shutil
import subprocess
import sys

argv = sys.argv[1:]
home = os.environ["HOME"]
with open(os.path.join(home, "npm-log.jsonl"), "a") as stream:
    stream.write(json.dumps(argv) + "\n")
if argv[0] == "view":
    print('"9.9.9"')
    sys.exit(0)
prefix, spec = argv[3], argv[-1]
name = spec.rsplit("@", 1)[0]
asked = subprocess.run(["agentbox-request", "npm", "metadata", json.dumps({"names": [name], "format": "full"})],
                       stdin=subprocess.DEVNULL, stdout=sys.stderr, check=False)
if asked.returncode != 0:
    sys.exit(1)
package = os.path.join(prefix, "lib", "node_modules", name)
os.makedirs(package)
os.makedirs(os.path.join(prefix, "bin"))
shutil.copyfile(os.path.join(home, ".local", "bin", "pi"), os.path.join(package, "cli.js"))
os.chmod(os.path.join(package, "cli.js"), 0o755)
for command in ("pi", "codex", "claude"):
    os.symlink(os.path.join("..", "lib", "node_modules", name, "cli.js"), os.path.join(prefix, "bin", command))
print("added 1 package")
