"""Host-side staging of image build contexts (README.md here). Stdlib only;
runs nothing but `ssh-keygen` (QEMU's build-only key). Each context is a
fresh directory of explicitly allowlisted files, never the repository: no
.git, HUMAN.md, caches, tests, host auth or workspace.

  stage.py podman --repo REPO --out DIR [--counterparts DIR]
  stage.py qemu   --repo REPO --inputs FILE --out DIR [--counterparts DIR]
  stage.py publish --stage DIR --output DIR     (QEMU, after packer build)

`--counterparts` holds handlers' ready jail modules (`ID.py`, worker.py's
module doc), staged as
worker-counterparts/ (empty without it) for `worker.py build`. QEMU's
`--inputs` is the operator's closed agentbox.qemu-build-inputs.v1 file
(images/qemu/README.md). Both contexts carry what resolves the agents'
latest releases in the build and checks them there (agents/: AGENT_TOOLS,
resolve.sh and agentlock.py); no agent lock or tarball is staged. Every
staged file and every referenced recipe/script is measured into
stage.json, the input to later cache keys. Nothing is downloaded.
"""
import hashlib
import json
import os
import re
import stat
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGES = os.path.dirname(HERE)
# Importing the builder must not write a __pycache__ beside the shipped
# assets this script stages.
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)

import agentlock  # noqa: E402
import worker  # noqa: E402

Refused = worker.Refused
STAGE_SCHEMA = "agentbox.image-stage.v1"
INPUTS_SCHEMA = "agentbox.qemu-build-inputs.v1"
IMAGE_SCHEMA = "agentbox.qemu-image.v1"
PODMAN = os.path.join(IMAGES, "podman")
# Podman's canonical recipes, one per preset (images/podman/PRESET/), each
# measured into every stage.json: the default (also the context's
# Dockerfile) and the others' (README.md there).
PODMAN_RECIPES = ("default/Dockerfile", "dev/Dockerfile")
# QEMU's one preset, `default`: its recipe and guest-side files together.
QEMU = os.path.join(IMAGES, "qemu", "default")
# The worker tools every context carries.
WORKER_TOOLS = ("worker.py", "layout.json")
# QEMU's guest-side files, beneath QEMU (staged as the context's qemu/).
QEMU_GUEST = ("guest-install.py", "finalize.sh",
              "profile/99-agentbox.cfg", "profile/00-agentbox.conf", "profile/10-agentbox-identity.conf",
              "profile/99-agentbox-no-periodic")
QEMU_RECIPE = "agentbox.pkr.hcl"
HOME_GUIDANCE = ("AGENTS.md", "CLAUDE.md")
# The canonical build's record of the built system (guest-install.py),
# downloaded beside the disk and copied into image.json (`system`).
SYSTEM_MANIFEST = "image-manifest.json"
SYSTEM_SCHEMA = "agentbox.qemu-system.v1"
MAX_SYSTEM_BYTES = 1 << 20
MAX_SYSTEM_PACKAGES = 8192
KERNEL = re.compile(r"[0-9][A-Za-z0-9.+_-]{0,63}")
DEB_ARCH = re.compile(r"[a-z0-9-]{1,32}")
BUILD_USER = "agentbox-build"
KEYGEN = "/usr/bin/ssh-keygen"
MAX_INPUT_BYTES = 1 << 30
# The base disk alone, apart from MAX_INPUT_BYTES (the built-in profile's
# resolver caps its download the same: builtin.MAX_BASE_BYTES).
MAX_BASE_BYTES = 2 << 30
FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}")
DEB = re.compile(r"[a-z0-9][a-z0-9+.-]*")
DEB_VERSION = re.compile(r"[A-Za-z0-9.+:~_-]+")
NODE_PART = re.compile(r"0|[1-9][0-9]{0,4}")
NODE_MAJOR = 24
# The image's coding agents (images/agents/README.md): each agent's npm
# `latest`, resolved and locked in every build of either recipe.
AGENTS = agentlock.AGENTS
AGENTS_DIR = os.path.join(IMAGES, "agents")
# The agent tools: context agents/NAME, from DIR.
AGENT_TOOLS = (("resolve.sh", AGENTS_DIR), ("agentlock.py", HERE))
REGISTRY = agentlock.REGISTRY


def measured_tree(root):
    """[{path, size, sha256}] of every regular file beneath `root`; any
    other entry is refused."""
    out = []
    for rel, kind, links, _ in worker.scan(root):
        if kind == "file" and links == 1:
            size, digest = worker.measured(os.path.join(root, rel))
            out.append({"path": rel, "size": size, "sha256": digest})
        elif kind != "dir":
            raise Refused("context")
    return sorted(out, key=lambda e: e["path"])


def copy_file(source, target, perm=0o644):
    os.makedirs(os.path.dirname(target), 0o755, exist_ok=True)
    worker._copy(source, target, perm)
    return worker.measured(target)


def stage_worker(repo, ctx, counterparts=None):
    """Writes ctx/worker (tools), ctx/worker-src (allowlisted sources) and
    ctx/worker-counterparts (ready jail modules, possibly none); returns
    identities."""
    for name in WORKER_TOOLS:
        copy_file(os.path.join(HERE, name), os.path.join(ctx, "worker", name))
    files = worker.stage_sources(repo, os.path.join(ctx, "worker-src"))
    os.mkdir(os.path.join(ctx, "worker-counterparts"), 0o755)
    added = []
    for name, path in worker.counterparts(counterparts):
        size, digest = copy_file(path, os.path.join(ctx, "worker-counterparts", name))
        added.append({"path": name, "size": size, "sha256": digest})
    return {"sources": {"revision": worker.source_revision(files), "files": files}, "counterparts": added}


def write_json(path, value, perm=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, perm)
    with os.fdopen(fd, "wb") as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def recipe_files(names, base):
    return [{"path": os.path.relpath(os.path.join(base, n), IMAGES), "size": s, "sha256": d}
            for n in names for s, d in [worker.measured(os.path.join(base, n))]]


def stage_agent_tools(ctx):
    """ctx/agents/: AGENT_TOOLS. Returns their recipe entries."""
    for name, base in AGENT_TOOLS:
        copy_file(os.path.join(base, name), os.path.join(ctx, "agents", name))
    return [entry for name, base in AGENT_TOOLS for entry in recipe_files((name,), base)]


def stage_podman(repo, out, counterparts=None):
    """`out`/context: Dockerfile, worker/, worker-src/,
    worker-counterparts/, agents/ (AGENT_TOOLS); and `out`/stage.json."""
    os.mkdir(out, 0o700)
    ctx = os.path.join(out, "context")
    os.mkdir(ctx, 0o755)
    copy_file(os.path.join(PODMAN, PODMAN_RECIPES[0]), os.path.join(ctx, "Dockerfile"))
    identity = stage_worker(repo, ctx, counterparts)
    tools = stage_agent_tools(ctx)
    stage = {"schema": STAGE_SCHEMA, "target": "podman", "worker": identity,
             "recipe": recipe_files(PODMAN_RECIPES, PODMAN) + recipe_files(WORKER_TOOLS + ("stage.py",), HERE)
             + tools,
             "context": measured_tree(ctx)}
    write_json(os.path.join(out, "stage.json"), stage)
    return stage


def _asset(value, base, total, limit=MAX_INPUT_BYTES):
    """The input file beside the inputs, exactly as declared; its declared
    size counted into `total` and bounded by `limit` before anything is
    read."""
    if total[0] + value["bytes"] > limit:
        raise Refused("limit")
    path = os.path.join(base, value["file"])
    size, digest = worker.measured(path)
    if (size, digest) != (value["bytes"], value["sha256"]):
        raise Refused("input_mismatch")
    total[0] += size
    return path


def node_version_ok(text):
    """The image's Node for npm and agents: a stable `MAJOR.MINOR.PATCH`
    (no suffix or leading zero) of at least `NODE_MAJOR`. The worker needs
    none."""
    parts = text.split(".")
    return (len(parts) == 3 and all(NODE_PART.fullmatch(part) is not None for part in parts)
            and int(parts[0]) >= NODE_MAJOR)


def load_inputs(path):
    """The operator's closed QEMU build inputs; every file beside it, with
    its exact size and SHA-256. The whole schema is checked before any
    file is opened. `base` and `node` may carry their provenance
    (`source`, recorded, not read). `git` and `packages` are optional operator extras, staged
    as before for a custom recipe; the canonical recipe installs Git and
    Python's venv with APT and ignores them. Returns (value, {role: path})."""
    try:
        value = json.loads(worker.read_small(path, 65536))
    except ValueError:
        raise Refused("inputs") from None
    if not isinstance(value, dict) or not {"schema", "base", "node"} <= set(value) \
            or not set(value) <= {"schema", "base", "node", "git", "packages"} \
            or ("git" in value) != ("packages" in value) or value["schema"] != INPUTS_SCHEMA:
        raise Refused("inputs")
    node, git, packages = value["node"], value.get("git"), value.get("packages", [])
    if not isinstance(node, dict) or set(node) - {"source"} != {"file", "bytes", "sha256", "version"} \
            or ("source" in node and not isinstance(node["source"], dict)) \
            or not isinstance(node["version"], str) or not node_version_ok(node["version"]) \
            or node["file"] != f"node-v{node['version']}-linux-x64.tar.xz":
        raise Refused("inputs")
    base = value["base"]
    if not isinstance(base, dict) or set(base) - {"source"} != {"file", "bytes", "sha256"} \
            or ("source" in base and not isinstance(base["source"], dict)):
        raise Refused("inputs")
    if git is not None and (not isinstance(git, dict) or set(git) != {"file", "bytes", "sha256"}):
        raise Refused("inputs")
    if not isinstance(packages, list) or len(packages) > 64 or (git is not None and not packages):
        raise Refused("inputs")
    names = set()
    for entry in packages:
        if not isinstance(entry, dict) or set(entry) != {"name", "version", "file", "bytes", "sha256"} \
                or not isinstance(entry["name"], str) or DEB.fullmatch(entry["name"]) is None \
                or not isinstance(entry["version"], str) or DEB_VERSION.fullmatch(entry["version"]) is None \
                or not isinstance(entry["file"], str) or not entry["file"].endswith(".deb") \
                or entry["name"] in names:
            raise Refused("inputs")
        names.add(entry["name"])
    extras = ([git] if git is not None else []) + packages
    for entry in [base, node, *extras]:
        if not isinstance(entry["file"], str) or FILE.fullmatch(entry["file"]) is None \
                or type(entry["bytes"]) is not int or entry["bytes"] <= 0 \
                or not isinstance(entry["sha256"], str) or worker.DIGEST.fullmatch(entry["sha256"]) is None:
            raise Refused("inputs")
    staged = [node["file"]] + [entry["file"] for entry in extras]
    if len(set(staged)) != len(staged):
        raise Refused("inputs")
    directory, total = os.path.dirname(os.path.abspath(path)), [0]
    paths = {"base": _asset(base, directory, [0], MAX_BASE_BYTES), "node": _asset(node, directory, total)}
    if git is not None:
        paths["git"] = _asset(git, directory, total)
    for entry in packages:
        paths["deb:" + entry["file"]] = _asset(entry, directory, total)
    return value, paths


def build_key(out):
    """A fresh build-only Ed25519 key pair, host-only; never uploaded."""
    keys = os.path.join(out, "build-key")
    os.mkdir(keys, 0o700)
    key = os.path.join(keys, "id_ed25519")
    subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", BUILD_USER, "-f", key],
                   env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL, capture_output=True,
                   timeout=60, check=True)
    public = worker.read_small(key + ".pub", 4096).decode().strip()
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68} " + BUILD_USER, public):
        raise Refused("key")
    return key, public


def seed(out, public, instance):
    """The build boot's NoCloud seed: one passwordless sudo build account
    reachable only by the build key; nothing else configured."""
    path = os.path.join(out, "seed")
    os.mkdir(path, 0o755)
    user_data = ("#cloud-config\n"
                 "ssh_pwauth: false\n"
                 "disable_root: true\n"
                 "package_update: false\n"
                 "package_upgrade: false\n"
                 "users:\n"
                 f"  - name: {BUILD_USER}\n"
                 "    lock_passwd: true\n"
                 "    shell: /bin/sh\n"
                 "    sudo: \"ALL=(ALL) NOPASSWD:ALL\"\n"
                 f"    ssh_authorized_keys: [\"{public}\"]\n")
    meta_data = f"instance-id: {instance}\nlocal-hostname: {BUILD_USER}\n"
    for name, text in (("user-data", user_data), ("meta-data", meta_data)):
        fd = os.open(os.path.join(path, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
    return path


def hcl(text):
    return json.dumps(text)


def stage_qemu(repo, inputs, out, counterparts=None):
    """`out`/context (uploaded to the builder guest), `out`/seed,
    `out`/build-key (host-only), `out`/agentbox.pkrvars.hcl, stage.json."""
    value, paths = load_inputs(inputs)
    os.mkdir(out, 0o700)
    out = os.path.abspath(out)
    ctx = os.path.join(out, "context")
    os.mkdir(ctx, 0o755)
    identity = stage_worker(repo, ctx, counterparts)
    for name in QEMU_GUEST:
        copy_file(os.path.join(QEMU, name), os.path.join(ctx, "qemu", name))
    for name in HOME_GUIDANCE:
        copy_file(os.path.join(repo, "guest", "home", name), os.path.join(ctx, "home", name))
    copy_file(paths["node"], os.path.join(ctx, "inputs", value["node"]["file"]))
    if "git" in value:
        copy_file(paths["git"], os.path.join(ctx, "inputs", value["git"]["file"]))
    for entry in value.get("packages", []):
        copy_file(paths["deb:" + entry["file"]], os.path.join(ctx, "inputs", "debs", entry["file"]))
    tools = stage_agent_tools(ctx)
    guest_inputs = {"schema": INPUTS_SCHEMA, "node": value["node"]}
    if "git" in value:
        guest_inputs.update(git=value["git"], packages=value["packages"])
    write_json(os.path.join(ctx, "inputs.json"), guest_inputs)
    write_json(os.path.join(ctx, "context.json"), {"files": measured_tree(ctx)})
    key, public = build_key(out)
    instance = "agentbox-build-" + hashlib.sha256(public.encode()).hexdigest()[:16]
    seed_dir = seed(out, public, instance)
    variables = {"base_image": paths["base"], "base_sha256": value["base"]["sha256"], "context": ctx,
                 "seed": seed_dir, "build_key": key, "output": os.path.join(out, "output")}
    with open(os.path.join(out, "agentbox.pkrvars.hcl"), "x") as stream:
        for name, text in variables.items():
            stream.write(f"{name} = {hcl(text)}\n")
    stage = {"schema": STAGE_SCHEMA, "target": "qemu", "worker": identity, "base": value["base"],
             "node": value["node"],
             "recipe": recipe_files((QEMU_RECIPE,) + QEMU_GUEST, QEMU)
             + recipe_files(WORKER_TOOLS + ("stage.py",), HERE) + tools,
             "context": measured_tree(ctx), "seed": measured_tree(seed_dir)}
    write_json(os.path.join(out, "stage.json"), stage)
    return stage


def publish(stage_dir, output):
    """After the build: the standalone disk, the downloaded worker metadata
    and exported bundle, and the stage's identities in image.json."""
    stage = json.loads(worker.read_small(os.path.join(stage_dir, "stage.json"), 1 << 22))
    if stage.get("schema") != STAGE_SCHEMA or stage.get("target") != "qemu":
        raise Refused("stage")
    disk = os.path.join(output, "agentbox.qcow2")
    st = os.lstat(disk)
    if not stat.S_ISREG(st.st_mode):
        raise Refused("output")
    with os.fdopen(worker.opened(disk), "rb") as stream:
        head = stream.read(4)
        stream.seek(0)
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if head != b"QFI\xfb":
        raise Refused("output")
    release, _ = worker.validate(os.path.join(output, "worker"))
    metadata = worker.check_metadata(os.path.join(output, worker.METADATA["file"]), release)
    if metadata["sources"]["revision"] != stage["worker"]["sources"]["revision"]:
        raise Refused("metadata")
    system = None
    if os.path.lexists(os.path.join(output, SYSTEM_MANIFEST)):
        system = check_system(os.path.join(output, SYSTEM_MANIFEST))
    image = {"schema": IMAGE_SCHEMA, "status": "built_native_unvalidated",
             "disk": {"file": "agentbox.qcow2", "format": "qcow2", "bytes": st.st_size, "sha256": digest},
             "worker": {"release": release, "metadata_sha256": worker.measured(
                 os.path.join(output, worker.METADATA["file"]))[1]},
             "stage_sha256": worker.measured(os.path.join(stage_dir, "stage.json"))[1],
             "base": stage["base"], "recipe": stage["recipe"]}
    if "node" in stage:
        image["node"] = stage["node"]
    if system is not None:
        image["system"] = system
    write_json(os.path.join(output, "image.json"), image)
    return image


def check_system(path):
    """The canonical build's system record (guest-install.py), bounded and
    closed: the build boot's kernel, the newest installed one (the one the
    disk boots), every installed one; every installed package; the npm
    sandbox's observed isolation; the baked agents (`agents`: each its own
    package, the version and lock digest the build resolved, verified and
    installed)."""
    try:
        value = json.loads(worker.read_small(path, MAX_SYSTEM_BYTES))
    except ValueError:
        raise Refused("system") from None
    if not isinstance(value, dict) or set(value) != {"schema", "kernel", "packages", "apt", "sandbox", "agents"} \
            or value["schema"] != SYSTEM_SCHEMA:
        raise Refused("system")
    kernel, packages = value["kernel"], value["packages"]
    if not isinstance(kernel, dict) or set(kernel) != {"build", "intended", "installed"} \
            or not all(isinstance(kernel[k], str) and KERNEL.fullmatch(kernel[k]) for k in ("build", "intended")) \
            or not isinstance(kernel["installed"], list) or not 0 < len(kernel["installed"]) <= 16 \
            or not all(isinstance(k, str) and KERNEL.fullmatch(k) for k in kernel["installed"]) \
            or kernel["intended"] not in kernel["installed"]:
        raise Refused("system")
    if not isinstance(packages, list) or not 0 < len(packages) <= MAX_SYSTEM_PACKAGES or not all(
            isinstance(p, list) and len(p) == 3 and all(isinstance(f, str) for f in p)
            and DEB.fullmatch(p[0]) and DEB_ARCH.fullmatch(p[1]) and DEB_VERSION.fullmatch(p[2]) for p in packages):
        raise Refused("system")
    if value["apt"] != {"phased_updates": "never", "recommends": False} or not isinstance(value["sandbox"], dict) \
            or value["sandbox"].get("isolated") is not True:
        raise Refused("system")
    agents = value["agents"]
    if not isinstance(agents, dict) or sorted(agents) != sorted(AGENTS) or not all(
            isinstance(entry, dict) and set(entry) == {"package", "version", "lock_sha256"}
            and entry["package"] == agentlock.PACKAGES[agent] and isinstance(entry["version"], str)
            and agentlock.NPM_VERSION.fullmatch(entry["version"]) is not None
            and isinstance(entry["lock_sha256"], str) and worker.DIGEST.fullmatch(entry["lock_sha256"]) is not None
            for agent, entry in agents.items()):
        raise Refused("system")
    return value


def _args(argv, names, optional=()):
    names = names + optional[:max(0, len(argv) // 2 - len(names))]
    if len(argv) != 2 * len(names) or argv[0::2] != ["--" + n for n in names]:
        raise Refused("usage")
    return [os.path.abspath(a) for a in argv[1::2]]


def main(argv):
    if argv[:1] == ["podman"]:
        stage_podman(*_args(argv[1:], ("repo", "out"), ("counterparts",)))
    elif argv[:1] == ["qemu"]:
        stage_qemu(*_args(argv[1:], ("repo", "inputs", "out"), ("counterparts",)))
    elif argv[:1] == ["publish"]:
        print(json.dumps(publish(*_args(argv[1:], ("stage", "output"))), indent=2))
    else:
        raise Refused("usage")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (Refused, OSError, subprocess.SubprocessError) as error:
        code = error if isinstance(error, Refused) else type(error).__name__
        print(f"agentbox-stage refused: {code}", file=sys.stderr)
        sys.exit(1)
