"""A stand-in provider for controller tests: the real contract codec
(protocol.py copied beside it), behaviour from STATE/behavior.json, every
invocation appended to STATE/log.jsonl (with STATE/inputs/podman-inputs.json's
store, when present: `inputs_store`).

behavior.json:
  transport      "tcp" | "stdio"
  user home control host_key worker_sha256
  retention features limits   the capabilities (default ["none"], [], LIMITS)
  checkpoints    true: `checkpoint` and `restore` advertised
  volume         a retained resource's `created.volume` (the provider's
                 HOME volume name, e.g. Podman's shared store)
  metadata       a worker-metadata.json to publish for `prepare`
  prepare create discard checkpoint restore
                 "ok" | "fail" | "hang" (answers a cancel) | "lost" (exits
                 without an answer) | a failure code (create: e.g.
                 "user_conflict", start: a mount code)
  start          "ok" | "fail" | "die" (exit after `started`)
                 | "hang" (answers a cancel) | "hang_ignore" (never answers)
                 | a failure code; an unclean resource refuses without
                 accept_unclean
  stop           "settled" | "unsettled" | "hang" (never answers; frames logged)
  stop_storage   "clean" | "unclean" (`stopped`'s durability: unchanged | uncertain)
  failed_durability  a failure code's durability (default "unchanged")
  engine         true: an engine child in D/engine, left running at stop

Resources and checkpoints are files under STATE/resources and
STATE/checkpoints (`{generation, storage}`).
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol  # noqa: E402

LIMITS = ["cpus", "memory_mib", "pids"]
STATE = None


def log(state, entry):
    with open(os.path.join(state, "log.jsonl"), "a") as stream:
        stream.write(json.dumps(entry) + "\n")


def membership(custody):
    """The leaf of D holding this process, by its cgroup.procs files."""
    if not custody:
        return None
    pid = str(os.getpid())
    for name in sorted(os.listdir(custody)):
        procs = os.path.join(custody, name, "cgroup.procs")
        if os.path.isfile(procs):
            with open(procs) as stream:
                if pid in stream.read().split():
                    return name
    return None


def write(frame):
    protocol.write_frame(sys.stdout.buffer, frame)


def read():
    data = protocol.read_frame(sys.stdin.buffer)
    return None if data is None else protocol.decode_request(data)


def failed(request, code, settlement="settled", durability="unchanged"):
    write({"type": "failed", "operation": request["operation"], "op": request["type"], "code": code,
           "settlement": settlement, "durability": durability})


def stopped(request, behavior=None):
    storage = (behavior or {}).get("stop_storage", "clean")
    durability = "uncertain" if storage == "unclean" else "unchanged"
    generation = request["generation"] + (1 if durability != "unchanged" else 0)
    resource = _load(STATE, "resources", request["resource"])
    if resource is not None:
        _save(STATE, "resources", request["resource"], dict(resource, generation=generation, storage=storage))
    write({"type": "stopped", "operation": request["operation"], "run": request["run"],
           "resource": request["resource"], "execution": request["execution"],
           "instance": request["instance"], "settlement": "settled", "durability": durability,
           "generation": generation, "storage": storage})


def _load(state, kind, name):
    try:
        with open(os.path.join(state, kind, name + ".json")) as stream:
            return json.load(stream)
    except FileNotFoundError:
        return None


def _save(state, kind, name, value):
    os.makedirs(os.path.join(state, kind), exist_ok=True)
    with open(os.path.join(state, kind, name + ".json"), "w") as stream:
        json.dump(value, stream)


def _mode(behavior, request):
    """`ok`, or what `hang`, `lost`, `fail`/code did (True: answered)."""
    mode = behavior.get(request["type"], "ok")
    if mode == "ok":
        return False
    if mode == "hang":
        frame = read()
        if frame is not None:
            log(STATE, {"frame": frame["type"]})
            failed(request, "cancelled")
        return True
    if mode == "lost":
        return True
    failed(request, "failed" if mode == "fail" else mode, durability=behavior.get("failed_durability", "unchanged"))
    return True


def lifecycle(behavior, request, state):
    kind = request["type"]
    if kind == "create" and behavior.get("create") == "hang":
        # Allocated, then hung.
        _save(state, "resources", request["resource"], {"generation": 0, "storage": "clean"})
    if _mode(behavior, request):
        return
    if kind == "prepare":
        image = hashlib.sha256(request["recipe"].encode()).hexdigest()
        entry = os.path.join(state, "images", image)
        os.makedirs(entry, exist_ok=True)
        target = os.path.join(entry, "worker-metadata.json")
        shutil.copyfile(behavior["metadata"], target)
        os.chmod(target, 0o600)
        prepared = {"type": "prepared", "operation": request["operation"], "image": image,
                    "worker_sha256": behavior["worker_sha256"]}
        if behavior.get("agents"):
            # Sent as given, unchecked: the host's decoding is under test.
            prepared = {"v": 1, **prepared, "agents": behavior["agents"]}
            sys.stdout.buffer.write(json.dumps(prepared, separators=(",", ":")).encode() + b"\n")
            sys.stdout.buffer.flush()
        else:
            write(prepared)
    elif kind == "create":
        _save(state, "resources", request["resource"], {"generation": 0, "storage": "clean",
                                                        "mounts": request.get("mounts", [])})
        created = {"type": "created", "operation": request["operation"], "run": request["run"],
                   "resource": request["resource"], "retention": request["retention"], "generation": 0,
                   "user": request["user"], "home": behavior["home"]}
        if behavior.get("volume") and request["retention"] != "none":
            created["volume"] = behavior["volume"]
        write(created)
    elif kind == "discard":
        name = request.get("checkpoint")
        kind_dir, ident = ("checkpoints", name) if name else ("resources", request["resource"])
        if _load(state, kind_dir, ident) is None:
            failed(request, "not_found")
            return
        os.unlink(os.path.join(state, kind_dir, ident + ".json"))
        frame = {"type": "discarded", "operation": request["operation"], "run": request["run"],
                 "resource": request["resource"], "settlement": "settled"}
        if name:
            frame["checkpoint"] = name
        write(frame)
    elif kind == "checkpoint":
        resource = _load(state, "resources", request["resource"])
        if resource["storage"] == "unclean" and not request["accept_unclean"]:
            failed(request, "unclean")
            return
        _save(state, "checkpoints", request["checkpoint"], dict(resource))
        write({"type": "checkpointed", "operation": request["operation"], "run": request["run"],
               "resource": request["resource"], "checkpoint": request["checkpoint"],
               "generation": request["generation"], "storage": resource["storage"]})
    elif kind == "restore":
        saved = _load(state, "checkpoints", request["checkpoint"])
        _save(state, "resources", request["resource"], dict(saved, generation=request["generation"] + 1))
        write({"type": "restored", "operation": request["operation"], "run": request["run"],
               "resource": request["resource"], "checkpoint": request["checkpoint"],
               "generation": request["generation"] + 1, "storage": saved["storage"]})


def stop(behavior, request):
    mode = behavior.get("stop", "settled")
    if mode == "hang":
        while True:
            frame = read()
            if frame is None:
                return
            log(STATE, {"frame": frame["type"]})
    if mode == "unsettled":
        failed(request, "failed", "unsettled")
    else:
        stopped(request, behavior)


def engine(custody):
    path = os.path.join(custody, "engine")
    os.makedirs(path, exist_ok=True)
    child = subprocess.Popen(["sleep", "1000"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    with open(os.path.join(path, "cgroup.procs"), "a") as stream:
        stream.write(f"{child.pid}\n")
    return child.pid


def main(argv):
    args = protocol.parse_argv(argv)
    state = args[1]
    global STATE
    STATE = state
    with open(os.path.join(state, "behavior.json")) as stream:
        behavior = json.load(stream)
    custody = os.environ.get("AGENTBOX_CUSTODY")
    entry = {"argv": args[0], "pid": os.getpid(), "custody": custody, "leaf": membership(custody),
             "scopes": os.environ.get("AGENTBOX_STORAGE_SCOPES")}
    if args[0] == "connect":
        entry.update(env=sorted(os.environ), path=os.environ.get("PATH"))
        log(state, entry)
        # A bridge: a banner, then its input echoed until EOF.
        try:
            os.write(1, b"standin-connect\n")
            while True:
                data = os.read(0, 65536)
                if not data:
                    break
                os.write(1, data)
        except OSError:
            pass
        return 0
    request = read()
    entry["type"] = request["type"]
    try:
        # A built-in Podman STATE's engine store, as the real provider reads it.
        with open(os.path.join(state, "inputs", "podman-inputs.json")) as stream:
            entry["inputs_store"] = json.load(stream).get("store", "private")
    except FileNotFoundError:
        pass
    entry.update({k: request[k] for k in ("user", "retention", "mounts", "accept_unclean", "limits", "recipe",
                                          "resource", "checkpoint") if k in request})
    log(state, entry)
    kind = request["type"]
    if kind == "capabilities":
        operations = list(protocol.REQUIRED_OPERATIONS)
        if behavior.get("checkpoints"):
            operations += list(protocol.OPTIONAL_OPERATIONS)
        write({"type": "described", "operation": request["operation"], "provider": "standin",
               "operations": operations, "transport": behavior.get("transport", "tcp"),
               "retention": behavior.get("retention", ["none"]), "limits": behavior.get("limits", LIMITS),
               "features": behavior.get("features", [])})
        return 0
    if kind == "stop":
        stop(behavior, request)
        return 0
    if kind != "start":
        lifecycle(behavior, request, state)
        return 0
    mode = behavior.get("start", "ok")
    resource = _load(state, "resources", request["resource"])
    if resource is not None and resource["storage"] == "unclean" and not request["accept_unclean"]:
        failed(request, "unclean")
        return 0
    if mode not in ("ok", "die", "hang", "hang_ignore"):
        failed(request, "failed" if mode == "fail" else mode)
        return 0
    if mode in ("hang", "hang_ignore"):
        frame = read()
        if frame is not None:
            log(state, {"frame": frame["type"]})
        if frame is not None and frame["type"] == "cancel" and mode == "hang":
            failed(request, "cancelled")
        while mode == "hang_ignore" and read() is not None:
            pass
        return 0
    if behavior.get("engine") and custody:
        log(state, {"engine": engine(custody)})
    transport = {"kind": "stdio"} if behavior.get("transport") == "stdio" else \
        {"kind": "tcp", "host": "127.0.0.1", "port": 2222}
    write({"type": "started", "operation": request["operation"], "run": request["run"],
           "resource": request["resource"], "execution": request["execution"],
           "instance": request["instance"], "generation": request["generation"], "transport": transport,
           "user": behavior["user"], "host_key": behavior["host_key"],
           "worker_sha256": behavior["worker_sha256"], "home": behavior["home"],
           "control": behavior["control"]})
    if mode == "die":
        time.sleep(float(behavior.get("die_after", 0.5)))
        return 3
    while True:
        frame = read()
        if frame is None:
            log(state, {"eof": True})
            return 0
        log(state, {"frame": frame["type"]})
        if frame["type"] == "stop":
            stop(behavior, frame)
            return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
