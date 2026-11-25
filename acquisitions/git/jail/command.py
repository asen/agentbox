"""Pure classification of a `git` argument vector into the supported v1 forms
of acquisitions/git/contract/v1. No I/O, config reading, Git invocation or relay.

This is a usability interface, not a security boundary: aliases, scripts,
`-c alias.*`, subcommands that run other commands and the real Git binary
bypass it, and gain no network route. It never classifies shell text, only
argv items, and it never builds argv for host tools. `local` means "not
intercepted": the real Git runs it. Global options follow one closed table of
Git's own; an unknown or incomplete global is refused rather than guessed
past, so no command behind it is presented as intercepted.

A command is a dict by `kind`: `clone` (repository, url, selector?, directory,
cwd?), `fetch` (remote, cwd?), `pull` (flag?, cwd?), `local` or `refused`
(code)."""

from acquisitions.git.jail.repository import (
    URL_PREFIX, is_selector, parse_repository_url, repository_id, repository_url,
)
from guest.src.protocol import is_id

COMMAND_CODES = (
    "git_push_refused", "git_command_unsupported", "git_option_unsupported", "git_arguments_invalid",
    "git_url_unsupported", "git_selector_invalid", "git_remote_unsupported",
)

DEFAULT_REMOTE = "origin"

# Globals whose value is the next item; those starting `--` also take `=VALUE`.
VALUED_GLOBALS = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--attr-source")
# Globals that take only `=VALUE`.
ATTACHED_GLOBALS = ("--exec-path=", "--list-cmds=")
FLAG_GLOBALS = ("-p", "--paginate", "-P", "--no-pager", "--no-replace-objects", "--no-lazy-fetch",
                "--no-optional-locks", "--no-advice", "--bare", "--literal-pathspecs", "--glob-pathspecs",
                "--noglob-pathspecs", "--icase-pathspecs")
# Globals after which Git runs no named command: it prints and exits, or runs help or version.
EXITING_GLOBALS = ("--exec-path", "--html-path", "--man-path", "--info-path", "--help", "-h", "--version", "-v")
# Upstream writes besides `push`.
PUSHES = ("send-pack", "http-push")
# Commands that only exist to contact a remote.
NETWORK_ONLY = ("ls-remote", "fetch-pack", "request-pull")
# Clone flags pip's VCS support passes (`--filter=blob:none` and its verbosity
# flags), each at most once: output only, and a partial-clone filter the full
# delivery already satisfies. Spellings of one flag share a tuple.
CLONE_FLAGS = (("--quiet", "-q"), ("--verbose",), ("--progress",), ("--filter=blob:none",))
# A pull's integration choices, at most one; without one, the configured strategy.
PULL_FLAGS = ("--ff-only", "--rebase", "--no-rebase")

LOCAL = {"kind": "local"}


def _refused(code):
    return {"kind": "refused", "code": code}


def classify_git_command(args):
    """Classifies the items after `git`."""
    cwd = []
    other = False
    index = 0
    while index < len(args) and args[index].startswith("-"):
        item = args[index]
        if item in EXITING_GLOBALS:
            return dict(LOCAL)
        if item in VALUED_GLOBALS:
            if index + 1 >= len(args):
                return _refused("git_arguments_invalid")
            if item == "-C":
                cwd.append(args[index + 1])
            else:
                other = True
            index += 2
        elif (item in FLAG_GLOBALS
              or any(name.startswith("--") and item.startswith(name + "=") for name in VALUED_GLOBALS)
              or any(item.startswith(prefix) for prefix in ATTACHED_GLOBALS)):
            other = True
            index += 1
        else:
            # Unknown to this profile, `--` included: the command cannot be known.
            return _refused("git_option_unsupported")
    if index >= len(args):
        return dict(LOCAL)
    command, rest = args[index], list(args[index + 1:])
    if command == "push" or command in PUSHES:
        return _refused("git_push_refused")
    if command in ("clone", "fetch", "pull"):
        if other or len(cwd) > 1:
            return _refused("git_option_unsupported")
        directory = cwd[0] if cwd else None
        if directory == "" or any("\0" in item for item in args):
            return _refused("git_arguments_invalid")
        at = {} if directory is None else {"cwd": directory}
        return {"clone": _clone, "fetch": _fetch, "pull": _pull}[command](rest, at)
    if command in NETWORK_ONLY:
        return _refused("git_command_unsupported")
    if command == "archive" and any(item == "--remote" or item.startswith("--remote=") for item in _options(rest)):
        return _refused("git_command_unsupported")
    if command == "remote":
        return _remote(rest)
    if command == "submodule":
        return _submodule(rest)
    if command == "lfs":
        return _lfs(rest)
    return dict(LOCAL)


def _remote(rest):
    """`remote [-v | --verbose] [--] SUB ...`. Network subcommands: `update`,
    `prune`, `show` without `-n`, `add` with `-f`/`--fetch`, `set-head` with
    `-a`/`--auto`. Their options are recognized only before a `--`."""
    index = 0
    while index < len(rest) and rest[index].startswith("-"):
        item = rest[index]
        index += 1
        if item == "--":
            break
        if item not in ("-v", "--verbose"):
            return _refused("git_option_unsupported")
    sub = rest[index] if index < len(rest) else None
    flags = _options(rest[index + 1:])
    if sub in ("update", "prune"):
        return _refused("git_command_unsupported")
    if sub == "show" and "-n" not in flags:
        return _refused("git_command_unsupported")
    if sub == "add" and any(item in ("-f", "--fetch") for item in flags):
        return _refused("git_command_unsupported")
    if sub == "set-head" and any(item in ("-a", "--auto") for item in flags):
        return _refused("git_command_unsupported")
    return dict(LOCAL)


def _submodule(rest):
    """`submodule [--quiet | -q | --cached] [--] SUB ...`; `update` and `add` acquire."""
    index = 0
    while index < len(rest) and rest[index].startswith("-"):
        item = rest[index]
        index += 1
        if item == "--":
            break
        if item not in ("--quiet", "-q", "--cached"):
            return _refused("git_option_unsupported")
    sub = rest[index] if index < len(rest) else None
    if sub in ("update", "add"):
        return _refused("git_command_unsupported")
    return dict(LOCAL)


def _lfs(rest):
    """`lfs SUB ...`; `push` writes, `fetch`, `pull` and `clone` acquire."""
    sub = rest[0] if rest else None
    if sub == "push":
        return _refused("git_push_refused")
    if sub in ("fetch", "pull", "clone"):
        return _refused("git_command_unsupported")
    if sub is not None and sub.startswith("-") and sub not in ("--version", "--help", "-h"):
        return _refused("git_option_unsupported")
    return dict(LOCAL)


def _options(items):
    """The option-looking items before the first `--`."""
    items = list(items)
    if "--" in items:
        items = items[:items.index("--")]
    return [item for item in items if item.startswith("-")]


def _clone(rest, at):
    """`clone [--branch NAME | -b NAME | --branch=NAME] [FLAG...] [--] URL [DIR]`,
    FLAG one of CLONE_FLAGS, options before the URL."""
    selector = None
    flags = set()
    positional = []
    ended = False
    index = 0
    while index < len(rest):
        item = rest[index]
        if not ended and item == "--":
            ended = True
        elif not ended and item.startswith("-"):
            flag = next((spellings for spellings in CLONE_FLAGS if item in spellings), None)
            if positional or (flag is None and selector is not None) or flag in flags:
                return _refused("git_option_unsupported")
            if flag is not None:
                flags.add(flag)
            elif item in ("--branch", "-b"):
                if index + 1 >= len(rest):
                    return _refused("git_arguments_invalid")
                selector = rest[index + 1]
                index += 1
            elif item.startswith("--branch="):
                selector = item[len("--branch="):]
            else:
                return _refused("git_option_unsupported")
        else:
            positional.append(item)
        index += 1
    if len(positional) < 1 or len(positional) > 2:
        return _refused("git_arguments_invalid")
    url = positional[0]
    repository = parse_repository_url(url)
    if repository is None:
        return _refused("git_url_unsupported")
    if selector is not None and not is_selector(selector):
        return _refused("git_selector_invalid")
    # Git's default: the URL's last segment as typed, without `.git`.
    typed = url[len(URL_PREFIX):].split("/")[1]
    directory = positional[1] if len(positional) > 1 else (typed[:-4] if typed.endswith(".git") else typed)
    if directory == "" or directory.startswith("-"):
        return _refused("git_arguments_invalid")
    command = {"kind": "clone", "repository": repository_id(repository), "url": repository_url(repository)}
    if selector is not None:
        command["selector"] = selector
    command["directory"] = directory
    command.update(at)
    return command


def _fetch(rest, at):
    """`fetch [--] [REMOTE]`, remote `origin` by default; no options or refspecs."""
    positional = []
    ended = False
    for item in rest:
        if not ended and item == "--":
            ended = True
        elif not ended and item.startswith("-"):
            return _refused("git_option_unsupported")
        else:
            positional.append(item)
    if len(positional) > 1:
        return _refused("git_arguments_invalid")
    remote = positional[0] if positional else DEFAULT_REMOTE
    if not is_remote_name(remote):
        return _refused("git_remote_unsupported")
    return dict({"kind": "fetch", "remote": remote}, **at)


def _pull(rest, at):
    """`pull [FLAG]`, FLAG one of PULL_FLAGS: the current branch's configured
    upstream only; no remote, refspec, URL or `--`."""
    if any(not item.startswith("-") for item in rest):
        return _refused("git_arguments_invalid")
    if len(rest) > 1 or any(item not in PULL_FLAGS for item in rest):
        return _refused("git_option_unsupported")
    command = {"kind": "pull"}
    if rest:
        command["flag"] = rest[0]
    command.update(at)
    return command


def is_remote_name(text):
    """A configured remote's name, never a URL or path: an id that is also a ref component."""
    return is_id(text) and ".." not in text and not text.endswith(".lock") and not text.endswith(".")
