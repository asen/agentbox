# Git acquisition v1

The Git handler acquires public GitHub repositories through the [artifact POST](../../../contracts/artifacts/post-v1/README.md). [Session configuration](../../../../docs/artifact-requests.md#selection) selects the handler and its policy. A repository saved in a jail never grants permission for a later request.

## Commands

```text
git [-C DIR] clone [--branch NAME | -b NAME] [FLAG...] [--] https://github.com/OWNER/REPO[.git] [DIR]
git [-C DIR] fetch [--] [REMOTE]
git [-C DIR] pull [--ff-only | --rebase | --no-rebase]

FLAG   --quiet | -q, --verbose, --progress, --filter=blob:none   each at most once
```

The flags are those pip passes (`pip install git+https://...@TAG`). They change neither the request nor the delivery: `--filter=blob:none` is served by the full bundle, the clone has every object and no promisor remote. pip then resolves and checks out its revision with local Git.

The shim resolves the fetch remote (default `origin`) inside the jail. A pull resolves the current branch's configured upstream (`branch.<name>.remote` and `.merge`), on every pull; no upstream, a local one or a detached HEAD is refused. Each command requests the host operation of the same name with a canonical lowercase `owner/name`, a clone also an optional selector; a pull requests `fetch`. The host derives the HTTPS URL; it does not accept a destination, arbitrary URL, shell command or Git options from the jail. Push is refused. Commands classified as local run the jail's Git. The shim is not the network boundary.

See [command cases](command-fixtures.json) and [repository and ref grammar cases](repository-fixtures.json) for accepted forms and refusal codes.

## Policy and delivery

The packaged policy grants `github-public-read-v1`. An operator can restrict it to named repositories:

```json
{"schema":"agentbox.git.request-policy.v1","grant":"github-public-read-v1","repositories":["octocat/hello-world"]}
```

The host worker uses anonymous HTTPS, without redirects, credentials or submodule recursion. It produces a self-contained Git bundle of the repository's branches and tags, or an empty-repository marker. The controller checks the staged artifact and uploads it; the guest verifies its size and digest before applying it. See the [handler interface](../../../contracts/handlers/v1/README.md) and [host prerequisites](../../../../docs/artifact-requests.md#host-prerequisites).

## Local application

The guest creates or updates the working repository using local Git. A selector chooses a branch or tag, not an arbitrary revision expression. Fetch uses the saved remote and explicit refspecs; its local paths and ref updates are not host inputs. Pull runs stock `git pull`, its fetch served from the verified delivery. See [guest application](guest-application.md) and [clone and fetch semantics cases](semantics-fixtures.json).
