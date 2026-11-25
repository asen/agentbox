# acquisition.json

Without one, `jail exec`, `jail serve`, an interactive `run AGENT` and
`dev` enable the packaged npm, pip and read-only GitHub Git handlers
(Git needs `git` on the host PATH). A file replaces that set:

```sh
install -m 600 -D no-git.json ~/.config/agentbox/acquisition.json  # npm and pip, no Git
install -m 600 -D none.json   ~/.config/agentbox/acquisition.json  # no lane at all
```

`{}` names the handler's packaged policy. See
[artifact requests](../../docs/artifact-requests.md#selection).
