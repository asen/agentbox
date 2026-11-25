# Guest worker

The worker runs commands in the jail. It is untrusted: host authorization, limits and cleanup do not depend on its reports. Managed images bake in the [source bundle](../images/worker/README.md); [attached jails](../docs/ssh-worker.md) receive it per execution. The jail supplies Python 3.12+.

`src/main.py` speaks the bounded [guest protocol](../contracts/v1/README.md) over SSH stdio. Commands get argv without a shell, a fixed environment, and null stdin unless explicitly enabled. Cancellation signals the guest process group, not a proof that all descendants ended. Interactive terminals use a separate SSH path.

`agentbox-request` and the handler shims submit [artifact requests](../docs/artifact-requests.md) to the session broker. They cannot grant host access. `home/` holds agent instructions, not enforcement.

```sh
python3 -I -B -m unittest discover -s guest/test -t .
```

Git application tests require the [fixture owner](../acquisitions/git/contract/v1/guest-application.md). Package adapter tests live under `acquisitions/`.
