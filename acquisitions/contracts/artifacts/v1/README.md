# Artifact timing profile v1

[`timing.json`](timing.json) records the host's timing constants. It is a test contract, not runtime configuration. `tests/server/test_ingress.py` checks the following values against the server, controller lane and handler ceilings:

| Clock | Limit |
| --- | ---: |
| Handler acquisition | 600 s |
| Upload | 60 s |
| Request | 1800 s |
| Control write | 10 s |
| Cleanup reserve | 250 ms |

A phase limit cannot extend the request or execution deadline. See the [POST contract](../post-v1/README.md) for framing and cancellation.
