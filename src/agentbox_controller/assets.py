"""The trusted asset tree this controller runs from, and the shared modules
it reuses from there: the provider contract codec and exchange checks
(providers/protocol.py), the providers' storage-scope rules
(providers/common.py), the guest protocol and artifact POST codecs
(guest/src/protocol.py, artifact_post_protocol.py) and the worker layout's
manifest rules (images/worker/worker.py).

ASSETS is the parent of this package's directory's parent
(ASSETS/controller/agentbox_controller installed, a checkout's
src/agentbox_controller; links resolved); nothing is looked up in the working
directory or PYTHONPATH (`python3 -I`).
"""
import importlib.util
import os
import sys

ASSETS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


def _load(name, relative):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, os.path.join(ASSETS, relative))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# providers/common.py imports `protocol` by its plain name: both load under
# their own names, the provider tree's modules only.
provider_protocol = _load("protocol", "providers/protocol.py")
provider_common = _load("common", "providers/common.py")
worker_layout = _load("agentbox_worker_layout", "images/worker/worker.py")

if ASSETS not in sys.path:
    sys.path.insert(0, ASSETS)
from guest.src import protocol as guest_protocol  # noqa: E402
from guest.src import artifact_post_protocol as post_codec  # noqa: E402
