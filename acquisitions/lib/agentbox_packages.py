"""The npm and pip workers' shared HTTPS pieces: the registry host grammar,
the system trust and the request's test seam.

TLS: the host's own resolver and the system trust (TLS 1.2 or later,
certificate and hostname verified). The request's `test` seam (the host's
test build only) is {"endpoint": "localhost:PORT", "ca_file": ABS}: every
source's host is replaced by `localhost:PORT`, trusting only that CA.
"""

import re
import ssl

from agentbox_handler import Refused, plain_path

USER_AGENT = "agentbox-acquisition/1"

LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOST = re.compile(r"%s(?:\.%s)+" % (LABEL, LABEL))
ENDPOINT = re.compile(r"localhost:([1-9][0-9]{0,4})")


def context(ca_file):
    """The system trust (or the seam's CA alone), TLS 1.2 or later,
    certificate and hostname verified."""
    if ca_file is None:
        tls = ssl.create_default_context()
    else:
        tls = ssl.create_default_context(cafile=ca_file)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.check_hostname = True
    tls.verify_mode = ssl.CERT_REQUIRED
    return tls


def seam(request):
    """The test seam's (endpoint, ca_file), or (None, None)."""
    test = request.test
    if test is None:
        return None, None
    endpoint = test.get("endpoint")
    match = ENDPOINT.fullmatch(endpoint) if isinstance(endpoint, str) else None
    ca_file = test.get("ca_file")
    if match is None or int(match.group(1)) > 65535 or not plain_path(ca_file):
        raise Refused("package_test_seam_invalid")
    return ("localhost", int(match.group(1))), ca_file
