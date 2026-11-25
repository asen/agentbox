"""The host Python suites (never packaged): controller/ (the agentbox CLI)
and server/ (agentbox-server), sharing support.py, which this package
imports first so that every suite module finds SRC's packages.

  cargo build --locked --bin agentbox-relay
  python3 -I -B -W error::ResourceWarning -m unittest discover -s tests -t .
"""
from . import support  # noqa: F401
