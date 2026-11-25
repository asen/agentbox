"""The Python session controller (src/README.md).

Trusted host code, stdlib only, single-threaded: one selectors loop owns
every pipe of its children (provider owner, agentbox-server, ssh), its own
stdin/stdout and its signals. Imported only from the trusted asset tree
(`main.py` beside it puts that tree on `sys.path`), never the working
directory.
"""
