"""The controller's entry from a source tree: `python3 -I -B src/main.py
...` (agentbox_controller/cli.py), installed as ASSETS/controller/main.py;
the packaged one is PREFIX/bin/agentbox (src/agentbox). Only the trusted
asset tree, found through this file's real location, is put on the path;
`-I` keeps out the working directory, PYTHONPATH and user site. No packaged
prefix: the server must be configured."""
import os
import sys

if __name__ == "__main__":
    here = os.path.dirname(os.path.realpath(__file__))
    sys.path[:0] = [here, os.path.dirname(here)]
    sys.dont_write_bytecode = True
    from agentbox_controller import cli

    sys.exit(cli.main(sys.argv[1:]))
