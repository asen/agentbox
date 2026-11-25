"""The git handler's jail module and its `git` shim.

  git ARGS...                     the shim: one Git command (dispatch.py)
  git-remote-agentbox REMOTE URL  a pull's remote helper, staged by the pull
                                  itself, never a manifest shim (pull.py)

Local Git runs as is, push and unsupported remote forms are refused, clone
and fetch go to the host's git handler and are applied locally by G3. Only
the repository and an optional selector reach the host. (`agentbox-request
git clone ...` is the generic client's: it saves the delivered bundle and
applies nothing.)"""

if __name__ == "__main__":
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import sys

from acquisitions.git.jail.main import git_main
from acquisitions.git.jail.pull import HELPER_COMMAND, remote_helper_main
from guest.src.counterpart import serve


if __name__ == "__main__":
    sys.exit(serve(sys.argv[1:], {"git": git_main, HELPER_COMMAND: remote_helper_main}))
