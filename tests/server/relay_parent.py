"""A stand-in broker for the relay tests: gives two inherited connected
sockets to an agentbox-relay child, prints the child's pid, then waits on
its stdin until killed. MODE: `started` (the frame and START), `spawned`
(nothing sent) or `partial` (half the frame, no START).

  python3 -I -B relay_parent.py SRC BINARY CLIENT_FD UPSTREAM_FD MODE
"""
import socket
import sys

sys.path.insert(0, sys.argv[1])
from agentbox_server import relay  # noqa: E402

client = socket.socket(fileno=int(sys.argv[3]))
upstream = socket.socket(fileno=int(sys.argv[4]))
mode = sys.argv[5]
if mode == "started":
    child = relay.Relay.start(sys.argv[2], client, upstream, idle=60, lifetime=60)
else:
    child = relay.Relay.spawn(sys.argv[2], client, upstream)
    if mode == "partial":
        data = relay.frame(b"prefix", 60, 60)
        child.control.sendall(data[:len(data) // 2])
sys.stdout.write(f"{child.pid}\n")
sys.stdout.flush()
sys.stdin.read()
