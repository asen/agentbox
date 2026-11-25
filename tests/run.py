"""Run the fast or full offline suite from the checkout."""
import argparse
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]

# Scenarios outside this selection run in the advanced tier. Full discovery
# includes new tests automatically.
FAST = (
    ("tests", (
        "test_units.", "test_b2_units.", "test_c1.Units.", "test_c2b.Units.",
        "test_create_exec_stop_discard", "test_ingress.",
        "test_a_tunnel_through_the_program_and_its_child_outlives_no_killed_broker",
    )),
    ("providers", (
        "test_protocol.", "test_scopes.",
        "test_create_start_connect_stop_with_a_closed_profile",
        "test_create_start_stop_resume_with_fresh_identities",
    )),
    ("images/worker", ()),
)

FULL = (
    "tests", "providers", "guest/test", "acquisitions", "agents", "inputs",
    "images/worker", "packaging",
)


def run(command):
    print("+", " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tier", choices=("fast", "full"), nargs="?", default="fast")
    parser.add_argument("--durations", type=int, help="show the slowest N tests in each Python suite")
    args = parser.parse_args()

    failures = [
        run(["cargo", "test", "--locked", "--offline"]),
        run(["cargo", "build", "--locked", "--offline", "--bin", "agentbox-relay"]),
    ]
    suites = FAST if args.tier == "fast" else ((directory, ()) for directory in FULL)
    for directory, patterns in suites:
        command = [sys.executable, "-I", "-B", "-m", "unittest", "discover", "-s", directory]
        if directory in ("tests", "guest/test"):
            command += ["-t", "."]
        for pattern in patterns:
            command += ["-k", pattern]
        if args.durations is not None:
            command += ["--durations", str(args.durations)]
        failures.append(run(command))
    return int(any(failures))


if __name__ == "__main__":
    sys.exit(main())
