"""`run [--image NAME | --jail JAIL] ... -- ARG...` offline (commandrun.py):
stdout only the command's output (rendered inert, as jail exec's), its
own exit code only with everything else confirmed (else 125, usage 2), an
owned run discarded once settled, an existing run never. Stand-in
provider and ssh, FakeCgroups.

  cargo build --bin agentbox-relay
  python3 -I -B -m unittest discover -s tests -t .
"""
import os
import signal
import subprocess
import unittest

from tests.controller.harness import World
from tests.controller.test_execution import QUICK, fields, final


class Command(unittest.TestCase):
    def setUp(self):
        self.world = World(behavior={"engine": True})
        self.addCleanup(self.world.close)

    def command(self, argv, extra=(), **kwargs):
        kwargs.setdefault("overrides", QUICK)
        return self.world.run(("run",), list(extra) + ["--"] + list(argv), command_args=False, **kwargs)

    def owned(self, argv, extra=(), **kwargs):
        return self.command(argv, ["--image", self.world.image] + list(extra), **kwargs)

    def runs(self):
        return sorted(os.listdir(f"{self.world.data}/controller-runs"))

    def created(self, err):
        return err.split("run: created id=", 1)[1].split()[0]

    def test_owned_exit_codes_and_streams(self):
        for script, expected in (("printf out; printf err >&2", 0), ("printf out; exit 3", 3),
                                 ("printf out; exit 125", 125)):
            code, out, err = self.owned(["/bin/sh", "-c", script], ["--env", "PICKED"], env={"PICKED": "v"})
            self.assertEqual((code, out), (expected, "out"), err)
            run_id = self.created(err)
            self.assertIn(f"run: created id={run_id} kind=managed owned=true retention=none\n", err)
            self.assertEqual(fields(final(err))["exit"], str(expected))
            self.assertIn(f"discard: {run_id} discarded\n", err)
            record = self.world.record(run_id)
            self.assertEqual((record["phase"], record["retention"]), ("discarded", "none"))
        self.assertEqual(self.world.domains(), [])
        # The existing run untouched.
        self.assertEqual(self.world.record()["phase"], "ready")

    def test_redirected_output_is_rendered_inert(self):
        # A regular file as stdout: still escaped (display.py), never raw.
        path = f"{self.world.tmp}/stdout"
        with open(path, "wb") as sink:
            done = subprocess.run(self.world.argv(("run",), ["--image", self.world.image, "--", "/bin/sh", "-c",
                                                             "printf 'a\\000b\\033[2Jc\\377\\n'; "
                                                             "printf 'e\\001' >&2"],
                                                  overrides=QUICK, command_args=False),
                                  env=self.world.env(), stdin=subprocess.DEVNULL, stdout=sink,
                                  stderr=subprocess.PIPE, timeout=60)
        err = done.stderr.decode()
        with open(path, "rb") as stream:
            self.assertEqual((done.returncode, stream.read()), (0, b"a\\x00b\\x1b[2Jc\\xff\n"), err)
        self.assertTrue(err.startswith("run: created id="), err)
        self.assertIn("e\\x01", err)
        self.assertIn("reason=completed exit=0", final(err))
        self.assertIn(f"discard: {self.created(err)} discarded\n", err)

    def test_stdin_env_and_argv_as_is(self):
        data = os.urandom(3000).hex().encode() + b"\n"
        code, out, err = self.owned(["/bin/cat"], ["--stdin"], input=data)
        self.assertEqual((code, out.encode()), (0, data), err)
        code, out, err = self.owned(["/bin/sh", "-c", 'printf "%s|%s|$1" "$PICKED" "$OTHER"', "x", "pi"],
                                    ["--env", "PICKED"], env={"PICKED": "a b", "OTHER": "no"})
        self.assertEqual((code, out), (0, "a b||pi"), err)

    def test_signaled_is_125_and_still_discarded(self):
        code, out, err = self.owned(["/bin/sh", "-c", "kill -TERM $$"])
        self.assertEqual((code, out), (125, ""), err)
        self.assertEqual(fields(final(err))["exit"], "signaled")
        self.assertEqual(self.world.record(self.created(err))["phase"], "discarded")

    def test_existing_jail_kept(self):
        code, out, err = self.command(["/bin/sh", "-c", "printf ok; exit 4"], ["--jail", self.world.run_id])
        self.assertEqual((code, out), (4, "ok"), err)
        code, out, err = self.command(["/bin/true"], ["--jail", self.world.run_id])
        self.assertEqual((code, out), (0, ""), err)
        self.assertIn("reason=completed exit=0", final(err))
        self.assertNotIn("discard:", err)
        self.assertNotIn("run: created", err)
        self.assertEqual(self.world.record()["phase"], "ready")
        code, out, err = self.command(["/bin/true"], ["--jail", "nope"])
        self.assertEqual((code, out, err), (125, "", "agentbox: run refused: run_unknown\n"))

    def test_unclean_jail_hint(self):
        self.world.edit_record(storage="unclean")
        code, out, err = self.command(["/bin/true"], ["--jail", self.world.run_id])
        self.assertEqual((code, out), (125, ""))
        self.assertEqual(err, "agentbox: run refused: storage_unclean\nagentbox: hint: check it with agentbox jail "
                              f"status {self.world.run_id}, then agentbox jail exec {self.world.run_id} "
                              "--allow-unclean GENERATION -- true\n")

    def test_refusals_before_any_effect(self):
        before = self.runs()
        for extra, expected in ((["--env", "MISSING"], "env_invalid"), (["--env", "PATH"], "env_invalid"),
                                (["--image", "nope"], "image_unknown")):
            code, out, err = self.command(["/bin/true"], extra)
            self.assertEqual((code, out, err.splitlines()[0]), (125, "", f"agentbox: run refused: {expected}"))
        code, out, err = self.command([""], ["--image", self.world.image])
        self.assertEqual((code, err), (125, "agentbox: run refused: argv_invalid\n"))
        # Usage: an agent-only option, no argv.
        for args in (["--image", self.world.image, "--prompt", "p", "--", "true"], ["--image", self.world.image]):
            code, out, err = self.world.run(("run",), args, command_args=False)
            self.assertEqual((code, out), (2, ""))
            self.assertTrue(err.startswith("usage:\n"))
        self.assertEqual(self.runs(), before)

    def test_unsettled_execution_keeps_the_owned_run(self):
        self.world.set_behavior(stop="unsettled")
        code, out, err = self.owned(["/bin/sh", "-c", "printf out"])
        self.assertEqual((code, out), (125, "out"), err)
        run_id = self.created(err)
        self.assertIn(f"agentbox: the owned run {run_id} is kept: its execution is not confirmed settled; "
                      f"agentbox jail status {run_id}, agentbox jail stop {run_id}, then agentbox jail discard "
                      f"{run_id}\n", err)
        self.assertNotIn("discard:", err)
        self.assertNotEqual(self.world.record(run_id)["phase"], "discarded")

    def test_failed_discard_is_125(self):
        self.world.set_behavior(discard="fail")
        code, out, err = self.owned(["/bin/true"])
        self.assertEqual((code, out), (125, ""), err)
        run_id = self.created(err)
        self.assertIn("agentbox: jail discard failed (code=", err)
        self.assertIn(f"the owned run {run_id} remains", err)

    def test_create_failures(self):
        # Refused: its record retired. Unanswered: pending, never discarded.
        self.world.set_behavior(create="user_conflict")
        before = self.runs()
        code, out, err = self.owned(["/bin/true"])
        self.assertEqual((code, out), (125, ""), err)
        self.assertIn("agentbox: jail create failed (code=", err)
        self.assertTrue(err.endswith("agentbox: run refused: run_create_failed\n"), err)
        (made,) = set(self.runs()) - set(before)
        self.assertEqual(self.world.record(made)["phase"], "discarded")
        self.world.set_behavior(create="lost")
        before = self.runs()
        code, out, err = self.owned(["/bin/true"])
        self.assertEqual((code, out), (125, ""), err)
        self.assertIn("agentbox: jail discard failed (code=resource_unsettled)", err)
        (made,) = set(self.runs()) - set(before)
        self.assertNotEqual(self.world.record(made)["phase"], "discarded")
        self.assertIsNotNone(self.world.record(made)["pending"])

    def test_an_interrupt_still_discards(self):
        proc = self.world.start(("run",), ["--image", self.world.image, "--", "/bin/sh", "-c",
                                           "echo started; exec sleep 30"], command_args=False, overrides=QUICK)
        self.assertEqual(proc.stdout.readline(), b"started\n")
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=60)
        err = err.decode()
        self.assertEqual((proc.returncode, out), (125, b""), err)
        self.assertEqual(fields(final(err))["reason"], "cancelled")
        self.assertIn(f"discard: {self.created(err)} discarded\n", err)
        self.assertEqual(self.world.domains(), [])


if __name__ == "__main__":
    unittest.main()
