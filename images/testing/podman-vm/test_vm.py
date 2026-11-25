"""Offline checks of the Podman test VM driver (README.md here): generated
argv, seed, provisioning and smoke scripts, parsing, owned-process
signalling and the launch/stop/smoke lifecycle with stand-in children
(python3/sleep) and a mocked guest. No QEMU, passt, guest, download or
network.

  python3 -I -B -m unittest discover -s images/testing/podman-vm -p 'test_*.py'
"""
import base64
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import vm  # noqa: E402

ROOT = "/nonexistent/abpvm-test"
IMAGE_ID = "1" * 64
CLIENT = "ssh-ed25519 AAAAC3NzaClient abpvm-client@x"
HOST_PUBLIC = "ssh-ed25519 AAAAC3NzaHost root@agentbox-podman-test"
HOST_PRIVATE = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
SHARES = ("-virtfs", "-fsdev", "9p", "virtio-fs", "vhost-user-fs", "-chardev", "hostfwd",
          "user,", "tap", "bridge", "-monitor stdio", "-vnc", "-spice", "-usb")


class Argv(unittest.TestCase):
    def test_qemu_has_one_disk_one_passt_nic_and_no_share(self):
        argv = vm.qemu_argv("/r/d.qcow2", vm.netdev(40000, []), "/r/logs/c.log")
        joined = " ".join(argv)
        for needle in ("-nodefaults", "q35,accel=kvm", "-m 4096", "-smp 2", "-display none",
                       "-monitor none", "-serial file:/r/logs/c.log", "-netdev passt,id=net0,"):
            self.assertIn(needle, joined)
        for absent in ("-daemonize", "-pidfile"):
            self.assertNotIn(absent, argv)
        for needle in SHARES:
            self.assertNotIn(needle, joined)
        self.assertEqual(argv.count("-drive"), 1)
        self.assertEqual(argv.count("-netdev"), 1)

    def test_qemu_seed_is_read_only_and_build_only(self):
        argv = vm.qemu_argv("/r/d.qcow2", vm.netdev(40000, []), "/r/c", seed="/r/build/seed.iso")
        self.assertIn("file=/r/build/seed.iso,if=virtio,format=raw,readonly=on", argv)
        self.assertEqual(argv.count("-drive"), 2)

    def test_passt_maps_no_gateway_and_forwards_only_loopback_ssh(self):
        spec = vm.netdev(40000, ["192.0.2.53", "192.0.2.54"])
        self.assertEqual(spec.split(","), [
            "passt", "id=net0", "path=/usr/bin/passt", "param=--no-map-gw", "tcp-ports=127.0.0.1/40000:22",
            "param=--dns=192.0.2.53", "param=--dns=192.0.2.54"])
        for absent in ("udp-ports", "map-host-loopback", "map-guest-addr", "dns-forward", "vhost-user"):
            self.assertNotIn(absent, spec)

    def test_upstream_nameservers_skip_loopback(self):
        with tempfile.NamedTemporaryFile("w") as conf:
            conf.write("nameserver 127.0.0.53\nnameserver 192.0.2.1\nnameserver ::1\n"
                       "nameserver 192.0.2.2\nsearch x\n")
            conf.flush()
            self.assertEqual(vm.host_nameservers(conf.name), ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(vm.host_nameservers("/nonexistent/resolv.conf"), [])

    def test_ssh_pins_the_host_key_and_uses_nothing_of_the_user(self):
        argv = vm.ssh_argv(ROOT, 40000, "abtest", ["true"])
        joined = " ".join(argv)
        for needle in ("-F /dev/null", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes",
                       "IdentityAgent=none", "ForwardAgent=no", "GlobalKnownHostsFile=/dev/null",
                       f"UserKnownHostsFile={ROOT}/keys/known_hosts", "HostKeyAlias=agentbox-podman-test",
                       "UpdateHostKeys=no", f"-i {ROOT}/keys/client", "-p 40000", "abtest@127.0.0.1"):
            self.assertIn(needle, joined)
        self.assertNotIn("StrictHostKeyChecking=no", joined)
        self.assertNotIn("accept-new", joined)
        self.assertEqual(argv[-2:], ["--", "true"])

    def test_ssh_request(self):
        self.assertEqual(vm.ssh_request(False, ["--admin", "--", "sudo", "-n", "id"]), (True, ["sudo", "-n", "id"]))
        self.assertEqual(vm.ssh_request(True, ["--", "id"]), (True, ["id"]))
        self.assertEqual(vm.ssh_request(False, ["id", "--admin"]), (False, ["id", "--admin"]))
        self.assertEqual(vm.ssh_request(False, []), (False, []))

    def test_known_hosts_names_the_alias(self):
        self.assertEqual(vm.known_hosts_line(HOST_PUBLIC), "agentbox-podman-test ssh-ed25519 AAAAC3NzaHost\n")


class Seed(unittest.TestCase):
    def config(self):
        text = vm.user_data(CLIENT, HOST_PRIVATE, HOST_PUBLIC)
        self.assertTrue(text.startswith("#cloud-config\n"))
        return json.loads(text.split("\n", 1)[1])

    def test_only_the_admin_account_with_the_fresh_key(self):
        config = self.config()
        self.assertEqual([u["name"] for u in config["users"]], ["vmadmin"])
        admin = config["users"][0]
        self.assertEqual(admin["uid"], 1500)
        self.assertTrue(admin["lock_passwd"])
        self.assertEqual(admin["ssh_authorized_keys"], [CLIENT])
        self.assertFalse(config["ssh_pwauth"])
        self.assertTrue(config["disable_root"])

    def test_host_key_is_supplied_never_generated(self):
        config = self.config()
        self.assertEqual(config["ssh_keys"], {"ed25519_private": HOST_PRIVATE, "ed25519_public": HOST_PUBLIC})
        self.assertEqual(config["ssh_genkeytypes"], [])
        self.assertTrue(config["ssh_deletekeys"])

    def test_no_package_actions_and_background_units_masked(self):
        config = self.config()
        self.assertFalse(config["package_update"])
        self.assertFalse(config["package_upgrade"])
        self.assertNotIn("packages", config)
        for unit in ("snapd.service", "unattended-upgrades.service", "apt-daily.timer", "motd-news.timer"):
            self.assertIn(f"systemctl mask --now {unit}", config["bootcmd"][0])

    def test_meta_data(self):
        self.assertEqual(vm.meta_data("abpvm-1"), "instance-id: abpvm-1\nlocal-hostname: agentbox-podman-test\n")


class Provision(unittest.TestCase):
    script = vm.provision_script(CLIENT)

    def test_the_test_account_and_its_subordinate_ids(self):
        for needle in ("groupadd -g 3001 abtest",
                       "useradd -u 2001 -g 3001 -m -d /home/abtest -s /bin/bash -K SUB_UID_COUNT=0",
                       "printf '%s\\n' abtest:100000:65536 > /etc/subuid",
                       "printf '%s\\n' abtest:100000:65536 > /etc/subgid",
                       "loginctl enable-linger abtest", "chown 2001:3001 /home/abtest/.ssh/authorized_keys"):
            self.assertIn(needle, self.script)
        self.assertNotIn("sudo", self.script)

    def test_only_listed_packages_from_the_image_sources(self):
        self.assertIn("apt-get install -y --no-install-recommends podman crun conmon uidmap catatonit passt "
                      "dbus-user-session", self.script)
        for forbidden in ("apt-get upgrade", "full-upgrade", "dist-upgrade", "add-apt-repository", "curl", "wget", "sources.list", ".sources",
                          "apparmor_restrict", "sysctl"):
            self.assertNotIn(forbidden, self.script)

    def test_cloud_init_disabled_after_provisioning(self):
        self.assertIn("touch /etc/cloud/cloud-init.disabled", self.script)
        self.assertIn("systemctl --global mask podman.socket", self.script)
        self.assertIn("systemctl mask --now podman.socket", self.script)
        self.assertLess(self.script.index("apt-get install"), self.script.index("cloud-init.disabled"))

    def test_shell_valid(self):
        subprocess.run(["sh", "-n"], input=self.script, text=True, check=True)


class Smoke(unittest.TestCase):
    def test_container_takes_the_production_sandbox_and_keep_id(self):
        argv = vm.container_argv(IMAGE_ID)
        self.assertEqual(argv[0], "create")
        for flag in ("--network=none", "--read-only", "--cap-drop=all", "--security-opt=no-new-privileges",
                     "--pull=never", "--cgroups=disabled", "--ipc=private", "--pid=private", "--uts=private",
                     "--cgroupns=private", "--userns=keep-id:uid=1000,gid=1000", "--user=1000:1000",
                     "--passwd-entry=agentbox:x:1000:1000:agentbox:/home/agentbox:/bin/sh",
                     "--group-entry=agentbox:x:1000:"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[-5:], ["--entrypoint=/usr/bin/tini", IMAGE_ID, "--", "/usr/bin/sleep", "infinity"])

    def test_binds_are_vm_local_and_restricted(self):
        binds = [a for a in vm.container_argv(IMAGE_ID) if a.startswith("--mount=type=bind")]
        self.assertEqual(binds, [
            "--mount=type=bind,source=/home/abtest/smoke/fx/ro,destination=/home/agentbox/ro,ro,nosuid,nodev,"
            "bind-propagation=private,bind-nonrecursive",
            "--mount=type=bind,source=/home/abtest/smoke/fx/rw,destination=/home/agentbox/rw,rw,nosuid,nodev,"
            "bind-propagation=private,bind-nonrecursive"])
        self.assertFalse([a for a in vm.container_argv(IMAGE_ID) if "type=volume" in a])

    def test_scripts_are_shell_valid(self):
        subprocess.run(["sh", "-n"], input=vm.smoke_script(IMAGE_ID), text=True, check=True)
        subprocess.run(["sh", "-n"], input=vm.FACTS_SCRIPT, text=True, check=True)
        subprocess.run(["sh", "-n"], input=vm.INNER, text=True, check=True)

    def test_engine_store_is_private_vfs(self):
        script = vm.smoke_script(IMAGE_ID)
        self.assertIn("--storage-driver=vfs", script)
        self.assertIn("--root /home/abtest/smoke/graph", script)
        for forbidden in ("pull ", "docker.io", "system service", "--remote", "podman.sock"):
            self.assertNotIn(forbidden, script)

    def passing(self):
        info = {"host": {"security": {"rootless": True}, "ociRuntime": {"name": "crun"},
                         "remoteSocket": {"path": "/run/user/2001/podman/podman.sock", "exists": False},
                         "pasta": {"version": "pasta 1\nCopyright"}}}
        return {"id": "2001:3001", "subuid": "abtest:100000:65536 ", "subgid": "abtest:100000:65536 ",
                "cgroupfs": "cgroup2fs", "user_bus": "present", "info": base64.b64encode(json.dumps(info).replace("\\n", "\n").encode()).decode(),
                "api_sockets": "", "listening_podman": "0", "podman_socket_units": "masked,masked",
                "loaded": f"sha256:{IMAGE_ID}", "jail_id": "1000:1000", "jail_net": "lo,",
                "jail_nnp": "NoNewPrivs:1", "jail_capeff": "CapEff:0000000000000000",
                "jail_mount_owner": "1000:1000,1000:1000", "jail_rw_write": "ok",
                "vm_new_owner": "2001:3001:600",
                "jail_ro_write": "sh: 1: cannot create /home/agentbox/ro/data: Read-only file system",
                "jail_ro_create": "sh: 1: cannot create /home/agentbox/ro/new: Read-only file system",
                "vm_ro_unchanged": "yes", "vm_ro_new_absent": "yes", "volume_uid_gid": "accepted 1000:1000",
                "containers_left": "0"}

    def test_checks_pass_and_each_fails_alone(self):
        good = self.passing()
        self.assertTrue(all(vm.smoke_checks(good, IMAGE_ID).values()))
        for key, bad in (("id", "1000:1000"), ("vm_new_owner", "1000:1000:600"), ("jail_net", "lo,eth0,"),
                         ("jail_ro_write", "UNEXPECTED"), ("vm_ro_unchanged", "no"), ("loaded", "sha256:" + "2" * 64),
                         ("subuid", "abtest:100000:65536 vmadmin:165536:65536 "), ("api_sockets", "podman.sock "), ("listening_podman", "1"),
                         ("podman_socket_units", "masked,enabled"),
                         ("volume_uid_gid", "accepted ")):
            checks = vm.smoke_checks({**good, key: bad}, IMAGE_ID)
            self.assertFalse(all(checks.values()), key)

    def test_facts_parse(self):
        self.assertEqual(vm.facts("a=1\nb=x=y\nnoise\npackage=p 1\npackage=q 2\nBad=no\n"),
                         {"a": "1", "b": "x=y", "package": ["p 1", "q 2"]})


class Verification(unittest.TestCase):
    def test_expected_digest_needs_exactly_one_entry(self):
        digest = "a" * 64
        sums = f"{'b' * 64} *other.img\n{digest} *{vm.IMAGE}\n"
        self.assertEqual(vm.expected_digest(sums, vm.IMAGE), digest)
        with self.assertRaises(vm.Failed):
            vm.expected_digest(sums + f"{'c' * 64} *{vm.IMAGE}\n", vm.IMAGE)
        with self.assertRaises(vm.Failed):
            vm.expected_digest(f"{digest} *{vm.IMAGE}.manifest\n", vm.IMAGE)

    def test_signature_status(self):
        fpr = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
        good = f"[GNUPG:] GOODSIG 1A5D6C4C7DB87C81 UEC\n[GNUPG:] VALIDSIG {fpr} 2026-11-14 0 4 0 1 10 00 {fpr}\n"
        self.assertEqual(vm.valid_signature(good), fpr)
        self.assertIsNone(vm.valid_signature("[GNUPG:] GOODSIG x\n"))
        self.assertIsNone(vm.valid_signature(good + "[GNUPG:] BADSIG 1 x\n"))
        self.assertIsNone(vm.valid_signature(good + "[GNUPG:] EXPKEYSIG 1 x\n"))

    def test_new_root_is_private_and_fresh(self):
        with tempfile.TemporaryDirectory() as parent:
            root = vm.new_root(os.path.join(parent, "r"))
            self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)
            self.assertEqual(sorted(os.listdir(root)), ["base", "build", "keys", "logs", "run"])
            with self.assertRaises(FileExistsError):
                vm.new_root(root)


class Processes(unittest.TestCase):
    def test_passt_pidfile_only_from_its_tmp_name(self):
        self.assertIsNone(vm.passt_pidfile(os.getpid()))

    def test_no_passt_claims_an_unused_port(self):
        self.assertEqual(vm.passt_for(vm.free_port()), [])

    def test_signals_only_the_recorded_process(self):
        child = subprocess.Popen(["sleep", "60"])
        try:
            recorded = vm.identity(child.pid)
            self.assertTrue(vm.same(recorded))
            self.assertFalse(vm.signal_owned({**recorded, "start": recorded["start"] + 1}, 15))
            self.assertFalse(vm.signal_owned({**recorded, "comm": "qemu-system-x86"}, 15))
            self.assertIsNone(child.poll())
            self.assertTrue(vm.signal_owned(recorded, 15))
            child.wait(10)
            self.assertFalse(vm.same(recorded))
            self.assertFalse(vm.signal_owned(recorded, 15))
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_stop_without_state_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as parent:
            root = vm.new_root(os.path.join(parent, "r"))
            self.assertEqual(vm.stop(root), "not running")


STANDIN = "import time; time.sleep(60)"


class Lifecycle(unittest.TestCase):
    """start_locked/stop_locked/smoke_locked against a python3 stand-in for
    QEMU (comm python3, the console marker in its argv) and a sleep
    stand-in for passt."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = vm.new_root(os.path.join(self.tmp.name, "r"))
        with open(vm.paths(self.root)["final"], "wb") as stream:
            stream.write(b"final disk bytes")
        self.procs = []
        self.popen = subprocess.Popen
        self.launched = []
        patches = [
            mock.patch.object(vm, "QEMU_COMM", "python3"),
            mock.patch.object(vm, "STOP_SECONDS", 0.2),
            mock.patch.object(vm, "PASST_SECONDS", 0.2),
            mock.patch.object(vm, "LOCK_SECONDS", 0.3),
            mock.patch.object(vm, "KILL_SECONDS", 5),
            mock.patch.object(vm, "mem_available_mib", lambda: 1 << 20),
            mock.patch.object(vm, "qemu_argv", lambda disk, net, console, seed=None:
                              [sys.executable, "-I", "-c", STANDIN, f"file:{console}"]),
            mock.patch.object(vm.subprocess, "Popen", self.spy_popen),
            mock.patch.object(vm, "wait_ssh", lambda root, state: None),
            mock.patch.object(vm, "run", self.fake_run),
            mock.patch.object(vm, "passt_for", self.fake_passt_for),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.passt = None
        self.runs = []

    def tearDown(self):
        for proc in self.procs + self.launched:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        vm.CHILDREN.clear()
        self.tmp.cleanup()

    def spy_popen(self, argv, **kw):
        proc = self.popen(argv, **kw)
        self.launched.append(proc)
        self.kwargs = kw
        return proc

    def fake_run(self, argv, **kw):
        self.runs.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def fake_passt_for(self, port):
        if self.passt is None:
            proc = self.popen(["sleep", "60"])
            self.procs.append(proc)
            self.passt = vm.identity(proc.pid)
        return [self.passt] if vm.same(self.passt) else []

    def state_bytes(self):
        with open(vm.paths(self.root)["state"], "rb") as stream:
            return stream.read()

    def assert_settled(self, proc):
        self.assertIsNotNone(proc.returncode, "child reaped")
        self.assertFalse(os.path.exists(vm.paths(self.root)["state"]))
        self.assertNotIn(proc.pid, vm.CHILDREN)

    def test_launch_publishes_identity_then_stop_settles_it(self):
        state = vm.start_locked(self.root, "/r/disk.qcow2")
        proc = self.launched[0]
        self.assertTrue(self.kwargs["start_new_session"])
        self.assertTrue(self.kwargs["close_fds"])
        self.assertIs(self.kwargs["stdin"], subprocess.DEVNULL)
        log = state["qemu_log"]
        self.assertEqual(os.stat(log).st_mode & 0o777, 0o600)
        self.assertTrue(log.startswith(vm.paths(self.root)["logs"] + "/"))
        saved = json.loads(self.state_bytes())
        self.assertEqual(saved["qemu"]["pid"], proc.pid)
        self.assertEqual(saved["phase"], "running")
        self.assertEqual(saved["passt"], [self.passt])
        outcome = vm.stop_locked(self.root)
        self.assertEqual(outcome, {"qemu": "SIGTERM", "passt": "SIGTERM"})
        self.assertIn("poweroff", self.runs[0])
        self.assert_settled(proc)

    def interrupted(self, failure):
        real = vm.identity

        def identity(pid):
            if self.launched and pid == self.launched[0].pid:
                raise failure
            return real(pid)
        with mock.patch.object(vm, "identity", identity):
            with self.assertRaises(type(failure)):
                vm.start_locked(self.root, "/r/disk.qcow2")
        return self.launched[0]

    def test_interrupt_before_publication_kills_and_reaps_through_the_handle(self):
        proc = self.interrupted(KeyboardInterrupt())
        self.assertEqual(proc.returncode, -9)
        self.assert_settled(proc)

    def test_ctrl_c_during_spawn_is_deferred_until_the_handle_is_held(self):
        def popen(argv, **kw):
            proc = self.spy_popen(argv, **kw)
            os.kill(os.getpid(), signal.SIGINT)
            time.sleep(0.2)
            return proc
        with mock.patch.object(vm.subprocess, "Popen", popen):
            with self.assertRaises(KeyboardInterrupt):
                vm.start_locked(self.root, "/r/disk.qcow2")
        self.assertEqual(self.launched[0].returncode, -9)
        self.assert_settled(self.launched[0])
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)

    def test_proc_error_before_publication_kills_and_reaps(self):
        proc = self.interrupted(PermissionError("proc"))
        self.assertEqual(proc.returncode, -9)
        self.assert_settled(proc)

    def test_missing_identity_settles(self):
        real = vm.identity
        with mock.patch.object(vm, "identity", lambda pid: None if self.launched and pid == self.launched[0].pid
                               else real(pid)):
            with self.assertRaises(vm.Failed):
                vm.start_locked(self.root, "/r/disk.qcow2")
        self.assert_settled(self.launched[0])

    def test_failed_publication_write_settles_the_unpublished_child(self):
        real, calls = vm.save_state, []

        def save_state(root, state):
            calls.append(state.get("phase"))
            if state.get("qemu"):
                raise OSError("disk full")
            real(root, state)
        with mock.patch.object(vm, "save_state", save_state):
            with self.assertRaises(OSError):
                vm.start_locked(self.root, "/r/disk.qcow2")
        self.assert_settled(self.launched[0])

    def test_failure_after_publication_stops_without_poweroff(self):
        with mock.patch.object(vm, "wait_ssh", mock.Mock(side_effect=vm.Failed("no ssh"))):
            with self.assertRaises(vm.Failed):
                vm.start_locked(self.root, "/r/disk.qcow2")
        self.assertEqual(self.runs, [])
        self.assert_settled(self.launched[0])

    def test_unconfirmed_settlement_keeps_the_state(self):
        with mock.patch.object(vm, "wait_ssh", mock.Mock(side_effect=KeyboardInterrupt())), \
                mock.patch.object(vm, "end_owned", mock.Mock(side_effect=vm.Failed("survived"))):
            with self.assertRaises(KeyboardInterrupt):
                vm.start_locked(self.root, "/r/disk.qcow2")
        saved = json.loads(self.state_bytes())
        self.assertEqual(saved["qemu"]["pid"], self.launched[0].pid)
        self.assertIsNone(self.launched[0].poll())

    def test_stop_recovers_a_launch_never_published(self):
        console = os.path.join(vm.paths(self.root)["logs"], "console-x.log")
        orphan = self.popen([sys.executable, "-I", "-c", STANDIN, f"file:{console}"])
        self.procs.append(orphan)
        time.sleep(0.3)
        vm.save_state(self.root, {"instance": "aa", "phase": "launching", "port": 1, "console": console})
        with mock.patch.object(vm, "passt_for", lambda port: []):
            self.assertEqual(vm.stop_locked(self.root), {"qemu": "SIGTERM"})
        orphan.wait(5)
        self.assertFalse(os.path.exists(vm.paths(self.root)["state"]))

    def test_stop_touches_only_its_instance(self):
        vm.save_state(self.root, {"instance": "aa", "phase": "running", "port": 1,
                                  "qemu": {"pid": 1, "start": 0, "comm": "init"}})
        before = self.state_bytes()
        with self.assertRaises(vm.Failed):
            vm.stop_locked(self.root, "bb")
        self.assertEqual(self.state_bytes(), before)
        self.assertEqual(self.runs, [])

    def test_start_refuses_occupied_root(self):
        vm.save_state(self.root, {"instance": "aa"})
        before = self.state_bytes()
        with self.assertRaises(vm.Failed):
            vm.start_locked(self.root, "/r/disk.qcow2")
        self.assertEqual(self.launched, [])
        self.assertEqual(self.state_bytes(), before)

    def test_lock_serializes_transitions_and_is_not_inherited(self):
        with vm.locked(self.root):
            with self.assertRaises(vm.Failed):
                with vm.locked(self.root, seconds=0.3):
                    pass
            with self.assertRaises(vm.Failed):
                vm.stop(self.root)
            fds = subprocess.run(["sh", "-c", "for f in /proc/self/fd/*; do readlink $f; done"],
                                 close_fds=False, capture_output=True, text=True).stdout
            self.assertNotIn(os.path.join(self.root, "lock"), fds)
        lock = os.path.join(self.root, "lock")
        self.assertEqual(os.stat(lock).st_mode & 0o777, 0o600)
        self.assertEqual(vm.stop(self.root), "not running")
        self.assertTrue(os.path.exists(lock))

    def test_concurrent_start_and_stop_serialize(self):
        order = []
        slow = threading.Event()

        def holder():
            with vm.locked(self.root):
                order.append("held")
                slow.wait(30)
        thread = threading.Thread(target=holder)
        thread.start()
        while not order:
            time.sleep(0.01)
        with self.assertRaises(vm.Failed):
            vm.start(self.root)
        slow.set()
        thread.join()
        self.assertEqual(self.launched, [])

    def test_lock_refuses_a_linked_or_shared_lock_file(self):
        lock = os.path.join(self.root, "lock")
        os.symlink(os.path.join(self.tmp.name, "elsewhere"), lock)
        with self.assertRaises(OSError):
            with vm.locked(self.root):
                pass
        os.unlink(lock)
        os.close(os.open(lock, os.O_CREAT | os.O_WRONLY, 0o644))
        with self.assertRaises(vm.Failed):
            with vm.locked(self.root):
                pass

    def smoke_with(self, guest):
        commands = []

        def ssh_run(root, user, command, stdin=None, timeout=1800, logname=None):
            commands.append(list(command))
            return guest(command)
        with mock.patch.object(vm, "ssh_run", ssh_run):
            try:
                return vm.smoke_locked(self.root, "/a.tar", b"archive", "a" * 64, IMAGE_ID), commands
            finally:
                self.commands = commands

    def test_smoke_refuses_an_occupied_root_and_touches_nothing(self):
        vm.save_state(self.root, {"instance": "aa", "phase": "running", "port": 1})
        before = self.state_bytes()
        with mock.patch.object(vm, "stop_locked", mock.Mock(side_effect=AssertionError("stopped"))):
            with self.assertRaises(vm.Failed):
                self.smoke_with(lambda command: "")
        self.assertEqual(self.state_bytes(), before)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.launched, [])
        self.assertEqual([n for n in os.listdir(vm.paths(self.root)["run"]) if n.startswith("smoke-")], [])

    def mismatch(self, line):
        def guest(command):
            return line if command[0] == "sha256sum" else ""
        with self.assertRaises(vm.Failed) as caught:
            self.smoke_with(guest)
        self.assertNotIn("evil", str(caught.exception))
        self.assertEqual([c[0] for c in self.commands], ["/bin/sh", "sha256sum", "rm"])
        self.assertEqual(self.commands[2], ["rm", "-f", "--", vm.GUEST_ARCHIVE])
        self.assertEqual([n for n in os.listdir(vm.paths(self.root)["run"]) if n.startswith("smoke-")], [])
        self.assert_settled(self.launched[0])

    def test_guest_checksum_mismatch_stops_before_load_or_any_script(self):
        self.mismatch(f"{'b' * 64}  {vm.GUEST_ARCHIVE}\n")

    def test_malformed_guest_checksum_stops_before_load(self):
        for line in (f"{'a' * 63}  {vm.GUEST_ARCHIVE}\n", f"{'a' * 64}  {vm.GUEST_ARCHIVE}\nevil\n",
                     f"{'a' * 64}  /other\n", "evil\n", ""):
            self.launched.clear()
            self.passt = None
            self.mismatch(line)

    def test_smoke_overlay_kept_while_its_instance_is_unsettled(self):
        def guest(command):
            raise vm.Failed("upload failed")
        with mock.patch.object(vm, "end_owned", mock.Mock(side_effect=vm.Failed("survived"))):
            with self.assertRaises(vm.Failed):
                self.smoke_with(guest)
        overlays = [n for n in os.listdir(vm.paths(self.root)["run"]) if n.startswith("smoke-")]
        self.assertEqual(len(overlays), 1)
        self.assertTrue(os.path.exists(vm.paths(self.root)["state"]))

    def test_read_archive_refuses_links(self):
        target = os.path.join(self.tmp.name, "a.tar")
        with open(target, "wb") as stream:
            stream.write(b"x" * 10)
        data, digest = vm.read_archive(target)
        self.assertEqual((data, len(digest)), (b"x" * 10, 64))
        link = os.path.join(self.tmp.name, "link.tar")
        os.symlink(target, link)
        with self.assertRaises(OSError):
            vm.read_archive(link)


class Digest(unittest.TestCase):
    def test_guest_digest_is_exact(self):
        good = f"{'a' * 64}  {vm.GUEST_ARCHIVE}\n"
        self.assertEqual(vm.guest_digest(good), "a" * 64)
        for bad in (good.upper(), good + "x", " " + good, good.replace("  ", " *"), good[:-1]):
            self.assertIsNone(vm.guest_digest(bad))


if __name__ == "__main__":
    unittest.main()
