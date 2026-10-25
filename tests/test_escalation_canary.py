"""Trusted canary only; never launch a VM, Docker, game, or submitted content."""

import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import escalation_canary as canary


@unittest.skipUnless(sys.platform == "linux" and Path("/proc/self/stat").is_file(), "Linux procfs required")
class CanaryTests(unittest.TestCase):
    def assert_clean(self, child, root, port):
        self.assertIsNotNone(child.returncode)
        self.assertFalse(Path(f"/proc/{child.pid}").exists())
        self.assertFalse(root.exists())
        with socket.socket() as client:
            client.settimeout(.2)
            self.assertNotEqual(client.connect_ex(("127.0.0.1", port)), 0)

    def test_repeatable_os_evidence_and_cleanup(self):
        original = canary.observe
        for _ in range(3):
            observed = []

            def observe(root, child, port, peer):
                observed.append((child, root, port))
                return original(root, child, port, peer)

            with patch.object(canary, "observe", observe):
                receipt = canary.exercise()
            self.assert_clean(*observed[0])
            self.assertEqual(set(receipt), {"schema-version", "exercise", "observations", "cleanup", "not-validated"})
            self.assertEqual(receipt["exercise"], "trusted-local-observer-only")
            facts = receipt["observations"]
            self.assertEqual(set(facts), {"files", "process", "network"})
            self.assertEqual(facts["process"]["parent-pid"], os.getpid())
            self.assertGreater(facts["process"]["start-ticks"], 0)
            self.assertTrue(facts["network"]["child-socket-inode-matched"])
            self.assertEqual(facts["network"]["state"], "ESTABLISHED")
            self.assertEqual(facts["network"]["client-address"], "127.0.0.1")
            self.assertEqual(facts["network"]["server-address"], "127.0.0.1")
            self.assertEqual(len(facts["files"]), 2)
            for file in facts["files"]:
                expected = canary.PAYLOADS[file["name"]]
                self.assertEqual(file["bytes"], len(expected))
                self.assertEqual(file["sha256"], hashlib.sha256(expected).hexdigest())
            self.assertNotEqual(facts["files"][0]["sha256"], facts["files"][1]["sha256"])
            self.assertTrue(all(receipt["cleanup"].values()))
            self.assertLess(len(json.dumps(receipt)), 2048)

    def test_error_and_keyboard_cancel_cleanup(self):
        for error in (canary.ObservationError("injected"), KeyboardInterrupt()):
            observed = []

            def fail(root, child, port, peer):
                observed.append((child, root, port))
                raise error

            with patch.object(canary, "observe", fail):
                with self.assertRaises(type(error)):
                    canary.exercise()
            self.assert_clean(*observed[0])

    def test_missing_proc_evidence_fails_closed(self):
        original = canary.bounded_read

        def read(path, limit=65536):
            if str(path).startswith("/proc/"):
                raise PermissionError("proc unavailable")
            return original(path, limit)

        with patch.object(canary, "bounded_read", read):
            with self.assertRaises(PermissionError):
                canary.exercise()

    def test_file_or_socket_evidence_mismatch_fails_closed(self):
        original_observe = canary.observe
        original_read = canary.bounded_read
        observed = []

        def tamper(root, child, port, peer):
            observed.append((child, root, port))
            (root / "first.txt").write_bytes(b"not the canary")
            return original_observe(root, child, port, peer)

        with patch.object(canary, "observe", tamper):
            with self.assertRaises(canary.ObservationError):
                canary.exercise()
        self.assert_clean(*observed[0])

        def no_socket(path, limit=65536):
            if str(path) == "/proc/net/tcp":
                return b"header\n"
            return original_read(path, limit)

        with patch.object(canary, "bounded_read", no_socket):
            with self.assertRaises(canary.ObservationError):
                canary.exercise()

    def test_cli_receipt_has_no_caller_environment(self):
        env = dict(os.environ, UE_PAK_POLICY_RULES="private-canary-policy-marker",
                   CANARY_CREDENTIAL="private-canary-credential-marker")
        result = subprocess.run([sys.executable, str(ROOT / "scripts/escalation_canary.py")],
                                env=env, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(b"private-canary", result.stdout)
        self.assertLess(len(result.stdout), 2048)
        self.assertEqual(json.loads(result.stdout)["exercise"], "trusted-local-observer-only")

    def test_timeout_cleans_child_and_directory(self):
        children = []
        original = subprocess.Popen

        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append((child, Path(args[0][-2]), int(args[0][-1])))
            self.assertEqual(kwargs["env"], {})
            return child

        with patch.object(canary, "CHILD", "import time; time.sleep(10)"), patch.object(canary.subprocess, "Popen", spawn):
            with self.assertRaises(TimeoutError):
                canary.exercise(timeout=.05)
        self.assert_clean(*children[0])

    def test_real_sigint_sigterm_cleanup(self):
        wrapper = '''
import json, sys, time
sys.path.insert(0, sys.argv[1])
import escalation_canary as c
original = c.observe
def observe(root, child, port, peer):
    original(root, child, port, peer)
    print(json.dumps([child.pid, str(root), port]), flush=True)
    time.sleep(30)
c.observe = observe
sys.argv = ["escalation_canary.py"]
sys.exit(c.main())
'''
        for sig in (signal.SIGINT, signal.SIGTERM):
            process = subprocess.Popen([sys.executable, "-I", "-S", "-c", wrapper, str(ROOT / "scripts")],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                self.assertTrue(ready, "observer handshake timed out")
                pid, root, port = json.loads(process.stdout.readline())
                process.send_signal(sig)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 1)
                self.assertEqual(stdout, b"")
                self.assertIn(b"no successful receipt", stderr)
                self.assertFalse(Path(root).exists())
                self.assertFalse(Path(f"/proc/{pid}").exists())
                with socket.socket() as client:
                    client.settimeout(.2)
                    self.assertNotEqual(client.connect_ex(("127.0.0.1", port)), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_no_path_command_or_receipt_arguments(self):
        with tempfile.TemporaryDirectory(prefix="canary-input-test-") as directory:
            root = Path(directory)
            artifact = root / "original.pak"
            artifact.write_bytes(b"must not change")
            link = root / "receipt.json"
            link.symlink_to(artifact)
            for args in (["--output", str(link)], ["../outside"], ["--command", "false"]):
                result = subprocess.run([sys.executable, str(ROOT / "scripts/escalation_canary.py"), *args],
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(artifact.read_bytes(), b"must not change")
                self.assertTrue(link.is_symlink())

    def test_limits_and_unsupported_platform(self):
        for timeout in (0, -1, 6):
            with self.assertRaises(ValueError):
                canary.exercise(timeout)
        with patch.object(canary.sys, "platform", "unsupported"):
            with self.assertRaises(canary.ObservationError):
                canary.exercise()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bounded"
            path.write_bytes(b"12345")
            with self.assertRaises(canary.ObservationError):
                canary.bounded_read(path, 4)


if __name__ == "__main__":
    unittest.main()
