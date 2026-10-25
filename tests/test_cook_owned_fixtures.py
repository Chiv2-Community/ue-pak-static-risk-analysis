import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
import time
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).parents[1]
DRIVER = ROOT / "scripts/cook_owned_fixtures.py"
TEMP_ROOT = "/tmp/opencode" if Path("/tmp/opencode").is_dir() else None

FAKE_DOCKER = '''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
root = Path(os.environ["FAKE_ROOT"])
with (root / "calls").open("a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
command = sys.argv[1]
if command == "run":
    (root / "output/build.log").write_text("partial build\\n")
    (root / "client.pid").write_text(str(os.getpid()))
    if os.environ["FAKE_MODE"] == "wait":
        time.sleep(60)
    if os.environ["FAKE_MODE"] in ("success", "cleanup-fails"):
        for folder, packages in {"tagged": ["BP_OwnedParent.uasset", "BP_OwnedChild.uasset", "OwnedMap.umap", "Data/OwnedData.uasset"], "unversioned": ["Data/OwnedData.uasset"]}.items():
            for package in packages:
                path = root / "output" / folder / "OwnedFixtures/Content" / package
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fake package; lifecycle test only")
        (root / "output/Saved").mkdir()
        (root / "output/Saved/producer-reflection.json").write_text(json.dumps({"schemas": [{"name": "Object", "properties": []}]}))
    sys.exit(7 if os.environ["FAKE_MODE"] == "fail" else 0)
if command == "stop" and os.environ["FAKE_MODE"] == "stop-fails":
    sys.exit(1)
if command == "rm" and os.environ["FAKE_MODE"] == "cleanup-fails":
    sys.exit(1)
'''

WRAPPER = '''import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, sys.argv.pop(1))
import cook_owned_fixtures as driver
read_text = Path.read_text
def read(path, *args, **kwargs):
    return "MemAvailable: 33554432 kB" if str(path) == "/proc/meminfo" else read_text(path, *args, **kwargs)
with patch.object(driver.shutil, "disk_usage", return_value=SimpleNamespace(free=32*1024**3)), patch.object(Path, "read_text", read):
    sys.exit(driver.main())
'''


class CookDriverGuards(unittest.TestCase):
    def reject(self, *arguments):
        result = subprocess.run([sys.executable, str(DRIVER), *map(str, arguments)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        return result.stderr

    def test_refuses_checkout_output_before_engine_invocation(self):
        self.assertIn("outside this checkout", self.reject(ROOT / "must-not-be-created"))
        self.assertFalse((ROOT / "must-not-be-created").exists())

    def test_refuses_existing_external_directory(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as output:
            sentinel = Path(output) / "preserve.txt"
            sentinel.write_text("user work")
            self.assertIn("new directory", self.reject(output))
            self.assertEqual(sentinel.read_text(), "user work")

    def test_timeout_must_be_bounded_before_engine_invocation(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as parent:
            for timeout in (0, 3601):
                with self.subTest(timeout=timeout):
                    self.assertIn("1..3600", self.reject(Path(parent) / "new", "--timeout", timeout))


class CookDriverLifecycle(unittest.TestCase):
    def run_driver(self, mode, cancel=None, group=False):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            root = Path(directory)
            docker = root / "docker"
            docker.write_text(FAKE_DOCKER)
            docker.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       FAKE_ROOT=directory, FAKE_MODE=mode)
            process = subprocess.Popen([sys.executable, "-c", WRAPPER, str(ROOT / "scripts"),
                                        str(root / "output"), "--timeout", "1" if cancel is None else "60"],
                                       env=env, start_new_session=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                if cancel is not None:
                    deadline = time.monotonic() + 10
                    while not (root / "client.pid").exists():
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail("fake Docker did not start")
                        time.sleep(0.01)
                    if group:
                        os.killpg(process.pid, cancel)
                    else:
                        process.send_signal(cancel)
                stdout, stderr = process.communicate(timeout=15)
                self.assertEqual(process.returncode == 0, mode == "success", (stdout, stderr))
                receipt = json.loads((root / "output/receipt.json").read_text())
                self.assertEqual(receipt["completed"], mode == "success")
                self.assertEqual(receipt["exit_code"] == 0, mode == "success")
                self.assertIn("build.log", receipt["evidence_sha256"])
                calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
                self.assertEqual([call[0] for call in calls], ["image", "run", "stop", "rm"])
                name = calls[1][calls[1].index("--name") + 1]
                self.assertTrue(name.startswith("owned-fixtures-"))
                self.assertEqual(calls[-2], ["stop", "--time", "5", name])
                self.assertEqual(calls[-1], ["rm", "--force", name])
                pid = int((root / "client.pid").read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
                return receipt
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_process_group_sigint_cleans_up(self):
        receipt = self.run_driver("wait", signal.SIGINT, group=True)
        self.assertEqual(receipt["exit_code"], 130)
        self.assertTrue(receipt["interrupted"])

    def test_sigterm_cleans_up(self):
        receipt = self.run_driver("wait", signal.SIGTERM)
        self.assertEqual(receipt["exit_code"], 143)
        self.assertTrue(receipt["interrupted"])

    def test_timeout_cleans_up(self):
        receipt = self.run_driver("wait")
        self.assertEqual(receipt["exit_code"], 124)
        self.assertTrue(receipt["timed_out"])

    def test_runtime_failure_cleans_up(self):
        self.assertEqual(self.run_driver("fail")["exit_code"], 7)

    def test_success_also_removes_container(self):
        receipt = self.run_driver("success")
        self.assertIn("usmap_sha256", receipt)
        self.assertNotIn("cleanup_errors", receipt)

    def test_cleanup_failure_cannot_report_success(self):
        receipt = self.run_driver("cleanup-fails")
        self.assertEqual(receipt["exit_code"], 1)
        self.assertTrue(receipt["cleanup_errors"])

    def test_postprocessing_exception_cleans_up(self):
        self.assertEqual(self.run_driver("missing-assets")["exit_code"], 1)

    def test_failed_stop_still_removes_container(self):
        receipt = self.run_driver("stop-fails")
        self.assertTrue(receipt["cleanup_errors"])

    def test_cleanup_timeout_still_removes_and_reaps_clients(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            import cook_owned_fixtures as driver
        finally:
            sys.path.pop(0)
        client = Mock(pid=123)
        stop = Mock(pid=124)
        stop.communicate.side_effect = subprocess.TimeoutExpired("docker stop", 10)
        remove = Mock(pid=125, returncode=0)
        remove.communicate.return_value = ("", "")
        with patch.object(driver.subprocess, "Popen", side_effect=[stop, remove]) as popen, \
                patch.object(driver.os, "killpg") as killpg:
            errors = driver.cleanup(client, "owned-fixtures-test")
        self.assertEqual(len(errors), 1)
        self.assertIn("stop:", errors[0])
        self.assertEqual(popen.call_args_list[-1].args[0],
                         ["docker", "rm", "--force", "owned-fixtures-test"])
        self.assertEqual([call.args for call in killpg.call_args_list],
                         [(123, signal.SIGKILL), (124, signal.SIGKILL), (125, signal.SIGKILL)])
        for process in (client, stop, remove):
            process.wait.assert_called_once_with(timeout=5)


if __name__ == "__main__":
    unittest.main()
