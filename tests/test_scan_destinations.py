"""Host output separation before Docker, policy disclosure, or input reads."""

import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import scan


class ScanDestinationTests(unittest.TestCase):
    def arguments(self, root, report, context):
        return ["scan", "--pak", str(root / "private-pak"), "--report", str(report),
                "--data-context", str(context), "--data-rules", str(root / "private-rules"),
                "--baseline-pak", str(root / "private-baseline"), "--policy-rules", str(root / "private-policy"),
                "--game-build", "private-build-canary", "--content-root", "Content=/Game",
                "--engine-version", "4.25", "--log-level", "verbose"]

    def aliases(self, root):
        (root / "child").mkdir()
        (root / "alias").symlink_to(root, target_is_directory=True)
        target = root / "ordinary.json"
        return [(target, target), (target, root / "child/../ordinary.json"),
                (target, root / "alias/ordinary.json"),
                (target, os.path.relpath(target)),
                (target, str(root) + "/./ordinary.json")]

    def test_aliases_fail_before_docker_policy_or_snapshots(self):
        with tempfile.TemporaryDirectory(prefix="scan-destinations-") as temporary:
            root = Path(temporary)
            for report, context in self.aliases(root):
                with self.subTest(context=str(context)), patch.object(scan, "Docker") as docker, \
                        patch.object(scan, "snapshot") as snapshot, patch.object(scan, "mount") as mount, \
                        patch.object(scan.os, "getuid", return_value=1000), \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    self.assertEqual(2, scan.main(self.arguments(root, report, context)))
                    docker.assert_not_called()
                    snapshot.assert_not_called()
                    mount.assert_not_called()
                    self.assertEqual("Scan failed.\n", stderr.getvalue())
                    self.assertFalse(report.exists())
                    self.assertFalse(Path(context).exists())

    @unittest.skipIf(os.getuid() == 0, "host CLI requires non-root operator")
    def test_public_host_cli_rejects_new_aliases_without_artifacts_or_disclosure(self):
        with tempfile.TemporaryDirectory(prefix="scan-cli-destinations-") as temporary:
            root = Path(temporary)
            # A raw verbose-policy canary must never reach the evaluator.
            (root / "private-policy").write_text("private-raw-policy-canary")
            for report, context in self.aliases(root):
                with self.subTest(context=str(context)):
                    result = subprocess.run([sys.executable, str(ROOT / "scripts/scan.py"),
                        *self.arguments(root, report, context)], capture_output=True, timeout=10)
                    self.assertEqual(2, result.returncode)
                    self.assertEqual(b"", result.stdout)
                    self.assertEqual(b"Scan failed.\n", result.stderr)
                    self.assertFalse(report.exists())
                    self.assertFalse(Path(context).exists())

    def test_occupied_outputs_never_modify_inputs_or_create_private_context(self):
        with tempfile.TemporaryDirectory(prefix="scan-occupied-") as temporary:
            root = Path(temporary)
            for key in ("pak", "rules", "baseline", "policy", "mapping", "catalog"):
                source = root / ("private-" + key)
                source.write_bytes(b"private-input-canary")
                for report, context in ((source, root / "new-context"), (root / "new-report", source)):
                    with self.subTest(key=key, report=str(report)), patch.object(scan, "Docker") as docker, \
                            patch.object(scan.os, "getuid", return_value=1000), \
                            contextlib.redirect_stderr(io.StringIO()) as stderr:
                        args = self.arguments(root, report, context) + ["--mapping", str(root / "private-mapping"),
                            "--capability-summaries", str(root / "private-catalog")]
                        self.assertEqual(3, scan.main(args))
                        docker.assert_not_called()
                        self.assertEqual("Scan failed.\n", stderr.getvalue())
                        self.assertEqual(b"private-input-canary", source.read_bytes())
                        self.assertFalse((root / "new-context").exists())
                        self.assertFalse((root / "new-report").exists())

    def test_final_symlinks_and_fifos_remain_occupied(self):
        with tempfile.TemporaryDirectory(prefix="scan-special-output-") as temporary:
            root = Path(temporary)
            (root / "dangling").symlink_to(root / "absent")
            os.mkfifo(root / "fifo")
            for name in ("dangling", "fifo"):
                for report, context in ((root / name, root / "context"), (root / "report", root / name)):
                    with self.subTest(name=name), patch.object(scan, "Docker") as docker, \
                            patch.object(scan.os, "getuid", return_value=1000), \
                            contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(3, scan.main(self.arguments(root, report, context)))
                        docker.assert_not_called()
                        self.assertFalse((root / "absent").exists())
                        self.assertFalse((root / "context").exists())
                        self.assertFalse((root / "report").exists())

    def test_distinct_case_sensitive_names_and_symlink_parent_normalization(self):
        with tempfile.TemporaryDirectory(prefix="scan-new-output-") as temporary:
            root = Path(temporary)
            (root / "alias").symlink_to(root, target_is_directory=True)
            args = scan.options(self.arguments(root, root / "alias/Report", root / "report"))
            scan.output_destinations(args)
            self.assertEqual(root / "Report", args.report)
            self.assertEqual(root / "report", args.data_context)
            scan.write_report(args.report, b"ordinary")
            scan.write_report(args.data_context, b"private")
            self.assertEqual(b"ordinary", args.report.read_bytes())
            self.assertEqual(b"private", args.data_context.read_bytes())
            with self.assertRaises(FileExistsError):
                scan.write_report(args.report, b"private")
            self.assertEqual(b"ordinary", args.report.read_bytes())


if __name__ == "__main__":
    unittest.main()
