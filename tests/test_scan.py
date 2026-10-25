"""Trusted host boundary tests; no Docker daemon required."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("scan", Path(__file__).resolve().parents[1] / "scripts/scan.py")
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)


class ScanTests(unittest.TestCase):
    def test_capability_catalog_is_snapshotted_only_for_trusted_evaluator(self):
        calls = []
        class Docker:
            def __init__(self, *args):
                pass
            def run(self, mounts, entry, arguments, **options):
                calls.append((list(mounts), list(arguments), options))
                return (0, b"{}")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pak, catalog = root / "pak", root / "catalog"
            pak.write_bytes(b"owned")
            catalog.write_bytes(b"original nonsecret catalog")
            with patch.object(scan, "Docker", Docker):
                code = scan.main(["scan", "--pak", str(pak), "--report", str(root / "report"),
                    "--engine-version", "4.25", "--capability-summaries", str(catalog)])
            self.assertEqual(0, code)
        self.assertEqual(3, len(calls))
        for mounts, args, options in (calls[0], calls[2]):
            self.assertIn("--capability-summaries", args)
            self.assertIn("/catalog/summaries", args)
            self.assertTrue(any("target=/catalog/summaries" in item for item in mounts))
        self.assertNotIn("--capability-summaries", calls[1][1])
        self.assertNotIn("/catalog/summaries", " ".join(calls[1][0]))

    def test_client_environment_allowlist(self):
        with patch.dict(os.environ, {"UE_PAK_POLICY_RULES": "private", "AWS_SECRET_ACCESS_KEY": "credential"}):
            self.assertEqual({"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, scan.client_environment())
            self.assertEqual("private", scan.client_environment(True)["UE_PAK_POLICY_RULES"])
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", scan.client_environment(True))
        with patch.dict(os.environ, {"UE_PAK_POLICY_RULES": "invalid-utf8-\udcff"}):
            with self.assertRaisesRegex(scan.Failure, "invalid-configuration"):
                scan.client_environment(True)
            self.assertNotIn("UE_PAK_POLICY_RULES", scan.client_environment())

    def test_fixed_containment_and_no_policy_argument(self):
        docker = object.__new__(scan.Docker)
        docker.prefix, docker.image = ["/usr/bin/docker"], "sha256:" + "a" * 64
        with patch.dict(os.environ, {"UE_PAK_POLICY_RULES": "private-policy-canary"}):
            args = docker.command("owned", [], "parser", [], False)
            for value in ("--read-only", "--cap-drop", "ALL", "no-new-privileges", "none", "--memory", "--pids-limit"):
                self.assertIn(value, args)
            self.assertNotIn("UE_PAK_POLICY_RULES", args)
            evaluated = docker.command("owned", [], "evaluator", [], True)
            self.assertIn("UE_PAK_POLICY_RULES", evaluated)
            self.assertNotIn("private-policy-canary", evaluated)

    def test_snapshot_and_report_never_overwrite(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"exact bytes")
            target = root / "snapshot"
            self.assertEqual(hashlib.sha256(b"exact bytes").hexdigest(), scan.snapshot(source, target, 11))
            self.assertEqual(b"exact bytes", target.read_bytes())
            self.assertEqual(0o400, target.stat().st_mode & 0o777)
            alias = root / "alias"
            alias.symlink_to(source)
            with self.assertRaises(OSError):
                scan.snapshot(alias, root / "bad", 100)
            with self.assertRaises(scan.Failure):
                scan.snapshot(source, root / "large", 2)
            scan.write_report(root / "report", b"report")
            with self.assertRaises(FileExistsError):
                scan.write_report(root / "report", b"replacement")
            with self.assertRaises(FileExistsError):
                scan.write_report(alias, b"replacement")
            self.assertEqual(b"exact bytes", source.read_bytes())
            self.assertFalse(list(root.glob(".risk-report-*")))

    def test_reject_mount_syntax_injection(self):
        for value in ("path,readonly=false", "path\nnext", "path\0"):
            with self.assertRaises(scan.Failure):
                scan.mount(value, "/input/submission")

    def test_supervisor_inspection_precedes_cleanup(self):
        from pak_ingest import ingest
        from ingestion_fixture import build
        observed = []
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.pak"
            source.write_bytes(build())
            def inspector(root, report):
                observed.append(Path(root))
                self.assertEqual("validated", report["ingestion_status"])
                self.assertEqual(b"owned", (Path(root) / "r00000000").read_bytes())
            ingest(source, inspector=inspector)
            self.assertEqual(1, len(observed))
            self.assertFalse(observed[0].exists())

    def test_content_configuration_only_reaches_trusted_stages(self):
        calls = []
        class Docker:
            def __init__(self, *args):
                pass
            def run(self, mounts, entry, arguments, **options):
                calls.append((mounts, entry, arguments, options))
                return (0, b"{}")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pak = root / "submission"
            pak.write_bytes(b"owned")
            with patch.object(scan, "Docker", Docker):
                code = scan.main(["scan", "--pak", str(pak), "--report", str(root / "report"),
                    "--engine-version", "4.25", "--allowed-path", "PrivateCanary", "--allowed-path", "Other",
                    "--allowed-class", "/Script/PrivateCanary.Class", "--protected-path", "ProtectedCanary",
                    "--replacement-policy", "review", "--replacement-policy", "reject"])
            self.assertEqual(0, code)
        self.assertEqual(3, len(calls))
        for index in (0, 2):
            self.assertTrue(calls[index][3]["policy"])
            self.assertIn("PrivateCanary", calls[index][2])
            self.assertIn("/Script/PrivateCanary.Class", calls[index][2])
            self.assertIn("ProtectedCanary", calls[index][2])
            self.assertEqual(2, calls[index][2].count("--replacement-policy"))
        self.assertTrue(calls[1][3]["parser"])
        self.assertNotIn("Canary", repr(calls[1]))

    def test_content_flag_abbreviations_are_not_accepted(self):
        with self.assertRaisesRegex(scan.Failure, "invalid-configuration"):
            scan.options(["scan", "--pak", "pak", "--report", "report", "--engine-version", "4.25", "--allowed-pa", "Content"])
