"""Runner lifecycle guards; semantic mutations use actual CLI reports in the gate."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import regression_corpus as corpus


class CorpusRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="corpus-guards-", dir="/tmp/opencode" if Path("/tmp/opencode").is_dir() else None)
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_required_missing_owned_evidence_fails_without_skip_or_engine(self):
        result = subprocess.run([sys.executable, str(corpus.ROOT / "scripts/regression_corpus.py"),
            "--output", str(self.root / "output"), "--owned-evidence", str(self.root / "missing")],
            capture_output=True, timeout=10)
        self.assertEqual(1, result.returncode)
        self.assertIn(b"requested owned evidence missing", result.stderr)
        self.assertNotIn(b"PASS", result.stdout)

    def test_deadline_kills_process_group(self):
        runner = corpus.Run(self.root)
        with self.assertRaises(subprocess.TimeoutExpired):
            runner.command([sys.executable, "-c", "import time;time.sleep(30)"], timeout=.1)
        self.assertEqual([], runner.receipts)

    def test_output_flood_is_bounded_and_fails(self):
        runner = corpus.Run(self.root)
        with self.assertRaisesRegex(ValueError, "process output budget"):
            runner.command([sys.executable, "-c", "import os;os.write(1,b'x'*(33*1024*1024))"], timeout=10)
        self.assertLessEqual(sum(p.stat().st_size for p in self.root.iterdir()), corpus.LIMIT)

    def test_output_oracle_uses_shipped_case_sensitive_duplicate_rejecting_validator(self):
        for raw in (b'{"schema-version":1,"schema-version":1}', b'{"Schema-Version":1}',
                    b'{"schema-version":1,"rule-ids":["corpus-policy-canary"]}'):
            with self.assertRaises(ValueError):
                corpus.report_validation.load(raw, corpus.ROOT)
