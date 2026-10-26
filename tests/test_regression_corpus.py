"""Runner lifecycle guards; semantic mutations use actual CLI reports in the gate."""

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import regression_corpus as corpus
import scan
import test_action


class CorpusRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="corpus-guards-")
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

    def test_all_local_action_parity_callers_use_isolated_adapter(self):
        tree = ast.parse((corpus.ROOT / "scripts/regression_corpus.py").read_text())
        callers = set()
        for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
            for node in ast.walk(function):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr != "command":
                    continue
                environment = next((kw.value for kw in node.keywords if kw.arg == "env"), None)
                if not isinstance(environment, ast.Dict) or not any(
                        isinstance(key, ast.Constant) and key.value == "UE_PAK_ACTION_IMAGE"
                        for key in environment.keys):
                    continue
                self.assertEqual("run.action_script", ast.unparse(node.args[0].elts[1]))
                callers.add(function.name)
        self.assertEqual({"integrated", "capability_policy_gate", "call_chain_container_gate",
                          "package_context_gate", "package_context_boundary_gate"}, callers)

    def test_manifest_present_local_parity_uses_selected_image_but_production_rejects_id(self):
        # A private fixture models B; never install a synthetic manifest in the checkout.
        source = self.root / "published-source"
        test_action.development_action(source)
        pin = {"version": "v0.1.0", "platform": "linux/amd64", "build-source": "a" * 40,
               "image": "ghcr.io/chiv2-community/ue-pak-static-risk-analysis@sha256:" + "b" * 64}
        manifest = source / "action-image.json"
        manifest.write_text(json.dumps(pin))
        selected = "sha256:" + "d" * 64
        value = test_action.report()
        # Fake only the Docker-backed scan boundary; run the actual Action adapter,
        # output validation, environment scrubbing and integrated parity assertions.
        stub = ("import os,sys\nfrom pathlib import Path\n"
                f"assert sys.argv[sys.argv.index('--image')+1] == {selected!r}\n"
                "assert os.environ['UE_PAK_POLICY_RULES'] == 'private-parity-policy'\n"
                "assert 'GITHUB_TOKEN' not in os.environ\n"
                "assert 'GITHUB_OUTPUT' not in os.environ\n"
                f"Path(sys.argv[sys.argv.index('--report')+1]).write_text({json.dumps(value)!r})\n"
                "sys.exit(1)\n")
        (source / "scripts/scan.py").write_text(stub)
        evidence = self.root / "evidence"
        evidence.mkdir()
        runner = corpus.Run(evidence)
        runner.evaluate = Mock(return_value=value)
        pak, catalog = self.root / "pak", self.root / "catalog.json"
        pak.write_bytes(b"original-test-pak")
        catalog.write_text("{}")
        docker = Mock(image=selected)
        docker.run.return_value = (0, b"{}")
        with patch.object(corpus, "ROOT", source), patch.object(test_action, "ROOT", source), \
                patch.object(scan, "Docker", return_value=docker) as docker_class, \
                patch.dict(os.environ, {}, clear=True):
            corpus.call_chain_container_gate(runner, "caller-selected:local", pak, catalog, "private-parity-policy")
            self.assertEqual("caller-selected:local", docker_class.call_args.args[1])
            self.assertIs(runner.action_script, runner.action_script)
        self.assertEqual([1, 1], [r["exit"] for r in runner.receipts])
        self.assertEqual(value, json.loads((evidence / "chain-action/report.json").read_bytes()))
        self.assertFalse((runner.action_script.parents[1] / "action-image.json").exists())
        self.assertEqual(pin, json.loads(manifest.read_bytes()))

        workspace = self.root / "production-workspace"
        workspace.mkdir()
        output, summary = workspace / "outputs", workspace / "summary"
        output.touch()
        summary.touch()
        result = subprocess.run([sys.executable, source / "scripts/action.py", "scan"],
            env={"GITHUB_WORKSPACE": str(workspace), "GITHUB_OUTPUT": str(output),
                 "GITHUB_STEP_SUMMARY": str(summary), "INPUT_REPORT": "report.json",
                 "INPUT_PAK": str(pak), "UE_PAK_ACTION_IMAGE": selected},
            cwd=workspace, capture_output=True, timeout=10)
        self.assertEqual(3, result.returncode, result.stderr)
        outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(["image-preparation-failed"], json.loads(outputs["diagnostics"]))
        self.assertEqual("false", outputs["report-available"])
        self.assertFalse((workspace / "report.json").exists())
