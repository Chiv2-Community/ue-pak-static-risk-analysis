"""Runtime assignment policies on original serialized fixtures; no game execution."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ingestion_fixture import build
from pak_ingest import ingest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import moderation
import report_validation as reports

POLICY = """schema-version: 1
rules:
  - id: private-write-canary
    description: Private write description
    effect: forbid
    expression:
      any:
        - property-write: {class: __WILDCARD__, property: IgnoreCorrection}
        - property-write: {class: __WILDCARD__, property: Settings}
        - property-write:
            class: __WILDCARD__
            property: CustomTimeDilation
            predicate: {kind: equals, value: 90.0}
"""


class PropertyWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="property-writes-", dir="/tmp/opencode")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        generated = cls.root / "generated"
        for command in (["dotnet", "build", "src/Parser", "--verbosity", "quiet"],
                        ["dotnet", "run", "--project", "tests/Corpus.Generate", "--", "property-writes", str(generated)]):
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=120)
            if result.returncode:
                raise AssertionError(result.stderr.decode() + result.stdout.decode())
        cls.pak = cls.root / "fixture.pak"
        cls.pak.write_bytes(build([("Content/" + p.name, p.read_bytes(), False) for p in sorted(generated.iterdir())
                                  if p.suffix in (".uasset", ".uexp")]))

        def inspector(root, inventory):
            (Path(root) / "inspection.json").write_text(json.dumps(inventory))
            result = subprocess.run(["dotnet", str(ROOT / "src/Parser/bin/Debug/net10.0/Parser.dll"),
                root, "-", "Content", "/Game", str(cls.pak)], capture_output=True, timeout=30)
            if result.returncode:
                raise AssertionError("Original property-write fixture parser failed")
            cls.facts = json.loads(result.stdout)
        ingest(cls.pak, inspector=inspector)

    def evaluate(self, policy=POLICY, facts=None, extra=()):
        with tempfile.TemporaryDirectory(prefix="case-", dir=self.root) as temporary:
            facts_path = Path(temporary) / "facts.json"
            facts_path.write_text(json.dumps(self.facts if facts is None else facts))
            result = subprocess.run(["dotnet", str(ROOT / "src/Scanner/bin/Debug/net10.0/Scanner.dll"), "evaluate",
                "--facts", str(facts_path), "--report", "-", "--engine-version", "4.25", "--policy-revision", "fixture", *extra],
                env=dict(os.environ, UE_PAK_POLICY_RULES=policy), capture_output=True, timeout=30)
            self.assertNotIn(b"private-write-canary", result.stdout + result.stderr)
            return result, reports.load(result.stdout, ROOT)

    def test_serialized_parser_to_evaluator_preserves_writes_and_gate(self):
        writes = self.facts["analysis"]["property-writes"]
        self.assertTrue(writes["complete"])
        self.assertEqual(["IgnoreCorrection", "CustomTimeDilation", "Settings", "Settings.Distance"], [w["property"] for w in writes["writes"]])
        result, report = self.evaluate()
        self.assertEqual(1, result.returncode)
        self.assertEqual(4, len(report["property-writes"]["forbidden"]))
        self.assertEqual(0, report["counts"]["invocations"])
        self.assertTrue(report["analysis-complete"])
        relaxed, _ = self.evaluate(extra=("--fail-on-any-forbidden", "false"))
        self.assertEqual(0, relaxed.returncode)

    def test_whole_struct_replacement_is_unknown_for_narrow_field_rule(self):
        policy = POLICY[:POLICY.index("      any:")] + "      property-write: {class: __WILDCARD__, property: Settings.Distance}\n"
        result, report = self.evaluate(policy=policy)
        self.assertEqual(1, result.returncode)
        self.assertFalse(report["analysis-complete"])
        self.assertEqual(1, len(report["property-writes"]["forbidden"]))

    def test_missing_write_evidence_requires_review(self):
        facts = deepcopy(self.facts)
        del facts["analysis"]["property-writes"]
        result, report = self.evaluate(facts=facts)
        self.assertEqual(1, result.returncode)
        self.assertFalse(report["analysis-complete"])

    def test_moderation_preserves_property_only_policy_violation(self):
        result, report = self.evaluate()
        template = json.loads((ROOT / "examples/moderation/context.json").read_text())
        template["report-context"] = report["context"]
        template["game-build"] = "fixture"
        handoff = moderation.handoff(result.stdout, template, self.pak, [])
        self.assertIn("policy-violation", handoff["routes"])
        self.assertEqual(4, handoff["property-write-counts"]["forbidden"])
        self.assertEqual(handoff["property-write-counts"], moderation.feedback(handoff)["property-write-counts"])

    def test_report_validator_rejects_duplicate_write_findings(self):
        _, report = self.evaluate()
        report["property-writes"]["forbidden"].append(report["property-writes"]["forbidden"][0])
        with self.assertRaises(reports.InvalidReport):
            reports.load(json.dumps(report).encode(), ROOT)
