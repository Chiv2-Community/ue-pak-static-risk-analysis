"""Actual serialized packages through V9 ingestion, Parser and the shared evaluator."""
from copy import deepcopy
import json
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
import regression_corpus as corpus
import report_validation as reports


class PackageContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="package-context-")
        cls.root = Path(cls.temporary.name)
        cls.runner = corpus.Run(cls.root)
        cls.runner.command(["dotnet", "build", ROOT / "tests/Corpus.Generate", "-c", "Release"], timeout=180)
        cls.pak, cls.path, cls.policy, cls.report = corpus.package_context_gate(cls.runner)
        cls.facts = json.loads(cls.path.read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def parse(self, pak, reverse=False):
        result = []
        def inspector(root, report):
            if reverse:
                report["records"].reverse()
            (Path(root) / "inspection.json").write_text(json.dumps(report))
            raw, _ = self.runner.command(["dotnet", ROOT / "src/Parser/bin/Release/net10.0/Parser.dll",
                root, "-", "Content", "/Game", pak])
            result.append(json.loads(raw))
        self.assertEqual("validated", ingest(pak, inspector=inspector)["ingestion_status"])
        return result[0]

    def test_fixed_oracle_checks_candidates_origins_and_possible_cross_package_chain(self):
        corpus.package_context_oracle(self.report)
        self.assertEqual(5, len(self.facts["analysis"]["call-graph"]["functions"]))
        self.assertEqual([], self.facts["dependencies"])
        self.assertEqual(corpus.digest(self.pak.read_bytes()), self.report["context"]["pak-sha256"])

    def test_combined_candidate_limit_keeps_large_package_direct_forbid_and_later_packages(self):
        corpus.package_context_boundary_gate(self.runner, "package-context-budget")

    def test_unused_case_variant_import_keeps_exact_declaration_policy_and_chain(self):
        corpus.package_context_boundary_gate(self.runner, "package-context-case")

    def test_reordered_manifest_preserves_all_facts(self):
        self.assertEqual(self.facts, self.parse(self.pak, reverse=True))

    def test_missing_archive_parent_keeps_sensitive_candidates_and_explicit_unknowns(self):
        generated = self.root / "package-context"
        pak = self.root / "missing-base.pak"
        pak.write_bytes(build([("Content/" + p.name, p.read_bytes(), False) for p in sorted(generated.iterdir())
                               if p.stem != "Base"]))
        facts = self.parse(pak)
        caller = facts["analysis"]["dispatches"][0]
        self.assertIn("dependency-context-unavailable", caller["diagnostics"])
        self.assertIn("parent-unavailable", caller["diagnostics"])
        self.assertIn("/Game/ChildOverride.Type", [c["owner"] for c in caller["candidates"]])
        self.assertIn("incomplete-extraction", facts["analysis"]["coverage-gaps"])

    def test_optional_context_never_changes_direct_ids_counts_or_forbidden_locations(self):
        stripped = deepcopy(self.facts)
        stripped["analysis"].pop("dispatches")
        path = self.root / "no-dispatches.json"
        path.write_text(json.dumps(stripped))
        report = self.runner.evaluate(path, policy=self.policy)
        for key in ("counts", "forbidden-invocations", "flagged-invocations"):
            self.assertEqual(self.report[key], report[key])

    def test_removal_mutation_is_schema_valid_but_fails_evidence_oracle(self):
        value = deepcopy(self.report)
        value["possible-dispatches"][0]["evidence"]["candidates"].pop()
        reports.load(json.dumps(value).encode(), ROOT)
        with self.assertRaisesRegex(ValueError, "archive candidate evidence lost"):
            corpus.package_context_oracle(value)

    def test_strict_wire_provenance_duplicates_unknown_keys_and_case_are_not_trimmed_away(self):
        for mode in ("unknown", "case", "duplicate", "key"):
            value = deepcopy(self.facts)
            dispatch = value["analysis"]["dispatches"][0]
            if mode in ("unknown", "case"):
                dispatch["candidates"][0]["provenance"] = "unknown" if mode == "unknown" else "Archive-function"
            elif mode == "duplicate":
                dispatch["candidates"].append(deepcopy(dispatch["candidates"][0]))
            else:
                dispatch["candidates"][0]["private-provenance"] = "private-canary"
            path = self.root / ("invalid-" + mode + ".json")
            path.write_text(json.dumps(value))
            report = self.runner.evaluate(path, policy=self.policy, codes=(2, 3))
            self.assertEqual("failed", report["status"])

    def test_exact_archive_and_report_bytes_bind_context_without_new_public_dependency_fields(self):
        report = self.runner.evaluate(self.path, policy=self.policy, extra=["--policy-revision", "original-context-v1"])
        raw = json.dumps(report).encode()
        context = {"schema-version": 1, "kind": "scan-context", "scanner-identity": "git:" + "1" * 40,
                   "game-build": "original-model", "report-context": report["context"]}
        handoff = moderation.handoff(raw, context, self.pak, [])
        approval = moderation.review(handoff, "fixture-reviewer", "approve", "Synthetic model only")
        self.assertTrue(moderation.verify(approval, context, self.pak, [], raw))
        changed = self.root / "changed-context.pak"
        generated = self.root / "package-context"
        changed.write_bytes(build([("Content/" + p.name, p.read_bytes(), False) for p in sorted(generated.iterdir())
                                   if p.stem != "Interface"]))
        with self.assertRaises(ValueError):
            moderation.verify(approval, context, changed, [], raw)
        mutant = deepcopy(report)
        mutant["possible-dispatches"][0]["evidence"]["candidates"].pop()
        with self.assertRaises(ValueError):
            moderation.verify(approval, context, self.pak, [], json.dumps(mutant).encode())
        feedback = json.dumps(moderation.feedback(handoff))
        for text in ("ChildOverride", "archive-function", corpus.digest(self.pak.read_bytes()), "original-archive-candidate"):
            self.assertNotIn(text, feedback)


if __name__ == "__main__":
    unittest.main()
