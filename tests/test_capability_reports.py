"""Public capability evidence consistency; no private policy reconstruction."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

import test_action

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import report_validation as reports


def report(kind="complete", effects=(True, True)):
    value = test_action.report([])
    chains = {"schema-version": 1, "complete": True, "needs-review": False,
              "catalog-revision": "fixture-v1", "catalog-sha256": "c" * 64,
              "witnesses": [], "diagnostics": []}
    value["context"]["capability-catalog-revision"] = "fixture-v1"
    value["context"]["dependencies"] = [{"kind": "capability-summaries", "sha256": "c" * 64}]
    value["call-chains"] = chains
    if kind in ("missing-catalog", "empty-no-catalog"):
        chains.update({"catalog-revision": None, "catalog-sha256": None})
        value["context"].pop("capability-catalog-revision")
        value["context"]["dependencies"] = []
    if kind in ("incomplete", "empty-no-catalog"):
        chains.update({"complete": False, "diagnostics": ["graph-context-incomplete"]})
    if kind == "absent":
        value.pop("call-chains")
        value["context"].pop("capability-catalog-revision")
        value["context"]["dependencies"] = []
    incomplete = kind != "complete"
    value["capability-analysis"] = {
        "schema-version": 1, "complete": not incomplete,
        "decision": "needs-review" if incomplete else "no-match", "findings": [],
        "possibly-flagged": incomplete and effects[0], "possibly-forbidden": incomplete and effects[1],
        "diagnostics": ["capability-evidence-incomplete"] if incomplete else []}
    value.update({"status": "partial" if incomplete else "successful", "analysis-complete": not incomplete})
    return value


class CapabilityReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        documents = [json.loads((ROOT / "schemas" / name).read_bytes())
                     for name in ("report-v1.schema.json", "facts-v1.schema.json")]
        registry = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in documents)
        cls.schema = Draft202012Validator(documents[0], registry=registry)
        cls.schema.check_schema(documents[0])

    def valid(self, value):
        self.schema.validate(value)
        self.assertEqual(value, reports.load(json.dumps(value).encode(), ROOT))

    def invalid(self, value):
        self.assertFalse(self.schema.is_valid(value))
        with self.assertRaises(reports.InvalidReport):
            reports.load(json.dumps(value).encode(), ROOT)

    @staticmethod
    def mutants():
        for kind in ("missing-catalog", "empty-no-catalog", "absent", "incomplete"):
            for mutation in ("all-removed", "diagnostic-only", "aggregate-only", "incomplete-no-match"):
                value = report(kind)
                capability = value["capability-analysis"]
                if mutation != "aggregate-only":
                    capability.update({"possibly-flagged": False, "possibly-forbidden": False})
                if mutation in ("all-removed", "aggregate-only"):
                    capability.update({"complete": True, "diagnostics": []})
                if mutation != "aggregate-only":
                    capability["decision"] = "no-match"
                yield kind + ":" + mutation, value
                forged = deepcopy(value)
                forged.update({"status": "successful", "analysis-complete": True})
                yield kind + ":" + mutation + ":successful", forged
            # Neither field can stand alone even when the decision is retained.
            for field in ("diagnostics", "effects"):
                value = report(kind)
                if field == "diagnostics":
                    value["capability-analysis"]["diagnostics"] = []
                else:
                    value["capability-analysis"].update({"possibly-flagged": False, "possibly-forbidden": False})
                yield kind + ":missing-" + field, value

    def test_schema_and_stdlib_loader_reject_missing_evidence_matrix(self):
        for name, value in self.mutants():
            with self.subTest(case=name):
                self.invalid(value)

    def test_valid_single_or_both_effects_and_legacy_reports(self):
        for kind in ("missing-catalog", "empty-no-catalog", "absent", "incomplete"):
            for effects in ((True, False), (False, True), (True, True)):
                with self.subTest(kind=kind, effects=effects):
                    self.valid(report(kind, effects))
        self.valid(report())
        legacy = report("absent")
        legacy.pop("capability-analysis")
        legacy.update({"status": "successful", "analysis-complete": True})
        self.valid(legacy)

    def test_possible_witness_only_does_not_require_aggregate_effects(self):
        value = report()
        value.update({"status": "partial", "analysis-complete": False})
        value["call-chains"]["needs-review"] = True
        value["call-chains"]["witnesses"] = [{
            "resolution": "possible", "callers": [], "endpoint": {
                "origin": {"asset": "fixture", "function": "Run", "offset": 0},
                "target": {"owner": "/Script/Fixture.Utility", "function": "Touch"},
                "resolution": "possible", "flagged": False, "forbidden": False, "capability": "fixture-capability"}}]
        for effects in ((True, False), (False, True), (True, True)):
            with self.subTest(effects=effects):
                value["capability-analysis"].update({
                    "complete": False, "decision": "needs-review", "diagnostics": ["capability-match-uncertain"],
                    "findings": [{"witness": 0, "flagged": False, "forbidden": False,
                                  "possibly-flagged": effects[0], "possibly-forbidden": effects[1]}]})
                self.valid(value)

    def test_actual_action_process_rejects_lying_json_before_projection(self):
        for name, value in self.mutants():
            with self.subTest(case=name):
                adapter = test_action.ActionTests()
                adapter.setUp()
                try:
                    result, outputs, _ = adapter.invoke(value, code=0)
                    self.assertEqual(3, result.returncode, result.stderr)
                    self.assertEqual("false", outputs["report-available"])
                    self.assertEqual("false", outputs["analysis-complete"])
                    self.assertEqual("unknown", outputs["capability-analysis-status"])
                    self.assertEqual("unknown", outputs["capability-forbidden-count"])
                    self.assertEqual("unknown", outputs["capability-possibly-forbidden-count"])
                    self.assertEqual(["invalid-report"], json.loads(outputs["diagnostics"]))
                finally:
                    adapter.tearDown()

    def test_fixed_diagnostics_remain_closed_unique_and_consistent(self):
        for diagnostic in (["extra"], ["capability-evidence-incomplete"] * 2):
            value = report("absent")
            value["capability-analysis"]["diagnostics"] = diagnostic
            self.invalid(value)
        value = report()
        value["capability-analysis"]["diagnostics"] = ["capability-evidence-incomplete"]
        self.invalid(value)
        value = report("absent")
        value["capability-analysis"]["extra"] = False
        self.invalid(value)
        value = report()
        value["capability-analysis"].update({"complete": False, "diagnostics": ["capability-match-uncertain"]})
        self.invalid(value)

    def test_actual_action_process_accepts_valid_evidence_states(self):
        values = [report()] + [report(kind, effects)
            for kind in ("missing-catalog", "empty-no-catalog", "absent", "incomplete")
            for effects in ((True, False), (False, True), (True, True))]
        for index, value in enumerate(values):
            with self.subTest(case=index):
                adapter = test_action.ActionTests()
                adapter.setUp()
                try:
                    result, outputs, _ = adapter.invoke(value, code=0 if index == 0 else 1)
                    self.assertEqual(0 if index == 0 else 1, result.returncode, result.stderr)
                    self.assertEqual("true", outputs["report-available"])
                    self.assertEqual("complete" if index == 0 else "incomplete", outputs["capability-analysis-status"])
                finally:
                    adapter.tearDown()


if __name__ == "__main__":
    unittest.main()
