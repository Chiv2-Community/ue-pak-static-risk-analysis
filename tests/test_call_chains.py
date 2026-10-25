"""Strict call-chain transport, default privacy and exact moderation binding; no Docker."""

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import action_report
import moderation
import report_validation as reports


def report():
    value = json.loads((ROOT / "examples/reports/successful-v1.json").read_bytes())
    finding = value["forbidden-invocations"][0]
    value["status"], value["analysis-complete"] = "partial", False
    value["call-chains"] = {"schema-version": 1, "complete": False, "needs-review": False,
        "catalog-revision": None, "catalog-sha256": None, "diagnostics": ["external-summary-unavailable"],
        "witnesses": [{"endpoint": {"origin": finding["location"], "target": finding["target"],
            "resolution": "direct", "flagged": True, "forbidden": True, "capability": None},
            "resolution": "possible", "callers": [{"origin": {"asset": "/Game/Caller", "function": "Root", "offset": 17},
                "target": {"owner": "/Game/Asset0.BP", "function": "Execute"}, "resolution": "possible", "kind": "delegate-binding"}]}]}
    return value


class CallChainTransportTests(unittest.TestCase):
    def load(self, value):
        return reports.load(json.dumps(value).encode(), ROOT)

    def test_default_report_accepts_separate_uncertain_witness_and_keeps_direct_counts(self):
        value = self.load(report())
        self.assertEqual(value, action_report.load(json.dumps(value).encode(), ROOT))
        self.assertEqual(1, value["counts"]["forbidden"])
        self.assertEqual(0, value["call-chains"]["witnesses"][0]["endpoint"]["origin"]["offset"])
        self.assertEqual(17, value["call-chains"]["witnesses"][0]["callers"][0]["origin"]["offset"])

    def test_closed_schema_uncertainty_actual_identity_and_bounds_are_mandatory(self):
        paths = [
            (("call-chains", "schema-version"), 2),
            (("call-chains", "complete"), True),
            (("call-chains", "witnesses", 0, "resolution"), "direct"),
            (("call-chains", "witnesses", 0, "endpoint", "origin", "offset"), 99),
            (("call-chains", "witnesses", 0, "endpoint", "capability"), "private-canary"),
            (("call-chains", "witnesses", 0, "endpoint", "private-rule-id"), "private-canary"),
            (("call-chains", "witnesses", 0, "callers", 0, "resolution"), "direct"),
            (("call-chains", "witnesses", 0, "callers"), report()["call-chains"]["witnesses"][0]["callers"] * 17),
            (("call-chains", "witnesses"), report()["call-chains"]["witnesses"] * 257),
        ]
        for path, replacement in paths:
            with self.subTest(path=path):
                value = copy.deepcopy(report())
                node = value
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = replacement
                with self.assertRaises(reports.InvalidReport):
                    self.load(value)

    def test_actual_endpoint_identity_uses_fields_not_json_member_order(self):
        value = report()
        endpoint = value["call-chains"]["witnesses"][0]["endpoint"]
        endpoint["origin"] = dict(reversed(list(endpoint["origin"].items())))
        endpoint["target"] = dict(reversed(list(endpoint["target"].items())))
        self.load(value)

    def test_nonsecret_catalog_example_matches_its_closed_schema(self):
        schema = json.loads((ROOT / "schemas/capability-summaries-v1.schema.json").read_bytes())
        value = json.loads((ROOT / "examples/capability-summaries-v1.json").read_bytes())
        reports.check_schema(schema)
        reports.validate(value, schema, schema, {})
        value["summaries"][0]["filename"] = "/private/policy"
        with self.assertRaises(reports.InvalidReport):
            reports.validate(value, schema, schema, {})

    def test_catalog_hash_revision_are_context_bound_and_moderation_copies_no_graph(self):
        with tempfile.TemporaryDirectory(prefix="chain-moderation-") as directory:
            pak, catalog = Path(directory) / "pak", Path(directory) / "catalog"
            pak.write_bytes(b"original-fixture-only")
            catalog.write_bytes((ROOT / "examples/capability-summaries-v1.json").read_bytes())
            value = report()
            value["context"].update({"pak-sha256": hashlib.sha256(pak.read_bytes()).hexdigest(),
                "policy-revision": "fixture-v1", "capability-catalog-revision": "original-call-chain-fixture-v1",
                "dependencies": [{"kind": "capability-summaries", "sha256": hashlib.sha256(catalog.read_bytes()).hexdigest()}]})
            chains = value["call-chains"]
            chains.update({"needs-review": True, "catalog-revision": value["context"]["capability-catalog-revision"],
                           "catalog-sha256": value["context"]["dependencies"][0]["sha256"]})
            chains["witnesses"][0]["endpoint"]["capability"] = "fixture-opaque-boundary"
            context = {"schema-version": 1, "kind": "scan-context", "scanner-identity": "git:" + "1" * 40,
                       "game-build": "fixture-only", "report-context": value["context"]}
            raw = json.dumps(value).encode()
            handoff = moderation.handoff(raw, context, pak, [("capability-summaries", catalog)])
            self.assertNotIn("call-chains", handoff)
            self.assertEqual({"complete": False, "needs-review": True}, handoff["call-chain-analysis"])
            approval = moderation.review(handoff, "fixture-reviewer", "approve", "Fixture only")
            self.assertTrue(moderation.verify(approval, context, pak, [("capability-summaries", catalog)], raw))
            chains["witnesses"][0]["callers"][0]["origin"]["offset"] += 1
            with self.assertRaises(reports.InvalidReport):
                moderation.verify(approval, context, pak, [("capability-summaries", catalog)], json.dumps(value).encode())
            catalog.write_bytes(b"changed catalog")
            with self.assertRaises(reports.InvalidReport):
                moderation.verify(approval, context, pak, [("capability-summaries", catalog)], raw)
            feedback = json.dumps(moderation.feedback(handoff))
            self.assertNotIn("fixture-opaque-boundary", feedback)
            self.assertNotIn("catalog-sha256", feedback)

    def test_context_catalog_cannot_disagree_with_evidence(self):
        value = report()
        value["call-chains"]["catalog-revision"] = "revision"
        value["call-chains"]["catalog-sha256"] = "a" * 64
        with self.assertRaises(reports.InvalidReport):
            self.load(value)
