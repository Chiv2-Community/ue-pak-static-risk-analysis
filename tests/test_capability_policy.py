"""Private capability predicates on original serialized fixtures; no game execution."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ingestion_fixture import build
from pak_ingest import ingest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import action
import moderation
import report_validation as reports
import scan
from regression_corpus import capability_policy_oracle

POLICY = """schema-version: 1
rules:
  - id: invocation-canary
    description: Original fixture only
    effect: forbid
    match:
      kind: invocation
      target:
        kind: exact
        owner: /Script/Fixture.Other
        function: Other
"""


def sha(value):
    return hashlib.sha256(value).hexdigest()


class CapabilityPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="capability-policy-")
        cls.root = Path(cls.temporary.name)
        cls.generated = cls.root / "generated"
        for command in (["dotnet", "build", "src/Scanner", "--verbosity", "quiet"],
                        ["dotnet", "build", "src/Parser", "--verbosity", "quiet"],
                        ["dotnet", "run", "--project", "tests/Corpus.Generate", "--", "chains", str(cls.generated)]):
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=120)
            if result.returncode:
                raise AssertionError("Original capability fixture build failed")
        cls.pak = cls.root / "fixture.pak"
        cls.pak.write_bytes(build([("Content/" + p.name, p.read_bytes(), False) for p in sorted(cls.generated.iterdir())
                                  if p.suffix in (".uasset", ".uexp")]))
        def inspector(root, inventory):
            (Path(root) / "inspection.json").write_text(json.dumps(inventory))
            result = subprocess.run(["dotnet", str(ROOT / "src/Parser/bin/Debug/net10.0/Parser.dll"),
                root, "-", "Content", "/Game", str(cls.pak)], capture_output=True, timeout=30)
            if result.returncode:
                raise AssertionError("Original capability fixture parser failed")
            cls.facts = result.stdout
        ingest(cls.pak, inspector=inspector)
        cls.rules = json.loads((ROOT / "examples/capability-rules-v1.json").read_bytes())
        cls.rules["revision"] = "private-revision-canary"
        for index, rule in enumerate(cls.rules["rules"]):
            rule["id"] = "private-rule-canary-" + str(index)
        cls.catalog = ROOT / "examples/capability-summaries-v1.json"

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def evaluate(self, rules=None, facts=None, extra=(), catalog=True, raw=None):
        with tempfile.TemporaryDirectory(prefix="case-", dir=self.root) as temporary:
            root = Path(temporary)
            (root / "facts").write_bytes(self.facts if facts is None else facts)
            rule_bytes = json.dumps(self.rules if rules is None else rules).encode() if raw is None else raw
            (root / "rules").write_bytes(rule_bytes)
            args = ["dotnet", str(ROOT / "src/Scanner/bin/Debug/net10.0/Scanner.dll"), "evaluate",
                "--facts", str(root / "facts"), "--report", "-", "--engine-version", "4.25",
                "--capability-rules", str(root / "rules"), "--capability-policy-revision", "private-revision-canary",
                "--policy-revision", "invocation-revision", "--fail-on-any-forbidden", "false",
                "--fail-on-any-flagged", "false", "--fail-on-incomplete", "false"]
            if catalog:
                args += ["--capability-summaries", str(self.catalog)]
            env = dict(os.environ, UE_PAK_POLICY_RULES=POLICY)
            result = subprocess.run([*args, *extra], env=env, capture_output=True, timeout=30)
            public = result.stdout + result.stderr
            for canary in (b"private-rule-canary", b"private-revision-canary", sha(rule_bytes).encode()):
                self.assertNotIn(canary, public)
            report = reports.load(result.stdout, ROOT, moderator_detail="--moderator-detail" in extra)
            return result, report, rule_bytes

    def test_real_parser_complete_chain_union_and_oracle(self):
        result, report, _ = self.evaluate()
        self.assertEqual(1, result.returncode)
        capability_policy_oracle(report)
        root = [w for w in report["call-chains"]["witnesses"] if w["callers"] and ":Root#" in w["callers"][0]["origin"]["function"]]
        self.assertEqual(2, len(root[0]["callers"]))
        self.assertIn(":Wrapper#", root[0]["endpoint"]["origin"]["function"])

    def test_all_verbosity_and_moderator_detail_never_disclose_capability_policy(self):
        for level in ("error", "warn", "info", "verbose"):
            for detail in ((), ("--moderator-detail",)):
                with self.subTest(level=level, detail=detail):
                    result, report, _ = self.evaluate(extra=("--log-level", level, *detail))
                    self.assertEqual(1, result.returncode)
                    capability_policy_oracle(report)
                    self.assertEqual(level == "verbose", b"invocation-canary" in result.stderr)

    def test_real_producer_accepts_flag_only_forbid_only_and_union(self):
        for effect in ("flag", "forbid", "both"):
            rules = deepcopy(self.rules)
            rules["rules"] = [r for r in rules["rules"] if effect == "both" or r["effect"] == effect]
            with self.subTest(effect=effect):
                result, report, _ = self.evaluate(rules=rules)
                self.assertEqual(1, result.returncode)
                capability = report["capability-analysis"]
                self.assertEqual(effect != "forbid", capability["possibly-flagged"])
                self.assertEqual(effect != "flag", capability["possibly-forbidden"])
                self.assertEqual("needs-review" if effect == "flag" else "reject", capability["decision"])

    def test_malformed_rules_fail_before_verbose_invocation_disclosure(self):
        for raw in (b"{private-rule-canary", b"\xff", b"{}", b"{\"schema-version\":1,\"schema-version\":1}",
                    json.dumps(dict(self.rules, unknown="private-rule-canary")).encode(), b" " * (256 * 1024 + 1)):
            with self.subTest(raw=raw[:30]):
                result, report, _ = self.evaluate(raw=raw, extra=("--log-level", "verbose"))
                self.assertEqual(2, result.returncode)
                self.assertNotIn(b"invocation-canary", result.stderr)
                self.assertEqual(["invalid-configuration"], report["diagnostics"])

    def test_missing_catalog_graph_or_summary_remains_unknown(self):
        for kind in ("catalog", "graph", "summary"):
            facts = json.loads(self.facts)
            if kind == "graph":
                facts["analysis"].pop("call-graph")
            rules = deepcopy(self.rules)
            if kind == "summary":
                for rule in rules["rules"]:
                    rule["capability"] = "unreviewed-capability"
            result, report, _ = self.evaluate(rules=rules, facts=json.dumps(facts).encode(), catalog=kind != "catalog")
            self.assertEqual(1, result.returncode)
            self.assertFalse(report["capability-analysis"]["complete"])
            self.assertTrue(report["capability-analysis"]["possibly-forbidden"])
            self.assertEqual([], report["forbidden-invocations"])

    def test_exact_caller_rule_on_serialized_identity(self):
        rules = deepcopy(self.rules)
        # Identity comes from the fixture's authored class and function, not a name heuristic.
        for rule in rules["rules"]:
            rule["caller"] = {"owner": "/Game/CallChains.BP_Corpus_C", "function": "Root", "max-depth": 2}
        result, report, _ = self.evaluate(rules=rules)
        self.assertEqual(1, result.returncode)
        self.assertEqual(1, len(report["capability-analysis"]["findings"]))
        self.assertTrue(report["capability-analysis"]["findings"][0]["forbidden"])

    def test_schema_and_shared_validator_reject_invalid_references_and_private_fields(self):
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        _, report, _ = self.evaluate()
        documents = [json.loads((ROOT / "schemas" / name).read_bytes()) for name in ("report-v1.schema.json", "facts-v1.schema.json")]
        registry = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in documents)
        Draft202012Validator(documents[0], registry=registry).validate(report)
        for key, value in (("witness", 255), ("rule-ids", ["private-rule-canary"]), ("private-policy-sha256", "a" * 64)):
            changed = deepcopy(report)
            changed["capability-analysis"]["findings"][0][key] = value
            with self.assertRaises(reports.InvalidReport):
                reports.load(json.dumps(changed).encode(), ROOT)
        changed = deepcopy(report)
        changed["capability-analysis"]["findings"].append(deepcopy(changed["capability-analysis"]["findings"][0]))
        with self.assertRaises(reports.InvalidReport):
            reports.load(json.dumps(changed).encode(), ROOT)

    def test_private_moderation_context_exact_bytes_and_feedback(self):
        result, report, rule_bytes = self.evaluate()
        rules = self.root / "moderation-rules"
        rules.write_bytes(rule_bytes)
        private = {"schema-version": 1, "kind": "capability-context", "report-sha256": sha(result.stdout),
            "policy-revision": "private-revision-canary", "catalog-sha256": sha(self.catalog.read_bytes()),
            "dependencies": [{"kind": "capability-rules", "sha256": sha(rule_bytes)}]}
        context = {"schema-version": 1, "kind": "scan-context", "scanner-identity": "git:" + "1" * 40,
            "game-build": "original-fixture-only", "report-context": report["context"], "capability-context": private}
        dependencies = [("capability-rules", rules), ("capability-summaries", self.catalog)]
        handoff = moderation.handoff(result.stdout, context, self.pak, dependencies)
        self.assertIn("policy-violation", handoff["routes"])
        approved = moderation.review(handoff, "fixture-reviewer", "approve", "Original model only")
        self.assertTrue(moderation.verify(approved, context, self.pak, dependencies, result.stdout))
        feedback = json.dumps(moderation.feedback(handoff)).encode()
        self.assertNotIn(b"private-", feedback)
        self.assertNotIn(sha(rule_bytes).encode(), feedback)
        changed = deepcopy(context)
        changed.pop("capability-context")
        with self.assertRaises(reports.InvalidReport):
            moderation.handoff(result.stdout, changed, self.pak, dependencies[:-1])
        rules.write_bytes(rule_bytes + b"\n")
        with self.assertRaises(reports.InvalidReport):
            moderation.verify(approved, context, self.pak, dependencies, result.stdout)
        rules.write_bytes(rule_bytes)
        with self.assertRaises(reports.InvalidReport):
            moderation.verify(approved, context, self.pak, dependencies, result.stdout + b"\n")
        with self.assertRaises(reports.InvalidReport):
            moderation.handoff(result.stdout, context, self.pak, dependencies[:-1])
        for kind in ("missing-catalog", "absent", "incomplete"):
            changed_report = deepcopy(report)
            if kind == "absent":
                changed_report.pop("call-chains")
            elif kind == "missing-catalog":
                changed_report["call-chains"].update({"catalog-revision": None, "catalog-sha256": None})
                changed_report["context"].pop("capability-catalog-revision")
                changed_report["context"]["dependencies"] = []
            changed_report["capability-analysis"].update({
                "complete": True, "decision": "no-match", "findings": [], "diagnostics": [],
                "possibly-flagged": False, "possibly-forbidden": False})
            changed_raw = json.dumps(changed_report).encode()
            changed_context = deepcopy(context)
            changed_context["report-context"] = changed_report["context"]
            changed_context["capability-context"]["report-sha256"] = sha(changed_raw)
            with self.subTest(kind=kind):
                with self.assertRaises(reports.InvalidReport):
                    moderation.handoff(changed_raw, changed_context, self.pak, dependencies)
                with self.assertRaises(reports.InvalidReport):
                    moderation.verify(approved, changed_context, self.pak, dependencies, changed_raw)

    def test_action_projection_has_fixed_counts_not_private_ids_or_digests(self):
        _, report, rule_bytes = self.evaluate()
        outputs = action.outputs(report, "report.json")
        self.assertEqual("3", outputs["capability-forbidden-count"])
        self.assertEqual("1", outputs["capability-possibly-forbidden-count"])
        self.assertEqual("0", outputs["forbidden-count"])
        self.assertNotIn("private-", json.dumps(outputs))
        self.assertNotIn(sha(rule_bytes), json.dumps(outputs))
        self.assertEqual("unknown", action.outputs(None, "report.json")["capability-forbidden-count"])

    def test_host_rejects_private_public_alias_before_docker_or_disclosure(self):
        with tempfile.TemporaryDirectory(prefix="aliases-", dir=self.root) as temporary:
            root = Path(temporary)
            (root / "alias").symlink_to(root, target_is_directory=True)
            with patch.object(scan, "Docker") as docker:
                code = scan.main(["scan", "--pak", str(self.pak), "--report", str(root / "report"),
                    "--engine-version", "4.25", "--capability-rules", "unused", "--capability-policy-revision", "private-v1",
                    "--capability-context", str(root / "alias/report")])
            self.assertEqual(2, code)
            docker.assert_not_called()
            self.assertFalse((root / "report").exists())


if __name__ == "__main__":
    unittest.main()
