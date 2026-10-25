"""Original serialized fixture through real Parser/evaluator; no Docker or engine."""

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

POLICY = """schema-version: 1
rules:
  - id: original-invocation-model
    description: Original illustrative fixture only
    effect: flag
    match:
      kind: invocation
      target:
        kind: exact
        owner: /Script/Fixture.Other
        function: Touch
"""

MATCHING_POLICY = POLICY.replace("original-invocation-model", "operator-rule-canary").replace(
    "effect: flag", "effect: forbid").replace("/Script/Fixture.Other", "/Script/Corpus.Sensitive").replace(
    "function: Touch", "function: Record")
DUAL_POLICY = (MATCHING_POLICY + MATCHING_POLICY.split("rules:\n", 1)[1].replace(
    "operator-rule-canary", "operator-flag-canary").replace("effect: forbid", "effect: flag")).replace(
    "Original illustrative fixture only", "operator-description-canary")


def sha(value):
    return hashlib.sha256(value).hexdigest()


class DataPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="data-integration-")
        cls.root = Path(cls.temporary.name)
        cls.generated = cls.root / "generated"
        for command in (["dotnet", "build", "src/Parser", "--verbosity", "quiet"],
                        ["dotnet", "run", "--project", "tests/Corpus.Generate", "--", "data-policy", str(cls.generated)]):
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=120)
            if result.returncode:
                raise AssertionError("Original fixture build/generation failed")
        cls.paks, cls.facts = {}, {}
        for version in ("baseline", "submission"):
            pak = cls.root / (version + ".pak")
            pak.write_bytes(build((("Content/Data.uasset", (cls.generated / version / "Data.uasset").read_bytes(), False),)))
            cls.paks[version] = pak
            def inspector(root, report):
                (Path(root) / "inspection.json").write_text(json.dumps(report))
                result = subprocess.run(["dotnet", str(ROOT / "src/Parser/bin/Debug/net10.0/Parser.dll"),
                    root, "-", "Content", "/Game", str(pak)], capture_output=True, timeout=30)
                if result.returncode:
                    raise AssertionError("Local Parser protocol failed")
                cls.facts[version] = result.stdout
            ingest(pak, inspector=inspector)
        cls.rules = json.loads((cls.generated / "data-rules.json").read_bytes())
        cls.rules["baseline"]["pak-sha256"] = sha(cls.paks["baseline"].read_bytes())
        cls.policy = cls.root / "policy.yml"
        cls.policy.write_text(POLICY)
        cls.env = dict(os.environ)
        cls.env.pop("UE_PAK_POLICY_RULES", None)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def evaluate(self, *, baseline=True, rules=None, facts=None, build_scope="original-fixture-v1", extra=(), policy=None):
        with tempfile.TemporaryDirectory(prefix="data-case-", dir=self.root) as temporary:
            root = Path(temporary)
            (root / "facts").write_bytes(self.facts["submission"] if facts is None else facts)
            (root / "rules").write_text(json.dumps(self.rules if rules is None else rules))
            (root / "policy").write_text(POLICY if policy is None else policy)
            args = ["dotnet", str(ROOT / "src/Scanner/bin/Debug/net10.0/Scanner.dll"), "evaluate", "--facts", str(root / "facts"),
                "--data-rules", str(root / "rules"), "--game-build", build_scope, "--engine-version", "4.25", "--report", "-",
                "--policy-rules", str(root / "policy"), "--policy-revision", "original-v1", "--fail-on-any-forbidden", "false",
                "--fail-on-any-flagged", "false", "--fail-on-incomplete", "false"]
            if baseline:
                (root / "baseline").write_bytes(self.facts["baseline"])
                args += ["--baseline-facts", str(root / "baseline"), "--expected-baseline-sha256", sha(self.paks["baseline"].read_bytes()),
                    "--baseline-facts-assertion", "caller-supplied-not-authenticated"]
            result = subprocess.run([*args, *extra], env=self.env, capture_output=True, timeout=30)
            self.assertNotIn(b"private-data-canary", result.stdout + result.stderr)
            self.assertNotIn(b"private-original-model", result.stdout + result.stderr)
            self.assertNotIn(sha(self.paks["baseline"].read_bytes()).encode(), result.stdout + result.stderr)
            report = reports.load(result.stdout, ROOT, moderator_detail="--moderator-detail" in extra)
            return result, report

    def test_operator_detail_profile_is_explicit_and_keeps_closed_validation(self):
        ordinary, default = self.evaluate(policy=MATCHING_POLICY)
        self.assertEqual(1, ordinary.returncode)
        self.assertNotIn(b"operator-rule-canary", ordinary.stdout + ordinary.stderr)
        result, report = self.evaluate(extra=("--moderator-detail",), policy=MATCHING_POLICY)
        self.assertEqual(1, result.returncode)
        self.assertEqual(["operator-rule-canary"], report["forbidden-invocations"][0]["rule-ids"])
        self.assertNotIn(b"operator-description-canary", result.stdout + result.stderr)
        self.assertEqual(1, report["counts"]["forbidden"])
        self.assertEqual(1, len(report["data-analysis"]["findings"]))
        self.assertEqual(default["counts"], report["counts"])
        self.assertEqual(default["data-analysis"], report["data-analysis"])
        self.assertNotIn(b"operator-rule-canary", result.stderr)
        with self.assertRaises(reports.InvalidReport):
            reports.load(result.stdout, ROOT)
        with self.assertRaises(reports.InvalidReport):
            moderation.handoff(result.stdout, {}, self.paks["submission"], [])
        for field, value in (("rule-ids", ["invalid private literal"]), ("rule-ids", ["a" * 65]),
                             ("rule-ids", []), ("rule-ids", ["valid", "valid"]),
                             ("private-condition", "private-data-canary")):
            changed = deepcopy(report)
            changed["forbidden-invocations"][0][field] = value
            with self.assertRaises(reports.InvalidReport):
                reports.load(json.dumps(changed).encode(), ROOT, moderator_detail=True)
        changed = deepcopy(report)
        changed["rule-ids"] = ["valid"]
        with self.assertRaises(reports.InvalidReport):
            reports.load(json.dumps(changed).encode(), ROOT, moderator_detail=True)

    def test_serialized_changed_destination_drives_separate_finding_with_identical_stored_bytecode(self):
        proof = json.loads((self.generated / "proof.json").read_bytes())
        self.assertTrue(proof["bytecodeUnchanged"] and proof["invocationFactsUnchanged"])
        self.assertEqual(1, proof["dataFindings"])
        before, after = (json.loads(self.facts[v]) for v in ("baseline", "submission"))
        self.assertEqual(before["analysis"], after["analysis"])
        self.assertNotEqual(before["asset-data"]["packages"][0]["evidence"]["properties"][0]["value"],
                            after["asset-data"]["packages"][0]["evidence"]["properties"][0]["value"])
        result, report = self.evaluate(extra=("--protected-path", "content", "--replacement-policy", "review"))
        self.assertEqual(1, result.returncode)
        self.assertEqual("needs-review", report["data-analysis"]["decision"])
        self.assertEqual(1, len(report["data-analysis"]["findings"]))
        self.assertTrue(report["data-analysis"]["complete"])
        self.assertEqual(1, report["counts"]["invocations"])
        self.assertEqual([], report["flagged-invocations"])
        self.assertEqual([], report["forbidden-invocations"])
        self.assertIn("protected-path-candidate", [f["diagnostic"] for f in report["content-policy"]["findings"]])
        self.assertNotIn("Destination", result.stdout.decode())

    def test_dual_effect_detail_only_varies_effect_specific_rule_ids(self):
        ordinary, default = self.evaluate(policy=DUAL_POLICY)
        result, report = self.evaluate(policy=DUAL_POLICY, extra=("--moderator-detail",))
        self.assertEqual((1, 1), (ordinary.returncode, result.returncode))
        self.assertEqual({"invocations": 1, "flagged": 1, "forbidden": 1, "affected-union": 1}, report["counts"])
        self.assertEqual(default["counts"], report["counts"])
        self.assertEqual(default["data-analysis"], report["data-analysis"])
        self.assertEqual(["operator-flag-canary"], report["flagged-invocations"][0]["rule-ids"])
        self.assertEqual(["operator-rule-canary"], report["forbidden-invocations"][0]["rule-ids"])
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        documents = [json.loads((ROOT / "schemas" / name).read_bytes()) for name in
                     ("report-v1.schema.json", "facts-v1.schema.json")]
        registry = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in documents)
        Draft202012Validator(documents[0], registry=registry).validate(report)
        for kind in ("flagged", "forbidden"):
            for ids in ([], ["valid", "valid"], ["invalid literal"], ["a" * 65], ["valid\n"], [None]):
                changed = deepcopy(report)
                changed[kind + "-invocations"][0]["rule-ids"] = ids
                with self.assertRaises(reports.InvalidReport):
                    reports.load(json.dumps(changed).encode(), ROOT, moderator_detail=True)
            changed = deepcopy(report)
            changed[kind + "-invocations"].append(deepcopy(changed[kind + "-invocations"][0]))
            changed["counts"][kind] += 1
            with self.assertRaises(reports.InvalidReport):
                reports.load(json.dumps(changed).encode(), ROOT, moderator_detail=True)
        for field, value in (("location", {"asset": "other", "function": "other", "offset": 5}),
                             ("target", {"owner": "/Script/Other.Object", "function": "Other"}),
                             ("argument-metadata", "known")):
            changed = deepcopy(report)
            changed["forbidden-invocations"][0][field] = value
            if field == "argument-metadata":
                changed["forbidden-invocations"][0]["known-argument-count"] = 0
            with self.assertRaises(reports.InvalidReport):
                reports.load(json.dumps(changed).encode(), ROOT, moderator_detail=True)
        with self.assertRaises(reports.InvalidReport):
            reports.load(result.stdout, ROOT)
        with self.assertRaises(reports.InvalidReport):
            moderation.handoff(result.stdout, {}, self.paks["submission"], [])

    def test_absent_data_is_incomplete_when_enabled(self):
        facts = json.loads(self.facts["submission"])
        del facts["asset-data"]
        result, report = self.evaluate(facts=json.dumps(facts).encode(), policy=MATCHING_POLICY)
        self.assertEqual(1, result.returncode)
        self.assertFalse(report["data-analysis"]["complete"])
        self.assertFalse(report["analysis-complete"])
        self.assertEqual(1, report["counts"]["forbidden"])

    def test_missing_baseline_cannot_pass_even_when_all_invocation_gates_are_off(self):
        result, report = self.evaluate(baseline=False)
        self.assertEqual(1, result.returncode)
        self.assertFalse(report["data-analysis"]["complete"])
        self.assertIn("data-baseline-unavailable", report["data-analysis"]["diagnostics"])
        self.assertFalse(report["analysis-complete"])

    def test_wrong_build_or_declared_baseline_is_configuration_error(self):
        result, report = self.evaluate(build_scope="wrong-build")
        self.assertEqual(2, result.returncode)
        self.assertEqual(["invalid-configuration"], report["diagnostics"])
        rules = deepcopy(self.rules)
        rules["baseline"]["pak-sha256"] = "0" * 64
        result, _ = self.evaluate(rules=rules)
        self.assertEqual(2, result.returncode)

    def test_host_snapshots_original_baseline_in_its_own_policy_free_parser_and_private_context(self):
        result, report = self.evaluate()
        calls = []
        class Docker:
            def __init__(self, *args):
                pass
            def run(_, mounts, entry, arguments, **options):
                calls.append((list(mounts), list(arguments), options))
                if "validate" in arguments:
                    return 0, b""
                if options.get("parser"):
                    # Independently staged baseline first, then submission.
                    return 0, self.facts["baseline" if len(calls) == 2 else "submission"]
                return result.returncode, result.stdout
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            root = Path(temporary)
            rules = root / "rules"
            rules.write_text(json.dumps(self.rules))
            with patch.object(scan, "Docker", Docker):
                code = scan.main(["scan", "--pak", str(self.paks["submission"]), "--baseline-pak", str(self.paks["baseline"]),
                    "--data-rules", str(rules), "--data-context", str(root / "private-context"), "--game-build", "original-fixture-v1",
                    "--content-root", "Content=/Game", "--engine-version", "4.25", "--report", str(root / "report")])
            self.assertEqual(1, code)
            private = json.loads((root / "private-context").read_bytes())
            self.assertEqual(sha(result.stdout), private["report-sha256"])
            self.assertEqual(0o600, (root / "private-context").stat().st_mode & 0o777)
            for index in (1, 2):
                mounts, arguments, options = calls[index]
                self.assertTrue(options["parser"])
                self.assertNotIn("data-rules", " ".join(mounts + arguments))
                self.assertNotIn("game-build", " ".join(arguments))
                self.assertNotIn("/policy", " ".join(mounts))
                self.assertEqual(1, sum("target=/input/submission" in m for m in mounts))
            self.assertIn("--expected-baseline-sha256", calls[3][1])
            self.assertNotIn("target=/input/submission", " ".join(calls[3][0]))

    def test_private_dependencies_and_exact_report_bytes_invalidate_moderation_approval(self):
        result, report = self.evaluate()
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            root = Path(temporary)
            rules = root / "rules"
            rules.write_text(json.dumps(self.rules))
            dependencies = [("data-rules", rules), ("baseline-pak", self.paks["baseline"])]
            private = {"schema-version": 1, "kind": "data-context", "report-sha256": sha(result.stdout), "engine-version": "4.25",
                "game-build": "original-fixture-v1", "content-root": "Content", "logical-root": "/Game", "mount-policy": "submission-over-baseline",
                "dependencies": sorted([{"kind": k, "sha256": sha(p.read_bytes())} for k, p in dependencies], key=lambda d: d["kind"])}
            context = {"schema-version": 1, "kind": "scan-context", "scanner-identity": "git:" + "a" * 40,
                "game-build": "original-fixture-v1", "report-context": report["context"], "data-context": private}
            handoff = moderation.handoff(result.stdout, context, self.paks["submission"], dependencies)
            self.assertIn("needs-review", handoff["routes"])
            review = moderation.review(handoff, "original-operator", "approve", "Reviewed original fixture")
            self.assertTrue(moderation.verify(review, context, self.paks["submission"], dependencies, result.stdout))
            public = json.dumps(moderation.feedback(handoff))
            for private_value in ("data-rules", "report-sha256", "private-original-model", "private-data-canary", private["dependencies"][0]["sha256"]):
                self.assertNotIn(private_value, public)
            changed = deepcopy(context)
            changed["data-context"]["logical-root"] = "/Other"
            with self.assertRaises(reports.InvalidReport):
                moderation.verify(review, changed, self.paks["submission"], dependencies, result.stdout)
            rules.write_bytes(b"changed private data policy")
            with self.assertRaises(reports.InvalidReport):
                moderation.verify(review, context, self.paks["submission"], dependencies, result.stdout)

    def test_action_only_exports_fixed_data_counts_not_findings_or_private_context(self):
        result, report = self.evaluate()
        outputs = action.outputs(report, "report.json")
        self.assertEqual("complete", outputs["data-analysis-status"])
        self.assertEqual("1", outputs["data-review-count"])
        self.assertEqual("0", outputs["data-reject-count"])
        self.assertNotIn("private-data-canary", json.dumps(outputs))
        self.assertNotIn("Destination", json.dumps(outputs))
        self.assertNotIn("data-findings", outputs)
        self.assertEqual("[]", outputs["forbidden-invocations"])

    def test_schema_and_semantic_mutations_fail_closed(self):
        result, report = self.evaluate()
        mutations = []
        for key, value in (("complete", False), ("decision", "no-match"), ("extra", True)):
            changed = deepcopy(report)
            changed["data-analysis"][key] = value
            mutations.append(changed)
        changed = deepcopy(report)
        changed["data-analysis"]["findings"][0]["value"] = "private-data-canary"
        mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(reports.InvalidReport):
                reports.load(json.dumps(changed).encode(), ROOT)

    def test_all_data_schemas_accept_real_closed_parser_and_policy_documents(self):
        documents = {name: json.loads((ROOT / "schemas" / name).read_bytes()) for name in
            ("facts-v1.schema.json", "data-rules-v1.schema.json", "report-v1.schema.json")}
        for document in documents.values():
            reports.check_schema(document)
        for raw in self.facts.values():
            reports.validate(json.loads(raw), documents["facts-v1.schema.json"], documents["facts-v1.schema.json"], documents)
        reports.validate(self.rules, documents["data-rules-v1.schema.json"], documents["data-rules-v1.schema.json"], documents)
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        registry = Registry().with_resources(("https://data-fixture/" + name, Resource.from_contents(document))
                                             for name, document in documents.items())
        for name, value in (("facts-v1.schema.json", json.loads(self.facts["submission"])), ("data-rules-v1.schema.json", self.rules)):
            schema = {"$ref": "https://data-fixture/" + name}
            # Relative references use each schema's declared canonical base URI.
            canonical = Registry().with_resources((document.get("$id", "https://data-fixture/" + key), Resource.from_contents(document))
                                                   for key, document in documents.items())
            registry = registry.combine(canonical)
            Draft202012Validator(schema, registry=registry).validate(value)

    def test_real_parser_global_data_bounds_preserve_later_invocations_and_inventory(self):
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            root = Path(temporary)
            generated = root / "packages"
            result = subprocess.run(["dotnet", str(ROOT / "tests/Corpus.Generate/bin/Debug/net10.0/Corpus.Generate.dll"),
                "data-budgets", str(generated)], capture_output=True, timeout=60)
            self.assertEqual(0, result.returncode)
            packages = sorted(generated.glob("*.uasset"))
            pak = root / "budget.pak"
            pak.write_bytes(build(tuple(("Content/" + p.name, p.read_bytes(), False) for p in packages)))
            observed = []
            def inspect(directory, manifest):
                (Path(directory) / "inspection.json").write_text(json.dumps(manifest))
                parsed = subprocess.run(["dotnet", str(ROOT / "src/Parser/bin/Debug/net10.0/Parser.dll"),
                    directory, "-", "Content", "/Game", str(pak)], capture_output=True, timeout=60)
                self.assertEqual(0, parsed.returncode)
                observed.append(json.loads(parsed.stdout))
            ingest(pak, inspector=inspect)
            facts = observed[0]
            self.assertEqual(6, len(facts["inspection"]["members"]))
            self.assertEqual(6, len(facts["analysis"]["invocations"]))
            self.assertTrue(any("/Game/Later" in f["location"]["asset"] for f in facts["analysis"]["invocations"]))
            self.assertFalse(facts["asset-data"]["complete"])
            properties = [p for package in facts["asset-data"]["packages"] for p in package["evidence"]["properties"]]
            self.assertGreater(len(properties), 0)
            self.assertLessEqual(len(properties), 4096)
            self.assertEqual({"kind": "integer", "value": 0, "type": "int32"}, properties[0]["value"])

    def test_real_parser_minimal_marker_cannot_displace_near_limit_mandatory_evidence(self):
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            root = Path(temporary)
            generated = root / "packages"
            result = subprocess.run(["dotnet", str(ROOT / "tests/Corpus.Generate/bin/Debug/net10.0/Corpus.Generate.dll"),
                "data-marker-budget", str(generated)], capture_output=True, timeout=60)
            self.assertEqual(0, result.returncode)
            pak = root / "submission.pak"
            pak.write_bytes(build((("Content/Data.uasset", (generated / "Data.uasset").read_bytes(), False),)))
            observed = []
            def inspect(directory, manifest):
                (Path(directory) / "inspection.json").write_text(json.dumps(manifest))
                parsed = subprocess.run(["dotnet", str(ROOT / "src/Parser/bin/Debug/net10.0/Parser.dll"),
                    directory, "-", "Content", "/Game", str(pak)], capture_output=True, timeout=60)
                self.assertEqual(0, parsed.returncode)
                observed.append(parsed.stdout)
            ingest(pak, inspector=inspect)
            raw = observed[0]
            facts = json.loads(raw)
            def tokens(value):
                if isinstance(value, dict):
                    return 2 + sum(1 + tokens(v) for v in value.values())
                if isinstance(value, list):
                    return 2 + sum(tokens(v) for v in value)
                return 1
            self.assertEqual(199994, tokens(facts))
            self.assertLess(len(raw), 8 * 1024 * 1024)
            self.assertEqual(7996, len(facts["analysis"]["invocations"]))
            self.assertEqual(sha(pak.read_bytes()), facts["pak-sha256"])
            self.assertEqual(1, len(facts["inspection"]["members"]))
            self.assertNotIn("asset-data", facts)
            self.assertFalse(facts["analysis"]["call-graph"]["complete"])
            enabled, report = self.evaluate(facts=raw, policy=MATCHING_POLICY)
            self.assertEqual(1, enabled.returncode)
            self.assertEqual(7996, report["counts"]["forbidden"])
            self.assertFalse(report["data-analysis"]["complete"])
            self.assertIn("data-evidence-incomplete", report["data-analysis"]["diagnostics"])
            self.assertLessEqual(len(report["data-analysis"]["diagnostics"]), 64)
            (root / "facts").write_bytes(raw)
            (root / "policy").write_text(MATCHING_POLICY)
            disabled = subprocess.run(["dotnet", str(ROOT / "src/Scanner/bin/Debug/net10.0/Scanner.dll"), "evaluate",
                "--facts", str(root / "facts"), "--policy-rules", str(root / "policy"), "--report", "-",
                "--engine-version", "4.25", "--fail-on-any-forbidden", "false", "--fail-on-incomplete", "false"],
                env=self.env, capture_output=True, timeout=60)
            self.assertEqual(0, disabled.returncode)
            legacy = reports.load(disabled.stdout, ROOT)
            self.assertNotIn("data-analysis", legacy)
            self.assertEqual(report["counts"], legacy["counts"])
            self.assertEqual(report["forbidden-invocations"], legacy["forbidden-invocations"])
            self.assertEqual(report["coverage"], legacy["coverage"])

    @unittest.skipUnless(os.environ.get("UE_PAK_CONTAINER_TEST_IMAGE"), "requires explicitly authorized local Docker image")
    def test_actual_isolated_host_and_action_parity(self):
        image = os.environ["UE_PAK_CONTAINER_TEST_IMAGE"]
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            root = Path(temporary)
            rules = root / "rules"
            rules.write_text(json.dumps(self.rules))
            policy = root / "policy"
            policy.write_text(DUAL_POLICY)
            common = ["--pak", str(self.paks["submission"]), "--baseline-pak", str(self.paks["baseline"]),
                "--data-rules", str(rules), "--game-build", "original-fixture-v1", "--content-root", "Content=/Game",
                "--policy-rules", str(policy), "--engine-version", "4.25", "--policy-revision", "original-v1",
                 "--fail-on-any-forbidden", "false", "--fail-on-any-flagged", "false", "--fail-on-incomplete", "false"]
            (root / "child").mkdir()
            (root / "alias").symlink_to(root, target_is_directory=True)
            ordinary = root / "alias-report"
            for context in (ordinary, root / "child/../alias-report", root / "alias/alias-report"):
                with self.subTest(alias=str(context)):
                    rejected = subprocess.run([sys.executable, str(ROOT / "scripts/scan.py"), "scan", *common,
                        "--image", image, "--log-level", "verbose", "--report", str(ordinary),
                        "--data-context", str(context)], env=self.env, capture_output=True, timeout=30)
                    self.assertEqual(2, rejected.returncode)
                    self.assertEqual(b"", rejected.stdout)
                    self.assertEqual(b"Scan failed.\n", rejected.stderr)
                    self.assertFalse(ordinary.exists())
                    self.assertFalse(context.exists())
            host = subprocess.run([sys.executable, str(ROOT / "scripts/scan.py"), "scan", *common, "--image", image,
                "--report", str(root / "host-report"), "--data-context", str(root / "host-private")], env=self.env, capture_output=True, timeout=240)
            self.assertEqual(1, host.returncode)
            report = reports.load((root / "host-report").read_bytes(), ROOT)
            self.assertEqual("needs-review", report["data-analysis"]["decision"])
            self.assertEqual(1, report["counts"]["forbidden"])
            self.assertEqual(1, report["counts"]["flagged"])
            self.assertEqual(1, report["counts"]["affected-union"])
            detailed = subprocess.run([sys.executable, str(ROOT / "scripts/scan.py"), "scan", *common, "--image", image,
                "--moderator-detail", "--report", str(root / "detail-report"), "--data-context", str(root / "detail-private")],
                env=self.env, capture_output=True, timeout=240)
            self.assertEqual(1, detailed.returncode)
            detailed_bytes = (root / "detail-report").read_bytes()
            detail = reports.load(detailed_bytes, ROOT, moderator_detail=True)
            self.assertEqual(report["counts"], detail["counts"])
            self.assertEqual(report["data-analysis"], detail["data-analysis"])
            self.assertEqual(["operator-rule-canary"], detail["forbidden-invocations"][0]["rule-ids"])
            self.assertEqual(["operator-flag-canary"], detail["flagged-invocations"][0]["rule-ids"])
            with self.assertRaises(reports.InvalidReport):
                reports.load(detailed_bytes, ROOT)
            with self.assertRaises(reports.InvalidReport):
                moderation.handoff(detailed_bytes, {}, self.paks["submission"], [])
            for name in ("host", "detail"):
                private = json.loads((root / (name + "-private")).read_bytes())
                self.assertEqual(sha((root / (name + "-report")).read_bytes()), private["report-sha256"])
                self.assertEqual(0o600, (root / (name + "-private")).stat().st_mode & 0o777)
            config = root / "docker"
            config.mkdir()
            identity = scan.Docker(config, image, 60).image
            output, summary = root / "outputs", root / "summary"
            output.touch(); summary.touch()
            env = dict(self.env, GITHUB_WORKSPACE=str(root), GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary),
                UE_PAK_ACTION_IMAGE=identity, INPUT_PAK=str(self.paks["submission"]), INPUT_BASELINE_PAK=str(self.paks["baseline"]),
                INPUT_DATA_RULES=str(rules), INPUT_GAME_BUILD="original-fixture-v1", INPUT_CONTENT_ROOT="Content=/Game",
                INPUT_POLICY_RULES=str(policy), INPUT_REPORT="action-report", INPUT_DATA_CONTEXT="action-private",
                INPUT_MODERATOR_DETAIL="true",
                 INPUT_FAIL_ON_ANY_FORBIDDEN="false", INPUT_FAIL_ON_ANY_FLAGGED="false", INPUT_FAIL_ON_INCOMPLETE="false")
            for context in ("action-alias-report", "alias/action-alias-report"):
                with self.subTest(action_alias=context):
                    alias_output, alias_summary = root / "alias-outputs", root / "alias-summary"
                    alias_output.write_bytes(b""); alias_summary.write_bytes(b"")
                    rejected = subprocess.run([sys.executable, str(ROOT / "scripts/action.py"), "scan"],
                        env=dict(env, INPUT_REPORT="action-alias-report", INPUT_DATA_CONTEXT=context,
                                 INPUT_LOG_LEVEL="verbose", GITHUB_OUTPUT=str(alias_output), GITHUB_STEP_SUMMARY=str(alias_summary)),
                        capture_output=True, timeout=30)
                    self.assertEqual(2, rejected.returncode)
                    self.assertFalse((root / "action-alias-report").exists())
                    self.assertFalse((root / context).exists())
                    self.assertIn("report-available=false", alias_output.read_text())
                    for data in (rejected.stdout + rejected.stderr, alias_output.read_bytes(), alias_summary.read_bytes()):
                        for secret in (b"operator-rule-canary", b"operator-flag-canary", b"private-data-canary",
                                       sha(self.paks["baseline"].read_bytes()).encode(), sha(rules.read_bytes()).encode()):
                            self.assertNotIn(secret, data)
            actual = subprocess.run([sys.executable, str(ROOT / "scripts/action.py"), "scan"], env=env, capture_output=True, timeout=240)
            self.assertEqual(1, actual.returncode)
            adapted = reports.load((root / "action-report").read_bytes(), ROOT)
            self.assertEqual(report["data-analysis"], adapted["data-analysis"])
            self.assertEqual(report["counts"], adapted["counts"])
            self.assertEqual(sha((root / "action-report").read_bytes()),
                json.loads((root / "action-private").read_bytes())["report-sha256"])
            self.assertIn("forbidden-count=1", output.read_text())
            self.assertIn("data-review-count=1", output.read_text())
            for data in (host.stdout + host.stderr, detailed.stdout + detailed.stderr, actual.stdout + actual.stderr,
                         output.read_bytes(), summary.read_bytes(), (root / "host-report").read_bytes(),
                         (root / "action-report").read_bytes()):
                self.assertNotIn(b"operator-rule-canary", data)
                self.assertNotIn(b"operator-flag-canary", data)
                self.assertNotIn(b"private-data-canary", data)
                self.assertNotIn(b"private-original-model", data)
                self.assertNotIn(sha(self.paks["baseline"].read_bytes()).encode(), data)
            self.assertTrue((root / "action-private").is_file())
            for private_value in (b"private-data-canary", b"private-original-model", b"Destination",
                                   b"operator-description-canary", sha(self.paks["baseline"].read_bytes()).encode()):
                self.assertNotIn(private_value, detailed_bytes)


if __name__ == "__main__":
    unittest.main()
