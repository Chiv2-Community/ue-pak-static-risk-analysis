"""Owned-byte moderation handoff and actual CLI boundary; no Docker or game data."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from indirect_fixture import dispatch, callback_dispatches, invalid_callback_dispatches

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    Draft202012Validator = None

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import moderation as mod
import report_validation as reports

CANARY = "private-rule-description-predicate-policy-canary"


def encoded(value):
    return json.dumps(value).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ModerationTests(unittest.TestCase):
    def test_callback_relations_require_unique_retained_binding_evidence_at_handoff(self):
        report = self.report(incomplete=True)
        report["coverage"]["gaps"] = ["unresolved-dispatch"]
        for opcode in ("EX_BindDelegate", "EX_InstanceDelegate"):
            report["possible-dispatches"] = callback_dispatches(opcode)
            self.assertEqual(["analysis-incomplete"], mod.handoff(
                encoded(report), self.context, self.pak, self.dependencies)["routes"])
        for name, items in invalid_callback_dispatches():
            with self.subTest(case=name):
                report["possible-dispatches"] = items
                with self.assertRaises(reports.InvalidReport):
                    mod.handoff(encoded(report), self.context, self.pak, self.dependencies)

    def test_reordered_duplicate_dispatch_origin_rejected_at_handoff(self):
        report = self.report(incomplete=True)
        report["coverage"]["gaps"] = ["unresolved-dispatch"]
        first, second = dispatch(), dispatch()
        second["origin"] = dict(reversed(list(second["origin"].items())))
        report["possible-dispatches"] = [
            {"evidence": evidence, "possibly-flagged": False, "possibly-forbidden": True}
            for evidence in (first, second)]
        single = deepcopy(report)
        single["possible-dispatches"] = [single["possible-dispatches"][1]]
        self.assertEqual(["analysis-incomplete"], mod.handoff(
            encoded(single), self.context, self.pak, self.dependencies)["routes"])
        with self.assertRaises(reports.InvalidReport):
            mod.handoff(encoded(report), self.context, self.pak, self.dependencies)

    def test_possible_callbacks_route_incomplete_and_exact_evidence_changes_invalidate_review(self):
        report = self.report(incomplete=True)
        report["coverage"]["gaps"] = ["unresolved-dispatch"]
        report["possible-dispatches"] = [{"evidence": dispatch(), "possibly-flagged": False, "possibly-forbidden": True}]
        raw = encoded(report)
        value = mod.handoff(raw, self.context, self.pak, self.dependencies)
        self.assertEqual(["analysis-incomplete"], value["routes"])
        review = self.review(value)
        self.assertTrue(mod.verify(review, self.context, self.pak, self.dependencies, raw))
        report["possible-dispatches"][0]["evidence"]["receiver"] = "object"
        with self.assertRaises(reports.InvalidReport):
            mod.verify(review, self.context, self.pak, self.dependencies, encoded(report))
        for key, replacement in (("diagnostics", ["binding-flow-unresolved"]), ("schema-version", 2),
                                 ("opcode", "EX_FinalFunction")):
            changed = json.loads(raw)
            changed["possible-dispatches"][0]["evidence"][key] = replacement
            with self.assertRaises(reports.InvalidReport):
                reports.load(encoded(changed), ROOT)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="moderation-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.pak = self.root / "mutable-release-url.pak"
        self.pak.write_bytes(b"owned original pak bytes")
        self.mapping = self.root / "mapping"
        self.mapping.write_bytes(b"owned mapping bytes")
        self.dependencies = [("mapping", self.mapping)]
        self.context = {"schema-version": 1, "kind": "scan-context", "scanner-identity": "git:" + "a" * 40,
                        "game-build": "caller-assigned-test-build", "report-context": {
                            "tool-version": "1.0.0.0", "engine-version": "4.25", "pak-sha256": sha(self.pak.read_bytes()),
                            "producer-version": "owned-test-v1", "policy-revision": "d17eb2b6-9029-44c8-9858-b4fe90abf617",
                            "dependencies": [{"kind": "mapping", "sha256": sha(self.mapping.read_bytes())}]}}
        self.report_data = encoded(self.report())

    def report(self, *, flag=False, forbid=False, incomplete=False, failed=False):
        finding = {"id": "1" * 64, "location": {"asset": "/Game/Owned", "function": "Run", "offset": 0},
                   "target": None, "argument-metadata": "unavailable", "known-argument-count": None}
        return {"schema-version": 1, "status": "failed" if failed else "partial" if incomplete else "successful",
                "analysis-complete": not (incomplete or failed), "context": deepcopy(self.context["report-context"]),
                "counts": {"invocations": int(flag or forbid), "flagged": int(flag), "forbidden": int(forbid),
                           "affected-union": int(flag or forbid)},
                "coverage": {"gaps": ["incomplete-extraction"] if incomplete else [], "evaluation-incomplete": failed},
                "flagged-invocations": [deepcopy(finding)] if flag else [],
                "forbidden-invocations": [deepcopy(finding)] if forbid else [],
                "diagnostics": ["parser-failed"] if failed else []}

    def handoff(self, **kwargs):
        return mod.handoff(encoded(self.report(**kwargs)), self.context, self.pak, self.dependencies)

    def review(self, value=None, decision="approve"):
        return mod.review(self.handoff() if value is None else value, "moderator-7", decision, CANARY,
                          datetime(2026, 10, 25, 12, 30, tzinfo=timezone.utc))

    def write(self, name, value):
        path = self.root / name
        path.write_bytes(encoded(value))
        return path

    def invoke(self, *arguments):
        return subprocess.run([sys.executable, str(ROOT / "scripts/moderation.py"), *map(str, arguments)],
                              capture_output=True, timeout=10)

    def test_routes_are_independent_and_keep_mixed_findings(self):
        cases = json.loads((ROOT / "examples/moderation/routes.json").read_bytes())
        for case in cases:
            options, expected = case["input"], case["routes"]
            with self.subTest(options=options):
                value = self.handoff(**options)
                self.assertEqual(expected, value["routes"])
                self.assertNotIn("decision", value)
                self.assertEqual(int(options.get("flag", False)), value["counts"]["flagged"])
                self.assertEqual(int(options.get("forbid", False)), value["counts"]["forbidden"])

    def test_shipped_owned_fixture_matches_exact_bytes(self):
        example = ROOT / "examples/moderation"
        context = mod.load(example / "context.json", "context")
        value = mod.handoff((example / "report.json").read_bytes(), context, example / "submission.txt",
                            [("mapping", example / "mapping.txt")])
        self.assertEqual(["qualified-completed"], value["routes"])
        self.assertTrue(mod.verify(self.review(value), context, example / "submission.txt",
                                    [("mapping", example / "mapping.txt")], (example / "report.json").read_bytes()))

    def test_content_results_use_shared_schema_routes_and_exact_report_binding(self):
        for decision, route in (("allow", "qualified-completed"), ("needs-review", "needs-review"),
                                ("reject", "policy-violation")):
            report = self.report()
            report["content-policy"] = {"schema-version": 1, "decision": decision, "incomplete": False,
                                        "findings": [{"member-id": "r00000000", "diagnostic": "protected-path-candidate"}]}
            data = encoded(report)
            self.assertEqual(report, reports.load(data, ROOT))
            value = mod.handoff(data, self.context, self.pak, self.dependencies)
            self.assertEqual([route], value["routes"])
            self.assertEqual(sha(data), value["report-sha256"])
            self.assertTrue(mod.verify(self.review(value), self.context, self.pak, self.dependencies, data))
            self.assertEqual(report["content-policy"], mod.feedback(value)["content-policy"])

    def test_content_incompleteness_is_not_a_fake_invocation_or_rule(self):
        report = self.report()
        report.update({"status": "partial", "analysis-complete": False,
                       "content-policy": {"schema-version": 1, "decision": "allow", "incomplete": True,
                                          "findings": [{"member-id": "inventory", "diagnostic": "inventory-unavailable"}]}})
        value = mod.handoff(encoded(report), self.context, self.pak, self.dependencies)
        self.assertEqual(["analysis-incomplete"], value["routes"])
        self.assertEqual(0, value["counts"]["invocations"])
        report["analysis-complete"] = True
        report["status"] = "successful"
        with self.assertRaises(reports.InvalidReport):
            reports.load(encoded(report), ROOT)

    def test_content_result_contract_is_closed_and_does_not_accept_policy_literals(self):
        for mutation in ({"schema-version": 2}, {"decision": "approve"}, {"allowed-paths": [CANARY]},
                         {"findings": [{"member-id": "r00000000", "diagnostic": CANARY}]}):
            report = self.report()
            report["content-policy"] = {"schema-version": 1, "decision": "allow", "incomplete": False,
                                        "findings": [], **mutation}
            with self.assertRaises(reports.InvalidReport):
                reports.load(encoded(report), ROOT)

    @unittest.skipIf(Draft202012Validator is None, "optional jsonschema/referencing unavailable")
    def test_shipped_owned_fixture_full_schema(self):
        example = ROOT / "examples/moderation"
        context = mod.load(example / "context.json", "context")
        value = mod.handoff((example / "report.json").read_bytes(), context, example / "submission.txt",
                            [("mapping", example / "mapping.txt")])
        documents = {name: json.loads((ROOT / "schemas" / name).read_bytes()) for name in
                     ("moderation-v1.schema.json", "report-v1.schema.json", "facts-v1.schema.json")}
        registry = Registry().with_resources((document["$id"], Resource.from_contents(document))
                                              for document in documents.values())
        validator = Draft202012Validator(documents["moderation-v1.schema.json"], registry=registry)
        for record in (context, value, self.review(value), mod.feedback(value)):
            validator.validate(record)

    def test_explicit_human_decisions_scope_context_and_time(self):
        for decision, expected in (("approve", True), ("reject", False), ("request-review", False)):
            record = self.review(decision=decision)
            self.assertEqual("2026-10-25T12:30:00Z", record["time"])
            self.assertEqual("moderator-7", record["actor"])
            self.assertEqual(CANARY, record["rationale"])
            self.assertEqual(expected, mod.verify(record, self.context, self.pak, self.dependencies, self.report_data))

    def test_operational_failure_never_approved_even_without_report_identity(self):
        report = self.report(failed=True)
        report["context"].update({"pak-sha256": None, "producer-version": None, "dependencies": []})
        report["context"].pop("policy-revision")
        value = mod.handoff(encoded(report), self.context, self.pak, self.dependencies)
        self.assertEqual(["operational-failed"], value["routes"])
        with self.assertRaises(ValueError):
            self.review(value)
        self.assertFalse(mod.verify(self.review(value, "reject"), self.context, self.pak, self.dependencies, encoded(report)))

    def test_replacement_at_same_url_invalidates_approval(self):
        approval = self.review()
        self.pak.write_bytes(b"replacement upload at same URL")
        with self.assertRaises(ValueError):
            mod.verify(approval, self.context, self.pak, self.dependencies, self.report_data)
        changed = deepcopy(self.context)
        changed["report-context"]["pak-sha256"] = sha(self.pak.read_bytes())
        with self.assertRaises(ValueError):
            mod.verify(approval, changed, self.pak, self.dependencies, self.report_data)

    def test_renamed_identical_bytes_remain_identical(self):
        approval = self.review()
        renamed = self.root / "different-url.pak"
        renamed.write_bytes(self.pak.read_bytes())
        self.assertTrue(mod.verify(approval, self.context, renamed, self.dependencies, self.report_data))

    def test_all_context_changes_invalidate_approval(self):
        approval = self.review()
        changes = [("game-build", "other-game"), ("scanner-identity", "sha256:" + "b" * 64),
                   ("tool-version", "1.0.0.1"), ("engine-version", "4.26"),
                   ("producer-version", "other-producer"), ("policy-revision", "arbitrary-new-external-id")]
        for key, value in changes:
            with self.subTest(key=key):
                changed = deepcopy(self.context)
                target = changed if key in changed else changed["report-context"]
                target[key] = value
                with self.assertRaises(ValueError):
                    mod.verify(approval, changed, self.pak, self.dependencies, self.report_data)

    def test_report_must_match_every_trusted_context_field(self):
        for key in self.context["report-context"]:
            with self.subTest(key=key):
                report = self.report()
                report["context"][key] = [] if key == "dependencies" else "mismatch"
                with self.assertRaises(ValueError):
                    mod.handoff(encoded(report), self.context, self.pak, self.dependencies)

    def test_exact_report_bytes_bind_findings_coverage_and_serialization(self):
        original = self.report(forbid=True, incomplete=True)
        original_data = encoded(original)
        value = mod.handoff(original_data, self.context, self.pak, self.dependencies)
        approval = self.review(value)
        self.assertEqual(sha(original_data), value["report-sha256"])
        variants = [original_data + b"\n"]
        for key, replacement in (("id", "2" * 64),
                                 ("location", {"asset": "/Game/Other", "function": "Other", "offset": 42}),
                                 ("target", {"owner": "/Script/Owned.Actor", "function": "OtherCall"})):
            changed = deepcopy(original)
            changed["forbidden-invocations"][0][key] = replacement
            variants.append(encoded(changed))
        changed = deepcopy(original)
        changed["coverage"]["gaps"] = ["unsupported-parsing"]
        variants.append(encoded(changed))
        for data in variants:
            with self.subTest(data=data):
                other = mod.handoff(data, self.context, self.pak, self.dependencies)
                self.assertEqual(value["counts"], other["counts"])
                self.assertNotEqual(value["report-sha256"], other["report-sha256"])
                self.assertNotEqual(approval, self.review(other))
                with self.assertRaises(ValueError):
                    mod.verify(approval, self.context, self.pak, self.dependencies, data)
        # A report hash is not enough: compare the complete reviewed handoff.
        tampered = deepcopy(approval)
        tampered["handoff"]["counts"]["invocations"] += 1
        with self.assertRaises(ValueError):
            mod.verify(tampered, self.context, self.pak, self.dependencies, original_data)

    def test_dependency_missing_extra_duplicate_and_tampered_bytes(self):
        approval = self.review()
        for dependencies in ([], self.dependencies * 2, [("other", self.mapping)]):
            with self.subTest(dependencies=dependencies), self.assertRaises(ValueError):
                mod.verify(approval, self.context, self.pak, dependencies, self.report_data)
        self.mapping.write_bytes(b"different mapping")
        with self.assertRaises(ValueError):
            mod.verify(approval, self.context, self.pak, self.dependencies, self.report_data)
        changed = deepcopy(self.context)
        changed["report-context"]["dependencies"][0]["sha256"] = sha(self.mapping.read_bytes())
        with self.assertRaises(ValueError):
            mod.verify(approval, changed, self.pak, self.dependencies, self.report_data)

    def test_dependency_argument_order_not_identity_but_stored_context_is_canonical(self):
        extra = self.root / "baseline"
        extra.write_bytes(b"owned baseline")
        self.context["report-context"]["dependencies"].insert(0, {"kind": "baseline", "sha256": sha(extra.read_bytes())})
        self.dependencies.append(("baseline", extra))
        report = self.report()
        report["context"]["dependencies"].reverse()
        value = mod.handoff(encoded(report), self.context, self.pak, self.dependencies)
        self.assertTrue(mod.verify(self.review(value), self.context, self.pak, list(reversed(self.dependencies)), encoded(report)))
        self.context["report-context"]["dependencies"].reverse()
        with self.assertRaises(ValueError):
            mod.validate(self.context, "context")

    def test_private_ids_and_raw_policy_not_public_feedback(self):
        value = self.handoff(flag=True, forbid=True, incomplete=True)
        value["context"]["report-context"]["policy-revision"] = CANARY
        public = mod.feedback(value)
        self.assertNotIn(CANARY, json.dumps(public))
        self.assertNotIn("context", public)
        self.assertNotIn("report-sha256", public)
        self.assertNotIn(value["report-sha256"], json.dumps(public))
        self.assertEqual(["policy-violation", "needs-review", "analysis-incomplete"], public["routes"])
        report = self.report(forbid=True)
        report["forbidden-invocations"][0]["rule-ids"] = [CANARY]
        with self.assertRaises(ValueError):
            mod.handoff(encoded(report), self.context, self.pak, self.dependencies)

    def test_policy_revisions_are_opaque_and_never_content_derived(self):
        for revision in ("random-caller-id", "ed9862fd-b67c-49ed-8d12-32f90a719240", "not-a-policy-hash"):
            self.context["report-context"]["policy-revision"] = revision
            self.assertEqual(revision, self.handoff()["context"]["report-context"]["policy-revision"])
        del self.context["report-context"]["policy-revision"]
        with self.assertRaises(ValueError):
            self.handoff()

    def test_malformed_report_batch_never_becomes_clean(self):
        good = self.report(forbid=True)
        variants = [b"[" + encoded(good) + b"]", b"{}", b"null", b"{", b"\xff",
                    encoded(good) + b"{}", encoded(good).replace(b'"schema-version": 1', b'"schema-version": 1,"schema-version": 1'),
                    encoded(good).replace(b'"successful"', b'"Successful"')]
        for key, value in (("extra", CANARY), ("counts", {}), ("analysis-complete", False), ("schema-version", True)):
            report = deepcopy(good)
            report[key] = value
            variants.append(encoded(report))
        for data in variants:
            with self.subTest(data=data[:80]), self.assertRaises((ValueError, TypeError)):
                mod.handoff(data, self.context, self.pak, self.dependencies)

    def test_malformed_handoff_review_and_context_rejected(self):
        for profile, original in (("handoff", self.handoff()), ("review", self.review()), ("context", self.context)):
            for key, replacement in (("extra", CANARY), ("schema-version", True), ("kind", "alias")):
                value = deepcopy(original)
                value[key] = replacement
                with self.subTest(profile=profile, key=key), self.assertRaises(ValueError):
                    mod.validate(value, profile)
        for replacement in (None, "A" * 64, "a" * 63, "a" * 64 + "\n"):
            value = self.handoff()
            value["report-sha256"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                mod.validate(value, "handoff")
        value = self.handoff()
        del value["report-sha256"]
        with self.assertRaises(ValueError):
            mod.validate(value, "handoff")
        for key, replacement in (("actor", ""), ("actor", "actor\n::error::"), ("rationale", " "),
                                 ("actor", "bad\udcff"), ("rationale", "bad\udcff"),
                                 ("time", "2026-02-30T00:00:00Z"), ("decision", "approved")):
            value = self.review()
            value[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                mod.validate(value, "review")

    def test_routes_and_coverage_cannot_be_tampered_to_clean(self):
        original = self.handoff(flag=True, forbid=True, incomplete=True)
        for key, replacement in (("routes", ["qualified-completed"]), ("analysis-complete", True),
                                 ("status", "successful"), ("coverage", {"gaps": [], "evaluation-incomplete": False})):
            value = deepcopy(original)
            value[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                mod.validate(value, "handoff")

    def test_nofollow_regular_files_and_bounded_hash_reads(self):
        alias = self.root / "alias"
        alias.symlink_to(self.pak)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (alias, fifo, self.root):
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                mod.digest(path, 100)
        with self.assertRaises(ValueError):
            mod.digest(self.pak, 2)
        with patch.object(mod, "PAK_LIMIT", 2), self.assertRaises(ValueError):
            self.handoff()
        with patch.object(mod, "DEPENDENCY_LIMIT", 2), self.assertRaises(ValueError):
            self.handoff()
        large = self.root / "large-json"
        with large.open("wb") as stream:
            stream.truncate(mod.JSON_LIMIT + 1)
        with self.assertRaises(ValueError):
            mod.load(large, "context")

    def test_modified_during_read_rejected(self):
        def change(chunk):
            self.pak.write_bytes(b"mutated during hashing")
        with self.assertRaises(ValueError):
            mod.consume(self.pak, 1000, change)

    def test_cli_full_handoff_review_feedback_verify_lifecycle(self):
        context = self.write("context.json", self.context)
        report = self.write("report.json", self.report(flag=True, forbid=True, incomplete=True))
        handoff, approval, feedback = [self.root / name for name in ("handoff.json", "approval.json", "feedback.json")]
        byte_args = ["--context", context, "--pak", self.pak, "--dependency", "mapping=" + str(self.mapping)]
        result = self.invoke("handoff", "--report", report, *byte_args, "--output", handoff)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(0o600, handoff.stat().st_mode & 0o777)
        result = self.invoke("review", "--handoff", handoff, "--actor", "moderator", "--decision", "approve",
                             "--rationale", CANARY, "--output", approval)
        self.assertEqual(0, result.returncode, result.stderr)
        result = self.invoke("feedback", "--handoff", handoff, "--output", feedback)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn(CANARY, feedback.read_text())
        self.assertNotIn(self.context["report-context"]["policy-revision"], feedback.read_text())
        self.assertNotIn(json.loads(handoff.read_bytes())["report-sha256"], feedback.read_text())
        self.assertEqual(3, len(json.loads(feedback.read_bytes())["routes"]))
        result = self.invoke("verify", "--approval", approval, "--report", report, *byte_args)
        self.assertEqual(0, result.returncode, result.stderr)
        self.pak.write_bytes(b"same URL replacement")
        result = self.invoke("verify", "--approval", approval, "--report", report, *byte_args)
        self.assertEqual(3, result.returncode)
        self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)

    def test_cli_rejection_is_not_approval(self):
        approval = self.write("rejected.json", self.review(decision="reject"))
        context = self.write("context.json", self.context)
        report = self.write("report.json", self.report())
        result = self.invoke("verify", "--approval", approval, "--context", context, "--pak", self.pak,
                             "--dependency", "mapping=" + str(self.mapping), "--report", report)
        self.assertEqual(1, result.returncode)
        self.assertEqual(b"Not approved.\n", result.stdout)

    def test_cli_distinct_equal_count_reports_cannot_share_approval(self):
        context = self.write("context.json", self.context)
        byte_args = ["--context", context, "--pak", self.pak, "--dependency", "mapping=" + str(self.mapping)]
        handoffs, approvals, reports = [], [], []
        for index, call in enumerate(("FirstCall", "DifferentCall")):
            report = self.report(forbid=True)
            report["forbidden-invocations"][0].update(
                id=str(index + 1) * 64,
                location={"asset": f"/Game/Owned{index}", "function": "Run", "offset": index * 42},
                target={"owner": "/Script/Owned.Actor", "function": call})
            source = self.write(f"report{index}.json", report)
            handoff, approval = [self.root / f"{kind}{index}.json" for kind in ("handoff", "approval")]
            result = self.invoke("handoff", "--report", source, *byte_args, "--output", handoff)
            self.assertEqual(0, result.returncode, result.stderr)
            result = self.invoke("review", "--handoff", handoff, "--actor", "moderator", "--decision", "approve",
                                 "--rationale", "Explicit exception for " + call, "--output", approval)
            self.assertEqual(0, result.returncode, result.stderr)
            handoffs.append(json.loads(handoff.read_bytes()))
            approvals.append(approval)
            reports.append(source)
        self.assertEqual(handoffs[0]["counts"], handoffs[1]["counts"])
        self.assertEqual(handoffs[0]["coverage"], handoffs[1]["coverage"])
        self.assertNotEqual(handoffs[0]["report-sha256"], handoffs[1]["report-sha256"])
        reviewed = [json.loads(path.read_bytes())["handoff"] for path in approvals]
        self.assertEqual(handoffs, reviewed)
        self.assertNotEqual(reviewed[0], reviewed[1])
        for index, approval in enumerate(approvals):
            result = self.invoke("verify", "--approval", approval, "--report", reports[index], *byte_args)
            self.assertEqual(0, result.returncode, result.stderr)
            result = self.invoke("verify", "--approval", approval, "--report", reports[1 - index], *byte_args)
            self.assertEqual(3, result.returncode)
            self.assertNotIn(handoffs[index]["report-sha256"].encode(), result.stdout + result.stderr)
        result = self.invoke("verify", "--approval", approvals[0], *byte_args)
        self.assertEqual(3, result.returncode)  # The retained report is required, not optional.

    def test_cli_malformed_and_special_inputs_no_output_no_leaks(self):
        context = self.write("context.json", self.context)
        report = self.write("report.json", self.report())
        report.write_text('{"private": "' + CANARY + '"}')
        alias = self.root / "report-alias"
        alias.symlink_to(report)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        oversized = self.root / "oversized"
        with oversized.open("wb") as stream:
            stream.truncate(mod.JSON_LIMIT + 1)
        for path in (report, alias, fifo, self.root, oversized):
            destination = self.root / "absent-output"
            result = self.invoke("handoff", "--report", path, "--context", context, "--pak", self.pak,
                                 "--dependency", "mapping=" + str(self.mapping), "--output", destination)
            self.assertEqual(3, result.returncode)
            self.assertFalse(destination.exists())
            self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)

    def test_cli_verify_report_uses_same_bounded_nofollow_validation(self):
        context = self.write("context.json", self.context)
        approval = self.write("approval.json", self.review())
        report = self.write("report.json", self.report())
        alias = self.root / "report-alias"
        alias.symlink_to(report)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        oversized = self.root / "oversized"
        with oversized.open("wb") as stream:
            stream.truncate(mod.JSON_LIMIT + 1)
        report.write_text('{"private": "' + CANARY + '"}')
        for path in (report, alias, fifo, self.root, oversized, self.root / "missing"):
            with self.subTest(path=path):
                result = self.invoke("verify", "--approval", approval, "--report", path, "--context", context,
                                     "--pak", self.pak, "--dependency", "mapping=" + str(self.mapping))
                self.assertEqual(3, result.returncode)
                self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)

    def test_cli_report_batch_and_unknown_aliases_fail_closed(self):
        context = self.write("context.json", self.context)
        original = self.report()
        alias = deepcopy(original)
        alias["coverage"]["gaps"] = ["IncompleteExtraction"]
        for report in ([original], {**original, "private-policy": CANARY}, alias):
            source = self.write("report.json", report)
            destination = self.root / "absent-output"
            result = self.invoke("handoff", "--report", source, "--context", context, "--pak", self.pak,
                                 "--dependency", "mapping=" + str(self.mapping), "--output", destination)
            self.assertEqual(3, result.returncode)
            self.assertFalse(destination.exists())
            self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)

    def test_cli_oversized_pak_and_dependency_rejected_before_hashing(self):
        context = self.write("context.json", self.context)
        report = self.write("report.json", self.report())
        for path, limit in ((self.pak, mod.PAK_LIMIT), (self.mapping, mod.DEPENDENCY_LIMIT)):
            original = path.read_bytes()
            with path.open("wb") as stream:
                stream.truncate(limit + 1)
            destination = self.root / "absent-output"
            result = self.invoke("handoff", "--report", report, "--context", context, "--pak", self.pak,
                                 "--dependency", "mapping=" + str(self.mapping), "--output", destination)
            self.assertEqual(3, result.returncode)
            self.assertFalse(destination.exists())
            path.write_bytes(original)

    def test_cli_outputs_never_overwrite_alias_or_special_file(self):
        source = self.write("handoff.json", self.handoff())
        alias = self.root / "alias"
        alias.symlink_to(source)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for destination in (source, alias, fifo, self.root):
            result = self.invoke("feedback", "--handoff", source, "--output", destination)
            self.assertEqual(3, result.returncode)
        self.assertEqual(self.handoff(), json.loads(source.read_bytes()))
        self.assertEqual([], list(self.root.glob(".risk-report-*")))

    def test_cli_option_aliases_and_duplicates_rejected(self):
        source = self.write("handoff.json", self.handoff())
        destination = self.root / "absent-output"
        for arguments in (("feedback", "--hand", source, "--output", destination),
                          ("feedback", "--handoff", source, "--handoff", source, "--output", destination)):
            result = self.invoke(*arguments)
            self.assertEqual(3, result.returncode)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
