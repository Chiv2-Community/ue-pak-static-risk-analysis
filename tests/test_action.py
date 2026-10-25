"""Action adapter process tests, plus opt-in real Docker/owned-cook parity."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ingestion_fixture import build

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import action
import action_report

IMAGE = os.environ.get("UE_PAK_CONTAINER_TEST_IMAGE")
POLICY = """schema-version: 1
rules:
  - id: private-action-canary
    description: private-action-canary ##[error] ::error:: $() `not executed`
    effect: forbid
    match:
      kind: invocation
      target:
        kind: exact
        owner: /Script/OwnedFixtures.FixtureActor
        function: RecordFixture
"""


def finding(index=0, metadata="/Game/Owned"):
    return {"id": f"{index:064x}", "location": {"asset": metadata, "function": "Run", "offset": index},
            "target": {"owner": "/Script/Owned.Actor", "function": "Call"},
            "argument-metadata": "unavailable", "known-argument-count": None}


def report(findings=None):
    findings = [finding()] if findings is None else findings
    return {"schema-version": 1, "status": "successful", "analysis-complete": True,
            "context": {"tool-version": "test", "engine-version": "4.25", "pak-sha256": "a" * 64,
                        "producer-version": "test", "dependencies": []},
            "counts": {"invocations": len(findings), "flagged": 0, "forbidden": len(findings), "affected-union": len(findings)},
            "coverage": {"gaps": [], "evaluation-incomplete": False},
            "flagged-invocations": [], "forbidden-invocations": findings, "diagnostics": []}


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="action-test-")
        self.root = Path(self.directory.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.output, self.summary = self.root / "outputs", self.root / "summary"
        self.output.touch()
        self.summary.touch()
        self.env = dict(os.environ)
        self.env.pop("UE_PAK_POLICY_RULES", None)
        self.env.update(GITHUB_WORKSPACE=str(self.workspace), GITHUB_OUTPUT=str(self.output),
                        GITHUB_STEP_SUMMARY=str(self.summary), INPUT_REPORT="report.json", INPUT_PAK="submission.pak",
                        UE_PAK_ACTION_IMAGE="sha256:" + "d" * 64)

    def tearDown(self):
        self.directory.cleanup()

    def invoke(self, value=None, code=1, *, missing=False, extra=None):
        source = self.root / "action"
        (source / "scripts").mkdir(parents=True, exist_ok=True)
        for name in ("action.py", "action_report.py", "report_validation.py"):
            shutil.copyfile(ROOT / "scripts" / name, source / "scripts" / name)
        shutil.copytree(ROOT / "schemas", source / "schemas", dirs_exist_ok=True)
        data = json.dumps(report() if value is None else value)
        stub = ("import os,sys\nfrom pathlib import Path\n"
                "assert 'GITHUB_TOKEN' not in os.environ\n"
                "assert 'ACTIONS_RUNTIME_TOKEN' not in os.environ\n"
                "assert 'GITHUB_OUTPUT' not in os.environ\n"
                "assert 'INPUT_POLICY_RULES' not in os.environ\n")
        if not missing:
            stub += f"Path(sys.argv[sys.argv.index('--report')+1]).write_text({data!r})\n"
        stub += f"sys.exit({code})\n"
        (source / "scripts/scan.py").write_text(stub)
        self.env.update(extra or {})
        result = subprocess.run([sys.executable, str(source / "scripts/action.py"), "scan"],
                                env=self.env, cwd=self.workspace, capture_output=True, timeout=15)
        outputs = dict(line.split("=", 1) for line in self.output.read_text().splitlines())
        return result, outputs, self.summary.read_text()

    def test_gate_failure_has_outputs_report_and_summary_before_exit(self):
        result, outputs, summary = self.invoke(extra={"GITHUB_TOKEN": "secret", "ACTIONS_RUNTIME_TOKEN": "secret"})
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("successful", outputs["status"])
        self.assertEqual("true", outputs["analysis-complete"])
        self.assertEqual("1", outputs["forbidden-count"])
        self.assertEqual(report()["forbidden-invocations"], json.loads(outputs["forbidden-invocations"]))
        self.assertTrue((self.workspace / outputs["report-path"]).exists())
        self.assertIn("Forbidden: 1", summary)

    def test_call_chain_report_is_valid_but_witnesses_and_capabilities_are_not_action_outputs(self):
        from test_call_chains import report as chain_report
        value = chain_report()
        value["context"]["capability-catalog-revision"] = "fixture-v1"
        value["context"]["dependencies"].insert(0, {"kind": "capability-summaries", "sha256": "c" * 64})
        value["call-chains"].update({"catalog-revision": "fixture-v1", "catalog-sha256": "c" * 64, "needs-review": True})
        value["call-chains"]["witnesses"][0]["endpoint"]["capability"] = "public-capability-canary"
        result, outputs, summary = self.invoke(value)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("true", outputs["report-available"])
        self.assertEqual("1", outputs["forbidden-count"])
        self.assertEqual(value["forbidden-invocations"], json.loads(outputs["forbidden-invocations"]))
        self.assertNotIn("public-capability-canary", json.dumps(outputs) + summary)
        self.assertNotIn("callers", json.dumps(outputs) + summary)
        self.assertIn("call-chains", json.loads((self.workspace / outputs["report-path"]).read_bytes()))

    def test_metadata_output_delimiters_commands_and_summary_are_data(self):
        metadata = 'x\r\nFORGED=1\nEOF\n::error:: ##[error]\x1b[31m </summary> [link](https://bad) \U0001f600'
        result, outputs, summary = self.invoke(report([finding(metadata=metadata)]))
        self.assertEqual(1, result.returncode)
        self.assertNotIn("FORGED", outputs)
        self.assertEqual(metadata, json.loads(outputs["forbidden-invocations"])[0]["location"]["asset"])
        self.assertNotIn(metadata, summary)
        self.assertNotIn(b"::error::", result.stdout + result.stderr)
        self.assertNotIn("##[error]", summary)

    def test_additive_content_result_keeps_real_arrays_and_nonzero_exit(self):
        value = report()
        value["content-policy"] = {"schema-version": 1, "decision": "reject", "incomplete": False,
                                   "findings": [{"member-id": "r00000000", "diagnostic": "path-not-allowed"}]}
        result, outputs, _ = self.invoke(value)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("1", outputs["forbidden-count"])
        self.assertEqual(value["forbidden-invocations"], json.loads(outputs["forbidden-invocations"]))
        self.assertEqual(value, json.loads((self.workspace / "report.json").read_text()))

    def test_large_arrays_explicitly_omitted_with_counts_and_report(self):
        value = report([finding(index, "\U0001f600" * 2000) for index in range(20)])
        result, outputs, _ = self.invoke(value)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("true", outputs["arrays-omitted"])
        self.assertEqual("output-budget", outputs["omission-reason"])
        self.assertEqual("20", outputs["forbidden-count"])
        self.assertEqual([], json.loads(outputs["forbidden-invocations"]))
        self.assertLessEqual(len(self.output.read_text().encode("utf-16-le")), action.OUTPUT_BUDGET)
        self.assertEqual(value, json.loads((self.workspace / "report.json").read_text()))

    def test_missing_report_never_becomes_clean_empty_success(self):
        result, outputs, _ = self.invoke(code=0, missing=True)
        self.assertEqual(3, result.returncode)
        self.assertEqual("failed", outputs["status"])
        self.assertEqual("unknown", outputs["forbidden-count"])
        self.assertEqual("false", outputs["report-available"])
        self.assertEqual(["report-unavailable"], json.loads(outputs["diagnostics"]))

    def test_preparation_failure_still_publishes_failed_outputs(self):
        result, outputs, summary = self.invoke(extra={"UE_PAK_ACTION_IMAGE": ""})
        self.assertEqual(3, result.returncode)
        self.assertEqual(["image-preparation-failed"], json.loads(outputs["diagnostics"]))
        self.assertEqual("false", outputs["report-available"])
        self.assertIn("Status: failed", summary)

    def test_wrapper_exit_and_report_status_must_agree(self):
        result, outputs, _ = self.invoke(code=3)
        self.assertEqual(3, result.returncode)
        self.assertEqual("failed", outputs["status"])
        self.assertEqual(["invalid-report"], json.loads(outputs["diagnostics"]))

    def test_invalid_reports_never_published(self):
        value = report()
        value["forbidden-invocations"][0]["rule-ids"] = ["private-action-canary"]
        result, outputs, summary = self.invoke(value)
        self.assertEqual(3, result.returncode)
        self.assertEqual(["invalid-report"], json.loads(outputs["diagnostics"]))
        self.assertNotIn("private-action-canary", self.output.read_text() + summary)

    def test_report_paths_do_not_overwrite_or_escape(self):
        for path in ("../escape", str(self.output), "report\nFORGED=1", "new/absent/report", "report.json"):
            with self.subTest(path=path):
                if path == "report.json":
                    (self.workspace / path).write_text("existing")
                with patch.dict(os.environ, dict(self.env, INPUT_REPORT=path), clear=True):
                    with self.assertRaises((ValueError, OSError)):
                        action.destination()
        self.assertEqual("existing", (self.workspace / "report.json").read_text())
        (self.workspace / "outside").symlink_to(self.root, target_is_directory=True)
        with patch.dict(os.environ, dict(self.env, INPUT_REPORT="outside/report"), clear=True):
            with self.assertRaises(ValueError):
                action.destination()

    def test_runner_files_cannot_alias_report_and_append_refuses_symlinks(self):
        with patch.dict(os.environ, dict(self.env, GITHUB_OUTPUT=str(self.workspace / "report.json")), clear=True):
            with self.assertRaises(ValueError):
                action.destination()
        alias = self.root / "alias"
        alias.symlink_to(self.output)
        with self.assertRaises(OSError):
            action.append(alias, b"x=1\n")
        action.append(self.output, b"fixed=one\n")
        action.append(self.output, b"other=two\n")
        self.assertEqual("fixed=one\nother=two\n", self.output.read_text())

    def test_report_cannot_alias_a_missing_policy_source(self):
        with patch.dict(os.environ, dict(self.env, INPUT_POLICY_RULES=str(self.workspace / "report.json")), clear=True):
            with self.assertRaises(ValueError):
                action.destination()

    def test_preparation_clean_environment_pinned_dependency_and_minimal_context(self):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            env = kwargs["env"]
            for key in ("GITHUB_TOKEN", "UE_PAK_POLICY_RULES", "ACTIONS_RUNTIME_TOKEN", "SSH_AUTH_SOCK"):
                self.assertNotIn(key, env)
            if "init" in command:
                Path(command[-1]).mkdir()
            if "build" in command:
                context = Path(command[-1])
                self.assertTrue((context / ".dockerignore").is_file())
                self.assertFalse((context / ".github").exists())
                self.assertFalse((context / "scripts").exists())
                self.assertFalse((context / "tests").exists())
        with patch.dict(os.environ, dict(self.env, UE_PAK_POLICY_RULES=POLICY, GITHUB_TOKEN="secret"), clear=True), patch.object(action.subprocess, "run", side_effect=run):
            action.prepare()
        self.assertTrue(any(action.UASSET in call and "fetch" in call for call in calls))
        self.assertRegex(self.output.read_text(), r"^image=ue-pak-action:[a-f0-9]{32}\n$")

    def test_metadata_contract_has_no_input_interpolation_in_shell(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("install PyYAML for structural Action metadata checks (required in Action CI)")
        value = yaml.safe_load((ROOT / "action.yml").read_text())
        self.assertEqual("composite", value["runs"]["using"])
        self.assertNotIn("image", value["inputs"])
        self.assertEqual("info", value["inputs"]["log-level"]["default"])
        for key, expected in (("fail-on-any-forbidden", "true"), ("fail-on-any-flagged", "false"),
                              ("fail-on-incomplete", "true"), ("engine-version", "4.25")):
            self.assertEqual(expected, value["inputs"][key]["default"])
        self.assertEqual(set(action.outputs(report(), "report.json")), set(value["outputs"]))
        for step in value["runs"]["steps"]:
            self.assertNotIn("${{", step["run"])
            self.assertNotIn("UE_PAK_POLICY_RULES", step["run"])


class ReportValidationTests(unittest.TestCase):
    def test_schema_evolution_cannot_silently_weaken_validation(self):
        with self.assertRaises(ValueError):
            action_report.check_schema({"properties": {"item": {"not": {"const": "forbidden"}}}})

    def test_schema_and_duplicate_unicode_depth_count_bounds(self):
        self.assertEqual(report(), action_report.load(json.dumps(report()).encode(), ROOT))
        invalid = []
        for mutate in (lambda r: r.update(extra=1), lambda r: r.update(status="clean"),
                       lambda r: r["counts"].update(forbidden=0),
                       lambda r: r["counts"].update(invocations=True),
                       lambda r: r["forbidden-invocations"][0]["location"].update(offset=-1),
                       lambda r: r["forbidden-invocations"][0]["location"].update(asset="\ud800"),
                       lambda r: r.update(diagnostics=["::error::"]),
                       lambda r: r.update(**{"analysis-complete": False})):
            value = report()
            mutate(value)
            invalid.append(json.dumps(value).encode())
        invalid += [b'{"schema-version":1,"schema-version":1}', b'[' * 1500 + b']' * 1500,
                    b'{"x":NaN}', b'x' * (16 * 1024 * 1024 + 1)]
        for data in invalid:
            with self.subTest(data=data[:80]), self.assertRaises((ValueError, RecursionError)):
                action_report.load(data, ROOT)


@unittest.skipUnless(IMAGE, "set UE_PAK_CONTAINER_TEST_IMAGE to a prebuilt local image")
class ActionDockerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="action-docker-")
        self.root = Path(self.directory.name)
        self.image = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], text=True).strip()

    def tearDown(self):
        self.directory.cleanup()

    def invoke(self, payload=None, *, policy=POLICY, file=False, extra=None):
        workspace = self.root / str(len(list(self.root.iterdir())))
        workspace.mkdir()
        (workspace / "pak").write_bytes(build() if payload is None else payload)
        output, summary = workspace / "outputs", workspace / "summary"
        output.touch()
        summary.touch()
        env = {k: v for k, v in os.environ.items() if k != "UE_PAK_POLICY_RULES"}
        env.update(GITHUB_WORKSPACE=str(workspace), GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary),
                   UE_PAK_ACTION_IMAGE=self.image, INPUT_PAK="pak", INPUT_REPORT="report.json")
        if file:
            (workspace / "rules").write_text(policy)
            env["INPUT_POLICY_RULES"] = "rules"
        elif policy is not None:
            env["UE_PAK_POLICY_RULES"] = policy
        env.update(extra or {})
        result = subprocess.run([sys.executable, str(ROOT / "scripts/action.py"), "scan"], env=env,
                                cwd=workspace, capture_output=True, timeout=90)
        outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
        report_path = workspace / "report.json"
        value = json.loads(report_path.read_bytes()) if report_path.exists() else None
        return result, outputs, value, summary.read_text()

    def test_actual_container_sources_levels_and_wrapper_parity(self):
        expected = None
        for file in (False, True):
            for level in (None, "error", "warn", "info", "verbose"):
                extra = {} if level is None else {"INPUT_LOG_LEVEL": level}
                result, outputs, value, summary = self.invoke(file=file, extra=extra)
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertEqual("partial", outputs["status"])
                self.assertEqual(value["forbidden-invocations"], json.loads(outputs["forbidden-invocations"]))
                self.assertEqual(str(value["counts"]["forbidden"]), outputs["forbidden-count"])
                self.assertNotIn("private-action-canary", json.dumps(outputs) + summary + json.dumps(value))
                logs = result.stdout + result.stderr
                if level == "verbose":
                    self.assertEqual(1, logs.count(b"WARNING: VERBOSE"))
                    self.assertLess(logs.index(b"WARNING:"), logs.index(b"private-action-canary"))
                    self.assertNotIn(b"::error::", logs)
                    self.assertNotIn(b"##[error]", logs)
                else:
                    self.assertNotIn(b"private-action-canary", logs)
                expected = value if expected is None else expected
                self.assertEqual(expected, value)
        workspace = self.root / "direct"
        workspace.mkdir()
        (workspace / "pak").write_bytes(build())
        direct = subprocess.run([sys.executable, str(ROOT / "scripts/scan.py"), "scan", "--pak", str(workspace / "pak"),
                                 "--report", str(workspace / "report"), "--engine-version", "4.25", "--image", self.image],
                                env=dict(os.environ, UE_PAK_POLICY_RULES=POLICY), capture_output=True, timeout=90)
        self.assertEqual(1, direct.returncode, direct.stderr)
        self.assertEqual(expected, json.loads((workspace / "report").read_bytes()))

    def test_actual_invalid_inputs_no_policy_leak(self):
        for policy, extra in ((None, {}), ("", {}), (POLICY, {"INPUT_LOG_LEVEL": "bad"}),
                              (POLICY, {"INPUT_FAIL_ON_INCOMPLETE": "yes"}),
                              (POLICY, {"INPUT_ENGINE_VERSION": "5.0"})):
            result, outputs, value, _ = self.invoke(policy=policy, extra=extra)
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertEqual("failed", outputs["status"])
            self.assertNotIn(b"private-action-canary", result.stdout + result.stderr)
        path = self.root / "policy"
        path.write_text(POLICY)
        result, outputs, _, _ = self.invoke(extra={"INPUT_POLICY_RULES": str(path)})
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertEqual("failed", outputs["status"])
        # Shared renderer, including malformed source text, remains reversible/safe.
        result, outputs, value, summary = self.invoke(policy="::error:: ##[error]\nEOF\n\x1b[31m private-action-canary", extra={"INPUT_LOG_LEVEL": "verbose"})
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertIn(b"\\u001b", result.stderr)
        self.assertNotIn(b"::error::", result.stderr)
        self.assertNotIn(b"##[error]", result.stderr)
        self.assertNotIn("private-action-canary", json.dumps(outputs) + summary + json.dumps(value))

    def test_actual_missing_local_image_is_not_clean(self):
        result, outputs, value, summary = self.invoke(extra={"UE_PAK_ACTION_IMAGE": "sha256:" + "1" * 64})
        self.assertEqual(3, result.returncode, result.stderr)
        self.assertEqual("failed", outputs["status"])
        self.assertEqual("unknown", outputs["forbidden-count"])
        self.assertEqual("false", outputs["report-available"])
        self.assertIsNone(value)
        self.assertIn("Status: failed", summary)

    @unittest.skipUnless(os.environ.get("OWNED_FIXTURE_EVIDENCE"), "set OWNED_FIXTURE_EVIDENCE for cooked calls")
    def test_owned_forbidden_outputs_before_failure_and_mapping(self):
        original = Path(os.environ["OWNED_FIXTURE_EVIDENCE"])
        content = original / "tagged/OwnedFixtures/Content"
        members = []
        for stem, extension in (("BP_OwnedParent", "uasset"), ("BP_OwnedChild", "uasset"), ("OwnedMap", "umap")):
            for suffix in (extension, "uexp"):
                path = content / (stem + "." + suffix)
                members.append(("OwnedFixtures/Content/" + path.name, path.read_bytes(), False))
        extra = {"INPUT_CONTENT_ROOT": "OwnedFixtures/Content=/Game"}
        result, outputs, value, summary = self.invoke(build(members), extra=extra)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("2", outputs["forbidden-count"])
        self.assertEqual("true", outputs["analysis-complete"])
        self.assertEqual(2, len(json.loads(outputs["forbidden-invocations"])))
        self.assertIn("Forbidden: 2", summary)
        self.assertEqual(6, value["counts"]["invocations"])
        content = original / "unversioned/OwnedFixtures/Content/Data"
        members = [("OwnedFixtures/Content/Data/" + p.name, p.read_bytes(), False)
                   for p in (content / "OwnedData.uasset", content / "OwnedData.uexp")]
        result, outputs, value, _ = self.invoke(build(members), extra=dict(extra, INPUT_MAPPING=str(original / "owned.usmap")))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("true", outputs["analysis-complete"])
