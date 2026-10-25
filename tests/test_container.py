"""Opt-in local-image integration; no registry publication or engine required.

UE_PAK_CONTAINER_TEST_IMAGE=ue-pak-static-risk-analysis:dev python3 -m unittest discover -s tests -p test_container.py -v
"""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from ingestion_fixture import build
from test_scan import scan

ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("UE_PAK_CONTAINER_TEST_IMAGE")
POLICY = """schema-version: 1
rules:
  - id: private-container-canary
    description: private-container-canary $() `echo not-executed` ##[error] ::warning::
    effect: forbid
    match:
      kind: invocation
      target:
        kind: exact
        owner: /Script/OwnedFixtures.FixtureActor
        function: RecordFixture
"""


@unittest.skipUnless(IMAGE, "set UE_PAK_CONTAINER_TEST_IMAGE to a prebuilt local image")
class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="container-test-", dir="/tmp/opencode" if Path("/tmp/opencode").exists() else None)
        self.root = Path(self.directory.name)
        self.config = self.root / "config"
        self.config.mkdir()
        self.docker = scan.Docker(self.config, IMAGE, 20)
        self.before = self.names()

    def tearDown(self):
        self.assertEqual(self.before, self.names(), "owned container leaked")
        self.directory.cleanup()

    def names(self):
        return set(subprocess.check_output(["docker", "ps", "-a", "--filter", "name=pak-scan-", "--format", "{{.Names}}"], text=True).splitlines())

    def invoke(self, payload=None, *, policy=POLICY, file=False, extra=()):
        pak, output = self.root / "submission", self.root / ("report-" + str(time.monotonic_ns()))
        pak.write_bytes(build() if payload is None else payload)
        env = dict(os.environ)
        env.pop("UE_PAK_POLICY_RULES", None)
        args = [sys.executable, str(ROOT / "scripts/scan.py"), "scan", "--pak", str(pak),
                "--report", str(output), "--engine-version", "4.25", "--image", IMAGE]
        if file:
            path = self.root / "policy"
            path.write_text(policy)
            args += ["--policy-rules", str(path)]
        elif policy is not None:
            env["UE_PAK_POLICY_RULES"] = policy
        result = subprocess.run(args + list(extra), env=env, capture_output=True, timeout=90)
        report = json.loads(output.read_bytes()) if output.exists() else None
        if report is not None:
            try:
                import jsonschema
                from referencing import Registry, Resource
            except ImportError:
                pass
            else:
                schemas = [json.loads((ROOT / "schemas" / name).read_bytes())
                           for name in ("facts-v1.schema.json", "report-v1.schema.json")]
                registry = Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in schemas)
                jsonschema.Draft202012Validator(schemas[1], registry=registry).validate(report)
        return result, report

    def test_file_environment_levels_privacy_and_exact_snapshot(self):
        expected = None
        for file in (False, True):
            for level in ("error", "warn", "info", "verbose"):
                result, report = self.invoke(file=file, extra=["--log-level", level])
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertFalse(report["analysis-complete"])
                self.assertEqual(hashlib.sha256(build()).hexdigest(), report["context"]["pak-sha256"])
                member = report["inspection"]["members"][0]
                self.assertEqual(hashlib.sha256(b"owned").hexdigest(), member["sha256"])
                self.assertEqual("uninspected", member["inspection-status"])
                text = result.stdout + result.stderr
                self.assertNotIn("private-container-canary", json.dumps(report))
                if level == "verbose":
                    self.assertEqual(1, text.count(b"WARNING: VERBOSE"))
                    self.assertIn(b"private-container-canary", text)
                    self.assertNotIn(b"##[error]", text)
                    self.assertNotIn(b"::warning::", text)
                else:
                    self.assertNotIn(b"private-container-canary", text)
                expected = report if expected is None else expected
                self.assertEqual(expected, report)

    def test_bad_policy_and_invalid_level_fail_before_parser_without_disclosure(self):
        for policy, extra in ((None, []), ("", []), ("private-container-canary: [", []),
                              (POLICY.replace("private-container-canary", "private-container-canary-\udcff"), []),
                              (POLICY, ["--log-level", "invalid"])):
            result, report = self.invoke(policy=policy, extra=extra)
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertEqual("failed", report["status"])
            self.assertNotIn(b"private-container-canary", result.stdout + result.stderr)
        result, report = self.invoke(policy="private-container-canary: [", extra=["--log-level", "verbose"])
        self.assertEqual(2, result.returncode)
        self.assertLess(result.stderr.index(b"WARNING:"), result.stderr.index(b"private-container-canary"))
        oversized, report = self.invoke(file=True, policy=POLICY + "#" + "x" * 262144)
        self.assertEqual(2, oversized.returncode, oversized.stderr)
        self.assertNotIn(b"private-container-canary", oversized.stdout + oversized.stderr)

    def test_parser_cannot_read_policy_credentials_workspace_or_host_process(self):
        code = """import os,json,socket
from pathlib import Path
assert os.getuid()!=0
assert 'UE_PAK_POLICY_RULES' not in os.environ
assert 'AWS_SECRET_ACCESS_KEY' not in os.environ
assert b'private-container-canary' not in Path('/proc/1/environ').read_bytes()
for p in ['/policy/rules','/var/run/docker.sock','/root/.docker/config.json','/workspace', '/home/jbarber']:
 try: assert not Path(p).exists(),p
 except PermissionError: pass
try:
 Path('/root-write').write_text('no')
 raise AssertionError('writable root')
except OSError: pass
s=socket.socket();s.settimeout(.2)
try:
 s.connect(('1.1.1.1',443));raise AssertionError('network')
except OSError: pass
Path('/scratch/approved').write_text('yes')
print('isolated')
"""
        with patch.dict(os.environ, {"UE_PAK_POLICY_RULES": POLICY, "AWS_SECRET_ACCESS_KEY": "unrelated-credential"}):
            status, output = self.docker.run([], "/usr/local/bin/python3", ["-c", code], parser=True)
        self.assertEqual(0, status)
        self.assertEqual(b"isolated\n", output)

    def test_stdout_flood_deadline_and_stderr_discard_cleanup(self):
        with self.assertRaisesRegex(scan.Failure, "parser-output-limit"):
            self.docker.run([], "/usr/local/bin/python3", ["-c", "import os; os.write(1,b'x'*(9*1024*1024))"], parser=True)
        status, output = self.docker.run([], "/usr/local/bin/python3",
            ["-c", "import os; os.write(2,b'private-container-canary'*(1024*1024)); print('done')"], parser=True)
        self.assertEqual((0, b"done\n"), (status, output))
        self.docker.timeout = .3
        with self.assertRaisesRegex(scan.Failure, "wall-timeout"):
            self.docker.run([], "/usr/local/bin/python3", ["-c", "import time;time.sleep(60)"], parser=True)

    def test_scratch_hard_quota(self):
        original = self.docker.command
        def command(*args, **kwargs):
            result = original(*args, **kwargs)
            return [s.replace("size=900m", "size=8m") for s in result]
        self.docker.command = command
        status, output = self.docker.run([], "/usr/local/bin/python3", ["-c", """import errno
try:
 with open('/scratch/fill','wb') as f:
  for _ in range(16): f.write(b'x'*1048576)
 raise AssertionError('quota not enforced')
except OSError as e:
 assert e.errno==errno.ENOSPC
 print('scratch-limit')
"""], parser=True)
        self.assertEqual((0, b"scratch-limit\n"), (status, output))

    def test_enforced_cgroup_process_cpu_and_memory_limits(self):
        status, output = self.docker.run([], "/usr/local/bin/python3", ["-c", """from pathlib import Path
assert Path('/sys/fs/cgroup/memory.max').read_text().strip()=='1073741824'
assert Path('/sys/fs/cgroup/memory.swap.max').read_text().strip()=='0'
assert Path('/sys/fs/cgroup/pids.max').read_text().strip()=='64'
quota,period=map(int,Path('/sys/fs/cgroup/cpu.max').read_text().split())
assert quota==period
print('limits')
"""], parser=True)
        self.assertEqual((0, b"limits\n"), (status, output))
        status, output = self.docker.run([], "/usr/local/bin/python3",
            ["-c", "x=bytearray(1200*1024*1024); print('unexpected')"], parser=True)
        self.assertNotEqual(0, status)
        self.assertNotIn(b"unexpected", output)

    def test_image_config_and_history_contain_no_policy(self):
        inspect = subprocess.check_output(self.docker.prefix + ["image", "inspect", self.docker.image], env=scan.client_environment())
        history = subprocess.check_output(self.docker.prefix + ["history", "--no-trunc", self.docker.image], env=scan.client_environment())
        self.assertNotIn(b"private-container-canary", inspect + history)
        self.assertNotIn(b"UE_PAK_POLICY_RULES=", inspect + history)
        config = json.loads(inspect)[0]["Config"]
        self.assertEqual("65532:65532", config["User"])

    def test_cancellation_removes_only_owned_container(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            code = """import sys,signal,tempfile
sys.path.insert(0,sys.argv[1]+'/scripts')
import scan
signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
try:
 scan.Docker(sys.argv[2],sys.argv[3],30).run([], '/usr/local/bin/python3',['-c','import time;time.sleep(60)'],parser=True)
except scan.Failure: sys.exit(3)
"""
            process = subprocess.Popen([sys.executable, "-c", code, str(ROOT), str(self.config), IMAGE],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
            try:
                deadline = time.monotonic() + 10
                while self.names() == self.before and time.monotonic() < deadline:
                    time.sleep(.05)
                self.assertNotEqual(self.before, self.names(), "test never started container")
                os.killpg(process.pid, sig)
                _, error = process.communicate(timeout=20)
                self.assertEqual(3, process.returncode, error)
                self.assertEqual(self.before, self.names())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_compression_bomb_unknown_and_missing_sidecar_are_not_clean(self):
        samples = [build([("Content/renamed.uasset", b"\x7fELF" + b"x" * 100, False)]),
                   build([("Content/bomb", b"x" * 1024 * 1024, True)]),
                   build([("Content/fake.uasset", b"\xc1\x83\x2a\x9e" + b"x" * 20, False)])]
        for payload in samples:
            result, report = self.invoke(payload, extra=["--content-root", "Content=/Game"])
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertFalse(report["analysis-complete"])
            self.assertTrue(report["coverage"]["gaps"])
        self.assertEqual(self.before, self.names())

    def test_content_path_boundaries_and_unknown_native_are_not_approved(self):
        disabled = ["--fail-on-any-forbidden", "false", "--fail-on-any-flagged", "false", "--fail-on-incomplete", "false"]
        for prefix, decision, code in (("Content", "allow", 0), ("content", "allow", 0),
                                       ("Cont", "reject", 1), ("private-namespace-canary", "reject", 1)):
            result, report = self.invoke(extra=disabled + ["--allowed-path", prefix])
            self.assertEqual(code, result.returncode, result.stderr)
            self.assertEqual(decision, report["content-policy"]["decision"])
            self.assertTrue(report["content-policy"]["incomplete"])
            self.assertFalse(report["analysis-complete"])
            self.assertNotIn("private-namespace-canary", json.dumps(report) + result.stderr.decode())
        for data in (b"\x7fELF" + bytes(60), b"#!/bin/sh\necho not-executed\n", b"unknown"):
            result, report = self.invoke(build([("Content/renamed.uasset", data, False)]),
                extra=["--allowed-path", "Content", "--allowed-class", "/Script/Engine.Actor"])
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertFalse(report["analysis-complete"])
            self.assertTrue(report["coverage"]["gaps"])

    @unittest.skipUnless(os.environ.get("OWNED_FIXTURE_EVIDENCE"), "set OWNED_FIXTURE_EVIDENCE for content-policy scan")
    def test_owned_content_classes_protected_candidates_and_partial_findings(self):
        content = Path(os.environ["OWNED_FIXTURE_EVIDENCE"]) / "tagged/OwnedFixtures/Content"
        header = (content / "BP_OwnedParent.uasset").read_bytes()
        exports = (content / "BP_OwnedParent.uexp").read_bytes()
        path = "Content/BP_OwnedParent"
        payload = build([(path + ".uasset", header, False), (path + ".uexp", exports, False)])
        disabled = ["--fail-on-any-forbidden", "false", "--fail-on-any-flagged", "false", "--fail-on-incomplete", "false"]
        root = ["--content-root", "Content=/Game"]
        for mode, expected, code in (("allow", "allow", 0), ("review", "needs-review", 1), ("reject", "reject", 1)):
            result, report = self.invoke(payload, extra=root + disabled + ["--protected-path", "content", "--replacement-policy", mode])
            self.assertEqual(code, result.returncode, result.stderr)
            self.assertEqual(expected, report["content-policy"]["decision"])
            self.assertTrue(report["analysis-complete"])
            self.assertEqual(1, report["counts"]["forbidden"])
            self.assertTrue(report["forbidden-invocations"])
        result, baseline = self.invoke(payload, extra=root + disabled)
        package = baseline["inspection"]["members"][0]
        self.assertTrue(package["parsed-classes"])
        self.assertTrue(all(c["provenance"].startswith("export-class-index-") for c in package["parsed-classes"]))
        classes = [arg for c in package["parsed-classes"] for arg in ("--allowed-class", c["identity"])]
        for inline in (False, True):
            source = build([(path + ".uasset", header + exports, False)]) if inline else payload
            result, report = self.invoke(source, extra=root + disabled + classes)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("allow", report["content-policy"]["decision"])
            self.assertEqual(not package["parsed-classes-complete"], report["content-policy"]["incomplete"])
            result, report = self.invoke(source, extra=root + disabled + ["--allowed-class", "/Script/Engine.Unrelated"])
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertEqual("reject", report["content-policy"]["decision"])
            self.assertEqual(1, report["counts"]["forbidden"])
        # Class rejection cannot erase invocation findings or earlier manifest members.
        corrupt = build([(path + ".uasset", header, False), (path + ".uexp", exports, False),
                         ("Content/later", b"bad", False)],
                        mutate=lambda metas, payloads: payloads.__setitem__(2, b"BAD"))
        result, report = self.invoke(corrupt, extra=root + disabled + ["--allowed-class", "/Script/Engine.Unrelated"])
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("reject", report["content-policy"]["decision"])
        self.assertEqual(1, report["counts"]["forbidden"])
        self.assertEqual(3, len(report["inspection"]["members"]))

    def test_invalid_content_config_does_not_disclose_verbose_invocation_policy(self):
        for settings in (["--allowed-path", "private-content-canary/../bad"],
                         ["--protected-path", "Content", "--replacement-policy", "allow", "--replacement-policy", "reject"]):
            result, _ = self.invoke(extra=[*settings, "--log-level", "verbose"])
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertNotIn(b"private-container-canary", result.stdout + result.stderr)
            self.assertNotIn(b"private-content-canary", result.stdout + result.stderr)

    @unittest.skipUnless(os.environ.get("OWNED_FIXTURE_EVIDENCE"), "set OWNED_FIXTURE_EVIDENCE for actual-class identity scan")
    def test_same_filename_different_actual_owned_classes(self):
        content = Path(os.environ["OWNED_FIXTURE_EVIDENCE"]) / "tagged/OwnedFixtures/Content"
        disabled = ["--fail-on-any-forbidden", "false", "--fail-on-any-flagged", "false", "--fail-on-incomplete", "false"]
        extra = ["--content-root", "Content=/Game", *disabled]
        def payload(stem):
            return build([("Content/Same.uasset", (content / (stem + ".uasset")).read_bytes(), False),
                          ("Content/Same.uexp", (content / (stem + ".uexp")).read_bytes(), False)])
        source = payload("Data/OwnedData")
        result, report = self.invoke(source, extra=extra)
        self.assertEqual(0, result.returncode, result.stderr)
        member = report["inspection"]["members"][0]
        self.assertTrue(member["parsed-classes-complete"])
        allowed = [arg for c in member["parsed-classes"] for arg in ("--allowed-class", c["identity"])]
        result, allowed_report = self.invoke(source, extra=extra + allowed)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(allowed_report["analysis-complete"])
        result, other = self.invoke(payload("BP_OwnedParent"), extra=extra + allowed)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("reject", other["content-policy"]["decision"])
        self.assertEqual(member["path"], other["inspection"]["members"][0]["path"])
        self.assertNotEqual(member["parsed-classes"], other["inspection"]["members"][0]["parsed-classes"])
        # Missing/synthetic corrupt package data stays incomplete under an allowlist.
        for source in (build([("Content/Same.uasset", (content / "BP_OwnedParent.uasset").read_bytes(), False)]),
                       build([("Content/Same.uasset", b"\xc1\x83\x2a\x9e" + bytes(20), False)])):
            result, partial = self.invoke(source, extra=extra + allowed)
            self.assertFalse(partial["analysis-complete"])
            self.assertTrue(partial["content-policy"]["incomplete"])
        # Additional signatures cannot mask a known class rejection when coverage gates are disabled.
        inline = (content / "BP_OwnedParent.uasset").read_bytes() + (content / "BP_OwnedParent.uexp").read_bytes()
        result, partial = self.invoke(build([("Content/Same.ini", inline, False)]), extra=extra + allowed)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("reject", partial["content-policy"]["decision"])

    @unittest.skipUnless(os.environ.get("OWNED_FIXTURE_EVIDENCE"), "set OWNED_FIXTURE_EVIDENCE for class ownership mutations")
    def test_serialized_class_ownership_coverage_is_independent_of_restrictions(self):
        fixtures = self.root / "class-fixtures"
        generated = subprocess.run(["dotnet", "run", "--project", str(ROOT / "tests/OwnedFixtures.Verify"),
            "-c", "Release", "--", os.environ["OWNED_FIXTURE_EVIDENCE"], "--class-fixtures", str(fixtures)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(0, generated.returncode, generated.stderr)
        cases = json.loads(generated.stdout)
        root = ["--content-root", "Content=/Game"]
        for case in cases:
            payload = build([("Content/Ownership.uasset", (fixtures / (case["name"] + ".uasset")).read_bytes(), False),
                             ("Content/Ownership.uexp", (fixtures / (case["name"] + ".uexp")).read_bytes(), False)])
            identity = case["identity"]
            allowed = identity or "/Script/OwnedFixtures.FixtureData"
            for settings in ([], ["--allowed-path", "Content"], ["--protected-path", "Other"], ["--allowed-class", allowed]):
                with self.subTest(case=case["name"], settings=settings):
                    result, report = self.invoke(payload, extra=root + settings)
                    member = report["inspection"]["members"][0]
                    self.assertEqual(identity is not None, member["parsed-classes-complete"])
                    self.assertEqual([] if identity is None else [identity], [c["identity"] for c in member["parsed-classes"]])
                    if identity is not None:
                        self.assertEqual("export-class-index-export" if case["name"] == "valid-local" else "export-class-index-import",
                                         member["parsed-classes"][0]["provenance"])
                    self.assertEqual("paired_export_data", report["inspection"]["members"][1]["inspection-status"])
                    # Unconfigured invocation-only behavior remains unchanged.
                    # Bounds failures already carry invocation-extraction gaps, even unconfigured.
                    incomplete = (bool(settings) and identity is None) or case["name"] in ("owner-out-of-range", "class-out-of-range")
                    self.assertEqual(int(incomplete), result.returncode, result.stderr)
                    self.assertEqual(not incomplete, report["analysis-complete"])
                    self.assertEqual(0, report["counts"]["invocations"])
                    if settings:
                        self.assertEqual("allow", report["content-policy"]["decision"])
                        self.assertEqual(identity is None, report["content-policy"]["incomplete"])
                        diagnostics = [f["diagnostic"] for f in report["content-policy"]["findings"]]
                        self.assertEqual(["class-inspection-unavailable"] if identity is None else [], diagnostics)
                    else:
                        self.assertNotIn("content-policy", report)

    @unittest.skipUnless(os.environ.get("OWNED_FIXTURE_EVIDENCE"), "set OWNED_FIXTURE_EVIDENCE for cooked-package scan")
    def test_real_cooked_calls_file_environment_direct_evaluator_and_hashes(self):
        original = Path(os.environ["OWNED_FIXTURE_EVIDENCE"])
        content = original / "tagged/OwnedFixtures/Content"
        members = []
        for stem, extension in (("BP_OwnedParent", "uasset"), ("BP_OwnedChild", "uasset"), ("OwnedMap", "umap")):
            for suffix in (extension, "uexp"):
                path = content / (stem + "." + suffix)
                members.append(("OwnedFixtures/Content/" + path.name, path.read_bytes(), False))
        payload = build(members)
        extra = ["--content-root", "OwnedFixtures/Content=/Game"]
        env, report = self.invoke(payload, extra=extra)
        file, other = self.invoke(payload, file=True, extra=extra)
        self.assertEqual((1, 1), (env.returncode, file.returncode))
        self.assertEqual(report, other)
        self.assertEqual(6, report["counts"]["invocations"])
        self.assertEqual(2, report["counts"]["forbidden"])
        self.assertTrue(report["analysis-complete"])
        hashes = {p: hashlib.sha256(data).hexdigest() for p, data, _ in members}
        self.assertEqual(hashes, {m["path"]: m["sha256"] for m in report["inspection"]["members"]})
        snapshot = self.root / "snapshot"
        scan.snapshot(self.root / "submission", snapshot, scan.INPUT_LIMIT)
        status, facts = self.docker.run(scan.mount(snapshot, "/input/submission"), "/usr/local/bin/python3",
            ["-m", "pak_ingest.container_parser", "-", "OwnedFixtures/Content", "/Game"], parser=True)
        self.assertEqual(0, status)
        facts_path, direct = self.root / "facts", self.root / "direct"
        facts_path.write_bytes(facts)
        result = subprocess.run(["dotnet", str(ROOT / "src/Scanner/bin/Release/net10.0/Scanner.dll"),
            "evaluate", "--facts", str(facts_path), "--report", str(direct), "--engine-version", "4.25"],
            env=dict(os.environ, UE_PAK_POLICY_RULES=POLICY), capture_output=True, timeout=15)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual(report, json.loads(direct.read_bytes()))
        # Real package summary/export data, not an extension-only fake.
        missing, partial = self.invoke(build([members[0]]), extra=extra)
        self.assertEqual(1, missing.returncode, missing.stderr)
        self.assertFalse(partial["analysis-complete"])
        self.assertIn("unsupported-parsing", partial["coverage"]["gaps"])
        # A later rejected entry must not erase previously verified package calls.
        corrupted = build(members[:2] + [("OwnedFixtures/Content/unknown", b"bad", False)],
            mutate=lambda metas, payloads: payloads.__setitem__(2, b"BAD"))
        failed, partial = self.invoke(corrupted, extra=extra)
        self.assertEqual(1, failed.returncode, failed.stderr)
        self.assertFalse(partial["analysis-complete"])
        self.assertEqual("rejected", partial["inspection"]["status"])
        self.assertEqual(1, partial["counts"]["forbidden"])
        self.assertEqual("entry_sha1", partial["inspection"]["diagnostic"])

    @unittest.skipUnless(os.environ.get("OWNED_FIXTURE_EVIDENCE"), "set OWNED_FIXTURE_EVIDENCE for paired-signature scan")
    def test_paired_exports_never_override_recognized_signatures(self):
        content = Path(os.environ["OWNED_FIXTURE_EVIDENCE"]) / "tagged/OwnedFixtures/Content"
        header = (content / "BP_OwnedParent.uasset").read_bytes()
        exports = (content / "BP_OwnedParent.uexp").read_bytes()
        path = "Content/BP_OwnedParent"
        extra = ["--content-root", "Content=/Game"]
        unrelated = POLICY.replace("function: RecordFixture", "function: Unrelated")
        # Exercise the production Read API with both split and inline cooked data.
        split, split_report = self.invoke(build([(path + ".uasset", header, False),
            (path + ".uexp", exports, False)]), policy=unrelated, extra=extra)
        inline, baseline = self.invoke(build([(path + ".uasset", header + exports, False)]),
                                       policy=unrelated, extra=extra)
        self.assertEqual((0, 0), (split.returncode, inline.returncode))
        self.assertTrue(split_report["analysis-complete"])
        self.assertTrue(baseline["analysis-complete"])
        self.assertGreater(baseline["counts"]["invocations"], 0)
        self.assertEqual(baseline["counts"], split_report["counts"])
        self.assertEqual("paired_export_data", split_report["inspection"]["members"][1]["inspection-status"])
        # Structural signature fixtures; none is executed or loaded as native code.
        pe = bytearray(90)
        pe[:2] = b"MZ"
        struct.pack_into("<I", pe, 60, 64)
        pe[64:68] = b"PE\0\0"
        struct.pack_into("<H", pe, 84, 2)
        pe[88:90] = b"\x0b\x01"
        samples = [("elf", b"\x7fELF" + bytes(60)),
                   ("pe", bytes(pe)), ("mach_o", b"\xcf\xfa\xed\xfe" + bytes(28)),
                   ("shebang", b"#!/bin/sh\necho not-executed\n")]
        for signature, data in samples:
            with self.subTest(signature=signature):
                members = [(path + ".uasset", header + exports, False), (path + ".uexp", data, False)]
                result, report = self.invoke(build(members), policy=unrelated, extra=extra)
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertEqual("partial", report["status"])
                self.assertFalse(report["analysis-complete"])
                self.assertIn("incomplete-extraction", report["coverage"]["gaps"])
                self.assertEqual(baseline["counts"], report["counts"])
                evidence = report["inspection"]["members"]
                self.assertEqual(2, len(evidence))
                self.assertEqual(signature, evidence[1]["signatures"][0])
                self.assertEqual(hashlib.sha256(data).hexdigest(), evidence[1]["sha256"])
                self.assertEqual("uninspected", evidence[1]["inspection-status"])
                for key in ("sha256", "signatures", "inspection-status", "classes"):
                    self.assertEqual(baseline["inspection"]["members"][0][key], evidence[0][key])
        result, report = self.invoke(build([(path + ".uasset", header + exports, False),
            (path + ".uexp", samples[0][1], False)]), extra=extra)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertFalse(report["analysis-complete"])
        self.assertEqual(1, report["counts"]["forbidden"])

    @unittest.skipUnless(os.environ.get("OWNED_FIXTURE_EVIDENCE"), "set OWNED_FIXTURE_EVIDENCE for adjacent inventory scan")
    def test_package_names_bulk_and_unpaired_content_retain_gaps(self):
        content = Path(os.environ["OWNED_FIXTURE_EVIDENCE"]) / "tagged/OwnedFixtures/Content"
        inline = (content / "BP_OwnedParent.uasset").read_bytes() + (content / "BP_OwnedParent.uexp").read_bytes()
        extra = ["--content-root", "Content=/Game"]
        unrelated = POLICY.replace("function: RecordFixture", "function: Unrelated")
        for suffix, signature in (("py", "script_candidate"), ("ini", "config_candidate")):
            with self.subTest(suffix=suffix):
                result, report = self.invoke(build([("Content/BP_OwnedParent." + suffix, inline, False)]),
                                             policy=unrelated, extra=extra)
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertFalse(report["analysis-complete"])
                self.assertGreater(report["counts"]["invocations"], 0)
                self.assertIn(signature, report["inspection"]["members"][0]["signatures"])
        for name, data, signature in (("BP_OwnedParent.ubulk", b"\x7fELF" + bytes(60), "elf"),
                                     ("BP_OwnedParent.ubulk", b"raw bulk", "unknown_content"),
                                     ("Other.uexp", b"raw exports", "unknown_content"),
                                     ("Other.bin", b"unknown", "unknown_content")):
            with self.subTest(name=name, signature=signature):
                result, report = self.invoke(build([("Content/BP_OwnedParent.uasset", inline, False),
                    ("Content/" + name, data, False)]), policy=unrelated, extra=extra)
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertFalse(report["analysis-complete"])
                self.assertGreater(report["counts"]["invocations"], 0)
                self.assertEqual(2, len(report["inspection"]["members"]))
                self.assertIn(signature, report["inspection"]["members"][1]["signatures"])
                self.assertEqual("uninspected", report["inspection"]["members"][1]["inspection-status"])

    @unittest.skipUnless(os.environ.get("OWNED_FIXTURE_EVIDENCE"), "set OWNED_FIXTURE_EVIDENCE for mapping scan")
    def test_real_unversioned_mapping_identity_and_missing_mapping(self):
        original = Path(os.environ["OWNED_FIXTURE_EVIDENCE"])
        content = original / "unversioned/OwnedFixtures/Content/Data"
        members = [("OwnedFixtures/Content/Data/" + p.name, p.read_bytes(), False)
                   for p in [content / "OwnedData.uasset", content / "OwnedData.uexp"]]
        payload = build(members)
        extra = ["--content-root", "OwnedFixtures/Content=/Game"]
        missing, partial = self.invoke(payload, extra=extra)
        self.assertEqual(1, missing.returncode, missing.stderr)
        self.assertFalse(partial["analysis-complete"])
        mapping = self.root / "mapping-source"
        mapping.write_bytes((original / "owned.usmap").read_bytes())
        valid, report = self.invoke(payload, extra=extra + ["--mapping", str(mapping)])
        self.assertEqual(0, valid.returncode, valid.stderr)
        self.assertTrue(report["analysis-complete"])
        self.assertEqual([{"kind": "mapping", "sha256": hashlib.sha256(mapping.read_bytes()).hexdigest()}], report["context"]["dependencies"])
