import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from ingestion_fixture import build
from pak_ingest import Limits, ingest
from pak_ingest.reader import parse, signatures
from pak_ingest import supervisor
from pak_ingest.worker import Budget
from pak_ingest import worker


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.path = self.root / "input.pak"

    def ingest(self, data=None, limits=None, **kwargs):
        if data is not None:
            self.path.write_bytes(data)
        result = ingest(self.path, limits=limits, scratch_parent=self.scratch, **kwargs)
        self.assertEqual(list(self.scratch.iterdir()), [], "scratch leaked")
        self.assertFalse(result["analysis_complete"])
        return result

    def rejected(self, data, diagnostic, limits=None):
        result = self.ingest(data, limits)
        self.assertEqual(result["ingestion_status"], "rejected", result)
        self.assertEqual(result["diagnostic"], diagnostic, result)
        return result

    def test_positive_none_zlib_empty_and_hashes(self):
        members = [("Content/a", b"\x7fELF" + b"x" * 50000, False),
                   ("Content/b", bytes(range(256)) * 300, True), ("Content/empty", b"", False)]
        data = build(members)
        result = self.ingest(data, namespaces=["Content"], protected=["Content/a"])
        self.assertEqual(result["ingestion_status"], "validated", result)
        self.assertEqual(result["input_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual([r["sha256"] for r in result["records"]],
                         [hashlib.sha256(m[1]).hexdigest() for m in members])
        self.assertTrue(result["records"][0]["replacement_candidate"])
        self.assertFalse(result["records"][1]["replacement_candidate"])
        self.assertIn("elf", result["records"][0]["signatures"])
        self.assertFalse(result["containment"]["os_aggregate_storage_quota"])

    def test_boundary_prefixes_and_mount(self):
        result = self.ingest(build([("Contention/a", b"", False)], mount="../../../Project/"),
                             namespaces=["Project/Content"], protected=["Project/Content"])
        self.assertEqual(result["ingestion_status"], "validated")
        self.assertEqual(result["records"][0]["virtual_path"], "Project/Contention/a")
        self.assertFalse(result["records"][0]["namespace_match"])

    def test_names_and_prefix_conflicts(self):
        for names, code in [(["x", "x"], "duplicate_or_case_collision"),
                            (["x", "X"], "duplicate_or_case_collision"),
                            (["a/b", "a", "a-b"], "path_prefix_conflict")]:
            with self.subTest(names=names):
                result = self.rejected(build([(n, b"", False) for n in names]), code)
                self.assertEqual([r["raw_name"] for r in result["records"]], names)
                self.assertTrue(all(r["status"] == "uninspected" for r in result["records"]))

    def test_unsafe_paths(self):
        for name in ("../x", "a/../x", "/absolute", "a//x", "a/./x", "C:x", "a\\b", "nul.txt", "a. ", "a?", "a*"):
            with self.subTest(name=name):
                self.rejected(build([(name, b"", False)]), "unsafe_path")
        self.rejected(build(mount="../../../../"), "unsafe_path")
        self.rejected(build(mount="/absolute/"), "unsupported_mount")

    def test_footer_and_codec_checks(self):
        changes = [(0, 1, "unsupported_encryption"), (16, 1, "unsupported_encryption"),
                   (17, 0, "invalid_magic"), (21, 8, "unsupported_version"),
                   (61, 1, "unsupported_frozen_index"), (62, ord("X"), "unsupported_codec"),
                   (67, 1, "invalid_codec_slot"), (29, 255, "index_bounds")]
        for offset, value, code in changes:
            with self.subTest(offset=offset):
                self.rejected(build(footer_mutate=lambda f: f.__setitem__(offset, value)), code)
        self.rejected(b"small", "truncated_footer")
        data = bytearray(build())
        data[-222 - 1] ^= 1
        self.rejected(data, "index_sha1")

    def test_index_counts_strings_and_trailing(self):
        self.rejected(build(index_mutate=lambda i: i.extend(b"x")), "index_trailing_data")
        self.rejected(build(index_mutate=lambda i: i.__setitem__(slice(0, 4), b"\xff" * 4)),
                      "string_limit_or_encoding")
        self.rejected(build(index_mutate=lambda i: i.__setitem__(4, 255)), "non_ascii_path")
        self.rejected(build(index_mutate=lambda i: i.__setitem__(slice(4, 5), b"\0")), "invalid_string")
        self.rejected(build(index_mutate=lambda i: i.__setitem__(slice(14, 18), b"\xff" * 4)), "entry_limit")

    def test_entry_structural_checks(self):
        cases = [("flags", 1, "unsupported_entry_flags"), ("flags", 2, "unsupported_entry_flags"),
                 ("flags", 4, "unsupported_entry_flags"),
                 ("output", 4, "invalid_plain_layout"), ("block_size", 1, "invalid_plain_layout"),
                 ("stored", 99999, "entry_bounds")]
        for key, value, code in cases:
            with self.subTest(key=key, value=value):
                self.rejected(build(mutate=lambda m, p: m[0].__setitem__(key, value)), code)
        self.rejected(build(local_mutate=lambda n, h: h.__setitem__(0, 1)), "local_header_mismatch")
        # Start with real blocks: a plain entry relabeled compressed would fail
        # block parsing before reaching codec validation.
        self.rejected(build([("a", b"owned", True)],
                            mutate=lambda m, p: m[0].__setitem__("codec", 6)),
                      "unsupported_entry_codec")

    def test_overlap(self):
        # Identical empty headers at offset zero make local validation pass.
        self.rejected(build([("a", b"", False), ("b", b"", False)],
                            mutate=lambda m, p: m[1].__setitem__("offset", 0)), "entry_overlap")

    def test_block_checks(self):
        members = [("a", b"abcd" * 10000, True)]
        for key, value, code in [("block_size", 0, "invalid_block_size"),
                                 ("block_size", 1, "invalid_block_count"),
                                 ("blocks", [(1, 2), (2, 3)], "invalid_block_layout")]:
            with self.subTest(key=key):
                self.rejected(build(members, mutate=lambda m, p: m[0].__setitem__(key, value)), code)
        self.rejected(build(members), "block_limit", dataclasses.replace(Limits(), blocks=1))

    def test_payload_hash(self):
        data = bytearray(build())
        data[53] ^= 1
        result = self.rejected(data, "entry_sha1")
        self.assertEqual(result["records"][0]["status"], "rejected")
        self.assertIn("input_sha256", result)

    def test_exact_zlib(self):
        def change_payload(transform):
            def mutate(metas, payloads):
                payloads[0] = transform(payloads[0])
                meta = metas[0]
                meta["stored"] = len(payloads[0])
                meta["digest"] = hashlib.sha1(payloads[0]).digest()
                meta["blocks"] = [(73, 73 + len(payloads[0]))]
            return mutate
        members = [("a", b"owned bytes", True)]
        self.rejected(build(members, mutate=change_payload(lambda p: p + p)), "zlib_trailing_data")
        self.rejected(build(members, mutate=change_payload(lambda p: p[:-1])), "zlib_incomplete")
        self.rejected(build(members, mutate=change_payload(lambda p: b"XX" + p[2:])), "invalid_zlib_stream")
        self.rejected(build(members, mutate=lambda m, p: m[0].__setitem__("output", 1)), "output_size_mismatch")
        self.rejected(build(members, mutate=lambda m, p: m[0].__setitem__("output", 100)), "output_size_mismatch")

    def test_quotas(self):
        for key, value, code in [("input_bytes", 10, "input_limit"), ("index_bytes", 10, "index_limit"),
                                 ("string_bytes", 2, "string_limit_or_encoding"),
                                 ("member_bytes", 1, "member_limit"),
                                 ("total_output_bytes", 1, "total_output_limit"),
                                 ("scratch_bytes", 1024, "scratch_limit"),
                                 ("report_bytes", 512, "report_limit")]:
            with self.subTest(key=key):
                self.rejected(build(), code, dataclasses.replace(Limits(), **{key: value}))
        self.rejected(build([("a", b"x" * 1000, True)]), "expansion_limit",
                      dataclasses.replace(Limits(), expansion_ratio=1))
        self.rejected(build([("a", b"", False), ("b", b"", False)]), "entry_limit",
                      dataclasses.replace(Limits(), entries=1))

    def test_scratch_quota_during_payload_preserves_hash(self):
        data = build([("a", b"x" * 5000, False)])
        result = self.rejected(data, "scratch_limit", dataclasses.replace(Limits(), scratch_bytes=8000))
        self.assertEqual(result["input_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["structure_status"], "validated")
        self.assertEqual(result["records"][0]["status"], "rejected")
        self.assertLessEqual(result["scratch_bytes_written"], 8000)

    def test_sidecars_inline_and_orphans(self):
        result = self.ingest(build([(n, b"", False) for n in
                                   ("a.uasset", "b.uasset", "b.uexp", "z.ubulk")]))
        self.assertEqual(result["ingestion_status"], "validated")
        a, b, side, orphan = result["records"]
        self.assertEqual(a["sidecars"], [])
        self.assertEqual(a["sidecar_status"], "required_sidecars_unresolved")
        self.assertEqual(b["sidecars"], [side["id"]])
        self.assertEqual(orphan["sidecar_status"], "orphan")

    def test_input_symlink_fifo_directory_and_secret_canary(self):
        canary = "CONFIDENTIAL_CANARY_NO_ERRORS"
        secret = self.root / canary
        secret.write_bytes(build())
        self.path.symlink_to(secret)
        result = self.ingest()
        self.assertEqual(result["ingestion_status"], "rejected")
        self.assertNotIn(canary, json.dumps(result))
        self.path.unlink()
        os.mkfifo(self.path)
        self.assertEqual(self.ingest()["ingestion_status"], "rejected")
        self.path.unlink()
        self.path.mkdir()
        self.assertEqual(self.ingest()["ingestion_status"], "rejected")

    def test_unknown_text_and_signatures(self):
        self.assertEqual(signatures(b"harmless?", "a.txt"), ["unknown_content"])
        self.assertEqual(signatures(b"MZbad", "a.dll"), ["unknown_content"])
        self.assertIn("unknown_content", signatures(b"x", "a.py"))
        self.assertIn("script_candidate", signatures(b"x", "a.py"))
        self.assertIn("config_candidate", signatures(b"x", "a.ini"))
        self.assertIn("shebang", signatures(b"#!/bin/sh", "a.bin"))
        self.assertIn("mach_o", signatures(b"\xcf\xfa\xed\xfe", "a.bin"))
        self.assertIn("unreal_package_tag", signatures(b"\xc1\x83\x2a\x9e", "a.bin"))
        pe = bytearray(512)
        pe[:2] = b"MZ"
        pe[60:64] = (64).to_bytes(4, "little")
        pe[64:68] = b"PE\0\0"
        pe[84:86] = (224).to_bytes(2, "little")
        pe[88:90] = b"\x0b\x01"
        self.assertIn("pe", signatures(pe, "a.bin"))
        pe[84:86] = b"\xff\xff"
        self.assertNotIn("pe", signatures(pe, "a.bin"))

    def test_cancel_timeout_environment_and_group_cleanup(self):
        self.path.write_bytes(build([("a", b"x" * 1000000, False)]))
        cancel = threading.Event()
        cancel.set()
        with mock.patch.dict(os.environ, {"POLICY_SECRET": "canary"}), \
                mock.patch.object(supervisor.subprocess, "Popen", wraps=subprocess.Popen) as launch, \
                mock.patch.object(supervisor.os, "killpg", wraps=os.killpg) as kill:
            result = self.ingest(cancel=cancel)
            self.assertEqual(result["diagnostic"], "cancelled")
            self.assertEqual(launch.call_args.kwargs["env"], {"LANG": "C", "LC_ALL": "C"})
            self.assertEqual(launch.call_args.kwargs["stdout"], subprocess.DEVNULL)
            self.assertTrue(launch.call_args.kwargs["start_new_session"])
            self.assertEqual(kill.call_args.args[1], signal.SIGKILL)
        with mock.patch.object(supervisor.time, "monotonic", side_effect=[0, 100]):
            self.assertEqual(self.ingest()["diagnostic"], "wall_timeout")

    def test_partial_evidence_on_cancel(self):
        data = build([(f"a/{i}", b"", False) for i in range(3000)])
        scratch = self.scratch

        class CancelAfterHash:
            def is_set(self):
                return any(b"input_sha256" in p.read_bytes()
                           for p in scratch.glob("*/events.jsonl"))

        result = self.ingest(data, cancel=CancelAfterHash())
        self.assertEqual(result["diagnostic"], "cancelled")
        self.assertEqual(result["input_sha256"], hashlib.sha256(data).hexdigest())

    def test_fail_closed_platform_and_invalid_config(self):
        with mock.patch.object(supervisor, "supported", return_value=False):
            self.assertEqual(self.ingest(build())["diagnostic"], "unsupported_resource_platform")
        self.assertEqual(self.ingest(build(), namespaces=["../secret"])["diagnostic"], "invalid_configuration")
        with self.assertRaisesRegex(ValueError, "invalid_limits"):
            ingest(self.path, limits=dataclasses.replace(Limits(), entries=True))

    def test_budget_counts_all_writes(self):
        budget, output = Budget(1024), io.BytesIO()
        budget.write(output, b"x" * 512)
        with self.assertRaisesRegex(Exception, "scratch_limit"):
            budget.write(output, b"x")
        budget.write(output, b"y" * 512, terminal=True)
        self.assertEqual(budget.used, 1024)

    def test_no_payload_writes_before_complete_validation(self):
        data = build([("a", b"x", False), ("a", b"y", False)])
        events = []
        with self.assertRaisesRegex(Exception, "duplicate_or_case_collision"):
            parse(io.BytesIO(data), len(data), Limits(), events.append)
        self.assertEqual(len([e for e in events if "record" in e]), 4)

    def test_snapshot_is_same_bytes_hashed_and_extracted(self):
        data = build()
        self.path.write_bytes(data)
        old_cwd = os.getcwd()
        self.addCleanup(os.chdir, old_cwd)
        os.chdir(self.scratch)
        real_parse = worker.parse

        def replace_original(*args, **kwargs):
            self.path.write_bytes(b"different input after snapshot")
            return real_parse(*args, **kwargs)

        request = {"input": str(self.path), "limits": Limits().as_dict(), "namespaces": [], "protected": []}
        with mock.patch.object(worker, "resource_limits"), \
                mock.patch.object(worker, "parse", side_effect=replace_original):
            self.assertEqual(worker.run(request), 0)
        events = [json.loads(line) for line in (self.scratch / "events.jsonl").read_text().splitlines()]
        self.assertEqual(next(e["input_sha256"] for e in events if "input_sha256" in e),
                         hashlib.sha256(data).hexdigest())
        self.assertEqual((self.scratch / "r00000000").read_bytes(), b"owned")
        self.assertEqual((self.scratch / "snapshot").stat().st_mode & 0o777, 0o400)
        self.assertEqual((self.scratch / "r00000000").stat().st_mode & 0o777, 0o600)
        self.assertEqual(events[-1]["scratch_bytes_written"],
                         sum(p.stat().st_size for p in self.scratch.iterdir()))

    def test_resource_limits_are_set_and_fsize_fails_closed(self):
        import resource
        with mock.patch.object(resource, "setrlimit") as setting:
            worker.resource_limits(Limits())
        applied = {call.args[0]: call.args[1] for call in setting.call_args_list}
        self.assertEqual(applied[resource.RLIMIT_CPU], (20, 20))
        self.assertEqual(applied[resource.RLIMIT_AS], (512 * 1024 * 1024,) * 2)
        self.assertEqual(applied[resource.RLIMIT_FSIZE], (512 * 1024 * 1024,) * 2)
        self.assertEqual(applied[resource.RLIMIT_NOFILE], (32, 32))
        self.assertEqual(applied[resource.RLIMIT_CORE], (0, 0))
        result = self.ingest(build([("a", b"x" * 4096, False)]),
                             limits=dataclasses.replace(Limits(), file_bytes=1024))
        self.assertEqual(result["ingestion_status"], "rejected")
        with mock.patch.object(resource, "setrlimit", side_effect=ValueError("PRIVATE_CANARY")):
            # Limit failures must not echo runtime exception values.
            old_cwd = os.getcwd()
            try:
                os.chdir(self.scratch)
                self.assertEqual(worker.run({"limits": Limits().as_dict()}), 1)
            finally:
                os.chdir(old_cwd)
        self.assertNotIn("PRIVATE_CANARY", (self.scratch / "events.jsonl").read_text())

    def test_exclusive_nofollow_payload_open(self):
        target = self.root / "canary"
        target.write_bytes(b"unchanged")
        link = self.root / "r00000000"
        link.symlink_to(target)
        with self.assertRaises(FileExistsError):
            worker.exclusive(link)
        self.assertEqual(target.read_bytes(), b"unchanged")

    @unittest.skipUnless(Path("/tmp/opencode/ue-pak-repak/target/release/repak").is_file(), "local pinned repak absent")
    def test_optional_repak_differential(self):
        data = build([("Content/a", b"owned bytes" * 10000, True), ("Content/b", b"plain", False)])
        self.path.write_bytes(data)
        output = self.root / "repak-output"
        process = subprocess.run(["/tmp/opencode/ue-pak-repak/target/release/repak", "unpack",
                                  str(self.path), "--output", str(output)], capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, "local repak positive differential failed")
        self.assertEqual((output / "Content/a").read_bytes(), b"owned bytes" * 10000)
        self.assertEqual((output / "Content/b").read_bytes(), b"plain")
        self.assertEqual(self.ingest()["ingestion_status"], "validated")


if __name__ == "__main__":
    unittest.main()
