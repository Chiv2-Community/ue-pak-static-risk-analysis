"""Archive safety with isolated Git fixtures; no project commits or Docker."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import source_bundle as bundle


class SourceBundleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="source-bundle-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo, self.vendor = self.root / "project", self.root / "vendor"
        for repo in (self.repo, self.vendor):
            repo.mkdir()
            self.git(repo, "init", "-q")
        for name, value in {"LICENSE": "MIT", "NOTICE.md": "retained", "README.md": "upstream",
                            "UAssetAPI/Library.cs": "// upstream source", "UAssetAPI/UAssetAPI.csproj": "<Project/>",
                            "UAssetAPI/Resources/AC7Key.bin": "private-key-canary",
                            "UAssetAPI/repak_bind.so.gz": "native-binary-canary",
                            "UAssetAPI/Properties/Resources.resx": "resource-canary",
                            "UAssetAPI.Tests/borrowed.uasset": "borrowed-canary"}.items():
            self.write(self.vendor, name, value)
        self.pin = self.commit(self.vendor)
        self.pin_patch = patch.object(bundle, "UASSET", self.pin)
        self.pin_patch.start()
        self.addCleanup(self.pin_patch.stop)
        names = (bundle.ROOT_FILES - {"action-image.json"}) | bundle.CONTAINER_FILES | bundle.SCRIPT_FILES
        names |= {"src/Parser/Parser.csproj", "src/Parser/Program.cs", "src/Parser/packages.lock.json"}
        for name in names:
            self.write(self.repo, name, "tracked " + name)
        self.write(self.repo, "container/source-files.txt", "\n".join(sorted(names | {"action-image.json"})) + "\n")
        self.write(self.repo, "private-policy.yaml", "private-policy-canary")
        self.write(self.repo, "game.pak", "game-canary")
        self.git(self.repo, "add", ".")
        self.git(self.repo, "update-index", "--add", "--cacheinfo", "160000," + self.pin + ",vendor/UAssetAPI")
        self.a = self.commit(self.repo, add=False)

    def git(self, repo, *args):
        return subprocess.check_output(["git", "-C", str(repo), "-c", "user.name=Archive Test",
            "-c", "user.email=archive-test@example.invalid", *args], stderr=subprocess.DEVNULL).decode().strip()

    def write(self, repo, name, value):
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def commit(self, repo, add=True):
        if add:
            self.git(repo, "add", "--", ".", ":!vendor")
        self.git(repo, "commit", "-qm", "isolated archive fixture")
        return self.git(repo, "rev-parse", "HEAD")

    def collect(self, a=None, b=None):
        return bundle.collect(self.repo, a or self.a, b or self.a, self.vendor)

    def test_exact_git_bytes_exclusions_inventory_and_deterministic_archive(self):
        self.write(self.repo, "LICENSE", "dirty-workspace-canary")
        self.write(self.repo, "untracked-key.key", "untracked-canary")
        files = self.collect()
        self.assertEqual(b"tracked LICENSE", files["LICENSE"])
        joined = b"".join(files.values())
        for value in (b"dirty-workspace-canary", b"untracked-canary", b"private-policy-canary",
                      b"game-canary", b"private-key-canary", b"native-binary-canary", b"borrowed-canary", b"resource-canary"):
            self.assertNotIn(value, joined)
        manifest = json.loads(files["SOURCE-MANIFEST.json"])
        self.assertEqual(self.a, manifest["build-source"])
        self.assertEqual(self.a, manifest["action-source"])
        for item in manifest["files"]:
            self.assertEqual(hashlib.sha256(files[item["path"]]).hexdigest(), item["sha256"])
            self.assertEqual(len(files[item["path"]]), item["bytes"])
        first, second = self.root / "first.tar.gz", self.root / "second.tar.gz"
        bundle.archive(files, first)
        bundle.archive(files, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        unpacked = self.root / "unpacked"
        with tarfile.open(first) as tar:
            self.assertTrue(all(m.isfile() and m.uid == m.gid == m.mtime == 0 for m in tar))
            tar.extractall(unpacked, filter="data")
        self.assertFalse(list(unpacked.rglob(".git")))
        self.assertTrue((unpacked / "ue-pak-static-risk-analysis/vendor/UAssetAPI/UAssetAPI/Library.cs").is_file())
        with self.assertRaises(FileExistsError):
            bundle.archive(files, first)

    def test_action_only_commit_b_records_but_preserves_image_source_a(self):
        pin = {"version": "v0.1.0", "platform": "linux/amd64", "build-source": self.a,
               "image": "ghcr.io/chiv2-community/ue-pak-static-risk-analysis@sha256:" + "b" * 64}
        self.write(self.repo, "action-image.json", json.dumps(pin))
        b = self.commit(self.repo)
        manifest = json.loads(self.collect(b=b)["SOURCE-MANIFEST.json"])
        self.assertEqual(self.a, manifest["build-source"])
        self.assertEqual(b, manifest["action-source"])

    def test_action_manifest_build_source_must_equal_archive_build_source(self):
        pin = {"version": "v0.1.0", "platform": "linux/amd64", "build-source": "f" * 40,
               "image": "ghcr.io/chiv2-community/ue-pak-static-risk-analysis@sha256:" + "b" * 64}
        self.write(self.repo, "action-image.json", json.dumps(pin))
        b = self.commit(self.repo)
        with self.assertRaises(ValueError):
            self.collect(b=b)

    def test_changed_image_input_between_a_and_b_is_rejected(self):
        self.write(self.repo, "src/Parser/Program.cs", "changed image")
        b = self.commit(self.repo)
        with self.assertRaises(ValueError):
            self.collect(b=b)

    def test_selected_symlinks_are_rejected_not_followed(self):
        (self.repo / "LICENSE").unlink()
        (self.repo / "LICENSE").symlink_to("/private/key")
        b = self.commit(self.repo)
        with self.assertRaises(ValueError):
            self.collect(a=b, b=b)

    def test_unlisted_new_runtime_file_and_missing_inventory_file_are_rejected(self):
        self.write(self.repo, "src/Parser/secret.json", "should-not-package")
        b = self.commit(self.repo)
        with self.assertRaises(ValueError):
            self.collect(a=b, b=b)
        (self.repo / "src/Parser/secret.json").unlink()
        (self.repo / "scripts/scan.py").unlink()
        c = self.commit(self.repo)
        with self.assertRaises(ValueError):
            self.collect(a=c, b=c)

    def test_commit_references_and_wrong_pinned_submodule_are_rejected(self):
        for commit in ("HEAD", "main", "a" * 39, "A" * 40):
            with self.assertRaises(ValueError):
                bundle.tree(self.repo, commit)
        with patch.object(bundle, "UASSET", "f" * 40), self.assertRaises(ValueError):
            self.collect()

    def test_inventory_is_closed_and_excludes_all_other_vendor_inputs(self):
        inventory = (ROOT / "container/source-files.txt").read_text().splitlines()
        self.assertEqual(len(inventory), len(set(inventory)))
        self.assertTrue(all(bundle.allowed(p) for p in inventory))
        for path in inventory:
            if path != "action-image.json":
                self.assertTrue((ROOT / path).is_file(), path)
        for path in ("vendor/repak/Cargo.toml", "vendor/UAssetAPI/UAssetAPI.Tests/test.uasset", ".git/config",
                     ".env", "keys.key", "production-policy.yaml", "fixtures/game.pak"):
            self.assertFalse(bundle.allowed(path), path)


if __name__ == "__main__":
    unittest.main()
