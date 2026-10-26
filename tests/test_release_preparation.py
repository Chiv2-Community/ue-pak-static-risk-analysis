"""Public prebuilt preparation without network, Docker execution or real digests."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import action


class PublishedImageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="release-unit-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / "output"
        self.output.touch()
        self.pin = {"version": "v0.1.0", "platform": "linux/amd64", "build-source": "a" * 40,
                    "image": "ghcr.io/chiv2-community/ue-pak-static-risk-analysis@sha256:" + "b" * 64}
        self.manifest = self.root / "action-image.json"
        self.root_patch = patch.object(action, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def write(self, value=None):
        self.manifest.write_text(json.dumps(self.pin if value is None else value))

    def test_absent_manifest_is_only_automatic_development_fallback(self):
        with patch.object(action, "prepare_local") as local:
            action.prepare()
        local.assert_called_once_with()

    def test_public_pull_digest_platform_and_isolated_environment_no_build(self):
        self.write()
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            self.assertEqual("/usr/bin/docker", command[0])
            self.assertEqual({"PATH", "LANG", "HOME"}, set(kwargs["env"]))
            config = Path(command[command.index("--config") + 1])
            self.assertEqual([], list(config.iterdir()))
            self.assertEqual([], list(Path(kwargs["env"]["HOME"]).iterdir()))
            self.assertNotIn("login", command)
            self.assertNotIn("build", command)
            self.assertEqual(subprocess.DEVNULL, kwargs["stdin"])
            value = json.dumps([self.pin["image"]]).encode() if "{{json .RepoDigests}}" in command else b"linux/amd64\n"
            return subprocess.CompletedProcess(command, 0, stdout=value)
        env = {"GITHUB_OUTPUT": str(self.output), "DOCKER_CONFIG": "/private/config", "HOME": "/private/home",
               "GITHUB_TOKEN": "secret", "UE_PAK_POLICY_RULES": "private", "SSH_AUTH_SOCK": "/private/agent"}
        with patch.dict(os.environ, env, clear=True), patch.object(action.subprocess, "run", side_effect=run), patch.object(action, "prepare_local") as local:
            action.prepare()
        local.assert_not_called()
        self.assertEqual(["pull", "--platform", "linux/amd64", self.pin["image"]], calls[0][-4:])
        self.assertEqual("image=" + self.pin["image"] + "\n", self.output.read_text())

    def test_bad_manifests_never_build_or_invoke_docker(self):
        cases = [[], {}, dict(self.pin, extra=True), dict(self.pin, version="v1"),
                 dict(self.pin, platform="linux/arm64"), dict(self.pin, **{"build-source": "main"}),
                 dict(self.pin, image="ghcr.io/attacker/scanner@sha256:" + "b" * 64),
                 dict(self.pin, image=self.pin["image"].upper()),
                 dict(self.pin, image="sha256:" + "b" * 64),
                 dict(self.pin, image="ghcr.io/chiv2-community/ue-pak-static-risk-analysis:v0.1.0")]
        for value in cases:
            with self.subTest(value=value):
                self.write(value)
                with patch.object(action, "prepare_local") as local, patch.object(action.subprocess, "run") as run:
                    with self.assertRaises(ValueError):
                        action.prepare()
                local.assert_not_called()
                run.assert_not_called()

    def test_duplicate_key_invalid_json_and_size_fail_closed(self):
        for raw in ('{"version":"v0.1.0","version":"v0.1.0"}', '{', 'x' * 4097):
            self.manifest.write_text(raw)
            with self.assertRaises(ValueError):
                action.published_image()

    def test_manifest_symlink_including_dangling_is_not_absence(self):
        self.manifest.symlink_to(self.root / "missing")
        with self.assertRaises((OSError, ValueError)):
            action.published_image()
        self.manifest.unlink()
        self.write()
        self.manifest.rename(self.root / "other")
        self.manifest.symlink_to(self.root / "other")
        with self.assertRaises((OSError, ValueError)):
            action.published_image()

    def test_pull_failure_digest_mismatch_and_wrong_architecture_emit_no_image(self):
        self.write()
        for mode in ("pull-failed", "config-id", "wrong-arch"):
            def run(command, **kwargs):
                if mode == "pull-failed":
                    raise subprocess.CalledProcessError(1, command)
                value = json.dumps(["sha256:" + "b" * 64] if mode == "config-id" else [self.pin["image"]]).encode()
                if "{{.Os}}/{{.Architecture}}" in command:
                    value = b"linux/arm64"
                return subprocess.CompletedProcess(command, 0, stdout=value)
            with self.subTest(mode=mode), patch.dict(os.environ, GITHUB_OUTPUT=str(self.output)), patch.object(action.subprocess, "run", side_effect=run), patch.object(action, "prepare_local") as local:
                with self.assertRaises((ValueError, subprocess.SubprocessError)):
                    action.prepare()
                self.assertEqual("", self.output.read_text())
                local.assert_not_called()

    def test_checked_in_licenses_and_manual_workflow_contract(self):
        import yaml
        workflow = yaml.safe_load((ROOT / ".github/workflows/release-candidate.yml").read_text())
        triggers = workflow.get("on", workflow.get(True))  # PyYAML YAML 1.1 boolean key.
        self.assertEqual({"workflow_dispatch": None}, triggers)
        self.assertEqual({"contents": "read"}, workflow["permissions"])
        self.assertNotIn("permissions", workflow["jobs"]["validate"])
        self.assertEqual("write", workflow["jobs"]["publish"]["permissions"]["packages"])
        source = (ROOT / ".github/workflows/release-candidate.yml").read_text()
        self.assertNotIn("gh release", source)
        self.assertNotIn("git push", source)
        self.assertIn("--password-stdin", source)
        license = (ROOT / "LICENSE").read_text()
        self.assertIn("END OF TERMS AND CONDITIONS", license)
        self.assertIn("How to Apply These Terms", license)
        self.assertGreater(len(license), 35000)
        dockerfile = (ROOT / "Dockerfile").read_text()
        for name in ("COPY LICENSE", "COPY container/CORRESPONDING-SOURCE.md", "ThirdPartyNotices.txt", "python3.12/LICENSE.txt"):
            self.assertIn(name, dockerfile)
        self.assertNotIn("action-image.json", dockerfile)


if __name__ == "__main__":
    unittest.main()
