import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("probe_pak", Path(__file__).parents[1] / "scripts" / "probe_pak.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FormatTests(unittest.TestCase):
    def test_only_evaluated_legacy_formats_pass(self):
        for compression in ("None", "Zlib"):
            MODULE.validate_format(Path("mod.pak"), f"version: V9\nencrypted index: false\ncompression: {compression}\n")

    def test_unavailable_keys_versions_codecs_are_explicit(self):
        for info in (
            "version: V11\nencrypted index: false\ncompression: Zlib",
            "version: V9\nencrypted index: true\ncompression: Zlib",
            "version: V9\nencrypted index: false\ncompression: Oodle",
            "version: V9\nencrypted index: false\ncompression: Zlib ,Oodle",
            "version: V9",
        ):
            with self.subTest(info=info), self.assertRaises(MODULE.UnsupportedInput):
                MODULE.validate_format(Path("mod.pak"), info)

    def test_iostore_companions_are_not_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            pak = Path(directory) / "mod.pak"
            pak.with_suffix(".utoc").touch()
            with self.assertRaises(MODULE.UnsupportedInput):
                MODULE.validate_format(pak, "version: V9\nencrypted index: false\ncompression: Zlib")

    def test_iostore_input_is_not_a_legacy_pak(self):
        with self.assertRaises(MODULE.UnsupportedInput):
            MODULE.validate_format(Path("mod.utoc"), "version: V9\nencrypted index: false\ncompression: Zlib")

    def test_missing_input_writes_error_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run([
                sys.executable, str(Path(__file__).parents[1] / "scripts" / "probe_pak.py"),
                "--pak", str(root / "missing.pak"),
                "--repak", str(root / "unused-repak"),
                "--probe-dll", str(root / "unused-probe.dll"),
                "--output", str(root / "output"),
            ], text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 1)
            report = json.loads((root / "output" / "experiment.json").read_text())
            self.assertEqual(report["status"], "error")
            self.assertFalse(report["analysis-complete"])
            self.assertFalse((root / "output" / "assets.json").exists())


if __name__ == "__main__":
    unittest.main()
