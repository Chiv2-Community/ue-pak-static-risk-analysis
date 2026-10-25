import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
DRIVER = ROOT / "scripts/cook_owned_fixtures.py"
TEMP_ROOT = "/tmp/opencode" if Path("/tmp/opencode").is_dir() else None


class CookDriverGuards(unittest.TestCase):
    def reject(self, *arguments):
        result = subprocess.run([sys.executable, str(DRIVER), *map(str, arguments)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        return result.stderr

    def test_refuses_checkout_output_before_engine_invocation(self):
        self.assertIn("outside this checkout", self.reject(ROOT / "must-not-be-created"))
        self.assertFalse((ROOT / "must-not-be-created").exists())

    def test_refuses_existing_external_directory(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as output:
            sentinel = Path(output) / "preserve.txt"
            sentinel.write_text("user work")
            self.assertIn("new directory", self.reject(output))
            self.assertEqual(sentinel.read_text(), "user work")

    def test_timeout_must_be_bounded_before_engine_invocation(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as parent:
            for timeout in (0, 3601):
                with self.subTest(timeout=timeout):
                    self.assertIn("1..3600", self.reject(Path(parent) / "new", "--timeout", timeout))


if __name__ == "__main__":
    unittest.main()
