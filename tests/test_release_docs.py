"""Keep operator input tables aligned with shipped command surfaces."""

import ast
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = (ROOT / "docs/inputs.md").read_text()


def section(title):
    return REFERENCE.split("## " + title + "\n", 1)[1].split("\n## ", 1)[0]


def rows(text):
    return {match[0]: match[1:] for match in re.findall(
        r"^\| `([^`]+)` \| ([^|]+) \| ([^|]+) \| ([^|]+) \| (.+) \|$",
        text, re.MULTILINE)}


class ReleaseDocumentationTests(unittest.TestCase):
    def test_host_options_all_documented(self):
        tree = ast.parse((ROOT / "scripts/scan.py").read_text())
        options = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                       and node.name == "options")
        flags = set()
        for node in ast.walk(options):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument":
                if isinstance(node.args[0], ast.Constant) and str(node.args[0].value).startswith("--"):
                    flags.add(node.args[0].value)
            if isinstance(node, ast.For) and isinstance(node.iter, ast.Tuple):
                flags.update("--" + ast.literal_eval(value) for value in node.iter.elts)
        documented = rows(section("Host scanner"))
        self.assertEqual(flags, {key for key in documented if key.startswith("--")})

    def test_shared_options_all_documented(self):
        source = (ROOT / "src/Scanner/Program.cs").read_text()
        allowed = source.split('var allowed = new HashSet<string>', 1)[1].split(';', 1)[0]
        flags = {"--" + value for value in re.findall(r'"([a-z0-9-]+)"', allowed)}
        content = (ROOT / "src/Scanner/ContentPolicy.cs").read_text()
        flags.update(re.findall(r'\["(--[a-z-]+)"\] = \[\]', content))
        self.assertEqual(flags, {key for key in rows(section("Shared evaluator")) if key.startswith("--")})

    def test_host_explicit_defaults(self):
        tree = ast.parse((ROOT / "scripts/scan.py").read_text())
        documented = rows(section("Host scanner"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_argument" and node.args
                    and isinstance(node.args[0], ast.Constant)):
                continue
            flag = node.args[0].value
            for keyword in node.keywords:
                if keyword.arg == "default":
                    value = ast.literal_eval(keyword.value)
                    if isinstance(value, list):
                        continue  # Transport append list; evaluator supplies effective default.
                    self.assertEqual(str(value),
                                     documented[flag][1].strip().strip("`"), flag)
        content = (ROOT / "src/Scanner/ContentPolicy.cs").read_text()
        self.assertIn('SingleOrDefault() ?? "review"', content)
        self.assertIn('`review` when protected paths exist', documented['--replacement-policy'][1])
        for title in ("Host scanner", "Shared evaluator", "Action inputs"):
            table = rows(section(title))
            prefix = "" if title == "Action inputs" else "--"
            for name, expected in (("fail-on-any-forbidden", "true"),
                                   ("fail-on-any-flagged", "false"), ("fail-on-incomplete", "true")):
                self.assertEqual(expected, table[prefix + name][1].strip().strip("`"))

    def test_operator_code_blocks_do_not_publish(self):
        for name in ("operators.md", "releases.md", "inputs.md"):
            blocks = re.findall(r"```[^\n]*\n(.*?)```", (ROOT / "docs" / name).read_text(), re.DOTALL)
            for block in blocks:
                self.assertIsNone(re.search(r"docker\s+(?:push|login)|gh\s+release|git\s+(?:push|tag)\b|packages:\s*write", block))

    def test_auxiliary_flags_are_documented(self):
        for filename, title in (("regression_corpus.py", "Regression runner"),
                                ("probe_pak.py", "Experimental/fixture tools"),
                                ("cook_owned_fixtures.py", "Experimental/fixture tools"),
                                ("owned_fixture_usmap.py", "Experimental/fixture tools")):
            tree = ast.parse((ROOT / "scripts" / filename).read_text())
            flags = {node.args[0].value for node in ast.walk(tree)
                     if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                     and node.func.attr == "add_argument" and node.args
                     and isinstance(node.args[0], ast.Constant)}
            self.assertTrue(flags <= rows(section(title)).keys(), filename)

    def test_action_inputs_defaults_and_enum_values(self):
        source = (ROOT / "action.yml").read_text().split("inputs:\n", 1)[1].split("outputs:\n", 1)[0]
        blocks = re.findall(r"^  ([a-z-]+):\n((?:    .*\n)+)", source, re.MULTILINE)
        documented = rows(section("Action inputs"))
        self.assertEqual({key for key, _ in blocks}, set(documented))
        for key, block in blocks:
            default = re.search(r"^    default: '?([^'\n]+)'?$", block, re.MULTILINE)
            expected = default[1] if default else "required" if "required: true" in block else "none"
            self.assertEqual(expected, documented[key][1].strip().strip("`"), key)
        for key in ("log-level", "fail-on-any-forbidden", "fail-on-any-flagged", "fail-on-incomplete"):
            values = ("error", "warn", "info", "verbose") if key == "log-level" else ("true", "false")
            self.assertEqual(set(values), set(re.findall(r"`([^`]+)`", documented[key][0])))

    def test_log_input_has_disclosure_warning(self):
        for title in ("Host scanner", "Shared evaluator", "Action inputs"):
            description = rows(section(title))["log-level" if title == "Action inputs" else "--log-level"][-1].lower()
            for phrase in ("verbose", "full policy", "anyone with log access", "admin", "masked"):
                self.assertIn(phrase, description, title)
        action = (ROOT / "action.yml").read_text().split("  log-level:\n", 1)[1].split("  fail-on-", 1)[0].lower()
        for phrase in ("full policy", "anyone with log access", "not masked secrets", "step setup", "administrators", "outside scanner logs"):
            self.assertIn(phrase, action)

    def test_new_guide_local_links_exist(self):
        for name in ("operators.md", "inputs.md", "security.md", "releases.md"):
            path = ROOT / "docs" / name
            for link in re.findall(r"\]\(([^)]+)\)", path.read_text()):
                target = link.split("#", 1)[0]
                if target and not target.startswith(("https://", "http://")):
                    self.assertTrue((path.parent / target).exists(), (name, link))


if __name__ == "__main__":
    unittest.main()
