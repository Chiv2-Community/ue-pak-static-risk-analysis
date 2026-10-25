"""Optional full JSON Schema checks; production CLI has no Python dependency."""

import copy
import json
from pathlib import Path
import unittest

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(Draft202012Validator is None, "optional jsonschema unavailable")
class ReportSchemaTests(unittest.TestCase):
    def test_generated_examples_validate(self):
        for name in ("facts", "report"):
            schema = json.loads((ROOT / "schemas" / f"{name}-v1.schema.json").read_text())
            Draft202012Validator.check_schema(schema)
            validator = Draft202012Validator(schema)
            examples = [ROOT / "examples/facts-v1.json"] if name == "facts" else sorted((ROOT / "examples/reports").glob("*.json"))
            for example in examples:
                with self.subTest(example=example.name):
                    validator.validate(json.loads(example.read_text()))

    def test_report_schema_rejects_private_and_missing_fields(self):
        schema = json.loads((ROOT / "schemas/report-v1.schema.json").read_text())
        validator = Draft202012Validator(schema)
        original = json.loads((ROOT / "examples/reports/successful-v1.json").read_text())
        for field in original:
            changed = copy.deepcopy(original)
            del changed[field]
            self.assertFalse(validator.is_valid(changed), field)
        for field in ("policy", "policy-hash", "description", "predicates", "allowlists", "uncertainties"):
            changed = copy.deepcopy(original)
            changed[field] = "private-canary"
            self.assertFalse(validator.is_valid(changed), field)
        changed = copy.deepcopy(original)
        changed["analysis-complete"] = False
        self.assertFalse(validator.is_valid(changed))
