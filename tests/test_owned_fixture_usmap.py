import importlib.util
import struct
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("usmap", Path(__file__).parents[1] / "scripts/owned_fixture_usmap.py")
USMAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(USMAP)


class MappingEncoderTests(unittest.TestCase):
    def test_header_and_local_slot_expansion(self):
        reflection = {"schemas": [
            {"name": "FixtureData", "super": "Object", "properties": [
                {"name": "Count", "type": "IntProperty", "array_dim": 2},
                {"name": "Text", "type": "StrProperty", "array_dim": 1}]},
            {"name": "Object", "properties": []}]}
        raw = USMAP.encode(reflection)
        magic, version, compression, size, decompressed = struct.unpack("<HBBII", raw[:12])
        self.assertEqual((magic, version, compression), (0x30C4, 0, 0))
        self.assertEqual((size, decompressed), (len(raw) - 12, len(raw) - 12))
        # Schema index 2 follows the two local array slots, not one record.
        self.assertIn(struct.pack("<HBiB", 2, 1, 3, 10), raw)
        self.assertTrue(raw.endswith(struct.pack("<iiHH", 1, -1, 0, 0)))

    def test_missing_zero_property_superclass_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing superclass"):
            USMAP.encode({"schemas": [{"name": "FixtureData", "super": "Object", "properties": []}]})

    def test_unknown_type_is_not_guessed(self):
        with self.assertRaises(KeyError):
            USMAP.encode({"schemas": [{"name": "FixtureData", "properties": [
                {"name": "Unknown", "type": "StructProperty", "array_dim": 1}]}]})

    def test_duplicate_schemas_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate schema"):
            USMAP.encode({"schemas": [{"name": "Object", "properties": []}] * 2})

    def test_invalid_array_dimensions_are_rejected(self):
        for dim in (-1, 0, 256, 1.5):
            with self.subTest(dim=dim), self.assertRaisesRegex(ValueError, "array dimension"):
                USMAP.encode({"schemas": [{"name": "FixtureData", "properties": [
                    {"name": "Number", "type": "IntProperty", "array_dim": dim}]}]})


if __name__ == "__main__":
    unittest.main()
