#!/usr/bin/env python3
"""Encode only supported producer-reflected schemas, never guessed layouts."""

import argparse
import json
import struct
from pathlib import Path


def encode(reflection):
    schemas = reflection["schemas"]
    names = []
    for schema in schemas:
        for name in [schema["name"], schema.get("super")] + [p["name"] for p in schema["properties"]]:
            if name is not None and name not in names:
                names.append(name)
    if len({schema["name"] for schema in schemas}) != len(schemas):
        raise ValueError("duplicate schema")
    schema_names = {schema["name"] for schema in schemas}
    if any(schema.get("super") and schema["super"] not in schema_names for schema in schemas):
        raise ValueError("missing superclass schema")
    payload = bytearray(struct.pack("<i", len(names)))
    for name in names:
        raw = name.encode("ascii")
        if not 0 < len(raw) < 256:
            raise ValueError("unsupported name length")
        payload += struct.pack("<B", len(raw)) + raw
    payload += struct.pack("<ii", 0, len(schemas))
    types = {"IntProperty": 2, "StrProperty": 10}
    for schema in schemas:
        properties = schema["properties"]
        if any(not isinstance(p["array_dim"], int) or not 1 <= p["array_dim"] <= 255 for p in properties):
            raise ValueError("unsupported array dimension")
        slots = sum(p["array_dim"] for p in properties)
        if slots > 65535 or len(properties) > 65535:
            raise ValueError("too many property slots")
        payload += struct.pack("<iiHH", names.index(schema["name"]),
                               names.index(schema["super"]) if schema.get("super") else -1,
                               slots, len(properties))
        index = 0
        for prop in properties:
            dim = prop["array_dim"]
            payload += struct.pack("<HBiB", index, dim, names.index(prop["name"]), types[prop["type"]])
            index += dim
    return struct.pack("<HBBII", 0x30C4, 0, 0, len(payload), len(payload)) + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reflection", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = encode(json.loads(args.reflection.read_text(encoding="utf-8-sig")))
    with args.output.open("xb") as stream:
        stream.write(data)


if __name__ == "__main__":
    main()
