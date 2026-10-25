"""Small owned synthetic V9 builder, independent of repak and game assets."""

import hashlib
import struct
import zlib


def string(value):
    value = value.encode("ascii") + b"\0"
    return struct.pack("<i", len(value)) + value


def header(meta, local=False):
    data = struct.pack("<QQQI", 0 if local else meta["offset"], meta["stored"],
                       meta["output"], meta["codec"]) + meta["digest"]
    if meta["codec"]:
        data += struct.pack("<I", len(meta["blocks"]))
        data += b"".join(struct.pack("<QQ", *b) for b in meta["blocks"])
    return data + struct.pack("<BI", meta["flags"], meta["block_size"])


def build(members=(("Content/a.bin", b"owned", False),), *, mount="../../../", mutate=None,
          index_mutate=None, footer_mutate=None, local_mutate=None):
    """Mutations recompute index SHA1, reaching deeper structural validation."""
    metas, payloads, position = [], [], 0
    for name, data, compressed in members:
        block_size = 32768 if compressed else 0
        chunks = [zlib.compress(data[i:i + block_size]) for i in range(0, len(data), block_size)] if compressed else []
        payload = b"".join(chunks) if compressed else data
        size = 53 + (4 + 16 * len(chunks) if compressed else 0)
        blocks, start = [], size
        for chunk in chunks:
            blocks.append((start, start + len(chunk)))
            start += len(chunk)
        meta = dict(name=name, offset=position, stored=len(payload), output=len(data),
                    codec=int(compressed), digest=hashlib.sha1(payload).digest(), blocks=blocks,
                    flags=0, block_size=block_size)
        metas.append(meta)
        payloads.append(payload)
        position += size + len(payload)
    if mutate:
        mutate(metas, payloads)
    body = bytearray()
    for i, (meta, payload) in enumerate(zip(metas, payloads)):
        local = bytearray(header(meta, True))
        if local_mutate:
            local_mutate(i, local)
        body.extend(local)
        body.extend(payload)
    index = bytearray(string(mount) + struct.pack("<I", len(metas)))
    for meta in metas:
        index.extend(string(meta["name"]) + header(meta))
    if index_mutate:
        index_mutate(index)
    footer = bytearray(b"\0" * 17 + struct.pack("<IIQQ", 0x5A6F12E1, 9, len(body), len(index))
                       + hashlib.sha1(index).digest() + b"\0"
                       + b"Zlib" + b"\0" * 28 + b"\0" * 128)
    if footer_mutate:
        footer_mutate(footer)
    return bytes(body + index + footer)
