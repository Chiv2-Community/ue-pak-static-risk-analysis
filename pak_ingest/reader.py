"""Narrow ordinary-index V9 reader. No archive path is a host path."""

import hashlib
import struct
import zlib

from .limits import require

FOOTER_SIZE = 222
CHUNK = 65536


class Cursor:
    def __init__(self, data, limits):
        self.data, self.pos, self.limits = data, 0, limits

    def take(self, count):
        require(0 <= count <= len(self.data) - self.pos, "truncated_structure")
        value = self.data[self.pos:self.pos + count]
        self.pos += count
        return value

    def number(self, fmt):
        return struct.unpack("<" + fmt, self.take(struct.calcsize("<" + fmt)))[0]

    def string(self):
        count = self.number("i")
        require(1 <= count <= self.limits.string_bytes, "string_limit_or_encoding")
        value = self.take(count)
        require(value[-1:] == b"\0" and b"\0" not in value[:-1], "invalid_string")
        require(all(32 <= c < 127 for c in value[:-1]), "non_ascii_path")
        return value[:-1].decode("ascii")


def entry(cursor, remaining_blocks):
    start = cursor.pos
    offset, stored, output = (cursor.number("Q") for _ in range(3))
    codec = cursor.number("I")
    digest = cursor.take(20)
    blocks = []
    if codec:
        count = cursor.number("I")
        require(0 < count <= remaining_blocks, "block_limit")
        require(count <= (len(cursor.data) - cursor.pos) // 16, "truncated_structure")
        blocks = [(cursor.number("Q"), cursor.number("Q")) for _ in range(count)]
    flags, block_size = cursor.number("B"), cursor.number("I")
    return dict(offset=offset, stored=stored, output=output, codec=codec,
                sha1=digest.hex(), blocks=blocks, flags=flags,
                block_size=block_size, header_size=cursor.pos - start)


def read_at(source, offset, size):
    source.seek(offset)
    data = source.read(size)
    require(len(data) == size, "truncated_structure")
    return data


def components(path):
    parts = path.split("/")
    require(bool(path) and all(p and p not in (".", "..") for p in parts), "unsafe_path")
    require(all(32 <= ord(c) < 127 for c in path)
            and not any(c in path for c in '\\:<>"|?*'), "unsafe_path")
    # Windows aliases and trailing-dot/space names are ambiguous even on Linux.
    reserved = {"con", "prn", "aux", "nul"} | {f"{p}{i}" for p in ("com", "lpt") for i in range(1, 10)}
    require(all(not p.endswith((".", " ")) and p.split(".")[0].lower() not in reserved
                for p in parts), "unsafe_path")
    return parts


def mount_components(mount):
    # This conventional virtual mount is allowed literally, not normalized.
    require(mount.startswith("../../../"), "unsupported_mount")
    suffix = mount[len("../../../"):]
    require(not suffix or suffix.endswith("/"), "unsupported_mount")
    return components(suffix[:-1]) if suffix else []


def under(path, prefix):
    return path == prefix or path.startswith(prefix + "/")


def parse(source, size, limits, emit, namespaces=(), protected=()):
    require(size >= FOOTER_SIZE, "truncated_footer")
    footer = Cursor(read_at(source, size - FOOTER_SIZE, FOOTER_SIZE), limits)
    guid = footer.take(16)
    encrypted = footer.number("B")
    require(footer.number("I") == 0x5A6F12E1, "invalid_magic")
    require(footer.number("I") == 9, "unsupported_version")
    index_offset, index_size = footer.number("Q"), footer.number("Q")
    index_hash = footer.take(20)
    frozen = footer.number("B")
    require(not encrypted and not any(guid), "unsupported_encryption")
    require(not frozen, "unsupported_frozen_index")
    codecs = []
    for _ in range(5):
        slot = footer.take(32)
        name, separator, padding = slot.partition(b"\0")
        require(separator and not any(padding), "invalid_codec_slot")
        require(name in (b"", b"Zlib", b"None"), "unsupported_codec")
        codecs.append(name)
    require(index_size <= limits.index_bytes, "index_limit")
    require(index_offset + index_size == size - FOOTER_SIZE, "index_bounds")
    index = read_at(source, index_offset, index_size)
    require(hashlib.sha1(index).digest() == index_hash, "index_sha1")
    cursor = Cursor(index, limits)
    mount = cursor.string()
    emit({"mount": mount, "index_sha1": index_hash.hex()})
    mount_parts = mount_components(mount)
    count = cursor.number("I")
    require(count <= limits.entries, "entry_limit")
    records, seen, ranges = [], set(), []
    blocks_left, total = limits.blocks, 0
    for ordinal in range(count):
        name = cursor.string()
        record = dict(id=f"r{ordinal:08d}", raw_name=name, status="uninspected")
        emit({"record": record})
        meta = entry(cursor, blocks_left)
        blocks_left -= len(meta["blocks"])
        record.update(meta)
        records.append(record)
        emit({"record": record})
        parts = mount_parts + components(name)
        virtual = "/".join(parts)
        key = virtual.lower()
        require(key not in seen, "duplicate_or_case_collision")
        seen.add(key)
        record["virtual_path"] = virtual
        record["namespace_match"] = any(under(key, p.lower()) for p in namespaces)
        record["replacement_candidate"] = any(under(key, p.lower()) for p in protected)
        require(not meta["flags"], "unsupported_entry_flags")
        codec = meta["codec"]
        require(codec == 0 or (codec <= len(codecs) and codecs[codec - 1] == b"Zlib"),
                "unsupported_entry_codec")
        require(meta["output"] <= limits.member_bytes, "member_limit")
        total += meta["output"]
        require(total <= limits.total_output_bytes, "total_output_limit")
        require(meta["output"] <= max(1, meta["stored"]) * limits.expansion_ratio,
                "expansion_limit")
        header_size = meta["header_size"]
        offset, stored, output = meta["offset"], meta["stored"], meta["output"]
        require(offset + header_size + stored <= index_offset, "entry_bounds")
        local = Cursor(read_at(source, offset, header_size), limits)
        local_meta = entry(local, len(meta["blocks"]))
        require(local_meta == dict(meta, offset=0), "local_header_mismatch")
        if not codec:
            require(stored == output and not meta["block_size"], "invalid_plain_layout")
        else:
            block_size = meta["block_size"]
            require(0 < block_size <= limits.member_bytes and output > 0, "invalid_block_size")
            require(len(meta["blocks"]) == (output + block_size - 1) // block_size,
                    "invalid_block_count")
            end = header_size
            for first, last in meta["blocks"]:
                require(first == end and last > first and last <= header_size + stored,
                        "invalid_block_layout")
                end = last
            require(end == header_size + stored, "invalid_block_layout")
        ranges.append((offset, offset + header_size + stored))
    require(cursor.pos == len(index), "index_trailing_data")
    # Sort once: prefix conflicts include nonadjacent records and case aliases.
    keys = sorted(seen)
    for key in keys:
        parts = key.split("/")
        require(not any("/".join(parts[:i]) in seen for i in range(1, len(parts))),
                "path_prefix_conflict")
    ranges.sort()
    require(all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:])), "entry_overlap")
    by_name = {r["virtual_path"].lower(): r for r in records}
    for record in records:
        path = record["virtual_path"].lower()
        stem, dot, extension = path.rpartition(".")
        record["sidecar_status"] = "not_applicable"
        if dot and extension in ("uexp", "ubulk", "uptnl"):
            owners = [by_name[p]["id"] for p in (stem + ".uasset", stem + ".umap") if p in by_name]
            record["sidecar_owners"] = owners
            record["sidecar_status"] = "mapped" if owners else "orphan"
        elif dot and extension in ("uasset", "umap"):
            record["sidecar_status"] = "required_sidecars_unresolved"
            record["sidecars"] = [by_name[p]["id"] for p in
                                  (stem + ".uexp", stem + ".ubulk", stem + ".uptnl") if p in by_name]
        emit({"record": record})
    emit({"structure_status": "validated", "entry_count": count})
    return records


def signatures(prefix, name):
    kinds = []
    if prefix.startswith(b"MZ") and len(prefix) >= 64:
        offset = struct.unpack_from("<I", prefix, 60)[0]
        if 64 <= offset <= len(prefix) - 24 and prefix[offset:offset + 4] == b"PE\0\0":
            optional_size = struct.unpack_from("<H", prefix, offset + 20)[0]
            if optional_size >= 2 and offset + 24 + optional_size <= len(prefix):
                if prefix[offset + 24:offset + 26] in (b"\x0b\x01", b"\x0b\x02"):
                    kinds.append("pe")
    if prefix.startswith(b"\x7fELF"):
        kinds.append("elf")
    if prefix[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                      b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                      b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        kinds.append("mach_o")
    if prefix[:4] in (b"\xc1\x83\x2a\x9e", b"\x9e\x2a\x83\xc1"):
        kinds.append("unreal_package_tag")
    if prefix.startswith(b"#!"):
        kinds.append("shebang")
    extension = name.rpartition(".")[2].lower()
    if extension in ("py", "js", "lua", "ps1", "bat", "cmd", "sh", "vbs"):
        kinds.append("script_candidate")
    if extension in ("ini", "cfg", "json", "yaml", "yml", "xml", "toml"):
        kinds.append("config_candidate")
    # Text and extension hints never establish benignness or inspected classes.
    if not any(k in kinds for k in ("pe", "elf", "mach_o", "unreal_package_tag", "shebang")):
        kinds.append("unknown_content")
    return kinds


def extract(source, record, destination, limits, budget):
    stored_hash, output_hash = hashlib.sha1(), hashlib.sha256()
    prefix = bytearray()
    produced = 0

    def write(data):
        nonlocal produced
        produced += len(data)
        require(produced <= record["output"], "output_size_mismatch")
        budget.write(destination, data)
        output_hash.update(data)
        if len(prefix) < CHUNK:
            prefix.extend(data[:CHUNK - len(prefix)])

    ranges = record["blocks"] or [(record["header_size"], record["header_size"] + record["stored"])]
    for first, last in ranges:
        source.seek(record["offset"] + first)
        remaining = last - first
        decoder = zlib.decompressobj() if record["codec"] else None
        block_output = 0
        expected = min(record["block_size"], record["output"] - produced) if decoder else remaining
        while remaining:
            chunk = source.read(min(CHUNK, remaining))
            require(bool(chunk), "truncated_payload")
            remaining -= len(chunk)
            stored_hash.update(chunk)
            if decoder:
                pending = chunk
                while pending:
                    out = decoder.decompress(pending, min(CHUNK, expected - block_output + 1))
                    block_output += len(out)
                    require(block_output <= expected, "output_size_mismatch")
                    write(out)
                    pending = decoder.unconsumed_tail
                    require(not decoder.unused_data, "zlib_trailing_data")
                require(not decoder.eof or remaining == 0, "zlib_trailing_data")
            else:
                write(chunk)
        if decoder:
            require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
                    "zlib_incomplete")
            require(block_output == expected, "output_size_mismatch")
    require(produced == record["output"], "output_size_mismatch")
    require(stored_hash.hexdigest() == record["sha1"], "entry_sha1")
    return dict(record, status="payload_verified", sha256=output_hash.hexdigest(),
                signatures=signatures(bytes(prefix), record["raw_name"]),
                class_inspection="deferred_issue_4")
