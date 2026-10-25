"""Private worker entry point; launched only by the supervisor."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import zlib

# -I excludes CWD and user site packages. Add only this trusted source root.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pak_ingest.limits import Limits, Rejected, require
from pak_ingest.reader import CHUNK, extract, parse


class Budget:
    def __init__(self, limit):
        self.limit, self.used = limit, 0

    def write(self, stream, data, terminal=False):
        require(self.used + len(data) + (0 if terminal else 512) <= self.limit, "scratch_limit")
        self.used += len(data)
        require(stream.write(data) == len(data), "short_scratch_write")


def exclusive(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "wb", buffering=0)


def resource_limits(limits):
    import resource

    for kind, value in ((resource.RLIMIT_CPU, limits.cpu_seconds),
                        (resource.RLIMIT_AS, limits.address_space_bytes),
                        (resource.RLIMIT_FSIZE, limits.file_bytes),
                        (resource.RLIMIT_NOFILE, limits.open_files),
                        (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(kind, (value, value))


def run(request):
    limits = Limits(**request["limits"]).validate()
    budget = Budget(limits.scratch_bytes)
    journal = exclusive("events.jsonl")
    report_used = 0

    def emit(event, terminal=False):
        nonlocal report_used
        event = dict(event)
        data = (json.dumps(event, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        if terminal:
            # Include this final evidence write in the reported cumulative total.
            while event.get("scratch_bytes_written") != budget.used + len(data):
                event["scratch_bytes_written"] = budget.used + len(data)
                data = (json.dumps(event, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        require(report_used + len(data) + (0 if terminal else 512) <= limits.report_bytes, "report_limit")
        budget.write(journal, data, terminal)
        report_used += len(data)

    try:
        resource_limits(limits)
        emit({"worker_status": "started"})
        fd = os.open(request["input"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb", buffering=0) as source:
            before = os.fstat(source.fileno())
            require(stat.S_ISREG(before.st_mode), "input_not_regular")
            require(before.st_size <= limits.input_bytes, "input_limit")
            digest, size = hashlib.sha256(), 0
            with exclusive("snapshot") as snapshot:
                while True:
                    chunk = source.read(CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    require(size <= limits.input_bytes, "input_limit")
                    budget.write(snapshot, chunk)
                    digest.update(chunk)
                # Remove write permissions before opening the private copy for reads.
                os.fchmod(snapshot.fileno(), 0o400)
            after = os.fstat(source.fileno())
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    and size == before.st_size, "input_changed_during_snapshot")
        emit({"input_sha256": digest.hexdigest(), "input_bytes": size,
              "snapshot_status": "private_read_only_copy"})
        snapshot_fd = os.open("snapshot", os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(snapshot_fd, "rb", buffering=0) as source:
            require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "snapshot_not_regular")
            records = parse(source, size, limits, emit, request["namespaces"], request["protected"])
            # No payload files are created until every indexed path/layout is validated.
            for record in records:
                try:
                    with exclusive(record["id"]) as output:
                        verified = extract(source, record, output, limits, budget)
                    emit({"record": verified})
                except Exception:
                    emit({"record": dict(record, status="rejected")})
                    raise
        emit({"ingestion_status": "validated", "diagnostic": "class_inspection_deferred",
              "scratch_bytes_written": budget.used}, terminal=True)
        return 0
    except BaseException as error:
        if isinstance(error, Rejected):
            code = str(error)
        elif isinstance(error, MemoryError):
            code = "memory_limit"
        elif isinstance(error, zlib.error):
            code = "invalid_zlib_stream"
        else:
            code = "worker_failure"
        try:
            emit({"ingestion_status": "rejected", "diagnostic": code,
                  "scratch_bytes_written": budget.used}, terminal=True)
        except BaseException:
            pass
        return 1
    finally:
        journal.close()


def main():
    try:
        request = json.loads(sys.stdin.buffer.read(16385))
        return run(request)
    except BaseException:
        return 2


if __name__ == "__main__":
    sys.exit(main())
