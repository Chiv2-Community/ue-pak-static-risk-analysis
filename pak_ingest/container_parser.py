"""Policy-free container entry point; stdout is bounded typed facts only."""

import json
import os
from pathlib import Path
import subprocess
import sys

from .supervisor import ingest


def main():
    if len(sys.argv) != 4:
        return 3

    emitted = False

    def inspect(root, report):
        nonlocal emitted
        # The worker has exited. Keep generated payloads within their private lifetime.
        manifest = Path(root) / "inspection.json"
        with manifest.open("x", encoding="ascii") as stream:
            json.dump(report, stream, ensure_ascii=True, separators=(",", ":"))
        # No RLIMIT_AS on managed runtime: cgroup memory and host deadline contain it.
        result = subprocess.run(["/usr/bin/dotnet", "/app/parser/Parser.dll", root, *sys.argv[1:]],
                                env={"LANG": "C.UTF-8", "DOTNET_EnableDiagnostics": "0",
                                     "DOTNET_GCHeapHardLimit": "0x20000000"},
                                stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if result.returncode:
            raise RuntimeError("parser_failed")
        emitted = True

    report = ingest("/input/submission", scratch_parent="/scratch", inspector=inspect)
    # Rejected ingestion can still carry useful partial findings and coverage.
    return 0 if emitted else 3


if __name__ == "__main__":
    sys.exit(main())
