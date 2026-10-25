"""Linux process/resource supervisor, not a VM or network sandbox."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from .limits import Limits
from .reader import components


def supported():
    if not sys.platform.startswith("linux") or not hasattr(os, "O_NOFOLLOW"):
        return False
    try:
        import resource
        return all(hasattr(resource, name) for name in
                   ("RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_FSIZE", "RLIMIT_NOFILE", "RLIMIT_CORE"))
    except ImportError:
        return False


def stop(process):
    # Kill the whole session's process group, even if its leader already exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def collect(root, limits, report):
    path = Path(root) / "events.jsonl"
    if not path.exists():
        return
    records = {}
    with path.open("rb") as events:
        remaining = limits.report_bytes
        while remaining:
            line = events.readline(remaining + 1)
            if not line:
                break
            if len(line) > remaining or not line.endswith(b"\n"):
                break
            remaining -= len(line)
            try:
                event = json.loads(line)
            except (ValueError, UnicodeError):
                break
            if "record" in event:
                record = event["record"]
                records[record["id"]] = record
            else:
                report.update(event)
    report["records"] = list(records.values())


def ingest(path, *, limits=None, scratch_parent=None, cancel=None, namespaces=(), protected=(), inspector=None):
    """Return evidence only; payloads and snapshot are removed before returning.

    `cancel` is a threading.Event-compatible object. Limits/prefixes are trusted
    deployment configuration, not policy or input metadata. No worker is allowed
    to invoke another executable.
    """
    limits = (limits or Limits()).validate()
    report = {"schema": "pak-ingest-foundation-v1", "analysis_complete": False,
              "ingestion_status": "rejected", "structure_status": "uninspected",
              "diagnostic": "worker_failure", "records": [],
              "class_inspection": "deferred_issue_4",
              "limits": limits.as_dict(),
              "containment": {"platform": "linux_rlimits", "network_isolated": False,
                              "os_aggregate_storage_quota": False,
                              "worker_write_budget_bytes": limits.scratch_bytes,
                              "configured_storage_allowance_bytes": limits.scratch_bytes}}
    if not supported():
        report["diagnostic"] = "unsupported_resource_platform"
        return report
    try:
        namespaces, protected = tuple(namespaces), tuple(protected)
        for prefix in namespaces + protected:
            components(prefix)
        request = json.dumps({"input": os.path.abspath(os.fspath(path)), "limits": limits.as_dict(),
                              "namespaces": namespaces, "protected": protected}).encode("ascii")
        if len(request) > 16384:
            raise ValueError("configuration_limit")
    except Exception:
        report["diagnostic"] = "invalid_configuration"
        return report
    process = None
    reason = None
    try:
        with tempfile.TemporaryDirectory(prefix="pak-ingest-", dir=scratch_parent) as root:
            try:
                process = subprocess.Popen(
                    [sys.executable, "-I", str(Path(__file__).with_name("worker.py"))],
                    cwd=root, env={"LANG": "C", "LC_ALL": "C"},
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True, close_fds=True, bufsize=0)
                deadline = time.monotonic() + limits.wall_seconds
                # A request can exceed pipe capacity. Never block here outside
                # the cancellation/deadline loop, even if worker startup stalls.
                os.set_blocking(process.stdin.fileno(), False)
                sent = 0
                while process.poll() is None:
                    if cancel is not None and cancel.is_set():
                        reason = "cancelled"
                        break
                    if time.monotonic() >= deadline:
                        reason = "wall_timeout"
                        break
                    if sent < len(request):
                        try:
                            sent += os.write(process.stdin.fileno(), request[sent:])
                        except BlockingIOError:
                            pass
                        if sent == len(request):
                            process.stdin.close()
                    time.sleep(0.01)
            except KeyboardInterrupt:
                reason = "cancelled"
            except Exception:
                reason = "supervisor_failure"
            finally:
                if process is not None:
                    stop(process)
                    process.stdin.close()
                collect(root, limits, report)
            if reason or process is None or process.returncode != 0:
                report["ingestion_status"] = "rejected"
                if reason:
                    report["diagnostic"] = reason
                elif process is not None and process.returncode < 0:
                    report["diagnostic"] = "worker_resource_or_signal_failure"
            # Only the trusted supervisor invokes the fixed inspector, after reaping
            # the ingestion worker and before removing its generated payloads.
            if inspector is not None:
                inspector(root, report)
            # TemporaryDirectory cleanup happens on success, failure, and cancellation.
    except Exception:
        report["ingestion_status"] = "rejected"
        report["diagnostic"] = "supervisor_or_cleanup_failure"
    return report
