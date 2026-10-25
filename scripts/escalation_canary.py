"""Trusted local observer exercise; not a VM driver or untrusted-content runner."""

import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile


PAYLOADS = {"first.txt": b"owned canary first\n", "second.txt": b"owned canary second\n"}
CHILD = r'''
import pathlib, resource, signal, socket, sys
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))
resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
signal.alarm(10)
root = pathlib.Path(sys.argv[1])
for name, payload in (("first.txt", b"owned canary first\n"), ("second.txt", b"owned canary second\n")):
    with (root / name).open("xb") as stream:
        stream.write(payload)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.settimeout(5)
    client.connect(("127.0.0.1", int(sys.argv[2])))
    sys.stdin.buffer.read(1)
'''


class ObservationError(Exception):
    """Required evidence was unavailable or inconsistent."""


def bounded_read(path, limit=65536):
    with open(path, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ObservationError("observation limit")
    return data


def observe(root, child, server_port, peer_port):
    """Read OS/filesystem evidence, not child event claims or child stdout."""
    if set(p.name for p in root.iterdir()) != set(PAYLOADS):
        raise ObservationError("unexpected files")
    files = []
    for name, expected in PAYLOADS.items():
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ObservationError("not a regular canary file")
        data = bounded_read(path, 64)
        if data != expected:
            raise ObservationError("unexpected canary content")
        files.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    # comm may contain spaces/parentheses; fields after its final ')' are stable.
    stat = bounded_read(f"/proc/{child.pid}/stat", 4096).decode("ascii")
    fields = stat[stat.rindex(")") + 2:].split()
    if int(fields[1]) != os.getpid() or child.poll() is not None:
        raise ObservationError("child identity mismatch")
    start_ticks = int(fields[19])
    inodes = set()
    for fd in Path(f"/proc/{child.pid}/fd").iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith("socket:["):
            inodes.add(target[8:-1])

    address = int.from_bytes(socket.inet_aton("127.0.0.1"), sys.byteorder)
    local = f"{address:08X}:{peer_port:04X}"
    remote = f"{address:08X}:{server_port:04X}"
    # Only this child's endpoint is retained. Never export unrelated TCP rows.
    rows = bounded_read("/proc/net/tcp").decode("ascii").splitlines()[1:]
    matches = [r.split() for r in rows if len(r.split()) >= 10]
    if not any(r[1] == local and r[2] == remote and r[3] == "01" and r[9] in inodes for r in matches):
        raise ObservationError("established child socket not observed")
    return {"files": files,
            "process": {"pid": child.pid, "parent-pid": os.getpid(), "start-ticks": start_ticks},
            "network": {"client-address": "127.0.0.1", "client-port": peer_port,
                        "server-address": "127.0.0.1", "server-port": server_port,
                        "state": "ESTABLISHED", "child-socket-inode-matched": True}}


def exercise(timeout=5):
    """Run exactly one fixed canary in an exclusively created temporary directory."""
    if sys.platform != "linux" or not Path("/proc/self/stat").is_file():
        raise ObservationError("Linux procfs required")
    if not 0 < timeout <= 5:
        raise ValueError("timeout outside bounds")
    child = None
    connection = None
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    directory = None
    signals = {signal.SIGINT, signal.SIGTERM}
    try:
        directory = tempfile.TemporaryDirectory(prefix="escalation-canary-")
        root = Path(directory.name)
        if list(root.iterdir()):
            raise ObservationError("baseline is not empty")
        server.settimeout(timeout)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        # Defer cancellation until Popen ownership is recorded for cleanup.
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        try:
            child = subprocess.Popen(
                [sys.executable, "-I", "-S", "-c", CHILD, str(root), str(port)],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={}, close_fds=True)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        connection, peer = server.accept()
        if peer[0] != "127.0.0.1":
            raise ObservationError("unexpected peer")
        evidence = observe(root, child, port, peer[1])
        child.communicate(b"x", timeout=timeout)
        if child.returncode != 0:
            raise ObservationError("child failed")
    finally:
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        try:
            if connection is not None:
                connection.close()
            server.close()
            try:
                if child is not None:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=2)
            finally:
                if directory is not None:
                    directory.cleanup()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    return {"schema-version": 1, "exercise": "trusted-local-observer-only",
            "observations": evidence,
            "cleanup": {"child-reaped": True, "sockets-closed": True, "temporary-files-removed": True},
            "not-validated": ["vm-isolation", "untrusted-content", "engine-or-game-behavior",
                              "crash-resource-save-config-monitoring", "egress-policy", "hypervisor-teardown"]}


def main():
    if len(sys.argv) != 1:
        print("No arguments accepted; receipt is written to stdout.", file=sys.stderr)
        return 2

    def cancel(signum, frame):
        raise ObservationError("cancelled")

    previous = {s: signal.signal(s, cancel) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        receipt = exercise()
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return 0
    except (ObservationError, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt):
        print("Canary observation failed or cancelled; no successful receipt.", file=sys.stderr)
        return 1
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)


if __name__ == "__main__":
    sys.exit(main())
