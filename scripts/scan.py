#!/usr/bin/env python3
"""Trusted host orchestrator. Docker is external; never mount its socket inside."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FACTS_LIMIT = 8 * 1024 * 1024
REPORT_LIMIT = 16 * 1024 * 1024
INPUT_LIMIT = 256 * 1024 * 1024


class Failure(Exception):
    pass


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise Failure("invalid-configuration")


def client_environment(policy=False):
    result = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    if policy and "UE_PAK_POLICY_RULES" in os.environ:
        value = os.environ["UE_PAK_POLICY_RULES"]
        # Docker's JSON transport replaces invalid UTF-8. Reject it before that
        # lossy boundary; policy parsing/source/log semantics remain in C#.
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise Failure("invalid-configuration") from None
        result["UE_PAK_POLICY_RULES"] = value
    return result


def mount(source, destination):
    source = os.path.abspath(os.fspath(source))
    if any(c in source for c in ",\n\r\0"):
        raise Failure("invalid-configuration")
    return ["--mount", f"type=bind,source={source},target={destination},readonly"]


def snapshot(source, destination, limit):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest, count = hashlib.sha256(), 0
    with os.fdopen(fd, "rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise Failure("input-failed")
        with open(destination, "xb", buffering=0) as output:
            os.chmod(destination, 0o400)
            while chunk := stream.read(65536):
                count += len(chunk)
                if count > limit:
                    raise Failure("input-failed")
                output.write(chunk)
                digest.update(chunk)
        after = os.fstat(stream.fileno())
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if fields(before) != fields(after) or count != before.st_size:
            raise Failure("input-failed")
    return digest.hexdigest()


class Docker:
    def __init__(self, config, image, timeout):
        self.prefix = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", str(config)]
        self.timeout = timeout
        # Resolve a mutable local tag once. Never pull during a policy-bearing scan.
        result = subprocess.run(self.prefix + ["image", "inspect", "--format", "{{.Id}}", image],
                                env=client_environment(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=10, check=False)
        identity = result.stdout.decode("ascii").strip()
        if result.returncode or len(identity) != 71 or not identity.startswith("sha256:"):
            raise Failure("container-unavailable")
        self.image = identity

    def command(self, name, mounts, entry, arguments, policy=False):
        return self.prefix + ["run", "--name", name, "--pull", "never", "--log-driver", "none",
            "--network", "none", "--ipc", "none", "--cgroupns", "private", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}", "--pids-limit", "64", "--memory", "1g",
            "--memory-swap", "1g", "--cpus", "1", "--ulimit", "core=0:0", "--ulimit", "nofile=128:128",
            "--ulimit", "fsize=536870912:536870912", "--ulimit", "cpu=45:45",
            "--tmpfs", f"/scratch:rw,noexec,nosuid,nodev,size=900m,mode=700,uid={os.getuid()},gid={os.getgid()}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
            "--env", "DOTNET_EnableDiagnostics=0", "--env", "DOTNET_GCHeapHardLimit=0x20000000",
            *( ["--env", "UE_PAK_POLICY_RULES"] if policy and "UE_PAK_POLICY_RULES" in os.environ else []),
            *mounts, "--entrypoint", entry, self.image, *arguments]

    def run(self, mounts, entry, arguments, *, policy=False, parser=False):
        name = "pak-scan-" + uuid.uuid4().hex
        command = self.command(name, mounts, entry, arguments, policy)
        process = None
        chunks, logs = bytearray(), bytearray()
        deadline = time.monotonic() + self.timeout
        try:
            process = subprocess.Popen(command, env=client_environment(policy), stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL if parser else subprocess.PIPE,
                                       start_new_session=True, close_fds=True)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, chunks)
                if not parser:
                    selector.register(process.stderr, selectors.EVENT_READ, logs)
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise Failure("wall-timeout")
                    for key, _ in selector.select(0.05):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        key.data.extend(data)
                        limit = FACTS_LIMIT if parser else REPORT_LIMIT
                        if len(key.data) > limit:
                            raise Failure("parser-output-limit" if parser else "parser-failed")
            try:
                code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise Failure("wall-timeout") from None
            if logs:
                # Only the trusted evaluator's fixed/safely rendered diagnostics.
                sys.stderr.buffer.write(logs)
            return code, bytes(chunks)
        except KeyboardInterrupt:
            raise Failure("cancelled") from None
        finally:
            # Repeated cancellation must not interrupt owned-container teardown.
            previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
            try:
                if process is not None and process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                # Retry removal: the daemon can finish a create request after its
                # client dies. Never select containers by labels/prefix or prune.
                for attempt in range(3):
                    subprocess.run(self.prefix + ["rm", "--force", name], env=client_environment(),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=3, check=False)
                    if attempt != 2:
                        time.sleep(0.1)
            finally:
                if process is not None:
                    process.stdout.close()
                    if process.stderr is not None:
                        process.stderr.close()
                for sig, handler in previous.items():
                    signal.signal(sig, handler)


def write_report(path, data):
    # No overwrite, including aliases to the pak/policy or hostile special files.
    destination = Path(path).absolute()
    with tempfile.NamedTemporaryFile(prefix=".risk-report-", dir=destination.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.link(temporary, destination, follow_symlinks=False)
        finally:
            temporary.unlink(missing_ok=True)


def output_destinations(args):
    # Resolve existing parents, not the final component: final symlinks and
    # special files must remain occupied destinations, never overwrite targets.
    paths = [Path(args.report)]
    if args.data_context is not None:
        paths.append(Path(args.data_context))
    if getattr(args, "capability_context", None) is not None:
        paths.append(Path(args.capability_context))
    try:
        paths = [path.parent.resolve(strict=True) / path.name for path in paths]
    except RuntimeError:
        # pathlib versions before 3.13 report parent symlink loops this way.
        raise Failure("input-failed") from None
    if len(set(paths)) != len(paths):
        raise Failure("invalid-configuration")
    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise FileExistsError()
    args.report = paths[0]
    if args.data_context is not None:
        args.data_context = paths[1]
    if getattr(args, "capability_context", None) is not None:
        args.capability_context = paths[-1]


def options(argv):
    parser = Arguments(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=["scan"])
    for key in ("pak", "report", "engine-version"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--image", default="ue-pak-static-risk-analysis:dev")
    parser.add_argument("--timeout", type=float, default=60)
    for key in ("policy-rules", "log-level", "policy-revision", "fail-on-any-forbidden", "fail-on-any-flagged", "fail-on-incomplete", "mapping", "content-root", "capability-summaries",
                "data-rules", "baseline-pak", "game-build", "data-context",
                "capability-rules", "capability-policy-revision", "capability-context"):
        parser.add_argument("--" + key)
    parser.add_argument("--moderator-detail", action="store_true")
    for key in ("allowed-path", "allowed-class", "protected-path"):
        parser.add_argument("--" + key, action="append", default=[])
    parser.add_argument("--replacement-policy", action="append", default=[])
    result = parser.parse_args(argv)
    if os.getuid() == 0 or not 0 < result.timeout <= 600:
        raise Failure("invalid-configuration")
    if result.data_rules:
        if not result.game_build or not result.content_root or not result.data_context:
            raise Failure("invalid-configuration")
    elif result.baseline_pak or result.game_build or result.data_context:
        raise Failure("invalid-configuration")
    if result.capability_rules:
        import re
        if not result.capability_context or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", result.capability_policy_revision or ""):
            raise Failure("invalid-configuration")
    elif result.capability_context or result.capability_policy_revision:
        raise Failure("invalid-configuration")
    return result


def main(argv=None):
    docker = None
    args = None
    try:
        args = options(sys.argv[1:] if argv is None else argv)
        # Reject output aliases/occupied paths before policy disclosure, parsing,
        # or either artifact write. Parents remain operator-controlled.
        output_destinations(args)
        # No source-policy copies. Only a file-only evaluator mount, never a parser mount.
        policy_mount = mount(args.policy_rules, "/policy/rules") if args.policy_rules is not None else []
        shared = ["--report", "-", "--engine-version", args.engine_version]
        if args.policy_rules is not None:
            shared += ["--policy-rules", "/policy/rules"]
        for key in ("log-level", "policy-revision", "fail-on-any-forbidden", "fail-on-any-flagged", "fail-on-incomplete"):
            value = getattr(args, key.replace("-", "_"))
            if value is not None:
                shared += ["--" + key, value]
        if args.moderator_detail:
            shared += ["--moderator-detail"]
        for key in ("allowed-path", "allowed-class", "protected-path"):
            for value in getattr(args, key.replace("-", "_")):
                shared += ["--" + key, value]
        for value in args.replacement_policy:
            shared += ["--replacement-policy", value]
        root, logical = "-", "-"
        if args.content_root is not None:
            from pak_ingest.reader import components
            from pak_ingest.limits import Rejected
            try:
                root, logical = args.content_root.split("=", 1)
                components(root)
                components(logical.removeprefix("/"))
                if not logical.startswith("/"):
                    raise ValueError()
            except (ValueError, Rejected):
                raise Failure("invalid-configuration") from None
        with tempfile.TemporaryDirectory(prefix="pak-scan-") as stage:
            stage = Path(stage)
            private_dependencies = []
            if args.capability_rules is not None:
                capability_rules = stage / "capability-rules"
                capability_rules_hash = snapshot(args.capability_rules, capability_rules, 256 * 1024)
                policy_mount += mount(capability_rules, "/policy/capability-rules")
                shared += ["--capability-rules", "/policy/capability-rules",
                    "--capability-policy-revision", args.capability_policy_revision]
            catalog_hash = None
            if args.data_rules is not None:
                rules = stage / "data-rules"
                rules_hash = snapshot(args.data_rules, rules, 256 * 1024)
                policy_mount += mount(rules, "/policy/data-rules")
                shared += ["--data-rules", "/policy/data-rules", "--game-build", args.game_build]
                private_dependencies.append({"kind": "data-rules", "sha256": rules_hash})
            if args.capability_summaries is not None:
                catalog = stage / "summaries"
                catalog_hash = snapshot(args.capability_summaries, catalog, 256 * 1024)
                policy_mount += mount(catalog, "/catalog/summaries")
                shared += ["--capability-summaries", "/catalog/summaries"]
            config = stage / "docker"
            config.mkdir()
            docker = Docker(config, args.image, args.timeout)
            code, validation_report = docker.run(policy_mount, "/usr/bin/dotnet",
                ["/app/evaluator/Scanner.dll", "validate", *shared], policy=True)
            if code:
                if validation_report:
                    write_report(args.report, validation_report)
                return code if code in (2, 3) else 3
            # Shared loader already emitted the single verbose warning/disclosure.
            if "--log-level" in shared:
                shared[shared.index("--log-level") + 1] = "info"
            pak = stage / "submission"
            pak_hash = snapshot(args.pak, pak, INPUT_LIMIT)
            parser_mounts = mount(pak, "/input/submission")
            mapping_arg, mapping_hash = "-", None
            if args.mapping:
                mapping = stage / "mapping"
                mapping_hash = snapshot(args.mapping, mapping, 16 * 1024 * 1024)
                parser_mounts += mount(mapping, "/input/mapping")
                mapping_arg = "/input/mapping"
            baseline_mounts = []
            baseline_expected = []
            if args.baseline_pak is not None:
                baseline_pak = stage / "baseline"
                baseline_hash = snapshot(args.baseline_pak, baseline_pak, INPUT_LIMIT)
                private_dependencies.append({"kind": "baseline-pak", "sha256": baseline_hash})
                baseline_parser_mounts = mount(baseline_pak, "/input/submission")
                if args.mapping:
                    baseline_parser_mounts += mount(mapping, "/input/mapping")
                baseline_code, baseline_facts = docker.run(baseline_parser_mounts, "/usr/local/bin/python3",
                    ["-m", "pak_ingest.container_parser", mapping_arg, root, logical], parser=True)
                if baseline_code or not baseline_facts:
                    raise Failure("parser-failed")
                baseline_path = stage / "baseline-facts"
                baseline_path.write_bytes(baseline_facts)
                baseline_path.chmod(0o400)
                baseline_mounts = mount(baseline_path, "/input/baseline-facts")
                baseline_expected = ["--baseline-facts", "/input/baseline-facts", "--expected-baseline-sha256", baseline_hash,
                    "--baseline-facts-assertion", "caller-supplied-not-authenticated"]
            code, facts = docker.run(parser_mounts, "/usr/local/bin/python3",
                ["-m", "pak_ingest.container_parser", mapping_arg, root, logical], parser=True)
            if code or not facts:
                raise Failure("parser-failed")
            facts_path = stage / "facts"
            with facts_path.open("xb") as stream:
                stream.write(facts)
            facts_path.chmod(0o400)
            expected = ["--expected-pak-sha256", pak_hash]
            if mapping_hash:
                expected += ["--expected-mapping-sha256", mapping_hash]
            code, report = docker.run(policy_mount + mount(facts_path, "/input/facts") + baseline_mounts, "/usr/bin/dotnet",
                ["/app/evaluator/Scanner.dll", "evaluate", "--facts", "/input/facts", *expected, *baseline_expected, *shared], policy=True)
            if not report or code not in (0, 1, 2, 3):
                raise Failure("parser-failed")
            if (args.data_rules is not None or args.capability_rules is not None) and code in (0, 1):
                from report_validation import load
                checked = load(report, Path(__file__).resolve().parents[1], moderator_detail=args.moderator_detail)
            if args.capability_rules is not None and code in (0, 1):
                if "capability-analysis" not in checked:
                    raise Failure("parser-failed")
                private = {"schema-version": 1, "kind": "capability-context",
                    "report-sha256": hashlib.sha256(report).hexdigest(),
                    "policy-revision": args.capability_policy_revision, "catalog-sha256": catalog_hash,
                    "dependencies": [{"kind": "capability-rules", "sha256": capability_rules_hash}]}
                write_report(args.capability_context, (json.dumps(private, separators=(",", ":")) + "\n").encode("utf-8"))
            if args.data_rules is not None and code in (0, 1):
                # Separate private artifact. No policy/baseline fingerprint enters ordinary reports.
                if "data-analysis" not in checked:
                    raise Failure("parser-failed")
                private = {"schema-version": 1, "kind": "data-context", "report-sha256": hashlib.sha256(report).hexdigest(),
                    "engine-version": args.engine_version, "game-build": args.game_build,
                    "content-root": root, "logical-root": logical,
                    "mount-policy": "submission-over-baseline", "dependencies": sorted(private_dependencies, key=lambda d: d["kind"])}
                write_report(args.data_context, (json.dumps(private, separators=(",", ":")) + "\n").encode("utf-8"))
            write_report(args.report, report)
            return code
    except (Failure, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        reason = "cancelled" if isinstance(error, KeyboardInterrupt) else str(error) if isinstance(error, Failure) else "input-failed"
        if reason not in ("parser-failed", "parser-output-limit", "wall-timeout", "cancelled", "container-unavailable", "input-failed", "invalid-configuration"):
            reason = "input-failed"
        # Failure reporting never re-evaluates policy or fabricates empty facts.
        # Docker may be unavailable; then no safe shared report producer exists.
        if docker is not None and args is not None:
            try:
                _, report = docker.run([], "/usr/bin/dotnet", ["/app/evaluator/Scanner.dll", "failure-report",
                    "--reason", reason, "--report", "-"])
                if report:
                    write_report(args.report, report)
            except (Failure, OSError, subprocess.SubprocessError):
                pass
        print("Scan failed.", file=sys.stderr)
        return 2 if reason == "invalid-configuration" else 3


if __name__ == "__main__":
    # SIGTERM follows the same bounded cleanup path as keyboard cancellation.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    sys.exit(main())
