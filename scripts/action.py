#!/usr/bin/env python3
"""GitHub adapter for the trusted host wrapper. Never interpret policy YAML."""

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

from action_report import compact, load, require

ROOT = Path(__file__).resolve().parents[1]
UASSET = "b4e8a012939295a6fd890ddc64e57ea78b709b95"
OUTPUT_BUDGET = 256 * 1024  # UTF-16 bytes, combined outputs; below the 1 MiB/job limit.
PUBLISHED_IMAGE = r"ghcr\.io/chiv2-community/ue-pak-static-risk-analysis@sha256:[a-f0-9]{64}"


def published_image():
    """The selected trusted Action commit supplies this assertion, not the runner."""
    path = ROOT / "action-image.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        require(not path.is_symlink())
        return None
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
        data = stream.read(4097)
    return image_manifest(data)["image"]


def image_manifest(data):
    """Closed release assertion, shared with corresponding-source packaging."""
    require(len(data) <= 4096)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=pairs)
    require(isinstance(value, dict) and set(value) ==
            {"version", "platform", "image", "build-source"})
    require(value["version"] == "v0.1.0" and value["platform"] == "linux/amd64")
    require(isinstance(value["build-source"], str) and
            re.fullmatch(r"[a-f0-9]{40}", value["build-source"]) is not None)
    require(isinstance(value["image"], str) and re.fullmatch(PUBLISHED_IMAGE, value["image"]) is not None)
    return value


def environment(policy=False):
    result = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    if policy and "UE_PAK_POLICY_RULES" in os.environ:
        result["UE_PAK_POLICY_RULES"] = os.environ["UE_PAK_POLICY_RULES"]
    return result


def append(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode))
        # One append, fixed keys, no heredoc delimiters or unescaped metadata.
        require(os.write(fd, data) == len(data))
    finally:
        os.close(fd)


def encode_outputs(outputs):
    require(all(re.fullmatch("[a-z][a-z0-9-]*", key) and "\n" not in value and "\r" not in value
                for key, value in outputs.items()))
    return "".join(f"{key}={value}\n" for key, value in outputs.items())


def prepare():
    image = published_image()
    if image is None:
        return prepare_local()
    with tempfile.TemporaryDirectory(prefix="pak-action-pull-") as temporary:
        stage = Path(temporary)
        config, home = stage / "docker", stage / "home"
        config.mkdir()
        home.mkdir()
        env = environment()
        env["HOME"] = str(home)
        docker = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", str(config)]
        subprocess.run(docker + ["pull", "--platform", "linux/amd64", image], env=env,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True, timeout=300)
        result = subprocess.run(docker + ["image", "inspect", "--format",
                                         "{{json .RepoDigests}}", image], env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=True, timeout=30)
        require(len(result.stdout) <= 16384)
        digests = json.loads(result.stdout)
        require(isinstance(digests, list) and image in digests)
        result = subprocess.run(docker + ["image", "inspect", "--format",
                                         "{{.Os}}/{{.Architecture}}", image], env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=True, timeout=30)
        require(result.stdout.strip() == b"linux/amd64")
        append(os.environ["GITHUB_OUTPUT"], f"image={image}\n".encode("ascii"))


def prepare_local():
    """Rehydrate only the pinned public dependency, even for an Action archive."""
    with tempfile.TemporaryDirectory(prefix="pak-action-build-") as temporary:
        stage = Path(temporary)
        context, config, home = stage / "context", stage / "docker", stage / "home"
        context.mkdir()
        config.mkdir()
        home.mkdir()
        env = environment()
        env.update(HOME=str(home), GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                   GIT_TERMINAL_PROMPT="0")
        # No credentials, host Git config, policy, workspace or foreign checkout.
        git = ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never"]
        source = stage / "source"
        commands = [git + ["init", "--quiet", str(source)],
                    git + ["-C", str(source), "fetch", "--quiet", "--depth=1",
                           "https://github.com/atenfyr/UAssetAPI.git", UASSET],
                    git + ["-C", str(source), "checkout", "--quiet", "--detach", UASSET]]
        for command in commands:
            subprocess.run(command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True, timeout=180)
        for name in ("Dockerfile", ".dockerignore", "LICENSE", "global.json", "src", "container", "pak_ingest"):
            source_path = ROOT / name
            if source_path.is_dir():
                shutil.copytree(source_path, context / name,
                                ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"))
            else:
                shutil.copyfile(source_path, context / name)
        dependency = context / "vendor/UAssetAPI"
        dependency.parent.mkdir()
        shutil.copytree(source, dependency, ignore=shutil.ignore_patterns(".git"))
        image = "ue-pak-action:" + uuid.uuid4().hex
        subprocess.run(["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", str(config),
                        "build", "--tag", image, str(context)], env=env, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=900)
        append(os.environ["GITHUB_OUTPUT"], f"image={image}\n".encode("ascii"))


def destination(input_key="INPUT_REPORT", default="ue-pak-risk-report.json"):
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    value = os.environ.get(input_key, default)
    require(len(value) <= 512 and re.fullmatch(r"[A-Za-z0-9_./-]+", value) is not None)
    relative = Path(value)
    require(not relative.is_absolute() and ".." not in relative.parts and relative.parts)
    require(relative.parts[0] not in {".git", ".github"})
    target = workspace / relative
    require(not target.exists() and not target.is_symlink())
    parent = target.parent.resolve(strict=True)
    require(parent.is_relative_to(workspace))
    target = parent / target.name
    # Local uses: ./ is supported, but reports cannot enter scanner source trees.
    if target.is_relative_to(ROOT):
        require(ROOT == workspace and target.relative_to(ROOT).parts[0] not in
                {".git", ".github", "scripts", "src", "schemas", "vendor", "container", "pak_ingest", "tests", "docs"})
    for key in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STATE"):
        if os.environ.get(key):
            require(target != Path(os.environ[key]).resolve())
    for key in ("INPUT_PAK", "INPUT_POLICY_RULES", "INPUT_MAPPING", "INPUT_CAPABILITY_SUMMARIES", "INPUT_DATA_RULES", "INPUT_BASELINE_PAK", "INPUT_DATA_CONTEXT", "INPUT_REPORT",
                "INPUT_CAPABILITY_RULES", "INPUT_CAPABILITY_CONTEXT"):
        if key == input_key:
            continue
        if os.environ.get(key):
            require(target != Path(os.environ[key]).resolve())
    return target, value


def outputs(report, path, reason=None):
    result = {"status": "failed", "analysis-complete": "false", "report-path": path,
              "report-available": "false", "diagnostics": compact([reason or "report-unavailable"]),
              "flagged-invocations": "[]", "forbidden-invocations": "[]",
              "arrays-omitted": "true", "omission-reason": reason or "report-unavailable"}
    result.update({"data-analysis-status": "unknown", "data-review-count": "unknown", "data-reject-count": "unknown"})
    result["capability-analysis-status"] = "unknown"
    for effect in ("flagged", "forbidden", "possibly-flagged", "possibly-forbidden"):
        result["capability-" + effect + "-count"] = "unknown"
    for kind in ("invocations", "flagged", "forbidden", "affected-union"):
        result[kind + "-count"] = "unknown"
    if report is None:
        return result
    result.update(status=report["status"], diagnostics=compact(report["diagnostics"]))
    result["analysis-complete"] = str(report["analysis-complete"]).lower()
    result["report-available"] = "true"
    result["arrays-omitted"], result["omission-reason"] = "false", "none"
    data = report.get("data-analysis")
    capability = report.get("capability-analysis")
    result["capability-analysis-status"] = "not-performed" if capability is None else "complete" if capability["complete"] else "incomplete"
    for effect in ("flagged", "forbidden", "possibly-flagged", "possibly-forbidden"):
        result["capability-" + effect + "-count"] = str(sum(f[effect] for f in capability["findings"])) if capability else "0"
    result["data-analysis-status"] = "not-performed" if data is None else "complete" if data["complete"] else "incomplete"
    for action in ("review", "reject"):
        result["data-" + action + "-count"] = str(sum(f["action"] == action for f in data["findings"])) if data else "0"
    for kind, count in report["counts"].items():
        result[kind + "-count"] = str(count)
    for kind in ("flagged", "forbidden"):
        result[kind + "-invocations"] = compact(report[kind + "-invocations"])
    if len(encode_outputs(result).encode("utf-16-le")) > OUTPUT_BUDGET:
        result.update({"flagged-invocations": "[]", "forbidden-invocations": "[]",
                       "arrays-omitted": "true", "omission-reason": "output-budget"})
    return result


def publish(result):
    require(not os.path.samefile(os.environ["GITHUB_OUTPUT"], os.environ["GITHUB_STEP_SUMMARY"]))
    append(os.environ["GITHUB_OUTPUT"], encode_outputs(result).encode("utf-8"))
    # No policy, finding metadata, supplied filenames, links, or annotations.
    summary = ("## Pak static-risk scan\n\n"
               f"Status: {result['status']}. Analysis complete: {result['analysis-complete']}.\n\n"
               f"Flagged: {result['flagged-count']}. Forbidden: {result['forbidden-count']}.\n\n"
                f"Data analysis: {result['data-analysis-status']}. Review: {result['data-review-count']}. Reject: {result['data-reject-count']}.\n\n"
                f"Capability analysis: {result['capability-analysis-status']}. Flagged witnesses: {result['capability-flagged-count']}. Forbidden witnesses: {result['capability-forbidden-count']}.\n\n"
               f"Report available: {result['report-available']}. Arrays omitted: {result['arrays-omitted']}.\n\n"
               "Use the report-path output to collect the authoritative report with restricted access.\n"
               "This is not a safety verdict.\n")
    append(os.environ["GITHUB_STEP_SUMMARY"], summary.encode("ascii"))


def scan():
    report, path, reason, code = None, "", "invalid-action-configuration", 2
    try:
        target, path = destination()
        # Internal prepare-step output, not an Action input.
        reason = "image-preparation-failed"
        image = os.environ["UE_PAK_ACTION_IMAGE"]
        pinned = published_image()
        if pinned is not None:
            require(image == pinned)
        else:
            require(re.fullmatch(r"(?:ue-pak-action:[a-f0-9]{32}|sha256:[a-f0-9]{64})", image) is not None)
        reason = "invalid-action-configuration"
        args = [sys.executable, str(ROOT / "scripts/scan.py"), "scan", "--pak", os.environ.get("INPUT_PAK", ""),
                "--report", str(target), "--image", image]
        for key, default in (("engine-version", "4.25"), ("log-level", "info"),
                             ("fail-on-any-forbidden", "true"), ("fail-on-any-flagged", "false"),
                             ("fail-on-incomplete", "true")):
            args += ["--" + key, os.environ.get("INPUT_" + key.upper().replace("-", "_"), default)]
        for key in ("policy-rules", "content-root", "mapping", "capability-summaries", "data-rules", "baseline-pak", "game-build",
                    "capability-rules", "capability-policy-revision"):
            value = os.environ.get("INPUT_" + key.upper().replace("-", "_"), "")
            if value:
                args += ["--" + key, value]
        if os.environ.get("INPUT_DATA_RULES"):
            private_target, _ = destination("INPUT_DATA_CONTEXT", "")
            require(private_target != target)
            args += ["--data-context", str(private_target)]
        else:
            require(not os.environ.get("INPUT_DATA_CONTEXT"))
        if os.environ.get("INPUT_CAPABILITY_RULES"):
            capability_target, _ = destination("INPUT_CAPABILITY_CONTEXT", "")
            require(capability_target != target)
            args += ["--capability-context", str(capability_target)]
        else:
            require(not os.environ.get("INPUT_CAPABILITY_CONTEXT") and not os.environ.get("INPUT_CAPABILITY_POLICY_REVISION"))
        # The shared renderer owns stderr. Do not decode/re-encode, prefix, or echo it.
        code = subprocess.run(args, env=environment(policy=True), stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, check=False).returncode
        reason = "report-unavailable"
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
            data = stream.read(16 * 1024 * 1024 + 1)
        reason = "invalid-report"
        report = load(data, ROOT)
        require(code in (0, 1, 2, 3))
        require((report["status"] == "failed") == (code in (2, 3)))
    except (OSError, ValueError, KeyError, RecursionError, subprocess.SubprocessError):
        report, code = None, 2 if reason == "invalid-action-configuration" else 3
    result = outputs(report, path, reason)
    try:
        publish(result)
    except (OSError, ValueError, KeyError):
        print("Action output or summary could not be written.", file=sys.stderr)
        return 3
    if report is None:
        print("Action failed; inspect diagnostics and report-available outputs.", file=sys.stderr)
    return code


if __name__ == "__main__":
    if sys.argv[1:] == ["prepare"]:
        try:
            prepare()
        except (OSError, ValueError, KeyError, RecursionError, subprocess.SubprocessError):
            print("Trusted image preparation failed; check the image manifest, Docker and public connectivity.", file=sys.stderr)
            sys.exit(3)
    elif sys.argv[1:] == ["scan"]:
        sys.exit(scan())
    else:
        sys.exit(2)
