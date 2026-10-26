#!/usr/bin/env python3
"""Package reviewed Git objects, never workspace bytes or submodule archives."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

from action import image_manifest

UASSET = "b4e8a012939295a6fd890ddc64e57ea78b709b95"
ROOT_FILES = {"LICENSE", "README.md", "Dockerfile", ".dockerignore", "global.json",
              "action.yml", "action-image.json"}
CONTAINER_FILES = {"container/ExcludeUnused.targets", "container/CORRESPONDING-SOURCE.md",
                   "container/licenses/MIT.txt", "container/licenses/README.md", "container/source-files.txt"}
SCRIPT_FILES = {"scripts/" + name + ".py" for name in
                ("action", "action_report", "report_validation", "scan", "moderation",
                 "probe_pak", "regression_corpus", "owned_fixture_usmap", "cook_owned_fixtures",
                 "escalation_canary", "source_bundle")}
FIXTURE_FILES = {"fixtures/corpus/expectations.json", "fixtures/corpus/package-context-expectations.json",
                 "fixtures/corpus/policy.yaml"}
EXAMPLE_FILES = {"examples/" + p for p in ("capability-rules-v1.json", "capability-summaries-v1.json",
    "facts-v1.json", "starter-policy.yaml", "moderation/context.json", "moderation/mapping.txt",
    "moderation/report.json", "moderation/routes.json", "moderation/submission.txt",
    "reports/failed-v1.json", "reports/partial-v1.json", "reports/successful-v1.json")}


def require(value):
    if not value:
        raise ValueError("source bundle input rejected")


def git(repository, *args):
    return subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-C", str(repository), *args],
                          env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "GIT_NO_REPLACE_OBJECTS": "1",
                               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
                          check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=60).stdout


def tree(repository, commit):
    require(re.fullmatch(r"[a-f0-9]{40}", commit) is not None)
    require(git(repository, "rev-parse", commit + "^{commit}").decode().strip() == commit)
    result = {}
    for record in git(repository, "ls-tree", "-rz", commit).split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8")
        require(not PurePosixPath(path).is_absolute() and ".." not in PurePosixPath(path).parts)
        result[path] = (mode, kind, oid)
    return result


def allowed(path):
    p = PurePosixPath(path)
    if path in ROOT_FILES | CONTAINER_FILES | SCRIPT_FILES | FIXTURE_FILES | EXAMPLE_FILES | {".github/workflows/release-candidate.yml"}:
        return True
    if any(part in {"bin", "obj", ".git", "__pycache__"} for part in p.parts):
        return False
    if p.parts[0] == "src":
        return p.suffix in {".cs", ".csproj"} or p.name == "packages.lock.json"
    if len(p.parts) == 2 and p.parts[0] == "pak_ingest":
        return p.suffix == ".py"
    if len(p.parts) == 2 and p.parts[0] == "schemas":
        return p.name.endswith(".schema.json")
    if len(p.parts) == 2 and p.parts[0] == "docs":
        return p.suffix == ".md"
    if p.parts[0] == "tests":
        return p.suffix in {".py", ".cs", ".csproj"} or p.name in {"packages.lock.json", "requirements.txt"}
    return False


def image_input(path):
    return path in {"Dockerfile", ".dockerignore", "global.json", "LICENSE", "vendor/UAssetAPI"} or path.startswith(
        ("src/", "container/", "pak_ingest/"))


def read_blob(repository, entry):
    mode, kind, oid = entry
    require(mode in {"100644", "100755"} and kind == "blob")
    size = int(git(repository, "cat-file", "-s", oid))
    require(size <= 2 * 1024 * 1024)
    return git(repository, "cat-file", "blob", oid)


def collect(repository, build_source, action_source, dependency):
    build, action = tree(repository, build_source), tree(repository, action_source)
    # B may only change files outside the Docker COPY inputs. Labels still name A.
    require({p: v for p, v in build.items() if image_input(p)} ==
            {p: v for p, v in action.items() if image_input(p)})
    require(build.get("vendor/UAssetAPI") == ("160000", "commit", UASSET))
    inventory = read_blob(repository, action["container/source-files.txt"]).decode("utf-8").splitlines()
    require(len(inventory) == len(set(inventory)) and all(allowed(p) for p in inventory))
    require(set(inventory) - {"action-image.json"} <= action.keys())
    # No silently omitted new runtime/build input; the tracked inventory needs review.
    require({p for p in action if image_input(p) and p != "vendor/UAssetAPI"} <= set(inventory))
    files = {p: read_blob(repository, action[p]) for p in inventory if p in action}
    if "action-image.json" in files:
        require(image_manifest(files["action-image.json"])["build-source"] == build_source)
    require((ROOT_FILES - {"action-image.json"}) | CONTAINER_FILES | SCRIPT_FILES <= files.keys())
    vendor = tree(dependency, UASSET)
    selected = {p: entry for p, entry in vendor.items() if
                p in {"LICENSE", "NOTICE.md", "README.md"} or
                (p.startswith("UAssetAPI/") and PurePosixPath(p).suffix in {".cs", ".csproj"})}
    require({"LICENSE", "NOTICE.md", "README.md", "UAssetAPI/UAssetAPI.csproj"} <= selected.keys())
    files.update({"vendor/UAssetAPI/" + p: read_blob(dependency, entry) for p, entry in selected.items()})
    # Excluded: borrowed test assets, AC7 key, native repak binaries and resource table.
    # ExcludeUnused.targets removes these resources from the actual scanner build.
    require(sum(map(len, files.values())) <= 32 * 1024 * 1024)
    manifest = {"schema-version": 1, "build-source": build_source, "action-source": action_source,
                "uassetapi-source": UASSET, "version": "v0.1.0", "files": [
                    {"path": p, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                    for p, data in sorted(files.items())]}
    files["SOURCE-MANIFEST.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    return files


def archive(files, output):
    # Exclusive create; deterministic metadata, regular files only, no Git directory.
    with Path(output).open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for path, data in sorted(files.items()):
                    require(not PurePosixPath(path).is_absolute() and ".." not in PurePosixPath(path).parts)
                    entry = tarfile.TarInfo("ue-pak-static-risk-analysis/" + path)
                    entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
                    tar.addfile(entry, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--build-source", required=True)
    parser.add_argument("--action-source", required=True)
    parser.add_argument("--uasset-repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    archive(collect(args.repository, args.build_source, args.action_source, args.uasset_repository), args.output)


if __name__ == "__main__":
    main()
