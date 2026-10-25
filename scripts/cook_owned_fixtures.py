#!/usr/bin/env python3
"""Build and cook original fixtures using an already installed authorized image."""

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import uuid
from pathlib import Path

from owned_fixture_usmap import encode

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:fe577896540682373f41e0c4fb5612c95a702c32535b7c1d17ee7637a013fc9c"
ENGINE_COMMIT = "2d1aaeede6780b14c3ef97272e8a68c3429d8231"
BUILD = "/opt/unreal-engine/Engine/Build/BatchFiles/Linux/Build.sh OwnedFixturesEditor Linux Development /work/OwnedFixtures.uproject -WaitMutex -NoHotReload -NoDebugInfo -MaxParallelActions=8"
EDITOR = "/opt/unreal-engine/Engine/Binaries/Linux/UE4Editor /work/OwnedFixtures.uproject"
FLAGS = "-unattended -NullRHI -NoSound -nop4"
COMMANDS = [
    BUILD,
    f"{EDITOR} -run=GenerateOwnedFixtures {FLAGS}",
    f"{EDITOR} -run=Cook {FLAGS} -TargetPlatform=LinuxNoEditor -CookSinglePackage -Map=/Game/BP_OwnedParent+/Game/BP_OwnedChild+/Game/OwnedMap+/Game/Data/OwnedData -OutputDir=/work/tagged",
    f"{EDITOR} -run=Cook {FLAGS} -TargetPlatform=LinuxNoEditor -CookSinglePackage -Map=/Game/Data/OwnedData -unversioned -OutputDir=/work/unversioned",
]


def hashes(directory):
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(directory.rglob("*")) if p.is_file()}


def terminate(signum, frame):
    raise SystemExit(128 + signum)


def reap(client):
    if client is not None:
        try:
            os.killpg(client.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        client.wait(timeout=5)


def cleanup(client, name):
    """Reap the isolated client, then stop/remove only this job's container."""
    errors = []
    try:
        reap(client)
    except (OSError, subprocess.TimeoutExpired) as error:
        errors.append(f"client: {error}")
    for command, timeout in ((["docker", "stop", "--time", "5", name], 10),
                             (["docker", "rm", "--force", name], 10)):
        cleaner = None
        try:
            cleaner = subprocess.Popen(command, start_new_session=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            _, stderr = cleaner.communicate(timeout=timeout)
            if cleaner.returncode:
                errors.append(f"{command[1]}: {stderr.strip()}")
        except (OSError, subprocess.TimeoutExpired) as error:
            errors.append(f"{command[1]}: {error}")
        finally:
            try:
                reap(cleaner)
            except (OSError, subprocess.TimeoutExpired) as error:
                errors.append(f"{command[1]} client: {error}")
            if cleaner is not None:
                for stream in (cleaner.stdout, cleaner.stderr):
                    stream.close()
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new external directory; never a tracked path")
    parser.add_argument("--timeout", type=int, default=1800, help="total runtime limit, seconds (1..3600)")
    parser.add_argument("--ddc-seed", type=Path, help="optional authorized local engine derived-data cache")
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents or output.exists():
        parser.error("output must be a new directory outside this checkout")
    if not 1 <= args.timeout <= 3600:
        parser.error("timeout must be 1..3600 seconds")
    seed = args.ddc_seed.resolve() if args.ddc_seed else None
    if seed and not seed.is_dir():
        parser.error("DDC seed must be a directory")
    disk_free = shutil.disk_usage(output.parent).free
    if disk_free < 8 * 1024**3:
        parser.error("at least 8 GiB free disk required")
    available = next(int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines()
                     if line.startswith("MemAvailable:"))
    if available < 18 * 1024**3:
        parser.error("at least 18 GiB available memory required")
    # Inspect only; Docker must never pull an image for this job.
    subprocess.run(["docker", "image", "inspect", IMAGE], check=True, stdout=subprocess.DEVNULL)
    output.mkdir(mode=0o777)
    output.chmod(0o777)  # Container UID 1001; contains only disposable job artifacts.
    cache = output / "engine-ddc"
    cache.mkdir(mode=0o777)
    cache.chmod(0o777)
    name = "owned-fixtures-" + uuid.uuid4().hex
    script = "set -euo pipefail\ncp -r /source/. /work/\n"
    if seed:
        script += "cp -r /seed/. /opt/unreal-engine/Engine/DerivedDataCache/\n"
    for label, command in zip(["build", "generate", "tagged", "unversioned"], COMMANDS):
        script += f"{command} > /work/{label}.log 2>&1\n"
    runtime = ["docker", "run", "--pull=never", "--name", name, "--network", "none",
               "--user", "1001:1001", "--cpus", "8", "--memory", "16g", "--memory-swap", "16g",
               "--pids-limit", "1024", "--cap-drop=ALL", "--security-opt=no-new-privileges",
               "--mount", f"type=bind,src={ROOT / 'fixtures/owned'},dst=/source,readonly",
               "--mount", f"type=bind,src={output},dst=/work", "--entrypoint", "/bin/bash", IMAGE,
               "-lc", script]
    runtime[2:2] = ["--mount", f"type=bind,src={cache},dst=/opt/unreal-engine/Engine/DerivedDataCache"]
    if seed:
        runtime[2:2] = ["--mount", f"type=bind,src={seed},dst=/seed,readonly"]
    receipt = {"image_id": IMAGE, "engine_commit": ENGINE_COMMIT, "target": "LinuxNoEditor",
               "preflight": {"disk_free_bytes": disk_free, "memory_available_bytes": available},
               "commands": COMMANDS, "runtime_argv": runtime,
               "source_sha256": hashes(ROOT / "fixtures/owned"),
               "tool_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in (Path(__file__), ROOT / "scripts/owned_fixture_usmap.py")},
               "ddc_seed": str(seed) if seed else None,
               "completed": False, "exit_code": 1}
    client = None
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        signal.signal(signal.SIGINT, signal.default_int_handler)
        signal.signal(signal.SIGTERM, terminate)
        client = subprocess.Popen(runtime, start_new_session=True)
        receipt["exit_code"] = client.wait(timeout=args.timeout)
        if receipt["exit_code"]:
            return receipt["exit_code"]
        # Verification/mapping errors must not retain Docker's successful exit code.
        receipt["exit_code"] = 1
        expected = {
            "tagged": ["BP_OwnedParent.uasset", "BP_OwnedChild.uasset", "OwnedMap.umap", "Data/OwnedData.uasset"],
            "unversioned": ["Data/OwnedData.uasset"],
        }
        for folder, packages in expected.items():
            for package in packages:
                if not (output / folder / "OwnedFixtures/Content" / package).is_file():
                    raise RuntimeError(f"missing cooked output: {folder}/{package}")
            actual = {str(p.relative_to(output / folder)) for p in (output / folder).rglob("*")
                      if p.suffix.lower() in (".uasset", ".umap")}
            wanted = {"OwnedFixtures/Content/" + package for package in packages}
            if actual != wanted:
                raise RuntimeError(f"unexpected cooked packages in {folder}: {sorted(actual - wanted)}")
        reflection = json.loads((output / "Saved/producer-reflection.json").read_text(encoding="utf-8-sig"))
        (output / "owned.usmap").write_bytes(encode(reflection))
        receipt["producer_reflection"] = reflection
        receipt["completed"] = True
        receipt["exit_code"] = 0
        return 0
    except subprocess.TimeoutExpired:
        receipt["timed_out"] = True
        receipt["exit_code"] = 124
        return 124
    except KeyboardInterrupt:
        receipt["completed"] = False
        receipt["exit_code"] = 130
        receipt["interrupted"] = True
        raise
    except SystemExit as error:
        receipt["completed"] = False
        receipt["exit_code"] = error.code if isinstance(error.code, int) and error.code else 1
        receipt["interrupted"] = True
        raise
    finally:
        # A second cancellation must not interrupt bounded teardown or its receipt.
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        try:
            errors = cleanup(client, name)
            cleanup_failed_success = bool(errors) and receipt["exit_code"] == 0
            if errors:
                receipt["cleanup_errors"] = errors
                receipt["completed"] = False
                if receipt["exit_code"] == 0:
                    receipt["exit_code"] = 1
            receipt["output_sha256"] = {folder: hashes(output / folder)
                                     for folder in ("tagged", "unversioned") if (output / folder).exists()}
            receipt["evidence_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in output.glob("*.log")}
            if (output / "owned.usmap").exists():
                receipt["usmap_sha256"] = hashlib.sha256((output / "owned.usmap").read_bytes()).hexdigest()
            (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            if cleanup_failed_success:
                raise RuntimeError("container cleanup failed; see receipt.json")
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
