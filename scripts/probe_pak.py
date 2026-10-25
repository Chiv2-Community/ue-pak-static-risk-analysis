"""Reproduce the trusted-local-input experiment for issue #2, not a submission service."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


class UnsupportedInput(ValueError):
    pass


def validate_format(pak: Path, info: str) -> None:
    if pak.suffix.lower() != ".pak":
        raise UnsupportedInput("Only legacy .pak input is supported in this experiment.")
    if pak.with_suffix(".utoc").exists() or pak.with_suffix(".ucas").exists():
        raise UnsupportedInput("IoStore companions require a separate compatibility evaluation.")
    lines = set(info.splitlines())
    if "version: V9" not in lines:
        raise UnsupportedInput("This experiment requires UE 4.25 V9 pak format.")
    if "encrypted index: false" not in lines:
        raise UnsupportedInput("Encrypted indexes are not supported by this experiment.")
    if not {"compression: None", "compression: Zlib"}.intersection(lines):
        raise UnsupportedInput("Only uncompressed or Zlib paks are evaluated here; no Oodle auto-download.")


def run(args: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, env=environment, capture_output=True, text=True, timeout=120, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pak", required=True, type=Path)
    parser.add_argument("--repak", required=True, type=Path)
    parser.add_argument("--probe-dll", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="New output directory; never overwritten.")
    parser.add_argument("--mappings", type=Path)
    options = parser.parse_args()
    # The probe does not evaluate policy. Do not expose a caller's policy to parsers.
    environment = os.environ.copy()
    environment.pop("UE_PAK_POLICY_RULES", None)
    output = options.output.resolve()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError:
        print("Output must be a new writable directory.", file=sys.stderr)
        return 1
    record: dict = {"schema-version": 1, "purpose": "compatibility-only", "analysis-complete": False}
    exit_code = 1
    try:
        pak = options.pak.resolve(strict=True)
        # Reject unsupported companions/extensions before invoking either parser.
        if pak.suffix.lower() != ".pak" or pak.with_suffix(".utoc").exists() or pak.with_suffix(".ucas").exists():
            raise UnsupportedInput("Expected a legacy pak without IoStore companions.")
        with pak.open("rb") as stream:
            record["pak-sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        record["pak-size"] = pak.stat().st_size
        extractor = str(options.repak.resolve(strict=True))
        info = run([extractor, "info", str(pak)], environment)
        if info.returncode:
            raise UnsupportedInput("Pak metadata could not be read; missing key, corruption, or unsupported format. No fallback.")
        validate_format(pak, info.stdout)
        record["pak-info"] = info.stdout.splitlines()
        extraction = run([extractor, "unpack", str(pak), "--output", str(output / "extracted"), "--quiet"], environment)
        if extraction.returncode:
            raise UnsupportedInput("Extraction failed; encrypted payloads/custom codecs are not silently skipped.")
        args = ["dotnet", str(options.probe_dll.resolve(strict=True)), str(output / "extracted"), str(output / "assets.json")]
        if options.mappings:
            args.append(str(options.mappings.resolve(strict=True)))
        probe = run(args, environment)
        record["probe-exit-code"] = probe.returncode
        if probe.returncode not in (0, 2) or not (output / "assets.json").is_file():
            raise UnsupportedInput("Asset probe failed; no successful compatibility result.")
        record["status"] = "parser-complete" if probe.returncode == 0 else "incomplete"
        exit_code = probe.returncode
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        record["status"] = "error"
        # Only application-owned unsupported-input messages are included.
        record["diagnostic"] = str(error) if isinstance(error, UnsupportedInput) else type(error).__name__
    finally:
        (output / "experiment.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"Compatibility experiment: {record['status']}; analysis-complete=false.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
