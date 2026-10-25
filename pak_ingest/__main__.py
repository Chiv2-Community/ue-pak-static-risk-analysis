"""Dedicated foundation CLI; not the shared reporting interface (#11)."""

import argparse
import json

from . import ingest


def main():
    parser = argparse.ArgumentParser(description="Bounded V9 ingestion evidence; no safety verdict")
    parser.add_argument("archive")
    args = parser.parse_args()
    report = ingest(args.archive)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ingestion_status"] == "validated" else 1


if __name__ == "__main__":
    raise SystemExit(main())
