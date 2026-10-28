#!/usr/bin/env python3
"""Local trusted-platform handoff. No network, policy evaluation or autoapproval."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

import report_validation as reports
from scan import write_report

ROOT = Path(__file__).resolve().parents[1]
JSON_LIMIT = 16 * 1024 * 1024
PAK_LIMIT = 256 * 1024 * 1024
DEPENDENCY_LIMIT = 16 * 1024 * 1024


def consume(path, limit, accept):
    """Read a stable regular file in bounded chunks; never follow its final link."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb", buffering=0) as stream:
        before = os.fstat(fd)
        reports.require(stat.S_ISREG(before.st_mode) and before.st_size <= limit)
        count = 0
        while chunk := stream.read(min(65536, limit - count + 1)):
            count += len(chunk)
            reports.require(count <= limit)
            accept(chunk)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        reports.require(identity(before) == identity(after) and count == before.st_size)


def read(path):
    data = bytearray()
    consume(path, JSON_LIMIT, data.extend)
    return bytes(data)


def digest(path, limit):
    value = hashlib.sha256()
    consume(path, limit, value.update)
    return value.hexdigest()


def validate(value, profile):
    documents = {name: json.loads((ROOT / "schemas" / name).read_bytes()) for name in
                 ("moderation-v1.schema.json", "report-v1.schema.json", "facts-v1.schema.json")}
    for document in documents.values():
        reports.check_schema(document)
    document = documents["moderation-v1.schema.json"]
    reports.validate(value, document["$defs"][profile], document, documents)
    if profile == "context":
        context = value["report-context"]
        reports.require(context["pak-sha256"] is not None and "policy-revision" in context)
        for key in ("tool-version", "producer-version"):
            reports.require(isinstance(context[key], str) and
                            re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", context[key]) is not None)
        kinds = [d["kind"] for d in context["dependencies"]]
        reports.require(len(kinds) == len(set(kinds)))
        reports.require(all(re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", kind) for kind in kinds))
        # Dependency order is not identity. Reject noncanonical storage rather
        # than making equivalent records compare differently at approval time.
        reports.require(kinds == sorted(kinds))
        if "data-context" in value:
            private = value["data-context"]
            reports.require(private["game-build"] == value["game-build"])
            private_kinds = [d["kind"] for d in private["dependencies"]]
            reports.require(private_kinds == sorted(set(private_kinds)) and "data-rules" in private_kinds)
            reports.require(not set(private_kinds) & set(kinds))
        if "capability-context" in value:
            private = value["capability-context"]
            reports.require("capability-rules" not in kinds)
            summaries = [d["sha256"] for d in context["dependencies"] if d["kind"] == "capability-summaries"]
            reports.require(summaries == ([] if private["catalog-sha256"] is None else [private["catalog-sha256"]]))
    elif profile in ("handoff", "feedback"):
        if profile == "handoff":
            validate(value["context"], "context")
        counts, coverage = value["counts"], value["coverage"]
        reports.require(max(counts["flagged"], counts["forbidden"]) <= counts["affected-union"] <=
                        min(counts["invocations"], counts["flagged"] + counts["forbidden"]))
        incomplete = bool(coverage["gaps"] or coverage["evaluation-incomplete"]
                          or not value.get("data-analysis", {}).get("complete", True)
                          or value.get("content-policy", {}).get("incomplete", False)
                          or not value.get("call-chain-analysis", {}).get("complete", True)
                          or not value.get("capability-analysis", {}).get("complete", True))
        reports.require(value["analysis-complete"] == (not incomplete))
        if value["status"] == "failed":
            reports.require(incomplete and not any(counts.values()))
        else:
            reports.require(value["status"] == ("partial" if incomplete else "successful"))
        reports.require(value["routes"] == routes(value))
        if "property-write-counts" in value:
            writes = value["property-write-counts"]
            reports.require(max(writes["flagged"], writes["forbidden"]) <= writes["observed"])
            reports.require(value["status"] != "failed" or not any(writes.values()))
        if "data-analysis" in value:
            data = value["data-analysis"]
            reports.require(data["decision"] == ("reject" if data["reject-count"] else "needs-review" if data["review-count"] else "no-match"))
        if profile == "handoff" and value["status"] != "failed":
            reports.require(("data-analysis" in value) == ("data-context" in value["context"]))
            reports.require(("capability-analysis" in value) == ("capability-context" in value["context"]))
    elif profile == "review":
        validate(value["handoff"], "handoff")
        datetime.strptime(value["time"], "%Y-%m-%dT%H:%M:%SZ")
        reports.require(value["actor"].strip() and value["rationale"].strip())
        value["actor"].encode("utf-8", "strict")
        value["rationale"].encode("utf-8", "strict")
        reports.require(all(ord(c) >= 32 and ord(c) != 127 for c in value["actor"]))
        reports.require(value["decision"] != "approve" or value["handoff"]["status"] != "failed")
    return value


def load(path, profile):
    value = json.loads(read(path).decode("utf-8", "strict"), object_pairs_hook=reports.pairs,
                       parse_constant=lambda _: reports.require(False))
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        reports.require(depth <= 32 and nodes <= 250000)
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            item.encode("utf-8", "strict")
    return validate(value, profile)


def verify_bytes(context, pak, dependencies):
    validate(context, "context")
    expected = context["report-context"]
    reports.require(digest(pak, PAK_LIMIT) == expected["pak-sha256"])
    identities = (expected["dependencies"] + context.get("data-context", {}).get("dependencies", [])
                  + context.get("capability-context", {}).get("dependencies", []))
    reports.require(len(dependencies) == len(identities))
    actual = [{"kind": kind, "sha256": digest(path, PAK_LIMIT if kind == "baseline-pak" else DEPENDENCY_LIMIT)} for kind, path in dependencies]
    reports.require(sorted(actual, key=lambda d: d["kind"]) == sorted(identities, key=lambda d: d["kind"]))


def routes(value):
    if value["status"] == "failed":
        return ["operational-failed"]
    result = []
    if (value["counts"]["forbidden"] or value.get("property-writes", {}).get("forbidden")
            or value.get("property-write-counts", {}).get("forbidden", 0)
            or value.get("content-policy", {}).get("decision") == "reject"
            or value.get("data-analysis", {}).get("decision") == "reject"
            or value.get("capability-analysis", {}).get("decision") == "reject"):
        result.append("policy-violation")
    if (value["counts"]["flagged"] or value.get("property-writes", {}).get("flagged")
            or value.get("property-write-counts", {}).get("flagged", 0)
            or value.get("content-policy", {}).get("decision") == "needs-review"
            or value.get("data-analysis", {}).get("decision") == "needs-review"
            or value.get("capability-analysis", {}).get("decision") == "needs-review"
            or value.get("call-chains", value.get("call-chain-analysis", {})).get("needs-review", False)):
        result.append("needs-review")
    if not value["analysis-complete"]:
        result.append("analysis-incomplete")
    return result or ["qualified-completed"]


def handoff(report_data, context, pak, dependencies):
    """Accept report bytes through the shared strict default report loader."""
    report = reports.load(report_data, ROOT)
    verify_bytes(context, pak, dependencies)
    if report["status"] != "failed":
        reports.require(("data-analysis" in report) == ("data-context" in context))
        reports.require(("capability-analysis" in report) == ("capability-context" in context))
    if "capability-context" in context:
        reports.require(context["capability-context"]["report-sha256"] == hashlib.sha256(report_data).hexdigest())
    if "data-context" in context:
        reports.require(context["data-context"]["report-sha256"] == hashlib.sha256(report_data).hexdigest())
        if "data-analysis" in report:
            kinds = {d["kind"] for d in context["data-context"]["dependencies"]}
            reports.require(("baseline-pak" in kinds) == ("data-baseline-unavailable" not in report["data-analysis"]["diagnostics"]))
    if report["status"] != "failed":
        expected = deepcopy(context["report-context"])
        actual = deepcopy(report["context"])
        actual["dependencies"].sort(key=lambda d: d["kind"])
        reports.require(actual == expected)
    # Failure reports can lack identities. They route operations only and cannot
    # be approved; trusted context still identifies the attempted submission.
    value = {"schema-version": 1, "kind": "moderation-handoff", "context": deepcopy(context),
             "report-sha256": hashlib.sha256(report_data).hexdigest(),
             **{key: deepcopy(report[key]) for key in ("status", "analysis-complete", "counts", "coverage")},
             "routes": routes(report)}
    if "content-policy" in report:
        value["content-policy"] = deepcopy(report["content-policy"])
    if "property-writes" in report:
        writes = report["property-writes"]
        value["property-write-counts"] = {"observed": writes["observed"],
            "flagged": len(writes["flagged"]), "forbidden": len(writes["forbidden"])}
    if "call-chains" in report:
        value["call-chain-analysis"] = {key: report["call-chains"][key] for key in ("complete", "needs-review")}
    if "capability-analysis" in report:
        value["capability-analysis"] = {key: report["capability-analysis"][key] for key in ("complete", "decision")}
    if "data-analysis" in report:
        data = report["data-analysis"]
        value["data-analysis"] = {"complete": data["complete"], "decision": data["decision"],
            "review-count": sum(f["action"] == "review" for f in data["findings"]),
            "reject-count": sum(f["action"] == "reject" for f in data["findings"])}
    return validate(value, "handoff")


def review(value, actor, decision, rationale, now=None):
    validate(value, "handoff")
    now = datetime.now(timezone.utc) if now is None else now
    reports.require(now.tzinfo is not None and now.utcoffset() is not None)
    record = {"schema-version": 1, "kind": "human-review", "handoff": deepcopy(value),
              "actor": actor, "time": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "decision": decision, "rationale": rationale}
    return validate(record, "review")


def verify(record, context, pak, dependencies, report_data):
    validate(record, "review")
    reports.require(record["handoff"] == handoff(report_data, context, pak, dependencies))
    return record["decision"] == "approve"


def feedback(value):
    validate(value, "handoff")
    public = {key: deepcopy(value[key]) for key in
              ("schema-version", "status", "analysis-complete", "counts", "coverage", "routes")}
    public["kind"] = "submitter-feedback"
    if "content-policy" in value:
        public["content-policy"] = deepcopy(value["content-policy"])
    if "property-write-counts" in value:
        public["property-write-counts"] = deepcopy(value["property-write-counts"])
    if "call-chain-analysis" in value:
        public["call-chain-analysis"] = deepcopy(value["call-chain-analysis"])
    if "capability-analysis" in value:
        public["capability-analysis"] = deepcopy(value["capability-analysis"])
    if "data-analysis" in value:
        public["data-analysis"] = deepcopy(value["data-analysis"])
    return validate(public, "feedback")


class Arguments(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, allow_abbrev=False, **kwargs)

    def error(self, message):
        raise reports.InvalidReport("invalid-input")


def main(argv=None):
    try:
        argv = sys.argv[1:] if argv is None else argv
        seen = set()
        for token in argv:
            if token.startswith("--"):
                key = token.split("=", 1)[0]
                reports.require(key == "--dependency" or key not in seen)
                seen.add(key)
        parser = Arguments(description=__doc__)
        commands = parser.add_subparsers(dest="command", required=True, parser_class=Arguments)
        for command in ("handoff", "review", "verify", "feedback"):
            child = commands.add_parser(command)
            if command in ("handoff", "verify"):
                for key in ("context", "pak", "report"):
                    child.add_argument("--" + key, required=True)
                child.add_argument("--dependency", action="append", default=[], metavar="KIND=PATH")
            if command != "verify":
                child.add_argument("--output", required=True)
            if command == "review":
                for key in ("handoff", "actor", "decision", "rationale"):
                    child.add_argument("--" + key, required=True)
            elif command == "verify":
                child.add_argument("--approval", required=True)
            elif command == "feedback":
                child.add_argument("--handoff", required=True)
        args = parser.parse_args(argv)
        if args.command in ("handoff", "verify"):
            context = load(args.context, "context")
            dependencies = []
            for value in args.dependency:
                kind, path = value.split("=", 1)
                reports.require(kind and path)
                dependencies.append((kind, path))
        if args.command == "handoff":
            value = handoff(read(args.report), context, args.pak, dependencies)
        elif args.command == "review":
            value = review(load(args.handoff, "handoff"), args.actor, args.decision, args.rationale)
        elif args.command == "feedback":
            value = feedback(load(args.handoff, "handoff"))
        else:
            approved = verify(load(args.approval, "review"), context, args.pak, dependencies, read(args.report))
            print("Approved bytes and context." if approved else "Not approved.")
            return 0 if approved else 1
        write_report(args.output, (reports.compact(value) + "\n").encode("utf-8"))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
        print("Moderation input or verification failed.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
