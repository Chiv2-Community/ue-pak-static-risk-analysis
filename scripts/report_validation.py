"""Bounded validation of the shipped report schema; no policy evaluation."""

import json
from pathlib import Path
import re


class InvalidReport(ValueError):
    pass


def require(condition):
    if not condition:
        raise InvalidReport("invalid-report")


def compact(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def location_key(location):
    return (location["asset"], location["function"], location["offset"])


def invocation_key(location, target):
    return (*location_key(location), None if target is None else (target["owner"], target["function"]))


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def check_schema(schema):
    # Fail closed if schema evolution needs a keyword this adapter cannot enforce.
    require(schema.keys() <= {"$schema", "$id", "title", "description", "$defs", "$ref", "type",
                              "const", "enum", "required", "properties", "additionalProperties",
                              "minimum", "maximum", "minLength", "maxLength", "pattern",
                              "minItems", "maxItems", "uniqueItems", "items", "allOf", "oneOf", "if", "then"})
    for key in ("properties", "$defs"):
        for child in schema.get(key, {}).values():
            check_schema(child)
    for key in ("items", "if", "then"):
        if key in schema:
            check_schema(schema[key])
    for key in ("allOf", "oneOf"):
        for child in schema.get(key, []):
            check_schema(child)


def validate(value, schema, document, documents):
    """Only keywords used by the shipped closed local schemas are supported."""
    if "$ref" in schema:
        name, pointer = schema["$ref"].split("#", 1)
        target = documents[name] if name else document
        part = target
        for key in pointer.lstrip("/").split("/"):
            part = part[key]
        validate(value, part, target, documents)
    if "type" in schema:
        types = schema["type"]
        types = types if isinstance(types, list) else [types]
        kind = {dict: "object", list: "array", str: "string", int: "integer",
                bool: "boolean", type(None): "null"}.get(type(value))
        require(kind in types)
    if "const" in schema:
        require(type(value) is type(schema["const"]) and value == schema["const"])
    if "enum" in schema:
        require(value in schema["enum"])
    if isinstance(value, dict):
        require(set(schema.get("required", [])) <= value.keys())
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            require(value.keys() <= properties.keys())
        for key, child in properties.items():
            if key in value:
                validate(value[key], child, document, documents)
    elif isinstance(value, list):
        require(schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)))
        if schema.get("uniqueItems"):
            require(len({compact(item) for item in value}) == len(value))
        if "items" in schema:
            for item in value:
                validate(item, schema["items"], document, documents)
    elif isinstance(value, str):
        require(schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)))
        if "pattern" in schema:
            # JSON Schema's $ can match before a trailing LF; our wire IDs cannot.
            require(re.fullmatch(schema["pattern"].removeprefix("^").removesuffix("$"), value) is not None)
    elif type(value) is int:
        require(schema.get("minimum", value) <= value <= schema.get("maximum", value))
    for child in schema.get("allOf", []):
        validate(value, child, document, documents)
    if "oneOf" in schema:
        require(sum(matches(value, child, document, documents) for child in schema["oneOf"]) == 1)
    if "if" in schema and matches(value, schema["if"], document, documents):
        validate(value, schema["then"], document, documents)


def matches(value, schema, document, documents):
    try:
        validate(value, schema, document, documents)
        return True
    except InvalidReport:
        return False


def load(data, root, *, moderator_detail=False):
    # Only trusted operator callers may select detail; public consumers stay strict.
    require(type(moderator_detail) is bool)
    require(len(data) <= 16 * 1024 * 1024)
    report = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=pairs,
                        parse_constant=lambda _: require(False))
    pending, nodes = [(report, 0)], 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        require(depth <= 32 and nodes <= 250000)
        if isinstance(value, dict):
            require(moderator_detail or "rule-ids" not in value)
            pending.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, str):
            value.encode("utf-8", "strict")
    documents = {name: json.loads((Path(root) / "schemas" / name).read_bytes())
                 for name in ("report-v1.schema.json", "facts-v1.schema.json")}
    for document in documents.values():
        check_schema(document)
    schema = documents["report-v1.schema.json"]
    validate(report, schema, schema, documents)
    counts = report["counts"]
    sets = []
    by_id = {}
    finding_identities = {}
    for kind in ("flagged", "forbidden"):
        findings = report[kind + "-invocations"]
        finding_identities[kind] = {invocation_key(f["location"], f["target"]) for f in findings}
        ids = {item["id"] for item in findings}
        require(len(ids) == len(findings) == counts[kind])
        sets.append(ids)
        for item in findings:
            require((item["argument-metadata"] == "known") == (item["known-argument-count"] is not None))
            # Rule IDs describe this effect; every other field identifies the shared invocation.
            shared = {key: value for key, value in item.items() if key != "rule-ids"}
            require(item["id"] not in by_id or by_id[item["id"]] == shared)
            by_id[item["id"]] = shared
    require(len(sets[0] | sets[1]) == counts["affected-union"] <= counts["invocations"])
    dispatch_origins = {}
    candidate_count = 0
    binding_origin_count = 0
    for dispatch in report.get("possible-dispatches", []):
        evidence = dispatch["evidence"]
        origin = location_key(evidence["origin"])
        require(origin not in dispatch_origins)
        dispatch_origins[origin] = evidence["kind"]
        require("open-world" in evidence["diagnostics"])
        require("unresolved-dispatch" in report["coverage"]["gaps"])
        require(evidence["source"] == ("ue425plus-2d1aae-kismet-timer" if evidence["kind"] == "timer" else "kismet-serialized-v1"))
        if evidence["kind"] == "timer":
            require("native-build-unverified" in evidence["diagnostics"])
        require(len({(c["owner"], c["function"]) for c in evidence["candidates"]}) == len(evidence["candidates"]))
        if evidence["kind"] != "multicast":
            require(all(evidence["function-name"] is not None and c["function"].lower() == evidence["function-name"].lower()
                        for c in evidence["candidates"]))
        bindings = evidence.get("possible-binding-origins", [])
        binding_origin_count += len(bindings)
        require(binding_origin_count <= 10000)
        require(len({location_key(b) for b in bindings}) == len(bindings))
        require(all(b["asset"] == evidence["origin"]["asset"] and b["function"] == evidence["origin"]["function"]
                    and b["offset"] < evidence["origin"]["offset"] for b in bindings))
        candidate_count += len(evidence["candidates"])
        require(candidate_count <= 10000)
        require(bool(evidence["candidates"]) or not (dispatch["possibly-flagged"] or dispatch["possibly-forbidden"]))
    # Retained evidence must contain each referenced binding; this is not a flow proof.
    for dispatch in report.get("possible-dispatches", []):
        require(all(dispatch_origins.get(location_key(b)) == "delegate-binding"
                    for b in dispatch["evidence"].get("possible-binding-origins", [])))
    incomplete = bool(report["coverage"]["gaps"] or report["coverage"]["evaluation-incomplete"]
                      or report.get("content-policy", {}).get("incomplete", False)
                      or not report.get("data-analysis", {}).get("complete", True)
                      or not report.get("call-chains", {}).get("complete", True))
    if "data-analysis" in report:
        data = report["data-analysis"]
        require(data["complete"] == (not data["diagnostics"]))
        actions = {f["action"] for f in data["findings"]}
        require(data["decision"] == ("reject" if "reject" in actions else "needs-review" if actions else "no-match"))
        members = {m["id"] for m in report.get("inspection", {}).get("members", [])}
        require(all(f["member-id"] in members for f in data["findings"]))
    if "call-chains" in report:
        chains = report["call-chains"]
        require(chains["complete"] == (not chains["diagnostics"]))
        require((chains["catalog-revision"] is None) == (chains["catalog-sha256"] is None))
        require(chains["catalog-revision"] == report["context"].get("capability-catalog-revision"))
        catalog_dependencies = [d for d in report["context"]["dependencies"] if d["kind"] == "capability-summaries"]
        require(catalog_dependencies == ([] if chains["catalog-sha256"] is None else
                [{"kind": "capability-summaries", "sha256": chains["catalog-sha256"]}]))
        require(len(compact(chains).encode()) <= 512 * 1024)
        for witness in chains["witnesses"]:
            endpoint = witness["endpoint"]
            possible = endpoint["resolution"] == "possible" or any(s["resolution"] == "possible" for s in witness["callers"])
            require(witness["resolution"] == ("possible" if possible else "direct"))
            require(endpoint["resolution"] != "possible" or not (endpoint["flagged"] or endpoint["forbidden"]))
            require(endpoint["flagged"] or endpoint["forbidden"] or endpoint["capability"] is not None)
            for effect in ("flagged", "forbidden"):
                if endpoint[effect]:
                    require(invocation_key(endpoint["origin"], endpoint["target"]) in finding_identities[effect])
            require(endpoint["capability"] is None or chains["needs-review"])
            require(endpoint["capability"] is None or chains["catalog-sha256"] is not None)
            require(all(s["resolution"] == ("direct" if s["kind"] == "invocation" else "possible") for s in witness["callers"]))
    require(report["analysis-complete"] == (not incomplete))
    if report["status"] == "failed":
        require(all(count == 0 for count in counts.values()))
    return report
