#!/usr/bin/env python3
"""Bounded integrated regression gate. No expectation-update mode or engine execution."""

import argparse
import copy
from functools import cached_property
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import resource
import selectors
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from ingestion_fixture import build
import report_validation

GENERATOR = ROOT / "tests/Corpus.Generate/bin/Release/net10.0/Corpus.Generate.dll"
SCANNER = ROOT / "src/Scanner/bin/Release/net10.0/Scanner.dll"
CANARY = b"corpus-policy-canary"
LIMIT = 32 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def location_for(asset, offset):
    filename = asset + (".umap" if asset == "Map" else ".uasset")
    member = "Content/" + filename
    return {"asset": f"10:submission{len(member)}:{member}/Game/{asset}",
            "function": f"/Game/{asset}.BP_Corpus_C:ExecuteUbergraph_Corpus#3", "offset": offset}


def facts_oracle(facts, expected):
    cases = expected["forbidden"] + expected["flagged"] + expected["nonfinding-invocations"]
    actual = facts["analysis"]["invocations"]
    require(len(actual) == len(cases), "normalized invocation count mismatch")
    by_location = {tuple(call["location"][key] for key in ("asset", "function", "offset")): call for call in actual}
    require(len(by_location) == len(cases), "duplicate normalized locations")
    for asset, offset, owner, function, metadata, count in cases:
        location = location_for(asset, offset)
        call = by_location.get(tuple(location.values()))
        target = {"kind": "resolved", "owner": owner, "function": function} if owner else {"kind": "unresolved"}
        require(call is not None and call["target"] == target, "normalized location/target mismatch")
        arguments = call["arguments"]
        require(arguments["kind"] == metadata, "argument metadata mismatch")
        if metadata == "known":
            require(len(arguments["arguments"]) == count, "known argument count mismatch")
            value = {"kind": "constant", "value": {"kind": "integer", "value": 1}} if offset == 45 else {"kind": "dynamic"}
            require(arguments["arguments"] == [{"name": "Value", "value": value}], "constant/dynamic argument mismatch")
    require(facts["analysis"]["coverage-gaps"] == expected["coverage"]["gaps"], "normalized coverage mismatch")
    dispatch = facts["analysis"]["dispatches"]
    require(len(dispatch) == 1, "normalized indirect evidence count")
    require(dispatch[0]["origin"] == location_for("Unresolved", 10), "normalized indirect origin")
    require(dispatch[0]["candidates"] == [{"owner": "/Game/Unresolved.BP_Corpus_C", "function": "DynamicDispatch", "provenance": "local-function"}], "normalized indirect candidates")
    graph = facts["analysis"]["call-graph"]
    require(graph["schema-version"] == 1 and not graph["complete"], "graph context uncertainty lost")
    require(len(graph["functions"]) == 8, "graph definition count")
    require(all(any(f["asset"] == call["location"]["asset"] and f["location-function"] == call["location"]["function"]
                    for f in graph["functions"]) for call in actual), "containing identity absent from graph")


def oracle(report, expected, pak_hash):
    """Reviewed locations/targets are inputs, never inferred from produced findings."""
    require(report["context"]["pak-sha256"] == pak_hash, "pak identity changed")
    for key in ("status", "analysis-complete", "counts", "coverage", "diagnostics"):
        require(report[key] == expected[key], "expectation mismatch: " + key)
    for kind in ("flagged", "forbidden"):
        findings = []
        for case in expected[kind]:
            asset, offset, owner, function, metadata, count = case
            location = location_for(asset, offset)
            identity = [pak_hash, location["asset"], location["function"], offset]
            findings.append({"id": digest(json.dumps(identity, separators=(",", ":")).encode()),
                             "location": location, "target": {"owner": owner, "function": function},
                             "argument-metadata": metadata, "known-argument-count": count})
        findings.sort(key=lambda f: (f["location"]["asset"], f["location"]["function"], f["location"]["offset"]))
        require(report[kind + "-invocations"] == findings, "expectation mismatch: " + kind)
    possible = report.get("possible-dispatches", [])
    require(len(possible) == 1, "possible dispatch lost")
    require(possible[0]["evidence"]["origin"] == location_for("Unresolved", 10), "possible dispatch origin changed")
    require(possible[0]["possibly-forbidden"] and not possible[0]["possibly-flagged"], "possible policy match lost or made definite")
    require(possible[0]["evidence"]["resolution"] == "possible" and "open-world" in possible[0]["evidence"]["diagnostics"], "indirect uncertainty lost")
    chains = report["call-chains"]
    require(not chains["complete"] and "external-summary-unavailable" in chains["diagnostics"], "unknown summary hidden")
    endpoints = [w["endpoint"] for w in chains["witnesses"] if not w["callers"]]
    for effect in ("flagged", "forbidden"):
        require({report_validation.compact(e["origin"]) for e in endpoints if e[effect]} ==
                {report_validation.compact(f["location"]) for f in report[effect + "-invocations"]}, "actual endpoint witness lost")


def mutation_gate(report, expected, pak_hash):
    oracle(report, expected, pak_hash)
    # Keep each mutation schema/count-consistent so schema validation alone cannot catch it.
    missing = copy.deepcopy(report)
    removed = missing["forbidden-invocations"].pop()
    missing["call-chains"]["witnesses"] = [w for w in missing["call-chains"]["witnesses"]
        if w["endpoint"]["origin"] != removed["location"]]
    missing["counts"]["forbidden"] -= 1
    missing["counts"]["affected-union"] -= 1
    suppressed = copy.deepcopy(report)
    suppressed["coverage"]["gaps"].remove("unsupported-parsing")
    indirect = copy.deepcopy(report)
    indirect.pop("possible-dispatches")
    for name, mutant in (("removed-sensitive-finding", missing), ("suppressed-coverage-diagnostic", suppressed),
                         ("removed-possible-dispatch", indirect)):
        report_validation.load(json.dumps(mutant).encode(), ROOT)
        try:
            oracle(mutant, expected, pak_hash)
        except ValueError:
            continue
        raise ValueError("oracle accepted " + name)


class Run:
    def __init__(self, root):
        self.root = root
        self.sequence = 0
        self.receipts = []

    @cached_property
    def action_script(self):
        # Local-image parity must not invoke the released, registry-pinned adapter.
        from test_action import development_action
        return development_action(self.root / "development-action")

    def command(self, args, *, env=None, timeout=30, codes=(0,), cwd=ROOT):
        self.sequence += 1
        prefix = self.root / f"process-{self.sequence:04d}"
        environment = {k: v for k, v in os.environ.items() if k not in
                       ("UE_PAK_POLICY_RULES", "UE_PAK_CONTAINER_TEST_IMAGE", "OWNED_FIXTURE_EVIDENCE")}
        environment.update(DOTNET_EnableDiagnostics="0", DOTNET_GCHeapHardLimit="0x20000000")
        environment.update(env or {})
        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        started = time.monotonic()
        with prefix.with_suffix(".stdout").open("xb") as out, prefix.with_suffix(".stderr").open("xb") as err:
            process = subprocess.Popen([str(a) for a in args], cwd=cwd, env=environment,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True, preexec_fn=limits)
            try:
                deadline, total = time.monotonic() + timeout, 0
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, out)
                    selector.register(process.stderr, selectors.EVENT_READ, err)
                    while selector.get_map():
                        if time.monotonic() >= deadline:
                            raise subprocess.TimeoutExpired(args, timeout)
                        for key, _ in selector.select(.1):
                            data = os.read(key.fileobj.fileno(), 65536)
                            if not data:
                                selector.unregister(key.fileobj)
                                continue
                            total += len(data)
                            require(total < LIMIT, "process output budget")
                            key.data.write(data)
                process.wait(timeout=max(.01, deadline - time.monotonic()))
            except BaseException:
                # Give scan.py its bounded owned-container cleanup window before hard kill.
                previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
                try:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    grace = time.monotonic() + 15
                    while time.monotonic() < grace:
                        process.poll()  # Reap the leader; descendants may still be cleaning up.
                        try:
                            os.killpg(process.pid, 0)
                        except ProcessLookupError:
                            break
                        time.sleep(.05)
                finally:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    for sig, handler in previous.items():
                        signal.signal(sig, handler)
                raise
            finally:
                process.stdout.close()
                process.stderr.close()
        stdout, stderr = prefix.with_suffix(".stdout").read_bytes(), prefix.with_suffix(".stderr").read_bytes()
        require(len(stdout) + len(stderr) < LIMIT, "process output budget")
        require(sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file()) <= 64 * 1024 * 1024,
                "corpus artifact budget")
        self.receipts.append({"command": [str(a) for a in args], "exit": process.returncode,
                              "seconds": round(time.monotonic() - started, 3),
                              "stdout-sha256": digest(stdout), "stderr-sha256": digest(stderr)})
        require(process.returncode in codes, f"unexpected exit {process.returncode}; see {prefix}.stderr")
        return stdout, stderr

    def evaluate(self, facts, *, policy, extra=(), codes=(1,), source="environment", level="info", report_required=True):
        destination = self.root / f"report-{self.sequence + 1}.json"
        args = ["dotnet", SCANNER, "evaluate", "--facts", facts, "--report", destination,
                "--engine-version", "4.25", "--log-level", level, *extra]
        env = {}
        if source == "file":
            args += ["--policy-rules", ROOT / "fixtures/corpus/policy.yaml"]
        elif source == "environment":
            env["UE_PAK_POLICY_RULES"] = policy
        logs = self.command(args, env=env, codes=codes)
        if not destination.exists() and not report_required:
            privacy(logs, b"")
            return None
        value = report_validation.load(destination.read_bytes(), ROOT)
        privacy(logs, destination.read_bytes(), verbose=level == "verbose")
        return value


def privacy(logs, public, *, verbose=False):
    require(CANARY not in public, "policy leaked into public channels")
    text = b"".join(logs)
    if verbose:
        require(b"WARNING: VERBOSE" in text and CANARY in text, "verbose disclosure missing")
        require(text.index(b"WARNING:") < text.index(CANARY), "verbose warning order")
        require(b"::warning::" not in text and b"##[error]" not in text, "unescaped runner command")
        require(b"\\u003a\\u003awarning" in text and b"\\u0023\\u0023" in text, "verbose policy not fully escaped")
    else:
        require(CANARY not in text, "policy leaked into ordinary logs")


def archive_properties(run, packages):
    from pak_ingest import ingest, Limits
    randomizer = random.Random(150425)
    valid = build([("Content/owned.bin", randomizer.randbytes(1024), False)])
    samples = [valid[:randomizer.randrange(len(valid))] for _ in range(16)]
    samples += [build([("../escape", b"original", False)]),
                build([("Content/a", b"a", False), ("content/A", b"b", False)]),
                build([("Content/bomb", b"x" * 1048576, True)])]
    for index, data in enumerate(samples):
        path = run.root / f"hostile-{index}.pak"
        path.write_bytes(data)
        result = ingest(path, limits=Limits(wall_seconds=1), scratch_parent=run.root)
        require(result["ingestion_status"] == "rejected", "malformed archive accepted")
        require(result["diagnostic"] not in ("worker_failure", "wall_timeout"), "archive property crashed/timed out")
    # Repeat exact generated bytes through the supervised archive boundary, before Docker.
    path = run.root / "synthetic.pak"
    path.write_bytes(build(packages))
    result = ingest(path, scratch_parent=run.root)
    require(result["ingestion_status"] == "validated", "synthetic archive invalid")
    return path


def integrated(run, image, pak, expected, policy):
    import scan
    config = run.root / "docker-config"
    config.mkdir()
    docker = scan.Docker(config, image, 30)
    image = docker.image  # Bind CLI and development Action parity to the selected local image.
    # Actual parser facts, then the actual direct evaluator: no alternate report producer.
    status, facts = docker.run(scan.mount(pak, "/input/submission"), "/usr/local/bin/python3",
        ["-m", "pak_ingest.container_parser", "-", "Content", "/Game"], parser=True)
    require(status == 0 and facts, "container facts failed")
    facts_oracle(json.loads(facts), expected)
    facts_path = run.root / "container-facts.json"
    facts_path.write_bytes(facts)
    direct = run.evaluate(facts_path, policy=policy)
    oracle(direct, expected, digest(pak.read_bytes()))
    mutation_gate(direct, expected, digest(pak.read_bytes()))
    destination = run.root / "wrapper-report.json"
    logs = run.command([sys.executable, ROOT / "scripts/scan.py", "scan", "--pak", pak,
        "--report", destination, "--engine-version", "4.25", "--image", image,
        "--content-root", "Content=/Game"], env={"UE_PAK_POLICY_RULES": policy}, timeout=120, codes=(1,))
    wrapper = report_validation.load(destination.read_bytes(), ROOT)
    privacy(logs, destination.read_bytes())
    require(wrapper == direct, "complete CLI/container report mismatch")
    for level in ("info", "verbose"):
        workspace = run.root / ("action-" + level)
        workspace.mkdir()
        output, summary = workspace / "outputs", workspace / "summary"
        output.touch()
        summary.touch()
        logs = run.command([sys.executable, run.action_script, "scan"], env={
            "UE_PAK_POLICY_RULES": policy, "UE_PAK_ACTION_IMAGE": image,
            "GITHUB_WORKSPACE": str(workspace), "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary),
            "INPUT_PAK": str(pak), "INPUT_REPORT": "report.json", "INPUT_CONTENT_ROOT": "Content=/Game",
            "INPUT_LOG_LEVEL": level}, timeout=120, codes=(1,), cwd=workspace)
        raw = (workspace / "report.json").read_bytes()
        require(report_validation.load(raw, ROOT) == direct, "complete Action report mismatch")
        privacy(logs, raw + output.read_bytes() + summary.read_bytes(), verbose=level == "verbose")
        outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
        for kind in ("flagged", "forbidden"):
            require(json.loads(outputs[kind + "-invocations"]) == direct[kind + "-invocations"], "Action arrays mismatch")


def call_chain_gate(run, image=None):
    generated = run.root / "call-chain-packages"
    run.command(["dotnet", GENERATOR, "chains", generated])
    path = generated / "facts.json"
    catalog = ROOT / "examples/capability-summaries-v1.json"
    policy = (ROOT / "fixtures/corpus/policy.yaml").read_text()
    baseline = run.evaluate(path, policy=policy)
    require(not baseline["call-chains"]["witnesses"], "fixture name automatically classified")
    require("external-summary-unavailable" in baseline["call-chains"]["diagnostics"], "missing summary hidden")
    supplied = run.evaluate(path, policy=policy, extra=["--capability-summaries", catalog])
    for key in ("counts", "flagged-invocations", "forbidden-invocations", "possible-dispatches"):
        require(supplied[key] == baseline[key], "catalog changed direct/indirect policy results")
    chains = supplied["call-chains"]
    require(chains["needs-review"] and not chains["complete"], "fixture uncertainty or review hidden")
    require(chains["catalog-sha256"] == digest(catalog.read_bytes()), "catalog bytes not bound")
    require(len(chains["witnesses"]) == 4, "cycle/duplicate chain witness count")
    root = [w for w in chains["witnesses"] if w["callers"] and ":Root#" in w["callers"][0]["origin"]["function"]]
    require(len(root) == 1 and len(root[0]["callers"]) == 2, "complete Root/Helper/Wrapper witness missing")
    require(root[0]["endpoint"]["origin"]["offset"] == 0 and ":Wrapper#" in root[0]["endpoint"]["origin"]["function"],
            "endpoint invocation confused with upstream witness")
    possible = [w for w in chains["witnesses"] if w["resolution"] == "possible"]
    require(len(possible) == 1 and possible[0]["callers"][0]["kind"] == "virtual", "possible edge upgraded or lost")
    require(supplied["counts"] == {"invocations": 6, "flagged": 0, "forbidden": 0, "affected-union": 0}, "fixture invocation counts inflated")
    relaxed = run.evaluate(path, policy=policy, extra=["--capability-summaries", catalog, "--fail-on-incomplete", "false"])
    require(relaxed == supplied, "review gate changed evidence")
    # The exact private report bytes, not a reconstructed graph, bind moderation approval.
    import moderation
    pak = run.root / "call-chain.pak"
    pak.write_bytes(build([("Content/" + p.name, p.read_bytes(), False) for p in sorted(generated.iterdir())
                           if p.suffix in (".uasset", ".uexp")]))
    facts = json.loads(path.read_bytes())
    facts["pak-sha256"] = digest(pak.read_bytes())
    path.write_text(json.dumps(facts))
    supplied = run.evaluate(path, policy=policy, extra=["--capability-summaries", catalog, "--policy-revision", "fixture-policy-v1"])
    context = {"schema-version": 1, "kind": "scan-context", "scanner-identity": "git:" + "1" * 40,
               "game-build": "original-fixture-only", "report-context": supplied["context"]}
    raw = json.dumps(supplied).encode()
    handoff = moderation.handoff(raw, context, pak, [("capability-summaries", catalog)])
    require(handoff["routes"] == ["needs-review", "analysis-incomplete"], "capability moderation route lost")
    review = moderation.review(handoff, "fixture-reviewer", "approve", "Original test contract only")
    require(moderation.verify(review, context, pak, [("capability-summaries", catalog)], raw), "exact call-chain report binding failed")
    changed = copy.deepcopy(supplied)
    changed["call-chains"]["witnesses"][0]["endpoint"]["origin"]["offset"] += 1
    try:
        moderation.verify(review, context, pak, [("capability-summaries", catalog)], json.dumps(changed).encode())
    except ValueError:
        pass
    else:
        raise ValueError("call-chain evidence substitution accepted")
    if image:
        call_chain_container_gate(run, image, pak, catalog, policy)
    capability_policy_gate(run, path, pak, catalog, policy, image)


def capability_policy_oracle(report):
    analysis = report["capability-analysis"]
    require(analysis["decision"] == "reject" and not analysis["complete"], "capability rule gate lost")
    require(analysis["possibly-flagged"] and analysis["possibly-forbidden"], "unlocated uncertainty lost")
    require(len(analysis["findings"]) == 4, "capability rule witness finding removed")
    direct = [f for f in analysis["findings"] if f["flagged"] and f["forbidden"]]
    possible = [f for f in analysis["findings"] if f["possibly-flagged"] and f["possibly-forbidden"]]
    require(len(direct) == 3 and len(possible) == 1, "capability effect removed or upgraded")
    require(report["counts"] == {"invocations": 6, "flagged": 0, "forbidden": 0, "affected-union": 0}, "capability inflated invocation counts")


def capability_policy_gate(run, path, pak, catalog, policy, image):
    rules = ROOT / "examples/capability-rules-v1.json"
    extra = ["--capability-summaries", catalog, "--capability-rules", rules,
             "--capability-policy-revision", "illustrative-only-v1"]
    report = run.evaluate(path, policy=policy, extra=extra)
    capability_policy_oracle(report)
    for name in ("removed-capability-finding", "removed-capability-effect"):
        mutant = copy.deepcopy(report)
        if name == "removed-capability-finding":
            mutant["capability-analysis"]["findings"].pop(0)
        else:
            mutant["capability-analysis"]["findings"][0]["forbidden"] = False
        report_validation.load(json.dumps(mutant).encode(), ROOT)
        try:
            capability_policy_oracle(mutant)
        except ValueError:
            continue
        raise ValueError("oracle accepted " + name)
    if not image:
        return
    import scan
    config = run.root / "capability-docker-config"
    config.mkdir()
    docker = scan.Docker(config, image, 30)
    status, facts = docker.run(scan.mount(pak, "/input/submission"), "/usr/local/bin/python3",
        ["-m", "pak_ingest.container_parser", "-", "Content", "/Game"], parser=True)
    require(status == 0 and facts, "capability parser failed")
    parsed = run.root / "capability-container-facts.json"
    parsed.write_bytes(facts)
    direct = run.evaluate(parsed, policy=policy, extra=extra)
    capability_policy_oracle(direct)
    destination, receipt = run.root / "capability-report.json", run.root / "capability-private-context.json"
    run.command([sys.executable, ROOT / "scripts/scan.py", "scan", "--pak", pak, "--report", destination,
        "--engine-version", "4.25", "--image", docker.image, "--content-root", "Content=/Game",
        *extra, "--capability-context", receipt], env={"UE_PAK_POLICY_RULES": policy}, timeout=120, codes=(1,))
    require(report_validation.load(destination.read_bytes(), ROOT) == direct, "capability wrapper parity")
    private = json.loads(receipt.read_bytes())
    require(private["report-sha256"] == digest(destination.read_bytes()), "capability private report binding")
    require(private["dependencies"] == [{"kind": "capability-rules", "sha256": digest(rules.read_bytes())}], "capability private rule binding")
    workspace = run.root / "capability-action"
    workspace.mkdir()
    output, summary = workspace / "outputs", workspace / "summary"
    output.touch()
    summary.touch()
    logs = run.command([sys.executable, run.action_script, "scan"], env={
        "UE_PAK_POLICY_RULES": policy, "UE_PAK_ACTION_IMAGE": docker.image,
        "GITHUB_WORKSPACE": str(workspace), "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary),
        "INPUT_PAK": str(pak), "INPUT_REPORT": "report.json", "INPUT_CONTENT_ROOT": "Content=/Game",
        "INPUT_CAPABILITY_SUMMARIES": str(catalog), "INPUT_CAPABILITY_RULES": str(rules),
        "INPUT_CAPABILITY_POLICY_REVISION": "illustrative-only-v1", "INPUT_CAPABILITY_CONTEXT": "private-context.json"
    }, timeout=120, codes=(1,), cwd=workspace)
    raw = (workspace / "report.json").read_bytes()
    require(report_validation.load(raw, ROOT) == direct, "capability Action parity")
    public = raw + output.read_bytes() + summary.read_bytes() + b"".join(logs)
    for canary in (b"illustrative-review", b"illustrative-reject", b"illustrative-only-v1", digest(rules.read_bytes()).encode()):
        require(canary not in public, "private capability policy exposed")
    require(json.loads((workspace / "private-context.json").read_bytes()) == private, "capability Action private receipt parity")


def call_chain_container_gate(run, image, pak, catalog, policy):
    """Serial actual parser/wrapper/Action coverage; runs only with explicit Docker opt-in."""
    import scan
    config = run.root / "chain-docker-config"
    config.mkdir()
    docker = scan.Docker(config, image, 30)
    status, facts = docker.run(scan.mount(pak, "/input/submission"), "/usr/local/bin/python3",
        ["-m", "pak_ingest.container_parser", "-", "Content", "/Game"], parser=True)
    require(status == 0 and facts, "call-chain parser failed")
    path = run.root / "chain-container-facts.json"
    path.write_bytes(facts)
    direct = run.evaluate(path, policy=policy, extra=["--capability-summaries", catalog])
    destination = run.root / "chain-wrapper-report.json"
    run.command([sys.executable, ROOT / "scripts/scan.py", "scan", "--pak", pak, "--report", destination,
        "--engine-version", "4.25", "--image", docker.image, "--content-root", "Content=/Game",
        "--capability-summaries", catalog], env={"UE_PAK_POLICY_RULES": policy}, timeout=120, codes=(1,))
    require(report_validation.load(destination.read_bytes(), ROOT) == direct, "call-chain wrapper parity")
    workspace = run.root / "chain-action"
    workspace.mkdir()
    output, summary = workspace / "outputs", workspace / "summary"
    output.touch()
    summary.touch()
    logs = run.command([sys.executable, run.action_script, "scan"], env={
        "UE_PAK_POLICY_RULES": policy, "UE_PAK_ACTION_IMAGE": docker.image,
        "GITHUB_WORKSPACE": str(workspace), "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary),
        "INPUT_PAK": str(pak), "INPUT_REPORT": "report.json", "INPUT_CONTENT_ROOT": "Content=/Game",
        "INPUT_CAPABILITY_SUMMARIES": str(catalog)}, timeout=120, codes=(1,), cwd=workspace)
    raw = (workspace / "report.json").read_bytes()
    require(report_validation.load(raw, ROOT) == direct, "call-chain Action parity")
    privacy(logs, raw + output.read_bytes() + summary.read_bytes())
    require(b"fixture-opaque-boundary" not in output.read_bytes() + summary.read_bytes(), "capability exposed in Action outputs")


def components(run, image=None, evidence=None):
    for name in ("CompatibilityProbe", "Policy", "PolicyInput", "Scanner"):
        project = ROOT / f"tests/{name}.Tests/{name}.Tests.csproj"
        run.command(["dotnet", "restore", project, "--locked-mode"], timeout=180)
        run.command(["dotnet", "test", project, "-c", "Release", "--no-restore"], timeout=180)
    env = {}
    if image:
        env["UE_PAK_CONTAINER_TEST_IMAGE"] = image
    if evidence:
        env["OWNED_FIXTURE_EVIDENCE"] = str(evidence)
    # One serial suite: component Docker ownership assertions cannot race each other.
    run.command([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                env=env, timeout=2400)


def data_policy_oracle(report):
    require(report["data-analysis"] == {"schema-version": 1, "decision": "needs-review", "complete": True,
        "findings": [{"member-id": "r00000000", "export-index": 1, "property-ordinal": 0,
            "reason": "reviewed-serialized-property-changed", "action": "review"}], "diagnostics": []},
        "reviewed original data finding mismatch")


def data_policy_gate(run, policy):
    generated = run.root / "data-policy"
    run.command(["dotnet", GENERATOR, "data-policy", generated])
    facts = generated / "submission-facts.json"
    extra = ["--data-rules", generated / "data-rules.json", "--game-build", "original-fixture-v1",
        "--fail-on-any-forbidden", "false", "--fail-on-any-flagged", "false", "--fail-on-incomplete", "false"]
    missing = run.evaluate(facts, policy=policy, extra=extra)
    require(not missing["data-analysis"]["complete"] and "data-baseline-unavailable" in missing["data-analysis"]["diagnostics"],
            "data missing-baseline uncertainty lost")
    compared = run.evaluate(facts, policy=policy, extra=[*extra, "--baseline-facts", generated / "baseline-facts.json",
        "--expected-baseline-sha256", "b" * 64, "--baseline-facts-assertion", "caller-supplied-not-authenticated"])
    data_policy_oracle(compared)
    require(compared["counts"] == missing["counts"], "data altered invocation counts")
    for value in (missing, compared):
        public = json.dumps(value).encode()
        require(b"private-data-canary" not in public and b"private-original-model" not in public and b"Destination" not in public,
                "private serialized values or data policy leaked")
    mutant = copy.deepcopy(compared)
    mutant["data-analysis"]["findings"] = []
    mutant["data-analysis"]["decision"] = "no-match"
    report_validation.load(json.dumps(mutant).encode(), ROOT)
    try:
        data_policy_oracle(mutant)
    except ValueError:
        pass
    else:
        raise ValueError("oracle accepted removed-data-finding")


def package_context_oracle(report):
    expected = json.loads((ROOT / "fixtures/corpus/package-context-expectations.json").read_bytes())
    require(report["counts"]["invocations"] == expected["invocations"] and
            report["counts"]["forbidden"] == expected["forbidden"], "archive direct counts changed")
    dispatches = report["possible-dispatches"]
    require(len(dispatches) == len(expected["dispatches"]), "archive dispatch origins lost")
    for actual, wanted in zip(dispatches, expected["dispatches"]):
        evidence = actual["evidence"]
        require(evidence["origin"]["function"] == wanted["function"] and evidence["origin"]["offset"] == wanted["offset"],
                "archive dispatch location changed")
        require(evidence["candidates"] == wanted["candidates"], "archive candidate evidence lost")
        require(evidence["resolution"] == "possible" and "open-world" in evidence["diagnostics"], "archive world closed")
        require(actual["possibly-forbidden"], "archive candidate policy effect lost")
    propagated = [w for w in report["call-chains"]["witnesses"] if w["callers"]]
    require(any(w["callers"][0]["origin"]["function"] == "/Game/Base.Type:Run#4" and
                w["resolution"] == "possible" and w["endpoint"]["target"] ==
                {"owner": "/Script/Corpus.Sensitive", "function": "Record"} for w in propagated),
            "cross-package possible capability chain lost")
    require(all(w["resolution"] == "possible" for w in propagated), "possible archive edge promoted")


def package_context_gate(run, image=None):
    from pak_ingest import ingest
    generated = run.root / "package-context"
    run.command(["dotnet", GENERATOR, "package-context", generated])
    expected = json.loads((ROOT / "fixtures/corpus/package-context-expectations.json").read_bytes())
    require({p.name: digest(p.read_bytes()) for p in sorted(generated.iterdir())} == expected["serialized-sha256"],
            "archive serialized fixture hashes changed; manual review required")
    pak = run.root / "package-context.pak"
    pak.write_bytes(build([("Content/" + p.name, p.read_bytes(), False) for p in sorted(generated.iterdir())]))
    project = ROOT / "src/Parser/Parser.csproj"
    run.command(["dotnet", "restore", project, "--locked-mode"], timeout=180)
    run.command(["dotnet", "build", project, "-c", "Release", "--no-restore"], timeout=180)
    path = run.root / "package-context-facts.json"
    def inspect(root, report):
        (Path(root) / "inspection.json").write_text(json.dumps(report))
        raw, _ = run.command(["dotnet", ROOT / "src/Parser/bin/Release/net10.0/Parser.dll", root,
            "-", "Content", "/Game", pak])
        path.write_bytes(raw)
    require(ingest(pak, inspector=inspect)["ingestion_status"] == "validated", "archive context ingestion failed")
    policy = (ROOT / "fixtures/corpus/policy.yaml").read_text() + """
  - id: original-archive-candidate
    description: Original synthetic override only
    effect: forbid
    match:
      kind: invocation
      target:
        kind: exact
        owner: /Game/ChildOverride.Type
        function: Sensitive
"""
    report = run.evaluate(path, policy=policy)
    package_context_oracle(report)
    mutant = copy.deepcopy(report)
    mutant["possible-dispatches"][0]["evidence"]["candidates"] = [
        c for c in mutant["possible-dispatches"][0]["evidence"]["candidates"] if c["owner"] != "/Game/ChildOverride.Type"]
    report_validation.load(json.dumps(mutant).encode(), ROOT)
    try:
        package_context_oracle(mutant)
    except ValueError:
        pass
    else:
        raise ValueError("oracle accepted removed-archive-candidate")
    if image:
        # Same serial parser/evaluator/wrapper/actual-Action parity as call chains,
        # without a catalog: the endpoint is the original direct policy match.
        import scan
        config = run.root / "archive-docker-config"
        config.mkdir()
        docker = scan.Docker(config, image, 60)
        status, raw = docker.run(scan.mount(pak, "/input/submission"), "/usr/local/bin/python3",
            ["-m", "pak_ingest.container_parser", "-", "Content", "/Game"], parser=True)
        require(status == 0 and json.loads(raw) == json.loads(path.read_bytes()), "archive container facts parity")
        destination = run.root / "archive-wrapper-report.json"
        run.command([sys.executable, ROOT / "scripts/scan.py", "scan", "--pak", pak, "--report", destination,
            "--engine-version", "4.25", "--image", docker.image, "--content-root", "Content=/Game"],
            env={"UE_PAK_POLICY_RULES": policy}, timeout=120, codes=(1,))
        require(report_validation.load(destination.read_bytes(), ROOT) == report, "archive wrapper report parity")
        workspace = run.root / "archive-action"
        workspace.mkdir()
        output, summary = workspace / "outputs", workspace / "summary"
        output.touch(); summary.touch()
        logs = run.command([sys.executable, run.action_script, "scan"], env={
            "UE_PAK_POLICY_RULES": policy, "UE_PAK_ACTION_IMAGE": docker.image, "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary), "INPUT_PAK": str(pak),
            "INPUT_REPORT": "report.json", "INPUT_CONTENT_ROOT": "Content=/Game"}, timeout=120, codes=(1,), cwd=workspace)
        raw = (workspace / "report.json").read_bytes()
        require(report_validation.load(raw, ROOT) == report, "archive Action report parity")
        privacy(logs, raw + output.read_bytes() + summary.read_bytes())
    return pak, path, policy, report


def package_context_boundary_gate(run, mode, image=None):
    """Serialized review regressions through ingestion, Parser and exact policy."""
    from pak_ingest import ingest
    generated = run.root / mode
    run.command(["dotnet", GENERATOR, mode, generated])
    pak = run.root / (mode + ".pak")
    pak.write_bytes(build([("Content/" + p.name, p.read_bytes(), False) for p in sorted(generated.iterdir())]))
    path = run.root / (mode + "-facts.json")
    def inspect(root, report):
        (Path(root) / "inspection.json").write_text(json.dumps(report))
        raw, _ = run.command(["dotnet", ROOT / "src/Parser/bin/Release/net10.0/Parser.dll", root,
            "-", "Content", "/Game", pak])
        path.write_bytes(raw)
    require(ingest(pak, inspector=inspect)["ingestion_status"] == "validated", "boundary ingestion failed")
    facts = json.loads(path.read_bytes())
    def reversed_inspect(root, inspection):
        inspection["records"].reverse()
        (Path(root) / "inspection.json").write_text(json.dumps(inspection))
        raw, _ = run.command(["dotnet", ROOT / "src/Parser/bin/Release/net10.0/Parser.dll", root,
            "-", "Content", "/Game", pak])
        require(json.loads(raw) == facts, "boundary record order changed facts")
    require(ingest(pak, inspector=reversed_inspect)["ingestion_status"] == "validated", "reordered boundary ingestion failed")
    members = {m["path"]: m for m in facts["inspection"]["members"]}
    require(members["Content/Base.uasset"]["inspection-status"] in ("parsed", "partial"), "mandatory Base facts lost")
    require(members["Content/ChildOverride.uasset"]["inspection-status"] in ("parsed", "partial"), "later package lost")
    policy = (ROOT / "fixtures/corpus/policy.yaml").read_text() + """
  - id: exact-base-declaration
    description: Original declaration identity
    effect: forbid
    match:
      kind: invocation
      target:
        kind: exact
        owner: /Game/Base.Type
        function: Sensitive
"""
    report = run.evaluate(path, policy=policy)
    if mode == "package-context-budget":
        require(len(facts["analysis"]["invocations"]) == 5006, "combined budget erased mandatory calls")
        dispatches = facts["analysis"]["dispatches"]
        # The existing optional transport bound retains a prefix, independently
        # of the package candidate bound tested through Read/Inspect/Validate.
        require(0 < len(dispatches) < 5004, "bounded dispatch prefix lost")
        require(sum(len(d["candidates"]) for d in dispatches) == 2 * len(dispatches) <= 10000,
                "combined wire candidate budget exceeded")
        require({"incomplete-extraction", "unresolved-dispatch"} <= set(facts["analysis"]["coverage-gaps"]),
                "missing optional limit diagnostics")
        require(not facts["analysis"]["call-graph"]["complete"], "bounded graph fallback claimed completeness")
        require(len(members) == 10 and all(m["inspection-status"] in ("parsed", "partial", "paired_export_data")
                for m in members.values()), "mandatory package inventory lost")
        base_calls = [c for c in facts["analysis"]["invocations"] if c["location"]["function"] == "/Game/Base.Type:Run#4"]
        require(len(base_calls) == 5002 and base_calls[0]["target"] ==
                {"kind": "resolved", "owner": "/Game/Base.Type", "function": "Sensitive"}, "Base calls/direct target lost")
        require(members["Content/Base.uasset"]["inspection-status"] == "partial", "limited package not partial")
        require(any(f["target"] == {"owner": "/Game/Base.Type", "function": "Sensitive"}
                    for f in report["forbidden-invocations"]), "mandatory exact forbid lost")
        stripped = copy.deepcopy(facts)
        stripped["analysis"].pop("dispatches")
        stripped_path = run.root / (mode + "-direct.json")
        stripped_path.write_text(json.dumps(stripped))
        direct = run.evaluate(stripped_path, policy=policy)
        for key in ("counts", "forbidden-invocations", "flagged-invocations"):
            require(direct[key] == report[key], "optional budget changed direct evidence: " + key)
    else:
        dispatch = next(d for d in report["possible-dispatches"]
                        if d["evidence"]["origin"]["function"] == "/Game/Caller.Caller:Run#5"
                        and d["evidence"]["origin"]["offset"] == 22)
        candidates = dispatch["evidence"]["candidates"]
        require({"owner": "/Game/Base.Type", "function": "Sensitive", "provenance": "inherited-function"}
                in candidates, "case import shadowed declaration")
        require({"owner": "/game/base.tYpE", "function": "SENSITIVE", "provenance": "imported-function"}
                in candidates, "original import evidence lost")
        require(dispatch["possibly-forbidden"], "exact canonical possible forbid lost")
        require(any(w["callers"] and w["callers"][0]["origin"]["function"] == "/Game/Caller.Caller:Run#5"
                    for w in report["call-chains"]["witnesses"]), "case import erased cross-package chain")
    if image:
        import scan
        config = run.root / (mode + "-docker-config")
        config.mkdir()
        docker = scan.Docker(config, image, 60)
        status, raw = docker.run(scan.mount(pak, "/input/submission"), "/usr/local/bin/python3",
            ["-m", "pak_ingest.container_parser", "-", "Content", "/Game"], parser=True)
        require(status == 0 and json.loads(raw) == facts, "boundary container facts parity")
        destination = run.root / (mode + "-wrapper-report.json")
        run.command([sys.executable, ROOT / "scripts/scan.py", "scan", "--pak", pak, "--report", destination,
            "--engine-version", "4.25", "--image", docker.image, "--content-root", "Content=/Game"],
            env={"UE_PAK_POLICY_RULES": policy}, timeout=120, codes=(1,))
        require(report_validation.load(destination.read_bytes(), ROOT) == report, "boundary wrapper report parity")
        workspace = run.root / (mode + "-action")
        workspace.mkdir()
        output, summary = workspace / "outputs", workspace / "summary"
        output.touch(); summary.touch()
        logs = run.command([sys.executable, run.action_script, "scan"], env={
            "UE_PAK_POLICY_RULES": policy, "UE_PAK_ACTION_IMAGE": docker.image, "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary), "INPUT_PAK": str(pak),
            "INPUT_REPORT": "report.json", "INPUT_CONTENT_ROOT": "Content=/Game"}, timeout=120, codes=(1,), cwd=workspace)
        raw = (workspace / "report.json").read_bytes()
        require(report_validation.load(raw, ROOT) == report, "boundary Action report parity")
        privacy(logs, raw + output.read_bytes() + summary.read_bytes())
    return facts, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new private directory outside checkout")
    parser.add_argument("--docker-image", help="existing local image; never pulled or published")
    parser.add_argument("--owned-evidence", type=Path, help="required if specified; never silently skipped")
    parser.add_argument("--components", action="store_true")
    parser.add_argument("--release", action="store_true", help="require Docker, external owned evidence and all component suites")
    args = parser.parse_args()
    require(not args.release or (args.docker_image and args.owned_evidence and args.components),
            "release requires --docker-image, --owned-evidence and --components")
    root = args.output.resolve()
    require(not root.is_relative_to(ROOT) and not root.exists(), "output must be new and external")
    root.mkdir(mode=0o700)
    run = Run(root)
    completed = False
    try:
        expected = json.loads((ROOT / "fixtures/corpus/expectations.json").read_bytes())
        if args.owned_evidence:
            verify_owned(args.owned_evidence)
        run.command(["dotnet", "--info"])
        run.command(["dotnet", "restore", ROOT / "tests/Corpus.Generate/Corpus.Generate.csproj", "--locked-mode"], timeout=180)
        run.command(["dotnet", "build", ROOT / "tests/Corpus.Generate/Corpus.Generate.csproj", "-c", "Release", "--no-restore"], timeout=180)
        run.command(["dotnet", GENERATOR, "properties", "unused"])
        generated = root / "packages"
        run.command(["dotnet", GENERATOR, "generate", generated])
        hashes = {p.name: digest(p.read_bytes()) for p in sorted(generated.iterdir())}
        require(hashes == expected["serialized-sha256"], "serialized fixture hashes changed; manual review required")
        packages = [("Content/" + p.name, p.read_bytes(), False) for p in sorted(generated.iterdir())]
        pak = archive_properties(run, packages)
        pak_hash = digest(pak.read_bytes())
        require(pak_hash == expected["pak-sha256"], "deterministic pak hash changed")
        raw, _ = run.command(["dotnet", GENERATOR, "facts", generated])
        facts = json.loads(raw)
        facts_oracle(facts, expected)
        facts["pak-sha256"] = pak_hash
        path = root / "facts.json"
        path.write_text(json.dumps(facts))
        policy = (ROOT / "fixtures/corpus/policy.yaml").read_text()
        baseline = None
        for source, level in itertools.product(("file", "environment"), ("error", "warn", "info", "verbose")):
            value = run.evaluate(path, policy=policy, source=source, level=level)
            oracle(value, expected, pak_hash)
            baseline = value if baseline is None else baseline
            require(value == baseline, "source/log-level report mismatch")
        mutation_gate(baseline, expected, pak_hash)
        for gates in itertools.product((False, True), repeat=3):
            extra = [item for name, value in zip(("forbidden", "flagged", "incomplete"), gates)
                     for item in ("--fail-on-" + ("incomplete" if name == "incomplete" else "any-" + name), str(value).lower())]
            value = run.evaluate(path, policy=policy, extra=extra, codes=(int(any(gates)),))
            require(value == baseline, "gate changed report evidence")
        for level in ("error", "warn", "info", "verbose"):
            value = run.evaluate(path, policy="corpus-policy-canary: [ ::warning:: ##[error]", level=level, codes=(2,))
            require(value["status"] == "failed", "malformed policy succeeded")
        for policy_value, source, extra in ((policy, "environment", ["--log-level", "invalid"]),
                (policy, "environment", ["--policy-rules", ROOT / "fixtures/corpus/policy.yaml"]),
                ("", "none", [])):
            value = run.evaluate(path, policy=policy_value, source=source, extra=extra, codes=(2,), report_required=False)
            require(value is None or value["status"] == "failed", "invalid configuration succeeded")
        output_properties(baseline)
        call_chain_gate(run, args.docker_image)
        data_policy_gate(run, policy)
        package_context_gate(run, args.docker_image)
        for mode in ("package-context-budget", "package-context-case"):
            package_context_boundary_gate(run, mode, args.docker_image)
        if args.docker_image:
            integrated(run, args.docker_image, pak, expected, policy)
        if args.owned_evidence:
            project = ROOT / "tests/OwnedFixtures.Verify/OwnedFixtures.Verify.csproj"
            run.command(["dotnet", "restore", project, "--locked-mode"], timeout=180)
            run.command(["dotnet", "run", "--project", project, "-c", "Release", "--no-restore", "--", args.owned_evidence], timeout=180)
        if args.components:
            components(run, args.docker_image, args.owned_evidence)
        completed = True
        print("PASS: integrated synthetic corpus; seven removal mutations rejected; Docker=" + str(bool(args.docker_image))
              + "; external owned cook=" + str(bool(args.owned_evidence)))
        return 0
    finally:
        (root / "execution.json").write_text(json.dumps({"schema-version": 1, "python": sys.version,
            "completed": completed, "release-requested": args.release,
            "source-sha256": {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in
                (ROOT / "scripts/regression_corpus.py", ROOT / "tests/Corpus.Generate/Program.cs",
                  ROOT / "fixtures/corpus/expectations.json", ROOT / "fixtures/corpus/policy.yaml",
                  ROOT / "tests/PackageContextFixture.cs", ROOT / "fixtures/corpus/package-context-expectations.json")},
            "commands": run.receipts, "docker-requested": bool(args.docker_image),
            "owned-evidence-requested": bool(args.owned_evidence)}, indent=2) + "\n")


def output_properties(baseline):
    randomizer = random.Random(150425)
    for _ in range(32):
        mutant = copy.deepcopy(baseline)
        mutant["forbidden-invocations"][randomizer.randrange(6)]["location"]["offset"] = -randomizer.randrange(1, 1000)
        try:
            report_validation.load(json.dumps(mutant).encode(), ROOT)
        except ValueError:
            continue
        raise ValueError("invalid output accepted")
    encoded = json.dumps(baseline).encode()
    for mutant in (encoded.replace(b'"schema-version": 1', b'"schema-version": 1, "schema-version": 1', 1),
                   encoded.replace(b'"status": "partial"', b'"status": "Partial"', 1),
                   encoded.replace(b'"schema-version": 1', b'"schema-version": 1, "rule-ids": ["corpus-policy-canary"]', 1)):
        require(mutant != encoded, "output mutation did not apply")
        try:
            report_validation.load(mutant, ROOT)
        except ValueError:
            continue
        raise ValueError("duplicate/case/private output accepted")


def verify_owned(root):
    require(root.is_dir(), "requested owned evidence missing")
    receipt = json.loads((root / "receipt.json").read_bytes())
    require(receipt["completed"], "requested cook incomplete")
    for group, entries in receipt["output_sha256"].items():
        for name, sha in entries.items():
            path = (root / group / name).resolve()
            require(path.is_relative_to(root.resolve()) and path.is_file(), "owned evidence path invalid")
            require(digest(path.read_bytes()) == sha, "owned cook hash mismatch")
    for name, sha in receipt["evidence_sha256"].items():
        path = (root / name).resolve()
        require(path.is_relative_to(root.resolve()) and path.is_file(), "owned receipt path invalid")
        require(digest(path.read_bytes()) == sha, "owned evidence hash mismatch")
    require(digest((root / "owned.usmap").read_bytes()) == receipt["usmap_sha256"], "owned mapping hash mismatch")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("Corpus failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
