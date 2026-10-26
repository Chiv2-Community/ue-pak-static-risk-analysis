# Operator guide

Inspect original pak bytes without loading the game or editor. A passing gate is
not approval, malware certification, or faithful source reconstruction. Start
with the [security boundaries](security.md), [input reference](inputs.md), and
[manual release gates](releases.md). Internal formats belong in the linked
component documents, not this guide.

## Trusted Linux setup

Use a disposable Linux VM, a non-root account, Python 3.11+, Git, and a working
local Docker installation at `/usr/bin/docker` with `/var/run/docker.sock`.
Docker access is host-admin access. The host wrapper needs no .NET installation;
local evaluator/tests require .NET SDK 10 (`global.json` selects stable 10.0.100
with latest-feature roll-forward). Rust/Cargo and a C compiler are needed only
for the old repak experiment, not the scanner or Action.

Start from a reviewed full source commit. Record it and the submodule IDs; never
substitute a submission checkout. From that trusted checkout:

```sh
git submodule update --init --recursive
docker build -t ue-pak-static-risk-analysis:dev .
docker image inspect ue-pak-static-risk-analysis:dev --format '{{.Id}}'
```

Initial source/dependency/base-image setup needs public network access. Scans
never pull images and run parser/evaluator containers without networking. Use
only an operator-built local image and retain its actual ID with build records;
a tag, OCI label, or source SHA alone does not establish binary provenance.
See [release provenance](releases.md) before promoting any build.

For local trusted-facts evaluation, restore **and build** first:

```sh
dotnet restore src/Scanner/Scanner.csproj --locked-mode
dotnet build src/Scanner/Scanner.csproj -c Release --no-restore
```

For full component/schema tests, install Python dependencies in a private venv:

```sh
python3 -m venv .venv
.venv/bin/pip install -r tests/requirements.txt
```

Use `.venv/bin/python` for the full Python suite and corpus runner. Data-schema
assertions are mandatory; a standard-library-only environment cannot run the full
suite. Production Python needs no third-party packages.

## File policy: recommended for private rules

Optional [capability summaries/call chains](call-chains.md) use a separate trusted,
explicitly nonsecret catalog, not private YAML or submitter-supplied configuration.
Default: no catalog. Supply `--capability-summaries /approved/catalog.json` only
after identity/build/provenance review; no game catalog is bundled. Matches always
require review and leave direct counts unchanged. Missing summaries/graph context
remain incomplete. Bind the exact catalog as a moderation dependency using
`--dependency capability-summaries=/approved/catalog.json`; any byte change
invalidates the old context/decision. Full reports expose public capability IDs,
revision and digest, not catalog prose or private policy. Action outputs omit
chains; retain the private full report.

Optional [private capability rules](capability-policy.md) are a separate closed
JSON file, not additions to invocation YAML. Example with operator-controlled
paths (all output parents must already exist):

```sh
python3 scripts/scan.py scan \
  --pak /approved/submission.pak --report /restricted/new-report.json \
  --engine-version 4.25 --policy-rules /private/invocations.yaml \
  --capability-summaries /approved/nonsecret-catalog.json \
  --capability-rules /private/capabilities.json \
  --capability-policy-revision reviewed-v1 \
  --capability-context /private/new-capability-context.json
```

The private revision must match the document. Retain the receipt/dependencies for
moderation; never publish it or use private rule hashes as public revisions. All
capability findings/unknowns fail mandatory gates even when invocation gates are
disabled. Verbose still warns/discloses invocation YAML, never capability rules.

Obtain only the original pak through trusted transfer, never submission scripts
or a submitter checkout. The policy owner controls rules, content settings, log
level and a fresh opaque policy revision. Keep policy source provenance privately;
do not use a public content hash as its revision. Use trusted local directories,
restrict their reader set, and keep policy files stable during scanning.

The following uses **public example policy and synthetic packages**, not
production material. Generate the synthetic archive with the reviewed corpus
runner first (requires local .NET 10, initialized UAssetAPI and fresh output).
This basic run intentionally tests public-canary verbose disclosure internally;
**verbose prints the full policy to logs; anyone with log access can read it.**
Its private output contains only public test policy, never production rules.
Ordinary env is not masked; runner setup/admin visibility is outside filtering.
No Docker test runs unless `--docker-image` is explicitly supplied.

```sh
.venv/bin/python scripts/regression_corpus.py --output /tmp/opencode/operator-corpus
```

```sh
umask 077
mkdir /tmp/opencode/operator-example
unset UE_PAK_POLICY_RULES
python3 scripts/scan.py scan \
  --pak /tmp/opencode/operator-corpus/synthetic.pak \
  --report /tmp/opencode/operator-example/file.json \
  --engine-version 4.25 --content-root Content=/Game \
  --policy-rules fixtures/corpus/policy.yaml --log-level info
```

Expect exit **1**: this fixture deliberately contains forbidden findings and
coverage gaps. Inspect/retain the new mode-0600 report even after gate failure.
For a real submission replace the pak, policy and mapping with approved inputs;
replace `Content=/Game` with its actual virtual prefix, not an assumed game root.
Exactly one root mapping and one optional `--mapping /approved/owned.usmap` are
supported. Missing context stays unknown. File parents must already exist; no
existing report may be overwritten. Default gates are forbidden=true,
flagged=false, incomplete=true. Content review/rejection always fails independently.
See [content configuration](content-policy.md), not a fabricated game allowlist.

## Raw environment policy

Exactly one source is required: file **or** raw UTF-8 YAML in
`UE_PAK_POLICY_RULES`. It is not a filename and does not require a GitHub secret.
An empty variable still selects the environment source; empty/missing/conflicting,
invalid or oversized sources fail closed. Unset it entirely for file input.

**Ordinary environment values are not masked secrets.** GitHub step setup/debug
logs, process/container administration and host operators may expose them outside
scanner-controlled channels. Default info logs omit policy, not those external
exposures. Do not put private policy in an untrusted job or grant submitters log
access. File input also requires trusted host/runner administration.

Public canary only; command substitution reads text, it does not evaluate YAML:

```sh
export UE_PAK_POLICY_RULES="$(cat fixtures/corpus/policy.yaml)"
python3 scripts/scan.py scan \
  --pak /tmp/opencode/operator-corpus/synthetic.pak \
  --report /tmp/opencode/operator-example/env.json \
  --engine-version 4.25 --content-root Content=/Game --log-level info
unset UE_PAK_POLICY_RULES
```

This also deliberately exits 1. File/env reports must match. Reports omit raw
policy, descriptions, predicate values and private rule IDs by default. Findings
and archive metadata are still sensitive; restrict report readers.

**Warning: verbose prints the full policy to logs; anyone with log access can
read it. Environment variables are not masked secrets; runner step setup and
administrators can expose them independently. Use only this public canary.**

```sh
python3 scripts/scan.py scan \
  --pak /tmp/opencode/operator-corpus/synthetic.pak \
  --report /tmp/opencode/operator-example/public-canary.json \
  --engine-version 4.25 --content-root Content=/Game \
  --policy-rules fixtures/corpus/policy.yaml --log-level verbose
```

Policy appears reversibly escaped in logs, never in reports or Action outputs.
No private-policy example requires verbose. Restrict and expire diagnostic logs.

## Ubuntu Action and report collection

Use the [Action guide](action.md) for complete file/env Ubuntu workflows and the
[exact input table](inputs.md#action-inputs). The Action builds from trusted source
and pinned public UAssetAPI, including an archive-safe submodule fallback. It
does not pull a private scanner image or need registry credentials. Public Git
and build dependency networking are required during preparation, not parsing.

Pin the remote Action to a reviewed full 40-character commit **only after** an
owner approves and tests named private consumers. Current external access is
`none`; no authorized consumer test exists (#13). Do not change visibility to
make an example work. Same-repository CI can use `uses: ./` after checking out
trusted scanner source; never check out a submitted repository in that job.

Collect valid reports in an `always()` step after failure. Default to restricted
local storage, not upload. The Action example leaves artifact upload off until
the complete artifact audience and retention are approved. Never upload whole
workspaces, policies, verbose logs, keys, engine/game assets or cooked evidence.
No `packages: write` or publication permission is required.

## Decide and retain

Capture exit status and the exact report together: 0 gates pass, 1 gate/content
failure, 2 invalid configuration, 3 runtime/transport/report failure. Some errors
cannot create a report; missing output is not a clean scan. Disabling gates does
not remove findings or turn uncertainty into safety. `successful` describes
analysis completion, not policy approval.

`possible-dispatches` records uncertain virtual/callback targets separately from
direct invocation counts. A possible forbid is not a definite forbidden occurrence;
it retains incomplete coverage and fails the default incomplete gate. See the
[partial indirect scope and source provenance](indirect-dispatch.md).
Recognized packages in that same pak now supply bounded possible hierarchy context,
bound by the original pak digest. External dependencies and unknown implementations
remain gaps; no new dependency path or game-installation lookup is available.

Use [moderation handoff](moderation.md) to bind original pak/dependency bytes,
retained report bytes, actual scanner identity, explicit game build and opaque
policy revision. Authenticate reviewer decisions outside this tool. Changed
context invalidates review. Unsettled findings/coverage go to the
[runtime escalation runbook](runtime-escalation.md), never automatic mod execution.

The [completed corpus/component receipt](regression-corpus.md#ci-upgrades-and-release-prerequisites)
and [original fixture provenance](owned-fixtures.md) document measured coverage.
The local release-path receipt is `/tmp/opencode/corpus-parent-release/execution.json`;
it is restricted local evidence, not a downloadable release or target-game proof.

## Guide validation (2026-10-25)

Fresh locked restore/build and direct evaluator file/env commands passed. The
basic corpus command above generated a new synthetic pak and rejected both
removal mutations. Host file/env/info and warned public-canary disclosure were
executed using the existing reviewed local corpus image
`sha256:8fe9e1347080c261eb285ed1a8a9e189009aa85f252b414de92066ea93005b3d`
via explicit `--image`, rather than rebuilding the documentation-only change.
All three reports matched byte-for-byte, mode 0600, after expected exit 1;
canary text appeared only in the warned verbose log, not reports or info logs.

The 137 existing Python tests, including serial Docker/Action and read-only
owned-evidence tests, passed without skips (142 total with the first five docs
checks). All eight final docs checks then passed separately. Extraction/Policy/
PolicyInput/Scanner passed 111/110/26/142. All 23 original receipt hashes matched;
no scanner containers remained. Restricted edit/test evidence is under
`/tmp/opencode/issue18-proof`; the basic corpus receipt is
`/tmp/opencode/operator-corpus/execution.json`.

No engine cook, mod/game execution, publication or external private-consumer
test occurred. Ubuntu workflow structure and local adapter behavior were tested,
not a newly authorized external GitHub consumer. This is edit/test evidence,
not independent review or release-artifact source provenance certification.
