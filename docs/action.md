# GitHub Action

Scan a pak on a trusted Ubuntu runner. The Action calls the same
[host Docker wrapper](container.md); it does not implement policy semantics.
It runs neither the game nor Unreal Editor. Analysis is not a safety verdict.

## Trust and access

- Pin this Action/scanner to a reviewed **full 40-character commit**, not a branch
  or mutable tag. Replace `REVIEWED_40_HEX_COMMIT` below before use.
- Use trusted workflow code and policy. Download only the submission **pak**, not
  submission code; never check out or execute a submitter's repository.
- Use a disposable Linux VM with non-root Python 3.11+, Git, and local Docker at
  `/usr/bin/docker` and `/var/run/docker.sock`. Docker access grants host-admin
  power. No Docker-in-Docker, socket mount, registry credentials, or publish step
  is needed. No arbitrary image input is offered.
- Keep `permissions: contents: read`, set a job timeout, and do not expose this
  policy-bearing job, its outputs, or logs to unapproved submitters.
- Reports/outputs omit private rule IDs and descriptions. They still reveal
  findings and package metadata. There is no moderator-detail Action profile.

Optional `capability-summaries` accepts only a trusted **nonsecret** catalog path;
never accept it from a submission. Exact bytes/revision bind report context and
matches always require review, even with all three gate flags disabled. The full
report adds [bounded call chains](call-chains.md), including public capability IDs;
direct Action arrays/counts and their budgets do not include caller witnesses.
No production game catalog is bundled. Optional separately versioned
[private capability rules](capability-policy.md) select catalog capabilities and
bounded callers without changing invocation YAML or direct counts.

**Private consumer gate remains open.** On 2026-10-25 the read-only API call
`gh api repos/Chiv2-Community/ue-pak-static-risk-analysis/actions/permissions/access`
returned `{"access_level":"none"}`. No authorized external consumer was supplied
or tested; no visibility/access settings were changed. An owner must authorize
and test a named consumer before claiming cross-repository private-Action access.
Do not make the repository public to bypass this gate. Local same-repository CI
tests do not verify private consumer access. #13 must remain open for this gate.

Images are built locally, never pulled from a private registry or published.
Private-image authentication is therefore not required or claimed verified.

## Use

The complete [input table](inputs.md#action-inputs) lists every input/default.

This example assumes `/approved/submission.pak` has been obtained without
executing submission code. Choose the actual virtual pak prefix for content-root.
Use no checkout step when only calling the remotely pinned Action.

```yaml
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      # Obtain only the approved submission file here, using trusted code.
      - name: Scan
        id: scan
        uses: Chiv2-Community/ue-pak-static-risk-analysis@REVIEWED_40_HEX_COMMIT
        with:
          pak: /approved/submission.pak
          content-root: OwnedFixtures/Content=/Game
          engine-version: '4.25'
          log-level: info
          fail-on-any-forbidden: 'true'
          fail-on-any-flagged: 'false'
          fail-on-incomplete: 'true'
          report: ue-pak-risk-report.json
          # mapping: /approved/owned.usmap
        env:
          # Example policy, not a required GitHub secret. Replace with trusted rules.
          UE_PAK_POLICY_RULES: |
            schema-version: 1
            rules:
              - id: review-launch
                description: Review external URL launches.
                effect: forbid
                match:
                  kind: invocation
                  target:
                    kind: exact
                    owner: /Script/Engine.KismetSystemLibrary
                    function: LaunchURL
      # OPTIONAL: enable only after approving access for every artifact reader.
      - name: Collect report after success or gate failure
        if: ${{ always() && steps.scan.outputs.report-available == 'true' && vars.ALLOW_PAK_REPORT_ARTIFACTS == 'true' }}
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        with:
          name: restricted-pak-report
          path: ${{ steps.scan.outputs.report-path }}
          retention-days: 1
          if-no-files-found: error
```

Artifact uploads are **off by default in this example and CI**. GitHub artifacts
are not a separate private vault; repository/workflow readers may have access.
Approve the reader set and retention first, or collect into an independently
access-controlled store in an `always()` step. Never upload policies, whole
workspaces, verbose logs, environment dumps, or cooked fixtures.

For file input, replace the `env` block with
`with: {pak: /approved/submission.pak, policy-rules: /private/rules.yaml}`.
`policy-rules` is a **file path**, never inline YAML. Exactly one policy source
is required; do not set `UE_PAK_POLICY_RULES` at all when using a file. Missing,
empty, conflicting, malformed, or oversized sources fail through the shared loader.
Raw environment YAML is not placed in argv or temporary files.

A complete file-backed variant, once the named private consumer is authorized:

```yaml
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      # Trusted transfer provisions only pak and operator-owned policy first.
      - name: Scan with restricted file policy
        id: scan
        uses: Chiv2-Community/ue-pak-static-risk-analysis@REVIEWED_40_HEX_COMMIT
        with:
          pak: /approved/submission.pak
          policy-rules: /private/rules.yaml
          content-root: Content=/Game
          log-level: info
          report: ue-pak-risk-report.json
      - name: Check local report after gates
        if: ${{ always() && steps.scan.outputs.report-available == 'true' }}
        shell: bash
        env:
          REPORT: ${{ steps.scan.outputs.report-path }}
        run: test -f "$REPORT"
```

Do not define `UE_PAK_POLICY_RULES` anywhere in this job for the file variant.
The last step leaves the report local; it does not upload it. Configure separately
authorized restricted collection if retention beyond the disposable runner is
needed. File and env examples require trusted scanner/workflow/policy provenance;
neither may execute submitted code or expose network credentials to the parser.

`log-level` accepts `error`, `warn`, `info` (default), and `verbose`.
**Verbose prints the complete escaped policy after a disclosure warning; anyone
with log access can read it.** Environment variables are not secrets and do not
guarantee masking or confidentiality. Runner setup/debug logs and administrators
can expose environment values independently of the scanner. Use file input with
restricted runner access for private rules; do not use verbose for private rules.
The Action preserves the shared reversible renderer, including LF and escaped
workflow-command/terminal characters. Verbose never adds policy to outputs,
summaries, annotations, or reports.

## Outputs and failures

Outputs and a fixed, metadata-free summary are appended **before** returning
scanner gate failures. No supplied filename or policy is rendered in the summary.

| Output | Meaning |
| --- | --- |
| `flagged-invocations`, `forbidden-invocations` | Single-line escaped JSON arrays from the report |
| `invocations-count`, `flagged-count`, `forbidden-count`, `affected-union-count` | Full counts; `unknown` if no valid report |
| `analysis-complete` | Completion, not safety or gate success |
| `status` | `successful`, `partial`, or `failed` analysis |
| `diagnostics` | JSON array of fixed report/adapter codes |
| `report-path`, `report-available` | Workspace-relative destination and valid-report availability |
| `arrays-omitted`, `omission-reason` | Explicit omission state; check before consuming arrays |
| `capability-analysis-status` | `not-performed`, `complete`, `incomplete`, or `unknown` |
| `capability-flagged-count`, `capability-forbidden-count` | Retained symbolically matching witness counts, never executed/direct invocation counts |
| `capability-possibly-flagged-count`, `capability-possibly-forbidden-count` | Retained uncertain witness counts; unlocated unknowns are not included, so check completeness/full report |

Optional private `capability-rules`, `capability-policy-revision` and new
`capability-context` inputs follow the [input table](inputs.md). Private rules,
revision, predicates and hashes never enter outputs/summary, even verbose. Keep
the context receipt restricted; it is not a submitter artifact. Capability gates
and existing catalog review cannot be disabled by invocation gate inputs.

The report is authoritative. Combined outputs are limited to **256 KiB counted
as UTF-16 bytes**, conservatively below GitHub's 1 MiB/job limit. If arrays exceed
the budget, both become valid `[]`, `arrays-omitted=true`, and
`omission-reason=output-budget`; counts and the complete report remain available.
This is not zero findings or silent truncation. Multiple scans/other outputs can
still exhaust the job-wide limit. GitHub may also suppress outputs it considers
secrets; consumers must not infer success from missing outputs.

The adapter bounds report bytes/depth/nodes, rejects duplicate keys and malformed
Unicode, validates the closed shipped report/facts schemas and count consistency,
and rejects moderator-detail fields. It does not re-evaluate rules or gates.
Missing/invalid reports produce `status=failed`, `analysis-complete=false`,
`report-available=false`, unknown counts, and explicit diagnostics rather than an
invented clean report. Inspect `diagnostics` and the prior fixed wrapper messages.
An unwritable runner output/summary file fails the step; outputs cannot be
guaranteed when GitHub's own files are unavailable.

The report destination must be a **new workspace-relative file** with an existing
parent. Only ASCII letters/digits, `_`, `.`, `/`, and `-` are accepted. No `..`,
outside-workspace resolution, Action-source-tree writes, runner-file aliases,
or overwrite is allowed. Keep policy files unchanged for the scan duration.

Exit behavior is inherited: 0 gates pass; 1 gate fails; 2 invalid configuration;
3 runtime, image, report, or transport failure. Disabling incomplete/forbidden
gates does not make incomplete/forbidden analysis safe.

## Archive-safe build

GitHub's downloaded Action archive may omit submodules. Preparation always fetches
the public UAssetAPI source at
`b4e8a012939295a6fd890ddc64e57ea78b709b95` from
`https://github.com/atenfyr/UAssetAPI.git` into an isolated temporary checkout.
No submitter repository, host Git config, hooks, credential helper, token, policy,
or SSH agent is passed to Git or Docker. Only trusted scanner source, the pinned
dependency, and the existing allowlisted `.dockerignore` build context are used.
The engine/repak CLI is not needed. Base images and restores retain the shared
Dockerfile's pinned/locked dependencies. Public network access is needed during
preparation; scans themselves retain the wrapper's network-free containment.
Preparation failure still reaches the adapter's failed-output path.

Each invocation builds a unique local tag; the wrapper resolves its immutable
identity before scanning. No local images are pruned automatically. Disposable
workers provide cleanup and stronger tenant separation than shared Docker hosts.

## Validation

`.github/workflows/action.yml` uses the same-repository Action on Ubuntu with a
synthetic owned pak and public example policy, then checks report/output/gate
parity and runs the driver against the actual local Docker boundary. It uses no
engine or private policy and uploads nothing.

```bash
python3 -m unittest discover -s tests -p test_action.py -v
UE_PAK_CONTAINER_TEST_IMAGE=ue-pak-static-risk-analysis:dev \
  OWNED_FIXTURE_EVIDENCE=/approved/owned-fixture-evidence \
  python3 -m unittest discover -s tests -p test_action.py -v
```

Install `tests/requirements.txt` in a venv for Python tests; CI uses the same pins.
The Action runtime uses only the
Python standard library. Owned evidence tests read original cooked files and
generate temporary pak copies. They do not establish exact Windows/game fidelity
or private external-consumer access.

Local validation (2026-10-25): archive-safe preparation succeeded with no initialized
Action submodules. The resulting local image is
`sha256:6c5caa9756b0f95872a770f527875b10d5b7db99cc33d107655322c5c6513e5a`;
policy/token canaries were absent from its config/history. This is not a published
digest. The authored GitHub workflow has not been run by this edit/test delivery;
external access and CI results still require parent verification.
