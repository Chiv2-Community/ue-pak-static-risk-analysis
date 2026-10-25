# Integrated regression gate

`scripts/regression_corpus.py` joins original serialized packages, supervised pak
ingestion, normalized extraction, the actual evaluator CLI, and optionally the
actual Docker/Action boundary. It does not implement policy or parsing semantics.

## Run

Requires Linux, Python 3.11+, .NET 10, and the pinned UAssetAPI submodule.

```sh
python3 scripts/regression_corpus.py --output /tmp/opencode/new-corpus-run --components
```

For container/Action parity, build the current checkout locally. Run Docker suites
serially: existing tests compare daemon-wide owned container names.

```sh
docker build -t ue-pak-corpus:local .
python3 scripts/regression_corpus.py --output /tmp/opencode/new-container-corpus --docker-image ue-pak-corpus:local --components
```

The stronger local release check requires existing authorized cooked evidence:

```sh
python3 scripts/regression_corpus.py --release --output /tmp/opencode/new-release-corpus --docker-image ue-pak-corpus:local --owned-evidence /path/to/authorized-owned-evidence --components
```

`--release` requires all three options. `--owned-evidence` always requires a
completed receipt, matching recorded cook/evidence/mapping hashes, and a passing
`OwnedFixtures.Verify`. Missing evidence fails rather than skips. With Docker and
`--components`, existing cooked container/Action tests also run. Evidence is only
read; all new receipts/logs stay under the new output directory. No engine cook,
game execution, engine download, or image publication occurs.

## Reviewed evidence

[expectations.json](../fixtures/corpus/expectations.json) is independent of current
producer output. There is no baseline-update mode.

| Case | Expected evidence | Source |
| --- | --- | --- |
| Synthetic `Calls` | Native VM 0; outer/nested 15/24; different-owner same-name nonfinding 35; local constant/dynamic 45/56 | `tests/Corpus.Generate/Program.cs` |
| Synthetic `Map.umap` | Native VM 0; extension/routing only, not an engine Level Blueprint | Same generator |
| Synthetic `Unresolved` | Earlier call retained; virtual VM 10 unresolved | Same generator |
| Synthetic `Unsupported` | Earlier call retained; lossy ANSI string rejects later root/offset evidence | Same generator |
| Aggregate policy | 10 calls, 6 forbidden, 1 flagged, 7 affected; all three global gaps and evaluation uncertainty | `fixtures/corpus/policy.yaml` |
| Hostile archives | 16 seeded truncations, traversal, case collision, expansion bomb rejected; valid control accepted | Runner and existing pak builder |
| Boundary properties | 32 seeded iterations each: YAML/AST roundtrip and invalid schema, serialized bytecode offsets/truncation, facts roundtrip/duplicate keys, invalid output locations | Generator/runner; seed `150425` |
| Actual owned cook | Inheritance, BeginPlay/Level graphs, native constants, defaults, mapped/unmapped unversioned values | `fixtures/owned`; `tests/OwnedFixtures.Verify`; external evidence |
| Keys, dependencies, sidecars, signatures, unsupported instructions, quotas, cancellation, large outputs | Existing component expectations run unchanged with `--components` | Manifest `component-coverage` references |

The manifest pins package/sidecar and deterministic uncompressed V9 pak SHA-256.
The oracle checks all normalized locations/targets, exact constant/dynamic values,
metadata, findings, coverage and outcomes. Public IDs are reconstructed from
reviewed locations and pak hash using the public identity encoding, not learned
from observed findings. No brittle Git revision enters expected semantics.

Generation uses the pinned UAssetAPI writer on original minimal models, followed
by public `InvocationExtractor.Read`/`PackageReader`. Two empty-header initializers
use reflection because upstream has no complete public blank-package builder.
The pak builder is `tests/ingestion_fixture.py`. These files are **synthetic,
not engine-cooked**, even when a synthetic package uses the `.umap` extension.

## Regression, parity and privacy

- Two mutations start from an actual validated CLI report: remove a sensitive
  finding and adjust counts; suppress `unsupported-parsing`. Both remain
  schema-valid and must fail the independent expectation checker.
- All eight gate combinations must preserve report evidence. File/environment
  sources and error/warn/info/verbose must produce identical reports. Malformed
  policy, source conflicts/missing sources and invalid configuration fail closed.
- With Docker, production parser facts feed the direct evaluator. Its **complete
  JSON report** must equal wrapper/Action reports, including inspection, IDs and
  context. No fields are dropped or normalized. The standalone synthetic route
  uses producer `synthetic-corpus-v1` and has no archive inspection; it is checked
  separately, not compared after stripping fields. Container routes all use
  `container-v1`.
- The original canary policy is public test data. Error/warn/info logs must not
  contain it; verbose logs must contain it after a warning with runner commands
  escaped. Reports, Action outputs and summaries must never contain it. Integrated
  real-finding Action checks cover info/verbose; existing component matrices cover
  all source/level/error/isolation and large-output paths.
- Report validation reuses `scripts/report_validation.py` and shipped closed
  schemas, including duplicate/case/count/privacy checks. No second validator or
  shadow evaluator is introduced.

Runner setup/services, administrators and Docker daemon access can expose ordinary
environment values outside these controlled channels. Raw environment YAML is not
a secret or an argv value. See [policy input](policy-input.md).

## Bounds and receipts

- Output must be new, external and mode 0700. Keep it private: intentional verbose
  logs contain policy text. CI uploads no generated artifacts.
- Per-command deadlines: 30 seconds normally, 180 for builds/tests, 900 for the
  serial Python component suite. Streamed stdout/stderr cap: 32 MiB combined.
  Aggregate output cap: 64 MiB checked after commands. No core dumps. Cancellation
  signals the process group, allows 15 seconds for owned-container cleanup, then
  kills the group. CI has a 30-minute outer deadline.
- Archive mutations use the production worker, one-second wall budgets, existing
  CPU/address-space/storage quotas, and inputs below 2 MiB. Worker crashes/timeouts
  do not count as successful rejection. Fixed-size generator/property processes
  have a 512 MiB managed heap limit and command deadline.
- Component tests retain production quotas. The runner does not lower inherited
  hard file limits: that would prevent worker limit setup and sparse oversize tests.
- `execution.json` records completion, runtime, source/oracle hashes, exact argv,
  exits, timings and log hashes. `dotnet --info` output is retained. Failed runs do
  not receive `completed: true`.

## CI, upgrades and release prerequisites

The **Integrated release regression gate** workflow runs on every push/PR/manual
dispatch, without path filters. It uses pinned Actions/submodules, builds only the
current local sandbox, and runs the corpus plus all component suites serially.
It needs no engine or private image. Owner-managed branch protection should require
this job; this change does not alter repository settings or publish a release.

For each pinned dependency upgrade:

1. Preserve old/new receipts and full report/facts diffs privately.
2. Run the full CI corpus and authorized local `--release` gate. Never auto-rewrite
   expectations to accept new output.
3. Review every identity, offset, argument, diagnostic, count and hash change.
   Compare serialized bytes/writer sizes and authorized engine bytecode/reflection;
   UAssetGUI/FModel or Kismet Analyzer can help. Decompiled output is not an oracle.
4. Commit justified source/oracle changes with review evidence; rerun both removal
   mutations and full parity/privacy checks. Hash-only updates do not prove correctness.

Source, policy and expectations are original test material. Generated packages,
paks, mappings and cooked binaries remain external; no proprietary or engine
content is committed/uploaded. See [owned-fixture provenance](owned-fixtures.md).
Owned binary redistribution is **not approved** by this work.

The non-Docker gate passed with immutable authorized evidence at
`/tmp/opencode/owned-fixture-clean-20261025`, without recooking or modifying it.
Receipt: `/tmp/opencode/corpus-run-8/execution.json` (2026-10-25).

| Validation | Result |
| --- | --- |
| Extraction / Policy / PolicyInput / Scanner | 111 / 110 / 26 / 91 passed |
| Ordinary Python, including four runner guards | 109 passed |
| Synthetic oracle and both removal mutations | Passed |
| External cook receipt hashes and owned verifier | Passed |
| Docker-dependent component tests | 17 skipped; no Docker run authorized in this edit leg |

Container/Action integration and hosted CI still require parent validation.
Do not close #15 solely on synthetic CI: release artifact authorization and
external cooked release evidence require confirmation. Exact game/Windows fidelity
remains #2; private external Action access remains #13. Indirect/data-driven/native
implementation analyses are not shipped and have no claimed corpus proof.
