# Input reference

Run from the trusted checkout root. No shorthand policy files or game defaults
are implied. See [operator examples](operators.md) for setup and safe collection.
`none` means omitted, not an empty string. Enum values below are exhaustive.

Optional [private data rules](data-policy.md) compare typed serialized evidence
against an explicitly supplied original pak. They do not verify a clean game
installation, effective defaults or native behavior. #10 remains open.

## Host scanner

`python3 scripts/scan.py scan`:

| Input | Type | Default | Example | Description |
| --- | --- | --- | --- | --- |
| `command` | enum: `scan` | required | `scan` | Trusted host orchestration, not an in-container command. |
| `--pak` | file path | required | `/approved/mod.pak` | Stable regular original pak, at most 256 MiB. |
| `--report` | new file path | required | `/restricted/new.json` | Existing trusted parent; exclusive mode-0600 output, including gate failures. |
| `--engine-version` | enum: `4.25` | required | `4.25` | Parsing hint, not producer/game-build proof. |
| `--image` | local image reference | `ue-pak-static-risk-analysis:dev` | `ue-pak-release-check:local` | Operator-built image; resolves to immutable local ID; never pulled during scan. |
| `--timeout` | number, seconds `(0,600]` | `60` | `90` | Per-container deadline, not whole-command deadline. |
| `--policy-rules` | file path | none | `/private/rules.yaml` | Exactly one file or raw environment policy source. |
| `--capability-summaries` | trusted nonsecret file path | none | `/approved/catalog.json` | Optional catalog v1, 256 KiB/256 exact targets; matched capabilities always require review. Parser never receives it. |
| `--data-rules` | private trusted file path | none | `/private/data-rules.json` | Closed data-policy v1; requires game-build, content-root and private data-context output. Never mounted in parser. |
| `--baseline-pak` | authorized file path | none | `/private/original.pak` | Optional original pak, independently bounded/snapshotted/parsed read-only; requires data-rules. Not authenticated clean or a safety guarantee. |
| `--game-build` | operator assertion | none | `original-fixture-v1` | Exact private data-rule build scope. Does not authenticate build metadata. |
| `--data-context` | new private file path | none | `/private/new-context.json` | Required with data-rules; mode-0600 private report/dependency binding. Never publish. |
| `--log-level` | enum: `error`, `warn`, `info`, `verbose` | `info` | `info` | **Warning: verbose prints the full policy to logs; anyone with log access can read it. Env values are not masked secrets; step setup/admin access can expose them independently.** |
| `--policy-revision` | opaque ASCII token, 1–128 characters | none | `review-2026-001` | Operator-controlled revision, not policy-content hash; required for moderation context. |
| `--fail-on-any-forbidden` | enum: `true`, `false` | `true` | `true` | Fail if any forbidden invocation exists. |
| `--fail-on-any-flagged` | enum: `true`, `false` | `false` | `true` | Fail if any flagged invocation exists. |
| `--fail-on-incomplete` | enum: `true`, `false` | `true` | `true` | Fail for coverage, rule uncertainty, content or call-chain incompleteness. |
| `--moderator-detail` | presence switch | absent | `--moderator-detail` | Add matched rule IDs; requires separately restricted readers, not authentication. |
| `--mapping` | file path | none | `/approved/owned.usmap` | One authorized property mapping, at most 16 MiB. |
| `--content-root` | `VIRTUAL_PREFIX=/LogicalRoot` | none | `Content=/Game` | One explicit virtual-to-logical mapping; no game root inferred. |
| `--allowed-path` | repeatable virtual prefix | empty list | `Content/Mods` | Known nonmatching member rejected; component-boundary ASCII case-insensitive match. |
| `--allowed-class` | repeatable class identity | empty list | `/Script/CoreUObject.Function` | Exact case-sensitive parsed ClassIndex identity, not inheritance/capability. |
| `--protected-path` | repeatable virtual prefix | empty list | `Content/Base` | Matching member is a replacement candidate, not a proven override. |
| `--replacement-policy` | enum: `allow`, `review`, `reject` | `review` when protected paths exist | `review` | Requires protected path; one setting only. No clean-install comparison. |
| `--help`, `-h` | presence switch | absent | `--help` | Argparse usage. |

Empty allowlists impose no restriction of that kind. Unknown inventory/classes
retain incomplete evidence; they are not approved by an allowlist. Content
`needs-review`/`reject` **always exits 1**, regardless of the three gates. Content
`allow` is not safety approval and does not override gaps or other restrictions.
See [content semantics/limits](content-policy.md).

## Shared evaluator

`dotnet src/Scanner/bin/Release/net10.0/Scanner.dll COMMAND` has no help switch.
Unknown or repeated nonrepeatable options fail. It accepts the shared policy,
log/revision, capability summaries, three gates, moderator-detail and four content flags above, with
the same defaults. Host-only image/timeout/pak/mapping/content-root are not flags.

| Input | Type | Default | Example | Description |
| --- | --- | --- | --- | --- |
| `COMMAND` | enum: `evaluate`, `validate`, `failure-report` | required | `evaluate` | Evaluate facts, validate trusted settings only, or fixed operational-failure transport. |
| `--report` | new path or `-` | required | `/restricted/new.json` | `-` writes JSON stdout; validate success produces no report. |
| `--engine-version` | enum: `4.25` | required except failure-report | `4.25` | Supported parsing contract. |
| `--facts` | stable regular file path | required for evaluate | `examples/facts-v1.json` | Bounded normalized facts, not uploaded trusted claims; verify producer provenance. |
| `--expected-pak-sha256` | lowercase SHA-256 | none | trusted 64-hex digest | Bind facts to original snapshot. |
| `--expected-mapping-sha256` | lowercase SHA-256 | none | trusted 64-hex digest | Bind the unique mapping dependency; pak binding required too. |
| `--reason` | enum: `parser-failed`, `parser-output-limit`, `wall-timeout`, `cancelled`, `container-unavailable`, `input-failed`, `invalid-configuration` | required for failure-report | `parser-failed` | Internal wrapper failure report; not an alternate empty-success path. |
| `--policy-rules` | file path | none | `/private/rules.yaml` | Exactly one file/env source for evaluate/validate. |
| `--capability-summaries` | trusted nonsecret file path | none | `/approved/catalog.json` | Optional bounded catalog v1; validates before verbose policy disclosure. Exact digest/revision bind report context. |
| `--data-rules` | private trusted file path | none | `/private/data-rules.json` | Optional closed data extension; validated before any verbose invocation-policy disclosure. Never logged, even verbose. |
| `--game-build` | operator assertion | none | `original-fixture-v1` | Required with data-rules; exact reviewed build scope. |
| `--baseline-facts` | private facts file path | none | `/private/baseline-facts.json` | Internal isolated-parser transport; standalone facts are caller assertions, not authenticated baseline content. Requires data-rules and both baseline options below. |
| `--expected-baseline-sha256` | lowercase SHA-256 | none | trusted 64-hex digest | Bind baseline facts to the independently snapshotted original pak; must match reviewed data-rule context too. |
| `--baseline-facts-assertion` | enum: `caller-supplied-not-authenticated` | none | `caller-supplied-not-authenticated` | Required explicit acknowledgement with baseline-facts. Shape/digest matching is not authenticity. |
| `--log-level` | enum: `error`, `warn`, `info`, `verbose` | `info` | `info` | **Warning: verbose prints the full policy to logs; anyone with log access can read it. Env is not masked; step setup/admin access can expose it independently.** |
| `--policy-revision` | opaque ASCII token, 1–128 characters | none | `review-2026-001` | Caller-owned identity, not policy-content hash. |
| `--fail-on-any-forbidden` | enum: `true`, `false` | `true` | `true` | Fail on any forbidden invocation. |
| `--fail-on-any-flagged` | enum: `true`, `false` | `false` | `true` | Fail on any flagged invocation. |
| `--fail-on-incomplete` | enum: `true`, `false` | `true` | `true` | Fail on coverage, evaluation, content or call-chain incompleteness. |
| `--moderator-detail` | presence switch | absent | `--moderator-detail` | Adds matched rule IDs; separately restrict report readers. |
| `--allowed-path` | repeatable virtual prefix | empty list | `Content/Mods` | Reject known nonmatching members. |
| `--allowed-class` | repeatable exact class identity | empty list | `/Script/CoreUObject.Function` | Reject known nonmatching classes. |
| `--protected-path` | repeatable virtual prefix | empty list | `Content/Base` | Mark replacement candidates, not proven overrides. |
| `--replacement-policy` | enum: `allow`, `review`, `reject` | `review` when protected paths exist | `review` | Requires protection; review/reject always fails gates. |

Shared `--log-level` is `error`, `warn`, `info` (default), `verbose`.
**Warning: verbose prints the full policy to logs; anyone with log access can
read it. Ordinary env is not masked; runner setup/admin visibility is external
to scanner filtering.** Full inherited input descriptions are in the host table;
[evaluate.md](evaluate.md) defines report and transport semantics.

## Action inputs

The composite Action exposes exactly these inputs, not all host flags. Boolean
inputs are strings with exact lowercase values. No arbitrary image, content
allowlists, policy revision or moderator-detail input exists.

| Input | Type | Default | Example | Description |
| --- | --- | --- | --- | --- |
| `pak` | runner file path | required | `/approved/mod.pak` | Original pak only; no submission checkout. |
| `policy-rules` | file path | none | `/private/rules.yaml` | Alternative to raw step environment YAML; exactly one source. |
| `capability-summaries` | trusted nonsecret runner file path | none | `/approved/catalog.json` | Optional bounded catalog v1, never submission-controlled; capability matches always require review. |
| `data-rules` | private trusted runner file path | none | `/private/data-rules.json` | Optional data-policy v1; requires game-build, content-root and data-context. No inline policy or submission-controlled model. |
| `baseline-pak` | authorized runner file path | none | `/private/original.pak` | Optional bounded original pak; isolated read-only parsing, not a verified clean installation. |
| `game-build` | operator assertion | none | `original-fixture-v1` | Exact reviewed private data-model build scope; not authentication. |
| `data-context` | new private workspace-relative path | none | `private/new-context.json` | Required with data-rules; restrict collection and never publish private dependency/context fingerprints. |
| `engine-version` | enum: `4.25` | `4.25` | `'4.25'` | Supported parsing hint. |
| `log-level` | enum: `error`, `warn`, `info`, `verbose` | `info` | `info` | **Warning: verbose prints the full policy to workflow logs; anyone with log access can read it. Env values are not masked secrets; step setup/admin access can expose them independently.** |
| `fail-on-any-forbidden` | enum: `true`, `false` | `true` | `'true'` | Fail on forbidden findings. |
| `fail-on-any-flagged` | enum: `true`, `false` | `false` | `'false'` | Fail on flagged findings. |
| `fail-on-incomplete` | enum: `true`, `false` | `true` | `'true'` | Fail on incomplete analysis/evaluation. |
| `report` | new workspace-relative path | `ue-pak-risk-report.json` | `reports/new.json` | Parent exists; ASCII path constraints and no overwrite; check report-available. |
| `content-root` | `VIRTUAL_PREFIX=/LogicalRoot` | none | `Content=/Game` | One explicit root mapping. |
| `mapping` | runner file path | none | `/approved/owned.usmap` | One authorized bounded property mapping. |

See [Action outputs and failures](action.md#outputs-and-failures). Reports remain
authoritative when arrays are omitted. The Action source pin is a full reviewed
commit; remote private use is blocked pending named-consumer authorization/test.
Indirect candidates appear only in the full report's optional `possible-dispatches`,
not direct invocation arrays/counts. [Call chains](call-chains.md) likewise remain
separate; no YAML predicate is added. Explicit catalog matches always require
review regardless of the three existing gate values.

## Environment policy source

| Input | Type | Default | Example | Description |
| --- | --- | --- | --- | --- |
| `UE_PAK_POLICY_RULES` | raw UTF-8 YAML | absent | public `fixtures/corpus/policy.yaml` text | Not a filename or required secret; exactly one file/env source. Empty counts as selected and fails. Not forwarded to parser; never baked into image. |

Default info omits policy from scanner-controlled logs. Environment is not
automatically masked; host/container/runner administrators and GitHub step setup
may expose it. Never claim that scanner filtering alone provides confidentiality.

## Regression runner

`python3 scripts/regression_corpus.py`:

| Input | Type | Default | Example | Description |
| --- | --- | --- | --- | --- |
| `--output` | new external directory | required | `/tmp/opencode/new-corpus` | Private evidence, no overwrite. |
| `--docker-image` | existing local image | none | `ue-pak-release-check:local` | Add real container/Action parity; no pull/publish. |
| `--owned-evidence` | authorized evidence directory | none | `/approved/owned-evidence` | Receipt/hash/verifier checks; failure cannot skip. |
| `--components` | presence switch | absent | `--components` | All component suites; Docker suites serial when image supplied. |
| `--release` | presence switch | absent | `--release` | Requires components, image and owned evidence; never authorizes publication. |
| `--help`, `-h` | presence switch | absent | `--help` | Usage. |

## Local moderation

`python3 scripts/moderation.py COMMAND`; all outputs are new files. No default
human approval exists. [moderation.md](moderation.md) defines authenticated
platform responsibilities, exact-byte binding and invalidation.

| Input | Type | Default | Example | Description |
| --- | --- | --- | --- | --- |
| `COMMAND` | enum: `handoff`, `review`, `verify`, `feedback` | required | `handoff` | Local operation, no network/service. |
| `--report` | file path | required for handoff/verify | `examples/moderation/report.json` | Exact default-profile report bytes. |
| `--context` | file path | required for handoff/verify | `examples/moderation/context.json` | Current trusted scan/build/game/policy context. |
| `--pak` | file path | required for handoff/verify | `examples/moderation/submission.txt` | Exact original bytes. |
| `--dependency` | repeatable `KIND=PATH` | empty list | `mapping=examples/moderation/mapping.txt` | Exact dependency set, no missing/extra kinds. |
| `--output` | new file path | required except verify | `/restricted/new.json` | Exclusive mode-0600 output. |
| `--handoff` | file path | required for review/feedback | `/restricted/handoff.json` | Valid private handoff. |
| `--actor` | bounded identity text | required for review | `example-moderator` | Caller assertion, not authentication. |
| `--decision` | enum: `approve`, `reject`, `request-review` | required for review | `request-review` | Explicit human disposition; failed analysis cannot be approved. |
| `--rationale` | bounded nonempty text | required for review | `'Review unresolved behavior.'` | Private human rationale. |
| `--approval` | file path | required for verify | `/restricted/review.json` | Current authoritative decision; caller enforces revocation. |
| `--help`, `-h` | presence switch | absent | `--help` | Usage. |

## Experimental/fixture tools

These are not the hostile-submission scanner. `python3 -m pak_ingest ARCHIVE`
accepts one required archive path, plus argparse `-h`/`--help`; it only emits
ingestion evidence. `scripts/escalation_canary.py` accepts **no arguments** and
executes only its fixed trusted local child, never game/mod code.

`python3 scripts/probe_pak.py` is trusted-input-only:

| Input | Type | Default | Example | Description |
| --- | --- | --- | --- | --- |
| `--pak` | file path | required | `/approved/mod.pak` | Authorized experiment input. |
| `--repak` | executable path | required | `vendor/repak/target/release/repak` | Separately built pinned external CLI. |
| `--probe-dll` | assembly path | required | `src/CompatibilityProbe/bin/Release/net10.0/CompatibilityProbe.dll` | Built trusted compatibility probe. |
| `--output` | new directory | required | `/restricted/new-experiment` | Extracted bytes/logs remain private. |
| `--mappings` | file path | none | `/approved/owned.usmap` | Optional authorized mapping. |
| `--help`, `-h` | presence switch | absent | `--help` | Usage. |

The probe DLL itself takes `INPUT NEW_REPORT [MAPPINGS]` (paths, first two
required, mappings default absent). Its exits differ from scanner gates;
`analysis-complete` always remains false. See [compatibility](compatibility.md).

`python3 scripts/cook_owned_fixtures.py` requires separate authorized engine
access. It is **not** run by operator examples or release preparation:

| Input | Type | Default | Example | Description |
| --- | --- | --- | --- | --- |
| `output` | new external directory | required | `/restricted/new-owned-cook` | Generated engine-derived assets stay external. |
| `--timeout` | integer seconds, 1–3600 | `1800` | `1800` | Whole cook driver deadline. |
| `--ddc-seed` | authorized directory | none | `/approved/engine-cache` | Read-only cache seed, not cook content. |
| `--help`, `-h` | presence switch | absent | `--help` | Usage. |

No engine/image download is performed; fixed local engine identity and legal
limits are in [owned-fixtures.md](owned-fixtures.md). Test generator/verifier
programs are internal corpus components, not released scanner interfaces.

`python3 scripts/owned_fixture_usmap.py` is a trusted producer helper, not a
general mapping dumper or hostile-input interface:

| Input | Type | Default | Example | Description |
| --- | --- | --- | --- | --- |
| `reflection` | file path | required | `/approved/producer-reflection.json` | Authorized original producer reflection; IntProperty/StrProperty only. |
| `output` | new file path | required | `/restricted/new-owned.usmap` | Exclusive creation; no overwrite. |
| `--help`, `-h` | presence switch | absent | `--help` | Usage. |

`python3 scripts/action.py COMMAND` is an internal adapter, not an alternative
operator scanner:

| Input | Type | Default | Example | Description |
| --- | --- | --- | --- | --- |
| `COMMAND` | enum: `prepare`, `scan` | required | `scan` | Action lifecycle; no further argv flags/help. Other argv exits 2. |

The composite supplies `INPUT_*` from the Action table, `GITHUB_WORKSPACE`,
existing runner `GITHUB_OUTPUT`/`GITHUB_STEP_SUMMARY` files and the internal
`UE_PAK_ACTION_IMAGE` preparation result. Do not let submitters select that image
or use test environment overrides as supported Action inputs. Preparation has
no policy/credential environment; scan forwards only the shared raw-policy
variable to trusted evaluators. See [archive-safe preparation](action.md#archive-safe-build).
