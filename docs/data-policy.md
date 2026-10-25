# Private serialized-data policy

Optional data-policy v1 produces separate non-invocation findings from exact
reviewed structural matches. No name, URL or command heuristic is used. No game
catalog is bundled. **#10 remains open:** cross-package effective defaults,
reflection/native implementations and exact-game property-purpose metadata are
not established.

## Configuration and gates

- `--data-rules FILE` is private JSON, maximum 256 KiB/256 rules. Invocation YAML
  v1 remains closed and unchanged. See [schema](../schemas/data-rules-v1.schema.json)
  and [all inputs](inputs.md).
- Required context: engine `4.25`, explicit build scope, virtual content root,
  logical root, optional exact mapping digest, and explicit
  `submission-over-baseline` precedence. This is an operator model, not proof of
  actual engine mount/load order or build authenticity.
- Each rule supplies exact member path, object/class identity, recorded CDO flag,
  structural property path, reviewed purpose/provenance and `review`/`reject`.
  Metadata and IDs are private even when the file happens to have a public name.
- Predicates: `changed` against the supplied baseline; `equals`/`not-equals`
  against an exact typed known literal. No regex, includes, code or network.
  `expected` is JSON null only for `changed`; explicit null references use
  `{"kind":"null-reference"}`. Unknown is never null or an unchanged value.
- Integer widths, names, enum types, delegate receivers/function names and exact
  reference target kinds remain typed. References compare symbols, not unstable
  package-table indices. Delegate values are not invocation/binding-flow proof.
- `review`/`reject` findings and **all enabled data-analysis unknowns fail the
  shared gate**, even with every invocation gate disabled. `no-match` is not
  unchanged behavior or safety approval.
- Without data rules, data analysis is not performed. Legacy report shape and
  completeness are unchanged; the absence of `data-analysis` means no coverage
  of this feature. No default global incomplete flag is added.

## Baseline boundary

The host takes `--baseline-pak FILE` only with data rules. It independently
snapshots a bounded no-follow regular original pak, hashes exact bytes, and mounts
only that snapshot plus the same authorized mapping read-only in a separate
policy-free parser container. Baseline and submitted parsers have no catalog,
policy, credentials, host game installation, socket or workspace mounts.

The private rules declare the baseline pak digest and an identical engine/build/
root/mapping/precedence context. Trusted evaluation verifies these declarations,
the host snapshot digest, parsed roots and mapping dependencies before comparing.
Mismatches are configuration/operational failures, not blind comparisons. Missing
baselines, missing properties, unsupported values, collisions and incomplete
baselines produce fixed data diagnostics. A supplied baseline is never called
verified clean or safe, and never certifies native code. No installation is
discovered/downloaded; baseline rights and provenance remain operator duties.

The lower-level `--baseline-facts` API requires the explicit acknowledgement
`--baseline-facts-assertion caller-supplied-not-authenticated`. Standalone facts
can claim a digest; this does not prove their source. Production host scans use
the isolated original-pak path, not uploaded baseline fact files.

Member identities use the existing normalized ASCII, case-insensitive namespace.
Case collisions never select a winner. [Protected prefixes](content-policy.md)
remain replacement candidates. Object/class/property identities are exact and
case-sensitive. Only serialized occurrences are compared, not engine-effective
values. Missing child properties do not silently inherit native, external or
cross-package values. The library's verified local CDO-chain API remains a
separate structural provenance proof; these rules do not promote it to effective
runtime values or bypass its unknowns.

## Reports and private moderation context

`data-analysis` has its own version, decision, completeness, fixed diagnostics and
findings. Findings contain only inventory member ID, export index, property
ordinal, fixed reason and action. No serialized value, rule ID, condition,
purpose/provenance, baseline path/hash or catalog fingerprint is copied into
ordinary reports, logs, Action outputs, summaries or feedback, even with
`--moderator-detail` or verbose logging. The invocation policy's existing
**verbose full-policy disclosure warning is unchanged**; it never prints data
rules. Host/runner administrator and step-setup visibility is outside filtering.

Direct invocation IDs/counts/arrays and possible/call-chain evidence are unchanged.
The Action adds only fixed data status/review/reject counts; disabled status is
`not-performed`. The report remains authoritative.

Host data scans require `--data-context NEW_PRIVATE_FILE`, also available as an
Action input. This mode-0600 artifact binds exact report bytes, engine, asserted
build, roots, precedence and private data-rule/original-baseline digests. Keep it
private. It is an operator-wrapper receipt, not an authentication mechanism.
An operator's explicit `--moderator-detail` also permits bounded invocation rule
IDs in the private report; receipt validation uses that explicit profile and still
validates the entire closed report. Default scans, the Action and moderation
handoff retain the default profile and reject detailed payloads. The Action has
no detail input. Do not submit a detailed report to the default moderation path
or publish it as feedback.

For moderation, insert this artifact as `data-context` in the trusted scan-context
object, alongside the ordinary `report-context`. Supply exact dependencies with
`--dependency data-rules=FILE` and, when used,
`--dependency baseline-pak=FILE`, plus ordinary mapping/catalog dependencies.
The existing moderation validator verifies all bytes and binds the complete
private context and exact report bytes into the human decision. Changes to any
private dependency/context invalidate approval. Missing private context cannot
downgrade a data report to legacy moderation. Feedback copies only fixed
data-analysis status/decision/counts, never the private artifact or properties.

The standalone evaluator does not create a host receipt; a trusted caller must
assemble and retain the same private binding. Do not approve standalone uploaded
facts as authenticated baseline evidence.

## Original proof and remaining validation

`Corpus.Generate data-policy NEW_DIRECTORY` writes original serialized assets,
private facts, a reviewed illustrative model and `proof.json` outside Git. The
source model is `Record(self.Destination)` with an explicit serialized property
pointer. Baseline/submission change only that property's text; stored bytecode
bytes/hash and invocation facts remain identical. A separate reviewed-property
change finding results. This is source/serialization evidence, **not execution,
engine cook, actual game behavior or a native-code certification**.

`tests/test_data_policy.py` exercises real local ingestion, Parser, public
evaluator CLI, report validation, host boundary mocks, Action projection and
private moderation invalidation. Its explicit opt-in Docker/actual-Action parity
case must be run only after parent authorization. Existing local inherited-default
and class-reference extraction proofs remain in `AssetDataTests`; absent effective
dependency closure remains unknown. No owned cook is modified.
