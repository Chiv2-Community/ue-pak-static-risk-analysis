# Private capability rules v1

Optional closed JSON rules select reviewed catalog capabilities and bounded
upstream callers. Invocation YAML v1 remains unchanged. This is a separate
versioned extension, like data rules, not a second generic expression engine:
one exact capability plus an optional exact upstream source identity/depth.
It reuses `CallChains`, typed `MatchResult`, and `GateOptions` without reloading
packages or adding a Policy-to-Scanner dependency.

See [schema](../schemas/capability-rules-v1.schema.json) and
[illustrative rules](../examples/capability-rules-v1.json). The fixture-only
`Touch`/`Record` assertions are not game API classifications or native analysis.
Exact-game catalog provenance and dependency closure remain open under #7/#9.

## Grammar and matching

- Required document: `schema-version: 1`, `disclosure: private`, opaque `revision`,
  nonempty `rules`. Each rule requires `id`, `capability`, `effect`, `caller`.
- IDs/revision/capability: 1–128 ASCII letters, digits, dots, underscores, hyphens;
  rule IDs unique and case-sensitive. Effects: `flag` or `forbid`, never allow.
- `caller` is null or `{owner, function, max-depth}`. Owner/function use the closed
  invocation identity grammar. Depth is an integer 1–16, measured backwards from
  the endpoint, excluding the endpoint instruction. Match the recorded upstream
  **source** function, not its call target or a split containing-function string.
- Exact ordinal catalog capability and caller comparisons only. No regex, includes,
  code, argument conditions, negation, generic Boolean AST or name heuristics.
- Bounds: strict UTF-8, 256 KiB, 8,192 tokens, JSON depth 16, 256 rules. Unknown/
  duplicate keys, wrong types, tags, unsupported versions and invalid identities
  fail closed before verbose invocation-policy disclosure. Existing bounded
  no-follow regular-file and closed JSON readers are reused. Parent-directory
  trust/latency limitations are unchanged.
- `CapabilityPolicy.Write` canonically orders rules by ID. The private receipt
  binds **exact input bytes**, not this canonical rendering; whitespace invalidates
  the original digest. The host snapshots once and forwards rules only to trusted
  validation/evaluation containers. The parser receives no rules, catalog or secrets.

An exact catalog endpoint with a supported direct witness is a symbolic `Match`,
not proof of execution or native implementation. A possible edge gives `Unknown`
and possible effects, never a definitive forbidden invocation. Capability mismatch
or a verified bounded caller mismatch is `NoMatch` for that witness. Missing
catalogs, native summaries/identities, extraction gaps and truncated graphs retain
global possible effects for every configured effect; they cannot establish an
aggregate negative. A symbol without a reviewed catalog is never classified by
name. Existing graph/work/evidence limits apply unchanged; matching visits at most
256 witnesses × 256 rules × 16 caller steps. No search outside retained evidence.

All matching effects are unioned; flag never cancels forbid. Separate
`capability-analysis` v1 findings reference the existing call-chain witness index,
whose endpoint and upstream origins remain distinct. It adds no VM offsets,
invocation IDs or direct counts. Each retained witness has four union booleans:
flagged/forbidden/possibly-flagged/possibly-forbidden. Unlocated gaps have separate
aggregate possible booleans, not invented witness locations. Counts are witness
counts, not unique endpoints, rules or executions.

Known forbid gives `reject`; other known/possible effects give `needs-review`;
only complete absence of effects gives `no-match`. **All enabled capability
unknowns and findings fail the shared gate**, regardless of invocation gate
opt-outs. Existing mandatory catalog review/content/data gates remain independent:
a nonmatching private rule never permits a catalog-positive scan to pass. Without
rules the field is absent and existing report bytes/semantics are unchanged.

The shared report loader and report schema reject capability completeness that
contradicts missing/incomplete call chains or a null catalog digest. These states
require `capability-evidence-incomplete`, `complete: false` and at least one
aggregate possible effect. They do not reveal which private effects are enabled.
Possible-witness-only uncertainty can retain complete graph/catalog evidence and
use per-finding effects without aggregate effects. Legacy reports omit the extension.

## Inputs, privacy and moderation

Evaluator: `--capability-rules FILE --capability-policy-revision TOKEN`.
Revision must equal the private document revision. Host/Action additionally require
a new private `--capability-context FILE`/`capability-context` destination. All
outputs must be distinct and absent, including resolved parent-directory aliases,
before validation, disclosure or parsing. No existing file/final symlink is replaced.
Separate writes are not transactional; operator-controlled parents remain required.

The mode-0600 private context binds exact report bytes, private rule revision and
digest, and the public catalog digest (or null). No private IDs, conditions, revision,
rationales or private policy hashes enter ordinary reports/logs, Action outputs/
summaries or moderator feedback, including verbose and moderator detail. The
existing warning that **verbose prints the complete invocation policy** remains;
it does not print capability/data policies. Runner setup/administrator access is
outside scanner filtering. Public catalog IDs/digests retain their explicit
nonsecret contract; never use it for private policies.

Insert the receipt as `capability-context` in trusted scan context. Supply
`--dependency capability-rules=FILE` and the existing catalog/mapping dependencies
to moderation. Exact report/rule/catalog/context changes invalidate approval;
missing private context cannot downgrade an enabled report to legacy moderation.
Standalone evaluation creates no host receipt: trusted callers must assemble and
retain this same binding, as for standalone data evaluation. Feedback retains
only fixed decision/completeness; no graph, rule IDs, conditions or private digest.
Action outputs contain fixed status/witness counts, including before gate failure;
unlocated unknowns are not counted as located witnesses. Inspect completeness and
the full report, never infer no capability from a zero compact count.

ArgonSDK UE4.25 minimum/UE4.25Plus preference does not block this generic symbolic
extension on exact patched-engine recovery. It supplies no game-wrapper behavior;
production catalogs still require authorized reviewed exact-build evidence.
