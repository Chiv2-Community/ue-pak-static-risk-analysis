# Bounded call-chain evidence

Partial #9 implementation, **not closure of #7–9**. Exact-game native summaries,
authorized build verification, cross-package dependency/hierarchy completeness
and flow-sensitive callbacks remain unproved. No game, native code or mod executes.

Same-function [delegate storage links](indirect-dispatch.md#same-function-delegate-storage-links)
now add possible multicast edges from retained binding evidence. These remain
possible along the entire witness; lexical may-history is not path/lifetime proof.

Same-submission [archive hierarchy linking](indirect-dispatch.md#same-archive-context)
now augments possible edges. This does not establish external dependency closure
or promote a possible upstream witness to a definite capability.

## Inputs and trust

`--capability-summaries FILE` is optional on `evaluate`, `validate` and host `scan`;
the Action exposes `capability-summaries`. Default: none. Policy input remains
mandatory. The separate [closed catalog v1](../schemas/capability-summaries-v1.schema.json)
requires:

- `schema-version: 1`, `disclosure: nonsecret`, opaque `revision`.
- Up to 256 unique exact, case-sensitive owner/function identities, each with one
  opaque `capability` ID, `provenance`, `build-scope` and `reviewed-limitations`.
- At most 256 KiB strict UTF-8, 8,192 JSON tokens, depth 16; IDs 1–128 ASCII
  letters/digits/dots/underscores/hyphens; provenance/build/limits 1–1,024 UTF-16
  code units, valid Unicode, nonblank, without controls. Owner/function use existing policy
  identity validation. Unknown/duplicate keys, null collections, integer/string
  coercion, duplicate targets and unsupported versions fail closed.

This is a trusted operator assertion, **not authenticated native analysis**.
Never accept the catalog, its path or its revision from a submission. The loader
reads a bounded regular Linux file through the existing nonblocking, final-symlink
rejecting file reader. Validation precedes verbose policy disclosure. Parent-path
symlinks, hostile filesystem latency and compromised administrators are not isolated.
There are no includes, secondary file references, downloads or environment source.

The host snapshots exact catalog bytes once and mounts that copy only in trusted
validation/evaluation containers. The parser receives no catalog, policy or secrets.
Report context adds dependency kind `capability-summaries` with the exact byte
SHA-256 and `capability-catalog-revision`. Formatting changes invalidate the digest.
These bind context, not authenticity or real-build applicability.

Use only a deliberately nonsecret catalog: ordinary full reports expose matched
capability IDs, revision and digest, along with submitted symbols/locations.
They do **not** copy provenance, build-scope prose, reviewed limitations, catalog
contents/paths or private policy IDs/predicates/rationale. Moderator detail retains
its existing separate policy-ID disclosure. A confidential capability catalog
profile is not supported; do not relabel private production material `nonsecret`.

## Graph and witnesses

- Optional facts `analysis.call-graph` has its own `schema-version: 1`, completeness
  flag and function definitions. Each binds the exact asset/containing-function
  location key to a resolved owner/function and serialized native flag. The parser
  uses actual `FunctionExport` identities from `TargetResolver`, including outer
  ownership; it does not split function-name strings or guess missing owners.
- Edges come from existing actual invocation records and supported possible
  dispatch candidates, not arbitrary string matching. Exact local/archive symbols
  link only when unambiguous. Colliding owner/function definitions are disclosed
  and not linked. External symbols need explicit summaries; they are not silently
  classified as natives from names. Uncalled native definitions without summaries
  also disclose `native-summary-unavailable`.
- Endpoints are actual sensitive invocations already matched by the shared policy
  evaluator, or exact explicit catalog matches. No second policy evaluator or JSON
  graph round-trip is used. Candidate-only policy effects remain in existing
  `possible-dispatches`; they are not converted into actual invocation endpoints.
- `call-chains` is an optional, independently versioned report-v1 extension.
  `endpoint.origin` is the actual sensitive instruction or explicitly possible
  dispatch/binding origin. `callers` contains separate upstream instruction
  witnesses, ordered outermost caller first. A possible endpoint is never labelled
  an actual policy flag/forbid. Bindings/timers remain hypotheses, not executed calls.
- `direct` means supported symbolic edges, **not proof of execution**. Any possible
  edge makes the entire upstream witness `possible`, even with a reviewed endpoint.
  All indirect sets remain open-world/nonexhaustive and callbacks retain unavailable
  arguments. Endpoint argument matches use only original endpoint arguments, never
  caller/binder arguments. No reachability or entry-point pruning is performed.
- Iterative reverse traversal uses visited `(function, certainty)` states. It emits
  one deterministic shortest witness per endpoint/upstream function/certainty,
  not every path or repeated caller instruction. Recursion/cycles terminate; direct
  invocation deduplication, IDs, counts and finding arrays remain unchanged.

Legacy facts without graph context and without an explicit catalog retain their
old report shape: absent `call-chains` means **analysis not performed**, not absence
of capabilities. Supplying a catalog with legacy facts explicitly reports
`graph-context-unavailable`/`source-identity-unavailable`; it never invents owners.
Current extraction/parser producers emit graph context, including empty/incomplete
context when definitions are unavailable.

## Bounds and gates

| Bound | Default / hard maximum |
| --- | --- |
| Function definitions | 4,096 and 65,536 aggregate UTF-16 text units across packages |
| Constructed edges | 10,000 |
| Edge construction/traversal visits | 100,000, plus bounded input indexing/sorting |
| Upstream witness depth | 16 edges, excluding the endpoint instruction |
| Total witnesses | 256 |
| Call-chain evidence | 512 KiB conservative escaped-JSON budget, including fixed metadata reserve |
| Facts transport | Existing 8 MiB / 200,000 tokens / depth 16 |

Library `CallChainLimits` can lower edge/work/depth/witness/evidence bounds; there
are no CLI overrides. Function aggregation is globally bounded, not just per
package. At the overall producer transport limit, optional graph definitions can
be dropped to an explicit incomplete empty context; original invocations remain.
Already retained endpoint witnesses are prioritized before upstream expansion.
Truncation keeps retained evidence and direct findings, adds fixed diagnostics,
sets call-chain completeness false and preserves default incomplete gating.
Missing summaries/identities, ambiguous targets and open-world indirect dispatch
also keep completeness false. Absence of a summary is not a clean result.

Any matched explicit capability sets `needs-review` and **always exits 1**,
independently of existing gate opt-outs. It does not synthesize policy flags or
inflate direct counts. Content review/reject gates remain mandatory. Disabling
`fail-on-incomplete` does not establish completeness or bypass capability review.
Policy AST v1 is unchanged: no capability/call-chain predicate is implemented.

Action direct arrays/counts and output budgets are unchanged; use the full report
for call chains. Moderation retains only `call-chain-analysis` completeness/review
booleans plus its existing exact report-byte hash, not a second graph model.
Pass the exact catalog as `--dependency capability-summaries=FILE`; trusted context
must include its digest/revision. Changed evidence/catalog bytes invalidate review.
Submitter feedback contains no capability IDs, catalog content/digest or witnesses.

## Original fixture and update procedure

[The illustrative catalog](../examples/capability-summaries-v1.json) classifies only
the original `Corpus.Generate` `chains` fixture: `Root → Helper → Wrapper → Touch`,
a recursion cycle, repeated paths and a possible virtual caller. The innocuous
`Touch` symbol has no supplied native implementation. Its capability is an explicit
test-model assertion, **not engine/game behavior or #7 catalog proof**. Removing
the catalog removes that capability evidence without changing invocation counts.
No owned cooked receipt/binary is modified or redistributed.

For production entries: obtain authorized exact-build implementation/reflection
evidence; verify exact identities/build scope; have a reviewer record provenance
and limitations; assign a new nonsecret catalog revision; rescan under the new
digest and obtain a fresh decision. Never infer wrappers from names or reuse a
fixture classification as game evidence. Preserve old evidence on updates.

Local non-Docker regression (new external output directory):

```sh
python3 scripts/regression_corpus.py --output /tmp/opencode/new-call-chain-proof
```

The same runner authors serial parser/wrapper/Action parity when explicitly given
`--docker-image`; release validation additionally requires `--components --release`
and authorized `--owned-evidence`. Do not run Docker concurrently with global
container-leak assertions. Local tests are not independent review or release approval.
