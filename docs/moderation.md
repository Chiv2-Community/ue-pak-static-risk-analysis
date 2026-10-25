# Exact-byte moderation handoff

`scripts/moderation.py` is a local Linux/Python 3.11+ platform adapter, not an
approval service. It uses the shared strict default report validator, not a second
policy evaluator. It makes no network requests, writes no launcher/registry, and
does not change publication or access settings. Integration in other repositories
and signing/authentication remain separate work.

## Ownership and provenance

1. The trusted platform snapshots the original pak and **every** relevant mapping
   or dependency. Hash original bytes, not unpacked members, URLs or filenames.
   Retain the exact scan inputs in authenticated, access-controlled storage.
2. The scan operator records a private `scan-context` before accepting results:
   - `scanner-identity`: trusted immutable image ID (`sha256:<64 lowercase hex>`),
     or clean source/build provenance (`git:<40 lowercase hex>`). Prefer the image
     ID actually resolved by the host wrapper; an assembly version such as
     `1.0.0.0` alone is insufficient. Record build provenance outside this adapter;
     a Git revision does not identify dirty code or independently rebuilt binaries.
   - `game-build`: explicit platform-controlled build ID, never inferred from
     engine version or an assumed installed Chivalry build. No exact game-build
     fidelity is invented. The engine currently supports only `4.25`.
   - `report-context`: tool version, engine version, original pak SHA-256,
     producer version, dependency kind/SHA-256 pairs, and opaque policy revision.
     Dependency kinds are unique and stored sorted by kind. An explicit empty
     array means no dependencies. All fields must come from trusted orchestration,
     not be copied unquestioningly from an uploaded report.
3. The policy owner assigns a fresh opaque revision, e.g. a random UUID, when
   private policy changes. Pass it as `--policy-revision` to `evaluate` or the
   existing `scan` wrapper. The adapter requires it and compares it exactly.
   Never use a policy-content hash, fingerprint, or guessable content-derived ID:
   those enable public dictionary checks. The adapter never reads policy content
   and cannot prove that an externally supplied ID was honestly assigned.
4. The platform accepts the report over authenticated transport/storage, checks
   provenance against its own scan record, then runs `handoff`. Nonfailed report
   context must match the complete trusted report context. Failed reports may lack
   identities; they identify an attempted scan, never accepted analysis/approval.

Hash equality is **not report authenticity**. A compromised parser can fabricate
calls, coverage and hashes. This module cannot authenticate an arbitrary report
or reviewer. The platform must retain its own trusted scan provenance and protect
reports, context, review records and their association. Signed transport/storage
and reviewer authentication/authorization are platform responsibilities.

## Routes and human decisions

| Evidence | Route |
| --- | --- |
| Any forbidden invocation | `policy-violation` |
| Any flagged invocation | `needs-review` |
| Incomplete analysis/evaluation | `analysis-incomplete` |
| Completed with no findings, within reported coverage | `qualified-completed` |
| Operational/configuration/transport failure | `operational-failed` |

The first three routes are independent and can coexist. Incomplete analysis does
not erase flags or forbids. Failed reports do not mean zero calls: their zero
counts mean no accepted evaluation. Missing, malformed, oversized or inconsistent
input fails closed (exit 3), without creating a handoff or clean fallback. The
caller must route this failure to operations; do not reuse an older output.

No route autoapproves, including `qualified-completed`. That code is not malware
certification, native-code safety, dependency closure or runtime reachability.
Optional AV/YARA results are supplemental; never replace bytecode analysis.

An authorized reviewer records an explicit actor, UTC time, decision (`approve`,
`reject`, `request-review`) and nonempty rationale against the **whole handoff**.
Approval of findings/incomplete coverage is an explicit human risk exception;
platform authorization/workflow may prohibit it. Operational failure cannot be
approved: fix and rescan first. Rejection/request-review never implies approval.
The platform owns reassessment scheduling, reviewer authorization and an append-only
audit trail. It must select the **current authoritative** decision, enforce
revocations and prevent replay of superseded approvals; this stateless CLI has no
store, expiry, concurrency control or revocation service.

## Invalidation and consumption

The consumer verifies the current approved record, a newly obtained trusted
context, and **the exact pak/dependency bytes about to be delivered/installed**.
`verify` compares all context fields and recomputes byte hashes. Missing, extra,
duplicate-kind or changed dependencies fail. Dependency argument order does not
matter; stored context is canonical. A changed URL with identical bytes/context
does not invalidate identity. Replacing bytes at the same URL does.

Any changed pak, dependency, scanner identity/tool/producer version, engine,
game build or policy revision invalidates the approval: obtain a new scan/context
and explicit decision. Never substitute context copied from the old approval for
the consumer's current trusted context. Approval records are private, not publicly
queryable policy fingerprints.

Verification is a point-in-time read, not installation or a retained file handle.
The platform/consumer must freeze the verified snapshots and atomically deliver
those same bytes; prevent modification between verification and use. Rehash after
download even if an earlier server-side check passed. No launcher behavior is
silently changed by this implementation.

## Profiles and bounded local I/O

[moderation-v1.schema.json](../schemas/moderation-v1.schema.json) defines private
context, handoff and human-review records, plus public `submitter-feedback`.
The module adds cross-field/identity validation beyond the structural schema.
API: `handoff(report_bytes, context, pak_path, dependencies)`,
`review(handoff, actor, decision, rationale, now=None)`,
`verify(review, current_context, pak_path, dependencies) -> bool`, `feedback(handoff)`.
`dependencies` is a list of `(kind, path)` pairs. Module inputs are validated;
`now` is injectable for deterministic tests.

- The handoff accepts only the strict **default** report profile: no `rule-ids`.
  It does not carry invocation locations/targets or inspection metadata forward.
- Store detailed `--moderator-detail` reports separately with restricted moderator
  access. They cannot be used as handoff inputs. Never publish them to submitters.
- Publish only `feedback` output: fixed status/route codes, counts and coverage.
  It omits policy revision, context, scanner/build IDs, rule IDs, descriptions,
  predicates, raw policy, fingerprints, findings and human rationale/identity.
  Access controls and release of even these counts remain platform decisions.
- `log-level=verbose` intentionally discloses policy to approved operators/log
  audiences. Log access does not relax report or feedback profiles.

Inputs open final-component-nofollow/nonblocking and must be stable regular files.
Limits: JSON 16 MiB/depth 32/250,000 value nodes, pak 256 MiB, each dependency
16 MiB, at most 256 dependencies; reads/hash chunks at most 64 KiB. Unknown or
duplicate fields, wrong types, aliases, malformed UTF-8/surrogates, noncanonical
context and inconsistent route/count/coverage fields fail closed. Use trusted
local parent directories: parent symlinks/renames, hostile same-UID writers,
remote/FUSE latency, kernel I/O deadlines and resource containment are not solved
here. Apply external worker time/memory limits.

Outputs use the shared wrapper's mode-0600, flushed, atomic exclusive-create
lifecycle. Existing paths, input aliases, symlinks, FIFOs and directories are never
replaced. No stdout contains private input. Exit 0: artifact created, or approved
bytes/context verified; exit 1: verified review is not an approval; exit 3: invalid
input, mismatch or I/O failure. CLI syntax errors also return 3. Missing reports
are not synthesized. Output destinations must be new for every invocation.

## Owned example and integration fixture

The [example](../examples/moderation/) contains synthetic text, not game data,
real scanner output or a real approval. Its scanner/game IDs are placeholders,
not proof of a particular installed build. `routes.json` drives independent and
mixed-route tests. No engine, private policy or Docker is required.

From the checkout, with a new external output directory:

```sh
mkdir /tmp/opencode/moderation-demo
python3 scripts/moderation.py handoff \
  --report examples/moderation/report.json \
  --context examples/moderation/context.json \
  --pak examples/moderation/submission.txt \
  --dependency mapping=examples/moderation/mapping.txt \
  --output /tmp/opencode/moderation-demo/handoff.json
python3 scripts/moderation.py review \
  --handoff /tmp/opencode/moderation-demo/handoff.json \
  --actor example-moderator --decision approve \
  --rationale 'Owned integration example only; not a safety claim.' \
  --output /tmp/opencode/moderation-demo/review.json
python3 scripts/moderation.py feedback \
  --handoff /tmp/opencode/moderation-demo/handoff.json \
  --output /tmp/opencode/moderation-demo/feedback.json
python3 scripts/moderation.py verify \
  --approval /tmp/opencode/moderation-demo/review.json \
  --context examples/moderation/context.json \
  --pak examples/moderation/submission.txt \
  --dependency mapping=examples/moderation/mapping.txt
python3 -m unittest discover -s tests -p test_moderation.py -v
```

For production, replace the synthetic inputs with retained snapshots and trusted
context, capture scanner exit/report together, and follow the platform approval
and consumer verification procedures above. This example grants nothing outside
its local files.
