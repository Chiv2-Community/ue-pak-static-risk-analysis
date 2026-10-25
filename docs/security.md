# Scope and trust boundaries

No malware-free guarantee, complete source reconstruction, native-code safety,
or runtime-behavior certification is provided. Empty findings and successful
parsing do not establish safety. A compromised parser can forge semantics even
when input hashes and schemas validate.

## Command-specific boundaries

| Interface | Boundary | Not provided |
| --- | --- | --- |
| `scripts/scan.py scan`, Action | Trusted host orchestration; separate policy-free parser and trusted evaluator containers; bounded snapshots/transport; network denied; cgroups/rlimits/tmpfs; exclusive reports | VM isolation, trusted hostile host/daemon, parser semantic authenticity, guaranteed cleanup after host/daemon failure |
| `Scanner.dll evaluate` | Bounded typed facts/policy validation and trusted evaluation | Asset-parser sandbox or authenticated facts; caller must enforce provenance and process budgets |
| `python3 -m pak_ingest` | Supervised worker and quotas | UID/filesystem/network isolation; not a standalone hostile-code sandbox |
| Extraction/PackageReader APIs, compatibility probe | Trusted-input experimentation; extraction preflight after upstream reads | Upstream parser memory/recursion containment or production submission boundary |
| Moderation/runtime canary | Exact-byte/context checks and trusted local observer components | Approval service, reviewer authentication, runtime VM authorization or game execution |

Use an ephemeral VM where shared-kernel escape or cross-tenant exposure is
unacceptable. Docker daemon/socket and host administrators are trusted. Never
mount the socket, credentials, policy, source checkout or writable host outputs
into the parser. Keep trusted workflow/source/policy out of submitter control.

## Compatibility and unsupported analysis

The hardened scanner accepts **ordinary sequential V9** legacy pak indices,
222-byte footers, ASCII paths, no encryption, and uncompressed entry index 0 or
explicit Zlib blocks. Frozen indices, other versions, encryption/keys, Oodle and
other codecs, IoStore `.utoc`/`.ucas`, and unknown/delete flags are unsupported.
The historical repak experiment has separate compatibility observations; do not
infer that it and the hardened reader accept identical containers.

Only the explicit **4.25** parsing hint is supported. One operator-supplied virtual
root mapping and one optional authorized `.usmap` are accepted. There is no game
root default, automatic dependency/mapping download, key lookup or network
resolution. Unknown roots, missing exports/mappings, malformed/unsupported
bytecode and unresolved dispatch retain diagnostics/coverage, not invented calls.
Bulk payloads are not decoded or certified. Signatures identify possible native,
script/config or unknown content, not harmlessness. ClassIndex identities are
recorded symbols, not an authenticated hierarchy or native capability catalog.

Partial [open-world indirect evidence](indirect-dispatch.md) ships for #8, not
exhaustive resolution or callback execution proof. Source-scoped engine timer
hypotheses explicitly retain unverified game-build applicability.
Not shipped: complete indirect resolution (#8), transitive dependency or
call-chain behavior (#9), data/default/configuration-driven effects (#10), native
implementation analysis/nativized behavior, reachability, exploit detection,
full serialization coverage, runtime computed arguments, or complete reconstruction.
Imported signatures can remain unavailable: exact invocation-only rules may
complete while argument-dependent rules stay Unknown, including under negation.
See [exact matching/three-valued rules](policies.md) and
[opcode/string limitations](extraction.md).

Linux owned UE4.25Plus cooks establish specific parser coverage, **not** exact
Windows/game producer fidelity or redistribution rights (#2). Exact game build
source/header/reflection and reviewed native summaries have not been supplied
(#7). Historical target-game observations do not close those gates.

## Capability ownership and review invalidation

The policy owner controls YAML, content settings and opaque revision assignment.
The scanner maintainer controls pinned parser/normalizer/build dependencies. The
platform owns explicit game-build context, authenticated evidence storage,
reviewer authorization and current approval/revocation state (#16).

For future #7 catalog updates, require authorized exact-build source, headers and
reflection plus reviewed native implementation summaries. Record build/source
identities, symbol owners, parameter types, inheritance evidence, reviewer and
uncertainty for each entry. Verify against authorized bytes/reflection; do not
invent game APIs from names, parser classes, pseudocode or this starter policy.
No exact-game catalog loader, capability predicate or authoritative native summary
evaluator is shipped; the narrow timer hypothesis remains build-unverified.

Treat a catalog, native summary, parser, dependency, game build, invocation policy
or content-setting change as new analysis context. Assign a new opaque policy
revision where policy interpretation/settings change; never publish a
content-derived policy fingerprint. Preserve old evidence, review all changed
expectations, rerun regression, rescan and obtain a new explicit decision. Any
changed report/pak/dependency/scanner/producer/engine/game/policy identity
invalidates approval under [the #16 contract](moderation.md#invalidation-and-consumption).
No mutable alias may silently preserve an old review. Escalate unresolved native
or runtime questions through [the manual runbook](runtime-escalation.md).
