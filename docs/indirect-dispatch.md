# Possible indirect dispatch

Partial #8 implementation. **Do not close #8:** exact-game native/wrapper semantics,
external dependency closure and delegate binding-lifetime/control-flow analysis
remain unavailable. No game/mod executes during analysis.

## Evidence and policy

- `InvocationAnalysis.Dispatches` is an optional additive facts-v1 extension. Each
  record has its own `schema-version: 1`, actual instruction origin/opcode,
  dispatch kind, available function name, receiver category, possible candidates,
  provenance, source and fixed diagnostics. Absence preserves old wire bytes.
- Original invocation records, unresolved virtual targets, direct arguments and
  offsets are unchanged. Bindings/mutations are **not invocation occurrences**;
  callbacks get no invented invocation offset or invocation count.
- Local `FunctionExport`/import symbols are indexed by validated name. Serialized
  `ClassExport.SuperStruct` and `Interfaces` provide package-local inheritance,
  override and implementation candidates. `TargetResolver` supplies bounded,
  cycle-checked symbolic identities. Imports are evidence, not loaded dependencies.
  FName lookup is ASCII case-insensitive; candidate spellings remain unchanged for
  the existing case-sensitive policy identity contract.
- Self and object-constant receivers use available owner/ClassIndex facts.
  Interface/dynamic receivers without usable type metadata remain unknown.
  Missing/partial hierarchies broaden candidates rather than exclude uncertain
  implementations. Interfaces are not treated as closed implementation sets.
- Every set remains **possible, nonexhaustive, open-world**, even a singleton on
  a fully observed local hierarchy. Other packages, inherited/unknown receivers
  and unseen overrides can supply missing implementations. No archive-wide
  closed-world assumption or safe absence claim is made.
- Bind/instance delegate names retain candidate functions. Add/remove/clear,
  delegate assignment and multicast calls retain mutation/dispatch evidence.
  Removing/clearing a binding does not erase earlier evidence: no execution order,
  reachability, alias/lifetime or guaranteed eventual callback is asserted.
  A serialized instance delegate with NAME_None records unbound evidence, not a
  candidate function named `None`.
- The shared evaluator evaluates each candidate with **unavailable callback
  argument metadata**, never the binder/scheduler's arguments. A matching or
  argument-uncertain rule produces a possible effect, not a definite finding.
  Zero known candidates means no known possible match, **not absence of risk**.
  Every dispatch independently forces `unresolved-dispatch` coverage, including
  when a facts producer omits that gap.
- Reports add `possible-dispatches`, separate from both definite finding arrays.
  Each entry carries evidence plus `possibly-flagged`/`possibly-forbidden`; no
  private rule IDs, predicates or descriptions are exposed. Direct finding IDs,
  counts and ordering are unchanged. Default incomplete gating fails. Explicitly
  disabling that existing gate does not make possible forbids definite forbids.
- Action outputs retain their existing direct arrays/counts and size limits;
  consult the full report for indirect evidence. Strict report validation and
  moderation use the same schema. Exact report-byte hashing binds this evidence
  without copying it into a second moderation model.

## Same-archive context

The isolated parser now reads recognized packages twice. Pass one retains a small
`ArchiveDispatchContext` of actual class/function identities and serialized parent/
interface links; it does not retain `UAsset` objects. Pass two performs the existing
full extraction and augments candidates from other packages in the **same submitted
pak**. No new CLI/Action input, host mount, network request or private catalog is used.
The original pak SHA-256 binds all context bytes, including sidecars. Changing a
context package changes that hash and invalidates the existing moderation decision.
Hash/schema checks do not authenticate parser semantics or submitted base classes.

- Identity matching reuses bounded `TargetResolver` traversal with strict stored
  FNames. Full package/class identities and function names match ASCII-case-
  insensitively; original declaration spelling is retained. A same-name class in
  another package is not the same class. Imported class links must name an actual
  class import; missing/invalid indices are not guessed from `ToString` fallbacks.
  Candidate deduplication uses exact owner/function identities, matching policy,
  call-chain and wire consumers. A differently cased import cannot suppress an
  unambiguous archive declaration; both spellings retain their provenance and
  each consumes candidate budget. Ambiguous declarations remain unknown.
- Validated observed inheritance yields `inherited-function`, `override` or
  `interface-implementation` provenance. An unknown receiver/partial ancestry can
  also retain `archive-function` candidates without claiming a relationship.
  This additive provenance tag uses the existing versioned dispatch-v1 evidence;
  producer/evaluator/report schemas share the same closed enum.
- Duplicate class/function identities never select an authoritative cross-package
  definition. Missing classes/parents, cycles, malformed storage and global limits
  remain explicit unknowns. Existing local evidence and diagnostics are not removed.
  Every set remains possible, nonexhaustive and open-world; a submitted replacement
  cannot certify a trusted base or establish safe absence.
- No external dependency pak input or automatic game-filesystem lookup is provided.
  Unseen external parents/implementations still require context and remain unknown.
  This does not implement CDO/default inheritance, native constructors, engine load
  precedence, binding lifetime or #7 exact-build summaries. The separate local
  default-provenance API and all #10 limitations are unchanged.

Hard archive-index bounds (lowerable in the trusted library API): 4,096 classes,
4,096 function definitions, 10,000 hierarchy edges, 100,000 shared index/query
operations, 256 ancestry depth, 262,144 retained UTF-16 text units, 10,000 added
candidates and 10,000 augmented origins. Each package indexes at most 4,096 exports.
Local candidates and archive additions share the 10,000-candidate package budget
and per-dispatch target limit. Archive additions also consume the shared archive
budget. Existing parser-global origin/candidate/transport budgets still apply;
a limit never stops mandatory call extraction, inventory or later packages.
The parser sorts records by virtual path before both passes, independently of
archive enumeration. Bounds are post-parse; upstream decoding still requires the
existing process/cgroup isolation.

Trusted library callers can `Add(asset, input)` for each original package, `Seal()`
the context, then pass `archiveContext:` to `InvocationExtractor.Read`/`Inspect`.
The caller owns ordering, exact archive binding and isolation. This AST API does
not authenticate caller-supplied objects or establish a closed world.

`tests/PackageContextFixture.cs` serializes separate Base, ChildOverride, Interface,
Caller and unrelated same-name Collision packages. The fixed corpus oracle checks
actual origins/offsets, candidates, unchanged direct counts and possible call-chain
witnesses across ingestion/Parser/evaluator/wrapper/Action. Its fifth removal
mutation removes a cross-package override candidate without changing counts;
schema validation accepts the mutation but the semantic oracle rejects it.
No generated asset is committed and no owned cooked evidence is changed.
Boundary regressions also serialize 5,001 virtual calls after a direct sensitive
call, plus an unused case-variant import. They check composed candidate limits,
unchanged mandatory calls and inventory, transport-prefix fallback, exact policy
matches and possible cross-package chains through the actual parser and Docker.

## Narrow engine-source timer hypothesis

Only exact imported symbolic identities
`/Script/Engine.KismetSystemLibrary:K2_SetTimer` and `K2_SetTimerDelegate`
receive the `ue425plus-2d1aae-kismet-timer` hypothesis. No substring/name heuristic
recognizes game wrappers or other schedulers. Applicability to the submitted
game/build is **unverified**, always recorded as `native-build-unverified`.

Reviewed source scope: local authorized UE4.25Plus commit
`2d1aaeede6780b14c3ef97272e8a68c3429d8231`:

- `Engine/Source/Runtime/Engine/Private/KismetSystemLibrary.cpp:432–487`:
  `K2_SetTimer` binds its Object/FunctionName operands to an FTimerDynamicDelegate
  and passes it to `K2_SetTimerDelegate`; that function conditionally schedules
  a bound delegate through the world's timer manager. Parameter/world/time/bound
  checks mean a candidate does not prove scheduling or execution.
- Constant ANSI/Unicode function strings retain candidates; runtime strings retain
  `target-name-unavailable`. A directly serialized instance delegate supplies its
  callback name; opaque delegate expressions retain binding-flow uncertainty.
  `NAME_None` (ASCII-case-insensitive) is an unbound name in delegate and timer
  evidence, never a candidate for a local function named `None`.
  At the same pinned commit, `Core/Public/UObject/ScriptDelegates.h:38–45`
  rejects `NAME_None` in `IsBound_Internal`; `Core/Public/UObject/NameTypes.h:394,
  515–536` defines case-insensitive FName equality and the zero-number EName check.
- `Engine/Source/Runtime/CoreUObject/Private/UObject/ScriptCore.cpp:2898–2917,
  3189–3215` corroborates name-based virtual dispatch and bind/instance delegate
  operands. Pinned UAssetAPI Read/Write/Visit, not source pseudocode, determines
  supported operand layout and VM offsets.

This is not the #7 exact-game catalog, native-code certification or a summary
loader. Authorized exact-build source/header/reflection plus reviewed summaries
are still required to establish wrapper/native applicability. The separate
[explicit catalog/call-chain slice](call-chains.md) does not verify this timer
hypothesis or supply an exact-game catalog. Source code and
engine-derived binaries are not redistributed.

## Bounds and proof scope

Maximum 256 candidates/dispatch (lowerable with `ExtractionLimits.MaxTargets`),
10,000 total emitted candidates/package and 10,000 evidence origins. Indexing,
candidate expansion and hierarchy inspection share a 100,000-operation package
budget, lowerable with `MaxOccurrences`; hierarchy paths cap at 256 references.
Limits preserve original dispatch evidence with `target-expansion-limit`.
Exhausting the evidence-origin budget adds a global diagnostic without stopping
original direct-call traversal.
Transport enforces 10,000 aggregate candidates, byte/node/depth budgets, closed
string enums, unknown-key rejection, unique origins and unique candidate identities.
Parser aggregation caps origins and candidates globally, marking truncation with
`unresolved-dispatch` and `incomplete-extraction`. Candidate tails receive
`target-expansion-limit`. If indirect evidence exceeds transport node/byte limits,
the parser retains the largest fitting origin prefix; direct facts and inventory
must fit independently and are never trimmed to make room for indirect evidence.
Later packages still undergo direct extraction and inventory inspection.
Malformed UTF-16/U+FFFD, ANSI non-ASCII, embedded NUL and unsupported cast-layout
preflight rejections remain unchanged. Missing signatures remain query-specific.

Synthetic serialized fixtures exercise inheritance/overrides, interfaces,
missing parents, cycles, imported symbols, unknown receivers, target limits,
delegate bind/mutations, dynamic/constant timer names and nonrecognized wrappers.
The integrated corpus preserves all direct expectations and separately checks a
possible forbid across Read, evaluator CLI, parser, Docker wrapper and Action.
Only the synthetic Unresolved package's previously unused local declaration
changes from `Local` to `DynamicDispatch`; its call opcodes/VM offsets and direct
counts stay fixed. Its name/export bytes and enclosing archive hash deliberately
change; the other six serialized files retain their old hashes. No owned cooked
receipt or binary is modified, regenerated or committed.

Remaining #8 acceptance: exhaustive bounded sets where justified by authorized
dependency context; flow-sensitive delegate/callback linking; exact-build native
timer/wrapper coverage and broader owned cooked fixtures. Current incomplete
diagnostics deliberately remain visible until those proofs exist.

## Local proof (2026-10-25)

`/tmp/opencode/issue8-final-release-proof3/execution.json` completed the serial
`--release --components` path: 131 extraction, 115 Policy, 26 PolicyInput,
158 Scanner and 147 Python tests; 32 seeded properties; three removal mutations;
full parser/evaluator/wrapper/Action parity and existing owned-evidence verification.
Local image ID: `sha256:e5a2cef068522bff6b60d97f7718b251aaf8131777ea9503bed4677a9c4351a0`.
This dirty-worktree local test is not independent review, publication approval or
clean release-source provenance. Initial failed/timeout attempts remain separate
receipts; the component-suite deadline is now 1200 seconds, not a scanner limit.

FIX1: `/tmp/opencode/pr32-fix1-release-proof1/execution.json` completed the same
serial release path: 135 extraction, 115 Policy, 26 PolicyInput, 158 Scanner and
150 Python tests, with no skips; 32 seeded properties and three removal mutations.
Local image: `sha256:46ac4ecb0d72bc586911e939787d3edcb4182dd0ede0bdf18215baf0b5e774d8`.
New serialized-package checks cover global origin/node, candidate and byte
exhaustion while retaining all direct forbidden calls, later-package extraction
and inventory. Timer `None`/ASCII-case and valid-name checks use serialized
bytecode; Action and moderation reject reordered duplicate origins.
`/tmp/opencode/pr32-fix1-proof` retains old-image failures and initial test-expectation
failures separately. Original owned evidence is unchanged; tests used a copy.
This remains an uncommitted local proof, not independent review or release approval.
