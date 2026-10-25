# Serialized asset-data evidence: partial #10

`PakRisk.Extraction.AssetDataExtractor` is an experimental library API, not a
shipped data-risk gate. **#10 remains open.** It collects bounded typed serialized
values without classifying property names, inventing sensitive APIs, or changing
Policy AST v1. Exact-game property-purpose metadata (#7) is unavailable.

## API and evidence

```csharp
var evidence = AssetDataExtractor.Read(input, mappings);
// Already parsed, trusted in-process objects:
var evidence2 = AssetDataExtractor.Inspect(asset, input);
var source = AssetDataExtractor.FindLocalDefaultOverride(
    asset, input, classExportIndex, "ReviewedPropertyName");
```

The caller supplies `PackageInput` identities and an explicit logical namespace,
as with [invocation extraction](extraction.md). Storage paths do not enter these
records. `Read` reuses the pinned read-only `PackageReader`; it loads no policy,
baseline, game installation, network dependency or private catalog.

- Evidence version 1 retains actual one-based export indices, resolved object and
  `ClassIndex` identities, the **recorded** `RF_ClassDefaultObject` bit, and a
  structural path. Static-array slots and dynamic-array ordinals are distinct;
  property names containing punctuation cannot collide with path delimiters.
- Supported exact reader models: `StrPropertyData`, `BoolPropertyData`,
  `IntPropertyData`, `Int64PropertyData`, `NamePropertyData`, `EnumPropertyData`,
  `ObjectPropertyData`, `DelegatePropertyData`, ordinary `ArrayPropertyData` and
  `StructPropertyData`. Integer widths, enum types and FName values remain typed.
  `NAME_None` is a name, not an inferred null reference.
- Object index zero is explicit null. Missing indices, cyclic/missing owners,
  unavailable enum mappings, reader enum-index fallback names and unsupported
  reader models are unknown. No unknown/raw property is stringified into evidence.
  Delegate records retain receiver and function name, **not** an invocation or a
  resolved runtime binding. Multicast, maps, sets, soft references, byte/enum
  reader heuristics and custom-serialized values remain unsupported.
- The pinned reader has no concrete `ClassPropertyData` model. Raw tagged
  `ClassProperty` bytes stay unknown. A supported object reference targeting a
  local `ClassExport` is labeled `local-class`; that does not prove its declared
  property type. Imports remain symbols, not authenticated external classes.
- FString decoding can replace malformed bytes. U+FFFD, malformed surrogates and
  control-bearing text stay unknown, even when U+FFFD was the original character.
  Valid Unicode, including surrogate pairs, is retained. The API does not recover
  original malformed bytes or claim strict upstream decoding.
- `PropertyData.RawValue` lazily supplies defaults. A fixed pinned backing-field
  read avoids turning unset storage into false/zero/null. Explicit unversioned
  zero-mask values are supported only for the listed integer/bool/object types
  with mappings present. `Inspect` remains a trusted AST API, not authentication.
- `Complete` describes supported serialized-property enumeration only. It does
  not establish property-purpose metadata, dependency closure, effective defaults,
  a baseline, behavior equivalence, or safety. Unknown custom export payloads,
  missing mappings/owners, unsupported properties and bounds retain fixed gaps.

`FindLocalDefaultOverride` freshly extracts from the same asset; it accepts no
caller-supplied baseline or evidence snapshot. Each visited local class must have
an actual `ClassDefaultObject` link to a flagged CDO whose `ClassIndex` points
back to that class. Parent traversal uses `SuperStruct`; conflicting header
`SuperIndex` metadata fails closed. It retains the requested class, bounded class
chain, origin class and origin default-export index. Ordinary exports are not
assumed to be defaults.

Only top-level scalar/reference overrides are located. A missing child override
may locate a serialized override on a verified **local** parent chain, with
`Inherited: true`; this is structural provenance, **not an engine-effective value**.
External/native parents, missing CDOs, cycles, duplicate properties, compound
merging and incomplete extraction return unknown. Reflection/property declarations,
native constructors, instance archetypes and cross-package inheritance are not
verified. No absent value is asserted to be a language/native zero default.

## Bounds and disclosure

Limits may only be lowered: 4096 exports, 4096 expanded property occurrences,
16 property depth, 4096 characters/string, and 65,536 characters for both read
property text and retained property text. The output budget includes repeated
owner/class identities, value/reason text and complete property paths; caller
identity components are separately bounded to 1024 characters. Active-path cycles fail; shared DAGs
consume an occurrence per expansion. Container count records are not proof that
all children fit. All limits describe **post-parse** traversal; upstream reads
still require external resource/isolation controls.

This API is deliberately **not connected** to `Parser`, `FactsCodec`, the shared
report schema, scanner CLI, Action outputs or moderation feedback. Raw submitted
properties must not be copied into ordinary reports, logs, workflow commands,
summaries or public feedback. They are untrusted, potentially private data, even
when valid Unicode. No data-policy or baseline CLI/Action inputs exist in this
slice. Existing direct/possible invocation arrays, counts, call-chain evidence,
catalog digest disclosure, gates and exact report-byte binding are unchanged.
Standalone extraction cannot evict later packages' mandatory facts/inventory or
consume the global FactsCodec 8 MiB/200,000-token budget.

## Remaining delivery gates

- Add a separately versioned, closed data extension, reviewed exact owner/class/
  property identities, purpose, build scope and source provenance. Do not extend
  invocation YAML implicitly or infer sensitivity from names/URLs.
- Accept baselines only through authorized operator input and isolated read-only
  parsing. Bind original hashes, build, engine, explicit namespace mapping,
  dependency/mapping and tool context. A user-supplied fact file is not a verified
  clean installation. Rights to inspect or redistribute baselines are external;
  no automatic discovery, download or game-content publication is authorized.
- [Protected paths](content-policy.md) already recognize normalized, ASCII
  case-insensitive component identities. Those matches remain **replacement
  candidates**, not proven vanilla overrides. No mount/load precedence is guessed.
- Retain optional evidence under package **and global** aggregation bounds without
  displacing mandatory calls/inventory, including at transport exhaustion.
- Add separate non-invocation findings and mandatory review/reject gates using the
  existing trusted evaluation path. Bind catalog/baseline dependencies and opaque
  revisions in shared report validation and moderation; invalidate changed context.
  Private conditions/provenance/paths must not leak through ordinary reports.
- Prove a reviewed original property-purpose model drives a finding when trusted
  Blueprint code is unchanged. Current tests prove changed typed data and stable
  real invocation facts, not that an engine consumes that property or that an
  exact-game behavior catalog exists. Local inherited provenance and class-target
  substitutions are exercised; cross-package effective defaults remain open.

## Proofs

`tests/CompatibilityProbe.Tests/AssetDataTests.cs` creates original serialized
fixtures through the pinned writer and tests the public `Read` API, including
malformed UTF-8/UTF-16 values. Temporary directories use the platform default.
No game/editor runtime, engine cook or proprietary binary is needed.

`tests/OwnedFixtures.Verify` additionally checks the retained owned Linux cook's
tagged parent/child defaults and tagged/mapped native data against its original
10101/20202/424242 and original string values. It only reads the supplied evidence
directory. Missing mappings remain incomplete. These checks establish neither
exact-game Windows fidelity nor baseline safety.

Local serial validation on 2026-10-25: 166 extraction tests (28 new), 115 Policy,
26 PolicyInput, 193 Scanner and 159 Python tests passed without skips, plus the
Docker/Action corpus, three removal mutations and owned-cook checks.
Receipt: `/tmp/opencode/issue10-data-evidence-release-proof1/execution.json`.
This is implementation validation, not independent review or release approval.
