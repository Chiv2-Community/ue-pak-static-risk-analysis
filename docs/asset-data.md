# Serialized asset-data evidence: partial #10

`PakRisk.Extraction.AssetDataExtractor` collects bounded typed serialized
values without classifying property names, inventing sensitive APIs, or changing
Policy AST v1. **#10 remains open.** Exact-game property-purpose metadata (#7) is unavailable.
The optional [data-policy path](data-policy.md) now transports these values privately
to trusted evaluation and emits separate gated, sanitized data findings.

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
  missing mappings/owners, unsupported properties, duplicate flagged CDOs for one
  `ClassIndex` and bounds retain fixed gaps. Like invocation extraction, either
  `PKG_Cooked` or the reader's editor-only-filtered marker is required; neither
  marker alone proves engine compatibility or safety.

`FindLocalDefaultOverride` freshly extracts from the same asset; it accepts no
caller-supplied baseline or evidence snapshot. Each visited local class must have
an actual `ClassDefaultObject` link to a flagged CDO whose `ClassIndex` points
back to that class, with no second flagged CDO claiming the same `ClassIndex`.
Parent traversal uses `SuperStruct`; conflicting header `SuperIndex` metadata
fails closed. The entire claimed local ancestry is validated before returning
the nearest candidate, including ancestors beyond a child or parent override.
Missing local metadata/CDOs, contradictions and cycles invalidate that candidate.
The retained class chain covers all validated local ancestors, not just those up
to the origin. Ordinary exports are not assumed to be defaults.

Only top-level scalar/reference overrides are located. A missing child override
may locate a serialized override on a verified **local** parent chain, with
`Inherited: true`; this is structural provenance, **not an engine-effective value**.
An external/native boundary ends local validation without resolving constructors
or external defaults; a previously located local override can still be returned.
Without a local override, such a boundary returns unknown. Missing CDOs, cycles,
duplicate properties/CDOs, compound merging and incomplete extraction also return
unknown. Reflection/property declarations,
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

`Parser` now includes an additive bounded `asset-data` block in private facts;
the shared typed models live in Policy without changing invocation AST v1. Raw submitted
properties must not be copied into ordinary reports, logs, workflow commands,
summaries or public feedback. They are untrusted, potentially private data, even
when valid Unicode. Optional private data-policy and baseline CLI/Action inputs
are documented separately. Existing direct/possible invocation arrays, counts, call-chain evidence,
catalog digest disclosure, gates and exact report-byte binding are unchanged.
Extraction is aggregated under 4096 property/262,144 text-character global caps.
FactsCodec retains a bounded useful prefix, then a fixed incomplete data marker
at the shared 8 MiB/200,000-token limit. Later mandatory calls/inventory are not evicted.

## Remaining delivery gates

The generic transport, optional exact data rules, isolated original-pak baseline,
separate findings, mandatory gates and private moderation binding below are now
implemented; see [current integration/limits](data-policy.md). The remaining
acceptance boundary is effective dependency closure and exact-game provenance,
plus authorized container validation and independent review of this integration.

- Supply reviewed exact-game property-purpose metadata, not merely the original
  illustrative fixture model. Build assertions do not authenticate implementations.
- Establish effective dependency closure where supported; absent child overrides,
  external/native constructors, compound merging and cross-package ancestry remain
  unknown. Local structural provenance is not an engine-effective value.
- [Protected paths](content-policy.md) already recognize normalized, ASCII
  case-insensitive component identities. Those matches remain **replacement
  candidates**, not proven vanilla overrides. No mount/load precedence is guessed.
- Complete parent-authorized serial Docker/Action validation and independent
  integration review. Original fixture source/property-pointer and stable-bytecode
  proofs do not prove engine execution, actual game behavior or baseline safety.

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
Tagged and mapped native `OwnedData` must have complete supported property
enumeration. Blueprint packages retain unsupported property-model gaps; their
supported values and cooked/filtered markers are checked without claiming completeness.

Initial implementation validation on 2026-10-25: 166 extraction tests (28 new), 115 Policy,
26 PolicyInput, 193 Scanner and 159 Python tests passed without skips, plus the
Docker/Action corpus, three removal mutations and owned-cook checks.
Receipt: `/tmp/opencode/issue10-data-evidence-release-proof1/execution.json`.
This is implementation validation, not independent review or release approval.

FIX1 serial validation: 192 extraction tests (26 additional), 115 Policy,
26 PolicyInput, 193 Scanner and 135 ordinary Python tests passed without skips.
The non-Docker corpus and read-only owned verifier passed; 24 Docker tests were
excluded, not rerun. Receipt: `/tmp/opencode/pr34-fix1-proof/execution.json`.
