# Normalized cooked invocation extraction

`PakRisk.Extraction.InvocationExtractor` is an additive library API in
`src/CompatibilityProbe`. It reuses the pinned UE 4.25 `PackageReader` and
`TargetResolver`. The existing compatibility CLI is not an extraction or policy
gate. Issue #11 owns CLI integration; ingestion can call this API separately.

```csharp
var input = new PackageInput(
    pakHash, entryIdentity, "/Game/Maps/Example", generatedStoragePath);
var report = InvocationExtractor.Read(input, mappings);
var evaluation = new PolicyEvaluator(policy).Evaluate(report.Analysis);
```

Use `Inspect(UAsset, PackageInput, ExtractionLimits?)` for already parsed packages.
The caller supplies stable pak and entry identities and the logical package path;
the extractor never derives them from generated storage names. Logical paths
should use Unreal package form, without `.uasset`/`.umap`, for local policy owners.
`FactIdentity` length-prefixes pak and entry before the logical path, avoiding
delimiter collisions and cross-pak location collisions. `StoragePath` is only a
read input and remains separate in `report.Input`. Each identity component is
bounded to 1024 UTF-16 characters and must be nonempty, valid Unicode, and free of
control characters. Invalid caller identities/limits throw fixed setup errors.

## Records and semantics

- Every `FunctionExport` is scanned in export order. No extension, function-name,
  event-graph, owner, or reachability filter suppresses functions. Maps and
  generated functions use the same path.
- Containing identity includes outer-qualified owner, function name, and one-based
  export index. Identical names, including duplicate names on one owner, remain
  distinct. Broken outer chains produce coverage, not fabricated owners.
- Calls preserve the exact opcode, VM offset, dispatch kind, package index,
  structured resolved identity, and unresolved virtual-name evidence. Offsets are
  not serialized-file offsets. The pinned upstream `EX_IntConstByte.Visit` omits
  its operand byte; extraction corrects it. Declared function VM size is checked.
- Direct final/local-final/math calls resolve only function imports/exports.
  Imported owner names are symbolic identities, not proofs about external code.
  Multicast dispatch is checked before its `EX_FinalFunction` base type; its
  signature index is never treated as the eventual direct target. Virtual and
  local-virtual calls retain names but stay unresolved.
- Context receivers retain object/interface opcode and available package-index or
  name evidence. Context calls and their nested argument calls are both visited.
  Bind/instance/add/remove/clear delegate operations produce unresolved-behavior
  coverage rather than invented calls.
- Local signature metadata uses serialized `LoadedProperties` order, selecting
  `CPF_Parm` and excluding `CPF_ReturnParm`. Legacy `PropertyExport`/`UProperty`
  child/next chains are bounded, ownership-checked, and cycle-checked. Duplicate
  names and malformed metadata fail closed. Imported signatures are unavailable;
  positional argument evidence is retained without inventing parameter names.
- String/UnicodeString, Int/Int64/IntConstByte/IntZero/IntOne, True/False, and
  NoObject/NoInterface become policy constants. Null, missing argument, unavailable
  metadata, malformed metadata, runtime expression, and parser failure remain
  distinct. Argument-count mismatches generate coverage.
- FName, byte/enum-like values, floats, object references, and other unsupported
  constant types remain `ArgumentValue.Dynamic` with the fixed reason
  `unsupported-constant-type` and source opcode. They are not coerced to policy
  strings/integers. No shared policy ADT variants or evaluator semantics changed.
- Policy-unrepresentable owner/function identities remain structured extraction
  evidence, but the policy target is unresolved with coverage. More than 256 named
  arguments uses unavailable policy metadata with coverage. Positional evidence
  remains in the extraction report.
- Package coverage includes total and inspected export counts. Per-function and
  package diagnostics use fixed codes, never dependency exception
  text. Native functions/targets and native classes are explicit boundaries. This
  is not native-code analysis or a complete nativization detector.

`Complete` describes only this package's extraction coverage, not safety, pak
coverage, or a gate verdict. Every diagnostic contributes an analysis coverage
gap; unresolved dispatch and unsupported parsing also get specific gap categories.
The legacy probe still always reports `analysis-complete: false`.

## Bounds and failure behavior

Before upstream recursive `Visit` runs, an iterative preflight checks an exact
pinned runtime-type/token/child-order registry. Unknown subclasses fail closed.
It follows active text-literal children, switch-case structs, expression fields,
arrays, and wrapped SoftObject/FieldPath constants; unrelated `Tag`/raw user data
are not bytecode children. Active-path cycles fail, while shared DAG nodes count
once per expanded occurrence. Visit must reproduce the preflight sequence.

Defaults and hard maxima: 100,000 exports, 100,000 expanded instructions/package,
128 expression depth, 10,000 roots/array elements/signature fields, 4096 characters
per string/name literal, and 10,000 emitted invocations. Argument evidence has a
separate 100,000-occurrence package budget. Signature-field inspection has its own
100,000-occurrence package budget and caches each signature. Property-pointer path
elements count against the instruction preflight budget. Limits may only be lowered. Outer
resolution is capped at 256 references and 4096 identity characters.

An invalid root is not passed to recursive Visit. Findings from prior roots and
already visited instructions survive. A failed root stops that function: later
offsets cannot be asserted. Other functions still receive coverage records. Raw
exports, unsupported export types, non-function script-bearing exports, missing
mappings/markers, parser failures, sequence errors, and size mismatches cannot
produce a clean result.

**These bounds apply after parsing, not to the upstream parser or file reads.**
`PackageReader` and upstream bytecode deserialization can allocate/recurse before
preflight. Do not expose this in-process API to hostile production inputs.
Ingestion quotas and externally supervised memory, CPU, filesystem, and process
containment remain required in #3/#11/#12. Dependency loading, native behavior,
dynamic dispatch, and runtime argument computation remain unknown.

## Validation and remaining acceptance work

`tests/CompatibilityProbe.Tests/ExtractionTests.cs` uses synthetic UAsset trees for
nested/generated/map-style functions, owner/name collisions, dispatch, constants,
loaded/legacy metadata, receivers, native boundaries, malformed references, raw
bytecode, cycles, depth, expanded DAGs, arrays, literals, and policy consumption.
Synthetic tests do not establish cooked-editor compatibility or actual engine VM
offset correctness for every opcode. Engine-cooked nested/event-graph/map/local/
native/name-collision fixtures and provenance remain issue #2 work. Issue #4's
fixture acceptance criteria are not complete on this evidence alone.
