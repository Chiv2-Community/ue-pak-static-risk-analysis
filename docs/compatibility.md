# UE 4.25 compatibility baseline

## Stack decision

Use the following stack for the trusted-input compatibility probe. The separate
[host scanner](container.md) implements bounded ingestion/container isolation;
this historical probe does not inherit that boundary.

| Component | Evaluated revision | Role |
| --- | --- | --- |
| UAssetAPI | `b4e8a012939295a6fd890ddc64e57ea78b709b95` | Cooked package parsing and Kismet visitor |
| repak | `355b5f62f51959c7cc6dd5a51708646ef483065d` | External, source-built pak inventory/extraction |

UAssetAPI's evaluated source targets .NET 10 and declares version 2.0.0. NuGet's
version listing exposed only 1.0.0, 1.0.1, and 1.1.0 at evaluation time; those
packages were not substituted or evaluated. Project package lockfiles record
transitive dependency resolutions.

Use repak's external CLI, built with `--no-default-features`, rather than
UAssetAPI's bundled native pak binding. That binding extracts a native library
beside the application on demand. The asset probe does not call it. No Oodle
library is downloaded by this experiment.

The asset adapter also avoids UAssetAPI's path-based reader: its `.uexp` helper
opens the sidecar with read/write access. This failed on a read-only Ubuntu
mount. `PackageReader` instead combines explicit read-only package and sidecar
streams before calling the upstream parser. No upstream files were modified.

CUE4Parse is a fallback candidate, not a tested dependency here. UAssetAPI already
parsed the selected target-game samples without adaptation, so adding another
parser is not justified yet. UEAssetToolkit/CAS and pseudocode decompilers are
not security baselines: reconstruction and supported constructs are incomplete.

## Measured local results

Evaluation date: 2026-10-24. Linux x86-64, glibc 2.44, .NET SDK 10.0.112/runtime
10.0.12. Chivalry 2 Steam installation build ID: `21012305`. The mod's exact cook
producer revision was not independently established. UE 4.25 is a supplied
parsing hint, not inferred proof of the producer build.

| Sample | Packages | Functions parsed | Invocation records | Result |
| --- | ---: | ---: | ---: | --- |
| Locally installed Unchained mod | 71 | 307/307 | 2,397 | 2,078 package-index targets; 319 name-only virtual calls; 52 delegate diagnostics |
| Base game `Engine/Content/Maps/Entry.umap` | 1 | 0 | 0 | 21 exports parsed; map loading only, not map Blueprint coverage |
| Base game frontend player controller and capture-area Blueprint | 2 | 23/23 | 97 | 5 unresolved virtual calls; 4 delegate diagnostics |

The mod pak has 147 entries, a V9/FrozenIndex container, an unencrypted index,
and Zlib compression. Its original SHA-256 is:

```text
a741920a647f2049e62ce3a2435fae48c8961b22a5285fb7fdb640e561dffb0c
```

The mod's 10,028 exports produced no raw-export fallbacks, bytecode parse
failures, or declared/visited VM-size mismatches. Ten symbolic calls resolve to
`/Script/Engine.KismetSystemLibrary:ExecuteConsoleCommand`; that is a capability
observation, **not a maliciousness finding**. One example is
`AgSDKFPSSync.ExecuteUbergraph_AgSDKFPSSync`, VM byte offset `704`.

All 71 mod packages have editor-only filtering set but do not have `PKG_Cooked`
set. Consequently, the probe records both markers and does not reject a package
merely because the latter is absent. Neither marker establishes authenticity.

Offsets are **function-relative in-memory Kismet byte offsets**, as reported by
the upstream visitor, not physical offsets in `.uasset` or `.uexp` files.
Package-index target resolution follows import/export outer chains; it does not
verify the native implementation or catalog its capabilities.

The same mod probe was then run in Ubuntu 24.04 using
`mcr.microsoft.com/dotnet/runtime:10.0-noble`, pinned to image digest:

```text
sha256:0cf09aaccf6a9f68900aed4c73fb28fe25bb59ec85de4dea08ba02240a8635f3
```

The container ran as non-root with read-only input/root, no network, dropped
capabilities, no-new-privileges, a 1 GiB memory limit, one CPU, and a 64-process
limit. Its parsed report was identical to the host result, including all 371
unresolved-behavior diagnostics. The report file SHA-256 was:

```text
974cc0b92097870a8ba82a33e65fb6f21342ce6a6b1477698de8867897061a0f
```

The host-built repak executable also read the mod index and extracted all 147
entries in that Ubuntu image under the same isolation settings. Every extracted
file hash matched the host extraction. A distributable image remains separate
work; this is runtime compatibility evidence, not a production sandbox
certification.

Detailed reports and extracted bytes remain outside the repository. The report
hashes each inspected package and available `.uexp`/`.ubulk` sidecar. Bulk bytes
are hashed but not decoded or security-validated.

## Coverage matrix

The [owned cook-fixture workflow](owned-fixtures.md) provides a separate original
source project and strict external-artifact verifier. Its Linux cook evidence
does not establish target-game Windows compatibility.

| Case | Evidence and behavior |
| --- | --- |
| V9 legacy pak, Zlib, unencrypted index | Verified on local mod and base-game containers |
| Plain V9 pak | Accepted by experiment guard; separate bounded scanner has synthetic round-trip/corpus coverage |
| `.uasset` + `.uexp` | Verified across mod and selected game samples |
| `.ubulk` | Local mod sidecars extracted and hashed; not decoded |
| Blueprint event graphs and nested calls | Real mod functions parsed; nested visitor regression tests |
| Native game types and inherited classes | Selected game samples parsed; no cross-package/inheritance behavior resolution |
| `.umap` | Simple game map plus owned Linux Level Blueprint with 2/2 executable functions verified; no Windows fixture claim |
| Unversioned properties | Owned Linux native UObject/mapping pair and missing-mapping negative verified; no target-game pair verified |
| Custom game serialization | Selected samples parsed; no general custom-serializer claim |
| Missing dependency context | No cross-package resolution; report limitations remain explicit |
| Encryption | No keys accepted in this experiment; metadata/extraction failure is not success |
| Oodle/custom codecs | Explicitly rejected by experiment format guard |
| IoStore `.utoc`/`.ucas` | Explicitly rejected when supplied or found as same-stem companions; broader mixed-container inventory deferred |
| Nativized Blueprint/native binary logic | Not analyzed; absence of Blueprint bytecode is not proof of harmlessness |
| Unknown/corrupt exports or bytecode | Raw-export, raw-bytecode, visit-failure, or read-failure diagnostics; never silently clean |

`parse-complete` only describes the probe's tracked parsing/resolution gaps.
`analysis-complete` is always false **in this probe**. No reachability filtering, policy evaluation,
argument analysis, virtual/delegate resolution, transitive analysis, or
data/default-driven behavior analysis is implemented.

## Runtime and redistribution

- Build: .NET 10 SDK; Rust/Cargo and C toolchain; Python 3.11+ for the driver.
- Runtime: .NET 10 runtime and the platform dependencies it requires; a Linux
  repak executable and Python for end-to-end extraction.
- The measured repak executable links `libc`, `libm`, and `libgcc_s`. Index
  inspection, extraction, and the managed asset probe were verified in the pinned
  Ubuntu runtime above. Other architectures and the eventual distributable image
  still need validation.
- UAssetAPI: [MIT license](../vendor/UAssetAPI/LICENSE) plus its
  [third-party notices](../vendor/UAssetAPI/NOTICE.md).
- repak: MIT OR Apache-2.0; preserve the selected license and notices for any
  binary distribution. See the pinned source's license files and Cargo metadata.
- NuGet/Rust transitive notices and the bundled UAssetAPI resources need a full
  redistribution review before packaging. This experiment publishes no binary
  artifacts or container images.
- No Epic engine source, game/mod assets, keys, mappings, or production policies
  are copied into this repository. Upstream submodules retain their own content;
  their third-party test assets are not promoted as redistributable fixtures.
- Unit tests create synthetic in-memory object graphs. They are reproducible
  code fixtures, **not evidence of successful cooking with Unreal Editor**.

## Remaining issue #2 work

- Validate build reproducibility in the final Ubuntu image; the managed probe
  and repak index reader/extractor already run in the pinned Ubuntu x86-64
  runtime above.
- Broaden the [owned Linux fixtures](owned-fixtures.md) beyond minimal calls,
  inheritance, custom native properties, and executable Level Blueprint coverage.
- Establish generated-fixture redistribution rights and target-game Windows cook
  provenance; the owned Linux producer is pinned and recorded.
- Extend unversioned coverage beyond the owned two-property UObject schema;
  validate target-game mappings and broader negative dependency cases. Do not
  reuse proprietary upstream samples without permission.
- Complete the dependency/native redistribution inventory before packaging.

Keep issue #2 open until these gaps have explicit evidence or agreed scope
adjustments. The closed #3 delivery adds bounded ingestion/content settings via
the [host wrapper](container.md); it does not broaden these fidelity claims.

## Sources

- [Pinned UAssetAPI README](https://github.com/atenfyr/UAssetAPI/blob/b4e8a012939295a6fd890ddc64e57ea78b709b95/README.md)
- [Pinned Kismet visitor offset contract](https://github.com/atenfyr/UAssetAPI/blob/b4e8a012939295a6fd890ddc64e57ea78b709b95/UAssetAPI/Kismet/Bytecode/KismetExpression.cs)
- [Pinned bytecode parse fallback](https://github.com/atenfyr/UAssetAPI/blob/b4e8a012939295a6fd890ddc64e57ea78b709b95/UAssetAPI/ExportTypes/StructExport.cs)
- [Pinned repak compatibility](https://github.com/trumank/repak/blob/355b5f62f51959c7cc6dd5a51708646ef483065d/README.md)
- [NuGet published versions](https://api.nuget.org/v3-flatcontainer/uassetapi/index.json)
- [CAS reconstruction limitations](https://github.com/LongerWarrior/UEAssetToolkitGenerator/blob/4e30eb55087228e8018fe14aeed65d2a34af3688/README.md)
