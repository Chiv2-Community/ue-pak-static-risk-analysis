# UE 4.25 compatibility probe baseline

- Date: 2026-10-24
- Status: accepted; implemented locally; issue #2 remains open
- Scope: cooked UE 4.25 package parsing and legacy pak inventory/extraction
- Repository: `Chiv2-Community/ue-pak-static-risk-analysis`
- Canonical remote: `https://github.com/Chiv2-Community/ue-pak-static-risk-analysis.git`
- Git provenance: investigation began in an unborn repository, with no prior `HEAD`, tag, or commit SHA. This record was first committed as `d19beb07769e1b30972e61b3ce61610f76f218d4`; all described probe implementation remains uncommitted.
- Related work: [epic #1](https://github.com/Chiv2-Community/ue-pak-static-risk-analysis/issues/1), [issue #2](https://github.com/Chiv2-Community/ue-pak-static-risk-analysis/issues/2)
- Sources: 2026-10-24 conversation checkpoint (source session/response IDs unavailable); `README.md`; `docs/compatibility.md`; pinned submodules.

## Decision

Establish a narrow compatibility probe before building a moderation scanner. Inspect cooked package bytecode directly with UAssetAPI at `b4e8a012939295a6fd890ddc64e57ea78b709b95` and inventory/extract supported paks with the external repak CLI at `355b5f62f51959c7cc6dd5a51708646ef483065d`.

Treat incomplete parsing or unresolved calls as diagnostics, never as a clean or safe result. Successful parsing is not a safety verdict.

## Context and evidence

The intended scanner must support Blueprint mods on Linux, but the compatibility of selected dependencies with target-game cooked assets had to be demonstrated first. The recorded local experiment parsed 307 of 307 functions across 71 mod packages, producing 2,397 invocation records. A constrained Ubuntu 24.04 run produced an identical report (`974cc0b92097870a8ba82a33e65fb6f21342ce6a6b1477698de8867897061a0f`) and repak extracted all 147 entries with matching hashes.

The probe avoids UAssetAPI's path-based `.uexp` helper because it requests read/write access and failed on a read-only Ubuntu mount. Its adapter supplies explicit read-only package and sidecar streams through `PackageReader`; no upstream source was changed.

## Options considered

- **Pinned UAssetAPI source plus external repak CLI (chosen).** UAssetAPI parsed the selected assets without adaptation; repak covered the evaluated legacy pak subset.
- **Current NuGet UAssetAPI release.** Rejected for this evaluation: only 1.0.0, 1.0.1, and 1.1.0 were listed, while the evaluated source targets .NET 10 and declares 2.0.0.
- **UAssetAPI bundled native pak binding.** Rejected: it extracts a native library beside the application on demand. The probe uses no Oodle download.
- **CUE4Parse.** Deferred as a fallback candidate; it was not evaluated because UAssetAPI met the selected sample need.
- **Uncooking/reconstruction, UEAssetToolkit/CAS, or pseudocode decompilers.** Rejected as the security baseline because supported constructs and reconstruction are incomplete.

## Consequences and limits

- Accepted input is limited to V9 legacy paks with unencrypted indexes and no compression or Zlib. Encryption, Oodle/custom codecs, IoStore, and unsupported formats are rejected rather than guessed.
- The probe reports raw-export, raw-bytecode, visit, and read failures. `analysis-complete` remains false; it has no policy evaluation, reachability, argument, virtual/delegate, transitive, or data-driven analysis.
- Symbolic target resolution does not establish native implementation behavior. The observed `ExecuteConsoleCommand` calls are capability observations, not maliciousness findings.
- No owned cooked fixtures, verified unversioned-properties/mapping pair, final-image reproducibility, or complete redistribution review exists. Do not present the implementation as production ingestion or containment.

## Follow-up and reconsideration

Keep issue #2 open until owned UE 4.25 fixtures cover expected calls, inheritance, custom properties, and executable map Blueprints; a real unversioned asset and `.usmap` pair are validated; provenance and redistribution rights are established; and final-image reproducibility is demonstrated. Issue #3 owns hostile-input containment.

Reconsider the parser or extraction choices if these fixtures expose unsupported target behavior, read-only operation regresses, final-image validation fails, or dependency licensing/distribution cannot be satisfied.

## Open historical gaps

The exact mod cook producer revision was not established. Detailed reports, extracted bytes, and the original assets remain outside the repository. The conversation checkpoint named no source response ID or responsible individual for each choice; repository documents corroborate the recorded implementation and limits.
