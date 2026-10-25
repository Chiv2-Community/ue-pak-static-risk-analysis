# Owned cook fixtures

Original source-only fixtures for [issue #2](https://github.com/Chiv2-Community/ue-pak-static-risk-analysis/issues/2).
These supplement the compatibility probe; they are not a safety verdict or game-compatibility proof.

## Producer

- UE 4.25Plus commit `2d1aaeede6780b14c3ef97272e8a68c3429d8231`.
- Local authorized image `ue-engine:ticket-1-built`, image ID
  `sha256:fe577896540682373f41e0c4fb5612c95a702c32535b7c1d17ee7637a013fc9c`.
- Editor and cook target: Linux / `LinuxNoEditor`. No Windows or Chivalry-specific claims.
- `fixtures/owned`: original native runtime classes and editor-only generation commandlet.
  No engine implementation, engine content, game assets, or third-party fixture binaries are copied into Git.

| Asset | Intended cooked evidence |
| --- | --- |
| `BP_OwnedParent` | Native `FixtureActor` superclass, custom defaults, BeginPlay calling `RecordFixture(101)` |
| `BP_OwnedChild` | Blueprint parent superclass, overridden custom defaults, BeginPlay calling `RecordFixture(202)` |
| `OwnedMap` | Placed child actor and actual Level Blueprint BeginPlay calling `ObserveFixture(303)` |
| `Data/OwnedData` | Native standalone `FixtureData` UObject, `FixtureNumber=424242`, `FixtureText=owned-unversioned-value` |

The commandlet builds and compiles graphs; it does not enter play mode or run the game.
The callable native methods are inert or only assign an original object's integer property.

## Reproduce locally

Requires Docker, Python 3.11+, .NET 10, authorized access to the already-built image,
18 GiB available RAM, and 8 GiB free output storage. No installs, pulls, engine builds,
or dependency downloads are performed by the cook driver.

```sh
python3 scripts/cook_owned_fixtures.py /tmp/opencode/new-owned-fixture-run
python3 -m unittest discover -s tests -p test_owned_fixture_usmap.py -v
dotnet restore tests/OwnedFixtures.Verify/OwnedFixtures.Verify.csproj --locked-mode
dotnet run --project tests/OwnedFixtures.Verify/OwnedFixtures.Verify.csproj --no-restore -- /tmp/opencode/new-owned-fixture-run
```

For offline restore, supply a local NuGet package source; the pinned UAssetAPI
submodule must already be initialized. Local worktree initialization can use
`git submodule update --init --no-fetch vendor/UAssetAPI` when its object store is available.

The driver refuses existing output paths and paths inside this checkout. It uses
UID/GID 1001, no network, no Linux capabilities, no privilege escalation, 8 CPUs,
16 GiB memory with no extra swap, 1,024 PIDs, and a 30-minute timeout. Only fixture
source is mounted read-only; output is writable. The fresh output directory is
mode 0777 for the container UID; do not place secrets there. Docker itself remains
a trusted host dependency, not an untrusted-submission sandbox.

`-CookSinglePackage` requests suppression of startup/default-map and unsolicited
packages, but this engine still saves some loaded engine packages without an
explicit exclusion. `DefaultGame.ini` excludes `/Engine`, `/Paper2D`, and `/Niagara`;
the driver rejects packages outside the exact owned selection. Both runs use
package names through `-Map` (which accepts
non-map packages in this engine). `-CookDir` is ignored with this flag. The tagged
run selects all four original packages. The unversioned run selects only
`/Game/Data/OwnedData`, with `-unversioned` and
`[Core.System] CanUseUnversionedPropertySerialization=True`.

## Mapping and verification

The producer emits `Saved/producer-reflection.json` by traversing `PropertyLink`,
excluding editor-only and inherited properties from each local schema. ArrayDim
expands local slots. Derived slots precede superclass slots. `FixtureData` is the
reflected class name, not `UFixtureData`; its zero-property `Object` superclass
is retained. The Python encoder writes uncompressed usmap v0 and rejects unknown
property types instead of guessing. Only IntProperty and StrProperty are supported.
This is not a general engine mapping dumper.

`OwnedFixtures.Verify` requires actual external cooked files; missing files fail
rather than skip. It asserts:

- Expected superclass identities and tagged custom defaults.
- Real parsed `ReceiveBeginPlay` and named ubergraph functions in parent, child,
  and Level Blueprint; exact native call owners and integer arguments.
- Cooked/filter markers, no `RawExport`, and no bytecode parse/size failures.
- Unversioned package marker and exact native int32/FString values with mappings.
- Explicit incomplete/failure diagnostic without mappings.
- Normalized native calls/constants and policy consumption: invocation-only rules
  stay complete; required imported argument metadata remains Unknown under
  negation; unrelated targets suppress irrelevant argument uncertainty.

`receipt.json` records image/engine identity, exact commands and runtime arguments,
source/tool SHA-256 hashes, reflection, output hashes, log hashes, and exit status.
`completed` means generation/cooking/mapping succeeded, not that verification or
security analysis passed. Run the verifier separately and preserve its output.
Package GUIDs can change between runs; semantic assertions, not identical cooked
hashes across regenerations, are the reproducibility contract.

## Measured local result: 2026-10-25

Successful commands from this worktree:

```sh
python3 scripts/cook_owned_fixtures.py /tmp/opencode/owned-fixture-clean-20261025 --ddc-seed /tmp/opencode/owned-fixture-final-20261025/engine-ddc --timeout 1800
dotnet tests/OwnedFixtures.Verify/bin/Debug/net10.0/OwnedFixtures.Verify.dll /tmp/opencode/owned-fixture-clean-20261025 > /tmp/opencode/owned-fixture-clean-20261025/verify.log 2>&1
```

- Build, generation, tagged cook, unversioned cook, and verifier exited 0.
  Each editor commandlet reported zero errors and warnings.
- Exactly four tagged packages and one unversioned package; no engine/plugin
  asset packages in either output selection.
- Parent, child, and Level Blueprint: 2/2 functions parsed each, exact native
  calls/arguments, no diagnostics or `RawExport`.
- Tagged defaults and native tagged/unversioned values matched. Removing mappings
  produced an explicit incomplete/failure result.
- Python tests: 13 passed. Existing compatibility-probe tests: 19 passed.

Private evidence directory: `/tmp/opencode/owned-fixture-clean-20261025`.
Its receipt contains the exact Docker/build/editor commands, producer reflection,
source hashes, package/sidecar hashes, and resource preflight measurements.

| Evidence | SHA-256 |
| --- | --- |
| `receipt.json` | `56b90c503c84cc9edeafff39579292e2cc54fc8b81e165ea05f85da27edd8ee2` |
| `verify.log` | `fd00709b955fa4eed38bd0c2d1a79ad7e9629129ca9930acf08a3d6859dfd79c` |
| `owned.usmap` | `f7f43158652035e106070c6dbc5eb0188543fe36dc91207b6be1ca8dd0a630eb` |

The verifier was then extended against normalized extraction revision `452c786`.
Reusing the same cooked bytes passed all checks above without recooking:

```sh
dotnet run --project tests/OwnedFixtures.Verify/OwnedFixtures.Verify.csproj --no-restore -- /tmp/opencode/owned-fixture-clean-20261025 > /tmp/opencode/owned-fixture-clean-20261025/normalized-verify.log
```

`normalized-verify.log` SHA-256:
`bdb8314d94226db158ef16a9a878550d8f7a5af8c7de8c919c7d943fb3e0311b`.
The original cook receipt and `verify.log` above are unchanged. GitHub CI builds
the verifier and runs source/tool unit tests; it does not cook or claim the local
engine-generated acceptance run.

Earlier exploratory directories are not the final evidence selection. They retain
the initial command-selection and engine/plugin-exclusion attempts; no artifacts
were deleted or promoted into Git.

## Artifact handling

All generated packages, binaries, mappings, build intermediates, and raw logs stay
in the external output directory. Do not commit or upload cooked output from this
workflow. Original source does not grant rights to redistribute Epic engine code,
engine-derived content, an engine image, or external game assets. Review the
applicable engine terms before sharing any generated artifact; retain hashes and
source-only provenance instead of assuming redistribution is permitted.

The per-job `engine-ddc/` mount preserves derived data outside the container.
`--ddc-seed /path/to/authorized/cache` can reuse an existing local engine cache;
the seed is mounted read-only and copied into the job cache, never used as cook
content. Keep these engine-derived caches private too.

This does not complete issue #2: game-specific Windows builds, authorized
representative external packages, broader unversioned schemas, archive/container
coverage, and other compatibility gates remain separate work.
