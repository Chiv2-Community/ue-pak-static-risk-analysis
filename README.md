# UE pak static risk analysis

Linux-based inspection of cooked UE 4.25 assets and Blueprint calls.

**Current status: bounded static-analysis prototype, not a safety verdict.**
There are a typed YAML policy parser, standalone three-valued evaluator, and
normalized extraction API, [trusted facts evaluation CLI](docs/evaluate.md), and
[local Docker pak scan](docs/container.md) with separate parser/evaluator containers.
A [reusable GitHub Action](docs/action.md) wraps that scanner; private external
consumer access remains unverified. Use disposable workers; Docker is not a
complete sandbox. Successful parsing does not mean a mod is safe.

Work is tracked in [epic #1](https://github.com/Chiv2-Community/ue-pak-static-risk-analysis/issues/1).
The first implementation addresses [compatibility issue #2](https://github.com/Chiv2-Community/ue-pak-static-risk-analysis/issues/2).

## Build and test

Requires Linux, .NET SDK 10, Rust/Cargo, a C compiler, Python 3.11+, and Git.

```bash
git submodule update --init --recursive
dotnet restore tests/CompatibilityProbe.Tests/CompatibilityProbe.Tests.csproj --locked-mode
dotnet test tests/CompatibilityProbe.Tests/CompatibilityProbe.Tests.csproj -c Release --no-restore
dotnet restore tests/Policy.Tests/Policy.Tests.csproj --locked-mode
dotnet test tests/Policy.Tests/Policy.Tests.csproj -c Release --no-restore
dotnet restore tests/PolicyInput.Tests/PolicyInput.Tests.csproj --locked-mode
dotnet test tests/PolicyInput.Tests/PolicyInput.Tests.csproj -c Release --no-restore
dotnet restore tests/Scanner.Tests/Scanner.Tests.csproj --locked-mode
dotnet test tests/Scanner.Tests/Scanner.Tests.csproj -c Release --no-restore
python3 -m unittest discover -s tests -p 'test_*.py' -v
cargo build --locked --release --manifest-path vendor/repak/Cargo.toml -p repak_cli --no-default-features
```

The dependency submodules are pinned. Do not substitute the current NuGet release
for the evaluated UAssetAPI source revision.

## Run a local compatibility experiment

Use only assets you are authorized to inspect. **Do not expose this prototype to
untrusted submissions:** it does not yet enforce memory, decompression, storage,
or process isolation limits. Run experiments on a disposable worker without
credentials. Neither Unreal Editor nor the game is launched.

```bash
python3 scripts/probe_pak.py \
  --pak /path/to/mod.pak \
  --repak vendor/repak/target/release/repak \
  --probe-dll src/CompatibilityProbe/bin/Release/net10.0/CompatibilityProbe.dll \
  --output /path/to/new-experiment-directory
```

The output directory must not exist. It contains:

- `experiment.json`: original pak hash, format information, and experiment status.
- `extracted/`: local extracted files; never commit these.
- `assets.json`: sidecar hashes, functions, symbolic call targets, VM offsets,
  diagnostics, and limitations, when asset parsing runs successfully.

The experiment only accepts V9 legacy paks with no compression or Zlib. It rejects
unsupported formats, index encryption, and other codecs rather than guessing.
Encrypted payload extraction failures also fail the experiment. This is a narrow
evaluated subset, not a claim about all formats repak supports.

For an already extracted asset or directory:

```bash
dotnet src/CompatibilityProbe/bin/Release/net10.0/CompatibilityProbe.dll \
  /path/to/extracted /path/to/new-report.json
```

An optional third argument supplies a locally authorized `.usmap` file. The
report path must be new and must not use an asset/sidecar extension.

Exit codes: `0` means this parser experiment completed without its tracked gaps;
`2` means incomplete parsing or unresolved behavior; `1` means invalid setup,
unsupported format, extraction failure, or report failure. **Every report still
has `analysis-complete: false`.** These are not the future moderation gate codes.

See [the compatibility baseline](docs/compatibility.md) for measured results,
licensing, unsupported cases, and remaining issue #2 work.

## Policy rules

The [YAML policy ADT/schema](docs/policies.md), strict parser, and standalone
evaluator are implemented. Evaluation consumes explicit normalized invocation
facts; the [extraction API](docs/extraction.md) produces these separately from the
compatibility CLI. Unknown evaluations
and global coverage gaps remain separate from findings and gate decisions.
See [the starter example](examples/starter-policy.yaml) and
[machine-readable structural schema](schemas/policy-v1.schema.json).

### Trusted facts evaluation and pak scanning

The Linux [shared policy input boundary](docs/policy-input.md) implements bounded
file/environment loading and safe verbose rendering. The [evaluate CLI](docs/evaluate.md)
uses it for bounded normalized facts and versioned reports. The
[host Docker wrapper](docs/container.md) integrates bounded pak extraction and
policy evaluation without exposing policy to the parser. The old compatibility
probe remains trusted-input-only. See the [Action guide](docs/action.md) for CI.

The evaluation CLI and Docker wrapper accept a
`policy-rules` file or raw YAML in `UE_PAK_POLICY_RULES`, with exactly one source.
The Action exposes `log-level`: `error`, `warn`, `info`, or `verbose`, default
`info`.

**Warning: `log-level: verbose` will print the policy to workflow logs. Anyone
with log access can read it.** Ordinary environment variables are not secrets and
are not automatically masked. GitHub step setup and host/container administration
may expose environment values outside scanner-controlled logs. Default scanner
log filtering alone cannot guarantee policy confidentiality.

Do not use verbose logging for a policy that must remain private. Keep policy
out of submitter-controlled jobs and the untrusted archive parser environment.
