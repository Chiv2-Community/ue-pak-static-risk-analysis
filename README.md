# UE pak static risk analysis

Linux-based inspection of cooked UE 4.25 assets and Blueprint calls.

**Current status: bounded static-analysis prototype, not a safety verdict.**
There are a typed YAML policy parser, standalone three-valued evaluator, and
normalized extraction API, [trusted facts evaluation CLI](docs/evaluate.md), and
[local Docker pak scan](docs/container.md) with separate parser/evaluator containers.
A [reusable GitHub Action](docs/action.md) wraps that scanner; private external
consumer access remains unverified. Use disposable workers; Docker is not a
complete sandbox. Successful parsing does not mean a mod is safe.

The local [moderation handoff](docs/moderation.md) binds explicit human decisions
to exact pak/dependency bytes and trusted scan/build/policy context. It does not
autoapprove or modify any platform, launcher or registry.

For unresolved submissions, see the [manual runtime escalation runbook](docs/runtime-escalation.md).
It includes a trusted local canary, not authorization to deploy VMs or execute mods.

Work is tracked in [epic #1](https://github.com/Chiv2-Community/ue-pak-static-risk-analysis/issues/1).
Compatibility and legal-fidelity limits remain tracked in [issue #2](https://github.com/Chiv2-Community/ue-pak-static-risk-analysis/issues/2).

Start with the [operator guide](docs/operators.md), [CLI/Action input tables](docs/inputs.md),
[security boundaries](docs/security.md) and [controlled release checklist](docs/releases.md).
No release/publication or expanded access is approved. [Partial indirect evidence](docs/indirect-dispatch.md)
does not close #8; [bounded call-chain evidence](docs/call-chains.md) is partial #9,
not exact-game native catalog proof. Optional [private serialized-data rules](docs/data-policy.md)
are partial #10, not effective-default or exact-game behavior proof. Native implementation
analysis is not shipped; exact
Windows/game fidelity and broader redistribution rights remain open.

## Build and test

Requires Linux, .NET SDK 10, Python 3.11+, and Git. See the
[fresh setup](docs/operators.md#trusted-linux-setup) for Docker and pinned optional
Python test dependencies. Rust/Cargo and a C compiler are needed only for repak.

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

The [integrated regression gate](docs/regression-corpus.md) checks reviewed synthetic
package/pak expectations, finding/coverage removal mutations, bounded boundary
properties and optional complete CLI/container/Action parity. Authorized external
owned cooks remain a separate release prerequisite; CI does not cook or redistribute
engine-derived assets.
The [completed local release-path/component receipt](docs/regression-corpus.md#ci-upgrades-and-release-prerequisites)
records 142 Scanner / 111 extraction / 110 Policy / 26 PolicyInput and 137 serial
Python tests. That run published nothing and does not complete exact game fidelity.

## Run a local compatibility experiment

Use only assets you are authorized to inspect. **This compatibility experiment
is trusted-input-only:** `probe_pak.py` and the probe DLL do not enforce the
host wrapper's memory/decompression/storage/container boundaries. This warning
does not describe `scripts/scan.py scan`, which has separate bounded parser and
evaluator containers. Those controls still do not make Docker a complete sandbox
or certify mod safety. Use disposable workers without credentials for either
route. Neither Unreal Editor nor the game is launched.

```bash
dotnet restore src/CompatibilityProbe/CompatibilityProbe.csproj --locked-mode
dotnet build src/CompatibilityProbe/CompatibilityProbe.csproj -c Release --no-restore
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
has `analysis-complete: false`.** These differ from the integrated scanner's gate codes.

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

Optional trusted [content-policy flags](docs/content-policy.md) restrict virtual
namespaces and parsed export classes and allow, review or reject protected-path
replacement candidates. They do not change invocation YAML or finding counts;
without a clean-install baseline, candidates are not verified replacements.

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
