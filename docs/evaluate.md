# Trusted facts evaluation

`src/Scanner` implements **evaluate** for bounded normalized facts. The separate
[host Docker wrapper](container.md) implements `scan --pak`, keeping policy away
from the untrusted parser. Do not run the old compatibility probe in a
policy-bearing job to manufacture facts from untrusted assets.

## Usage

See the [complete shared CLI input reference](inputs.md#shared-evaluator).

Linux and .NET 10:

```sh
dotnet restore src/Scanner/Scanner.csproj --locked-mode
dotnet build src/Scanner/Scanner.csproj -c Release --no-restore
dotnet src/Scanner/bin/Release/net10.0/Scanner.dll evaluate \
  --facts examples/facts-v1.json \
  --policy-rules examples/starter-policy.yaml \
  --report /trusted/output/new-report.json \
  --engine-version 4.25 \
  --log-level info \
  --fail-on-any-forbidden true \
  --fail-on-any-flagged false \
  --fail-on-incomplete true
```

Omit `--policy-rules` to read raw YAML from `UE_PAK_POLICY_RULES`. Exactly one
source is required, including when an environment variable is empty. The shared
[PolicyLoader](policy-input.md) handles both sources without a second parser.

- Gate values are exactly `true` or `false`; defaults are shown above.
- Log levels are exactly `error`, `warn`, `info` (default), `verbose`.
- **Verbose prints the entire supplied policy, including malformed YAML, after
  a disclosure warning; anyone with log access can read it.** Ordinary env is
  not masked; runner setup and administrators can expose it independently.
  PolicyLoader escapes controls and workflow commands.
  It never puts policy YAML into reports. Other levels never print policy.
- `--moderator-detail` includes matched rule IDs per effect. Authorize access
  outside this CLI; the switch itself is not authentication. Descriptions,
  predicates, argument literals, allowlists, raw policy and fingerprints are
  never report fields, even with detail or verbose.
- `--policy-revision` is an optional caller-selected opaque identifier, 1–128
  ASCII letters/digits/dots/underscores/hyphens. Do not derive it from private
  policy values. No policy hash or inferred stable policy identity is generated.
- Unknown/repeated options and other engine versions are configuration errors.
- Report paths must be new. There are no extension restrictions. A private
  same-directory temporary report is flushed and moved without overwrite.
  Existing files, input/policy aliases, symlinks, FIFOs and directories are not
  overwritten. Failed writes are operational failures; temporary files are
  removed on handled errors. Abrupt process/host termination can leave a private
  temporary file; the future worker must clean its controlled output directory.

Use trusted local input/output directories. Final facts symlinks, FIFOs, devices,
directories and unavailable Linux `statx` are rejected before reads. Parent path
symlinks, hostile directory renames, remote/FUSE latency and kernel I/O deadlines
are not sandboxed. External worker runtime/memory limits remain necessary.

## Facts contract

[facts-v1.schema.json](../schemas/facts-v1.schema.json) is structural documentation;
`FactsCodec` is authoritative. It consumes and produces the exact Policy
`InvocationAnalysis` types, without a dependency on the asset parser:

```csharp
var facts = new FactsDocument(1, originalPakSha256, "4.25", producerVersion,
    dependencyIdentities, extractionReport.Analysis);
byte[] transport = FactsCodec.Write(facts);
```

`ExtractionReport` itself is **not** public transport: it contains local storage
paths. Hash the exact original pak bytes, not the unpacked content. Supply every
mapping/dependency identity actually used, each with its SHA-256 and unique kind;
an explicit empty list means none were used. Hashes are lowercase 64-digit hex.
Producer version and dependency kinds are nonempty bounded ASCII identity tokens.

Core constructor fields are required. Optional `inspection` carries bounded
inventory/member hashes and inspection states; it contains no storage paths.
Optional `analysis.dispatches` adds independently versioned, bounded possible
target evidence; it never inserts callback invocations or changes YAML v1.
Optional `analysis.call-graph` carries independently versioned bounded function
definitions for [call-chain evidence](call-chains.md), not inferred invocation
occurrences. New parser/extractor producers emit it; legacy absence means no
call-chain analysis unless an explicit catalog is supplied. Optional
`--capability-summaries` is trusted nonsecret input, never private policy syntax.
Closed `kind` tags cover resolved/unresolved
targets; known/unavailable argument metadata; constant/dynamic/missing values;
and string/integer/boolean/null literals. Enums are names, never integers. Keys
are kebab-case and case-sensitive; property order does not matter. Unknown or
duplicate keys, missing/null collections, unknown tags, wrong types, malformed
UTF-8/UTF-16, trailing/truncated JSON and conflicting duplicate locations fail.

Limits: 8 MiB UTF-8; depth 16; 200,000 JSON tokens; 4,096 UTF-16 code units per
string; 10,000 invocations; 256 arguments per invocation, dependencies or coverage
gaps. Streaming preflight checks bytes, tokens, strings, duplicate keys and array
counts **before** typed deserialization. The evaluator's shared facts validator
then checks locations, targets, names, literal values and duplicate consistency.
Producer serialization is bounded too. Valid empty invocations require explicit
identities and explicit coverage; absent/truncated input never becomes empty success.

Producers must report honest coverage. Schema validation, hashes and an empty gap
list are **not authenticity guarantees**: a compromised parser can fabricate
semantics, omit calls or lie about hashes/completeness. The Docker wrapper runs parsing in a
separate isolated container/worker with no policy mount/environment/credentials,
not merely another same-UID process. Trusted orchestration must bind producer
artifacts to the original pak and dependency hashes. Never replay raw parser
output into trusted logs. This command logs only fixed diagnostics and the
explicit PolicyLoader verbose representation.

## Reports and exits

[report-v1.schema.json](../schemas/report-v1.schema.json) defines the public shape.
Generated [examples](../examples/reports/) cover all statuses:

- `successful`: evaluation completed with no coverage gaps or rule uncertainty;
  it may still contain forbidden findings and fail gates. This is not a safety verdict.
- `partial`: accepted facts have gaps or evaluation uncertainty. Empty findings
  do not make this complete. Rule-specific uncertainties/reasons are not public.
- `failed`: configuration or analysis failed; no accepted evaluation exists.
  Hash/producer context is null if facts were not accepted. Zero counts here do
  not assert zero calls. A fixed diagnostic and incomplete coverage mark failure.

Optional trusted [content settings](content-policy.md) add a separate versioned
result. Content incompleteness also produces `partial`; content review/rejection
alone does not change analysis completeness or invocation counts. No configured
allowlists or prefixes are emitted. The invocation YAML grammar is unchanged.

Counts are distinct locations: flagged, forbidden, and their union. A location
appears once per effect and can appear in both lists with the same finding ID.
IDs are SHA-256 of the JSON tuple `[pak-sha256, asset, function, offset]`, using
System.Text.Json's default encoding. They depend only on public artifact/location,
not policy or effects. Lists sort by ordinal asset/function then offset;
dependencies sort by ordinal kind; detail IDs sort ordinally. Reordering facts
or rules does not alter reports. No timestamps, worker order or source paths
are emitted. Public locations/targets and argument availability/counts come
from facts, not policy. Argument values and names are not emitted.
The optional [possible-dispatches](indirect-dispatch.md) section exposes validated
callback function-name operands as target evidence, not arbitrary argument literals.
Its possible effects and open-world diagnostics never count as direct findings.

| Exit | Meaning |
| --- | --- |
| 0 | Selected gates passed; not moderation approval |
| 1 | A selected forbidden/flagged/incomplete gate failed, or content requires review/rejection |
| 2 | Invalid configuration or policy |
| 3 | Invalid/unreadable facts, analysis/runtime failure, or report-write failure |

Final/partial/failed reports are written before returning when a report path is
available and safe. Syntax errors before options are accepted may have no report.
Operational failures are never overridden by disabled gates. Report-write failure
returns 3 even after configuration/gate failure. Human diagnostics are fixed text:
no source paths, parser output, upstream exception text, or policy values.

## Validation

```sh
dotnet restore tests/Scanner.Tests/Scanner.Tests.csproj --locked-mode
dotnet test tests/Scanner.Tests/Scanner.Tests.csproj -c Release --no-restore
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Process tests launch the built DLL for gates, file/environment loading, log-level
parity, warned disclosure, special files, malformed facts, deterministic ordering
and output-write failures. Schema-example checks use Python `jsonschema` when
installed; no new production dependency is required. Parser timeout, cancellation
and private-policy isolation tests run through the [Docker wrapper](container.md).
