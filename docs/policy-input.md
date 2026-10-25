# Shared policy input boundary

`src/PolicyInput` supplies trusted policy transport for future CLI, Docker, and
Action entry points. It does not implement those interfaces. Issue #14 remains
open until #11/#12/#13 integrate it and test job/process/report lifecycles.

## API

```csharp
using PakRisk.PolicyInput;

// Null path selects UE_PAK_POLICY_RULES; a non-null path selects a file.
// Load still inspects the variable to reject conflicting sources.
var policy = PolicyLoader.Load(filePath: null, logLevel: "info",
    log: Console.WriteLine, cancellationToken: cancellationToken);
// Only trusted evaluator code should access policy.Document.
```

- Exactly one source is required. An empty environment variable is selected,
  not absent. Empty/whitespace-only sources, conflicts, invalid UTF-8/YAML, and
  size violations fail closed. No permissive fallback.
- Levels are exactly `error`, `warn`, `info`, `verbose`; null defaults to `info`.
  Validate the level before reading policy. Nonverbose loading emits no logs.
  Level selection does not change the parsed document or evaluator semantics.
- Default byte limit is `PolicyYaml.MaxInputBytes`; callers may lower it.
  UTF-8 BOM is optional and counts toward the limit. UTF-16 is not accepted.
- Linux only. Environment bytes come directly from bounded libc `getenv`,
  avoiding .NET's invalid-UTF-8 replacement. Do not concurrently mutate the
  process environment during loading. The optional test/host byte reader must
  be trusted, bounded, and transfer buffer ownership; the loader clears it.
- File handles use nonblocking, no-follow, close-on-exec open, then fixed-layout
  Linux `statx` to require a regular file. Final symlinks, FIFOs, directories,
  devices, and unavailable `statx` fail closed. Parent symlinks are not sandboxed.
  Use trusted paths on local filesystems; remote/FUSE/pseudo-filesystem latency
  is not bounded by this API. Cancellation is cooperative between bounded reads,
  not a kernel I/O deadline. Parsing itself is size/depth/node bounded, not
  interruptible. Handles close on every exit path.
- No shell evaluation, YAML arguments, temporary policy files, caches, hashes,
  reports, or process execution. Raw strings are not retained in the result;
  managed strings and the process environment cannot be securely erased.
  `LoadedPolicy.ToString()` is constant and its document is ignored by default
  System.Text.Json serialization. Explicit AST access is private trusted data,
  not an approved report object. Existing evaluator findings may contain rule IDs;
  future orchestration must apply its private/public result contract separately.
- Source errors have fixed codes and no original exception/path. Existing safe
  `PolicyException` retains only code and location. Callback exceptions are
  replaced with a fixed error without an inner exception. Callers must not dump
  caller arguments, environment, ASTs, or evaluator internals on crash paths.

## Verbose disclosure

**Verbose prints the complete supplied policy to logs, including malformed YAML.
Anyone with log access can read it.** A warning is emitted before disclosure.
Invalid UTF-8 and oversized inputs fail before disclosure; they cannot be
represented as an accepted bounded UTF-8 document.

The original UTF-8 text (including BOM) is represented reversibly:

- `:`, `#`, `\`, terminal control characters other than LF, Unicode format characters,
  and Unicode line/paragraph separators become lowercase `\uXXXX` escapes.
- LF remains a line break. Other characters are unchanged.
- Decode each escape once, without recursively decoding its result. For example,
  literal `\u003a` becomes `\u005cu003a`, distinct from an actual colon.

No colon or hash survives in rendered policy text, so the runner cannot find
`::` or legacy `##[` commands anywhere, including attacker-supplied stop/resume commands. No stop-commands
token or masking-disabling command is used. Caller/platform masking remains
active and may hide values independently. This is a log representation only;
verbose does not authorize adding raw policy to reports or outputs.

## Environment configuration

Multiline raw YAML is supported, not a filename or shell program:

```sh
export UE_PAK_POLICY_RULES='schema-version: 1
rules:
  - id: reviewed-target
    description: "Reviewed target"
    effect: forbid
    match:
      kind: invocation
      target:
        kind: exact
        owner: /Script/Engine.KismetSystemLibrary
        function: LaunchURL'
```

Future CLI orchestration should read the variable directly. Future Docker usage
can forward an existing variable with `docker run --env UE_PAK_POLICY_RULES ...`,
not expand YAML into argv or bake it into an image. Future Action configuration
can supply ordinary multiline `env: UE_PAK_POLICY_RULES: |` YAML; no GitHub secret
is required. These are transport contracts, not working CLI/Action examples yet.

Environment variables are **not secrets**. GitHub may display them in step setup
logs; host/container administrators and authorized processes can inspect them.
Application log filtering cannot guarantee secrecy. Workflow configuration must
control policy provenance, who may enable verbose, and who may read logs. Use
trusted workflow/scanner code; never execute submitter-controlled code in the
policy-bearing job. A caller-selected secret store is optional, not automatic
redaction or a confidentiality guarantee.

## Untrusted parser handoff (not integrated)

Before starting any untrusted pak parser, trusted orchestration must construct a
fresh allowlist of nonsecret runtime environment values. `SetParserEnvironment`
clears `ProcessStartInfo.Environment` and copies only that explicit allowlist;
it rejects `UE_PAK_POLICY_RULES`. Never build the allowlist by copying host env.
Do not pass policy/keys through argv, filesystem inheritance, or descriptors.
The helper does not configure sandboxing or descriptor inheritance. Validate
bounded parser facts before evaluator use. #11 must test success, gate failure,
timeout, cancellation, and malformed-policy isolation across the real process
boundary; this component does not claim that integration.

## Validation

```sh
dotnet restore tests/PolicyInput.Tests/PolicyInput.Tests.csproj --locked-mode
dotnet test tests/PolicyInput.Tests/PolicyInput.Tests.csproj -c Release --no-restore
```

Tests cover file/env equivalence, all log levels and evaluator result parity,
canary-free nonverbose diagnostics, original malformed YAML disclosure,
workflow/terminal injection escaping, strict encoding, limits/BOM, source
selection, real libc empty/absent/invalid bytes, special files, cancellation,
callback failure, no policy temporary files, and explicit parser env allowlisting.
