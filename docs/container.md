# Local sandboxed pak scan

`scripts/scan.py scan` is a trusted **host** wrapper, not an executable to run
inside Docker. It needs Linux, Python 3.11+, a non-root caller, `/usr/bin/docker`,
and the local Docker daemon at `/var/run/docker.sock`. Docker access is a
host-administrator privilege. Use trusted scanner code and a disposable worker.
There is no uncontained fallback if Docker is unavailable.

```bash
git submodule update --init --recursive
docker build -t ue-pak-static-risk-analysis:dev .
python3 scripts/scan.py scan \
  --pak /approved/submission.pak --report /approved/new-report.json \
  --engine-version 4.25 --content-root 'TBL/Content=/Game' \
  --policy-rules /private/rules.yaml
```

The report must not exist. No archive member is written into the checkout or
host output directory. Replace `TBL/Content` with the actual virtual mount/index
prefix for your input; there is no built-in game namespace. Only one content-root
mapping is supported. Unknown roots become incomplete, not invented identities.
`--mapping /approved/owned.usmap` supplies one optional, bounded property mapping.
Encrypted paks and keys, other dependency bundles, indirect-call analysis (#8),
transitive packages (#9), and default/configuration effects (#10) are unsupported.

Optional trusted [content-policy flags](content-policy.md) restrict virtual paths
and parsed export classes and handle protected-path replacement candidates.
These are separate from invocation YAML and are never forwarded to the parser.

Environment policy input uses the same shared loader, not Python YAML parsing:

```bash
export UE_PAK_POLICY_RULES='schema-version: 1
rules:
  - id: review-native-call
    description: Review this native invocation.
    effect: flag
    match:
      kind: invocation
      target:
        kind: exact
        owner: /Script/Engine.KismetSystemLibrary
        function: LaunchURL
'
python3 scripts/scan.py scan --pak /approved/submission.pak \
  --report /approved/new-report.json --engine-version 4.25
unset UE_PAK_POLICY_RULES
```

Exactly one source is required. Raw YAML is never passed in argv, copied to a
temporary policy file, or built into an image. File policy mounts exist only in
the trusted evaluator. The parser has neither source, nor unrelated credentials.
The host rejects invalid UTF-8 before Docker's otherwise lossy JSON environment
transport. OS process-environment size limits also apply; use a file for larger
policies, within the shared loader's 256 KiB limit.
Default logs/reports omit private rule IDs/descriptions/predicates. Explicit
`--moderator-detail` includes matched rule IDs; restrict report access accordingly.

`--log-level` accepts `error`, `warn`, `info` (default), or `verbose`.
**Verbose prints the complete escaped policy once, after a disclosure warning.
Anyone with log access can read it.** This includes malformed YAML when decoding
succeeds. Invalid levels fail before disclosure. The wrapper validates shared
configuration in a trusted evaluator before parsing; final evaluation suppresses
the duplicate verbose rendering. Both evaluations use `PolicyLoader`.
Policy files should remain unchanged for the scan duration.

Environment values are not secrets: trusted host/container administrators,
Docker inspection, and runner setup logs may expose them outside scanner logs.
Do not allow submitters to configure the image, policy source, scanner code,
moderator detail, verbose level, or access policy-bearing jobs/logs.

## Stages and binding

1. Resolve the local image tag to an immutable image identity. Never pull during
   a scan. Use a trusted locally built image, not a submitter-supplied image.
2. Validate content settings, policy, log level, engine version and gates in a
   trusted container. Invalid content settings fail before policy disclosure.
3. Open final-component-nofollow regular pak/mapping files nonblocking. Bound,
   copy, hash and check metadata stability; make private copies mode 0400.
4. Mount only those copies read-only into a separate policy-free parser container.
   The ingestion worker writes generated IDs, never archive paths. After it is
   reaped, the fixed managed inspector reads those exact ephemeral payloads and
   explicit generated-ID export sidecars before cleanup. It does not require a
   `.uexp` for every inline package. Content signatures select package candidates;
   unknown, native/script/config and unpaired bulk data remain coverage gaps.
   Export pairing accounts only for unclassified raw bytes; recognized signatures
   remain gaps even when the package reads successfully using that sidecar.
5. Collect at most 8 MiB of stdout facts. Discard parser stderr; do not replay it.
   Validate the closed typed facts protocol in another trusted evaluator, including
   exact expected pak and mapping SHA256 values from the host snapshots. A hash
   mismatch or unexpected dependency fails before report evaluation/acceptance.
6. Produce the shared report and gates; atomically create the host report mode
   0600 without replacing existing files. Remove private staged copies and owned
   containers on success, failure, timeout, SIGINT and SIGTERM.

The optional `inspection` field in facts/reports preserves bounded inventory,
member SHA256, signatures, class names, optional qualified class-index identities
with provenance/completeness, sidecar state, and fixed ingestion and
inspection diagnostics, including partial inventories. No generated storage path
is transported. Metadata-only partial records can lack size/hash. Evidence remains
parser-produced and unauthenticated: hash binding prevents accidental source
substitution, **not forged findings from a compromised parser**. The parent
snapshot is read-only to the parser, not immutable against a hostile host UID.

The evaluator's existing query-specific treatment of unavailable imported
signatures is retained: exact target checks can complete while argument predicates
remain Unknown. Inventory `partial` does not automatically mean a global policy
gap for that reviewed metadata-only case. `analysis-complete` is not a safety,
native-code, reachability, dependency-closure, or moderation verdict.

## Enforced controls

Both containers use non-root host UID/GID, read-only root, read-only input mounts,
network/IPC `none`, all capabilities dropped, `no-new-privileges`, Docker's default
seccomp profile, private PID/mount/cgroup namespaces, and no host PID namespace, Docker
socket, credentials or checkout mounts. `--log-driver none` avoids daemon log
floods. No writable host output is mounted into either container.

| Control | Default |
| --- | ---: |
| Cgroup memory / swap | 1 GiB / no additional swap |
| CPU quota | 1 CPU |
| Process/thread count | 64 |
| CPU rlimit (each process) | 45 seconds |
| Each container deadline | 60 seconds (`--timeout`, greater than 0, at most 600) |
| Scratch aggregate tmpfs | 900 MiB, noexec/nosuid/nodev |
| `/tmp` aggregate tmpfs | 16 MiB, noexec/nosuid/nodev |
| Individual file rlimit | 512 MiB |
| Open descriptors / core | 128 / 0 |
| Host pak / mapping snapshot | 256 MiB / 16 MiB |
| Parser stdout / evaluator stdout or stderr | 8 MiB / 16 MiB each |

The [ingestion worker limits](ingestion.md#resource-boundary-and-defaults) still
apply, including decoded totals, expansion, per-member, journal, and write budget.
Its 512 MiB `RLIMIT_AS` applies only to Python ingestion. The managed parser needs
large virtual reservations: it uses the cgroup memory ceiling and a 512 MiB .NET
GC heap budget, **not an address-space guarantee**. Tmpfs pages count against the
cgroup; a large submission may hit memory before scratch capacity. The controls
are fail-closed ceilings, not capacity promises. CPU quota is aggregate; CPU rlimit
is per process. Each trusted validation/report stage gets a separate deadline;
there is no single whole-command deadline. Removal retries have bounded timeouts.

On gate failure the shared report is written first. Defaults are forbidden=true,
flagged=false, incomplete=true, with strict `true`/`false` values and the shared
`GateOptions` implementation. Exit 0: gates pass; 1: gate failure; 2: shared
configuration error; 3: input/runtime/transport/report failure. Operational failures
try to write a shared failed report. Docker unavailable or an unwritable report
path can prevent any report; they never become clean empty scans. Rejected
ingestion with usable facts produces a partial report, not an operational crash.

Configured content rejection or review always exits 1, even with all three gates
disabled. Content results remain separate from invocation counts and coverage.

SIGKILL, host death, Docker daemon failure, or a kernel/container escape can defeat
cleanup. The daemon is trusted; teardown is bounded and cannot prove removal when
the daemon is unavailable. Do not share this worker with credentials or valuable
data. Use an ephemeral VM for hostile/adversarial submissions, stronger tenant
separation, or where a shared-kernel/container escape is unacceptable. Docker is
not a complete sandbox.

## Build and validation

SDK, runtime and CPython base images are pinned by digest in `Dockerfile`; .NET
packages use locked restores. Only needed UAssetAPI source is copied; no engine,
game fixtures, test assets, policy, Git state or keys enter the build context.
MSBuild excludes unused native repak bindings and AC7 resources without modifying
the vendored source. No Oodle or proprietary component is downloaded. Required
CPython standard-library/native imports and Zlib are exercised during the build.
Full dependency notices and OS inventory are described in
`container/licenses/README.md`. This is an inventory, not legal certification.
Pinning does not guarantee bit-for-bit rebuilds or eliminate the need to patch
base images. No image is published by the workflow.

```bash
docker image inspect ue-pak-static-risk-analysis:dev --format '{{.Id}} {{.Config.User}}'
UE_PAK_CONTAINER_TEST_IMAGE=ue-pak-static-risk-analysis:dev \
  python3 -m unittest discover -s tests -p test_container.py -v
# Optional original cooked evidence, read-only; only copies enter generated paks:
UE_PAK_CONTAINER_TEST_IMAGE=ue-pak-static-risk-analysis:dev \
  OWNED_FIXTURE_EVIDENCE=/approved/owned-fixture-evidence \
  python3 -m unittest discover -s tests -p test_container.py -v
```

Synthetic CI needs no engine or game. Tests exercise actual local Docker
isolation, policy canaries and source/log equivalence, snapshot/member hashes,
flood/deadline/cancellation cleanup, cgroup limits, scratch exhaustion, bombs and
unknown/missing package data. Optional cooked tests compare direct evaluator and
container reports for the same normalized facts and private policy. Configured
class/path restrictions and protected-path candidate decisions use the shared
trusted evaluator. No clean-install replacement baseline or complete native type
inventory is claimed. The reusable Action does not expose content-policy flags.

Run the Docker suite without concurrent scanner jobs on the same daemon. Cleanup
assertions compare the global `pak-scan-*` inventory before and after each test;
unrelated concurrent scans can cause false failures. Tests never remove foreign
containers to satisfy those assertions.

Local validation, 2026-10-25, Linux x86-64, Docker 29.8.2 with cgroup v2:

- Local image identity:
  `sha256:d4b2e414e45614ce2111d704a3accc0c121b7a4f1436e47ea3095c72e643537d`.
  This is local build evidence, not a published registry digest.
- 111 extraction/compatibility, 91 Scanner, 110 Policy, 26 PolicyInput tests passed.
- 54 ordinary Python tests passed; 11 opt-in Docker tests skipped in that run.
  All 11 passed separately with the image and authorized owned cooked evidence.
- Parent/child/map scan: six invocations, two forbidden native calls; direct
  evaluator and Docker reports agree. Missing export data/mappings stay incomplete;
  a later corrupt member retains earlier forbidden findings.
- All 23 hashes recorded in the original owned-fixture receipt still match.
  Original cooked files were read only; generated paks/snapshots used temporary copies.
- No `pak-scan-*` containers remained after the integration suite.

### PR #25 signature-fix validation

Rebuilt locally on the same host/date; no registry publication:

- Image: `sha256:4b2346e3d74c7d6f7a16640723e067a8124972e42fbda161e00b639f42f64849`.
- 111 extraction/compatibility, 91 Scanner, 110 Policy, 26 PolicyInput tests passed.
- 54 ordinary Python tests passed; 13 opt-in Docker tests skipped in that run.
- All 13 Docker tests passed separately, serialized with owned cooked evidence.
  ELF, PE, Mach-O and shebang export sidecars retain signatures, package findings
  and incomplete coverage. Legitimate split export data still completes; script/
  config package-name hints, unknown content and bulk data retain their gaps.
- Original review repro: inline package exits 0; ELF and shebang sidecars exit 1
  with partial reports, `analysis-complete=false`, and both package invocations.
- Direct production `PackageReader.Read` checks retain two invocations and no
  global gaps for both split and inline copies of the owned parent package.
  `AssetBinaryReader.LoadUexp` must be enabled for both layouts to load exports.
- All 23 original receipt hashes still match; original evidence was read only.
- No `pak-scan-*` containers remained after the serialized suite and repro.

### Content-policy validation

Local Linux validation, 2026-10-25; no image publication or engine/game execution:

- Image: `sha256:195582570bc9c5ddf69d02a33c10c554454d95ec158ad5925385b5bf0ef3f054`
  (`ue-pak-static-risk-analysis:content-policy-local`).
- 111 extraction, 138 Scanner, 110 Policy and 26 PolicyInput tests passed.
- 111 ordinary Python tests passed; 21 opt-in Docker tests skipped in that run.
  Serialized runs passed all 17 container tests and all 19 Action tests, including
  its four Docker tests. The read-only owned cooked verifier also passed.
- Owned packages with the same virtual filename but different parsed classes
  produce different class decisions. Split/inline packages, protected candidates,
  class rejection with retained invocation findings, missing/malformed data and
  signature gaps are covered. Ordinary CI uses synthetic fixtures; original
  cooked evidence remains an authorized local opt-in, not redistributed data.
- All 495 original evidence files are byte-identical before/after validation;
  all 23 recorded receipt hashes match. No scanner containers remained.
- This validates the bounded V9 contract, not exact game-build fidelity (#2),
  native class hierarchy (#7), clean-install replacements or mod safety.
