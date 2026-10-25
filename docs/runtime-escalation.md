# Manual runtime escalation

Supplementary human review, **not a safety verdict or scanner/Action stage**.
Issue #17 authorizes this runbook and a trusted local canary, **not live VM
deployment, credentials, network access, or execution of a submitted mod**.
The steps below are a checklist for a separately authorized future exercise.
No workflow automatically opens content in an editor or game.

## Decide and hand off

Escalate flags/forbidden findings, incomplete coverage, unresolved dispatch,
unsupported formats, unexpected native code, suspicious exploit indicators,
or content whose tools/parsers cannot safely settle the question. A clean
static report does not remove parser or engine exploit risk for data-only assets.
Record the question, reviewer, owner, authorization scope, stop conditions,
time/resource budget, and unresolved findings before any runtime work.

Use the [moderation handoff contract](moderation.md); this document does not
define an alternative approval format. Retain the exact report required by
`moderation.py verify --report`, not just its aggregate counts.
Keep its artifact/report/context binding and restricted policy reference intact.

- FModel/UAssetGUI can help *static manual inspection*, but opening content still
  exercises potentially flawed parsers. Use disposable isolation for these too.
- Unreal Editor/game loading can execute behavior as well as parse content.
  Never treat an editor preview as passive inspection.
- Reconstructed assets and pseudocode are not authoritative cooked bytecode;
  names, defaults, control flow, and omitted behavior can differ. Retain original
  bytes and relate every observation back to them.
- Native binaries require native-code review; never auto-load or execute them
  just to complete a content review. Stop and obtain separate authorization.
- Optional AV/YARA results supplement, never replace, static/native/manual review.
- Source submission and platform-controlled cooking improve provenance and
  reproducibility, not safety of either source or cooked behavior.

## Prepare a disposable environment (future authorization required)

1. Record exact hypervisor, immutable base image and snapshot identifiers/hashes,
   guest OS patches, engine/game build, tool versions/revisions, and authorized
   asset/dependency set. Use only legally authorized engine/game/assets. A Linux
   surrogate or different engine/game build is not exact target coverage.
2. Create a fresh disposable VM from the recorded clean snapshot for **each
   original artifact**. Do not carry saves, caches, registry/config, or other
   persistent state between submissions. Re-test variants from a new reset.
3. No personal, production, cloud, GitHub, SSH, agent, or scanner credentials.
   No production access, writable host mounts, shared folders, clipboard, host
   integration channels, or attached host disks. Disable unnecessary guest agents.
   Do not use a credentialed CI runner as the runtime host. Docker alone is not
   this VM boundary, nor proof against parser/engine/hypervisor escape.
4. Deny egress by default at the hypervisor/network boundary, including DNS and
   metadata endpoints. No bridge/NAT to production or the Internet. Only if
   separately approved, allow explicit destinations/protocols in an isolated
   controlled observation network; record rules, capture, and denied attempts.
   An observation sink must not forward traffic. Missing connectivity is a
   test limitation, not permission to enable unrestricted access.
5. Install/verify monitoring before introducing content. Fix a bounded observation
   window, CPU/memory/disk ceilings, and shutdown deadline. Validate monitors with
   a benign canary in that environment before any separately authorized mod test.
   Keep independent hypervisor-side observation where possible: a compromised
   guest can lie, suppress logs, or tamper with guest monitoring.

## Observe, compare, stop

Take a no-mod baseline with the exact build/config and same planned actions.
Record clock basis and monitor configuration, gaps, drops, and time bounds.

| Surface | Baseline and comparison evidence |
| --- | --- |
| Files | Bounded file inventory/hashes and write/delete/rename events; saves, config, caches, startup/persistence locations |
| Processes | Parent/child identities, start times, executable hashes, unexpected children/loads; do not dump credential-bearing environments |
| Network | Independent connection/DNS/packet metadata, endpoints and denied attempts; keep capture restricted and bounded |
| Resources | CPU, memory, disk growth, hangs, restarts, crashes/dumps and monitor losses |
| Game | Actions exercised, relevant visible behavior, save/config changes; exact observation duration and paths not exercised |

Introduce only the hash-verified original artifact plus recorded dependencies
through a controlled read-only transfer. Do not substitute reconstructed assets.
Stop on unexpected native loads, isolation/monitor failure, budget breach,
unexpected access, or exploit/crash signals. Preserve evidence before destroying
the guest if safe; never relax isolation to make a failing submission work.

## Evidence and confidentiality

Use the #16 handoff record, not a new approval channel. Attach:

- Original pak SHA-256, each dependency SHA-256, original report SHA-256 and scan
  status/coverage, tool revision, and **opaque restricted policy revision**.
  Do not publish private policy rules, descriptions, or policy content hashes as
  an ad hoc replacement for that reference.
- Reviewer/authorization reference, question, UTC start/end, snapshot/image/build
  identifiers, monitored actions, baseline IDs, budgets, network rules, tool
  configurations, observed changes, missing coverage, stop reason, and limitations.
- Output manifest: evidence IDs, SHA-256 and byte size of each bounded export,
  collector/source, collection/export times, custodians/transfers and storage ACL.
  Preserve originals read-only in restricted quarantine; hash again after transfer.
  Hashes bind bytes, not authenticity of malicious guest claims.

Evaluate policy only in the trusted environment outside the guest. Do not place
production policy, policy environment variables, verbose policy output, or agent
credentials in the runtime VM. Verbose policy logging is never required here;
if an authorized operator needs it elsewhere, use restricted operator-only logs.

Treat guest logs, crash dumps, screenshots, filenames and exports as hostile.
Export only bounded allowlisted evidence over a controlled read-only path, not
shared writable folders. Do not open raw logs/dumps/assets with host parsers,
render guest markup, execute attachments, or paste guest text into a shell or CI
command channel. Review in a separate disposable viewer; release only sanitized,
bounded summaries through the moderation process. Keep raw evidence restricted.

## Reset and disposition

- Stop the VM and verify from the hypervisor that it is off; terminate residual
  processes/devices. Remove exercise disks/clones, saved memory, temporary
  snapshots and exports outside retained quarantine; retain only the recorded
  clean base snapshot. Verify no writable submission state survives.
- Remove temporary adapters, observation sinks, routes/firewall exceptions and
  captures; verify network rules return to deny-default. Verify no shared mounts,
  clipboard/agent channels, or host files remain. Record teardown checks/failures.
- If escape or host compromise is suspected, stop reuse and escalate host incident
  response; a guest reset is insufficient. Do not declare cleanup complete on error.
- Update human review with findings and remaining uncertainty. **A clean run never
  automatically approves a submission or clears static findings.** Delayed and
  conditional behavior, unexecuted paths, incomplete coverage, native boundaries,
  parser/engine vulnerabilities and guest/hypervisor escape remain possible.

## Trusted local canary (no VM or game)

From the repository root, on Linux with Python 3.11+ and readable procfs:

```bash
python3 scripts/escalation_canary.py
python3 -m unittest discover -s tests -p test_escalation_canary.py -v
```

The first command runs exactly one original, fixed Python child with an empty
environment and isolated Python imports; no mod, policy, shell, arbitrary command,
or path input is accepted. It writes two small distinct files in an exclusive
temporary directory, opens one TCP connection to a strict `127.0.0.1` dynamic-port
listener, then waits for the observer's release. No external requests are made.
The observer compares an empty baseline to actual bytes/hashes, checks child
PID/parent/start time via `/proc`, and matches the established loopback endpoint
to a socket inode in that child's fd table and `/proc/net/tcp`. Child stdout and
self-reported events are not evidence. Reads, waits, child CPU/memory/file limits,
and output are bounded; files, sockets and child are cleaned on success, error,
timeout, SIGINT and SIGTERM. SIGKILL/host failure cannot guarantee cleanup.

A successful bounded JSON stdout receipt contains only generated allowlisted
facts and cleanup status; it is **trusted-local-observer-only**. Exit 1 means
failed/cancelled observations (including unavailable procfs); exit 2 rejects
arguments. No receipt file option exists, so the script cannot overwrite an
artifact or follow a caller-selected output path. If saving stdout, use a new
restricted file without clobbering existing evidence. Never feed guest input to
this script. No privileged tracing, Docker, dependency install or live VM is used.

This validates only local file/network/process observer components. It does not
validate VM isolation, egress enforcement, hostile code containment, game/engine
behavior, crash/resource/save/config monitors, or hypervisor teardown. The child
shares the observer UID/kernel; this is **not** a sandbox. No untrusted runtime
exercise has been performed by these commands. A future separately approved VM
exercise must validate those missing controls and record its own evidence.

## References

- [Issue #17 scope](https://github.com/Chiv2-Community/ue-pak-static-risk-analysis/issues/17)
- [Docker isolation/resource options](https://docs.docker.com/engine/containers/run/)
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [Cooked reconstruction limits (pinned)](https://github.com/LongerWarrior/UEAssetToolkitGenerator/blob/4e30eb55087228e8018fe14aeed65d2a34af3688/README.md)
- [Pseudocode accuracy warning (pinned)](https://github.com/Krowe-moh/BlueprintToCpp/blob/c42cbd4074c8097dfa15a22580efe615f1194a49/README.md)
