# Bounded V9 ingestion foundation (#3)

`python3 -m pak_ingest archive.pak` emits JSON ingestion evidence. Exit 0 means
the narrow ingestion checks passed, not that the archive is safe. Exit 1 means
ingestion failed. `analysis_complete` is always false: parsed class inspection
and invocation extraction are deferred to #4. Keep #3 open until that integration
is delivered. This is not the shared CLI/report contract planned in #11.

## Scope and evidence

- Python standard library only. Linux is required; unavailable resource support
  fails closed. No unchanged repak CLI is used as a security boundary.
- Ordinary sequential V9 index, 222-byte footer, ASCII FString paths, unencrypted
  None (entry compression index 0) and explicitly named `Zlib` blocks only.
  Negative FString lengths, frozen indices, encryption GUIDs/flags, delete flags,
  unknown flags, unknown codec names and slots, and other versions are rejected.
  A named `None` footer slot is recognized but cannot serve as compressed data.
- Index SHA1, counts, string/block bounds, local header equality (local offset
  must be zero), contiguous relative block layout, exact index termination,
  member ranges, overlap, size, expansion and output limits are checked.
- Entry SHA1 covers **stored payload bytes**, including compressed bytes, matching
  pinned repak's writer. SHA256 covers the input snapshot and each decoded member.
  SHA1 here detects corruption; it is not an authenticity guarantee.
- Zlib decoding is streaming with `max_length`; each block must produce its exact
  expected output, reach EOF, and consume all input. Trailing bytes, concatenated
  streams, incomplete streams, and inconsistent sizes fail closed.
- Raw index order and supported raw names are retained as records with generated
  IDs, not collapsed into a map. Metadata/progress is journaled before extraction.
  Failures retain available input hash, records, statuses and fixed diagnostics;
  abrupt death may leave only a prefix of that evidence. A missing hash is not a
  hash of a partial input. No raw exception text, input path, payload or environment
  is logged. Manifests intentionally contain archive-supplied names and metadata.

The parser follows `vendor/repak/repak/src/{footer,entry,data}.rs` at pinned repak
commit `355b5f62f51959c7cc6dd5a51708646ef483065d`. That implementation discards
duplicate index names in a `BTreeMap`, lacks the required metadata interface, and
allocates unbounded buffers. The new reader does not modify the submodule or the
trusted-input compatibility probe in `scripts/probe_pak.py`.

## Paths and classification

- Mount `../../../` is explicitly allowed as a literal virtual prefix, optionally
  followed by safe directory components and `/`. It is never normalized onto a
  host path. All other traversal, absolute paths, empty/dot components, backslashes,
  Windows reserved punctuation, control/non-ASCII characters, device aliases, and trailing
  dots/spaces are rejected.
- Exact duplicates, ASCII case collisions and file/directory prefix conflicts
  fail before **any payload file** is created. Snapshot/journal files are allowed
  before validation. Payloads use generated `r00000000`-style IDs only, with
  exclusive nofollow opens, mode 0600, inside a private mode-0700 directory.
- `ingest(..., namespaces=(...), protected=(...))` accepts trusted configurable
  component-boundary virtual prefixes, without a hardcoded game namespace.
  Protected-prefix matches are replacement **candidates**, not verified changes:
  there is no clean-install baseline or load-order analysis.
- Sidecars (`uexp`, `ubulk`, `uptnl`) map to same-stem `uasset`/`umap` records;
  orphans are explicit. Package required-sidecar status remains unresolved until
  package-summary inspection in #4. An inline package need not have a `uexp`.
- Up to 64 KiB of decoded content is examined regardless of extension for a
  bounded validated PE header, ELF/Mach-O magic, Unreal package tag and shebang.
  Script/config extensions produce candidate findings only. No recognized content
  signature means `unknown_content`, including ordinary text. A PE header beyond
  that prefix remains unknown. These are identification hints, not execution,
  authenticity checks, full binary validation, parsed classes or benign verdicts.

`payload_verified` means exact decoding and stored SHA1 passed. It does not mean
class inspection completed. Unknown, rejected and uninspected records cannot
produce `analysis_complete=true`. Even all-known records currently cannot.

## Resource boundary and defaults

The supervisor starts only the dedicated Python worker, in a new process session,
using isolated Python mode, closed inherited descriptors and a fixed `LANG`/
`LC_ALL` environment. It passes no policy or inherited credentials. The worker
does not spawn subprocesses. Cancellation/timeout kills the full process group,
reaps the worker, collects available evidence, and removes the controlled
`TemporaryDirectory`. Outputs are ephemeral: the public API returns evidence, not
member paths. A future inspector must run against this same private snapshot and
payload set before cleanup, rather than reopen the original archive.

The input must be a regular final-component-nofollow file. It is copied once with
a streaming input quota, checked for metadata changes during copying, SHA256
hashed, closed for writes, and chmod 0400. Parsing and extraction use only that
private read-only copy; later changes/replacement of the original do not change
the analyzed bytes. This is not kernel-enforced immutability against another
hostile process running as the same UID.

| Limit | Default |
| --- | ---: |
| Input | 256 MiB |
| Index | 16 MiB |
| Records | 10,000 |
| FString bytes including NUL | 1,024 |
| Compression blocks across archive | 65,536 |
| Decoded member | 128 MiB |
| Total decoded output | 512 MiB |
| Member expansion ratio | 200:1 (denominator at least 1 byte) |
| Cumulative worker scratch writes | 800 MiB |
| Evidence journal | 16 MiB |
| Wall time | 30 seconds |
| CPU (`RLIMIT_CPU`) | 20 seconds |
| Address space (`RLIMIT_AS`) | 512 MiB |
| Individual file (`RLIMIT_FSIZE`) | 512 MiB |
| Open descriptors (`RLIMIT_NOFILE`) | 32 |
| Core dump | 0 |

Trusted callers can supply a validated immutable `Limits` object. Scratch write
accounting covers the snapshot, every decoded payload write, and every journal
write, including failed/partial write attempts. A 512-byte reserve allows terminal
failure evidence when ordinary writes hit a budget. Journal growth also has a
separate hard application limit. Resource death can still prevent final reporting;
the supervisor then reports a fixed failure and preserves earlier complete events.

The report records the configured storage allowance and the worker write budget.
**`RLIMIT_FSIZE` is per-file, not an aggregate disk quota.** The application write
budget is enforced for every worker-created file, but this is not an OS aggregate
quota or reservation. Run scratch on a deployment-managed quota-backed volume
before claiming a hard host-storage boundary against a compromised worker.

Linux rlimits, a private directory, and a scrubbed environment are **not a VM or
container sandbox**. They do not isolate the network, filesystem, UID, syscalls,
or Python interpreter. This code does not execute archive content, but interpreter
or decompressor compromise is outside this boundary. Container/stronger isolation,
network denial and an aggregate OS quota remain future #12 work. Do not label this
foundation production-ready hostile-code containment.

## Validation

Run `python3 -m unittest discover -s tests -v`. Existing CI discovery includes the
new tests without workflow changes. The owned deterministic V9 builder generates
fixtures in temporary directories; no engine, game assets or downloads are needed.
Negative mutations recompute index hashes to reach structural checks. Tests cover
duplicate/path conflicts, flags/codecs, headers/ranges/blocks, exact decoding,
hashes, quotas, snapshot identity, cancellation/timeout, full-group termination,
environment/secret canaries, and cleanup. If the existing pinned binary is present
at `/tmp/opencode/ue-pak-repak/target/release/repak`, a positive differential checks
synthetic None/Zlib output; otherwise that optional test is explicitly skipped.

These synthetic cases do not establish broad UE4.25/game compatibility. Owned
cooked-package fixtures/provenance (#2) and parsed-class integration (#4) remain
separate required evidence.
