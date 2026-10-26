# v0.1.0 release preparation

The owner authorized original project code under GPL-3.0-only, a public GitHub
v0.1.0 release, and a public Linux amd64 image at
`ghcr.io/chiv2-community/ue-pak-static-risk-analysis:v0.1.0`.
Third-party licenses remain unchanged. This checkout prepares that release;
**no image digest, publication, public pull or final tag is claimed verified**.
Only the parent operator publishes after review and green CI. No major/latest
aliases, billing changes or unrelated access changes are part of this release.

## Two source identities, no digest cycle

1. Review/merge core commit **A**: GPL, Docker notice copies, host support,
   packaging, tests and the manual candidate workflow. No `action-image.json`
   is checked in yet. The source-only Action retains its development build.
2. After independent review, green CI and full local release validation, dispatch
   `release-candidate.yml` on main at exactly A. The workflow has no source-ref
   input; it checks out `github.sha`, builds Linux amd64, runs the serial public
   component/Docker/Action/regression mutation gate, then transfers the validated
   image to a separate `packages: write` job. Only that job logs in, using token
   stdin and an isolated Docker config. It publishes `sha-<full-A>`, not v0.1.0.
   Dispatch is an operator publication action, never automatic on push/PR.
3. Verify effective GHCR visibility and an **unauthenticated** public pull from
   an empty Docker config. Initial packages can be private: do not claim public
   access from a successful authenticated publisher push. The parent owns the
   expressly authorized public-package setting and remote digest verification.
4. Commit **B** adds root `action-image.json` with exactly four keys:
   `version` = `v0.1.0`, `platform` = `linux/amd64`, `build-source` = full A,
   and `image` = canonical approved repository `@sha256:` registry digest.
   Do not insert a placeholder production digest. This trusted Action-commit
   assertion is not self-authenticating provenance. Verify it against the actual
   build/run and registry record. B may change only host/Action/docs outside
   image inputs. The source-bundle helper rejects any changed Docker input.
5. Review B, rerun CI and verify a clean public consumer: prepare pulls rather
   than builds, validates RepoDigests/platform, then scans using the same digest.
   No Git checkout, .NET SDK, NuGet, Cargo, registry login, package-write permission
   or private Docker config is needed by the released consumer. Python 3.11+,
   `/usr/bin/docker`, local socket and Linux amd64 remain required.
6. Generate the final corresponding-source archive from exact A+B Git objects,
   not the workspace; verify hashes, exclusions and unpacked non-Git build.
   Publish that archive, build/source inventory and checksums with the GitHub
   release. Tag v0.1.0 at B; label the image revision **A**, never B. Promote the
   already validated digest to image tag v0.1.0 without rebuilding. Verify both
   remote exact identities. Never move/reuse v0.1.0 after publication.

`action-image.json` is outside every Docker COPY input and excluded by the
allowlisted `.dockerignore`. Changing B's pin cannot change A's image payload.
Candidate workflow artifacts contain only the validated image, allowlisted source,
checksums and bounded public build record. They do not contain test logs/reports,
owned cooks, private policies, credentials or environment dumps. Retention is
three days; download and retain the approved records before they expire.

## Source and licenses

Root [LICENSE](../LICENSE) contains the full GPLv3 text; original code is version
3 **only**, not "or later". See [license review](../container/licenses/README.md)
and [source/build instructions](../container/CORRESPONDING-SOURCE.md).
The 35,149-byte text was compared byte-for-byte with
`https://gnu.org/licenses/gpl-3.0.txt`; SHA-256 is
`3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`.

The packaging helper reads only exact committed objects from an explicit tracked
`container/source-files.txt` inventory and the pinned UAssetAPI library revision.
It rejects symlinks, missing required inputs, mismatched gitlinks, changed image
inputs between A/B, and oversized files. Its deterministic tar metadata and
SHA-256 inventory are not a claim of reproducible binary digests. It includes
the library's exact C# sources/csproj, LICENSE, NOTICE.md and README.md, not its
borrowed fixtures, key/resource table or native binaries. Excluded resources
are removed by the existing scanner build target. It never uses a generic
Git archive with an omitted submodule.

Local preparation only (replace A/B and paths with approved actual values):

```sh
python3 scripts/source_bundle.py --build-source FULL_COMMIT_A --action-source FULL_COMMIT_B \
  --uasset-repository vendor/UAssetAPI --output /approved/new-source.tar.gz
```

Retain the original unmodified upstream notices. Inspect actual NuGet DLLs,
CPython/.NET/base-OS notices and exact installed package versions from the **new**
image. Retain applicable exact-version base component source records/availability;
generic source links do not complete that check. Do not publish until source
delivery and redistribution obligations for the selected artifacts are met.
No engine source, game assets, mappings, AES/native keys, cooked binaries or
production policies may enter the source bundle or public artifacts.

## Serial release gate

Before publication, the parent builds the changed Dockerfile from reviewed A
and runs the complete release path with authorized existing owned evidence:

```sh
docker build -t ue-pak-release-check:local .
IMAGE_ID="$(docker image inspect ue-pak-release-check:local --format '{{.Id}}')"
.venv/bin/python scripts/regression_corpus.py --release --components \
  --docker-image "$IMAGE_ID" --owned-evidence /approved/owned-fixture-evidence \
  --output /approved/new-release-check
```

`--release` selects test strength, not publication authority. Require all component
suites, full report/privacy parity and all removal mutations, with no unintended
skips. CI's public synthetic gate does not replace the separately authorized
owned-evidence gate. Preserve owned files and receipt hashes; do not cook, restore
unknown deleted paths, or publish owned evidence. Existing images do not validate
the new license COPY instructions. Never infer source provenance from labels alone.

Record A/B/UAssetAPI commits, actual image ID and registry digest, platform, run
identity, Docker version, base digests, lockfile/license/inventory hashes, archive
bytes/hash, test receipts and actual public consumer result. Keep private evidence
outside the public build record. The parent retains review/merge/publication control.

## Remaining limits

This remains bounded partial static analysis, not malware absence or approval.
Linux UE4.25Plus owned cooks do not prove exact Windows/game producer fidelity
([compatibility](compatibility.md), #2). Exact-build native implementation analysis,
exhaustive indirect dispatch, complete call chains and effective data/default
behavior remain incomplete (#7–10). Public GHCR publication does not establish
the historical named private-Action access gate (#13). Runtime escalation remains
[separately authorized human work](runtime-escalation.md). PR #37 is held and
excluded from this v0.1.0 baseline.
