# Controlled release preparation

**No release, exact tag, registry package/image, public Action, source bundle or
access change is authorized or published by this procedure.** #18 remains open
for owner decisions and publication evidence. This is a manual checklist, not a
publisher or an approval service. Existing workflows build/test locally only.

## Stop gates before any publication

Obtain explicit owner approval for the exact version, source, artifact set,
licenses/rights, destinations, audiences and publication operator. Record it in
restricted release records. Do not infer approval from a green test or merged PR.

| Surface | Required owner decision and verification |
| --- | --- |
| Repository/release/tag/source archive | Keep current visibility unless explicitly approved; enumerate source/archive rights, readers, release attachments and immutable exact tag policy |
| GHCR/other packages | Approve namespace, initial/effective visibility, inherited repository permissions and linked-repository behavior; verify intended readers before publishing any bytes |
| Actions access | Approve named consumer repositories/organizations, runner/log audiences and exact pinned commit; test authorized external consumer before declaring it usable (#13) |
| Workflow artifacts | Approve reader set, retention and storage ACL; no implicit/public upload, workspace archive or cooked fixture attachment |
| Logs/summaries/outputs | Approve all readers including admins; ordinary env is not masked; no private verbose logs or policy-bearing setup output in publish jobs |
| Credentials/permissions | Separate human-authorized publication identity/job; least privilege, no untrusted code, no policy/keys in build inputs; no automatic `packages: write` workflow |

Current private Action access is `none`; an authorized external consumer is
missing. Publication/visibility approvals have not been provided. Private registry
pull/authentication is not implemented/tested by the local-build Action. If later
approved, use the registry's managed credential store or stdin-based login, not
tokens in argv; test scoped read access and exact digest pulls in the named
consumer separately. Do not add registry credentials to parser/evaluator jobs.

## Version and immutable references

Choose SemVer `MAJOR.MINOR.PATCH` after compatibility review. Breaking CLI, YAML,
facts/report or Action contracts require a new major or an explicitly versioned
compatible extension; fixes increment patch. A release candidate is not stable
until its exact source/artifact set passes the checklist.

- Reserve `vMAJOR.MINOR.PATCH` as an immutable source tag; never move/delete/reuse
  it. Pin Actions to its full reviewed commit, not a moving tag.
- Record each **actual artifact's** SHA-256, byte size and producing source/build
  record. A Git tag does not identify arbitrary DLL bytes or a local image.
- Pin published images by registry `repository@sha256:...` manifest digest.
  Record platform and per-platform digest when an index is involved. A local
  Docker image ID is a config identity, not necessarily a registry manifest digest.
- After approval, compatible major aliases (`vMAJOR`, image `MAJOR`) advance
  alongside minor/patch releases. They are explicitly mutable discovery handles;
  exact-version tags/digests and prior release records never move. Consumers
  review new exact references and update pins on patches; aliases alone are not
  provenance or review continuity. Avoid an unqualified `latest` recommendation.

Pinned references are reproducible **identities**, not a claim of bit-for-bit
rebuilds. Timestamps, managed assemblies and OS package state may vary. Record
actual output hashes/digests and inventory for each build even from the same source.

## Prepare locally (no publication)

1. Use a clean reviewed checkout at the intended full commit. Record `git rev-parse
   HEAD`, `git status --porcelain`, `git submodule status --recursive` and
   `git diff --submodule=log`; reject dirty/missing/mismatched submodules and
   untracked build-context inputs. Record exact source/tool hashes and approval.
   Never attach a generic whole-checkout/vendor/source archive without rights
   approval (#2). Do not include Git credentials, keys, policies or environment.
2. Review `global.json`, `.gitmodules` gitlinks, `src/**/packages.lock.json`,
   project versions and all Dockerfile base **digests**. Locked restores are
   required. If distributing the separate probe, also inventory pinned repak,
   Cargo.lock and selected Rust licenses; it is not in the scanner image.
3. Review redistribution for the exact selected artifacts. Retain UAssetAPI
   license/NOTICE, Newtonsoft.Json, YamlDotNet/ZstdSharp.Port MIT, CPython and
   copied Debian notices, .NET notices and Ubuntu package copyrights. Extract
   actual `/licenses/os-packages.tsv` and accompanying notices from the built
   image for restricted review; base tags or this static list are insufficient.
   See [inventory paths](../container/licenses/README.md). No Oodle/native repak
   binding is shipped. Inventory is not legal certification.
   This checkout has no top-level source LICENSE; obtain an explicit owner
   licensing/redistribution decision before distributing project binaries or
   source archives. Private hosting is not a substitute for that decision.
4. Build only from that clean, known tracked source snapshot using the reviewed
   Dockerfile/allowlisted `.dockerignore`, with no policies/secrets or alternate
   build instructions. Retain bounded build logs, source/dependency IDs, Docker
   version, resolved base digests, build command and resulting image ID together.
   Set the local test tag to this newly built image; record the resolved ID, not
   merely `:dev`. No OCI revision label can prove an arbitrary image came from
   that source. Existing images without a trustworthy build record are
   **unverified; block release** until rebuilt and validated from clean source.
5. Run the complete release path **serially**, with authorized existing owned
   evidence; do not cook or load a game to complete this checklist:

   ```sh
   docker build -t ue-pak-release-check:local .
   IMAGE_ID="$(docker image inspect ue-pak-release-check:local --format '{{.Id}}')"
   /tmp/opencode/pak-test-venv/bin/python scripts/regression_corpus.py \
     --release --components --docker-image "$IMAGE_ID" \
     --owned-evidence /approved/owned-fixture-evidence \
     --output /tmp/opencode/new-release-check
   ```

   Output must be new, external and private. `--release` is a test-strength flag,
   **not publication approval**. Require completed receipt, no unintended skips,
   all component suites, full report parity/privacy and both removal mutations.
   Preserve exact commands/log hashes and owned receipt/verifier identities.
   Review every changed bytecode offset, identity, argument, coverage, finding,
   count and expectation before accepting it; never auto-update the oracle.
6. Prepare a **local restricted release record**, versioned as a document (no new
   packaging tool required): candidate version; source and submodule commits;
   lockfile/base-digest/inventory hashes; build record and exact image ID;
   existing artifact names/sizes/hashes; complete test receipt hash; license and
   owner-review references; remaining gates. Do not record ordinary environment,
   private absolute paths, policy text/fingerprints, credentials or engine assets.
   Store restricted opaque evidence IDs in place of private storage locations.
   Mark `prepared-only`, `publication-approved: false` until an owner acts.
   Unverified source-to-image provenance must be explicit, never relabeled as
   verified because a candidate version/source annotation was supplied.

## Separate human-approved publication (not executed)

Only after all stop gates pass may an authorized operator create the approved
immutable exact source tag and publish the individually approved artifacts/image
from the validated source/build. Verify remote exact commit, artifact hashes,
registry digest/platforms and effective access with the named consumer. Record
those *actual* remote identities, not local tag assumptions. Then advance only
the compatible major aliases, review consumers' patch pin updates, and archive
the final approval/evidence record privately. Abort on any identity/access mismatch.

No automatic publisher, registry login command, broad sharing change or
`packages: write` workflow is added here. No automatic source bundles. Never
publish game/proprietary assets, engine code/images/caches, production policies,
AES/native keys, mappings or owned cooked outputs on the strength of this guide.

## Evidence and remaining inputs

The [regression/component record](regression-corpus.md) includes the completed
local parent release-path run: `/tmp/opencode/corpus-parent-release/execution.json`,
142 Scanner, 111 extraction, 110 Policy, 26 PolicyInput and 137 serial Python tests.
This proves that recorded local gate, not publication or independent provenance
of any differently built artifact. [Owned fixture provenance](owned-fixtures.md)
is Linux UE4.25Plus, not exact Windows/game fidelity. #3/#4/#15 delivery is closed;
those completed components do not remove the gates below.

- #2: exact game/Windows producer coverage and broader redistribution rights.
- #7: authorized exact-build source/header/reflection and reviewed native summaries.
- #8–10: indirect, transitive and data/default effects remain unshipped.
- #13: owner-authorized named external private Action consumer and access test.
- #18: owner publication/version/destination/audience approval, selected artifact
  rights review and verified publication identities. No approval is supplied.

Catalog ownership and review invalidation follow [security.md](security.md#capability-ownership-and-review-invalidation)
and [#16 moderation](moderation.md); release upgrades require rescan/review of
changed context. [Runtime escalation](runtime-escalation.md) remains separately
authorized human work, never a release workflow stage.
