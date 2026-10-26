# v0.1.0 base sources

This inventory conservatively covers all 69 Ubuntu source versions for the 97
installed packages and 73 Debian source versions associated with the copied
Python-stage documentation. Debian binaries outside `/usr/local` are not copied.
It also mirrors CPython 3.12.14, pip 25.0.1 and its vendored certifi 2024.8.30
(MPL-2.0). Third-party licenses remain unchanged; this is not legal certification.

`source-inventory.json` contains exact versions, official URLs, sizes and SHA-256
values: 459 files, 647,494,595 bytes. Of these, 456 files / 624,554,938 bytes cover
Ubuntu and Debian descriptors, original archives, signatures and patches. Hashes
come from fetched source descriptors and official Python/PyPI metadata. The large
archive bodies were not downloaded when this inventory was prepared.

`image-baseline.json` records an older local image using the same pinned bases,
not inspection of the new image. Its Debian copyright hashes come from the
digest-bound upstream Python SPDX inventory, not an independent signature audit.
The workflow must inspect the rebuilt image and compare the complete copied doc
tree against the exact Python stage. Unexpected paths, versions or hashes stop
validation; review/regenerate coverage rather than weakening the gate.

## Retrieve and build

From the reviewed project source checkout, on a host with Python 3.11+, network
access and at least 2 GiB free (the GitHub runner, not a disk-constrained host):

```sh
python3 scripts/collect_base_sources.py --output /approved/new-base-sources
cd /approved/new-base-sources
sha256sum --check SHA256SUMS
```

The helper downloads sequentially, uses HTTPS official-host redirect allowlists,
checks exact sizes/SHA-256, verifies each descriptor's complete file set, and
creates deterministic **uncompressed** `base-source.tar`. No source is extracted
or executed. It limits files to 128 MiB, declared/actual total to 800 MiB, socket
waits to 30 seconds and each file to approximately 300 seconds (one blocking read
may add 30 seconds). Failed attempts produce no completed output directory. A new
path is required; existing files or links are never overwritten. Root checksums
cover the archive, exact inventory bytes and these instructions. The tar contains
the same inventory, instructions and per-source-file checksums.

After obtaining the release assets, inspect the tar listing, extract into a new
directory using your normal archive tools, and check its `SHA256SUMS`. Each source
version has its own `GROUP/SOURCE/VERSION/` directory, preserving epochs. Read the
descriptor and packaging instructions before building in an isolated development
environment; upstream build scripts are executable code. Typical Debian/Ubuntu
commands (not executed by the collector):

```sh
dpkg-source -x PACKAGE_VERSION.dsc
cd EXTRACTED_SOURCE
# Install the exact Build-Depends described in the .dsc for that distribution.
dpkg-buildpackage -b -us -uc
```

Keep all `.dsc`, orig, Debian/Ubuntu patch and signature files together. Source
URLs are recorded per file; `debian-doc-sources` additionally links exact Snapshot
source pages. CPython's exact Docker recipe is linked in `image-baseline.json`;
use its configure/build instructions. pip and certifi retain their upstream source
build metadata. No package rebuild or reproducible binary digest is claimed.
The .NET runtime is MIT: its exact source and mapped runtime commit are linked in
the baseline. The SDK is a build input, not a shipped SDK. NuGet MIT source commits
are also recorded there. UAssetAPI and the original project are delivered in the
separate reviewed `source.tar.gz` A/B archive; retain all applicable notices.

## Publication gate

1. Dispatch reviewed main with `publish: false` (default). This builds/tests the
   new image and remotely downloads/hash-checks all sources, without registry login.
2. Retain and review the image/source identities, notices and inventory. Authenticated
   Actions artifacts expire in three days: **staging only, not public delivery**.
3. Only after the operator confirms private GHCR candidate visibility, dispatch
   `publish: true` with the explicit visibility acknowledgement. An existing public
   namespace could expose a push immediately; do not guess its visibility. No
   workflow changes visibility, creates a release, or publishes v0.1.0/aliases.
4. Parent prepares final A/B source, `base-source.tar`, inventory, image record,
   notices and checksums as durable assets of the authorized GitHub v0.1.0 release.
   While draft/authenticated-only, keep GHCR private. Make source assets public,
   verify anonymous downloads/hashes, then enable approved GHCR public access and
   verify the exact digest/consumer path. Link source directions next to binaries
   in the release, GHCR description and image notice.
5. Retain/maintain the exact sources for applicable GPL/LGPL/MPL obligations.
   System Library exclusions do not waive obligations for separately distributed
   utilities/libraries. GPLv3 section 6(d) is not a blanket GPLv2/LGPLv2.1 exception.
   No written-offer route or legal certification is asserted.
