# Corresponding source and build instructions

Original project code: Copyright (C) 2026 UE pak static-risk-analysis contributors.
Licensed under GNU GPL version 3 only (SPDX: GPL-3.0-only), not "or later".
No warranty. See `/app/licenses/ue-pak-static-risk-analysis-GPL-3.0-only.txt`.
Third-party copyright, licenses and notices remain unchanged; see
`container/licenses/README.md` in source and `/licenses/dependencies/README.md`.

Repository: https://github.com/Chiv2-Community/ue-pak-static-risk-analysis
Release source: https://github.com/Chiv2-Community/ue-pak-static-risk-analysis/releases/tag/v0.1.0

Publication requires the operator to attach the reviewed corresponding-source
archive and check its hashes. Do not distribute the candidate without that source.
The release must retain source alongside the image, with equivalent access, under
GPLv3 section 6(d). This notice is informational, not a substitute for delivery.

The source archive includes original runtime/host sources, schemas, build scripts,
locked NuGet inputs, Dockerfile with pinned bases, this notice and the exact pinned
UAssetAPI library sources with LICENSE, NOTICE.md and README.md. It excludes upstream
fixtures, native repak binaries, key/resource data, Git metadata and all game/engine
outputs. UAssetAPI sources remain under their original licenses. No repak/Rust,
Oodle, engine SDK, game assets, mappings or production policy is required to build.

`SOURCE-MANIFEST.json` records per-file SHA-256/size, UAssetAPI revision,
actual image build commit A and final host Action commit B. The image's OCI revision
names A; the release tag names B. B may not change any Docker COPY input. The
manifest is an inventory assertion, not authenticated provenance by itself.

From the unpacked archive root, with Docker on Linux amd64 and public network:

```sh
docker build --platform linux/amd64 -t ue-pak-static-risk-analysis:source .
```

No Git checkout or submodule initialization is needed in the unpacked tree.
The build restores exact packages from public NuGet using checked-in lockfiles;
it does not download game/engine/native codecs. .NET SDK 10.0.100 selection is in
`global.json`; all three base image digests and target frameworks are in source.
Use the release build record for OCI labels and exact tool/base inventories.
Identical source inputs do not promise byte-identical assemblies or image digests.

Base OS, .NET, CPython and NuGet dependencies are separately supplied components;
retain their licenses and any applicable source obligations. For base source,
follow the exact image versions/digests in Dockerfile and the release inventory:
https://github.com/dotnet/dotnet-docker and https://github.com/docker-library/python.
Ubuntu source packages: https://archive.ubuntu.com/ubuntu/pool/ ; Debian source
packages: https://deb.debian.org/debian/pool/ . Match installed versions from the
image inventories and retain required source with the release where applicable;
do not treat these generic links as a completed exact-version source delivery.
CPython: https://github.com/python/cpython ; .NET: https://github.com/dotnet/runtime.
NuGet sources/versions: Newtonsoft.Json 13.0.4
(https://github.com/JamesNK/Newtonsoft.Json), YamlDotNet 18.1.0
(https://github.com/aaubry/YamlDotNet), ZstdSharp.Port 0.8.1
(https://github.com/oleg-st/ZstdSharp). Content hashes are in the lockfiles.
