# Runtime inventory

- Original scanner/host code: GPL-3.0-only, `/app/licenses/ue-pak-static-risk-analysis-GPL-3.0-only.txt`.
  Source/build instructions: `/app/licenses/CORRESPONDING-SOURCE.md`.
- UAssetAPI b4e8a012939295a6fd890ddc64e57ea78b709b95: MIT; full license and
  adopted BSD/Apache/MIT notices are in `/app/licenses`.
- Newtonsoft.Json 13.0.4: MIT, `/app/licenses/Newtonsoft.Json-MIT.md`.
- YamlDotNet 18.1.0 and ZstdSharp.Port 0.8.1: MIT, adjacent `MIT.txt`.
  Versions and package content hashes are locked in `src/**/packages.lock.json`.
- CPython and copied Debian notices: `/licenses/python-os` and
  `/usr/local/lib/python3.12/LICENSE.txt`.
- .NET runtime: `/usr/share/dotnet/LICENSE.txt` and
  `/usr/share/dotnet/ThirdPartyNotices.txt`.
- Ubuntu packages: `/licenses/os-packages.tsv`, `/usr/share/doc/*/copyright`.

No engine/game assets, Oodle, repak native binding, or AES key resource is shipped.
UAssetAPI's original notices are retained even for excluded components.
This inventory is not legal certification or permission to redistribute inputs.

## GPLv3 compatibility review for this build

Review inputs: pinned UAssetAPI `UAssetAPI.csproj`, `LICENSE`, `NOTICE.md`, its
302 C# source files and resource exclusions; Parser/Scanner lockfiles; Dockerfile.
Release builds do not define ADDTRACING, so the conditional proprietary PostSharp
diagnostics dependency is not restored or shipped. Release locks contain only
Newtonsoft.Json 13.0.4, YamlDotNet 18.1.0 and ZstdSharp.Port 0.8.1 as NuGet runtime
packages; test-only packages are not published. Check the actual published DLL
inventory before release rather than inferring this from dependency declarations.

- The three runtime NuGet packages use MIT, compatible with combining under
  GPLv3 while retaining their notices. UAssetAPI's top-level MIT does not erase
  its adopted-code notices: dotmore/Json.NET/repak MIT, ZstdNet/zstd BSD-3-Clause,
  and CUE4Parse/UEAssetToolkitGenerator Apache-2.0 notices remain in NOTICE.md.
- MIT, BSD-3-Clause and Apache-2.0 permit this GPLv3 combination. Apache-2.0's
  notice/change-marking and patent-termination terms still apply; this is not
  a patent clearance opinion. No extra GPL linking exception is asserted.
- .NET's MIT runtime and third-party notices, CPython's PSF/derived notices,
  Debian notices copied with Python, and Ubuntu OS package copyrights remain
  separate. Do not replace them with the project's GPL. GPL/LGPL OS components
  have their own applicable source obligations; retain exact base digests and
  installed package/source versions for the distributed image. Generic upstream
  URLs alone are not proof those obligations have been met.
- Native repak bindings, AC7 key resource and resource table are excluded by
  `ExcludeUnused.targets`; repak CLI/Rust, native Oodle and Unreal Engine are not
  image dependencies. No engine/game redistribution permission is inferred.

The Docker build checks that CPython and .NET license/notice files survive the
multi-stage copy, keeps `/usr/share/doc`, and writes actual Ubuntu versions to
`/licenses/os-packages.tsv`. The Python stage's Debian notices are separately
copied to `/licenses/python-os`. Before publishing, extract/check these paths,
the actual app DLL list and base-image source records. Record their hashes in
the release build record. This source review is not an independent audit, legal
certification, patent assurance or a substitute for exact-image inspection.
