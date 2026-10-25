# Local builds only. No policy, engine, game files, keys, or repak native bindings.
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:747cbade5bfd918a175ac32f8f1d931edec2c7d0d5397a3de72eaef1ac1f66d2 AS build
WORKDIR /source
COPY global.json ./
COPY src/ src/
COPY vendor/UAssetAPI/UAssetAPI/ vendor/UAssetAPI/UAssetAPI/
COPY vendor/UAssetAPI/LICENSE vendor/UAssetAPI/NOTICE.md vendor/UAssetAPI/README.md vendor/UAssetAPI/
COPY container/ExcludeUnused.targets /build/ExcludeUnused.targets
RUN dotnet restore src/Parser/Parser.csproj --locked-mode \
    && dotnet publish src/Parser/Parser.csproj -c Release --no-restore -o /out/parser \
        -p:GeneratePackageOnBuild=false -p:CustomBeforeMicrosoftCommonTargets=/build/ExcludeUnused.targets \
    && dotnet publish src/Scanner/Scanner.csproj -c Release --no-restore -o /out/evaluator \
    && mkdir /out/licenses \
    && cp vendor/UAssetAPI/LICENSE /out/licenses/UAssetAPI-MIT.txt \
    && cp vendor/UAssetAPI/NOTICE.md /out/licenses/UAssetAPI-NOTICE.md \
    && cp /root/.nuget/packages/newtonsoft.json/13.0.4/LICENSE.md /out/licenses/Newtonsoft.Json-MIT.md

FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS python

FROM mcr.microsoft.com/dotnet/runtime:10.0-noble@sha256:0cf09aaccf6a9f68900aed4c73fb28fe25bb59ec85de4dea08ba02240a8635f3
# CPython built on glibc 2.36; Ubuntu 24.04 uses glibc 2.39. Required stdlib
# modules are exercised below, not assumed from copying the executable alone.
COPY --from=python /usr/local/ /usr/local/
COPY --from=python /usr/share/doc/ /licenses/python-os/
COPY --from=build /out/ /app/
COPY pak_ingest/ /app/pak_ingest/
COPY container/licenses/ /licenses/dependencies/
WORKDIR /app
RUN /usr/local/bin/python3 -c 'import hashlib,zlib,resource,subprocess,json,tempfile,selectors; assert zlib.decompress(zlib.compress(b"check")) == b"check"' \
    && dpkg-query -W -f='${Package}\t${Version}\n' > /licenses/os-packages.tsv \
    && mkdir /scratch /input /policy \
    && chmod 1777 /scratch
USER 65532:65532
ENTRYPOINT ["/usr/bin/dotnet", "/app/evaluator/Scanner.dll"]
