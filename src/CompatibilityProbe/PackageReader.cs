using UAssetAPI;
using UAssetAPI.UnrealTypes;
using UAssetAPI.Unversioned;

namespace CompatibilityProbe;

public static class PackageReader
{
    public static UAsset Read(string path, Usmap? mappings)
    {
        // The upstream path helper opens .uexp with read/write access. Never use
        // it for mounted moderation inputs; assemble its documented stream layout.
        var sidecar = Path.ChangeExtension(path, ".uexp");
        return Read(path, File.Exists(sidecar) ? sidecar : null, mappings);
    }

    // Explicit generated payload IDs, never archive-supplied filesystem paths.
    public static UAsset Read(string path, string? sidecar, Usmap? mappings)
    {
        var separate = sidecar is not null;
        using var combined = new MemoryStream();
        using (var package = File.OpenRead(path))
            package.CopyTo(combined);
        if (separate)
        {
            using var exportData = File.OpenRead(sidecar!);
            exportData.CopyTo(combined);
        }
        combined.Position = 0;
        var asset = new UAsset(EngineVersion.VER_UE4_25, mappings)
        {
            FilePath = path,
            UseSeparateBulkDataFiles = separate
        };
        using var reader = new AssetBinaryReader(combined, separate, asset);
        asset.Read(reader);
        return asset;
    }
}
