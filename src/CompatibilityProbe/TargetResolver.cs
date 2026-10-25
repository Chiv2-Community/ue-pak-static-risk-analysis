using UAssetAPI;
using UAssetAPI.UnrealTypes;

namespace CompatibilityProbe;

public static class TargetResolver
{
    private static readonly System.Reflection.PropertyInfo? NameIndex = typeof(FName).GetProperty("Index",
        System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
    public sealed record Identity(string Owner, string Function, int PackageIndex);

    public static string? Resolve(UAsset asset, FPackageIndex? index, string localPackage)
    {
        var identity = ResolveIdentity(asset, index, localPackage);
        return identity is null ? null : identity.Owner + ":" + identity.Function;
    }

    public static Identity? ResolveIdentity(UAsset asset, FPackageIndex? index, string localPackage)
        => ResolveIdentity(asset, index, localPackage, false);

    internal static Identity? ResolveDataIdentity(UAsset asset, FPackageIndex? index, string localPackage)
        => ResolveIdentity(asset, index, localPackage, true);

    // Pinned FName.ToString invents "null" for absent storage. Dummy names with real
    // values are supported; literal "null", NAME_None and instance suffixes stay intact.
    internal static string? StoredName(FName? name)
    {
        if (name?.Value?.Value is null) return null;
        // GetNameReference also invents numeric text for out-of-range indices.
        // Index is internal in the pinned API; an unknown layout fails closed.
        if (!name.IsDummy && (NameIndex?.GetValue(name) is not int index || index < 0
            || name.Asset is null || index >= name.Asset.GetNameMapIndexList().Count)) return null;
        return name.ToString();
    }

    private static Identity? ResolveIdentity(UAsset asset, FPackageIndex? index, string localPackage, bool requireStoredNames)
    {
        try { return ResolveCore(asset, index, localPackage, requireStoredNames); }
        catch (Exception error) when (error is not OutOfMemoryException) { return null; }
    }

    private static Identity? ResolveCore(UAsset asset, FPackageIndex? index, string localPackage, bool requireStoredNames)
    {
        if (index is null || index.Index == 0)
            return null;

        var names = new List<string>();
        var seen = new HashSet<int>();
        var current = index.Index;
        var local = current > 0;
        var characters = 0;
        while (current != 0)
        {
            if (!seen.Add(current) || seen.Count > 256)
                return null;

            if (current < 0)
            {
                // Widen before negation so int.MinValue cannot wrap into an index.
                var position = -(long)current - 1;
                if (position >= asset.Imports.Count)
                    return null;
                var import = asset.Imports[(int)position];
                if (import is null || import.ObjectName is null || import.OuterIndex is null)
                    return null;
                var name = requireStoredNames ? StoredName(import.ObjectName) : import.ObjectName.ToString();
                if (name is null) return null;
                names.Add(name);
                current = import.OuterIndex.Index;
            }
            else
            {
                var position = current - 1;
                if (position >= asset.Exports.Count)
                    return null;
                var export = asset.Exports[position];
                if (export is null || export.ObjectName is null || export.OuterIndex is null)
                    return null;
                var name = requireStoredNames ? StoredName(export.ObjectName) : export.ObjectName.ToString();
                if (name is null) return null;
                names.Add(name);
                current = export.OuterIndex.Index;
            }
            characters += names[^1].Length + 1;
            if (characters > 4096)
                return null;
        }

        names.Reverse();
        if (local)
        {
            if (characters + localPackage.Length + 1 > 4096) return null;
            names.Insert(0, localPackage);
        }
        if (names.Count < 2)
            return null;
        return new Identity(string.Join('.', names.Take(names.Count - 1)), names[^1], index.Index);
    }
}
