using System.Reflection;
using System.Text.Json;
using CompatibilityProbe;
using UAssetAPI;

// Mutate copies only; offsets come from the pinned reader's parsed tables.
internal static class ClassOwnership
{
    public static int WriteFixtures(string evidence, string output)
    {
        var path = Path.Combine(evidence, "tagged/OwnedFixtures/Content/Data/OwnedData.uasset");
        var original = File.ReadAllBytes(path);
        var asset = PackageReader.Read(path, null);
        int Offset(string name) => (int)typeof(UAsset).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(asset)!;
        var importOffset = Offset("ImportOffset");
        var exportOffset = Offset("ExportOffset");
        var classIndex = asset.Exports[0].ClassIndex.Index;
        var classPosition = -classIndex - 1;
        var ownerIndex = asset.Imports[classPosition].OuterIndex.Index;
        if (classIndex >= 0 || ownerIndex >= 0 || asset.Exports.Count != 1) throw new InvalidDataException();
        Directory.CreateDirectory(output);
        var cases = new[] {
            ("valid-import", -1, 0, "/Script/OwnedFixtures.FixtureData"),
            ("owner-cycle", importOffset + 28 * (-ownerIndex - 1) + 16, ownerIndex, (string?)null),
            ("ownerless", importOffset + 28 * classPosition + 16, 0, null),
            ("owner-out-of-range", importOffset + 28 * classPosition + 16, int.MinValue, null),
            ("null-class", exportOffset, 0, null),
            ("class-out-of-range", exportOffset, int.MaxValue, null),
            ("valid-local", exportOffset, 1, "/Game/Ownership.OwnedData"),
            ("local-owner-cycle", exportOffset + 12, 1, null),
            ("local-owner-out-of-range", exportOffset + 12, int.MaxValue, null),
        };
        foreach (var (name, offset, value, expected) in cases)
        {
            var bytes = (byte[])original.Clone();
            if (offset >= 0) BitConverter.GetBytes(value).CopyTo(bytes, offset);
            if (name.StartsWith("local-owner-", StringComparison.Ordinal)) BitConverter.GetBytes(1).CopyTo(bytes, exportOffset);
            var target = Path.Combine(output, name + ".uasset");
            File.WriteAllBytes(target, bytes);
            File.Copy(Path.ChangeExtension(path, ".uexp"), Path.ChangeExtension(target, ".uexp"), false);
            // The same public reader used by the production parser must preserve the mutation.
            var parsed = PackageReader.Read(target, null);
            var identity = TargetResolver.ResolveIdentity(parsed, parsed.Exports[0].ClassIndex, "/Game/Ownership");
            var actual = identity is null ? null : identity.Owner + "." + identity.Function;
            if (actual != expected) throw new InvalidDataException(name + ": unexpected class identity");
        }
        Console.WriteLine(JsonSerializer.Serialize(cases.Select(c => new { name = c.Item1, identity = c.Item4 })));
        return 0;
    }
}
