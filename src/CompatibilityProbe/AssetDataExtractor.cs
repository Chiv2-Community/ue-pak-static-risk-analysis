using System.Collections.Immutable;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.PropertyTypes.Objects;
using UAssetAPI.PropertyTypes.Structs;
using UAssetAPI.UnrealTypes;
using UAssetAPI.Unversioned;
using CompatibilityProbe;

namespace PakRisk.Extraction;

public sealed record DataExtractionLimits(int MaxExports = 4096, int MaxNodes = 4096,
    int MaxDepth = 16, int MaxText = 4096, int MaxTotalText = 65_536)
{
    internal void Validate()
    {
        if (MaxExports is < 1 or > 4096 || MaxNodes is < 1 or > 4096 || MaxDepth is < 1 or > 16
            || MaxText is < 1 or > 4096 || MaxTotalText is < 1 or > 65_536)
            throw new ArgumentOutOfRangeException(nameof(DataExtractionLimits));
    }
}

public sealed record DefaultOverrideEvidence(SerializedValue Value, int RequestedClassIndex,
    int? OriginClassIndex, int? OriginDefaultExportIndex, bool Inherited,
    ImmutableArray<int> ClassChain, string Context);

public static class AssetDataExtractor
{
    // Pinned PropertyData.RawValue lazily invents DefaultValue when unset. Read the backing
    // field without triggering that fallback; unknown upstream layout must fail closed.
    private static readonly System.Reflection.FieldInfo? RawValueField = typeof(PropertyData).GetField("_rawValue",
        System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
    public static AssetDataEvidence Read(PackageInput input, Usmap? mappings = null, DataExtractionLimits? limits = null)
    {
        ValidateInput(input);
        (limits ?? new()).Validate();
        try { return Inspect(PackageReader.Read(input.StoragePath, mappings), input, limits); }
        catch (Exception error) when (error is not OutOfMemoryException)
        { return new(1, input.FactIdentity, false, [], ["package-data-unavailable"]); }
    }

    public static AssetDataEvidence Inspect(UAsset asset, PackageInput input, DataExtractionLimits? limits = null)
    {
        ValidateInput(input);
        ArgumentNullException.ThrowIfNull(asset);
        var bounds = limits ?? new();
        bounds.Validate();
        return new Walker(asset, input, bounds).Run();
    }

    // Validate the whole claimed local CDO chain, even beyond the nearest override.
    // External/native boundaries do not invalidate a local override or supply absent defaults.
    // This is structural provenance, not verified reflection metadata or engine-effective values.
    public static DefaultOverrideEvidence FindLocalDefaultOverride(UAsset asset, PackageInput input,
        int classIndex, string property, int arrayIndex = 0, DataExtractionLimits? limits = null)
    {
        if (!SafeText(property, 4096) || property.Length == 0 || arrayIndex < 0)
            throw new ArgumentException("Invalid default property identity.");
        var chain = ImmutableArray.CreateBuilder<int>();
        var seen = new HashSet<int>();
        var current = classIndex;
        (SerializedValue Value, int Class, int Default)? candidate = null;
        DefaultOverrideEvidence Unknown(string code) => new(new SerializedValue.Unknown(code), classIndex,
            null, null, false, chain.ToImmutable(), "local-chain-incomplete");
        var evidence = Inspect(asset, input, limits);
        if (!evidence.Complete) return Unknown("property-evidence-incomplete");
        while (true)
        {
            if (current <= 0)
                return candidate is { } found
                    ? new(found.Value, classIndex, found.Class, found.Default, found.Class != classIndex,
                        chain.ToImmutable(), "serialized-local-default-override")
                    : Unknown(current < 0 ? "external-parent-unavailable" : "native-default-unavailable");
            if (!seen.Add(current) || seen.Count > 256) return Unknown("class-chain-cycle-or-limit");
            chain.Add(current);
            if (current > asset.Exports.Count || asset.Exports[current - 1] is not ClassExport cls)
                return Unknown("class-metadata-unavailable");
            var cdo = cls.ClassDefaultObject?.Index ?? 0;
            if (cdo <= 0 || cdo > asset.Exports.Count || asset.Exports[cdo - 1] is not NormalExport defaults
                || !defaults.ObjectFlags.HasFlag(EObjectFlags.RF_ClassDefaultObject)
                || defaults.ClassIndex?.Index != current)
                return Unknown("class-default-object-unavailable");
            if (cls.SuperStruct is null) return Unknown("parent-metadata-unavailable");
            if (cls.SuperIndex is not null && cls.SuperIndex.Index != cls.SuperStruct.Index)
                return Unknown("conflicting-parent-metadata");
            if (candidate is null)
            {
                var candidates = evidence.Properties.Where(p => p.ExportIndex == cdo && p.Path.Length == 1
                    && p.Path[0] == new DataPathPart(property, arrayIndex)).Take(2).ToArray();
                if (candidates.Length > 1) return Unknown("duplicate-property-identity");
                if (candidates.Length == 1 && candidates[0].Value is SerializedValue.Container)
                    return Unknown("compound-default-unavailable");
                if (candidates.Length == 1) candidate = (candidates[0].Value, current, cdo);
            }
            current = cls.SuperStruct.Index;
        }
    }

    private static void ValidateInput(PackageInput input)
    {
        if (input is null || !SafeText(input.Pak, 1024) || input.Pak.Length == 0
            || !SafeText(input.Entry, 1024) || input.Entry.Length == 0
            || !SafeText(input.LogicalPath, 1024) || input.LogicalPath.Length == 0)
            throw new ArgumentException("Invalid package identity.");
    }

    private static bool SafeText(string? text, int max)
    {
        if (text is null || text.Length > max) return false;
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsControl(text[i]) || text[i] == '\ufffd') return false;
            if (char.IsSurrogate(text[i]) && (!char.IsHighSurrogate(text[i]) || ++i >= text.Length
                || !char.IsLowSurrogate(text[i]))) return false;
        }
        return true;
    }

    private sealed class Walker(UAsset asset, PackageInput input, DataExtractionLimits limits)
    {
        private readonly List<SerializedProperty> properties = [];
        private readonly HashSet<string> gaps = new(StringComparer.Ordinal);
        private readonly HashSet<PropertyData> active = new(ReferenceEqualityComparer.Instance);
        private readonly HashSet<string> identities = new(StringComparer.Ordinal);
        private int nodes;
        private int text;
        private int outputText;

        private static int ValueText(SerializedValue value) => value switch
        {
            SerializedValue.Unknown v => v.Reason.Length,
            SerializedValue.Text v => v.Value.Length,
            SerializedValue.Integer v => v.Type.Length,
            SerializedValue.Name v => v.Value.Length,
            SerializedValue.Enumeration v => v.Type.Length + v.Value.Length,
            SerializedValue.Reference v => v.Owner.Length + v.ObjectName.Length + v.TargetKind.Length,
            SerializedValue.Delegate v => v.Function.Length + ValueText(v.Object),
            SerializedValue.Container v => v.Type.Length,
            _ => 0
        };

        private string? Text(string? value)
        {
            if (!SafeText(value, limits.MaxText) || value!.Length > limits.MaxTotalText - text)
            { gaps.Add("data-text-unavailable-or-limit"); return null; }
            text += value.Length;
            return value;
        }

        private string? Name(FName? value)
        {
            try { return Text(TargetResolver.StoredName(value)); }
            catch (Exception error) when (error is not OutOfMemoryException)
            { gaps.Add("property-name-unavailable"); return null; }
        }
        private string? Identity(FPackageIndex? index)
        {
            var identity = TargetResolver.ResolveDataIdentity(asset, index, input.LogicalPath);
            return identity is null ? null : Text(identity.Owner + "." + identity.Function);
        }

        public AssetDataEvidence Run()
        {
            if (!asset.PackageFlags.HasFlag(EPackageFlags.PKG_Cooked) && !asset.IsFilterEditorOnly)
                gaps.Add("cooked-marker-unavailable");
            if (asset.HasUnversionedProperties && asset.Mappings is null) gaps.Add("property-mappings-unavailable");
            if (asset.Exports.Count > limits.MaxExports) gaps.Add("data-export-limit");
            var defaultClasses = new HashSet<int>();
            for (var i = 0; i < Math.Min(asset.Exports.Count, limits.MaxExports); i++)
            {
                if (nodes >= limits.MaxNodes) { gaps.Add("data-node-limit"); break; }
                if (asset.Exports[i] is not NormalExport export || export.Data is null)
                { gaps.Add("export-properties-unavailable"); continue; }
                if (export.ObjectFlags.HasFlag(EObjectFlags.RF_ClassDefaultObject)
                    && export.ClassIndex is { } defaultClass && !defaultClasses.Add(defaultClass.Index))
                    gaps.Add("duplicate-class-default-object");
                if (export.GetType() != typeof(NormalExport) && export.GetType() != typeof(ClassExport)
                    && export.GetType() != typeof(FunctionExport)) gaps.Add("additional-export-data-uninspected");
                var owner = Identity(new(i + 1));
                var cls = Identity(export.ClassIndex);
                if (owner is null || cls is null) gaps.Add("property-owner-or-class-unavailable");
                for (var j = 0; j < export.Data.Count; j++)
                {
                    if (nodes >= limits.MaxNodes) { gaps.Add("data-node-limit"); break; }
                    Visit(export.Data[j], [], i + 1, owner, cls,
                        export.ObjectFlags.HasFlag(EObjectFlags.RF_ClassDefaultObject), 0, false);
                }
            }
            return new(1, input.FactIdentity, gaps.Count == 0, properties.ToImmutableArray(),
                gaps.Order(StringComparer.Ordinal).ToImmutableArray());
        }

        private void Visit(PropertyData? property, ImmutableArray<DataPathPart> prefix,
            int export, string? owner, string? cls, bool cdo, int depth, bool arrayElement)
        {
            if (nodes++ >= limits.MaxNodes) { gaps.Add("data-node-limit"); return; }
            if (depth >= limits.MaxDepth) { gaps.Add("data-depth-limit"); return; }
            if (property is null) { gaps.Add("property-unavailable"); return; }
            var name = arrayElement ? null : Name(property.Name);
            if (!arrayElement && (name is null || name.Length == 0) || property.ArrayIndex < 0)
            { gaps.Add("property-identity-unavailable"); return; }
            var path = arrayElement ? prefix : prefix.Add(new(name, property.ArrayIndex));
            void Emit(SerializedValue value)
            {
                var characters = (owner?.Length ?? 0) + (cls?.Length ?? 0)
                    + path.Sum(p => p.Property?.Length ?? 0) + ValueText(value);
                if (characters > limits.MaxTotalText - outputText)
                { gaps.Add("data-output-text-limit"); return; }
                outputText += characters;
                var identity = export + ":" + string.Concat(path.Select(p =>
                    $"{p.Property?.Length ?? -1}:{p.Property}:{p.ArrayIndex}:{p.Element};"));
                if (!identities.Add(identity)) gaps.Add("duplicate-property-identity");
                properties.Add(new(export, owner, cls, cdo, path, value));
            }
            if (!active.Add(property)) { Emit(Unknown("property-cycle")); return; }
            try
            {
                // Exact types: subclasses with unrelated custom serialization do not inherit trust.
                var type = property.GetType();
                if (type == typeof(ArrayPropertyData) && property is ArrayPropertyData array)
                {
                    if (array.Value is null) { Emit(Unknown("container-unavailable")); return; }
                    Emit(new SerializedValue.Container("array", array.Value.Length));
                    for (var i = 0; i < array.Value.Length; i++)
                    {
                        if (nodes >= limits.MaxNodes) { gaps.Add("data-node-limit"); break; }
                        Visit(array.Value[i], path.Add(new(null, 0, i)), export, owner, cls, cdo, depth + 1, true);
                    }
                }
                else if (type == typeof(StructPropertyData) && property is StructPropertyData structure
                    && !structure.HasCustomStructSerialization)
                {
                    if (structure.Value is null) { Emit(Unknown("container-unavailable")); return; }
                    Emit(new SerializedValue.Container("struct", structure.Value.Count));
                    for (var i = 0; i < structure.Value.Count; i++)
                    {
                        if (nodes >= limits.MaxNodes) { gaps.Add("data-node-limit"); break; }
                        Visit(structure.Value[i], path, export, owner, cls, cdo, depth + 1, false);
                    }
                }
                else Emit(Scalar(property));
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            { Emit(Unknown("property-value-unavailable")); }
            finally { active.Remove(property); }
        }

        private SerializedValue Unknown(string reason)
        { gaps.Add(reason); return new SerializedValue.Unknown(reason); }

        private SerializedValue Reference(FPackageIndex? index)
        {
            if (index is null) return Unknown("reference-unavailable");
            if (index.Index == 0) return new SerializedValue.NullReference();
            var identity = TargetResolver.ResolveDataIdentity(asset, index, input.LogicalPath);
            if (identity is null) return Unknown("reference-owner-unavailable");
            var owner = Text(identity.Owner);
            var name = Text(identity.Function);
            if (owner is null || name is null) return Unknown("reference-text-unavailable");
            // Target kind is not a declared property type or proof of external class behavior.
            var kind = index.Index > 0
                ? asset.Exports[index.Index - 1] is ClassExport ? "local-class" : "local-object"
                : "import-symbol";
            return new SerializedValue.Reference(index.Index, owner, name, kind);
        }

        private SerializedValue Scalar(PropertyData property)
        {
            var type = property.GetType();
            if (RawValueField is null) return Unknown("property-storage-unavailable");
            if (RawValueField.GetValue(property) is null)
            {
                // An explicit unversioned zero mask is serialized evidence, not a native default.
                if (property.IsZero && asset.HasUnversionedProperties && asset.Mappings is not null)
                {
                    if (type == typeof(IntPropertyData)) return new SerializedValue.Integer(0, "int32");
                    if (type == typeof(Int64PropertyData)) return new SerializedValue.Integer(0, "int64");
                    if (type == typeof(BoolPropertyData)) return new SerializedValue.Boolean(false);
                    if (type == typeof(ObjectPropertyData)) return new SerializedValue.NullReference();
                }
                return Unknown("property-value-unavailable");
            }
            if (type == typeof(StrPropertyData))
            {
                var value = Text(((StrPropertyData)property).Value?.Value);
                return value is null ? Unknown("string-value-unavailable") : new SerializedValue.Text(value);
            }
            if (type == typeof(BoolPropertyData)) return new SerializedValue.Boolean(((BoolPropertyData)property).Value);
            if (type == typeof(IntPropertyData)) return new SerializedValue.Integer(((IntPropertyData)property).Value, "int32");
            if (type == typeof(Int64PropertyData)) return new SerializedValue.Integer(((Int64PropertyData)property).Value, "int64");
            if (type == typeof(NamePropertyData))
            {
                var value = Name(((NamePropertyData)property).Value);
                return value is null ? Unknown("name-value-unavailable") : new SerializedValue.Name(value);
            }
            if (type == typeof(EnumPropertyData))
            {
                var enumeration = (EnumPropertyData)property;
                var enumType = Name(enumeration.EnumType);
                var value = Name(enumeration.Value);
                if (enumType is null or "" or "None" || value is null or ""
                    || value.StartsWith(EnumPropertyData.InvalidEnumIndexFallbackPrefix, StringComparison.Ordinal))
                    return Unknown("enum-metadata-unavailable");
                return new SerializedValue.Enumeration(enumType, value);
            }
            if (type == typeof(ObjectPropertyData)) return Reference(((ObjectPropertyData)property).Value);
            if (type == typeof(DelegatePropertyData))
            {
                var binding = ((DelegatePropertyData)property).Value;
                var function = Name(binding?.Delegate);
                return binding is null || function is null ? Unknown("delegate-unavailable")
                    : new SerializedValue.Delegate(Reference(binding.Object), function);
            }
            return Unknown("unsupported-property-type");
        }
    }
}
