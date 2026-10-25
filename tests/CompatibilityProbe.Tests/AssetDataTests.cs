using System.Text;
using CompatibilityProbe;
using PakRisk.Extraction;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.PropertyTypes.Objects;
using UAssetAPI.PropertyTypes.Structs;
using UAssetAPI.UnrealTypes;
using Xunit;

namespace CompatibilityProbe.Tests;

public sealed class AssetDataTests
{
    private static readonly PackageInput Input = new("original-fixture", "Content/Data.uasset", "/Game/Data", "unused");

    private static UAsset Asset()
    {
        var asset = new UAsset(EngineVersion.VER_UE4_25)
        {
            PackageFlags = EPackageFlags.PKG_Cooked | EPackageFlags.PKG_FilterEditorOnly,
            Imports = [], Exports = [], LegacyFileVersion = -7, FolderName = new("None"),
            Generations = [], ChunkIDs = [], AssetRegistryRecords = [], AdditionalFiles = [],
            RecordedEngineVersion = new(), RecordedCompatibleWithEngineVersion = new(),
            UseSeparateBulkDataFiles = false
        };
        asset.ClearNameIndexList();
        asset.AddNameReference(new("None"));
        foreach (var name in new[] { "StrProperty", "BoolProperty", "IntProperty", "Int64Property", "NameProperty",
            "EnumProperty", "ObjectProperty", "DelegateProperty", "StructProperty", "ArrayProperty" })
            asset.AddNameReference(new(name));
        // Same pinned writer header initialization as Corpus.Generate; original synthetic bytes only.
        typeof(UAsset).GetField("AdditionalPackagesToCook", System.Reflection.BindingFlags.Instance
            | System.Reflection.BindingFlags.NonPublic)!.SetValue(asset, new List<FString>());
        typeof(UAsset).GetField("doWeHaveWorldTileInfo", System.Reflection.BindingFlags.Instance
            | System.Reflection.BindingFlags.NonPublic)!.SetValue(asset, false);
        asset.Imports.Add(new Import("/Script/CoreUObject", "Package", new(0), "/Script/CoreUObject", false, asset));
        foreach (var name in new[] { "Object", "Class", "Function" })
            asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-1), name, false, asset));
        asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "Data"),
            OuterIndex = new(0), ClassIndex = new(-2), Data = [], Extras = [] });
        return asset;
    }

    private static NormalExport Data(UAsset asset) => (NormalExport)asset.Exports[0];
    private static AssetDataEvidence Inspect(UAsset asset, DataExtractionLimits? limits = null) =>
        AssetDataExtractor.Inspect(asset, Input, limits);
    private static SerializedValue Value(AssetDataEvidence evidence, string name) =>
        Assert.Single(evidence.Properties.Where(p => p.ExportIndex == 1 && p.Path.Length == 1
            && p.Path[0].Property == name)).Value;

    private sealed class TemporaryPackage : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "asset-data-" + Guid.NewGuid().ToString("N"));
        public string PathName { get; }
        public TemporaryPackage(UAsset asset)
        {
            Directory.CreateDirectory(root);
            PathName = Path.Combine(root, "Data.uasset");
            asset.Write(PathName);
        }
        public AssetDataEvidence Read(DataExtractionLimits? limits = null) =>
            AssetDataExtractor.Read(Input with { StoragePath = PathName }, limits: limits);
        public void Dispose() => Directory.Delete(root, true);
    }

    [Fact]
    public void PublicReadPreservesTypedSerializedValuesAndNeverStoragePaths()
    {
        var asset = Asset();
        Data(asset).Data = [
            new StrPropertyData(new(asset, "Destination")) { Value = new("owned-original-destination") },
            new BoolPropertyData(new(asset, "Enabled")) { Value = true },
            new IntPropertyData(new(asset, "Number")) { Value = 424242 },
            new Int64PropertyData(new(asset, "Wide")) { Value = long.MinValue },
            new NamePropertyData(new(asset, "Named")) { Value = new(asset, "None") },
            new EnumPropertyData(new(asset, "Mode")) { EnumType = new(asset, "OwnedMode"), Value = new(asset, "OwnedMode::One") },
            new ObjectPropertyData(new(asset, "Absent")) { Value = new(0) },
            new ObjectPropertyData(new(asset, "Target")) { Value = new(1) },
            new DelegatePropertyData(new(asset, "Binding")) { Value = new(new(1), new(asset, "OwnedHandler")) }
        ];
        using var package = new TemporaryPackage(asset);
        var evidence = package.Read();
        Assert.True(evidence.Complete, string.Join(",", evidence.Diagnostics));
        Assert.Equal(new SerializedValue.Text("owned-original-destination"), Value(evidence, "Destination"));
        Assert.Equal(new SerializedValue.Boolean(true), Value(evidence, "Enabled"));
        Assert.Equal(new SerializedValue.Integer(424242, "int32"), Value(evidence, "Number"));
        Assert.Equal(new SerializedValue.Integer(long.MinValue, "int64"), Value(evidence, "Wide"));
        Assert.Equal(new SerializedValue.Name("None"), Value(evidence, "Named"));
        Assert.Equal(new SerializedValue.Enumeration("OwnedMode", "OwnedMode::One"), Value(evidence, "Mode"));
        Assert.IsType<SerializedValue.NullReference>(Value(evidence, "Absent"));
        var reference = Assert.IsType<SerializedValue.Reference>(Value(evidence, "Target"));
        Assert.Equal(new SerializedValue.Reference(1, "/Game/Data", "Data", "local-object"), reference);
        Assert.Equal(new SerializedValue.Delegate(reference, "OwnedHandler"), Value(evidence, "Binding"));
        Assert.Equal(Input.FactIdentity, evidence.Asset);
        Assert.DoesNotContain(package.PathName, evidence.ToString());
        Assert.All(evidence.Properties, p => Assert.False(p.ClassDefaultFlag));
    }

    [Fact]
    public void PublicReadRecursesThroughSupportedStructsAndArraysWithStructuralPaths()
    {
        var asset = Asset();
        Data(asset).Data = [new StructPropertyData(new(asset, "Settings"), new(asset, "OwnedSettings"))
        {
            Value = [new ArrayPropertyData(new(asset, "Destinations")) { Value = [
                new StrPropertyData(new(asset, "0")) { Value = new("original-one") },
                new StrPropertyData(new(asset, "1")) { Value = new("original-two") }
            ] }]
        }];
        using var package = new TemporaryPackage(asset);
        var evidence = package.Read();
        Assert.True(evidence.Complete, string.Join(",", evidence.Diagnostics));
        Assert.Equal(4, evidence.Properties.Length);
        Assert.Equal(new DataPathPart("Settings", 0), evidence.Properties[3].Path[0]);
        Assert.Equal(new DataPathPart("Destinations", 0), evidence.Properties[3].Path[1]);
        Assert.Equal(new DataPathPart(null, 0, 1), evidence.Properties[3].Path[2]);
        Assert.Equal(new SerializedValue.Text("original-two"), evidence.Properties[3].Value);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void PublicReadAndInspectRejectMissingNameStorage(int index)
    {
        var asset = Asset();
        Data(asset).Data = [
            new NamePropertyData(new(asset, "Named")) { Value = new(asset, index) },
            new EnumPropertyData(new(asset, "EnumType")) { EnumType = new(asset, index), Value = new(asset, "OwnedMode::One") },
            new EnumPropertyData(new(asset, "EnumValue")) { EnumType = new(asset, "OwnedMode"), Value = new(asset, index) },
            new DelegatePropertyData(new(asset, "Binding")) { Value = new(new(1), new(asset, index)) }
        ];
        using var package = new TemporaryPackage(asset);
        var inspected = Inspect(asset);
        Assert.False(inspected.Complete);
        Assert.Equal(new SerializedValue.Unknown("name-value-unavailable"), Value(inspected, "Named"));
        Assert.Equal(new SerializedValue.Unknown("enum-metadata-unavailable"), Value(inspected, "EnumType"));
        Assert.Equal(new SerializedValue.Unknown("enum-metadata-unavailable"), Value(inspected, "EnumValue"));
        Assert.Equal(new SerializedValue.Unknown("delegate-unavailable"), Value(inspected, "Binding"));
        var read = package.Read();
        Assert.False(read.Complete);
        Assert.Equal(inspected.Properties.Select(p => p.Value), read.Properties.Select(p => p.Value));
        Assert.Equal(inspected.Diagnostics.ToArray(), read.Diagnostics.ToArray());
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void PublicReadAndInspectRejectInvalidStaticPropertyName(int index)
    {
        var asset = Asset();
        Data(asset).Data = [new IntPropertyData(new(asset, index)) { ArrayIndex = 3, Value = 424242 }];
        using var package = new TemporaryPackage(asset);
        var inspected = Inspect(asset);
        Assert.False(inspected.Complete);
        Assert.Empty(inspected.Properties);
        Assert.Contains("property-identity-unavailable", inspected.Diagnostics);
        var read = package.Read();
        Assert.False(read.Complete);
        Assert.Empty(read.Properties);
        Assert.Equal(index < 0 ? new[] { "export-properties-unavailable" } : inspected.Diagnostics.ToArray(), read.Diagnostics.ToArray());
    }

    [Theory]
    [InlineData("export", -1)]
    [InlineData("import", -1)]
    [InlineData("outer", -1)]
    [InlineData("export", int.MaxValue)]
    [InlineData("import", int.MaxValue)]
    [InlineData("outer", int.MaxValue)]
    public void PublicReadAndInspectRejectMissingDataIdentityStorage(string location, int index)
    {
        var asset = Asset();
        Data(asset).Data = [new ObjectPropertyData(new(asset, "Target")) { Value = new(1) }];
        if (location == "export") Data(asset).ObjectName = new(asset, index);
        else if (location == "import") asset.Imports[1].ObjectName = new(asset, index);
        else
        {
            Data(asset).OuterIndex = new(-1);
            asset.Imports[0].ObjectName = new(asset, index);
        }
        using var package = new TemporaryPackage(asset);
        foreach (var evidence in new[] { Inspect(asset), package.Read() })
        {
            Assert.False(evidence.Complete);
            if (location == "import" && evidence.Properties.IsEmpty)
            {
                Assert.Equal(new[] { "export-properties-unavailable" }, evidence.Diagnostics.ToArray());
                continue; // Invalid class identity prevents upstream typed export reading.
            }
            Assert.Contains("property-owner-or-class-unavailable", evidence.Diagnostics);
            var property = Assert.Single(evidence.Properties);
            if (location == "import") Assert.Null(property.ClassIdentity);
            else
            {
                Assert.Null(property.ObjectIdentity);
                Assert.Equal(new SerializedValue.Unknown("reference-owner-unavailable"), property.Value);
            }
        }
        // Data validation must not change the existing invocation identity contract.
        Assert.NotNull(TargetResolver.ResolveIdentity(asset, new(1), Input.LogicalPath));
    }

    [Theory]
    [InlineData("null", 0, "null")]
    [InlineData("null", 2, "null_1")]
    [InlineData("None", 0, "None")]
    [InlineData("None", 1, "None_0")]
    public void PublicReadAndInspectPreserveStoredNamesAndInstanceSuffixes(string name, int number, string expected)
    {
        var asset = Asset();
        Data(asset).ObjectName = new(asset, name, number);
        Data(asset).Data = [
            new NamePropertyData(new(asset, "Named")) { ArrayIndex = 3, Value = new(asset, name, number) },
            new EnumPropertyData(new(asset, "Mode")) { EnumType = new(asset, "OwnedMode"), Value = new(asset, name, number) },
            new DelegatePropertyData(new(asset, "Binding")) { Value = new(new(1), new(asset, name, number)) }
        ];
        using var package = new TemporaryPackage(asset);
        foreach (var evidence in new[] { Inspect(asset), package.Read() })
        {
            Assert.True(evidence.Complete, string.Join(",", evidence.Diagnostics));
            Assert.Equal(new SerializedValue.Name(expected), Value(evidence, "Named"));
            Assert.Equal(3, evidence.Properties[0].Path[0].ArrayIndex);
            Assert.Equal(new SerializedValue.Enumeration("OwnedMode", expected), Value(evidence, "Mode"));
            Assert.Equal(new SerializedValue.Delegate(new SerializedValue.Reference(1, "/Game/Data", expected, "local-object"), expected), Value(evidence, "Binding"));
            Assert.All(evidence.Properties, p => Assert.Equal("/Game/Data." + expected, p.ObjectIdentity));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InspectSupportsAssetlessDummyNamesButNotNullBackingText(bool missing)
    {
        var asset = Asset();
        var name = FName.DefineDummy(null, new FString(missing ? null : "null"), 2);
        Data(asset).ObjectName = name;
        Data(asset).Data = [new NamePropertyData(new(asset, "Named")) { Value = name }];
        var evidence = Inspect(asset);
        Assert.Equal(!missing, evidence.Complete);
        Assert.Equal(missing ? new SerializedValue.Unknown("name-value-unavailable") : (SerializedValue)new SerializedValue.Name("null_1"), Value(evidence, "Named"));
        Assert.Equal(missing ? null : "/Game/Data.null_1", Assert.Single(evidence.Properties).ObjectIdentity);
    }

    [Theory]
    [InlineData("null", 0, "null")]
    [InlineData("null", 2, "null_1")]
    [InlineData("None", 1, "None_0")]
    public void PublicReadPreservesLiteralStaticPropertyAndEnumTypeNames(string name, int number, string expected)
    {
        var asset = Asset();
        // Pinned tagged-property reading treats base NAME_None as the terminator,
        // even with a number. It is valid value/enum text, not a property tag here.
        var propertyName = name == "None" ? new FName(asset, "Mode") : new FName(asset, name, number);
        Data(asset).Data = [new EnumPropertyData(propertyName)
            { ArrayIndex = 3, EnumType = new(asset, name, number), Value = new(asset, "OwnedMode::One") }];
        using var package = new TemporaryPackage(asset);
        var evidence = package.Read();
        Assert.True(evidence.Complete, string.Join(",", evidence.Diagnostics));
        Assert.Equal(new DataPathPart(propertyName.ToString(), 3), Assert.Single(evidence.Properties).Path[0]);
        Assert.Equal(new SerializedValue.Enumeration(expected, "OwnedMode::One"), Value(evidence, propertyName.ToString()));
    }

    [Fact]
    public void AssetlessNonDummyNameDoesNotBecomeEvidence()
    {
        var asset = Asset();
        Data(asset).Data = [new NamePropertyData(new(asset, "Named")) { Value = new FName() }];
        var evidence = Inspect(asset);
        Assert.False(evidence.Complete);
        Assert.Equal(new SerializedValue.Unknown("name-value-unavailable"), Value(evidence, "Named"));
        Assert.Contains("property-name-unavailable", evidence.Diagnostics);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InvalidNameCannotSupplyLocalDefaultOverride(bool propertyName)
    {
        var asset = Asset();
        var (_, child) = AddDefaults(asset);
        ((NormalExport)asset.Exports[2]).Data = [new NamePropertyData(new(asset, propertyName ? -1 : asset.AddNameReference(new("Destination"))))
            { Value = propertyName ? new(asset, "OwnedValue") : new(asset, -1) }];
        var result = AssetDataExtractor.FindLocalDefaultOverride(asset, Input, child, propertyName ? "null" : "Destination");
        Assert.Equal(new SerializedValue.Unknown("property-evidence-incomplete"), result.Value);
        Assert.Null(result.OriginDefaultExportIndex);
        Assert.Equal("local-chain-incomplete", result.Context);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PublicReadLossyStringDecodingRemainsUnknown(bool unicode)
    {
        var asset = Asset();
        var marker = unicode ? "有😀界" : "owned-malformed-marker";
        Data(asset).Data = [new StrPropertyData(new(asset, "Value"))
            { Value = new(marker, unicode ? Encoding.Unicode : Encoding.UTF8) }];
        using var package = new TemporaryPackage(asset);
        var bytes = File.ReadAllBytes(package.PathName);
        var pattern = (unicode ? Encoding.Unicode : Encoding.UTF8).GetBytes(marker);
        var position = bytes.AsSpan().IndexOf(pattern);
        Assert.True(position >= 0);
        if (unicode) { bytes[position + 4] = 0; bytes[position + 5] = 0xd8; } // broken surrogate pair
        else bytes[position] = 0xff;
        File.WriteAllBytes(package.PathName, bytes);
        var evidence = package.Read();
        Assert.False(evidence.Complete);
        Assert.Equal(new SerializedValue.Unknown("string-value-unavailable"), Value(evidence, "Value"));
    }

    [Theory]
    [InlineData("\ufffd")]
    [InlineData("\u001b[31m")]
    [InlineData("\u0000")]
    [InlineData("\ud800")]
    public void AmbiguousOrControlBearingPropertyTextIsNotDefinitive(string value)
    {
        var asset = Asset();
        Data(asset).Data = [new StrPropertyData(new(asset, "Value")) { Value = new(value) }];
        Assert.IsType<SerializedValue.Unknown>(Value(Inspect(asset), "Value"));
    }

    private sealed class UnsupportedString : StrPropertyData
    {
        public UnsupportedString() { }
        public UnsupportedString(FName name) : base(name) { }
        public override bool ShouldBeRegistered => false;
        public override string ToString() => throw new InvalidOperationException("Must not stringify unknown data.");
    }

    [Fact]
    public void UnknownTypesAndMissingOrCyclicReferencesNeverBecomeNullOrStrings()
    {
        var asset = Asset();
        Data(asset).Data = [new UnsupportedString(new(asset, "Unsupported")) { Value = new("not-evidence") },
            new ObjectPropertyData(new(asset, "Missing")) { Value = new(int.MinValue) },
            new ObjectPropertyData(new(asset, "Cycle")) { Value = new(1) }];
        Data(asset).OuterIndex = new(1);
        var evidence = Inspect(asset);
        Assert.False(evidence.Complete);
        Assert.All(evidence.Properties, p => Assert.IsType<SerializedValue.Unknown>(p.Value));
        Assert.Contains("property-owner-or-class-unavailable", evidence.Diagnostics);
    }

    [Fact]
    public void InvalidEnumMappingFallbackIsUnknown()
    {
        var asset = Asset();
        Data(asset).Data = [new EnumPropertyData(new(asset, "Mode")) { EnumType = new(asset, "OwnedEnum"),
            Value = new(asset, EnumPropertyData.InvalidEnumIndexFallbackPrefix + "999") }];
        Assert.IsType<SerializedValue.Unknown>(Value(Inspect(asset), "Mode"));
    }

    [Fact]
    public void UninitializedPropertyStorageDoesNotInventZeroFalseOrNull()
    {
        var asset = Asset();
        Data(asset).Data = [new IntPropertyData(new(asset, "Number")), new BoolPropertyData(new(asset, "Boolean")),
            new ObjectPropertyData(new(asset, "Reference"))];
        Assert.All(Inspect(asset).Properties, p => Assert.IsType<SerializedValue.Unknown>(p.Value));
    }

    [Fact]
    public void PublicReadUnsupportedClassPropertyBytesAreNotPromotedToObjectReferences()
    {
        var asset = Asset();
        asset.AddNameReference(new("ClassProperty"));
        var property = new UnknownPropertyData(new(asset, "DeclaredClass")) { Value = BitConverter.GetBytes(1) };
        property.SetSerializingPropertyType(new("ClassProperty"));
        Data(asset).Data = [property];
        using var package = new TemporaryPackage(asset);
        var evidence = package.Read();
        Assert.False(evidence.Complete);
        Assert.IsType<SerializedValue.Unknown>(Value(evidence, "DeclaredClass"));
    }

    [Theory]
    [InlineData("世界😀", true)]
    [InlineData("\ufffd", false)]
    public void PublicReadValidUnicodeAndAmbiguousReplacementStayDistinct(string value, bool known)
    {
        var asset = Asset();
        Data(asset).Data = [new StrPropertyData(new(asset, "Value")) { Value = new(value, Encoding.Unicode) }];
        using var package = new TemporaryPackage(asset);
        Assert.Equal(known, Value(package.Read(), "Value") is SerializedValue.Text);
    }

    [Fact]
    public void PropertyCyclesDepthAndExpandedDagCountsAreBounded()
    {
        var asset = Asset();
        var array = new ArrayPropertyData(new(asset, "Loop"));
        array.Value = [array];
        Data(asset).Data = [array];
        Assert.Contains("property-cycle", Inspect(asset).Diagnostics);
        Assert.Contains("data-depth-limit", Inspect(asset, new(MaxDepth: 1)).Diagnostics);
        var scalar = new IntPropertyData(new(asset, "0")) { Value = 1 };
        array.Value = Enumerable.Repeat<PropertyData>(scalar, 100).ToArray();
        var bounded = Inspect(asset, new(MaxNodes: 4));
        Assert.Equal(4, bounded.Properties.Length);
        Assert.Contains("data-node-limit", bounded.Diagnostics);
    }

    [Fact]
    public void TotalTextIncludesRepeatedOutputPathsAndOwnerIdentities()
    {
        var asset = Asset();
        Data(asset).Data = [new ArrayPropertyData(new(asset, new string('p', 80)))
            { Value = Enumerable.Range(0, 100).Select(i => (PropertyData)new IntPropertyData(new(asset, "0")) { Value = i }).ToArray() }];
        var evidence = Inspect(asset, new(MaxTotalText: 512));
        Assert.Contains("data-output-text-limit", evidence.Diagnostics);
        Assert.InRange(evidence.Properties.Length, 1, 5);
    }

    private static (int Parent, int Child) AddDefaults(UAsset asset)
    {
        ClassExport Class(string name, int defaultIndex, int parent) => new() { Asset = asset,
            ObjectName = new(asset, name), OuterIndex = new(0), ClassIndex = new(-3), Data = [],
            ClassDefaultObject = new(defaultIndex), SuperStruct = new(parent) };
        asset.Exports.Add(Class("OwnedParent", 3, -2));
        asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "Default__OwnedParent"),
            OuterIndex = new(0), ClassIndex = new(2), ObjectFlags = EObjectFlags.RF_ClassDefaultObject,
            Data = [new StrPropertyData(new(asset, "Destination")) { Value = new("original-parent") },
                new ObjectPropertyData(new(asset, "Target")) { Value = new(2) }] });
        asset.Exports.Add(Class("OwnedChild", 5, 2));
        asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "Default__OwnedChild"),
            OuterIndex = new(0), ClassIndex = new(4), ObjectFlags = EObjectFlags.RF_ClassDefaultObject, Data = [] });
        return (2, 4);
    }

    [Fact]
    public void PublicReadAndInspectRejectDuplicateFlaggedClassDefaults()
    {
        var asset = Asset();
        Data(asset).ObjectFlags = EObjectFlags.RF_ClassDefaultObject;
        Data(asset).Data = [new StrPropertyData(new(asset, "Destination")) { Value = new("original-first") }];
        asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "SecondDefault"),
            OuterIndex = new(0), ClassIndex = new(-2), ObjectFlags = EObjectFlags.RF_ClassDefaultObject,
            Data = [new StrPropertyData(new(asset, "Destination")) { Value = new("original-second") }], Extras = [] });
        using var package = new TemporaryPackage(asset);
        foreach (var evidence in new[] { Inspect(asset), package.Read() })
        {
            Assert.False(evidence.Complete);
            Assert.Contains("duplicate-class-default-object", evidence.Diagnostics);
            Assert.Equal(2, evidence.Properties.Length);
        }
        asset.Exports[1].ObjectFlags = 0;
        Assert.True(Inspect(asset).Complete); // Ordinary instances are not additional CDOs.
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void PublicReadAndInspectUseCookedOrFilteredMarkerContract(bool cooked, bool filtered)
    {
        var asset = Asset();
        asset.PackageFlags = (cooked ? EPackageFlags.PKG_Cooked : 0)
            | (filtered ? EPackageFlags.PKG_FilterEditorOnly : 0);
        Data(asset).Data = [new IntPropertyData(new(asset, "Number")) { Value = 424242 }];
        using var package = new TemporaryPackage(asset);
        foreach (var evidence in new[] { Inspect(asset), package.Read() })
        {
            Assert.Equal(cooked || filtered, evidence.Complete);
            Assert.Equal(!cooked && !filtered, evidence.Diagnostics.Contains("cooked-marker-unavailable"));
            Assert.Equal(new SerializedValue.Integer(424242, "int32"), Value(evidence, "Number"));
        }
        var (_, child) = AddDefaults(asset);
        var result = AssetDataExtractor.FindLocalDefaultOverride(asset, Input, child, "Destination");
        Assert.Equal(cooked || filtered, result.Value is SerializedValue.Text);
    }

    [Fact]
    public void LocalDefaultInheritanceAndOverridesRetainActualOriginAndClassReferenceTarget()
    {
        var asset = Asset();
        var (_, child) = AddDefaults(asset);
        var inherited = AssetDataExtractor.FindLocalDefaultOverride(asset, Input, child, "Destination");
        Assert.Equal(new SerializedValue.Text("original-parent"), inherited.Value);
        Assert.True(inherited.Inherited);
        Assert.Equal(2, inherited.OriginClassIndex);
        Assert.Equal(3, inherited.OriginDefaultExportIndex);
        Assert.Equal(new[] { 4, 2 }, inherited.ClassChain.ToArray());
        Assert.Equal("local-class", Assert.IsType<SerializedValue.Reference>(
            AssetDataExtractor.FindLocalDefaultOverride(asset, Input, child, "Target").Value).TargetKind);
        ((NormalExport)asset.Exports[4]).Data = [new StrPropertyData(new(asset, "Destination")) { Value = new("original-child") },
            new ObjectPropertyData(new(asset, "Target")) { Value = new(4) }];
        var overridden = AssetDataExtractor.FindLocalDefaultOverride(asset, Input, child, "Destination");
        Assert.False(overridden.Inherited);
        Assert.Equal(5, overridden.OriginDefaultExportIndex);
        Assert.Equal(new SerializedValue.Text("original-child"), overridden.Value);
        Assert.Equal(new[] { 4, 2 }, overridden.ClassChain.ToArray());
        Assert.Equal(4, Assert.IsType<SerializedValue.Reference>(
            AssetDataExtractor.FindLocalDefaultOverride(asset, Input, child, "Target").Value).PackageIndex);
        Assert.All(Inspect(asset).Properties.Where(p => p.ExportIndex == 5), p => Assert.True(p.ClassDefaultFlag));
    }

    [Theory]
    [InlineData("conflicting-parent", false)]
    [InlineData("conflicting-parent", true)]
    [InlineData("cycle", false)]
    [InlineData("cycle", true)]
    [InlineData("matching-cycle", false)]
    [InlineData("matching-cycle", true)]
    [InlineData("missing-parent-metadata", false)]
    [InlineData("missing-parent-metadata", true)]
    [InlineData("duplicate-cdo", false)]
    [InlineData("duplicate-cdo", true)]
    [InlineData("missing-cdo", false)]
    [InlineData("missing-cdo", true)]
    [InlineData("unflagged-cdo", false)]
    [InlineData("unflagged-cdo", true)]
    [InlineData("wrong-cdo-class", false)]
    [InlineData("wrong-cdo-class", true)]
    [InlineData("missing-local-ancestor", false)]
    [InlineData("missing-local-ancestor", true)]
    public void DefaultCandidateRequiresWholeClaimedLocalProvenance(string failure, bool childOverride)
    {
        var asset = Asset();
        var (_, child) = AddDefaults(asset);
        var parentClass = (ClassExport)asset.Exports[1];
        var parentDefault = (NormalExport)asset.Exports[2];
        if (childOverride)
            ((NormalExport)asset.Exports[4]).Data = [new StrPropertyData(new(asset, "Destination"))
                { Value = new("original-child") }];
        switch (failure)
        {
            case "conflicting-parent": parentClass.SuperIndex = new(child); break;
            case "cycle": parentClass.SuperStruct = new(child); break;
            case "matching-cycle": parentClass.SuperIndex = parentClass.SuperStruct = new(child); break;
            case "missing-parent-metadata": parentClass.SuperStruct = null; break;
            case "missing-cdo": parentClass.ClassDefaultObject = new(999); break;
            case "unflagged-cdo": parentDefault.ObjectFlags = 0; break;
            case "wrong-cdo-class": parentDefault.ClassIndex = new(child); break;
            case "missing-local-ancestor": parentClass.SuperStruct = new(999); break;
            case "duplicate-cdo":
                asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "SecondParentDefault"),
                    OuterIndex = new(0), ClassIndex = new(2), ObjectFlags = EObjectFlags.RF_ClassDefaultObject,
                    Data = [new StrPropertyData(new(asset, "Destination")) { Value = new("contradictory-parent") }] });
                break;
        }
        var evidence = Inspect(asset);
        Assert.Contains(evidence.Properties, p => p.Value == new SerializedValue.Text("original-parent"));
        if (failure == "duplicate-cdo") Assert.Contains("duplicate-class-default-object", evidence.Diagnostics);
        var result = AssetDataExtractor.FindLocalDefaultOverride(asset, Input, child, "Destination");
        Assert.IsType<SerializedValue.Unknown>(result.Value);
        Assert.Null(result.OriginClassIndex);
        Assert.Null(result.OriginDefaultExportIndex);
        Assert.False(result.Inherited);
        Assert.Equal("local-chain-incomplete", result.Context);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-2)]
    public void LocalSerializedCandidateDoesNotRequireNativeOrExternalDefaults(int boundary)
    {
        var asset = Asset();
        var (_, child) = AddDefaults(asset);
        var parentClass = (ClassExport)asset.Exports[1];
        parentClass.SuperIndex = parentClass.SuperStruct = new(boundary);
        var result = AssetDataExtractor.FindLocalDefaultOverride(asset, Input, child, "Destination");
        Assert.Equal(new SerializedValue.Text("original-parent"), result.Value);
        Assert.Equal(new[] { 4, 2 }, result.ClassChain.ToArray());
        Assert.Equal("serialized-local-default-override", result.Context);
        Assert.IsType<SerializedValue.Unknown>(AssetDataExtractor.FindLocalDefaultOverride(
            asset, Input, child, "NotSerialized").Value);
    }

    [Fact]
    public void LocalCandidateCannotBypassClassChainBound()
    {
        var asset = Asset();
        var (_, child) = AddDefaults(asset);
        var ancestor = (ClassExport)asset.Exports[1];
        for (var i = 0; i < 255; i++)
        {
            var index = asset.Exports.Count + 1;
            ancestor.SuperStruct = new(index);
            ancestor = new ClassExport { Asset = asset, ObjectName = new(asset, "Ancestor" + i),
                OuterIndex = new(0), ClassIndex = new(-3), Data = [],
                ClassDefaultObject = new(index + 1), SuperStruct = new(-2) };
            asset.Exports.Add(ancestor);
            asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "Default" + i),
                OuterIndex = new(0), ClassIndex = new(index), ObjectFlags = EObjectFlags.RF_ClassDefaultObject, Data = [] });
        }
        Assert.True(Inspect(asset).Complete);
        var result = AssetDataExtractor.FindLocalDefaultOverride(asset, Input, child, "Destination");
        Assert.Equal(new SerializedValue.Unknown("class-chain-cycle-or-limit"), result.Value);
        Assert.Equal(256, result.ClassChain.Length);
    }

    [Theory]
    [InlineData("external")]
    [InlineData("cycle")]
    [InlineData("missing-default")]
    [InlineData("not-default")]
    [InlineData("wrong-class")]
    [InlineData("duplicate")]
    [InlineData("limit")]
    [InlineData("conflicting-parent")]
    public void MissingOrUnverifiedDefaultContextIsUnknown(string failure)
    {
        var asset = Asset();
        var (_, child) = AddDefaults(asset);
        var parentClass = (ClassExport)asset.Exports[1];
        var childClass = (ClassExport)asset.Exports[3];
        var parentDefault = (NormalExport)asset.Exports[2];
        parentDefault.Data = [];
        switch (failure)
        {
            case "cycle": parentClass.SuperStruct = new(child); break;
            case "missing-default": childClass.ClassDefaultObject = new(999); break;
            case "not-default": parentDefault.ObjectFlags = 0; break;
            case "wrong-class": parentDefault.ClassIndex = new(child); break;
            case "conflicting-parent": parentClass.SuperIndex = new(child); break;
            case "duplicate": parentDefault.Data = [new IntPropertyData(new(asset, "Destination")) { Value = 1 },
                new IntPropertyData(new(asset, "Destination")) { Value = 2 }]; break;
        }
        var result = AssetDataExtractor.FindLocalDefaultOverride(asset, Input, child, "Destination",
            limits: failure == "limit" ? new(MaxExports: 1) : null);
        Assert.IsType<SerializedValue.Unknown>(result.Value);
        Assert.Null(result.OriginDefaultExportIndex);
        Assert.Equal("local-chain-incomplete", result.Context);
    }

    [Fact]
    public void DataChangesAndDataLimitsCannotChangeRealInvocationFactsOrPolicyFindings()
    {
        var asset = Asset();
        asset.Imports.Add(new Import("/Script/CoreUObject", "Function", new(-2), "OwnedCall", false, asset));
        KismetExpression[] code = [new EX_FinalFunction { StackNode = new(-5), Parameters = [] }];
        asset.Exports.Add(new FunctionExport { Asset = asset, ObjectName = new(asset, "Execute"), OuterIndex = new(1),
            ClassIndex = new(-4), Data = [], Extras = [], Field = new(), SuperStruct = new(0),
            LoadedProperties = [], Children = [], ScriptBytecode = code, ScriptBytecodeSize = (int)code[0].GetSize(asset) });
        Data(asset).Data = [new StrPropertyData(new(asset, "Destination")) { Value = new("original-first") }];
        using var first = new TemporaryPackage(asset);
        Data(asset).Data = [new StrPropertyData(new(asset, "Destination")) { Value = new("original-second") }];
        using var second = new TemporaryPackage(asset);
        Assert.NotEqual(Value(first.Read(), "Destination"), Value(second.Read(), "Destination"));
        var before = InvocationExtractor.Read(Input with { StoragePath = first.PathName });
        var after = InvocationExtractor.Read(Input with { StoragePath = second.PathName });
        Assert.Equal(Assert.Single(before.Invocations).Fact, Assert.Single(after.Invocations).Fact);
        Assert.False(second.Read(new(MaxTotalText: 1)).Complete);
        var policy = new PolicyDocument(1, [new("original", "Original fixture only", RuleEffect.Forbid,
            new MatchExpression.Invocation(new TargetMatcher.Exact("/Script/CoreUObject.Object", "OwnedCall")))]);
        Assert.True(new PolicyEvaluator(policy).Evaluate(after.Analysis).HasForbiddenFindings);
        Assert.Single(after.Analysis.Invocations);
    }

    [Fact]
    public void PublicReadFailureHasFixedDiagnosticsAndNoBaselineSafetyAssertion()
    {
        var missing = Input with { StoragePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")) };
        var evidence = AssetDataExtractor.Read(missing);
        Assert.False(evidence.Complete);
        Assert.Empty(evidence.Properties);
        Assert.Equal(new[] { "package-data-unavailable" }, evidence.Diagnostics.ToArray());
    }

    [Fact]
    public void LimitsCanOnlyBeLowered()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Inspect(Asset(), new(MaxNodes: 4097)));
        Assert.Throws<ArgumentOutOfRangeException>(() => Inspect(Asset(), new(MaxDepth: 0)));
        Assert.Throws<ArgumentOutOfRangeException>(() => Inspect(Asset(), new(MaxTotalText: 65_537)));
    }
}
