using PakRisk.Extraction;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.FieldTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;
using Xunit;

namespace CompatibilityProbe.Tests;

public sealed class PropertyWriteTests
{
    private static readonly PackageInput Input = new("submission", "Content/Writes.uasset", "/Game/Writes", "unused");
    private static KismetPropertyPointer Pointer(UAsset asset, int owner, params string[] names) =>
        new(new FFieldPath { ResolvedOwner = new(owner), Path = names.Select(n => new FName(asset, n)).ToArray() });
    private static EX_InstanceVariable Instance(UAsset asset, string name) => new() { Variable = Pointer(asset, 1, name) };

    private static ExtractionReport Extract(UAsset asset, params KismetExpression[] code) => Extract(asset, [], code);

    private static ExtractionReport Extract(UAsset asset, FProperty[] properties, params KismetExpression[] code)
    {
        var index = PackageContextFixture.Function(asset, "Run");
        ((FunctionExport)asset.Exports[index - 1]).LoadedProperties = properties;
        using var stream = new MemoryStream();
        using var writer = new AssetBinaryWriter(stream, asset);
        var size = code.Sum(e => ExpressionSerializer.WriteExpression(e, writer));
        stream.Position = 0;
        using var reader = new AssetBinaryReader(stream, asset);
        var parsed = code.Select(_ => ExpressionSerializer.ReadExpression(reader)).ToArray();
        ((FunctionExport)asset.Exports[index - 1]).ScriptBytecode = parsed;
        ((FunctionExport)asset.Exports[index - 1]).ScriptBytecodeSize = size;
        return InvocationExtractor.Inspect(asset, Input);
    }

    [Theory]
    [InlineData("EX_Let")]
    [InlineData("EX_LetBool")]
    [InlineData("EX_LetObj")]
    [InlineData("EX_LetWeakObjPtr")]
    [InlineData("EX_LetDelegate")]
    [InlineData("EX_LetMulticastDelegate")]
    public void SerializedAssignmentVariantsRetainDestinationAndOffset(string opcode)
    {
        var asset = PackageContextFixture.Asset("Type");
        var destination = Instance(asset, "Sensitive");
        KismetExpression assignment = opcode == "EX_Let" ? new EX_Let {
            Value = Pointer(asset, 1, "NotTheDestination"), Variable = destination, Expression = new EX_IntOne() }
            : opcode switch {
                "EX_LetBool" => new EX_LetBool(), "EX_LetObj" => new EX_LetObj(),
                "EX_LetWeakObjPtr" => new EX_LetWeakObjPtr(), "EX_LetDelegate" => new EX_LetDelegate(),
                _ => new EX_LetMulticastDelegate() };
        if (assignment is EX_LetBase let) { let.VariableExpression = destination; let.AssignmentExpression = new EX_IntOne(); }
        var report = Extract(asset, new EX_IntZero(), assignment);
        var write = Assert.Single(report.Analysis.PropertyWrites!.Writes);
        Assert.Equal("/Game/Writes.Type", write.Owner);
        Assert.Equal("Sensitive", write.Property);
        Assert.Equal(opcode, write.Opcode);
        Assert.Equal(1, write.Location.Offset);
        Assert.Equal(new ArgumentValue.Constant(new PolicyLiteral.Integer(1)), write.Value);
        Assert.Empty(report.Analysis.Invocations);
    }

    [Fact]
    public void StructFieldWritesRetainRootAndWholeStructWritesAreNotLost()
    {
        var asset = PackageContextFixture.Asset("Type");
        var memberOwner = PackageContextFixture.ImportClass(asset, "/Script/Example", "Settings");
        var member = new EX_StructMemberContext { StructExpression = Instance(asset, "Settings"),
            StructMemberExpression = Pointer(asset, memberOwner, "Distance") };
        var report = Extract(asset,
            new EX_Let { Value = Pointer(asset, 1, "Settings"), Variable = member, Expression = new EX_FloatConst { Value = 5000 } },
            new EX_Let { Value = Pointer(asset, 1, "Settings"), Variable = Instance(asset, "Settings"), Expression = new EX_Self() });
        Assert.Equal(["Settings.Distance", "Settings"], report.Analysis.PropertyWrites!.Writes.Select(w => w.Property));
        var policy = new PolicyDocument(1, [new("test", "Test", RuleEffect.Forbid,
            new MatchExpression.PropertyWrite(null, "Settings.Distance"))]);
        var result = new PolicyEvaluator(policy).Evaluate(report.Analysis);
        Assert.Single(result.PropertyWriteFindings);
        Assert.Contains(UncertaintyReason.AncestorPropertyWrite, Assert.Single(result.Uncertainties).Reasons);
    }

    [Fact]
    public void LocalStructConstructionAndPersistentLocalsAreNotInstanceWrites()
    {
        var asset = PackageContextFixture.Asset("Type");
        var local = new EX_LocalVariable { Variable = Pointer(asset, 3, "Temporary") };
        var member = new EX_StructMemberContext { StructExpression = local,
            StructMemberExpression = Pointer(asset, 1, "Distance") };
        var report = Extract(asset, [new FGenericProperty { Name = new(asset, "Temporary") }],
            new EX_Let { Value = local.Variable, Variable = member, Expression = new EX_IntOne() },
            new EX_LetValueOnPersistentFrame { DestinationProperty = local.Variable, AssignmentExpression = new EX_IntOne() });
        Assert.Empty(report.Analysis.PropertyWrites!.Writes);
        Assert.True(report.Analysis.PropertyWrites.Complete);
    }

    [Fact]
    public void ContextReceiversAndImportedOwnersAreRecordedWithoutClaimingOwnership()
    {
        var asset = PackageContextFixture.Asset("Type");
        var owner = PackageContextFixture.ImportClass(asset, "/Script/Engine", "Actor");
        var write = new EX_Let { Value = Pointer(asset, owner, "CustomTimeDilation"),
            Variable = new EX_InstanceVariable { Variable = Pointer(asset, owner, "CustomTimeDilation") }, Expression = new EX_FloatConst { Value = 90 } };
        var context = new EX_Context { ObjectExpression = new EX_Self(), RValuePointer = Pointer(asset, owner, "CustomTimeDilation"), ContextExpression = write };
        var fact = Assert.Single(Extract(asset, context).Analysis.PropertyWrites!.Writes);
        Assert.Equal("/Script/Engine.Actor", fact.Owner);
        Assert.Equal("object", fact.Receiver);
        Assert.Equal(new ArgumentValue.Constant(new PolicyLiteral.Number(90)), fact.Value);
    }

    [Fact]
    public void LegacyPropertyPointersResolveAndFunctionLocalPointersDoNotEscape()
    {
        var asset = PackageContextFixture.Asset("Type");
        asset.Exports.Add(new PropertyExport { ObjectName = new(asset, "Sensitive"), OuterIndex = new(1) });
        foreach (var version in asset.CustomVersionContainer)
            if (version.FriendlyName == "FReleaseObjectVersion") version.Version = 0;
        var pointer = new KismetPropertyPointer(new FPackageIndex(3));
        var report = Extract(asset, new EX_LetObj { VariableExpression = new EX_InstanceVariable { Variable = pointer }, AssignmentExpression = new EX_NoObject() });
        Assert.Equal("Sensitive", Assert.Single(report.Analysis.PropertyWrites!.Writes).Property);
    }

    [Fact]
    public void OutAliasesAndUnresolvableOwnersRemainIncomplete()
    {
        var asset = PackageContextFixture.Asset("Type");
        var report = Extract(asset,
            new EX_LetObj { VariableExpression = new EX_LocalOutVariable { Variable = Pointer(asset, 3, "Alias") }, AssignmentExpression = new EX_Self() },
            new EX_LetBool { VariableExpression = new EX_InstanceVariable { Variable = Pointer(asset, 0, "Sensitive") }, AssignmentExpression = new EX_True() });
        Assert.Equal(2, report.Analysis.PropertyWrites!.Writes.Length);
        Assert.False(report.Analysis.PropertyWrites.Complete);
        Assert.Contains(CoverageGap.IncompleteExtraction, report.Analysis.CoverageGaps);
    }

    [Theory]
    [InlineData("array")]
    [InlineData("map")]
    [InlineData("set")]
    public void ContainerReplacementRetainsDestinationButNotInventedScalarValue(string kind)
    {
        var asset = PackageContextFixture.Asset("Type");
        KismetExpression expression = kind switch
        {
            "array" => new EX_SetArray { AssigningProperty = Instance(asset, "Items"), Elements = [] },
            "map" => new EX_SetMap { MapProperty = Instance(asset, "Items"), Elements = [] },
            _ => new EX_SetSet { SetProperty = Instance(asset, "Items"), Elements = [] }
        };
        var write = Assert.Single(Extract(asset, expression).Analysis.PropertyWrites!.Writes);
        Assert.Equal("Items", write.Property);
        Assert.IsType<ArgumentValue.Dynamic>(write.Value);
    }

    [Fact]
    public void ReferenceParameterCannotBeDiscardedAsHarmlessLocal()
    {
        var asset = PackageContextFixture.Asset("Type");
        var function = PackageContextFixture.Function(asset, "Run");
        ((FunctionExport)asset.Exports[function - 1]).LoadedProperties = [new FGenericProperty {
            Name = new(asset, "Alias"), PropertyFlags = EPropertyFlags.CPF_Parm | EPropertyFlags.CPF_ReferenceParm }];
        var assignment = new EX_LetObj { VariableExpression = new EX_LocalVariable { Variable = Pointer(asset, function, "Alias") }, AssignmentExpression = new EX_Self() };
        var target = (FunctionExport)asset.Exports[function - 1];
        target.ScriptBytecode = [assignment]; target.ScriptBytecodeSize = (int)assignment.GetSize(asset);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Single(report.Analysis.PropertyWrites!.Writes);
        Assert.False(report.Analysis.PropertyWrites.Complete);
    }

    [Theory]
    [InlineData("missing", false)]
    [InlineData("unrelated", false)]
    [InlineData("duplicate", false)]
    [InlineData("conflicting", false)]
    [InlineData("out", false)]
    [InlineData("ref", false)]
    [InlineData("local", true)]
    [InlineData("parameter", true)]
    public void SerializedLocalExclusionRequiresUniqueNonAliasingDeclaration(string metadata, bool harmless)
    {
        var asset = PackageContextFixture.Asset("Type");
        var index = PackageContextFixture.Function(asset, "Run");
        FProperty Declaration(string name, EPropertyFlags flags = 0) => new FGenericProperty { Name = new(asset, name), PropertyFlags = flags };
        var function = (FunctionExport)asset.Exports[index - 1];
        function.LoadedProperties = metadata switch
        {
            "missing" => [],
            "unrelated" => [Declaration("Other")],
            "duplicate" => [Declaration("Alias"), Declaration("Alias")],
            "conflicting" => [Declaration("Alias"), Declaration("Alias", EPropertyFlags.CPF_ReferenceParm)],
            "out" => [Declaration("Alias", EPropertyFlags.CPF_Parm | EPropertyFlags.CPF_OutParm)],
            "ref" => [Declaration("Alias", EPropertyFlags.CPF_Parm | EPropertyFlags.CPF_ReferenceParm)],
            "parameter" => [Declaration("Alias", EPropertyFlags.CPF_Parm)],
            _ => [Declaration("Alias")]
        };
        var pointer = Pointer(asset, index, "Alias");
        function.ScriptBytecode = [
            new EX_LetObj { VariableExpression = new EX_LocalVariable { Variable = pointer }, AssignmentExpression = new EX_Self() },
            new EX_LetValueOnPersistentFrame { DestinationProperty = pointer, AssignmentExpression = new EX_Self() }];
        function.ScriptBytecodeSize = function.ScriptBytecode.Sum(e => (int)e.GetSize(asset));
        var root = Path.Combine(Path.GetTempPath(), "property-write-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "Writes.uasset");
            asset.Write(path);
            foreach (var report in new[] { InvocationExtractor.Inspect(asset, Input), InvocationExtractor.Read(Input with { StoragePath = path }) })
            {
                Assert.Equal(harmless ? 0 : 2, report.Analysis.PropertyWrites!.Writes.Length);
                Assert.Equal(harmless, report.Analysis.PropertyWrites.Complete);
                var policy = new PolicyDocument(1, [new("test", "Test", RuleEffect.Forbid, new MatchExpression.PropertyWrite(null, "Alias"))]);
                var result = new PolicyEvaluator(policy).Evaluate(report.Analysis);
                Assert.Equal(!harmless, result.IsIncomplete);
                Assert.Empty(result.PropertyWriteFindings);
                Assert.Equal(harmless ? 0 : 2, result.Uncertainties.Length);
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData("missing", false)]
    [InlineData("duplicate", false)]
    [InlineData("out", false)]
    [InlineData("ref", false)]
    [InlineData("local", true)]
    public void LegacyLocalExclusionRequiresUniqueNonAliasingDeclaration(string metadata, bool harmless)
    {
        var asset = PackageContextFixture.Asset("Type");
        var index = PackageContextFixture.Function(asset, "Run");
        var property = new PropertyExport { ObjectName = new(asset, "Alias"), OuterIndex = new(index),
            Property = metadata == "missing" ? null : new UIntProperty {
                PropertyFlags = metadata switch { "out" => EPropertyFlags.CPF_OutParm, "ref" => EPropertyFlags.CPF_ReferenceParm, _ => 0 } } };
        asset.Exports.Add(property);
        var pointer = new KismetPropertyPointer(new FPackageIndex(asset.Exports.Count));
        if (metadata == "duplicate")
            asset.Exports.Add(new PropertyExport { ObjectName = new(asset, "Alias"), OuterIndex = new(index), Property = new UIntProperty() });
        var function = (FunctionExport)asset.Exports[index - 1];
        function.ScriptBytecode = [new EX_LetObj {
            VariableExpression = new EX_LocalVariable { Variable = pointer }, AssignmentExpression = new EX_Self() }];
        foreach (var version in asset.CustomVersionContainer)
            if (version.FriendlyName == "FReleaseObjectVersion") version.Version = 0;
        function.ScriptBytecodeSize = function.ScriptBytecode.Sum(e => (int)e.GetSize(asset));
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal(harmless ? 0 : 1, report.Analysis.PropertyWrites!.Writes.Length);
        Assert.Equal(harmless, report.Analysis.PropertyWrites.Complete);
    }
}
