using System.Collections.Immutable;
using CompatibilityProbe;
using PakRisk.Extraction;
using PakRisk.Policy;
using PakRisk.Scanner;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.FieldTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;

// Original synthetic serialization, not engine-cooked or game-derived content.
if (args.Length != 2 || args[0] is not ("generate" or "facts" or "properties")) return 2;
if (args[0] == "properties") return Properties();
var root = Path.GetFullPath(args[1]);
if (args[0] == "generate")
{
    if (Directory.Exists(root)) return 2;
    Directory.CreateDirectory(root);
    foreach (var name in new[] { "Calls", "Map", "Unresolved", "Unsupported" })
    {
        var asset = Asset();
        KismetExpression Call(params KismetExpression[] values) => new EX_FinalFunction { StackNode = new(-3), Parameters = values };
        KismetExpression[] code = name switch
        {
            "Calls" => [Call(new EX_IntConst { Value = 101 }), Call(Call()),
                new EX_FinalFunction { StackNode = new(-5), Parameters = [] },
                new EX_FinalFunction { StackNode = new(2), Parameters = [new EX_IntOne()] },
                new EX_FinalFunction { StackNode = new(2), Parameters = [new EX_Self()] }],
            "Map" => [Call(new EX_IntConst { Value = 303 })],
            "Unresolved" => [Call(), new EX_VirtualFunction { VirtualFunctionName = new(asset, "DynamicDispatch"), Parameters = [] }],
            _ => [Call(), new EX_StringConst { Value = "é" }, Call()]
        };
        asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "BP_Corpus_C"),
            OuterIndex = new(0), ClassIndex = new(-6), Data = [], Extras = [] });
        AddFunction(asset, name == "Unresolved" ? "DynamicDispatch" : "Local", []);
        ((FunctionExport)asset.Exports[1]).LoadedProperties = [new FGenericProperty {
            Name = new(asset, "Value"), SerializedType = new(asset, "IntProperty"),
            RepNotifyFunc = new(asset, "None"), ElementSize = 4, ArrayDim = (EArrayDim)1,
            PropertyFlags = EPropertyFlags.CPF_Parm }];
        AddFunction(asset, "ExecuteUbergraph_Corpus", code);
        asset.Write(Path.Combine(root, name + (name == "Map" ? ".umap" : ".uasset")));
    }
    return 0;
}
var calls = ImmutableArray.CreateBuilder<InvocationFact>();
var dispatches = new List<IndirectDispatch>();
var gaps = new HashSet<CoverageGap>();
foreach (var path in Directory.GetFiles(root).Where(p => p.EndsWith(".uasset") || p.EndsWith(".umap")).Order())
{
    var input = new PackageInput("submission", "Content/" + Path.GetFileName(path),
        "/Game/" + Path.GetFileNameWithoutExtension(path), path);
    var extracted = InvocationExtractor.Read(input);
    calls.AddRange(extracted.Analysis.Invocations);
    dispatches.AddRange(extracted.Analysis.Dispatches ?? []);
    gaps.UnionWith(extracted.Analysis.CoverageGaps);
}
Console.OpenStandardOutput().Write(FactsCodec.Write(new FactsDocument(1, new string('a', 64), "4.25", "synthetic-corpus-v1", [],
    new(calls.ToImmutable(), gaps.Order().ToImmutableArray(), dispatches.Count == 0 ? null : dispatches.ToArray()))));
return 0;

static UAsset Asset()
{
    var asset = new UAsset(EngineVersion.VER_UE4_25)
    {
        PackageFlags = EPackageFlags.PKG_Cooked | EPackageFlags.PKG_FilterEditorOnly,
        Imports = [], Exports = [], LegacyFileVersion = -7, FolderName = new("None"),
        Generations = [], ChunkIDs = [], AssetRegistryRecords = [], AdditionalFiles = [],
        RecordedEngineVersion = new(), RecordedCompatibleWithEngineVersion = new(),
        UseSeparateBulkDataFiles = true
    };
    asset.ClearNameIndexList();
    asset.AddNameReference(new("None"));
    // Upstream initializes this internal header list only during Read.
    typeof(UAsset).GetField("AdditionalPackagesToCook", System.Reflection.BindingFlags.Instance
        | System.Reflection.BindingFlags.NonPublic)!.SetValue(asset, new List<FString>());
    typeof(UAsset).GetField("doWeHaveWorldTileInfo", System.Reflection.BindingFlags.Instance
        | System.Reflection.BindingFlags.NonPublic)!.SetValue(asset, false);
    asset.Imports.Add(new Import("/Script/CoreUObject", "Package", new(0), "/Script/Corpus", false, asset));
    asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-1), "Sensitive", false, asset));
    asset.Imports.Add(new Import("/Script/CoreUObject", "Function", new(-2), "Record", false, asset));
    asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-1), "Other", false, asset));
    asset.Imports.Add(new Import("/Script/CoreUObject", "Function", new(-4), "Record", false, asset));
    asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(0), "Object", false, asset));
    asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(0), "Function", false, asset));
    return asset;
}

static void AddFunction(UAsset asset, string name, KismetExpression[] code) => asset.Exports.Add(new FunctionExport
{
    Asset = asset, ObjectName = new(asset, name), OuterIndex = new(1), ClassIndex = new(-7),
    ScriptBytecode = code, ScriptBytecodeSize = code.Sum(e => (int)e.GetSize(asset)),
    LoadedProperties = [], Children = [], Data = [], Extras = [], Field = new(), SuperStruct = new(0)
});

static int Properties()
{
    var random = new Random(150425);
    for (var i = 0; i < 32; i++)
    {
        var number = random.Next(-100000, 100000);
        var policy = new PolicyDocument(1, [new("seeded", "Original seeded property", RuleEffect.Flag,
            new MatchExpression.Argument("Value", new ValuePredicate.EqualTo(new PolicyLiteral.Integer(number))))]);
        for (var depth = random.Next(5); depth > 0; depth--)
            policy = new PolicyDocument(1, [policy.Rules[0] with { Match = new MatchExpression.Not(policy.Rules[0].Match) }]);
        var canonical = PolicyYaml.Write(policy);
        Check(canonical == PolicyYaml.Write(PolicyYaml.Parse(canonical)), "yaml-ast-roundtrip");
        Reject<PolicyException>(() => PolicyYaml.Parse(canonical.Replace("\"schema-version\": 1", "\"schema-version\": 9")));
        var asset = Asset();
        KismetExpression[] code = [new EX_IntConst { Value = number },
            new EX_FinalFunction { StackNode = new(-3), Parameters = [new EX_IntConst { Value = number }] }];
        using var stream = new MemoryStream();
        using var writer = new AssetBinaryWriter(stream, asset);
        foreach (var expression in code) ExpressionSerializer.WriteExpression(expression, writer);
        stream.Position = 0;
        using var reader = new AssetBinaryReader(stream, asset);
        var parsed = code.Select(_ => ExpressionSerializer.ReadExpression(reader)).ToArray();
        Check(stream.Position == stream.Length, "bytecode-consumed");
        using var truncated = new MemoryStream(stream.ToArray()[..random.Next(1, 5)]);
        using var truncatedReader = new AssetBinaryReader(truncated, asset);
        // Pinned UnrealBinaryReader uses BitConverter for short integer reads.
        Reject<ArgumentException>(() => ExpressionSerializer.ReadExpression(truncatedReader));
        asset.Exports.Add(new NormalExport { ObjectName = new(asset, "BP_Corpus_C"), OuterIndex = new(0) });
        AddFunction(asset, "Seeded", parsed);
        var result = InvocationExtractor.Inspect(asset, new("seed", "entry", "/Game/Seeded", "unused"));
        Check(result.Invocations.Length == 1 && result.Invocations[0].Offset == 5, "bytecode-vm-offset");
        Check(result.Analysis.CoverageGaps.IsEmpty, "bytecode-coverage: " + string.Join(",", result.Functions.SelectMany(f => f.Diagnostics).Select(d => d.Code)));
        var facts = new FactsDocument(1, new string('a', 64), "4.25", "seeded", [], result.Analysis);
        var bytes = FactsCodec.Write(facts);
        Check(bytes.SequenceEqual(FactsCodec.Write(FactsCodec.Read(bytes))), "facts-roundtrip");
        var bad = System.Text.Encoding.UTF8.GetBytes(System.Text.Encoding.UTF8.GetString(bytes)
            .Replace("\"schema-version\":1", "\"schema-version\":1,\"schema-version\":1"));
        Reject<FactsException>(() => FactsCodec.Read(bad));
    }
    Console.WriteLine("PASS: 32 seeded YAML/AST, serialized bytecode and facts properties; seed=150425.");
    return 0;
}

static void Check(bool valid, string name)
{
    if (!valid) throw new InvalidOperationException(name);
}

static void Reject<T>(Action operation) where T : Exception
{
    try { operation(); }
    catch (T) { return; }
    throw new InvalidOperationException("Expected rejection: " + typeof(T).Name);
}
