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
using UAssetAPI.PropertyTypes.Objects;
using System.Security.Cryptography;
using System.Text.Json;

// Original synthetic serialization, not engine-cooked or game-derived content.
if (args.Length != 2 || args[0] is not ("generate" or "facts" or "properties" or "chains" or "dispatch-budgets" or "data-policy" or "data-budgets" or "data-marker-budget")) return 2;
if (args[0] == "properties") return Properties();
if (args[0] == "chains") return Chains(args[1]);
if (args[0] == "data-policy") return DataPolicyFixtures(args[1]);
if (args[0] == "data-budgets") return DataBudgetFixtures(args[1]);
if (args[0] == "data-marker-budget")
{
    if (Directory.Exists(args[1])) return 2;
    Directory.CreateDirectory(args[1]);
    var asset = DataFixtureAsset();
    AddFunction(asset, "Consume", Enumerable.Range(0, 7996).Select(_ => (KismetExpression)
        new EX_FinalFunction { StackNode = new(-3), Parameters = [] }).ToArray());
    foreach (var index in new[] { -6, -2 })
        asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "Data" + -index), OuterIndex = new(0),
            ClassIndex = new(index), Data = [], Extras = [] });
    asset.Write(Path.Combine(args[1], "Data.uasset"));
    return 0;
}
var root = Path.GetFullPath(args[1]);
if (args[0] == "dispatch-budgets") return DispatchBudgets(root);
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
var graphs = new List<CallGraphContext>();
var gaps = new HashSet<CoverageGap>();
foreach (var path in Directory.GetFiles(root).Where(p => p.EndsWith(".uasset") || p.EndsWith(".umap")).Order())
{
    var input = new PackageInput("submission", "Content/" + Path.GetFileName(path),
        "/Game/" + Path.GetFileNameWithoutExtension(path), path);
    var extracted = InvocationExtractor.Read(input);
    calls.AddRange(extracted.Analysis.Invocations);
    dispatches.AddRange(extracted.Analysis.Dispatches ?? []);
    graphs.Add(extracted.Analysis.CallGraph!);
    gaps.UnionWith(extracted.Analysis.CoverageGaps);
}
Console.OpenStandardOutput().Write(FactsCodec.Write(new FactsDocument(1, new string('a', 64), "4.25", "synthetic-corpus-v1", [],
    new(calls.ToImmutable(), gaps.Order().ToImmutableArray(), dispatches.Count == 0 ? null : dispatches.ToArray(),
        CallGraphContext.Bounded(graphs.SelectMany(g => g.Functions), graphs.All(g => g.Complete) && gaps.Count == 0)))));
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

static int Chains(string destination)
{
    if (Directory.Exists(destination)) return 2;
    Directory.CreateDirectory(destination);
    var asset = Asset();
    asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-1), "Utility", false, asset));
    asset.Imports.Add(new Import("/Script/CoreUObject", "Function", new(-8), "Touch", false, asset));
    asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "BP_Corpus_C"), OuterIndex = new(0),
        ClassIndex = new(-6), Data = [], Extras = [] });
    // Fixture contract: Touch is an opaque native boundary, classified ONLY by the explicit catalog.
    // No implementation, engine applicability or real-world capability is asserted by its name.
    AddFunction(asset, "Wrapper", [new EX_FinalFunction { StackNode = new(-9), Parameters = [] }]);
    AddFunction(asset, "Helper", [new EX_FinalFunction { StackNode = new(2), Parameters = [] },
        new EX_FinalFunction { StackNode = new(4), Parameters = [] }]);
    AddFunction(asset, "Root", [new EX_FinalFunction { StackNode = new(3), Parameters = [] },
        new EX_FinalFunction { StackNode = new(3), Parameters = [] }]);
    AddFunction(asset, "Maybe", [new EX_VirtualFunction { VirtualFunctionName = new(asset, "Helper"), Parameters = [] }]);
    var path = Path.Combine(destination, "CallChains.uasset");
    asset.Write(path);
    var input = new PackageInput("submission", "Content/CallChains.uasset", "/Game/CallChains", path);
    var extraction = InvocationExtractor.Read(input);
    var facts = new FactsDocument(1, new string('a', 64), "4.25", "synthetic-call-chains-v1", [], extraction.Analysis);
    File.WriteAllBytes(Path.Combine(destination, "facts.json"), FactsCodec.Write(facts));
    return 0;
}

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

static int DispatchBudgets(string root)
{
    if (Directory.Exists(root)) return 2;
    Directory.CreateDirectory(root);
    foreach (var mode in new[] { "origins", "candidates", "bytes", "graph" })
    {
        var directory = Path.Combine(root, mode);
        Directory.CreateDirectory(directory);
        foreach (var package in new[] { "A", "B", "Later" })
        {
            var asset = Asset();
            asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "Class"),
                OuterIndex = new(0), ClassIndex = new(-6), Data = [], Extras = [] });
            var name = mode == "bytes" ? new string('S', 3500) : "Sensitive";
            if (mode == "graph")
                for (var i = 0; i < 2200; i++) AddFunction(asset, "Definition" + i, []);
            else if (mode != "origins")
            {
                AddFunction(asset, name, []);
                if (mode == "candidates")
                    for (var i = 1; i < 150; i++)
                    {
                        asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "Owner" + i),
                            OuterIndex = new(0), ClassIndex = new(-6), Data = [], Extras = [] });
                        var owner = asset.Exports.Count;
                        AddFunction(asset, name, []);
                        asset.Exports[^1].OuterIndex = new(owner);
                    }
            }
            var count = package == "Later" || mode == "graph" ? 0 : mode == "origins" ? 6000 : mode == "candidates" ? 40 : 650;
            var code = Enumerable.Range(0, count).Select(_ => (KismetExpression)new EX_InstanceDelegate
                { FunctionName = new(asset, mode == "origins" ? "None" : name) }).ToList();
            code.Add(new EX_FinalFunction { StackNode = new(-3), Parameters = [] });
            AddFunction(asset, "Run", code.ToArray());
            asset.Write(Path.Combine(directory, package + ".uasset"));
            // Verify actual serialized input independently, before Parser aggregation.
            var extracted = InvocationExtractor.Read(new("submission", "Content/" + package + ".uasset",
                "/Game/" + package, Path.Combine(directory, package + ".uasset")));
            PolicyEvaluator.Validate(extracted.Analysis);
            Check(extracted.Analysis.Invocations.Length == 1, "budget-direct-count");
            Check((extracted.Analysis.Dispatches?.Length ?? 0) == count, "budget-origin-count");
            Check((extracted.Analysis.Dispatches?.Sum(d => d.Candidates.Length) ?? 0)
                == count * (mode == "origins" ? 0 : mode == "candidates" ? 150 : 1), "budget-candidate-count");
        }
    }
    return 0;
}

static void Check(bool valid, string name)
{
    if (!valid) throw new InvalidOperationException(name);
}

static int DataPolicyFixtures(string destination)
{
    if (Directory.Exists(destination)) return 2;
    Directory.CreateDirectory(destination);
    var bytecodes = new List<byte[]>();
    var analyses = new List<InvocationAnalysis>();
    foreach (var version in new[] { "baseline", "submission" })
    {
        var directory = Path.Combine(destination, version);
        Directory.CreateDirectory(directory);
        var asset = DataFixtureAsset();
        asset.AddNameReference(new("StrProperty"));
        asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "Data"), OuterIndex = new(0),
            ClassIndex = new(-6), Data = [new StrPropertyData(new(asset, "Destination"))
                { Value = new(version == "baseline" ? "original-fixture-destination" : "private-data-canary") }], Extras = [] });
        // Original illustrative source model: Record(self.Destination). This serialized
        // property pointer is source proof, not engine execution or a game/native catalog.
        AddFunction(asset, "Consume", [new EX_FinalFunction { StackNode = new(-3), Parameters = [
            new EX_InstanceVariable { Variable = new KismetPropertyPointer(new FFieldPath
                { Path = [new(asset, "Destination")], ResolvedOwner = new(1) }) }] }]);
        var path = Path.Combine(directory, "Data.uasset");
        asset.Write(path);
        var input = new PackageInput("submission", "Content/Data.uasset", "/Game/Data", path);
        var parsed = PackageReader.Read(path, null);
        var function = (FunctionExport)parsed.Exports[1];
        using var stream = new MemoryStream();
        using (var writer = new AssetBinaryWriter(stream, parsed))
            foreach (var expression in function.ScriptBytecode) ExpressionSerializer.WriteExpression(expression, writer);
        var code = stream.ToArray();
        Check(File.ReadAllBytes(path).AsSpan().IndexOf(code) >= 0, "data-bytecode-stored-exactly");
        bytecodes.Add(code);
        var extraction = InvocationExtractor.Read(input);
        analyses.Add(extraction.Analysis);
        var data = AssetDataExtractor.Read(input);
        Check(data.Complete && data.Properties.Length == 1, "data-serialized-properties");
        var facts = new FactsDocument(1, new(version == "baseline" ? 'b' : 'a', 64), "4.25", "original-data-fixture-v1", [], extraction.Analysis,
            new("validated", "ok", [new("r00000000", input.Entry, new FileInfo(path).Length,
                Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))), "payload_verified", ["unreal_package_tag"], [], "parsed", "resolved", PathNormalized: true)]),
            new(1, "Content", "/Game", true, [new("r00000000", data)]));
        File.WriteAllBytes(Path.Combine(destination, version + "-facts.json"), FactsCodec.Write(facts));
    }
    Check(bytecodes[0].SequenceEqual(bytecodes[1]), "data-bytecode-unchanged");
    Check(analyses[0].Invocations.SequenceEqual(analyses[1].Invocations), "data-invocations-unchanged");
    var context = new DataBuildContext("4.25", "original-fixture-v1", "Content", "/Game", null, "submission-over-baseline");
    var rules = new DataPolicyDocument(1, "private", context, new(new('b', 64), context), [
        new("private-original-model", "Content/Data.uasset", "/Game/Data.Data", "Object", false,
            [new("Destination", 0)], "changed", null, "review", "Original fixture Record(self.Destination) model only",
            "tests/Corpus.Generate/Program.cs; not a game implementation or native-code certification")]);
    // Read the actual resolved class identity; do not guess an import's owning namespace.
    var submitted = FactsCodec.Read(File.ReadAllBytes(Path.Combine(destination, "submission-facts.json")));
    rules = rules with { Rules = [rules.Rules[0] with { ClassIdentity = submitted.AssetData!.Packages[0].Evidence.Properties[0].ClassIdentity! }] };
    var json = JsonSerializer.SerializeToUtf8Bytes(rules, RiskReport.JsonOptions);
    File.WriteAllBytes(Path.Combine(destination, "data-rules.json"), json);
    var result = DataPolicy.Read(json).Evaluate(submitted, context.BuildScope,
        FactsCodec.Read(File.ReadAllBytes(Path.Combine(destination, "baseline-facts.json"))));
    Check(result.Complete && result.Findings.Length == 1, "data-policy-finding");
    File.WriteAllText(Path.Combine(destination, "proof.json"), JsonSerializer.Serialize(new
    {
        bytecodeSha256 = Convert.ToHexStringLower(SHA256.HashData(bytecodes[0])), bytecodeUnchanged = true,
        invocationFactsUnchanged = true, invocations = analyses[0].Invocations.Length, dataFindings = result.Findings.Length,
        evidence = "Original serialized fixture and reviewed source model; not engine/game execution"
    }));
    return 0;
}

static UAsset DataFixtureAsset()
{
    var asset = Asset();
    asset.UseSeparateBulkDataFiles = false;
    asset.Imports.Add(new Import("/Script/CoreUObject", "Package", new(0), "/Script/CoreUObject", false, asset));
    asset.Imports[5].OuterIndex = new(-8);
    asset.Imports[6].OuterIndex = new(-8);
    return asset;
}

static int DataBudgetFixtures(string destination)
{
    if (Directory.Exists(destination)) return 2;
    Directory.CreateDirectory(destination);
    foreach (var name in new[] { "A", "B", "C", "D", "E", "Later" })
    {
        var asset = DataFixtureAsset();
        asset.AddNameReference(new("IntProperty"));
        asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "Data"), OuterIndex = new(0),
            ClassIndex = new(-6), Data = Enumerable.Range(0, 4096).Select(i => (PropertyData)new IntPropertyData(new(asset, "Property" + i))
                { Value = i }).ToList(), Extras = [] });
        AddFunction(asset, "Consume", [new EX_FinalFunction { StackNode = new(-3), Parameters = [] }]);
        asset.Write(Path.Combine(destination, name + ".uasset"));
    }
    return 0;
}

static void Reject<T>(Action operation) where T : Exception
{
    try { operation(); }
    catch (T) { return; }
    throw new InvalidOperationException("Expected rejection: " + typeof(T).Name);
}
