using CompatibilityProbe;
using PakRisk.Extraction;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;
using Xunit;

namespace CompatibilityProbe.Tests;

public sealed class ArchiveDispatchTests
{
    private sealed class Packages : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "archive-dispatch-" + Guid.NewGuid().ToString("N"));
        internal readonly Dictionary<string, PackageInput> Inputs = [];
        internal Packages(Action<Dictionary<string, UAsset>>? change = null)
        {
            Directory.CreateDirectory(root);
            var assets = PackageContextFixture.Create(); change?.Invoke(assets);
            foreach (var (name, asset) in assets)
            {
                var path = Path.Combine(root, name + ".uasset"); asset.Write(path);
                Inputs.Add(name, new("submission", "Content/" + name + ".uasset", "/Game/" + name, path));
            }
        }
        internal UAsset Read(string name) => PackageReader.Read(Inputs[name].StoragePath, null);
        internal ArchiveDispatchContext Context(ArchiveDispatchLimits? limits = null, bool reverse = false)
        {
            var context = new ArchiveDispatchContext(limits);
            var names = Inputs.Keys.Order(StringComparer.Ordinal).ToArray();
            foreach (var name in reverse ? names.Reverse() : names) context.Add(Read(name), Inputs[name]);
            context.Seal(); return context;
        }
        internal ExtractionReport Inspect(string name, ArchiveDispatchContext context, ExtractionLimits? limits = null) =>
            InvocationExtractor.Read(Inputs[name], limits: limits, archiveContext: context);
        public void Dispose() => Directory.Delete(root, true);
    }

    [Fact]
    public void SeparateSerializedPackagesLinkOverrideInterfaceAndCaseFoldedImportsWithoutClosingWorld()
    {
        using var packages = new Packages();
        Assert.IsType<ClassExport>(packages.Read("Base").Exports[0]);
        var context = packages.Context();
        var parent = packages.Inspect("Base", context);
        var dispatch = Assert.Single(parent.Analysis.Dispatches!);
        Assert.Contains(dispatch.Candidates, c => c.Owner == "/Game/ChildOverride.Type" && c.Provenance == "override");
        Assert.DoesNotContain(dispatch.Candidates, c => c.Owner == "/Game/Collision.Type");
        var caller = packages.Inspect("Caller", context).Analysis.Dispatches!;
        Assert.Equal(3, caller.Length);
        Assert.Contains(caller[0].Candidates, c => c.Owner == "/Game/Base.Type" && c.Provenance == "inherited-function");
        Assert.Contains(caller[0].Candidates, c => c.Owner == "/Game/ChildOverride.Type" && c.Provenance == "override");
        Assert.DoesNotContain(caller[0].Candidates, c => c.Owner == "/Game/Collision.Type");
        Assert.Contains(caller[1].Candidates, c => c.Owner == "/Game/ChildOverride.Type" && c.Provenance == "interface-implementation");
        Assert.Contains(caller[2].Candidates, c => c.Owner == "/Game/Collision.Type" && c.Provenance == "archive-function");
        Assert.Contains("receiver-unavailable", caller[2].Diagnostics);
        Assert.All(caller.Append(dispatch), d => { Assert.Equal("possible", d.Resolution); Assert.Contains("open-world", d.Diagnostics); });
        PolicyEvaluator.Validate(parent.Analysis);
    }

    [Fact]
    public void ContextIsAdditiveAndKeepsEveryOriginalDirectLocationTargetAndCount()
    {
        using var packages = new Packages();
        var context = packages.Context();
        foreach (var name in packages.Inputs.Keys)
        {
            var before = InvocationExtractor.Read(packages.Inputs[name]);
            var after = packages.Inspect(name, context);
            Assert.Equal(before.Analysis.Invocations.Select(c => (c.Location, c.Target)), after.Analysis.Invocations.Select(c => (c.Location, c.Target)));
            Assert.Equal(before.Invocations.Select(c => (c.Offset, c.Opcode, c.ContainingFunction)), after.Invocations.Select(c => (c.Offset, c.Opcode, c.ContainingFunction)));
        }
    }

    [Fact]
    public void ReorderedIndexInsertionHasIdenticalCandidateOrderAndDiagnostics()
    {
        using var packages = new Packages();
        var forward = packages.Context(); var reverse = packages.Context(reverse: true);
        foreach (var name in packages.Inputs.Keys)
        {
            var first = packages.Inspect(name, forward).Analysis.Dispatches ?? [];
            var second = packages.Inspect(name, reverse).Analysis.Dispatches ?? [];
            Assert.Equal(first.Length, second.Length);
            for (var i = 0; i < first.Length; i++)
            { Assert.Equal(first[i].Candidates.ToArray(), second[i].Candidates.ToArray()); Assert.Equal(first[i].Diagnostics.ToArray(), second[i].Diagnostics.ToArray()); }
        }
    }

    [Theory]
    [InlineData("missing", "dependency-context-unavailable")]
    [InlineData("cycle", "class-cycle")]
    [InlineData("index", "class-metadata-unavailable")]
    [InlineData("collision", "class-metadata-unavailable")]
    public void IncompleteCrossPackageHierarchyNeverQuietlyExcludesPossibleImplementations(string mode, string diagnostic)
    {
        using var packages = new Packages(assets =>
        {
            if (mode == "missing") assets.Remove("Base");
            if (mode == "cycle") PackageContextFixture.Parent(assets["Base"], PackageContextFixture.ImportClass(assets["Base"], "/Game/ChildOverride"));
            if (mode == "index") PackageContextFixture.Parent(assets["ChildOverride"], int.MinValue);
            if (mode == "collision")
            {
                var asset = assets["ChildOverride"];
                asset.Exports.Add(new ClassExport { Asset = asset, ObjectName = new(asset, "Type"), OuterIndex = new(0), ClassIndex = new(-2),
                    SuperIndex = new(0), SuperStruct = new(0), Data = [], Extras = [], Field = new(), Children = [], LoadedProperties = [],
                    ScriptBytecode = [], FuncMap = new(), ClassWithin = new(-4), ClassConfigName = new(asset, "None"), ClassGeneratedBy = new(0),
                    Interfaces = [], ClassDefaultObject = new(0), bCooked = true });
            }
        });
        var report = packages.Inspect("Caller", packages.Context());
        Assert.Contains(report.Analysis.Dispatches!, d => d.Diagnostics.Contains(diagnostic));
        Assert.Contains(CoverageGap.IncompleteExtraction, report.Analysis.CoverageGaps);
        Assert.Contains(CoverageGap.UnresolvedDispatch, report.Analysis.CoverageGaps);
        Assert.Contains(report.Analysis.Dispatches![0].Candidates,
            c => c.Owner == (mode == "index" ? "/Game/ChildOverride.Type" : "/Game/Collision.Type"));
    }

    [Theory]
    [InlineData("classes")]
    [InlineData("functions")]
    [InlineData("edges")]
    [InlineData("operations")]
    [InlineData("depth")]
    [InlineData("text")]
    [InlineData("candidates")]
    [InlineData("origins")]
    public void GlobalLimitsRetainOriginsAndMandatoryCalls(string bound)
    {
        var limits = bound switch
        {
            "classes" => new ArchiveDispatchLimits(MaxClasses: 1), "functions" => new(MaxFunctions: 1),
            "edges" => new(MaxEdges: 1), "operations" => new(MaxOperations: 1), "depth" => new(MaxDepth: 1),
            "text" => new(MaxCharacters: 1), "candidates" => new(MaxCandidates: 1), _ => new(MaxOrigins: 1)
        };
        using var packages = new Packages();
        var context = packages.Context(limits);
        var report = packages.Inspect("Caller", context);
        Assert.Equal(3, report.Analysis.Dispatches!.Length);
        Assert.Contains(report.Analysis.Dispatches, d => d.Diagnostics.Contains("target-expansion-limit"));
        Assert.Single(packages.Inspect("ChildOverride", context).Invocations);
        PolicyEvaluator.Validate(report.Analysis);
    }

    [Fact]
    public void LoweredPerDispatchLimitKeepsTheOriginalLocalCandidate()
    {
        using var packages = new Packages();
        var report = packages.Inspect("Base", packages.Context(), new(MaxTargets: 1));
        var dispatch = Assert.Single(report.Analysis.Dispatches!);
        Assert.Equal("/Game/Base.Type", Assert.Single(dispatch.Candidates).Owner);
        Assert.Contains("target-expansion-limit", dispatch.Diagnostics);
        Assert.Single(report.Invocations);
    }

    [Fact]
    public void DuplicateFunctionIdentityIsUnknownNotAnUnambiguousArchiveDefinition()
    {
        using var packages = new Packages(assets =>
        {
            // The writer's function map cannot contain duplicate keys; the duplicate
            // export is serialized independently and must not win by source order.
            var asset = assets["ChildOverride"];
            asset.Exports.Add(new FunctionExport { Asset = asset, ObjectName = new(asset, "Sensitive"), OuterIndex = new(1),
                ClassIndex = new(-3), SuperStruct = new(0), ScriptBytecode = [], Data = [], Extras = [], Field = new(), Children = [], LoadedProperties = [] });
        });
        var dispatch = packages.Inspect("Base", packages.Context()).Analysis.Dispatches![0];
        Assert.DoesNotContain(dispatch.Candidates, c => c.Owner == "/Game/ChildOverride.Type");
        Assert.Contains("class-metadata-unavailable", dispatch.Diagnostics);
    }
}
