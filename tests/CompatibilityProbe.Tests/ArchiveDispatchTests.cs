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
    public void CaseVariantImportCannotShadowExactDeclarationIdentity()
    {
        using var packages = new Packages(PackageContextFixture.CaseImport);
        var before = InvocationExtractor.Read(packages.Inputs["Caller"]);
        var after = packages.Inspect("Caller", packages.Context());
        Assert.Equal(before.Analysis.Invocations.ToArray(), after.Analysis.Invocations.ToArray());
        var dispatch = after.Analysis.Dispatches![0];
        Assert.Equal(22u, dispatch.Origin.Offset);
        Assert.Contains(dispatch.Candidates, c => c.Owner == "/game/base.tYpE" && c.Function == "SENSITIVE" && c.Provenance == "imported-function");
        Assert.Contains(dispatch.Candidates, c => c.Owner == "/Game/Base.Type" && c.Function == "Sensitive" && c.Provenance == "inherited-function");
        PolicyEvaluator.Validate(after.Analysis);
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(3, 3)]
    public void ExactCaseVariantsSharePerOriginTargetLimit(int limit, int expected)
    {
        using var packages = new Packages(PackageContextFixture.CaseImport);
        var report = packages.Inspect("Caller", packages.Context(), new(MaxTargets: limit));
        var dispatch = report.Analysis.Dispatches![0];
        Assert.Equal(expected, dispatch.Candidates.Length);
        Assert.Contains(dispatch.Candidates, c => c.Provenance == "imported-function");
        if (limit > 1) Assert.Contains(dispatch.Candidates, c => c.Owner == "/Game/Base.Type" && c.Function == "Sensitive");
        if (limit < 3) Assert.Contains("target-expansion-limit", dispatch.Diagnostics);
        PolicyEvaluator.Validate(report.Analysis);
    }

    [Theory]
    [InlineData(3333, 9999)]
    [InlineData(3334, 10000)]
    public void ExactCaseVariantsShareAggregateBudgetAcrossOriginsAndPackages(int count, int expected)
    {
        using var packages = new Packages(assets =>
        {
            PackageContextFixture.CaseImport(assets);
            var caller = assets["Caller"];
            var run = (FunctionExport)caller.Exports[4];
            var expression = run.ScriptBytecode![0];
            run.ScriptBytecode = Enumerable.Range(0, count).Select(_ => expression).ToArray();
            run.ScriptBytecodeSize = run.ScriptBytecode.Sum(e => (int)e.GetSize(caller));
        });
        var context = packages.Context();
        var before = InvocationExtractor.Read(packages.Inputs["Caller"]);
        var after = packages.Inspect("Caller", context);
        Assert.Equal(before.Analysis.Invocations.ToArray(), after.Analysis.Invocations.ToArray());
        var dispatches = after.Analysis.Dispatches!;
        Assert.Equal(expected, dispatches.Sum(d => d.Candidates.Length));
        Assert.Equal(3, dispatches[0].Candidates.Length);
        if (count > 3333) Assert.Contains("target-expansion-limit", dispatches[^1].Diagnostics);
        PolicyEvaluator.Validate(after.Analysis);
        var later = packages.Inspect("Base", context);
        Assert.Single(later.Invocations);
        PolicyEvaluator.Validate(later.Analysis);
    }

    [Theory]
    [InlineData(false, 0, 0)]
    [InlineData(false, 5001, 5001)]
    [InlineData(true, 5000, 10000)]
    [InlineData(true, 5001, 10000)]
    public void ComposedPackageBudgetRetainsMandatoryCallsAndLaterPackages(bool local, int count, int expected)
    {
        using var packages = new Packages(assets => PackageContextFixture.Boundary(assets, count, local));
        var context = packages.Context();
        var before = InvocationExtractor.Read(packages.Inputs["Base"]);
        var after = packages.Inspect("Base", context);
        Assert.Equal(before.Analysis.Invocations.ToArray(), after.Analysis.Invocations.ToArray());
        Assert.Equal(count + 1, after.Invocations.Length);
        Assert.Equal(expected, (after.Analysis.Dispatches ?? []).Sum(d => d.Candidates.Length));
        Assert.All(after.Analysis.Dispatches ?? [], d => Assert.Contains("open-world", d.Diagnostics));
        if (local && count > 5000)
        {
            Assert.Contains(after.Analysis.Dispatches!, d => d.Diagnostics.Contains("target-expansion-limit"));
            Assert.Contains(CoverageGap.IncompleteExtraction, after.Analysis.CoverageGaps);
            Assert.Contains(CoverageGap.UnresolvedDispatch, after.Analysis.CoverageGaps);
        }
        PolicyEvaluator.Validate(after.Analysis);
        var later = packages.Inspect("ChildOverride", context);
        Assert.Single(later.Invocations);
        PolicyEvaluator.Validate(later.Analysis);
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
