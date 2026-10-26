using CompatibilityProbe;
using PakRisk.Extraction;
using PakRisk.Policy;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode.Expressions;
using Xunit;

namespace CompatibilityProbe.Tests;

public sealed class DelegateStorageTests
{
    private static ExtractionReport Read(string mode, ExtractionLimits? limits = null,
        Action<UAssetAPI.UAsset>? mutate = null)
    {
        var root = Path.Combine(Path.GetTempPath(), "delegate-flow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "DelegateFlow.uasset");
            var asset = DelegateFlowFixture.Create(mode);
            mutate?.Invoke(asset);
            asset.Write(path);
            var report = InvocationExtractor.Read(new("submission", "Content/DelegateFlow.uasset", "/Game/DelegateFlow", path), limits: limits);
            Assert.DoesNotContain(report.Diagnostics, d => d.Code == "package-read-failed");
            Assert.DoesNotContain(report.Functions.SelectMany(f => f.Diagnostics), d => d.Code is "indirect-analysis-failed" or "bytecode-size-mismatch");
            PolicyEvaluator.Validate(report.Analysis);
            return report;
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void PublicReadLinksHistoryWithoutErasingBindingsOrInventingInvocationOccurrences()
    {
        var report = Read("history");
        var calls = report.Analysis.Dispatches!.Where(d => d.Kind == "multicast").ToArray();
        Assert.Equal(5, calls.Length);
        Assert.Equal(6, report.Invocations.Length); // original direct call plus five multicast occurrences
        Assert.IsType<InvocationTarget.Resolved>(report.Invocations[0].Target);
        Assert.Equal(0, report.Invocations[0].Offset);
        Assert.All(calls.Take(3), d => Assert.Equal("Sensitive", Assert.Single(d.Candidates).Function));
        Assert.All(calls.Skip(3), d => Assert.Equal(new[] { "Safe", "Sensitive" }, d.Candidates.Select(c => c.Function)));
        Assert.All(calls, d =>
        {
            Assert.Equal("possible", d.Resolution);
            Assert.Contains("binding-flow-unresolved", d.Diagnostics);
            Assert.NotEmpty(d.PossibleBindingOrigins!);
            Assert.Contains(report.Invocations, c => c.Fact.Location == d.Origin);
            Assert.All(d.PossibleBindingOrigins!, origin => Assert.Contains(report.Analysis.Dispatches!,
                b => b.Origin == origin && b.Kind == "delegate-binding"));
        });
        Assert.Equal(3, report.Analysis.Dispatches!.Count(d => d.Kind == "delegate-binding"));
    }

    [Theory]
    [InlineData("instance", true)]
    [InlineData("copy", true)]
    [InlineData("branch", true)]
    [InlineData("unknown-assignment", true)]
    [InlineData("none", false)]
    [InlineData("alias", false)]
    [InlineData("before", false)]
    [InlineData("loop", false)]
    [InlineData("remove-only", false)]
    public void SerializedVariantsRetainPossibleLinksAndExplicitUnknowns(string mode, bool linked)
    {
        var report = Read(mode);
        var call = Assert.Single(report.Analysis.Dispatches!, d => d.Kind == "multicast");
        Assert.Equal(linked ? 1 : 0, call.Candidates.Length);
        Assert.Contains(CoverageGap.UnresolvedDispatch, report.Analysis.CoverageGaps);
        Assert.Contains("binding-flow-unresolved", call.Diagnostics);
        if (linked) Assert.Equal("Sensitive", call.Candidates[0].Function);
        if (mode == "none") Assert.Contains(report.Analysis.Dispatches!, d => d.Diagnostics.Contains("unbound-delegate"));
    }

    [Fact]
    public void ExactObjectIdentitySeparatesSameNamedInstanceFields()
    {
        var report = Read("objects");
        var calls = report.Analysis.Dispatches!.Where(d => d.Kind == "multicast").ToArray();
        Assert.Empty(calls[0].Candidates);
        Assert.Equal("Sensitive", Assert.Single(calls[1].Candidates).Function);
    }

    [Theory]
    [InlineData("wrong-owner")]
    [InlineData("duplicate")]
    [InlineData("parameter")]
    [InlineData("array")]
    public void InvalidOrAliasedStorageDoesNotLinkByName(string mode)
    {
        var report = Read("instance", mutate: asset =>
        {
            var run = (FunctionExport)asset.Exports[5];
            if (mode == "wrong-owner") ((EX_LocalVariable)((EX_LetDelegate)run.ScriptBytecode[0]).VariableExpression).Variable.New.ResolvedOwner = new(5);
            if (mode == "duplicate") run.LoadedProperties = [.. run.LoadedProperties, DelegateFlowFixture.Property(asset, "cALLBACK")];
            if (mode == "parameter") run.LoadedProperties[0].PropertyFlags = UAssetAPI.UnrealTypes.EPropertyFlags.CPF_Parm;
            if (mode == "array") run.LoadedProperties[0].ArrayDim = (UAssetAPI.FieldTypes.EArrayDim)2;
        });
        Assert.Empty(Assert.Single(report.Analysis.Dispatches!, d => d.Kind == "multicast").Candidates);
        Assert.Contains(report.Analysis.Dispatches!, d => d.Kind == "delegate-binding" && d.Candidates.Length == 1);
    }

    [Fact]
    public void LinkExpansionSharesCandidateBudgetAndNeverDropsOriginalDirectForbid()
    {
        var report = Read("history", new(MaxTargets: 1));
        Assert.All(report.Analysis.Dispatches!, d => Assert.True(d.Candidates.Length <= 1));
        Assert.Contains(report.Analysis.Dispatches!, d => d.Kind == "multicast" && d.Diagnostics.Contains("target-expansion-limit"));
        Assert.Equal(6, report.Invocations.Length);
        Assert.IsType<InvocationTarget.Resolved>(report.Invocations[0].Target);
    }

    [Fact]
    public void LiteralNullAndNumberedNoneRemainRealNamesNotUnboundSentinels()
    {
        foreach (var (mode, name) in new[] { ("literal-null", "null"), ("numbered-none", "None_0") })
        {
            var report = Read(mode);
            var call = Assert.Single(report.Analysis.Dispatches!, d => d.Kind == "multicast");
            Assert.Equal(name, Assert.Single(call.Candidates).Function);
        }
    }

    [Fact]
    public void AggregateRelationLimitKeepsBindingsAndLaterMandatoryCalls()
    {
        var report = Read("history", mutate: asset =>
        {
            DelegateFlowFixture.Budget(asset, 400);
        });
        Assert.Equal(401, report.Invocations.Length);
        Assert.Equal(40, report.Analysis.Dispatches!.Count(d => d.Kind == "delegate-binding"));
        Assert.Equal(10000, report.Analysis.Dispatches!.Sum(d => d.PossibleBindingOrigins?.Length ?? 0));
        Assert.Contains("target-expansion-limit", report.Analysis.Dispatches![^1].Diagnostics);
        Assert.IsType<InvocationTarget.Resolved>(report.Invocations[0].Target);
    }

    [Theory]
    [InlineData("history")]
    [InlineData("instance")]
    [InlineData("copy")]
    public void EveryProductionDispatchPrefixRetainsReferencedBindingEvidence(string mode)
    {
        var report = Read(mode);
        var dispatches = report.Analysis.Dispatches!;
        for (var count = 1; count <= dispatches.Length; count++)
            PolicyEvaluator.Validate(report.Analysis with { Dispatches = dispatches.Take(count).ToArray() });
    }

    [Fact]
    public void LocalHistoryNeverEscapesItsContainingFunction()
    {
        var report = Read("instance", mutate: asset =>
        {
            var index = PackageContextFixture.Function(asset, "Later",
                new EX_AddMulticastDelegate { Delegate = DelegateFlowFixture.Events(asset), DelegateToAdd = DelegateFlowFixture.Local(asset, owner: 7) },
                DelegateFlowFixture.Call(asset));
            ((FunctionExport)asset.Exports[index - 1]).LoadedProperties = [DelegateFlowFixture.Property(asset, "Callback")];
        });
        var calls = report.Analysis.Dispatches!.Where(d => d.Kind == "multicast").ToArray();
        Assert.Single(calls[0].Candidates);
        Assert.Empty(calls[1].Candidates);
        Assert.Contains("binding-flow-unresolved", calls[1].Diagnostics);
    }

    [Fact]
    public void SingleDelegateCannotMasqueradeAsMulticastStorage()
    {
        var report = Read("instance", mutate: asset =>
        {
            var run = (FunctionExport)asset.Exports[5];
            ((EX_CallMulticastDelegate)run.ScriptBytecode[^1]).Delegate = DelegateFlowFixture.Local(asset);
            run.ScriptBytecodeSize = run.ScriptBytecode.Sum(e => (int)e.GetSize(asset));
        });
        Assert.Empty(Assert.Single(report.Analysis.Dispatches!, d => d.Kind == "multicast").Candidates);
    }

    [Fact]
    public void PublicReadProducesDeterministicLinks()
    {
        var first = Read("copy").Analysis.Dispatches!;
        var second = Read("copy").Analysis.Dispatches!;
        Assert.Equal(System.Text.Json.JsonSerializer.Serialize(first), System.Text.Json.JsonSerializer.Serialize(second));
    }
}
