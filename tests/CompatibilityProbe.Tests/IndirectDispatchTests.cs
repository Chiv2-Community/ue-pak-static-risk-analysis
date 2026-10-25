using CompatibilityProbe;
using PakRisk.Extraction;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;
using Xunit;

namespace CompatibilityProbe.Tests;

public sealed class IndirectDispatchTests
{
    private static readonly PackageInput Input = new("owned", "entry", "/Game/Indirect", "unused");
    private static UAsset Asset()
    {
        var asset = new UAsset(EngineVersion.VER_UE4_25) { PackageFlags = EPackageFlags.PKG_Cooked, Imports = [], Exports = [] };
        asset.ClearNameIndexList();
        return asset;
    }
    private static int Class(UAsset asset, string name, int parent = 0, bool face = false)
    {
        asset.Exports.Add(new ClassExport { ObjectName = new(asset, name), OuterIndex = new(0), SuperStruct = new(parent),
            Interfaces = [], ScriptBytecode = [], ClassFlags = face ? EClassFlags.CLASS_Interface : 0 });
        return asset.Exports.Count;
    }
    private static int Function(UAsset asset, int owner, string name, params KismetExpression[] code)
    {
        // Pinned Write's VM sizes, not a pseudocode/AST-only offset oracle.
        using var stream = new MemoryStream();
        using var writer = new AssetBinaryWriter(stream, asset);
        var size = code.Sum(e => ExpressionSerializer.WriteExpression(e, writer));
        stream.Position = 0;
        using var reader = new AssetBinaryReader(stream, asset);
        var parsed = code.Select(_ => ExpressionSerializer.ReadExpression(reader)).ToArray();
        Assert.Equal(stream.Length, stream.Position);
        asset.Exports.Add(new FunctionExport { ObjectName = new(asset, name), OuterIndex = new(owner), ScriptBytecode = parsed,
            ScriptBytecodeSize = size, LoadedProperties = [], Children = [] });
        return asset.Exports.Count;
    }
    private static EX_VirtualFunction Virtual(UAsset asset, string name = "Sensitive") => new() { VirtualFunctionName = new(asset, name), Parameters = [] };
    private static IndirectDispatch Dispatch(ExtractionReport report) => Assert.Single(report.Analysis.Dispatches!);

    [Fact]
    public void GraphDefinitionsUseActualContainingExportOwnerNotCollidingFunctionNames()
    {
        var asset = Asset();
        var first = Class(asset, "First");
        var second = Class(asset, "Second");
        var target = Function(asset, first, "Helper");
        Function(asset, second, "Helper");
        Function(asset, first, "Root", new EX_FinalFunction { StackNode = new(target), Parameters = [] });
        var report = InvocationExtractor.Inspect(asset, Input);
        var graph = report.Analysis.CallGraph!;
        Assert.Equal(3, graph.Functions.Length);
        var call = Assert.Single(report.Analysis.Invocations);
        var source = Assert.Single(graph.Functions, f => f.Asset == call.Location.Asset && f.LocationFunction == call.Location.Function);
        Assert.Equal("/Game/Indirect.First", source.Owner);
        Assert.Equal("Root", source.Function);
        Assert.Equal("/Game/Indirect.First", Assert.IsType<InvocationTarget.Resolved>(call.Target).Owner);
        Assert.Contains(graph.Functions, f => f.Owner == "/Game/Indirect.Second" && f.Function == "Helper");
        PolicyEvaluator.Validate(report.Analysis);
    }

    [Fact]
    public void GraphOmitsUnresolvedContainingOwnerRatherThanInventingIdentity()
    {
        var asset = Asset();
        Function(asset, 999, "Root", new EX_FinalFunction { StackNode = new(0), Parameters = [] });
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Empty(report.Analysis.CallGraph!.Functions);
        Assert.False(report.Analysis.CallGraph.Complete);
        Assert.Single(report.Analysis.Invocations);
        Assert.Contains(report.Functions[0].Diagnostics, d => d.Code == "containing-function-identity-unresolved");
    }

    [Fact]
    public void OptionalGraphDefinitionLimitDoesNotStopLaterBytecodeExtraction()
    {
        var asset = Asset();
        var owner = Class(asset, "Owner");
        var target = Function(asset, owner, "Target");
        for (var i = 0; i < 1000; i++) Function(asset, owner, "F" + i);
        Function(asset, owner, "Last", new EX_FinalFunction { StackNode = new(target), Parameters = [] });
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.False(report.Analysis.CallGraph!.Complete);
        Assert.True(report.Analysis.CallGraph.Functions.Sum(CallGraphContext.Characters) <= CallGraphContext.MaxCharacters);
        Assert.Equal("Last", Assert.Single(report.Invocations).ContainingFunction.Name);
        Assert.DoesNotContain(report.Analysis.CallGraph.Functions, f => f.Function == "Last");
        Assert.Equal(1002, report.Functions.Length);
    }

    [Fact]
    public void BaseCallRetainsOverrideCandidatesAndOriginalUnresolvedInvocation()
    {
        var asset = Asset();
        var parent = Class(asset, "Base");
        var child = Class(asset, "Child", parent);
        Function(asset, parent, "Sensitive");
        Function(asset, child, "Sensitive");
        Function(asset, parent, "Run", Virtual(asset));
        var report = InvocationExtractor.Inspect(asset, Input);
        var dispatch = Dispatch(report);
        Assert.Equal(2, dispatch.Candidates.Length);
        Assert.Contains(dispatch.Candidates, c => c.Owner == "/Game/Indirect.Child" && c.Provenance == "override");
        Assert.IsType<InvocationTarget.Unresolved>(Assert.Single(report.Invocations).Target);
        Assert.Equal("EX_VirtualFunction", dispatch.Opcode);
        Assert.Equal(Assert.Single(report.Invocations).Fact.Location, dispatch.Origin);
        Assert.Contains("open-world", dispatch.Diagnostics);
        PolicyEvaluator.Validate(report.Analysis);
    }

    [Fact]
    public void InheritedImplementationAndUnseenOverridesRemainPossible()
    {
        var asset = Asset();
        var parent = Class(asset, "Base");
        var child = Class(asset, "Child", parent);
        Function(asset, parent, "Sensitive");
        Function(asset, child, "Run", Virtual(asset));
        var dispatch = Dispatch(InvocationExtractor.Inspect(asset, Input));
        Assert.Equal("inherited-function", Assert.Single(dispatch.Candidates).Provenance);
        Assert.Equal("possible", dispatch.Resolution);
        Assert.Contains("open-world", dispatch.Diagnostics);
    }

    [Fact]
    public void FNameLookupIsCaseInsensitiveButPreservesCandidateSymbolSpelling()
    {
        var asset = Asset();
        var owner = Class(asset, "Class");
        Function(asset, owner, "Sensitive");
        Function(asset, owner, "Run", Virtual(asset, "sEnSiTiVe"));
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal("Sensitive", Assert.Single(Dispatch(report).Candidates).Function);
        Assert.Equal("sEnSiTiVe", Dispatch(report).FunctionName);
        PolicyEvaluator.Validate(report.Analysis);
    }

    [Fact]
    public void InterfaceClassFindsSerializedImplementationWithoutClosingWorld()
    {
        var asset = Asset();
        var face = Class(asset, "Interface", face: true);
        var implementation = Class(asset, "Implementation");
        ((ClassExport)asset.Exports[implementation - 1]).Interfaces = [new(face, 0, true)];
        Function(asset, implementation, "Sensitive");
        Function(asset, face, "Run", Virtual(asset));
        var dispatch = Dispatch(InvocationExtractor.Inspect(asset, Input));
        Assert.Equal("interface-implementation", Assert.Single(dispatch.Candidates).Provenance);
        Assert.Contains("open-world", dispatch.Diagnostics);
    }

    [Fact]
    public void InterfaceAncestryAndSharedHierarchyAreTraversedWithoutFalseCycle()
    {
        var asset = Asset();
        var face = Class(asset, "ParentInterface", face: true);
        var childFace = Class(asset, "ChildInterface", face, face: true);
        var parent = Class(asset, "Base");
        ((ClassExport)asset.Exports[parent - 1]).Interfaces = [new(childFace, 0, true)];
        var implementation = Class(asset, "Implementation", parent);
        ((ClassExport)asset.Exports[implementation - 1]).Interfaces = [new(childFace, 0, true)];
        Function(asset, implementation, "Sensitive");
        Function(asset, face, "Run", Virtual(asset));
        var dispatch = Dispatch(InvocationExtractor.Inspect(asset, Input));
        Assert.Equal("interface-implementation", Assert.Single(dispatch.Candidates).Provenance);
        Assert.DoesNotContain("class-cycle", dispatch.Diagnostics);
    }

    [Theory]
    [InlineData("missing-parent", "parent-unavailable")]
    [InlineData("cycle", "class-cycle")]
    [InlineData("missing-class", "class-metadata-unavailable")]
    public void InvalidHierarchyProducesExplicitDiagnostics(string mode, string code)
    {
        var asset = Asset();
        var owner = Class(asset, "Class");
        ((ClassExport)asset.Exports[owner - 1]).SuperStruct = mode == "missing-parent" ? null : new(mode == "cycle" ? owner : 999);
        Function(asset, owner, "Sensitive");
        Function(asset, owner, "Run", Virtual(asset));
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Contains(code, Dispatch(report).Diagnostics);
        Assert.Contains(CoverageGap.UnresolvedDispatch, report.Analysis.CoverageGaps);
        Assert.Contains(CoverageGap.IncompleteExtraction, report.Analysis.CoverageGaps);
    }

    [Fact]
    public void ImportedParentAndFunctionRemainSymbolicDependencyEvidence()
    {
        var asset = Asset();
        asset.Imports.Add(new Import("/Script/CoreUObject", "Package", new(0), "/Script/Fixture", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-1), "Parent", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Function", new(-2), "Sensitive", false, asset));
        var owner = Class(asset, "Child", -2);
        Function(asset, owner, "Run", Virtual(asset));
        var dispatch = Dispatch(InvocationExtractor.Inspect(asset, Input));
        Assert.Equal("/Script/Fixture.Parent", Assert.Single(dispatch.Candidates).Owner);
        Assert.Equal("imported-function", dispatch.Candidates[0].Provenance);
        Assert.Contains("dependency-context-unavailable", dispatch.Diagnostics);
        Assert.Contains("parent-unavailable", dispatch.Diagnostics);
    }

    [Fact]
    public void ExpansionLimitKeepsOriginalDispatchAndDirectCallOffsets()
    {
        var asset = Asset();
        var parent = Class(asset, "Base");
        var child = Class(asset, "Child", parent);
        var direct = Function(asset, parent, "Sensitive");
        Function(asset, child, "Sensitive");
        Function(asset, parent, "Run", Virtual(asset), new EX_FinalFunction { StackNode = new(direct), Parameters = [] });
        var report = InvocationExtractor.Inspect(asset, Input, new(MaxTargets: 1));
        Assert.Single(Dispatch(report).Candidates);
        Assert.Contains("target-expansion-limit", Dispatch(report).Diagnostics);
        Assert.Equal(14, report.Invocations[1].Offset); // opcode + FName + EndFunctionParms
        Assert.IsType<InvocationTarget.Resolved>(report.Invocations[1].Target);
    }

    [Fact]
    public void ExhaustedIndirectEvidenceBudgetDoesNotDiscardLaterDirectCalls()
    {
        var asset = Asset();
        var owner = Class(asset, "Class");
        var target = Function(asset, owner, "Sensitive");
        Function(asset, owner, "Bindings", Enumerable.Range(0, PolicyEvaluator.MaxInvocations)
            .Select(_ => (KismetExpression)new EX_InstanceDelegate { FunctionName = new(asset, "Sensitive") }).ToArray());
        Function(asset, owner, "Later", new EX_InstanceDelegate { FunctionName = new(asset, "Sensitive") },
            new EX_FinalFunction { StackNode = new(target), Parameters = [] });
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal(PolicyEvaluator.MaxInvocations, report.Analysis.Dispatches!.Length);
        Assert.Equal(13, Assert.Single(report.Invocations).Offset);
        Assert.IsType<InvocationTarget.Resolved>(report.Invocations[0].Target);
        Assert.Contains(report.Functions.SelectMany(f => f.Diagnostics), d => d.Code == "indirect-dispatch-limit");
        PolicyEvaluator.Validate(report.Analysis);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnknownAndInterfaceReceiversDoNotDiscardNameCandidates(bool face)
    {
        var asset = Asset();
        var owner = Class(asset, "Class");
        Function(asset, owner, "Sensitive");
        KismetExpression receiver = face ? new EX_InterfaceContext { InterfaceValue = new EX_NoInterface() } : new EX_NoObject();
        Function(asset, owner, "Run", new EX_Context { ObjectExpression = receiver, Offset = 0,
            RValuePointer = new KismetPropertyPointer(new FFieldPath { Path = [], ResolvedOwner = new(0) }), ContextExpression = Virtual(asset) });
        var dispatch = Dispatch(InvocationExtractor.Inspect(asset, Input));
        Assert.Single(dispatch.Candidates);
        Assert.Contains("receiver-unavailable", dispatch.Diagnostics);
        if (face) Assert.Contains("interface-context-unavailable", dispatch.Diagnostics);
    }

    [Fact]
    public void BindUnbindAndMulticastMutationsRetainRealInstructionOriginsNotCalls()
    {
        var asset = Asset();
        var owner = Class(asset, "Class");
        Function(asset, owner, "Sensitive");
        Function(asset, owner, "Run",
            new EX_BindDelegate { FunctionName = new(asset, "Sensitive"), Delegate = new EX_Nothing(), ObjectTerm = new EX_Self() },
            new EX_InstanceDelegate { FunctionName = new(asset, "Sensitive") },
            new EX_AddMulticastDelegate { Delegate = new EX_Nothing(), DelegateToAdd = new EX_InstanceDelegate { FunctionName = new(asset, "Sensitive") } },
            new EX_RemoveMulticastDelegate { Delegate = new EX_Nothing(), DelegateToAdd = new EX_InstanceDelegate { FunctionName = new(asset, "Sensitive") } },
            new EX_ClearMulticastDelegate { DelegateToClear = new EX_Nothing() },
            new EX_BindDelegate { FunctionName = new(asset, "None"), Delegate = new EX_Nothing(), ObjectTerm = new EX_NoObject() });
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Empty(report.Invocations);
        Assert.Equal(8, report.Analysis.Dispatches!.Length);
        Assert.Equal(8, report.Analysis.Dispatches.Select(d => d.Origin.Offset).Distinct().Count());
        Assert.All(report.Analysis.Dispatches, d => Assert.Contains("binding-flow-unresolved", d.Diagnostics));
        Assert.Single(report.Analysis.Dispatches[0].Candidates);
        Assert.Empty(report.Analysis.Dispatches[^1].Candidates);
        PolicyEvaluator.Validate(report.Analysis);
    }

    [Fact]
    public void SerializedNoneInstanceDelegateIsUnboundNotAPossibleFunctionNamedNone()
    {
        var asset = Asset();
        var owner = Class(asset, "Class");
        Function(asset, owner, "None");
        Function(asset, owner, "Run", new EX_InstanceDelegate { FunctionName = new(asset, "None") });
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Empty(report.Invocations);
        var dispatch = Dispatch(report);
        Assert.Equal("None", dispatch.FunctionName);
        Assert.Empty(dispatch.Candidates);
        Assert.Contains("unbound-delegate", dispatch.Diagnostics);
    }

    [Fact]
    public void SerializedMulticastSignatureDoesNotBecomeCallbackTarget()
    {
        var asset = Asset();
        var owner = Class(asset, "Class");
        var signature = Function(asset, owner, "Sensitive");
        Function(asset, owner, "Run", new EX_CallMulticastDelegate { StackNode = new(signature),
            Delegate = new EX_Nothing(), Parameters = [] });
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.IsType<InvocationTarget.Unresolved>(Assert.Single(report.Invocations).Target);
        var dispatch = Dispatch(report);
        Assert.Equal("multicast", dispatch.Kind);
        Assert.Empty(dispatch.Candidates);
        Assert.Contains("binding-flow-unresolved", dispatch.Diagnostics);
        Assert.DoesNotContain(report.Functions.SelectMany(f => f.Diagnostics), d => d.Code == "bytecode-size-mismatch");
    }

    [Theory]
    [InlineData("None", false)]
    [InlineData("nOnE", false)]
    [InlineData("NONE", false)]
    [InlineData("sEnSiTiVe", true)]
    public void TimerAndNestedInstanceDelegateShareValidatedFNameBinding(string name, bool bound)
    {
        var asset = Asset();
        asset.Imports.Add(new Import("/Script/CoreUObject", "Package", new(0), "/Script/Engine", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-1), "KismetSystemLibrary", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Function", new(-2), "K2_SetTimerDelegate", false, asset));
        var owner = Class(asset, "Class");
        Function(asset, owner, "None");
        Function(asset, owner, "Sensitive");
        Function(asset, owner, "Run", new EX_FinalFunction { StackNode = new(-3), Parameters =
            [new EX_InstanceDelegate { FunctionName = new(asset, name) }, new EX_FloatConst { Value = 1 },
             new EX_False(), new EX_FloatConst(), new EX_FloatConst()] });
        var report = InvocationExtractor.Inspect(asset, Input);
        var direct = Assert.Single(report.Invocations);
        Assert.Equal(0, direct.Offset);
        Assert.Equal("K2_SetTimerDelegate", Assert.IsType<InvocationTarget.Resolved>(direct.Target).Function);
        Assert.Equal(2, report.Analysis.Dispatches!.Length);
        foreach (var dispatch in report.Analysis.Dispatches)
        {
            Assert.Equal(bound ? 1 : 0, dispatch.Candidates.Length);
            Assert.Equal(!bound, dispatch.Diagnostics.Contains("unbound-delegate"));
            Assert.Equal(!bound, dispatch.Diagnostics.Contains("target-name-unavailable"));
            if (bound) Assert.Equal("Sensitive", dispatch.Candidates[0].Function);
        }
        var timer = Assert.Single(report.Analysis.Dispatches, d => d.Kind == "timer");
        Assert.Equal(direct.Fact.Location, timer.Origin);
        Assert.Contains("native-build-unverified", timer.Diagnostics);
        Assert.All(report.Analysis.Dispatches, d => Assert.Contains("open-world", d.Diagnostics));
        PolicyEvaluator.Validate(report.Analysis);
    }

    [Theory]
    [InlineData("constant")]
    [InlineData("dynamic")]
    [InlineData("delegate")]
    [InlineData("wrapper")]
    public void ReviewedSourceTimerIsScopedHypothesisNotGameOrWrapperCatalog(string mode)
    {
        var asset = Asset();
        asset.Imports.Add(new Import("/Script/CoreUObject", "Package", new(0), "/Script/Engine", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-1), "KismetSystemLibrary", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Function", new(-2), mode == "delegate" ? "K2_SetTimerDelegate" : mode == "wrapper" ? "GameSetTimer" : "K2_SetTimer", false, asset));
        var owner = Class(asset, "Class");
        Function(asset, owner, "Sensitive");
        KismetExpression[] scheduling = [new EX_FloatConst { Value = 1 }, new EX_False(), new EX_FloatConst { Value = 0 }, new EX_FloatConst { Value = 0 }];
        KismetExpression functionName = mode == "dynamic"
            ? new EX_InstanceVariable { Variable = new KismetPropertyPointer(new FFieldPath { Path = [new(asset, "RuntimeFunctionName")], ResolvedOwner = new(owner) }) }
            : new EX_UnicodeStringConst { Value = "Sensitive" };
        KismetExpression[] parameters = mode == "delegate" ? [new EX_InstanceDelegate { FunctionName = new(asset, "Sensitive") }, .. scheduling]
            : [new EX_Self(), functionName, .. scheduling];
        Function(asset, owner, "Run", new EX_FinalFunction { StackNode = new(-3), Parameters = parameters });
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.IsType<InvocationTarget.Resolved>(Assert.Single(report.Invocations).Target);
        if (mode == "wrapper") { Assert.Null(report.Analysis.Dispatches); return; }
        var timer = Assert.Single(report.Analysis.Dispatches!, d => d.Kind == "timer");
        Assert.Equal("ue425plus-2d1aae-kismet-timer", timer.Source);
        Assert.Contains("native-build-unverified", timer.Diagnostics);
        Assert.Equal("possible", timer.Resolution);
        Assert.DoesNotContain(report.Functions.SelectMany(f => f.Diagnostics), d => d.Code == "bytecode-size-mismatch");
        if (mode == "dynamic")
        {
            Assert.Null(timer.FunctionName);
            Assert.Contains("target-name-unavailable", timer.Diagnostics);
        }
        else Assert.Single(timer.Candidates);
        PolicyEvaluator.Validate(report.Analysis);
    }
}
