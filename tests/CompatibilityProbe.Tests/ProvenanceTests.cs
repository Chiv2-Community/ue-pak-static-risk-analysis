using PakRisk.Extraction;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;
using Xunit;

namespace CompatibilityProbe.Tests;

public sealed partial class ExtractionTests
{
    private const string LocalOwner = "/Game/Maps/Test.BP_Test_C";
    private static EX_LocalVariable Local(UAsset asset, int owner, string name) => new()
    {
        Variable = new KismetPropertyPointer(new FFieldPath { ResolvedOwner = new(owner), Path = [new(asset, name)] })
    };
    private static EX_FinalFunction Invoke(int function, params KismetExpression[] arguments) => new()
        { StackNode = new(function), Parameters = arguments };
    private static EX_Let Set(UAsset asset, int owner, string name, KismetExpression value) => new()
        { Value = Local(asset, owner, name).Variable, Variable = Local(asset, owner, name), Expression = value };
    private static void Code(UAsset asset, FunctionExport function, params KismetExpression[] expressions)
    {
        var (parsed, size, _) = RoundTrip(asset, expressions);
        function.ScriptBytecode = parsed;
        function.ScriptBytecodeSize = size;
    }
    private static MatchExpression.Invocation ProducerRule() => new(new TargetMatcher.Exact(LocalOwner, "Baz"),
        [new("foo", new ValuePredicate.SubexprMatch(new MatchExpression.Invocation(new TargetMatcher.Exact(LocalOwner, "Append"),
            [new("A", new ValuePredicate.EqualTo(new PolicyLiteral.String("foo")))])))]);

    private static (UAsset Asset, FunctionExport Caller) Pipeline()
    {
        var asset = Asset();
        var append = Function(asset, [], "Append"); // export 2
        append.LoadedProperties = [Parameter(asset, "A")];
        Code(asset, append, new EX_Return { ReturnExpression = Local(asset, 2, "A") });
        var baz = Function(asset, [], "Baz"); // export 3
        baz.LoadedProperties = [Parameter(asset, "foo")];
        var identity = Function(asset, [], "Transform"); // export 4
        identity.LoadedProperties = [Parameter(asset, "X")];
        Code(asset, identity, new EX_Return { ReturnExpression = Local(asset, 4, "X") });
        return (asset, Function(asset, [], "Caller")); // export 5
    }

    [Fact]
    public void SerializedSubexpressionProvenanceCoversNestingLocalsAndReturnValues()
    {
        var (asset, caller) = Pipeline();
        var helper = Function(asset, [], "MakeValue"); // export 6
        helper.LoadedProperties = [Parameter(asset, "Input")];
        Code(asset, helper, new EX_Return { ReturnExpression = Invoke(2, Local(asset, 6, "Input")) });
        Code(asset, caller,
            Invoke(3, Invoke(2, new EX_StringConst { Value = "foo" })),
            Set(asset, 5, "x", Invoke(2, new EX_StringConst { Value = "foo" })),
            Set(asset, 5, "y", Invoke(4, Local(asset, 5, "x"))),
            Invoke(3, Local(asset, 5, "y")),
            Invoke(3, Invoke(6, new EX_StringConst { Value = "foo" })));
        var report = InvocationExtractor.Inspect(asset, Input);
        var evaluation = Evaluate(report, ProducerRule());
        Assert.Equal(3, evaluation.Findings.Length);
        Assert.Empty(evaluation.Uncertainties);
        Assert.All(report.Analysis.Invocations.Where(f => f.Target is InvocationTarget.Resolved { Function: "Baz" }), fact =>
            Assert.IsType<ArgumentValue.Derived>(Assert.Single(Assert.IsType<ArgumentMetadata.Known>(fact.Arguments).Arguments).Value));
    }

    [Fact]
    public void OverwrittenLocalsAndUnrelatedCallsDoNotBecomeProvenance()
    {
        var (asset, caller) = Pipeline();
        var helper = Function(asset, [], "IgnoreInput");
        helper.LoadedProperties = [Parameter(asset, "Input")];
        Code(asset, helper, Invoke(2, new EX_StringConst { Value = "foo" }),
            new EX_Return { ReturnExpression = new EX_StringConst { Value = "other" } });
        Code(asset, caller,
            Set(asset, 5, "x", Invoke(2, new EX_StringConst { Value = "foo" })),
            Set(asset, 5, "x", new EX_StringConst { Value = "other" }),
            Invoke(3, Local(asset, 5, "x")),
            Invoke(3, Invoke(6, Invoke(2, new EX_StringConst { Value = "foo" }))));
        var evaluation = Evaluate(InvocationExtractor.Inspect(asset, Input), ProducerRule());
        Assert.Empty(evaluation.Findings);
        Assert.Empty(evaluation.Uncertainties);
    }

    [Theory]
    [InlineData("recursion")]
    [InlineData("branch")]
    [InlineData("native")]
    [InlineData("out-param")]
    [InlineData("side-effect")]
    [InlineData("nested-assignment")]
    [InlineData("sibling-out-call")]
    public void UnsupportedProvenanceRemainsUnknown(string boundary)
    {
        var (asset, caller) = Pipeline();
        var helper = Function(asset, [], "Boundary");
        helper.LoadedProperties = [Parameter(asset, "Input")];
        if (boundary == "native") helper.FunctionFlags |= EFunctionFlags.FUNC_Native;
        if (boundary == "out-param") helper.LoadedProperties[0].PropertyFlags |= EPropertyFlags.CPF_OutParm;
        Code(asset, helper, new EX_Return { ReturnExpression = boundary == "recursion"
            ? Invoke(6, Local(asset, 6, "Input")) : Local(asset, 6, "Input") });
        if (boundary == "branch") Code(asset, helper, new EX_Jump { CodeOffset = 0 },
            new EX_Return { ReturnExpression = Invoke(2, new EX_StringConst { Value = "foo" }) });
        if (boundary == "side-effect")
            Code(asset, caller, Set(asset, 5, "x", Invoke(2, new EX_StringConst { Value = "foo" })),
                Call(), Invoke(3, Local(asset, 5, "x")));
        else if (boundary == "nested-assignment")
            Code(asset, caller, Set(asset, 5, "x", new EX_StringConst { Value = "other" }),
                Invoke(3, Invoke(4, Set(asset, 5, "x", Invoke(2, new EX_StringConst { Value = "foo" })))),
                Invoke(3, Local(asset, 5, "x")));
        else if (boundary == "sibling-out-call")
        {
            helper.LoadedProperties[0].PropertyFlags |= EPropertyFlags.CPF_OutParm;
            var outer = Function(asset, [], "TwoInputs");
            outer.LoadedProperties = [Parameter(asset, "Discard"), Parameter(asset, "foo")];
            Code(asset, caller, Set(asset, 5, "x", new EX_StringConst { Value = "other" }),
                Invoke(7, Invoke(6, Local(asset, 5, "x")), Local(asset, 5, "x")));
        }
        else Code(asset, caller, Invoke(3, Invoke(6, Invoke(2, new EX_StringConst { Value = "foo" }))));
        var rule = boundary == "sibling-out-call" ? ProducerRule() with
            { Target = new TargetMatcher.Exact(LocalOwner, "TwoInputs") } : ProducerRule();
        var evaluation = Evaluate(InvocationExtractor.Inspect(asset, Input), rule);
        Assert.Empty(evaluation.Findings);
        Assert.NotEmpty(evaluation.Uncertainties);
    }
}
