using CompatibilityProbe;
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

public sealed class ExtractionTests
{
    private static readonly PackageInput Input = new("pak-sha256", "entry-17", "/Game/Maps/Test", "/storage/0001.uasset");
    private static UAsset Asset()
    {
        var asset = new UAsset(EngineVersion.VER_UE4_25) { PackageFlags = EPackageFlags.PKG_Cooked, Imports = [], Exports = [] };
        asset.ClearNameIndexList();
        asset.Exports.Add(new NormalExport { ObjectName = new(asset, "BP_Test_C"), OuterIndex = new(0) });
        asset.Imports.Add(new Import("/Script/CoreUObject", "Package", new(0), "/Script/Engine", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-1), "KismetSystemLibrary", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Function", new(-2), "Run", false, asset));
        return asset;
    }
    private static FunctionExport Function(UAsset asset, KismetExpression[]? code, string name = "ExecuteUbergraph_Test")
    {
        var function = new FunctionExport { ObjectName = new(asset, name), OuterIndex = new(1), ScriptBytecode = code,
            ScriptBytecodeSize = code?.Sum(e => (int)e.GetSize(asset)) ?? 1, LoadedProperties = [], Children = [] };
        asset.Exports.Add(function);
        return function;
    }
    private static EX_FinalFunction Call(params KismetExpression[] arguments) => new() { StackNode = new(-3), Parameters = arguments };
    private static FProperty Parameter(UAsset asset, string name, EPropertyFlags flags = EPropertyFlags.CPF_Parm) =>
        new FGenericProperty { Name = new(asset, name), PropertyFlags = flags };

    private static PolicyEvaluation Evaluate(ExtractionReport report, MatchExpression match) =>
        new PolicyEvaluator(new PolicyDocument(1, [new("test", "Test", RuleEffect.Flag, match)])).Evaluate(report.Analysis);

    [Theory]
    [InlineData("parameter")]
    [InlineData("target")]
    [InlineData("owner")]
    public void ControlSuffixedNamesNeverProduceInvalidPolicyFacts(string kind)
    {
        var asset = Asset();
        if (kind == "owner") asset.Exports[0].ObjectName = new(asset, "BP_Test_C\n");
        var target = Function(asset, [], kind == "target" ? "Target\n" : "Target");
        target.LoadedProperties = [Parameter(asset, kind == "parameter" ? "Value\n" : "Value")];
        Function(asset, [new EX_FinalFunction { StackNode = new(2), Parameters = [new EX_IntOne()] }]);
        var report = InvocationExtractor.Inspect(asset, Input);
        var call = Assert.Single(report.Invocations);
        if (kind == "parameter")
        {
            Assert.IsType<ArgumentMetadata.Unavailable>(call.Fact.Arguments);
            Assert.Equal("malformed", call.MetadataState);
            Assert.Contains(report.Functions[1].Diagnostics, d => d.Code == "parameter-metadata-invalid");
        }
        else
        {
            Assert.IsType<InvocationTarget.Unresolved>(call.Target);
            Assert.NotNull(call.ResolvedIdentity);
            Assert.Contains(report.Functions[1].Diagnostics, d => d.Code == "policy-target-unrepresentable");
        }
        Assert.False(report.Complete);
        Assert.Contains(CoverageGap.IncompleteExtraction, report.Analysis.CoverageGaps);
        Assert.True(Evaluate(report, new MatchExpression.Argument("Value", new ValuePredicate.EqualTo(new PolicyLiteral.Integer(1)))).IsIncomplete);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PrimitiveInterfaceCastIsRejectedBeforeAnyRootCallsAreEmitted(bool serialized)
    {
        var asset = Asset();
        KismetExpression cast = new EX_PrimitiveCast { ConversionType = ECastToken.ObjectToInterface, Target = Call() };
        if (serialized)
        {
            // Pinned Read mistakes the class index's first byte for the target opcode.
            byte[] bytes = [(byte)EExprToken.EX_PrimitiveCast, (byte)ECastToken.ObjectToInterface,
                (byte)EExprToken.EX_Nothing, 0, 0, 0, (byte)EExprToken.EX_ObjectConst, 1, 0, 0, 0];
            using var stream = new MemoryStream(bytes);
            using var reader = new AssetBinaryReader(stream, asset);
            cast = ExpressionSerializer.ReadExpression(reader);
            Assert.Equal(3, stream.Position);
            Assert.IsType<EX_Nothing>(((EX_PrimitiveCast)cast).Target);
        }
        Function(asset, [Call(), new EX_Return { ReturnExpression = Call(cast) }, Call()]);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal(0, Assert.Single(report.Invocations).Offset); // Prior roots survive, not the suspect root or later offsets.
        Assert.Contains(report.Functions[0].Diagnostics, d => d.Code == "unsupported-primitive-interface-cast");
        Assert.Contains(CoverageGap.UnsupportedParsing, report.Analysis.CoverageGaps);
    }

    [Fact]
    public void OtherPrimitiveCastsStillTraverseNestedCalls()
    {
        var asset = Asset();
        Function(asset, [new EX_PrimitiveCast { ConversionType = ECastToken.ObjectToBool, Target = Call() }]);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal(2, Assert.Single(report.Invocations).Offset);
        Assert.Empty(report.Analysis.CoverageGaps);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingSignaturesAreRuleSpecificNotGlobalCoverage(bool local)
    {
        var asset = Asset();
        var call = Call(new EX_IntOne());
        if (local)
        {
            var target = Function(asset, [], "Target");
            target.LoadedProperties = null; target.Children = null;
            call.StackNode = new(2);
        }
        Function(asset, [call]);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.False(report.Complete); // Extraction evidence still records missing metadata.
        Assert.Equal(local ? "parameter-metadata-unavailable" : "imported-signature-unavailable",
            Assert.Single(report.Functions.SelectMany(f => f.Diagnostics)).Code);
        Assert.IsType<ArgumentMetadata.Unavailable>(Assert.Single(report.Invocations).Fact.Arguments);
        Assert.Empty(report.Analysis.CoverageGaps);
        var targetMatch = new MatchExpression.Invocation(new TargetMatcher.Exact(
            local ? "/Game/Maps/Test.BP_Test_C" : "/Script/Engine.KismetSystemLibrary", local ? "Target" : "Run"));
        var unrelated = new MatchExpression.Invocation(new TargetMatcher.Exact("/Script/Other.Owner", "Unrelated"));
        var argument = new MatchExpression.Argument("Value", new ValuePredicate.EqualTo(new PolicyLiteral.Integer(1)));
        var exact = Evaluate(report, targetMatch);
        Assert.Single(exact.Findings);
        Assert.Empty(exact.Uncertainties);
        Assert.False(exact.IsIncomplete);
        foreach (var match in new MatchExpression[] { unrelated, new MatchExpression.All([argument, unrelated]),
                     new MatchExpression.All([unrelated, new MatchExpression.Not(argument)]) })
        {
            var result = Evaluate(report, match);
            Assert.Empty(result.Findings);
            Assert.Empty(result.Uncertainties);
            Assert.False(result.IsIncomplete);
            Assert.False(result.ShouldFail(true));
        }
        foreach (var match in new MatchExpression[] { argument, new MatchExpression.Not(argument),
                     new MatchExpression.All([targetMatch, argument]) })
        {
            var result = Evaluate(report, match);
            Assert.Empty(result.Findings);
            Assert.Equal(UncertaintyReason.ArgumentMetadataUnavailable, Assert.Single(Assert.Single(result.Uncertainties).Reasons));
            Assert.True(result.IsIncomplete);
            Assert.True(result.ShouldFail(true));
        }
    }

    [Theory]
    [InlineData("malformed", "parameter-metadata-invalid")]
    [InlineData("count", "argument-count-mismatch")]
    [InlineData("metadata-limit", "parameter-metadata-limit")]
    [InlineData("policy-limit", "policy-argument-limit")]
    [InlineData("native", "native-target-boundary")]
    public void SignatureCorruptionLimitsAndNativeBoundariesRemainGlobal(string kind, string code)
    {
        var asset = Asset();
        var target = Function(asset, [], "Target");
        target.LoadedProperties = kind switch
        {
            "malformed" => [Parameter(asset, "Value\n")],
            "metadata-limit" => [Parameter(asset, "First"), Parameter(asset, "Second")],
            "policy-limit" => Enumerable.Range(0, PolicyEvaluator.MaxArguments + 1).Select(i => Parameter(asset, $"P{i}")).ToArray(),
            _ => [Parameter(asset, "Value")]
        };
        if (kind == "native") target.FunctionFlags = EFunctionFlags.FUNC_Native;
        Function(asset, [new EX_FinalFunction { StackNode = new(2), Parameters = kind == "count" ? [] : [new EX_IntOne()] }]);
        var report = InvocationExtractor.Inspect(asset, Input, kind == "metadata-limit" ? new(MaxArray: 1) : null);
        Assert.Contains(report.Functions[1].Diagnostics, d => d.Code == code);
        Assert.Contains(CoverageGap.IncompleteExtraction, report.Analysis.CoverageGaps);
        var result = Evaluate(report, new MatchExpression.Invocation(new TargetMatcher.Exact("/Script/Other.Owner", "Unrelated")));
        Assert.Empty(result.Findings);
        Assert.Empty(result.Uncertainties);
        Assert.True(result.IsIncomplete);
        Assert.True(result.ShouldFail(true));
    }

    [Fact]
    public void MapGeneratedFunctionsAndNestedCallsKeepStableIdentityAndVmOffsets()
    {
        var asset = Asset();
        Function(asset, [new EX_Context { ObjectExpression = new EX_Self(), ContextExpression = Call(Call()), RValuePointer = new(new FPackageIndex(0)) }]);
        Function(asset, [new EX_Return { ReturnExpression = Call() }], "Unreachable");
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal(3, report.Invocations.Length);
        Assert.Equal([14L, 23L, 1L], report.Invocations.Select(i => i.Offset));
        Assert.Equal("/Game/Maps/Test.BP_Test_C:ExecuteUbergraph_Test#2", report.Invocations[0].ContainingFunction.Qualified);
        Assert.Equal("EX_Self", Assert.Single(report.Invocations[1].Receivers).Opcode);
        Assert.Equal(Input, report.Input);
        Assert.Equal(report.Analysis.Invocations.ToArray(), InvocationExtractor.Inspect(asset, Input with { StoragePath = "/other/random.umap" }).Analysis.Invocations.ToArray());
        Assert.All(report.Invocations, i => Assert.Equal(Input.FactIdentity, i.Fact.Location.Asset));
        Assert.Equal(2, report.Functions.Length);
    }

    [Fact]
    public void DuplicateContainingNamesUseOwnerAndExportIndex()
    {
        var asset = Asset();
        Function(asset, [Call()], "Same");
        Function(asset, [Call()], "Same");
        asset.Exports.Add(new NormalExport { ObjectName = new(asset, "Other_C"), OuterIndex = new(0) });
        Function(asset, [Call()], "Same").OuterIndex = new(4);
        var calls = InvocationExtractor.Inspect(asset, Input).Invocations;
        Assert.Equal(3, calls.Select(c => c.Fact.Location).Distinct().Count());
        Assert.NotEqual(calls[0].ContainingFunction.Owner, calls[2].ContainingFunction.Owner);
    }

    [Theory]
    [InlineData("final")]
    [InlineData("local")]
    [InlineData("math")]
    public void DirectDispatchKeepsStructuredOwnerAndOpcode(string kind)
    {
        var asset = Asset();
        EX_FinalFunction expression = kind switch { "local" => new EX_LocalFinalFunction(), "math" => new EX_CallMath(), _ => new EX_FinalFunction() };
        expression.StackNode = new(-3); expression.Parameters = [];
        Function(asset, [expression]);
        var call = Assert.Single(InvocationExtractor.Inspect(asset, Input).Invocations);
        Assert.Equal(expression.Token.ToString(), call.Opcode);
        Assert.Equal(new InvocationTarget.Resolved("/Script/Engine.KismetSystemLibrary", "Run"), call.Target);
        Assert.Equal(-3, call.ResolvedIdentity!.PackageIndex);
        Assert.Equal("unavailable", call.MetadataState);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void VirtualCallsKeepNameButNeverInventAnOwner(bool local)
    {
        var asset = Asset();
        EX_VirtualFunction call = local ? new EX_LocalVirtualFunction() : new EX_VirtualFunction();
        call.VirtualFunctionName = new(asset, "Run"); call.Parameters = [];
        Function(asset, [call]);
        var report = InvocationExtractor.Inspect(asset, Input);
        var result = Assert.Single(report.Invocations);
        Assert.IsType<InvocationTarget.Unresolved>(result.Target);
        Assert.Equal("Run", result.TargetName);
        Assert.False(report.Complete);
        Assert.Contains(CoverageGap.UnresolvedDispatch, report.Analysis.CoverageGaps);
    }

    [Fact]
    public void MulticastIsNeverMisclassifiedAsDirectInEitherApi()
    {
        var asset = Asset();
        Function(asset, [new EX_CallMulticastDelegate { StackNode = new(-3), Delegate = new EX_Self(), Parameters = [Call()] }]);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal("multicast-delegate", report.Invocations[0].Dispatch);
        Assert.IsType<InvocationTarget.Unresolved>(report.Invocations[0].Target);
        Assert.Equal("direct", report.Invocations[1].Dispatch);
        Assert.Single(Probe.Inspect(asset, Input.LogicalPath, []).Invocations);
    }

    [Fact]
    public void DelegateOperationsAreCoverageNotInventedCalls()
    {
        var asset = Asset();
        Function(asset, [new EX_BindDelegate { FunctionName = new(asset, "Run"), Delegate = new EX_Self(), ObjectTerm = new EX_Self() },
            new EX_InstanceDelegate { FunctionName = new(asset, "Run") },
            new EX_AddMulticastDelegate { Delegate = new EX_Self(), DelegateToAdd = new EX_Self() },
            new EX_RemoveMulticastDelegate { Delegate = new EX_Self(), DelegateToAdd = new EX_Self() },
            new EX_ClearMulticastDelegate { DelegateToClear = new EX_Self() }]);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Empty(report.Invocations);
        Assert.Equal(5, Assert.Single(report.Functions).Diagnostics.Count(d => d.Code == "unresolved-delegate-behavior"));
    }

    [Fact]
    public void LoadedParametersUseSerializedOrderExcludeReturnAndRetainMissing()
    {
        var asset = Asset();
        var target = Function(asset, [], "Target");
        target.LoadedProperties = [Parameter(asset, "Second"), Parameter(asset, "Result", EPropertyFlags.CPF_Parm | EPropertyFlags.CPF_ReturnParm),
            Parameter(asset, "First"), Parameter(asset, "Local", 0), Parameter(asset, "Missing")];
        Function(asset, [new EX_LocalFinalFunction { StackNode = new(2), Parameters = [new EX_NoObject(), new EX_IntOne()] }]);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.False(report.Complete);
        var call = Assert.Single(report.Invocations);
        Assert.Equal(["Second", "First", "Missing"], call.Arguments.Select(a => a.Name));
        Assert.Equal(new ArgumentValue.Constant(new PolicyLiteral.Null()), call.Arguments[0].Value);
        Assert.IsType<ArgumentValue.Missing>(call.Arguments[2].Value);
        Assert.IsType<ArgumentMetadata.Known>(call.Fact.Arguments);
    }

    [Fact]
    public void LegacyPropertyChildNextChainIsOrderedAndBounded()
    {
        var asset = Asset();
        var target = Function(asset, [], "Target");
        target.LoadedProperties = null;
        target.Children = [new(3)];
        asset.Exports.Add(new PropertyExport { ObjectName = new(asset, "A"), OuterIndex = new(2),
            Property = new UIntProperty { PropertyFlags = EPropertyFlags.CPF_Parm, Next = new(4) } });
        asset.Exports.Add(new PropertyExport { ObjectName = new(asset, "B"), OuterIndex = new(2),
            Property = new UIntProperty { PropertyFlags = EPropertyFlags.CPF_Parm, Next = new(0) } });
        Function(asset, [new EX_FinalFunction { StackNode = new(2), Parameters = [new EX_IntZero(), new EX_True()] }]);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal(["A", "B"], Assert.Single(report.Invocations).Arguments.Select(a => a.Name));
        ((PropertyExport)asset.Exports[3]).Property.Next = new(3);
        report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal("malformed", Assert.Single(report.Invocations).MetadataState);
        Assert.IsType<ArgumentMetadata.Unavailable>(report.Invocations[0].Fact.Arguments);
    }

    [Fact]
    public void ConstantsPreserveTypesAndUnsupportedValuesStayDynamicWithEvidence()
    {
        var asset = Asset();
        KismetExpression[] args = [new EX_StringConst { Value = "a" }, new EX_UnicodeStringConst { Value = "世界" },
            new EX_IntConst { Value = -17 }, new EX_Int64Const { Value = long.MaxValue }, new EX_IntConstByte { Value = 200 },
            new EX_IntZero(), new EX_IntOne(), new EX_True(), new EX_False(), new EX_NoObject(), new EX_NoInterface(),
            new EX_NameConst { Value = new(asset, "Name") }, new EX_ByteConst { Value = 1 }, new EX_FloatConst { Value = 1 },
            new EX_ObjectConst { Value = new(-2) }, new EX_Self()];
        var function = Function(asset, [Call(args)]);
        function.ScriptBytecodeSize++; // Correct pinned IntConstByte Visit omission.
        var call = Assert.Single(InvocationExtractor.Inspect(asset, Input).Invocations);
        Assert.Equal(11, call.Arguments.Count(a => a.Value is ArgumentValue.Constant));
        Assert.Equal(new ArgumentValue.Constant(new PolicyLiteral.Integer(200)), call.Arguments[4].Value);
        Assert.All(call.Arguments.Skip(11).Take(4), a => { Assert.IsType<ArgumentValue.Dynamic>(a.Value); Assert.Equal("unsupported-constant-type", a.Reason); });
        Assert.Equal("runtime-expression", call.Arguments[^1].Reason);
        Assert.IsType<ArgumentMetadata.Unavailable>(call.Fact.Arguments);
    }

    [Fact]
    public void IntConstByteCorrectionPreservesFollowingVmOffsets()
    {
        var asset = Asset();
        var function = Function(asset, [new EX_IntConstByte { Value = 4 }, Call()]);
        function.ScriptBytecodeSize++;
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal(2, Assert.Single(report.Invocations).Offset);
        Assert.DoesNotContain(report.Functions[0].Diagnostics, d => d.Code == "bytecode-size-mismatch");
    }

    [Fact]
    public void ContextAndInterfaceReceiverEvidenceIsRetained()
    {
        var asset = Asset();
        Function(asset, [new EX_Context { ObjectExpression = new EX_InterfaceContext { InterfaceValue = new EX_ObjectConst { Value = new(-2) } },
            ContextExpression = Call(), RValuePointer = new(new FPackageIndex(0)) }]);
        var call = Assert.Single(InvocationExtractor.Inspect(asset, Input).Invocations);
        Assert.Equal(["EX_InterfaceContext", "EX_ObjectConst"], call.Receivers.Select(r => r.Opcode));
        Assert.Equal(-2, call.Receivers[1].PackageIndex);
    }

    [Fact]
    public void SwitchTextAndWrappedConstantsVisitTheirActiveChildren()
    {
        var asset = Asset();
        Function(asset, [new EX_SwitchValue { IndexTerm = new EX_IntZero(), Cases = [new(new EX_IntOne(), 0, Call())],
            DefaultTerm = new EX_TextConst { Value = new FScriptText { TextLiteralType = EBlueprintTextLiteralType.InvariantText,
                InvariantLiteralString = new EX_SoftObjectConst { Value = new EX_FieldPathConst { Value = Call() } } } } }]);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal(2, report.Invocations.Length);
        Assert.DoesNotContain(report.Functions[0].Diagnostics, d => d.Code.Contains("sequence"));
    }

    [Fact]
    public void NativeRawAndNonFunctionBytecodeHaveExplicitCoverage()
    {
        var asset = Asset();
        Function(asset, []).FunctionFlags = EFunctionFlags.FUNC_Native;
        Function(asset, null);
        asset.Exports.Add(new RawExport());
        asset.Exports.Add(new StructExport { ScriptBytecode = [Call()] });
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.True(report.Functions[0].Native);
        Assert.Contains(report.Functions[0].Diagnostics, d => d.Code == "native-function-boundary");
        Assert.Contains(report.Functions[1].Diagnostics, d => d.Code == "unparsed-bytecode");
        Assert.Contains(report.Diagnostics, d => d.Code == "raw-export");
        Assert.Contains(report.Diagnostics, d => d.Code == "unsupported-script-export");
        Assert.False(report.Complete);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(int.MinValue)]
    [InlineData(999)]
    [InlineData(-999)]
    public void BadTargetReferencesRetainCallsAsUnresolved(int index)
    {
        var asset = Asset();
        var call = Call(); call.StackNode = new(index);
        Function(asset, [call]);
        Assert.IsType<InvocationTarget.Unresolved>(Assert.Single(InvocationExtractor.Inspect(asset, Input).Invocations).Target);
    }

    private sealed class UnknownExpression : EX_Nothing { }

    [Theory]
    [InlineData("cycle", "expression-cycle")]
    [InlineData("deep", "expression-depth-limit")]
    [InlineData("dag", "instruction-limit")]
    [InlineData("unknown", "unsupported-instruction")]
    [InlineData("null", "required-expression-missing")]
    [InlineData("literal", "literal-limit")]
    [InlineData("array", "expression-array-limit")]
    public void MalformedGraphsAreRejectedBeforeRecursiveVisit(string kind, string code)
    {
        var asset = Asset();
        var function = Function(asset, [Call()]);
        KismetExpression root = new EX_Nothing();
        switch (kind)
        {
            case "cycle": var cycle = new EX_Return(); cycle.ReturnExpression = cycle; root = cycle; break;
            case "deep": for (var i = 0; i < 20; i++) root = new EX_Return { ReturnExpression = root }; break;
            case "dag": for (var i = 0; i < 10; i++) root = new EX_FinalFunction { StackNode = new(-3), Parameters = [root, root] }; break;
            case "unknown": root = new UnknownExpression(); break;
            case "null": root = new EX_Return(); break;
            case "literal": root = new EX_StringConst { Value = new string('x', 33) }; break;
            case "array": root = new EX_FinalFunction { StackNode = new(-3), Parameters = Enumerable.Repeat(root, 11).ToArray() }; break;
        }
        function.ScriptBytecode = [Call(), root, Call()];
        var report = InvocationExtractor.Inspect(asset, Input, new(MaxOccurrences: 30, MaxDepth: 16, MaxArray: 10, MaxLiteral: 32));
        Assert.Single(report.Invocations); // Prior findings survive; later offsets are unknown.
        Assert.Contains(report.Functions[0].Diagnostics, d => d.Code == code);
        Assert.False(report.Complete);
    }

    [Fact]
    public void SharedDagOccurrencesAreNotMistakenForCyclesOrDeduplicated()
    {
        var asset = Asset();
        var shared = Call(); Function(asset, [Call(shared, shared)]);
        Assert.Equal([0L, 9L, 19L], InvocationExtractor.Inspect(asset, Input).Invocations.Select(c => c.Offset));
    }

    [Fact]
    public void SizeMismatchAndMissingMetadataAreDifferentFromNullAndParserFailure()
    {
        var asset = Asset();
        var target = Function(asset, [], "Target"); target.LoadedProperties = null; target.Children = null;
        var function = Function(asset, [new EX_FinalFunction { StackNode = new(2), Parameters = [new EX_NoInterface(), new EX_Self()] }]);
        function.ScriptBytecodeSize++;
        var report = InvocationExtractor.Inspect(asset, Input);
        var call = Assert.Single(report.Invocations);
        Assert.Equal("constant", call.Arguments[0].Reason);
        Assert.Equal("runtime-expression", call.Arguments[1].Reason);
        Assert.Equal("unavailable", call.MetadataState);
        Assert.Contains(report.Functions[1].Diagnostics, d => d.Code == "parameter-metadata-unavailable");
        Assert.Contains(report.Functions[1].Diagnostics, d => d.Code == "bytecode-size-mismatch");
    }

    [Fact]
    public void ParserFailureDiagnosticsNeverLeakInputOrTemporaryPath()
    {
        var report = InvocationExtractor.Read(Input with { StoragePath = "/nonexistent/private-secret.uasset" });
        Assert.Equal("package-read-failed", Assert.Single(report.Diagnostics).Code);
        Assert.Empty(report.Invocations);
        Assert.Contains(CoverageGap.UnsupportedParsing, report.Analysis.CoverageGaps);
    }

    [Theory]
    [InlineData("null-property")]
    [InlineData("duplicate")]
    [InlineData("bad-name")]
    [InlineData("bad-child")]
    public void MalformedSignaturesNeverInventArgumentNames(string kind)
    {
        var asset = Asset();
        var target = Function(asset, [], "Target");
        target.LoadedProperties = kind switch
        {
            "null-property" => [null!],
            "duplicate" => [Parameter(asset, "Same"), Parameter(asset, "Same")],
            "bad-name" => [Parameter(asset, "Not valid")],
            _ => null
        };
        if (kind == "bad-child") target.Children = [new(int.MinValue)];
        Function(asset, [new EX_FinalFunction { StackNode = new(2), Parameters = [new EX_IntOne()] }]);
        var call = Assert.Single(InvocationExtractor.Inspect(asset, Input).Invocations);
        Assert.Equal("malformed", call.MetadataState);
        Assert.IsType<ArgumentMetadata.Unavailable>(call.Fact.Arguments);
        Assert.Null(Assert.Single(call.Arguments).Name);
        Assert.Equal("constant", call.Arguments[0].Reason);
    }

    [Fact]
    public void ImportedIdenticalNamesOnDifferentOwnersRemainDistinct()
    {
        var asset = Asset();
        asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-1), "OtherLibrary", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Function", new(-4), "Run", false, asset));
        var other = Call(); other.StackNode = new(-5);
        Function(asset, [Call(), other]);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.NotEqual(report.Invocations[0].Target, report.Invocations[1].Target);
        Assert.Equal(report.Invocations[0].TargetName, report.Invocations[1].TargetName);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(-2)]
    public void NonFunctionReferencesAreNeverResolvedAsCalls(int reference)
    {
        var asset = Asset(); var call = Call(); call.StackNode = new(reference);
        Function(asset, [call]);
        Assert.IsType<InvocationTarget.Unresolved>(Assert.Single(InvocationExtractor.Inspect(asset, Input).Invocations).Target);
    }

    [Theory]
    [InlineData("unicode", "invalid-unicode-literal")]
    [InlineData("null-array", "required-expression-missing")]
    [InlineData("null-element", "required-expression-missing")]
    [InlineData("null-value", "invalid-expression-value")]
    [InlineData("null-target", "required-value-missing")]
    [InlineData("text-kind", "unsupported-text-literal")]
    public void InvalidOperandsFailClosedWithFixedReasons(string kind, string reason)
    {
        var asset = Asset(); var function = Function(asset, []);
        var nullArray = Call(); nullArray.Parameters = null;
        var nullTarget = Call(); nullTarget.StackNode = null;
        function.ScriptBytecode = [kind switch
        {
            "unicode" => new EX_StringConst { Value = "\ud800" },
            "null-array" => nullArray,
            "null-element" => Call(null!),
            "null-value" => new EX_IntConst(),
            "null-target" => nullTarget,
            _ => new EX_TextConst { Value = new FScriptText { TextLiteralType = (EBlueprintTextLiteralType)255 } }
        }];
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Empty(report.Invocations);
        Assert.Contains(report.Functions[0].Diagnostics, d => d.Code == reason);
    }

    [Fact]
    public void NativeTargetAndClassBoundariesAreExplicit()
    {
        var asset = Asset();
        var native = Function(asset, [], "Native"); native.FunctionFlags = EFunctionFlags.FUNC_Native;
        asset.Exports.Add(new ClassExport { ObjectName = new(asset, "Nativized_C"), OuterIndex = new(0), ClassFlags = EClassFlags.CLASS_Native });
        Function(asset, [new EX_FinalFunction { StackNode = new(2), Parameters = [] }]);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Contains(report.Diagnostics, d => d.Code == "native-class-boundary");
        Assert.Contains(report.Functions[1].Diagnostics, d => d.Code == "native-target-boundary");
        Assert.IsType<InvocationTarget.Resolved>(Assert.Single(report.Invocations).Target);
    }

    [Fact]
    public void ExportAndArgumentEvidenceLimitsGenerateCoverage()
    {
        var asset = Asset();
        var target = Function(asset, [], "Target");
        target.LoadedProperties = Enumerable.Range(0, 8).Select(i => Parameter(asset, $"P{i}")).ToArray();
        Function(asset, [new EX_FinalFunction { StackNode = new(2), Parameters = [] }, new EX_FinalFunction { StackNode = new(2), Parameters = [] }]);
        var report = InvocationExtractor.Inspect(asset, Input, new(MaxOccurrences: 10));
        Assert.Single(report.Invocations);
        Assert.Contains(report.Functions[1].Diagnostics, d => d.Code == "argument-evidence-limit");
        report = InvocationExtractor.Inspect(asset, Input, new(MaxExports: 1));
        Assert.Empty(report.Functions);
        Assert.Contains(report.Diagnostics, d => d.Code == "export-limit");
    }

    [Fact]
    public void PolicyFactsEvaluateAndPakEntryIdentitiesDoNotCollide()
    {
        var asset = Asset();
        var target = Function(asset, [], "Target"); target.LoadedProperties = [Parameter(asset, "Value")];
        Function(asset, [new EX_FinalFunction { StackNode = new(2), Parameters = [new EX_NoObject()] }]);
        var report = InvocationExtractor.Inspect(asset, Input);
        var policy = new PolicyDocument(1, [new("null-value", "Null argument", RuleEffect.Forbid,
            new MatchExpression.Argument("Value", new ValuePredicate.EqualTo(new PolicyLiteral.Null()))) ]);
        var evaluation = new PolicyEvaluator(policy).Evaluate(report.Analysis);
        Assert.True(evaluation.HasForbiddenFindings);
        Assert.False(evaluation.IsIncomplete);
        Assert.NotEqual(Input.FactIdentity, (Input with { Pak = "different" }).FactIdentity);
        Assert.NotEqual(Input.FactIdentity, (Input with { Entry = "different" }).FactIdentity);
        Assert.Equal(Input.FactIdentity, (Input with { StoragePath = "/changed" }).FactIdentity);
    }

    [Fact]
    public void RegistryRecognizesEveryConcreteInstructionInPinnedDependency()
    {
        foreach (var type in typeof(EX_Nothing).Assembly.GetTypes().Where(t => !t.IsAbstract &&
                     t.Namespace == typeof(EX_Nothing).Namespace && typeof(KismetExpression).IsAssignableFrom(t)))
        {
            var asset = Asset(); var function = Function(asset, []);
            function.ScriptBytecode = [(KismetExpression)Activator.CreateInstance(type)!];
            var report = InvocationExtractor.Inspect(asset, Input);
            Assert.DoesNotContain(report.Functions[0].Diagnostics, d => d.Code == "unsupported-instruction");
        }
    }

    private sealed class UnknownExport : NormalExport { }

    [Fact]
    public void UnknownExportsAndBrokenContainingOuterChainsHaveCoverage()
    {
        var asset = Asset();
        asset.Exports.Add(new UnknownExport());
        var function = Function(asset, [Call()]); function.OuterIndex = new(3);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Contains(report.Diagnostics, d => d.Code == "unsupported-export");
        Assert.Contains(report.Functions[0].Diagnostics, d => d.Code == "containing-function-identity-unresolved");
        Assert.Single(report.Invocations);
    }

    [Fact]
    public void MissingPropertyPointersDoNotPassAsSupportedCleanInstructions()
    {
        var asset = Asset(); var function = Function(asset, []);
        function.ScriptBytecode = [new EX_LocalVariable()];
        Assert.Contains(InvocationExtractor.Inspect(asset, Input).Functions[0].Diagnostics, d => d.Code == "required-value-missing");
    }

    [Theory]
    [InlineData("name")]
    [InlineData("float")]
    [InlineData("byte")]
    [InlineData("uint64")]
    [InlineData("object")]
    public void UnsupportedTypedConstantsProducePolicyUnknownNotFalseMatches(string kind)
    {
        var asset = Asset(); var target = Function(asset, [], "Target"); target.LoadedProperties = [Parameter(asset, "Value")];
        KismetExpression expression = kind switch
        {
            "name" => new EX_NameConst { Value = new(asset, "a") },
            "float" => new EX_FloatConst { Value = 1 },
            "byte" => new EX_ByteConst { Value = 1 },
            "uint64" => new EX_UInt64Const { Value = ulong.MaxValue },
            _ => new EX_ObjectConst { Value = new(-2) }
        };
        Function(asset, [new EX_FinalFunction { StackNode = new(2), Parameters = [expression] }]);
        var report = InvocationExtractor.Inspect(asset, Input);
        var policy = new PolicyDocument(1, [new("value", "Typed value", RuleEffect.Forbid,
            new MatchExpression.Argument("Value", new ValuePredicate.EqualTo(new PolicyLiteral.String("a"))))]);
        var evaluation = new PolicyEvaluator(policy).Evaluate(report.Analysis);
        Assert.Empty(evaluation.Findings);
        Assert.Contains(UncertaintyReason.DynamicArgument, Assert.Single(evaluation.Uncertainties).Reasons);
        Assert.Contains(CoverageGap.IncompleteExtraction, evaluation.CoverageGaps);
        Assert.Equal("unsupported-constant-type", Assert.Single(report.Invocations).Arguments[0].Reason);
    }

    [Fact]
    public void MissingMappingsAndCookedMarkersArePackageCoverageNotParserSuccess()
    {
        var asset = Asset(); asset.PackageFlags = EPackageFlags.PKG_UnversionedProperties;
        Function(asset, []);
        var report = InvocationExtractor.Inspect(asset, Input);
        Assert.Equal(2, report.ExportCount);
        Assert.Equal(2, report.InspectedExports);
        Assert.Contains(report.Diagnostics, d => d.Code == "missing-property-mappings");
        Assert.Contains(report.Diagnostics, d => d.Code == "no-cooked-or-filtered-marker");
        Assert.False(report.Complete);
    }
}
