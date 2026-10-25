using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using PakRisk.Policy;
using PakRisk.Scanner;
using Xunit;

namespace Scanner.Tests;

public sealed class CallChainTests
{
    private const string Owner = "/Game/Fixture.BP";
    private const string Native = "/Script/Fixture.Utility";
    private static CallGraphFunction Function(string name, string owner = Owner, string asset = "fixture", bool native = false) =>
        new(asset, owner + ":" + name, owner, name, native);
    private static InvocationFact Call(string source, string target, int offset = 0, string owner = Owner) =>
        new(new("fixture", Owner + ":" + source, offset), new InvocationTarget.Resolved(owner, target), new ArgumentMetadata.Unavailable());
    private static InvocationAnalysis Analysis(params InvocationFact[] calls) => new(calls.ToImmutableArray(), [], null,
        new(1, true, [Function("Root"), Function("Helper"), Function("Wrapper")]));
    private static readonly PolicyEvaluator Evaluator = new(PolicyYaml.Parse("""
        schema-version: 1
        rules:
          - id: private-policy-canary
            description: private-policy-canary
            effect: forbid
            match:
              kind: invocation
              target:
                kind: exact
                owner: /Script/Fixture.Utility
                function: Sensitive
        """));
    private static CapabilityCatalog Catalog(string function = "Touch") => CapabilityCatalog.Read(Encoding.UTF8.GetBytes($$"""
        {"schema-version":1,"disclosure":"nonsecret","revision":"original-fixture-v1","summaries":[
          {"owner":"/Script/Fixture.Utility","function":"{{function}}","capability":"fixture-capability",
           "provenance":"Original synthetic symbolic fixture; not a native-code claim",
           "build-scope":"original-fixture-v1 only; exact game unverified",
           "reviewed-limitations":"Model assertion only; no execution or argument/control-flow semantics"}]}
        """));
    private static CallChainEvidence Run(InvocationAnalysis analysis, CapabilityCatalog? catalog = null, CallChainLimits? limits = null) =>
        CallChains.Analyze(analysis, Evaluator.Evaluate(analysis), catalog, limits);

    [Fact]
    public void InnocuousWrapperHasCapabilityOnlyWithExactExplicitCatalog()
    {
        var analysis = Analysis(Call("Root", "Helper"), Call("Helper", "Wrapper"), Call("Wrapper", "Touch", 27, Native));
        Assert.Empty(Run(analysis).Witnesses);
        Assert.Contains("external-summary-unavailable", Run(analysis).Diagnostics);
        var result = Run(analysis, Catalog());
        Assert.True(result.Complete);
        Assert.True(result.NeedsReview);
        var chain = Assert.Single(result.Witnesses, w => w.Callers.Length == 2);
        Assert.Equal(27, chain.Endpoint.Origin.Offset);
        Assert.Equal("Wrapper", chain.Callers[1].Target.Function);
        Assert.Equal(Owner + ":Root", chain.Callers[0].Origin.Function);
        Assert.Equal("fixture-capability", chain.Endpoint.Capability);
        Assert.False(chain.Endpoint.Forbidden);
        Assert.Equal("direct", chain.Resolution);
        Assert.Empty(Run(analysis, Catalog("Other")).Witnesses);
    }

    [Fact]
    public void ActualMatchedEndpointsUseSharedEvaluationWithoutLeakingPrivatePolicyOrChangingCounts()
    {
        var analysis = Analysis(Call("Root", "Helper"), Call("Helper", "Wrapper"), Call("Wrapper", "Sensitive", 27, Native));
        var facts = ScannerTests.Facts(analysis);
        var evaluation = Evaluator.Evaluate(analysis);
        var report = RiskReport.Create(facts, evaluation, false, null);
        var before = RiskReport.Create(facts with { Analysis = analysis with { CallGraph = null } }, evaluation, false, null);
        Assert.Equal(before.Counts, report.Counts);
        Assert.Equal(before.ForbiddenInvocations, report.ForbiddenInvocations);
        Assert.Equal(3, report.Counts.Invocations);
        Assert.Equal(1, report.Counts.Forbidden);
        Assert.Single(report.CallChains!.Witnesses, w => w.Callers.Length == 2);
        Assert.DoesNotContain("private-policy-canary", JsonSerializer.Serialize(report, RiskReport.JsonOptions));
    }

    [Fact]
    public void CyclesAndDuplicatePathsTerminateWithOneShortestWitnessPerSourceAndCertainty()
    {
        var analysis = Analysis(Call("Root", "Helper"), Call("Root", "Helper", 9), Call("Helper", "Root"),
            Call("Helper", "Wrapper", 10), Call("Wrapper", "Touch", 27, Native));
        var result = Run(analysis, Catalog());
        Assert.True(result.Complete);
        Assert.Equal(3, result.Witnesses.Length);
        Assert.All(result.Witnesses, w => Assert.True(w.Callers.Length <= 2));
        var reversed = analysis with { Invocations = analysis.Invocations.Reverse().ToImmutableArray(),
            CallGraph = analysis.CallGraph! with { Functions = analysis.CallGraph.Functions.Reverse().ToArray() } };
        Assert.Equal(JsonSerializer.Serialize(result), JsonSerializer.Serialize(Run(reversed, Catalog())));
    }

    [Theory]
    [InlineData("virtual", "EX_VirtualFunction")]
    [InlineData("delegate-binding", "EX_BindDelegate")]
    [InlineData("timer", "EX_FinalFunction")]
    public void PossibleEdgesStayPossibleEvenWithReviewedEndpoint(string kind, string opcode)
    {
        var analysis = Analysis(Call("Helper", "Wrapper"), Call("Wrapper", "Touch", 27, Native));
        analysis = analysis with { Dispatches = [new(1, new("fixture", Owner + ":Root", 40), opcode, kind, "Helper", "unknown", "possible",
            [new(Owner, "Helper", "local-function")], kind == "timer" ? ["open-world", "native-build-unverified"] : ["open-world"],
            kind == "timer" ? "ue425plus-2d1aae-kismet-timer" : "kismet-serialized-v1")] };
        var result = Run(analysis, Catalog());
        var chain = Assert.Single(result.Witnesses, w => w.Callers.Length == 2);
        Assert.Equal("possible", chain.Resolution);
        Assert.Equal("possible", chain.Callers[0].Resolution);
        Assert.Equal("direct", chain.Endpoint.Resolution);
        Assert.Contains("indirect-open-world", result.Diagnostics);
        Assert.False(result.Complete);
    }

    [Fact]
    public void PossibleCatalogEndpointIsNotAnActualSensitiveInvocation()
    {
        var analysis = Analysis() with { Dispatches = [new(1, new("fixture", Owner + ":Root", 40), "EX_BindDelegate", "delegate-binding", "Touch",
            "unknown", "possible", [new(Native, "Touch", "imported-function")], ["open-world"], "kismet-serialized-v1")] };
        var result = Run(analysis, Catalog());
        var witness = Assert.Single(result.Witnesses);
        Assert.Equal("possible", witness.Endpoint.Resolution);
        Assert.False(witness.Endpoint.Flagged || witness.Endpoint.Forbidden);
        Assert.Empty(Evaluator.Evaluate(analysis).Findings);
    }

    [Fact]
    public void MissingSourceDoesNotInventOwnerAndAmbiguousSymbolsDoNotCrossLink()
    {
        var analysis = Analysis(Call("Root", "Helper"), Call("Helper", "Touch", 27, Native));
        var absent = Run(analysis with { CallGraph = null }, Catalog());
        Assert.Contains("graph-context-unavailable", absent.Diagnostics);
        Assert.Contains("source-identity-unavailable", absent.Diagnostics);
        Assert.Empty(Assert.Single(absent.Witnesses).Callers);
        var ambiguous = analysis with { CallGraph = new(1, true, [.. analysis.CallGraph!.Functions,
            Function("Helper", asset: "other-package")]) };
        var result = Run(ambiguous, Catalog());
        Assert.Contains("target-identity-ambiguous", result.Diagnostics);
        Assert.Empty(Assert.Single(result.Witnesses).Callers);
        var distinctOwner = analysis with { CallGraph = new(1, true, [.. analysis.CallGraph.Functions,
            Function("Helper", "/Game/Other.BP")]) };
        Assert.Single(Run(distinctOwner, Catalog()).Witnesses, w => w.Callers.Length == 1);
    }

    [Fact]
    public void MissingNativeSummaryIsExplicitEvenWhenUncalled()
    {
        var analysis = Analysis() with { CallGraph = new(1, true, [Function("Touch", Native, native: true)]) };
        Assert.Contains("native-summary-unavailable", Run(analysis).Diagnostics);
        Assert.True(Run(analysis, Catalog()).Complete);
    }

    [Fact]
    public void LimitsPreserveDirectFindingsAndKnownWitnessesWithIncompleteGate()
    {
        var analysis = Analysis(Call("Root", "Helper"), Call("Helper", "Wrapper"), Call("Wrapper", "Sensitive", 27, Native));
        var evaluation = Evaluator.Evaluate(analysis);
        foreach (var (limits, diagnostic) in new[] {
            (new CallChainLimits(MaxDepth: 1), "witness-depth-limit"),
            (new CallChainLimits(MaxWitnesses: 1), "witness-limit"),
            (new CallChainLimits(MaxEdges: 1), "graph-edge-limit"),
            (new CallChainLimits(MaxWork: 2), "graph-work-limit"),
            (new CallChainLimits(MaxEvidenceBytes: 1), "evidence-byte-limit") })
        {
            var evidence = CallChains.Analyze(analysis, evaluation, Catalog("Sensitive"), limits);
            Assert.Contains(diagnostic, evidence.Diagnostics);
            var report = RiskReport.Create(ScannerTests.Facts(analysis), evaluation, false, null).WithCallChains(evidence);
            Assert.False(report.AnalysisComplete);
            Assert.True(new GateOptions().Fails(report));
            Assert.Single(report.ForbiddenInvocations);
            Assert.Equal(1, report.Counts.Forbidden);
        }
    }

    [Fact]
    public void WorkLimitPrioritizesAllAlreadyKnownEndpointsBeforeUpstreamExpansion()
    {
        var analysis = Analysis(Call("Root", "Helper"), Call("Helper", "Sensitive", 10, Native), Call("Wrapper", "Sensitive", 27, Native));
        var result = Run(analysis, Catalog("Sensitive"), new(MaxWork: 3));
        Assert.Contains("graph-work-limit", result.Diagnostics);
        Assert.Equal(2, result.Witnesses.Length);
        Assert.All(result.Witnesses, witness => Assert.Empty(witness.Callers));
        Assert.Equal(new long[] { 10, 27 }, result.Witnesses.Select(w => w.Endpoint.Origin.Offset).ToArray());
    }

    [Theory]
    [InlineData("schema-version", "2")]
    [InlineData("complete", "\"true\"")]
    [InlineData("functions", "null")]
    [InlineData("private-policy", "{}")]
    public void GraphContextHasClosedStrictTransport(string key, string value)
    {
        var node = JsonNode.Parse(FactsCodec.Write(ScannerTests.Facts(Analysis())))!;
        node["analysis"]!["call-graph"]![key] = JsonNode.Parse(value);
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Fact]
    public void DuplicateOrOversizedGraphDefinitionsAreRejectedAndBoundedProducerRetainsPartialPrefix()
    {
        var function = Function("Root");
        Assert.Throws<FactsException>(() => FactsCodec.Write(ScannerTests.Facts(Analysis() with { CallGraph = new(1, true, [function, function]) })));
        var functions = Enumerable.Range(0, 4097).Select(i => Function("F" + i)).ToArray();
        var bounded = CallGraphContext.Bounded(functions, true);
        Assert.False(bounded.Complete);
        Assert.True(bounded.Functions.Sum(CallGraphContext.Characters) <= CallGraphContext.MaxCharacters);
        Assert.NotEmpty(bounded.Functions);
        var facts = ScannerTests.Facts(Analysis() with { CallGraph = bounded });
        Assert.Equal(FactsCodec.Write(facts), FactsCodec.Write(FactsCodec.Read(FactsCodec.Write(facts))));
    }

    [Fact]
    public void OptionalGraphCannotEvictDirectFactsAtAggregateTransportLimit()
    {
        var calls = Enumerable.Range(0, 7000).Select(i => Call("Root", "Sensitive", i, Native)).ToImmutableArray();
        var analysis = new InvocationAnalysis(calls, []);
        var baseline = FactsCodec.Write(ScannerTests.Facts(analysis));
        var functions = Enumerable.Range(0, 3000).Select(i => new CallGraphFunction("a", "f" + i, "/A.B", "F" + i, false)).ToArray();
        var result = FactsCodec.Read(FactsCodec.Write(ScannerTests.Facts(analysis with { CallGraph = CallGraphContext.Bounded(functions, true) })));
        Assert.False(result.Analysis.CallGraph!.Complete);
        Assert.Empty(result.Analysis.CallGraph.Functions);
        Assert.Equal(calls.Length, result.Analysis.Invocations.Length);
        Assert.Equal(7000, Evaluator.Evaluate(result.Analysis).Findings.Length);
        Assert.Equal(baseline, FactsCodec.Write(result with { Analysis = result.Analysis with { CallGraph = null } }));
    }

    [Fact]
    public void OptionalGraphCannotEvictDirectFactsAtAggregateByteLimit()
    {
        var arguments = new ArgumentMetadata.Known([new("Value", new ArgumentValue.Constant(new PolicyLiteral.String(new string('x', 4096))))]);
        var analysis = new InvocationAnalysis(Enumerable.Range(0, 1900).Select(i => Call("Root", "Sensitive", i, Native)
            with { Arguments = arguments }).ToImmutableArray(), []);
        var baseline = FactsCodec.Write(ScannerTests.Facts(analysis));
        var functions = Enumerable.Range(0, 3000).Select(i => new CallGraphFunction("a", "f" + i, "/A.B", "F" + i, false)).ToArray();
        var result = FactsCodec.Read(FactsCodec.Write(ScannerTests.Facts(analysis with { CallGraph = CallGraphContext.Bounded(functions, true) })));
        Assert.False(result.Analysis.CallGraph!.Complete);
        Assert.Empty(result.Analysis.CallGraph.Functions);
        Assert.Equal(1900, result.Analysis.Invocations.Length);
        Assert.Equal(baseline, FactsCodec.Write(result with { Analysis = result.Analysis with { CallGraph = null } }));
    }

    [Theory]
    [InlineData("schema-version", "2")]
    [InlineData("schema-version", "\"1\"")]
    [InlineData("disclosure", "\"private\"")]
    [InlineData("revision", "\"../file\"")]
    [InlineData("summaries", "null")]
    [InlineData("policy", "{}")]
    public void CatalogHasClosedVersionedNonsecretContract(string key, string value)
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(Catalog().Document, RiskReport.JsonOptions))!;
        node[key] = JsonNode.Parse(value);
        Assert.Throws<CapabilityConfigurationException>(() => CapabilityCatalog.Read(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Fact]
    public void CatalogRejectsDuplicatesInvalidUtf8UnknownSummaryKeysAndOversize()
    {
        var document = Catalog().Document;
        void Reject(CapabilityCatalogDocument changed) => Assert.Throws<CapabilityConfigurationException>(() =>
            CapabilityCatalog.Read(JsonSerializer.SerializeToUtf8Bytes(changed, RiskReport.JsonOptions)));
        Reject(document with { Summaries = [document.Summaries[0], document.Summaries[0]] });
        Reject(document with { Summaries = [document.Summaries[0] with { Provenance = "" }] });
        Reject(document with { Summaries = Enumerable.Range(0, 257).Select(i => document.Summaries[0] with { Function = "F" + i }).ToImmutableArray() });
        Assert.Throws<CapabilityConfigurationException>(() => CapabilityCatalog.Read([0xff]));
        Assert.Throws<CapabilityConfigurationException>(() => CapabilityCatalog.Read(new byte[CapabilityCatalog.MaxBytes + 1]));
        var json = JsonSerializer.Serialize(document, RiskReport.JsonOptions);
        Assert.Throws<CapabilityConfigurationException>(() => CapabilityCatalog.Read(Encoding.UTF8.GetBytes(json.Replace("\"schema-version\": 1", "\"schema-version\": 1, \"schema-version\": 1"))));
        Assert.Throws<CapabilityConfigurationException>(() => CapabilityCatalog.Read(Encoding.UTF8.GetBytes(json.Replace("\"capability\":", "\"secret-policy\": 1, \"capability\":"))));
    }

    [Fact]
    public void CatalogReportDisclosesOnlyExplicitPublicIdAndDigestNotContentsOrPolicy()
    {
        var catalog = Catalog();
        var analysis = Analysis(Call("Wrapper", "Touch", 27, Native));
        var report = RiskReport.Create(ScannerTests.Facts(analysis), Evaluator.Evaluate(analysis), false, null, catalog);
        var text = JsonSerializer.Serialize(report, RiskReport.JsonOptions);
        Assert.Contains(catalog.Sha256, text);
        Assert.Contains("fixture-capability", text);
        Assert.DoesNotContain("Model assertion", text);
        Assert.DoesNotContain("Original synthetic", text);
        Assert.DoesNotContain("private-policy-canary", text);
        Assert.True(new GateOptions(false, false, false).Fails(report));
        Assert.Equal(0, report.Counts.Forbidden);
    }

    [Fact]
    public void SeededCyclicGraphsKeepBoundedStableWitnessesAndNeverUpgradePossibleEdges()
    {
        var random = new Random(150409);
        for (var seed = 0; seed < 32; seed++)
        {
            var functions = Enumerable.Range(0, 8).Select(i => Function("F" + i)).ToArray();
            var calls = Enumerable.Range(0, 24).Select(i => Call("F" + random.Next(8), "F" + random.Next(8), i)).ToList();
            calls.Add(Call("F7", "Touch", 200, Native));
            var dispatches = Enumerable.Range(0, 8).Select(i =>
            {
                var name = "F" + random.Next(8);
                return new IndirectDispatch(1, new("fixture", Owner + ":F" + i, 100 + i), "EX_VirtualFunction", "virtual",
                    name, "unknown", "possible", [new(Owner, name, "local-function")], ["open-world"], "kismet-serialized-v1");
            }).ToArray();
            var analysis = new InvocationAnalysis(calls.ToImmutableArray(), [], dispatches, new(1, true, functions));
            var result = Run(analysis, Catalog());
            Assert.True(result.Witnesses.Length <= 16);
            foreach (var witness in result.Witnesses)
            {
                Assert.Equal(200, witness.Endpoint.Origin.Offset);
                Assert.True(witness.Callers.Length <= 16);
                Assert.Equal(witness.Callers.Any(s => s.Resolution == "possible") ? "possible" : "direct", witness.Resolution);
                Assert.All(witness.Callers, step => Assert.True(calls.Any(c => c.Location == step.Origin)
                    || dispatches.Any(d => d.Origin == step.Origin)));
            }
            var reversed = analysis with { Invocations = analysis.Invocations.Reverse().ToImmutableArray(),
                Dispatches = dispatches.Reverse().ToArray(), CallGraph = new(1, true, functions.Reverse().ToArray()) };
            Assert.Equal(JsonSerializer.Serialize(result), JsonSerializer.Serialize(Run(reversed, Catalog())));
        }
    }
}
