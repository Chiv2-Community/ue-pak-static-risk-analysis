using System.Text;
using System.Collections.Immutable;
using System.Text.Json.Nodes;
using PakRisk.Policy;
using PakRisk.Scanner;
using Xunit;

namespace Scanner.Tests;

public sealed class ProvenanceCodecTests
{
    private static FactsDocument Facts() => ScannerTests.Facts(new([
        new(new("/Game/Asset", "Run", 1), new InvocationTarget.Resolved("/Script/Example.Bar", "Baz"),
            new ArgumentMetadata.Known([new("foo", new ArgumentValue.Derived(new(1, [
                new("literal", [], true, Literal: new PolicyLiteral.String("foo")),
                new("call", [0], true, new InvocationTarget.Resolved("/Script/Example.String", "Append"), [new("A", 0)])])))]))], []));

    [Fact]
    public void ProvenanceRoundTripsThroughClosedFactsTransport()
    {
        var bytes = FactsCodec.Write(Facts());
        var parsed = FactsCodec.Read(bytes);
        Assert.Equal(bytes, FactsCodec.Write(parsed));
        var derived = Assert.IsType<ArgumentValue.Derived>(Assert.Single(
            Assert.IsType<ArgumentMetadata.Known>(Assert.Single(parsed.Analysis.Invocations).Arguments).Arguments).Value);
        Assert.Equal(2, derived.Provenance.Nodes.Length);
        var predicate = new ValuePredicate.SubexprMatch(new MatchExpression.Invocation(
            new TargetMatcher.Exact("/Script/Example.String", "Append"),
            [new("A", new ValuePredicate.EqualTo(new PolicyLiteral.String("foo")))]));
        var evaluator = new PolicyEvaluator(new(1, [new("test", "Test", RuleEffect.Forbid,
            new MatchExpression.Argument("foo", predicate))]));
        Assert.Single(evaluator.Evaluate(parsed.Analysis).Findings);
    }

    [Theory]
    [InlineData("1.5")]
    [InlineData("__WILDCARD__")]
    public void NumericFactsSupportWildcardProvenanceSearch(string pattern)
    {
        var facts = Facts();
        var invocation = facts.Analysis.Invocations[0];
        var derived = (ArgumentValue.Derived)((ArgumentMetadata.Known)invocation.Arguments).Arguments[0].Value;
        var graph = derived.Provenance with { Nodes = derived.Provenance.Nodes.SetItem(0,
            derived.Provenance.Nodes[0] with { Literal = new PolicyLiteral.Number(1.5) }) };
        facts = facts with { Analysis = facts.Analysis with { Invocations = [invocation with {
            Arguments = new ArgumentMetadata.Known([new("foo", new ArgumentValue.Derived(graph))]) }] } };
        var bytes = FactsCodec.Write(facts);
        var parsed = FactsCodec.Read(bytes);
        Assert.Equal(bytes, FactsCodec.Write(parsed));
        var policy = PolicyYaml.Parse($$"""
            schema-version: 1
            rules:
              - id: test
                description: Test
                effect: forbid
                expression:
                  argument:
                    name: __WILDCARD__
                    predicate:
                      kind: subexpr-match
                      subexpr:
                        invocation:
                          class: __WILDCARD__
                          function: __WILDCARD__
                          args:
                            - argument:
                                name: __WILDCARD__
                                predicate: {kind: equals, value: {{pattern}}}
            """);
        Assert.Single(new PolicyEvaluator(policy).Evaluate(parsed.Analysis).Findings);
    }

    [Theory]
    [InlineData("root", "99")]
    [InlineData("root", "-1")]
    [InlineData("root", "null")]
    [InlineData("nodes", "[]")]
    [InlineData("nodes", "null")]
    [InlineData("extra", "true")]
    public void InvalidGraphsAreRejectedAtTheTransportBoundary(string key, string value)
    {
        var node = JsonNode.Parse(FactsCodec.Write(Facts()))!;
        node["analysis"]!["invocations"]![0]!["arguments"]!["arguments"]![0]!["value"]!["provenance"]![key] = JsonNode.Parse(value);
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Fact]
    public void CyclicGraphReferencesAreRejected()
    {
        var node = JsonNode.Parse(FactsCodec.Write(Facts()))!;
        node["analysis"]!["invocations"]![0]!["arguments"]!["arguments"]![0]!["value"]!["provenance"]!["nodes"]![1]!["inputs"] = new JsonArray(1);
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Fact]
    public void TransportExhaustionDropsProvenanceNotInvocations()
    {
        var nodes = ImmutableArray.CreateBuilder<ValueOrigin>();
        nodes.Add(new("literal", [], true, Literal: new PolicyLiteral.String("foo")));
        for (var i = 1; i < 256; i++) nodes.Add(new("call", [0], true,
            new InvocationTarget.Resolved("/Script/Example.String", "Append"), [new("A", 0), new("B", 0)]));
        var derived = new ArgumentValue.Derived(new(255, nodes.ToImmutable()));
        var facts = ScannerTests.Facts(new(Enumerable.Range(0, 32).Select(i => new InvocationFact(
            new("/Game/Asset", "Caller", i), new InvocationTarget.Resolved("/Script/Example.Bar", "Baz"),
            new ArgumentMetadata.Known([new("foo", derived)]))).ToImmutableArray(), []));
        var parsed = FactsCodec.Read(FactsCodec.Write(facts));
        Assert.Equal(32, parsed.Analysis.Invocations.Length);
        Assert.All(parsed.Analysis.Invocations, fact => Assert.IsType<ArgumentValue.Dynamic>(
            Assert.Single(Assert.IsType<ArgumentMetadata.Known>(fact.Arguments).Arguments).Value));
    }
}
