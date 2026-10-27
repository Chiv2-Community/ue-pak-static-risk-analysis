using System.Collections.Immutable;
using PakRisk.Policy;
using Xunit;

namespace Policy.Tests;

public sealed class SubexpressionTests
{
    private static readonly MatchExpression Producer = new MatchExpression.Invocation(
        new TargetMatcher.Exact("/Script/Example.String", "Append"),
        [new("A", new ValuePredicate.EqualTo(new PolicyLiteral.String("foo")))]);
    private static readonly ValueProvenance Graph = new(1, [
        new("literal", [], true, Literal: new PolicyLiteral.String("foo")),
        new("call", [0], true, new InvocationTarget.Resolved("/Script/Example.String", "Append"), [new("A", 0)])]);
    private static PolicyDocument Policy(MatchExpression? subexpr = null, bool negate = false)
    {
        MatchExpression expression = new MatchExpression.Argument("foo", new ValuePredicate.SubexprMatch(subexpr ?? Producer));
        if (negate) expression = new MatchExpression.Not(expression);
        return new(1, [new("test", "Test", RuleEffect.Forbid, expression)]);
    }
    private static InvocationAnalysis Analysis(ValueProvenance graph) => new([
        new(new("/Game/Asset", "Caller", 1), new InvocationTarget.Resolved("/Script/Example.Bar", "Baz"),
            new ArgumentMetadata.Known([new("foo", new ArgumentValue.Derived(graph))]))], []);

    [Fact]
    public void OnlyReachableValueDependenciesCanMatch()
    {
        var evaluator = new PolicyEvaluator(Policy());
        Assert.Single(evaluator.Evaluate(Analysis(Graph)).Findings);
        var unrelated = evaluator.Evaluate(Analysis(Graph with { Root = 0 }));
        Assert.Empty(unrelated.Findings);
        Assert.Empty(unrelated.Uncertainties);
        var noMatch = new PolicyEvaluator(Policy(new MatchExpression.Invocation(new TargetMatcher.ByOwner("/Script/Other.Class"))))
            .Evaluate(Analysis(Graph));
        Assert.Empty(noMatch.Findings);
        Assert.Empty(noMatch.Uncertainties);
    }

    [Fact]
    public void IncompleteProvenanceCannotBecomeApprovalThroughNegation()
    {
        var graph = new ValueProvenance(0, [new("unknown", [], false)]);
        foreach (var negate in new[] { false, true })
        {
            var result = new PolicyEvaluator(Policy(negate: negate)).Evaluate(Analysis(graph));
            Assert.Empty(result.Findings);
            Assert.Contains(UncertaintyReason.IncompleteProvenance, Assert.Single(result.Uncertainties).Reasons);
        }
        // A known producer is still actionable when further dependencies are opaque.
        var partial = Graph with { Nodes = Graph.Nodes.SetItem(1, Graph.Nodes[1] with { Complete = false }) };
        Assert.Single(new PolicyEvaluator(Policy()).Evaluate(Analysis(partial)).Findings);
    }

    [Fact]
    public void InvalidProvenanceIsRejectedBeforeEvaluation()
    {
        ValueProvenance[] invalid = [Graph with { Root = -1 }, Graph with { Root = 2 }, new(0, []),
            new(0, default), new(0, [null!]),
            new(0, [new("unknown", [], true)]),
            new(0, [new("call", [], true)]),
            Graph with { Nodes = Graph.Nodes.SetItem(1, Graph.Nodes[1] with { Inputs = [1] }) },
            Graph with { Nodes = Graph.Nodes.SetItem(1, Graph.Nodes[1] with { Inputs = [2] }) },
            Graph with { Nodes = Graph.Nodes.SetItem(1, Graph.Nodes[1] with { Arguments = [new("A", 1)] }) },
            Graph with { Nodes = Graph.Nodes.SetItem(1, Graph.Nodes[1] with { Arguments = [new("A", 0), new("A", 0)] }) }];
        foreach (var graph in invalid)
            Assert.Throws<ArgumentException>(() => new PolicyEvaluator(Policy()).Evaluate(Analysis(graph)));
    }

    [Fact]
    public void RecursivePolicyAstsAreBoundedBeforeSerialization()
    {
        MatchExpression expression = Producer;
        for (var i = 0; i < 40; i++) expression = new MatchExpression.Argument("A", new ValuePredicate.SubexprMatch(expression));
        Assert.Throws<ArgumentException>(() => new PolicyEvaluator(Policy(expression)));
        Assert.Throws<ArgumentException>(() => new PolicyEvaluator(Policy(new MatchExpression.Argument("A", new ValuePredicate.SubexprMatch(null!)))));
    }

    [Fact]
    public void DroppedProvenanceRemainsUnknown()
    {
        var trimmed = ValueProvenance.Bound(Analysis(Graph), 0);
        var result = new PolicyEvaluator(Policy()).Evaluate(trimmed);
        Assert.Empty(result.Findings);
        Assert.Single(result.Uncertainties);
    }

    [Fact]
    public void SearchWorkExhaustionCannotBecomeANegativeMatch()
    {
        var nodes = ImmutableArray.CreateBuilder<ValueOrigin>();
        nodes.Add(new("literal", [], true, Literal: new PolicyLiteral.String("bar")));
        for (var i = 1; i < 255; i++) nodes.Add(new("call", [0], true,
            new InvocationTarget.Resolved("/Script/Other.Class", "Other"), []));
        nodes.Add(new("call", Enumerable.Range(1, 254).ToImmutableArray(), true,
            new InvocationTarget.Resolved("/Script/Other.Class", "Root"), []));
        var graph = new ValueProvenance(255, nodes.ToImmutable());
        var noProducer = new MatchExpression.Not(new MatchExpression.Argument("foo", new ValuePredicate.SubexprMatch(Producer)));
        var expression = new MatchExpression.All(Enumerable.Repeat<MatchExpression>(noProducer, 20).ToImmutableArray());
        var evaluator = new PolicyEvaluator(new(1, [new("bounded", "Bounded", RuleEffect.Forbid, expression)]));
        var result = evaluator.Evaluate(Analysis(graph));
        Assert.Empty(result.Findings);
        Assert.Contains(UncertaintyReason.ProvenanceLimit, Assert.Single(result.Uncertainties).Reasons);
    }
}
