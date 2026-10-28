using PakRisk.Policy;
using Xunit;

namespace Policy.Tests;

public sealed class PropertyWriteTests
{
    private static PolicyDocument Policy(string expression) => PolicyYaml.Parse(
        "schema-version: 1\nrules:\n- id: test\n  description: Test\n  effect: forbid\n  expression:\n    " + expression.Replace("\n", "\n    "));
    private static InvocationAnalysis Facts(string? property = "Settings.Distance", string? owner = "/Script/Example.Player",
        ArgumentValue? value = null, bool complete = true) => new([], [], PropertyWrites: new(complete, [
            new(new("/Game/Test", "Run", 0), "EX_Let", owner, property, "object", value ?? new ArgumentValue.Dynamic())]));

    [Theory]
    [InlineData("Settings", true, false)]
    [InlineData("Settings.Distance", true, false)]
    [InlineData("Settings.Distance.Other", false, true)]
    [InlineData("Settings.Other", false, false)]
    [InlineData("Setting", false, false)]
    [InlineData("__WILDCARD__", true, false)]
    public void RootSelectorsCoverDescendantsAndAncestorsAreUnknown(string property, bool match, bool unknown)
    {
        var policy = Policy($"property-write: {{class: __WILDCARD__, property: {property}}}");
        Assert.Equal(PolicyYaml.Write(policy), PolicyYaml.Write(PolicyYaml.Parse(PolicyYaml.Write(policy))));
        var result = new PolicyEvaluator(policy).Evaluate(Facts());
        Assert.Equal(match, result.PropertyWriteFindings.Length == 1);
        Assert.Equal(unknown, result.Uncertainties.Length == 1);
        Assert.Empty(result.Findings);
    }

    [Theory]
    [InlineData("{kind: equals, value: 1.5}", true)]
    [InlineData("{kind: equals, value: 2.5}", false)]
    [InlineData("{kind: in, values: [foo, 1.5]}", true)]
    [InlineData("{kind: equals, value: __WILDCARD__}", true)]
    public void ValuePredicatesReuseTypedMatching(string predicate, bool match)
    {
        var policy = Policy($"property-write: {{class: /Script/Example.Player, property: Settings.Distance, predicate: {predicate}}}");
        var result = new PolicyEvaluator(policy).Evaluate(Facts(value: new ArgumentValue.Constant(new PolicyLiteral.Number(1.5))));
        Assert.Equal(match, result.HasForbiddenFindings);
        Assert.Empty(result.Uncertainties);
        Assert.True(new PolicyEvaluator(policy).Evaluate(Facts()).IsIncomplete);
    }

    [Fact]
    public void LogicalKeysAndEventDomainsDoNotCreateSpuriousCallFindings()
    {
        var policy = Policy("""
            all:
              - any:
                  - property-write: {class: __WILDCARD__, property: Settings}
                  - property-write: {class: __WILDCARD__, property: Other}
              - not:
                  property-write: {class: __WILDCARD__, property: Allowed}
            """);
        var facts = Facts() with { Invocations = [new(new("/Game/Test", "Run", 5),
            new InvocationTarget.Unresolved(), new ArgumentMetadata.Unavailable())] };
        var result = new PolicyEvaluator(policy).Evaluate(facts);
        Assert.Single(result.PropertyWriteFindings);
        Assert.Empty(result.Findings);
        Assert.Empty(result.Uncertainties);
        var callsOnly = new PolicyEvaluator(Policy("not: {invocation: /Script/Example.Player:Run}")).Evaluate(Facts());
        Assert.Empty(callsOnly.PropertyWriteFindings);
    }

    [Fact]
    public void MissingWriteEvidenceAndUnknownDestinationsCannotBecomeClean()
    {
        var evaluator = new PolicyEvaluator(Policy("not: {property-write: {class: __WILDCARD__, property: Settings}}"));
        Assert.True(evaluator.Evaluate(new([], [])).IsIncomplete);
        Assert.True(evaluator.Evaluate(Facts(complete: false)).IsIncomplete);
        Assert.Single(evaluator.Evaluate(Facts(property: null)).Uncertainties);
        Assert.Single(evaluator.Evaluate(Facts(owner: null)).Uncertainties);
        Assert.False(evaluator.Evaluate(new([], [], PropertyWrites: new(true, []))).IsIncomplete);
    }

    [Fact]
    public void KnownOwnerMismatchCanDisproveMatchButWholeStructCannotSatisfyFieldValue()
    {
        var evaluator = new PolicyEvaluator(Policy("property-write: {class: /Script/Example.Other, property: Settings}"));
        Assert.False(evaluator.Evaluate(Facts(property: null)).IsIncomplete);
        evaluator = new PolicyEvaluator(Policy("property-write: {class: __WILDCARD__, property: Settings.Distance, predicate: {kind: equals, value: 1.5}}"));
        Assert.Single(evaluator.Evaluate(Facts(property: "Settings")).Uncertainties);
    }

    [Theory]
    [InlineData("and: [{invocation: /Script/Example.Player}]")]
    [InlineData("or: [{invocation: /Script/Example.Player}]")]
    [InlineData("property-write: {class: __WILDCARD__, property: 'Bad..Path'}")]
    [InlineData("property-write: {property: Settings}")]
    [InlineData("property-write: {class: __WILDCARD__, property: Settings, extra: true}")]
    [InlineData("argument: {name: Value, predicate: {kind: subexpr-match, subexpr: {property-write: {class: __WILDCARD__, property: Settings}}}}")]
    public void OldAliasesAndInvalidPropertyExpressionsAreRejected(string expression) =>
        Assert.Throws<PolicyException>(() => Policy(expression));
}
