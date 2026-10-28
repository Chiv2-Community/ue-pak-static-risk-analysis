using System.Collections.Immutable;
using PakRisk.Policy;
using Xunit;

namespace Policy.Tests;

public class WildcardTests
{
    private static PolicyDocument Parse(string expression) => PolicyYaml.Parse(
        "schema-version: 1\nrules:\n- id: test\n  description: Test rule\n  effect: forbid\n  expression:\n    " + expression.Replace("\n", "\n    "));

    private static PolicyEvaluation Evaluate(PolicyDocument policy, ArgumentMetadata arguments, bool unresolved = false) =>
        new PolicyEvaluator(policy).Evaluate(new InvocationAnalysis([
            new InvocationFact(new InvocationLocation("/Game/Test", "Run", 0),
                unresolved ? new InvocationTarget.Unresolved() : new InvocationTarget.Resolved("/Script/Engine.Test", "Run"), arguments)
        ], []));

    private static ArgumentMetadata Known(params NamedArgument[] arguments) => new ArgumentMetadata.Known(arguments.ToImmutableArray());
    private static NamedArgument Constant(string name, PolicyLiteral literal) => new(name, new ArgumentValue.Constant(literal));
    private static PolicyDocument Argument(string predicate, string name = "__WILDCARD__") =>
        Parse($"argument:\n  name: {name}\n  predicate:\n    " + predicate.Replace("\n", "\n    "));

    [Theory]
    [InlineData("__WILDCARD__")]
    [InlineData("__WILDCARD__:Run")]
    [InlineData("/Script/Engine.Test:__WILDCARD__")]
    [InlineData("{class: __WILDCARD__, function: Run}")]
    [InlineData("{class: /Script/Engine.Test, function: __WILDCARD__}")]
    [InlineData("{function: '__WILDCARD__:Run'}")]
    public void TargetWildcardsMatchResolvedButNotUnresolvedEvidence(string target)
    {
        var document = Parse("invocation: " + target);
        Assert.Single(Evaluate(document, Known()).Findings);
        Assert.Single(Evaluate(document, Known(), true).Uncertainties);
        Assert.Single(Evaluate(PolicyYaml.Parse(PolicyYaml.Write(document)), Known()).Findings);
    }

    [Fact]
    public void WildcardArgumentsAreExistentialAndPreserveUnknown()
    {
        var document = Argument("kind: equals\nvalue: foo");
        Assert.Single(Evaluate(document, Known(Constant("A", new PolicyLiteral.String("bar")), Constant("B", new PolicyLiteral.String("foo")))).Findings);
        Assert.Empty(Evaluate(document, Known()).Findings);
        Assert.Empty(Evaluate(document, Known()).Uncertainties);
        Assert.Single(Evaluate(document, Known(new NamedArgument("A", new ArgumentValue.Dynamic()))).Uncertainties);
        Assert.Single(Evaluate(document, new ArgumentMetadata.Unavailable()).Uncertainties);
        Assert.Single(Evaluate(document, Known(new NamedArgument("A", new ArgumentValue.Dynamic()), Constant("B", new PolicyLiteral.String("foo")))).Findings);
    }

    [Theory]
    [InlineData("42", "integer")]
    [InlineData("+42", "integer")]
    [InlineData("0x2A", "integer")]
    [InlineData("0o52", "integer")]
    [InlineData("'42'", "string")]
    [InlineData("yes", "string")]
    [InlineData("no", "string")]
    [InlineData("true", "boolean")]
    [InlineData("False", "boolean")]
    [InlineData("null", "null")]
    [InlineData("~", "null")]
    [InlineData("1.5", "number")]
    [InlineData("1e3", "number")]
    [InlineData("__WILDCARD__", "wildcard")]
    [InlineData("'__WILDCARD__'", "wildcard")]
    public void ScalarsUseYamlCoreInferenceAndRoundTrip(string value, string kind)
    {
        var document = Argument("kind: equals\nvalue: " + value);
        var canonical = PolicyYaml.Write(document);
        Assert.Contains($"\"kind\": \"{kind}\"", canonical);
        Assert.Equal(canonical, PolicyYaml.Write(PolicyYaml.Parse(canonical)));
    }

    [Fact]
    public void MixedSetsAndExplicitWildcardEscapesWork()
    {
        var set = Argument("kind: in\nvalues: [foo, 42, true, 1.5, null]");
        foreach (var value in new PolicyLiteral[] { new PolicyLiteral.String("foo"), new PolicyLiteral.Integer(42),
            new PolicyLiteral.Boolean(true), new PolicyLiteral.Number(1.5), new PolicyLiteral.Null() })
            Assert.Single(Evaluate(set, Known(Constant("A", value))).Findings);
        var literal = Argument("kind: equals\nvalue: {kind: string, value: '__WILDCARD__'}", "{literal: __WILDCARD__}");
        Assert.Empty(Evaluate(literal, Known(Constant("A", new PolicyLiteral.String("__WILDCARD__")))).Findings);
        Assert.Single(Evaluate(literal, Known(Constant("__WILDCARD__", new PolicyLiteral.String("__WILDCARD__")))).Findings);
        Assert.Equal(PolicyYaml.Write(literal), PolicyYaml.Write(PolicyYaml.Parse(PolicyYaml.Write(literal))));
        var wildcard = Argument("kind: equals\nvalue: __WILDCARD__");
        Assert.Single(Evaluate(wildcard, Known(Constant("A", new PolicyLiteral.Null()))).Findings);
        Assert.Single(Evaluate(wildcard, Known(new NamedArgument("A", new ArgumentValue.Dynamic()))).Uncertainties);
    }

    [Theory]
    [InlineData(".inf")]
    [InlineData(".NaN")]
    [InlineData("1e999")]
    [InlineData("9223372036854775808")]
    [InlineData("0xffffffffffffffff")]
    [InlineData("[1, 2]")]
    public void RejectsUnrepresentableScalarsAndArrayEquality(string value) =>
        Assert.Throws<PolicyException>(() => Argument("kind: equals\nvalue: " + value));

    [Fact]
    public void WildcardArgsStayOnOneCallAndAreIndependent()
    {
        var document = Parse("""
            invocation:
              class: __WILDCARD__
              function: __WILDCARD__
              args:
                - argument:
                    name: __WILDCARD__
                    predicate: {kind: equals, value: foo}
                - argument:
                    name: __WILDCARD__
                    predicate: {kind: equals, value: bar}
            """);
        Assert.Single(Evaluate(document, Known(Constant("A", new PolicyLiteral.String("foo")),
            Constant("B", new PolicyLiteral.String("bar")))).Findings);
        Assert.Empty(Evaluate(document, Known(Constant("A", new PolicyLiteral.String("foo")))).Findings);
        Assert.Empty(Evaluate(document, Known(Constant("B", new PolicyLiteral.String("bar")))).Findings);
    }

    [Fact]
    public void LiteralFunctionEscapeAndPartialTokensAreNotWildcards()
    {
        var literal = Parse("invocation: {class: /Script/Engine.Test, function: {literal: __WILDCARD__}}");
        Assert.Empty(Evaluate(literal, Known()).Findings);
        Assert.Equal(PolicyYaml.Write(literal), PolicyYaml.Write(PolicyYaml.Parse(PolicyYaml.Write(literal))));
        Assert.Empty(Evaluate(Parse("invocation: /Script/Engine.Test:Run__WILDCARD__"), Known()).Findings);
        Assert.Empty(Evaluate(Argument("kind: equals\nvalue: foo__WILDCARD__"),
            Known(Constant("A", new PolicyLiteral.String("foobar")))).Findings);
        Assert.Throws<PolicyException>(() => Parse("invocation: {class: __WILDCARD__, args: [{argument: {name: A, predicate: {kind: equals, value: foo}}}]}"));
    }

    [Fact]
    public void WildcardsAreForbiddenInFacts()
    {
        var document = Argument("kind: equals\nvalue: foo");
        Assert.Throws<ArgumentException>(() => Evaluate(document, Known(Constant("A", new PolicyLiteral.Wildcard()))));
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("exact")]
    [InlineData("pattern")]
    [InlineData("write")]
    public void PublicAstCannotReinterpretLiteralOwnerAsWildcard(string variant)
    {
        MatchExpression expression = variant switch
        {
            "owner" => new MatchExpression.Invocation(new TargetMatcher.ByOwner(PolicyYaml.Wildcard)),
            "exact" => new MatchExpression.Invocation(new TargetMatcher.Exact(PolicyYaml.Wildcard, "Run")),
            "pattern" => new MatchExpression.Invocation(new TargetMatcher.Pattern(PolicyYaml.Wildcard, "Run")),
            _ => new MatchExpression.PropertyWrite(PolicyYaml.Wildcard, "Sensitive")
        };
        var document = new PolicyDocument(1, [new("test", "Test", RuleEffect.Forbid, expression)]);
        Assert.Throws<InvalidOperationException>(() => PolicyYaml.Write(document));
        Assert.Throws<ArgumentException>(() => new PolicyEvaluator(document));
    }

    [Theory]
    [InlineData("invocation: __WILDCARD__")]
    [InlineData("invocation: {class: __WILDCARD__, function: Run}")]
    [InlineData("invocation: {class: __WILDCARD__, function: __WILDCARD__}")]
    [InlineData("property-write: {class: __WILDCARD__, property: Sensitive}")]
    public void IntentionalWildcardOwnersRemainNullAndRoundTrip(string expression)
    {
        var document = Parse(expression);
        var facts = new InvocationAnalysis([
            new(new("/Game/Test", "Run", 0), new InvocationTarget.Resolved("/Script/Engine.Test", "Run"), Known())
        ], [], PropertyWrites: new(true, [
            new(new("/Game/Test", "Run", 1), "EX_Let", "/Script/Engine.Test", "Sensitive", "self", new ArgumentValue.Dynamic())]));
        foreach (var policy in new[] { document, PolicyYaml.Parse(PolicyYaml.Write(document)) })
        {
            var leaf = Assert.Single(policy.Rules).Match;
            if (leaf is MatchExpression.Invocation invocation)
                Assert.Null(Assert.IsType<TargetMatcher.Pattern>(invocation.Target).Owner);
            else Assert.Null(Assert.IsType<MatchExpression.PropertyWrite>(leaf).Owner);
            var result = new PolicyEvaluator(policy).Evaluate(facts);
            Assert.True(result.HasForbiddenFindings);
            Assert.False(result.IsIncomplete);
        }
    }
}
