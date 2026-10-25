using System.Collections.Immutable;
using System.Text.Json;
using PakRisk.Policy;
using Xunit;

namespace Policy.Tests;

public sealed class EvaluatorTests
{
    private const string Owner = "/Script/Engine.KismetSystemLibrary";
    private static readonly InvocationFact Fact = new(new("/Game/Test", "Run", 12),
        new InvocationTarget.Resolved(Owner, "LaunchURL"),
        new ArgumentMetadata.Known([new("URL", new ArgumentValue.Dynamic())]));
    private static MatchExpression Target(string function = "LaunchURL") => new MatchExpression.Invocation(new TargetMatcher.Exact(Owner, function));
    private static MatchExpression Argument(ValuePredicate? predicate = null) => new MatchExpression.Argument("URL", predicate ?? new ValuePredicate.UrlHostIn(["mods.example.org"]));
    private static PolicyDocument Document(params PolicyRule[] rules) => new(1, rules.ToImmutableArray());
    private static PolicyRule Rule(MatchExpression expression, string id = "test", RuleEffect effect = RuleEffect.Forbid) => new(id, "Test rule.", effect, expression);
    private static PolicyEvaluation Run(MatchExpression expression, InvocationFact? fact = null) =>
        new PolicyEvaluator(Document(Rule(expression))).Evaluate(new([fact ?? Fact], []));
    private static MatchResult Result(PolicyEvaluation result) => !result.Findings.IsEmpty ? MatchResult.Match
        : !result.Uncertainties.IsEmpty ? MatchResult.Unknown : MatchResult.NoMatch;
    private static MatchExpression State(MatchResult result) => result switch
    {
        MatchResult.Match => Target(),
        MatchResult.NoMatch => Target("Other"),
        _ => Argument()
    };

    public static IEnumerable<object[]> TruthTables()
    {
        foreach (var left in Enum.GetValues<MatchResult>())
        foreach (var right in Enum.GetValues<MatchResult>())
            yield return [left, right];
    }

    [Theory, MemberData(nameof(TruthTables))]
    public void AllAndAnyUseDecisiveOperands(MatchResult left, MatchResult right)
    {
        var all = left == MatchResult.NoMatch || right == MatchResult.NoMatch ? MatchResult.NoMatch
            : left == MatchResult.Unknown || right == MatchResult.Unknown ? MatchResult.Unknown : MatchResult.Match;
        var any = left == MatchResult.Match || right == MatchResult.Match ? MatchResult.Match
            : left == MatchResult.Unknown || right == MatchResult.Unknown ? MatchResult.Unknown : MatchResult.NoMatch;
        Assert.Equal(all, Result(Run(new MatchExpression.All([State(left), State(right)]))));
        Assert.Equal(any, Result(Run(new MatchExpression.Any([State(left), State(right)]))));
        Assert.Equal(all, Result(Run(new MatchExpression.Not(new MatchExpression.Any([
            new MatchExpression.Not(State(left)), new MatchExpression.Not(State(right))])))));
    }

    [Theory]
    [InlineData(MatchResult.Match, MatchResult.NoMatch)]
    [InlineData(MatchResult.NoMatch, MatchResult.Match)]
    [InlineData(MatchResult.Unknown, MatchResult.Unknown)]
    public void NotPreservesUnknown(MatchResult input, MatchResult expected) =>
        Assert.Equal(expected, Result(Run(new MatchExpression.Not(State(input)))));

    [Fact]
    public void MetadataMissingDynamicAndKnownNullAreDistinct()
    {
        var equalsNull = Argument(new ValuePredicate.EqualTo(new PolicyLiteral.Null()));
        Assert.Equal(MatchResult.Match, Result(Run(equalsNull, WithValue(new ArgumentValue.Constant(new PolicyLiteral.Null())))));
        Assert.Equal(UncertaintyReason.DynamicArgument, Assert.Single(Assert.Single(Run(equalsNull).Uncertainties).Reasons));
        Assert.Equal(UncertaintyReason.MissingArgument, Assert.Single(Assert.Single(Run(equalsNull,
            Fact with { Arguments = new ArgumentMetadata.Known([]) }).Uncertainties).Reasons));
        Assert.Equal(UncertaintyReason.MissingArgument, Assert.Single(Assert.Single(Run(equalsNull,
            WithValue(new ArgumentValue.Missing())).Uncertainties).Reasons));
        Assert.Equal(UncertaintyReason.ArgumentMetadataUnavailable, Assert.Single(Assert.Single(Run(equalsNull,
            Fact with { Arguments = new ArgumentMetadata.Unavailable() }).Uncertainties).Reasons));
    }

    private static InvocationFact WithValue(ArgumentValue value) => Fact with { Arguments = new ArgumentMetadata.Known([new("URL", value)]) };
    private static InvocationFact WithLiteral(PolicyLiteral value) => WithValue(new ArgumentValue.Constant(value));

    [Fact]
    public void TypedComparisonsNeverCoerce()
    {
        PolicyLiteral[] values = [new PolicyLiteral.String("1"), new PolicyLiteral.Integer(1), new PolicyLiteral.Boolean(true), new PolicyLiteral.Null()];
        foreach (var expected in values)
        foreach (var actual in values)
        {
            var wanted = expected == actual ? MatchResult.Match : MatchResult.NoMatch;
            Assert.Equal(wanted, Result(Run(Argument(new ValuePredicate.EqualTo(expected)), WithLiteral(actual))));
            Assert.Equal(wanted, Result(Run(Argument(new ValuePredicate.In([expected])), WithLiteral(actual))));
        }
        Assert.Equal(MatchResult.NoMatch, Result(Run(Argument(new ValuePredicate.StringStartsWith("1")), WithLiteral(new PolicyLiteral.Integer(1)))));
        Assert.Equal(MatchResult.NoMatch, Result(Run(Argument(), WithLiteral(new PolicyLiteral.Null()))));
        Assert.Equal(MatchResult.NoMatch, Result(Run(Argument(new ValuePredicate.StringStartsWith("A")), WithLiteral(new PolicyLiteral.String("abc")))));
        Assert.Equal(MatchResult.Match, Result(Run(Argument(new ValuePredicate.StringStartsWith("a")), WithLiteral(new PolicyLiteral.String("abc")))));
    }

    [Theory]
    [InlineData("https://mods.example.org/", true)]
    [InlineData("HTTPS://MODS.EXAMPLE.ORG:443/a?q=b#c", true)]
    [InlineData("https://mods.example.org:444/", false)]
    [InlineData("https://mods.example.org:/", false)]
    [InlineData("https://mods.example.org.evil.org/", false)]
    [InlineData("https://sub.mods.example.org/", false)]
    [InlineData("https://mods.example.org@evil.org/", false)]
    [InlineData("https://user:password@mods.example.org/", false)]
    [InlineData("https://@mods.example.org/", false)]
    [InlineData("https://mods.example.org./", false)]
    [InlineData("http://mods.example.org/", false)]
    [InlineData("ftp://mods.example.org/", false)]
    [InlineData("//mods.example.org/", false)]
    [InlineData("not a URL", false)]
    [InlineData(" https://mods.example.org/", false)]
    [InlineData("https://mods.example.org/\n", false)]
    [InlineData("https://mods.example.org\\@evil.org/", false)]
    [InlineData("https://%6dods.example.org/", false)]
    [InlineData("https://mоds.example.org/", false)]
    [InlineData("https://127.0.0.1/", false)]
    [InlineData("https://[::1]/", false)]
    [InlineData("https:///mods.example.org/", false)]
    public void UrlHostMatchingIsParsedAndStrict(string url, bool match) =>
        Assert.Equal(match ? MatchResult.Match : MatchResult.NoMatch, Result(Run(Argument(), WithLiteral(new PolicyLiteral.String(url)))));

    [Fact]
    public void IdnaRequiresExplicitAsciiHostAndUrlAuthority()
    {
        var expression = Argument(new ValuePredicate.UrlHostIn(["xn--bcher-kva.example"]));
        Assert.Equal(MatchResult.Match, Result(Run(expression, WithLiteral(new PolicyLiteral.String("https://xn--bcher-kva.example/")))));
        Assert.Equal(MatchResult.NoMatch, Result(Run(expression, WithLiteral(new PolicyLiteral.String("https://bücher.example/")))));
    }

    [Fact]
    public void UnrelatedDynamicArgumentsDoNotMakeNonmatchingTargetIncomplete()
    {
        Assert.False(Run(new MatchExpression.All([Argument(), Target("Other")])).IsIncomplete);
        Assert.False(Run(new MatchExpression.All([Target("Other"), Argument()])).IsIncomplete);
        Assert.Equal(UncertaintyReason.UnresolvedTarget, Assert.Single(Assert.Single(Run(Target(),
            Fact with { Target = new InvocationTarget.Unresolved() }).Uncertainties).Reasons));
        Assert.Equal(MatchResult.Match, Result(Run(new MatchExpression.Invocation(new TargetMatcher.ByOwner(Owner)))));
    }

    [Fact]
    public void RulesAndLocationsAreStableDeduplicatedAndNeverOverride()
    {
        PolicyRule[] rules = [Rule(Target(), "z-flag", RuleEffect.Flag), Rule(Target(), "a-forbid"), Rule(Argument(), "unknown")];
        var other = Fact with { Location = Fact.Location with { Offset = 4 } };
        var first = new PolicyEvaluator(Document(rules)).Evaluate(new([Fact, other, Fact], []));
        var second = new PolicyEvaluator(Document(rules.Reverse().ToArray())).Evaluate(new([other, Fact], []));
        Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
        Assert.Equal(2, first.Findings.Length);
        Assert.All(first.Findings, finding =>
        {
            Assert.True(finding.IsForbidden);
            Assert.Equal(new[] { "a-forbid", "z-flag" }, finding.Rules.Select(rule => rule.RuleId));
        });
        Assert.True(first.ShouldFail(false));
    }

    [Fact]
    public void CoverageAndFailureDecisionAreSeparateFromFindings()
    {
        var evaluator = new PolicyEvaluator(Document(Rule(Target("Other"))));
        var result = evaluator.Evaluate(new([Fact], [CoverageGap.UnsupportedParsing, CoverageGap.UnsupportedParsing]));
        Assert.Empty(result.Findings);
        Assert.Empty(result.Uncertainties);
        Assert.Single(result.CoverageGaps);
        Assert.False(result.ShouldFail(false));
        Assert.True(result.ShouldFail(true));
        var unknown = Run(Argument());
        Assert.False(unknown.ShouldFail(false));
        Assert.True(unknown.ShouldFail(true));
        var flag = new PolicyEvaluator(Document(Rule(Target(), effect: RuleEffect.Flag))).Evaluate(new([Fact], []));
        Assert.False(flag.ShouldFail(true));
        Assert.False(evaluator.Evaluate(new([], [])).IsIncomplete);
    }

    [Fact]
    public void ReasonsDoNotExposePolicyLiteralsOrDescriptions()
    {
        var rule = Rule(new MatchExpression.Not(Argument(new ValuePredicate.EqualTo(new PolicyLiteral.String("private-canary")))));
        var result = new PolicyEvaluator(Document(rule with { Description = "secret-description" })).Evaluate(new([Fact], []));
        var json = JsonSerializer.Serialize(result);
        Assert.DoesNotContain("private-canary", json);
        Assert.DoesNotContain("secret-description", json);
        Assert.Equal(UncertaintyReason.DynamicArgument, Assert.Single(Assert.Single(result.Uncertainties).Reasons));
    }

    [Fact]
    public void UnknownReasonSetsAreSortedDeduplicatedAndOrderIndependent()
    {
        var fact = Fact with { Target = new InvocationTarget.Unresolved() };
        MatchExpression[] operands = [Argument(), Target(), Argument()];
        var first = Run(new MatchExpression.All(operands.ToImmutableArray()), fact);
        var second = Run(new MatchExpression.All(operands.Reverse().ToImmutableArray()), fact);
        Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
        Assert.Equal(new[] { UncertaintyReason.UnresolvedTarget, UncertaintyReason.DynamicArgument },
            Assert.Single(first.Uncertainties).Reasons);
    }

    [Fact]
    public void DuplicateFactsIgnoreNamedArgumentOrdering()
    {
        NamedArgument[] arguments = [new("URL", new ArgumentValue.Dynamic()), new("Other", new ArgumentValue.Missing())];
        var first = Fact with { Arguments = new ArgumentMetadata.Known(arguments.ToImmutableArray()) };
        var second = Fact with { Arguments = new ArgumentMetadata.Known(arguments.Reverse().ToImmutableArray()) };
        var result = new PolicyEvaluator(Document(Rule(Target()))).Evaluate(new([first, second], []));
        Assert.Single(result.Findings);
    }

    [Fact]
    public void InvalidFactsRejectWholeBatchEvenWhenRulesWouldNotMatch()
    {
        InvocationFact[] invalid = [null!, Fact with { Target = null! }, Fact with { Arguments = null! },
            Fact with { Location = new("", "Run", 0) }, Fact with { Location = Fact.Location with { Offset = -1 } },
            Fact with { Target = new InvocationTarget.Resolved("invalid", "Run") },
            Fact with { Target = new InvocationTarget.Resolved(Owner, "Run\n") },
            Fact with { Arguments = new ArgumentMetadata.Known(default) },
            Fact with { Arguments = new ArgumentMetadata.Known([new("URL", new ArgumentValue.Dynamic()), new("URL", new ArgumentValue.Missing())]) },
            WithValue(new ArgumentValue.Constant(null!)), WithLiteral(new PolicyLiteral.String(null!)),
            WithLiteral(new PolicyLiteral.String("\ud800")), WithLiteral(new PolicyLiteral.String(new string('a', 4097)))];
        var evaluator = new PolicyEvaluator(Document(Rule(Target("Other"))));
        foreach (var fact in invalid)
            Assert.Equal("Invalid invocation analysis.", Assert.Throws<ArgumentException>(() => evaluator.Evaluate(new([fact], []))).Message);
        Assert.Throws<ArgumentException>(() => evaluator.Evaluate(new(default, [])));
        Assert.Throws<ArgumentException>(() => evaluator.Evaluate(new([], default)));
        Assert.Throws<ArgumentException>(() => evaluator.Evaluate(new([], [(CoverageGap)99])));
        Assert.Throws<ArgumentException>(() => evaluator.Evaluate(new([Fact, Fact with { Target = new InvocationTarget.Unresolved() }], [])));
        Assert.Throws<ArgumentException>(() => evaluator.Evaluate(new(Enumerable.Repeat(Fact, PolicyEvaluator.MaxInvocations + 1).ToImmutableArray(), [])));
        Assert.Throws<ArgumentException>(() => evaluator.Evaluate(new([Fact with { Arguments = new ArgumentMetadata.Known(
            Enumerable.Range(0, 257).Select(i => new NamedArgument("A" + i, new ArgumentValue.Dynamic())).ToImmutableArray()) }], [])));
    }

    [Fact]
    public void PublicAstsRejectInvalidUnicodeInEveryStringField()
    {
        foreach (var text in new[] { "\ud800", "\udc00", "private-canary\ud800x" })
        {
            PolicyRule[] rules = [Rule(Target(), text), Rule(Target()) with { Description = text },
                Rule(new MatchExpression.Invocation(new TargetMatcher.Exact(text, "LaunchURL"))),
                Rule(new MatchExpression.Invocation(new TargetMatcher.Exact(Owner, text))),
                Rule(new MatchExpression.Invocation(new TargetMatcher.ByOwner(text))),
                Rule(new MatchExpression.Argument(text, new ValuePredicate.StringStartsWith("prefix"))),
                Rule(Argument(new ValuePredicate.StringStartsWith(text))),
                Rule(Argument(new ValuePredicate.UrlHostIn([text]))),
                Rule(Argument(new ValuePredicate.EqualTo(new PolicyLiteral.String(text)))),
                Rule(Argument(new ValuePredicate.In([new PolicyLiteral.String(text)])))];
            foreach (var rule in rules)
            {
                var error = Assert.Throws<ArgumentException>(() => new PolicyEvaluator(Document(rule)));
                Assert.Equal("Invalid policy document.", error.Message);
                Assert.Null(error.InnerException);
                Assert.DoesNotContain("private-canary", error.ToString());
            }
        }
    }

    [Fact]
    public void PublicAstsPreserveValidUnicodeMatching()
    {
        foreach (var text in new[] { "\ufffd", "\ud800\udc00", "é" })
        {
            var fact = WithLiteral(new PolicyLiteral.String(text + "-data"));
            var rule = Rule(Argument(new ValuePredicate.StringStartsWith(text))) with { Description = text };
            var result = new PolicyEvaluator(Document(rule)).Evaluate(new([fact], []));
            Assert.Equal(MatchResult.Match, Result(result));
            Assert.Equal(MatchResult.NoMatch, Result(Run(Argument(new ValuePredicate.StringStartsWith(text)),
                WithLiteral(new PolicyLiteral.String("other-data")))));
        }
    }

    [Fact]
    public void InvalidPublicAstsAreRejectedBeforeEvaluation()
    {
        MatchExpression deep = Target();
        for (var i = 0; i < 1000; i++) deep = new MatchExpression.Not(deep);
        PolicyDocument[] invalid = [null!, new(1, default), new(1, []), Document(null!),
            Document(Rule(null!)), Document(Rule(deep)), Document(Rule(Target())) with { SchemaVersion = 2 },
            Document(Rule(Target()) with { Id = null! }), Document(Rule(Target()) with { Description = null! }),
            Document(Rule(Target()) with { Description = "" }), Document(Rule(Target()) with { Description = "private\ncanary" }),
            Document(Rule(new MatchExpression.Invocation(null!))), Document(Rule(new MatchExpression.Argument("URL", null!))),
            Document(Rule(Argument(new ValuePredicate.StringStartsWith(null!)))),
            Document(Rule(Argument(new ValuePredicate.EqualTo(null!)))),
            Document(Rule(Argument(new ValuePredicate.In([new PolicyLiteral.Integer(1), new PolicyLiteral.String("1")])))),
            Document(Rule(new MatchExpression.All([]))), Document(Rule(Argument(new ValuePredicate.In(default)))),
            Document(Rule(Argument(new ValuePredicate.UrlHostIn(["UPPER.example.org"])))),
            Document(Rule(Target(), effect: (RuleEffect)99)), Document(Rule(Target()), Rule(Target()))];
        foreach (var document in invalid)
            Assert.Equal("Invalid policy document.", Assert.Throws<ArgumentException>(() => new PolicyEvaluator(document)).Message);
    }

    [Fact]
    public void PublicAstBudgetsRemainEnforced()
    {
        MatchExpression deep = Target();
        for (var i = 0; i < PolicyYaml.MaxYamlDepth; i++) deep = new MatchExpression.Not(deep);
        PolicyDocument[] invalid = [Document(Rule(deep)),
            Document(Rule(new MatchExpression.All(Enumerable.Repeat(Target(), PolicyYaml.MaxYamlNodes + 1).ToImmutableArray()))),
            Document(Rule(new MatchExpression.All(Enumerable.Repeat(Target(), 800).ToImmutableArray()))),
            Document(Rule(Target()) with { Description = new string('x', PolicyEvaluator.MaxFactStringLength + 1) }),
            Document(Enumerable.Range(0, 64).Select(i => Rule(Target(), "rule-" + i) with
                { Description = new string('x', PolicyEvaluator.MaxFactStringLength) }).ToArray())];
        foreach (var document in invalid)
            Assert.Equal("Invalid policy document.", Assert.Throws<ArgumentException>(() => new PolicyEvaluator(document)).Message);
    }
}
