using System.Collections.Immutable;
using PakRisk.Policy;
using Xunit;

namespace Policy.Tests;

public sealed class PolicyTests
{
    private const string Example = """
        schema-version: 1
        rules:
          - id: forbid-console
            description: Review console commands.
            effect: forbid
            match:
              kind: invocation
              target:
                kind: exact
                owner: /Script/Engine.KismetSystemLibrary
                function: ExecuteConsoleCommand
        """;

    private static string Argument(string predicate) => """
        schema-version: 1
        rules:
          - id: argument-rule
            description: Test argument matching.
            effect: flag
            match:
              kind: argument
              name: URL
              predicate:
        """ + "\n" + string.Join('\n', predicate.Split('\n').Select(line => "        " + line));

    [Fact]
    public void ParsesIntoTypedVariants()
    {
        var policy = PolicyYaml.Parse(Example);
        Assert.Equal(1, policy.SchemaVersion);
        var rule = Assert.Single(policy.Rules);
        Assert.Equal(RuleEffect.Forbid, rule.Effect);
        var invocation = Assert.IsType<MatchExpression.Invocation>(rule.Match);
        var target = Assert.IsType<TargetMatcher.Exact>(invocation.Target);
        Assert.Equal("/Script/Engine.KismetSystemLibrary", target.Owner);
        Assert.Equal("ExecuteConsoleCommand", target.Function);
    }

    [Fact]
    public void EveryVariantRoundTripsThroughCanonicalYaml()
    {
        MatchExpression[] leaves =
        [
            new MatchExpression.Invocation(new TargetMatcher.Exact("/Script/Engine.KismetSystemLibrary", "LaunchURL")),
            new MatchExpression.Invocation(new TargetMatcher.ByOwner("/Script/Engine.KismetSystemLibrary")),
            new MatchExpression.Argument("URL", new ValuePredicate.EqualTo(new PolicyLiteral.String("https://example.org/"))),
            new MatchExpression.Argument("Count", new ValuePredicate.EqualTo(new PolicyLiteral.Integer(long.MinValue))),
            new MatchExpression.Argument("Enabled", new ValuePredicate.EqualTo(new PolicyLiteral.Boolean(true))),
            new MatchExpression.Argument("Context", new ValuePredicate.EqualTo(new PolicyLiteral.Null())),
            new MatchExpression.Argument("Command", new ValuePredicate.In([new PolicyLiteral.String("a"), new PolicyLiteral.String("b")])),
            new MatchExpression.Argument("Command", new ValuePredicate.StringStartsWith("stat ")),
            new MatchExpression.Argument("URL", new ValuePredicate.UrlHostIn(["mods.example.org"]))
        ];
        var expression = new MatchExpression.All([
            new MatchExpression.Any(leaves.ToImmutableArray()),
            new MatchExpression.Not(leaves[0])
        ]);
        var policy = new PolicyDocument(1, [new PolicyRule("round-trip", "Every variant.", RuleEffect.Flag, expression)]);
        var serialized = PolicyYaml.Write(policy);
        Assert.Equal(serialized, PolicyYaml.Write(PolicyYaml.Parse(serialized)));
        Assert.IsType<MatchExpression.All>(Assert.Single(PolicyYaml.Parse(serialized).Rules).Match);
    }

    [Theory]
    [InlineData("schema-version: 2", "unsupported-schema-version")]
    [InlineData("schema-version: '1'", "invalid-integer")]
    [InlineData("schema-version: 01", "invalid-integer")]
    public void RejectsInvalidVersions(string replacement, string code)
    {
        Assert.Equal(code, Assert.Throws<PolicyException>(() => PolicyYaml.Parse(Example.Replace("schema-version: 1", replacement))).Code);
    }

    [Theory]
    [InlineData("effect: allow")]
    [InlineData("effect: Flag")]
    [InlineData("kind: arbitrary")]
    [InlineData("kind: invocation\n      unexpected: private-canary")]
    public void RejectsUnknownOrContradictoryVariants(string replacement)
    {
        var input = replacement.StartsWith("effect:", StringComparison.Ordinal)
            ? Example.Replace("effect: forbid", replacement)
            : Example.Replace("kind: invocation", replacement);
        Assert.Throws<PolicyException>(() => PolicyYaml.Parse(input));
    }

    [Theory]
    [InlineData("schema-version: 1\nschema-version: 1\nrules: []", "duplicate-key")]
    [InlineData("schema-version: 1\nrules: []", "empty-array")]
    [InlineData("schema-version: 1\nrulse: []", "unknown-field")]
    [InlineData("rules: []", "missing-field")]
    [InlineData("schema-version: 1\nrules: &rules []", "anchors-and-tags-not-supported")]
    [InlineData("schema-version: 1\nrules: *rules", "aliases-not-supported")]
    [InlineData("!!map {schema-version: 1, rules: []}", "anchors-and-tags-not-supported")]
    [InlineData("schema-version: 1\n<<: {}\nrules: []", "merge-keys-not-supported")]
    [InlineData("%YAML 1.1\n---\nschema-version: 1\nrules: []", "directives-not-supported")]
    [InlineData("%TAG !custom! tag:private.example,2026:\n---\nschema-version: 1\nrules: []", "directives-not-supported")]
    [InlineData("[value, value]", "expected-object")]
    public void RejectsUnsafeYamlAndInvalidShapes(string input, string code)
    {
        Assert.Equal(code, Assert.Throws<PolicyException>(() => PolicyYaml.Parse(input)).Code);
    }

    [Fact]
    public void RejectsMultipleDocuments()
    {
        Assert.Equal("multiple-documents", Assert.Throws<PolicyException>(() => PolicyYaml.Parse(Example + "\n---\n" + Example)).Code);
    }

    [Fact]
    public void RejectsDuplicateRuleIds()
    {
        var rule = Example[Example.IndexOf("  - id:", StringComparison.Ordinal)..];
        Assert.Equal("duplicate-rule-id", Assert.Throws<PolicyException>(() => PolicyYaml.Parse(Example + "\n" + rule)).Code);
    }

    [Theory]
    [InlineData("kind: integer\nvalue: '1'", "invalid-integer")]
    [InlineData("kind: integer\nvalue: 1.0", "invalid-integer")]
    [InlineData("kind: integer\nvalue: 9223372036854775808", "invalid-integer")]
    [InlineData("kind: integer\nvalue: +1", "invalid-integer")]
    [InlineData("kind: integer\nvalue: 0x10", "invalid-integer")]
    [InlineData("kind: boolean\nvalue: yes", "invalid-boolean")]
    [InlineData("kind: boolean\nvalue: 'true'", "invalid-boolean")]
    [InlineData("kind: string\nvalue: true", "string-literal-requires-quotes")]
    [InlineData("kind: 'null'\nvalue: null", "unknown-field")]
    [InlineData("kind: integer\nvalue: -0", "invalid-integer")]
    public void RejectsAmbiguousOrInvalidLiterals(string literal, string code)
    {
        var predicate = "kind: equals\nvalue:\n" + string.Join('\n', literal.Split('\n').Select(line => "  " + line));
        Assert.Equal(code, Assert.Throws<PolicyException>(() => PolicyYaml.Parse(Argument(predicate))).Code);
    }

    [Theory]
    [InlineData("kind: all\nexpressions: []")]
    [InlineData("kind: any\nexpressions: []")]
    public void RejectsEmptyBooleanCollections(string expression)
    {
        var start = Example[..Example.IndexOf("      kind: invocation", StringComparison.Ordinal)];
        var yaml = start + string.Join('\n', expression.Split('\n').Select(line => "      " + line));
        Assert.Throws<PolicyException>(() => PolicyYaml.Parse(yaml));
    }

    [Theory]
    [InlineData("https://mods.example.org")]
    [InlineData("mods.example.org:443")]
    [InlineData("*.example.org")]
    [InlineData("Mods.example.org")]
    [InlineData("mods.example.org.")]
    [InlineData("127.0.0.1")]
    [InlineData("local")]
    [InlineData("evil@mods.example.org")]
    public void RejectsNoncanonicalHosts(string host)
    {
        Assert.Equal("invalid-host", Assert.Throws<PolicyException>(() =>
            PolicyYaml.Parse(Argument($"kind: url-host-in\nhosts: ['{host}']"))).Code);
    }

    [Theory]
    [InlineData("kind: in\nvalues: [{kind: string, value: '1'}, {kind: integer, value: 1}]", "mixed-literal-types")]
    [InlineData("kind: in\nvalues: [{kind: integer, value: 1}, {kind: integer, value: 1}]", "duplicate-literal")]
    [InlineData("kind: url-host-in\nhosts: [mods.example.org, mods.example.org]", "duplicate-host")]
    [InlineData("kind: in\nvalues: []", "empty-array")]
    public void RejectsMixedOrDuplicateCollections(string predicate, string code)
    {
        Assert.Equal(code, Assert.Throws<PolicyException>(() => PolicyYaml.Parse(Argument(predicate))).Code);
    }

    [Fact]
    public void DiagnosticsContainLocationsButNoInputOrInnerExceptions()
    {
        foreach (var input in new[]
        {
            Example.Replace("effect: forbid", "effect: private-canary"),
            Example.Replace("schema-version: 1", "private-canary: 1"),
            "schema-version: 1\nrules: [private-canary",
            "!private-canary {}"
        })
        {
            var exception = Assert.Throws<PolicyException>(() => PolicyYaml.Parse(input));
            Assert.DoesNotContain("private-canary", exception.ToString());
            Assert.Null(exception.InnerException);
            Assert.True(exception.Line >= 1);
            Assert.True(exception.Column >= 1);
        }
    }

    [Theory]
    [InlineData("description: true")]
    [InlineData("description: null")]
    [InlineData("description: 123")]
    [InlineData("description: 1.0")]
    [InlineData("description: 0x10")]
    public void StructuralStringsDoNotCoerceYamlScalarTypes(string replacement)
    {
        var yaml = Example.Replace("description: Review console commands.", replacement);
        Assert.Equal("ambiguous-string-requires-quotes", Assert.Throws<PolicyException>(() => PolicyYaml.Parse(yaml)).Code);
    }

    [Fact]
    public void InvalidUnicodeIsNotSilentlyReplaced()
    {
        Assert.Equal("invalid-unicode", Assert.Throws<PolicyException>(() => PolicyYaml.Parse(Example + "\n#\ud800")).Code);
        Assert.Throws<PolicyException>(() => PolicyYaml.Parse(Argument("kind: equals\nvalue: {kind: string, value: \"\\uD800\"}")));
    }

    [Theory]
    [InlineData("kind: owner\nowner: relative.Class")]
    [InlineData("kind: owner\nowner: /Script/Engine.KismetSystemLibrary\nfunction: Extra")]
    [InlineData("kind: future\nowner: /Script/Engine.KismetSystemLibrary")]
    public void InvalidTargetVariantsAreRejected(string target)
    {
        var start = Example[..Example.IndexOf("        kind: exact", StringComparison.Ordinal)];
        Assert.Throws<PolicyException>(() => PolicyYaml.Parse(start + string.Join('\n', target.Split('\n').Select(line => "        " + line))));
    }

    [Theory]
    [InlineData("kind: arbitrary")]
    [InlineData("kind: equals\nvalue: {kind: future, value: 1}")]
    [InlineData("kind: string-starts-with\nprefix: ''")]
    [InlineData("kind: equals\nvalue: {kind: integer, value: 1, prefix: private-canary}")]
    public void InvalidPredicateAndLiteralVariantsAreRejected(string predicate)
    {
        Assert.Throws<PolicyException>(() => PolicyYaml.Parse(Argument(predicate)));
    }

    [Fact]
    public void InputDepthAndNodeBudgetsAreEnforced()
    {
        Assert.Equal("input-size-limit", Assert.Throws<PolicyException>(() => PolicyYaml.Parse(new string('x', PolicyYaml.MaxInputBytes + 1))).Code);
        Assert.Equal("input-size-limit", Assert.Throws<PolicyException>(() => PolicyYaml.Parse(new string('é', PolicyYaml.MaxInputBytes))).Code);
        Assert.Equal("nesting-limit", Assert.Throws<PolicyException>(() => PolicyYaml.Parse(new string('[', 40) + "x" + new string(']', 40))).Code);
        var manyNodes = "[" + string.Join(',', Enumerable.Repeat("x", PolicyYaml.MaxYamlNodes + 1)) + "]";
        Assert.Equal("node-limit", Assert.Throws<PolicyException>(() => PolicyYaml.Parse(manyNodes)).Code);
    }

    [Fact]
    public void PublishedExamplesParseAndRoundTrip()
    {
        var examples = Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "examples"), "*.yaml");
        Assert.NotEmpty(examples);
        foreach (var path in examples)
        {
            var policy = PolicyYaml.Parse(File.ReadAllText(path));
            Assert.Equal(PolicyYaml.Write(policy), PolicyYaml.Write(PolicyYaml.Parse(PolicyYaml.Write(policy))));
        }
    }
}
