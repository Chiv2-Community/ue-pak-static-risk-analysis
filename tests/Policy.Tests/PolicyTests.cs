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
            expression:
              invocation: /Script/Engine.KismetSystemLibrary:ExecuteConsoleCommand
        """;

    private static string Argument(string predicate) => """
        schema-version: 1
        rules:
          - id: argument-rule
            description: Test argument matching.
            effect: flag
            expression:
              argument:
                name: URL
                predicate:
        """ + "\n" + string.Join('\n', predicate.Split('\n').Select(line => "          " + line));

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
            new MatchExpression.Argument("Command", new ValuePredicate.RegexMatch("^stat ")),
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
    [InlineData("arbitrary: value")]
    [InlineData("invocation: /Script/Test.Actor\n      unexpected: private-canary")]
    public void RejectsUnknownOrContradictoryVariants(string replacement)
    {
        var input = replacement.StartsWith("effect:", StringComparison.Ordinal)
            ? Example.Replace("effect: forbid", replacement)
            : Example.Replace("invocation: /Script/Engine.KismetSystemLibrary:ExecuteConsoleCommand", replacement);
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
    [InlineData("all: []")]
    [InlineData("any: []")]
    public void RejectsEmptyBooleanCollections(string expression)
    {
        var start = Example[..Example.IndexOf("      invocation:", StringComparison.Ordinal)];
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
    [InlineData("kind: in\nvalues: [{kind: integer, value: 1}, {kind: integer, value: 1}]", "duplicate-literal")]
    [InlineData("kind: url-host-in\nhosts: [mods.example.org, mods.example.org]", "duplicate-host")]
    [InlineData("kind: in\nvalues: []", "empty-array")]
    public void RejectsInvalidOrDuplicateCollections(string predicate, string code)
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
    [InlineData("class: relative.Class")]
    [InlineData("class: /Script/Engine.KismetSystemLibrary\nfunction: 'Bad:Name'")]
    [InlineData("kind: future\nclass: /Script/Engine.KismetSystemLibrary")]
    public void InvalidTargetVariantsAreRejected(string target)
    {
        var start = Example[..Example.IndexOf("      invocation:", StringComparison.Ordinal)] + "      invocation:\n";
        Assert.Throws<PolicyException>(() => PolicyYaml.Parse(start + string.Join('\n', target.Split('\n').Select(line => "        " + line))));
    }

    [Theory]
    [InlineData("kind: arbitrary")]
    [InlineData("kind: equals\nvalue: {kind: future, value: 1}")]
    [InlineData("kind: regex-match\npattern: ''")]
    [InlineData("kind: regex-match\npattern: '['")]
    [InlineData("kind: regex-match\npattern: '(?=private-canary)'")]
    [InlineData("kind: regex-match\npattern: '(private-canary)\\1'")]
    [InlineData("kind: string-starts-with\nprefix: private-canary")]
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

    private static string WithExpression(string expression) =>
        Example[..Example.IndexOf("      invocation:", StringComparison.Ordinal)]
        + string.Join('\n', expression.Split('\n').Select(line => "      " + line));

    [Theory]
    [InlineData("/Script/Engine.KismetSystemLibrary", "class: /Script/Engine.KismetSystemLibrary")]
    [InlineData("/Script/Engine.KismetSystemLibrary:LaunchURL", "class: /Script/Engine.KismetSystemLibrary\nfunction: LaunchURL")]
    public void SimpleAndExpandedInvocationsAreEquivalent(string simple, string expanded)
    {
        var shortPolicy = PolicyYaml.Parse(WithExpression("invocation: " + simple));
        var expandedPolicy = PolicyYaml.Parse(WithExpression("invocation:\n" +
            string.Join('\n', expanded.Split('\n').Select(line => "  " + line))));
        Assert.Equal(PolicyYaml.Write(shortPolicy), PolicyYaml.Write(expandedPolicy));
        if (simple.Contains(':'))
        {
            var qualifiedPolicy = PolicyYaml.Parse(WithExpression("invocation:\n  function: " + simple));
            Assert.Equal(PolicyYaml.Write(shortPolicy), PolicyYaml.Write(qualifiedPolicy));
        }
    }

    [Fact]
    public void ExpandedArgumentsAndLogicalExpressionsRoundTrip()
    {
        var input = WithExpression("""
            any:
              - invocation: /Script/Engine.KismetSystemLibrary
              - all:
                  - invocation:
                      class: /Script/Engine.KismetSystemLibrary
                      function: LaunchURL
                      args:
                        - argument:
                            name: URL
                            predicate: {kind: url-host-in, hosts: [mods.example.org]}
                        - argument:
                            name: Enabled
                            predicate: {kind: equals, value: {kind: boolean, value: true}}
                  - not:
                      invocation: /Script/Engine.KismetSystemLibrary:Other
            """);
        var parsed = PolicyYaml.Parse(input);
        var written = PolicyYaml.Write(parsed);
        Assert.Equal(written, PolicyYaml.Write(PolicyYaml.Parse(written)));
        var either = Assert.IsType<MatchExpression.Any>(Assert.Single(parsed.Rules).Match);
        var both = Assert.IsType<MatchExpression.All>(either.Expressions[1]);
        Assert.Equal(2, Assert.IsType<MatchExpression.Invocation>(both.Expressions[0]).Args!.Value.Length);
        Assert.DoesNotContain("\"match\"", written);
        Assert.DoesNotContain("\"target\"", written);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("all: []")]
    [InlineData("any: []")]
    [InlineData("all: {invocation: /Script/Test.Actor}")]
    [InlineData("not: [{invocation: /Script/Test.Actor}]")]
    [InlineData("all: [{invocation: /Script/Test.Actor}]\nany: [{invocation: /Script/Test.Actor}]")]
    [InlineData("invocation: /Script/Test.Actor:")]
    [InlineData("invocation: '/Script/Test.Actor:Call:Extra'")]
    [InlineData("invocation: '/Script/Test.Actor$Call'")]
    [InlineData("invocation: '/Script/Test.Actor:Call*'")]
    [InlineData("invocation: relative.Actor")]
    [InlineData("invocation: null")]
    [InlineData("invocation: {}")]
    [InlineData("invocation: {function: Call}")]
    [InlineData("invocation: {class: /Script/Test.Actor, function: null}")]
    [InlineData("invocation: {class: /Script/Test.Actor, function: ''}")]
    [InlineData("invocation: {class: /Script/Test.Actor, args: []}")]
    [InlineData("invocation: {class: /Script/Test.Actor, function: Call, args: []}")]
    [InlineData("invocation: {class: /Script/Test.Actor, function: Call, args: null}")]
    [InlineData("invocation: {class: /Script/Test.Actor, function: Call, args: [{invocation: /Script/Test.Actor}]}")]
    [InlineData("invocation: {class: /Script/Test.Actor, function: Call, args: [{argument: {name: A}}]}")]
    [InlineData("invocation: {class: /Script/Test.Actor, owner: /Script/Test.Actor}")]
    [InlineData("kind: invocation\ntarget: {kind: owner, owner: /Script/Test.Actor}")]
    [InlineData("invocation: /Script/Test.Actor\ninvocation: /Script/Test.Other")]
    public void MalformedExpressionsAndInvocationsFailClosed(string expression) =>
        Assert.Throws<PolicyException>(() => PolicyYaml.Parse(WithExpression(expression)));

    [Fact]
    public void RemovedRuleMatchFieldIsNotAccepted() =>
        Assert.Throws<PolicyException>(() => PolicyYaml.Parse(Example.Replace("expression:", "match:")));

    [Fact]
    public void QualifiedFunctionWithArgsNormalizesToClassAndFunction()
    {
        var input = WithExpression("""
            invocation:
              function: /Script/Engine.KismetSystemLibrary:LaunchURL
              args:
                - argument:
                    name: URL
                    predicate: {kind: url-host-in, hosts: [mods.example.org]}
            """);
        var expanded = input.Replace("function: /Script/Engine.KismetSystemLibrary:LaunchURL",
            "class: /Script/Engine.KismetSystemLibrary\n        function: LaunchURL");
        var parsed = PolicyYaml.Parse(input);
        Assert.Equal(PolicyYaml.Write(PolicyYaml.Parse(expanded)), PolicyYaml.Write(parsed));
        var call = Assert.IsType<MatchExpression.Invocation>(Assert.Single(parsed.Rules).Match);
        Assert.Single(call.Args!.Value);
        var target = Assert.IsType<TargetMatcher.Exact>(call.Target);
        Assert.Equal("LaunchURL", target.Function);
    }

    [Theory]
    [InlineData("/Script/Engine.KismetSystemLibrary")]
    [InlineData("/Script/Other.Class")]
    [InlineData("null")]
    public void QualifiedFunctionsForbidAnyClassKey(string value)
    {
        var input = WithExpression("invocation:\n  class: " + value +
            "\n  function: /Script/Engine.KismetSystemLibrary:LaunchURL");
        Assert.Equal("class-with-qualified-function", Assert.Throws<PolicyException>(() => PolicyYaml.Parse(input)).Code);
    }

    [Theory]
    [InlineData("/Script/Engine.KismetSystemLibrary")]
    [InlineData("/Script/Engine.KismetSystemLibrary:")]
    [InlineData("/Script/Engine.KismetSystemLibrary:LaunchURL:Other")]
    [InlineData("KismetSystemLibrary:LaunchURL")]
    [InlineData("/Script/Engine.KismetSystemLibrary:Launch*")]
    public void InvalidQualifiedFunctionsFailClosed(string function) =>
        Assert.Throws<PolicyException>(() => PolicyYaml.Parse(WithExpression("invocation: {function: '" + function + "'}")));

    [Fact]
    public void RegexPatternsPreserveBackslashesThroughRoundTrip()
    {
        var policy = PolicyYaml.Parse(Argument("kind: regex-match\npattern: '\\Ahttps://mods\\.example\\.org/.*\\z'"));
        var expression = Assert.IsType<MatchExpression.Argument>(Assert.Single(policy.Rules).Match);
        Assert.Equal(@"\Ahttps://mods\.example\.org/.*\z", Assert.IsType<ValuePredicate.RegexMatch>(expression.Predicate).Pattern);
        var written = PolicyYaml.Write(policy);
        Assert.Equal(written, PolicyYaml.Write(PolicyYaml.Parse(written)));
    }

    [Fact]
    public void NestedSubexpressionPredicatesRoundTrip()
    {
        var policy = PolicyYaml.Parse(WithExpression("""
            invocation:
              function: /Script/Example.Bar:Baz
              args:
                - argument:
                    name: foo
                    predicate:
                      kind: subexpr-match
                      subexpr:
                        invocation:
                          function: /Script/Engine.String:Append
                          args:
                            - argument:
                                name: A
                                predicate:
                                  kind: equals
                                  value: {kind: string, value: "foo"}
            """));
        var written = PolicyYaml.Write(policy);
        Assert.Equal(written, PolicyYaml.Write(PolicyYaml.Parse(written)));
        var invocation = Assert.IsType<MatchExpression.Invocation>(Assert.Single(policy.Rules).Match);
        Assert.IsType<ValuePredicate.SubexprMatch>(Assert.Single(invocation.Args!.Value).Predicate);
    }

    [Theory]
    [InlineData("kind: subexpr-match")]
    [InlineData("kind: subexpr-match\nsubexpr: null")]
    [InlineData("kind: subexpr-match\nsubexpr: {invocation: /Script/Test.Actor}\nextra: private-canary")]
    [InlineData("kind: subexpr-match\nsubexpr: {all: []}")]
    public void InvalidSubexpressionsFailClosed(string predicate) =>
        Assert.Throws<PolicyException>(() => PolicyYaml.Parse(Argument(predicate)));
}
