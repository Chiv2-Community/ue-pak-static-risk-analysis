using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using PakRisk.Policy;
using PakRisk.Scanner;
using Xunit;

namespace Scanner.Tests;

public sealed class CapabilityPolicyTests
{
    private const string Owner = "/Game/Fixture.BP";
    private static InvocationFact Call(string source, string target, int offset, string owner = Owner) =>
        new(new("fixture", source, offset), new InvocationTarget.Resolved(owner, target), new ArgumentMetadata.Unavailable());
    private static InvocationAnalysis Analysis() => new([
        Call("Root", "Helper", 0), Call("Helper", "Wrapper", 10), Call("Wrapper", "Touch", 20, "/Script/Fixture.Utility")
    ], [], null, new(1, true, [
        new("fixture", "Root", Owner, "Root", false), new("fixture", "Helper", Owner, "Helper", false),
        new("fixture", "Wrapper", Owner, "Wrapper", false)]));
    private static readonly PolicyEvaluator Evaluator = new(PolicyYaml.Parse("""
        schema-version: 1
        rules:
          - id: unrelated
            description: Original unrelated fixture rule
            effect: forbid
            match:
              kind: invocation
              target:
                kind: exact
                owner: /Script/Fixture.Other
                function: Other
        """));
    private static CapabilityCatalog Catalog() => CapabilityCatalog.Read(Encoding.UTF8.GetBytes("""
        {"schema-version":1,"disclosure":"nonsecret","revision":"fixture-v1","summaries":[
          {"owner":"/Script/Fixture.Utility","function":"Touch","capability":"fixture-capability",
           "provenance":"Original fixture assertion","build-scope":"fixture-v1","reviewed-limitations":"Not game behavior"}]}
        """));
    private static CapabilityPolicy Policy(string capability = "fixture-capability", CapabilityCaller? caller = null) =>
        CapabilityPolicy.Read(JsonSerializer.SerializeToUtf8Bytes(new CapabilityPolicyDocument(1, "private", "private-revision-canary", [
            new("private-flag-canary", capability, "flag", caller), new("private-forbid-canary", capability, "forbid", caller)
        ]), RiskReport.JsonOptions));
    private static CapabilityRuleAnalysis Run(InvocationAnalysis analysis, CapabilityPolicy? policy = null,
        CapabilityCatalog? catalog = null, CallChainLimits? limits = null) =>
        (policy ?? Policy()).Evaluate(analysis, CallChains.Analyze(analysis, Evaluator.Evaluate(analysis), catalog ?? Catalog(), limits));

    [Fact]
    public void ExactCatalogRulesUnionWithoutChangingInvocationFindingsOrDisclosingPrivatePolicy()
    {
        var analysis = Analysis();
        var report = RiskReport.Create(ScannerTests.Facts(analysis), Evaluator.Evaluate(analysis), true, null, Catalog());
        var changed = report.WithCapabilities(Run(analysis));
        Assert.Equal(report.Counts, changed.Counts);
        Assert.Empty(changed.ForbiddenInvocations);
        Assert.Empty(changed.FlaggedInvocations);
        Assert.Equal("reject", changed.CapabilityAnalysis!.Decision);
        Assert.All(changed.CapabilityAnalysis.Findings, f => Assert.True(f.Flagged && f.Forbidden));
        Assert.True(new GateOptions(false, false, false).Fails(changed));
        var json = JsonSerializer.Serialize(changed, RiskReport.JsonOptions);
        Assert.DoesNotContain("private-", json);
        Assert.DoesNotContain(Policy().Sha256, json);
    }

    [Theory]
    [InlineData("Root", 2, true)]
    [InlineData("Root", 1, false)]
    [InlineData("Helper", 1, true)]
    [InlineData("Other", 16, false)]
    public void CallerUsesExactSourceIdentityAndEndpointRelativeDepth(string function, int depth, bool matched)
    {
        var result = Run(Analysis(), Policy(caller: new(Owner, function, depth)));
        Assert.True(result.Complete);
        Assert.Equal(matched ? "reject" : "no-match", result.Decision);
    }

    [Fact]
    public void PossibleCallerNeverBecomesDefinitiveForbid()
    {
        var analysis = Analysis() with { Invocations = Analysis().Invocations.RemoveAt(0), Dispatches = [
            new(1, new("fixture", "Root", 0), "EX_VirtualFunction", "virtual", "Helper", "unknown", "possible",
                [new(Owner, "Helper", "local-function")], ["open-world"], "kismet-serialized-v1")] };
        var result = Run(analysis, Policy(caller: new(Owner, "Root", 2)));
        Assert.Equal("needs-review", result.Decision);
        var finding = Assert.Single(result.Findings);
        Assert.True(finding.PossiblyFlagged && finding.PossiblyForbidden);
        Assert.False(finding.Flagged || finding.Forbidden);
        Assert.False(result.Complete);
    }

    [Theory]
    [InlineData("catalog")]
    [InlineData("graph")]
    [InlineData("summary")]
    [InlineData("truncation")]
    public void MissingEvidenceCannotBecomeCleanNegative(string kind)
    {
        var analysis = Analysis();
        var catalog = kind == "catalog" ? null : Catalog();
        if (kind == "graph") analysis = analysis with { CallGraph = null };
        if (kind == "summary") analysis = analysis with { Invocations = analysis.Invocations.Add(Call("Root", "OtherNative", 90, "/Script/Fixture.Other")) };
        var evidence = CallChains.Analyze(analysis, Evaluator.Evaluate(analysis), catalog,
            kind == "truncation" ? new(MaxWitnesses: 1) : null);
        var result = Policy("unrelated-capability").Evaluate(analysis, evidence);
        Assert.False(result.Complete);
        Assert.True(result.PossiblyFlagged && result.PossiblyForbidden);
        Assert.Equal("needs-review", result.Decision);
    }

    [Fact]
    public void NonmatchingRulesCannotClearMandatoryCatalogReviewAndAbsencePreservesBytes()
    {
        var analysis = Analysis();
        var report = RiskReport.Create(ScannerTests.Facts(analysis), Evaluator.Evaluate(analysis), false, null, Catalog());
        Assert.Equal(JsonSerializer.Serialize(report), JsonSerializer.Serialize(report.WithCapabilities(null)));
        var changed = report.WithCapabilities(Run(analysis, Policy("unrelated")));
        Assert.Equal("no-match", changed.CapabilityAnalysis!.Decision);
        Assert.True(new GateOptions(false, false, false).Fails(changed));
    }

    [Theory]
    [InlineData("flag", true, false)]
    [InlineData("forbid", false, true)]
    [InlineData("both", true, true)]
    public void AggregateUnknownEffectsFollowEnabledRulesNotWitnessMatches(string effect, bool flag, bool forbid)
    {
        var policy = CapabilityPolicy.Read(CapabilityPolicy.Write(Policy("unrelated").Document with
            { Rules = Policy("unrelated").Document.Rules.Where(r => effect == "both" || r.Effect == effect).ToImmutableArray() }));
        foreach (var kind in new[] { "catalog", "graph", "incomplete-graph", "extraction", "summary", "truncation" })
        {
            var analysis = Analysis();
            if (kind == "graph") analysis = analysis with { CallGraph = null };
            if (kind == "incomplete-graph") analysis = analysis with { CallGraph = analysis.CallGraph! with { Complete = false } };
            if (kind == "extraction") analysis = analysis with { CoverageGaps = [CoverageGap.IncompleteExtraction] };
            if (kind == "summary") analysis = analysis with { Invocations = analysis.Invocations.Add(Call("Root", "Other", 90, "/Script/Fixture.Other")) };
            var evidence = CallChains.Analyze(analysis, Evaluator.Evaluate(analysis), kind == "catalog" ? null : Catalog(),
                kind == "truncation" ? new(MaxWitnesses: 1) : null);
            var result = policy.Evaluate(analysis, evidence);
            Assert.False(result.Complete);
            Assert.Equal(new[] { "capability-evidence-incomplete" }, result.Diagnostics);
            Assert.Equal(flag, result.PossiblyFlagged);
            Assert.Equal(forbid, result.PossiblyForbidden);
            Assert.Empty(result.Findings);
            Assert.Equal("needs-review", result.Decision);
        }
        var missing = policy.Evaluate(Analysis(), null);
        Assert.Equal(flag, missing.PossiblyFlagged);
        Assert.Equal(forbid, missing.PossiblyForbidden);
        var complete = Run(Analysis(), policy);
        Assert.True(complete.Complete);
        Assert.Equal("no-match", complete.Decision);
        Assert.False(complete.PossiblyFlagged || complete.PossiblyForbidden);
    }

    [Theory]
    [InlineData("schema-version", "2")]
    [InlineData("schema-version", "\"1\"")]
    [InlineData("disclosure", "\"nonsecret\"")]
    [InlineData("revision", "\"private\\ncanary\"")]
    [InlineData("rules", "null")]
    [InlineData("rules", "[]")]
    [InlineData("unknown", "true")]
    public void ClosedDocumentRejectsInvalidFields(string field, string value)
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(Policy().Document, RiskReport.JsonOptions))!;
        node[field] = JsonNode.Parse(value);
        Assert.Throws<CapabilityConfigurationException>(() => CapabilityPolicy.Read(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Theory]
    [InlineData("effect", "\"allow\"")]
    [InlineData("effect", "1")]
    [InlineData("id", "\"private\\ncanary\"")]
    [InlineData("capability", "\"\"")]
    [InlineData("caller", "{\"owner\":\"/Game/Fixture.BP\",\"function\":\"Root\",\"max-depth\":17}")]
    [InlineData("caller", "{\"owner\":\"/Game/Fixture.BP\",\"function\":\"Root\",\"max-depth\":0}")]
    [InlineData("caller", "{\"owner\":\"/Game/Fixture.BP\",\"function\":\"Root\\n\",\"max-depth\":1}")]
    [InlineData("caller", "{\"kind\":\"invocation\"}")]
    [InlineData("predicate", "\"private-canary\"")]
    public void ClosedRuleRejectsInvalidFields(string field, string value)
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(Policy().Document, RiskReport.JsonOptions))!;
        node["rules"]![0]![field] = JsonNode.Parse(value);
        Assert.Throws<CapabilityConfigurationException>(() => CapabilityPolicy.Read(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Fact]
    public void RejectsDuplicateKeysIdsMalformedUtf8AndBounds()
    {
        var policy = Policy();
        var json = JsonSerializer.Serialize(policy.Document, RiskReport.JsonOptions);
        Assert.Throws<CapabilityConfigurationException>(() => CapabilityPolicy.Read(Encoding.UTF8.GetBytes(json.Replace("\"schema-version\": 1", "\"schema-version\":1,\"schema-version\":1"))));
        Assert.Throws<CapabilityConfigurationException>(() => CapabilityPolicy.Read([0xff]));
        Assert.Throws<CapabilityConfigurationException>(() => CapabilityPolicy.Read(new byte[CapabilityPolicy.MaxBytes + 1]));
        foreach (var rules in new[] { ImmutableArray.Create(policy.Document.Rules[0], policy.Document.Rules[0]),
            Enumerable.Range(0, 257).Select(i => policy.Document.Rules[0] with { Id = "r" + i }).ToImmutableArray() })
            Assert.Throws<CapabilityConfigurationException>(() => CapabilityPolicy.Read(JsonSerializer.SerializeToUtf8Bytes(policy.Document with { Rules = rules }, RiskReport.JsonOptions)));
        Assert.Equal(policy.Sha256, CapabilityPolicy.Read(Encoding.UTF8.GetBytes(json)).Sha256);
        Assert.NotEqual(policy.Sha256, CapabilityPolicy.Read(Encoding.UTF8.GetBytes(json + "\n")).Sha256);
        var canonical = CapabilityPolicy.Write(policy.Document);
        Assert.Equal(canonical, CapabilityPolicy.Write(policy.Document with { Rules = policy.Document.Rules.Reverse().ToImmutableArray() }));
        Assert.Equal(canonical, CapabilityPolicy.Write(CapabilityPolicy.Read(canonical).Document));
    }
}
