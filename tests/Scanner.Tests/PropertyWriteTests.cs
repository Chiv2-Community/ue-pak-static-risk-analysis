using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using PakRisk.Policy;
using PakRisk.Scanner;
using Xunit;

namespace Scanner.Tests;

public sealed class PropertyWriteTests
{
    private static PropertyWriteFact Write(long offset = 1) => new(new("/Game/Test", "Run", offset), "EX_LetBool",
        "/Script/Example.Player", "Sensitive", "object", new ArgumentValue.Constant(new PolicyLiteral.Boolean(true)));
    private static FactsDocument Facts() => ScannerTests.Facts(new([], [], PropertyWrites: new(true, [Write()])));
    private static PolicyEvaluator Evaluator(RuleEffect effect = RuleEffect.Forbid) => new(new(1, [
        new("private-canary", "Private description", effect, new MatchExpression.PropertyWrite(null, "Sensitive"))]));

    [Fact]
    public void PropertyWritesRoundTripAndReportsDoNotLeakPolicyOrInflateInvocations()
    {
        var bytes = FactsCodec.Write(Facts());
        var facts = FactsCodec.Read(bytes);
        Assert.Equal(bytes, FactsCodec.Write(facts));
        var evaluation = Evaluator().Evaluate(facts.Analysis);
        var report = RiskReport.Create(facts, evaluation, false, null);
        var json = JsonSerializer.Serialize(report, RiskReport.JsonOptions);
        Assert.DoesNotContain("private-canary", json);
        Assert.DoesNotContain("Private description", json);
        Assert.Equal(new ReportCounts(0, 0, 0, 0), report.Counts);
        Assert.Single(report.PropertyWrites!.Forbidden);
        Assert.True(new GateOptions().Fails(report));
        Assert.False(new GateOptions(false).Fails(report));
        Assert.Contains("private-canary", JsonSerializer.Serialize(RiskReport.Create(facts, evaluation, true, null), RiskReport.JsonOptions));
    }

    [Fact]
    public void FlagGateAndMissingCoverageAreEnforcedIndependently()
    {
        var facts = Facts();
        var evaluator = Evaluator(RuleEffect.Flag);
        var report = RiskReport.Create(facts, evaluator.Evaluate(facts.Analysis), false, null);
        Assert.False(new GateOptions().Fails(report));
        Assert.True(new GateOptions(FailOnAnyFlagged: true).Fails(report));
        facts = facts with { Analysis = facts.Analysis with { PropertyWrites = null } };
        report = RiskReport.Create(facts, evaluator.Evaluate(facts.Analysis), false, null);
        Assert.False(report.AnalysisComplete);
        Assert.True(new GateOptions().Fails(report));
    }

    [Theory]
    [InlineData("owner", "42")]
    [InlineData("owner", "\"NotAnOwner\"")]
    [InlineData("property", "\"Bad..Path\"")]
    [InlineData("opcode", "\"EX_VirtualFunction\"")]
    [InlineData("receiver", "\"player\"")]
    [InlineData("extra", "true")]
    [InlineData("value", "{\"kind\":\"constant\",\"value\":{\"kind\":\"wildcard\"}}")]
    public void FactsUseClosedPropertyWriteContract(string key, string value)
    {
        var node = JsonNode.Parse(FactsCodec.Write(Facts()))!;
        node["analysis"]!["property-writes"]!["writes"]![0]![key] = JsonNode.Parse(value);
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Fact]
    public void DuplicateWriteLocationsAreRejected()
    {
        var facts = Facts();
        facts = facts with { Analysis = facts.Analysis with { PropertyWrites = new(true, [Write(), Write()]) } };
        Assert.Throws<FactsException>(() => FactsCodec.Write(facts));
    }

    [Fact]
    public void PropertyFindingOrderAndIdsAreDeterministicAndSeparateFromCalls()
    {
        var facts = Facts();
        facts = facts with { Analysis = facts.Analysis with { PropertyWrites = new(true, [Write(5), Write(1)]) } };
        var reversed = facts with { Analysis = facts.Analysis with { PropertyWrites = new(true, [Write(1), Write(5)]) } };
        var evaluator = Evaluator();
        string Report(FactsDocument input) => JsonSerializer.Serialize(RiskReport.Create(input, evaluator.Evaluate(input.Analysis), false, null), RiskReport.JsonOptions);
        Assert.Equal(Report(facts), Report(reversed));
        var ids = RiskReport.Create(facts, evaluator.Evaluate(facts.Analysis), false, null).PropertyWrites!.Forbidden.Select(f => f.Id);
        Assert.Equal(2, ids.Distinct().Count());
    }
}
