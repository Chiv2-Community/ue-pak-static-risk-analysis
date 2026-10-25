using PakRisk.Policy;
using PakRisk.Scanner;
using Xunit;

namespace Scanner.Tests;

public sealed class FactsContextTests
{
    private static readonly FactsDocument Facts = new(1, new('a', 64), "4.25", "test", [], new([], []));

    [Fact]
    public void ExpectedSnapshotAndDependenciesAreRequiredToMatch()
    {
        FactsContext.Verify(Facts, new('a', 64), null);
        Assert.Throws<FactsException>(() => FactsContext.Verify(Facts, new('b', 64), null));
        Assert.Throws<FactsException>(() => FactsContext.Verify(Facts, new('a', 64), new('b', 64)));
        var mapped = Facts with { Dependencies = [new("mapping", new('b', 64))] };
        FactsContext.Verify(mapped, new('a', 64), new('b', 64));
        Assert.Throws<FactsException>(() => FactsContext.Verify(mapped, new('a', 64), null));
        Assert.Throws<FactsException>(() => FactsContext.Verify(mapped, null, new('b', 64)));
    }

    [Fact]
    public void OptionalInspectionIsBoundedAndSurvivesCodecAndReport()
    {
        var member = new MemberEvidence("r00000000", "Content/file", 3, new('c', 64), "payload_verified",
            ["unknown_content"], [], "uninspected", "not_applicable");
        var facts = Facts with { Inspection = new("validated", "class_inspection_deferred", [member]),
            Analysis = new([], [CoverageGap.IncompleteExtraction]) };
        var decoded = FactsCodec.Read(FactsCodec.Write(facts));
        Assert.Equal(member, decoded.Inspection!.Members[0] with { Signatures = member.Signatures, Classes = member.Classes });
        var policy = PolicyYaml.Parse("schema-version: 1\nrules:\n- id: test\n  description: test\n  effect: flag\n  match:\n    kind: invocation\n    target:\n      kind: exact\n      owner: /Script/Test.Actor\n      function: Call\n");
        var report = RiskReport.Create(decoded, new PolicyEvaluator(policy).Evaluate(decoded.Analysis), false, null);
        Assert.False(report.AnalysisComplete);
        Assert.Same(decoded.Inspection, report.Inspection);
        Assert.Throws<FactsException>(() => FactsCodec.Write(facts with {
            Inspection = facts.Inspection with { Members = [member with { Sha256 = "wrong" }] } }));
        Assert.Throws<FactsException>(() => FactsCodec.Write(facts with {
            Inspection = facts.Inspection with { Members = [member, member] } }));
    }
}
