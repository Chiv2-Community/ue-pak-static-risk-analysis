using System.Collections.Immutable;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using PakRisk.Extraction;
using PakRisk.Policy;
using PakRisk.Scanner;
using Xunit;

namespace Scanner.Tests;

public sealed class DataPolicyTests
{
    private const string Canary = "private-data-canary";
    private const string MemberPath = "Content/Data.uasset";
    private const string InvocationPolicy = "schema-version: 1\nrules:\n  - id: original\n    description: Original fixture\n    effect: flag\n    match:\n      kind: invocation\n      target:\n        kind: exact\n        owner: /Script/Fixture.Object\n        function: Touch\n";
    private static PolicyEvaluator Evaluator() => new(PolicyYaml.Parse(InvocationPolicy));
    private static readonly DataBuildContext Context = new("4.25", "original-fixture-v1", "Content", "/Game", null, "submission-over-baseline");
    private static SerializedProperty Property(SerializedValue? value = null) => new(1, "/Game/Data.Data", "/Script/Fixture.Object", false,
        [new("Destination", 0)], value ?? new SerializedValue.Text(Canary));
    private static FactsDocument Facts(SerializedValue? value = null, char hash = 'a') => new(1, new(hash, 64), "4.25", "original-fixture-v1", [], new([], []),
        new("validated", "ok", [new("r00000000", MemberPath, 100, new('e', 64), "payload_verified", ["unreal_package_tag"], [], "parsed", "resolved", PathNormalized: true)]),
        new(1, "Content", "/Game", true, [new("r00000000", new(1, "submission:Content/Data.uasset", true, [Property(value)], []))]));
    private static JsonObject Rules(string predicate = "changed", string action = "review", SerializedValue? expected = null)
    {
        var rule = new DataRule(Canary, MemberPath, "/Game/Data.Data", "/Script/Fixture.Object", false, [new("Destination", 0)],
            predicate, expected, action, Canary, Canary);
        // Use the same typed transport serializer, not a second value-tag implementation.
        var node = JsonSerializer.SerializeToNode(new DataPolicyDocument(1, "private", Context, new(new('b', 64), Context), [rule]), RiskReport.JsonOptions)!.AsObject();
        if (expected is not null)
            node["rules"]![0]!["expected"] = JsonNode.Parse(FactsCodec.Write(Facts(expected)))!["asset-data"]!["packages"]![0]!["evidence"]!["properties"]![0]!["value"]!.DeepClone();
        return node;
    }
    private static DataPolicy Policy(JsonObject? node = null) => DataPolicy.Read(Encoding.UTF8.GetBytes((node ?? Rules()).ToJsonString()));

    [Theory]
    [InlineData("review", "needs-review")]
    [InlineData("reject", "reject")]
    public void ChangedTypedDataProducesSeparateMandatoryFindingsWithoutChangingInvocationCounts(string action, string decision)
    {
        var facts = Facts();
        var analysis = Policy(Rules(action: action)).Evaluate(facts, Context.BuildScope, Facts(new SerializedValue.Text("original"), 'b'));
        Assert.True(analysis.Complete);
        Assert.Equal(decision, analysis.Decision);
        var finding = Assert.Single(analysis.Findings);
        Assert.Equal("reviewed-serialized-property-changed", finding.Reason);
        Assert.Equal(1, finding.ExportIndex);
        var evaluation = Evaluator().Evaluate(facts.Analysis);
        var before = RiskReport.Create(facts, evaluation, true, null);
        var report = before.WithData(analysis);
        Assert.Equal(before.Counts, report.Counts);
        Assert.Empty(report.FlaggedInvocations);
        Assert.Empty(report.ForbiddenInvocations);
        Assert.True(new GateOptions(false, false, false).Fails(report));
        Assert.DoesNotContain(Canary, JsonSerializer.Serialize(report, RiskReport.JsonOptions));
        Assert.DoesNotContain(new string('b', 64), JsonSerializer.Serialize(report, RiskReport.JsonOptions));
        Assert.DoesNotContain("Destination", JsonSerializer.Serialize(report, RiskReport.JsonOptions));
    }

    [Fact]
    public void MissingBaselineIsUnknownEvenWithAllLegacyGatesDisabled()
    {
        var facts = Facts();
        var analysis = Policy().Evaluate(facts, Context.BuildScope);
        Assert.False(analysis.Complete);
        Assert.Equal("no-match", analysis.Decision);
        Assert.Empty(analysis.Findings);
        Assert.Contains("data-baseline-unavailable", analysis.Diagnostics);
        Assert.Contains("data-comparison-unavailable", analysis.Diagnostics);
        var report = RiskReport.Create(facts, Evaluator().Evaluate(facts.Analysis), false, null).WithData(analysis);
        Assert.Equal("partial", report.Status);
        Assert.True(new GateOptions(false, false, false).Fails(report));
    }

    [Fact]
    public void DisabledFeaturePreservesLegacyReportShapeAndCompleteness()
    {
        var facts = Facts();
        var report = RiskReport.Create(facts, Evaluator().Evaluate(facts.Analysis), false, null);
        Assert.True(report.AnalysisComplete);
        Assert.Null(report.DataAnalysis);
        Assert.DoesNotContain("asset-data", JsonSerializer.Serialize(report, RiskReport.JsonOptions));
        Assert.DoesNotContain("data-analysis", JsonSerializer.Serialize(report, RiskReport.JsonOptions));
    }

    [Fact]
    public void NullIsKnownButUnknownIsNeverEqualOrUnchanged()
    {
        var baseline = Facts(new SerializedValue.NullReference(), 'b');
        Assert.True(Policy().Evaluate(Facts(new SerializedValue.NullReference()), Context.BuildScope, baseline).Complete);
        Assert.Empty(Policy().Evaluate(Facts(new SerializedValue.NullReference()), Context.BuildScope, baseline).Findings);
        var unknown = Policy().Evaluate(Facts(new SerializedValue.Unknown("unavailable")), Context.BuildScope, baseline);
        Assert.False(unknown.Complete);
        Assert.Empty(unknown.Findings);
        Assert.Single(Policy().Evaluate(Facts(new SerializedValue.Text("null")), Context.BuildScope, baseline).Findings);
        foreach (var name in new[] { "null", "None" })
        {
            var genuine = new SerializedValue.Name(name);
            Assert.True(Policy().Evaluate(Facts(genuine), Context.BuildScope, Facts(genuine, 'b')).Complete);
            Assert.Empty(Policy().Evaluate(Facts(genuine), Context.BuildScope, Facts(genuine, 'b')).Findings);
            var unavailable = Policy().Evaluate(Facts(new SerializedValue.Unknown("name-value-unavailable")), Context.BuildScope, Facts(genuine, 'b'));
            Assert.False(unavailable.Complete);
            Assert.Empty(unavailable.Findings);
        }
    }

    [Fact]
    public void ComparisonsRetainIntegerWidthAndReferenceIdentityNotPackageIndices()
    {
        Assert.Single(Policy().Evaluate(Facts(new SerializedValue.Integer(1, "int64")), Context.BuildScope, Facts(new SerializedValue.Integer(1, "int32"), 'b')).Findings);
        var first = new SerializedValue.Reference(1, "/Game/Fixture", "Original", "local-class");
        Assert.Empty(Policy().Evaluate(Facts(first), Context.BuildScope, Facts(first with { PackageIndex = 3 }, 'b')).Findings);
        Assert.Single(Policy().Evaluate(Facts(first with { ObjectName = "Replacement" }), Context.BuildScope, Facts(first, 'b')).Findings);
        var binding = new SerializedValue.Delegate(first, "Handler");
        Assert.Single(Policy().Evaluate(Facts(binding with { Function = "Other" }), Context.BuildScope, Facts(binding, 'b')).Findings);
    }

    [Theory]
    [InlineData("equals", true)]
    [InlineData("not-equals", false)]
    public void ExactAssertionsHaveNoNameOrUrlHeuristics(string predicate, bool finding)
    {
        var result = Policy(Rules(predicate, expected: new SerializedValue.Text(Canary))).Evaluate(Facts(), Context.BuildScope, Facts(hash: 'b'));
        Assert.Equal(finding, result.Findings.Length != 0);
        var rules = Rules(predicate, expected: new SerializedValue.Text(Canary));
        rules["rules"]![0]!["object-identity"] = "/Game/Data.Different";
        var missing = Policy(rules).Evaluate(Facts(), Context.BuildScope, Facts(hash: 'b'));
        Assert.Empty(missing.Findings);
        Assert.False(missing.Complete);
    }

    [Theory]
    [InlineData("schema-version", "2")]
    [InlineData("disclosure", "\"nonsecret\"")]
    [InlineData("unknown", "true")]
    public void DataPolicyIsClosedAndSeparatelyVersioned(string key, string value)
    {
        var node = Rules(); node[key] = JsonNode.Parse(value);
        Assert.Throws<DataConfigurationException>(() => Policy(node));
    }

    [Theory]
    [InlineData("predicate", "\"regex\"")]
    [InlineData("action", "\"allow\"")]
    [InlineData("include", "\"private-path\"")]
    [InlineData("purpose", "\"\"")]
    [InlineData("expected", "{\"kind\":\"null-reference\"}")]
    public void NoImplicitInvocationAstRegexIncludesOrUnreviewedRules(string key, string value)
    {
        var node = Rules(); node["rules"]![0]![key] = JsonNode.Parse(value);
        Assert.Throws<DataConfigurationException>(() => Policy(node));
    }

    [Fact]
    public void DuplicateKeysAndRulesAreRejectedWithoutExposingContents()
    {
        var raw = Rules().ToJsonString().Replace("\"schema-version\":1", "\"schema-version\":1,\"schema-version\":1");
        Assert.Throws<DataConfigurationException>(() => DataPolicy.Read(Encoding.UTF8.GetBytes(raw)));
        var rules = Rules(); rules["rules"]!.AsArray().Add(rules["rules"]![0]!.DeepClone());
        Assert.Throws<DataConfigurationException>(() => Policy(rules));
    }

    [Fact]
    public void NamespaceCasefoldMatchesButCollisionsAndDuplicatePropertiesAreUnknown()
    {
        var facts = Facts(); var member = facts.Inspection!.Members[0];
        var folded = facts with { Inspection = facts.Inspection with { Members = [member with { Path = MemberPath.ToUpperInvariant() }] } };
        Assert.Single(Policy().Evaluate(folded, Context.BuildScope, Facts(new SerializedValue.Text("original"), 'b')).Findings);
        var collision = facts with { Inspection = facts.Inspection with { Members = [member, member with { Id = "r00000001", Path = MemberPath.ToUpperInvariant() }] } };
        Assert.False(Policy().Evaluate(collision, Context.BuildScope, Facts(hash: 'b')).Complete);
        var duplicate = facts.AssetData!.Packages[0];
        var ambiguous = facts with { AssetData = facts.AssetData with { Complete = false, Packages = [duplicate with
            { Evidence = duplicate.Evidence with { Complete = false, Properties = [Property(), Property()], Diagnostics = ["duplicate-property-identity"] } }] } };
        Assert.Empty(Policy().Evaluate(ambiguous, Context.BuildScope, Facts(hash: 'b')).Findings);
    }

    [Fact]
    public void ContextMismatchIsConfigurationErrorNotBlindComparison()
    {
        Assert.Throws<DataConfigurationException>(() => Policy().Evaluate(Facts(), "other", Facts(hash: 'b')));
        Assert.Throws<DataConfigurationException>(() => Policy().Evaluate(Facts(), Context.BuildScope, Facts(hash: 'c')));
        Assert.Throws<DataConfigurationException>(() => Policy().Evaluate(Facts() with { AssetData = Facts().AssetData! with { ContentRoot = "Other" } }, Context.BuildScope));
        Assert.Throws<DataConfigurationException>(() => Policy().Evaluate(Facts() with { Dependencies = [new("mapping", new('e', 64))] }, Context.BuildScope));
        var rules = Rules(); rules["baseline"]!["context"]!["build-scope"] = "other";
        Assert.Throws<DataConfigurationException>(() => Policy(rules));
    }

    [Fact]
    public void PartialBaselineRetainsKnownEvidenceButCannotPass()
    {
        var baseline = Facts(new SerializedValue.Text("original"), 'b');
        baseline = baseline with { AssetData = baseline.AssetData! with { Complete = false } };
        var result = Policy().Evaluate(Facts(), Context.BuildScope, baseline);
        Assert.Single(result.Findings);
        Assert.False(result.Complete);
        Assert.Contains("data-baseline-incomplete", result.Diagnostics);
    }

    [Theory]
    [InlineData("kind", "\"dynamic\"")]
    [InlineData("value", "true")]
    [InlineData("private-extra", "1")]
    public void UntrustedTypedValuesAreClosed(string key, string value)
    {
        var json = JsonNode.Parse(FactsCodec.Write(Facts()))!;
        json["asset-data"]!["packages"]![0]!["evidence"]!["properties"]![0]!["value"]![key] = JsonNode.Parse(value);
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(json.ToJsonString())));
    }

    [Fact]
    public void AssetDataRoundtripIsCanonicalAndEnforcesGlobalNodesTextAndPathBounds()
    {
        var bytes = FactsCodec.Write(Facts()); Assert.Equal(bytes, FactsCodec.Write(FactsCodec.Read(bytes)));
        var data = Facts().AssetData!; var package = data.Packages[0];
        void Reject(ImmutableArray<SerializedProperty> properties) => Assert.Throws<FactsException>(() => FactsCodec.Write(Facts() with
            { AssetData = data with { Packages = [package with { Evidence = package.Evidence with { Properties = properties } }] } }));
        Reject(Enumerable.Range(0, 4097).Select(i => Property() with { ExportIndex = i / 4096 + 1, Path = [new("P" + i, 0)] }).ToImmutableArray());
        Reject([Property() with { Path = Enumerable.Repeat(new DataPathPart("P", 0), 33).ToImmutableArray() }]);
        Reject([Property(new SerializedValue.Text(new('s', 4097)))]);
    }

    [Fact]
    public void SharedTransportOverflowRetainsKnownPrefixAndAllMandatoryLaterCallsAndInventory()
    {
        var facts = Facts();
        var package = facts.AssetData!.Packages[0];
        var properties = Enumerable.Range(1, 4096).Select(i => new SerializedProperty(i, "/O.O", "/C.C", false,
            Enumerable.Repeat(new DataPathPart("P", 0), 16).ToImmutableArray(), new SerializedValue.Text("known"))).ToImmutableArray();
        var invocation = new InvocationFact(new("later-package", "/Game/Later.Object:Run", 0),
            new InvocationTarget.Resolved("/Script/Fixture.Object", "Touch"), new ArgumentMetadata.Unavailable());
        facts = facts with { Analysis = new([invocation], []), AssetData = facts.AssetData with
            { Packages = [package with { Evidence = package.Evidence with { Properties = properties } }] } };
        var bounded = FactsCodec.Read(FactsCodec.Write(facts));
        Assert.Equal(invocation, Assert.Single(bounded.Analysis.Invocations));
        Assert.Equal(facts.Inspection!.Members.Length, bounded.Inspection!.Members.Length);
        Assert.Equal(facts.Inspection.Members[0].Path, bounded.Inspection.Members[0].Path);
        Assert.False(bounded.AssetData!.Complete);
        var retained = Assert.Single(bounded.AssetData.Packages).Evidence;
        Assert.NotEmpty(retained.Properties);
        Assert.True(retained.Properties.Length < properties.Length);
        Assert.Equal(properties[0].Value, retained.Properties[0].Value);
        Assert.Contains("data-transport-limit", retained.Diagnostics);
    }

    [Theory]
    [InlineData("error")]
    [InlineData("warn")]
    [InlineData("info")]
    [InlineData("verbose")]
    public async Task PublicCliNeverPrintsDataRulesValuesBaselineHashesOrPathsAtAnyVerbosity(string verbosity)
    {
        var directory = Path.Combine("/tmp/opencode", "data-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllBytes(Path.Combine(directory, "facts"), FactsCodec.Write(Facts()));
            File.WriteAllBytes(Path.Combine(directory, "baseline"), FactsCodec.Write(Facts(new SerializedValue.Text("original"), 'b')));
            File.WriteAllText(Path.Combine(directory, "rules"), Rules(action: "reject").ToJsonString());
            File.WriteAllText(Path.Combine(directory, "policy"), InvocationPolicy);
            var process = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var argument in new[] { typeof(Program).Assembly.Location, "evaluate", "--facts", Path.Combine(directory, "facts"),
                "--baseline-facts", Path.Combine(directory, "baseline"), "--expected-baseline-sha256", new string('b', 64),
                "--baseline-facts-assertion", "caller-supplied-not-authenticated", "--data-rules", Path.Combine(directory, "rules"),
                "--game-build", Context.BuildScope, "--policy-rules", Path.Combine(directory, "policy"), "--log-level", verbosity,
                "--report", "-", "--engine-version", "4.25", "--fail-on-any-forbidden", "false", "--fail-on-incomplete", "false" }) process.ArgumentList.Add(argument);
            process.Environment.Remove("UE_PAK_POLICY_RULES");
            using var child = Process.Start(process)!;
            var stdout = child.StandardOutput.ReadToEndAsync(); var stderr = child.StandardError.ReadToEndAsync();
            Assert.True(child.WaitForExit(30_000));
            var text = await stdout; var log = await stderr;
            Assert.Equal(1, child.ExitCode);
            Assert.DoesNotContain(Canary, text + log); Assert.DoesNotContain(directory, text + log);
            Assert.DoesNotContain(new string('b', 64), text + log);
            Assert.Equal("reject", JsonNode.Parse(text)!["data-analysis"]!["decision"]!.GetValue<string>());
            Assert.Equal(verbosity == "verbose", log.Contains("WARNING", StringComparison.Ordinal));
            var invalid = Rules(); invalid["rules"]![0]!["predicate"] = "regex";
            File.WriteAllText(Path.Combine(directory, "rules"), invalid.ToJsonString());
            using var failed = Process.Start(process)!;
            var failedOut = failed.StandardOutput.ReadToEndAsync(); var failedLog = failed.StandardError.ReadToEndAsync();
            Assert.True(failed.WaitForExit(30_000));
            var failureText = await failedOut; var failureLog = await failedLog;
            Assert.Equal(2, failed.ExitCode);
            Assert.DoesNotContain(Canary, failureText + failureLog);
            Assert.DoesNotContain(directory, failureText + failureLog);
            Assert.DoesNotContain("WARNING", failureLog);
        }
        finally { Directory.Delete(directory, true); }
    }
}
