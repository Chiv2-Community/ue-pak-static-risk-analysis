using System.Collections.Immutable;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using PakRisk.Policy;
using PakRisk.Scanner;
using Xunit;

namespace Scanner.Tests;

public sealed class ScannerTests : IDisposable
{
    private readonly string directory = Path.Combine("/tmp/opencode", "scanner-test-" + Guid.NewGuid().ToString("N"));
    private const string Canary = "private-canary";
    private const string Policy = """
        schema-version: 1
        rules:
          - id: private-canary-flag
            description: private-canary description
            effect: flag
            match:
              kind: invocation
              target:
                kind: exact
                owner: /Script/Engine.Actor
                function: Destroy
          - id: private-canary-forbid
            description: private-canary description
            effect: forbid
            match:
              kind: invocation
              target:
                kind: exact
                owner: /Script/Engine.Actor
                function: Destroy
        """;

    public ScannerTests() => Directory.CreateDirectory(directory);
    public void Dispose() => Directory.Delete(directory, recursive: true);
    private string FileAt(string name) => Path.Combine(directory, name);

    private static InvocationFact Fact(int index = 0) => new(new("/Game/Asset" + index, "Execute", index),
        new InvocationTarget.Resolved("/Script/Engine.Actor", "Destroy"), new ArgumentMetadata.Known([]));
    public static FactsDocument Facts(InvocationAnalysis? analysis = null) => new(1, new string('a', 64), "4.25", "test-1",
        [new("mappings", new string('b', 64))], analysis ?? new([Fact()], []));

    private (int Exit, string Log, string? Report) Run(string? facts = null, string policy = Policy,
        bool environment = false, params string[] extra)
    {
        var input = FileAt("facts-" + Guid.NewGuid().ToString("N"));
        var policyPath = FileAt("policy-" + Guid.NewGuid().ToString("N"));
        var report = FileAt("report-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(input, facts ?? Encoding.UTF8.GetString(FactsCodec.Write(Facts())));
        File.WriteAllText(policyPath, policy);
        var args = new List<string> { "evaluate", "--facts", input, "--report", report, "--engine-version", "4.25" };
        if (!environment) args.AddRange(["--policy-rules", policyPath]);
        args.AddRange(extra);
        var result = Launch(args, environment ? policy : null);
        return (result.Exit, result.Log, File.Exists(report) ? File.ReadAllText(report) : null);
    }

    private static (int Exit, string Log) Launch(IEnumerable<string> args, string? environment = null)
    {
        var start = new ProcessStartInfo("dotnet") { RedirectStandardError = true, RedirectStandardOutput = true };
        // Use the actual executable build, including its runtimeconfig, not the test output copy.
        var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
        start.ArgumentList.Add(Path.Combine(root, "src/Scanner/bin", configuration, "net10.0/Scanner.dll"));
        foreach (var arg in args) start.ArgumentList.Add(arg);
        start.Environment.Remove("UE_PAK_POLICY_RULES");
        if (environment is not null) start.Environment["UE_PAK_POLICY_RULES"] = environment;
        using var process = Process.Start(start)!;
        var stderr = process.StandardError.ReadToEndAsync();
        var stdout = process.StandardOutput.ReadToEndAsync();
        Assert.True(process.WaitForExit(15_000), "CLI timeout");
        return (process.ExitCode, stdout.Result + stderr.Result);
    }

    [Fact]
    public void CodecRoundTripsAllClosedVariants()
    {
        ArgumentValue[] values = [new ArgumentValue.Dynamic(), new ArgumentValue.Missing(),
            new ArgumentValue.Constant(new PolicyLiteral.String("https://example.org/\n😀")),
            new ArgumentValue.Constant(new PolicyLiteral.Integer(long.MinValue)),
            new ArgumentValue.Constant(new PolicyLiteral.Boolean(true)), new ArgumentValue.Constant(new PolicyLiteral.Null())];
        var invocations = values.Select((v, i) => Fact(i) with
        { Arguments = new ArgumentMetadata.Known([new("Parameter", v)]) }).Append(Fact(10) with
        { Target = new InvocationTarget.Unresolved(), Arguments = new ArgumentMetadata.Unavailable() }).ToImmutableArray();
        var original = Facts(new(invocations, [CoverageGap.UnsupportedParsing, CoverageGap.UnresolvedDispatch, CoverageGap.IncompleteExtraction]));
        var bytes = FactsCodec.Write(original);
        Assert.Equal(bytes, FactsCodec.Write(FactsCodec.Read(bytes)));
        Assert.DoesNotContain("storage", Encoding.UTF8.GetString(bytes));
    }

    [Theory]
    [InlineData("{\"schema-version\":1,\"schema-version\":1}")]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("")]
    public void MissingOrDuplicateFactsFail(string input) => Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(input)));

    public static IEnumerable<object[]> Mutations()
    {
        yield return ["unknown", "true"];
        yield return ["schema-version", "2"];
        yield return ["schema-version", "\"1\""];
        yield return ["pak-sha256", "null"];
        yield return ["pak-sha256", "\"abc\""];
        yield return ["engine-version", "\"5.0\""];
        yield return ["producer-version", "\"\""];
        yield return ["dependencies", "null"];
        yield return ["analysis", "{}"];
        yield return ["analysis", "{\"invocations\":[],\"coverage-gaps\":[0]}"];
        yield return ["analysis", "{\"invocations\":[],\"coverage-gaps\":[\"nonsense\"]}"];
    }

    [Theory]
    [MemberData(nameof(Mutations))]
    public void StrictRootAndEnums(string key, string value)
    {
        var node = JsonNode.Parse(FactsCodec.Write(Facts()))!;
        node[key] = JsonNode.Parse(value);
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Theory]
    [InlineData("{\"kind\":\"resolved\",\"owner\":\"/Script/Engine.Actor\"}")]
    [InlineData("{\"kind\":\"unresolved\",\"extra\":1}")]
    [InlineData("{\"kind\":\"other\"}")]
    [InlineData("{\"kind\":0}")]
    [InlineData("null")]
    public void StrictTaggedVariants(string target)
    {
        var node = JsonNode.Parse(FactsCodec.Write(Facts()))!;
        node["analysis"]!["invocations"]![0]!["target"] = JsonNode.Parse(target);
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Theory]
    [InlineData("\\ud800")]
    [InlineData("\\udc00")]
    [InlineData("\\ud800X")]
    public void MalformedUnicodeRejected(string value)
    {
        var text = Encoding.UTF8.GetString(FactsCodec.Write(Facts())).Replace("test-1", value);
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(text)));
    }

    [Fact]
    public void BoundsAndEvaluatorValidation()
    {
        Assert.Throws<FactsException>(() => FactsCodec.Read(new byte[FactsCodec.MaxBytes + 1]));
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(new string('[', 20) + new string(']', 20))));
        Assert.Throws<FactsException>(() => FactsCodec.Write(Facts(new([Fact() with { Location = new("asset", "fn", -1) }], []))));
        Assert.Throws<FactsException>(() => FactsCodec.Write(Facts(new([Fact() with
        { Arguments = new ArgumentMetadata.Known(Enumerable.Repeat(new NamedArgument("Arg", new ArgumentValue.Dynamic()), 257).ToImmutableArray()) }], []))));
        var text = Encoding.UTF8.GetString(FactsCodec.Write(Facts())).Replace("test-1", new string('x', 4097));
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(text)));
        text = Encoding.UTF8.GetString(FactsCodec.Write(Facts())).Replace("\"coverage-gaps\":[]", "\"coverage-gaps\":[" + string.Join(',', Enumerable.Repeat("\"incomplete-extraction\"", 257)) + "]");
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(text)));
    }

    [Fact]
    public void NestedPreflightBoundsAndReorderedTags()
    {
        var text = Encoding.UTF8.GetString(FactsCodec.Write(Facts()));
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(text.Replace("\"offset\":0", "\"offset\":0,\"offset\":0"))));
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(text.Replace("\"offset\":0", "\"offset\":0.5"))));
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(text[..^1])));
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(text + "{}")));
        var invalidUtf8 = Encoding.UTF8.GetBytes(text);
        invalidUtf8[Array.IndexOf(invalidUtf8, (byte)'t', text.IndexOf("test-1", StringComparison.Ordinal))] = 0xff;
        Assert.Throws<FactsException>(() => FactsCodec.Read(invalidUtf8));
        var reordered = text.Replace("\"kind\":\"resolved\",\"owner\":\"/Script/Engine.Actor\",\"function\":\"Destroy\"",
            "\"function\":\"Destroy\",\"owner\":\"/Script/Engine.Actor\",\"kind\":\"resolved\"");
        Assert.Equal(FactsCodec.Write(Facts()), FactsCodec.Write(FactsCodec.Read(Encoding.UTF8.GetBytes(reordered))));
        var nodeOverflow = "[" + string.Join(',', Enumerable.Repeat("[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]", 10000)) + "]";
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(nodeOverflow)));
        var collectionOverflow = "[" + string.Join(',', Enumerable.Repeat("0", 10001)) + "]";
        Assert.Throws<FactsException>(() => FactsCodec.Read(Encoding.UTF8.GetBytes(collectionOverflow)));
    }

    [Fact]
    public void ProducerWriteAlsoBoundsAggregateBytes()
    {
        var large = new ArgumentMetadata.Known([new("Arg", new ArgumentValue.Constant(new PolicyLiteral.String(new string('x', 4096))))]);
        var facts = Facts(new(Enumerable.Range(0, 2500).Select(i => Fact(i) with { Arguments = large }).ToImmutableArray(), []));
        Assert.Throws<FactsException>(() => FactsCodec.Write(facts));
    }

    [Fact]
    public void RuleSpecificUncertaintyNeverLeaks()
    {
        var facts = Facts(new([Fact() with { Target = new InvocationTarget.Unresolved() }], []));
        var result = Run(Encoding.UTF8.GetString(FactsCodec.Write(facts)), extra: ["--moderator-detail"]);
        Assert.Equal(1, result.Exit);
        Assert.DoesNotContain(Canary, result.Report!);
        Assert.DoesNotContain("unresolved-target", result.Report!);
        Assert.Contains("\"evaluation-incomplete\": true", result.Report!);
    }

    [Fact]
    public void SourceConflictsAndMissingPolicyAreConfigurationErrors()
    {
        var input = FileAt("input");
        var policy = FileAt("policy");
        File.WriteAllBytes(input, FactsCodec.Write(Facts()));
        File.WriteAllText(policy, Policy);
        var args = new[] { "evaluate", "--facts", input, "--report", FileAt("report"), "--engine-version", "4.25" };
        Assert.Equal(2, Launch(args).Exit);
        var conflict = args.Concat(new[] { "--policy-rules", policy }).ToArray();
        // Existing report-write failure still wins over configuration failure.
        Assert.Equal(3, Launch(conflict, Policy).Exit);
        File.Delete(FileAt("report"));
        var result = Launch(conflict, Policy);
        Assert.Equal(2, result.Exit);
        Assert.DoesNotContain(Canary, result.Log + File.ReadAllText(FileAt("report")));
    }

    [Fact]
    public void ExamplesMatchProductionSerializers()
    {
        var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
        var facts = Facts();
        var evaluation = new PolicyEvaluator(PolicyYaml.Parse(Policy)).Evaluate(facts.Analysis);
        var partial = Facts(new([], [CoverageGap.IncompleteExtraction]));
        var partialEvaluation = new PolicyEvaluator(PolicyYaml.Parse(Policy)).Evaluate(partial.Analysis);
        var examples = new Dictionary<string, byte[]>
        {
            ["facts-v1.json"] = FactsCodec.Write(facts),
            ["reports/successful-v1.json"] = JsonSerializer.SerializeToUtf8Bytes(RiskReport.Create(facts, evaluation, false, null), RiskReport.JsonOptions),
            ["reports/partial-v1.json"] = JsonSerializer.SerializeToUtf8Bytes(RiskReport.Create(partial, partialEvaluation, false, null), RiskReport.JsonOptions),
            ["reports/failed-v1.json"] = JsonSerializer.SerializeToUtf8Bytes(RiskReport.Failed("analysis-failed"), RiskReport.JsonOptions)
        };
        foreach (var (path, bytes) in examples)
        {
            var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "examples", path)));
            Assert.True(JsonNode.DeepEquals(expected, JsonNode.Parse(bytes)), path);
        }
    }

    [Fact]
    public void GateHelperAll64Combinations()
    {
        for (var flags = 0; flags < 8; flags++)
        for (var state = 0; state < 8; state++)
        {
            var gates = new GateOptions((flags & 1) != 0, (flags & 2) != 0, (flags & 4) != 0);
            Assert.Equal((flags & state) != 0, gates.Fails((state & 1) != 0, (state & 2) != 0, (state & 4) != 0));
        }
    }

    [Fact]
    public void ProcessGateAll64Combinations()
    {
        for (var flags = 0; flags < 8; flags++)
        for (var state = 0; state < 8; state++)
        {
            var analysis = new InvocationAnalysis([Fact()], (state & 4) != 0 ? [CoverageGap.IncompleteExtraction] : []);
            // Select each rule independently; absent effects use a nonmatching target.
            var node = PolicyYaml.Parse(Policy);
            node = node with { Rules = node.Rules.Select(r => r with
            { Match = new MatchExpression.Invocation(new TargetMatcher.Exact("/Script/Engine.Actor",
                ((r.Effect == RuleEffect.Flag ? state & 2 : state & 1) != 0) ? "Destroy" : "Other")) }).ToImmutableArray() };
            var policy = PolicyYaml.Write(node);
            var result = Run(Encoding.UTF8.GetString(FactsCodec.Write(Facts(analysis))), policy, false,
                "--fail-on-any-forbidden", ((flags & 1) != 0).ToString().ToLowerInvariant(),
                "--fail-on-any-flagged", ((flags & 2) != 0).ToString().ToLowerInvariant(),
                "--fail-on-incomplete", ((flags & 4) != 0).ToString().ToLowerInvariant());
            Assert.Equal((flags & state) != 0 ? 1 : 0, result.Exit);
            Assert.NotNull(result.Report);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ProfilesAndLogLevels(bool environment)
    {
        string? first = null;
        foreach (var level in new[] { "error", "warn", "info", "verbose" })
        {
            var result = Run(environment: environment, extra: ["--log-level", level]);
            Assert.Equal(1, result.Exit);
            Assert.DoesNotContain(Canary, result.Report!);
            if (level == "verbose")
            {
                Assert.Contains(Canary, result.Log);
                Assert.True(result.Log.IndexOf("WARNING", StringComparison.Ordinal) < result.Log.IndexOf(Canary, StringComparison.Ordinal));
            }
            else Assert.DoesNotContain(Canary, result.Log);
            first ??= result.Report;
            Assert.Equal(first, result.Report);
        }
        var detail = Run(environment: environment, extra: ["--moderator-detail"]);
        Assert.Contains(Canary + "-flag", detail.Report!);
        Assert.Contains(Canary + "-forbid", detail.Report!);
        Assert.DoesNotContain("description", detail.Report!);
        using var json = JsonDocument.Parse(detail.Report!);
        var root = json.RootElement;
        Assert.Equal(1, root.GetProperty("counts").GetProperty("affected-union").GetInt32());
        Assert.Equal(root.GetProperty("flagged-invocations")[0].GetProperty("id").GetString(),
            root.GetProperty("forbidden-invocations")[0].GetProperty("id").GetString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MalformedPoliciesAndEscapedVerbose(bool environment)
    {
        foreach (var level in new[] { "error", "warn", "info", "verbose" })
        {
            var result = Run(policy: "private-canary\n::error::injected\u001b[31m\n##[error]\n[", environment: environment,
                extra: ["--log-level", level]);
            Assert.Equal(2, result.Exit);
            Assert.DoesNotContain(Canary, result.Report!);
            Assert.DoesNotContain("::", result.Log);
            Assert.False(result.Log.Contains('\u001b'));
            Assert.DoesNotContain("##[", result.Log);
            Assert.Equal(level == "verbose", result.Log.Contains(Canary));
        }
    }

    [Theory]
    [InlineData("--log-level", "debug")]
    [InlineData("--fail-on-any-forbidden", "True")]
    [InlineData("--fail-on-any-flagged", "1")]
    [InlineData("--fail-on-incomplete", "no")]
    public void InvalidOptionsNeverDisclose(string option, string value)
    {
        var result = Run(environment: true, extra: [option, value]);
        Assert.Equal(2, result.Exit);
        Assert.DoesNotContain(Canary, result.Log + result.Report);
    }

    [Fact]
    public void IncompleteAndInvalidFactsNeverSucceedByAccident()
    {
        var partial = Facts(new([], [CoverageGap.UnsupportedParsing]));
        var result = Run(Encoding.UTF8.GetString(FactsCodec.Write(partial)));
        Assert.Equal(1, result.Exit);
        Assert.Contains("\"status\": \"partial\"", result.Report!);
        result = Run("{}", extra: ["--fail-on-any-forbidden", "false", "--fail-on-any-flagged", "false", "--fail-on-incomplete", "false"]);
        Assert.Equal(3, result.Exit);
        Assert.Contains("\"status\": \"failed\"", result.Report!);
        Assert.DoesNotContain(Canary, result.Log + result.Report);
    }

    [Fact]
    public void DeterministicReorderingAndDuplicateLocations()
    {
        var facts = Facts(new([Fact(2), Fact(1), Fact(2)], []));
        var result = Run(Encoding.UTF8.GetString(FactsCodec.Write(facts)));
        var reordered = facts with { Analysis = new([Fact(1), Fact(2)], []) };
        Assert.Equal(result.Report, Run(Encoding.UTF8.GetString(FactsCodec.Write(reordered))).Report);
        var conflict = facts with { Analysis = new([Fact(), Fact() with { Target = new InvocationTarget.Unresolved() }], []) };
        Assert.Throws<FactsException>(() => FactsCodec.Write(conflict));
    }

    [Fact]
    public void LargeFactsRoundTripAndCli()
    {
        var facts = Facts(new(Enumerable.Range(0, 2000).Select(i => Fact(i)).ToImmutableArray(), []));
        var bytes = FactsCodec.Write(facts);
        Assert.Equal(2000, FactsCodec.Read(bytes).Analysis.Invocations.Length);
        var result = Run(Encoding.UTF8.GetString(bytes));
        Assert.Equal(1, result.Exit);
        Assert.Contains("\"affected-union\": 2000", result.Report!);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("symlink")]
    [InlineData("fifo")]
    [InlineData("device")]
    [InlineData("directory")]
    public void UnsafeFactsFilesFailWithoutBlocking(string kind)
    {
        var input = FileAt("input");
        if (kind == "symlink") File.CreateSymbolicLink(input, "/dev/null");
        if (kind == "device") input = "/dev/null";
        if (kind == "directory") Directory.CreateDirectory(input);
        if (kind == "fifo")
        {
            using var mkfifo = Process.Start(new ProcessStartInfo("mkfifo") { ArgumentList = { input } })!;
            mkfifo.WaitForExit();
            Assert.Equal(0, mkfifo.ExitCode);
        }
        var output = FileAt("report");
        var result = Launch(["evaluate", "--facts", input, "--report", output, "--engine-version", "4.25"], Policy);
        Assert.Equal(3, result.Exit);
        Assert.Contains("analysis-failed", File.ReadAllText(output));
        Assert.DoesNotContain(input, result.Log);
    }

    [Theory]
    [InlineData("existing")]
    [InlineData("input")]
    [InlineData("policy")]
    [InlineData("symlink")]
    [InlineData("fifo")]
    [InlineData("directory")]
    [InlineData("missing-parent")]
    public void ReportNeverOverwritesAndFailureIsOperational(string kind)
    {
        var input = FileAt("input");
        var policy = FileAt("policy");
        var output = FileAt("output");
        File.WriteAllBytes(input, FactsCodec.Write(Facts()));
        File.WriteAllText(policy, Policy);
        if (kind == "input") output = input;
        if (kind == "policy") output = policy;
        if (kind == "existing") File.WriteAllText(output, "preserve");
        if (kind == "symlink") File.CreateSymbolicLink(output, input);
        if (kind == "directory") Directory.CreateDirectory(output);
        if (kind == "missing-parent") output = FileAt("missing/output");
        if (kind == "fifo")
        {
            using var mkfifo = Process.Start(new ProcessStartInfo("mkfifo") { ArgumentList = { output } })!;
            mkfifo.WaitForExit();
        }
        var result = Launch(["evaluate", "--facts", input, "--policy-rules", policy, "--report", output,
            "--engine-version", "4.25", "--fail-on-any-forbidden", "false"]);
        Assert.Equal(3, result.Exit);
        Assert.Equal(FactsCodec.Write(Facts()), File.ReadAllBytes(input));
        Assert.Equal(Policy, File.ReadAllText(policy));
        if (kind == "existing") Assert.Equal("preserve", File.ReadAllText(output));
        Assert.Empty(Directory.GetFiles(directory, ".risk-report-*"));
        Assert.DoesNotContain(directory, result.Log);
    }
}
