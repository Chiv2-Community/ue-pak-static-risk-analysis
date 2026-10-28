using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using PakRisk.Policy;
using PakRisk.Scanner;
using Xunit;

namespace Scanner.Tests;

public sealed class CapabilityCliTests : IDisposable
{
    private readonly string directory = Path.Combine("/tmp/opencode", "capability-cli-" + Guid.NewGuid().ToString("N"));
    private const string Policy = """
        schema-version: 1
        rules:
          - id: private-catalog-cli-canary
            description: private-catalog-cli-canary
            effect: forbid
            expression:
              invocation: /Script/Fixture.Other:Other
        """;
    private const string Catalog = """
        {"schema-version":1,"disclosure":"nonsecret","revision":"fixture-v1","summaries":[
          {"owner":"/Script/Fixture.Utility","function":"Touch","capability":"fixture-capability",
           "provenance":"Original symbolic test fixture only","build-scope":"fixture-v1 only",
           "reviewed-limitations":"No game/native implementation proof"}]}
        """;
    public CapabilityCliTests() => Directory.CreateDirectory(directory);
    public void Dispose() => Directory.Delete(directory, recursive: true);

    private (int Exit, string Log, JsonNode Report) Run(string catalog, params string[] extra)
    {
        var facts = Path.Combine(directory, "facts");
        if (!File.Exists(facts)) File.WriteAllBytes(facts, FactsCodec.Write(ScannerTests.Facts(new([
            new(new("fixture", "Root", 0), new InvocationTarget.Resolved("/Script/Fixture.Utility", "Touch"), new ArgumentMetadata.Unavailable())
        ], [], null, new(1, true, [new("fixture", "Root", "/Game/Fixture.BP", "Root", false)])))));
        var destination = Path.Combine(directory, "report-" + Guid.NewGuid().ToString("N"));
        var start = new ProcessStartInfo("dotnet") { RedirectStandardError = true, RedirectStandardOutput = true };
        var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
        start.ArgumentList.Add(Path.Combine(root, "src/Scanner/bin", configuration, "net10.0/Scanner.dll"));
        foreach (var arg in new[] { "evaluate", "--facts", facts, "--report", destination, "--engine-version", "4.25",
            "--capability-summaries", catalog }.Concat(extra)) start.ArgumentList.Add(arg);
        start.Environment["UE_PAK_POLICY_RULES"] = Policy;
        using var process = Process.Start(start)!;
        var stderr = process.StandardError.ReadToEndAsync();
        var stdout = process.StandardOutput.ReadToEndAsync();
        Assert.True(process.WaitForExit(30_000), "CLI timeout");
        return (process.ExitCode, stdout.Result + stderr.Result, JsonNode.Parse(File.ReadAllText(destination))!);
    }

    [Fact]
    public void ExplicitCatalogRequiresReviewWithoutChangingDirectCountsOrPrivateDisclosure()
    {
        var path = Path.Combine(directory, "catalog");
        File.WriteAllText(path, Catalog);
        var result = Run(path, "--fail-on-incomplete", "false", "--fail-on-any-forbidden", "false");
        Assert.Equal(1, result.Exit);
        Assert.Equal(0, result.Report["counts"]!["forbidden"]!.GetValue<int>());
        Assert.True(result.Report["call-chains"]!["needs-review"]!.GetValue<bool>());
        Assert.Equal("fixture-v1", result.Report["context"]!["capability-catalog-revision"]!.GetValue<string>());
        Assert.DoesNotContain("private-catalog-cli-canary", result.Log + result.Report);
        Assert.DoesNotContain("No game/native", result.Log + result.Report);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("directory")]
    [InlineData("symlink")]
    [InlineData("fifo")]
    [InlineData("invalid-utf8")]
    [InlineData("oversize")]
    [InlineData("unknown-key")]
    public void InvalidCatalogFailsBeforeVerbosePolicyDisclosure(string kind)
    {
        var path = Path.Combine(directory, "catalog");
        switch (kind)
        {
            case "directory": Directory.CreateDirectory(path); break;
            case "symlink":
                var target = Path.Combine(directory, "target");
                File.WriteAllText(target, Catalog);
                File.CreateSymbolicLink(path, target); break;
            case "fifo":
                using (var process = Process.Start(new ProcessStartInfo("mkfifo") { ArgumentList = { path } })!)
                    Assert.True(process.WaitForExit(5000));
                break;
            case "invalid-utf8": File.WriteAllBytes(path, [0xff]); break;
            case "oversize": File.WriteAllBytes(path, new byte[CapabilityCatalog.MaxBytes + 1]); break;
            case "unknown-key": File.WriteAllText(path, Catalog.Replace("\"schema-version\":1", "\"schema-version\":1,\"policy\":{}")); break;
        }
        var result = Run(path, "--log-level", "verbose");
        Assert.Equal(2, result.Exit);
        Assert.DoesNotContain("private-catalog-cli-canary", result.Log + result.Report);
        Assert.DoesNotContain("VERBOSE", result.Log);
        Assert.Equal("invalid-configuration", result.Report["diagnostics"]![0]!.GetValue<string>());
    }
}
