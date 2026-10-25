using System.Text.Json;
using PakRisk.Policy;
using PakRisk.PolicyInput;

namespace PakRisk.Scanner;

public static class Program
{
    public static int Main(string[] args)
    {
        string? output = null;
        string? revision = null;
        FactsDocument? facts = null;
        RiskReport report;
        var exit = 3;
        try
        {
            var options = Parse(args);
            output = Required(options, "report");
            if (args[0] == "failure-report")
            {
                var reason = Required(options, "reason");
                if (reason is not ("parser-failed" or "parser-output-limit" or "wall-timeout" or "cancelled" or "container-unavailable" or "input-failed" or "invalid-configuration"))
                    throw new ConfigurationException();
                report = RiskReport.Failed(reason);
                if (reason == "invalid-configuration") exit = 2;
                goto Write;
            }
            if (Required(options, "engine-version") != "4.25") throw new ConfigurationException();
            var suppliedRevision = options.GetValueOrDefault("policy-revision");
            if (suppliedRevision is not null && (suppliedRevision.Length is 0 or > 128
                || !suppliedRevision.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')))
                throw new ConfigurationException();
            revision = suppliedRevision;
            var gates = new GateOptions(Boolean(options, "fail-on-any-forbidden", true),
                Boolean(options, "fail-on-any-flagged", false), Boolean(options, "fail-on-incomplete", true));
            var loaded = PolicyLoader.Load(options.GetValueOrDefault("policy-rules"), options.GetValueOrDefault("log-level"),
                Console.Error.WriteLine);
            if (args[0] == "validate") return 0;
            var input = Required(options, "facts");
            var candidate = FactsCodec.Read(FactsFile.Read(input));
            FactsContext.Verify(candidate, options.GetValueOrDefault("expected-pak-sha256"),
                options.GetValueOrDefault("expected-mapping-sha256"));
            facts = candidate;
            var evaluation = new PolicyEvaluator(loaded.Document).Evaluate(facts.Analysis);
            report = RiskReport.Create(facts, evaluation, options.ContainsKey("moderator-detail"), revision);
            exit = gates.Fails(report.Counts.Forbidden > 0, report.Counts.Flagged > 0, !report.AnalysisComplete) ? 1 : 0;
        }
        catch (Exception error) when (error is ConfigurationException or PolicyInputException or PolicyException)
        {
            Console.Error.WriteLine("Invalid configuration.");
            report = RiskReport.Failed("invalid-configuration", facts, revision);
            exit = 2;
        }
        catch (Exception)
        {
            Console.Error.WriteLine("Analysis failed.");
            report = RiskReport.Failed("analysis-failed", facts, revision);
        }
        Write:
        if (output is null) return exit;
        try
        {
            // CreateNew never truncates an existing input, policy, symlink, FIFO, or report.
            var bytes = JsonSerializer.SerializeToUtf8Bytes(report, RiskReport.JsonOptions);
            if (output == "-") Console.OpenStandardOutput().Write(bytes);
            else WriteReport(output, bytes);
        }
        catch (Exception)
        {
            Console.Error.WriteLine("Report write failed.");
            return 3;
        }
        return exit;
    }

    private static void WriteReport(string output, byte[] bytes)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var destination = Path.GetFullPath(output);
        var temporary = Path.Combine(Path.GetDirectoryName(destination)!, ".risk-report-" + Guid.NewGuid().ToString("N"));
        var created = false;
        try
        {
            using (var stream = new FileStream(temporary, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            }))
            {
                created = true;
                stream.Write(bytes);
                stream.Flush(true);
            }
            File.Move(temporary, destination, overwrite: false);
        }
        finally
        {
            if (created && File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private sealed class ConfigurationException : Exception;
    private static string Required(Dictionary<string, string> options, string key) =>
        options.TryGetValue(key, out var value) && value.Length > 0 ? value : throw new ConfigurationException();
    private static bool Boolean(Dictionary<string, string> options, string key, bool fallback) =>
        options.GetValueOrDefault(key) switch { null => fallback, "true" => true, "false" => false, _ => throw new ConfigurationException() };

    private static Dictionary<string, string> Parse(string[] args)
    {
        if (args.Length == 0 || args[0] is not ("evaluate" or "validate" or "failure-report")) throw new ConfigurationException();
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        var allowed = new HashSet<string> { "facts", "report", "engine-version", "policy-rules", "log-level", "policy-revision",
            "fail-on-any-forbidden", "fail-on-any-flagged", "fail-on-incomplete", "moderator-detail",
            "expected-pak-sha256", "expected-mapping-sha256", "reason" };
        for (var i = 1; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal)) throw new ConfigurationException();
            var key = args[i][2..];
            if (!allowed.Contains(key) || options.ContainsKey(key)) throw new ConfigurationException();
            if (key == "moderator-detail") options.Add(key, "true");
            else
            {
                if (++i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal)) throw new ConfigurationException();
                options.Add(key, args[i]);
            }
        }
        return options;
    }
}
