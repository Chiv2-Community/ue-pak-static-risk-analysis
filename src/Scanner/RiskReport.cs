using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using PakRisk.Policy;

namespace PakRisk.Scanner;

public sealed record GateOptions(bool FailOnAnyForbidden = true, bool FailOnAnyFlagged = false, bool FailOnIncomplete = true)
{
    public bool Fails(bool forbidden, bool flagged, bool incomplete) =>
        (FailOnAnyForbidden && forbidden) || (FailOnAnyFlagged && flagged) || (FailOnIncomplete && incomplete);
}

public sealed record PublicTarget(string Owner, string Function);
public sealed record ReportFinding(string Id, InvocationLocation Location, PublicTarget? Target,
    string ArgumentMetadata, int? KnownArgumentCount,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string[]? RuleIds);
public sealed record ReportCounts(int Invocations, int Flagged, int Forbidden, int AffectedUnion);
public sealed record ReportCoverage(string[] Gaps, bool EvaluationIncomplete);
public sealed record ReportContext(string ToolVersion, string EngineVersion, string? PakSha256,
    string? ProducerVersion, DependencyIdentity[] Dependencies,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PolicyRevision);
public sealed record RiskReport(int SchemaVersion, string Status, bool AnalysisComplete,
    ReportContext Context, ReportCounts Counts, ReportCoverage Coverage,
    ReportFinding[] FlaggedInvocations, ReportFinding[] ForbiddenInvocations, string[] Diagnostics,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] InspectionEvidence? Inspection = null)
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.KebabCaseLower,
        WriteIndented = true
    };

    public static RiskReport Create(FactsDocument facts, PolicyEvaluation evaluation, bool detail, string? revision)
    {
        var byLocation = facts.Analysis.Invocations.DistinctBy(f => f.Location).ToDictionary(f => f.Location);
        ReportFinding[] Findings(RuleEffect effect) => evaluation.Findings
            .Where(f => f.Rules.Any(r => r.Effect == effect))
            .OrderBy(f => f.Location.Asset, StringComparer.Ordinal)
            .ThenBy(f => f.Location.Function, StringComparer.Ordinal).ThenBy(f => f.Location.Offset)
            .Select(f =>
            {
                var fact = byLocation[f.Location];
                var identity = JsonSerializer.SerializeToUtf8Bytes(new object[]
                    { facts.PakSha256, f.Location.Asset, f.Location.Function, f.Location.Offset });
                return new ReportFinding(Convert.ToHexStringLower(SHA256.HashData(identity)), f.Location,
                    fact.Target is InvocationTarget.Resolved target ? new PublicTarget(target.Owner, target.Function) : null,
                    fact.Arguments is ArgumentMetadata.Known ? "known" : "unavailable",
                    fact.Arguments is ArgumentMetadata.Known known ? known.Arguments.Length : null,
                    detail ? f.Rules.Where(r => r.Effect == effect).Select(r => r.RuleId).Order(StringComparer.Ordinal).ToArray() : null);
            }).ToArray();
        var flagged = Findings(RuleEffect.Flag);
        var forbidden = Findings(RuleEffect.Forbid);
        return new(1, evaluation.IsIncomplete ? "partial" : "successful", !evaluation.IsIncomplete,
            ContextFor(facts, revision), new(byLocation.Count, flagged.Length, forbidden.Length, evaluation.Findings.Length),
            new(evaluation.CoverageGaps.Select(g => JsonNamingPolicy.KebabCaseLower.ConvertName(g.ToString())).ToArray(),
                !evaluation.Uncertainties.IsEmpty), flagged, forbidden, [], facts.Inspection);
    }

    public static RiskReport Failed(string code, FactsDocument? facts = null, string? revision = null) =>
        new(1, "failed", false, ContextFor(facts, revision), new(0, 0, 0, 0), new([], true), [], [], [code]);

    private static ReportContext ContextFor(FactsDocument? facts, string? revision) => new(
        typeof(RiskReport).Assembly.GetName().Version!.ToString(), "4.25", facts?.PakSha256, facts?.ProducerVersion,
        facts?.Dependencies.OrderBy(d => d.Kind, StringComparer.Ordinal).ToArray() ?? [], revision);
}
