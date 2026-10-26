using System.Security.Cryptography;
using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using PakRisk.Policy;

namespace PakRisk.Scanner;

public sealed record GateOptions(bool FailOnAnyForbidden = true, bool FailOnAnyFlagged = false, bool FailOnIncomplete = true)
{
    public bool Fails(bool forbidden, bool flagged, bool incomplete) =>
        (FailOnAnyForbidden && forbidden) || (FailOnAnyFlagged && flagged) || (FailOnIncomplete && incomplete);
    public bool Fails(RiskReport report) => report.ContentPolicy?.Decision is "reject" or "needs-review"
        || report.DataAnalysis is { } data && (!data.Complete || data.Decision is "reject" or "needs-review")
        || report.CallChains?.NeedsReview == true
        || report.CapabilityAnalysis is { } capability && (!capability.Complete || capability.Decision is "reject" or "needs-review")
        || Fails(report.Counts.Forbidden > 0, report.Counts.Flagged > 0, !report.AnalysisComplete);
}

public sealed record PublicTarget(string Owner, string Function);
public sealed record ReportFinding(string Id, InvocationLocation Location, PublicTarget? Target,
    string ArgumentMetadata, int? KnownArgumentCount,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string[]? RuleIds);
public sealed record ReportCounts(int Invocations, int Flagged, int Forbidden, int AffectedUnion);
public sealed record ReportPossibleDispatch(IndirectDispatch Evidence, bool PossiblyFlagged, bool PossiblyForbidden);
public sealed record ReportCoverage(string[] Gaps, bool EvaluationIncomplete);
public sealed record ReportContext(string ToolVersion, string EngineVersion, string? PakSha256,
    string? ProducerVersion, DependencyIdentity[] Dependencies,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PolicyRevision,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? CapabilityCatalogRevision = null);
public sealed record RiskReport(int SchemaVersion, string Status, bool AnalysisComplete,
    ReportContext Context, ReportCounts Counts, ReportCoverage Coverage,
    ReportFinding[] FlaggedInvocations, ReportFinding[] ForbiddenInvocations, string[] Diagnostics,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] InspectionEvidence? Inspection = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ContentResult? ContentPolicy = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ReportPossibleDispatch[]? PossibleDispatches = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] CallChainEvidence? CallChains = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DataAnalysis? DataAnalysis = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] CapabilityRuleAnalysis? CapabilityAnalysis = null)
{
    public RiskReport WithCapabilities(CapabilityRuleAnalysis? result) => result is null ? this : this with
    {
        CapabilityAnalysis = result,
        AnalysisComplete = AnalysisComplete && result.Complete,
        Status = !result.Complete && Status == "successful" ? "partial" : Status
    };
    public RiskReport WithData(DataAnalysis? result) => result is null ? this : this with
    {
        DataAnalysis = result,
        AnalysisComplete = AnalysisComplete && result.Complete,
        Status = !result.Complete && Status == "successful" ? "partial" : Status
    };
    public RiskReport WithCallChains(CallChainEvidence? evidence) => evidence is null ? this : this with
    {
        CallChains = evidence,
        AnalysisComplete = AnalysisComplete && evidence.Complete,
        Status = !evidence.Complete && Status == "successful" ? "partial" : Status
    };
    public RiskReport WithContent(ContentResult? result) => result is null ? this : this with
    {
        ContentPolicy = result,
        AnalysisComplete = AnalysisComplete && !result.Incomplete,
        Status = result.Incomplete && Status == "successful" ? "partial" : Status
    };
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.KebabCaseLower,
        WriteIndented = true
    };

    public static RiskReport Create(FactsDocument facts, PolicyEvaluation evaluation, bool detail, string? revision,
        CapabilityCatalog? catalog = null)
    {
        var byLocation = facts.Analysis.Invocations.DistinctBy(f => f.Location).ToDictionary(f => f.Location);
        var possibleByOrigin = evaluation.PossibleDispatches.IsDefault
            ? new Dictionary<InvocationLocation, PossibleDispatchFinding>() : evaluation.PossibleDispatches.ToDictionary(d => d.Origin);
        bool PossibleEffect(IndirectDispatch dispatch, RuleEffect effect) => possibleByOrigin.TryGetValue(dispatch.Origin, out var finding)
            && finding.Rules.Any(r => r.Effect == effect);
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
        var report = new RiskReport(1, evaluation.IsIncomplete ? "partial" : "successful", !evaluation.IsIncomplete,
            ContextFor(facts, revision, catalog), new(byLocation.Count, flagged.Length, forbidden.Length, evaluation.Findings.Length),
            new(evaluation.CoverageGaps.Select(g => JsonNamingPolicy.KebabCaseLower.ConvertName(g.ToString())).ToArray(),
                 !evaluation.Uncertainties.IsEmpty), flagged, forbidden, [], facts.Inspection, PossibleDispatches:
             facts.Analysis.Dispatches is { Length: > 0 } dispatches ? dispatches
                 .OrderBy(d => d.Origin.Asset, StringComparer.Ordinal).ThenBy(d => d.Origin.Function, StringComparer.Ordinal).ThenBy(d => d.Origin.Offset)
                 .Select(d => new ReportPossibleDispatch(d with
                     { Candidates = d.Candidates.OrderBy(c => c.Owner, StringComparer.Ordinal).ThenBy(c => c.Function, StringComparer.Ordinal).ToImmutableArray(),
                       Diagnostics = d.Diagnostics.Order(StringComparer.Ordinal).ToImmutableArray() },
                     PossibleEffect(d, RuleEffect.Flag), PossibleEffect(d, RuleEffect.Forbid))).ToArray() : null);
        return report.WithCallChains(facts.Analysis.CallGraph is not null || catalog is not null
            ? Scanner.CallChains.Analyze(facts.Analysis, evaluation, catalog) : null);
    }

    public static RiskReport Failed(string code, FactsDocument? facts = null, string? revision = null) =>
        new(1, "failed", false, ContextFor(facts, revision), new(0, 0, 0, 0), new([], true), [], [], [code]);

    private static ReportContext ContextFor(FactsDocument? facts, string? revision, CapabilityCatalog? catalog = null)
    {
        var dependencies = facts?.Dependencies.ToList() ?? [];
        if (catalog is not null)
        {
            if (dependencies.Any(d => d.Kind == "capability-summaries") || dependencies.Count >= 256) throw new FactsException();
            dependencies.Add(new("capability-summaries", catalog.Sha256));
        }
        return new(typeof(RiskReport).Assembly.GetName().Version!.ToString(), "4.25", facts?.PakSha256, facts?.ProducerVersion,
            dependencies.OrderBy(d => d.Kind, StringComparer.Ordinal).ToArray(), revision, catalog?.Document.Revision);
    }
}
