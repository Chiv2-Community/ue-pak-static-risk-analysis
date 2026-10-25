using System.Collections.Immutable;

namespace PakRisk.Policy;

public enum MatchResult { Match, NoMatch, Unknown }
public enum UncertaintyReason { UnresolvedTarget, ArgumentMetadataUnavailable, MissingArgument, DynamicArgument }
public sealed record RuleMatch(string RuleId, RuleEffect Effect);
public sealed record InvocationFinding(InvocationLocation Location, ImmutableArray<RuleMatch> Rules)
{
    public bool IsForbidden => Rules.Any(rule => rule.Effect == RuleEffect.Forbid);
}
public sealed record RuleUncertainty(InvocationLocation Location, string RuleId, ImmutableArray<UncertaintyReason> Reasons);
public sealed record PolicyEvaluation(
    ImmutableArray<InvocationFinding> Findings,
    ImmutableArray<RuleUncertainty> Uncertainties,
    ImmutableArray<CoverageGap> CoverageGaps)
{
    public bool IsIncomplete => !Uncertainties.IsEmpty || !CoverageGaps.IsEmpty;
    public bool HasForbiddenFindings => Findings.Any(finding => finding.IsForbidden);
    public bool ShouldFail(bool failOnIncomplete) => HasForbiddenFindings || (failOnIncomplete && IsIncomplete);
}
