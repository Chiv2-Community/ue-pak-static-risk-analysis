using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PakRisk.Policy;

namespace PakRisk.Scanner;

// A closed, private extension; invocation-policy v1 is deliberately unchanged.
public sealed record CapabilityCaller(string Owner, string Function, int MaxDepth);
public sealed record CapabilityRule(string Id, string Capability, string Effect, CapabilityCaller? Caller);
public sealed record CapabilityPolicyDocument(int SchemaVersion, string Disclosure, string Revision,
    ImmutableArray<CapabilityRule> Rules);
public sealed record CapabilityRuleFinding(int Witness, bool Flagged, bool Forbidden, bool PossiblyFlagged, bool PossiblyForbidden);
public sealed record CapabilityRuleAnalysis(int SchemaVersion, bool Complete, string Decision,
    CapabilityRuleFinding[] Findings, bool PossiblyFlagged, bool PossiblyForbidden, string[] Diagnostics);

public sealed class CapabilityPolicy
{
    public const int MaxBytes = 256 * 1024;
    public CapabilityPolicyDocument Document { get; }
    public string Sha256 { get; }
    private CapabilityPolicy(CapabilityPolicyDocument document, string sha256) { Document = document; Sha256 = sha256; }

    public static CapabilityPolicy Load(string path)
    {
        try { return Read(FactsFile.Read(path, MaxBytes)); }
        catch (Exception error) when (error is not OutOfMemoryException) { throw new CapabilityConfigurationException(); }
    }

    public static CapabilityPolicy Read(ReadOnlySpan<byte> bytes)
    {
        try
        {
            _ = new UTF8Encoding(false, true).GetString(bytes);
            var document = FactsCodec.ReadClosed<CapabilityPolicyDocument>(bytes, MaxBytes, 8192);
            Validate(document);
            return new(document, Convert.ToHexStringLower(SHA256.HashData(bytes)));
        }
        catch (Exception error) when (error is not OutOfMemoryException) { throw new CapabilityConfigurationException(); }
    }

    private static bool Id(string? text) => text is { Length: > 0 and <= 128 }
        && text.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');

    public static byte[] Write(CapabilityPolicyDocument document)
    {
        Validate(document);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(document with
            { Rules = document.Rules.OrderBy(r => r.Id, StringComparer.Ordinal).ToImmutableArray() }, RiskReport.JsonOptions);
        if (bytes.Length > MaxBytes) throw new CapabilityConfigurationException();
        return bytes;
    }

    public static void Validate(CapabilityPolicyDocument document)
    {
        if (document is null || document.SchemaVersion != 1 || document.Disclosure != "private"
            || !Id(document.Revision) || document.Rules.IsDefaultOrEmpty || document.Rules.Length > 256)
            throw new CapabilityConfigurationException();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var rule in document.Rules)
            if (rule is null || !Id(rule.Id) || !ids.Add(rule.Id) || !Id(rule.Capability)
                || rule.Effect is not ("flag" or "forbid")
                || rule.Caller is { } caller && (!PolicyYaml.IsOwner(caller.Owner)
                    || !PolicyYaml.IsIdentifier(caller.Function) || caller.MaxDepth is < 1 or > 16))
                throw new CapabilityConfigurationException();
    }

    public CapabilityRuleAnalysis Evaluate(InvocationAnalysis analysis, CallChainEvidence? evidence)
    {
        Validate(Document);
        var gaps = new SortedSet<string>(StringComparer.Ordinal);
        var findings = new List<CapabilityRuleFinding>();
        var possibleFlag = false;
        var possibleForbid = false;
        // Missing or bounded-away evidence cannot establish a negative capability claim.
        var incomplete = evidence is null || !evidence.Complete || evidence.CatalogSha256 is null;
        if (incomplete) gaps.Add("capability-evidence-incomplete");
        var functions = (analysis.CallGraph?.Functions ?? []).ToDictionary(f => (f.Asset, f.LocationFunction));
        var witnesses = evidence?.Witnesses ?? [];
        for (var i = 0; i < witnesses.Length; i++)
        {
            var witness = witnesses[i];
            if (witness.Endpoint.Capability is null) continue;
            bool flag = false, forbid = false, uncertainFlag = false, uncertainForbid = false;
            foreach (var rule in Document.Rules)
            {
                var result = Match(rule, witness, functions);
                if (result == MatchResult.NoMatch) continue;
                if (result == MatchResult.Unknown)
                {
                    gaps.Add("capability-match-uncertain");
                    if (rule.Effect == "flag") uncertainFlag = true; else uncertainForbid = true;
                }
                else if (rule.Effect == "flag") flag = true; else forbid = true;
            }
            if (flag || forbid || uncertainFlag || uncertainForbid)
                findings.Add(new(i, flag, forbid, uncertainFlag, uncertainForbid));
        }
        if (incomplete)
        {
            possibleFlag = Document.Rules.Any(r => r.Effect == "flag");
            possibleForbid = Document.Rules.Any(r => r.Effect == "forbid");
        }
        var decision = findings.Any(f => f.Forbidden) ? "reject"
            : findings.Count > 0 || possibleFlag || possibleForbid ? "needs-review" : "no-match";
        return new(1, gaps.Count == 0, decision, findings.ToArray(), possibleFlag, possibleForbid, gaps.ToArray());
    }

    private static MatchResult Match(CapabilityRule rule, CallChainWitness witness,
        Dictionary<(string, string), CallGraphFunction> functions)
    {
        if (rule.Capability != witness.Endpoint.Capability) return MatchResult.NoMatch;
        if (rule.Caller is { } caller)
        {
            var matched = witness.Callers.Select((step, index) => (step, index))
                .Any(item => witness.Callers.Length - item.index <= caller.MaxDepth
                    && functions.TryGetValue((item.step.Origin.Asset, item.step.Origin.Function), out var source)
                    && source.Owner == caller.Owner && source.Function == caller.Function);
            if (!matched) return MatchResult.NoMatch;
        }
        return witness.Resolution == "direct" ? MatchResult.Match : MatchResult.Unknown;
    }
}
