using System.Collections.Immutable;
using System.Text;
using PakRisk.Extraction;

namespace PakRisk.Scanner;

// Private operator assertions. Build scope and purpose are reviewed metadata, not authentication.
public sealed record DataBuildContext(string EngineVersion, string BuildScope, string ContentRoot,
    string LogicalRoot, string? MappingSha256, string MountPolicy);
public sealed record DataBaseline(string PakSha256, DataBuildContext Context);
public sealed record DataRule(string Id, string MemberPath, string ObjectIdentity, string ClassIdentity,
    bool ClassDefaultFlag, ImmutableArray<DataPathPart> Path, string Predicate, SerializedValue? Expected,
    string Action, string Purpose, string Provenance);
public sealed record DataPolicyDocument(int SchemaVersion, string Disclosure, DataBuildContext Context,
    DataBaseline? Baseline, ImmutableArray<DataRule> Rules);
public sealed record DataFinding(string MemberId, int ExportIndex, int PropertyOrdinal, string Reason, string Action);
public sealed record DataAnalysis(int SchemaVersion, string Decision, bool Complete, DataFinding[] Findings, string[] Diagnostics);
public sealed class DataConfigurationException() : Exception("Invalid configuration.");

public sealed class DataPolicy
{
    public const int MaxBytes = 256 * 1024;
    public DataPolicyDocument Document { get; }
    private DataPolicy(DataPolicyDocument document) { Document = document; }

    public static DataPolicy Load(string path)
    {
        try { return Read(FactsFile.Read(path, MaxBytes)); }
        catch (Exception error) when (error is not OutOfMemoryException) { throw new DataConfigurationException(); }
    }

    public static DataPolicy Read(ReadOnlySpan<byte> bytes)
    {
        try
        {
            _ = new UTF8Encoding(false, true).GetString(bytes);
            var document = FactsCodec.ReadClosed<DataPolicyDocument>(bytes, MaxBytes, 20_000);
            Validate(document);
            return new(document);
        }
        catch (Exception error) when (error is not OutOfMemoryException) { throw new DataConfigurationException(); }
    }

    private static bool Text(string? text) => text is { Length: > 0 and <= 1024 }
        && !string.IsNullOrWhiteSpace(text) && FactsCodec.Unicode(text) && !text.Any(c => char.IsControl(c) || c == '\ufffd');
    private static bool Hash(string? text) => text is { Length: 64 } && text.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static void Context(DataBuildContext context)
    {
        if (context is null || context.EngineVersion != "4.25" || !Text(context.BuildScope)
            || context.BuildScope.Length > 128 || !context.BuildScope.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')
            || !DataEvidenceValidation.Root(context.ContentRoot, context.LogicalRoot) || context.ContentRoot == "-"
            || context.MappingSha256 is not null && !Hash(context.MappingSha256)
            || context.MountPolicy != "submission-over-baseline") throw new DataConfigurationException();
    }

    public static void Validate(DataPolicyDocument document)
    {
        if (document is null || document.SchemaVersion != 1 || document.Disclosure != "private"
            || document.Rules.IsDefaultOrEmpty || document.Rules.Length > 256) throw new DataConfigurationException();
        Context(document.Context);
        if (document.Baseline is { } baseline)
        {
            Context(baseline.Context);
            if (!Hash(baseline.PakSha256) || baseline.Context != document.Context) throw new DataConfigurationException();
        }
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var rule in document.Rules)
        {
            if (rule is null || !Text(rule.Id) || !ids.Add(rule.Id) || !ContentPolicy.VirtualPath(rule.MemberPath)
                || !Text(rule.ObjectIdentity) || !Text(rule.ClassIdentity) || rule.Path.IsDefaultOrEmpty || rule.Path.Length > DataEvidenceValidation.MaxPathParts
                || rule.Predicate is not ("changed" or "equals" or "not-equals") || rule.Action is not ("review" or "reject")
                || !Text(rule.Purpose) || !Text(rule.Provenance)) throw new DataConfigurationException();
            foreach (var part in rule.Path)
                if (part is null || part.ArrayIndex < 0 || part.Element < 0
                    || (part.Property is null) != (part.Element is not null)
                    || part.Element is not null && part.ArrayIndex != 0
                    || part.Property is not null && !Text(part.Property)) throw new DataConfigurationException();
            if ((rule.Predicate == "changed") != (rule.Expected is null)) throw new DataConfigurationException();
            if (rule.Expected is { } expected)
            {
                DataEvidenceValidation.ValidateValue(expected, (text, _) =>
                {
                    // Empty literal strings are valid; identity metadata above is nonempty.
                    if (text is null || text.Length > 4096 || !FactsCodec.Unicode(text)
                        || text.Any(c => char.IsControl(c) || c == '\ufffd')) throw new DataConfigurationException();
                });
                if (!Known(expected)) throw new DataConfigurationException();
            }
        }
    }

    private static bool Known(SerializedValue value) => value is not (SerializedValue.Unknown or SerializedValue.Container)
        && (value is not SerializedValue.Delegate d || Known(d.Object));

    // References compare symbolic identities, not unstable package-table indices.
    internal static bool Equal(SerializedValue left, SerializedValue right) => (left, right) switch
    {
        (SerializedValue.Reference a, SerializedValue.Reference b) => a.Owner == b.Owner && a.ObjectName == b.ObjectName && a.TargetKind == b.TargetKind,
        (SerializedValue.Delegate a, SerializedValue.Delegate b) => a.Function == b.Function && Equal(a.Object, b.Object),
        _ => left == right
    };

    private void Verify(FactsDocument facts)
    {
        var context = Document.Context;
        if (facts.EngineVersion != context.EngineVersion || facts.AssetData is { } data
            && (data.ContentRoot != context.ContentRoot || data.LogicalRoot != context.LogicalRoot)
            || facts.Dependencies.SingleOrDefault(d => d.Kind == "mapping")?.Sha256 != context.MappingSha256)
            throw new DataConfigurationException();
    }

    public DataAnalysis Evaluate(FactsDocument facts, string buildScope, FactsDocument? baseline = null)
    {
        if (buildScope != Document.Context.BuildScope) throw new DataConfigurationException();
        Verify(facts);
        if (baseline is not null)
        {
            if (Document.Baseline is null || baseline.PakSha256 != Document.Baseline.PakSha256) throw new DataConfigurationException();
            Verify(baseline);
        }
        var gaps = new HashSet<string>(StringComparer.Ordinal);
        var findings = new HashSet<DataFinding>();
        if (baseline is null) gaps.Add("data-baseline-unavailable");
        if (facts.AssetData is null || facts.AssetData.Complete != true || facts.Inspection?.Status != "validated") gaps.Add("data-evidence-incomplete");
        if (baseline is not null && (baseline.AssetData?.Complete != true || baseline.Inspection?.Status != "validated")) gaps.Add("data-baseline-incomplete");

        (MemberEvidence? Member, SerializedProperty? Property, int Ordinal) Locate(FactsDocument input, DataRule rule)
        {
            // Same normalized ASCII namespace as protected replacement candidates. Collisions are unknown.
            var members = input.Inspection?.Members.Where(m => m.PathNormalized == true && ContentPolicy.VirtualPath(m.Path)
                && m.Path.Equals(rule.MemberPath, StringComparison.OrdinalIgnoreCase)).Take(2).ToArray() ?? [];
            if (members.Length != 1 || members[0].Status != "payload_verified"
                || members[0].InspectionStatus is not ("parsed" or "partial")
                || !members[0].Signatures.SequenceEqual(["unreal_package_tag"])) return (null, null, 0);
            var packages = input.AssetData?.Packages.Where(p => p.MemberId == members[0].Id).Take(2).ToArray() ?? [];
            if (packages.Length != 1) return (members[0], null, 0);
            var properties = packages[0].Evidence.Properties.Select((p, i) => (Property: p, Ordinal: i))
                .Where(p => p.Property.ObjectIdentity == rule.ObjectIdentity && p.Property.ClassIdentity == rule.ClassIdentity
                    && p.Property.ClassDefaultFlag == rule.ClassDefaultFlag && p.Property.Path.SequenceEqual(rule.Path)).Take(2).ToArray();
            return properties.Length == 1 && Known(properties[0].Property.Value)
                ? (members[0], properties[0].Property, properties[0].Ordinal) : (members[0], null, 0);
        }

        foreach (var rule in Document.Rules)
        {
            var current = Locate(facts, rule);
            if (current.Property is null) { gaps.Add("data-property-unavailable"); continue; }
            bool matched;
            if (rule.Predicate == "changed")
            {
                var original = baseline is null ? default : Locate(baseline, rule);
                if (original.Property is null) { gaps.Add("data-comparison-unavailable"); continue; }
                matched = !Equal(current.Property.Value, original.Property.Value);
            }
            else
            {
                matched = Equal(current.Property.Value, rule.Expected!);
                if (rule.Predicate == "not-equals") matched = !matched;
            }
            if (matched) findings.Add(new(current.Member!.Id, current.Property.ExportIndex, current.Ordinal,
                rule.Predicate == "changed" ? "reviewed-serialized-property-changed" : "reviewed-serialized-assertion-matched", rule.Action));
        }
        var ordered = findings.OrderBy(f => f.MemberId, StringComparer.Ordinal).ThenBy(f => f.ExportIndex)
            .ThenBy(f => f.PropertyOrdinal).ThenBy(f => f.Action, StringComparer.Ordinal).ThenBy(f => f.Reason, StringComparer.Ordinal).ToArray();
        return new(1, findings.Any(f => f.Action == "reject") ? "reject" : findings.Count != 0 ? "needs-review" : "no-match",
            gaps.Count == 0, ordered, gaps.Order(StringComparer.Ordinal).ToArray());
    }
}
