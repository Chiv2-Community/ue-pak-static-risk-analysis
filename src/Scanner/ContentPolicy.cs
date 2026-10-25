using System.Collections.Immutable;
using PakRisk.Policy;

namespace PakRisk.Scanner;

public sealed class ContentConfigurationException() : Exception("Invalid configuration.");
public sealed record ContentFinding(string MemberId, string Diagnostic);
public sealed record ContentResult(int SchemaVersion, string Decision, bool Incomplete, ContentFinding[] Findings);

// Operator configuration, never part of the closed invocation-policy grammar.
public sealed class ContentPolicy
{
    private readonly string[] paths, classes, protectedPaths;
    private readonly string replacement;
    private ContentPolicy(string[] paths, string[] classes, string[] protectedPaths, string replacement)
    { this.paths = paths; this.classes = classes; this.protectedPaths = protectedPaths; this.replacement = replacement; }

    public static (ContentPolicy? Policy, string[] Remaining) Parse(string[] args)
    {
        var values = new Dictionary<string, List<string>>(StringComparer.Ordinal)
        { ["--allowed-path"] = [], ["--allowed-class"] = [], ["--protected-path"] = [], ["--replacement-policy"] = [] };
        var remaining = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            if (!values.TryGetValue(args[i], out var list)) { remaining.Add(args[i]); continue; }
            if (++i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal)) throw new ContentConfigurationException();
            if (list.Count == 256) throw new ContentConfigurationException();
            list.Add(args[i]);
        }
        foreach (var (key, list) in values)
        {
            if (key == "--replacement-policy")
            {
                if (list.Count > 1 || list.Any(v => v is not ("allow" or "review" or "reject"))) throw new ContentConfigurationException();
            }
            else if (list.Any(v => key == "--allowed-class" ? !ClassIdentity(v) : !VirtualPath(v))
                || list.Distinct(key == "--allowed-class" ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase).Count() != list.Count)
                throw new ContentConfigurationException();
        }
        var protectedPaths = values["--protected-path"].ToArray();
        if (values["--replacement-policy"].Count != 0 && protectedPaths.Length == 0) throw new ContentConfigurationException();
        return (values.Values.All(v => v.Count == 0) ? null : new(values["--allowed-path"].ToArray(),
            values["--allowed-class"].ToArray(), protectedPaths, values["--replacement-policy"].SingleOrDefault() ?? "review"), remaining.ToArray());
    }

    // Same ASCII virtual-component rules as pak_ingest.reader.components; never a host path.
    public static bool VirtualPath(string value)
    {
        if (value.Length is 0 or > 4096 || value.Any(c => c < 32 || c >= 127 || "\\:<>\"|?*".Contains(c))) return false;
        return value.Split('/').All(p => p.Length > 0 && p is not ("." or "..") && !p.EndsWith('.') && !p.EndsWith(' ')
            && !Reserved(p.Split('.')[0]));
    }
    private static bool Reserved(string p) => p.ToLowerInvariant() is "con" or "prn" or "aux" or "nul"
        || p.Length == 4 && (p.StartsWith("com", StringComparison.OrdinalIgnoreCase) || p.StartsWith("lpt", StringComparison.OrdinalIgnoreCase)) && p[3] is >= '1' and <= '9';
    public static bool ClassIdentity(string value) => value.Length <= 4096 && PolicyYaml.IsOwner(value);
    private static bool Under(string path, string prefix) => path.Equals(prefix, StringComparison.OrdinalIgnoreCase)
        || path.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase);

    public ContentResult Evaluate(InspectionEvidence? inspection)
    {
        var findings = new List<ContentFinding>();
        var reject = false;
        var review = false;
        var incomplete = inspection is null || inspection.Status != "validated" || inspection.Members.IsEmpty;
        foreach (var member in inspection?.Members ?? ImmutableArray<MemberEvidence>.Empty)
        {
            void Add(string diagnostic) => findings.Add(new(member.Id, diagnostic));
            var normalized = member.PathNormalized == true && VirtualPath(member.Path);
            if ((paths.Length != 0 || protectedPaths.Length != 0) && !normalized)
            { Add("path-identity-unavailable"); incomplete = true; }
            if (normalized && paths.Length != 0 && !paths.Any(p => Under(member.Path, p)))
            { Add("path-not-allowed"); reject = true; }
            if (normalized && protectedPaths.Any(p => Under(member.Path, p)))
            {
                Add("protected-path-candidate");
                reject |= replacement == "reject";
                review |= replacement == "review";
            }
            // Only parsed package class-index evidence can satisfy a class allowlist.
            // Paired, unclassified export bytes are accounted for by their package.
            if (member.InspectionStatus == "paired_export_data" && member.Status == "payload_verified"
                && member.Signatures.SequenceEqual(["unknown_content"])) continue;
            var parsedPackage = member.Status == "payload_verified" && (member.InspectionStatus is "parsed" or "partial")
                && member.Signatures.Contains("unreal_package_tag");
            if (!parsedPackage || !member.Signatures.SequenceEqual(["unreal_package_tag"]))
            { Add("content-inspection-unavailable"); incomplete = true; }
            if (classes.Length == 0) continue;
            if (!parsedPackage || member.ParsedClasses is not { Length: > 0 } parsed)
            { Add("class-inspection-unavailable"); incomplete = true; continue; }
            if (member.ParsedClassesComplete != true)
            { Add("class-inspection-unavailable"); incomplete = true; }
            if (parsed.Any(c => !classes.Contains(c.Identity, StringComparer.Ordinal)))
            { Add("class-not-allowed"); reject = true; }
        }
        if (inspection is null || inspection.Members.IsEmpty) findings.Add(new("inventory", "inventory-unavailable"));
        return new(1, reject ? "reject" : review ? "needs-review" : "allow", incomplete, findings.ToArray());
    }
}
