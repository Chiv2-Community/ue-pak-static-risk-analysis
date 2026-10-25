using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using CompatibilityProbe;
using PakRisk.Extraction;
using PakRisk.Policy;
using PakRisk.Scanner;
using UAssetAPI.Unversioned;

// Container-internal protocol. Input paths are fixed trusted supervisor arguments.
try
{
    if (args.Length != 4) return 3;
    static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }
    var root = args[0];
    using var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, "inspection.json")));
    var report = manifest.RootElement;
    var calls = ImmutableArray.CreateBuilder<InvocationFact>();
    var gaps = new HashSet<CoverageGap>();
    if (report.GetProperty("ingestion_status").GetString() != "validated") gaps.Add(CoverageGap.IncompleteExtraction);
    var records = report.GetProperty("records").EnumerateArray().ToArray();
    var byPath = records.ToLookup(r => r.TryGetProperty("virtual_path", out var p) ? p.GetString()! : "",
        StringComparer.OrdinalIgnoreCase);
    if (records.Length == 0) gaps.Add(CoverageGap.IncompleteExtraction);
    var mapping = args[1] == "-" ? null : new Usmap(args[1]);
    var dependencies = mapping is null ? ImmutableArray<DependencyIdentity>.Empty
        : [new DependencyIdentity("mapping", Hash(args[1]))];
    var contentRoot = args[2];
    var logicalRoot = args[3];
    var paired = new HashSet<string>();
    var inspections = new Dictionary<string, string>();
    var classes = new Dictionary<string, ImmutableArray<string>>();
    foreach (var record in records)
    {
        if (!record.TryGetProperty("signatures", out var signatures)
            || !signatures.EnumerateArray().Any(s => s.GetString() == "unreal_package_tag")) continue;
        var path = record.GetProperty("virtual_path").GetString()!;
        // An explicit virtual content-root mapping establishes Unreal ownership.
        if (contentRoot == "-" || !path.StartsWith(contentRoot + "/", StringComparison.Ordinal))
        {
            inspections[record.GetProperty("id").GetString()!] = "unknown_content_root";
            gaps.Add(CoverageGap.IncompleteExtraction);
            continue;
        }
        var relative = path[(contentRoot.Length + 1)..];
        var dot = relative.LastIndexOf('.');
        var logical = logicalRoot + "/" + (dot <= relative.LastIndexOf('/') ? relative : relative[..dot]);
        string Payload(JsonElement r)
        {
            var id = r.GetProperty("id").GetString()!;
            if (!Regex.IsMatch(id, @"\Ar[0-9]{8}\z")) throw new InvalidDataException();
            var file = Path.Combine(root, id);
            if (r.GetProperty("status").GetString() != "payload_verified"
                || Hash(file) != r.GetProperty("sha256").GetString())
                throw new InvalidDataException();
            return file;
        }
        var stem = path.LastIndexOf('.') > path.LastIndexOf('/') ? path[..path.LastIndexOf('.')] : path;
        var exports = byPath[stem + ".uexp"].ToArray();
        try
        {
            if (exports.Length > 1) throw new InvalidDataException();
            var asset = PackageReader.Read(Payload(record), exports.Length == 1 ? Payload(exports[0]) : null, mapping);
            // Pairing accounts only for unclassified raw export bytes, not recognized content.
            if (exports.Length == 1 && exports[0].TryGetProperty("signatures", out var exportSignatures)
                && exportSignatures.GetArrayLength() == 1
                && exportSignatures[0].GetString() == "unknown_content")
                paired.Add(exports[0].GetProperty("id").GetString()!);
            // Bulk payload inspection is not implemented; it must not become clean.
            var input = new PackageInput("submission", path, logical, Payload(record));
            var extraction = InvocationExtractor.Inspect(asset, input);
            var id = record.GetProperty("id").GetString()!;
            inspections[id] = extraction.Complete ? "parsed" : "partial";
            calls.AddRange(extraction.Analysis.Invocations);
            foreach (var gap in extraction.Analysis.CoverageGaps) gaps.Add(gap);
            classes[id] = asset.Exports.Select(e => e.GetClassTypeForAncestry(asset, out var module).ToString())
                .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToImmutableArray();
            paired.Add(record.GetProperty("id").GetString()!);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        { gaps.Add(CoverageGap.UnsupportedParsing); inspections[record.GetProperty("id").GetString()!] = "parse_failed"; }
    }
    if (records.Any(r => !paired.Contains(r.GetProperty("id").GetString()!)
        || (r.TryGetProperty("signatures", out var signatures)
            && signatures.EnumerateArray().Any(s => s.GetString() is not ("unknown_content" or "unreal_package_tag")))))
        gaps.Add(CoverageGap.IncompleteExtraction);
    var pakHash = Hash("/input/submission");
    if (report.TryGetProperty("input_sha256", out var recordedHash) && recordedHash.GetString() != pakHash)
        throw new InvalidDataException();
    var evidence = records.Select(r =>
    {
        string Text(string name, string fallback) => r.TryGetProperty(name, out var value) ? value.GetString()! : fallback;
        var id = Text("id", "unknown");
        return new MemberEvidence(id, Text("virtual_path", Text("raw_name", "")),
            r.TryGetProperty("output", out var size) && size.TryGetInt64(out var count) ? count : null,
            r.TryGetProperty("sha256", out var sha) ? sha.GetString() : null, Text("status", "uninspected"),
            r.TryGetProperty("signatures", out var sigs) ? sigs.EnumerateArray().Select(s => s.GetString()!).ToImmutableArray() : [],
            classes.GetValueOrDefault(id, []), inspections.GetValueOrDefault(id, paired.Contains(id) ? "paired_export_data" : "uninspected"),
            Text("sidecar_status", "unresolved"));
    }).ToImmutableArray();
    var facts = new FactsDocument(1, pakHash, "4.25", "container-v1",
        dependencies, new(calls.ToImmutable(), gaps.Order().ToImmutableArray()),
        new InspectionEvidence(report.GetProperty("ingestion_status").GetString()!,
            report.GetProperty("diagnostic").GetString()!, evidence));
    Console.OpenStandardOutput().Write(FactsCodec.Write(facts));
    return 0;
}
catch (Exception) { return 3; }
