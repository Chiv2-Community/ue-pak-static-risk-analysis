using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using PakRisk.Policy;

namespace PakRisk.Scanner;

// Operator-supplied, explicitly nonsecret evidence. Never loaded in the parser.
public sealed record CapabilitySummary(string Owner, string Function, string Capability, string Provenance,
    string BuildScope, string ReviewedLimitations);
public sealed record CapabilityCatalogDocument(int SchemaVersion, string Disclosure, string Revision, ImmutableArray<CapabilitySummary> Summaries);
public sealed class CapabilityCatalog
{
    public CapabilityCatalogDocument Document { get; }
    public string Sha256 { get; }
    private CapabilityCatalog(CapabilityCatalogDocument document, string sha256) { Document = document; Sha256 = sha256; }
    public const int MaxBytes = 256 * 1024;
    public const int MaxSummaries = 256;

    public static CapabilityCatalog Load(string path)
    {
        try { return Read(FactsFile.Read(path, MaxBytes)); }
        catch (Exception error) when (error is not OutOfMemoryException) { throw new CapabilityConfigurationException(); }
    }

    public static CapabilityCatalog Read(ReadOnlySpan<byte> bytes)
    {
        try
        {
            if (bytes.Length is 0 or > MaxBytes) throw new CapabilityConfigurationException();
            // Reject replacement decoding; the digest binds the exact supplied bytes.
            _ = new UTF8Encoding(false, true).GetString(bytes);
            var document = FactsCodec.ReadClosed<CapabilityCatalogDocument>(bytes, MaxBytes, 8192);
            Validate(document);
            return new(document, Convert.ToHexStringLower(SHA256.HashData(bytes)));
        }
        catch (Exception error) when (error is not OutOfMemoryException) { throw new CapabilityConfigurationException(); }
    }

    public static void Validate(CapabilityCatalogDocument document)
    {
        if (document is null || document.SchemaVersion != 1 || document.Disclosure != "nonsecret"
            || !Id(document.Revision) || document.Summaries.IsDefault || document.Summaries.Length > MaxSummaries)
            throw new CapabilityConfigurationException();
        var identities = new HashSet<(string, string)>();
        foreach (var summary in document.Summaries)
            if (summary is null || !PolicyYaml.IsOwner(summary.Owner) || !PolicyYaml.IsIdentifier(summary.Function)
                || !identities.Add((summary.Owner, summary.Function)) || !Id(summary.Capability)
                || !Text(summary.Provenance) || !Text(summary.BuildScope) || !Text(summary.ReviewedLimitations))
                throw new CapabilityConfigurationException();
    }

    private static bool Id(string? value) => value is { Length: > 0 and <= 128 }
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');
    private static bool Text(string? value) => value is { Length: > 0 and <= 1024 }
        && !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl) && FactsCodec.Unicode(value);
}

public sealed class CapabilityConfigurationException : Exception;
