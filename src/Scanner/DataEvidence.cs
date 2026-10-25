using System.Collections.Immutable;
using PakRisk.Extraction;

namespace PakRisk.Scanner;

public sealed record PackageDataEvidence(string MemberId, AssetDataEvidence Evidence);
public sealed record DataEvidence(int SchemaVersion, string ContentRoot, string LogicalRoot, bool Complete,
    ImmutableArray<PackageDataEvidence> Packages);

public static class DataEvidenceValidation
{
    public const int MaxProperties = 4096;
    public const int MaxCharacters = 262_144;
    public const int MaxPathParts = 32; // Array ordinals add a second part per extractor depth.

    public static int Characters(SerializedValue value) => value switch
    {
        SerializedValue.Unknown v => v.Reason.Length,
        SerializedValue.Text v => v.Value.Length,
        SerializedValue.Integer v => v.Type.Length,
        SerializedValue.Name v => v.Value.Length,
        SerializedValue.Enumeration v => v.Type.Length + v.Value.Length,
        SerializedValue.Reference v => v.Owner.Length + v.ObjectName.Length + v.TargetKind.Length,
        SerializedValue.Delegate v => v.Function.Length + Characters(v.Object),
        SerializedValue.Container v => v.Type.Length,
        _ => 0
    };
    public static int Characters(SerializedProperty property) => (property.ObjectIdentity?.Length ?? 0)
        + (property.ClassIdentity?.Length ?? 0) + property.Path.Sum(p => p.Property?.Length ?? 0) + Characters(property.Value);

    public static void Validate(DataEvidence data)
    {
        if (data.SchemaVersion != 1 || !Root(data.ContentRoot, data.LogicalRoot)
            || data.Packages.IsDefault || data.Packages.Length > 4096) throw new FactsException();
        var members = new HashSet<string>(StringComparer.Ordinal);
        var nodes = 0;
        var characters = 0;
        void Text(string? text, bool nullable = false)
        {
            if (nullable && text is null) return;
            if (text is null || text.Length > 4096 || !FactsCodec.Unicode(text)
                || text.Any(c => char.IsControl(c) || c == '\ufffd')) throw new FactsException();
            characters += text.Length;
            if (characters > MaxCharacters) throw new FactsException();
        }
        foreach (var package in data.Packages)
        {
            if (package is null || package.MemberId is not { Length: > 0 and <= 128 }
                || !package.MemberId.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '+')
                || !members.Add(package.MemberId)) throw new FactsException();
            Text(package.MemberId);
            var evidence = package.Evidence;
            if (evidence is null || evidence.SchemaVersion != 1 || evidence.Properties.IsDefault
                || evidence.Diagnostics.IsDefault || evidence.Diagnostics.Length > 64
                || evidence.Complete && evidence.Diagnostics.Length != 0) throw new FactsException();
            if (evidence.Asset.Length == 0) throw new FactsException();
            Text(evidence.Asset);
            foreach (var diagnostic in evidence.Diagnostics) Text(diagnostic);
            var identities = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in evidence.Properties)
            {
                if (++nodes > MaxProperties || property is null || property.ExportIndex is < 1 or > 4096
                    || property.Path.IsDefaultOrEmpty || property.Path.Length > MaxPathParts) throw new FactsException();
                Text(property.ObjectIdentity, true); Text(property.ClassIdentity, true);
                var identity = property.ExportIndex + ":";
                foreach (var part in property.Path)
                {
                    if (part is null || part.ArrayIndex < 0 || part.Element < 0
                        || (part.Property is null) != (part.Element is not null)
                        || part.Element is not null && part.ArrayIndex != 0
                        || part.Property is { Length: 0 }) throw new FactsException();
                    Text(part.Property, true);
                    identity += $"{part.Property?.Length ?? -1}:{part.Property}:{part.ArrayIndex}:{part.Element};";
                }
                // Duplicates stay visible as incomplete extraction, never pick a winner.
                if (!identities.Add(identity) && evidence.Complete) throw new FactsException();
                ValidateValue(property.Value, Text);
            }
        }
        if (data.Complete && data.Packages.Any(p => !p.Evidence.Complete)) throw new FactsException();
    }

    internal static bool Root(string content, string logical) => content == "-" && logical == "-"
        || ContentPolicy.VirtualPath(content) && logical.StartsWith('/') && ContentPolicy.VirtualPath(logical[1..]);

    internal static void ValidateValue(SerializedValue value, Action<string?, bool> text)
    {
        switch (value)
        {
            case SerializedValue.Unknown v: text(v.Reason, false); break;
            case SerializedValue.Text v: text(v.Value, false); break;
            case SerializedValue.Boolean: break;
            case SerializedValue.Integer v when v.Type == "int64" || v.Type == "int32" && v.Value is >= int.MinValue and <= int.MaxValue: break;
            case SerializedValue.Name v: text(v.Value, false); break;
            case SerializedValue.Enumeration v: text(v.Type, false); text(v.Value, false); break;
            case SerializedValue.NullReference: break;
            case SerializedValue.Reference v when v.PackageIndex != 0 && v.TargetKind is "local-class" or "local-object" or "import-symbol":
                if ((v.PackageIndex < 0) != (v.TargetKind == "import-symbol")) throw new FactsException();
                text(v.Owner, false); text(v.ObjectName, false); break;
            case SerializedValue.Delegate v when v.Object is SerializedValue.Reference or SerializedValue.NullReference or SerializedValue.Unknown:
                ValidateValue(v.Object, text); text(v.Function, false); break;
            case SerializedValue.Container v when v.Type is "array" or "struct" && v.Count >= 0: break;
            default: throw new FactsException();
        }
    }
}
