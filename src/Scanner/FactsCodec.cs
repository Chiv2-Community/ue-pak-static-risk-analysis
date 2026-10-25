using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using PakRisk.Policy;

namespace PakRisk.Scanner;

public sealed record DependencyIdentity(string Kind, string Sha256);
public sealed record FactsDocument(int SchemaVersion, string PakSha256, string EngineVersion,
    string ProducerVersion, ImmutableArray<DependencyIdentity> Dependencies, InvocationAnalysis Analysis,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] InspectionEvidence? Inspection = null);

public sealed record ParsedClassEvidence(string Identity, string Provenance);
public sealed record MemberEvidence(string Id, string Path, long? Size, string? Sha256, string Status,
    ImmutableArray<string> Signatures, ImmutableArray<string> Classes, string InspectionStatus, string SidecarStatus,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ParsedClassEvidence[]? ParsedClasses = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? ParsedClassesComplete = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? PathNormalized = null);
public sealed record InspectionEvidence(string Status, string Diagnostic, ImmutableArray<MemberEvidence> Members);

public sealed class FactsException() : Exception("Invalid facts input.");

// No parser/storage paths belong in this transport. It establishes shape, not authenticity.
public static class FactsCodec
{
    public const int MaxBytes = 8 * 1024 * 1024;
    public const int MaxNodes = 200_000;
    public const int MaxDepth = 16;
    private static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var resolver = new DefaultJsonTypeInfoResolver();
        resolver.Modifiers.Add(info =>
        {
            if (info.Type == typeof(InvocationTarget)) Tags(info,
                (typeof(InvocationTarget.Resolved), "resolved"), (typeof(InvocationTarget.Unresolved), "unresolved"));
            if (info.Type == typeof(ArgumentMetadata)) Tags(info,
                (typeof(ArgumentMetadata.Known), "known"), (typeof(ArgumentMetadata.Unavailable), "unavailable"));
            if (info.Type == typeof(ArgumentValue)) Tags(info,
                (typeof(ArgumentValue.Constant), "constant"), (typeof(ArgumentValue.Dynamic), "dynamic"),
                (typeof(ArgumentValue.Missing), "missing"));
        });
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.KebabCaseLower,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            RespectRequiredConstructorParameters = true,
            RespectNullableAnnotations = true,
            AllowOutOfOrderMetadataProperties = true,
            MaxDepth = MaxDepth,
            TypeInfoResolver = resolver
        };
        options.Converters.Add(new CoverageGapConverter());
        return options;
    }

    private static void Tags(JsonTypeInfo info, params (Type Type, string Tag)[] variants)
    {
        info.PolymorphismOptions = new JsonPolymorphismOptions { TypeDiscriminatorPropertyName = "kind" };
        foreach (var (type, tag) in variants)
            info.PolymorphismOptions.DerivedTypes.Add(new JsonDerivedType(type, tag));
    }

    private sealed class CoverageGapConverter : JsonConverter<CoverageGap>
    {
        public override CoverageGap Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options) =>
            reader.TokenType == JsonTokenType.String ? reader.GetString() switch
            {
                "unsupported-parsing" => CoverageGap.UnsupportedParsing,
                "unresolved-dispatch" => CoverageGap.UnresolvedDispatch,
                "incomplete-extraction" => CoverageGap.IncompleteExtraction,
                _ => throw new JsonException()
            } : throw new JsonException();

        public override void Write(Utf8JsonWriter writer, CoverageGap value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value switch
            {
                CoverageGap.UnsupportedParsing => "unsupported-parsing",
                CoverageGap.UnresolvedDispatch => "unresolved-dispatch",
                CoverageGap.IncompleteExtraction => "incomplete-extraction",
                _ => throw new JsonException()
            });
    }

    public static FactsDocument Read(ReadOnlySpan<byte> bytes)
    {
        try
        {
            Preflight(bytes);
            var document = JsonSerializer.Deserialize<FactsDocument>(bytes, Options) ?? throw new FactsException();
            Validate(document);
            return document;
        }
        catch (Exception error) when (error is JsonException or ArgumentException or InvalidOperationException
            or NotSupportedException or NullReferenceException)
        { throw new FactsException(); }
    }

    public static byte[] Write(FactsDocument document)
    {
        try
        {
            Validate(document);
            using var stream = new BoundedStream();
            JsonSerializer.Serialize(stream, document, Options);
            var bytes = stream.ToArray();
            Preflight(bytes);
            return bytes;
        }
        catch (Exception error) when (error is JsonException or ArgumentException or InvalidOperationException
            or NotSupportedException or NullReferenceException)
        { throw new FactsException(); }
    }

    private static void Validate(FactsDocument document)
    {
        if (document is null || document.SchemaVersion != 1 || document.EngineVersion != "4.25"
            || !Hash(document.PakSha256) || !Identity(document.ProducerVersion)
            || document.Dependencies.IsDefault || document.Dependencies.Length > 256)
            throw new FactsException();
        var kinds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var dependency in document.Dependencies)
            if (dependency is null || !Identity(dependency.Kind) || !Hash(dependency.Sha256) || !kinds.Add(dependency.Kind))
                throw new FactsException();
        if (document.Inspection is { } inspection)
        {
            if (inspection.Status is not ("validated" or "rejected") || !Identity(inspection.Diagnostic)
                || inspection.Members.IsDefault || inspection.Members.Length > 10_000) throw new FactsException();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var member in inspection.Members)
                if (member is null || !Identity(member.Id) || !ids.Add(member.Id)
                    || member.Path is null || member.Path.Length > 4096 || !Unicode(member.Path)
                    || member.Size < 0
                    || member.Sha256 is not null && !Hash(member.Sha256)
                    || member.Status is not ("uninspected" or "rejected" or "payload_verified")
                    || member.Signatures.IsDefault || member.Signatures.Length > 16 || member.Signatures.Any(s => !Identity(s))
                    || member.Classes.IsDefault || member.Classes.Length > 256 || member.Classes.Any(s => s is null || s.Length > 4096 || !Unicode(s))
                    || !Identity(member.InspectionStatus) || !Identity(member.SidecarStatus)
                    || member.ParsedClasses is { } parsed && (parsed.Length > 256 || parsed.Any(c => c is null
                        || !ContentPolicy.ClassIdentity(c.Identity) || c.Provenance is not ("export-class-index-import" or "export-class-index-export")))) throw new FactsException();
        }
        PolicyEvaluator.Validate(document.Analysis);
    }

    private static bool Hash(string? value) => value is { Length: 64 }
        && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool Identity(string? value) => value is { Length: > 0 and <= 128 }
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or '+');

    // Bound allocations before deserializing; duplicate names are forbidden at every depth.
    private static void Preflight(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is 0 or > MaxBytes) throw new FactsException();
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = MaxDepth });
        var frames = new Stack<Frame>();
        var nodes = 0;
        string? property = null;
        while (reader.Read())
        {
            if (++nodes > MaxNodes) throw new FactsException();
            if (property == "dispatches" && reader.TokenType != JsonTokenType.StartArray) throw new FactsException();
            if (reader.TokenType is JsonTokenType.PropertyName or JsonTokenType.String)
            {
                if (reader.ValueSpan.Length > PolicyEvaluator.MaxFactStringLength * 6) throw new FactsException();
                var text = reader.GetString()!;
                if (text.Length > PolicyEvaluator.MaxFactStringLength || !Unicode(text)) throw new FactsException();
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    if (!frames.Peek().Names!.Add(text)) throw new FactsException();
                    property = text;
                    continue;
                }
            }
            if (reader.TokenType is JsonTokenType.EndArray or JsonTokenType.EndObject)
            { frames.Pop(); continue; }
            if (frames.TryPeek(out var parent) && parent.Names is null && ++parent.Count > parent.Limit)
                throw new FactsException();
            if (reader.TokenType == JsonTokenType.StartObject) frames.Push(new Frame(new HashSet<string>(StringComparer.Ordinal), 0));
            if (reader.TokenType == JsonTokenType.StartArray)
                frames.Push(new Frame(null, property is "arguments" or "coverage-gaps" or "dependencies" or "candidates" ? 256 : property == "diagnostics" ? 16 : PolicyEvaluator.MaxInvocations));
            property = null;
        }
    }

    private sealed class Frame(HashSet<string>? names, int limit)
    {
        public HashSet<string>? Names { get; } = names;
        public int Limit { get; } = limit;
        public int Count { get; set; }
    }

    private sealed class BoundedStream : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (Length + count > MaxBytes) throw new FactsException();
            base.Write(buffer, offset, count);
        }
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (Length + buffer.Length > MaxBytes) throw new FactsException();
            base.Write(buffer);
        }
    }

    private static bool Unicode(string text)
    {
        for (var i = 0; i < text.Length; i++)
            if (char.IsSurrogate(text[i]) && (!char.IsHighSurrogate(text[i])
                || ++i >= text.Length || !char.IsLowSurrogate(text[i]))) return false;
        return true;
    }
}
