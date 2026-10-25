using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace PakRisk.Extraction;

// Typed serialized evidence, not runtime values or invocation evidence.
public abstract record SerializedValue
{
    public sealed record Unknown(string Reason) : SerializedValue;
    public sealed record Text(string Value) : SerializedValue;
    public sealed record Boolean(bool Value) : SerializedValue;
    public sealed record Integer(long Value, string Type) : SerializedValue;
    public sealed record Name(string Value) : SerializedValue;
    public sealed record Enumeration(string Type, string Value) : SerializedValue;
    public sealed record NullReference : SerializedValue;
    public sealed record Reference(int PackageIndex, string Owner, string ObjectName, string TargetKind) : SerializedValue;
    public sealed record Delegate(SerializedValue Object, string Function) : SerializedValue;
    public sealed record Container(string Type, int Count) : SerializedValue;
}

// ArrayIndex is a static-array slot; Element is a dynamic-array ordinal.
public sealed record DataPathPart(string? Property, int ArrayIndex, [property: JsonRequired] int? Element = null);
public sealed record SerializedProperty(int ExportIndex, string? ObjectIdentity, string? ClassIdentity,
    bool ClassDefaultFlag, ImmutableArray<DataPathPart> Path, SerializedValue Value);
public sealed record AssetDataEvidence(int SchemaVersion, string Asset, bool Complete,
    ImmutableArray<SerializedProperty> Properties, ImmutableArray<string> Diagnostics);
