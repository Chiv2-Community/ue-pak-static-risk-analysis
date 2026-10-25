using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace PakRisk.Policy;

public sealed record InvocationLocation(string Asset, string Function, long Offset);
public sealed record InvocationFact(InvocationLocation Location, InvocationTarget Target, ArgumentMetadata Arguments);

public abstract record InvocationTarget
{
    private InvocationTarget() { }
    public sealed record Resolved(string Owner, string Function) : InvocationTarget;
    public sealed record Unresolved : InvocationTarget;
}

public abstract record ArgumentMetadata
{
    private ArgumentMetadata() { }
    public sealed record Known(ImmutableArray<NamedArgument> Arguments) : ArgumentMetadata;
    public sealed record Unavailable : ArgumentMetadata;
}

public sealed record NamedArgument(string Name, ArgumentValue Value);

public abstract record ArgumentValue
{
    private ArgumentValue() { }
    public sealed record Constant(PolicyLiteral Value) : ArgumentValue;
    public sealed record Dynamic : ArgumentValue;
    public sealed record Missing : ArgumentValue;
}

public enum CoverageGap { UnsupportedParsing, UnresolvedDispatch, IncompleteExtraction }
public sealed record DispatchCandidate(string Owner, string Function, string Provenance);
// Origins are actual instructions, including bindings; candidates are not invocation occurrences.
public sealed record IndirectDispatch(int SchemaVersion, InvocationLocation Origin, string Opcode, string Kind,
    string? FunctionName, string Receiver, string Resolution, ImmutableArray<DispatchCandidate> Candidates,
    ImmutableArray<string> Diagnostics, string Source);
public sealed record InvocationAnalysis(ImmutableArray<InvocationFact> Invocations, ImmutableArray<CoverageGap> CoverageGaps,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IndirectDispatch[]? Dispatches = null);
