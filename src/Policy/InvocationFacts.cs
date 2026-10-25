using System.Collections.Immutable;

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
public sealed record InvocationAnalysis(ImmutableArray<InvocationFact> Invocations, ImmutableArray<CoverageGap> CoverageGaps);
