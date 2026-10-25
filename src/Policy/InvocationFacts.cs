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
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IndirectDispatch[]? Dispatches = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] CallGraphContext? CallGraph = null);

// LocationFunction is the exact containing-function key, not a parsed function-name guess.
public sealed record CallGraphFunction(string Asset, string LocationFunction, string Owner, string Function, bool Native);
public sealed record CallGraphContext(int SchemaVersion, bool Complete, CallGraphFunction[] Functions)
{
    public const int MaxFunctions = 4096;
    public const int MaxCharacters = 65_536;
    public static int Characters(CallGraphFunction function) => function.Asset.Length + function.LocationFunction.Length
        + function.Owner.Length + function.Function.Length;

    public static CallGraphContext Bounded(IEnumerable<CallGraphFunction> functions, bool complete)
    {
        var result = new List<CallGraphFunction>();
        var characters = 0;
        foreach (var function in functions)
        {
            if (result.Count >= MaxFunctions || characters + Characters(function) > MaxCharacters) { complete = false; continue; }
            characters += Characters(function);
            result.Add(function);
        }
        return new(1, complete, result.ToArray());
    }
}
