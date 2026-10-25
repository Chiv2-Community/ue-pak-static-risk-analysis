using System.Collections.Immutable;
using PakRisk.Policy;

namespace PakRisk.Extraction;

// StoragePath is only a parser input. Identities never derive from temporary paths.
public sealed record PackageInput(string Pak, string Entry, string LogicalPath, string StoragePath)
{
    public string FactIdentity => $"{Pak.Length}:{Pak}{Entry.Length}:{Entry}{LogicalPath}";
}
public sealed record FunctionIdentity(string Owner, string Name, int ExportIndex)
{
    public string Qualified => $"{Owner}:{Name}#{ExportIndex}";
}
public sealed record ExtractionDiagnostic(string Code, int? ExportIndex = null, long? Offset = null);
public sealed record ReceiverEvidence(string Opcode, int? PackageIndex, string? Name);
public sealed record ArgumentEvidence(int Position, string? Name, string Opcode, ArgumentValue Value, string Reason);
public sealed record ExtractedInvocation(FunctionIdentity ContainingFunction, long Offset, string Opcode,
    string Dispatch, int? TargetIndex, string? TargetName, CompatibilityProbe.TargetResolver.Identity? ResolvedIdentity, InvocationTarget Target,
    ImmutableArray<ReceiverEvidence> Receivers, string MetadataState,
    ImmutableArray<ArgumentEvidence> Arguments, InvocationFact Fact);
public sealed record FunctionCoverage(FunctionIdentity Identity, bool Complete, bool Native,
    int VisitedInstructions, ImmutableArray<ExtractionDiagnostic> Diagnostics);
public sealed record ExtractionReport(PackageInput Input, int ExportCount, int InspectedExports, ImmutableArray<ExtractedInvocation> Invocations,
    ImmutableArray<FunctionCoverage> Functions, ImmutableArray<ExtractionDiagnostic> Diagnostics,
    InvocationAnalysis Analysis)
{
    public bool Complete => Diagnostics.IsEmpty && Functions.All(f => f.Complete);
}

public sealed record ExtractionLimits(int MaxExports = 100_000, int MaxOccurrences = 100_000,
    int MaxDepth = 128, int MaxArray = 10_000, int MaxLiteral = 4096)
{
    internal void Validate()
    {
        if (MaxExports is < 1 or > 100_000 || MaxOccurrences is < 1 or > 100_000 ||
            MaxDepth is < 1 or > 128 || MaxArray is < 1 or > 10_000 || MaxLiteral is < 1 or > 4096)
            throw new ArgumentOutOfRangeException(nameof(ExtractionLimits));
    }
}
