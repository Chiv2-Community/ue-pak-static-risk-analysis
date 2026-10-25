namespace CompatibilityProbe;

public sealed record Diagnostic(string Code, string? Function, string? Detail = null);

public sealed record InputFile(string Name, string Sha256, long Size);

public sealed record Invocation(
    string Function,
    uint BytecodeOffset,
    string Instruction,
    string? Target,
    string Resolution);

public sealed record AssetReport(
    string Asset,
    InputFile[] Inputs,
    bool? CookedFlag,
    bool? EditorOnlyFiltered,
    bool? UnversionedProperties,
    int Exports,
    int Functions,
    int ParsedFunctions,
    Invocation[] Invocations,
    Diagnostic[] Diagnostics)
{
    public bool ParseComplete => Diagnostics.Length == 0;
}

public sealed record ProbeReport(AssetReport[] Assets)
{
    public int SchemaVersion => 1;
    public string Purpose => "compatibility-only";
    public string EngineVersionHint => "4.25";
    public string OffsetUnit => "function-relative-kismet-in-memory-bytes";
    public string UAssetApiRevision => "b4e8a012939295a6fd890ddc64e57ea78b709b95";
    // A successful parser experiment is not a completed security analysis.
    public bool AnalysisComplete => false;
    public bool ParseComplete => Assets.Length > 0 && Assets.All(a => a.ParseComplete);
    public string[] Limitations =>
    [
        "No policy evaluation or malware verdict.",
        "Package-index targets are symbolic references, not verified native implementations.",
        "No cross-package, virtual, delegate, timer, native-wrapper, or transitive resolution.",
        "No defaults/reference/replacement behavior analysis or bulk-payload validation.",
        "Engine version is an explicit parsing hint, not proof of the producer build.",
        "Trusted local compatibility inputs only; hostile-input containment is not implemented."
    ];
}
