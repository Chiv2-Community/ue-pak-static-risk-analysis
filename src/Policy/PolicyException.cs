namespace PakRisk.Policy;

// No source values, key names, rule IDs, or upstream exceptions are retained.
public sealed class PolicyException(string code, long line = 1, long column = 1)
    : Exception($"Policy validation failed ({code}) at line {line}, column {column}.")
{
    public string Code { get; } = code;
    public long Line { get; } = line;
    public long Column { get; } = column;
}
