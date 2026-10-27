using System.Text.RegularExpressions;

namespace PakRisk.Policy;

internal static class PolicyRegex
{
    // Linear-time matching; no lookarounds, backreferences, or backtracking.
    internal static Regex Create(string pattern) => new(pattern,
        RegexOptions.NonBacktracking | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
}
