namespace PakRisk.Scanner;

public static class FactsContext
{
    // Expected identities come from trusted snapshotting, not the parser transport.
    public static void Verify(FactsDocument facts, string? pak, string? mapping)
    {
        if (pak is null && mapping is null) return; // Standalone facts evaluation.
        if (pak != facts.PakSha256) throw new FactsException();
        if (mapping is null)
        {
            if (facts.Dependencies.Length != 0) throw new FactsException();
        }
        else if (facts.Dependencies.Length != 1 || facts.Dependencies[0] != new DependencyIdentity("mapping", mapping))
            throw new FactsException();
    }
}
