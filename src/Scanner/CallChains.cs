using PakRisk.Policy;

namespace PakRisk.Scanner;

public sealed record CallChainStep(InvocationLocation Origin, PublicTarget Target, string Resolution, string Kind);
public sealed record CallChainEndpoint(InvocationLocation Origin, PublicTarget Target, string Resolution,
    bool Flagged, bool Forbidden, string? Capability);
public sealed record CallChainWitness(CallChainEndpoint Endpoint, string Resolution, CallChainStep[] Callers);
public sealed record CallChainEvidence(int SchemaVersion, bool Complete, bool NeedsReview, string? CatalogRevision,
    string? CatalogSha256, CallChainWitness[] Witnesses, string[] Diagnostics);
public sealed record CallChainLimits(int MaxEdges = 10_000, int MaxDepth = 16, int MaxWitnesses = 256,
    int MaxWork = 100_000, int MaxEvidenceBytes = 512 * 1024)
{
    internal void Validate()
    {
        if (MaxEdges is < 1 or > 10_000 || MaxDepth is < 1 or > 16 || MaxWitnesses is < 1 or > 256
            || MaxWork is < 1 or > 100_000 || MaxEvidenceBytes is < 1 or > 512 * 1024)
            throw new ArgumentOutOfRangeException(nameof(CallChainLimits));
    }
}

public static class CallChains
{
    private sealed record Edge(CallGraphFunction Source, CallChainStep Step);

    // One shortest witness per endpoint/upstream function/certainty, not all Cartesian paths.
    // No control-flow or entry-point pruning: every recorded instruction is considered.
    public static CallChainEvidence Analyze(InvocationAnalysis analysis, PolicyEvaluation evaluation,
        CapabilityCatalog? catalog = null, CallChainLimits? limits = null)
    {
        PolicyEvaluator.Validate(analysis);
        limits ??= new();
        limits.Validate();
        if (catalog is not null) CapabilityCatalog.Validate(catalog.Document);
        var diagnostics = new SortedSet<string>(StringComparer.Ordinal);
        var graph = analysis.CallGraph;
        if (graph is null) diagnostics.Add("graph-context-unavailable");
        else if (!graph.Complete) diagnostics.Add("graph-context-incomplete");
        if (analysis.CoverageGaps.Length > 0) diagnostics.Add("extraction-incomplete");
        if (analysis.Dispatches is { Length: > 0 }) diagnostics.Add("indirect-open-world");
        var functions = (graph?.Functions ?? []).OrderBy(f => f.Asset, StringComparer.Ordinal)
            .ThenBy(f => f.LocationFunction, StringComparer.Ordinal).ToArray();
        var sources = functions.ToDictionary(f => (f.Asset, f.LocationFunction));
        var symbols = functions.GroupBy(f => (f.Owner, f.Function)).ToDictionary(g => g.Key, g => g.ToArray());
        var summaries = (catalog?.Document.Summaries ?? []).ToDictionary(s => (s.Owner, s.Function));
        foreach (var function in functions)
            if (function.Native && !summaries.ContainsKey((function.Owner, function.Function))) diagnostics.Add("native-summary-unavailable");
        var effects = evaluation.Findings.ToDictionary(f => f.Location);
        var incoming = new Dictionary<(string, string), List<Edge>>();
        var endpoints = new List<CallChainEndpoint>();
        var edgeCount = 0;
        var work = 0;
        var stopped = false;
        bool Spend()
        {
            if (++work <= limits.MaxWork) return true;
            diagnostics.Add("graph-work-limit");
            stopped = true;
            return false;
        }
        void Add(InvocationLocation origin, string owner, string function, string resolution, string kind, bool actual)
        {
            if (!Spend()) return;
            summaries.TryGetValue((owner, function), out var summary);
            effects.TryGetValue(origin, out var effect);
            // Only the shared evaluator's actual findings are policy endpoints.
            var flagged = actual && effect is not null && effect.Rules.Any(r => r.Effect == RuleEffect.Flag);
            var forbidden = actual && effect is not null && effect.Rules.Any(r => r.Effect == RuleEffect.Forbid);
            if (summary is not null || flagged || forbidden)
                endpoints.Add(new(origin, new(owner, function), resolution, flagged, forbidden, summary?.Capability));
            if (!sources.TryGetValue((origin.Asset, origin.Function), out var source)) diagnostics.Add("source-identity-unavailable");
            if (!symbols.TryGetValue((owner, function), out var targets))
            {
                if (summary is null) diagnostics.Add("external-summary-unavailable");
                return;
            }
            if (targets.Length != 1) { diagnostics.Add("target-identity-ambiguous"); return; }
            if (source is null) return;
            if (edgeCount >= limits.MaxEdges) { diagnostics.Add("graph-edge-limit"); return; }
            var target = targets[0];
            var key = (target.Asset, target.LocationFunction);
            if (!incoming.TryGetValue(key, out var edges)) incoming[key] = edges = [];
            edges.Add(new(source, new(origin, new(owner, function), resolution, kind)));
            edgeCount++;
        }
        foreach (var call in analysis.Invocations.DistinctBy(f => f.Location).OrderBy(f => f.Location.Asset, StringComparer.Ordinal)
            .ThenBy(f => f.Location.Function, StringComparer.Ordinal).ThenBy(f => f.Location.Offset))
        {
            if (stopped) break;
            if (call.Target is InvocationTarget.Resolved target) Add(call.Location, target.Owner, target.Function, "direct", "invocation", true);
            else { diagnostics.Add("target-unresolved"); if (!Spend()) break; }
        }
        foreach (var dispatch in (analysis.Dispatches ?? []).OrderBy(d => d.Origin.Asset, StringComparer.Ordinal)
            .ThenBy(d => d.Origin.Function, StringComparer.Ordinal).ThenBy(d => d.Origin.Offset))
        {
            if (stopped) break;
            foreach (var candidate in dispatch.Candidates.OrderBy(c => c.Owner, StringComparer.Ordinal).ThenBy(c => c.Function, StringComparer.Ordinal))
            {
                if (stopped) break;
                Add(dispatch.Origin, candidate.Owner, candidate.Function, "possible", dispatch.Kind, false);
            }
        }
        var witnesses = new List<CallChainWitness>();
        var evidenceBytes = 8192;
        // Conservative JSON upper bound: six bytes per UTF-16 code unit plus structure overhead.
        static int LocationSize(InvocationLocation location) => 256 + 6 * (location.Asset.Length + location.Function.Length);
        static int TargetSize(PublicTarget target) => 256 + 6 * (target.Owner.Length + target.Function.Length);
        bool Emit(CallChainEndpoint endpoint, string resolution, CallChainStep[] path)
        {
            var bytes = 1024 + LocationSize(endpoint.Origin) + TargetSize(endpoint.Target) + 6 * (endpoint.Capability?.Length ?? 0)
                + path.Sum(s => LocationSize(s.Origin) + TargetSize(s.Target) + 256);
            if (witnesses.Count >= limits.MaxWitnesses) { diagnostics.Add("witness-limit"); return false; }
            if (evidenceBytes + bytes > limits.MaxEvidenceBytes) { diagnostics.Add("evidence-byte-limit"); return false; }
            evidenceBytes += bytes;
            witnesses.Add(new(endpoint, resolution, path));
            return true;
        }
        var retainedEndpoints = new List<CallChainEndpoint>();
        foreach (var endpoint in endpoints.Distinct())
        {
            if (!Emit(endpoint, endpoint.Resolution, [])) break;
            retainedEndpoints.Add(endpoint);
        }
        foreach (var endpoint in retainedEndpoints)
        {
            if (stopped) break;
            var visited = new HashSet<(string, string, string)> { (endpoint.Origin.Asset, endpoint.Origin.Function, endpoint.Resolution) };
            var pending = new Queue<(string Asset, string Function, string Resolution, CallChainStep[] Path)>();
            pending.Enqueue((endpoint.Origin.Asset, endpoint.Origin.Function, endpoint.Resolution, []));
            while (pending.TryDequeue(out var current))
            {
                if (!incoming.TryGetValue((current.Asset, current.Function), out var edges)) continue;
                if (current.Path.Length >= limits.MaxDepth) { diagnostics.Add("witness-depth-limit"); continue; }
                foreach (var edge in edges)
                {
                    if (!Spend()) break;
                    var resolution = current.Resolution == "possible" || edge.Step.Resolution == "possible" ? "possible" : "direct";
                    if (!visited.Add((edge.Source.Asset, edge.Source.LocationFunction, resolution))) continue;
                    var path = new[] { edge.Step }.Concat(current.Path).ToArray();
                    if (!Emit(endpoint, resolution, path)) { pending.Clear(); break; }
                    pending.Enqueue((edge.Source.Asset, edge.Source.LocationFunction, resolution, path));
                }
                if (stopped) break;
            }
            if (stopped) break;
        }
        return new(1, diagnostics.Count == 0, endpoints.Any(e => e.Capability is not null), catalog?.Document.Revision,
            catalog?.Sha256, witnesses.ToArray(), diagnostics.ToArray());
    }
}
