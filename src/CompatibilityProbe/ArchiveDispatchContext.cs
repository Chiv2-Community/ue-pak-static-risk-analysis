using System.Collections.Immutable;
using CompatibilityProbe;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.UnrealTypes;

namespace PakRisk.Extraction;

public sealed record ArchiveDispatchLimits(int MaxClasses = 4096, int MaxFunctions = 4096,
    int MaxEdges = 10000, int MaxOperations = 100000, int MaxDepth = 256,
    int MaxCharacters = 262144, int MaxCandidates = 10000, int MaxOrigins = 10000)
{
    internal void Validate()
    {
        if (MaxClasses is < 1 or > 4096 || MaxFunctions is < 1 or > 4096 || MaxEdges is < 1 or > 10000
            || MaxOperations is < 1 or > 100000 || MaxDepth is < 1 or > 256
            || MaxCharacters is < 1 or > 262144 || MaxCandidates is < 1 or > 10000 || MaxOrigins is < 1 or > 10000)
            throw new ArgumentOutOfRangeException(nameof(ArchiveDispatchLimits));
    }
}

// A bounded two-pass symbol index, not a cache of parsed assets or trusted base classes.
// The caller binds the complete archive bytes; in-process ASTs are not authenticated.
public sealed class ArchiveDispatchContext
{
    private sealed record ClassNode(string[] Parents, bool Interface, bool Incomplete);
    private sealed record FunctionNode(string Owner, string Name, string Asset);
    private readonly ArchiveDispatchLimits limits;
    private readonly Dictionary<string, ClassNode?> classes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, FunctionNode?> functions = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, FunctionNode[]> byName = new(StringComparer.OrdinalIgnoreCase);
    private int operations, characters, edges, candidates, origins;
    private bool limited, invalid, sealedIndex;

    public ArchiveDispatchContext(ArchiveDispatchLimits? limits = null)
    {
        this.limits = limits ?? new();
        this.limits.Validate();
    }

    private bool Spend() { if (operations < limits.MaxOperations) { operations++; return true; } limited = true; return false; }
    private bool Text(int count)
    {
        if (count <= limits.MaxCharacters - characters) { characters += count; return true; }
        limited = true; return false;
    }

    internal static string? ClassIdentity(UAsset asset, int index, string logical)
    {
        if (index > 0)
        {
            if (index > asset.Exports.Count || asset.Exports[index - 1] is not ClassExport) return null;
        }
        else if (index == 0 || -(long)index > asset.Imports.Count
            || TargetResolver.StoredName(asset.Imports[(int)(-(long)index - 1)]?.ClassName) is not ("Class" or "BlueprintGeneratedClass")) return null;
        var identity = TargetResolver.ResolveDataIdentity(asset, new(index), logical);
        if (identity is null || !PolicyYaml.IsIdentifier(identity.Function)) return null;
        var name = identity.Owner + "." + identity.Function;
        return PolicyYaml.IsOwner(name) ? name : null;
    }

    public void Add(UAsset asset, PackageInput input)
    {
        if (sealedIndex) throw new InvalidOperationException("Archive index is sealed.");
        InvocationExtractor.ValidateInput(input);
        if (asset.Exports.Count > 4096) limited = true;
        for (var i = 0; i < Math.Min(asset.Exports.Count, 4096); i++)
        {
            if (!Spend()) break;
            if (asset.Exports[i] is ClassExport type)
            {
                var name = ClassIdentity(asset, i + 1, input.LogicalPath);
                if (name is null) { invalid = true; continue; }
                if (classes.ContainsKey(name)) { classes[name] = null; invalid = true; continue; }
                if (classes.Count >= limits.MaxClasses || !Text(name.Length)) { limited = true; continue; }
                var parents = new List<string>();
                var incomplete = false;
                void Link(int index)
                {
                    if (!Spend() || edges >= limits.MaxEdges) { limited = true; incomplete = true; return; }
                    var parent = ClassIdentity(asset, index, input.LogicalPath);
                    if (parent is null) { incomplete = true; return; }
                    if (!Text(parent.Length)) { incomplete = true; return; }
                    edges++; parents.Add(parent);
                }
                if (type.SuperStruct is null) incomplete = true;
                else if (type.SuperStruct.Index != 0) Link(type.SuperStruct.Index);
                if (type.SuperIndex is null || type.SuperStruct is null || type.SuperIndex.Index != type.SuperStruct.Index)
                    incomplete = true;
                if (type.Interfaces is null) incomplete = true;
                else foreach (var face in type.Interfaces)
                {
                    if (!Spend()) { incomplete = true; break; }
                    Link(face.Class);
                }
                classes.Add(name, new(parents.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToArray(),
                    type.ClassFlags.HasFlag(EClassFlags.CLASS_Interface), incomplete));
            }
            else if (asset.Exports[i] is FunctionExport function)
            {
                var identity = TargetResolver.ResolveDataIdentity(asset, new(i + 1), input.LogicalPath);
                var owner = ClassIdentity(asset, function.OuterIndex?.Index ?? 0, input.LogicalPath);
                if (identity is null || owner is null || !StringComparer.OrdinalIgnoreCase.Equals(owner, identity.Owner)
                    || !PolicyYaml.IsIdentifier(identity.Function)) { invalid = true; continue; }
                var key = owner + ":" + identity.Function;
                if (functions.ContainsKey(key)) { functions[key] = null; invalid = true; continue; }
                var size = key.Length + owner.Length + identity.Function.Length + input.FactIdentity.Length;
                if (functions.Count >= limits.MaxFunctions || !Text(size)) { limited = true; continue; }
                functions.Add(key, new(owner, identity.Function, input.FactIdentity));
            }
        }
    }

    public void MarkIncomplete() => invalid = true;

    public void Seal()
    {
        if (sealedIndex) return;
        byName = functions.Values.Where(f => f is not null).Select(f => f!)
            .OrderBy(f => f.Owner, StringComparer.Ordinal).ThenBy(f => f.Name, StringComparer.Ordinal)
            .GroupBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.OrdinalIgnoreCase);
        sealedIndex = true;
    }

    private (HashSet<string> Names, HashSet<string> Diagnostics) Chain(string? start)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var diagnostics = new HashSet<string>(StringComparer.Ordinal);
        var active = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<(string Name, int Depth, bool Exit)>();
        if (start is null) diagnostics.Add("class-metadata-unavailable");
        else pending.Push((start, 0, false));
        while (pending.TryPop(out var item))
        {
            if (item.Exit) { active.Remove(item.Name); continue; }
            if (!Spend() || item.Depth >= limits.MaxDepth) { diagnostics.Add("target-expansion-limit"); break; }
            if (active.Contains(item.Name)) { diagnostics.Add("class-cycle"); continue; }
            if (!names.Add(item.Name)) continue;
            if (!classes.TryGetValue(item.Name, out var type))
            { diagnostics.UnionWith(["dependency-context-unavailable", "parent-unavailable"]); continue; }
            if (type is null) { diagnostics.Add("class-metadata-unavailable"); continue; }
            if (type.Incomplete) diagnostics.Add("class-metadata-unavailable");
            active.Add(item.Name); pending.Push((item.Name, item.Depth, true));
            foreach (var parent in type.Parents.Reverse()) pending.Push((parent, item.Depth + 1, false));
        }
        return (names, diagnostics);
    }

    internal IndirectDispatch Augment(IndirectDispatch dispatch, UAsset asset, PackageInput input, int receiver, int maxTargets)
    {
        if (!sealedIndex) throw new InvalidOperationException("Archive index is not sealed.");
        var diagnostics = dispatch.Diagnostics.ToHashSet(StringComparer.Ordinal);
        if (limited) diagnostics.Add("target-expansion-limit");
        if (invalid) diagnostics.Add("class-metadata-unavailable");
        if (origins >= limits.MaxOrigins || !Spend())
            return dispatch with { Diagnostics = diagnostics.Append("target-expansion-limit").Distinct().Order(StringComparer.Ordinal).ToImmutableArray() };
        origins++;
        if (dispatch.FunctionName is null || diagnostics.Contains("unbound-delegate"))
            return dispatch with { Diagnostics = diagnostics.Order(StringComparer.Ordinal).ToImmutableArray() };
        var receiverName = ClassIdentity(asset, receiver, input.LogicalPath);
        var chain = Chain(receiverName);
        diagnostics.UnionWith(chain.Diagnostics);
        var retained = dispatch.Candidates.ToList();
        var seen = retained.Select(c => c.Owner + ":" + c.Function).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (byName.TryGetValue(dispatch.FunctionName, out var entries))
            foreach (var function in entries)
            {
                if (!Spend()) { diagnostics.Add("target-expansion-limit"); break; }
                if (function.Asset == input.FactIdentity) continue;
                var ownerChain = Chain(function.Owner);
                diagnostics.UnionWith(ownerChain.Diagnostics);
                var inherited = chain.Names.Contains(function.Owner);
                var derived = receiverName is not null && ownerChain.Names.Contains(receiverName);
                if (!inherited && !derived && chain.Diagnostics.Count == 0 && ownerChain.Diagnostics.Count == 0 && !invalid && !limited) continue;
                if (!classes.TryGetValue(function.Owner, out var owner) || owner is null)
                { diagnostics.Add("target-metadata-unavailable"); continue; }
                if (seen.Contains(function.Owner + ":" + function.Name)) continue;
                if (retained.Count >= maxTargets || candidates >= limits.MaxCandidates)
                { diagnostics.Add("target-expansion-limit"); break; }
                var provenance = inherited ? "inherited-function" : derived
                    ? receiverName is not null && classes.TryGetValue(receiverName, out var type) && type is { Interface: true }
                        ? "interface-implementation" : "override" : "archive-function";
                retained.Add(new(function.Owner, function.Name, provenance)); candidates++;
                seen.Add(function.Owner + ":" + function.Name);
            }
        return dispatch with { Candidates = retained.OrderBy(c => c.Owner, StringComparer.Ordinal).ThenBy(c => c.Function, StringComparer.Ordinal).ToImmutableArray(),
            Diagnostics = diagnostics.Order(StringComparer.Ordinal).ToImmutableArray() };
    }
}
