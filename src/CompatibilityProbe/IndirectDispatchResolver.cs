using System.Collections.Immutable;
using CompatibilityProbe;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;

namespace PakRisk.Extraction;

// Open-world, package-local evidence. No control-flow or binding-lifetime assertion.
internal sealed class IndirectDispatchResolver
{
    private readonly UAsset asset;
    private readonly PackageInput input;
    private readonly ExtractionLimits limits;
    private readonly ArchiveDispatchContext? archiveContext;
    private readonly Dictionary<string, List<(int Index, int Owner)>> functions = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, (HashSet<int> Classes, HashSet<string> Diagnostics)> chains = [];
    private int work;
    private int emitted;
    private bool indexLimited;

    internal IndirectDispatchResolver(UAsset asset, PackageInput input, ExtractionLimits limits, ArchiveDispatchContext? archiveContext = null)
    {
        this.asset = asset;
        this.input = input;
        this.limits = limits;
        this.archiveContext = archiveContext;
        indexLimited = asset.Exports.Count > limits.MaxExports;
        for (var i = 0; i < Math.Min(asset.Exports.Count, limits.MaxExports); i++)
        {
            if (++work > limits.MaxOccurrences) { indexLimited = true; break; }
            if (asset.Exports[i] is FunctionExport function)
                Add(TargetResolver.StoredName(function.ObjectName), i + 1, function.OuterIndex?.Index ?? 0);
        }
        for (var i = 0; i < asset.Imports.Count; i++)
        {
            if (++work > limits.MaxOccurrences) { indexLimited = true; break; }
            var import = asset.Imports[i];
            if (TargetResolver.StoredName(import?.ClassName) == "Function")
                Add(TargetResolver.StoredName(import!.ObjectName), -i - 1, import.OuterIndex?.Index ?? 0);
        }
    }

    private void Add(string? name, int index, int owner)
    {
        if (name is null || !PolicyYaml.IsIdentifier(name)) return;
        if (!functions.TryGetValue(name, out var entries)) functions[name] = entries = [];
        entries.Add((index, owner));
    }

    internal IndirectDispatch? Inspect(FunctionIdentity containing, KismetExpression node, uint offset,
        ImmutableArray<ReceiverEvidence> contexts)
    {
        string kind;
        string? name = null;
        KismetExpression? receiver = null;
        var source = "kismet-serialized-v1";
        var diagnostics = new HashSet<string>(StringComparer.Ordinal) { "open-world" };
        switch (node)
        {
            case EX_CallMulticastDelegate:
                kind = "multicast";
                diagnostics.Add("binding-flow-unresolved");
                break;
            case EX_VirtualFunction call:
                kind = "virtual";
                name = TargetResolver.StoredName(call.VirtualFunctionName);
                break;
            case EX_BindDelegate binding:
                kind = "delegate-binding";
                name = TargetResolver.StoredName(binding.FunctionName);
                receiver = binding.ObjectTerm;
                diagnostics.Add("binding-flow-unresolved");
                break;
            case EX_InstanceDelegate binding:
                kind = "delegate-binding";
                name = TargetResolver.StoredName(binding.FunctionName);
                diagnostics.Add("binding-flow-unresolved");
                break;
            case EX_FinalFunction call:
                var target = TargetResolver.ResolveIdentity(asset, call.StackNode, input.LogicalPath);
                // This exact symbolic match is only a source-scoped hypothesis, never a game summary.
                if (target?.Owner != "/Script/Engine.KismetSystemLibrary" || target.Function is not ("K2_SetTimer" or "K2_SetTimerDelegate")) return null;
                if (target.PackageIndex >= 0 || -(long)target.PackageIndex > asset.Imports.Count
                    || asset.Imports[(int)(-(long)target.PackageIndex - 1)]?.ClassName?.ToString() != "Function") return null;
                kind = "timer";
                source = "ue425plus-2d1aae-kismet-timer";
                diagnostics.Add("native-build-unverified");
                diagnostics.Add("binding-flow-unresolved");
                if (target.Function == "K2_SetTimer")
                {
                    receiver = call.Parameters.ElementAtOrDefault(0);
                    name = call.Parameters.ElementAtOrDefault(1) switch
                    {
                        EX_StringConst value => value.Value,
                        EX_UnicodeStringConst value => value.Value,
                        _ => null
                    };
                }
                else if (call.Parameters.ElementAtOrDefault(0) is EX_InstanceDelegate instance)
                    name = TargetResolver.StoredName(instance.FunctionName);
                else diagnostics.Add("receiver-unavailable");
                break;
            default:
                if (node.Token is not (EExprToken.EX_AddMulticastDelegate or EExprToken.EX_RemoveMulticastDelegate
                    or EExprToken.EX_ClearMulticastDelegate or EExprToken.EX_LetDelegate or EExprToken.EX_LetMulticastDelegate)) return null;
                kind = "delegate-mutation";
                diagnostics.Add("binding-flow-unresolved");
                break;
        }
        // NAME_None is a null binding in both the serialized delegate and the
        // source-scoped timer hypothesis, not a callback named None.
        if ((kind == "delegate-binding" || kind == "timer")
            && string.Equals(name, "None", StringComparison.OrdinalIgnoreCase))
            diagnostics.Add("unbound-delegate");
        var receiverKind = "self";
        var receiverClass = asset.Exports[containing.ExportIndex - 1].OuterIndex?.Index ?? 0;
        if (receiver is not null)
            (receiverKind, receiverClass) = Receiver(receiver, receiverClass);
        else if (!contexts.IsEmpty)
        {
            var evidence = contexts[^1];
            receiverKind = evidence.Opcode == "EX_Self" ? "self" : evidence.Opcode == "EX_ObjectConst" ? "object" : "unknown";
            receiverClass = evidence.Opcode == "EX_Self" ? receiverClass : ObjectClass(evidence.PackageIndex);
        }
        if (contexts.Any(c => c.Opcode == "EX_InterfaceContext"))
        {
            receiverKind = "interface";
            diagnostics.Add("interface-context-unavailable");
        }
        if (kind is "multicast" or "delegate-mutation")
        {
            receiverKind = "unknown";
            receiverClass = 0;
        }
        if (receiverClass == 0) diagnostics.Add("receiver-unavailable");
        var candidates = ImmutableArray.CreateBuilder<DispatchCandidate>();
        var seen = new HashSet<(string, string)>();
        if (indexLimited) diagnostics.Add("target-expansion-limit");
        if (name is null || !PolicyYaml.IsIdentifier(name) || diagnostics.Contains("unbound-delegate")) diagnostics.Add("target-name-unavailable");
        else
        {
            var receiverChain = Chain(receiverClass);
            diagnostics.UnionWith(receiverChain.Diagnostics);
            if (functions.TryGetValue(name, out var entries))
                foreach (var entry in entries)
                {
                    if (++work > limits.MaxOccurrences || candidates.Count >= limits.MaxTargets || emitted >= PolicyEvaluator.MaxInvocations)
                    { diagnostics.Add("target-expansion-limit"); break; }
                    var ownerChain = Chain(entry.Owner);
                    diagnostics.UnionWith(ownerChain.Diagnostics);
                    var inherited = receiverChain.Classes.Contains(entry.Owner);
                    var derived = ownerChain.Classes.Contains(receiverClass);
                    var uncertain = receiverChain.Diagnostics.Count != 0 || ownerChain.Diagnostics.Count != 0;
                    if (!inherited && !derived && !uncertain) continue;
                    var identity = TargetResolver.ResolveDataIdentity(asset, new(entry.Index), input.LogicalPath);
                    if (identity is null || !PolicyYaml.IsOwner(identity.Owner) || !PolicyYaml.IsIdentifier(identity.Function))
                    { diagnostics.Add("target-metadata-unavailable"); continue; }
                    if (seen.Add((identity.Owner, identity.Function)))
                    {
                        candidates.Add(new(identity.Owner, identity.Function, entry.Index < 0 ? "imported-function" :
                            entry.Owner == receiverClass ? "local-function" : inherited ? "inherited-function" : derived ?
                            receiverClass is > 0 && receiverClass <= asset.Exports.Count && asset.Exports[receiverClass - 1] is ClassExport face && face.ClassFlags.HasFlag(UAssetAPI.UnrealTypes.EClassFlags.CLASS_Interface)
                                ? "interface-implementation" : "override" : "local-function"));
                        emitted++;
                    }
                }
            if (candidates.Count == 0) diagnostics.Add("target-metadata-unavailable");
        }
        var dispatch = new IndirectDispatch(1, new(input.FactIdentity, containing.Qualified, offset), node.Token.ToString(), kind,
            PolicyYaml.IsIdentifier(name) ? name : null,
            receiverKind, "possible", candidates.OrderBy(c => c.Owner, StringComparer.Ordinal).ThenBy(c => c.Function, StringComparer.Ordinal).ToImmutableArray(),
            diagnostics.Order(StringComparer.Ordinal).ToImmutableArray(), source);
        return archiveContext?.Augment(dispatch, asset, input, receiverClass, limits.MaxTargets) ?? dispatch;
    }

    private (string Kind, int Class) Receiver(KismetExpression expression, int self) => expression switch
    {
        EX_Self => ("self", self),
        EX_ObjectConst obj => ("object", ObjectClass(obj.Value?.Index)),
        EX_InterfaceContext => ("interface", 0),
        _ => ("unknown", 0)
    };

    private int ObjectClass(int? index) => index is > 0 && index <= asset.Exports.Count
        ? asset.Exports[index.Value - 1]?.ClassIndex?.Index ?? 0 : 0;

    private (HashSet<int> Classes, HashSet<string> Diagnostics) Chain(int start)
    {
        if (chains.TryGetValue(start, out var cached)) return cached;
        var classes = new HashSet<int>();
        var diagnostics = new HashSet<string>(StringComparer.Ordinal);
        var visited = new HashSet<int>();
        var active = new HashSet<int>();
        var pending = new Stack<(int Index, bool Exit)>();
        if (start == 0) diagnostics.Add("class-metadata-unavailable");
        else pending.Push((start, false));
        while (pending.TryPop(out var item))
        {
            var current = item.Index;
            if (item.Exit) { active.Remove(current); continue; }
            if (++work > limits.MaxOccurrences || classes.Count >= 256)
            { diagnostics.Add("target-expansion-limit"); break; }
            if (active.Contains(current)) { diagnostics.Add("class-cycle"); continue; }
            if (!visited.Add(current)) continue;
            active.Add(current);
            pending.Push((current, true));
            classes.Add(current);
            if (current < 0) { diagnostics.Add("dependency-context-unavailable"); diagnostics.Add("parent-unavailable"); continue; }
            if (current > asset.Exports.Count || asset.Exports[current - 1] is not ClassExport type)
            { diagnostics.Add("class-metadata-unavailable"); continue; }
            if (type.Interfaces is null) diagnostics.Add("interface-context-unavailable");
            else if (type.Interfaces.Length > limits.MaxArray) diagnostics.Add("target-expansion-limit");
            else foreach (var face in type.Interfaces)
            {
                if (++work > limits.MaxOccurrences || classes.Count >= 256)
                { diagnostics.Add("target-expansion-limit"); break; }
                if (face.Class == 0) diagnostics.Add("interface-context-unavailable");
                else pending.Push((face.Class, false));
            }
            if (type.SuperStruct is null) diagnostics.Add("parent-unavailable");
            else if (type.SuperStruct.Index != 0) pending.Push((type.SuperStruct.Index, false));
        }
        return chains[start] = (classes, diagnostics);
    }
}
