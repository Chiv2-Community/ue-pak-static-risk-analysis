using System.Collections.Immutable;
using CompatibilityProbe;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.FieldTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;

namespace PakRisk.Extraction;

// A lexical may-history, not a VM or a control-flow solver. Mutations never kill
// earlier evidence. Unknown aliases, backedges and interprocedural state stay gaps.
internal sealed class DelegateStorageLinks(UAsset asset, int functionIndex, IndirectDispatchResolver resolver)
{
    private readonly record struct Storage(int Receiver, int Owner, int Field, bool Multicast);
    private readonly List<(KismetExpression Node, int Dispatch, ImmutableArray<ReceiverEvidence> Contexts)> events = [];
    private readonly Dictionary<Storage, HashSet<int>> history = [];
    private bool limited;

    internal void Observe(KismetExpression node, int dispatch, ImmutableArray<ReceiverEvidence> contexts)
    {
        if (node is EX_BindDelegate or EX_InstanceDelegate or EX_LetDelegate or EX_LetMulticastDelegate
            or EX_AddMulticastDelegate or EX_CallMulticastDelegate)
            events.Add((node, dispatch, contexts));
    }

    internal void Link(List<IndirectDispatch> dispatches)
    {
        // Reused AST objects are not unique serialized origins. Do not select one.
        var origins = new Dictionary<KismetExpression, int?>(ReferenceEqualityComparer.Instance);
        foreach (var item in events)
            if (!origins.TryAdd(item.Node, item.Dispatch)) origins[item.Node] = null;
        foreach (var item in events)
        {
            if (!resolver.FlowWork()) { limited = true; break; }
            switch (item.Node)
            {
                case EX_BindDelegate binding:
                    Add(Key(binding.Delegate, item.Contexts, false), [item.Dispatch]);
                    break;
                case EX_LetDelegate assignment:
                    Add(Key(assignment.VariableExpression, item.Contexts, false), Sources(assignment.AssignmentExpression, item.Contexts, false));
                    break;
                case EX_LetMulticastDelegate assignment:
                    Add(Key(assignment.VariableExpression, item.Contexts, true), Sources(assignment.AssignmentExpression, item.Contexts, true));
                    break;
                case EX_AddMulticastDelegate addition:
                    Add(Key(addition.Delegate, item.Contexts, true), Sources(addition.DelegateToAdd, item.Contexts, false));
                    break;
                case EX_CallMulticastDelegate call:
                    var sources = Sources(call.Delegate, item.Contexts, true).Where(i => dispatches[i].Origin.Offset < dispatches[item.Dispatch].Origin.Offset)
                        .OrderBy(i => dispatches[i].Origin.Offset).Select(i => dispatches[i]);
                    dispatches[item.Dispatch] = resolver.LinkBindings(dispatches[item.Dispatch], sources);
                    break;
            }
        }
        if (limited)
            foreach (var item in events.Where(e => e.Node is EX_CallMulticastDelegate))
                dispatches[item.Dispatch] = dispatches[item.Dispatch] with
                { Diagnostics = dispatches[item.Dispatch].Diagnostics.Append("target-expansion-limit").Distinct().Order(StringComparer.Ordinal).ToImmutableArray() };

        IEnumerable<int> Sources(KismetExpression expression, ImmutableArray<ReceiverEvidence> contexts, bool multicast)
        {
            if (!multicast && expression is EX_InstanceDelegate && contexts.IsEmpty && origins.TryGetValue(expression, out var origin) && origin is { } index)
                return [index];
            var key = Key(expression, contexts, multicast);
            return key is { } value && history.TryGetValue(value, out var known) ? known.ToArray() : [];
        }
    }

    private void Add(Storage? key, IEnumerable<int> sources)
    {
        if (key is not { } value) return;
        if (!history.TryGetValue(value, out var known)) history[value] = known = [];
        foreach (var source in sources)
        {
            if (!resolver.FlowWork()) { limited = true; break; }
            known.Add(source);
        }
    }

    private Storage? Key(KismetExpression expression, ImmutableArray<ReceiverEvidence> contexts, bool? multicast)
    {
        if (expression is EX_Context wrapped && contexts.IsEmpty)
        {
            var receiverEvidence = wrapped.ObjectExpression switch
            {
                EX_Self => new ReceiverEvidence("EX_Self", null, null),
                EX_ObjectConst obj => new ReceiverEvidence("EX_ObjectConst", obj.Value?.Index, null),
                _ => null
            };
            return receiverEvidence is null ? null : Key(wrapped.ContextExpression, [receiverEvidence], multicast);
        }
        // Only direct FFieldPath declarations. No out/ref parameters, arrays,
        // persistent frames, inherited property guesses, casts or alias resolution.
        KismetPropertyPointer? pointer;
        int owner;
        int receiver;
        if (expression is EX_LocalVariable local && contexts.IsEmpty)
        { pointer = local.Variable; owner = functionIndex; receiver = 0; }
        else if (expression is EX_InstanceVariable instance)
        {
            pointer = instance.Variable;
            owner = asset.Exports[functionIndex - 1].OuterIndex?.Index ?? 0;
            receiver = -1; // implicit self, distinct from any serialized object constant
            if (!contexts.IsEmpty)
            {
                if (contexts.Length != 1) return null;
                var context = contexts[0];
                if (context.Opcode == "EX_ObjectConst" && context.PackageIndex is > 0 && context.PackageIndex <= asset.Exports.Count)
                {
                    receiver = context.PackageIndex.Value;
                    owner = asset.Exports[receiver - 1].ClassIndex?.Index ?? 0;
                }
                else if (context.Opcode != "EX_Self") return null;
            }
        }
        else return null;
        if (owner <= 0 || owner > asset.Exports.Count || asset.Exports[owner - 1] is not StructExport declaration
            || receiver != 0 && declaration is not ClassExport
            || pointer?.Old is not null || pointer?.New is not { Path.Length: 1 } path || path.ResolvedOwner?.Index != owner
            || TargetResolver.StoredName(path.Path[0]) is not { } name || !PolicyYaml.IsIdentifier(name)
            || string.Equals(name, "None", StringComparison.OrdinalIgnoreCase) || declaration.LoadedProperties is null) return null;
        if (declaration.LoadedProperties.Length > resolver.FlowArrayLimit) { limited = true; return null; }
        var found = -1;
        for (var i = 0; i < declaration.LoadedProperties.Length; i++)
        {
            if (!resolver.FlowWork()) { limited = true; return null; }
            if (!string.Equals(TargetResolver.StoredName(declaration.LoadedProperties[i]?.Name), name, StringComparison.OrdinalIgnoreCase)) continue;
            if (found != -1) return null;
            found = i;
        }
        if (found < 0 || declaration.LoadedProperties[found] is not FDelegateProperty property
            || (int)property.ArrayDim != 1 || property.PropertyFlags.HasFlag(UAssetAPI.UnrealTypes.EPropertyFlags.CPF_Parm)) return null;
        var multi = property.GetType() == typeof(FMulticastDelegateProperty) || property.GetType() == typeof(FMulticastInlineDelegateProperty);
        if (!multi && property.GetType() != typeof(FDelegateProperty) || multicast is { } expected && expected != multi) return null;
        return new(receiver, owner, found, multi);
    }
}
