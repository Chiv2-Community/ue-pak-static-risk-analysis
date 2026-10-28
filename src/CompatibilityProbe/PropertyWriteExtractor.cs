using CompatibilityProbe;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.FieldTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;

namespace PakRisk.Extraction;

// Inspects assignment destinations, never EX_Let's value-type pointer or names in text.
internal static class PropertyWriteExtractor
{
    private sealed record Destination(string? Owner, string? Property, string Receiver, bool Local = false);

    public static PropertyWriteFact? Inspect(UAsset asset, PackageInput input, FunctionIdentity function,
        KismetExpression node, uint offset, bool objectContext)
    {
        var assignment = node switch
        {
            EX_Let let => (let.Variable, let.Expression),
            EX_LetBase let => (let.VariableExpression, let.AssignmentExpression),
            EX_LetValueOnPersistentFrame frame => ((KismetExpression)new EX_InstanceVariable { Variable = frame.DestinationProperty }, frame.AssignmentExpression),
            EX_SetArray array => (array.AssigningProperty, (KismetExpression)array),
            EX_SetMap map => (map.MapProperty, (KismetExpression)map),
            EX_SetSet set => (set.SetProperty, (KismetExpression)set),
            _ => ((KismetExpression?, KismetExpression?))(null, null)
        };
        if (assignment.Item1 is null && node is not (EX_SetArray or EX_SetMap or EX_SetSet)) return null;
        var destination = assignment.Item1 is null ? new Destination(null, null, "unknown")
            : Resolve(asset, input, function.ExportIndex, assignment.Item1, 0);
        if (node is EX_LetValueOnPersistentFrame frameWrite && IsLocal(asset, frameWrite.DestinationProperty, function.ExportIndex)) return null;
        if (destination.Local) return null;
        return new(new(input.FactIdentity, function.Qualified, offset), node.Token.ToString(), destination.Owner,
            destination.Property, objectContext && destination.Receiver == "self" ? "object" : destination.Receiver,
            InvocationExtractor.Value(assignment.Item2).Item1);
    }

    private static Destination Resolve(UAsset asset, PackageInput input, int function, KismetExpression node, int depth)
    {
        if (depth >= 24) return new(null, null, "unknown");
        switch (node)
        {
            case EX_LocalVariable local:
                return new(null, null, "unknown", IsLocal(asset, local.Variable, function));
            case EX_LocalOutVariable:
                // Out/ref parameters may alias instance storage.
                return new(null, null, "unknown");
            case EX_InstanceVariable instance:
                return Pointer(asset, input, instance.Variable, "self");
            case EX_DefaultVariable defaults:
                return Pointer(asset, input, defaults.Variable, "unknown");
            case EX_Context context:
                return Resolve(asset, input, function, context.ContextExpression, depth + 1) with { Receiver = "object" };
            case EX_StructMemberContext member:
                var parent = Resolve(asset, input, function, member.StructExpression, depth + 1);
                if (parent.Local) return parent;
                var child = Pointer(asset, input, member.StructMemberExpression, parent.Receiver);
                var path = parent.Property is not null && child.Property is not null
                    ? parent.Property + "." + child.Property : null;
                return parent with { Property = PolicyYaml.IsPropertyPath(path) ? path : null };
            default:
                // Container elements, sparse storage and aliases are not guessed.
                return new(null, null, "unknown");
        }
    }

    private static bool IsLocal(UAsset asset, KismetPropertyPointer? pointer, int function)
    {
        if (function <= 0 || function > asset.Exports.Count || asset.Exports[function - 1] is not FunctionExport declaration) return false;
        if (pointer?.New is { } path)
        {
            if (path.ResolvedOwner?.Index != function || path.Path is not { Length: 1 }
                || !PolicyYaml.IsIdentifier(TargetResolver.StoredName(path.Path[0]))) return false;
            var name = TargetResolver.StoredName(path.Path[0]);
            if (declaration.LoadedProperties is not { } properties) return false;
            FProperty? match = null;
            foreach (var field in properties)
            {
                if (field is null) return false;
                if (TargetResolver.StoredName(field.Name) != name) continue;
                if (match is not null) return false;
                match = field;
            }
            // Missing or ambiguous metadata cannot prove the destination is non-aliasing.
            return match is not null && (match.PropertyFlags & (EPropertyFlags.CPF_OutParm | EPropertyFlags.CPF_ReferenceParm)) == 0;
        }
        return pointer?.Old is { Index: > 0 } old && old.Index <= asset.Exports.Count
            && asset.Exports[old.Index - 1] is PropertyExport property && property.OuterIndex?.Index == function
            && PolicyYaml.IsIdentifier(TargetResolver.StoredName(property.ObjectName)) && property.Property is not null
            && asset.Exports.OfType<PropertyExport>().Count(candidate => candidate.OuterIndex?.Index == function
                && TargetResolver.StoredName(candidate.ObjectName) == TargetResolver.StoredName(property.ObjectName)) == 1
            && (property.Property.PropertyFlags & (EPropertyFlags.CPF_OutParm | EPropertyFlags.CPF_ReferenceParm)) == 0;
    }

    private static Destination Pointer(UAsset asset, PackageInput input, KismetPropertyPointer? pointer, string receiver)
    {
        FPackageIndex? owner = null;
        string? property = null;
        if (pointer?.New is { } path)
        {
            owner = path.ResolvedOwner;
            if (path.Path is { Length: > 0 and <= 24 })
            {
                var names = path.Path.Select(TargetResolver.StoredName).ToArray();
                if (names.All(PolicyYaml.IsIdentifier)) property = string.Join('.', names!);
            }
        }
        else if (pointer?.Old is { Index: > 0 } old && old.Index <= asset.Exports.Count
            && asset.Exports[old.Index - 1] is PropertyExport export)
        { owner = export.OuterIndex; property = TargetResolver.StoredName(export.ObjectName); }
        else if (pointer?.Old is { Index: < 0 } importIndex && -(long)importIndex.Index <= asset.Imports.Count)
        {
            var import = asset.Imports[(int)(-(long)importIndex.Index - 1)];
            if (TargetResolver.StoredName(import.ClassName)?.EndsWith("Property", StringComparison.Ordinal) == true)
            { owner = import.OuterIndex; property = TargetResolver.StoredName(import.ObjectName); }
        }
        if (!PolicyYaml.IsPropertyPath(property)) property = null;
        var validOwner = owner is { Index: > 0 } local && local.Index <= asset.Exports.Count
            ? asset.Exports[local.Index - 1] is StructExport and not FunctionExport
            : owner is { Index: < 0 } imported && -(long)imported.Index <= asset.Imports.Count
                && TargetResolver.StoredName(asset.Imports[(int)(-(long)imported.Index - 1)].ClassName) is "Class" or "ScriptStruct";
        var identity = validOwner ? TargetResolver.ResolveDataIdentity(asset, owner, input.LogicalPath) : null;
        var ownerName = identity is null ? null : identity.Owner + "." + identity.Function;
        return new(PolicyYaml.IsOwner(ownerName) ? ownerName : null, property, receiver);
    }
}
