using System.Collections.Immutable;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;

namespace PakRisk.Extraction;

internal sealed record ProvenanceSite(int Call, KismetExpression Expression, int Function, int Root);

// Policy-free backwards slicing. Unsupported flow is opaque, not an invented dependency.
internal sealed class ArgumentProvenanceExtractor(UAsset asset, List<ExtractedInvocation> calls,
    List<ProvenanceSite> sites, List<FunctionCoverage> coverage, HashSet<(int Function, int Root)> unsafeRoots)
{
    private sealed record Frame(int Function, int Before, Dictionary<string, (KismetExpression Expression, Frame Frame)> Bindings);
    private readonly Dictionary<KismetExpression, ExtractedInvocation> instructions = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<int> validFunctions = coverage.Where(f => !f.Native && f.Diagnostics.All(d =>
        d.Code is "imported-signature-unavailable" or "parameter-metadata-unavailable" or "native-target-boundary"))
        .Select(f => f.Identity.ExportIndex).ToHashSet();
    private int work;
    private int retained;
    private readonly Dictionary<int, bool> straightLine = [];
    private readonly HashSet<int> returnSafe = [];

    internal void Enrich()
    {
        foreach (var site in sites) instructions.TryAdd(site.Expression, calls[site.Call]);
        foreach (var index in validFunctions)
        {
            straightLine[index] = StraightLine((FunctionExport)asset.Exports[index - 1]);
            var function = (FunctionExport)asset.Exports[index - 1];
            if (function.LoadedProperties is { Length: <= 256 } properties && function.Children is not { Length: > 0 }
                && properties.All(p => p is not null && !p.PropertyFlags.HasFlag(EPropertyFlags.CPF_ReferenceParm)
                    && (!p.PropertyFlags.HasFlag(EPropertyFlags.CPF_OutParm) || p.PropertyFlags.HasFlag(EPropertyFlags.CPF_ReturnParm))))
                returnSafe.Add(index);
        }
        foreach (var site in sites)
        {
            var call = calls[site.Call];
            if (call.Fact.Arguments is not ArgumentMetadata.Known || Parameters(site.Expression) is not { } parameters) continue;
            var arguments = call.Arguments.ToBuilder();
            for (var i = 0; i < arguments.Count && i < parameters.Length; i++)
            {
                if (arguments[i].Value is not ArgumentValue.Dynamic || work >= 65_536) continue;
                try
                {
                    var nodes = new List<ValueOrigin>();
                    var frame = new Frame(site.Function, site.Root, new(StringComparer.Ordinal));
                    var root = Trace(parameters[i], frame, nodes, [site.Function], 0);
                    if (nodes[root].Kind == "unknown" || retained + nodes.Count > ValueProvenance.MaxAnalysisNodes) continue;
                    var graph = new ValueProvenance(root, nodes.ToImmutableArray());
                    // The same closed validation applies before emitting parser-owned evidence.
                    var probe = new InvocationFact(call.Fact.Location, call.Target,
                        new ArgumentMetadata.Known([new("Value", new ArgumentValue.Derived(graph))]));
                    PolicyEvaluator.Validate(new([probe], []));
                    retained += nodes.Count;
                    arguments[i] = arguments[i] with { Value = new ArgumentValue.Derived(graph), Reason = "value-provenance" };
                }
                catch (Exception error) when (error is ExtractionFailure or ArgumentException or InvalidOperationException)
                { /* Leave the argument Dynamic when evidence cannot be retained. */ }
            }
            var enriched = arguments.ToImmutable();
            calls[site.Call] = call with { Arguments = enriched, Fact = call.Fact with
            { Arguments = new ArgumentMetadata.Known(enriched.Where(a => a.Name is not null)
                .Select(a => new NamedArgument(a.Name!, a.Value)).ToImmutableArray()) } };
        }
    }

    private int Trace(KismetExpression expression, Frame frame, List<ValueOrigin> nodes, HashSet<int> active, int depth)
    {
        if (++work > 65_536 || depth >= 24 || nodes.Count >= 128) throw new ExtractionFailure("provenance-limit");
        var (value, _) = InvocationExtractor.Value(expression);
        if (value is ArgumentValue.Constant constant)
            return Add(new("literal", [], true, Literal: constant.Value));
        if (expression is EX_LocalVariable local && Name(local.Variable, frame.Function) is { } name)
        {
            if (!validFunctions.Contains(frame.Function) || unsafeRoots.Contains((frame.Function, frame.Before))) return Unknown();
            var function = (FunctionExport)asset.Exports[frame.Function - 1];
            var code = function.ScriptBytecode;
            // A branch/loop invalidates straight-line reaching definitions, even if it occurs later.
            if (!straightLine.GetValueOrDefault(frame.Function)) return Unknown();
            for (var index = frame.Before - 1; index >= 0; index--)
            {
                if (++work > 65_536) throw new ExtractionFailure("provenance-limit");
                var root = code[index];
                if (unsafeRoots.Contains((frame.Function, index))) return Unknown();
                var assignment = Assignment(root);
                if (assignment is { } pair && pair.Variable is EX_LocalVariable variable
                    && Name(variable.Variable, frame.Function) == name)
                    return Trace(pair.Value, frame with { Before = index }, nodes, active, depth + 1);
                // Unmodelled side effects may mutate aliases; do not reuse a stale definition.
                if (root is not (EX_Nothing or EX_EndOfScript) && assignment is null) return Unknown();
                if (assignment is { } target && target.Variable is not EX_LocalVariable) return Unknown();
                if (assignment is { } other && InvocationExtractor.Value(other.Value).Item1 is not ArgumentValue.Constant)
                    return Unknown();
            }
            if (frame.Bindings.TryGetValue(name, out var binding))
                return Trace(binding.Expression, binding.Frame, nodes, active, depth + 1);
            return Unknown();
        }
        if (instructions.TryGetValue(expression, out var call) && Parameters(expression) is { } parameters)
        {
            var arguments = ImmutableArray.CreateBuilder<OriginArgument>();
            var completeArguments = call.Fact.Arguments is ArgumentMetadata.Known && call.Arguments.Length == parameters.Length;
            // Keep all known parameter expressions, but not as presumed return dependencies.
            for (var i = 0; i < parameters.Length; i++)
            {
                var input = Trace(parameters[i], frame, nodes, active, depth + 1);
                if (i < call.Arguments.Length && call.Arguments[i].Name is { } parameterName)
                    arguments.Add(new(parameterName, input));
            }
            var result = Return(expression, call, parameters, frame, nodes, active, depth + 1);
            return Add(new("call", result is { } returned ? [returned] : [], result is not null,
                call.Target, completeArguments ? arguments.ToImmutable() : null));
        }
        return Unknown();

        int Add(ValueOrigin origin) { nodes.Add(origin); return nodes.Count - 1; }
        int Unknown() => Add(new("unknown", [], false));
    }

    private int? Return(KismetExpression expression, ExtractedInvocation call, KismetExpression[] parameters,
        Frame caller, List<ValueOrigin> nodes, HashSet<int> active, int depth)
    {
        if (expression is not EX_FinalFunction direct || expression is EX_CallMulticastDelegate
            || call.Target is not InvocationTarget.Resolved || direct.StackNode.Index <= 0
            || direct.StackNode.Index > asset.Exports.Count || !validFunctions.Contains(direct.StackNode.Index)
            || call.Fact.Arguments is not ArgumentMetadata.Known known || known.Arguments.Length != parameters.Length)
            return null;
        var index = direct.StackNode.Index;
        var function = (FunctionExport)asset.Exports[index - 1];
        if (!straightLine.GetValueOrDefault(index) || !returnSafe.Contains(index)
            || active.Count >= 16 || !active.Add(index)) return null;
        try
        {
            var bindings = new Dictionary<string, (KismetExpression, Frame)>(StringComparer.Ordinal);
            for (var i = 0; i < parameters.Length; i++) bindings.Add(known.Arguments[i].Name, (parameters[i], caller));
            var code = function.ScriptBytecode;
            for (var root = 0; root < code.Length; root++)
            {
                if (++work > 65_536) throw new ExtractionFailure("provenance-limit");
                if (code[root] is EX_Return returned)
                    return Trace(returned.ReturnExpression, new(index, root, bindings), nodes, active, depth + 1);
            }
            return null;
        }
        finally { active.Remove(index); }
    }

    private static bool StraightLine(FunctionExport function) => function.ScriptBytecode is { } code
        && code.All(root => root is EX_FinalFunction or EX_VirtualFunction or EX_Let or EX_LetBool
            or EX_LetObj or EX_LetWeakObjPtr or EX_Return or EX_EndOfScript or EX_Nothing)
        && code.Count(root => root is EX_Return) <= 1;

    private string? Name(KismetPropertyPointer pointer, int function)
    {
        if (pointer.New is { } path && path.ResolvedOwner?.Index == function && path.Path is { Length: 1 })
            return PolicyYaml.IsIdentifier(path.Path[0]?.ToString()) ? path.Path[0]!.ToString() : null;
        if (pointer.Old is { Index: > 0 } old && old.Index <= asset.Exports.Count
            && asset.Exports[old.Index - 1] is PropertyExport property && property.OuterIndex?.Index == function)
            return PolicyYaml.IsIdentifier(property.ObjectName?.ToString()) ? property.ObjectName!.ToString() : null;
        return null;
    }

    private static (KismetExpression Variable, KismetExpression Value)? Assignment(KismetExpression root) => root switch
    {
        EX_Let let => (let.Variable, let.Expression),
        EX_LetBool let => (let.VariableExpression, let.AssignmentExpression),
        EX_LetObj let => (let.VariableExpression, let.AssignmentExpression),
        _ => null
    };

    private static KismetExpression[]? Parameters(KismetExpression expression) => expression switch
    {
        EX_FinalFunction call => call.Parameters,
        EX_VirtualFunction call => call.Parameters,
        _ => null
    };
}
