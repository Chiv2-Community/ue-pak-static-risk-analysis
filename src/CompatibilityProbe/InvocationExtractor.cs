using System.Collections.Immutable;
using CompatibilityProbe;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;
using UAssetAPI.Unversioned;

namespace PakRisk.Extraction;

public static class InvocationExtractor
{
    private static readonly HashSet<Type> KnownExports = [typeof(NormalExport), typeof(RawExport), typeof(FunctionExport),
        typeof(ClassExport), typeof(StructExport), typeof(UserDefinedStructExport), typeof(PropertyExport),
        typeof(ActorComponentExport), typeof(SceneComponentExport), typeof(LevelExport), typeof(EnumExport),
        typeof(DataTableExport), typeof(StringTableExport), typeof(MetaDataExport), typeof(AssetImportDataExport)];

    internal static void ValidateInput(PackageInput input)
    {
        foreach (var text in new[] { input.Pak, input.Entry, input.LogicalPath })
            if (string.IsNullOrWhiteSpace(text) || text.Length > 1024 || text.Any(char.IsControl))
                throw new ArgumentException("Invalid package identity.", nameof(input));
        foreach (var text in new[] { input.Pak, input.Entry, input.LogicalPath })
            if (!ValidUnicode(text)) throw new ArgumentException("Invalid package identity.", nameof(input));
    }

    internal static bool ValidUnicode(string text)
    {
        for (var i = 0; i < text.Length; i++)
            if (char.IsSurrogate(text[i]) && (!char.IsHighSurrogate(text[i]) || ++i == text.Length || !char.IsLowSurrogate(text[i]))) return false;
        return true;
    }

    public static ExtractionReport Read(PackageInput input, Usmap? mappings = null, ExtractionLimits? limits = null,
        ArchiveDispatchContext? archiveContext = null)
    {
        limits ??= new();
        limits.Validate();
        ValidateInput(input);
        try { return Inspect(PackageReader.Read(input.StoragePath, mappings), input, limits, archiveContext); }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            return Report(input, [], [], [new("package-read-failed")]);
        }
    }

    public static ExtractionReport Inspect(UAsset asset, PackageInput input, ExtractionLimits? limits = null,
        ArchiveDispatchContext? archiveContext = null)
    {
        limits ??= new();
        limits.Validate();
        ValidateInput(input);
        var calls = new List<ExtractedInvocation>();
        var writes = new List<PropertyWriteFact>();
        var writeCharacters = 0;
        var functions = new List<FunctionCoverage>();
        var diagnostics = new List<ExtractionDiagnostic>();
        if (!asset.PackageFlags.HasFlag(EPackageFlags.PKG_Cooked) && !asset.IsFilterEditorOnly)
            diagnostics.Add(new("no-cooked-or-filtered-marker"));
        if (asset.HasUnversionedProperties && asset.Mappings is null)
            diagnostics.Add(new("missing-property-mappings"));
        if (asset.Exports.Count > limits.MaxExports) diagnostics.Add(new("export-limit"));
        var budget = 0;
        var evidenceBudget = 0;
        var metadataBudget = 0;
        var signatures = new Dictionary<int, (List<string>? Names, string? Error)>();
        var byValueSignatures = new Dictionary<int, bool>();
        IndirectDispatchResolver? indirect = null;
        try { indirect = new(asset, input, limits, archiveContext); }
        catch (Exception error) when (error is not OutOfMemoryException) { diagnostics.Add(new("indirect-analysis-failed")); }
        var dispatches = new List<IndirectDispatch>();
        var provenanceSites = new List<ProvenanceSite>();
        var unsafeProvenanceRoots = new HashSet<(int Function, int Root)>();
        for (var i = 0; i < Math.Min(asset.Exports.Count, limits.MaxExports); i++)
        {
            var export = asset.Exports[i];
            var index = i + 1;
            if (export is null || !KnownExports.Contains(export.GetType()))
                diagnostics.Add(new("unsupported-export", index));
            if (export is RawExport) diagnostics.Add(new("raw-export", index));
            if (export is ClassExport nativeClass && nativeClass.ClassFlags.HasFlag(EClassFlags.CLASS_Native))
                diagnostics.Add(new("native-class-boundary", index));
            if (export is not FunctionExport function)
            {
                if (export is StructExport structure &&
                    (structure.ScriptBytecode is { Length: > 0 } || structure.ScriptBytecodeSize != 0 ||
                     structure.ScriptBytecodeRaw is { Length: > 0 }))
                    diagnostics.Add(new("unsupported-script-export", index));
                continue;
            }
            var local = new List<ExtractionDiagnostic>();
            var resolved = TargetResolver.ResolveIdentity(asset, new(index), input.LogicalPath);
            var identity = new FunctionIdentity(resolved?.Owner ?? input.LogicalPath,
                resolved?.Function ?? "<unresolved>", index);
            if (resolved is null) local.Add(new("containing-function-identity-unresolved", index));
            if (identity.Qualified.Length > PolicyEvaluator.MaxFactStringLength || identity.Qualified.Any(char.IsControl) || !ValidUnicode(identity.Qualified))
            {
                identity = new(input.LogicalPath, "<unresolved>", index);
                local.Add(new("containing-function-identity-unresolved", index));
            }
            var native = function.FunctionFlags.HasFlag(EFunctionFlags.FUNC_Native);
            if (native) local.Add(new("native-function-boundary", index));
            var visited = 0;
            uint offset = 0;
            if (function.ScriptBytecode is null) local.Add(new("unparsed-bytecode", index));
            else if (function.ScriptBytecode.Length > limits.MaxArray) local.Add(new("expression-array-limit", index));
            else
            {
                for (var rootIndex = 0; rootIndex < function.ScriptBytecode.Length; rootIndex++)
                {
                    var root = function.ScriptBytecode[rootIndex];
                    try
                    {
                        var expected = ExpressionPreflight.Check(root, limits, ref budget);
                        if (expected.Skip(1).Any(item => item.Expression is EX_Let or EX_LetBase or EX_LetValueOnPersistentFrame
                            or EX_LocalOutVariable)) unsafeProvenanceRoots.Add((index, rootIndex));
                        if (expected.Any(item => item.Expression is EX_LocalVariable)
                            && expected.Skip(1).Any(item => item.Expression is EX_VirtualFunction or EX_CallMulticastDelegate
                                || item.Expression is EX_FinalFunction call && !ByValueSignature(asset, call, byValueSignatures)))
                            unsafeProvenanceRoots.Add((index, rootIndex));
                        var cursor = 0;
                        root.Visit(asset, ref offset, (node, position) =>
                        {
                            if (cursor >= expected.Count || !ReferenceEquals(expected[cursor].Expression, node))
                                throw new ExtractionFailure("visitor-sequence-mismatch");
                            var occurrence = expected[cursor++];
                            visited++;
                            try
                            {
                                var dispatch = indirect?.Inspect(identity, node, position, occurrence.Receivers);
                                if (dispatch is not null)
                                {
                                    if (dispatches.Count >= PolicyEvaluator.MaxInvocations) local.Add(new("indirect-dispatch-limit", index, position));
                                    else dispatches.Add(dispatch);
                                    local.Add(new("indirect-dispatch-incomplete", index, position));
                                }
                            }
                            catch (Exception error) when (error is not OutOfMemoryException) { local.Add(new("indirect-analysis-failed", index, position)); }
                            var callCount = calls.Count;
                            try
                            {
                                var write = PropertyWriteExtractor.Inspect(asset, input, identity, node, position, occurrence.Receivers.Length > 0);
                                if (write is not null)
                                {
                                    if (writes.Count >= PropertyWriteEvidence.MaxWrites
                                        || writeCharacters + PropertyWriteEvidence.Characters(write) > PropertyWriteEvidence.MaxCharacters)
                                        local.Add(new("property-write-limit", index, position));
                                    else
                                    {
                                        writes.Add(write);
                                        writeCharacters += PropertyWriteEvidence.Characters(write);
                                        if (write.Owner is null || write.Property is null)
                                            local.Add(new("property-write-unresolved", index, position));
                                    }
                                }
                            }
                            catch (Exception error) when (error is not OutOfMemoryException)
                            { local.Add(new("property-write-analysis-failed", index, position)); }
                            Extract(asset, input, identity, node, position, occurrence.Receivers, calls, local, limits,
                                ref evidenceBudget, ref metadataBudget, signatures);
                            if (calls.Count != callCount) provenanceSites.Add(new(callCount, node, index, rootIndex));
                            // The pinned upstream IntConstByte lacks its one-byte operand in Visit.
                            if (node.GetType() == typeof(EX_IntConstByte)) offset++;
                        });
                        if (cursor != expected.Count) throw new ExtractionFailure("visitor-sequence-mismatch");
                    }
                    catch (Exception error) when (error is not OutOfMemoryException)
                    {
                        local.Add(new(error is ExtractionFailure failure ? failure.Code : "bytecode-visit-failed", index));
                        // A failed root has unknown size; later offsets cannot be asserted.
                        break;
                    }
                }
                if (offset != function.ScriptBytecodeSize) local.Add(new("bytecode-size-mismatch", index));
            }
            functions.Add(new(identity, local.Count == 0, native, visited, local.ToImmutableArray()));
        }
        new ArgumentProvenanceExtractor(asset, calls, provenanceSites, functions, unsafeProvenanceRoots).Enrich();
        return Report(input, calls, functions, diagnostics, asset.Exports.Count, Math.Min(asset.Exports.Count, limits.MaxExports), dispatches, writes);
    }

    private static ExtractionReport Report(PackageInput input, List<ExtractedInvocation> calls,
        List<FunctionCoverage> functions, List<ExtractionDiagnostic> diagnostics, int exports = 0, int inspectedExports = 0,
        List<IndirectDispatch>? dispatches = null, List<PropertyWriteFact>? writes = null)
    {
        var all = diagnostics.Concat(functions.SelectMany(f => f.Diagnostics)).ToArray();
        var gaps = new List<CoverageGap>();
        if (all.Any(d => d.Code is "unresolved-virtual-target" or "unresolved-delegate-behavior" or "unresolved-direct-target" or "indirect-dispatch-incomplete" or "indirect-analysis-failed" or "indirect-dispatch-limit"))
            gaps.Add(CoverageGap.UnresolvedDispatch);
        if (all.Any(d => d.Code is "package-read-failed" or "unparsed-bytecode" or "raw-export" or "unsupported-instruction" or "unsupported-primitive-interface-cast" or "unsupported-string-literal-encoding" or "unsupported-unicode-string-literal-encoding" or "embedded-string-terminator"))
            gaps.Add(CoverageGap.UnsupportedParsing);
        // Missing signatures affect argument rules, not which invocations were traversed.
        // Keep corruption, count mismatches, limits, and all other diagnostics global.
        if (all.Any(d => d.Code is not ("imported-signature-unavailable" or "parameter-metadata-unavailable")))
            gaps.Add(CoverageGap.IncompleteExtraction);
        var graphFunctions = functions.Where(f => PolicyYaml.IsOwner(f.Identity.Owner) && PolicyYaml.IsIdentifier(f.Identity.Name)
            && !f.Diagnostics.Any(d => d.Code == "containing-function-identity-unresolved")).ToArray();
        var graph = CallGraphContext.Bounded(graphFunctions.Select(f => new CallGraphFunction(input.FactIdentity, f.Identity.Qualified,
                f.Identity.Owner, f.Identity.Name, f.Native)), graphFunctions.Length == functions.Count
            && all.All(d => d.Code is "imported-signature-unavailable" or "parameter-metadata-unavailable"));
        return new(input, exports, inspectedExports, calls.ToImmutableArray(), functions.ToImmutableArray(), diagnostics.ToImmutableArray(),
            new(calls.Select(c => c.Fact).ToImmutableArray(), gaps.ToImmutableArray(), dispatches is { Count: > 0 } ? dispatches.ToArray() : null, graph,
                new(!gaps.Contains(CoverageGap.IncompleteExtraction) && !gaps.Contains(CoverageGap.UnsupportedParsing), (writes ?? []).ToImmutableArray())));
    }

    private static void Extract(UAsset asset, PackageInput input, FunctionIdentity containing,
        KismetExpression node, uint offset, ImmutableArray<ReceiverEvidence> receivers,
        List<ExtractedInvocation> calls, List<ExtractionDiagnostic> diagnostics, ExtractionLimits limits,
        ref int evidenceBudget, ref int metadataBudget, Dictionary<int, (List<string>? Names, string? Error)> signatures)
    {
        void Gap(string code) => diagnostics.Add(new(code, containing.ExportIndex, offset));
        var dispatch = "direct";
        int? targetIndex = null;
        string? name = null;
        TargetResolver.Identity? resolvedIdentity = null;
        InvocationTarget target = new InvocationTarget.Unresolved();
        KismetExpression[] parameters;
        if (node is EX_CallMulticastDelegate multicast)
        {
            dispatch = "multicast-delegate";
            parameters = multicast.Parameters;
            targetIndex = multicast.StackNode?.Index;
            receivers = receivers.Add(new(multicast.Delegate.Token.ToString(), null, null));
            Gap("unresolved-delegate-behavior");
        }
        else if (node is EX_FinalFunction direct)
        {
            parameters = direct.Parameters;
            targetIndex = direct.StackNode?.Index;
            var identity = TargetResolver.ResolveIdentity(asset, direct.StackNode, input.LogicalPath);
            var functionReference = targetIndex is > 0 && targetIndex <= asset.Exports.Count
                ? asset.Exports[targetIndex.Value - 1] is FunctionExport
                : targetIndex is < 0 && -(long)targetIndex.Value <= asset.Imports.Count &&
                  asset.Imports[(int)(-(long)targetIndex.Value - 1)]?.ClassName?.ToString() == "Function";
            if (identity is null || !functionReference) Gap("unresolved-direct-target");
            else
            {
                resolvedIdentity = identity;
                if (PolicyYaml.IsOwner(identity.Owner) && PolicyYaml.IsIdentifier(identity.Function))
                    target = new InvocationTarget.Resolved(identity.Owner, identity.Function);
                else Gap("policy-target-unrepresentable");
                name = identity.Function;
            }
        }
        else if (node is EX_VirtualFunction virtualCall)
        {
            dispatch = "virtual";
            parameters = virtualCall.Parameters;
            name = virtualCall.VirtualFunctionName?.ToString();
            Gap("unresolved-virtual-target");
        }
        else
        {
            if (node.Token is EExprToken.EX_BindDelegate or EExprToken.EX_InstanceDelegate or
                EExprToken.EX_AddMulticastDelegate or EExprToken.EX_RemoveMulticastDelegate or EExprToken.EX_ClearMulticastDelegate)
                Gap("unresolved-delegate-behavior");
            return;
        }

        var metadataState = "unavailable";
        List<string>? names = null;
        // A multicast StackNode describes a signature, never the eventual dispatch target.
        if (targetIndex is > 0 && targetIndex <= asset.Exports.Count && asset.Exports[targetIndex.Value - 1] is FunctionExport signature)
        {
            if (signature.FunctionFlags.HasFlag(EFunctionFlags.FUNC_Native)) Gap("native-target-boundary");
            if (!signatures.TryGetValue(targetIndex.Value, out var cached))
            {
                try { cached = (ParameterNames(asset, signature, targetIndex.Value, limits, ref metadataBudget), null); }
                catch (Exception error) when (error is not OutOfMemoryException)
                {
                    cached = (null, error is ExtractionFailure failure ? failure.Code : "parameter-metadata-invalid");
                }
                signatures.Add(targetIndex.Value, cached);
            }
            names = cached.Names;
            metadataState = "known";
            if (cached.Error is not null)
            {
                metadataState = cached.Error == "parameter-metadata-unavailable" ? "unavailable" : "malformed";
                Gap(cached.Error);
            }
        }
        else Gap(targetIndex is < 0 ? "imported-signature-unavailable" : "parameter-metadata-unavailable");
        var arguments = new List<ArgumentEvidence>();
        if (calls.Count >= PolicyEvaluator.MaxInvocations) throw new ExtractionFailure("invocation-limit");
        var argumentCount = Math.Max(parameters.Length, names?.Count ?? 0);
        if (evidenceBudget + argumentCount > limits.MaxOccurrences) throw new ExtractionFailure("argument-evidence-limit");
        evidenceBudget += argumentCount;
        for (var i = 0; i < Math.Max(parameters.Length, names?.Count ?? 0); i++)
        {
            var parameter = i < parameters.Length ? parameters[i] : null;
            var (value, reason) = Value(parameter);
            if (reason is "unsupported-constant-type") Gap(reason);
            arguments.Add(new(i, names is not null && i < names.Count ? names[i] : null,
                parameter?.Token.ToString() ?? "missing", value, reason));
        }
        if (names is not null && parameters.Length != names.Count) Gap("argument-count-mismatch");
        if (names is { Count: > PolicyEvaluator.MaxArguments })
        {
            Gap("policy-argument-limit");
            metadataState = "policy-limit";
        }
        ArgumentMetadata metadata = names is null || names.Count > PolicyEvaluator.MaxArguments ? new ArgumentMetadata.Unavailable() :
            new ArgumentMetadata.Known(arguments.Where(a => a.Name is not null)
                .Select(a => new NamedArgument(a.Name!, a.Value)).ToImmutableArray());
        var fact = new InvocationFact(new(input.FactIdentity, containing.Qualified, offset), target, metadata);
        calls.Add(new(containing, offset, node.Token.ToString(), dispatch, targetIndex, name, resolvedIdentity, target,
            receivers, metadataState, arguments.ToImmutableArray(), fact));
    }

    private static List<string> ParameterNames(UAsset asset, FunctionExport function, int owner, ExtractionLimits limits, ref int budget)
    {
        var names = new List<string>();
        var seenNames = new HashSet<string>(StringComparer.Ordinal);
        void Add(FName? name, EPropertyFlags flags)
        {
            if (!flags.HasFlag(EPropertyFlags.CPF_Parm) || flags.HasFlag(EPropertyFlags.CPF_ReturnParm)) return;
            var text = name?.ToString();
            if (string.IsNullOrEmpty(text) || !PolicyYaml.IsIdentifier(text) || text.Length > limits.MaxLiteral || !seenNames.Add(text))
                throw new ExtractionFailure("parameter-metadata-invalid");
            names.Add(text);
        }
        if (function.LoadedProperties is { Length: > 0 } ||
            (function.LoadedProperties is not null && function.Children is not { Length: > 0 }))
        {
            if (function.LoadedProperties.Length > limits.MaxArray) throw new ExtractionFailure("parameter-metadata-limit");
            budget += function.LoadedProperties.Length;
            if (budget > limits.MaxOccurrences) throw new ExtractionFailure("parameter-metadata-limit");
            foreach (var property in function.LoadedProperties)
            {
                if (property is null) throw new ExtractionFailure("parameter-metadata-invalid");
                Add(property.Name, property.PropertyFlags);
            }
            return names;
        }
        if (function.Children is null) throw new ExtractionFailure("parameter-metadata-unavailable");
        if (function.Children.Length > limits.MaxArray) throw new ExtractionFailure("parameter-metadata-limit");
        var seen = new HashSet<int>();
        foreach (var child in function.Children)
        {
            if (child is null) throw new ExtractionFailure("parameter-metadata-invalid");
            var current = child.Index;
            while (current != 0)
            {
                if (++budget > limits.MaxOccurrences) throw new ExtractionFailure("parameter-metadata-limit");
                if (!seen.Add(current) || seen.Count > limits.MaxArray || current < 1 || current > asset.Exports.Count)
                    throw new ExtractionFailure("parameter-metadata-invalid");
                if (asset.Exports[current - 1] is not PropertyExport property || property.Property is null || property.OuterIndex?.Index != owner)
                    throw new ExtractionFailure("parameter-metadata-invalid");
                Add(property.ObjectName, property.Property.PropertyFlags);
                current = property.Property.Next?.Index ?? 0;
            }
        }
        return names;
    }

    internal static (ArgumentValue, string) Value(KismetExpression? expression)
    {
        if (expression is null) return (new ArgumentValue.Missing(), "missing-argument");
        PolicyLiteral? literal = expression switch
        {
            EX_StringConst text when text.Value.Length <= PolicyEvaluator.MaxFactStringLength => new PolicyLiteral.String(text.Value),
            EX_UnicodeStringConst text when text.Value.Length <= PolicyEvaluator.MaxFactStringLength => new PolicyLiteral.String(text.Value),
            EX_IntConst integer => new PolicyLiteral.Integer(integer.Value),
            EX_Int64Const integer => new PolicyLiteral.Integer(integer.Value),
            EX_IntConstByte integer => new PolicyLiteral.Integer(integer.Value),
            EX_IntZero => new PolicyLiteral.Integer(0),
            EX_IntOne => new PolicyLiteral.Integer(1),
            EX_FloatConst number when float.IsFinite(number.Value) => new PolicyLiteral.Number(number.Value),
            EX_True => new PolicyLiteral.Boolean(true),
            EX_False => new PolicyLiteral.Boolean(false),
            EX_NoObject or EX_NoInterface => new PolicyLiteral.Null(),
            _ => null
        };
        if (literal is not null) return (new ArgumentValue.Constant(literal), "constant");
        var unsupported = expression.Token.ToString().Contains("Const", StringComparison.Ordinal);
        return (new ArgumentValue.Dynamic(), unsupported ? "unsupported-constant-type" : "runtime-expression");
    }

    private static bool ByValueSignature(UAsset asset, EX_FinalFunction call, Dictionary<int, bool> cache)
    {
        var index = call.StackNode.Index;
        if (cache.TryGetValue(index, out var safe)) return safe;
        safe = index > 0 && index <= asset.Exports.Count && asset.Exports[index - 1] is FunctionExport function
            && function.LoadedProperties is { Length: <= 256 } properties && function.Children is not { Length: > 0 }
            && properties.All(p => p is not null && !p.PropertyFlags.HasFlag(EPropertyFlags.CPF_ReferenceParm)
                && (!p.PropertyFlags.HasFlag(EPropertyFlags.CPF_OutParm) || p.PropertyFlags.HasFlag(EPropertyFlags.CPF_ReturnParm)));
        cache[index] = safe;
        return safe;
    }
}
