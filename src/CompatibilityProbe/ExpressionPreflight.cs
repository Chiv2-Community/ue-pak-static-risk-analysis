using System.Collections.Immutable;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;

namespace PakRisk.Extraction;

internal sealed class ExtractionFailure(string code) : Exception
{
    public string Code { get; } = code;
}

internal sealed record ExpressionOccurrence(KismetExpression Expression, ImmutableArray<ReceiverEvidence> Receivers);

internal static class ExpressionPreflight
{
    // Exact pinned runtime types and Visit child order, not an extensible subclass allowlist.
    private static readonly Dictionary<Type, (EExprToken Token, string[] Children)> Registry = BuildRegistry();

    private static Dictionary<Type, (EExprToken, string[])> BuildRegistry()
    {
        var result = new Dictionary<Type, (EExprToken, string[])>();
        void Add(string names, params string[] children)
        {
            foreach (var name in names.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var type = typeof(EX_Nothing).Assembly.GetType($"UAssetAPI.Kismet.Bytecode.Expressions.EX_{name}", true)!;
                result.Add(type, (Enum.Parse<EExprToken>($"EX_{name}"), children));
            }
        }
        Add("Breakpoint ByteConst ClassSparseDataVariable DefaultVariable DeprecatedOp4A DoubleConst EndArray EndArrayConst EndFunctionParms EndMap EndMapConst EndOfScript EndParmValue EndSet EndSetConst EndStructConst False FloatConst InstanceDelegate InstanceVariable InstrumentationEvent Int64Const IntConst IntConstByte IntOne IntZero Jump LocalOutVariable LocalVariable NameConst NoInterface NoObject Nothing NothingInt32 ObjectConst PopExecutionFlow PropertyConst PushExecutionFlow RotationConst Self SkipOffsetConst StringConst Tracepoint TransformConst True UInt64Const UnicodeStringConst Vector3fConst VectorConst WireTracepoint BitFieldConst");
        Add("FinalFunction LocalFinalFunction CallMath VirtualFunction LocalVirtualFunction", "Parameters");
        Add("CallMulticastDelegate", "Delegate", "Parameters");
        Add("AddMulticastDelegate RemoveMulticastDelegate", "Delegate", "DelegateToAdd");
        Add("BindDelegate", "Delegate", "ObjectTerm");
        Add("ClearMulticastDelegate", "DelegateToClear");
        Add("ArrayConst MapConst SetConst", "Elements");
        Add("ArrayGetByRef", "ArrayVariable", "ArrayIndex");
        Add("Assert", "AssertExpression");
        Add("ClassContext Context Context_FailSilent", "ObjectExpression", "ContextExpression");
        Add("CrossInterfaceCast DynamicCast InterfaceToObjCast MetaCast ObjToInterfaceCast PrimitiveCast", "Target");
        Add("ComputedJump", "CodeOffsetExpression");
        Add("FieldPathConst SoftObjectConst StructConst", "Value");
        Add("InterfaceContext", "InterfaceValue");
        Add("JumpIfNot PopExecutionFlowIfNot", "BooleanExpression");
        Add("Let", "Variable", "Expression");
        Add("LetBool LetDelegate LetMulticastDelegate LetObj LetWeakObjPtr", "VariableExpression", "AssignmentExpression");
        Add("LetValueOnPersistentFrame", "AssignmentExpression");
        Add("Return", "ReturnExpression");
        Add("SetArray", "AssigningProperty", "Elements");
        Add("SetMap", "MapProperty", "Elements");
        Add("SetSet", "SetProperty", "Elements");
        Add("Skip", "SkipExpression");
        Add("StructMemberContext", "StructExpression");
        Add("SwitchValue TextConst");
        return result;
    }

    internal static List<ExpressionOccurrence> Check(KismetExpression root, ExtractionLimits limits, ref int budget)
    {
        var result = new List<ExpressionOccurrence>();
        var active = new HashSet<KismetExpression>(ReferenceEqualityComparer.Instance);
        var stack = new Stack<(KismetExpression? Node, int Depth, bool Exit, ImmutableArray<ReceiverEvidence> Receivers)>();
        stack.Push((root, 1, false, []));
        while (stack.TryPop(out var item))
        {
            var node = item.Node ?? throw new ExtractionFailure("required-expression-missing");
            if (item.Exit) { active.Remove(node); continue; }
            if (++budget > limits.MaxOccurrences) throw new ExtractionFailure("instruction-limit");
            if (item.Depth > limits.MaxDepth) throw new ExtractionFailure("expression-depth-limit");
            if (!active.Add(node)) throw new ExtractionFailure("expression-cycle");
            if (!Registry.TryGetValue(node.GetType(), out var spec) || node.Token != spec.Token)
                throw new ExtractionFailure("unsupported-instruction");
            // Pinned Read/Write omit InterfaceClass, but Visit counts its eight VM bytes.
            if (node is EX_PrimitiveCast { ConversionType: ECastToken.ObjectToInterface })
                throw new ExtractionFailure("unsupported-primitive-interface-cast");
            ValidateLiteral(node, limits, ref budget);
            result.Add(new(node, item.Receivers));
            var children = Children(node, spec.Children, limits);
            stack.Push((node, item.Depth, true, item.Receivers));
            for (var i = children.Count - 1; i >= 0; i--)
            {
                var receivers = item.Receivers;
                if (node is EX_Context context && i == 1)
                {
                    receivers = receivers.Add(Evidence(context.ObjectExpression));
                    var receiver = context.ObjectExpression;
                    while (receiver is EX_InterfaceContext wrapped)
                    {
                        receiver = wrapped.InterfaceValue;
                        if (receiver is null) throw new ExtractionFailure("required-expression-missing");
                        if (receivers.Length >= limits.MaxDepth) throw new ExtractionFailure("expression-depth-limit");
                        receivers = receivers.Add(Evidence(receiver));
                    }
                }
                if (node is EX_InterfaceContext face)
                    receivers = receivers.Add(Evidence(face.InterfaceValue));
                stack.Push((children[i], item.Depth + 1, false, receivers));
            }
        }
        return result;
    }

    private static ReceiverEvidence Evidence(KismetExpression expression) => new(expression.Token.ToString(),
        expression is EX_ObjectConst obj ? obj.Value?.Index : null,
        expression is EX_NameConst name ? name.Value?.ToString() : null);

    private static void ValidateLiteral(KismetExpression node, ExtractionLimits limits, ref int budget)
    {
        void CheckText(string text)
        {
            if (text.Length > limits.MaxLiteral) throw new ExtractionFailure("literal-limit");
            if (!InvocationExtractor.ValidUnicode(text)) throw new ExtractionFailure("invalid-unicode-literal");
        }
        foreach (var field in node.GetType().GetFields())
        {
            if (field.FieldType == typeof(UAssetAPI.UnrealTypes.FName) && field.GetValue(node) is UAssetAPI.UnrealTypes.FName fieldName)
                CheckText(fieldName.ToString());
            if (field.FieldType == typeof(UAssetAPI.UnrealTypes.FPackageIndex) && field.Name != "ArrayInnerProp" && field.GetValue(node) is null)
                throw new ExtractionFailure("required-value-missing");
            if (field.FieldType != typeof(KismetPropertyPointer)) continue;
            if (field.GetValue(node) is not KismetPropertyPointer pointer || (pointer.Old is null && pointer.New is null))
                throw new ExtractionFailure("required-value-missing");
            if (pointer.New is not { } path) continue;
            if (path.Path is null || path.ResolvedOwner is null) throw new ExtractionFailure("required-value-missing");
            if (path.Path.Length > limits.MaxArray) throw new ExtractionFailure("expression-array-limit");
            foreach (var part in path.Path)
            {
                if (++budget > limits.MaxOccurrences) throw new ExtractionFailure("instruction-limit");
                if (part is null) throw new ExtractionFailure("required-value-missing");
                CheckText(part.ToString());
            }
        }
        if ((node is EX_FinalFunction direct && direct.StackNode is null) ||
            (node is EX_VirtualFunction virtualCall && virtualCall.VirtualFunctionName is null) ||
            (node is EX_InstanceDelegate instance && instance.FunctionName is null) ||
            (node is EX_BindDelegate binding && binding.FunctionName is null))
            throw new ExtractionFailure("required-value-missing");
        // Generic scalar Value access must succeed before upstream Visit can read it.
        object? value;
        try { value = node.GetType().GetProperty("Value")?.GetValue(node); }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            throw new ExtractionFailure("invalid-expression-value");
        }
        if (node.GetType().GetProperty("Value") is not null && value is null)
            throw new ExtractionFailure("required-value-missing");
        if (value is UAssetAPI.UnrealTypes.FName name) value = name.ToString();
        if (value is string text)
        {
            CheckText(text);
            if (node is EX_StringConst or EX_UnicodeStringConst)
            {
                // Pinned Read stops at the first terminator; synthetic values must too.
                if (text.Contains('\0')) throw new ExtractionFailure("embedded-string-terminator");
                // Visit counts UTF-16 characters, but ANSI Read consumes lossy UTF-8 bytes.
                if (node is EX_StringConst && text.Any(c => c > 0x7f))
                    throw new ExtractionFailure("unsupported-string-literal-encoding");
                // Non-virtual XFERUNICODESTRING replaces malformed UTF-16 with U+FFFD.
                // The AST cannot distinguish replacement from a genuine U+FFFD literal.
                if (node is EX_UnicodeStringConst && text.Contains('\ufffd'))
                    throw new ExtractionFailure("unsupported-unicode-string-literal-encoding");
            }
        }
    }

    private static List<KismetExpression?> Children(KismetExpression node, string[] members, ExtractionLimits limits)
    {
        var children = new List<KismetExpression?>();
        void Add(object? value)
        {
            if (value is KismetExpression[] array)
            {
                if (array.Length > limits.MaxArray) throw new ExtractionFailure("expression-array-limit");
                children.AddRange(array);
            }
            else if (value is KismetExpression expression) children.Add(expression);
            else throw new ExtractionFailure("required-expression-missing");
        }
        if (node is EX_SwitchValue sw)
        {
            if (sw.Cases is null) throw new ExtractionFailure("required-expression-missing");
            if (sw.Cases.Length > limits.MaxArray) throw new ExtractionFailure("expression-array-limit");
            children.Add(sw.IndexTerm);
            foreach (var c in sw.Cases) { children.Add(c.CaseIndexValueTerm); children.Add(c.CaseTerm); }
            children.Add(sw.DefaultTerm);
        }
        else if (node is EX_TextConst text)
        {
            var value = text.Value ?? throw new ExtractionFailure("required-value-missing");
            switch (value.TextLiteralType)
            {
                case EBlueprintTextLiteralType.Empty: break;
                case EBlueprintTextLiteralType.LocalizedText:
                    children.AddRange([value.LocalizedSource, value.LocalizedKey, value.LocalizedNamespace]); break;
                case EBlueprintTextLiteralType.InvariantText: children.Add(value.InvariantLiteralString); break;
                case EBlueprintTextLiteralType.LiteralString: children.Add(value.LiteralString); break;
                case EBlueprintTextLiteralType.StringTableEntry:
                    children.AddRange([value.StringTableId, value.StringTableKey]); break;
                default: throw new ExtractionFailure("unsupported-text-literal");
            }
        }
        else foreach (var member in members)
        {
            var type = node.GetType();
            Add(type.GetField(member)?.GetValue(node) ?? type.GetProperty(member)?.GetValue(node));
        }
        return children;
    }
}
