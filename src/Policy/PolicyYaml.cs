using System.Collections.Immutable;
using System.Globalization;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using YamlDotNet.Core;
using static PakRisk.Policy.YamlTree;

namespace PakRisk.Policy;

public static partial class PolicyYaml
{
    public const int SchemaVersion = 1;
    public const string Wildcard = "__WILDCARD__";
    public const int MaxInputBytes = MaxBytes;
    public const int MaxYamlDepth = MaxDepth;
    public const int MaxYamlNodes = MaxNodes;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.KebabCaseLower,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter<RuleEffect>(JsonNamingPolicy.KebabCaseLower, allowIntegerValues: false),
            new ExpressionConverter() }
    };

    public static PolicyDocument Parse(string yaml)
    {
        ArgumentNullException.ThrowIfNull(yaml);
        var root = Object(Read(yaml), "schema-version", "rules");
        var version = Number(root.Fields["schema-version"]);
        if (version != SchemaVersion)
            throw Error("unsupported-schema-version", root.Mark);
        var rulesNode = Array(root.Fields["rules"]);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var rules = rulesNode.Items.Select(node =>
        {
            var rule = Object(node, "id", "description", "effect", "expression");
            var id = String(rule.Fields["id"]);
            if (!RuleId().IsMatch(id))
                throw Error("invalid-rule-id", rule.Fields["id"].Mark);
            if (!ids.Add(id))
                throw Error("duplicate-rule-id", rule.Fields["id"].Mark);
            var description = String(rule.Fields["description"]);
            var effect = String(rule.Fields["effect"]) switch
            {
                "flag" => RuleEffect.Flag,
                "forbid" => RuleEffect.Forbid,
                _ => throw Error("unknown-effect", rule.Fields["effect"].Mark)
            };
            return new PolicyRule(id, description, effect, Expression(rule.Fields["expression"]));
        }).ToImmutableArray();
        return new PolicyDocument(SchemaVersion, rules);
    }

    // JSON is the canonical YAML 1.2 subset. Writing does not log anything.
    // Revalidation prevents callers from emitting invalid hand-constructed ASTs.
    public static string Write(PolicyDocument document)
    {
        var yaml = JsonSerializer.Serialize(document, JsonOptions) + "\n";
        _ = Parse(yaml);
        return yaml;
    }

    private static MatchExpression Expression(Node node)
    {
        if (node is not Map map || map.Fields.Count != 1)
            throw Error("expected-expression", node.Mark);
        var (name, value) = map.Fields.Single();
        return name switch
        {
            "all" => new MatchExpression.All(Expressions(value)),
            "any" => new MatchExpression.Any(Expressions(value)),
            "not" => new MatchExpression.Not(Expression(value)),
            "invocation" => Invocation(value),
            "argument" => Argument(value),
            "property-write" => PropertyWrite(value),
            _ => throw Error("unknown-expression-kind", node.Mark)
        };
    }

    private static ImmutableArray<MatchExpression> Expressions(Node node) =>
        Array(node).Items.Select(Expression).ToImmutableArray();

    private static MatchExpression.Argument Argument(Node node)
    {
        var fields = Object(node, "name", "predicate").Fields;
        var (name, wildcard) = Selector(fields["name"]);
        if (!Identifier().IsMatch(name))
            throw Error("invalid-argument-name", fields["name"].Mark);
        return new MatchExpression.Argument(name, Predicate(fields["predicate"]), wildcard);
    }

    private static MatchExpression.PropertyWrite PropertyWrite(Node node)
    {
        if (node is not Map map || map.Fields.Keys.Any(key => key is not ("class" or "property" or "predicate"))
            || !map.Fields.ContainsKey("class") || !map.Fields.ContainsKey("property"))
            throw Error("invalid-property-write", node.Mark);
        var owner = OwnerSelector(map.Fields["class"]);
        var (property, wildcard) = Selector(map.Fields["property"]);
        if (!IsPropertyPath(property)) throw Error("invalid-property-path", node.Mark);
        return new(owner, wildcard ? null : property,
            map.Fields.TryGetValue("predicate", out var predicate) ? Predicate(predicate) : null);
    }

    public static bool IsPropertyPath(string? value) => value is { Length: > 0 and <= 4096 }
        && value.Split('.').All(IsIdentifier);

    private static MatchExpression.Invocation Invocation(Node node)
    {
        if (node is Text)
        {
            var parts = String(node).Split(':');
            if (parts.Length is < 1 or > 2 || parts[0] != Wildcard && !IsOwner(parts[0]))
                throw Error("invalid-owner", node.Mark);
            if (parts.Length == 1)
                return new(parts[0] == Wildcard ? new TargetMatcher.Pattern(null, null, false) : new TargetMatcher.ByOwner(parts[0]));
            if (!IsIdentifier(parts[1]))
                throw Error("invalid-function-name", node.Mark);
            return new(parts.Contains(Wildcard) ? new TargetMatcher.Pattern(parts[0] == Wildcard ? null : parts[0],
                parts[1] == Wildcard ? null : parts[1]) : new TargetMatcher.Exact(parts[0], parts[1]));
        }
        if (node is not Map map || map.Fields.Keys.Any(key => key is not ("class" or "function" or "args")))
            throw Error("invalid-invocation", node.Mark);
        if (!map.Fields.TryGetValue("function", out var functionNode))
        {
            if (map.Fields.ContainsKey("args"))
                throw Error("args-require-function", node.Mark);
            if (!map.Fields.TryGetValue("class", out var classNode))
                throw Error("missing-field", node.Mark);
            var owner = OwnerSelector(classNode);
            return new(owner is null ? new TargetMatcher.Pattern(null, null, false) : new TargetMatcher.ByOwner(owner));
        }
        var (function, functionWildcard) = Selector(functionNode);
        TargetMatcher target;
        if (function.Contains(':'))
        {
            if (map.Fields.ContainsKey("class"))
                throw Error("class-with-qualified-function", node.Mark);
            target = Invocation(functionNode).Target;
        }
        else
        {
            if (!map.Fields.TryGetValue("class", out var classNode))
                throw Error("missing-field", node.Mark);
            if (!IsIdentifier(function))
                throw Error("invalid-function-name", functionNode.Mark);
            var owner = OwnerSelector(classNode);
            target = owner is null || functionWildcard
                ? new TargetMatcher.Pattern(owner, functionWildcard ? null : function)
                : new TargetMatcher.Exact(owner, function);
        }
        ImmutableArray<MatchExpression.Argument>? args = null;
        if (map.Fields.TryGetValue("args", out var argsNode))
            args = Array(argsNode).Items.Select(item => Expression(item) as MatchExpression.Argument
                ?? throw Error("expected-argument", item.Mark)).ToImmutableArray();
        return new(target, args);
    }

    private sealed class ExpressionConverter : JsonConverter<MatchExpression>
    {
        public override MatchExpression Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options) =>
            throw new NotSupportedException();

        public override void Write(Utf8JsonWriter writer, MatchExpression value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            switch (value)
            {
                case MatchExpression.All all:
                    writer.WritePropertyName("all");
                    JsonSerializer.Serialize(writer, all.Expressions, options);
                    break;
                case MatchExpression.Any any:
                    writer.WritePropertyName("any");
                    JsonSerializer.Serialize(writer, any.Expressions, options);
                    break;
                case MatchExpression.Not not:
                    writer.WritePropertyName("not");
                    JsonSerializer.Serialize(writer, not.Expression, options);
                    break;
                case MatchExpression.Invocation invocation:
                    writer.WritePropertyName("invocation");
                    writer.WriteStartObject();
                    switch (invocation.Target)
                    {
                        case TargetMatcher.Exact exact:
                            if (!IsOwner(exact.Owner)) throw new InvalidOperationException("Invalid policy document.");
                            writer.WriteString("class", exact.Owner);
                            WriteSelector(writer, "function", exact.Function, false);
                            break;
                        case TargetMatcher.ByOwner owner:
                            if (!IsOwner(owner.Owner)) throw new InvalidOperationException("Invalid policy document.");
                            writer.WriteString("class", owner.Owner);
                            break;
                        case TargetMatcher.Pattern pattern:
                            if (pattern.Owner is not null && !IsOwner(pattern.Owner)
                                || !pattern.HasFunction && pattern.Function is not null)
                                throw new InvalidOperationException("Invalid policy document.");
                            writer.WriteString("class", pattern.Owner ?? Wildcard);
                            if (pattern.HasFunction) WriteSelector(writer, "function", pattern.Function ?? Wildcard, pattern.Function is null);
                            break;
                        default: throw new InvalidOperationException("Invalid policy document.");
                    }
                    if (invocation.Args is { } args)
                    {
                        writer.WritePropertyName("args");
                        JsonSerializer.Serialize(writer, args.Cast<MatchExpression>().ToImmutableArray(), options);
                    }
                    writer.WriteEndObject();
                    break;
                case MatchExpression.Argument argument:
                    writer.WritePropertyName("argument");
                    writer.WriteStartObject();
                    WriteSelector(writer, "name", argument.Name, argument.Wildcard);
                    writer.WritePropertyName("predicate");
                    JsonSerializer.Serialize(writer, argument.Predicate, options);
                    writer.WriteEndObject();
                    break;
                case MatchExpression.PropertyWrite write:
                    if (write.Owner is not null && !IsOwner(write.Owner)) throw new InvalidOperationException("Invalid policy document.");
                    writer.WritePropertyName("property-write");
                    writer.WriteStartObject();
                    writer.WriteString("class", write.Owner ?? Wildcard);
                    WriteSelector(writer, "property", write.Property ?? Wildcard, write.Property is null);
                    if (write.Predicate is not null)
                    {
                        writer.WritePropertyName("predicate");
                        JsonSerializer.Serialize(writer, write.Predicate, options);
                    }
                    writer.WriteEndObject();
                    break;
                default: throw new InvalidOperationException("Invalid policy document.");
            }
            writer.WriteEndObject();
        }
    }

    private static (string Value, bool Wildcard) Selector(Node node)
    {
        if (node is Map map) return (String(Object(map, "literal").Fields["literal"]), false);
        var value = String(node);
        return (value, value == Wildcard);
    }

    private static string? OwnerSelector(Node node)
    {
        var (value, wildcard) = Selector(node);
        if (!wildcard && !IsOwner(value)) throw Error("invalid-owner", node.Mark);
        return wildcard ? null : value;
    }

    private static void WriteSelector(Utf8JsonWriter writer, string key, string value, bool wildcard)
    {
        if (wildcard && value != Wildcard) throw new InvalidOperationException("Invalid policy document.");
        writer.WritePropertyName(key);
        if (!wildcard && value == Wildcard)
        {
            writer.WriteStartObject();
            writer.WriteString("literal", value);
            writer.WriteEndObject();
        }
        else writer.WriteStringValue(value);
    }

    private static string Owner(Node node)
    {
        var owner = String(node);
        if (!OwnerPath().IsMatch(owner))
            throw Error("invalid-owner", node.Mark);
        return owner;
    }

    private static ValuePredicate Predicate(Node node)
    {
        switch (Kind(node))
        {
            case "equals":
                return new ValuePredicate.EqualTo(Literal(Object(node, "kind", "value").Fields["value"]));
            case "in":
                var values = Array(Object(node, "kind", "values").Fields["values"]).Items.Select(Literal).ToImmutableArray();
                if (values.Distinct().Count() != values.Length)
                    throw Error("duplicate-literal", node.Mark);
                return new ValuePredicate.In(values);
            case "regex-match":
                var patternNode = Object(node, "kind", "pattern").Fields["pattern"];
                var pattern = String(patternNode);
                try { _ = PolicyRegex.Create(pattern); }
                catch (Exception error) when (error is ArgumentException or NotSupportedException)
                {
                    throw Error("invalid-regex-pattern", patternNode.Mark);
                }
                return new ValuePredicate.RegexMatch(pattern);
            case "url-host-in":
                var hosts = Array(Object(node, "kind", "hosts").Fields["hosts"]).Items.Select(Host).ToImmutableArray();
                if (hosts.Distinct(StringComparer.Ordinal).Count() != hosts.Length)
                    throw Error("duplicate-host", node.Mark);
                return new ValuePredicate.UrlHostIn(hosts);
            case "subexpr-match":
                var subexpr = Expression(Object(node, "kind", "subexpr").Fields["subexpr"]);
                if (HasWrite(subexpr)) throw Error("property-write-in-subexpr", node.Mark);
                return new ValuePredicate.SubexprMatch(subexpr);
            default:
                throw Error("unknown-predicate-kind", node.Mark);
        }
    }

    private static bool HasWrite(MatchExpression expression) => expression switch
    {
        MatchExpression.PropertyWrite => true,
        MatchExpression.All all => all.Expressions.Any(HasWrite),
        MatchExpression.Any any => any.Expressions.Any(HasWrite),
        MatchExpression.Not not => HasWrite(not.Expression),
        _ => false
    };

    private static PolicyLiteral Literal(Node node)
    {
        if (node is Text inferred) return InferredLiteral(inferred);
        switch (Kind(node))
        {
            case "string":
                var scalar = Scalar(Object(node, "kind", "value").Fields["value"]);
                // String literals must be quoted or block style; no YAML implicit coercion.
                if (scalar.Style is ScalarStyle.Plain or ScalarStyle.Any)
                    throw Error("string-literal-requires-quotes", scalar.Mark);
                if (scalar.Value.Length > 4096)
                    throw Error("string-literal-size-limit", scalar.Mark);
                ValidateUnicode(scalar.Value, scalar.Mark);
                return new PolicyLiteral.String(scalar.Value);
            case "integer":
                return new PolicyLiteral.Integer(Number(Object(node, "kind", "value").Fields["value"]));
            case "boolean":
                var boolean = Scalar(Object(node, "kind", "value").Fields["value"]);
                if (boolean.Style != ScalarStyle.Plain || boolean.Value is not ("true" or "false"))
                    throw Error("invalid-boolean", boolean.Mark);
                return new PolicyLiteral.Boolean(boolean.Value == "true");
            case "null":
                _ = Object(node, "kind");
                return new PolicyLiteral.Null();
            case "number":
                var number = Scalar(Object(node, "kind", "value").Fields["value"]);
                if (number.Style != ScalarStyle.Plain || !CoreFloat().IsMatch(number.Value))
                    throw Error("invalid-number", number.Mark);
                return Floating(number);
            case "wildcard":
                _ = Object(node, "kind");
                return new PolicyLiteral.Wildcard();
            default:
                throw Error("unknown-literal-kind", node.Mark);
        }
    }

    private static PolicyLiteral InferredLiteral(Text scalar)
    {
        ValidateUnicode(scalar.Value, scalar.Mark);
        if (scalar.Value.Length > 4096) throw Error("string-literal-size-limit", scalar.Mark);
        var text = scalar.Value;
        if (text == Wildcard) return new PolicyLiteral.Wildcard();
        if (scalar.Style != ScalarStyle.Plain) return new PolicyLiteral.String(text);
        if (text is "" or "~" or "null" or "Null" or "NULL") return new PolicyLiteral.Null();
        if (text is "true" or "True" or "TRUE") return new PolicyLiteral.Boolean(true);
        if (text is "false" or "False" or "FALSE") return new PolicyLiteral.Boolean(false);
        if (CoreInteger().IsMatch(text))
        {
            BigInteger integer;
            if (text.StartsWith("0x", StringComparison.Ordinal) || text.StartsWith("0o", StringComparison.Ordinal))
            {
                integer = 0;
                var radix = text[1] == 'x' ? 16 : 8;
                foreach (var digit in text[2..])
                {
                    integer = integer * radix + (char.IsAsciiDigit(digit) ? digit - '0' : char.ToLowerInvariant(digit) - 'a' + 10);
                    if (integer > long.MaxValue) throw Error("invalid-integer", scalar.Mark);
                }
            }
            else if (!BigInteger.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out integer))
                throw Error("invalid-integer", scalar.Mark);
            if (integer < long.MinValue || integer > long.MaxValue) throw Error("invalid-integer", scalar.Mark);
            return new PolicyLiteral.Integer((long)integer);
        }
        if (CoreFloat().IsMatch(text)) return Floating(scalar);
        if (text.TrimStart('+', '-').ToLowerInvariant() is ".inf" or ".nan") throw Error("invalid-number", scalar.Mark);
        return new PolicyLiteral.String(text);
    }

    private static PolicyLiteral.Number Floating(Text scalar)
    {
        if (!double.TryParse(scalar.Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var number) || !double.IsFinite(number))
            throw Error("invalid-number", scalar.Mark);
        return new(number);
    }

    private static string Host(Node node)
    {
        var host = String(node);
        // Require canonical lowercase ASCII DNS names; no URL, port, userinfo,
        // trailing dot, wildcard, IP literal, or implicit subdomain matching.
        if (host.Length > 253 || host != host.ToLowerInvariant() || Uri.CheckHostName(host) != UriHostNameType.Dns
            || !host.Contains('.') || host.Split('.').Any(label => !HostLabel().IsMatch(label)))
            throw Error("invalid-host", node.Mark);
        return host;
    }

    private static string Kind(Node node)
    {
        if (node is not Map map || !map.Fields.TryGetValue("kind", out var kind))
            throw Error("missing-kind", node.Mark);
        return String(kind);
    }

    private static Map Object(Node node, params string[] required)
    {
        if (node is not Map map)
            throw Error("expected-object", node.Mark);
        if (map.Fields.Keys.Any(key => !required.Contains(key, StringComparer.Ordinal)))
            throw Error("unknown-field", map.Mark);
        if (required.Any(key => !map.Fields.ContainsKey(key)))
            throw Error("missing-field", map.Mark);
        return map;
    }

    private static Sequence Array(Node node)
    {
        if (node is not Sequence sequence)
            throw Error("expected-array", node.Mark);
        if (sequence.Items.Count == 0)
            throw Error("empty-array", node.Mark);
        return sequence;
    }

    private static Text Scalar(Node node) => node as Text ?? throw Error("expected-scalar", node.Mark);

    private static string String(Node node)
    {
        var text = Scalar(node);
        ValidateUnicode(text.Value, text.Mark);
        if (string.IsNullOrWhiteSpace(text.Value) || text.Value.Length > 4096
            || text.Value.Any(char.IsControl))
            throw Error("invalid-string", text.Mark);
        if (text.Style == ScalarStyle.Plain && (text.Value == "~"
            || text.Value.Equals("null", StringComparison.OrdinalIgnoreCase)
            || bool.TryParse(text.Value, out _)
            || double.TryParse(text.Value, NumberStyles.Float, CultureInfo.InvariantCulture, out _)
            || YamlNumber().IsMatch(text.Value)))
            throw Error("ambiguous-string-requires-quotes", text.Mark);
        return text.Value;
    }

    private static long Number(Node node)
    {
        var text = Scalar(node);
        if (text.Style != ScalarStyle.Plain || !CanonicalInteger().IsMatch(text.Value)
            || !long.TryParse(text.Value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var number))
            throw Error("invalid-integer", text.Mark);
        return number;
    }

    [GeneratedRegex("^[a-z][a-z0-9-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex RuleId();
    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.CultureInvariant)]
    private static partial Regex Identifier();
    [GeneratedRegex("^/[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*(?:\\.[A-Za-z0-9_]+)+$", RegexOptions.CultureInvariant)]
    private static partial Regex OwnerPath();
    [GeneratedRegex("^(?:0|-?[1-9][0-9]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex CanonicalInteger();
    [GeneratedRegex("^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$", RegexOptions.CultureInvariant)]
    private static partial Regex CoreInteger();
    [GeneratedRegex("^[-+]?(?:\\.[0-9]+|[0-9]+(?:\\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex CoreFloat();
    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex HostLabel();
    [GeneratedRegex("^[+-]?(?:0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|[0-9][0-9_]*|\\.(?:inf|Inf|INF|nan|NaN|NAN))$", RegexOptions.CultureInvariant)]
    private static partial Regex YamlNumber();

    /// <summary>Checks the bounded, control-free identifier grammar used by policies and invocation facts.</summary>
    public static bool IsIdentifier(string? value) => value is not null && value.Length <= 4096 && !value.Any(char.IsControl) && Identifier().IsMatch(value);
    /// <summary>Checks the bounded, control-free owner grammar used by policies and invocation facts.</summary>
    public static bool IsOwner(string? value) => value is not null && value.Length <= 4096 && !value.Any(char.IsControl) && OwnerPath().IsMatch(value);
}
