using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using YamlDotNet.Core;
using static PakRisk.Policy.YamlTree;

namespace PakRisk.Policy;

public static partial class PolicyYaml
{
    public const int SchemaVersion = 1;
    public const int MaxInputBytes = MaxBytes;
    public const int MaxYamlDepth = MaxDepth;
    public const int MaxYamlNodes = MaxNodes;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.KebabCaseLower,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter<RuleEffect>(JsonNamingPolicy.KebabCaseLower, allowIntegerValues: false) }
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
            var rule = Object(node, "id", "description", "effect", "match");
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
            return new PolicyRule(id, description, effect, Expression(rule.Fields["match"]));
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
        return Kind(node) switch
        {
            "all" => new MatchExpression.All(Expressions(node)),
            "any" => new MatchExpression.Any(Expressions(node)),
            "not" => new MatchExpression.Not(Expression(Object(node, "kind", "expression").Fields["expression"])),
            "invocation" => new MatchExpression.Invocation(Target(Object(node, "kind", "target").Fields["target"])),
            "argument" => Argument(node),
            _ => throw Error("unknown-expression-kind", node.Mark)
        };
    }

    private static ImmutableArray<MatchExpression> Expressions(Node node) =>
        Array(Object(node, "kind", "expressions").Fields["expressions"]).Items.Select(Expression).ToImmutableArray();

    private static MatchExpression.Argument Argument(Node node)
    {
        var fields = Object(node, "kind", "name", "predicate").Fields;
        var name = String(fields["name"]);
        if (!Identifier().IsMatch(name))
            throw Error("invalid-argument-name", fields["name"].Mark);
        return new MatchExpression.Argument(name, Predicate(fields["predicate"]));
    }

    private static TargetMatcher Target(Node node)
    {
        switch (Kind(node))
        {
            case "exact":
                var exact = Object(node, "kind", "owner", "function").Fields;
                var function = String(exact["function"]);
                if (!Identifier().IsMatch(function))
                    throw Error("invalid-function-name", exact["function"].Mark);
                return new TargetMatcher.Exact(Owner(exact["owner"]), function);
            case "owner":
                return new TargetMatcher.ByOwner(Owner(Object(node, "kind", "owner").Fields["owner"]));
            default:
                throw Error("unknown-target-kind", node.Mark);
        }
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
                if (values.Select(value => value.GetType()).Distinct().Count() != 1)
                    throw Error("mixed-literal-types", node.Mark);
                if (values.Distinct().Count() != values.Length)
                    throw Error("duplicate-literal", node.Mark);
                return new ValuePredicate.In(values);
            case "string-starts-with":
                return new ValuePredicate.StringStartsWith(String(Object(node, "kind", "prefix").Fields["prefix"]));
            case "url-host-in":
                var hosts = Array(Object(node, "kind", "hosts").Fields["hosts"]).Items.Select(Host).ToImmutableArray();
                if (hosts.Distinct(StringComparer.Ordinal).Count() != hosts.Length)
                    throw Error("duplicate-host", node.Mark);
                return new ValuePredicate.UrlHostIn(hosts);
            default:
                throw Error("unknown-predicate-kind", node.Mark);
        }
    }

    private static PolicyLiteral Literal(Node node)
    {
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
            default:
                throw Error("unknown-literal-kind", node.Mark);
        }
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
    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex HostLabel();
    [GeneratedRegex("^[+-]?(?:0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|[0-9][0-9_]*|\\.(?:inf|Inf|INF|nan|NaN|NAN))$", RegexOptions.CultureInvariant)]
    private static partial Regex YamlNumber();

    internal static bool IsIdentifier(string? value) => value is not null && value.Length <= 4096 && !value.Any(char.IsControl) && Identifier().IsMatch(value);
    internal static bool IsOwner(string? value) => value is not null && value.Length <= 4096 && !value.Any(char.IsControl) && OwnerPath().IsMatch(value);
}
