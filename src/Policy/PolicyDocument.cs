using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace PakRisk.Policy;

public sealed record PolicyDocument(int SchemaVersion, ImmutableArray<PolicyRule> Rules);

public sealed record PolicyRule(string Id, string Description, RuleEffect Effect,
    [property: JsonPropertyName("expression")] MatchExpression Match);

public enum RuleEffect { Flag, Forbid }

public abstract record MatchExpression
{
    private MatchExpression() { }
    public sealed record All(ImmutableArray<MatchExpression> Expressions) : MatchExpression;
    public sealed record Any(ImmutableArray<MatchExpression> Expressions) : MatchExpression;
    public sealed record Not(MatchExpression Expression) : MatchExpression;
    public sealed record Invocation(TargetMatcher Target, ImmutableArray<Argument>? Args = null) : MatchExpression;
    public sealed record Argument(string Name, ValuePredicate Predicate, bool Wildcard = false) : MatchExpression;
    public sealed record PropertyWrite(string? Owner, string? Property, ValuePredicate? Predicate = null) : MatchExpression;
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(TargetMatcher.Exact), "exact")]
[JsonDerivedType(typeof(TargetMatcher.ByOwner), "owner")]
[JsonDerivedType(typeof(TargetMatcher.Pattern), "pattern")]
public abstract record TargetMatcher
{
    private TargetMatcher() { }
    public sealed record Exact(string Owner, string Function) : TargetMatcher;
    public sealed record ByOwner(string Owner) : TargetMatcher;
    // Null removes that selector's constraint; HasFunction preserves args validation.
    public sealed record Pattern(string? Owner, string? Function, bool HasFunction = true) : TargetMatcher;
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(ValuePredicate.EqualTo), "equals")]
[JsonDerivedType(typeof(ValuePredicate.In), "in")]
[JsonDerivedType(typeof(ValuePredicate.RegexMatch), "regex-match")]
[JsonDerivedType(typeof(ValuePredicate.UrlHostIn), "url-host-in")]
[JsonDerivedType(typeof(ValuePredicate.SubexprMatch), "subexpr-match")]
public abstract record ValuePredicate
{
    private ValuePredicate() { }
    public sealed record EqualTo(PolicyLiteral Value) : ValuePredicate;
    public sealed record In(ImmutableArray<PolicyLiteral> Values) : ValuePredicate;
    public sealed record RegexMatch(string Pattern) : ValuePredicate;
    public sealed record UrlHostIn(ImmutableArray<string> Hosts) : ValuePredicate;
    public sealed record SubexprMatch(MatchExpression Subexpr) : ValuePredicate;
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(PolicyLiteral.String), "string")]
[JsonDerivedType(typeof(PolicyLiteral.Integer), "integer")]
[JsonDerivedType(typeof(PolicyLiteral.Boolean), "boolean")]
[JsonDerivedType(typeof(PolicyLiteral.Null), "null")]
[JsonDerivedType(typeof(PolicyLiteral.Number), "number")]
[JsonDerivedType(typeof(PolicyLiteral.Wildcard), "wildcard")]
public abstract record PolicyLiteral
{
    private PolicyLiteral() { }
    public sealed record String(string Value) : PolicyLiteral;
    public sealed record Integer(long Value) : PolicyLiteral;
    public sealed record Boolean(bool Value) : PolicyLiteral;
    public sealed record Null : PolicyLiteral;
    public sealed record Number(double Value) : PolicyLiteral;
    // Policy pattern only; never valid as a fact value.
    public sealed record Wildcard : PolicyLiteral;
}
