using System.Collections.Immutable;
using System.Text.Json;

namespace PakRisk.Policy;

public sealed class PolicyEvaluator
{
    public const int MaxInvocations = 10_000;
    public const int MaxArguments = 256;
    public const int MaxFactStringLength = 4096;
    public const int MaxDispatchCandidates = 256;
    private readonly PolicyDocument policy;

    // Validate public AST construction before recursive serialization or evaluation.
    public PolicyEvaluator(PolicyDocument document)
    {
        try
        {
            if (document is null || document.Rules.IsDefaultOrEmpty || document.Rules.Length > PolicyYaml.MaxYamlNodes)
                throw new ArgumentException();
            var pending = new Stack<(MatchExpression? Expression, int Depth)>();
            var count = 0;
            var characters = 0;
            foreach (var rule in document.Rules)
            {
                CheckString(rule?.Id);
                CheckString(rule?.Description);
                pending.Push((rule?.Match, 0));
            }
            while (pending.TryPop(out var item))
            {
                if (++count > PolicyYaml.MaxYamlNodes || item.Depth > PolicyYaml.MaxYamlDepth || item.Expression is null)
                    throw new ArgumentException();
                switch (item.Expression)
                {
                    case MatchExpression.All all:
                        Push(all.Expressions, item.Depth);
                        break;
                    case MatchExpression.Any any:
                        Push(any.Expressions, item.Depth);
                        break;
                    case MatchExpression.Not not:
                        pending.Push((not.Expression, item.Depth + 1));
                        break;
                    case MatchExpression.Invocation invocation:
                        switch (invocation.Target)
                        {
                            case TargetMatcher.Exact exact:
                                CheckString(exact.Owner);
                                CheckString(exact.Function);
                                break;
                            case TargetMatcher.ByOwner owner:
                                CheckString(owner.Owner);
                                break;
                        }
                        break;
                    case MatchExpression.Argument argument:
                        CheckString(argument.Name);
                        switch (argument.Predicate)
                        {
                            case ValuePredicate.EqualTo equal:
                                CheckLiteral(equal.Value);
                                break;
                            case ValuePredicate.In set:
                                if (set.Values.IsDefaultOrEmpty || set.Values.Length > PolicyYaml.MaxYamlNodes)
                                    throw new ArgumentException();
                                foreach (var value in set.Values) CheckLiteral(value);
                                break;
                            case ValuePredicate.StringStartsWith prefix:
                                CheckString(prefix.Prefix);
                                break;
                            case ValuePredicate.UrlHostIn hosts:
                                if (hosts.Hosts.IsDefaultOrEmpty || hosts.Hosts.Length > PolicyYaml.MaxYamlNodes)
                                    throw new ArgumentException();
                                foreach (var host in hosts.Hosts) CheckString(host);
                                break;
                        }
                        break;
                }
            }
            _ = PolicyYaml.Write(document);
            policy = document;

            void Push(ImmutableArray<MatchExpression> expressions, int depth)
            {
                if (expressions.IsDefaultOrEmpty || expressions.Length + pending.Count + count > PolicyYaml.MaxYamlNodes)
                    throw new ArgumentException();
                foreach (var expression in expressions)
                    pending.Push((expression, depth + 1));
            }
            void CheckString(string? value)
            {
                if (value is null || value.Length > MaxFactStringLength || !ValidUnicode(value)
                    || (characters += value.Length) > PolicyYaml.MaxInputBytes || ++count > PolicyYaml.MaxYamlNodes)
                    throw new ArgumentException();
            }
            void CheckLiteral(PolicyLiteral? value)
            {
                if (!ValidLiteral(value) || ++count > PolicyYaml.MaxYamlNodes) throw new ArgumentException();
                if (value is PolicyLiteral.String text) CheckString(text.Value);
            }
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or JsonException or PolicyException or NullReferenceException)
        {
            throw new ArgumentException("Invalid policy document.");
        }
    }


    public PolicyEvaluation Evaluate(InvocationAnalysis analysis)
    {
        Validate(analysis);
        var findings = ImmutableArray.CreateBuilder<InvocationFinding>();
        var uncertainties = ImmutableArray.CreateBuilder<RuleUncertainty>();
        foreach (var fact in analysis.Invocations.DistinctBy(fact => fact.Location)
            .OrderBy(fact => fact.Location.Asset, StringComparer.Ordinal)
            .ThenBy(fact => fact.Location.Function, StringComparer.Ordinal).ThenBy(fact => fact.Location.Offset))
        {
            var matches = ImmutableArray.CreateBuilder<RuleMatch>();
            foreach (var rule in policy.Rules.OrderBy(rule => rule.Id, StringComparer.Ordinal))
            {
                var result = Evaluate(rule.Match, fact);
                if (result.Result == MatchResult.Match)
                    matches.Add(new RuleMatch(rule.Id, rule.Effect));
                else if (result.Result == MatchResult.Unknown)
                    uncertainties.Add(new RuleUncertainty(fact.Location, rule.Id, result.Reasons));
            }
            if (matches.Count != 0)
                findings.Add(new InvocationFinding(fact.Location, matches.ToImmutable()));
        }
        var possible = ImmutableArray.CreateBuilder<PossibleDispatchFinding>();
        foreach (var dispatch in (analysis.Dispatches ?? []).OrderBy(d => d.Origin.Asset, StringComparer.Ordinal)
            .ThenBy(d => d.Origin.Function, StringComparer.Ordinal).ThenBy(d => d.Origin.Offset))
        {
            var matches = ImmutableArray.CreateBuilder<RuleMatch>();
            foreach (var rule in policy.Rules.OrderBy(r => r.Id, StringComparer.Ordinal))
                if (dispatch.Candidates.Any(c => Evaluate(rule.Match,
                    new InvocationTarget.Resolved(c.Owner, c.Function), new ArgumentMetadata.Unavailable()).Result != MatchResult.NoMatch))
                    matches.Add(new(rule.Id, rule.Effect));
            possible.Add(new(dispatch.Origin, matches.ToImmutable()));
        }
        // Evidence is never exhaustive: callers cannot suppress this gap by dropping a transport flag.
        var gaps = analysis.CoverageGaps.AsEnumerable();
        if (analysis.Dispatches is { Length: > 0 }) gaps = gaps.Append(CoverageGap.UnresolvedDispatch);
        return new PolicyEvaluation(findings.ToImmutable(), uncertainties.ToImmutable(),
            gaps.Distinct().Order().ToImmutableArray(), possible.ToImmutable());
    }

    private sealed record Outcome(MatchResult Result, ImmutableArray<UncertaintyReason> Reasons);
    private static Outcome Known(bool matches) => new(matches ? MatchResult.Match : MatchResult.NoMatch, []);
    private static Outcome Unknown(UncertaintyReason reason) => new(MatchResult.Unknown, [reason]);

    private static Outcome Evaluate(MatchExpression expression, InvocationFact fact) => Evaluate(expression, fact.Target, fact.Arguments);

    private static Outcome Evaluate(MatchExpression expression, InvocationTarget target, ArgumentMetadata arguments) => expression switch
    {
        MatchExpression.All all => Combine(all.Expressions, target, arguments, all: true),
        MatchExpression.Any any => Combine(any.Expressions, target, arguments, all: false),
        MatchExpression.Not not => Negate(Evaluate(not.Expression, target, arguments)),
        MatchExpression.Invocation invocation => target is InvocationTarget.Resolved resolved
            ? Known(invocation.Target switch
            {
                TargetMatcher.Exact exact => exact.Owner == resolved.Owner && exact.Function == resolved.Function,
                TargetMatcher.ByOwner owner => owner.Owner == resolved.Owner,
                _ => false
            }) : Unknown(UncertaintyReason.UnresolvedTarget),
        MatchExpression.Argument argument => Evaluate(argument, arguments),
        _ => throw new InvalidOperationException("Invalid policy document.")
    };

    private static Outcome Negate(Outcome outcome) => outcome.Result == MatchResult.Unknown
        ? outcome : Known(outcome.Result == MatchResult.NoMatch);

    private static Outcome Combine(ImmutableArray<MatchExpression> expressions, InvocationTarget target, ArgumentMetadata arguments, bool all)
    {
        var reasons = new HashSet<UncertaintyReason>();
        foreach (var expression in expressions)
        {
            var outcome = Evaluate(expression, target, arguments);
            if (outcome.Result == (all ? MatchResult.NoMatch : MatchResult.Match))
                return Known(!all);
            reasons.UnionWith(outcome.Reasons);
        }
        return reasons.Count == 0 ? Known(all) : new Outcome(MatchResult.Unknown, reasons.Order().ToImmutableArray());
    }

    private static Outcome Evaluate(MatchExpression.Argument expression, ArgumentMetadata metadata)
    {
        if (metadata is not ArgumentMetadata.Known known)
            return Unknown(UncertaintyReason.ArgumentMetadataUnavailable);
        var argument = known.Arguments.FirstOrDefault(argument => argument.Name == expression.Name);
        return argument?.Value switch
        {
            ArgumentValue.Constant constant => Known(Matches(expression.Predicate, constant.Value)),
            ArgumentValue.Dynamic => Unknown(UncertaintyReason.DynamicArgument),
            _ => Unknown(UncertaintyReason.MissingArgument)
        };
    }

    private static bool Matches(ValuePredicate predicate, PolicyLiteral value) => predicate switch
    {
        ValuePredicate.EqualTo equal => equal.Value == value,
        ValuePredicate.In set => set.Values.Contains(value),
        ValuePredicate.StringStartsWith prefix => value is PolicyLiteral.String text && text.Value.StartsWith(prefix.Prefix, StringComparison.Ordinal),
        ValuePredicate.UrlHostIn hosts => value is PolicyLiteral.String text && UrlMatches(text.Value, hosts.Hosts),
        _ => false
    };

    private static bool UrlMatches(string text, ImmutableArray<string> hosts)
    {
        // Reject URI repairs, userinfo, Unicode authorities, and ambiguous delimiters.
        if (!text.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            || text.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)) || text.Contains('\\'))
            return false;
        var authority = text[8..].Split('/', '?', '#')[0];
        if (authority.Length == 0 || authority.Any(character => character > 127) || authority.Contains('@') || authority.Contains('%'))
            return false;
        var portSeparator = authority.IndexOf(':');
        if (portSeparator >= 0 && authority[portSeparator..] != ":443")
            return false;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || !uri.IsWellFormedOriginalString()
            || uri.Scheme != Uri.UriSchemeHttps || uri.HostNameType != UriHostNameType.Dns
            || uri.UserInfo.Length != 0 || uri.Port != 443 || uri.Host.EndsWith('.'))
            return false;
        return hosts.Contains(uri.IdnHost.ToLowerInvariant(), StringComparer.Ordinal);
    }

    public static void Validate(InvocationAnalysis analysis)
    {
        if (analysis is null || analysis.Invocations.IsDefault || analysis.Invocations.Length > MaxInvocations
            || analysis.CoverageGaps.IsDefault || analysis.CoverageGaps.Length > 256
            || analysis.CoverageGaps.Any(gap => !Enum.IsDefined(gap)))
            InvalidFacts();
        var locations = new Dictionary<InvocationLocation, InvocationFact>();
        if (analysis.CallGraph is { } graph)
        {
            if (graph.SchemaVersion != 1 || graph.Functions is null || graph.Functions.Length > 4096) InvalidFacts();
            var keys = new HashSet<(string, string)>();
            var characters = 0;
            foreach (var function in graph.Functions!)
                if (function is null || !Text(function.Asset) || !Text(function.LocationFunction)
                    || !PolicyYaml.IsOwner(function.Owner) || !PolicyYaml.IsIdentifier(function.Function)
                    || !keys.Add((function.Asset, function.LocationFunction))
                    || (characters += CallGraphContext.Characters(function)) > CallGraphContext.MaxCharacters) InvalidFacts();
        }
        var origins = new HashSet<InvocationLocation>();
        var candidates = 0;
        if (analysis.Dispatches is { } dispatches)
        {
            if (dispatches.Length > MaxInvocations) InvalidFacts();
            foreach (var dispatch in dispatches)
            {
                if (dispatch is null || dispatch.SchemaVersion != 1 || dispatch.Origin is null
                    || !Text(dispatch.Origin.Asset) || !Text(dispatch.Origin.Function) || dispatch.Origin.Offset < 0
                    || !origins.Add(dispatch.Origin) || !ValidDispatchOpcode(dispatch.Opcode, dispatch.Kind)
                    || dispatch.FunctionName is not null && !PolicyYaml.IsIdentifier(dispatch.FunctionName)
                    || dispatch.Receiver is not ("self" or "object" or "interface" or "unknown")
                    || dispatch.Resolution != "possible" || dispatch.Candidates.IsDefault
                    || dispatch.Candidates.Length > MaxDispatchCandidates || (candidates += dispatch.Candidates.Length) > MaxInvocations
                    || dispatch.Diagnostics.IsDefaultOrEmpty || dispatch.Diagnostics.Length > 16
                    || dispatch.Diagnostics.Distinct().Count() != dispatch.Diagnostics.Length
                    || dispatch.Diagnostics.Any(d => !DispatchDiagnostic(d))
                    || !dispatch.Diagnostics.Contains("open-world")
                    || dispatch.Source != (dispatch.Kind == "timer" ? "ue425plus-2d1aae-kismet-timer" : "kismet-serialized-v1")
                    || dispatch.Kind == "timer" && !dispatch.Diagnostics.Contains("native-build-unverified")) InvalidFacts();
                var seen = new HashSet<(string, string)>();
                foreach (var candidate in dispatch!.Candidates)
                    if (candidate is null || !PolicyYaml.IsOwner(candidate.Owner) || !PolicyYaml.IsIdentifier(candidate.Function)
                        || !string.Equals(candidate.Function, dispatch.FunctionName, StringComparison.OrdinalIgnoreCase)
                        || !seen.Add((candidate.Owner, candidate.Function))
                        || candidate.Provenance is not ("local-function" or "inherited-function" or "override" or "interface-implementation" or "imported-function")) InvalidFacts();
            }
        }
        foreach (var fact in analysis!.Invocations)
        {
            if (fact is null || fact.Location is null || !Text(fact.Location.Asset) || !Text(fact.Location.Function) || fact.Location.Offset < 0)
                InvalidFacts();
            if (fact!.Target is InvocationTarget.Resolved target)
            {
                if (!PolicyYaml.IsOwner(target.Owner) || !PolicyYaml.IsIdentifier(target.Function))
                    InvalidFacts();
            }
            else if (fact.Target is not InvocationTarget.Unresolved)
                InvalidFacts();
            if (fact.Arguments is ArgumentMetadata.Known known)
            {
                if (known.Arguments.IsDefault || known.Arguments.Length > MaxArguments)
                    InvalidFacts();
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var argument in known.Arguments)
                {
                    if (argument is null || !PolicyYaml.IsIdentifier(argument.Name) || !names.Add(argument.Name)
                        || argument.Value is null)
                        InvalidFacts();
                    if (argument!.Value is ArgumentValue.Constant constant && !ValidLiteral(constant.Value))
                        InvalidFacts();
                }
            }
            else if (fact.Arguments is not ArgumentMetadata.Unavailable)
                InvalidFacts();
            if (locations.TryGetValue(fact.Location, out var previous) && !Equivalent(previous, fact))
                InvalidFacts();
            locations[fact.Location] = fact;
        }
    }

    private static bool Equivalent(InvocationFact left, InvocationFact right) => left.Target == right.Target
        && (left.Arguments == right.Arguments || (left.Arguments is ArgumentMetadata.Known a
            && right.Arguments is ArgumentMetadata.Known b
            && a.Arguments.OrderBy(x => x.Name, StringComparer.Ordinal).SequenceEqual(b.Arguments.OrderBy(x => x.Name, StringComparer.Ordinal))));

    private static bool Text(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= MaxFactStringLength
        && !value.Any(char.IsControl) && ValidUnicode(value);
    public static bool DispatchDiagnostic(string? code) => code is "open-world" or "receiver-unavailable" or "parent-unavailable"
        or "class-cycle" or "target-name-unavailable" or "target-metadata-unavailable" or "target-expansion-limit"
        or "native-build-unverified" or "binding-flow-unresolved" or "dependency-context-unavailable"
        or "interface-context-unavailable" or "class-metadata-unavailable" or "unbound-delegate";
    private static bool ValidDispatchOpcode(string? opcode, string? kind) => kind switch
    {
        "virtual" => opcode is "EX_VirtualFunction" or "EX_LocalVirtualFunction",
        "delegate-binding" => opcode is "EX_BindDelegate" or "EX_InstanceDelegate",
        "delegate-mutation" => opcode is "EX_AddMulticastDelegate" or "EX_RemoveMulticastDelegate" or "EX_ClearMulticastDelegate" or "EX_LetDelegate" or "EX_LetMulticastDelegate",
        "multicast" => opcode == "EX_CallMulticastDelegate",
        "timer" => opcode is "EX_FinalFunction" or "EX_LocalFinalFunction" or "EX_CallMath",
        _ => false
    };
    private static bool ValidUnicode(string value)
    {
        for (var index = 0; index < value.Length; index++)
            if (char.IsSurrogate(value[index]) && (!char.IsHighSurrogate(value[index])
                || ++index >= value.Length || !char.IsLowSurrogate(value[index])))
                return false;
        return true;
    }
    private static bool ValidLiteral(PolicyLiteral? value) => value switch
    {
        PolicyLiteral.String text => text.Value is not null && text.Value.Length <= MaxFactStringLength && ValidUnicode(text.Value),
        PolicyLiteral.Integer or PolicyLiteral.Boolean or PolicyLiteral.Null => true,
        _ => false
    };
    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void InvalidFacts() => throw new ArgumentException("Invalid invocation analysis.");
}
