# Policy YAML v1

This grammar stays closed. Optional [capability rules v1](capability-policy.md)
use a separate private JSON document; capability/caller kinds are not YAML v1 kinds.

The policy parser, typed model and evaluator are implemented. The
[extraction API](extraction.md), [shared policy input](policy-input.md),
[evaluation CLI](evaluate.md), [Docker scanner](container.md) and [Action](action.md)
integrate them. The old compatibility probe remains a separate experiment.
See the [integrated regression gate](regression-corpus.md) for measured coverage
and remaining release prerequisites.

Start with [the illustrative policy](../examples/starter-policy.yaml). It is not
a complete security policy for any game. Editor integrations can use
[the JSON Schema](../schemas/policy-v1.schema.json). The parser is authoritative
for lexical rules, budgets, and semantic constraints beyond that structural
schema.

## Document

```yaml
schema-version: 1
rules:
  - id: review-console
    description: Review console command use.
    effect: flag
    expression:
      invocation: /Script/Engine.KismetSystemLibrary:ExecuteConsoleCommand
```

- Exactly one document; unknown keys and schema versions are errors.
- `rules` is nonempty. IDs are unique, case-sensitive, and match
  `[a-z][a-z0-9-]{0,63}`.
- All rule fields are required. `effect` is `flag` or `forbid`; there is no
  allow/override effect or rule precedence.
- Descriptions are nonempty single-line text. Structural strings are limited to
  4,096 UTF-16 code units and cannot contain control characters.
- Quote structural strings that resemble YAML numbers, booleans, or nulls.

## Expression ADT

| Expression key | Value | Contract |
| --- | --- | --- |
| `all` | Nonempty expression list | Every expression must match |
| `any` | Nonempty expression list | At least one expression must match |
| `not` | One expression | Negates a known result; preserves Unknown |
| `invocation` | Class path, function path or expanded object | Recorded call identity, optionally with argument conditions |
| `argument` | Object with `name`, `predicate` | Named parameter and a typed value predicate |
| `property-write` | Object with `class`, `property`, optional `predicate` | Runtime assignment destination and optional value test |

Each expression is a mapping with exactly one expression key; there is no
expression-level `kind`. The rule field is `expression`, not `match`.
Singleton `all`/`any` lists are valid. Empty lists are rejected to avoid
accidental always-true or always-false policies. Argument and function names
must match `[A-Za-z_][A-Za-z0-9_]*` in v1.

Simple invocations:

```yaml
# Any function recorded under this exact class.
invocation: /Script/Engine.KismetSystemLibrary

# One exact function. Unreal function object paths use a colon.
invocation: /Script/Engine.KismetSystemLibrary:LaunchURL
```

```yaml
invocation:
  class: /Script/Engine.KismetSystemLibrary
  function: LaunchURL
  args:
    - argument:
        name: URL
        predicate:
          kind: url-host-in
          hosts:
            - mods.example.org
```

The expanded form accepts either `class` with an optional short `function` name,
or a fully qualified `function` path with **no `class` key**:

```yaml
invocation:
  function: /Script/Engine.KismetSystemLibrary:LaunchURL
  args:
    - argument:
        name: URL
        predicate:
          kind: url-host-in
          hosts: [mods.example.org]
```

A qualified function forbids `class`, even if it names the same class. A short
function name requires `class`. If `function` is present, it selects that function
or the whole-field wildcard. If `args` is present,
`function` is required and `args` must be a nonempty list of `argument` expressions.
All argument conditions are ANDed on the **same call**. A condition from another
call cannot satisfy this invocation. Missing/dynamic arguments remain Unknown.
Canonical output uses the expanded form, preserving argument conditions.

Class identities are absolute Unreal package/object paths, such as
`/Script/Engine.KismetSystemLibrary` or `/Game/Mods/BP_Test.BP_Test_C`.
Segments use ASCII letters, digits, and underscores. No trimming, case folding,
partial wildcards, suffix matching, or implicit rewriting occurs. Names outside this
initial grammar require a future schema extension, not a silent approximation.

Combine expressions explicitly:

```yaml
all:
  - any:
      - invocation: /Script/Engine.KismetSystemLibrary:LaunchURL
      - invocation: /Script/Engine.KismetSystemLibrary:ExecuteConsoleCommand
  - not:
      argument:
        name: URL
        predicate:
          kind: url-host-in
          hosts: [mods.example.org]
```

These shapes replace the old grammar in schema version 1; old `match`, `and`,
`or`, `target` and expression-level `kind` forms are not accepted. Predicate and
literal `kind` discriminators are unchanged. Capability/data JSON formats and
content CLI settings are separate and unchanged.

### Whole-field wildcards

`__WILDCARD__` selects any recorded class, function, argument name or literal value.
It is a matching token, not interpolation; `Foo__WILDCARD__Bar` is literal text.
Occurrences are independent, without variable bindings. Structural keys, IDs,
effects, predicate kinds, regex patterns and DNS host lists do not accept wildcards.

```yaml
invocation:
  class: /Script/Engine.KismetSystemLibrary
  function: __WILDCARD__
  args:
    - argument:
        name: __WILDCARD__
        predicate: {kind: equals, value: foo}
```

This selects any function on that class with **at least one argument** equal to
`foo`. Each wildcard argument condition searches independently; different
conditions may match different arguments on the same call. An empty known
argument list does not match. Missing metadata, dynamic values and unresolved
targets preserve Unknown, even with wildcard selectors. Wildcards also work
inside `subexpr-match`.

Use `{literal: __WILDCARD__}` for a literal function or argument name. Use
`{kind: string, value: "__WILDCARD__"}` for a literal string value. Quoting the
shorthand token alone does not escape it. A qualified function may use a wildcard
class or function component, such as `__WILDCARD__:LaunchURL`.

## Predicate and literal ADTs

| `kind` | Required fields | Contract |
| --- | --- | --- |
| `equals` | `value` | One inferred or explicitly typed literal |
| `in` | `values` | Nonempty, duplicate-free array of inferred or typed literals; mixed kinds permitted |
| `regex-match` | `pattern` | Nonempty .NET non-backtracking regex; searches a string for a match |
| `url-host-in` | `hosts` | Nonempty, duplicate-free canonical DNS hosts |
| `subexpr-match` | `subexpr` | Search the argument's recorded value-producing invocation chain |

Regex example (single quotes preserve backslashes):

```yaml
kind: regex-match
pattern: '^https://mods\.example\.org/'
```

Matching searches anywhere unless anchored; use `\A` and `\z` for the entire
string (`$` also accepts a final newline). Matching is case-sensitive and
culture-invariant by default; inline options such as `(?i)` are supported.
Patterns use the .NET non-backtracking engine: lookarounds, backreferences,
atomic groups and other unsupported constructs are rejected during validation.
Patterns are nonempty and limited to 4,096 UTF-16 code units; regex execution
has a 100 ms timeout per match. A timeout produces Unknown, including under
negation; it never becomes NoMatch or approval. Non-string constants produce
NoMatch; missing/dynamic arguments remain Unknown. The schema checks structure;
the policy parser also validates regex syntax and engine support.
`regex-match` replaces `string-starts-with`; the old predicate is rejected.
For URL host checks, prefer `url-host-in` rather than approximating URL parsing.

### Subexpression provenance

```yaml
invocation:
  function: /Script/Example.Bar:Baz
  args:
    - argument:
        name: foo
        predicate:
          kind: subexpr-match
          subexpr:
            invocation:
              function: /Script/Example.String:Append
              args:
                - argument:
                    name: A
                    predicate:
                      kind: equals
                      value: {kind: string, value: "foo"}
```

This searches the provenance of `Baz`'s specific `foo` argument for an `Append`
call with `A` equal to the known string `"foo"`. `subexpr` accepts the normal
expression grammar, including nested `subexpr-match` predicates. Argument
wrappers, typed literals and absolute Unreal class/function identities are
unchanged. These paths are illustrative, not engine APIs.

The extractor traces directly nested calls, straight-line local assignments and
return values of directly resolved functions with available bytecode in the same
package. Callee parameters are substituted from the exact caller. Overwrites
replace earlier definitions; unrelated calls and unused callee arguments are
not return dependencies. Locally propagated constants can satisfy ordinary
predicates too. A function call's output is not evaluated or constant-folded.

- **Match:** a recorded producer satisfies `subexpr`; other opaque dependencies
  do not erase this evidence.
- **NoMatch:** the searched chain is complete and no producer matches, including
  a literal with no producing invocation.
- **Unknown:** a potentially relevant dependency is unresolved or truncated;
  negation preserves Unknown.

Native/imported bodies, cross-package returns, virtual/delegate dispatch,
branches/loops, fields/containers, unsupported transformations, out/ref aliases
and unmodelled intervening side effects remain opaque. Imported parameter names
are not guessed. Recursion stops at the active call boundary. This is bounded
static evidence, not proof of runtime execution or arbitrary causal influence.

Extraction permits 16 active functions, 24 tracing levels and 65,536 work units
per package. Retained graphs have at most 256 nodes, 1,024 edges and depth 32;
the analysis retains at most 8,192 nodes. Evaluation permits 4,096 visited nodes
per rule/invocation and 32 nested searches. Transport exhaustion drops optional
provenance back to Dynamic without dropping mandatory invocation facts, so
argument-dependent results remain Unknown. Policies remain evaluator-only;
the parser extracts provenance without seeing private rules.

Shorthand literals use YAML 1.2 core scalar inference:

```yaml
kind: in
values: [foo, "42", 42, 1.5, true, null]
```

Quoted/block scalars remain strings. Plain `true`/`false` (including YAML core
capitalizations) are booleans; `yes`/`no` remain strings. Plain decimal, `0x` hex
and `0o` octal integers must fit signed 64 bits. Decimal/exponent floating-point
values use finite IEEE-754 doubles; nonfinite and out-of-range values are rejected.
Null is a known null, not missing evidence. Lists belong in `in.values`, not
`equals.value`; nested lists and arbitrary mappings are not literal values.
Equality retains numeric kinds and exact floating-point values; no string
coercion or approximate comparison occurs. Extracted UE float constants are
promoted to doubles, so decimal rounding can differ from a YAML double.

Explicit types remain available and canonical output uses them:

```yaml
kind: equals
value: {kind: string, value: "123"}
```

```yaml
kind: in
values:
  - {kind: integer, value: 1}
  - {kind: integer, value: 2}
```

- `string`: `value` must be quoted or a block scalar; empty strings are valid.
  At most 4,096 UTF-16 code units; block strings retain YAML's decoded value.
- `integer`: unquoted signed 64-bit decimal, `0` or `-?[1-9][0-9]*`. No `+`,
  leading zeros, negative zero, hex, floats, or coercion from strings.
- `boolean`: unquoted lowercase `true` or `false`, not `yes` or `1`.
- `number`: finite unquoted floating-point value.
- `wildcard`: no `value` field; canonical form of the shorthand matching token.
- `"null"`: no `value` field. Quote the discriminator: `{kind: "null"}`.

Known null is distinct from an unresolved value. A string `"1"` is not integer
`1`; predicates never request coercion between literal kinds. Parameter runtime
types and missing argument metadata cannot be established by YAML validation;
the evaluator must retain uncertainty rather than treating missing data as null.

For `url-host-in`, policy hosts are lowercase ASCII DNS names with at least two
labels. Unicode hosts must be explicitly supplied as reviewed ASCII/Punycode.
URLs, ports, credentials, IP literals, trailing dots, wildcards, and implicit
subdomain matching are not allowed in the host list. Evaluation will require
HTTPS and parsed host comparison, not prefix checks; the policy parser does not
evaluate URLs or claim that a destination is safe.

## Runtime property writes

`property-write` matches Kismet assignments, not serialized asset defaults:

```yaml
expression:
  property-write:
    class: /Script/Engine.Actor
    property: CustomTimeDilation
    predicate: {kind: equals, value: 90.0}
```

- `class` and `property` are required. Either accepts whole-field `__WILDCARD__`.
- `class` selects the stored declaring owner, not the runtime receiver's class.
- `property` is a case-sensitive dotted path. A root selector such as
  `InteractableSettings` covers writes to its nested fields.
- `predicate` is optional and uses the argument value predicates. Dynamic values
  remain Unknown. A predicate on a parent cannot inspect an assigned child value.
- A whole-struct replacement is Unknown for a narrower child selector; it cannot
  silently become NoMatch. Select the root to match any replacement or child write.
- Direct instance/default assignments and array/map/set replacements are retained.
  Known function-local construction is excluded. Out/ref aliases and unresolved
  destinations remain incomplete; native mutations are not reconstructed.
- Pure write rules evaluate write events; pure invocation rules evaluate calls.
  `subexpr-match` cannot contain `property-write` expressions.
- Missing or incomplete write evidence blocks completeness when write rules exist.
  Receiver evidence does not prove ownership, reachability or runtime execution.

See [the illustrative write policy](../examples/property-write-policy.yaml).
It is not an adopted production baseline or proof of exact-game owner identities.

## Evaluation boundary

`PolicyEvaluator` uses `Match`, `NoMatch`, and `Unknown`. In particular,
`not Unknown` stays `Unknown`; an unresolved URL cannot become approved through
negation. All matching rules apply, and a flag cannot cancel a forbid. These are
implemented by the evaluator, not by the YAML parser.

| Inputs | `all` | `any` |
| --- | --- | --- |
| Match, Match | Match | Match |
| Match, NoMatch | NoMatch | Match |
| Match, Unknown | Unknown | Match |
| NoMatch, NoMatch | NoMatch | NoMatch |
| NoMatch, Unknown | NoMatch | Unknown |
| Unknown, Unknown | Unknown | Unknown |

Operand order does not matter. `not` swaps Match/NoMatch and preserves Unknown.
Decisive operands discard irrelevant uncertainty. A nonmatching target in `all`
does not become incomplete because another operand has a dynamic argument.
Known values of different literal kinds produce NoMatch, without coercion.
Literal string comparisons are ordinal and case-sensitive; regex matching uses
the options described above.

URL matching requires an absolute, well-formed HTTPS URL. Scheme and DNS host
case are normalized. Only an omitted port or literal `:443` is accepted.
Credentials (including empty userinfo), trailing host dots, IP literals,
Unicode authorities, percent-encoded authorities, backslashes, whitespace, and
control characters are rejected. ASCII/Punycode hosts must match exactly;
Unicode URLs are not silently IDNA-converted. Subdomains require explicit policy
entries. Paths, queries, and fragments do not affect host matching. Invalid or
disallowed known URLs produce NoMatch; dynamic URLs remain Unknown, even under
negation. Host approval is not proof of destination safety or redirect behavior.

### Normalized invocation contract

`InvocationAnalysis` is the shared boundary supplied by the implemented
[normalized extractor](extraction.md) through the Docker scanner. The old
compatibility CLI does **not** supply it. Each `InvocationFact` has:

- `InvocationLocation`: canonical asset identity, containing function identity,
  and nonnegative bytecode offset. The producer must supply stable identities.
- `InvocationTarget`: complete `Resolved` owner/function or `Unresolved`.
  Owner/function matching is exact, ordinal, and case-sensitive.
- `ArgumentMetadata`: a complete `Known` named-parameter table or `Unavailable`.
  Names are unique and case-sensitive. Do not invent names from positions.
- `ArgumentValue`: typed `Constant`, `Dynamic`, or `Missing`. Known null uses
  `Constant(new PolicyLiteral.Null())`, never a C# null reference. An absent name
  in a known table means Missing; neither missing nor unavailable metadata means
  known null. All three unresolved argument states produce distinct fixed reasons.

The producer must mark unsupported parsing, unresolved dispatch that may hide
invocations, and incomplete extraction in `CoverageGaps`. These global gaps are
separate from rule-specific uncertainty and do not manufacture findings. An empty
invocation array is valid only when it honestly represents the producer's coverage.
The evaluator cannot detect omitted calls or false claims of complete extraction.

All matching rules are retained as ID/effect pairs, sorted by ordinal ID, in one
finding per location. Locations sort by ordinal asset/function, then offset.
Equivalent duplicate facts are deduplicated; conflicting facts at one location
reject the entire analysis. Argument table order is irrelevant. Unknown results
are separate location/rule records with sorted, fixed `UncertaintyReason` codes;
they expose no predicate literals, values, descriptions, or parser exception text.
Rule IDs and locations remain report identifiers, not redacted secrets.

`IsIncomplete` combines rule uncertainty and global coverage gaps.
`ShouldFail(failOnIncomplete)` fails for any forbid finding, or for incomplete
analysis when requested. Flags do not fail this gate. Changing the gate does not
change findings or uncertainties. There is no clean/safe verdict.

### Validation and evaluation limits

The constructor revalidates public ASTs through the existing YAML contract after
bounded iterative preflight. Nulls, invalid variants, duplicate IDs, empty/default
arrays, and oversized/deep trees are rejected with fixed `ArgumentException`
text. Preflight bounds expression/string/literal visits to 8,192, depth to 32,
individual strings to 4,096 UTF-16 units, and total string units to 256 KiB;
canonical serialization must also satisfy the parser's stricter byte/node budgets.

Every fact is validated before any rule runs, even if no target would match.
Invalid input rejects the whole batch with `Invalid invocation analysis.`; callers
must treat exceptions as evaluation failure, never as an empty result. Limits:
10,000 facts per batch, 256 arguments per fact, 256 coverage entries, and 4,096
UTF-16 units per string. Default immutable arrays, null references, malformed
Unicode, duplicate argument names, invalid target syntax, negative offsets, and
unknown coverage enum values are rejected. Constant strings may contain controls
(URL predicates reject them); location identifiers may not. These are evaluator
budgets, not a parser sandbox or transport resource limit. Evaluation is bounded
by facts times validated policy size; callers must bound batch count externally.

Defaults, asset replacement, call chains, and capability predicates are not v1
expression variants. They need versioned extensions and corresponding analysis.

## Validation and confidentiality

- Limit: 256 KiB of UTF-8 input, 8,192 YAML nodes (including keys), and node depth
  32 (root depth zero). These are parser budgets, not GitHub/environment limits.
- Aliases, anchors, merge keys, explicit tags, version directives, and custom tag
  directives are rejected. YAML's built-in tag handles are not themselves unsafe;
  explicitly tagged nodes are still rejected.
- Duplicate keys are rejected before building rule objects. YAML is parsed as
  bounded events; it cannot instantiate arbitrary runtime objects.
- Errors expose a fixed diagnostic code and one-based line/column, never rule
  IDs, unknown source keys/values, snippets, or the dependency's exception text.
- `PolicyYaml.Write` produces canonical JSON, which is valid YAML 1.2. It
  revalidates the document before returning it. Parsing/writing never logs.

Implemented input: `policy-rules` file or `UE_PAK_POLICY_RULES` containing raw YAML,
exactly one source. The Action has `log-level` enum (`error`, `warn`,
`info`, `verbose`), default `info`.

**Warning: verbose logging prints the policy to logs. Anyone with log access
can read it.** Ordinary environment variables are not secrets and may also be
exposed by runner setup logs or host/container administrators. Do not enable
verbose for a policy that must remain confidential. Policy printing and safe
workflow-command rendering use the [shared input boundary](policy-input.md).

## Library API

```csharp
var document = PolicyYaml.Parse(yaml);
var canonicalYaml = PolicyYaml.Write(document);
var evaluator = new PolicyEvaluator(document);
// analysis must come from a trusted normalizer, not the compatibility report.
PolicyEvaluation result = evaluator.Evaluate(analysis);
bool gateFailed = result.ShouldFail(failOnIncomplete: true);
```

The model uses sealed variants and immutable arrays. YamlDotNet 18.1.0 is pinned
in the project and package lockfiles; it is MIT-licensed. Preserve its license
when distributing the eventual library/image.
