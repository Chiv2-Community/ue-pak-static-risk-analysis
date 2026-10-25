# Policy YAML v1

The policy parser and typed model are implemented. **Evaluation, environment
loading, CLI gates, and the reusable Action are not implemented yet.**

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
    match:
      kind: invocation
      target:
        kind: exact
        owner: /Script/Engine.KismetSystemLibrary
        function: ExecuteConsoleCommand
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

| `kind` | Required fields | Contract |
| --- | --- | --- |
| `all` | `expressions` | Nonempty expression array; every expression must match |
| `any` | `expressions` | Nonempty expression array; at least one must match |
| `not` | `expression` | Exactly one nested expression |
| `invocation` | `target` | Resolved function identity, not a string search |
| `argument` | `name`, `predicate` | Named parameter and a typed value predicate |

Singleton `all`/`any` arrays are valid. Empty arrays are rejected to avoid
accidental always-true or always-false policies. Argument and function names
must match `[A-Za-z_][A-Za-z0-9_]*` in v1.

Target variants:

```yaml
kind: exact
owner: /Script/Engine.KismetSystemLibrary
function: LaunchURL
```

```yaml
kind: owner
owner: /Script/Engine.KismetSystemLibrary
```

Owners are absolute Unreal package/object paths, such as
`/Script/Engine.KismetSystemLibrary` or `/Game/Mods/BP_Test.BP_Test_C`.
Segments use ASCII letters, digits, and underscores. No trimming, case folding,
wildcards, suffix matching, or implicit rewriting occurs. Names outside this
initial grammar require a future schema extension, not a silent approximation.

## Predicate and literal ADTs

| `kind` | Required fields | Contract |
| --- | --- | --- |
| `equals` | `value` | One typed literal |
| `in` | `values` | Nonempty, duplicate-free array of literals of one kind |
| `string-starts-with` | `prefix` | Nonempty text prefix; intended ordinal comparison |
| `url-host-in` | `hosts` | Nonempty, duplicate-free canonical DNS hosts |

Literals always identify their type:

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

## Evaluation boundary

The next evaluator uses `Match`, `NoMatch`, and `Unknown`. In particular,
`not Unknown` stays `Unknown`; an unresolved URL cannot become approved through
negation. All matching rules apply, and a flag cannot cancel a forbid. These are
the interface contract for issue #6, not behavior implemented by this parser.

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

Planned input: `policy-rules` file or `UE_PAK_POLICY_RULES` containing raw YAML,
exactly one source. The Action will have `log-level` enum (`error`, `warn`,
`info`, `verbose`), default `info`.

**Warning: verbose logging will print the policy to logs. Anyone with log access
can read it.** Ordinary environment variables are not secrets and may also be
exposed by runner setup logs or host/container administrators. Do not enable
verbose for a policy that must remain confidential. Policy printing and safe
workflow-command rendering belong to the later transport/logging work.

## Library API

```csharp
var document = PolicyYaml.Parse(yaml);
var canonicalYaml = PolicyYaml.Write(document);
```

The model uses sealed variants and immutable arrays. YamlDotNet 18.1.0 is pinned
in the project and package lockfiles; it is MIT-licensed. Preserve its license
when distributing the eventual library/image.
