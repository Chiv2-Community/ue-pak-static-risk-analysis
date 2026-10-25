# Trusted content policy

The host `scan` CLI and shared `evaluate`/`validate` CLI accept optional operator
settings, separate from the closed invocation YAML grammar:

| Flag | Meaning |
| --- | --- |
| `--allowed-path PREFIX` | Repeatable allowed virtual namespaces; a nonmatching member is rejected. |
| `--allowed-class IDENTITY` | Repeatable exact parsed export class identities; a known nonmatching class is rejected. |
| `--protected-path PREFIX` | Repeatable protected virtual namespaces; matching members are replacement candidates. |
| `--replacement-policy allow\|review\|reject` | Candidate handling; defaults to `review` when protection is configured. Requires a protected prefix. |

```bash
python3 scripts/scan.py scan --pak /approved/submission.pak \
  --report /approved/new-report.json --engine-version 4.25 \
  --content-root 'Owned/Content=/Game' --policy-rules /private/rules.yaml \
  --allowed-path Owned/Content --allowed-class /Script/CoreUObject.Function \
  --protected-path Owned/Content/Base --replacement-policy review
```

This is an interface example, not a usable game allowlist. Supply every required
class identity for the authorized archive. There are no built-in game paths or
classes. The reusable Action does not expose these flags; use the trusted CLI.

## Matching and decisions

- Prefixes use normalized virtual identities, without `../../../`, a leading or
  trailing slash, traversal, empty components, backslashes, controls, non-ASCII,
  reserved device components, or trailing dots/spaces. Matching is ASCII
  case-insensitive and component-boundary aware: `Content/Foo` does not match
  `Content/Foobar`. Exact file identities can also be prefixes.
- Class identities are case-sensitive `/Package/Path.Class` names. They come
  from parsed export `ClassIndex` references, not extensions, filenames, managed
  reader types, or caller-provided defaults. Imported classes retain their
  recorded owner; local export classes use the explicitly mapped logical package.
  Provenance is `export-class-index-import` or `export-class-index-export`.
  These are recorded identities, not authenticated native types or inheritance
  inventory (#7). Ownership uses the existing bounded package-index traversal;
  cycles, invalid references and missing/unrepresentable owners remain unavailable.
- Empty allowlists impose no restriction of that kind. Each repeatable flag is
  bounded to 256 distinct values; prefixes are at most 4096 ASCII characters.
  Class identifiers use the existing bounded owner-name grammar. Duplicates
  (case-insensitive for prefixes), blanks and invalid values fail configuration
  before invocation-policy loading or verbose disclosure. Diagnostics are fixed.
- Protected matches are **candidates only**. There is no clean-install baseline,
  changed-file comparison, package-identity authentication or load-order analysis.
  `allow` permits a candidate, `review` requires review, and `reject` rejects it.
  None of these options suppresses other restrictions or incomplete coverage.
- Nonmatching allowed paths/classes reject. Missing inventory, unparsed packages,
  unknown classes and native/script/config/unknown content cannot be approved by
  an allowlist. Verified, unclassified paired export bytes are accounted for by
  their parsed package; recognized signatures never receive that exemption.
  Known disallowed classes still reject when other class identities are missing.
  Parsed-package class inventory gaps remain incomplete with path-only or
  protected-only settings too; only class membership rejection needs a class
  allowlist. Non-package members retain content gaps, not class requirements.

## Reports and gates

Configured runs add an optional `content-policy` result, with its own
`schema-version: 1`, `decision` (`allow`, `needs-review`, `reject`), `incomplete`
and bounded fixed findings keyed by actual manifest member IDs. A missing
inventory uses the sentinel `inventory`. Resolve member IDs through `inspection`;
that manifest retains actual archive paths, hashes and class evidence.
`path-normalized` distinguishes validated virtual identities from raw-name
fallbacks in rejected/partial inventories. Raw names cannot establish protected
matches or namespace violations; configured path checks remain incomplete.

No allowlists, prefixes, replacement setting, predicates, private rule IDs or
synthetic invocation locations are published. Content decisions never change
invocation counts or the real flagged/forbidden arrays. Earlier findings and
coverage gaps survive content rejection and partial extraction.

`reject` and `needs-review` always exit 1, independently of all three invocation/
coverage gates. `allow` means no content rejection/review requirement, **not**
approval or complete analysis: content incompleteness also sets
`analysis-complete: false` and uses the existing incomplete gate. Review/rejection
alone does not turn complete analysis into incomplete analysis.

Unconfigured runs omit the content result and retain existing gate behavior.
Path/class provenance is additive optional manifest evidence; older facts without
it remain readable but cannot satisfy the corresponding configured checks. Shared report,
Action and moderation validators use the published additive v1 schemas.
Moderation routes content rejection to `policy-violation` and content review to
`needs-review`, independently of analysis incompleteness; exact report-byte
binding is unchanged. No automated moderation approval is introduced.
Assign a new opaque `--policy-revision` when invocation or content settings change;
no content-derived policy fingerprint is published.

Settings go only to trusted validation/evaluation, never the parser. Default
reports/logs omit the configuration even at verbose invocation-policy log level.
CLI arguments can still be visible to trusted host/Docker administrators. Do not
give submitters control of flags, policy sources, scanner code, images or logs.
No content configuration file loader, extra mount or output path is introduced.
