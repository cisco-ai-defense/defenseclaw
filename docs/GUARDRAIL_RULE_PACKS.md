# Guardrail rule-pack engineering contract

Operator CEL authoring and engine behavior are maintained in the published
[CEL authoring guide](https://cisco-ai-defense.github.io/defenseclaw/docs/policies/cel/authoring/)
and [CEL engine reference](https://cisco-ai-defense.github.io/defenseclaw/docs/policies/cel/engine/).
The complete shipped detector inventory and enforcement boundaries are in the
[deterministic detection reference](https://cisco-ai-defense.github.io/defenseclaw/docs/policies/deterministic-detection/).
Recipes, suppressions, and verification steps remain in the broader
[policies documentation](https://cisco-ai-defense.github.io/defenseclaw/docs/policies/).

## Two policy layers

DefenseClaw deliberately ships two distinct policy mechanisms:

| Layer | Repository authority | Purpose |
| --- | --- | --- |
| Admission and policy domains | [`../policies/rego/`](../policies/rego/) | OPA decisions for admission, guardrail actions, firewall, audit, and skill actions |
| Guardrail rule packs | [`../policies/guardrail/`](../policies/guardrail/) | Trusted tool-call CEL rules with bounded regex fallback, unstructured runtime rules, sensitive-tool metadata, judge prompts, and suppressions |

Activating an admission policy does not select a rule-pack directory, and
selecting `guardrail.rule_pack` does not activate an admission policy. Keep
that separation explicit in code and tests.

## Implementation ownership

- Go parsing and evaluation inputs:
  [`../internal/guardrail/rulepack.go`](../internal/guardrail/rulepack.go) and
  [`../internal/guardrail/suppress.go`](../internal/guardrail/suppress.go).
- Reload-aware caching:
  [`../internal/guardrail/rulepack_cache.go`](../internal/guardrail/rulepack_cache.go).
- Effective global/per-connector lookup:
  [`../internal/config/config.go`](../internal/config/config.go) and
  [`../internal/config/application_protection.go`](../internal/config/application_protection.go).
- Python scanner overlay:
  [`../cli/defenseclaw/scanner/rulepack.py`](../cli/defenseclaw/scanner/rulepack.py).
- Bundled profile data:
  [`../policies/guardrail/default/`](../policies/guardrail/default/),
  [`../policies/guardrail/permissive/`](../policies/guardrail/permissive/), and
  [`../policies/guardrail/strict/`](../policies/guardrail/strict/).
- Opt-in high-assurance use cases:
  [`../policies/guardrail-use-cases/`](../policies/guardrail-use-cases/).

Any format or precedence change must update both language implementations and
their focused tests.

## Trusted tool-call boundary

CEL expressions run only inside the existing authenticated tool-call
evaluation path. They do not replace OPA, scan arbitrary prompt or result
text, or expose another policy endpoint. `tool_call_only` independently limits
the rule's regex fallback to that path; omitting it preserves legacy
prompt/result regex coverage while CEL remains tool-call scoped.
Authoritative ActionFacts own the semantic decision; unsupported or ambiguous
input keeps the legacy fallback. Each migrated owner emits one canonical
finding rather than independent regex and CEL findings.

Semantic-only rules use the intentionally never-matching RE2 sentinel `a^`
when a raw command mention cannot safely serve as fallback evidence.

All trusted-action findings cross a final same-rule proof gate before they can
affect a block decision. A complete code-owned semantic proof, a complete exact
built-in CodeGuard proof, or a bounded code-owned exact fallback proof may
independently authorize enforcement. Raw or custom regex matches, custom
CodeGuard matches, parser-shadow evidence, partial or invalid facts, and proof
for another rule remain detection-only unless a separate complete proof is
pinned to that same rule; lexical metadata alone never authorizes.

Two partial forms still get a semantic decision. First, when the only unknown part of
a POSIX command is a redirect target the shell expands at run time and that
can only name a file (`> ~/out.txt`, `> "$HOME/out.txt"`, `> out-*.txt`), CEL
rules also run on the analysis of the same command with a static stand-in
target, wrapped commands included, without the stand-in's redirect and path.
A match there is complete proof for a rule that cannot depend on the dropped
redirect and path (no `!`, `==`, `!=`, `in` or `all()` over `redirects`,
`paths`, `artifacts` or `archive_lineages`, and no `parse` or lineage
`authoritative` read; a command's `c.argv_complete` may be read). A built-in
owner's code-owned prerequisite must hold both on that analysis and on the
one with the stand-in target. A non-match proves nothing, so the regex
fallback still sees the whole command.

Second, a POSIX command with `&&` or `||` lists (`cd <dir> && <cmd>`,
`<cmd> || true`) is judged as if every command of each list runs: a block
stops the whole call before any of it runs. CEL rules, code-owned
prerequisites and the context checks for content and sensitive-path findings
run on the analysis of the command with each list read as the sequence of its
commands, so a rule that blocks `a; b` also blocks `a && b` and `a || b`.
For a rule with no `parse` or lineage `authoritative` read (a command's
`c.argv_complete` may be read), a match or non-match there counts as it does
for `a; b`; other rules keep the regex fallback, and a fallback finding
blocks when that analysis proves it, as for `a; b`. A list with a
runtime-expanded redirect target gets both treatments. A negated,
background or coprocess statement in a list, a function definition or a
here-document keeps the regex fallback, and its matches stay detection-only.

Durable ordered-chain enforcement is limited to authenticated connector hooks
with canonical connector/session correlation. The audit store persists only
bounded masks and fingerprints, never raw commands, arguments, paths, URLs, or
ActionFacts.

## Opt-in high-assurance profiles

The `policies/guardrail-use-cases/` directories are complete selectable rule
packs layered over the embedded balanced defaults by the existing partial-pack
inheritance contract. They are intentionally not enabled by the default,
permissive, or strict profiles.

- `privacy-high-assurance` blocks only the selected structured PII families
  that have the strongest deterministic validation and excludes noisier
  email, phone, passport, driver's-license, unformatted-SSN, and NHS patterns.
- `cloud-production-protection` blocks a closed set of destructive AWS,
  Google Cloud, and Azure CLI operations. Assign it to a production-scoped
  connector; resource-name heuristics are not treated as production proof.
- `database-destruction-protection` blocks statically supplied unbounded SQL
  deletes and schema-wide destructive statements for a closed list of clients.
- `kubernetes-production-protection` blocks named namespace deletion and a
  closed set of `delete --all` workload forms for production-scoped contexts.
- `infrastructure-destruction-protection` blocks unscoped Terraform, OpenTofu,
  and Pulumi destruction while allowing plans, previews, and targeted changes.
- `ssh-authorized-keys-protection` is a contract only and cannot be activated.
  It defines how an approved-fingerprint allowlist would guard writes to
  `~/.ssh/authorized_keys`. Do not point `policy_dir` at it; see its
  [README](../policies/guardrail-use-cases/ssh-authorized-keys-protection/README.md).

Cloud, SQL, Kubernetes, and infrastructure rules use semantic-only `a^` regex fallbacks. A complete
ActionFacts parse, an exact code-owned prerequisite, a successful CEL result,
and same-rule proof are all required for enforcement. Unsupported or dynamic
forms do not gain blocking authority.

The vendored low-support conformance matrices live in
`benchmarks/fixtures/cloud-production-conformance-v1.jsonl` and
`benchmarks/fixtures/database-destruction-conformance-v1.jsonl`, with matching
Kubernetes and infrastructure matrices beside them. They verify covered
positives and parser hard negatives without executing any command.
Population noise must be reported from the much larger benign trace corpora,
not inferred from these authored matrices.
