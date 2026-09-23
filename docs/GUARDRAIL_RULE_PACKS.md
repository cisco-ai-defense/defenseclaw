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
| Admission and policy domains | [`../policies/rego/`](../policies/rego/) | OPA decisions for admission, guardrail actions, firewall, audit, sandbox, and skill actions |
| Guardrail rule packs | [`../policies/guardrail/`](../policies/guardrail/) | Trusted tool-call CEL rules with bounded regex fallback, unstructured runtime rules, sensitive-tool metadata, judge prompts, and suppressions |

Activating an admission policy does not select a rule-pack directory, and
selecting `guardrail.rule_pack_dir` does not activate an admission policy. Keep
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
