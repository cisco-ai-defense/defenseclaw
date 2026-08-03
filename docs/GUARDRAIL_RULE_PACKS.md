# Guardrail rule-pack engineering contract

Operator recipes, suppressions, and verification steps are maintained in the
published [policies documentation](https://cisco-ai-defense.github.io/defenseclaw/docs/policies/).

## Two policy layers

DefenseClaw deliberately ships two distinct policy mechanisms:

| Layer | Repository authority | Purpose |
| --- | --- | --- |
| Admission and policy domains | [`../policies/rego/`](../policies/rego/) | OPA decisions for admission, guardrail actions, firewall, audit, sandbox, and skill actions |
| Guardrail rule packs | [`../policies/guardrail/`](../policies/guardrail/) | Runtime regex rules, sensitive-tool metadata, judge prompts, and suppressions |

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

Any format or precedence change must update both language implementations and
their focused tests.
