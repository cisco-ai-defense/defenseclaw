# AI discovery confidence implementation map

The current operator explanation and workflows are maintained on the
[published AI discovery page](https://cisco-ai-defense.github.io/defenseclaw/docs/ai-discovery/).

This file records code ownership only:

- [`../internal/inventory/confidence.go`](../internal/inventory/confidence.go)
  computes the separate identity and presence scores and their factors;
- [`../internal/inventory/policy.go`](../internal/inventory/policy.go) loads,
  merges, and validates confidence policy;
- [`../internal/inventory/confidence_policy.yaml`](../internal/inventory/confidence_policy.yaml)
  is the embedded default policy;
- [`../internal/inventory/ai_discovery.go`](../internal/inventory/ai_discovery.go)
  rolls discovered signals into component confidence;
- [`../internal/inventory/store.go`](../internal/inventory/store.go) persists
  scans, component scores, bands, and factors;
- [`../internal/gateway/ai_usage.go`](../internal/gateway/ai_usage.go) exposes
  component and confidence-policy endpoints;
- [`../cli/defenseclaw/commands/cmd_agent.py`](../cli/defenseclaw/commands/cmd_agent.py)
  owns the Python CLI surface;
- focused behavior and persistence contracts are in the adjacent
  `confidence_test.go`, `policy_test.go`, `ai_discovery_test.go`, and
  `store_test.go` files.

Do not copy scoring constants or endpoint examples into repository prose.
Review the policy, implementation, and tests together when changing the
algorithm; update the published page in the same change.
