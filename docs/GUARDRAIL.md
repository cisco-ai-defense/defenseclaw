# Guardrail implementation map

Operator setup and behavior are documented on the published
[guardrail guide](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/guardrail/).
Policy authoring and tuning live under the published
[policies section](https://cisco-ai-defense.github.io/defenseclaw/docs/policies/).

This file is intentionally limited to repository implementation ownership.

## Runtime paths

DefenseClaw has connector-specific ingress paths rather than one universal
proxy topology:

- proxy-capable connectors are implemented around
  [`../internal/gateway/proxy.go`](../internal/gateway/proxy.go) and the
  provider adapters in `internal/gateway/adapter_*.go`;
- hook connectors are registered from
  [`../internal/gateway/connector/`](../internal/gateway/connector/) and
  dispatched through
  [`../internal/gateway/unified_hook_dispatch.go`](../internal/gateway/unified_hook_dispatch.go)
  and [`../internal/gateway/agent_hook.go`](../internal/gateway/agent_hook.go);
- inspection orchestration is implemented in
  [`../internal/gateway/inspect.go`](../internal/gateway/inspect.go),
  [`../internal/gateway/inspector.go`](../internal/gateway/inspector.go), and
  the focused `inspect_*.go` tests;
- rule-pack parsing, suppression, correlation, and caching are in
  [`../internal/guardrail/`](../internal/guardrail/);
- optional judge behavior is in
  [`../internal/gateway/llm_judge.go`](../internal/gateway/llm_judge.go) and
  adjacent tests;
- connector-independent application-protection posture is resolved in
  [`../internal/config/application_protection.go`](../internal/config/application_protection.go)
  and enforced by
  [`../internal/gateway/application_protection.go`](../internal/gateway/application_protection.go).

The exact supported behavior for each connector is published in the
[connector compatibility matrix](https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/compatibility/).

## Configuration and policy ownership

The v8 configuration shape is authoritative in
[`../schemas/config/v8/defenseclaw-config.schema.json`](../schemas/config/v8/defenseclaw-config.schema.json).
Go defaults and effective per-connector lookups are in
[`../internal/config/config.go`](../internal/config/config.go). Python setup
mutation is in
[`../cli/defenseclaw/commands/cmd_guardrail.py`](../cli/defenseclaw/commands/cmd_guardrail.py)
and [`../cli/defenseclaw/config.py`](../cli/defenseclaw/config.py).

The repository ships two separate policy layers:

- admission and policy-domain Rego under
  [`../policies/rego/`](../policies/rego/);
- runtime rule-pack profiles under
  [`../policies/guardrail/`](../policies/guardrail/).

They are not interchangeable. The focused engineering contract is
[`GUARDRAIL_RULE_PACKS.md`](GUARDRAIL_RULE_PACKS.md).

## Verification

Behavior changes should be proven by the owning unit tests, the security corpus
described in [`SECURITY-TEST-SUITE.md`](SECURITY-TEST-SUITE.md), and connector
contract tests under `internal/gateway/connector/`. The public CLI examples are
validated separately against the real Click command tree by
[`../scripts/check_docs_cli_commands.py`](../scripts/check_docs_cli_commands.py).
