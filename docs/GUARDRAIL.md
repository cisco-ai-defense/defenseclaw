# Guardrail implementation map

Operator setup and behavior are documented on the published
[guardrail guide](https://cisco-ai-defense.github.io/defenseclaw/docs/guardrail/).
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

## Command reading budget

Every shell reader of a hook call (the parser, the statement split, the
analysers) works inside one budget in `internal/shellparse`, checked before
any of them runs: nesting of `(`, `{` and `[` (`MaxNestingDepth`, 512), brace
expansion size, the chain operators `|`, `&&` and `||` of the parse tree
(`MaxChainOperators`, 4096; a text with more than `MaxChainOperatorBytes`,
32,768, `|` and `&&` bytes is refused without a parse), and, for a command of
64 KiB or more, the nodes of its tree (`MaxParsedNodes`, 262,144). The values
are 20 to 100 times the largest of 3.1 million real agent calls. A call past
the budget is opaque to the readers: it gets the evaluation-limit finding
(`ACTION-COMPOUND-LIMIT`, reason `parse_budget_exceeded`), which alerts outside
the strict profile (managed non-strict included, rel-1-0-6:GAP-0675) and blocks
in strict (managed strict included). Allocation and time grow linearly up to
the budget, and the copy of the parse cache stops at a depth limit instead of
overflowing the stack.

## Verification

Behavior changes should be proven by the owning unit tests, the security corpus
described in [`SECURITY-TEST-SUITE.md`](SECURITY-TEST-SUITE.md), and connector
contract tests under `internal/gateway/connector/`. The public CLI examples are
validated separately against the real Click command tree by
[`../scripts/check_docs_cli_commands.py`](../scripts/check_docs_cli_commands.py).

## Known issues / OpenClaw version compatibility

A live `:4000` port is not proof that DefenseClaw intercepts OpenClaw traffic. The published
[OpenClaw connector page](https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/openclaw/)
explains the interception self-test and how to confirm coverage.
