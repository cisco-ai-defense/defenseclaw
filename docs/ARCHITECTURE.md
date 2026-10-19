# Architecture

This is a code-ownership map for contributors. Product concepts and operator
workflows belong on the
[documentation website](https://cisco-ai-defense.github.io/defenseclaw/docs/).

## Top-level components

```text
connector runtime / operator CLI
            |
            v
   DefenseClaw gateway
      |      |      |
      |      |      +--> policy and scanners
      |      +---------> mandatory local audit history
      +----------------> configured observability destinations
```

The diagram is deliberately topology-neutral: proxy connectors, hook
connectors, and the OpenClaw extension do not share one universal request path.
The published
[connector compatibility matrix](https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/compatibility/)
defines the supported path for each connector.

| Component | Source ownership |
| --- | --- |
| Python CLI, setup, migrations, TUI | [`../cli/defenseclaw/`](../cli/defenseclaw/) |
| Go binaries | [`../cmd/`](../cmd/) |
| Gateway API, proxy, hooks, connector ingress | [`../internal/gateway/`](../internal/gateway/) |
| Connector registration and hook contracts | [`../internal/gateway/connector/`](../internal/gateway/connector/) |
| OpenClaw TypeScript extension | [`../extensions/defenseclaw/`](../extensions/defenseclaw/) |
| Configuration loading and effective defaults | [`../internal/config/`](../internal/config/) |
| Admission and enforcement | [`../internal/policy/`](../internal/policy/), [`../internal/enforce/`](../internal/enforce/), [`../policies/`](../policies/) |
| Scanners and runtime guardrail | [`../internal/scanner/`](../internal/scanner/), [`../internal/guardrail/`](../internal/guardrail/) |
| OpenShell sandbox integration (see [`SANDBOX.md`](SANDBOX.md)) | [`../internal/openshell/`](../internal/openshell/), [`../internal/sandboxauth/`](../internal/sandboxauth/), [`../policies/sandbox/`](../policies/sandbox/) |
| Audit store and action contract | [`../internal/audit/`](../internal/audit/) |
| Inventory and discovery persistence | [`../internal/inventory/`](../internal/inventory/) |
| Canonical telemetry and destinations | [`../internal/observability/`](../internal/observability/), [`../internal/telemetry/`](../internal/telemetry/) |
| Versioned configuration and telemetry schemas | [`../schemas/`](../schemas/) |

## Contract boundaries

### Configuration

The v8 source schema is
[`../schemas/config/v8/defenseclaw-config.schema.json`](../schemas/config/v8/defenseclaw-config.schema.json).
Go and Python loaders must agree with it. Generated reference files are views,
not independent authorities; see [`../schemas/README.md`](../schemas/README.md).

### Gateway API

Routes are registered in
[`../internal/gateway/api.go`](../internal/gateway/api.go) and focused endpoint
files. Consumer documentation is published on the
[gateway API page](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/gateway-api/).
Do not maintain a second endpoint table in repository Markdown.

### Connectors

Hook delivery fails closed by default. Only under the Secure Client
integration does an unset `hook_fail_mode` default to open, independently of
action-mode policy enforcement (see the published
[fail modes](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/fail-modes/) page). An explicit closed is always kept; OSS, standalone
and other managed installs keep the fail-closed rules, including managed Codex
and Claude Code and standalone Devin. Managed authorization, runtime integrity
and strict availability remain distinct controls.

Windows Cursor's protected machine adapter binds delivery fallback to each
enrolled process SID and verifies it against that user's authenticated runtime.
Its shared `failClosed` flag remains conservative if any enrolled user is closed;
launcher errors inside the running adapter use the individual user's policy.

Connector names, capabilities, hook profiles, and setup behavior are executable
contracts under `internal/gateway/connector/` and
`cli/defenseclaw/connector_contracts.py`. A new connector or capability change
must update both implementations, their tests, and the published compatibility
pages.

Agent-version evidence selects the exact hook contract when available, but is
not a Unix enterprise installation prerequisite. An unversioned, unsupported,
or incompatibly changed contract uses the reviewed best-effort event matrix,
in fail-open mode under Secure Client, until a later reconciliation verifies a
known contract. Version
changes inside the same registered contract remain compatible. A delivered
DefenseClaw deny stays a deny: fail-open covers only delivery, authentication,
timeout and malformed-response failures, and Windows enrollment and the strict
managed artifact readers stay mandatory for an unverified contract.

### Policy

OPA admission/policy-domain files under `policies/rego/` are separate from
runtime guardrail rule packs under `policies/guardrail/`. The code-level
boundary is documented in
[`GUARDRAIL_RULE_PACKS.md`](GUARDRAIL_RULE_PACKS.md).

Trusted tool-call parsing is private to `internal/actionfacts/`. Narrow CEL
expressions are compiled with rule packs and dispatched by
`internal/gateway/`; OPA keeps its existing policy-domain role. Fixed ordered
tool chains are defined in `internal/guardrail/` and use content-free state in
the existing `internal/audit/` SQLite store. Only authenticated connector-hook
events with canonical session correlation can join a blocking chain.

### Observability

Telemetry families are authored in
[`../schemas/telemetry/v8/`](../schemas/telemetry/v8/). Deterministic generators
produce runtime schemas, Go builders, IDs, and fixtures. Destination code
consumes canonical records through `internal/observability/`; it does not define
parallel event families. See [`OBSERVABILITY.md`](OBSERVABILITY.md).

## Verification rule

When prose and code disagree, fix both in the same change. Behavioral claims
should point to a schema, registry, route registration, implementation, or test;
mutable installation and operator commands should point to the website instead.
