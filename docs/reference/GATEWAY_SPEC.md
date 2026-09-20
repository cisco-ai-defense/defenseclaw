# `internal/gateway` implementation map

`internal/gateway` is the integration package for the long-running Go gateway.
It composes the local API, connector ingress, optional proxy paths, policy and
inspection, audit persistence, and observability. It is not specific to one
connector topology.

The consumer-facing endpoint contract is maintained on the
[published gateway API page](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/gateway-api/).

## Ownership

| Concern | Primary source |
| --- | --- |
| Server construction and lifecycle | `sidecar.go`, `health.go` |
| Local HTTP API and middleware | `api.go`, `api_*.go`, `*_endpoint.go` |
| Provider proxy and adapters | `proxy.go`, `adapter_*.go` |
| Hook ingress and normalization | `agent_hook.go`, `unified_hook_dispatch.go`, `hook_*.go` |
| Connector contracts | `connector/` |
| Inspection and judge lanes | `inspect.go`, `inspector.go`, `llm_judge.go`, focused companion files |
| Application protection | `application_protection.go` |
| WebSocket integration | `client.go`, `router.go`, `gateway_ws*.go` |
| Canonical telemetry production | `*_observability_v8.go` and generated builders in `internal/observability/` |

Route registration in `api.go`, configuration in `internal/config`, and the
adjacent tests are authoritative. Filenames in this table are navigation aids,
not a claim that all behavior is contained in one file.

## Change requirements

- Add or update focused tests for every route, middleware, connector, proxy, or
  enforcement change.
- Preserve correlation, redaction, audit, and generated-telemetry contracts;
  do not create an endpoint-local parallel schema.
- Update the published API or connector page when externally observable
  behavior changes.
- Run the relevant Go package tests plus the schema/telemetry parity gates
  described in [`../TESTING.md`](../TESTING.md).
