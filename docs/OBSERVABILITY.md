# Observability implementation

Configuration, setup, routing, redaction, destinations, dashboards, upgrades,
and troubleshooting are documented in the
[published observability guide](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/).
This file only maps the config-v8 implementation and its authoring sources.

## Authoritative sources

| Concern | Source |
| --- | --- |
| Event, span, metric, field, and producer registry | [`schemas/telemetry/v8/registry.yaml`](../schemas/telemetry/v8/registry.yaml), [`genai.yaml`](../schemas/telemetry/v8/genai.yaml), [`security.yaml`](../schemas/telemetry/v8/security.yaml), and [`operations.yaml`](../schemas/telemetry/v8/operations.yaml) |
| Configuration schema | [`schemas/config/v8/defenseclaw-config.schema.json`](../schemas/config/v8/defenseclaw-config.schema.json) |
| Canonical records, builders, imports, projection, and redaction | [`internal/observability/`](../internal/observability/) |
| Runtime collection, local history, health, routing, and delivery | [`internal/observability/runtime/`](../internal/observability/runtime/), [`router/`](../internal/observability/router/), and [`delivery/`](../internal/observability/delivery/) |
| Destination adapters | [`internal/observability/destinations/`](../internal/observability/destinations/) |
| Local Grafana stack and Prometheus rules | [`bundles/local_observability_stack/`](../bundles/local_observability_stack/) |

Files named `internal/observability/zz_generated_telemetry_*.go` and the runtime
assets under `schemas/telemetry/runtime/` are generated outputs. Edit the v8
registry/domain YAML, run `make telemetry-generate`, review the generated diff,
and verify it with `make telemetry-check`. Do not hand-edit those outputs.

The exhaustive generated configuration-field reference is
[`schemas/config/v8/reference/observability.md`](../schemas/config/v8/reference/observability.md).
It is a schema artifact, not a second operator guide.

## Bundled integrations

- [Local OpenTelemetry, Prometheus, Loki, Tempo, and Grafana](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/local-observability/)
- [Grafana dashboard catalog](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/grafana-dashboards/)
- [Agent360](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/agent360/)
- [Splunk](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/splunk/)
- [Galileo](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/galileo/)

## Alert runbooks

The bundled Prometheus annotations target these canonical website sections:

- [Schema violations](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/#runbook-schema-violations)
- [Block SLO](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/#runbook-block-slo)
- [Exporter stalled](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/#runbook-exporter-stalled)
- [Audit sink](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/#runbook-audit-sink)

Keep those published anchors stable when changing alert annotations.
