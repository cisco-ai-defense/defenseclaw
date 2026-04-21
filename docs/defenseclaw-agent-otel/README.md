# DefenseClaw Agent OTel

`defenseclaw-agent-otel` writes persistent OTLP configuration for
`Claude Code` and `Codex`.

After a one-time configuration step, normal desktop launches of `claude` and
`codex` send telemetry directly to Splunk Observability Cloud or another
OTLP/HTTP endpoint. There is no local relay in this flow.

## Build

```bash
make agent-otel
```

This produces:

```bash
./defenseclaw-agent-otel
```

## Configure Direct Splunk Observability Export

```bash
export SPLUNK_OBSERVABILITY_TOKEN="your-token-here"

./defenseclaw-agent-otel configure \
  --tool all \
  --splunk-host app.us1.observability.splunkcloud.com \
  --token "$SPLUNK_OBSERVABILITY_TOKEN" \
  --environment defenseclaw-direct-test
```

This writes:

- `~/.claude/settings.json`
- `~/.codex/config.toml`

The tool derives:

- traces → `https://ingest.us1.signalfx.com/v2/trace/otlp`
- metrics → `https://ingest.us1.signalfx.com/v2/datapoint/otlp`

and uses the `X-SF-Token` header.

For `Claude Code`, the tool also writes OTLP log-exporter settings pointed at
`https://ingest.<realm>.signalfx.com/v1/logs`. Splunk O11y does not accept
direct OTLP logs there, but current Claude desktop builds bootstrap trace
export more reliably when the OTLP log exporter is present.

## Configure Distinct Claude and Codex Agents

Use shared flags such as `--environment` and `--agent-name` as defaults, then
override them per tool with `--claude-*` and `--codex-*` flags when Claude and
Codex should appear as separate desktop agents.

```bash
./defenseclaw-agent-otel configure \
  --tool all \
  --splunk-host app.us1.observability.splunkcloud.com \
  --token "$SPLUNK_OBSERVABILITY_TOKEN" \
  --environment desktop \
  --claude-agent-name claude-desktop \
  --claude-environment claude-dev \
  --claude-tenant-id tenant-a \
  --claude-workspace-id workspace-claude \
  --codex-agent-name codex-desktop \
  --codex-environment codex-dev \
  --codex-tenant-id tenant-a \
  --codex-workspace-id workspace-codex
```

When both shared and tool-specific flags are present, the tool-specific value
takes precedence for that tool.

## Configure a Generic OTLP/HTTP Endpoint

Use this when you want Claude and Codex to send directly to your own collector
or OTLP gateway instead of Splunk O11y’s ingest endpoints.

```bash
./defenseclaw-agent-otel configure \
  --tool all \
  --endpoint http://collector.internal:4318 \
  --token "$OTLP_AUTH_TOKEN" \
  --header-name Authorization \
  --header-prefix "Bearer " \
  --tenant-id demo-tenant \
  --workspace-id defenseclaw \
  --agent-name desktop-agents \
  --environment dev
```

## Unconfigure

```bash
./defenseclaw-agent-otel unconfigure --tool all
```

You can also target one tool:

```bash
./defenseclaw-agent-otel unconfigure --tool claude
./defenseclaw-agent-otel unconfigure --tool codex
```

## Notes

- Direct Splunk Observability mode configures `traces` and `metrics`
- `Claude Code` direct mode also writes OTLP log-exporter settings as a
  bootstrap requirement for current desktop builds
- Splunk Observability Cloud still does not accept direct OTLP logs on
  `/v1/logs`, so those requests may 404 while traces and metrics continue to
  work
- Claude Code persistent config supports `OTEL_RESOURCE_ATTRIBUTES`, so
  `tenant_id`, `workspace_id`, and `agent_name` are written there
- Codex persistent config supports native OTEL exporter config in
  `~/.codex/config.toml`, but does not expose a documented config key for
  arbitrary OTEL resource attributes, so `--codex-agent-name`,
  `--codex-tenant-id`, and `--codex-workspace-id` are accepted as CLI
  overrides but are not persisted in direct mode today
- In live verification, `Codex Desktop` traces reached Splunk O11y but still
  showed `deployment.environment` / `sf_environment` as `unknown`, so treat
  `--environment` as best-effort for Codex direct mode today
