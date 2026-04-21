# DefenseClaw Agent OTel

`defenseclaw-agent-otel` writes persistent OTLP configuration for
`Claude Code` and `Codex`, and can also launch one-shot sessions with direct
OTEL settings applied at runtime.

After a one-time configuration step, normal desktop launches of `claude` and
`codex` send telemetry directly to Splunk Observability Cloud or another
OTLP/HTTP endpoint. There is no local relay in this flow.

It also supports a one-shot `run` mode that launches `claude` or `codex` with
direct OTEL settings for that session only. `Claude Code` uses runtime OTEL
environment variables only. `Codex` uses runtime OTEL environment variables
plus one-shot `otel.*` command-line overrides. This mode does not create a
temporary home directory or write per-run settings files.

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

## Run a Single Session Without Persisting Desktop Config

Use `run` when you want to start one `claude` or `codex` session with direct
OTEL export and tags, without writing `~/.claude/settings.json` or
`~/.codex/config.toml`.

Codex example:

```bash
export CODEX_RUN_ENV="codex-run-test-$(date +%s)"

./defenseclaw-agent-otel run \
  --tool codex \
  --splunk-host app.us1.observability.splunkcloud.com \
  --token "$SPLUNK_OBSERVABILITY_TOKEN" \
  --environment "$CODEX_RUN_ENV" \
  --tenant-id tenant-a \
  --workspace-id workspace-codex \
  --agent-name codex-desktop \
  -- exec --skip-git-repo-check --json "Reply with ok only"
```

Claude example:

```bash
export CLAUDE_RUN_ENV="claude-run-test-$(date +%s)"

./defenseclaw-agent-otel run \
  --tool claude \
  --splunk-host app.us1.observability.splunkcloud.com \
  --token "$SPLUNK_OBSERVABILITY_TOKEN" \
  --claude-environment "$CLAUDE_RUN_ENV" \
  --claude-tenant-id tenant-a \
  --claude-workspace-id workspace-claude \
  --claude-agent-name claude-desktop \
  -- -p --model haiku --output-format json "Reply with ok only"
```

If you omit the arguments after `--`, the tool launches the interactive
`claude` or `codex` session with OTEL config injected.

For `Claude Code`, `run` injects OTEL settings through runtime environment
variables only. For `Codex`, `run` injects OTEL settings through runtime
environment variables and one-shot `otel.*` CLI overrides. It does not modify
the real `~/.claude/settings.json` or `~/.codex/config.toml`.

When verifying these one-shot runs in Splunk O11y, the trace-derived series can
take a couple of minutes to appear after the command finishes.

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
- Codex one-shot `run` mode injects the same resource tags through
  `OTEL_RESOURCE_ATTRIBUTES` as best effort, but you should still verify which
  dimensions your backend actually receives
- Recent live verification showed the one-shot `run` flow publishing
  trace-derived series for both `Codex Desktop` and `claude-code`, with the
  requested `sf_environment` visible in Splunk O11y after a short ingestion
  delay
