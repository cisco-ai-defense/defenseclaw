# DefenseClaw OpenTelemetry — Implementation Status

> Audit of `OTEL.md` spec vs actual implementation as of **2026-04-21** (v7 closeout).

---

## v7 posture (2026-04-21)

- **Gateway structured events:** `internal/gatewaylog` + `internal/telemetry/gateway_events.go` map every `gatewaylog.Event` to OTel LogRecords (when logs enabled) and derive **metrics** for `verdict`, `judge`, and `error` event types (`defenseclaw.gateway.verdicts`, `defenseclaw.gateway.judge.invocations`, `defenseclaw.gateway.judge.latency`, `defenseclaw.gateway.judge.errors`, `defenseclaw.gateway.errors`). Scan/activity add `defenseclaw.scan.*` and `defenseclaw.activity.*` via `EmitScanResult` / `RecordActivityTotal`.
- **Provenance:** `gatewaylog.Writer.Emit` stamps `schema_version`, `content_hash`, `generation`, `binary_version` via `Event.StampProvenance` / writer choke point — do not hand-stamp at call sites.
- **SLO histograms:** `defenseclaw.slo.block.latency` (admission enforce path) and `defenseclaw.slo.tui.refresh` include multi-second upper buckets (e.g. 2000ms / 5000ms targets per product SLOs).
- **Sampling / exporters:** Controlled by `config.OTel` — traces, metrics, logs independently toggled; OTLP gRPC/HTTP supported (`internal/telemetry/provider.go`). When OTel is disabled, structured gateway events still flow to JSONL + SQLite-relevant paths.
- **Known limitations:** `telemetry.RecordGatewayEventEmitted` exists but is not yet invoked from `gatewaylog.Writer` (rate comparison helper for Track 10); lifecycle/diagnostic events rely on log body + JSONL for observability. See `docs/OBSERVABILITY-CONTRACT.md` and `test/e2e/v7_observability_test.go` TODOs.

Downstream contract: **[OBSERVABILITY-CONTRACT.md](./OBSERVABILITY-CONTRACT.md)**.

---

## Summary

The OTel implementation covers **all 4 signal categories** fully. The
guardrail proxy path provides full GenAI semconv trace hierarchy with
`invoke_agent`, `chat`, `apply_guardrail`, and `execute_tool` spans.

As of the **v7 observability contract**, every emitted
event — OTel span, audit row, `gatewaylog.Event`, Splunk HEC record,
OTLP log record — should carry a consistent correlation envelope where
the event type allows: `run_id`, `session_id`, `trace_id`, `request_id`,
`agent_id`, `agent_name`, `agent_instance_id`, `sidecar_instance_id`,
`policy_id`, `destination_app`, `tool_name`, and `tool_id`. See
[Correlation envelope](#correlation-envelope-v6) (field list evolved in v7;
three-tier identity in OBSERVABILITY-CONTRACT.md).

| Category | Spec Section | Status | Notes |
|----------|-------------|--------|-------|
| Asset lifecycle events | §3 Logs | **COMPLETE** | All actions mapped and emitted |
| Asset scan results | §4 Logs + Metrics | **COMPLETE** | Summary + individual findings + metrics |
| Runtime events (Traces) | §5 Traces | **COMPLETE** | Full proxy path + WS tool/approval spans |
| Runtime alerts | §6 Logs | **COMPLETE** | All alert types emitted |
| Metrics | §7 | **COMPLETE** | `gen_ai.client.*` semconv + `defenseclaw.*` custom metrics |
| Configuration | §8 | **COMPLETE** | Full config struct, env var overrides |

---

## Telemetry Paths

DefenseClaw has **two distinct telemetry paths**:

### Path 1: Guardrail Proxy (LLM Gateway)

HTTP proxy on port 4000 intercepts OpenAI-compatible requests. Produces
the full GenAI semconv trace hierarchy:

```
invoke_agent {agentName}                    root span (SpanKind=INTERNAL)
├── apply_guardrail defenseclaw input       input inspection
└── chat {model}                            LLM call (SpanKind=CLIENT)
    ├── apply_guardrail defenseclaw output  output inspection
    ├── execute_tool {toolName}             per tool_call in response
    │   └── apply_guardrail defenseclaw tool_call  tool args inspection
    └── execute_tool {toolName}
        └── apply_guardrail defenseclaw tool_call
```

**Metrics emitted per LLM call:**
- `gen_ai.client.token.usage` — histogram, `{token}`, with `gen_ai.token.type` = `input`/`output`
- `gen_ai.client.operation.duration` — histogram, `s`

**Common attributes on both metrics:**
- `gen_ai.operation.name` (e.g. `chat`)
- `gen_ai.provider.name` (e.g. `defenseclaw`)
- `gen_ai.request.model` (e.g. `gpt-4o-mini`)

### Path 2: WebSocket Event Router

Gateway subscribes to OpenClaw WebSocket events. Tool/approval spans are
emitted from real-time agent session events:

```
tool/{toolName}           from tool_call → tool_result WS events
exec.approval/{id}        from exec.approval.requested WS events
```

---

## Detailed Status by Telemetry Method

### Traces (Spans)

| Method | File | Wired In Production? | Trigger |
|--------|------|---------------------|---------|
| `EmitStartupSpan` | `runtime.go` | **YES** | Gateway startup (once) |
| `EmitInspectSpan` | `runtime.go` | **YES** | HTTP `/inspect/tool` (CodeGuard) |
| `StartAgentSpan` / `EndAgentSpan` | `runtime.go` | **YES** | Guardrail proxy — per HTTP request |
| `StartLLMSpan` / `EndLLMSpan` | `runtime.go` | **YES** | Guardrail proxy — LLM forward + response |
| `StartGuardrailSpan` / `EndGuardrailSpan` | `runtime.go` | **YES** | Guardrail proxy — input/output/tool_call inspection |
| `StartToolSpan` / `EndToolSpan` | `runtime.go` | **YES** | Guardrail proxy (tool_calls in response) + WS events |
| `StartApprovalSpan` / `EndApprovalSpan` | `runtime.go` | **YES** | WS `exec.approval.requested` via `router.go` |
| `StartPolicySpan` / `EndPolicySpan` | `policy.go` | **YES** | HTTP `/policy/evaluate/*` + watcher |

### Logs

| Method | File | Wired? | Trigger |
|--------|------|--------|---------|
| `EmitLifecycleEvent` | `lifecycle.go` | **YES** | `audit.Logger.LogAction()` |
| `EmitScanResult` | `scan.go` | **YES** | `audit.Logger.LogScan()` |
| `EmitScanFinding` | `scan.go` | **YES** | Per-finding (opt-in `emit_individual_findings`) |
| `EmitRuntimeAlert` | `alerts.go` | **YES** | `router.go` + `inspect.go` + guardrail proxy |

### Metrics — GenAI Semconv

| Metric | Instrument | Unit | Buckets | Callers |
|--------|-----------|------|---------|---------|
| `gen_ai.client.token.usage` | Float64Histogram | `{token}` | 1,4,16,...,67M | `RecordLLMTokens()` ← `EndLLMSpan()` |
| `gen_ai.client.operation.duration` | Float64Histogram | `s` | 0.01,...,81.92 | `RecordLLMDuration()` ← `EndLLMSpan()` |

### Metrics — DefenseClaw Custom

| Metric | Instrument | Callers |
|--------|-----------|---------|
| `defenseclaw.scan.count` | Counter | `RecordScan()` ← `EmitScanResult()` |
| `defenseclaw.scan.duration` | Histogram | `RecordScan()` |
| `defenseclaw.scan.findings` | Counter | `RecordScan()` |
| `defenseclaw.scan.findings.gauge` | UpDownCounter | `RecordScan()` |
| `defenseclaw.tool.calls` | Counter | `RecordToolCall()` ← `StartToolSpan()` |
| `defenseclaw.tool.duration` | Histogram | `RecordToolDuration()` ← `EndToolSpan()` |
| `defenseclaw.tool.errors` | Counter | `RecordToolError()` ← `EndToolSpan()` |
| `defenseclaw.approval.count` | Counter | `RecordApproval()` ← `EndApprovalSpan()` |
| `defenseclaw.alert.count` | Counter | `RecordAlert()` ← `EmitRuntimeAlert()` |
| `defenseclaw.guardrail.evaluations` | Counter | `RecordGuardrailEvaluation()` |
| `defenseclaw.guardrail.latency` | Histogram | `RecordGuardrailLatency()` |
| `defenseclaw.policy.evaluations` | Counter | `RecordPolicyEvaluation()` ← `EndPolicySpan()` |
| `defenseclaw.policy.latency` | Histogram | `RecordPolicyLatency()` ← `EndPolicySpan()` |

---

## Correlation envelope (v6 / v7)

Every emitted event carries as many of these fields as the event type
meaningfully provides. Fields that don't apply to a given event stay
empty rather than being faked. **v7** adds `agent_id` and
`sidecar_instance_id` alongside `agent_instance_id` (see OBSERVABILITY-CONTRACT.md).

| Field | Semantics | Source of truth |
|-------|-----------|-----------------|
| `run_id` | One per agent invocation (OpenClaw `runId`). | `activeAgent.runID` / `DEFENSECLAW_RUN_ID` env / per-request envelope |
| `session_id` | OpenClaw conversation / session key. | `payload.sessionKey` (agent stream) or `X-Conversation-ID` header |
| `trace_id` | W3C trace ID for the enclosing OTel span. | Populated from active span context; written into `audit.Event.TraceID` + `gatewaylog.Event.TraceID` |
| `request_id` | Proxy HTTP request correlator. | `X-Request-ID` header / generated by guardrail proxy |
| `agent_id` | **v7** Logical stable agent identifier. | Stream / plugin / config |
| `agent_name` | Agent framework name, e.g. `openclaw`. | Stream-supplied hint wins; falls back to `cfg.Claw.Mode` via `SetDefaultAgentName` |
| `agent_instance_id` | Session-scoped or process-default agent instance. | Router session key hash or `audit.SetProcessAgentInstanceID` |
| `sidecar_instance_id` | **v7** Per gateway process. | Minted at sidecar boot; distinct from `agent_instance_id` |
| `policy_id` | Active guardrail / admission policy. | `cfg.Guardrail.Mode`, threaded via `SetDefaultPolicyID` on router + proxy |
| `destination_app` | Tool provider bucket. | `builtin`, `mcp:<server>`, `skill:<key>` for tool events; `gen_ai.system` (e.g. `openai`, `anthropic`) for LLM events |
| `tool_name` | Human-readable tool name. | `ToolCallPayload.Tool` / `ToolResultPayload.Tool` |
| `tool_id` | Provider-assigned tool_call id (e.g. OpenAI `tool_call_id`). | `ToolCallPayload.ID` — required for `/v1/agentwatch/summary` `top_tools` aggregation and for joining `tool_call` + `tool_result` rows in SIEMs |

**Propagation surfaces:**

1. `audit.Event` (SQLite `audit_events` — migrated in Phase 6) —
   persistent store of record, selectable by every new column.
2. `sinks.Event` → `SplunkHECSink` / `OTLPLogsSink` / `http_jsonl` —
   every sink emits the full envelope.
3. `gatewaylog.Event` envelope — JSONL stream consumed by the Splunk
   Local Bridge and the AgentWatch API.
4. OTel spans — `StartToolSpan` and `StartApprovalSpan` take a
   `telemetry.ToolSpanContext` that carries the correlation fields
   onto span attributes (`gen_ai.tool.call.id`,
   `defenseclaw.tool.id`, `gen_ai.conversation.id`,
   `defenseclaw.session.id`, `defenseclaw.run.id`,
   `defenseclaw.destination.app`, `defenseclaw.policy.id`,
   `gen_ai.agent.name`, `gen_ai.agent.id`,
   `defenseclaw.agent.instance_id`).

**Best-effort correlation for approvals:** exec approval events don't
carry `run_id`/`session_id` on the wire. `EventRouter.activeAgentCorrelation()`
returns them only when exactly one agent is active in the sidecar;
with zero or multiple active agents it returns empty values and
downstream consumers must fall back to `trace_id`.

---

## Gaps and Recommendations

### 1. `gen_ai.agent.name` propagation to metrics

**Current state**: The `invoke_agent` span carries `gen_ai.agent.name` but
`RecordLLMTokens()` and `RecordLLMDuration()` do not include it as a metric
attribute. The SDOT Python utils (`MetricsEmitter`) propagate `gen_ai.agent.name`
to all `gen_ai.client.*` metrics when `llm_invocation.agent_name` is set.

**Action**: Add optional `agentName` parameter to `RecordLLMTokens()` and
`RecordLLMDuration()`. Thread agent name from the proxy handler (known at
`StartAgentSpan` time) through to `EndLLMSpan()` → metric recording.

### 2. `gen_ai.workflow.name` support

**Current state**: No workflow concept exists in DefenseClaw proxy path.
The SDOT utils support `Workflow` as a parent span with `gen_ai.workflow.name`
that propagates to all child LLM calls. DefenseClaw could treat the OpenClaw
conversation/session as a workflow.

**Action**: Optional for v1. Consider adding `gen_ai.workflow.name` to
the `invoke_agent` span attributes and to metric dimensions when a workflow
name is available (e.g. from OpenClaw config or conversation metadata).

### 3. Span attributes alignment with SDOT semconv

**Current state**: DefenseClaw spans use correct `gen_ai.*` attributes.
Some attributes are DefenseClaw-specific (`defenseclaw.llm.tool_calls`,
`defenseclaw.llm.guardrail`, etc.) — these are additive over semconv.

The `execute_tool` spans from the proxy path use `gen_ai.operation.name`
and `gen_ai.tool.name` matching semconv. The WS-path tool spans use
`defenseclaw.tool.*` attributes (different naming, predates proxy path).

**Action**: Consider aligning WS-path tool spans to also use `gen_ai.*`
semconv attributes for consistency.

### 4. `gen_ai.system` attribute on spans and metrics

**Current state**: `StartLLMSpan` sets `gen_ai.system` on the span but
`RecordLLMTokens`/`RecordLLMDuration` use `gen_ai.provider.name` instead.
The SDOT utils include `gen_ai.system` in metrics via the `system` field
on `GenAI` base type, separate from `provider`.

**Action**: The proxy passes `"defenseclaw"` as `providerName` because it
acts as a proxy, not the actual LLM provider. Consider also passing the
underlying `gen_ai.system` (e.g. `openai`) for proper metric dimensioning.

---

## Event Router — Complete Event Flow

The gateway's `EventRouter.Route()` handles all WebSocket events from
OpenClaw. Tool call telemetry flows through multiple normalization layers:

```
OpenClaw WebSocket Events
│
├── tool_call ───────────────────────────→ handleToolCall() → StartToolSpan
├── tool_result ─────────────────────────→ handleToolResult() → EndToolSpan
├── exec.approval.requested ─────────────→ handleApprovalRequest() → StartApprovalSpan/EndApprovalSpan
│
├── session.tool ────────────────────────→ handleSessionTool()
│   └── normalize phase → type             └──→ synthetic tool_call/tool_result → handleToolCall/Result
│
├── agent (stream=tool) ─────────────────→ handleAgentStreamEvent()
│   └── wrap as session.tool                └──→ handleSessionTool() → handleToolCall/Result
│
├── agent (legacy: toolCall/toolResult) ─→ handleAgentEvent()
│   └── wrap as tool_call/tool_result       └──→ handleToolCall/Result
│
├── session.message (stream=tool) ───────→ handleSessionTool() → handleToolCall/Result
├── session.message (Format A: chat) ────→ LogAction only (NO TELEMETRY SPANS)
│
├── sessions.changed ────────────────────→ LogAction (errors only)
├── chat ────────────────────────────────→ LogAction (errors only)
└── tick/health/presence/heartbeat ──────→ ignored
```

---

## Guardrail Proxy — Request Flow

```
HTTP POST /v1/chat/completions
│
├── StartAgentSpan(conversationID, "openclaw")
│
├── Input Inspection
│   ├── StartGuardrailSpan("defenseclaw", "input", model)
│   ├── inspector.Inspect(direction="prompt")
│   └── EndGuardrailSpan(decision, severity)
│
├── StartLLMSpan(system, model, provider, maxTokens, temperature)
│
├── ChatCompletion → upstream LLM provider
│
├── Output Inspection (if content present)
│   ├── StartGuardrailSpan("defenseclaw", "output", model)
│   ├── inspector.Inspect(direction="completion")
│   └── EndGuardrailSpan(decision, severity)
│
├── Tool Call Spans (for each tool_call in response)
│   ├── StartToolSpan(toolName)
│   ├── StartGuardrailSpan("defenseclaw", "tool_call", model)
│   ├── inspector.Inspect(direction="tool_call", content=args)
│   ├── EndGuardrailSpan(decision, severity)
│   └── EndToolSpan(toolName)
│
├── EndLLMSpan(model, tokens, finishReasons, toolCallCount, guardrail)
│   ├── RecordLLMTokens → gen_ai.client.token.usage
│   └── RecordLLMDuration → gen_ai.client.operation.duration
│
└── EndAgentSpan
```

---

## File Reference

| File | Purpose | Signal Types |
|------|---------|-------------|
| `internal/telemetry/provider.go` | OTel Provider, InitProvider | All |
| `internal/telemetry/resource.go` | buildResource() | All |
| `internal/telemetry/lifecycle.go` | EmitLifecycleEvent() | Logs |
| `internal/telemetry/scan.go` | EmitScanResult(), EmitScanFinding() | Logs + Metrics |
| `internal/telemetry/runtime.go` | Agent/LLM/Tool/Approval/Guardrail spans | Traces + Metrics |
| `internal/telemetry/alerts.go` | EmitRuntimeAlert() | Logs + Metrics |
| `internal/telemetry/metrics.go` | All metric instruments (28+) | Metrics |
| `internal/telemetry/policy.go` | StartPolicySpan, EndPolicySpan | Traces + Metrics |
| `internal/gateway/router.go` | EventRouter — WS event dispatch | Consumes telemetry |
| `internal/gateway/proxy.go` | Guardrail proxy — full GenAI trace hierarchy | Consumes telemetry |
| `internal/gateway/inspect.go` | CodeGuard inspection | Consumes telemetry |
| `internal/gateway/api.go` | REST API | Consumes telemetry |

---

*Compiled: 2026-04-21 | Source: Code audit of DefenseClaw (v7 Track 11 closeout)*
