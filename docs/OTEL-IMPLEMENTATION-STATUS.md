# DefenseClaw OpenTelemetry — Implementation Status

> Audit of `OTEL.md` spec vs actual implementation as of 2026-04-01.

---

## Summary

The OTel implementation covers **all 4 signal categories** fully. The
guardrail proxy path provides full GenAI semconv trace hierarchy with
`invoke_agent`, `chat`, `apply_guardrail`, and `execute_tool` spans.

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

*Compiled: 2026-04-01 | Source: Code audit of DefenseClaw*
