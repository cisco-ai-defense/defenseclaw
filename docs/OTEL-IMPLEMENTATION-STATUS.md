# DefenseClaw OpenTelemetry — Implementation Status

> Audit of `OTEL.md` spec vs actual implementation as of 2026-03-29.

---

## Summary

The OTel implementation covers **3 of 4 signal categories** fully, with
partial implementation of the fourth (Runtime Traces). Overall the
telemetry foundation is mature — the main gap is **LLM call spans**,
which are defined in code but never wired to any event source.

| Category | Spec Section | Status | Notes |
|----------|-------------|--------|-------|
| Asset lifecycle events | §3 Logs | **COMPLETE** | All actions mapped and emitted |
| Asset scan results | §4 Logs + Metrics | **COMPLETE** | Summary + individual findings + metrics |
| Runtime events (Traces) | §5 Traces | **PARTIAL** | Tool + Approval spans wired; LLM spans dead code |
| Runtime alerts | §6 Logs | **COMPLETE** | All alert types emitted |
| Metrics | §7 | **COMPLETE** | All counters/histograms registered, 28+ instruments |
| Configuration | §8 | **COMPLETE** | Full config struct, env var overrides |

---

## Detailed Status by Telemetry Method

### Traces (Spans)

| Method | File | Wired In Production? | Trigger |
|--------|------|---------------------|---------|
| `EmitStartupSpan` | `runtime.go:35` | **YES** | Gateway startup (once) |
| `EmitInspectSpan` | `runtime.go:49` | **YES** | HTTP `/inspect/tool` (CodeGuard) |
| `StartToolSpan` / `EndToolSpan` | `runtime.go:70–148` | **YES** | WS `tool_call` / `tool_result` via `router.go` |
| `StartApprovalSpan` / `EndApprovalSpan` | `runtime.go:150–210` | **YES** | WS `exec.approval.requested` via `router.go` |
| `StartLLMSpan` / `EndLLMSpan` | `runtime.go:212–280` | **NO — DEAD CODE** | No caller anywhere in codebase |
| `StartPolicySpan` / `EndPolicySpan` | `policy.go:20–80` | **YES** | HTTP `/policy/evaluate/*` + watcher |

#### LLM Span Gap Analysis

`StartLLMSpan()` and `EndLLMSpan()` are fully implemented with correct
GenAI semantic convention attributes (`gen_ai.system`, `gen_ai.request.model`,
`gen_ai.usage.prompt_tokens`, etc.) but **zero production callers exist**.

**Root cause**: OpenClaw does not emit `llm_call` / `llm_result` WebSocket
events. The `OTEL.md` spec (§9c) documents these as "future":

```
### 9c. LLM Gateway Hooks (future)
When OpenClaw provides `llm_call` / `llm_result` events: ...
```

The `EventRouter.Route()` switch in `router.go` handles these events:
- `tool_call` → `handleToolCall()` → `StartToolSpan` ✓
- `tool_result` → `handleToolResult()` → `EndToolSpan` ✓
- `exec.approval.requested` → `handleApprovalRequest()` → `StartApprovalSpan` ✓
- `session.tool` → normalizes to `tool_call`/`tool_result` ✓
- `agent` (stream=tool) → normalizes to `session.tool` ✓
- `session.message` (stream=tool) → normalizes to `session.tool` ✓

**No handler exists for `llm_call` / `llm_result`**. The `session.message`
handler (Format A) parses chat messages with `model` and `provider` fields
but only logs them — it does not create LLM spans.

#### What Would Be Needed for LLM Spans

Two options:

1. **Wait for OpenClaw** to emit explicit `llm_call` / `llm_result` events
   and add handlers in `Route()` (the spec's stated plan).

2. **Derive LLM spans from `session.message`** — the `handleSessionMessage()`
   Format A handler already parses `role`, `model`, `provider`, `stopReason`,
   and `content`, but no telemetry calls are made. An `assistant` message
   with a `model` field could trigger `StartLLMSpan`/`EndLLMSpan`.

### Logs

| Method | File | Wired? | Trigger |
|--------|------|--------|---------|
| `EmitLifecycleEvent` | `lifecycle.go` | **YES** | `audit.Logger.LogAction()` |
| `EmitScanResult` | `scan.go` | **YES** | `audit.Logger.LogScan()` |
| `EmitScanFinding` | `scan.go` | **YES** | Per-finding (opt-in `emit_individual_findings`) |
| `EmitRuntimeAlert` | `alerts.go` | **YES** | `router.go` (dangerous commands, guardrails) + `inspect.go` (CodeGuard) |

### Metrics

All metric instruments are registered in `metrics.go` and recorded by their
respective telemetry methods. **All spec'd metrics from §7 are implemented**:

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
| `defenseclaw.llm.calls` | Counter | `RecordLLMCall()` ← `StartLLMSpan()` (**dead path**) |
| `defenseclaw.llm.tokens` | Counter | `RecordLLMTokens()` ← `EndLLMSpan()` (**dead path**) |
| `defenseclaw.llm.duration` | Histogram | `RecordLLMDuration()` ← `EndLLMSpan()` (**dead path**) |
| `defenseclaw.alert.count` | Counter | `RecordAlert()` ← `EmitRuntimeAlert()` |
| `defenseclaw.guardrail.evaluations` | Counter | `RecordGuardrailEvaluation()` |
| `defenseclaw.guardrail.latency` | Histogram | `RecordGuardrailLatency()` |
| `defenseclaw.policy.evaluations` | Counter | `RecordPolicyEvaluation()` ← `EndPolicySpan()` |
| `defenseclaw.policy.latency` | Histogram | `RecordPolicyLatency()` ← `EndPolicySpan()` |

**Note**: LLM metrics (`defenseclaw.llm.*`) instruments are registered but
never called because the LLM span methods are dead code.

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

**Key observation**: Tool calls reach `StartToolSpan`/`EndToolSpan` via
5 different OpenClaw event formats (tool_call, session.tool, agent stream,
agent legacy, session.message stream). The normalization is robust.

---

## Runtime Span Prerequisites

Tool, approval, and inspect spans **require a live OpenClaw WebSocket
connection**. The gateway connects to OpenClaw at `wss://<host>:<port>` and
receives events only when an agent session is actively running.

Without OpenClaw:
- `defenseclaw/startup` span — **always emitted** (verifies pipeline)
- `tool/*` spans — **never emitted** (no `tool_call` events arrive)
- `exec.approval/*` spans — **never emitted** (no approval events)
- `inspect/*` spans — **emitted via HTTP** (CodeGuard, not WS-dependent)
- `policy/*` spans — **emitted via HTTP** (REST API or watcher, not WS-dependent)

---

## File Reference

| File | Purpose | Signal Types |
|------|---------|-------------|
| `internal/telemetry/provider.go` | OTel Provider, InitProvider, TracerProvider/LoggerProvider/MeterProvider | All |
| `internal/telemetry/resource.go` | buildResource() with all resource attributes | All |
| `internal/telemetry/lifecycle.go` | EmitLifecycleEvent() — asset install/block/allow/quarantine | Logs |
| `internal/telemetry/scan.go` | EmitScanResult(), EmitScanFinding() | Logs + Metrics |
| `internal/telemetry/runtime.go` | StartToolSpan, EndToolSpan, StartLLMSpan (**dead**), EndLLMSpan (**dead**), StartApprovalSpan, EndApprovalSpan, EmitStartupSpan, EmitInspectSpan | Traces + Metrics |
| `internal/telemetry/alerts.go` | EmitRuntimeAlert() | Logs + Metrics |
| `internal/telemetry/metrics.go` | All metric instruments (28+ counters/histograms) | Metrics |
| `internal/telemetry/policy.go` | StartPolicySpan, EndPolicySpan | Traces + Metrics |
| `internal/gateway/router.go` | EventRouter — WS event dispatch, tool/approval span lifecycle | Consumes telemetry |
| `internal/gateway/inspect.go` | CodeGuard inspection — EmitInspectSpan, EmitRuntimeAlert | Consumes telemetry |
| `internal/gateway/api.go` | REST API — StartPolicySpan/EndPolicySpan | Consumes telemetry |

---

## Recommendations

1. **Update OTEL.md §5d** to mark LLM Call Span as `(planned — awaiting OpenClaw llm_call/llm_result events)` instead of presenting it alongside implemented spans.

2. **Consider deriving LLM spans from `session.message`** — the Format A handler already parses `model`, `provider`, `stopReason`, and `content`. Adding `StartLLMSpan`/`EndLLMSpan` calls for `role=assistant` messages with a `model` field would activate the existing dead code without waiting for OpenClaw.

3. **Add `Agent Session Span`** — OTEL.md §5a shows a root `[Agent Session Span]` in the hierarchy but no implementation exists. The `handleAgentStreamEvent()` lifecycle handler (`start`/`end` events) could create this span.

---

*Compiled: 2026-03-29 | Source: Code audit of DefenseClaw v0.2.0*
