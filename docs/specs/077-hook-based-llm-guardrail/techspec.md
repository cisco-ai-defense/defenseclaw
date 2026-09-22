# Spec 077 — Technical Specification

## 1. Plugin TypeScript changes

### 1.1 New file: `src/llm-scan-types.ts`

```typescript
export type ScanDirection = "input" | "output";

export interface ScanRequest {
  direction: ScanDirection;
  provider: string;
  model: string;
  content: ScanContent;
  session_id?: string;
  run_id?: string;
  agent_id?: string;
  trace_id?: string;
}

export interface ScanContent {
  system_prompt?: string;
  messages?: Array<{ role: string; content: string }>;
  tools?: Array<{ name: string; description?: string }>;
  assistant_text?: string;
}

export interface ScanFinding {
  type: string;
  severity: string;
  evidence?: string;
  scanner: string;
}

export interface ScanVerdict {
  action: "allow" | "block" | "flag";
  severity: "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reason: string;
  mode: "observe" | "action";
  findings: ScanFinding[];
  scan_duration_ms: number;
}
```

### 1.2 New file: `src/llm-scan.ts`

```typescript
import { randomUUID } from "node:crypto";
import type { ScanDirection, ScanRequest, ScanVerdict } from "./llm-scan-types.js";

export interface LlmScanClientOptions {
  sidecarBaseUrl: string;
  sidecarToken: string;
  timeoutMs?: number;
  getCorrelationHeaders: () => Record<string, string>;
  logOutboundRequest: (entry: Record<string, unknown>) => void;
}

const DEFAULT_TIMEOUT_MS = 5_000;

function failClosedVerdict(reason: string): ScanVerdict {
  const failOpen =
    (process.env.DEFENSECLAW_LLM_SCAN_FAIL_OPEN || "").trim() === "1";
  if (failOpen) {
    return {
      action: "allow",
      severity: "NONE",
      reason: `${reason} (fail-open opt-in)`,
      mode: "observe",
      findings: [],
      scan_duration_ms: 0,
    };
  }
  return {
    action: "block",
    severity: "HIGH",
    reason: `defenseclaw failing closed: ${reason}`,
    mode: "action",
    findings: [],
    scan_duration_ms: 0,
  };
}

export class LlmScanClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly timeoutMs: number;
  private readonly getHeaders: () => Record<string, string>;
  private readonly log: (entry: Record<string, unknown>) => void;

  constructor(opts: LlmScanClientOptions) {
    this.baseUrl = opts.sidecarBaseUrl;
    this.token = opts.sidecarToken;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.getHeaders = opts.getCorrelationHeaders;
    this.log = opts.logOutboundRequest;
  }

  async scan(req: ScanRequest): Promise<ScanVerdict> {
    const started = performance.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers: Record<string, string> = {
        ...this.getHeaders(),
        "Content-Type": "application/json",
      };
      if (this.token) {
        headers["Authorization"] = `Bearer ${this.token}`;
      }

      const res = await fetch(`${this.baseUrl}/api/v1/scan`, {
        method: "POST",
        headers,
        body: JSON.stringify(req),
        signal: controller.signal,
      });

      const durationMs = Math.round(performance.now() - started);
      this.log({
        message: "defenseclaw.plugin.llm_scan",
        direction: req.direction,
        status_code: res.status,
        duration_ms: durationMs,
      });

      if (!res.ok) {
        return failClosedVerdict(`sidecar returned ${res.status}`);
      }

      return (await res.json()) as ScanVerdict;
    } catch (err) {
      const durationMs = Math.round(performance.now() - started);
      this.log({
        message: "defenseclaw.plugin.llm_scan",
        direction: req.direction,
        status_code: 0,
        duration_ms: durationMs,
      });
      const msg = err instanceof Error ? err.message : String(err);
      return failClosedVerdict(`sidecar unreachable: ${msg}`);
    } finally {
      clearTimeout(timer);
    }
  }
}
```

### 1.3 Hook registration in `src/index.ts`

Add after the existing `createFetchInterceptor` block:

```typescript
import { LlmScanClient } from "./llm-scan.js";
import type { ScanVerdict } from "./llm-scan-types.js";

// ─── Hook-based LLM guardrail ───

// Detect whether the host supports typed hooks.
// OpenClaw 2026.6.8+ exposes llm_input/llm_output via the plugin API.
function hasLlmHookSupport(api: PluginApi): boolean {
  // api.on("llm_input", ...) succeeds silently on supported versions.
  // On unsupported versions the hook is never dispatched.
  // We rely on the hook-runner advertising via hasHooks, but since we
  // register eagerly we can only detect at first dispatch.  The
  // VERSION_MIN check is the reliable gate.
  try {
    // OpenClaw sets api._hostVersion or we parse from package.json
    const ver = (api as any)._hostVersion ?? process.env.OPENCLAW_VERSION ?? "";
    const match = ver.match(/^(\d{4})\.(\d+)\.(\d+)/);
    if (!match) return false;
    const [, year, major, minor] = match.map(Number);
    // 2026.6.8 is the minimum
    return year > 2026 || (year === 2026 && (major > 6 || (major === 6 && minor >= 8)));
  } catch {
    return false;
  }
}

// Shared per-turn state: llm_input stores the scan promise,
// before_model_resolve awaits it.
interface PendingScan {
  promise: Promise<ScanVerdict>;
  runId: string;
}

function registerLlmHooks(
  api: PluginApi,
  scanClient: LlmScanClient,
  guardrailMode: "observe" | "action",
  getCorrelationHeaders: () => Record<string, string>,
) {
  let pendingScan: PendingScan | null = null;

  // ── llm_input: scan the full prompt ──
  api.on("llm_input", (event: any, ctx: any) => {
    const req = {
      direction: "input" as const,
      provider: event.provider ?? "",
      model: event.model ?? "",
      content: {
        system_prompt: event.systemPrompt,
        messages: (event.historyMessages ?? []).concat(
          event.prompt ? [{ role: "user", content: event.prompt }] : []
        ),
        tools: event.tools,
      },
      session_id: ctx?.sessionId ?? ctx?.sessionKey,
      run_id: ctx?.runId,
      trace_id: getCorrelationHeaders()["X-DefenseClaw-Trace-Id"],
    };

    const promise = scanClient.scan(req);
    pendingScan = { promise, runId: ctx?.runId ?? "" };

    if (guardrailMode === "observe") {
      // Fire-and-forget: log verdict, don't block
      promise.then((v) => {
        console.log(
          `[defenseclaw] llm_input scan: action=${v.action} severity=${v.severity}`
        );
      }).catch(() => {});
    }
  });

  // ── before_model_resolve: block if input scan flagged ──
  api.on("before_model_resolve", async (_event: any, ctx: any) => {
    if (guardrailMode !== "action") return {};
    if (!pendingScan || pendingScan.runId !== (ctx?.runId ?? "")) return {};

    const scan = pendingScan;
    pendingScan = null;

    try {
      const verdict = await scan.promise;
      if (verdict.action === "block" && verdict.mode === "action") {
        console.log(
          `[defenseclaw] BLOCKED llm_input: ${verdict.reason} (severity=${verdict.severity})`
        );
        return { modelOverride: "__defenseclaw_blocked__" };
      }
    } catch {
      // Fail-closed: if scan errored, block
      return { modelOverride: "__defenseclaw_blocked__" };
    }

    return {};
  });

  // ── llm_output: scan the LLM response ──
  api.on("llm_output", (event: any, ctx: any) => {
    const assistantText =
      event.lastAssistant ?? (event.assistantTexts ?? []).join("\n");
    if (!assistantText) return;

    const req = {
      direction: "output" as const,
      provider: event.provider ?? "",
      model: event.model ?? "",
      content: {
        assistant_text: assistantText,
      },
      session_id: ctx?.sessionId ?? ctx?.sessionKey,
      run_id: ctx?.runId,
      trace_id: getCorrelationHeaders()["X-DefenseClaw-Trace-Id"],
    };

    // Always fire-and-forget: output scan cannot block inline
    // (llm_output is a void hook — response is already assembled)
    scanClient.scan(req).then((v) => {
      console.log(
        `[defenseclaw] llm_output scan: action=${v.action} severity=${v.severity}`
      );
      if (v.action === "block") {
        console.warn(
          `[defenseclaw] OUTPUT VIOLATION (post-delivery): ${v.reason}`
        );
      }
    }).catch(() => {});
  });
}
```

### 1.4 Boot-time detection in `src/index.ts`

Replace the unconditional `interceptor.start()` with:

```typescript
const llmScanClient = new LlmScanClient({
  sidecarBaseUrl: SIDECAR_API,
  sidecarToken: SIDECAR_TOKEN,
  getCorrelationHeaders: getFetchCorrelationHeaders,
  logOutboundRequest: (e) => logOutboundRequest(e as any),
});

const guardrailMode: "observe" | "action" =
  ((api.pluginConfig as any)?.guardrail?.mode ?? "observe") === "action"
    ? "action"
    : "observe";

let hookModeActive = false;

if (hasLlmHookSupport(api)) {
  registerLlmHooks(api, llmScanClient, guardrailMode, getFetchCorrelationHeaders);
  hookModeActive = true;
  console.log(
    `[defenseclaw] LLM guardrail: hook mode (llm_input/llm_output) [${guardrailMode}]`
  );
} else {
  interceptor.start();
  console.log("[defenseclaw] LLM guardrail: fetch interceptor mode (legacy)");
}
```

Update the `registerService` block to skip the interceptor in hook mode:

```typescript
api.registerService({
  id: "llm-interceptor",
  start: async () => {
    if (!hookModeActive) interceptor.start();
    healthMonitor.start();
    return {
      stop: () => {
        if (!hookModeActive) interceptor.stop();
        healthMonitor.stop();
      },
    };
  },
});
```

### 1.5 Updated type declarations: `typings/@openclaw/plugin-sdk.d.ts`

Add to the existing `PluginApi` interface:

```typescript
interface LlmInputEvent {
  runId?: string;
  sessionId?: string;
  provider: string;
  model: string;
  systemPrompt?: string;
  prompt?: string;
  historyMessages?: Array<{ role: string; content: string }>;
  imagesCount?: number;
  tools?: Array<{ name: string; description?: string }>;
}

interface LlmOutputEvent {
  runId?: string;
  sessionId?: string;
  provider: string;
  model: string;
  assistantTexts?: string[];
  lastAssistant?: string;
  usage?: Record<string, unknown>;
}

interface BeforeModelResolveEvent {
  [key: string]: unknown;
}

interface BeforeModelResolveResult {
  modelOverride?: string;
  providerOverride?: string;
}

interface ModelCallEvent {
  [key: string]: unknown;
  durationMs?: number;
  outcome?: string;
}

// Add to PluginApi.on() overloads:
export interface PluginApi {
  // ... existing overloads ...
  on(event: "llm_input", handler: (event: LlmInputEvent, ctx?: ToolContext) => void | Promise<void>): void;
  on(event: "llm_output", handler: (event: LlmOutputEvent, ctx?: ToolContext) => void | Promise<void>): void;
  on(event: "before_model_resolve", handler: (event: BeforeModelResolveEvent, ctx?: ToolContext) => BeforeModelResolveResult | void | Promise<BeforeModelResolveResult | void>): void;
  on(event: "model_call_started", handler: (event: ModelCallEvent, ctx?: ToolContext) => void | Promise<void>): void;
  on(event: "model_call_ended", handler: (event: ModelCallEvent, ctx?: ToolContext) => void | Promise<void>): void;
}
```

## 2. Sidecar Go changes

### 2.1 New file: `internal/gateway/scan_llm.go`

```go
package gateway

import (
	"encoding/json"
	"net/http"
	"time"
)

type ScanDirection string

const (
	ScanDirectionInput  ScanDirection = "input"
	ScanDirectionOutput ScanDirection = "output"
)

type ScanContent struct {
	SystemPrompt  string                   `json:"system_prompt,omitempty"`
	Messages      []map[string]interface{} `json:"messages,omitempty"`
	Tools         []map[string]interface{} `json:"tools,omitempty"`
	AssistantText string                   `json:"assistant_text,omitempty"`
}

type ScanRequest struct {
	Direction ScanDirection `json:"direction"`
	Provider  string        `json:"provider"`
	Model     string        `json:"model"`
	Content   ScanContent   `json:"content"`
	SessionID string        `json:"session_id,omitempty"`
	RunID     string        `json:"run_id,omitempty"`
	AgentID   string        `json:"agent_id,omitempty"`
	TraceID   string        `json:"trace_id,omitempty"`
}

type ScanFinding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence,omitempty"`
	Scanner  string `json:"scanner"`
}

type ScanResponse struct {
	Action         string        `json:"action"`
	Severity       string        `json:"severity"`
	Reason         string        `json:"reason"`
	Mode           string        `json:"mode"`
	Findings       []ScanFinding `json:"findings"`
	ScanDurationMs int64         `json:"scan_duration_ms"`
}

// HandleScan processes POST /api/v1/scan requests from the plugin's
// llm_input / llm_output hooks.  It delegates to the same evaluator
// pipeline used by the guardrail proxy.
func (s *Sidecar) HandleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Direction != ScanDirectionInput && req.Direction != ScanDirectionOutput {
		http.Error(w, "direction must be 'input' or 'output'", http.StatusBadRequest)
		return
	}

	started := time.Now()

	// Delegate to the guardrail evaluator.  The evaluator is the same
	// pipeline that the proxy uses — we just build the evaluator request
	// from the hook payload instead of from an intercepted HTTP request.
	verdict := s.evaluateLlmContent(r.Context(), req)

	durationMs := time.Since(started).Milliseconds()

	// Write audit row
	s.writeScanAudit(r.Context(), req, verdict, durationMs)

	resp := ScanResponse{
		Action:         verdict.Action,
		Severity:       verdict.Severity,
		Reason:         verdict.Reason,
		Mode:           s.guardrailMode(),
		Findings:       verdict.Findings,
		ScanDurationMs: durationMs,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
```

### 2.2 Route registration in `sidecar.go`

Add to the REST mux setup (alongside existing `/api/v1/inspect/tool`):

```go
mux.HandleFunc("/api/v1/scan", s.HandleScan)
```

### 2.3 Audit integration

Add `ScanTypeLLMContent = "LLM_CONTENT"` to the audit type constants.
The `writeScanAudit` method writes to the existing `scan_results` table with
`scan_type = "LLM_CONTENT"` and `direction = req.Direction`.

## 3. Plugin config (`openclaw.plugin.json`)

Add to the existing `configSchema`:

```json
{
  "guardrail": {
    "type": "object",
    "properties": {
      "mode": {
        "type": "string",
        "enum": ["observe", "action"],
        "default": "observe",
        "description": "observe: scan and log. action: scan and block violating prompts."
      }
    }
  }
}
```

## 4. Helm values

Add to `helm/dataplane/values.yaml` under the `defenseclaw` section:

```yaml
defenseclaw:
  guardrailProxy:
    enabled: true  # set false to disable proxy on 2026.6.8+ deployments
```

## 5. Sequence diagrams

### Input scan — action mode (block)

```
Plugin                    Sidecar              Evaluator
  │                         │                     │
  │──[llm_input]────────────│                     │
  │  POST /api/v1/scan      │                     │
  │  {direction:"input"...} │                     │
  │                         │──evaluate()────────>│
  │                         │<───{block,HIGH}─────│
  │                         │──writeAudit()       │
  │<────{action:"block"}────│                     │
  │                         │                     │
  │──[before_model_resolve] │                     │
  │  await pendingScan      │                     │
  │  verdict = block        │                     │
  │  return {modelOverride: │                     │
  │    "__defenseclaw_blocked__"}                  │
  │                         │                     │
  │──(model resolution fails)                     │
  │  agent turn ends with                         │
  │  guardrail block reason                       │
```

### Output scan — observe mode

```
Plugin                    Sidecar              Evaluator
  │                         │                     │
  │──(LLM call completes)   │                     │
  │──[llm_output]───────────│                     │
  │  POST /api/v1/scan      │                     │
  │  {direction:"output"..} │                     │
  │                         │──evaluate()────────>│
  │  (reply delivered to     │<───{allow,NONE}────│
  │   user immediately)     │──writeAudit()       │
  │                         │                     │
  │<────{action:"allow"}────│                     │
  │  (logged, no action)    │                     │
```

## 6. Error handling

| Failure | Behavior |
|---------|----------|
| Sidecar unreachable | Fail-closed by default (block). Opt-in fail-open via `DEFENSECLAW_LLM_SCAN_FAIL_OPEN=1` |
| Sidecar returns non-200 | Fail-closed |
| Sidecar returns malformed JSON | Fail-closed |
| Scan timeout (> 5s default) | AbortController fires, fail-closed |
| `before_model_resolve` timeout | OpenClaw enforces per-hook timeout (default 5s). If scan hasn't returned, the hook returns empty (pass-through). Mitigated by setting `hooks.timeouts.before_model_resolve: 10000` in plugin config |
| `llm_input` handler throws | OpenClaw catches and logs warning. `before_model_resolve` sees no `pendingScan`, passes through |

## 7. Observability

| Signal | Where |
|--------|-------|
| `defenseclaw.plugin.llm_scan` structured log | Plugin — every scan call with direction, status, duration |
| `[defenseclaw] llm_input scan: action=X severity=Y` | Plugin — console log per input scan |
| `[defenseclaw] llm_output scan: action=X severity=Y` | Plugin — console log per output scan |
| `[defenseclaw] BLOCKED llm_input: reason` | Plugin — console warn on block |
| `[defenseclaw] OUTPUT VIOLATION (post-delivery): reason` | Plugin — console warn on output violation |
| `scan_results` table row | Sidecar audit DB — `scan_type=LLM_CONTENT`, `direction=input|output` |
| `defenseclaw.guardrail.llm_scan` OTel span | Sidecar — if OTel is wired |
