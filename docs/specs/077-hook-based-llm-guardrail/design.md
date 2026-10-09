# Spec 077 — Hook-Based LLM Guardrail

| Field         | Value |
|---------------|-------|
| Status        | Draft |
| Author        | nghodki |
| Created       | 2026-09-08 |
| Minimum OC    | 2026.6.8 |
| Replaces      | fetch-interceptor (undici dispatcher patch) as primary LLM scanning path |

## Problem

The current DefenseClaw LLM interception relies on patching Node's `globalThis.fetch`
via an undici `setGlobalDispatcher` call to redirect outbound LLM API requests through
a guardrail proxy running at `127.0.0.1:4000`.  This approach has two production-blocking
defects (documented in `defenseclaw-interception-findings-2026-09-08.md`):

1. **Worker-thread isolation** — `setGlobalDispatcher` is per-thread.  OpenClaw 2026.6.8
   executes model calls inside `worker_threads` (`dist/agents/*.worker.js`), so the
   patched dispatcher on the main thread never sees those fetches.
   `network_egress_events = 0` for every agent turn.

2. **Proxy header forwarding** — When the guardrail proxy *does* intercept a call
   (main-thread test), it cannot forward custom upstream auth headers
   (e.g. AMD's `Ocp-Apim-Subscription-Key`).  The customer gets HTTP 401 from their
   LLM gateway.

Both defects are inherent to the proxy architecture.  A fundamentally different
interception point is needed.

## Solution

Replace fetch-level interception with **OpenClaw's native plugin hook lifecycle**.
OpenClaw 2026.6.8 exposes `llm_input`, `llm_output`, `model_call_started`,
`model_call_ended`, and the modifying hook `before_model_resolve`.  These fire from
the main agent harness — not the worker thread that issues the HTTP call — and carry
the full prompt and response payloads.  No proxy, no undici, no thread isolation
problems.

The guardrail proxy at `:4000` is no longer required for LLM traffic.  A single
sidecar REST endpoint (`POST /api/v1/scan`) handles all content scanning: tool calls,
LLM input, and LLM output.

## Hook Inventory (OpenClaw 2026.6.8)

| Hook                  | Type              | Payload summary | Can block? |
|-----------------------|-------------------|-----------------|------------|
| `llm_input`           | void (fire-and-forget) | provider, model, systemPrompt, prompt, historyMessages, tools | No (observe) |
| `llm_output`          | void (fire-and-forget) | provider, model, assistantTexts, lastAssistant, usage | No (observe) |
| `model_call_started`  | void (fire-and-forget) | sanitized model-call metadata | No |
| `model_call_ended`    | void (fire-and-forget) | metadata + durationMs + outcome | No |
| `before_model_resolve`| modifying         | (receives model context) | Yes — can return `{ modelOverride }` |
| `before_agent_reply`  | claiming          | user message | Yes — can return `{ handled: true, text }` |
| `before_tool_call`    | claiming          | tool name, params | Yes — existing |

The `allowConversationAccess` plugin permission gate must be `true` for
`llm_input`, `llm_output`, `before_model_resolve`, and `before_agent_reply`.

## Architecture

### Request flow — observe mode

```
User message
  → [before_agent_reply] — no-op (pass-through)
  → prompt built (system + history + user + tools)
  → [llm_input] → async POST /api/v1/scan {direction:"input"}
                   sidecar logs finding, returns verdict
                   plugin logs verdict, fire-and-forget
  → LLM HTTP call (direct to provider — no proxy)
  → LLM response received
  → [llm_output] → async POST /api/v1/scan {direction:"output"}
                    sidecar logs finding, fire-and-forget
  → reply delivered to user
```

Zero added latency.  Scan results land in the sidecar audit DB asynchronously.

### Request flow — action (block) mode

```
User message
  → [before_agent_reply] — no-op
  → prompt built
  → [llm_input] → await POST /api/v1/scan {direction:"input"}
                   sidecar returns {action:"block", reason:"..."}
                   plugin stores ScanDecision in shared turn state
  → [before_model_resolve] → reads ScanDecision
       if blocked → return {modelOverride: "__defenseclaw_blocked__"}
       else       → pass-through (no override)
  → OpenClaw tries to resolve "__defenseclaw_blocked__"
       → model resolution fails → agent turn ends
       → error includes the guardrail block reason
  → (no LLM call made — no wasted tokens)
  → [llm_output] — does not fire (no model call completed)
```

For output blocking (response scanning in action mode):

```
  → LLM response received
  → [llm_output] → await POST /api/v1/scan {direction:"output"}
       if blocked → log violation + emit audit event
                    (response already streamed — cannot retract)
       else       → pass-through
  → reply delivered
```

Output blocking is **best-effort**: the response is streamed to the user before the
scan completes.  The audit trail records the violation for downstream enforcement
(supervisor alerts, session termination).  True inline output blocking requires an
OpenClaw change to make `llm_output` a claiming hook — tracked as a future enhancement.

### Shared turn state for input blocking

`llm_input` and `before_model_resolve` fire sequentially in the same agent turn.
However, `llm_input` is void (fire-and-forget) — OpenClaw does not `await` it before
calling `before_model_resolve`.  To bridge this gap:

```typescript
// Shared state between hooks within a single agent turn
let pendingScan: {
  promise: Promise<ScanVerdict>;
  runId: string;
} | null = null;

// llm_input handler: starts the scan, stores the promise
api.on("llm_input", (event, ctx) => {
  pendingScan = {
    promise: scanClient.scan({ direction: "input", ...event }),
    runId: ctx.runId,
  };
});

// before_model_resolve handler: awaits the scan result
api.on("before_model_resolve", async (event, ctx) => {
  if (!pendingScan || pendingScan.runId !== ctx.runId) return {};
  const verdict = await pendingScan.promise;
  pendingScan = null;
  if (verdict.action === "block" && verdict.mode === "action") {
    return { modelOverride: "__defenseclaw_blocked__" };
  }
  return {};
});
```

`before_model_resolve` is a modifying hook — OpenClaw **does** await it.  The sidecar
scan typically completes in 50-200 ms.  The `before_model_resolve` handler awaits
the scan promise, so even if `llm_input` fired fire-and-forget the scan always
completes before the model call proceeds.

### Sidecar API

#### `POST /api/v1/scan`

Unified content scan endpoint.  Replaces the guardrail proxy for LLM traffic and
extends the existing `/api/v1/inspect/tool` pattern.

**Request:**

```json
{
  "direction": "input" | "output",
  "provider": "anthropic",
  "model": "claude-opus-4.6",
  "content": {
    "system_prompt": "...",
    "messages": [
      {"role": "user", "content": "..."},
      {"role": "assistant", "content": "..."}
    ],
    "tools": [{"name": "bash", "description": "..."}],
    "assistant_text": "..."
  },
  "session_id": "...",
  "run_id": "...",
  "agent_id": "...",
  "trace_id": "..."
}
```

- `direction: "input"`: `content.messages`, `content.system_prompt`, and
  `content.tools` are populated from the `llm_input` hook event.
- `direction: "output"`: `content.assistant_text` is populated from the
  `llm_output` hook event's `assistantTexts` / `lastAssistant`.

**Response:**

```json
{
  "action": "allow" | "block" | "flag",
  "severity": "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "reason": "prompt injection detected in user message",
  "mode": "observe" | "action",
  "findings": [
    {
      "type": "prompt_injection",
      "severity": "HIGH",
      "evidence": "...",
      "scanner": "llm_judge"
    }
  ],
  "scan_duration_ms": 142
}
```

**Internal routing:**

The Go handler delegates to the same guardrail evaluator pipeline that the proxy
currently uses (LiteLLM judge, PII scanner, content classifier).  The handler:

1. Builds a `ScanRequest` from the JSON body.
2. Calls `evaluator.Evaluate(ctx, req)` — the same evaluator wired into the
   existing proxy `handleChat` path.
3. Writes the result to the audit DB (`scan_results` table).
4. Returns the verdict.

No new evaluator code.  The only new code is the HTTP handler and the
request/response serialization.

### Fetch interceptor fallback

On plugin boot:

```typescript
const hasHookSupport = typeof api.on === "function"
  && hookRunnerAvailable("llm_input");

if (hasHookSupport) {
  registerLlmHooks(api);
  console.log("[defenseclaw] LLM guardrail: hook mode (llm_input/llm_output)");
} else {
  interceptor.start();
  console.log("[defenseclaw] LLM guardrail: fetch interceptor mode (legacy)");
}
```

`hookRunnerAvailable` probes whether the hook runner accepts `llm_input`
registrations.  On OpenClaw < 2026.6.8 this returns false and the existing
undici-based fetch interceptor activates.

### Proxy deprecation

With hooks as the primary path, the guardrail proxy at `:4000` becomes optional:

- **New deployments** (OpenClaw >= 2026.6.8): proxy can be disabled.  The sidecar
  runs only the REST API on `:18970`.
- **Existing deployments** (mixed versions): proxy stays active as fallback.
  Config flag `DEFENSECLAW_DISABLE_GUARDRAIL_PROXY=1` turns it off.
- **Full removal**: targeted for the next major release once all customers are on
  2026.6.8+.

### Plugin config changes

```jsonc
// openclaw.plugin.json — add to configSchema
{
  "guardrail": {
    "mode": {
      "type": "string",
      "enum": ["observe", "action"],
      "default": "observe",
      "description": "observe: scan and log, no blocking. action: scan and block violating prompts."
    }
  }
}
```

```jsonc
// Customer openclaw.json — plugin permissions
{
  "plugins": {
    "entries": {
      "defenseclaw": {
        "hooks": {
          "allowConversationAccess": true
        }
      }
    }
  }
}
```

## Files changed

### Plugin (TypeScript — `extensions/defenseclaw/`)

| File | Change |
|------|--------|
| `src/index.ts` | Register `llm_input`, `llm_output`, `before_model_resolve` hooks; hook-vs-interceptor detection; shared `pendingScan` state |
| `src/llm-scan.ts` **(new)** | `LlmScanClient` class — formats hook payloads → sidecar `POST /api/v1/scan`, parses verdict |
| `src/llm-scan-types.ts` **(new)** | TypeScript types for scan request/response/verdict |
| `src/fetch-interceptor.ts` | Add `isHookModeActive()` guard — skip interceptor start when hooks are registered |
| `src/health-monitor.ts` | No change (continues polling `/status`) |
| `typings/@openclaw/plugin-sdk.d.ts` | Add `llm_input`, `llm_output`, `before_model_resolve`, `model_call_started`, `model_call_ended` event type declarations |
| `openclaw.plugin.json` | Add `guardrail.mode` to `configSchema` |
| `package.json` | No new dependencies (uses native `fetch`) |

### Sidecar (Go — `internal/gateway/`)

| File | Change |
|------|--------|
| `scan_llm.go` **(new)** | `POST /api/v1/scan` HTTP handler: deserialize request, call evaluator, write audit row, return verdict |
| `scan_llm_test.go` **(new)** | Table-driven tests: input/output scan, block/allow/flag, malformed request, evaluator timeout |
| `sidecar.go` | Register `/api/v1/scan` route on the REST mux |
| `audit.go` | Add `ScanTypeEnum = "LLM_CONTENT"` constant for audit rows |

### Helm

| File | Change |
|------|--------|
| `helm/dataplane/values.yaml` | Add `defenseclaw.guardrailProxy.enabled: true` toggle (default true for backward compat) |

### Docs

| File | Change |
|------|--------|
| `docs/specs/077-hook-based-llm-guardrail/design.md` | This document |

## Testing

### Unit tests (plugin)

- `llm-scan.test.ts` — payload formatting for input/output directions; verdict parsing;
  timeout handling; correlation header injection.
- `index.test.ts` — hook registration: verify `llm_input` + `before_model_resolve` +
  `llm_output` registered when hook support detected; verify fetch interceptor skipped.
- `index.test.ts` — action-mode blocking: mock sidecar returns `block` → verify
  `before_model_resolve` returns `{ modelOverride: "__defenseclaw_blocked__" }`.
- `index.test.ts` — observe-mode pass-through: mock sidecar returns `allow` → verify
  `before_model_resolve` returns `{}`.
- `index.test.ts` — fallback: simulate missing `llm_input` support → verify fetch
  interceptor activates.

### Unit tests (sidecar)

- `scan_llm_test.go` — table-driven: input scan → allow; input scan → block;
  output scan → flag; malformed body → 400; evaluator timeout → fail-closed;
  audit row written.

### Integration tests

- Mock sidecar + real plugin: trigger agent turn → verify `llm_input` fires →
  scan request reaches sidecar → verdict returned → `before_model_resolve` blocks
  or passes through.
- Mock sidecar + real plugin: verify `llm_output` fires after LLM response → scan
  request includes assistant text → audit row written.

### E2E validation

- Deploy to preview sandbox with OpenClaw 2026.6.8 image.
- Trigger agent turn with known prompt-injection payload.
- Verify `scan_results` table in sidecar audit DB has `direction=input` row.
- Verify `network_egress_events > 0` (from the scan call, not fetch interception).
- Verify agent reply delivered (observe mode) or blocked (action mode).

## Migration

1. **Phase 1 (this spec):** Ship hook-based scanning.  Fetch interceptor remains as
   fallback.  Proxy remains enabled.  Default mode: `observe`.
2. **Phase 2:** Customer validation on staging.  Switch AMD worker to `action` mode.
   Verify blocking works on known-bad prompts.
3. **Phase 3:** Disable proxy via `DEFENSECLAW_DISABLE_GUARDRAIL_PROXY=1` on new
   deployments.  Monitor for regressions.
4. **Phase 4:** Remove fetch interceptor and proxy code.  Hooks-only.

## Open questions

1. **Output blocking latency:** If OpenClaw makes `llm_output` a claiming hook in a
   future release, we can block responses inline.  Until then, output blocking is
   audit-only.  Is this acceptable for the AMD deployment?

2. **Streaming responses:** `llm_output` fires after the full response is assembled.
   For streaming-enabled models, the user sees tokens before the scan runs.  Do we
   need a streaming-aware scan path?

3. **`before_model_resolve` timeout:** If the sidecar scan takes > 600ms, the
   `before_model_resolve` hook may hit OpenClaw's per-hook timeout (default 5s,
   configurable via `hooks.timeouts.before_model_resolve`).  Should we set an
   explicit timeout in the plugin config?
