## Webhook Notifications for Enforcement Events

### Summary

Adds an outbound webhook notification system that pushes enforcement events (skill/plugin blocks, drift alerts, guardrail blocks) to external systems in real time. Supports Slack, PagerDuty, Webex, and generic HTTP endpoints with per-endpoint severity filtering, event-type filtering, and automatic retry with exponential backoff.

### Motivation

Before this PR, DefenseClaw enforcement events were only visible through the SQLite audit DB, the TUI dashboard, and Splunk HEC forwarding. There was no way to push real-time alerts to team collaboration tools (Slack, Webex) or incident management platforms (PagerDuty) without building custom integrations on top of the SIEM pipeline. This created a gap in operational workflows — security teams couldn't receive immediate, actionable notifications when a malicious skill was blocked or drift was detected.

This PR closes that gap by adding a lightweight, configurable webhook dispatcher that runs alongside the existing audit pipeline.

### What Changed

#### New Files

| File | Purpose |
|------|---------|
| `internal/gateway/webhook.go` | `WebhookDispatcher` — async dispatch engine with retry, severity/event filtering, and payload formatters for Slack (Block Kit), PagerDuty (Events API v2), Webex (Messages API with markdown), and generic JSON |
| `internal/gateway/webhook_test.go` | 9 unit tests — payload formatting (Slack, PagerDuty, Webex, generic), severity filtering matrix, event-type filtering, action categorization, nil dispatcher safety, disabled endpoint handling |
| `internal/gateway/webhook_e2e_test.go` | 11 E2E tests — full enforcement pipeline simulation, retry on transient failure, retry exhaustion, secret/auth header validation (generic, Slack, Webex Bearer), severity edge cases (25-combination matrix), Webex payload + multi-endpoint fan-out, enabled/disabled mixing, concurrent dispatch (50 goroutines), post-close safety |

#### Modified Files

| File | Change |
|------|--------|
| `internal/config/config.go` | Added `WebhookConfig` struct (with `RoomID` for Webex) and `Webhooks []WebhookConfig` field to top-level `Config`; `ResolvedSecret()` helper reads secret from env var |
| `internal/gateway/sidecar.go` | Initializes `WebhookDispatcher` on startup; passes it to watcher and guardrail proxy; dispatches `block` events from `sendEnforcementAlert`; drains dispatcher on shutdown |
| `internal/gateway/proxy.go` | Added `webhooks *WebhookDispatcher` field and `SetWebhookDispatcher` method; dispatches `guardrail-block` events from `recordTelemetry` when verdict is block |
| `internal/watcher/watcher.go` | Added `WebhookDispatcher` interface and `SetWebhookDispatcher` method to break import cycle between `gateway` and `watcher` packages |
| `internal/watcher/rescan.go` | Dispatches drift audit events to webhook dispatcher (if configured) after logging to audit store |
| `cli/defenseclaw/config.py` | Mirrored `WebhookConfig` dataclass in Python CLI; added `_merge_webhooks()` parser; wired into `Config.webhooks` field |
| `policies/default.yaml` | Added `webhooks: []` (disabled by default) |
| `policies/strict.yaml` | Added `webhooks: []` with commented-out Slack/Webex/PagerDuty examples |
| `policies/permissive.yaml` | Added `webhooks: []` |
| `schemas/audit-event.json` | Extended `action` enum with `"guardrail-block"` |
| `README.md` | Added Notifications section with webhook config example and channel type table |
| `docs/ARCHITECTURE.md` | Added webhook dispatch to Gateway responsibility table and data flow diagram |
| `docs/CONFIG_FILES.md` | Added Webhook Notification Config section with full field reference |

### Architecture

```
Enforcement Event Sources                  WebhookDispatcher
                                           (internal/gateway/webhook.go)
┌─────────────────────┐                    ┌──────────────────────────────┐
│ Watcher             │──── block ────────▶│                              │
│ (sidecar.go)        │                    │  For each configured endpoint│
├─────────────────────┤                    │    ├─ severity ≥ threshold?  │
│ Rescan Loop         │──── drift ────────▶│    ├─ event category match?  │
│ (rescan.go)         │                    │    └─ async POST with retry  │
├─────────────────────┤                    │                              │
│ Guardrail Proxy     │── guardrail ──────▶│  Payload formatters:         │
│ (proxy.go)          │   block            │    ├─ Slack (Block Kit)      │
└─────────────────────┘                    │    ├─ PagerDuty (Events v2)  │
                                           │    ├─ Webex (Messages API)   │
                                           │    └─ Generic (flat JSON)    │
                                           └──┬──────┬──────┬───────┬────┘
                                              │      │      │       │
                                              ▼      ▼      ▼       ▼
                                           Slack  PagerDuty Webex  HTTP
                                           webhook Events   Room  endpoint
```

### Webhook Channel Types

| Type | Payload Format | Auth Mechanism | Status Code |
|------|---------------|----------------|-------------|
| `slack` | Block Kit attachments with severity-color-coded sidebar, header, section fields, context with event ID/timestamp | URL token embedded in Slack incoming webhook URL | 200 |
| `pagerduty` | Events API v2 `trigger` with `dedup_key` (target+action), severity mapping (CRITICAL→critical, HIGH→error, MEDIUM→warning), `custom_details` | `routing_key` from `secret_env` | 202 |
| `webex` | Markdown message via Webex Messages API (`POST /v1/messages`) with severity icon, structured fields, and `roomId` | Bot access token as `Authorization: Bearer` from `secret_env` | 200 |
| `generic` | Flat JSON envelope (`webhook_type`, `defenseclaw_version`, nested `event` object with all audit fields) | `X-Webhook-Secret` header from `secret_env` | 200 |

### Severity and Event Filtering

Each webhook endpoint can configure:

- **`min_severity`** — only events at or above this rank are dispatched (CRITICAL=5, HIGH=4, MEDIUM=3, LOW=2, INFO=1)
- **`events`** — list of event categories to include; empty means all. The `categorizeAction()` function maps audit actions to categories:

| Audit Action | Category | Example Source |
|-------------|----------|----------------|
| `block`, `quarantine`, `disable` | `block` | Watcher blocks a malicious skill |
| `drift`, `rescan` | `drift` | Periodic rescan detects mutation |
| `guardrail-block`, `guardrail-*` | `guardrail` | Proxy blocks a prompt injection |
| `scan` | `scan` | Routine scan completes |

### Retry Behavior

- Up to 3 retries (4 total attempts) with exponential backoff (2s, 4s, 6s)
- Retries on HTTP 5xx responses and network errors
- Non-retryable: 4xx responses, payload formatting errors
- In-flight retries complete before `Close()` returns (graceful shutdown)
- Events dispatched after `Close()` are silently dropped

### Configuration Example

```yaml
webhooks:
  - url: "https://hooks.slack.com/services/T00/B00/xxx"
    type: slack
    min_severity: HIGH
    events: [block, drift, guardrail]
    enabled: true

  - url: "https://webexapis.com/v1/messages"
    type: webex
    secret_env: WEBEX_BOT_TOKEN
    room_id: "Y2lzY29zcGFyazovL3VzL1JPT00v..."
    min_severity: HIGH
    events: [block, drift, guardrail]
    enabled: true

  - url: "https://events.pagerduty.com/v2/enqueue"
    type: pagerduty
    secret_env: PAGERDUTY_ROUTING_KEY
    min_severity: CRITICAL
    events: [block]
    enabled: true

  - url: "https://security.internal.example.com/webhook"
    type: generic
    secret_env: WEBHOOK_SECRET
    min_severity: INFO
    events: []  # all events
    timeout_seconds: 5
    enabled: true
```

### Design Decisions

1. **Interface in watcher package** — `WebhookDispatcher` is defined as an interface in `internal/watcher/watcher.go` to break the import cycle between `gateway` and `watcher` packages. The concrete struct lives in `gateway`.

2. **Modeled after SplunkForwarder** — The dispatcher follows the same async fire-and-forget pattern as the existing Splunk HEC forwarder, with `wg.Add/Done` for graceful shutdown.

3. **Retry backoff via struct field** — `retryBackoff` is a field (not just a constant) so E2E tests can zero it out for sub-second test execution without `time.Sleep` waits.

4. **No new dependencies** — Uses only stdlib `net/http`, `encoding/json`, and `sync`. No external webhook libraries.

5. **Disabled by default** — All policy presets ship with `webhooks: []`. Operators must explicitly configure and enable endpoints.

### Test Plan

- [x] 9 unit tests pass (payload formatting for Slack, PagerDuty, Webex, generic; severity filtering, event-type filtering, action categorization, nil safety, disabled endpoints)
- [x] 11 E2E tests pass:
  - [x] Full enforcement pipeline: 4 events (block, drift, guardrail-block, scan) → 3 endpoints (Slack, PagerDuty, generic) with correct routing, payload structure, and deep field validation
  - [x] Retry on transient failure: server returns 503 twice, then 200 — verifies 3 attempts
  - [x] Retry exhaustion: server always returns 500 — verifies exactly `maxRetries+1` attempts without hang
  - [x] Secret header: generic webhook receives `X-Webhook-Secret`, Slack does not
  - [x] Webex payload + auth: verifies `Authorization: Bearer`, `roomId`, markdown content, no `X-Webhook-Secret`
  - [x] Webex in multi-endpoint pipeline: Webex participates correctly alongside Slack and generic in fan-out with proper filtering
  - [x] Severity edge cases: 25-combination matrix (5 thresholds x 5 event severities)
  - [x] Mixed enabled/disabled: disabled and empty-URL endpoints skipped
  - [x] Concurrent dispatch: 50 goroutines dispatch simultaneously — no races, no lost payloads
  - [x] Post-close safety: events after `Close()` silently dropped
- [x] Full `go test ./...` passes (22 packages, zero regressions)
- [x] `go vet ./...` clean
- [x] No linter errors on changed files
- [x] Documentation updated: README.md, ARCHITECTURE.md, CONFIG_FILES.md
