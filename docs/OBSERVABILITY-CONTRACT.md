# DefenseClaw v7 — Observability Contract

Downstream-facing contract for SIEM, analytics, and integration tests. **Schema version** for JSON envelopes is **7** (`internal/version.SchemaVersion`, `schema_version` on every stamped event). **Generation** is a monotonic counter bumped on config/policy save (`version.BumpGeneration()`); **content_hash** is SHA-256 of canonical JSON config/policy; **binary_version** is the running DefenseClaw semver.

| Source of truth (Go) | Parity (Python / CI) |
|------------------------|----------------------|
| `internal/audit/actions.go` — `AllActions()` | `cli/defenseclaw/audit_actions.py`, `make check-audit-actions` |
| `internal/gatewaylog/error_codes.go` — `AllErrorCodes()`, `AllSubsystems()` | `cli/defenseclaw/gateway_error_codes.py`, `make check-error-codes` |
| `schemas/*.json` | `make check-schemas` |

**Gate:** `make check-v7` before merging changes to actions, error codes, or schemas.

---

## Event types (`gatewaylog.EventType`)

Each emission is one JSON object per line (`gateway.jsonl`) with `event_type` discriminating the payload. Full schema: `schemas/gateway-event-envelope.json` (references `scan-event.json`, `scan-finding-event.json`, `activity-event.json`).

| `event_type` | Payload key | Primary SQLite projection |
|--------------|-------------|---------------------------|
| `verdict` | `verdict` | Mirror `audit_events` when guardrail emits audit twin (`guardrail-*` actions); isolated `gatewaylog.Writer.Emit` tests may not persist |
| `judge` | `judge` | `judge_responses` when retention enabled |
| `lifecycle` | `lifecycle` | Often mirrored from `audit.Logger` via `auditBridge` |
| `error` | `error` | Optional `audit_events` / alerts path depending on subsystem |
| `diagnostic` | `diagnostic` | Operator-opt-in sinks; always stderr-capable |
| `scan` | `scan` | `scan_results` + `audit_events` summary |
| `scan_finding` | `scan_finding` | `scan_findings` |
| `activity` | `activity` | `activity_events` + redacted `audit_events` summary |

### Example: `verdict` (trimmed)

```json
{
  "ts": "2026-04-20T12:00:00Z",
  "event_type": "verdict",
  "severity": "HIGH",
  "schema_version": 7,
  "generation": 1,
  "content_hash": "<sha256>",
  "binary_version": "0.2.0",
  "run_id": "<run>",
  "session_id": "<session>",
  "trace_id": "<32-char-hex>",
  "agent_id": "<logical>",
  "agent_instance_id": "<session-scoped>",
  "sidecar_instance_id": "<process-scoped>",
  "verdict": { "stage": "final", "action": "block", "reason": "…", "latency_ms": 12 }
}
```

---

## Correlation fields

| Field | Role |
|-------|------|
| `run_id` | One per agent invocation; env `DEFENSECLAW_RUN_ID`, stream `runId`, or proxy context |
| `session_id` | OpenClaw / conversation key when present |
| `trace_id` | W3C trace id from OTel span context |
| `request_id` | HTTP request id from proxy / API |

**Minting:** Gateway and scanner paths stamp what they know; missing fields stay empty (never fabricated).

---

## Three-tier agent identity

| Field | Meaning | Example |
|-------|---------|---------|
| `agent_id` | Stable logical agent | `openclaw`, plugin id |
| `agent_instance_id` | Session-scoped or process default from `audit.SetProcessAgentInstanceID` | Per conversation or boot UUID |
| `sidecar_instance_id` | **DefenseClaw gateway process** | New UUID each sidecar start |

**Breaking change vs v6:** Do not treat `agent_instance_id` as interchangeable with `sidecar_instance_id`. They answer different questions (who ran vs which binary emitted).

---

## Nullability (summary)

Consult `schemas/gateway-event-envelope.json` and nested `$defs`. Envelope fields use `omitempty`; exactly **one** of `verdict` / `judge` / `lifecycle` / `error` / `diagnostic` / `scan` / `scan_finding` / `activity` is populated per `oneOf` in the schema.

---

## Error codes (`gatewaylog.ErrorCode`)

Complete enumeration (must match `AllErrorCodes()`):

- `SINK_DELIVERY_FAILED`, `SINK_QUEUE_FULL`
- `EXPORT_FAILED`
- `CONFIG_LOAD_FAILED`
- `POLICY_LOAD_FAILED`
- `AUTH_INVALID_TOKEN`, `AUTH_MISSING_TOKEN`, `AUTH_CSRF_MISMATCH`, `AUTH_ORIGIN_BLOCKED`
- `INVALID_HEADER`
- `INVALID_RESPONSE`
- `SUBPROCESS_EXIT`
- `WEBHOOK_DELIVERY_FAILED`, `WEBHOOK_COOLDOWN`
- `FS_MOVE_FAILED`, `FS_LINK_FAILED`
- `CLIENT_DISCONNECT`, `UPSTREAM_ERROR`, `STREAM_TIMEOUT`
- `SQLITE_BUSY`
- `PANIC_RECOVERED`
- `LLM_BRIDGE_ERROR`
- `SCHEMA_VIOLATION`

---

## Subsystems (`gatewaylog.Subsystem`)

Complete enumeration (must match `AllSubsystems()`):

`sidecar`, `watcher`, `gateway`, `scanner`, `policy`, `guardrail`, `auth`, `config`, `inspect`, `approvals`, `sink`, `telemetry`, `correlation`, `stream`, `cisco-inspect`, `openshell`, `webhook`, `quarantine`, `agent-registry`, `sqlite`, `admission`, `config_mutation`, `gatewaylog`

---

## Audit actions (`audit.Action`)

Complete enumeration (must match `AllActions()`):

`init`, `stop`, `ready`, `scan`, `scan-start`, `rescan`, `rescan-start`, `block`, `allow`, `warn`, `quarantine`, `restore`, `disable`, `enable`, `deploy`, `drift`, `network-egress-blocked`, `network-egress-allowed`, `guardrail-block`, `guardrail-warn`, `guardrail-allow`, `approval-request`, `approval-granted`, `approval-denied`, `tool-call`, `tool-result`, `config-update`, `policy-update`, `policy-reload`, `action`, `acknowledge-alerts`, `dismiss-alerts`, `webhook-delivered`, `webhook-failed`, `sink-failure`, `sink-restored`, `alert`

---

## Surface matrix (five observability tiers)

| Tier | Mechanism |
|------|-----------|
| 1 — SQLite | `audit_events`, `activity_events`, `scan_results` / `scan_findings`, `judge_responses`, … |
| 2 — Gateway JSONL | `gatewaylog.Writer` → file + fanout |
| 3 — OTel traces | `sdktrace` spans (proxy, tools, approvals, …) |
| 4 — OTel metrics | `sdkmetric` instruments (`defenseclaw.*`, `gen_ai.*`, …) |
| 5 — Audit sinks | `audit_sinks` → Splunk HEC, OTLP logs, HTTP JSONL (`sinks.Event`; wire shape mirrors `audit.Event` with optional `structured`) |

Not every `event_type` duplicates into all five tiers; gateway-native emissions may skip SQLite until a mirror row exists.

---

## Breaking changes vs v6

- **Identity:** three-tier model; column / field rename: prefer `sidecar_instance_id` for process scope.
- **Schema:** `schema_version == 7` minimum for provenance fields on audited rows and gateway envelopes.

---

## Downstream TODOs

- TODO: Reject or quarantine events with `schema_version` < 7 once fleet is migrated.
- TODO: Dashboards: bucket by `content_hash` + `generation` after policy reloads.
- TODO: Join `scan.scan_id` → `scan_findings` → `audit_events` via `run_id` / `trace_id`.
- TODO: `sinks.Event` forward path may omit zero `schema_version` in JSON — validate against persisted `audit_events` when strict schema compliance is required (see `TODO(v7-followup)` in `test/e2e/v7_observability_test.go`).

---

*Validated by `go test ./test/e2e/ -run TestObservabilityContractDocListsMatchGo`*
