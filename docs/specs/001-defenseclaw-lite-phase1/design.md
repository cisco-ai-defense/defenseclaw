# Design: DefenseClaw Edge Connector — Phase 1 (STANDARD Profile)

## Summary

DefenseClaw Edge Connector Phase 1 delivers a C-language enforcement agent (~80KB) for
Linux SBC devices and a companion Go fleet management service embedded in the existing
DefenseClaw gateway. The agent intercepts AI agent tool calls via Unix IPC, evaluates
them against compiled policy tables in <5us, runs a streaming DFA content scanner over
tool arguments and payloads, validates destinations against SSRF/netguard rules, infers
trust boundaries from session context, and escalates unknowns to the cloud via MQTT 5.0
with mTLS — now including truncated content and local findings for full cloud-side
inspection. A Python policy compiler bridges the existing YAML policy format to
device-optimized C headers, pre-compiled DFA state machine tables, and signed binary
blobs.

The system fits within the existing DefenseClaw architecture as a new connector type
(`edge-connector`) in the connector matrix, reusing the inspection pipeline, audit store,
and webhook infrastructure.

---

## Architecture

### Components

```
+--------------------------------------------------------------------------+
|                         PHASE 1 COMPONENT MAP                            |
+--------------------------------------------------------------------------+
|                                                                          |
|  ON-DEVICE (C, ~80KB binary)              |  CLOUD (Go + Python)        |
|  ---------------------------------------- | --------------------------- |
|                                           |                             |
|  +-------------+  +-----------------+     |  +------------------+       |
|  | IPC Hook    |  | Decision        |     |  | Fleet Manager    |       |
|  | (ipc_hook.c)|->| Engine          |     |  | (Go, embedded in |       |
|  |             |  |                 |     |  |  existing gateway)|      |
|  | * SO_PEERCRED|  | * Policy tbl   |     |  |                  |       |
|  | * Input val |  | * Content scan  |     |  | * Device registry|       |
|  | * Reg token |  | * Correlator    |     |  | * Heartbeat proc |       |
|  | * 512B max  |  | * Rate limit    |     |  | * Alert engine   |       |
|  | * Direction |  | * Verdict $     |     |  | * Audit sink     |       |
|  +-------------+  | * SSRF/netguard |     |  +--------+---------+       |
|                    | * Trust infer   |     |           |                 |
|                    | * Speculative   |     |  +--------v---------+       |
|                    +--------+--------+     |  | Verdict Cache    |       |
|                             |              |  | (Go, in-memory)  |       |
|                    +--------v--------+     |  |                  |       |
|                    | MQTT Client     |<-------->| * Hash->verdict |       |
|                    | (mqtt_client)   | MQTT 5.0 | * Category+evid.|       |
|                    |                 | mTLS     | * TTL management|       |
|                    | * Broker list   |     |  | * Pipeline fall- |       |
|                    | * Heartbeat     |     |  |   back           |       |
|                    | * Verdict req   |     |  +------------------+       |
|                    | * Content+dir   |     |                             |
|                    | * OTA receive   |     |  +------------------+       |
|                    | * Emergency     |     |  | Policy Compiler  |       |
|                    +--------+--------+     |  | (Python CLI)     |       |
|                             |              |  |                  |       |
|                    +--------v--------+     |  | * YAML -> C hdr  |       |
|                    | Audit Ring      |     |  | * YAML -> .bin   |       |
|                    | (audit_ring)    |     |  | * DFA table gen  |       |
|                    |                 |     |  | * Ed25519 sign   |       |
|                    | * 256 entries   |     |  | * Size validation|       |
|                    | * HMAC chain    |     |  +------------------+       |
|                    | * RAM buffer    |     |                             |
|                    | * Flash-safe    |     |                             |
|                    +--------+--------+     |                             |
|                                            |                             |
+--------------------------------------------------------------------------+
```

### Pipeline Stages

The edge connector runs an 8-stage pipeline for every intercepted call:

```
+-------+    +-------+    +---------+    +--------+    +---------+
| [1]   |    | [2]   |    | [3]     |    | [4]    |    | [5]     |
| Input |--->| Rate  |--->| Content |--->| Deny   |--->| Dest    |
| Valid. |    | Limit |    | Scan    |    | Hash   |    | Check + |
|        |    |        |    | (DFA)  |    | Lookup |    | SSRF    |
+-------+    +-------+    +---------+    +--------+    +---------+
                                                            |
                                                            v
+----------+    +---------+    +------------+
| [8]      |    | [7]     |    | [6]        |
| Enriched |<---| Verdict |<---| Trust-Aware|
| Cloud    |    | Cache   |    | Sequence   |
| Escalate |    | (+cat/  |    | Correlator |
|          |    |  evid.) |    |            |
+----------+    +---------+    +------------+
```

**Stage descriptions:**

1. **Input validation** (existing) — 512B max, ASCII, hash length, SO_PEERCRED, registration nonce.
2. **Rate limiting** (existing) — 100/s global, per-peer token bucket.
3. **Content scan** (NEW) — Single-pass streaming DFA pattern matcher over tool args and content fields. Detects SECRET, PII, CREDENTIAL, EXFIL, INJECTION, COMMAND patterns. Up to 4 findings per scan.
4. **Deny hash lookup** (existing) — SHA-256 tool hash checked against compiled deny-list table.
5. **Destination check** (existing + SSRF/netguard) — Allow/deny-list lookup plus loopback, link-local, cloud metadata, RFC1918, scheme, and inline credential validation.
6. **Trust-aware sequence correlation** (existing correlator + content_scope) — Sliding window sequence analysis with trust boundary inference: first-in-session = system, tool_result direction = tool output, otherwise user_input. Stricter rules for user_input scope.
7. **Verdict cache** (existing + category/evidence) — Local cache keyed by tool hash; entries now include category enum and 64-byte evidence snippet from cloud verdicts.
8. **Enriched cloud escalation** (expanded) — MQTT verdict request includes truncated content, direction tag, inferred content_scope, and local findings array. Cloud runs full inspection pipeline on enriched payload.

### Data Flow — Tool Call Evaluation

```
AI Agent                Edge Connector                      Cloud
   |                         |                                |
   | 1. JSON-RPC tool_call   |                                |
   | (via Unix socket)       |                                |
   | (+optional direction,   |                                |
   |  content fields)        |                                |
   |------------------------>|                                |
   |                         |                                |
   |                    2. Input validation (512B, ASCII, hash length)
   |                    3. SO_PEERCRED + start_time verify
   |                    4. Rate limit check (100/s)
   |                    5. IPC rate limit check (token bucket)
   |                         |                                |
   |                    6. Content scan (DFA pattern match):   |
   |                       - Scan tool args + content field    |
   |                       - Up to 4 findings (category+offset)|
   |                         |                                |
   |                    7. Decision engine:                    |
   |                       a. Deny-list hash check            |
   |                       b. Policy table lookup             |
   |                       c. Destination + SSRF/netguard     |
   |                       d. Trust-aware correlator           |
   |                       e. Verdict cache lookup (+cat/evid)|
   |                         |                                |
   |                    [If local decision]                    |
   |<------------------------|  8a. Return ALLOW/BLOCK/WARN   |
   |                         |      + audit ring write        |
   |                         |                                |
   |                    [If escalation needed]                 |
   |                         |                                |
   |                    8b. Check escalation_mode table:       |
   |                        sync_block -> block & wait (5s)   |
   |                        speculative -> return PENDING     |
   |                         |                                |
   |<------------------------|  8c. PENDING (speculative)     |
   |  (agent proceeds)       |                                |
   |                         |  9. MQTT publish verdict/req   |
   |                         |     (enriched: content +       |
   |                         |      direction + scope +       |
   |                         |      local findings)           |
   |                         |------------------------------->|
   |                         |                                |
   |                         |       10. Cloud inspection:    |
   |                         |           regex + LLM judge +  |
   |                         |           AI Defense pipeline  |
   |                         |                                |
   |                         |  11. MQTT verdict/resp         |
   |                         |      (+category + evidence)    |
   |                         |<-------------------------------|
   |                         |                                |
   |                    12. Verify HMAC tag                    |
   |                    13. Dedup check (request_id)           |
   |                    14. Cache verdict (TTL + cat/evidence) |
   |                    15. Update clock (server_ts)           |
   |                         |                                |
   |                    [If BLOCK + speculative was PENDING]   |
   | 16. Retroactive callback|                                |
   |<------------------------|                                |
   |  (agent kills tool)     |                                |
   |                         |                                |
   |                    17. Audit ring write                   |
```

### Data Flow — Heartbeat & Fleet Health

```
Device                    MQTT Broker              Fleet Manager
  |                           |                         |
  | heartbeat (32B CBOR)      |                         |
  | every 30s, QoS 0          |                         |
  |-------------------------->|------------------------>|
  |                           |                         |
  |                           |                    Process:
  |                           |                    * Update last_seen
  |                           |                    * Accumulate counters
  |                           |                    * Check audit_head_hmac
  |                           |                    * Evaluate alert rules
  |                           |                         |
  |                           |                    [If anomaly detected]
  |                           |                    * Fire webhook/alert
```

---

## Content Scanner Module

### Overview

The content scanner is a new pipeline stage (stage 3) that performs streaming pattern
matching over tool arguments and optional content fields. It is designed for zero dynamic
allocation, deterministic execution time, and minimal flash/RAM footprint.

### Pattern Categories

Six pattern categories are ported from the full DefenseClaw gateway:

| Category | Code | Source in Gateway | Examples |
|----------|------|-------------------|----------|
| SECRET | 0x01 | `secretPatternDetectors` | API keys, tokens, private keys |
| PII | 0x02 | `defaultPIIDataRegexSources` | SSNs, emails, credit card numbers |
| CREDENTIAL | 0x03 | `redaction/credentials.go` | Passwords, auth headers, connection strings |
| EXFIL | 0x04 | `findStrongExfilIntent` | Data exfiltration attempts, encoded payloads |
| INJECTION | 0x05 | `actionfacts/` (injection patterns) | Prompt injection, SQL injection, path traversal |
| COMMAND | 0x06 | `actionfacts/` (dangerous commands) | rm -rf, chmod 777, curl pipes, reverse shells |

### Design

- **Pre-compiled DFA state machine tables**: The policy compiler converts gateway regex
  patterns into deterministic finite automaton transition tables at build time. These are
  emitted as const arrays in the generated C header and occupy flash only (zero static RAM).
- **Single-pass streaming matcher**: The scanner walks the input byte-by-byte through the
  DFA. Each byte triggers at most one table lookup per active pattern category. No
  backtracking.
- **Reusable `scan_context_t` on stack**: ~200 bytes allocated on the stack per scan
  invocation. Holds current DFA state per category, findings count, and scratch space.
  Fully reentrant; no global state.
- **Up to 4 findings per scan**: The scanner records the first 4 pattern matches
  (category + byte offset). If more than 4 patterns match, only the first 4 are retained
  and a `truncated` flag is set. Any single finding is sufficient to trigger BLOCK or
  escalation depending on policy.
- **Zero static RAM**: All DFA tables reside in `.rodata` (flash). The only RAM consumed
  is the stack-allocated `scan_context_t` during a scan.

### Data Structures

```c
typedef struct {
    uint8_t  category;     /* DCLAW_SCAN_SECRET..DCLAW_SCAN_COMMAND */
    uint16_t byte_offset;  /* offset in scanned input where match started */
    uint8_t  pattern_id;   /* index into pattern table for this category */
} dclaw_finding_t;          /* 4 bytes */

typedef struct {
    uint16_t dfa_state[6]; /* current state per category */
    dclaw_finding_t findings[4];
    uint8_t  finding_count;
    uint8_t  truncated;    /* 1 if >4 matches found */
    uint8_t  _pad[2];
    /* scratch space for partial UTF-8 decode, etc. */
    uint8_t  scratch[168];
} scan_context_t;           /* ~200 bytes, stack-allocated */
```

### Integration

The content scanner runs after rate limiting and before the deny hash lookup. If the
JSON-RPC request includes a `content` field (see Response Interception below), both
`tool_name`/`destination` args and `content` are scanned. Findings flow into the
correlator (as trust-scoped signals) and into the enriched cloud escalation payload.

---

## SSRF / Network Validation

### Overview

Ported from the gateway's `internal/netguard/` package, the SSRF validation module
extends the existing destination check stage (stage 5) with network-level blocking rules.

### Blocked Address Ranges

| Range | Reason |
|-------|--------|
| `127.0.0.0/8` | Loopback |
| `::1/128` | IPv6 loopback |
| `0.0.0.0/8` | Unspecified / "this network" |
| `169.254.0.0/16` | Link-local (includes cloud metadata at `169.254.169.254`) |
| `10.0.0.0/8` | RFC1918 private |
| `172.16.0.0/12` | RFC1918 private |
| `192.168.0.0/16` | RFC1918 private |
| `fc00::/7` | IPv6 unique local |
| `fe80::/10` | IPv6 link-local |

### Additional Checks

- **Inline credential rejection**: URLs containing `user:pass@` authority syntax are
  blocked to prevent credential leakage through tool destinations.
- **Scheme validation**: Only `http` and `https` schemes are permitted. All other schemes
  (ftp, file, gopher, data, etc.) are rejected.
- **DNS rebinding guard**: If the destination is a hostname (not an IP literal), the
  resolved IP is checked against the blocked ranges before the connection proceeds. On
  constrained devices without DNS resolution capability, hostname destinations are
  escalated to the cloud.

### Implementation

The netguard check is implemented as an inline function called within the existing
destination check stage. It parses the destination string, extracts host and scheme, and
performs range checks using a compact bitmask table (~64 bytes in flash). No additional
RAM is required beyond the stack frame.

---

## Trust Boundary Inference

### Overview

The edge connector infers a `content_scope` tag for each intercepted call, enabling
stricter policy rules for untrusted content without requiring the AI agent to explicitly
label trust boundaries. This keeps the connector agent-agnostic.

### Inference Rules

| Condition | Inferred `content_scope` | Rationale |
|-----------|--------------------------|-----------|
| First call in session (`session_id` is new or call index == 0) | `system` | Initial tool calls typically set up system-level context (config, env) |
| `direction` field == `tool_result` | `tool_output` | Data returned by external tools is semi-trusted but not user-controlled |
| All other calls | `user_input` | Default assumption: content originates from or is influenced by the user |

### Policy Implications

- **`system` scope**: All pattern categories enabled, but threshold is lenient (finding
  alone does not trigger BLOCK; escalation preferred).
- **`tool_output` scope**: All pattern categories enabled at normal sensitivity.
- **`user_input` scope**: Strictest rules. INJECTION and COMMAND findings trigger
  immediate BLOCK. SECRET and CREDENTIAL findings trigger BLOCK. PII and EXFIL findings
  trigger escalation.

### Integration

Trust boundary inference is built into the correlator module (stage 6). The inferred
`content_scope` is stored alongside the session's sliding window state and is included
in the enriched cloud escalation payload so the cloud pipeline can apply its own
scope-aware rules.

---

## Response Interception

### Overview

The edge connector supports bidirectional IPC, allowing it to inspect both outgoing
tool calls (requests) and incoming tool results (responses). This is achieved through
a backward-compatible extension of the JSON-RPC schema.

### Extended JSON-RPC Schema

The IPC request schema is extended with two optional fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `direction` | string | `"request"` | One of: `request`, `response`, `tool_call`, `tool_result` |
| `content` | string | (absent) | Optional content payload for scanning (tool args, response body, etc.) |

When `direction` is `response` or `tool_result`, the content scanner runs on the content
field, the trust boundary inference tags it as `tool_output`, and all pipeline stages
execute normally.

### Backward Compatibility

- If `direction` is absent, the connector assumes `"request"` — identical to Phase 1
  behavior.
- If `content` is absent, the content scanner runs only on the `tool_name` and
  `destination` fields — identical to scanning tool args only.
- Agents that do not send tool results through the connector experience no change in
  behavior or protocol.

### Agent Integration Modes

| Mode | Agent Behavior | Connector Behavior |
|------|----------------|-------------------|
| Request-only (Phase 1 compat) | Sends `evaluate` with tool_name/hash/dest | Scans args, evaluates policy, returns verdict |
| Bidirectional | Sends `evaluate` for requests AND responses with `direction` + `content` | Full content scan on both directions; trust-scoped correlation |
| Content-augmented | Sends `evaluate` with `content` field on requests | Content scanner has richer input; still request-only flow |

---

## Enriched Cloud Escalation

### Overview

When local evaluation cannot produce a definitive verdict and the call must be escalated
to the cloud, the MQTT verdict request payload is expanded to include content and context.
This enables the cloud to run its full inspection pipeline (regex + LLM judge + AI
Defense) on meaningful data rather than an opaque hash.

### Expanded Verdict Request Payload

```
CBOR map {
  "request_id":     uint32,          // (existing) unique request ID
  "tool_hash":      bytes(32),       // (existing) SHA-256 of tool binary
  "tool_name":      text(max 64),    // (existing) tool name string
  "capabilities":   uint8,           // (existing) capability bitmask
  "destination":    text(max 128),   // (existing) destination URL/host
  "session_id":     uint16,          // (existing) session identifier

  // --- NEW fields ---
  "content":        bytes(max 1024), // truncated content payload
  "direction":      uint8,           // 0=prompt, 1=completion, 2=tool_call, 3=tool_result
  "content_scope":  uint8,           // 0=system, 1=tool_output, 2=user_input
  "findings": [                      // local scanner findings (0..4)
    { "category": uint8, "offset": uint16 },
    ...
  ]
}
```

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_escalation_payload_bytes` | 1024 (1 KB) | Maximum content bytes included in escalation. Content is truncated with a `truncated` flag if it exceeds this limit. |

### Expanded Verdict Response Payload

```
CBOR map {
  "request_id":    uint32,          // (existing) echo back
  "action":        uint8,           // (existing) 0=ALLOW, 1=BLOCK, 2=WARN
  "severity":      uint8,           // (existing) 0-3
  "ttl_minutes":   uint16,          // (existing)
  "hmac":          bytes(4),        // (existing) truncated HMAC-SHA256
  "server_ts":     uint32,          // (existing) UTC epoch seconds

  // --- NEW fields ---
  "category":      uint8,           // category enum: 0=none, 1=injection, 2=pii,
                                    //   3=secret, 4=exfil, 5=command, 6=credential
  "evidence":      bytes(max 64)    // truncated evidence snippet from cloud analysis
}
```

### Cloud Processing

When the fleet manager receives an enriched verdict request:

1. If `content` is present and non-empty, the full gateway inspection pipeline runs on it:
   - Regex pattern matching (all gateway rule sets)
   - LLM judge evaluation (prompt injection, jailbreak detection)
   - AI Defense policy evaluation
2. The `direction` and `content_scope` tags inform scope-aware rules in the pipeline.
3. The `findings` array from the device is compared with cloud findings for consistency
   and telemetry.
4. The verdict response includes `category` and `evidence` so the device can cache and
   log meaningful context.

---

## Interfaces

### Device IPC (Unix Socket)

```
Path: /var/run/edge-connector.sock
Protocol: JSON-RPC 2.0 (single message per connection)
Max payload: 512 bytes
Auth: SO_PEERCRED + registration nonce

Request:
{
  "jsonrpc": "2.0",
  "method": "evaluate",
  "params": {
    "tool_name": "string (max 64, ASCII)",
    "tool_hash": "hex string (64 chars = 32 bytes)",
    "capabilities": "uint8 bitmask",
    "destination": "string (max 128, optional)",
    "session_id": "uint16",
    "direction": "string (request|response|tool_call|tool_result, optional, default: request)",
    "content": "string (max 256, optional, scanned by content scanner)"
  },
  "id": 1
}

Response:
{
  "jsonrpc": "2.0",
  "result": {
    "action": "allow|block|warn|pending",
    "reason": "string (reason code name)",
    "mode": "sync|pending|retroactive_block",
    "category": "string (none|injection|pii|secret|exfil|command|credential, optional)",
    "evidence": "string (truncated evidence snippet, optional)"
  },
  "id": 1
}
```

### MQTT Topics (Device Side)

Per architecture proposal section 7.1, using multi-tenant topic hierarchy:

| Direction | Topic | QoS | Payload |
|-----------|-------|-----|---------|
| Device->Cloud | `defenseclaw/{t}/{f}/{d}/heartbeat` | 0 | 32B CBOR |
| Device->Cloud | `defenseclaw/{t}/{f}/{d}/register` | 1 | Registration CBOR |
| Device->Cloud | `defenseclaw/{t}/{f}/{d}/verdict/req` | 1 | Enriched verdict request CBOR (up to ~1.3KB) |
| Cloud->Device | `defenseclaw/{t}/{f}/{d}/verdict/resp` | 1 | Verdict response CBOR (~24-88B with category/evidence) |
| Cloud->Device | `defenseclaw/{t}/{f}/{d}/ota/policy` | 1 | Signed policy blob (includes DFA tables) |
| Cloud->Device | `defenseclaw/{t}/{f}/{d}/cmd/request` | 1 | Operator command |
| Device->Cloud | `defenseclaw/{t}/{f}/{d}/audit/sync` | 1 | Audit ring batch |
| Cloud->Fleet | `defenseclaw/{t}/{f}/broadcast/emergency-block` | 1 | 108B signed msg |

### Cloud Fleet Manager REST API

Embedded in existing gateway HTTP server at `/api/v1/fleet/`:

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/devices/register` | Auto-register on first MQTT connect |
| GET | `/devices/{id}` | Device status and metadata |
| GET | `/devices` | List/filter devices |
| POST | `/devices/{id}/command` | Send command to device |
| GET | `/fleet/health` | Fleet-wide dashboard data |
| POST | `/audit/query` | Query audit logs across fleet |
| POST | `/threat-intel/push` | Push new deny hashes to fleet |
| POST | `/policy/compile` | Compile + distribute policy (includes DFA tables) |
| POST | `/policy/simulate` | Dry-run policy change |
| GET | `/devices/{id}/traces` | Distributed trace lookup |

### Policy Compiler CLI

```bash
dclaw-compile \
  --input policies/strict.yaml \
  --profile standard \
  --target-partition-size 4096 \
  --generate-dfa-tables \
  --pattern-source gateway/internal/scanner/ \
  --signing-key /path/to/ota-ca.key \
  --output-header generated/policy_tables.h \
  --output-binary dist/policy.bin \
  --output-report dist/size-report.txt
```

---

## Data Model

### On-Device (C Structs — Static Allocation)

All data structures use fixed-size static allocation. No malloc/free.

| Structure | Size | Count | Total RAM |
|-----------|------|-------|-----------|
| `dclaw_session_t` | 24B | 16 | 384B |
| `dclaw_verdict_cache_entry_t` | 112B | 64 | 7,168B |
| `dclaw_pending_verdict_t` | 8B | 8 | 64B |
| `dclaw_speculative_slot_t` | 12B | 4 | 48B |
| `dclaw_rate_limiter_t` | 8B | 3 | 24B |
| `dclaw_canary_state_t` | 32B | 1 | 32B |
| `dclaw_clock_t` | 13B | 1 | 16B (aligned) |
| `dclaw_emergency_state_t` | 9B | 1 | 12B (aligned) |
| `dclaw_ipc_peer_t` | 48B | 1 | 48B |
| `dclaw_audit_writer_t` | 268B | 1 | 268B |
| Broker fallback URLs | 128B | 3 | 384B |
| MQTT client state | -- | 1 | 1,024B |
| TLS session (mbedTLS) | -- | 1 | 16,384B |
| Stack (incl. scan_context_t) | -- | -- | 4,096B |
| **TOTAL** | | | **~14-19 KB** |

Note: `scan_context_t` (~200 bytes) is stack-allocated and included in the stack budget.
DFA state machine tables reside in `.rodata` (flash) and consume zero static RAM.
`dclaw_session_t` grows by 4B to include `content_scope`.
`dclaw_verdict_cache_entry_t` grows by 72B to include `category` (1B) + `evidence` (64B) + padding (7B).

### On-Device (Flash Partitions)

| Partition | Size | Purpose |
|-----------|------|---------|
| Policy A | 4 KB | Active policy tables |
| Policy B | 4 KB | Inactive (OTA write target) |
| DFA Tables | 8 KB | Pre-compiled DFA state machine tables (shared by A/B) |
| Audit Ring | 4 KB | 256 x 16B audit entries |
| Config Store | 1 KB | Certs, broker list, emergency seq |
| **Total data flash** | **21 KB** | |

### Size Budget

| Resource | Phase 1 | Phase 1 + AI Security | Limit |
|----------|---------|----------------------|-------|
| Binary (`.text` + `.rodata`) | ~53 KB | ~68 KB | 80 KB |
| RAM (static + stack) | ~10-15 KB | ~14-19 KB | 25 KB |

The ~15 KB binary increase comes from: DFA table code (~8 KB in `.rodata`), SSRF/netguard
validation (~2 KB), trust inference logic (~1 KB), enriched MQTT serialization (~2 KB),
content scanner engine (~2 KB). Still within the 80 KB binary / 25 KB RAM hard limits.

### Cloud-Side (Fleet Manager)

Extends existing DefenseClaw PostgreSQL schema:

```sql
-- New table: IoT device registry
CREATE TABLE iot_devices (
    device_id       BIGINT PRIMARY KEY,  -- DCLAW_FULL_ID composite
    tenant_id       SMALLINT NOT NULL,
    fleet_id        SMALLINT NOT NULL,
    hw_profile      TEXT NOT NULL,       -- 'mcu', 'sbc', 'gateway'
    fw_version      TEXT NOT NULL,
    policy_version  SMALLINT NOT NULL,
    capabilities    SMALLINT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'online',
    last_heartbeat  TIMESTAMPTZ,
    last_audit_hmac BYTEA,
    site_id         TEXT,
    registered_at   TIMESTAMPTZ DEFAULT NOW(),
    flags           SMALLINT DEFAULT 0
);

-- New table: Fleet audit events (TimescaleDB hypertable)
CREATE TABLE iot_audit_events (
    device_id       BIGINT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    action          SMALLINT NOT NULL,
    reason          SMALLINT NOT NULL,
    tool_hash_short SMALLINT NOT NULL,
    session_id      SMALLINT NOT NULL,
    hmac_valid      BOOLEAN NOT NULL,
    category        SMALLINT,            -- pattern category (nullable for Phase 1 events)
    content_scope   SMALLINT             -- inferred trust scope (nullable)
);

-- Verdict cache (in-memory Redis, persisted for restart)
-- Key: SHA256 tool hash (32 bytes)
-- Value: {action, severity, ttl_minutes, cached_at, category, evidence}
-- TTL: per-action (ALLOW=24h, BLOCK=7d, WARN=4h)
```

---

## Integration Points

### With Existing DefenseClaw Gateway

| Integration | Mechanism | Notes |
|-------------|-----------|-------|
| Inspection pipeline | Internal Go function call | Fleet manager calls `inspect.Evaluate()` for cache misses; now passes content + direction + scope |
| Content scanner patterns | Gateway pattern sources | DFA tables compiled from gateway's `secretPatternDetectors`, `defaultPIIDataRegexSources`, `redaction/credentials.go`, `findStrongExfilIntent`, `actionfacts/` |
| SSRF/netguard rules | Ported from `internal/netguard/` | Same blocked ranges and validation logic, reimplemented in C for on-device use |
| Audit store | Shared PostgreSQL + existing `audit.Store` interface | IoT events flow into same SIEM pipeline; now include category/scope |
| Webhook dispatcher | Existing `WebhookDispatcher` | Fleet alerts use same webhook infra |
| Prometheus metrics | Existing `/metrics` endpoint | New `defenseclaw_fleet_*` and `defenseclaw_edge_scanner_*` metric families |
| Connector matrix | New entry: `edge-connector` | Registered alongside claude-code, codex, cursor |
| MQTT broker | External (EMQX/Mosquitto) | Fleet manager subscribes; devices connect directly |

### With External Systems

| System | Protocol | Purpose |
|--------|----------|---------|
| EMQX/Mosquitto | MQTT 5.0 | Device<->Cloud messaging (enriched payloads) |
| Redis | TCP | Verdict cache persistence across gateway restarts |
| TimescaleDB | PostgreSQL | Audit event hypertable for time-series queries |
| Prometheus | HTTP /metrics | Fleet metrics scraping |
| Grafana | Prometheus datasource | Fleet dashboard (pre-built JSON) |

---

## Tradeoffs

| Decision | Chosen | Alternative | Rationale |
|----------|--------|-------------|-----------|
| Static allocation only | Yes | Dynamic malloc | Deterministic, no fragmentation, provable RAM budget |
| HMAC-SHA256 truncated to 4B for verdicts | 4 bytes | Full 32B HMAC | Bandwidth: response fits single MQTT packet. Security: 2^32 forgery resistance at 60 req/min = 136 years |
| Policy tables compiled at build-time | C headers | Runtime interpreter | O(1) lookup in <1us vs. interpreted Rego at ~1ms |
| Embedded fleet manager in gateway binary | Embedded | Separate microservice | Avoids deployment complexity; gateway is already 50MB |
| Redis for verdict cache persistence | Redis | SQLite | Sub-millisecond reads; gateway restart doesn't lose cache |
| EMQX as MQTT broker (external) | EMQX | Embedded broker | EMQX handles 200K+ connections; clustering; proven |
| Compiled DFA tables for content scanning | Pre-compiled DFA | Runtime regex engine | DFA gives deterministic O(n) execution per byte with no backtracking. Regex engines (PCRE/RE2) require 10-50KB of library code and unpredictable stack usage. DFA tables in `.rodata` consume flash only, not RAM. Trade: patterns must be recompiled on policy update (handled by OTA). |
| Inferred trust scope vs. agent-provided tags | Inference from context | Explicit agent tags | Agent-agnostic design: works with any AI agent without protocol changes. Agents that label content correctly are future-compatible (connector will prefer explicit tags when present). Trade: inference heuristic may misclassify edge cases; cloud pipeline serves as backstop. |
| Content in MQTT escalation payload | Truncated content (1KB default) | Hash-only (Phase 1 approach) | Hash-only prevents cloud from running meaningful content analysis (regex, LLM judge, AI Defense). Including truncated content enables full inspection while keeping payload under 1.5KB. Configurable cap (`max_escalation_payload_bytes`) lets operators reduce for bandwidth-constrained networks. Trade: content in transit (mitigated by mTLS + MQTT 5.0 encryption). |

---

## Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|------------|
| mbedTLS handshake exceeds RAM budget on some SBCs | High | Low | Measure on target hardware in week 1; fall back to wolfSSL if needed |
| MQTT broker becomes bottleneck at 100K heartbeats/s | Medium | Medium | EMQX cluster; heartbeat QoS 0 (fire-and-forget) reduces broker state |
| Policy compiler generates tables too large for flash | Low | Medium | Size validation step (REQ-44) catches before OTA; compiler reports breakdown |
| Ed25519 verification latency on Cortex-A53 exceeds 5ms | Medium | Low | Measured at ~0.5ms on Cortex-M4; A72 will be faster. Only needed for OTA/emergency (rare) |
| Flash wear from audit writes exceeds endurance | High | Very Low | Write coalescing reduces to 6.6 writes/min; math shows >180 year lifetime at 100K cycles |
| IPC parser vulnerability (buffer overflow) | Critical | Low | AFL++ fuzz mandate (REQ-52); banned function list; static analysis in CI |
| DFA table size exceeds flash budget for complex patterns | Medium | Low | Policy compiler validates total DFA size against partition limit; large pattern sets can be split across priority tiers with lower-priority patterns cloud-only |
| Content in MQTT payload leaks sensitive data | Medium | Low | mTLS encrypts in transit; `max_escalation_payload_bytes` caps exposure; operators can set to 0 to disable content escalation entirely (falls back to hash-only) |
| Trust inference misclassifies system calls as user input | Low | Medium | Misclassification triggers stricter rules (safe direction); cloud pipeline re-evaluates with full context; future protocol extension allows explicit agent tags |
| Enriched verdict request exceeds MQTT max packet size | Low | Very Low | Default 1KB content + headers = ~1.3KB; MQTT 5.0 max is 256MB; even constrained brokers support 4KB+ |
