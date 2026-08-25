# Design: DefenseClaw Lite — Phase 1 (STANDARD Profile)

## Summary

DefenseClaw Lite Phase 1 delivers a C-language enforcement agent (~80KB) for Linux
SBC devices and a companion Go fleet management service embedded in the existing
DefenseClaw gateway. The agent intercepts AI agent tool calls via Unix IPC, evaluates
them against compiled policy tables in <5μs, and escalates unknowns to the cloud via
MQTT 5.0 with mTLS. A Python policy compiler bridges the existing YAML policy format
to device-optimized C headers and signed binary blobs.

The system fits within the existing DefenseClaw architecture as a new connector type
(`iot-lite`) in the connector matrix, reusing the inspection pipeline, audit store,
and webhook infrastructure.

---

## Architecture

### Components

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         PHASE 1 COMPONENT MAP                             │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ON-DEVICE (C, ~80KB binary)              │  CLOUD (Go + Python)          │
│  ─────────────────────────────            │  ────────────────────         │
│                                           │                               │
│  ┌─────────────┐  ┌──────────────┐       │  ┌──────────────────┐        │
│  │ IPC Hook    │  │ Decision     │       │  │ Fleet Manager    │        │
│  │ (ipc_hook.c)│─►│ Engine       │       │  │ (Go, embedded in │        │
│  │             │  │              │       │  │  existing gateway)│        │
│  │ • SO_PEERCRED│  │ • Policy tbl │       │  │                  │        │
│  │ • Input val │  │ • Correlator │       │  │ • Device registry│        │
│  │ • Reg token │  │ • Rate limit │       │  │ • Heartbeat proc │        │
│  │ • 512B max  │  │ • Verdict $  │       │  │ • Alert engine   │        │
│  └─────────────┘  │ • Speculative│       │  │ • Audit sink     │        │
│                    └──────┬───────┘       │  └────────┬─────────┘        │
│                           │               │           │                   │
│                    ┌──────▼───────┐       │  ┌────────▼─────────┐        │
│                    │ MQTT Client  │◄─────────►│ Verdict Cache    │        │
│                    │ (mqtt_client)│  MQTT 5.0 │ (Go, in-memory)  │        │
│                    │              │  mTLS     │                  │        │
│                    │ • Broker list│       │  │ • Hash→verdict   │        │
│                    │ • Heartbeat  │       │  │ • TTL management │        │
│                    │ • Verdict req│       │  │ • Pipeline fall-  │        │
│                    │ • OTA receive│       │  │   back            │        │
│                    │ • Emergency  │       │  └──────────────────┘        │
│                    └──────┬───────┘       │                               │
│                           │               │  ┌──────────────────┐        │
│                    ┌──────▼───────┐       │  │ Policy Compiler  │        │
│                    │ Audit Ring   │       │  │ (Python CLI)     │        │
│                    │ (audit_ring) │       │  │                  │        │
│                    │              │       │  │ • YAML → C header│        │
│                    │ • 256 entries│       │  │ • YAML → .bin    │        │
│                    │ • HMAC chain │       │  │ • Ed25519 sign   │        │
│                    │ • RAM buffer │       │  │ • Size validation│        │
│                    │ • Flash-safe │       │  └──────────────────┘        │
│                    └──────────────┘       │                               │
│                                           │                               │
└──────────────────────────────────────────────────────────────────────────┘
```

### Data Flow — Tool Call Evaluation

```
AI Agent                DefenseClaw Lite                    Cloud
   │                         │                                │
   │ 1. JSON-RPC tool_call   │                                │
   │ (via Unix socket)       │                                │
   │────────────────────────►│                                │
   │                         │                                │
   │                    2. Input validation (512B, ASCII, hash length)
   │                    3. SO_PEERCRED + start_time verify
   │                    4. Rate limit check (100/s)
   │                    5. IPC rate limit check (token bucket)
   │                         │                                │
   │                    6. Decision engine:                    │
   │                       a. Deny-list hash check            │
   │                       b. Policy table lookup             │
   │                       c. Correlator sequence check       │
   │                       d. Destination allow/deny          │
   │                       e. Verdict cache lookup            │
   │                         │                                │
   │                    [If local decision]                    │
   │◄────────────────────────│ 7a. Return ALLOW/BLOCK/WARN   │
   │                         │     + audit ring write         │
   │                         │                                │
   │                    [If escalation needed]                 │
   │                         │                                │
   │                    7b. Check escalation_mode table:       │
   │                        sync_block → block & wait (5s)    │
   │                        speculative → return PENDING      │
   │                         │                                │
   │◄────────────────────────│ 7c. PENDING (speculative)      │
   │  (agent proceeds)       │                                │
   │                         │ 8. MQTT publish verdict/req    │
   │                         │───────────────────────────────►│
   │                         │                                │
   │                         │       9. Inspect pipeline      │
   │                         │          (YARA/OPA/regex)      │
   │                         │                                │
   │                         │ 10. MQTT verdict/resp          │
   │                         │◄───────────────────────────────│
   │                         │                                │
   │                    11. Verify HMAC tag                    │
   │                    12. Dedup check (request_id)           │
   │                    13. Cache verdict (TTL)                │
   │                    14. Update clock (server_ts)           │
   │                         │                                │
   │                    [If BLOCK + speculative was PENDING]   │
   │ 15. Retroactive callback│                                │
   │◄────────────────────────│                                │
   │  (agent kills tool)     │                                │
   │                         │                                │
   │                    16. Audit ring write                   │
```

### Data Flow — Heartbeat & Fleet Health

```
Device                    MQTT Broker              Fleet Manager
  │                           │                         │
  │ heartbeat (32B CBOR)      │                         │
  │ every 30s, QoS 0          │                         │
  │──────────────────────────►│────────────────────────►│
  │                           │                         │
  │                           │                    Process:
  │                           │                    • Update last_seen
  │                           │                    • Accumulate counters
  │                           │                    • Check audit_head_hmac
  │                           │                    • Evaluate alert rules
  │                           │                         │
  │                           │                    [If anomaly detected]
  │                           │                    • Fire webhook/alert
```

---

## Interfaces

### Device IPC (Unix Socket)

```
Path: /var/run/defenseclaw-lite.sock
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
    "session_id": "uint16"
  },
  "id": 1
}

Response:
{
  "jsonrpc": "2.0",
  "result": {
    "action": "allow|block|warn|pending",
    "reason": "string (reason code name)",
    "mode": "sync|pending|retroactive_block"
  },
  "id": 1
}
```

### MQTT Topics (Device Side)

Per architecture proposal §7.1, using multi-tenant topic hierarchy:

| Direction | Topic | QoS | Payload |
|-----------|-------|-----|---------|
| Device→Cloud | `defenseclaw/{t}/{f}/{d}/heartbeat` | 0 | 32B CBOR |
| Device→Cloud | `defenseclaw/{t}/{f}/{d}/register` | 1 | Registration CBOR |
| Device→Cloud | `defenseclaw/{t}/{f}/{d}/verdict/req` | 1 | Verdict request CBOR |
| Cloud→Device | `defenseclaw/{t}/{f}/{d}/verdict/resp` | 1 | 16B verdict response |
| Cloud→Device | `defenseclaw/{t}/{f}/{d}/ota/policy` | 1 | Signed policy blob |
| Cloud→Device | `defenseclaw/{t}/{f}/{d}/cmd/request` | 1 | Operator command |
| Device→Cloud | `defenseclaw/{t}/{f}/{d}/audit/sync` | 1 | Audit ring batch |
| Cloud→Fleet | `defenseclaw/{t}/{f}/broadcast/emergency-block` | 1 | 108B signed msg |

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
| POST | `/policy/compile` | Compile + distribute policy |
| POST | `/policy/simulate` | Dry-run policy change |
| GET | `/devices/{id}/traces` | Distributed trace lookup |

### Policy Compiler CLI

```bash
dclaw-compile \
  --input policies/strict.yaml \
  --profile standard \
  --target-partition-size 4096 \
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
| `dclaw_session_t` | 20B | 16 | 320B |
| `dclaw_verdict_cache_entry_t` | 40B | 64 | 2,560B |
| `dclaw_pending_verdict_t` | 8B | 8 | 64B |
| `dclaw_speculative_slot_t` | 12B | 4 | 48B |
| `dclaw_rate_limiter_t` | 8B | 3 | 24B |
| `dclaw_canary_state_t` | 32B | 1 | 32B |
| `dclaw_clock_t` | 13B | 1 | 16B (aligned) |
| `dclaw_emergency_state_t` | 9B | 1 | 12B (aligned) |
| `dclaw_ipc_peer_t` | 48B | 1 | 48B |
| `dclaw_audit_writer_t` | 268B | 1 | 268B |
| Broker fallback URLs | 128B | 3 | 384B |
| MQTT client state | — | 1 | 1,024B |
| TLS session (mbedTLS) | — | 1 | 16,384B |
| Stack | — | — | 4,096B |
| **TOTAL** | | | **~25 KB** |

### On-Device (Flash Partitions)

| Partition | Size | Purpose |
|-----------|------|---------|
| Policy A | 4 KB | Active policy tables |
| Policy B | 4 KB | Inactive (OTA write target) |
| Audit Ring | 4 KB | 256 × 16B audit entries |
| Config Store | 1 KB | Certs, broker list, emergency seq |
| **Total data flash** | **13 KB** | |

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
    hmac_valid      BOOLEAN NOT NULL
);

-- Verdict cache (in-memory Redis, persisted for restart)
-- Key: SHA256 tool hash (32 bytes)
-- Value: {action, severity, ttl_minutes, cached_at}
-- TTL: per-action (ALLOW=24h, BLOCK=7d, WARN=4h)
```

---

## Integration Points

### With Existing DefenseClaw Gateway

| Integration | Mechanism | Notes |
|-------------|-----------|-------|
| Inspection pipeline | Internal Go function call | Fleet manager calls `inspect.Evaluate()` for cache misses |
| Audit store | Shared PostgreSQL + existing `audit.Store` interface | IoT events flow into same SIEM pipeline |
| Webhook dispatcher | Existing `WebhookDispatcher` | Fleet alerts use same webhook infra |
| Prometheus metrics | Existing `/metrics` endpoint | New `defenseclaw_fleet_*` metric families |
| Connector matrix | New entry: `iot-lite` | Registered alongside claude-code, codex, cursor |
| MQTT broker | External (EMQX/Mosquitto) | Fleet manager subscribes; devices connect directly |

### With External Systems

| System | Protocol | Purpose |
|--------|----------|---------|
| EMQX/Mosquitto | MQTT 5.0 | Device↔Cloud messaging |
| Redis | TCP | Verdict cache persistence across gateway restarts |
| TimescaleDB | PostgreSQL | Audit event hypertable for time-series queries |
| Prometheus | HTTP /metrics | Fleet metrics scraping |
| Grafana | Prometheus datasource | Fleet dashboard (pre-built JSON) |

---

## Tradeoffs

| Decision | Chosen | Alternative | Rationale |
|----------|--------|-------------|-----------|
| Static allocation only | Yes | Dynamic malloc | Deterministic, no fragmentation, provable RAM budget |
| HMAC-SHA256 truncated to 4B for verdicts | 4 bytes | Full 32B HMAC | Bandwidth: 16B response fits single MQTT packet. Security: 2^32 forgery resistance at 60 req/min = 136 years |
| Policy tables compiled at build-time | C headers | Runtime interpreter | O(1) lookup in <1μs vs. interpreted Rego at ~1ms |
| Embedded fleet manager in gateway binary | Embedded | Separate microservice | Avoids deployment complexity; gateway is already 50MB |
| Redis for verdict cache persistence | Redis | SQLite | Sub-millisecond reads; gateway restart doesn't lose cache |
| EMQX as MQTT broker (external) | EMQX | Embedded broker | EMQX handles 200K+ connections; clustering; proven |

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
