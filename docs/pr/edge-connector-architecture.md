# Edge Connector — Architecture & How It Works

## Overview

The Edge Connector is DefenseClaw's security enforcement layer for AI agents running on constrained edge/IoT devices (ESP32, Raspberry Pi, Jetson Nano). It intercepts every AI agent tool call in real-time and makes an ALLOW/BLOCK/WARN/ESCALATE decision in microseconds, without requiring cloud connectivity.

The system has three tiers:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        OPERATOR LAYER                               │
│                                                                     │
│   defenseclaw CLI          Docs Site (MDX)         Grafana          │
│   ┌──────────────┐        ┌──────────────┐      ┌──────────┐      │
│   │ edge-connector│        │ install.mdx  │      │ Fleet    │      │
│   │ devices       │        │ policies.mdx │      │ Dashboard│      │
│   │ health        │        │ api-ref.mdx  │      │          │      │
│   │ policy push   │        │ arch.mdx     │      │          │      │
│   │ emergency     │        └──────────────┘      └──────────┘      │
│   └──────┬───────┘                                    ▲             │
│          │ HTTP                                       │ Prometheus  │
│          ▼                                            │             │
├──────────────────────────────────────────────────────────────────────┤
│                     FLEET MANAGEMENT LAYER (Go Gateway)             │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Gateway Sidecar                            │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │   │
│  │  │  Fleet API   │  │ Fleet Manager│  │  Policy Service   │  │   │
│  │  │ /api/v1/fleet│  │  (in-memory  │  │  (compile, sign,  │  │   │
│  │  │  12 endpoints│  │   + SQLite)  │  │   distribute)     │  │   │
│  │  └──────┬───────┘  └──────┬───────┘  └────────┬──────────┘  │   │
│  │         │                 │                    │              │   │
│  │  ┌──────▼─────────────────▼────────────────────▼──────────┐  │   │
│  │  │              MQTT Bridge                                │  │   │
│  │  │  ┌────────────┐ ┌─────────────┐ ┌───────────────────┐ │  │   │
│  │  │  │ Heartbeat  │ │  Verdict    │ │  Registration     │ │  │   │
│  │  │  │ Handler    │ │  Handler    │ │  Handler          │ │  │   │
│  │  │  │ (HMAC      │ │ (evaluate + │ │ (HMAC verify +    │ │  │   │
│  │  │  │  verify)   │ │  respond)   │ │  decommission chk)│ │  │   │
│  │  │  └────────────┘ └─────────────┘ └───────────────────┘ │  │   │
│  │  └────────────────────────┬───────────────────────────────┘  │   │
│  │                           │                                   │   │
│  │  ┌────────────────────────▼───────────────────────────────┐  │   │
│  │  │              Audit Pipeline (v8 Telemetry)              │  │   │
│  │  │  SQLite  │  Splunk HEC  │  OTLP  │  JSONL  │  Webhook │  │   │
│  │  └──────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                           │ MQTT 3.1.1 (TCP)                        │
│                           ▼                                         │
├─────────────────────────────────────────────────────────────────────┤
│                     MQTT BROKER (Mosquitto)                         │
│                           │                                         │
│         Topics:           │                                         │
│         defenseclaw/{tenant}/{fleet}/{device}/heartbeat              │
│         defenseclaw/{tenant}/{fleet}/{device}/verdict/req            │
│         defenseclaw/{tenant}/{fleet}/{device}/verdict/resp           │
│         defenseclaw/{tenant}/{fleet}/{device}/register               │
│         defenseclaw/{tenant}/{fleet}/ota/policy                      │
│         defenseclaw/{tenant}/{fleet}/ota/emergency                   │
│                           │                                         │
├───────────────────────────┼─────────────────────────────────────────┤
│                     EDGE DEVICE LAYER                               │
│                           │                                         │
│  ┌────────────────────────▼───────────────────────────────────────┐ │
│  │              C Edge Connector Daemon (~68KB)                    │ │
│  │                                                                 │ │
│  │  ┌─────────────┐   ┌──────────────────────────────────────┐   │ │
│  │  │  IPC Server  │   │        8-Stage Evaluation Pipeline   │   │ │
│  │  │  (Unix sock  │──▶│                                      │   │ │
│  │  │  JSON-RPC)   │   │  1. Emergency check (block_all?)    │   │ │
│  │  └─────────────┘   │  2. Input validation + hash binding  │   │ │
│  │        ▲            │  3. Rate limiting (3 token buckets)  │   │ │
│  │        │            │  4. Content scan (Aho-Corasick DFA)  │   │ │
│  │  ┌─────┴─────┐     │  5. SSRF check (private IP ranges)  │   │ │
│  │  │ AI Agent  │     │  6. Deny-list hash check             │   │ │
│  │  │ Framework │     │  7. Destination allow/deny            │   │ │
│  │  │           │     │  8. Sequence correlation              │   │ │
│  │  │ • Generic │     │  9. Verdict cache lookup              │   │ │
│  │  │ • LangChn │     │ 10. Cloud escalation (MQTT)           │   │ │
│  │  │ • MCP Prxy│     └──────────────────────────────────────┘   │ │
│  │  │ • PicoClaw│                                                 │ │
│  │  └───────────┘      ┌──────────────┐  ┌──────────────────┐   │ │
│  │                      │ MQTT Client  │  │  Flash Storage   │   │ │
│  │                      │ (heartbeat,  │  │  • Audit ring    │   │ │
│  │                      │  verdict req,│  │  • OTA policy    │   │ │
│  │                      │  OTA receive)│  │  • Config (A/B)  │   │ │
│  │                      └──────────────┘  │  • Emergency     │   │ │
│  │                                        └──────────────────┘   │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  Target hardware: ESP32-S3 | Raspberry Pi | Jetson Nano | Linux PC │
└─────────────────────────────────────────────────────────────────────┘
```

---

## How a Tool Call Flows Through the System

### Step 1: Agent Makes a Tool Call

An AI agent (running in any Python framework) calls a tool — for example, `fetch_url("https://api.openai.com/v1/chat")`.

```python
# Any framework — the hook intercepts before execution
from generic_hook import EdgeConnector

ec = EdgeConnector()  # auto-detects IPC or FFI
verdict = ec.evaluate("fetch_url", {"url": "https://api.openai.com/v1/chat"}, destination="api.openai.com")

if verdict.blocked:
    raise SecurityError(f"Tool call blocked: {verdict.reason}")
# else: proceed with tool execution
```

### Step 2: C Engine Evaluates (8 Logical Stages, <5μs target)

> **Stage count note:** The diagram below shows 10 implementation steps. These map to **8 logical stages**: (1) emergency check, (2) input validation + hash binding, (3) rate limiting, (4) content scanning + SSRF check, (5) hash deny-list, (6) destination control, (7) sequence correlation, (8) cloud escalation/cache. Steps 4-5 (content scan + SSRF) are grouped as one stage because both inspect the request payload; steps 9-10 (cache lookup + cloud escalation) are grouped as one stage because they handle the final disposition together.

```
                    Tool Request
                        │
                        ▼
            ┌───────────────────────┐
            │ 1. EMERGENCY CHECK    │──── block_all_active? ──▶ BLOCK
            └───────────┬───────────┘
                        ▼
            ┌───────────────────────┐
            │ 2. INPUT VALIDATION   │──── empty name?        ──▶ BLOCK
            │    + HASH BINDING     │──── SHA256(name)≠hash? ──▶ BLOCK
            └───────────┬───────────┘
                        ▼
            ┌───────────────────────┐
            │ 3. RATE LIMITING      │──── tokens exhausted?  ──▶ BLOCK
            │    (3 token buckets)  │    60/min tools
            │                       │    30/min network
            │                       │    10/min actuations
            └───────────┬───────────┘
                        ▼
            ┌───────────────────────┐
            │ 4. CONTENT SCAN       │──── secret/PII/cred    ──▶ BLOCK
            │    (Aho-Corasick DFA) │    detected?
            │    52 patterns        │
            │    324 DFA states     │
            └───────────┬───────────┘
                        ▼
            ┌───────────────────────┐
            │ 5. SSRF CHECK         │──── 169.254.x?         ──▶ BLOCK
            │    (private IP ranges)│    127.x? 10.x?
            │                       │    172.16.x? 192.168.x?
            └───────────┬───────────┘
                        ▼
            ┌───────────────────────┐
            │ 6. DENY-LIST HASH     │──── known-bad tool?    ──▶ BLOCK
            │    (binary search)    │
            └───────────┬───────────┘
                        ▼
            ┌───────────────────────┐
            │ 7. DESTINATION CHECK  │──── not in allowlist?  ──▶ BLOCK
            │    (allow/deny list)  │
            └───────────┬───────────┘
                        ▼
            ┌───────────────────────┐
            │ 8. SEQUENCE CORRELATE │──── NET_FETCH then     ──▶ BLOCK
            │    (per-session)      │    EXEC_SHELL?
            └───────────┬───────────┘
                        ▼
            ┌───────────────────────┐
            │ 9. VERDICT CACHE      │──── cached result?     ──▶ return it
            └───────────┬───────────┘
                        ▼
            ┌───────────────────────┐
            │ 10. CLOUD ESCALATION  │──── speculative cap?   ──▶ ALLOW (PENDING)
            │     (MQTT to fleet)   │──── sync_block cap?    ──▶ wait / BLOCK
            └───────────────────────┘
```

Each stage can short-circuit with BLOCK. If all pass, the tool call is ALLOWED (locally or pending cloud confirmation).

### Step 3: Heartbeat Reports Device Health

Every 30 seconds (STANDARD profile), the C daemon publishes a 32-byte CBOR heartbeat + 32-byte HMAC signature to the MQTT broker:

```
Heartbeat Wire Format (32 bytes, big-endian):
┌─────────┬─────────┬──────────┬──────────┬─────────┬─────────┐
│ bytes   │ 0-3     │ 4-7      │ 8-9      │ 10-11   │ 12-13   │
│ field   │device_id│uptime_sec│policy_ver│fw_ver   │denied   │
├─────────┼─────────┼──────────┼──────────┼─────────┼─────────┤
│ bytes   │ 14-15   │ 16-17    │ 18-19    │ 20-23   │ 24-27   │
│ field   │allowed  │warned    │escalated │flash_wr │reserved │
├─────────┼─────────┼──────────┼──────────┼─────────┼─────────┤
│ bytes   │ 28      │ 29       │ 30       │ 31      │         │
│ field   │cache_pct│sessions  │flags     │caps     │         │
└─────────┴─────────┴──────────┴──────────┴─────────┴─────────┘

+ 32-byte HMAC-SHA256 tag = 64 bytes total (signed heartbeat)
HMAC computed over: topic_string + payload[0:32]
```

**Flags byte (bit field):**
- `0x02` — SE (Secure Enclave) degraded
- `0x08` — Canary rollback occurred (one-shot, cleared after 3 successful sends)
- `0x20` — Firmware OK

### Step 4: Fleet Manager Processes Heartbeat

```
Signed Heartbeat (64 bytes)
        │
        ▼
┌───────────────────┐
│ Parse MQTT Topic   │ → Extract tenant_id, fleet_id, device_id
└────────┬──────────┘
         ▼
┌───────────────────┐
│ Decommission Check │ → Is device decommissioned? → REJECT
└────────┬──────────┘
         ▼
┌───────────────────┐
│ Decode Heartbeat   │ → 32-byte (unsigned) or 64-byte (signed)?
└────────┬──────────┘
         ▼
┌───────────────────┐
│ Topic/Payload ID   │ → device_id in topic ≠ payload? → REJECT
│ Cross-check        │
└────────┬──────────┘
         ▼
┌───────────────────┐
│ HMAC Verification  │ → HMAC(device_key, topic + payload[0:32])
│                    │ → Signed + keyed device: verify HMAC
│                    │ → Signed + wrong key: REJECT
│                    │ → Unsigned + keyed device: REJECT
│                    │ → Unsigned + no key: accept (legacy)
└────────┬──────────┘
         ▼
┌───────────────────┐
│ Replay Detection   │ → uptime ≤ last_uptime? → REJECT (replay)
│                    │ → uptime < last (reboot)? → reset counters
└────────┬──────────┘
         ▼
┌───────────────────┐
│ Counter Delta      │ → denied_total += (new_denied - prev_denied)
│ Computation        │ → allowed_total += (new_allowed - prev_allowed)
│                    │ → warned_total, escalated_total (same logic)
└────────┬──────────┘
         ▼
┌───────────────────┐
│ Anomaly Detection  │ → Tamper detect (capabilities changed)?
│                    │ → SE degraded (flag 0x02)?
│                    │ → Canary rollback (flag 0x08)?
│                    │ → Block spike?
└────────┬──────────┘
         ▼
┌───────────────────┐
│ Persist to SQLite  │ → Update device record with new state
│ + Fire Metrics     │ → Prometheus gauges/counters updated
│ + Fire Alerts      │ → Alert → Audit pipeline → SQLite/Splunk/OTLP/Webhooks
└───────────────────┘
```

### Step 5: OTA Policy Update

```
Operator                  Gateway                    Edge Device
   │                         │                           │
   │  defenseclaw            │                           │
   │  edge-connector         │                           │
   │  policy push            │                           │
   │  strict.yaml            │                           │
   │ ────────────────────▶   │                           │
   │                         │                           │
   │                    ┌────▼────────────────┐          │
   │                    │ Policy Compiler      │          │
   │                    │ (Python)             │          │
   │                    │                      │          │
   │                    │ YAML → binary blob:  │          │
   │                    │ ┌──────────────────┐ │          │
   │                    │ │Header (8 bytes)  │ │          │
   │                    │ │ version(2)       │ │          │
   │                    │ │ payload_len(2)   │ │          │
   │                    │ │ canary_base(2)   │ │          │
   │                    │ │ reserved(2)      │ │          │
   │                    │ ├──────────────────┤ │          │
   │                    │ │Bitmask (1 byte)  │ │          │
   │                    │ │ 0x87 = all       │ │          │
   │                    │ │ sections present │ │          │
   │                    │ ├──────────────────┤ │          │
   │                    │ │Severity rules    │ │          │
   │                    │ │Sequence rules    │ │          │
   │                    │ │Dest allowlist    │ │          │
   │                    │ │Content rules     │ │          │
   │                    │ │SSRF flags        │ │          │
   │                    │ └──────────────────┘ │          │
   │                    │                      │          │
   │                    │ + HMAC-SHA256 sign   │          │
   │                    └────┬────────────────┘          │
   │                         │                           │
   │                    ┌────▼────────────────┐          │
   │                    │ MQTT Publish         │          │
   │                    │ Topic: defenseclaw/  │          │
   │                    │ {t}/{f}/ota/policy   │          │
   │                    └────┬────────────────┘          │
   │                         │         MQTT              │
   │                         │ ─────────────────────▶    │
   │                         │                      ┌────▼──────────┐
   │                         │                      │ OTA Receiver  │
   │                         │                      │               │
   │                         │                      │ 1. Verify sig │
   │                         │                      │ 2. Anti-      │
   │                         │                      │    rollback   │
   │                         │                      │    (v≤current │
   │                         │                      │    → reject)  │
   │                         │                      │ 3. Parse      │
   │                         │                      │    bitmask    │
   │                         │                      │ 4. Apply to   │
   │                         │                      │    runtime    │
   │                         │                      │    tables     │
   │                         │                      │ 5. Persist to │
   │                         │                      │    flash (A/B)│
   │                         │                      │ 6. Atomic     │
   │                         │                      │    version +  │
   │                         │                      │    partition  │
   │                         │                      │    write      │
   │                         │                      └───────────────┘
```

---

## Build Profiles

```
                    MINIMAL              STANDARD             EDGE
                   (ESP32-S3)          (Raspberry Pi)       (Jetson Nano)
                  ┌──────────┐        ┌──────────────┐     ┌──────────────┐
Binary size       │   ~79KB  │        │    ~265KB    │     │    ~265KB    │
                  ├──────────┤        ├──────────────┤     ├──────────────┤
MQTT              │    OFF   │        │      ON      │     │      ON      │
Speculative exec  │    OFF   │        │      ON      │     │      ON      │
Content scan      │    OFF   │        │      ON      │     │      ON      │
Verdict cache     │    0     │        │      64      │     │     256      │
Audit ring        │    64    │        │     256      │     │    1024      │
Max sessions      │    4     │        │      16      │     │      64      │
                  └──────────┘        └──────────────┘     └──────────────┘

MINIMAL: Standalone enforcement, no cloud. Everything decided locally.
STANDARD: Cloud-connected with speculative execution for low-risk tools.
EDGE: High-throughput with large caches for AI inference accelerators.
```

---

## Security Model

```
┌─────────────────────────────────────────────────────────┐
│                    DEVICE IDENTITY                       │
│                                                         │
│  Registration: POST /api/v1/fleet/devices               │
│  → Generates 32-byte random per-device HMAC key         │
│  → Key returned ONCE (not retrievable later)            │
│  → Stored in gateway SQLite (device_keys table)         │
│  → Provisioned on device via DCLAW_DEVICE_KEY env var   │
│                                                         │
│  Heartbeat HMAC: HMAC-SHA256(device_key, topic+payload) │
│  → Topic binding prevents cross-topic replay            │
│  → Per-device key prevents fleet-wide key compromise    │
│  → Keyed devices REJECT unsigned heartbeats             │
│  → Key-store errors → REJECT (fail-closed)              │
│                                                         │
│  Verdict HMAC: HMAC-SHA256(device_key, all_fields)      │
│  → Covers action, reason, severity, ttl, flags, ts,     │
│    request_id, full 32-byte tool_hash                   │
│  → 4-byte truncated tag (constrained device tradeoff)   │
│                                                         │
│  OTA Signature: Ed25519 (or HMAC-SHA256 fallback)       │
│  → Anti-rollback: version must be > current             │
│  → Crash-safe: CRC16 double-write for config records    │
│                                                         │
│  Audit HMAC: HMAC-SHA256(audit_key, entry)              │
│  → Chained: each entry's HMAC includes prev entry's tag │
│  → Production requires DCLAW_AUDIT_KEY (non-zero)       │
│  → Head position + prev HMAC persisted to flash         │
│                                                         │
│  Decommission: API removes device + deletes key +       │
│  bridge marks decommissioned → all MQTT paths rejected  │
└─────────────────────────────────────────────────────────┘
```

---

## Flash Persistence Layout

```
Flash file (DCLAW_FLASH_PATH):
┌──────────────────────────────────────────────────────┐
│ Config Record A (8 bytes)                             │
│  [magic_0=0xDC][magic_1=0xAB][partition][reserved]   │
│  [version_hi][version_lo][crc16_hi][crc16_lo]        │
├──────────────────────────────────────────────────────┤
│ Config Record B (backup copy, 8 bytes)                │
│  (identical format, validated on load if A corrupt)   │
├──────────────────────────────────────────────────────┤
│ Audit Ring Header (8 bytes)                           │
│  [magic_0=0xDC][magic_1=0xE9][head_hi][head_lo]     │
│  [prev_hmac_0][prev_hmac_1][prev_hmac_2][prev_hmac_3]│
├──────────────────────────────────────────────────────┤
│ Audit Ring Entries (24 bytes each × ring_size)        │
│  [timestamp(8)][target_hash(2)][session_id(2)]       │
│  [hmac(4)][action(1)][reason(1)][pad(6)]             │
├──────────────────────────────────────────────────────┤
│ Policy Partition A (variable size)                     │
│  [OTA header(8) + bitmask + section data]             │
├──────────────────────────────────────────────────────┤
│ Policy Partition B (variable size)                     │
│  [OTA header(8) + bitmask + section data]             │
├──────────────────────────────────────────────────────┤
│ Emergency State (4 bytes)                             │
│  [magic_0=0xDC][magic_1=0xE9]                        │
│  [block_all_active(1)][last_seen_seq(1)]             │
└──────────────────────────────────────────────────────┘
```

---

## Python Framework Integration

```
┌───────────────────────────────────────────────────────────┐
│                 AI Agent Frameworks                        │
│                                                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │  LangChain   │  │   MCP       │  │  HTTP Middleware │  │
│  │  Agent       │  │   Server    │  │  (FastAPI/Flask) │  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │
│         │                │                    │           │
│  ┌──────▼──────┐  ┌──────▼──────┐  ┌────────▼────────┐  │
│  │ langchain   │  │ mcp_proxy   │  │ http_middleware  │  │
│  │ _hook.py    │  │ .py         │  │ .py             │  │
│  │             │  │ (transparent│  │ (WSGI/ASGI      │  │
│  │ BaseTool    │  │  MCP proxy) │  │  middleware)     │  │
│  │ subclass    │  │             │  │                  │  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │
│         │                │                    │           │
│         └────────────────┼────────────────────┘           │
│                          │                                │
│                   ┌──────▼──────┐                         │
│                   │ generic_hook│                         │
│                   │ .py         │                         │
│                   │             │                         │
│                   │ EdgeConnect │                         │
│                   │ or class    │                         │
│                   │             │                         │
│                   │ Backend:    │                         │
│                   │ IPC preferred│                        │
│                   │ FFI fallback│                         │
│                   └──────┬──────┘                         │
│                          │                                │
│              ┌───────────┴───────────┐                    │
│              │                       │                    │
│       ┌──────▼──────┐        ┌──────▼──────┐             │
│       │ IPC Backend │        │ FFI Backend │             │
│       │ (Unix sock  │        │ (ctypes     │             │
│       │  JSON-RPC)  │        │  libdclaw)  │             │
│       └──────┬──────┘        └──────┬──────┘             │
│              │                       │                    │
│              ▼                       ▼                    │
│     C Daemon (main.c)      libdclaw_core.dylib           │
│     via /tmp/defenseclaw   (in-process evaluation)       │
│     .sock                                                 │
└───────────────────────────────────────────────────────────┘
```

---

## Emergency & Lockdown Flow

```
Operator: defenseclaw edge-connector policy emergency block-all

    │
    ▼
POST /api/v1/fleet/policy/emergency
    {"tenant_id":1, "fleet_id":1, "command":"block_all"}
    │
    ▼
Policy Service → MQTT publish to defenseclaw/1/1/ota/emergency
    │
    ▼
Edge Device: dclaw_apply_emergency()
    │
    ├── BLOCK_ALL (0x01): g_state.emergency.block_all_active = true
    │                     → ALL tool calls immediately BLOCK
    │                     → Persists to flash (survives restart)
    │
    ├── ENTER_LOCKDOWN (0x02): Sets lockdown status
    │
    ├── REVOKE_SESSIONS (0x04): Clears all session state
    │
    ├── RELEASE_LOCKDOWN (0x05): Clears block_all_active
    │                            → Persists cleared state to flash
    │                            → Normal evaluation resumes
    │
    └── FORCE_SYNC (0x03): Flushes audit ring to flash
```

---

## Metrics & Observability

```
Prometheus Metrics (GET /api/v1/fleet/metrics):

  defenseclaw_fleet_devices_total{status="online|offline|degraded|lockdown"}
  defenseclaw_fleet_heartbeats_received_total
  defenseclaw_fleet_blocks_total
  defenseclaw_fleet_alerts_total
  defenseclaw_fleet_ota_rollbacks_total
  defenseclaw_fleet_registrations_total
  defenseclaw_fleet_verdict_cache_size
  defenseclaw_fleet_verdict_cache_hits_total
  defenseclaw_fleet_verdict_cache_misses_total

Audit Events (SQLite + Splunk + OTLP):

  fleet.device.registered    → asset.lifecycle bucket
  fleet.device.decommission  → asset.lifecycle bucket
  fleet.device.command       → enforcement.action bucket
  fleet.policy.push          → compliance.activity bucket
  fleet.policy.emergency     → compliance.activity bucket
  fleet.threat_intel.push    → compliance.activity bucket
  fleet.alert                → security.finding bucket
  fleet.device.heartbeat     → platform.health bucket
  fleet.device.offline       → platform.health bucket
```
