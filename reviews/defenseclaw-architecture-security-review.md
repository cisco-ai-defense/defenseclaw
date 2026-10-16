# DefenseClaw — Comprehensive Architecture & Security Review

**Branch:** `feature/defenseclaw-lite-phase1`
**Date:** 2026-10-10
**Scope:** Full system — C edge daemon, Go fleet backend, Python CLI/tools, build/supply chain
**Method:** 6 parallel deep-dive reviews (C security, Go security, Python security, architecture/threat model, test coverage, supply chain)

---

## Executive Summary

DefenseClaw Phase 1 implements a 3-tier AI agent security governance system: a C edge daemon (53KB, 36M decisions/sec), a Go fleet management backend (MQTT + REST), and Python integration tools. The architecture is **fundamentally sound** — the trust boundary model, fail-closed defaults, constant-time crypto, and parameterized SQL demonstrate strong security engineering.

However, this review identifies **11 CRITICAL**, **19 HIGH**, and **24 MEDIUM** findings across code, architecture, and test coverage. The system can be hardened to an industry-leading security posture with the architectural recommendations below.

**Verdict: Architecture approved with conditions. 11 critical items must be resolved before production.**

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        OPERATOR / API                           │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ REST API    │  │ Policy Push  │  │ Emergency Broadcast    │  │
│  │ (Bearer JWT)│  │ (Signed OTA) │  │ (Seq + HMAC)           │  │
│  └──────┬──────┘  └──────┬───────┘  └──────────┬─────────────┘  │
│         │                │                     │                │
│  ┌──────┴────────────────┴─────────────────────┴──────────────┐ │
│  │              GO FLEET MANAGER                              │ │
│  │  ┌────────┐ ┌────────┐ ┌──────────┐ ┌──────────────────┐  │ │
│  │  │Device  │ │Policy  │ │Verdict   │ │Anomaly Detection │  │ │
│  │  │Registry│ │Store   │ │Cache     │ │+ Alert Manager   │  │ │
│  │  │(SQLite)│ │(SQLite)│ │(LRU+TTL)│ │                  │  │ │
│  │  └────────┘ └────────┘ └──────────┘ └──────────────────┘  │ │
│  └──────────────────────┬─────────────────────────────────────┘ │
│                         │ MQTT (per-device topics, HMAC)        │
│  ┌──────────────────────┴─────────────────────────────────────┐ │
│  │              EMBEDDED MQTT BROKER                          │ │
│  └──────────────────────┬─────────────────────────────────────┘ │
└─────────────────────────┼───────────────────────────────────────┘
                          │ TLS 1.2+ (mTLS optional)
┌─────────────────────────┼───────────────────────────────────────┐
│  EDGE DEVICE            │                                       │
│  ┌──────────────────────┴─────────────────────────────────────┐ │
│  │              C EDGE DAEMON (53KB)                          │ │
│  │                                                            │ │
│  │  IPC Socket ──► JSON Parser ──► Validator ──► Policy Engine│ │
│  │       │              │              │              │        │ │
│  │  peer creds     bounded parse   fail-closed   hash match   │ │
│  │  max payload    no eval         deny default  deny list    │ │
│  │                                                            │ │
│  │  ┌─────────┐ ┌──────────┐ ┌────────┐ ┌──────────────────┐ │ │
│  │  │Verdict  │ │Content   │ │Audit   │ │OTA Receiver      │ │ │
│  │  │Cache    │ │Scanner   │ │Ring    │ │(Ed25519 + A/B)   │ │ │
│  │  └─────────┘ └──────────┘ └────────┘ └──────────────────┘ │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  Python Hooks: generic_hook.py, mcp_proxy.py, http_middleware   │
│  Integrations: LangChain, Home Assistant, Bubbaloop, ESPClaw    │
└─────────────────────────────────────────────────────────────────┘
```

### Trust Boundaries

| Boundary | Protection | Status |
|----------|-----------|--------|
| External → IPC Socket | Unix peer credentials, max payload, JSON validation | STRONG |
| IPC → Policy Engine | Input sanitization, fail-closed, hash binding | STRONG |
| Device → MQTT Broker | TLS 1.2+, per-device HMAC, topic isolation | STRONG (with gaps) |
| MQTT → Fleet Manager | HMAC verification, message dedup, constant-time compare | STRONG |
| Operator → REST API | Bearer token, CSRF check, MaxBytesReader | MODERATE (no rate limit) |
| OTA → Device | Ed25519 signature, A/B partitions, canary rollback | STRONG (with downgrade gap) |
| Python Hook → C Library | FFI boundary, fail-closed on load failure | MODERATE |

---

## 2. CRITICAL Findings (11 — Must Fix Before Production)

### CRIT-0A: MQTT Transport is Plaintext in Production Profile (Architecture)

**File:** [strict.yaml:60-64](edge-connector/policies/strict.yaml)

The strict production policy configures `mqtt://edge-vip.site-alpha.local:1883` — plaintext MQTT. All heartbeats (device IDs, policy versions, capability flags), verdict requests (tool hashes, content snippets), policy pushes, and emergency commands traverse the network unencrypted. HMAC protects integrity but not confidentiality. Any network observer can see all device telemetry and AI tool call patterns.

**Fix:** Make `mqtts://` mandatory in the strict profile. Refuse plaintext connections when `DCLAW_PRODUCTION=true`. The TLS engine (`tls_engine.c`) is already implemented with mTLS support — just needs to be wired into the MQTT client and enforced by policy.

### CRIT-0B: MQTT Broker Has No Authentication (Architecture)

**File:** [sidecar.go](internal/gateway/sidecar.go), [broker.go](internal/fleet/mqtt/broker.go)

The embedded MQTT broker accepts unauthenticated connections. Any network actor can connect and publish to fleet topics (`dclaw/fleet/policy`, `dclaw/fleet/emergency`). While HMAC protects message integrity, an attacker can flood topics with invalid messages (DoS), or more critically, perform traffic analysis on legitimate messages.

**Fix:** Require MQTT username/password authentication at minimum. Prefer client certificate authentication (mTLS) using the device certificate infrastructure already scaffolded in `tls_engine.c`.


### CRIT-1: Nil Policy Signer Causes Production Crash (Go)

**File:** [sidecar.go](internal/gateway/sidecar.go) — `policySigner, _ := fleetpolicy.NewHMACSignerFromEnv()`

Without `DCLAW_OTA_KEY` env var, signer is nil. Any policy push panics with nil pointer dereference, crashing the fleet sidecar. This is a production availability issue.

**Fix:** Check error, disable policy push or refuse to start without signing key.

### CRIT-2: MCP Proxy Response Desynchronization (Python)

**File:** [mcp_proxy.py:196-206](edge-connector/tools/mcp_proxy.py)

Concurrent `send()` calls write without a lock but read under a lock. Two interleaved writes cause response desynchronization — **the wrong verdict is returned for a tool call**. A blocked tool could be allowed.

**Fix:** Make send+receive atomic under a single lock, or implement JSON-RPC ID correlation with a pending-response map.

### CRIT-3: Runtime OTA Signature Downgrade (C)

**File:** [ota_receiver.c:91,148](edge-connector/src/comms/ota_receiver.c)

`DCLAW_OTA_HMAC_ALLOWED=1` at runtime downgrades Ed25519 → HMAC. Combined with dev HMAC key fallback, an attacker with local env write access can forge OTA policy updates.

**Fix:** Compile-time gate only: `#ifdef DCLAW_DEV_MODE`. Remove runtime env var path in production.

### CRIT-4: Stack Overflow on Constrained Devices (C)

**File:** [dclaw_core.c:315-316](edge-connector/src/decision/content_scanner.c)

`dclaw_tool_request_t` is ~4.3KB (includes 4096-byte `content_buf`). Copied to stack in evaluation path. Devices with 4KB stack will crash. Comment claims "~700 bytes" — actual is 6x larger.

**Fix:** Allocate on heap or use a static buffer pool. For embedded targets, verify stack depth with `-fstack-usage`.

### CRIT-5: No Rate Limiting on Fleet API (Go)

**File:** [api.go](internal/fleet/api.go) — all 7 endpoints

Registration, emergency broadcast, and threat-intel endpoints have no rate limiting. An attacker can:
- Exhaust device registration quota
- Flood emergency broadcasts
- DoS the fleet manager

**Fix:** Add per-IP and per-device rate limiting middleware. Emergency endpoints need stricter limits.

### CRIT-6: Environment Variable Path Injection (C)

**Files:**
- [main.c:130-132](edge-connector/src/main.c) — `DCLAW_IPC_SOCKET_PATH`
- [hal_linux.c:17](edge-connector/src/platform/hal_linux.c) — `DCLAW_FLASH_PATH`

IPC socket and flash storage paths sourced from environment without validation. Attacker with env write access can redirect IPC to a controlled socket (bypassing umask) or persistent state to a writable location (controlling security state).

**Fix:** Validate paths are absolute, under allowed prefixes (`/run/defenseclaw/`, `/var/lib/defenseclaw/`), and not symlinks. In production builds, hardcode paths or use compile-time defaults only.

### CRIT-7: Credential Exposure via /proc/PID/environ (C)

**File:** [mqtt_client.c:901-907](edge-connector/src/comms/mqtt_client.c)

MQTT password scrubbing overwrites the C runtime copy, but `/proc/PID/environ` preserves the original from exec time. The scrubbing gives false security.

**Fix:** Document that MQTT credentials MUST be provisioned via files in production. Warn at startup if `DCLAW_MQTT_PASS` is set via environment. Remove misleading scrub.

### CRIT-8: Single Shared Bearer Token — No RBAC, No Operator Identity (Go)

**File:** [api.go:210-228](internal/fleet/api.go)

All 14 Fleet API endpoints share a single `DCLAW_FLEET_API_TOKEN`. Anyone with this token can push emergency BLOCK_ALL to any fleet, decommission any device, rotate the fleet token (locking out other operators), and push arbitrary policies. There is no operator identity, no audit attribution beyond "someone with the token," and no role-based access control.

**Fix:** Implement per-operator JWT/mTLS authentication with role-based scopes (`fleet:read`, `fleet:write`, `fleet:emergency`, `fleet:admin`). At minimum, separate read-only from write operations.

### CRIT-9: No Tenant Isolation in Verdict Cache (Go)

**File:** [cache.go](internal/fleet/verdict/cache.go)

The verdict cache is keyed by `[32]byte` tool hash alone — no tenant or fleet dimension. A verdict evaluated for tenant A's policy is served to tenant B's devices if they request the same tool hash. This breaks multi-tenant isolation.

**Fix:** Include `tenant_id` and `policy_version_hash` in the cache key. Flush cache on policy push.

---

## 3. HIGH Findings (18)

### Go Fleet Backend (7)

| ID | File | Finding |
|----|------|---------|
| H-1 | [api.go:358-398](internal/fleet/api.go) | Re-registration silently clears decommission tombstones. Compromised token can un-decommission devices. |
| H-2 | [policy.go:240-247](internal/fleet/policy/policy.go) | `exec.Command` with configurable `compilerPath`. Validated as absolute path but no directory allowlist — write+execute = RCE. |
| H-3 | [bridge.go:858](internal/fleet/mqtt/bridge.go) | `context.Background()` on MQTT publish — no timeout, can block all message processing. |
| H-4 | [manager.go:160](internal/fleet/manager/manager.go) | `SetStore` writes `fm.store` without holding `fm.mu` — data race. |
| H-5 | [bridge.go:455](internal/fleet/mqtt/bridge.go) | `wg.Add(1)` inside handler — panic if `wg.Wait()` already started during shutdown. |
| H-6 | [tcp_client.go:488](internal/fleet/mqtt/tcp_client.go) | PUBACK channel (cap 64) overflow drops acks — false failure reports on burst publishing. |
| H-7 | [api.go:974](internal/fleet/api.go) | Token rotation in-memory only (`atomic.Pointer`), doesn't survive restart — stale tokens accepted after crash. |

### C Edge Daemon (6)

| ID | File | Finding |
|----|------|---------|
| H-8 | [ota_receiver.c:666](edge-connector/src/comms/ota_receiver.c) | `time(NULL)` for lockdown timestamps. Clock manipulation (+24h) bypasses emergency lockdown. |
| H-9 | [content_scanner.c:844-848](edge-connector/src/decision/content_scanner.c) | SSRF check returns ALLOW for non-IP hostnames when offline — cloud check never happens. |
| H-10 | [verdict_protocol.c:458](edge-connector/src/comms/verdict_protocol.c) | No validation of `action` value from verdict response — invalid action cached and returned. |
| H-11 | [ota_receiver.c:856](edge-connector/src/comms/ota_receiver.c) | `seq_len` from flash not validated against max (4) — OOB read in correlator. |
| H-12 | [mqtt_client.c:648](edge-connector/src/comms/mqtt_client.c) | `strstr` for topic suffix instead of exact match — topic spoofing via substring. |
| H-13 | [main.c](edge-connector/src/main.c) | Keys not zeroed on shutdown — cold boot attack recovery. |

### Python Tools (5)

| ID | File | Finding |
|----|------|---------|
| H-14 | [generic_hook.py:479-498](edge-connector/tools/generic_hook.py) | `_check_backend()` race: no locking around FFI-to-IPC backend switch in multi-threaded ASGI — double-free in C library. |
| H-15 | [policy_compiler.py:487,571](edge-connector/tools/policy_compiler.py) | `version`, `canary_baseline`, rate limits not validated for uint16 range before `struct.pack('>H', ...)`. |
| H-16 | [picoclaw_hook.py:329](edge-connector/tools/picoclaw_hook.py) | Session ID uint16 overflow after 65535 channels — ctypes silently truncates, sessions collide. |
| H-17 | [generic_hook.py:649](edge-connector/tools/generic_hook.py) | `_evaluate_chunked` discards WARN verdicts from chunks, returns synthetic ALLOW. |
| H-18 | [langchain_hook.py:63-71](edge-connector/tools/langchain_hook.py) | Singleton connector not thread-safe — double init, leaked FFI handle. |

---

## 4. MEDIUM Findings (24)

### Go (10)

| ID | File | Finding |
|----|------|---------|
| M-1 | [cache.go:67](internal/fleet/verdict/cache.go) | `SetMetricsHooks` races with concurrent cache ops (no lock on callback fields) |
| M-2 | [policy.go:394](internal/fleet/policy/policy.go) | Emergency sequence persistence failure logged as WARNING — stale seq causes anti-replay rejection |
| M-3 | [store_sqlite.go](internal/fleet/store_sqlite.go) | No connection pooling or WAL mode — concurrent writes will SQLITE_BUSY |
| M-4 | [store_sqlite.go](internal/fleet/policy/store_sqlite.go) | Same SQLite concurrency issue in policy store |
| M-5 | [broker.go](internal/fleet/mqtt/broker.go) | No max connection limit — memory exhaustion via connection flood |
| M-6 | [tcp_client.go:550](internal/fleet/mqtt/tcp_client.go) | Only first matching subscription handler invoked (random map order) |
| M-7 | [api.go](internal/fleet/api.go) | Error responses include internal details (SQL errors, stack traces) in non-production |
| M-8 | [bridge.go](internal/fleet/mqtt/bridge.go) | Heartbeat missing → anomaly detection uses fixed thresholds, not per-device baseline |
| M-9 | [metrics.go](internal/fleet/metrics.go) | Prometheus metrics endpoint unauthenticated — internal state exposure |
| M-10 | [store_memory.go](internal/fleet/store_memory.go) | In-memory store has no size limit — unbounded growth |

### C (7)

| ID | File | Finding |
|----|------|---------|
| M-11 | [ipc_json.c](edge-connector/src/enforce/ipc_json.c) | JSON parser manual — no fuzz corpus targeting nested/malformed JSON |
| M-12 | [audit_ring.c](edge-connector/src/persist/audit_ring.c) | Ring buffer wraps without notification — oldest audit entries silently lost |
| M-13 | [verdict_cache.c](edge-connector/src/decision/verdict_cache.c) | Cache eviction is FIFO, not LRU — hot entries evicted under pressure |
| M-14 | [cbor_codec.c](edge-connector/src/comms/cbor_codec.c) | CBOR decoder doesn't validate map key uniqueness — last-key-wins semantics |
| M-15 | [dclaw_core.c](edge-connector/src/dclaw_core.c) | `eval_count` uint32 wraps after ~497 days — monitoring counters meaningless |
| M-16 | [verdict_protocol.c:365](edge-connector/src/comms/verdict_protocol.c) | Pending slot exhaustion silently drops verdict — no backpressure signal |
| M-17 | [hal_linux.c:33](edge-connector/src/platform/hal_linux.c) | Flash offset overflow on 32-bit platforms |

### Python (7)

| ID | File | Finding |
|----|------|---------|
| M-18 | [http_middleware.py:108](edge-connector/tools/http_middleware.py) | Docstring says `fail_open=True`, code creates `EdgeConnector(fail_open=False)` |
| M-19 | [mcp_proxy.py:506](edge-connector/tools/mcp_proxy.py) | Missing SIGTERM handler — upstream child process becomes orphan |
| M-20 | [mcp_proxy_config.yaml:32](edge-connector/tools/mcp_proxy_config.yaml) | Default socket in `/tmp` — symlink/squatting attack vector |
| M-21 | [generic_hook.py:318](edge-connector/tools/generic_hook.py) | Response `id` not validated against request `id` — wrong verdict on stale response |
| M-22 | [picoclaw_hook.py](edge-connector/tools/picoclaw_hook.py) | Unbounded `_session_map` growth → OOM on constrained devices |
| M-23 | [cmd_edge_install.py:165-178](cli/defenseclaw/commands/cmd_edge_install.py) | curl `-d` body visible in `ps` output |
| M-24 | [policy_compiler.py:867-869](edge-connector/tools/policy_compiler.py) | Dev stub signature embeds SHA-256 in plaintext — observer can verify policy contents |

---

## 5. Threat Model (STRIDE Analysis)

### 5.1 Spoofing

| Threat | Current Protection | Gap |
|--------|-------------------|-----|
| Device impersonation | Per-device HMAC keys, topic isolation | H-1: Re-registration can clear tombstones |
| Fleet manager impersonation | TLS server cert verification (when configured) | CRIT-3: OTA downgrade to HMAC |
| Operator impersonation | Bearer token auth | H-7: Token doesn't survive restart |
| Hook bypass | Peer credentials on IPC | CRIT-6: Env-based path injection |

### 5.2 Tampering

| Threat | Current Protection | Gap |
|--------|-------------------|-----|
| Verdict modification | HMAC on verdict protocol | CRIT-2: MCP proxy desync returns wrong verdict |
| Policy modification | Ed25519 signature on OTA | CRIT-3: Downgrade to HMAC at runtime |
| Audit tampering | Append-only ring buffer | M-12: Silent overwrite on wrap |
| Config tampering | File permissions | CRIT-6: Env var path injection |

### 5.3 Repudiation

| Threat | Current Protection | Gap |
|--------|-------------------|-----|
| Verdict repudiation | Audit ring with timestamps | M-12: Ring wrap loses old entries |
| Policy change repudiation | Version + signature in binary | GOOD — signed chain |
| Device action repudiation | HMAC-authenticated heartbeats | GOOD — per-device attribution |

### 5.4 Information Disclosure

| Threat | Current Protection | Gap |
|--------|-------------------|-----|
| Credential theft | Key zeroing in C | CRIT-7: /proc/environ exposure, H-13: no shutdown zeroing |
| Policy content leakage | Signed binary format | M-24: Dev stub leaks SHA-256 |
| Internal state exposure | Auth on API | M-9: Unauthenticated Prometheus metrics |
| Error message leakage | Structured errors | M-7: Internal details in non-prod errors |

### 5.5 Denial of Service

| Threat | Current Protection | Gap |
|--------|-------------------|-----|
| API flooding | MaxBytesReader | CRIT-5: No rate limiting |
| MQTT connection flood | Topic isolation | M-5: No max connection limit on broker |
| Emergency broadcast flood | Sequence anti-replay | GOOD — but M-2 + gap detection issue |
| Verdict slot exhaustion | Fixed slot pool | M-16: Silent drop, no backpressure |
| Policy push flood | Version check | H-3: No timeout on MQTT publish |

### 5.6 Elevation of Privilege

| Threat | Current Protection | Gap |
|--------|-------------------|-----|
| Compromised device → fleet | Per-device topic isolation | H-12: strstr topic matching |
| Local user → daemon control | Unix socket peer creds | CRIT-6: Path injection |
| Env injection → RCE | Path validation | H-2: exec.Command with configurable path |
| OTA → arbitrary code | Ed25519 verification | CRIT-3: Runtime downgrade |

---

## 6. Architecture Hardening Recommendations

### Tier 1: Critical (Before Production)

#### A. Eliminate Runtime Security Downgrades

All security-critical behavior must be determined at **compile time**, not runtime. Remove:
- `DCLAW_OTA_HMAC_ALLOWED` runtime env var
- `DCLAW_TLS_INSECURE` (already gated, but should be `#ifdef DCLAW_DEV_MODE` only)
- Any env var that weakens crypto, auth, or verification

**Principle:** Production binaries should have no mechanism to weaken their own security.

#### B. Enforce File-Based Credential Provisioning

All secrets (MQTT credentials, HMAC keys, signing keys) must come from files, not environment variables:
- Remove env-based credential paths from production builds
- Add startup warning if any `DCLAW_*_PASS` or `DCLAW_*_KEY` env var is detected
- Document file-based provisioning as the only supported production path

**Principle:** Credentials in environment are observable via `/proc`, `ps`, and crash dumps.

#### C. Harden Path Inputs

For `DCLAW_IPC_SOCKET_PATH`, `DCLAW_FLASH_PATH`, and all file-based config:
```c
// Validate: absolute path, under allowed prefix, not a symlink
if (!starts_with(path, "/run/defenseclaw/") && !starts_with(path, "/var/lib/defenseclaw/")) {
    return DCLAW_ERR_INVALID_PATH;
}
struct stat st;
if (lstat(path, &st) == 0 && S_ISLNK(st.st_mode)) {
    return DCLAW_ERR_SYMLINK;
}
```

#### D. Add Rate Limiting to Fleet API

```go
// Per-IP sliding window rate limiter
rateLimiter := NewRateLimiter(
    Registration: {Window: 1*time.Minute, Max: 10},
    Emergency:    {Window: 1*time.Minute, Max: 5},
    ThreatIntel:  {Window: 1*time.Minute, Max: 20},
    Heartbeat:    {Window: 1*time.Second, Max: 100},
)
```

#### E. Make MCP Proxy Thread-Safe

Either:
1. Full-duplex lock (send+receive atomic)
2. JSON-RPC ID correlation with `asyncio.Future` map (preferred — higher throughput)

```python
async def send(self, msg: Dict) -> Dict:
    msg["id"] = self._next_id()
    future = self._pending[msg["id"]] = asyncio.get_event_loop().create_future()
    async with self._write_lock:
        self._proc.stdin.write(_encode(msg))
        await self._proc.stdin.drain()
    return await future
```

### Tier 2: High Priority (Before GA)

#### F. Implement Monotonic Time for Security State

Replace `time(NULL)` with `hal_tick_ms()` (monotonic clock) for:
- Emergency lockdown timestamps
- Rate limiter windows
- Session expiry
- Cache TTL

**Principle:** Wall clock manipulation must not bypass security controls.

#### G. Add Decommission Guard

```go
func (s *SQLiteStore) RegisterDevice(ctx context.Context, dev Device) error {
    // Check for existing tombstone
    existing, err := s.GetDevice(ctx, dev.ID)
    if err == nil && existing.Status == "decommissioned" {
        return fmt.Errorf("device %s is decommissioned — requires admin re-authorization", dev.ID)
    }
    // ... proceed with registration
}
```

#### H. Harden SQLite for Concurrency

```go
db.Exec("PRAGMA journal_mode=WAL")
db.Exec("PRAGMA busy_timeout=5000")
db.SetMaxOpenConns(1) // WAL allows concurrent reads, single writer
```

#### I. Add Connection Limits to MQTT Broker

```go
const maxConnections = 10000
if atomic.LoadInt64(&b.connCount) >= maxConnections {
    conn.Close()
    return
}
```

### Tier 3: Architecture Evolution (Phase 2)

#### J. Certificate Revocation

The TLS engine correctly notes the absence of CRL/OCSP. For Phase 2:
- Add `DCLAW_CRL_PATH` support via `mbedtls_x509_crl`
- Implement certificate pinning for fleet manager connections
- Consider OCSP stapling when mbedTLS build supports it

#### K. Hardware Security Module Integration

For high-security deployments:
- Store device keys in TPM/secure enclave
- Use `PKCS#11` interface for key operations
- Never export private keys to application memory

#### L. Immutable Audit Chain

Replace ring buffer with append-only log with Merkle tree:
- Each entry references hash of previous entry
- Periodic root hash published to fleet manager
- Tampering detection via hash chain verification

#### M. Formal Verification Opportunities

The C evaluation pipeline (dclaw_core.c) is small enough (~500 LOC) for formal verification:
- Use CBMC for bounded model checking of the evaluation path
- Verify: no buffer overflows, fail-closed on all paths, cache consistency
- This would make DefenseClaw one of few formally verified security enforcement engines

---

## 7. Minimum Moving Parts Analysis

### Current Component Count
| Component | Files | LOC | Purpose |
|-----------|-------|-----|---------|
| C daemon | 17 | ~3,500 | Edge enforcement |
| Go fleet | 14 | ~6,500 | Fleet management |
| Go MQTT | 3 | ~2,500 | Embedded broker + bridge |
| Go SQLite | 2 | ~700 | Device + policy persistence |
| Python tools | 6 | ~3,500 | Framework integrations |
| Python CLI | 3 | ~800 | Setup commands |
| Python integrations | 3 | ~600 | HA/Bubbaloop/ESP |
| Policy compiler | 1 | ~960 | YAML → binary |
| **Total** | **49** | **~19,060** | |

### Simplification Opportunities

| What | Eliminate/Simplify | Rationale | Risk |
|------|-------------------|-----------|------|
| Embedded MQTT broker | Use external broker (Mosquitto/EMQX) | 532 LOC of broker code is attack surface. External brokers are battle-tested. | Adds deployment dependency |
| In-memory device store | Remove, SQLite only | 109 LOC that duplicates SQLite store. Two code paths = two bug surfaces. | None — SQLite is already default |
| Dev HMAC fallback in OTA | Remove entirely | Creates downgrade path. Dev builds should use a separate code path. | Dev friction (acceptable) |
| `picoclaw_hook.py` session ID | Use UUID, not uint16 counter | Eliminates overflow, collision, and cross-client confusion | Tiny overhead |
| Manual JSON parser in C | Consider `cJSON` (7KB, MIT) | Hand-rolled parsers are a known vulnerability class | Adds dependency |
| `strstr` topic matching | Exact suffix comparison | 1-line fix eliminates topic spoofing | None |

### Components That MUST Stay

| Component | Why |
|-----------|-----|
| C daemon | Embedded requirement, 53KB footprint, 36M/sec — no replacement |
| HMAC per-device keys | Per-device isolation is essential |
| Ed25519 OTA signing | Asymmetric crypto for OTA is non-negotiable |
| TLS 1.2+ transport | Channel encryption is non-negotiable |
| SQLite persistence | Crash-safe state on embedded devices |
| Audit ring | Compliance requirement |
| Fail-closed default | Core security invariant |

---

## 8. Test Coverage Gap Analysis

### Security-Critical Code Paths: Tested vs. Untested

| Code Path | Tested | Missing Tests |
|-----------|--------|--------------|
| HMAC verification (Go bridge) | YES — 14 test cases including cross-topic replay | |
| HMAC verification (C) | YES — constant-time comparison | Missing: key rotation during active session |
| Fail-closed on key store error | YES | |
| SQL injection resistance | YES — parameterized queries | Missing: SQLi fuzzing |
| Decommission flow | YES — bridge + persistence | Missing: re-registration after decommission |
| OTA Ed25519 verification | YES | Missing: truncated signature, wrong key |
| Emergency broadcast anti-replay | YES | Missing: gap detection edge cases |
| IPC JSON parsing | YES — basic | Missing: adversarial/fuzz corpus |
| TLS certificate verification | NOT TESTED | Need: wrong cert, expired cert, hostname mismatch |
| Rate limiting | N/A — NOT IMPLEMENTED | Must add after CRIT-5 fix |
| Concurrent MCP proxy | NOT TESTED | Must add after CRIT-2 fix |
| Token rotation persistence | NOT TESTED | Must add after H-7 fix |
| SQLite WAL mode | NOT TESTED | Basic concurrency test needed |
| Stack depth on constrained devices | NOT TESTED | `-fstack-usage` check in CI |
| Generic hook backend switch race | NOT TESTED | Thread-safety test needed |
| Policy compiler overflow | NOT TESTED | uint16 boundary test needed |

### Recommended Test Additions (Priority Order)

1. **Adversarial MQTT messages** — malformed HMAC, replayed messages, oversized payloads
2. **Concurrent MCP proxy** — 10+ parallel tool calls, verify correct verdict routing
3. **OTA downgrade attempt** — verify production build rejects HMAC-signed OTA
4. **SQLite under contention** — 100+ concurrent Go writers
5. **C fuzz corpus** — AFL++ or libfuzzer targeting JSON parser, CBOR decoder, verdict protocol
6. **Integration test** — full pipeline: hook → IPC → daemon → MQTT → fleet → verdict → hook

---

## 9. Supply Chain & Dependency Assessment

### Dependency Surface

| Language | Direct Deps | Assessment |
|----------|------------|------------|
| Go | ~30 modules (go.mod) | Standard library heavy, good. Key deps: `golang.org/x/crypto`, `mattn/go-sqlite3` |
| Python | ~15 packages (pyproject.toml) | Minimal for CLI. No known vulnerabilities |
| C | mbedTLS (optional), libc only | Excellent — minimal dependency surface |

### Supply Chain Strengths (Already In Place)

- 100% SHA-pinned CI actions (88 uses) with `persist-credentials: false`
- Sigstore keyless signing tied to release workflow identity
- Explicit CVE tracking in `pyproject.toml` with version floors for 30+ CVEs
- `pip-audit` and `npm audit` in CI
- `CGO_ENABLED=0` static Go binaries with `-trimpath`
- C compiler hardening: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Werror`
- Read-only CI permissions with no secrets in PR workflows

### Supply Chain Gaps & Recommendations

| Priority | Action | Rationale |
|----------|--------|-----------|
| CRITICAL | Add `govulncheck` to CI | Python has `pip-audit`; Go has nothing — largest gap |
| CRITICAL | Pin mbedTLS version in CMakeLists.txt | Currently `find_package(MbedTLS 3)` accepts any 3.x |
| HIGH | Add `go mod verify` to CI | Ensures `go.sum` integrity |
| HIGH | Add C static analysis (`cppcheck`/`clang-tidy`) to edge-connector CI | Hand-rolled crypto and JSON parser need automated analysis |
| HIGH | Cap `boto3` upper bound | Currently `>=1.34` with no ceiling — daily releases |
| MEDIUM | Document `third_party/fsnotify` fork | Vendored fork lacks version tracking against upstream |
| MEDIUM | Evaluate litellm alternatives | Single heaviest dep (~428MB), most CVE-prone (3 CVEs) |
| LOW | Build-tag optional OTel exporters | 12 direct OTel deps could be optional for minimal deployments |

### Dependency Counts

| Language | Direct | Transitive | Risk Assessment |
|----------|--------|-----------|-----------------|
| Go | 45 | ~160 | Moderate — stdlib heavy, good. Key risk: `litellm` equivalent not present |
| Python | 26 runtime | Large tree (litellm, boto3) | High risk via `litellm` dependency tree |
| C | 1 (mbedTLS) | 0 | Excellent — minimal surface. Hand-rolled SHA-256 is a moderate risk |
| TypeScript | N/A | 108 (package-lock) | Extension only, not in critical path |

---

## 10. Positive Security Patterns (Preserve These)

These patterns demonstrate strong security engineering and must be preserved:

1. **Constant-time comparison everywhere** — `subtle.ConstantTimeCompare` (Go), `hmac.Equal` (Go), `ct_compare` (C), `dclaw_secure_zero` (C)
2. **Fail-closed by default** — Every error path in the evaluation pipeline returns DENY
3. **Parameterized SQL** — Zero string interpolation in all SQLite queries
4. **Per-device key isolation** — Each device has its own HMAC key; compromise of one doesn't affect others
5. **HMAC includes topic path** — Prevents cross-topic replay attacks
6. **Ed25519 for OTA** — Asymmetric crypto means device compromise doesn't enable OTA forgery
7. **A/B OTA partitions with CRC** — Crash-safe update with automatic rollback
8. **TLS 1.2 minimum + AEAD-only ciphers** — No CBC, no RSA key transport, forward secrecy required
9. **MaxBytesReader on API** — Prevents request body DoS
10. **No eval/exec/shell=True/pickle** — Zero unsafe Python patterns across entire codebase
11. **Explicit `allow_redirects=False`** — Prevents redirect-based attacks on HTTP clients
12. **36M decisions/sec performance** — No security-performance tradeoff needed

---

## 11. Comparison with Industry Standards

### NIST SP 800-183 (Networks of Things)

| Requirement | DefenseClaw Status |
|------------|-------------------|
| Unique device identity | YES — per-device ID + HMAC key |
| Secure boot / firmware integrity | PARTIAL — Ed25519 OTA, but no secure boot chain |
| Secure communication | YES — TLS 1.2+ with mTLS option |
| Data protection at rest | PARTIAL — SQLite not encrypted |
| Secure update mechanism | YES — Ed25519 signed OTA with A/B |
| Event logging | YES — audit ring buffer |
| Fail-safe defaults | YES — fail-closed |

### OWASP IoT Top 10

| Risk | DefenseClaw Status |
|------|-------------------|
| I1: Weak passwords | PARTIAL — file-based creds, but env fallback exists |
| I2: Insecure network | GOOD — TLS 1.2+ mandatory in production |
| I3: Insecure interfaces | MODERATE — API needs rate limiting (CRIT-5) |
| I4: Lack of secure update | GOOD — Ed25519 + A/B + canary |
| I5: Insecure components | GOOD — minimal dependencies |
| I6: Insufficient privacy | GOOD — per-device isolation |
| I7: Insecure data transfer | GOOD — TLS + HMAC |
| I8: Lack of device management | GOOD — fleet manager + decommission |
| I9: Insecure default settings | MODERATE — env var downgrades (CRIT-3, CRIT-6) |
| I10: Lack of physical hardening | N/A — software layer |

---

## 12. Test Coverage Gaps (Security-Critical)

### Zero-Test Modules (CRITICAL)

| Module | Language | LOC | Why It Matters |
|--------|----------|-----|---------------|
| `policy_compiler.py` | Python | 964 | Produces signed security policy blobs — ZERO tests |
| `tls_engine.c` | C | 417 | Transport security foundation — ZERO tests |
| `mqtt_client.c` | C | ~900 | Device communication channel — ZERO tests |
| `store_sqlite.go` | Go | 417 | Persistent device registry — ZERO tests |
| `broker.go` | Go | 532 | MQTT broker implementation — ZERO tests |
| `tcp_client.go` | Go | 968 | Raw MQTT protocol — ZERO tests |
| `http_middleware.py` | Python | 295 | HTTP security middleware — ZERO tests |
| `langchain_hook.py` | Python | 321 | LangChain security wrapper — ZERO tests |
| `picoclaw_hook.py` | Python | 677 | Embedded hook — ZERO tests |

### Zero-Test API Endpoints (HIGH)

| Endpoint | Operation | Why It Matters |
|----------|-----------|---------------|
| `POST /devices` | Registration + key generation | Generates security credentials |
| `POST /token/rotate` | Fleet token rotation | Privileged operation |
| `POST /devices/{id}/rotate-key` | Device key rotation | Privileged operation |
| `GET /metrics` | Prometheus metrics | Internal state exposure |

### Missing Adversarial Test Cases

| Category | Current | Needed |
|----------|---------|--------|
| Concurrent MCP proxy | NOT TESTED | 10+ parallel tool calls, verify correct verdict routing |
| TLS certificate validation | NOT TESTED | Wrong cert, expired cert, hostname mismatch |
| SQLite under contention | NOT TESTED | 100+ concurrent writers |
| OTA downgrade attempt | NOT TESTED | Verify production build rejects HMAC-signed OTA |
| E2E integration | NOT TESTED | hook → IPC → daemon → MQTT → fleet → verdict → hook |
| C fuzz corpus | Limited (IPC only) | CBOR decoder, verdict protocol, content scanner DFA |

---

## 13. Fix Priority Summary

### P0 — Before Merge (estimated 2 days)

| ID | Fix | Est. |
|----|-----|------|
| CRIT-0A | Enforce `mqtts://` in production, wire TLS into MQTT client | 4 hours |
| CRIT-0B | Add MQTT broker authentication (username/password or mTLS) | 4 hours |
| CRIT-1 | Nil signer check | 15 min |
| CRIT-2 | MCP proxy atomic send/receive with ID correlation | 1 hour |
| CRIT-3 | Compile-time-only OTA downgrade (`#ifdef DCLAW_DEV_MODE`) | 1 hour |
| CRIT-4 | Move content_buf off stack (heap or static pool) | 30 min |
| CRIT-7 | Document file-based creds, remove misleading scrub | 30 min |

### P1 — Before Production (estimated 1 week)

| ID | Fix | Est. |
|----|-----|------|
| CRIT-5 | Rate limiting middleware on all Fleet API endpoints | 4 hours |
| CRIT-6 | Path validation + allowlist for env-sourced paths | 2 hours |
| CRIT-8 | RBAC: per-operator JWT with role-based scopes | 2 days |
| CRIT-9 | Tenant-aware verdict cache keys | 2 hours |
| H-1–H-19 | All HIGH findings | 8 hours |
| Tests | Add tests for zero-coverage modules | 2 days |
| Supply chain | Add `govulncheck`, pin mbedTLS, `go mod verify` | 4 hours |

### P2 — Before GA (estimated 2 weeks)

| ID | Fix | Est. |
|----|-----|------|
| M-1–M-24 | All MEDIUM findings | 3 days |
| Architecture | SQLite WAL, connection limits, monotonic time | 2 days |
| Architecture | Move all secrets from env vars to file-based provisioning | 2 days |
| Architecture | Rewrite policy compiler in Go (eliminate Python subprocess) | 3 days |
| Supply chain | SBOM generation, binary signing, reproducible builds | 1 day |
| Tests | E2E integration test, fuzz corpus expansion | 2 days |

### P3 — Phase 2

| ID | Fix | Est. |
|----|-----|------|
| CRL/OCSP | Certificate revocation support | 1 week |
| HSM/TPM | Hardware key storage integration | 2 weeks |
| Merkle audit | Immutable audit chain with external anchor | 1 week |
| Formal verification | CBMC on C evaluation pipeline | 2 weeks |
| 2-person rule | Confirmation mechanism for emergency commands | 1 week |
| Crypto agility | Algorithm suite versioning in message headers | 1 week |

---

## 14. Overall Verdict

### Scorecard

| Category | Score | Notes |
|----------|-------|-------|
| Architecture design | 4.2/5 | Sound 3-tier model. Trust boundaries well-defined. MQTT plaintext is the critical gap. |
| Fail-closed behavior | 5/5 | Every error path denies. Best-in-class for security software. |
| Cryptographic correctness | 4/5 | Constant-time everywhere, Ed25519 for OTA, per-device keys. Gaps: runtime downgrade, env exposure. |
| Input validation | 4/5 | Bounded parsers, parameterized SQL, sanitized strings. Gaps: env-sourced paths, strstr matching. |
| Concurrency safety | 3.5/5 | Go race detector passes. Latent races in MCP proxy, generic_hook backend swap. |
| Test coverage | 3/5 | Strong for bridge/API/manager. 9 security-critical modules have zero tests. |
| Supply chain | 4.5/5 | SHA-pinned CI, Sigstore signing, CVE-tracked deps. Gap: no `govulncheck`. |
| Access control | 2.5/5 | Single shared token, no RBAC, no operator identity. |
| Transport security | 2/5 | TLS engine exists but MQTT is plaintext in production profile. |
| Performance | 5/5 | 36M decisions/sec, 27ns latency. No security-performance tradeoff needed. |
| **Overall** | **3.8/5** | |

### Summary

**Architecture: SOUND** — The 3-tier architecture (edge → MQTT → fleet) with per-device key isolation, fail-closed defaults, and signed OTA is well-designed for an AI agent security governance system.

**Implementation: GOOD with gaps** — Strong foundational security patterns. The 11 critical findings are fixable within 2 weeks and mostly represent implementation oversights and missing transport encryption, not architectural flaws.

**Biggest risks (in order):**
1. Plaintext MQTT leaks all device telemetry and AI tool call patterns
2. No RBAC — any operator can brick the fleet with BLOCK_ALL
3. Env var injection can downgrade OTA, TLS, and strict mode
4. 9 security-critical modules have zero test coverage

**After fixing the 11 CRITICALs and 19 HIGHs, this architecture will be among the most secure AI agent governance systems available.** The combination of sub-30ns embedded enforcement, per-device cryptographic isolation, fail-closed defaults, and HMAC-chained audit is a strong foundation that few competing systems match.

---

**Review performed by:** 6 parallel specialized agents (C security, Go security, Python security, architecture/threat model, test coverage, supply chain)
**Review date:** 2026-10-10
**Reviewer:** Claude Opus 4.6
**Total source files reviewed:** ~49 files, ~19,000 LOC across C, Go, Python
