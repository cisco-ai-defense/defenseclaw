# Plan: DefenseClaw Edge Connector — Phase 1 (STANDARD Profile)

## Scope

### In scope — Phase 1A (8-week delivery)

- C agent binary (STANDARD profile) targeting Raspberry Pi 4 and Jetson Nano
  - Policy table enforcement with compiled decision tables
  - Capability correlator (16-session FSM)
  - IPC hook with SO_PEERCRED + input validation boundary
  - Speculative execution engine with escalation mode table
  - Verdict cache (64-entry LRU with TTL)
  - Token-bucket rate limiters (3 independent)
  - Audit ring buffer (256 entries, HMAC chain, write coalescing)
  - MQTT 5.0 client with mTLS, broker fallback list, heartbeat
  - Clock synchronization via server_ts in verdict responses
  - Verdict HMAC tag verification + pending dedup (8 slots)
  - Emergency broadcast verification (Ed25519 + sequence)
  - Policy OTA with A/B partitions + canary health-check
  - Destination allow/deny list enforcement (256 entries)
- Policy compiler (Python CLI tool)
  - YAML parsing + sequence rule expansion
  - C header generation + signed binary blob generation
  - Size validation with per-component report
  - Ed25519 signing with OTA CA key
- Cloud fleet manager (Go, embedded in gateway)
  - Device registration (auto on first MQTT connect)
  - Heartbeat ingestion + fleet-wide metric computation
  - Anomaly detection (offline, block spike, tamper)
  - Alert dispatch via existing webhook infrastructure
  - Audit sink (receive + verify HMAC chain + store)
  - Verdict cache service (in-memory + Redis persistence)
  - Integration with existing inspection pipeline
- Fleet REST API
  - Device CRUD, command dispatch, health dashboard
  - Audit query, threat-intel push, policy compile+distribute
  - Policy simulation (dry-run), trace lookup
- Prometheus metrics + Grafana dashboard + alerting rules
- CMake build system with Kconfig profile selection
- CI pipeline: compile, static analysis (cppcheck), AFL++ fuzz

### In scope — Phase 1B (Weeks 9-12, AI-aware security)

- Content Scanner Module (Weeks 9-10)
  - DFA pattern table walker in C (`src/decision/content_scanner.c`)
  - 6 pattern categories: SECRET, PII, CREDENTIAL, EXFIL, INJECTION, COMMAND
  - Policy compiler extended to generate DFA state machine tables from pattern strings
  - `content_scanner.h` with `scan_context_t`, `dfa_table_t`, `finding_t` structs
  - SSRF/netguard validation in destination check stage (IP class checks, inline credential rejection, scheme validation)
  - Trust boundary inference in correlator (`content_scope` enum, session-based inference)
  - Unit tests for all 6 pattern categories + SSRF + trust inference
- Enriched Cloud Escalation + Response Interception (Weeks 11-12)
  - IPC JSON-RPC schema extended: `"direction"` and `"content"` fields (backward compatible)
  - CBOR verdict request extended: truncated content, direction, content_scope, local findings
  - CBOR verdict response extended: category enum + 64-byte evidence snippet
  - Verdict cache updated to store category + evidence alongside action
  - Configurable `max_escalation_payload_bytes` (default 1024)
  - Integration tests: content scan -> enriched escalation -> verdict with category
  - Performance benchmark: verify <5us with content scan, binary <80KB, RAM <25KB
  - AFL++ fuzz campaign on content scanner input paths
  - Acceptance tests for AC-13 through AC-17

### Out of scope (deferred to Phase 2-4)

- Edge gateway topology (Option B with local MQTT broker)
- Tier 1 MCU support (Zephyr/FreeRTOS, CoAP/DTLS)
- MINIMAL and EDGE profiles
- Bloom filter for known-bad detection
- PII redaction module
- Netfilter/nftables rule generation
- Device-to-device mesh verdict sharing
- Staged OTA rollout with batch/pause logic (fleet-level)
- Certificate rotation protocol
- Multi-tenant isolation in fleet manager
- Cisco Umbrella / XDR integration

---

## Dependencies

### Internal

| Dependency | Required By | Notes |
|-----------|-------------|-------|
| Existing inspection pipeline (`internal/gateway/inspect.go`) | Fleet Manager verdict routing | Reused unchanged |
| Existing audit store (`internal/audit/`) | Fleet Manager audit sink | Reused unchanged |
| Existing webhook dispatcher | Fleet Manager alerts | Reused unchanged |
| Existing Prometheus endpoint (`/metrics`) | Fleet metrics exposure | Extended with new families |
| Existing connector matrix | IoT-lite registration | New entry added |
| YAML policy format (`policies/*.yaml`) | Policy compiler | Extended with `iot_extensions` |

### External

| Dependency | Version | Purpose |
|-----------|---------|---------|
| mbedTLS | 3.5+ | TLS 1.3 + mTLS on device |
| libcbor | 0.10+ | CBOR encode/decode (or custom minimal impl) |
| EMQX | 5.x | MQTT 5.0 broker (cloud-hosted) |
| Redis | 7.x | Verdict cache persistence |
| TimescaleDB | 2.x (on PostgreSQL 15) | Audit event hypertable |
| Ed25519 (TweetNaCl or ref10) | — | Signature verification on device |
| Python 3.10+ | — | Policy compiler runtime |
| PyNaCl | 1.5+ | Ed25519 signing in compiler |
| CMake | 3.22+ | C agent build system |
| ARM GCC toolchain | 12+ | Cross-compilation for aarch64 |
| AFL++ | 4.x | Fuzz testing framework |
| cppcheck | 2.x | Static analysis |

Phase 1B adds no new external dependencies. DFA tables are generated at compile time by the policy compiler; patterns are compiled into C arrays linked directly into the binary.

---

## Rollout Plan

### Week 1-2: Foundation

```
1. Set up CMake + Kconfig build for edge-connector/
2. Implement HAL for Linux (hal_linux.c)
3. Implement core data structures (static allocation)
4. Implement IPC hook with input validation
5. Basic decision engine (policy table lookup, no cache)
6. Unit tests for input validation + policy table
```

### Week 3-4: Communication + Audit

```
7. Implement MQTT client (mbedTLS, mTLS, broker fallback)
8. Implement heartbeat + clock sync (server_ts)
9. Implement verdict request/response + HMAC verification
10. Implement pending dedup table
11. Implement audit ring (HMAC chain + write coalescing)
12. Implement correlator (session FSM)
13. Integration test: device -> MQTT -> mock cloud -> verdict
```

### Week 5-6: Cloud Services + Policy

```
14. Implement fleet manager (device registry, heartbeat)
15. Implement verdict cache (Redis-backed, TTL policy)
16. Wire verdict requests to existing inspection pipeline
17. Implement policy compiler (Python: YAML -> C + .bin)
18. Implement OTA receiver + A/B partition + canary
19. Implement emergency broadcast verification
20. Integration test: full device -> cloud -> device flow
```

### Week 7-8: Hardening + Observability

```
21. Implement speculative execution + retroactive callback
22. Implement rate limiters (3 token buckets)
23. AFL++ fuzz campaign on IPC parser (1M+ iterations)
24. Static analysis pass (cppcheck, fix all findings)
25. Prometheus metrics + Grafana dashboard
26. Alert rules (device offline, block spike, tamper, etc.)
27. Performance benchmarking on Raspberry Pi 4
28. Binary size audit (must be <80KB)
29. End-to-end acceptance test suite (AC-01 through AC-12)
30. Documentation: operator guide, policy compiler usage
```

### Week 9-10: Content Scanner Module

```
31. Implement DFA pattern table walker (src/decision/content_scanner.c)
32. Define content_scanner.h: scan_context_t, dfa_table_t, finding_t structs
33. Implement 6 pattern categories: SECRET, PII, CREDENTIAL, EXFIL, INJECTION, COMMAND
34. Extend policy compiler to generate DFA state machine tables from pattern strings
35. Add SSRF/netguard validation to destination check stage
    - IP class checks (private range, loopback, link-local rejection)
    - Inline credential rejection (user:pass@ in URI)
    - Scheme validation (reject file://, gopher://, dict://)
36. Add trust boundary inference to correlator
    - content_scope enum (INTERNAL, EXTERNAL, CROSS_BOUNDARY)
    - Session-based inference from IPC peer identity
37. Unit tests for all 6 pattern categories
38. Unit tests for SSRF validation + trust boundary inference
```

### Week 11-12: Enriched Cloud Escalation + Response Interception

```
39. Extend IPC JSON-RPC schema: add "direction" and "content" fields (backward compatible)
40. Extend CBOR verdict request: truncated content, direction, content_scope, local findings
41. Extend CBOR verdict response: category enum + 64-byte evidence snippet
42. Update verdict cache to store category + evidence alongside action
43. Add configurable max_escalation_payload_bytes (default 1024)
44. Integration tests: content scan -> enriched escalation -> verdict with category
45. Performance benchmark: verify <5us with content scan, binary <80KB, RAM <25KB
46. AFL++ fuzz campaign on content scanner input paths
47. Acceptance tests for AC-13 through AC-17
48. Documentation update: content scanner operator guide, pattern authoring reference
```

### Feature flags / Backward compatibility

- Fleet manager registers as connector type `iot-lite` — existing connectors unaffected
- New fleet REST API lives under `/api/v1/fleet/` — no collision with existing routes
- New DB tables are additive (no migrations to existing tables)
- MQTT broker is a new infrastructure component (no impact on existing gateway traffic)
- Policy compiler extends YAML format with `iot_extensions` section (existing fields unchanged)
- Phase 1B IPC schema additions (`direction`, `content`) are optional fields — existing clients send/receive without them
- CBOR verdict extensions use new map keys — old agents ignore unknown keys, old cloud ignores missing keys
- Content scanner is compiled in only when `CONFIG_CONTENT_SCANNER=y` in Kconfig (off by default for MINIMAL profile)

---

## Observability Plan

### Logs

Structured JSON logs from fleet manager (Go):

| Field | Description |
|-------|-------------|
| `device_id` | Composite uint64 device identity |
| `event` | `device_registered`, `heartbeat_processed`, `verdict_served`, `anomaly_detected` |
| `action` | Verdict action (for verdict events) |
| `latency_ms` | Verdict processing time |
| `cache_hit` | Boolean (for verdict events) |
| `reason` | Reason code (for block events) |

Device-side: no structured logging (no filesystem). All diagnostics via heartbeat flags + audit ring.

### Metrics

```
# Fleet-level (from fleet manager)
defenseclaw_fleet_devices_total{status}                    gauge
defenseclaw_fleet_blocks_total{reason}                     counter
defenseclaw_fleet_allows_total                             counter
defenseclaw_fleet_verdict_latency_seconds{source}          histogram
defenseclaw_fleet_audit_chain_breaks_total                 counter
defenseclaw_fleet_policy_rollback_total{device_id}         counter
defenseclaw_fleet_emergency_seq_gap{device_id}             gauge
defenseclaw_fleet_device_flash_writes_total{device_id}     counter
defenseclaw_fleet_speculative_retroactive_blocks_total     counter

# Verdict cache (from cache service)
defenseclaw_fleet_verdict_cache_hit_rate                   gauge
defenseclaw_fleet_verdict_cache_size                       gauge
defenseclaw_fleet_verdict_cache_evictions_total            counter

# Per-device decision latency (sampled, from heartbeats)
defenseclaw_fleet_device_decision_latency_us{type}         histogram
```

### Traces

- 8-byte `trace_id` = SHA256(device_id || request_id || boot_counter)[0:8]
- Propagated in verdict request CBOR payload
- Stored in cloud for 24h rolling window (10K entries per device)
- Queryable via `GET /api/v1/fleet/devices/{id}/traces`

### Alerting Rules

7 Prometheus alert rules defined:
- DeviceOffline, AuditChainTamper, BlockSpike, PolicyDrift
- PolicyCanaryRollback, SecureElementDegraded, FlashWearWarning

---

## Security Plan

### Auth/Authz

| Layer | Mechanism |
|-------|-----------|
| Device -> Broker | mTLS (X.509 device certificate, chain to DefenseClaw Root CA) |
| Device -> IPC | SO_PEERCRED UID/GID + start_time + one-time registration nonce |
| Admin -> Fleet API | Bearer JWT (existing gateway auth middleware) |
| OTA Integrity | Ed25519 signature (OTA Signing CA) |
| Verdict Integrity | Session-scoped HMAC-SHA256 (truncated 4B) |
| Emergency Integrity | Ed25519 signature + monotonic sequence |

### Data handling

| Data | At rest | In transit |
|------|---------|-----------|
| Device private key | Secure element / protected flash | Never transmitted |
| Policy tables | Flash (signed, verified on apply) | TLS 1.3 (MQTT) |
| Audit entries | Flash (HMAC-chained) | TLS 1.3 (MQTT) |
| Verdict cache | Redis (encrypted at rest optional) | Internal network |
| Fleet DB | PostgreSQL (encrypted tablespace) | Internal network |

### Input validation boundary

Section 8.4 of architecture proposal defines the invariant:
**All IPC input is untrusted and bounds-checked before processing.**

Enforced rules:
1. Max 512 bytes payload
2. ASCII-only strings (0x20-0x7E)
3. Exact 32-byte tool_hash
4. No banned functions (strcpy, sprintf, sscanf)
5. CBOR decoder rejects nested depth >2, indefinite lengths, duplicate keys
6. 100 req/s IPC rate limit

Verified by:
- AFL++ fuzz testing (1M iterations minimum per release)
- cppcheck static analysis in CI (zero findings policy)
- `-fstack-protector-strong` compiler flag

### Multi-tenancy (Phase 1 scope)

- Topic isolation via broker ACL (device cert OU encodes tenant_id/fleet_id)
- Cloud DB uses composite device_id (tenant+fleet+device) as primary key
- Full multi-tenant API isolation deferred to Phase 4

---

## Exit Criteria

Phase 1 is complete when:

### Phase 1A (Weeks 1-8)

1. All 12 acceptance criteria (AC-01 through AC-12) pass
2. Binary size <80KB measured on ARM64 (GCC -Os)
3. RAM usage <25KB measured via linker map analysis
4. <5us local decision latency verified on Raspberry Pi 4
5. <500ms cloud verdict P95 measured over public internet
6. AFL++ fuzz campaign completes 1M iterations with zero crashes
7. cppcheck reports zero findings
8. Grafana dashboard shows correct fleet metrics from 10 test devices
9. Policy compiler accepts and rejects policies at documented size limits
10. Emergency broadcast with invalid signature/sequence is rejected (demo)

### Phase 1B (Weeks 9-12)

11. All 5 acceptance criteria (AC-13 through AC-17) pass
12. Content scanner detects full test corpus with zero false negatives across all 6 pattern categories
13. Binary remains <80KB after content scanner additions (ARM64, GCC -Os)
14. <5us local decision latency maintained with content scan enabled
15. RAM usage remains <25KB with content scanner active
16. Enriched MQTT payload validated end-to-end: device content scan -> cloud verdict with category + evidence -> device cache with category
17. AFL++ fuzz campaign on content scanner input paths completes with zero crashes
18. SSRF/netguard validation rejects all test vectors (private IPs, inline credentials, banned schemes)
19. Trust boundary inference correctly classifies INTERNAL/EXTERNAL/CROSS_BOUNDARY in integration tests
20. Backward compatibility verified: Phase 1A-only agent communicates with Phase 1B cloud (and vice versa) without errors
