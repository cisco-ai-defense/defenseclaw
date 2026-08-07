# Tasks: DefenseClaw Lite — Phase 1 (STANDARD Profile)

## Tasks

Order matters — earlier tasks are dependencies for later ones.
Each task is independently mergeable where possible.

### Foundation (Week 1-2)

1. [ ] **Build system setup** — CMake + Kconfig for defenseclaw-lite/, cross-compile
   for aarch64-linux-gnu, profile selection (STANDARD default), CI integration.
   Maps to: REQ-45, REQ-46.

2. [ ] **Platform HAL (Linux)** — Implement `hal_linux.c`: flash read/write (mmap'd
   file), monotonic tick source (clock_gettime CLOCK_MONOTONIC), secure storage
   paths, Unix socket creation. Maps to: REQ-12.

3. [ ] **Core data structures** — Implement all static-allocation structs from
   `defenseclaw.h`: dclaw_device_info_t, dclaw_clock_t, dclaw_tool_request_t,
   dclaw_verdict_t, dclaw_audit_entry_t, dclaw_session_t, dclaw_rate_limiter_t,
   dclaw_canary_state_t, dclaw_emergency_state_t, dclaw_ipc_peer_t,
   dclaw_pending_verdict_t, dclaw_speculative_slot_t, dclaw_escalation_entry_t.
   Maps to: REQ-02, REQ-04, REQ-07, REQ-17.

4. [ ] **IPC hook + input validation** — Implement `ipc_hook.c`: Unix socket server,
   JSON-RPC parsing (minimal, no external lib), SO_PEERCRED verification,
   /proc start_time check, registration nonce flow, 512B payload limit,
   ASCII validation, tool_hash length check, 100 req/s rate limit.
   Maps to: REQ-12, REQ-13, REQ-14, REQ-15, REQ-16, REQ-51.

5. [ ] **Policy table engine** — Implement `policy_table.c`: binary search over
   sorted compiled tables (severity rules, sequence rules, dest allowlist,
   deny hashes). Return verdict in O(log n). Maps to: REQ-01, REQ-06.

6. [ ] **Unit tests: input validation + policy table** — Test cases for all
   REQ-15 rejection scenarios (oversized, non-ASCII, bad hash), policy table
   hit/miss cases, binary search edge cases (empty table, single entry, full).
   Maps to: AC-08, AC-01.

### Communication + Audit (Week 3-4)

7. [ ] **MQTT client** — Implement `mqtt_client.c`: MQTT 5.0 connect/subscribe/
   publish using mbedTLS for TLS 1.3 mTLS. Load device cert from config store.
   Broker fallback list (3 endpoints, exponential backoff). QoS 0 for heartbeat,
   QoS 1 for verdict/OTA/audit. CONNACK user property for server timestamp.
   Maps to: REQ-22, REQ-23.

8. [ ] **CBOR codec** — Implement `cbor_codec.c`: encode/decode for heartbeat (32B),
   verdict request (~42B), verdict response (16B), audit sync batch. Minimal
   implementation — fixed schemas only, no generic CBOR parser.
   Maps to: REQ-24.

9. [ ] **Heartbeat + clock sync** — Implement heartbeat construction (32B format
   per §7.2), 30s timer loop, flag byte assembly. On verdict response receipt,
   update dclaw_clock_t from server_ts. Implement time_trusted logic.
   Maps to: REQ-24, REQ-25, REQ-26.

10. [ ] **Verdict request/response protocol** — Implement verdict request publishing
    (CBOR encode, MQTT QoS 1) and response handling (CBOR decode, 16B format).
    Maps to: REQ-27.

11. [ ] **Verdict HMAC verification + dedup** — Implement session_key derivation
    (HKDF from device_key + mqtt_session_id), HMAC-SHA256 tag computation +
    truncation to 4 bytes, comparison. Implement 8-slot pending dedup table
    (silently discard duplicate request_ids). Maps to: REQ-27, REQ-28, REQ-29.

12. [ ] **Audit ring buffer** — Implement `audit_ring.c`: 256-entry ring in flash,
    16B fixed entries with HMAC chain, write-coalescing RAM buffer (16 entries),
    60s flush timer, immediate flush on BLOCK, flash_safe writes with wear leveling.
    Maps to: REQ-17, REQ-18, REQ-19, REQ-20, REQ-21.

13. [ ] **Capability correlator** — Implement `correlator.c`: 16-session FSM,
    8-deep capability history ring per session, sequence matching against compiled
    rules (linear scan over sorted sequence_rules table), risk score accumulation.
    Maps to: REQ-02, REQ-03.

14. [ ] **Integration test: device→MQTT→mock cloud→verdict** — Stand up mock MQTT
    broker + mock verdict responder. Device sends verdict request for unknown hash,
    receives ALLOW with valid HMAC, caches result, subsequent request hits cache.
    Maps to: AC-02.

### Cloud Services + Policy (Week 5-6)

15. [ ] **Fleet manager: device registry** — Go service (embedded in gateway):
    subscribe to `+/+/+/register` topic, parse registration CBOR, insert into
    iot_devices table, return MQTT response. Maps to: REQ-37.

16. [ ] **Fleet manager: heartbeat processor** — Subscribe to `+/+/+/heartbeat`,
    parse 32B CBOR, update last_heartbeat, accumulate denied/allowed/warned counters,
    verify audit_head_hmac continuity. Maps to: REQ-38.

17. [ ] **Fleet manager: anomaly detection + alerts** — Implement alert rules:
    device_offline (3× heartbeat interval), block_spike (5× baseline in 5min),
    audit chain break (HMAC mismatch). Dispatch via existing WebhookDispatcher.
    Maps to: REQ-39.

18. [ ] **Verdict cache service** — In-memory hash map (Go map[string]VerdictEntry)
    with Redis persistence. TTL per-action (ALLOW=24h, BLOCK=7d, WARN=4h). LRU
    eviction at 10M entries. On cache miss: call `inspect.Evaluate()` from existing
    pipeline, store result, return to device via MQTT. Maps to: REQ-40.

19. [ ] **Policy compiler (Python)** — Implement `tools/policy_compiler.py`:
    parse YAML (including iot_extensions), expand sequence rules, generate sorted C
    struct arrays (policy_tables.h), generate signed binary blob (policy.bin) with
    Ed25519 + version counter. Size validation step with fail-fast and report.
    Maps to: REQ-41, REQ-42, REQ-43, REQ-44.

20. [ ] **OTA receiver + A/B partition** — Implement `ota_receiver.c`: receive
    policy blob via MQTT ota/policy topic, verify Ed25519 signature, check
    version > current, write to inactive partition, verify CRC, switch active
    pointer. Maps to: REQ-33, REQ-34, REQ-36.

21. [ ] **Canary health-check window** — After policy apply, enter 10-min canary:
    track blocks/min vs. baseline (from policy blob or last-hour rate), auto-rollback
    to previous partition if spike 5× for 3 consecutive minutes. Report via heartbeat
    flag. Maps to: REQ-35.

22. [ ] **Emergency broadcast handler** — Implement `dclaw_apply_emergency()`:
    verify Ed25519 signature using pinned OTA CA pubkey, check monotonic sequence,
    reject delta >1000, apply command (BLOCK_ALL, REVOKE_HASH, FORCE_SYNC,
    ENTER_LOCKDOWN). On reconnect: detect sequence gap, request replay.
    Maps to: REQ-30, REQ-31, REQ-32.

23. [ ] **Integration test: full flow** — End-to-end: device boots, registers,
    sends heartbeats, receives policy OTA, evaluates tool calls (local + cloud),
    handles emergency broadcast. Fleet manager shows correct state.
    Maps to: AC-02, AC-04, AC-06, AC-07, AC-11.

### Hardening + Observability (Week 7-8)

24. [ ] **Speculative execution engine** — Implement escalation_mode lookup table,
    4-slot speculative tracker, PENDING return for speculative caps, retroactive
    block callback invocation on cloud BLOCK, DCLAW_REASON_RETROACTIVE audit entry.
    Maps to: REQ-08, REQ-09, REQ-10, REQ-11.

25. [ ] **Rate limiters** — Implement 3 token-bucket rate limiters configured from
    policy rate_limits section. Token refill on tick timer. Reject with
    DCLAW_REASON_RATE_LIMIT. Maps to: REQ-07.

26. [ ] **AFL++ fuzz campaign** — Create fuzz harness targeting IPC parser
    (dclaw_ipc_parse_request). Run 1M+ iterations. Fix any crashes/hangs found.
    Verify no buffer overflows, no undefined behavior. Maps to: REQ-52.

27. [ ] **Static analysis** — Run cppcheck on entire defenseclaw-lite/ codebase.
    Zero findings policy. Fix all warnings. Add to CI as blocking check.
    Maps to: REQ-51.

28. [ ] **Prometheus metrics** — Expose fleet-level metrics from Go fleet manager:
    defenseclaw_fleet_devices_total, blocks_total, verdict_latency_seconds,
    cache_hit_rate, audit_chain_breaks_total, etc. (full list in plan.md).
    Maps to: AC-11.

29. [ ] **Grafana dashboard + alert rules** — Create fleet dashboard JSON
    (device count, block rate timeline, policy versions, top reasons, edge status).
    Configure 7 alerting rules in Prometheus. Maps to: AC-11.

30. [ ] **Performance benchmark** — Measure on Raspberry Pi 4:
    - Local policy table decision latency (target: <5μs)
    - Verdict cache hit latency (target: <10μs)
    - Cloud verdict round-trip (target: <500ms P95)
    - Tool call throughput (target: 100K/s for local decisions)
    Maps to: REQ-47, REQ-48, REQ-50.

31. [ ] **Binary size + RAM audit** — Measure .text+.rodata from ELF (arm-none-eabi-size
    or equivalent). Generate linker map, sum all .bss + static allocations. Verify
    <80KB binary, <25KB RAM. Maps to: REQ-45, REQ-46, AC-12.

32. [ ] **Acceptance test suite** — Automated tests for all 12 acceptance criteria
    (AC-01 through AC-12). Run on Raspberry Pi 4 hardware or QEMU aarch64 emulation.
    Maps to: All ACs.

33. [ ] **Fleet REST API** — Implement all fleet management endpoints in Go
    (device CRUD, command dispatch, health dashboard, audit query, threat-intel push,
    policy compile, policy simulate, trace lookup). Wire to fleet manager internals.
    Maps to: REQ-37 (expanded).

34. [ ] **Documentation** — Operator guide (fleet setup, policy compiler usage,
    dashboard walkthrough, incident response for tamper detection). Developer guide
    (build from source, run tests, add new policy rules). Maps to: —.

35. [ ] **Spec updates + CONTEXT.md** — Update architecture proposal version note,
    mark Phase 1 tasks complete, append CONTEXT.md entry.

---

## Test Plan

### Unit Tests

| Module | Coverage Target | Key Test Cases |
|--------|----------------|----------------|
| `ipc_hook.c` | 100% branch | Oversized payload, non-ASCII, bad hash length, PID recycle, rate limit |
| `policy_table.c` | 100% branch | Empty table, single entry, binary search boundaries, all reason codes |
| `correlator.c` | 95% branch | Sequence match, session overflow, risk accumulation, session timeout |
| `audit_ring.c` | 100% branch | HMAC chain verify, buffer flush triggers, BLOCK bypass, ring wrap |
| `verdict_cache.c` | 95% branch | Hit, miss, TTL expiry, LRU eviction, clock-untrusted |
| `cbor_codec.c` | 100% branch | All message types, malformed input, oversized strings |
| `mqtt_client.c` | 90% branch | Connect, disconnect, reconnect, fallback, QoS 1 retry |
| `ota_receiver.c` | 100% branch | Valid sig, invalid sig, version check, partition swap, canary rollback |
| `rate_limiter.c` | 100% branch | Token depletion, refill, burst |

### Integration Tests

| Scenario | Components | Verification |
|----------|-----------|--------------|
| End-to-end verdict | Device + MQTT broker + Fleet Manager | Unknown tool → cloud → ALLOW cached → second hit from cache |
| Offline enforcement | Device (no MQTT) | Unknown tool → BLOCK; known policy → ALLOW; sequence → BLOCK |
| Broker fallback | Device + 3 brokers (2 down) | Connects to 3rd broker, heartbeats arrive |
| OTA + canary rollback | Device + Fleet Manager | Push policy → spike → rollback → old policy restored |
| Emergency broadcast | Device + Fleet Manager | Valid broadcast applied; invalid rejected |
| Audit chain integrity | Device + Fleet Manager | Verify HMAC chain over 100 entries; detect tampered entry |
| Speculative execution | Device + slow cloud | PENDING returned <10μs; retroactive BLOCK callback fires |

### Performance Tests

| Test | Target | Method |
|------|--------|--------|
| Local decision latency | <5μs P99 | 1M iterations, measure rdtsc/clock_gettime |
| Verdict cache hit | <10μs P99 | 100K iterations with warm cache |
| Cloud verdict RTT | <500ms P95 | 10K requests over public internet |
| IPC throughput | 100K decisions/s | Flood IPC socket, measure throughput |
| Heartbeat overhead | <0.1% CPU at 30s interval | Profile CPU usage over 1 hour |
| Flash write rate | <7 writes/min | Monitor total_flash_writes over 1 hour at 60 tool calls/min |

### Fuzz Tests

| Target | Tool | Iterations | Input |
|--------|------|-----------|-------|
| `dclaw_ipc_parse_request()` | AFL++ | 1M minimum | Random bytes up to 1024B |
| `dclaw_cbor_decode_verdict()` | AFL++ | 500K | Random bytes up to 32B |
| `dclaw_verify_emergency()` | AFL++ | 500K | Random 108B messages |
| `dclaw_apply_policy()` | AFL++ | 500K | Random blobs up to 8KB |
