# Edge Connector — Complete Limitation Inventory

**PR**: #678 (`feature/defenseclaw-lite-phase1`)
**Commit**: `fdb79e4ae`
**Date**: 2026-10-07
**Source**: Exhaustive code audit of all C, Go, Python, and MDX files in the edge-connector feature

---

## Summary

| Category | Count | Fixable in PR | Phase 2 |
|----------|-------|---------------|---------|
| Phase-2 / Not Implemented | 5 | 0 | 5 |
| Dead Code | 7 | 7 | 0 |
| Hardcoded Values | 10 | 4 | 6 |
| Security | 8 | 3 | 5 |
| Operational / Resilience | 7 | 3 | 4 |
| Functional Gaps | 6 | 3 | 3 |
| Portability | 2 | 0 | 2 |
| **Total** | **45** | **20** | **25** |

---

## Phase-2 / Not Yet Implemented

| # | Limitation | Location | Impact | Priority |
|---|-----------|----------|--------|----------|
| 1 | **TLS/mTLS transport** — `mqtts://` always returns -1. All MQTT is plaintext. `tls_engine.c` is a stub with no callers. | `mqtt_client.c:714-728`, `tls_engine.c:1-21` | All fleet communication is unencrypted | P1 Phase-2 |
| 2 | **Destination denylist** — policy field documented but compiler doesn't read it | `policies.mdx:70` | Can only allowlist, not explicitly block | P2 Phase-2 |
| 3 | **Custom regex content patterns** — only built-in keyword patterns supported | `policies.mdx:148` | Content scanning limited to hardcoded patterns | P2 Phase-2 |
| 4 | **Device certificate loading** — `hal_load_device_cert()` / `hal_load_ca_cert()` defined but never called | `hal_linux.c:156-183` | No certificate-based device identity | P2 Phase-2 |
| 5 | **SSRF DFA tables** — `dclaw_ssrf_init_tables()` is Phase 1B stub, never called | `content_scanner.c:585-587` | SSRF uses hardcoded IP checks only | P3 Phase-2 |

## Dead Code

| # | Function | Location | Why Dead | Action |
|---|----------|----------|----------|--------|
| 6 | `dclaw_flash_write_safe()` / `dclaw_flash_read_safe()` | `flash_safe.c:7-13` | Passthrough wrappers, zero callers | Remove file |
| 7 | `dclaw_ipc_verify_peer()` | `ipc_hook.c:27-42` | Defined but `main.c` never calls it | Wire it or remove |
| 8 | `dclaw_report_result()` | `dclaw_core.c:402-413` | No external callers, uses fake hash | Remove |
| 9 | `dclaw_check_destination()` | `dclaw_core.c:397-400` | No external callers | Remove |
| 10 | `dclaw_mqtt_subscribe()` | `mqtt_client.c:950` | Dead public API | Remove |
| 11 | `dclaw_mqtt_disconnect()` | `mqtt_client.c:1026` | Never called, socket FD leaked | Wire to shutdown or remove |
| 12 | `dclaw_policy_check_severity()` | `policy_table.c:206` | Never called — **runtime severity rules from OTA have no effect** | Wire into evaluation pipeline |

## Hardcoded Values

| # | Value | Location | Current | Configurable? | Action |
|---|-------|----------|---------|---------------|--------|
| 13 | Heartbeat interval | `mqtt_client.c:1062` | Compile-time constant | No | Accept — compile-time is correct for embedded |
| 14 | Verdict cache TTLs | `verdict_cache.c:9-16` | ALLOW=24h, BLOCK=7d, WARN=4h | No | Read from OTA policy |
| 15 | Rate limiter buckets | `dclaw_core.c:88-99` | 60/30/10 per min | No | **Read from compiled policy defaults** |
| 16 | Canary window + spike params | `ota_receiver.c:321` | 10min, 3 consecutive | No | Accept — compile-time for safety |
| 17 | MQTT keepalive | `mqtt_client.c:53` | 60 seconds | No | Accept — standard value |
| 18 | MQTT max backoff | `mqtt_client.c:872` | 5 minutes | No | Accept |
| 19 | Verdict response TTL | `bridge.go:598` | 60 minutes | No | Accept |
| 20 | IPC socket path | `main.c:12` | `/tmp/defenseclaw.sock` | Compile-time only | Add env var override |
| 21 | Default flash path | `hal_linux.c:17` | `/tmp/edge-connector-flash.bin` | `DCLAW_FLASH_PATH` env var | Fix default to `/var/lib/defenseclaw/` |
| 22 | Default broker URL | `config_store.c:222` | `mqtts://localhost:8883` | `DCLAW_BROKER_URL` env var | Fix to `mqtt://` since mqtts not implemented |

## Security Limitations

| # | Limitation | Location | Impact | Action |
|---|-----------|----------|--------|--------|
| 23 | **IPC has no peer credential verification** | `main.c` | Any local process can send requests | Wire `dclaw_ipc_verify_peer()` |
| 24 | **`hal_get_peer_cred()` Linux-only** | `hal_linux.c:111-113` | macOS IPC auth impossible | Phase-2 (macOS `LOCAL_PEERCRED`) |
| 25 | **Ed25519 degrades to HMAC-SHA256** without TweetNaCl | `ota_receiver.c:73-131` | Loses non-repudiation | Document — acceptable for Phase 1 |
| 26 | **Verdict HMAC covers only 8 bytes of tool_hash** | `verdict_protocol.c:97` | Reduced collision resistance | Extend to full 32 bytes |
| 27 | **Verdict HMAC truncated to 4 bytes** | `verdict_protocol.c:103` | 2^16 brute-force cost | Accept — constrained device tradeoff |
| 28 | **Dev-stub OTA signature** when PyNaCl unavailable | `policy_compiler.py:742-751` | Unsigned policies possible | Document + warn in compiler output |
| 29 | **Dev-mode audit key is deterministic** | `audit_ring.c:161-164` | Audit entries forgeable in dev mode | Accept — dev mode only |
| 30 | **Zero-key fallback for device key** in dev mode | `verdict_protocol.c:263`, `bridge.go:119` | Trivially forgeable HMACs | Accept — dev mode only |

## Operational / Resilience Limitations

| # | Limitation | Location | Impact | Action |
|---|-----------|----------|--------|--------|
| 31 | **Heartbeat counters wrap at 16 bits** | `cbor_codec.c:143-157` | Phantom reboot delta every 65K events | Use 32-bit counters |
| 32 | **`cache_hit_pct` always 0** in heartbeat | `cbor_codec.c:160` | Dashboard shows 0% forever | Compute from cache stats |
| 33 | **`audit_head_hmac` only 4 of 8 bytes** | `cbor_codec.c:170-174` | Incomplete chain verification from fleet | Copy all 8 bytes |
| 34 | **Emergency lockdown + no MQTT = permanently bricked** | `ota_receiver.c:462-483` | No local escape mechanism | Phase-2: add IPC emergency release |
| 35 | **Sync-block + failed MQTT = permanent denial** | `dclaw_core.c:362-368` | Intermittent connectivity → unnecessary blocks | Phase-2: add retry queue |
| 36 | **Pending verdict ring 16 slots, silent overwrite** | `mqtt_client.c:94` | High-throughput devices lose tracking | Log eviction + increase default |
| 37 | **Session eviction resets risk_score to 0** | `correlator.c:22-41` | Long-running attack sessions could evade detection | Phase-2: persist high-risk sessions |

## Functional Gaps

| # | Limitation | Location | Impact | Action |
|---|-----------|----------|--------|--------|
| 38 | **Tool capability map is compile-time only** | `policy_table.c:24-99` | New tools require recompilation | Phase-2: OTA tool mapping updates |
| 39 | **Warned/Escalated counters never accumulated** on fleet side | `manager.go:330-342` | Fleet dashboard missing warn/escalate data | Add accumulation |
| 40 | **Emergency gap detection never called** on reconnect | `ota_receiver.c:683-691` | Missed emergencies during disconnect undetected | Wire to reconnect handler |
| 41 | **`content_scope` not parsed from IPC** | `ipc_json.c` | Clients can't specify input/output/system | Add to parser |
| 42 | **`findings` in verdict request always 0** | `cbor_codec.c:261-262` | Cloud has no visibility into local scans | Populate from scan results |
| 43 | **Unregistered devices can submit verdict requests** | `bridge.go:559-637` | Minor — HMAC protects response integrity | Add registration check |

## Portability

| # | Limitation | Location | Impact | Action |
|---|-----------|----------|--------|--------|
| 44 | **`hal_get_peer_cred()` Linux-only** | `hal_linux.c:102-115` | `SO_PEERCRED` not on macOS | Phase-2: `LOCAL_PEERCRED` for macOS |
| 45 | **`hal_get_pid_start_time()` Linux-only** | `hal_linux.c:117-146` | `/proc/[pid]/stat` not on macOS | Phase-2: `sysctl` for macOS |

---

## What Can Be Fixed in This PR (20 items)

### Dead Code Removal (7)
Remove: `flash_safe.c`, `dclaw_report_result()`, `dclaw_check_destination()`, `dclaw_mqtt_subscribe()`, `dclaw_mqtt_disconnect()`. Wire `dclaw_policy_check_severity()` into evaluation pipeline. Wire `dclaw_ipc_verify_peer()` into IPC accept.

### Hardcoded Value Fixes (4)
- Rate limiters: read from `policy_tables.h` compiled defaults instead of hardcoded 60/30/10
- Default flash path: change from `/tmp/` to `/var/lib/defenseclaw/`
- Default broker URL: change from `mqtts://` to `mqtt://`
- IPC socket path: add `DCLAW_IPC_SOCKET_PATH` env var override

### Security Fixes (3)
- Wire `dclaw_ipc_verify_peer()` into `main.c` IPC accept loop
- Extend verdict HMAC to cover full 32-byte tool_hash
- Add compiler warning when PyNaCl unavailable (dev-stub signature)

### Operational Fixes (3)
- Compute `cache_hit_pct` from actual cache stats
- Copy full 8 bytes of `audit_head_hmac`
- Log pending verdict slot eviction

### Functional Fixes (3)
- Accumulate warned/escalated counters on fleet side
- Wire emergency gap detection to reconnect handler
- Add unregistered device check in verdict request handler

---

## What Stays for Phase 2 (25 items)

TLS/mTLS, destination denylist, custom regex patterns, device certificates, SSRF DFA tables, macOS peer credentials, macOS PID start time, 32-bit heartbeat counters, IPC emergency release for locked devices, sync-block retry queue, session persistence for high-risk, tool capability OTA updates, content_scope parsing, verdict request findings population.
