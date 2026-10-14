# DefenseClaw Lite Phase 1 — Release Readiness Review

**Date**: 2026-10-12  
**Branch**: `feature/defenseclaw-lite-phase1`  
**Scope**: 174 files, ~57,600 lines added (C, Go, Python)  
**Verdict**: **NOT RELEASE READY** — 4 BLOCKERs, 7 CRITICALs, 17 HIGHs remaining

---

## Test Results Summary

| Suite | Result | Notes |
|-------|--------|-------|
| Go fleet tests (all packages) | **54/54 PASS** | Race detector clean |
| Go gateway tests | **PASS** | All notifier tests pass |
| Go vet | **CLEAN** | No warnings |
| Python edge-connector tests | **54/54 PASS** | generic_hook + mcp_proxy |
| Python CLI tests (policy) | **42/42 PASS** | Full lifecycle |
| Python CLI tests (status) | **53/53 PASS** | Multi-connector |
| C edge-connector build | **FAIL** | mbedTLS 4.x incompatibility |

---

## BLOCKER Findings (Must Fix Before Release)

### BLK-1: C Build Fails on mbedTLS 4.x — `entropy.h` Removed + HMAC API Mismatch
- **Files**: `edge-connector/CMakeLists.txt:211`, `edge-connector/src/comms/tls_engine.c:26`, `edge-connector/src/comms/mqtt_client.c:570-802`, `edge-connector/src/comms/verdict_protocol.c:66-111`, `edge-connector/src/persist/audit_ring.c:221-223`
- **Description**: `find_package(MbedTLS 3 QUIET)` fails on mbedTLS 4.x (current Homebrew). The fallback `find_library` path finds the library but misses include directories for `tls_engine.c`. Additionally, `mbedtls_md_hmac_starts/update/finish` calls produce "undeclared function" errors across 3 source files (27 call sites).
- **Impact**: The edge-connector binary cannot be built on any system with mbedTLS 4.x. CI will fail.
- **Fix**: Update CMake to `find_package(MbedTLS 3..4 QUIET)`, add mbedTLS 4.x include path detection, and ensure the HMAC API declarations are resolved (they exist in mbedtls 4.x `md.h` but the include path is missing).

### BLK-2: Go Fleet Server HMAC Signing Incompatible with C Production OTA Verification
- **Files**: `internal/fleet/policy/signer.go:88-91` (HMAC-SHA256 only), `edge-connector/src/comms/ota_receiver.c:89-97` and `149-157` (rejects HMAC in production)
- **Description**: The Go fleet server signs OTA policy blobs with HMAC-SHA256. The C edge-connector in production mode (`DCLAW_DEV_MODE=OFF`) unconditionally rejects HMAC-SHA256 verification and requires Ed25519 (TweetNaCl). No Ed25519 signing implementation exists on the Go side. **OTA policy distribution is non-functional in production.**
- **Impact**: The fleet server cannot push policy updates or emergency commands to production edge devices. This breaks the core fleet management value proposition.
- **Fix**: Either (a) implement Ed25519 signing in Go `signer.go`, or (b) add a build flag `DCLAW_ALLOW_HMAC_OTA=1` that permits HMAC verification in production when explicitly opted in.

### BLK-3: Token Rotation Leaves Old Token Valid in `tenantScopes` Map
- **Files**: `internal/fleet/api.go:1201-1218` (rotateToken), `internal/fleet/api.go:247-263` (authMiddleware)
- **Description**: `rotateToken()` updates `a.currentToken` via atomic store but does NOT remove the old admin token from the `tenantScopes` map. The `authMiddleware` checks `tenantScopes` first (line 258), so the old token remains valid indefinitely after rotation.
- **Impact**: Token rotation provides a false sense of security. A compromised pre-rotation token retains full admin access.
- **Fix**: In `rotateToken()`, delete the old token from `tenantScopes` and insert the new token with `tenant_id=0`. Use a `sync.RWMutex` to protect concurrent map access.

### BLK-4: `handleIncomingPublish` Only Dispatches to First Matching Subscription
- **Files**: `internal/fleet/mqtt/tcp_client.go:562-571`
- **Description**: When iterating `c.subs` and finding a match, the handler releases the RLock and returns after calling the first matched handler. Go map iteration is non-deterministic, so if multiple topic filters match, messages are randomly routed to incorrect handlers.
- **Impact**: While current topic patterns are non-overlapping, this is a correctness hazard that would cause silent message loss if patterns ever overlap.
- **Fix**: Collect all matching handlers under the read lock, release the lock, then invoke them all.

---

## CRITICAL Findings

### CRT-1: Missing Tenant Authorization on Emergency/Policy/Threat-Intel Endpoints
- **Files**: `internal/fleet/api.go:900-978` (pushEmergency), `780-898` (pushPolicy/listPolicyVersions), `980-1047` (pushThreatIntel)
- **Description**: These endpoints accept `tenant_id`/`fleet_id` in the request body but never check `tenantFromRequest(r)` against them. A tenant-scoped token can push BLOCK_ALL/ENTER_LOCKDOWN commands to ANY tenant's fleet, push malicious policies to other tenants' devices, or flush the global verdict cache.
- **Impact**: Cross-tenant denial of service and policy tampering.
- **Fix**: Add `authorizedForDevice(r, tenantID)` checks to all three endpoints.

### CRT-2: SSRF Protection Bypass via DNS Rebinding in MCP Proxy
- **Files**: `edge-connector/tools/mcp_proxy.py:70-93`
- **Description**: `_validate_upstream_url()` checks if a hostname resolves to a private IP at config time only. The aiohttp session resolves DNS lazily per-request. An attacker controlling DNS could point a hostname to a public IP during config, then switch to `169.254.169.254` after the proxy starts.
- **Fix**: Use a custom aiohttp connector that validates resolved IPs at request time.

### CRT-3: SSRF Bypass via Backslash in URL
- **Confirmed by testing**: `http://127.0.0.1\@evil.com` parses as hostname `evil.com` in Python's `urlparse()`.
- **Description**: The SSRF validation in `generic_hook.py` does not normalize backslash-based URL authority bypasses.
- **Fix**: Reject URLs containing `\` in the authority component.

### CRT-4: Policy Compiler symlink bypass in Go `validateCompilerPath`
- **Files**: `internal/fleet/policy/policy.go:236`
- **Description**: `isUnderAllowedDir` checks path prefixes after `filepath.Abs()` but does NOT resolve symlinks. A symlink at `$HOME/.defenseclaw/evil -> /tmp/malicious.py` would pass the prefix check.
- **Fix**: Use `filepath.EvalSymlinks()` before the prefix check.

### CRT-5: Fail-Open Mode Activatable via Environment Variable
- **Files**: `edge-connector/tools/generic_hook.py:430-432`
- **Description**: `DCLAW_FAIL_OPEN=1` bypasses all policy enforcement for 5 minutes / 1000 calls. An LLM agent with filesystem access could write this to a `.env` file.
- **Fix**: Require a signed attestation token when fail-open is activated.

### CRT-6: Emergency Commands Also Blocked in Production (Same as BLK-2)
- **Files**: `internal/fleet/policy/policy.go:509`, `edge-connector/src/comms/ota_receiver.c:555-564`
- **Description**: Emergency commands are signed with HMAC by the Go side. The C side's `verify_emergency_signature()` calls `verify_ed25519()` which rejects HMAC in production. Emergency BLOCK_ALL/LOCKDOWN commands cannot reach production devices.

### CRT-7: `tenantScopes` Map Concurrent Read/Write Race (Latent)
- **Files**: `internal/fleet/api.go:70-74`, `247-284`
- **Description**: The `tenantScopes` map is a plain `map[string]uint16` shared across goroutines with no synchronization. Currently write-only at startup, but fixing BLK-3 requires writes at runtime, which would cause data races.
- **Fix**: Replace with `sync.Map` or protect with `sync.RWMutex`.

---

## HIGH Findings

### HIGH-1: WaitGroup Panic on Shutdown Under Load
- **Files**: `internal/fleet/mqtt/bridge.go:470-473`, `586-589`, `705-708`
- **Description**: Race between `stopping.Load()` and `wg.Add(1)`. Under high message rate during shutdown, `wg.Wait()` could run between these, causing a negative counter panic.

### HIGH-2: Case-Sensitive Hostname Matching in C Destination Allowlist
- **Files**: `edge-connector/src/decision/policy_table.c:274-293`
- **Description**: Uses `strcmp()` for hostname matching. DNS is case-insensitive (RFC 4343). `API.OPENAI.COM` would be blocked despite `api.openai.com` being allowed.

### HIGH-3: Double-Close of TCP FD After Failed TLS Handshake
- **Files**: `edge-connector/src/comms/mqtt_client.c:471-476`
- **Description**: `dclaw_tls_shutdown()` closes the fd via `mbedtls_net_free()`, then line 475 closes it again. UB; could close an unrelated fd.

### HIGH-4: No Deny Hash OTA Distribution
- **Files**: `edge-connector/src/comms/ota_receiver.c:754-759`, `edge-connector/tools/policy_compiler.py:565-571`
- **Description**: The OTA binary format does not include deny hash lists. Operators cannot block specific tool hashes fleet-wide without a firmware reflash.

### HIGH-5: HTTP Middleware Does Not Scan Response Direction
- **Files**: `edge-connector/tools/http_middleware.py:116-183`
- **Description**: Only intercepts POST requests in the "request" direction. Tool responses (containing potential prompt injection, credential exfiltration) flow back unscanned.

### HIGH-6: MCP Proxy Does Not Scan Tool Response Content
- **Files**: `edge-connector/tools/mcp_proxy.py:494`
- **Description**: When a tool call is allowed, the upstream response is forwarded without content scanning. An adversarial MCP server could return poisoned data.

### HIGH-7: Policy Compiler C Comment Injection
- **Files**: `edge-connector/tools/policy_compiler.py:661`
- **Description**: Pattern strings emitted as C comments (`/* "{pat}" */`). If a pattern contains `*/`, it prematurely closes the comment and could inject C code. Currently all patterns are hardcoded literals, but external policy loading would make this exploitable.

### HIGH-8: `_validate_output_path` Allows Absolute Paths
- **Files**: `edge-connector/tools/policy_compiler.py:937-940`
- **Description**: Path traversal check `if ".." in os.path.normpath(path)` misses absolute paths like `/etc/cron.d/malicious`. 

### HIGH-9: Session ID Map Unbounded Growth in picoclaw_hook.py
- **Files**: `edge-connector/tools/picoclaw_hook.py:350-355`
- **Description**: `_session_map` grows without bound — OOM risk under adversarial load.

### HIGH-10: Integration Adapters Default to Plaintext HTTP
- **Files**: `edge-connector/integrations/bubbaloop/defenseclaw_bubbaloop.py:191`, `espclaw/defenseclaw_espclaw.py:123`, `homeassistant/defenseclaw_ha.py:178`
- **Description**: `requests.post()` uses `http://` by default for non-loopback connections.

### HIGH-11: Device Registration Key Delivery Failure Leaves Unrecoverable State
- **Files**: `internal/fleet/api.go:584-597`
- **Description**: Registration saves the key before checking TLS. If TLS check fails (HTTP 403), the device is registered but the operator never receives the key.

### HIGH-12: 2-Byte Audit Target Hash Has High Collision Probability
- **Files**: `edge-connector/include/defenseclaw.h:157`, `edge-connector/src/dclaw_core.c:228`
- **Description**: `target_hash` is only `uint16_t` (65536 values). An attacker can choose a tool name whose first 2 SHA-256 bytes collide with a benign tool, making malicious audit entries indistinguishable.

### HIGH-13: Verdict Replay in Dev Mode with Zero Boot Nonce
- **Files**: `edge-connector/src/dclaw_core.c:69-89`
- **Description**: When `hal_random_bytes()` fails in dev mode, boot_nonce is all zeros. Verdicts captured in one session can be replayed in another.

### HIGH-14: `ProcessHeartbeat` Auto-Register Holds Shard Lock During SQLite Write
- **Files**: `internal/fleet/manager/manager.go:333-357`
- **Description**: Store writes under shard lock; a slow SQLite operation blocks all heartbeats for 1/256 of devices.

### HIGH-15: Device Status Not Validated on SQLite Load
- **Files**: `internal/fleet/store_sqlite.go:396`
- **Description**: Arbitrary status strings from a tampered DB are loaded without validation.

### HIGH-16: Metrics Gauge Drift on Device Registration
- **Files**: `internal/fleet/metrics.go:108-109`
- **Description**: `DevicesOnline` may not accurately reflect reality after device churn. No periodic reconciliation.

### HIGH-17: MCP Proxy Method Normalization — Original Case Forwarded to Upstream
- **Files**: `edge-connector/tools/mcp_proxy.py:398-404`
- **Description**: Method is lowercased for security check but forwarded as-is. Semantic mismatch possible if upstream is case-insensitive.

---

## MEDIUM Findings (16 total)

| ID | File | Issue |
|----|------|-------|
| MED-1 | `verdict_protocol.c:61-113` | mbedTLS HMAC path doesn't zero intermediate state |
| MED-2 | `content_scanner.c:698` | `parse_ipv4` edge cases in octal parsing |
| MED-3 | `ota_receiver.c:577` | Emergency `scope` field parsed but ignored |
| MED-4 | `hal_linux.c:112` | `strtoul` without overflow check on IPC UID/GID |
| MED-5 | `mqtt_client.c:737` | Heartbeat HMAC silently drops on oversized topic |
| MED-6 | `audit_ring.c:226` | Audit HMAC truncated to 16 bytes (vs 32 for verdicts) |
| MED-7 | `api.go:1373` | `sanitizeString` truncates by byte, splits UTF-8 |
| MED-8 | `api.go:1084` | `decommissionBatch` doesn't report partial completion |
| MED-9 | `policy.go:564` | Policy version increment not atomic with store |
| MED-10 | `tcp_client.go:474` | `reconnectLoop` can spawn unbounded goroutines |
| MED-11 | `policy.go:429` | uint64 tenant_id in topic vs uint16 in ParseTopic |
| MED-12 | Multiple Go files | `isProductionMode()` duplicated in 3 locations |
| MED-13 | `verdict/cache.go:195` | `FlushAll` eviction callbacks outside lock cause metrics drift |
| MED-14 | `generic_hook.py:47-68` | Loopback check uses string allowlist, not `is_loopback` |
| MED-15 | `mcp_proxy.py:628-655` | Rate limiter memory growth under distributed attack |
| MED-16 | Multiple `.env` parsers | Naive `.env` parsing doesn't handle edge cases |

---

## LOW Findings (12 total)

| ID | File | Issue |
|----|------|-------|
| LOW-1 | `ipc_json.c:23` | `parse_string` scans past max_len (bounded by IPC max) |
| LOW-2 | `mqtt_client.c:148` | `dclaw_paho_read` masks poll() errors as timeouts |
| LOW-3 | `mqtt_client.c:85` | `pending_ring_next` is uint8_t; needs static assert |
| LOW-4 | `content_scanner.c:209` | Email/phone PII patterns have false positives |
| LOW-5 | `api.go:1420` | `writeJSON` swallows encode errors |
| LOW-6 | `broker.go:91` | Deprecated warning logs on every legacy client message |
| LOW-7 | `store_sqlite.go:235` | `parsePolicyRow` returns nil,nil for not-found |
| LOW-8 | `policy.go:456` | Emergency seq not multi-instance safe (single-process only) |
| LOW-9 | `store_sqlite.go:257` | Device keys stored as hex without encryption at rest |
| LOW-10 | `routing/manager.go:57` | `pip install` without `--require-hashes` |
| LOW-11 | `picoclaw_hook.py:651` | Logs exact payload lengths (inference side-channel) |
| LOW-12 | `cmd_edge_install.py:53` | `_run()` echoes full commands to terminal |

---

## Positive Security Findings

These areas are well-implemented and should be preserved:

1. **Constant-time HMAC comparison**: `ct_compare()` uses volatile XOR accumulation — correct. Go uses `subtle.ConstantTimeCompare`. Python uses `hmac.compare_digest`.
2. **Anti-rollback protection**: OTA rejects `version <= current` (ota_receiver.c:311).
3. **SSRF validation breadth**: Handles octal IPs, IPv6 mapped, URL encoding, DNS rebinding (at startup), decimal IPs, hex IPs. Missing only backslash bypass.
4. **Content scanner**: Aho-Corasick DFA with O(n) single-pass — no ReDoS risk.
5. **IPC JSON parser**: Depth-limited (8), size-limited, NUL-validated, handles escape sequences correctly.
6. **OTA signature verification**: Ed25519 with no-key-rejection, zero-key-rejection, flash sync + read-back.
7. **YAML loading**: `yaml.safe_load()` everywhere — no unsafe deserialization.
8. **Subprocess usage**: No `shell=True`, proper `shlex.quote()`, stdin-based secret passing.
9. **SQL injection**: All Go SQLite queries use parameterized statements — no string concatenation.
10. **Audit ring**: Flash-backed with HMAC chain integrity, bounded by static assertions.

---

## Recommended Fix Priority

### Before Release (BLOCKERs + Critical CRT-1)
1. **BLK-1**: Fix CMake for mbedTLS 4.x compatibility
2. **BLK-2 + CRT-6**: Implement Ed25519 signing in Go OR add HMAC production opt-in flag
3. **BLK-3 + CRT-7**: Fix token rotation to invalidate old token, add sync.RWMutex
4. **BLK-4**: Fix subscription dispatch to invoke all matching handlers
5. **CRT-1**: Add tenant authorization to emergency/policy/threat-intel endpoints

### Before Production Deployment
6. **CRT-2 + CRT-3**: Fix SSRF DNS rebinding + backslash bypass
7. **CRT-4**: Resolve symlinks in compiler path validation
8. **CRT-5**: Add signed attestation for fail-open mode
9. **HIGH-1**: Fix WaitGroup race on shutdown
10. **HIGH-2**: Use `strcasecmp()` for hostname matching
11. **HIGH-3**: Fix double-close of TCP fd
12. **HIGH-5 + HIGH-6**: Add response-direction content scanning

### Phase 2 Improvements
13. **HIGH-4**: Add deny hash support to OTA format
14. **HIGH-12**: Widen audit target_hash to 32+ bits
15. **MED-9**: Atomic policy version increment
16. **LOW-9**: Encrypt device keys at rest

---

## Review Methodology

- **4 parallel review agents**: C security, Go concurrency/auth, Python SSRF/injection, 2nd-order cross-layer behavioral
- **Real test execution**: Go (race detector), Python (pytest), C (cmake build)
- **Manual verification**: All BLOCKERs and CRITICALs confirmed by reading source
- **SSRF bypass testing**: Automated testing of 8 bypass vectors against validation functions
- **Policy compiler injection testing**: Tested escape_c_string, validate_destination, _validate_output_path
- **Cross-layer dataflow tracing**: 6 critical flows traced end-to-end (policy, verdict, OTA, interception, registration, audit)
