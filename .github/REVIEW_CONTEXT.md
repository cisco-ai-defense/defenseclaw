# Review Context for DefenseClaw Edge Connector

This document prevents AI and human reviewers from re-flagging intentional
design decisions. Reference this file in every review prompt.

## Intentional Design Decisions (Do NOT Flag)

### Wire Format
- **16-bit heartbeat counters**: CBOR wire format uses uint16 for denied/allowed/warned/escalated counts. Internal counters are uint32. Truncation is intentional for IoT bandwidth.
- **16-byte audit HMAC**: Audit entries are fixed 32-byte records for flash storage. HMAC-SHA256 truncated to 128 bits per NIST SP 800-107. Was expanded from 4 to 16 bytes.
- **No protocol version field**: Backward compatibility uses optional trailing CBOR fields. Version negotiation is Phase 2 scope.

### Security Architecture
- **DCLAW_DEV_MODE**: Defaults to OFF in CMakeLists.txt. CI builds STANDARD profile (OFF). The build/ directory may contain ON from local dev builds — this is expected.
- **Zero-key fallback in dev mode**: Allowed in dev mode only. Production mode (DCLAW_PRODUCTION=true or DCLAW_DEV_MODE=OFF) rejects zero keys at compile time and runtime.
- **HMAC-SHA256 for OTA** (when Ed25519 unavailable): Accepted only with explicit DCLAW_ALLOW_HMAC_OTA compile flag. Production builds without TweetNaCl reject HMAC-only OTA.
- **Emergency key fallback to OTA key**: Dev mode only. Production requires separate DCLAW_EMERGENCY_KEY.

### CLI Conventions
- **DEFENSECLAW_HOME**: Project-wide convention used in 31+ places across the entire codebase. Not a path traversal vulnerability — CLI runs with user permissions locally.
- **subprocess with list args**: All subprocess calls use list form (never shell=True). This is the established pattern.

### MQTT Architecture
- **Emergency broadcast to tenant=0/fleet=0**: Known limitation — devices subscribe to specific fleet topics. Fleet-wide broadcast requires iterating known tenants. Tracked for Phase 2.
- **Application-level ACL check**: Depends on MQTT broker-level ACLs (Mosquitto). The bridge-level AuthorizePublish is defense-in-depth.
- **`strstr` topic routing in C daemon**: Uses substring matching for `verdict/resp`, `ota/policy`, `ota/emergency`. Mitigated by broker ACLs and device-side subscriptions (device only receives messages on exact subscribed topics). Suffix matching is Phase 2.

### Heartbeat Flags
- **TAMPER_DETECT (0x04) and SE_DEGRADED (0x80) not set by C encoder**: The C daemon does not yet track audit chain integrity or secure element status at runtime. The Go fleet manager has handlers for these flags ready for Phase 2. Currently only 0x02 (POLICY_STALE), 0x08 (CANARY_ROLLBACK), and 0x20 (OFFLINE_MODE) are active.

### Fleet Operational Limits
- **Emergency sequence anti-replay gap of 10**: Hardcoded in `ota_receiver.c`. A device that misses >10 emergency commands rejects subsequent ones until reboot. Making this configurable is Phase 2.
- **Threat-intel deny hashes are in-memory only**: Pushed via the fleet API at runtime, not included in OTA policy blobs. Lost on device reboot. Flash persistence for deny hashes is Phase 2.

### Embedded Constraints
- **Single-threaded C daemon**: All state access from main event loop. No threading concerns. Signal handler only sets volatile sig_atomic_t.
- **Static buffers**: Used intentionally to avoid heap allocation on constrained devices.
- **Flash layout**: Emergency state (0-15), partition B (16-23), partition A (24-31) — tightly packed, non-overlapping.

## How to Review This Codebase

1. **Review incremental diffs** — not the full branch diff against main
2. **Check commit messages** for fix rationale — it's not in inline comments
3. **Don't flag design trade-offs** listed above as vulnerabilities
4. **Focus on**: new code correctness, API contracts, concurrency, input validation at system boundaries
