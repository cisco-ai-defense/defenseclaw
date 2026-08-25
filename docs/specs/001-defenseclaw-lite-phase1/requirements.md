# Requirements: DefenseClaw Lite — Phase 1 (STANDARD Profile)

## Context

DefenseClaw Lite extends AI agent security governance to resource-constrained IoT
and edge devices. Phase 1 delivers the core C-language enforcement agent (STANDARD
profile, ~80KB binary) running on Linux SBC hardware (Raspberry Pi 4, NVIDIA Jetson
Nano) with MQTT 5.0 cloud connectivity.

The agent provides sub-microsecond local policy enforcement while delegating complex
analysis (YARA, LLM judge, OPA) to the existing DefenseClaw cloud gateway via a
verdict request/response protocol. It is not a smaller gateway — it is a fast
enforcement point that executes pre-compiled decisions locally and escalates unknowns
to the cloud.

**Source of truth:** `docs/architecture/defenseclaw-lite-iot-proposal.md` (v1.2, approved)

**Actors:**
- IoT device AI agent runtime (untrusted — the thing being secured)
- Platform operator / SRE (fleet management, policy deployment, incident response)
- Security admin (policy authoring, audit review, threat intel)
- Cloud services (verdict cache, fleet manager, inspection pipeline)

**Constraints (co-equal):**
- Performance: <5μs local decisions, <500ms cloud verdicts (P95)
- Security: fail-closed on unknowns, IPC input validation, HMAC-verified verdicts
- Resources: ≤80KB binary (.text+.rodata), ≤25KB RAM (without bloom)

---

## EARS Requirements

### Functional — Decision Engine

- REQ-01: The system shall evaluate tool call requests against compiled policy tables
  and return ALLOW, BLOCK, WARN, or ESCALATE verdicts in <5 microseconds for local
  decisions.

- REQ-02: The system shall maintain a capability correlator (session FSM) tracking
  up to 16 concurrent sessions with 8-deep capability history per session.

- REQ-03: When a tool call's capability sequence matches a configured dangerous
  pattern (e.g., NET_FETCH→EXEC_SHELL), the system shall BLOCK the request and
  log the reason as CAP_SEQUENCE.

- REQ-04: The system shall maintain an LRU verdict cache of 64 entries storing
  cloud verdicts with per-action TTLs (ALLOW=24h, BLOCK=7d, WARN=4h).

- REQ-05: When the verdict cache contains a valid (non-expired) entry for a tool
  hash, the system shall return the cached verdict without cloud escalation.

- REQ-06: The system shall enforce destination allow/deny lists (up to 256 entries)
  for network tool calls, blocking requests to destinations not in the allow-list.

- REQ-07: The system shall enforce token-bucket rate limits with 3 independent
  limiters: global tool calls/min, network requests/min, actuations/min.

### Functional — Speculative Execution

- REQ-08: When a tool call requires cloud escalation and the capability is
  classified as speculative-allowed (NET_FETCH, SENSOR_READ, READ_FS, SEND_MSG),
  the system shall return a PENDING verdict allowing the agent to proceed.

- REQ-09: When a tool call requires cloud escalation and the capability is
  classified as sync_block (ACTUATE, EXEC_SHELL, WRITE_FS), the system shall
  block synchronously for up to 5 seconds awaiting the cloud verdict.

- REQ-10: If a cloud verdict returns BLOCK for a speculatively-allowed tool call,
  the system shall invoke the registered retroactive block callback and log the
  event with reason RETROACTIVE.

- REQ-11: If cap_flags in a tool request contains any sync_block capability bit,
  the system shall treat the entire request as sync_block regardless of other
  capability bits present (most-restrictive-wins rule).

### Functional — IPC Hook

- REQ-12: The system shall intercept tool calls from the AI agent runtime via a
  Unix domain socket accepting JSON-RPC formatted requests.

- REQ-13: The system shall verify IPC peer identity using SO_PEERCRED (UID/GID)
  plus /proc/{pid}/stat start_time to prevent PID recycling attacks.

- REQ-14: The system shall require a one-time 16-byte registration nonce from
  the agent runtime on first IPC connection, rejecting unregistered peers.

- REQ-15: The system shall reject any IPC payload exceeding 512 bytes, any
  tool_name containing non-ASCII characters (outside 0x20-0x7E), and any
  tool_hash not exactly 32 bytes.

- REQ-16: The system shall rate-limit IPC requests to 100/second, dropping
  excess requests with reason RATE_LIMIT.

### Functional — Audit Ring

- REQ-17: The system shall maintain a 256-entry HMAC-chained ring buffer of
  16-byte audit entries in flash storage.

- REQ-18: Each audit entry's 8-byte truncated HMAC-SHA256 shall cover the
  previous entry's HMAC, creating a tamper-evident chain.

- REQ-19: The system shall buffer WARN and sampled-ALLOW audit entries in a
  16-entry RAM coalescing buffer, flushing to flash every 60 seconds or when
  the buffer is full.

- REQ-20: When action is BLOCK, the system shall bypass the coalescing buffer
  and write directly to flash, ensuring BLOCK events survive power loss.

- REQ-21: The system shall track total flash write cycles and expose the count
  in the health status for fleet-level wear monitoring.

### Functional — MQTT Communication

- REQ-22: The system shall connect to MQTT 5.0 brokers using mTLS with X.509
  device certificates loaded from a secure element or protected flash.

- REQ-23: The system shall maintain a priority-ordered broker fallback list of
  up to 3 endpoints, trying each in order on disconnect with exponential backoff
  (1s, 2s, 4s...300s max).

- REQ-24: The system shall publish 32-byte CBOR heartbeats at configurable
  intervals (default 30s) containing device_id, counters, audit_head_hmac,
  and status flags.

- REQ-25: When the system receives a verdict response, it shall update the
  internal clock (dclaw_clock_t) from the server_ts field for TTL calculations.

- REQ-26: If time has never been synchronized (!time_trusted), the system shall
  treat all cached verdict TTLs as expired, forcing cloud re-escalation.

### Functional — Verdict Protocol Security

- REQ-27: The system shall verify a 4-byte truncated HMAC-SHA256 tag on every
  verdict response, computed as HMAC(session_key, request_id || action || tool_hash)
  where session_key = HKDF(device_key, mqtt_session_id).

- REQ-28: The system shall silently discard duplicate verdict responses for
  request_ids already marked as resolved in the 8-slot pending deduplication table.

- REQ-29: When a verdict response fails HMAC verification, the system shall
  discard it, log INVALID_INPUT, and treat the pending request as timed out
  (resulting in BLOCK for sync_block capabilities).

### Functional — Emergency Broadcast

- REQ-30: The system shall verify Ed25519 signatures on emergency broadcast
  messages using the pinned OTA CA public key before applying any command.

- REQ-31: The system shall reject emergency broadcasts with sequence ≤
  last_seen_emergency_seq (anti-replay) or sequence delta > 1000 (jump attack).

- REQ-32: On reconnect, if the cloud's current emergency sequence exceeds the
  device's last_seen_seq + 1, the system shall request replay of missed commands
  and operate in conservative mode (bloom hits = BLOCK) until replay completes.

### Functional — Policy OTA

- REQ-33: The system shall verify Ed25519 signatures on all policy OTA blobs
  before applying, rejecting any unsigned or incorrectly signed updates.

- REQ-34: The system shall use A/B flash partitions for policy storage, writing
  to the inactive partition and switching only after signature verification passes.

- REQ-35: After applying a new policy, the system shall enter a 10-minute canary
  window, auto-rolling back to the previous partition if block rate exceeds 5×
  baseline for 3 consecutive minutes.

- REQ-36: The system shall reject policy OTA blobs with version ≤ current
  policy_version (anti-rollback).

### Functional — Cloud Fleet Manager (Go Service)

- REQ-37: The cloud fleet manager shall register new devices on first MQTT
  connection, storing device_id, hw_profile, fw_version, policy_version, and
  capabilities.

- REQ-38: The fleet manager shall ingest heartbeats from all connected devices,
  computing fleet-wide metrics: online count, block rate, policy version
  distribution, and audit chain integrity.

- REQ-39: The fleet manager shall detect anomalies: device silent >3× heartbeat
  interval, block spike >5× baseline in 5 minutes, audit chain break.

- REQ-40: The fleet manager shall route verdict requests to the existing
  inspection pipeline (YARA + regex + OPA + LLM judge) for cache misses.

### Functional — Policy Compiler (Python Tool)

- REQ-41: The policy compiler shall parse DefenseClaw YAML policy files and
  generate both a C header (policy_tables.h) and a signed binary blob (policy.bin).

- REQ-42: The policy compiler shall expand capability sequence rules from the
  iot_extensions section into sorted C struct arrays with binary-search lookup.

- REQ-43: The policy compiler shall sign the binary blob with Ed25519 using the
  OTA Signing CA private key and embed a monotonic version counter.

- REQ-44: The policy compiler shall validate that generated output fits within
  the target profile's partition size, emitting a size report and failing if
  the output exceeds the limit.

### Non-Functional

- REQ-45: The agent binary (.text + .rodata) shall not exceed 80 KB for the
  STANDARD profile.

- REQ-46: The agent RAM footprint (stack + heap + static) shall not exceed
  25 KB (excluding optional bloom filter).

- REQ-47: Local policy table evaluation shall complete in <5 microseconds on
  ARM Cortex-A72 (Raspberry Pi 4) under worst-case conditions.

- REQ-48: Cloud verdict round-trip (device→cloud→device) shall complete in
  <500ms at P95 over a standard internet connection.

- REQ-49: The system shall continue full local enforcement when cloud
  connectivity is unavailable, blocking any tool/destination not in the local
  cache or policy tables (fail-closed).

- REQ-50: The system shall withstand 100,000 tool call evaluations per second
  for local (cached/policy) decisions without degradation.

- REQ-51: All string inputs from IPC shall be bounds-checked, ASCII-validated,
  and length-limited before processing; no use of strcpy, sprintf, or sscanf
  in the codebase.

- REQ-52: The implementation shall pass AFL++ fuzz testing (minimum 1M iterations)
  on the IPC parser before release.

---

## Acceptance Criteria

- AC-01: Agent blocks capability sequence [NET_FETCH, EXEC_SHELL] in <5μs
  on Raspberry Pi 4 (maps to REQ-01, REQ-03).

- AC-02: Unknown tool hash with cloud reachable returns verdict in <500ms P95;
  with cloud unreachable returns BLOCK in <10μs (maps to REQ-04, REQ-49).

- AC-03: BLOCK audit entries persist across immediate power-cycle (pull power
  during active tool calls, verify chain integrity on reboot) (maps to REQ-20).

- AC-04: Device successfully reconnects through 3-endpoint fallback list when
  primary broker is unreachable (maps to REQ-23).

- AC-05: Verdict response with invalid HMAC tag is silently discarded; tool call
  results in BLOCK (maps to REQ-27, REQ-29).

- AC-06: Emergency broadcast with invalid Ed25519 signature or replayed sequence
  number is rejected (maps to REQ-30, REQ-31).

- AC-07: Policy OTA with canary spike triggers auto-rollback within 3 minutes,
  device resumes on previous policy version (maps to REQ-35).

- AC-08: IPC payload of 513 bytes is rejected; tool_name with byte 0x80 is
  rejected; all-zero tool_hash triggers escalation (maps to REQ-15).

- AC-09: Speculative execution for NET_FETCH returns PENDING in <10μs; retroactive
  BLOCK callback fires within 1ms of cloud response arrival (maps to REQ-08, REQ-10).

- AC-10: Policy compiler rejects policy that generates >4096B binary for STANDARD
  target, emitting size report with per-component breakdown (maps to REQ-44).

- AC-11: Heartbeats aggregate correctly in fleet dashboard; device offline >90s
  triggers DeviceOffline alert (maps to REQ-38, REQ-39).

- AC-12: Binary size measured at <80KB (.text+.rodata), RAM at <25KB (maps to
  REQ-45, REQ-46).

---

## Traceability

| REQ | Architecture Section | Acceptance Criteria |
|-----|---------------------|---------------------|
| REQ-01 | Proposal §6.1 (Decision Engine) | AC-01 |
| REQ-02 | Proposal §6.1 (Session State) | AC-01 |
| REQ-03 | Proposal §6.1 (Policy Tables) | AC-01 |
| REQ-04..05 | Proposal §6.2 (Verdict Cache) | AC-02 |
| REQ-06 | Proposal §3 (Component Mapping) | AC-02 |
| REQ-07 | Proposal §6.1 (Rate Limiter) | AC-08 |
| REQ-08..11 | Proposal §6.1 (Speculative Execution) | AC-09 |
| REQ-12..16 | Proposal §8.4 (Input Validation) | AC-08 |
| REQ-17..21 | Proposal §6.1 (Audit Write Coalescing) | AC-03 |
| REQ-22..26 | Proposal §7.1, §7.2, §5.4 | AC-04, AC-12 |
| REQ-27..29 | Proposal §7.2 (Verdict Response) | AC-05 |
| REQ-30..32 | Proposal §7.2 (Emergency Broadcast) | AC-06 |
| REQ-33..36 | Proposal §9.3 (OTA Policy Update) | AC-07 |
| REQ-37..40 | Proposal §6.2 (Fleet Manager) | AC-11 |
| REQ-41..44 | Proposal §6.2 (Policy Compiler) | AC-10 |
| REQ-45..52 | Proposal §1, Appendix E | AC-12, AC-08 |
