# DefenseClaw Lite Phase 1 — Patent Filing Analysis

> **CONFIDENTIAL — ATTORNEY-CLIENT PRIVILEGED**
>
> This document contains patent strategy analysis. Do not distribute
> outside the patent filing team. Do not commit to version control.

**Date:** 2026-10-14
**PR:** #678 (feature/defenseclaw-lite-phase1)
**Analyst:** AI-assisted review of full PR codebase, prior art, and market landscape

---

## Executive Summary

This PR implements a first-of-its-kind system: **AI agent security guardrails
running directly on IoT/edge devices**, managed as a fleet from the cloud. No
commercial product currently combines on-device AI guardrail enforcement + IoT
fleet management + embedded-class hardware support.

We identified **12 potentially patentable inventions**, of which **5 are Tier 1**
(strong novelty, high commercial value, defensible claims) and **7 are Tier 2**
(novel combinations, defensive portfolio).

---

## Market Context

| Segment | Current | 2031 Forecast |
|---|---|---|
| IoT Security | $24.2B | $80.3B (18.7% CAGR) |
| AI Security/TRiSM | ~$2-4B | ~$10-15B (~30% CAGR) |
| **AI + IoT + Edge intersection** | **$0 — no products exist** | **Greenfield** |

### Key Market Gap

Every AI guardrail vendor (Cisco AI Defense, Palo Alto AIRS, Lakera, CalypsoAI)
enforces in the cloud or at the network perimeter. Every IoT security vendor
(Armis, Claroty, Forescout) monitors the network, not what AI agents on devices
do. **Nobody runs guardrails on the device itself.**

### Regulatory Tailwinds

- **EU AI Act Annex I** (Aug 2028): Mandates risk assessment and logging for AI
  in regulated products (machinery, medical, toys). On-device enforcement with
  signed OTA policies and tamper-evident audit logs maps directly.
- **NIST AI RMF**: Requires enforceable controls at the point of execution.
- **US Executive Orders on AI Safety**: Push for AI red-teaming and risk
  management across federal supply chains including defense and critical
  infrastructure IoT.
- **AI Kill Switch Act 2026 / California EO N-9-26**: Creates demand for
  cryptographically authenticated emergency lockdown mechanisms.

### Competitive Landscape

| Player | Focus | On-Device? | AI Guardrails? | Fleet Mgmt? |
|---|---|---|---|---|
| Cisco AI Defense | Network-level guardrails | No | Yes | No |
| Palo Alto AIRS | Cloud AI security lifecycle | No | Yes | No |
| Lakera Guard | Cloud API for prompt injection | No | Yes | No |
| CalypsoAI | Enterprise AI security | On-prem only | Yes | No |
| Armis | Agentless IoT discovery | No | No | Partial |
| Claroty / Nozomi | OT network visibility | No | No | Partial |
| Forescout | Device classification | No | No | Partial |
| Microsoft Defender IoT | Azure OT monitoring | No | No | Partial |
| CrowdStrike Falcon IoT | Endpoint detection | Agent (x86) | No | Yes |
| **DefenseClaw Lite** | **Edge AI guardrails** | **Yes (80KB, <5us)** | **Yes** | **Yes** |

---

## Prior Art Landscape

### Existing Patents by Area

**IoT Fleet Management with MQTT:**
- US12489767B2 (ZTE, 2021) — MQTT topic randomization for secure device comms
- US10581875B2 (Afero, 2016) — IoT PKI, ECDH key exchange, counter replay prevention
- EP4409944A1 (Palo Alto, 2022) — IoT firewall policy with ML device classification

**OTA Updates:**
- US20250322072A1 (Micron, 2025) — Secure firmware updates with dual-nonce HMAC
- US20250272405A1 (Changzhou, 2024) — Vehicle OTA with Merkle tree verification

**Audit Chain:**
- US12706763B2 (Micro Focus, 2023) — Hash-chain audit with quantum-resistant tokenization

**AI Guardrails:**
- NVIDIA NeMo Guardrails, Guardrails AI — cloud-side only, no edge patents found

**Emergency Lockdown:**
- No specific patents found. Legislative activity (AI Kill Switch Act) but no
  technical patents for the IoT fleet lockdown protocol.

### Confirmed Gaps (Our Opportunity)

1. **Edge AI guardrails for tool-call interception** — No prior art whatsoever
2. **Emergency lockdown broadcast with crypto auth on IoT** — No prior art
3. **HMAC-chained audit logs on embedded flash ring buffers** — No prior art
4. **Policy-only OTA with A/B partitions and canary rollback** — Firmware OTA
   patented; policy-blob OTA is not
5. **Security verdict caching with TTL on constrained devices** — General
   caching exists; security-verdict-specific for embedded does not
6. **Capability-sequence correlation for AI agent behavioral anomaly** — IDS
   patents exist for network packets; none for AI agent tool-call sequences

---

## Tier 1 Patent Candidates (File Immediately)

### Patent 1: Speculative Execution with Retroactive Revocation for AI Agent Tool Calls

**Problem:** Edge devices running AI agents need sub-millisecond tool execution
but cloud-level policy approval introduces unacceptable latency.

**Novel Mechanism:** The device speculatively allows low-risk tool calls
(classified by a per-capability `escalation_table`) while asynchronously
requesting cloud verdicts over MQTT. If the cloud returns BLOCK, a retroactive
callback (`dclaw_retroactive_block_fn`) revokes the already-allowed action. A
per-capability `mode` flag (0=sync_block, 1=speculative) controls which tools
proceed immediately versus which must wait.

**Why Patentable:** Standard practice is either block-until-approved or
fire-and-forget. The retroactive revocation pattern with per-capability
escalation modes in an embedded security daemon is a novel composition. No
existing patent covers speculative security execution with callback-based
revocation for AI agent tool calls.

**Prior Art Gap:** WIDE OPEN — cloud guardrails exist but no on-device
speculative execution patent found.

**Commercial Value:** Very high — this is the core latency innovation that makes
on-device AI guardrails practical on constrained hardware.

**Implementation:** `dclaw_core.c:452-463, 158-164`, `verdict_protocol.c:460-467`

**Suggested Claims:**
1. System claim: An embedded security device comprising a processor executing
   a speculative policy evaluation engine that allows a tool call from an AI
   agent based on a local capability classification while asynchronously
   transmitting a verdict request to a remote policy server, and upon receiving
   a block verdict, invoking a retroactive revocation callback.
2. Method claim: A method for low-latency security enforcement on AI agent
   tool calls comprising: classifying the tool call by capability flags;
   determining a speculative-vs-synchronous mode; if speculative, allowing
   execution and queuing an async verdict request; receiving a remote verdict;
   if the remote verdict is block, invoking a retroactive revocation.
3. Apparatus claim: A resource-constrained computing device with firmware
   implementing the above.

---

### Patent 2: Capability-Sequence Correlation for AI Agent Behavioral Anomaly Detection

**Problem:** Individual tool calls may be benign, but specific sequences
(e.g., read-filesystem then send-network) indicate data exfiltration.

**Novel Mechanism:** A per-session circular buffer records capability flags for
each tool invocation. Policy-defined sequence rules (compiled at build time +
runtime-updatable via OTA) are matched against the tail of the history using a
sliding window. Matching sequences escalate action severity. A cumulative
`risk_score` per session increases on each BLOCK/WARN, providing progressive
threat assessment across the session lifetime.

**Why Patentable:** Encoding multi-step attack patterns as capability-flag
sequences and matching them in O(rules x seq_len) on constrained hardware,
combined with cumulative risk scoring, is a novel behavioral IDS approach for
AI agent security. Existing IDS patents focus on network packet sequences, not
AI agent tool-call sequences.

**Prior Art Gap:** WIDE OPEN — network IDS sequence patents exist but none for
AI agent tool-call capability sequences.

**Commercial Value:** Very high — detects attack patterns that per-call scanning
misses entirely. Unique security differentiation.

**Implementation:** `correlator.c` (entire file), `defenseclaw.h:199-207`

**Suggested Claims:**
1. A system for detecting multi-step attack patterns in AI agent tool
   invocations comprising: maintaining a per-session circular buffer of
   capability flags; matching the buffer against a set of sequence rules
   defining prohibited capability-flag orderings; escalating the security
   action when a match is found; and accumulating a risk score across
   the session.
2. A method for behavioral anomaly detection in an AI agent executing on an
   edge device, the method comprising recording capability classifications of
   sequential tool calls and pattern-matching against attack sequence
   definitions.

---

### Patent 3: Canary-Window Auto-Rollback for OTA Security Policy Updates

**Problem:** A malicious or buggy OTA policy update could cause a device to
over-block legitimate traffic, with no operator present to intervene.

**Novel Mechanism:** After applying a new policy via A/B flash partition write,
the device enters a configurable canary window. It tracks per-minute block
counts against a baseline embedded in the policy blob header itself — each
policy version defines its own acceptable block rate. If blocks exceed
`baseline * SPIKE_MULT` for N consecutive minutes, the device automatically
rolls back to the previous partition's policy, reinitializes tables, flushes
the verdict cache, and sets `rollback_pending` reported in heartbeats.

**Why Patentable:** The self-contained canary baseline embedded in the policy
binary (not configured separately) combined with automatic A/B partition
rollback is novel. Standard OTA systems use external watchdogs or
cloud-initiated rollback, not policy-defined acceptance criteria. Firmware OTA
with A/B partitions is patented (Micron US20250322072A1); policy-only OTA with
embedded canary criteria is not.

**Prior Art Gap:** Firmware OTA patented; policy-blob OTA with self-defined
canary baselines is OPEN.

**Commercial Value:** High — addresses a real deployment risk. Directly maps to
EU AI Act continuous monitoring requirements.

**Implementation:** `ota_receiver.c:365-413, 290-378, 426-459`

**Suggested Claims:**
1. A method for self-healing policy deployment on an embedded security device
   comprising: receiving a signed policy blob containing enforcement rules and
   a canary baseline metric; writing the blob to an inactive flash partition;
   activating the new partition; monitoring enforcement actions against the
   embedded baseline during a canary window; and automatically reverting to
   the previous partition when the monitored actions exceed the baseline.

---

### Patent 4: HMAC-Chained Tamper-Evident Audit Ring Buffer with Cross-Boot Flash Persistence

**Problem:** Edge devices need tamper-evident audit logs on constrained flash
storage that survive reboots without breaking the integrity chain.

**Novel Mechanism:** Each 32-byte audit entry includes a 16-byte truncated
HMAC-SHA256 computed over a message containing the previous entry's HMAC
(chain link), using a device-local key. A persistent 20-byte flash header
stores the ring write-head position and last HMAC tag so the chain continues
unbroken across reboots. BLOCK events bypass the RAM coalescing buffer and
write directly to flash for guaranteed durability. A migration scanner
validates old-format HMAC chains for backward-compatible upgrades.

**Why Patentable:** The combination of (a) HMAC chain via message inclusion
(not key derivation), (b) persistent header for cross-boot continuity, (c)
priority bypass for critical events, and (d) backward-compatible chain
migration is not found in existing patents. Enterprise audit chain patents
(Micro Focus US12706763B2) operate on servers; none targets embedded flash
with ring-buffer wrap-around.

**Prior Art Gap:** Enterprise hash-chain audit patented; embedded flash ring
buffer with HMAC chain is OPEN.

**Commercial Value:** High — tamper-evident logging on constrained devices is a
compliance requirement under EU AI Act and NIST AI RMF.

**Implementation:** `audit_ring.c` (entire file), `defenseclaw.h:173-195`

---

### Patent 5: Scope-Aware Asymmetric Content Scanning with Aho-Corasick DFA for AI Agent Security

**Problem:** Content in AI agent tool calls must be scanned for secrets, PII,
injection, and exfiltration, but the threat model differs by direction (user
input vs. tool output) and the scanner must run in O(n) on embedded hardware.

**Novel Mechanism:** A precompiled Aho-Corasick DFA performs single-pass O(n)
keyword matching for secrets, credentials, and injection patterns. Separate
structural scanners handle PII (SSN, credit card, phone), credential patterns,
SQL/XSS injection, path traversal, shell commands, and base64 exfiltration
heuristics. The system applies asymmetric thresholds: USER_INPUT blocks on
MEDIUM+ severity; TOOL_OUTPUT blocks only on HIGH+. SYSTEM-scope content
bypasses scanning. Truncated content (exceeding the embedded buffer) is
automatically escalated to the cloud for full scanning.

**Why Patentable:** The combination of Aho-Corasick DFA with direction-aware
severity thresholds, structural pattern scanners, SSRF detection (including
octal/hex IP obfuscation and offline fail-closed), and automatic cloud
escalation for truncated payloads is novel for embedded AI security. Existing
content scanning patents target cloud/gateway deployments.

**Prior Art Gap:** WIDE OPEN — no patent covers direction-aware content scanning
on embedded devices for AI agent security.

**Commercial Value:** High — addresses "what data is the AI agent leaking?" at
the edge, not just at the cloud perimeter.

**Implementation:** `content_scanner.c:72-127, 523-578, 611-639, 656-972`

---

## Tier 2 Patent Candidates (Defensive Portfolio)

### Patent 6: Dual-Nonce Anti-Replay for Verdict Responses

Boot-nonce (16 bytes, generated at startup) + per-request-nonce (4 bytes) both
included in verdict HMAC computation. Makes replay across reboots AND across
requests cryptographically impossible without additional round trips.

**Implementation:** `verdict_protocol.c:63-127, 332-343`, `bridge.go:1022-1069`

---

### Patent 7: Emergency Broadcast with Sequence-Gap Jump-Attack Detection

Emergency commands carry strictly-increasing sequence numbers with Ed25519/HMAC
signatures. Anti-replay rejects seq <= last_seen. Jump-attack detection rejects
seq - last_seen > 10, limiting damage from a compromised signing key. On
reconnect, gap detection requests re-transmission. Emergency state persists to
flash with 24-hour monotonic-clock auto-clear.

**Prior Art Gap:** WIDE OPEN — no patents found for the complete protocol.
Consider elevating to Tier 1.

**Implementation:** `ota_receiver.c:549-642, 826-861, 896-957`

---

### Patent 8: Hash-to-Name Binding for Tool Identity Verification

Dual binding: SHA-256 of the submitted tool_name is verified against the
submitted tool_hash before any policy evaluation. Server-side capability
override replaces caller-declared capabilities. Closes a split-identity attack
where hash-based and name-based security systems are used together.

**Implementation:** `dclaw_core.c:266-313`

---

### Patent 9: Topic-Bound HMAC for MQTT Cross-Message Replay Prevention

The full MQTT topic string is included in the HMAC computation for every signed
message, binding the signature to both content and routing path. Prevents an
attacker from moving a valid heartbeat message to the registration topic.

**Implementation:** `bridge.go:976-1017, 534-539`

---

### Patent 10: SSRF Detection with IP Obfuscation and Offline Fail-Closed

Comprehensive SSRF checker handles hex IPs (0x7f000001), octal octets
(0177.0.0.01), IPv4-mapped IPv6, IPv6 ULA/link-local, data: URIs, non-HTTP
schemes, and inline credentials. When offline and unable to resolve hostnames
via cloud, unknown hostnames are BLOCKED (fail-closed) rather than allowed.

**Implementation:** `content_scanner.c:656-972`

---

### Patent 11: Sharded-Lock Fleet Manager with Boot-Epoch Replay Detection

256-slot sharded mutex array indexed by deviceID % 256 separates per-device
mutations from the global map lock. Boot-epoch counter (persisted to SQLite)
increments on each detected reboot (uptime < last_uptime), distinguishing
genuine reboots from replayed heartbeats. Policy version, firmware version,
and capabilities are monotonically increasing (anti-rollback).

**Implementation:** `manager.go:131-152, 416-449`

---

### Patent 12: Dual-Key Separation for OTA Policy vs Emergency Commands

Independent DCLAW_OTA_KEY (policy signatures) and DCLAW_EMERGENCY_KEY
(emergency broadcast signatures) with graceful dev-mode fallback. Missing
emergency key in production causes all emergency commands to be rejected.
Limits blast radius of single-key compromise.

**Implementation:** `ota_receiver.c:462-537`, `policy.go:171-179`

---

## Filing Strategy

### Priority Order

| Priority | Patent | Breadth | Blocking Value | Prior Art Risk |
|---|---|---|---|---|
| **File immediately** | #1 Speculative Execution | Broad | Very high | Very low |
| **File immediately** | #2 Capability-Sequence | Broad | Very high | Very low |
| **File Q1 2027** | #3 Canary Auto-Rollback | Medium | High | Low |
| **File Q1 2027** | #4 Audit Ring Chain | Medium | High | Low |
| **File Q1 2027** | #5 Asymmetric Scanning | Broad | High | Very low |
| **File Q1 2027** | #7 Emergency Lockdown | Medium | High | Very low |
| **File Q2 2027** | #6,8-12 (defensive) | Narrow | Medium | Low |

### Claim Structure (Each Tier 1)

1. **System claim** — complete edge-connector + fleet-manager architecture
2. **Method claim** — specific algorithm/process
3. **Apparatus claim** — embedded device with specific firmware
4. **Computer-readable medium claim** — standard coverage

### Geographic Filing

- **US (USPTO)** — primary market, Cisco HQ
- **EU (EPO)** — EU AI Act compliance creates demand
- **China (CNIPA)** — large IoT manufacturing base
- **PCT** — 30-month window for additional countries

---

## Competitive Moat Assessment

| Competitor | Time to Replicate | Which Patents Block Them |
|---|---|---|
| Palo Alto AIRS | 18-24 months | #1, #2, #5 block edge approach |
| Armis | 24-36 months | #1, #3, #4 block embedded approach |
| CrowdStrike | 12-18 months | #2, #5 block AI-specific claims |
| Microsoft Defender IoT | 18-24 months | #1, #4 block offline-capable approach |
| Lakera / CalypsoAI | 24-36 months | All 5 Tier 1 patents block |

---

## Appendix: Inventor Attribution

All inventions derive from PR #678 on the defenseclaw repository.
Inventor determination should follow Cisco's standard patent policy based on
the git commit history and design document authorship.

---

*Analysis generated 2026-10-14. Prior art search covers USPTO, EPO, and WIPO
databases plus commercial patent intelligence sources. Market data from
MarketsandMarkets, Gartner, and public company filings.*
