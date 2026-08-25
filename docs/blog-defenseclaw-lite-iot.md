# Agents on the Edge: Extending AI Security Governance to IoT with DefenseClaw Lite

**Author:** Nikhil Ghodki, AI Researcher

**Read time:** 7 min

---

Every AI agent is a tool-calling machine. In the cloud, we govern those tool calls through the full DefenseClaw gateway — YARA scanning, LLM-based injection detection, OPA policy evaluation, behavioral analysis. But a growing class of AI agents never touches the cloud at all. They run on factory controllers, medical devices, autonomous vehicles, and industrial gateways — devices with 256KB of flash and 32KB of RAM that cannot run a 50MB security binary. Until now, those agents operated with no security governance whatsoever.

DefenseClaw Lite changes that. It is a purpose-built enforcement agent — 54 kilobytes of C, making sub-microsecond policy decisions on-device — designed for the hardware realities of IoT while maintaining the security guarantees enterprises expect from Cisco AI Defense. DefenseClaw Lite ships as part of the [DefenseClaw open-source project](https://github.com/cisco-ai-defense/defenseclaw), available today for the community to adopt, extend, and harden.

## The security gap no one talks about

AI agents on edge devices use the same MCP tool-call patterns as their cloud counterparts. A sensor-reading agent on an industrial controller can be prompt-injected through a malicious reading just as easily as a chat agent can be manipulated through user input. The difference is consequences: a compromised cloud agent might leak data; a compromised factory agent can command actuators, open valves, or disable safety interlocks.

These devices face the same threats — prompt injection, tool abuse, lateral movement, data exfiltration — but none of the existing defenses fit. The full DefenseClaw gateway requires 200–500MB of RAM and always-on HTTPS connectivity. IoT devices have neither. The result is a critical enforcement gap at exactly the point where AI agent compromise carries the highest physical-world risk.

## A split-brain architecture for constrained devices

DefenseClaw Lite does not attempt to shrink the cloud gateway. Instead, it splits security decisions into two tiers based on what each environment does best.

**On-device (local, under 5 microseconds):** A compiled C agent intercepts every tool call via Unix IPC. It evaluates requests against pre-compiled policy tables, detects dangerous capability sequences (like network-fetch followed by shell-execute), enforces destination allow-lists, rate-limits actuations, and checks a local verdict cache — all without network round-trips. If the answer is knowable locally, the decision happens in microseconds.

**In the cloud (deep, 100–500ms):** When local policy cannot determine the verdict — an unknown tool hash, an ambiguous intent pattern — the agent escalates to the existing DefenseClaw cloud gateway over MQTT 5.0. The cloud runs the full inspection pipeline: YARA rule scanning, LLM judge for injection detection, OPA policy evaluation. The verdict flows back, gets cached locally, and subsequent identical requests resolve instantly on-device.

The critical invariant: if the cloud is unreachable and there is no cached verdict, the device blocks. DefenseClaw Lite never fails open.

## How a tool call is evaluated

When an AI agent on the device invokes a tool — read a sensor, fetch a URL, execute a command — the request passes through a seven-stage pipeline before anything happens:

1. **Input validation** — payload bounds, ASCII enforcement, peer identity verification via kernel credentials
2. **Rate limiting** — three independent token buckets (global, network, actuation) prevent resource exhaustion
3. **Hash deny-list** — binary search against known-malicious tool signatures, updated via threat intelligence push
4. **Destination filtering** — network calls checked against compiled allow-lists with wildcard support
5. **Sequence correlation** — a 16-session finite state machine tracks capability history, blocking dangerous multi-step chains before they complete
6. **Verdict cache** — 64-entry LRU of previous cloud decisions, with time-aware expiry
7. **Cloud escalation** — for genuinely unknown requests, with a dual-mode execution model

That dual-mode is where the architecture gets interesting. Tool calls classified as low-risk (sensor reads, network fetches) proceed speculatively — the agent gets a tentative allow while the cloud evaluates. If the cloud returns a block, a retroactive callback revokes the action. But high-risk calls (actuations, shell execution, filesystem writes) block synchronously. The device waits for an explicit cloud allow before permitting execution. Physical-world actions are never speculative.

## Security without compromise — in 54 kilobytes

Running on devices with kilobytes of RAM demands a different engineering discipline. DefenseClaw Lite uses zero dynamic memory allocation. Every data structure — the 16-session correlator, the 64-entry verdict cache, the 8-slot pending dedup table — is statically sized at compile time. Total RAM: 25KB including the TLS session.

The audit trail is HMAC-chained: each 16-byte log entry cryptographically links to its predecessor, creating a tamper-evident chain that the fleet manager verifies on every heartbeat. Block events bypass the RAM buffer and write directly to flash, ensuring they survive immediate power loss — because in an industrial environment, an attacker's next move after being detected may be to cut power.

Policy updates arrive as Ed25519-signed binary blobs written to an inactive flash partition. The device switches partitions atomically and enters a 10-minute canary window. If the block rate spikes to five times baseline for three consecutive minutes, the device rolls back to the previous policy automatically — no human intervention, no connectivity required.

## Fleet-scale visibility from day one

DefenseClaw Lite devices are not islands. A companion fleet manager, embedded in the existing DefenseClaw cloud gateway, ingests 32-byte heartbeats from every device at configurable intervals. It maintains a real-time device registry, computes fleet-wide metrics, and detects anomalies: devices that go silent beyond three heartbeat intervals, block rate spikes indicating a coordinated attack, audit chain integrity failures suggesting tampering, secure element degradation.

All of this integrates with the infrastructure teams already operate. Fleet metrics flow to Prometheus. Alerts dispatch through existing webhook pipelines to Slack, PagerDuty, or email. Audit events land in the same SIEM pipeline as cloud agent telemetry. There is no parallel system to stand up.

## The policy bridge

Security teams should not need to learn a new policy language for IoT devices. DefenseClaw Lite uses the same YAML policy format as the cloud gateway, extended with an `iot_extensions` section for device-specific concerns: capability sequence rules, destination allow-lists, rate limits, escalation mode tables, and canary baselines.

A Python policy compiler transforms this YAML into two artifacts: a C header compiled directly into the firmware for zero-latency lookups, and a signed binary blob for over-the-air delivery to deployed devices. The compiler validates that generated output fits within the target device's flash partition, reporting per-component size breakdowns and failing the build if the policy exceeds hardware limits. Policy that cannot ship does not ship.

## Open source, open security

DefenseClaw Lite ships in the [cisco-ai-defense/defenseclaw](https://github.com/cisco-ai-defense/defenseclaw) open-source repository — the same repo that houses the full DefenseClaw gateway. We made this choice deliberately. IoT security cannot be a black box. Device manufacturers, integrators, and security researchers need to audit the enforcement logic that protects physical-world systems. They need to port it to new hardware, extend the policy language for domain-specific threats, and validate the cryptographic chain independently.

The repository includes everything needed to build, test, and deploy:

- **C agent source** (`defenseclaw-lite/`) — 17 source files, CMake build with Kconfig profile selection (MINIMAL/STANDARD/EDGE)
- **Go fleet manager** (`internal/fleet/`) — device registry, heartbeat processing, anomaly detection, REST API
- **Python policy compiler** (`defenseclaw-lite/tools/`) — YAML-to-C-header and signed-binary generation
- **Test suite** — 10 test binaries with 77+ test cases, acceptance suite, fuzz harness, latency benchmark
- **Grafana dashboard** — pre-built fleet observability (8 panels)
- **Production-ready policy** (`defenseclaw-lite/policies/strict.yaml`) — a starting point teams can adapt

Contributions are welcome. The architecture is designed for extensibility: the HAL abstraction layer means porting to new hardware requires implementing a single platform file. The policy compiler can be extended with new rule types. The fleet manager exposes a clean REST API for integration with existing device management platforms.

## What this means for the enterprise

The devices are already deployed. The AI agents are already running on them. Industrial controllers manage production lines. Medical devices monitor patients. Autonomous systems make real-time decisions. The question is not whether these agents need security governance — it is how quickly that gap gets closed.

DefenseClaw Lite brings the same security posture Cisco AI Defense provides for cloud agents to every device that can run a 54KB binary. Sub-microsecond enforcement for local decisions. Full inspection pipeline access for complex analysis. Fail-closed resilience when connectivity drops. Tamper-evident audit that an attacker cannot silently erase. Fleet-scale observability from the same dashboard teams already watch.

The IoT AI agent era is already here. Now, so is the security.

---

*DefenseClaw Lite is available in the [cisco-ai-defense/defenseclaw](https://github.com/cisco-ai-defense/defenseclaw) repository. Clone it, build it, run the tests, and deploy it to your fleet.*