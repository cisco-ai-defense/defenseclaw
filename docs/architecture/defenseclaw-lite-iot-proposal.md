# DefenseClaw Lite: IoT Agent Architecture Proposal

**Document Version:** 1.0  
**Date:** 2026-07-27  
**Status:** DRAFT — Pending Architecture Review  
**Authors:** Nikhil Ghodki  
**Classification:** Cisco Confidential

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Solution Overview](#3-solution-overview)
4. [System Architecture](#4-system-architecture)
5. [Deployment Topologies](#5-deployment-topologies)
6. [Component Specifications](#6-component-specifications)
7. [Communication Protocol Design](#7-communication-protocol-design)
8. [Security Model](#8-security-model)
9. [Data Flow Analysis](#9-data-flow-analysis)
10. [Hardware Tier Profiles](#10-hardware-tier-profiles)
11. [Failure Modes and Resilience](#11-failure-modes-and-resilience)
12. [Scalability Analysis](#12-scalability-analysis)
13. [API Specification](#13-api-specification)
14. [Observability and Fleet Management](#14-observability-and-fleet-management)
15. [Migration Path from Full DefenseClaw](#15-migration-path-from-full-defenseclaw)
16. [Delivery Phases](#16-delivery-phases)
17. [Decision Log](#17-decision-log)
18. [Appendices](#appendices)

---

## 1. Executive Summary

### Vision

DefenseClaw Lite extends AI agent security governance to resource-constrained IoT and edge devices. As AI agents proliferate beyond cloud and desktop environments into industrial controllers, edge inference platforms, and embedded systems, the attack surface for agentic AI expands to devices that cannot run the full 50MB DefenseClaw gateway.

DefenseClaw Lite is a purpose-built C-language enforcement agent (~80-150KB) that provides sub-microsecond local policy enforcement while delegating complex analysis (YARA scanning, LLM-based inspection, OPA evaluation) to a cloud or edge DefenseClaw instance. It is not a "smaller DefenseClaw" — it is a different architectural role: a fast enforcement point that executes pre-compiled decisions locally and escalates unknowns to the cloud brain.

### Key Metrics

| Metric | Target |
|--------|--------|
| Binary size (minimal profile) | < 32 KB |
| Binary size (standard profile) | < 80 KB |
| Binary size (full edge profile) | < 150 KB |
| RAM footprint | 8 KB - 64 KB |
| Local decision latency | < 5 microseconds |
| Cloud verdict latency (P95) | < 500 ms |
| Heartbeat bandwidth | < 100 bytes/min |
| Offline enforcement | Full (local rules) |
| Fleet scale (per cloud instance) | 100,000 devices |
| Fleet scale (per edge gateway) | 10,000 devices |

### Strategic Value

1. **Market expansion** — DefenseClaw becomes viable for industrial IoT, automotive, medical devices, and edge inference platforms where the full gateway cannot run
2. **Defense in depth** — IoT agents protected at the enforcement layer even when cloud connectivity is intermittent
3. **Cisco portfolio synergy** — Leverages Cisco IR series, Meraki, and IoT gateway hardware for the edge tier
4. **Compliance enablement** — Provides audit chain and policy enforcement for AI agents in regulated environments (NIST AI RMF, EU AI Act Article 9)

---

## 2. Problem Statement

### The AI Agent IoT Gap

AI agents are moving to the edge:

- **Industrial:** Predictive maintenance agents running local inference on PLCs and gateways
- **Automotive:** In-vehicle AI assistants using MCP tools for vehicle control
- **Medical:** Diagnostic AI agents on bedside monitoring equipment
- **Smart infrastructure:** Building management agents coordinating HVAC, lighting, security

These agents use the same MCP/tool-call patterns as cloud agents but run on hardware with:
- 256 KB - 4 MB flash storage
- 32 KB - 512 KB RAM
- ARM Cortex-M4/M7, RISC-V, or low-power ARM Cortex-A class processors
- Intermittent or bandwidth-constrained network connectivity
- Real-time operating systems (Zephyr, FreeRTOS) or minimal Linux

The current DefenseClaw gateway requires:
- 50+ MB binary
- 200-500 MB RAM
- Always-on HTTPS/gRPC connectivity
- Linux/macOS/Windows with full userspace

**No version of the current architecture can be squeezed onto these devices.** A fundamentally different agent architecture is needed — one that preserves the security invariants of DefenseClaw while respecting IoT resource constraints.

### Threat Model for IoT AI Agents

| Threat | Vector | Impact |
|--------|--------|--------|
| Prompt injection via sensor data | Malicious input to local LLM | Unauthorized tool execution |
| MCP tool abuse | Compromised LLM commands actuators | Physical safety (HVAC, valves, motors) |
| Lateral movement | Agent uses network tools to reach other devices | Fleet-wide compromise |
| Data exfiltration | Agent sends sensor/PII data to attacker endpoint | Privacy/IP violation |
| Supply chain (malicious tools) | Compromised MCP server installed on device | Persistent backdoor |
| Offline policy bypass | Attacker disconnects device from cloud to evade scanning | Unmonitored execution |

---

## 3. Solution Overview

### Architectural Principle: Split-Brain Security

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY DECISION SPECTRUM                     │
│                                                                   │
│  FAST (local)                                    DEEP (cloud)    │
│  ◄──────────────────────────────────────────────────────────►    │
│                                                                   │
│  • Capability sequence blocking    • YARA rule scanning          │
│  • Destination allow/deny          • LLM judge (injection/PII)   │
│  • Rate limiting                   • Cisco AI Defense            │
│  • Known-bad hash blocking         • Behavioral analysis         │
│  • Input PII redaction             • Taint tracking              │
│  • Policy table enforcement        • OPA/Rego evaluation         │
│                                                                   │
│  ◄── IoT Lite handles locally ──► ◄── Cloud/Edge handles ──►    │
│                                                                   │
│  Latency: <5us                     Latency: 100-500ms            │
│  Connectivity: not required         Connectivity: required        │
└─────────────────────────────────────────────────────────────────┘
```

The system is designed around two invariants:

1. **Fail-closed on unknowns** — If the IoT agent encounters a tool/destination not in its local cache and cannot reach the cloud, it BLOCKS. Safety over availability.

2. **Local decisions are irrevocable** — The IoT agent's BLOCK verdict is final. The cloud can only expand permissions (via cached ALLOW verdicts), never override a local BLOCK in real-time. This prevents a compromised cloud from weakening device security.

### Component Mapping from Full DefenseClaw

| Full DefenseClaw Component | IoT Lite Equivalent | Location |
|---|---|---|
| Gateway proxy (115K LoC) | IPC/netfilter hook (inline) | Device |
| OPA/Rego policy engine | Compiled decision tables (C) | Device |
| Guardrail correlator | Session capability FSM (C) | Device |
| Firewall compiler | iptables/nftables rule gen (C) | Device |
| PII redaction | Outbound regex strip (C) | Device |
| SSRF protection (netguard) | Destination allow-list (C) | Device |
| Audit store (SQLite) | Ring buffer + HMAC chain (C) | Device |
| OpenTelemetry (75K LoC) | 32-byte CBOR heartbeat | Device→Cloud |
| YARA scanners | Hash-and-ask (verdict request) | Cloud |
| LLM Judge | N/A on device | Cloud |
| Cisco AI Defense | N/A on device | Cloud |
| Inspection pipeline (4-stage) | Verdict cache hit or escalate | Cloud |
| Bifrost routing | N/A (single endpoint) | N/A |
| Connector matrix | "iot-lite" connector type | Cloud registry |

---

## 4. System Architecture

### 4.1 Logical Architecture (Both Topologies)

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                              LOGICAL VIEW                                         ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────────┐ ║
║  │                         MANAGEMENT PLANE                                     │ ║
║  │                                                                             │ ║
║  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────────┐    │ ║
║  │  │ Fleet Manager  │  │ Policy         │  │ Firmware Update Service    │    │ ║
║  │  │                │  │ Compiler       │  │ (OTA)                      │    │ ║
║  │  │ • Device CRUD  │  │                │  │                            │    │ ║
║  │  │ • Health agg   │  │ • YAML→binary  │  │ • Delta firmware updates   │    │ ║
║  │  │ • Alert rules  │  │ • Version mgmt │  │ • Staged rollout           │    │ ║
║  │  │ • Audit sink   │  │ • Signing      │  │ • Rollback on failure      │    │ ║
║  │  └────────────────┘  └────────────────┘  └────────────────────────────┘    │ ║
║  └─────────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────────┐ ║
║  │                         ANALYSIS PLANE                                       │ ║
║  │                                                                             │ ║
║  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────────┐    │ ║
║  │  │ Verdict Engine │  │ Inspection     │  │ Fleet Correlator           │    │ ║
║  │  │                │  │ Pipeline       │  │                            │    │ ║
║  │  │ • Hash lookup  │  │                │  │ • Cross-device pattern     │    │ ║
║  │  │ • Cache mgmt   │  │ • Regex (113)  │  │ • Campaign detection       │    │ ║
║  │  │ • TTL policy   │  │ • YARA scan    │  │ • Anomaly scoring          │    │ ║
║  │  │ • Escalation   │  │ • LLM Judge    │  │ • Blast radius estimation  │    │ ║
║  │  │               │  │ • Cisco AID    │  │                            │    │ ║
║  │  └────────────────┘  └────────────────┘  └────────────────────────────┘    │ ║
║  └─────────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────────┐ ║
║  │                         ENFORCEMENT PLANE (on-device)                        │ ║
║  │                                                                             │ ║
║  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────────┐    │ ║
║  │  │ Decision       │  │ Network        │  │ IPC Hook                   │    │ ║
║  │  │ Engine         │  │ Enforcer       │  │                            │    │ ║
║  │  │                │  │                │  │ • JSON-RPC intercept       │    │ ║
║  │  │ • Policy table │  │ • Dest filter  │  │ • Tool name extraction     │    │ ║
║  │  │ • Correlator   │  │ • Rate limit   │  │ • Payload hash compute     │    │ ║
║  │  │ • Verdict cache│  │ • Firewall gen │  │ • Verdict injection        │    │ ║
║  │  └────────────────┘  └────────────────┘  └────────────────────────────┘    │ ║
║  └─────────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────────┐ ║
║  │                         DATA PLANE                                           │ ║
║  │                                                                             │ ║
║  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────────┐    │ ║
║  │  │ Audit Ring     │  │ Telemetry      │  │ Cloud Comms                │    │ ║
║  │  │ Buffer         │  │ Reporter       │  │                            │    │ ║
║  │  │                │  │                │  │ • MQTT 5.0 / CoAP client   │    │ ║
║  │  │ • 256 entries  │  │ • Heartbeat    │  │ • mTLS (X.509 device cert) │    │ ║
║  │  │ • HMAC chain   │  │ • Counters     │  │ • Reconnect backoff        │    │ ║
║  │  │ • Flash-safe   │  │ • Flags        │  │ • Message queue (8 deep)   │    │ ║
║  │  └────────────────┘  └────────────────┘  └────────────────────────────┘    │ ║
║  └─────────────────────────────────────────────────────────────────────────────┘ ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
```

### 4.2 Physical Architecture — Option A: Hub-and-Spoke

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                    OPTION A: HUB-AND-SPOKE (Direct Cloud)                         ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║                        ┌────────────────────────────────────┐                    ║
║                        │         CLOUD DATACENTER            │                    ║
║                        │                                    │                    ║
║                        │  ┌──────────────────────────────┐  │                    ║
║                        │  │    DefenseClaw Cloud Gateway  │  │                    ║
║                        │  │    (existing Go binary)       │  │                    ║
║                        │  │                              │  │                    ║
║                        │  │  ┌────────┐ ┌────────────┐   │  │                    ║
║                        │  │  │Inspect │ │ OPA/Rego   │   │  │                    ║
║                        │  │  │Pipeline│ │ Engine     │   │  │                    ║
║                        │  │  └────────┘ └────────────┘   │  │                    ║
║                        │  │  ┌────────┐ ┌────────────┐   │  │                    ║
║                        │  │  │ YARA   │ │ LLM Judge  │   │  │                    ║
║                        │  │  │Scanner │ │            │   │  │                    ║
║                        │  │  └────────┘ └────────────┘   │  │                    ║
║                        │  │  ┌────────┐ ┌────────────┐   │  │                    ║
║                        │  │  │Cisco AI│ │ SQLite     │   │  │                    ║
║                        │  │  │Defense │ │ Audit DB   │   │  │                    ║
║                        │  │  └────────┘ └────────────┘   │  │                    ║
║                        │  └──────────────────────────────┘  │                    ║
║                        │                                    │                    ║
║                        │  ┌──────────────────────────────┐  │                    ║
║                        │  │    IoT Fleet Services (NEW)   │  │                    ║
║                        │  │                              │  │                    ║
║                        │  │  ┌──────────────────────┐    │  │                    ║
║                        │  │  │   Fleet Manager       │    │  │                    ║
║                        │  │  │   • Device registry   │    │  │                    ║
║                        │  │  │   • Heartbeat proc    │    │  │                    ║
║                        │  │  │   • Alert engine      │    │  │                    ║
║                        │  │  └──────────────────────┘    │  │                    ║
║                        │  │  ┌──────────────────────┐    │  │                    ║
║                        │  │  │   Verdict Cache       │    │  │                    ║
║                        │  │  │   • Hash→verdict map  │    │  │                    ║
║                        │  │  │   • TTL management    │    │  │                    ║
║                        │  │  │   • Pipeline fallback │    │  │                    ║
║                        │  │  └──────────────────────┘    │  │                    ║
║                        │  │  ┌──────────────────────┐    │  │                    ║
║                        │  │  │   Policy Compiler     │    │  │                    ║
║                        │  │  │   • YAML→C tables     │    │  │                    ║
║                        │  │  │   • OTA packaging     │    │  │                    ║
║                        │  │  │   • Ed25519 signing   │    │  │                    ║
║                        │  │  └──────────────────────┘    │  │                    ║
║                        │  │  ┌──────────────────────┐    │  │                    ║
║                        │  │  │   MQTT Broker         │    │  │                    ║
║                        │  │  │   (Mosquitto/EMQX)    │    │  │                    ║
║                        │  │  │   • TLS termination   │    │  │                    ║
║                        │  │  │   • Topic ACL         │    │  │                    ║
║                        │  │  └──────────────────────┘    │  │                    ║
║                        │  └──────────────────────────────┘  │                    ║
║                        └──────────────┬─────────────────────┘                    ║
║                                       │                                          ║
║                         MQTT 5.0 over TLS 1.3                                    ║
║                         (mTLS with device X.509 certificates)                    ║
║                                       │                                          ║
║          ┌────────────────────────────┼────────────────────────────┐             ║
║          │                            │                            │             ║
║          ▼                            ▼                            ▼             ║
║  ┌───────────────┐           ┌───────────────┐           ┌───────────────┐      ║
║  │  IoT Device   │           │  IoT Device   │           │  IoT Device   │      ║
║  │  (Tier 1-3)   │           │  (Tier 1-3)   │           │  (Tier 1-3)   │      ║
║  │               │           │               │           │               │      ║
║  │ ┌───────────┐ │           │ ┌───────────┐ │           │ ┌───────────┐ │      ║
║  │ │DefenseClaw│ │           │ │DefenseClaw│ │           │ │DefenseClaw│ │      ║
║  │ │   Lite    │ │           │ │   Lite    │ │           │ │   Lite    │ │      ║
║  │ │  (C agent)│ │           │ │  (C agent)│ │           │ │  (C agent)│ │      ║
║  │ └───────────┘ │           │ └───────────┘ │           │ └───────────┘ │      ║
║  │ ┌───────────┐ │           │ ┌───────────┐ │           │ ┌───────────┐ │      ║
║  │ │ AI Agent  │ │           │ │ AI Agent  │ │           │ │ AI Agent  │ │      ║
║  │ │ Runtime   │ │           │ │ Runtime   │ │           │ │ Runtime   │ │      ║
║  │ └───────────┘ │           │ └───────────┘ │           │ └───────────┘ │      ║
║  └───────────────┘           └───────────────┘           └───────────────┘      ║
║                                                                                   ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║  CHARACTERISTICS:                                                                 ║
║  • Verdict latency: 100-500ms (WAN round-trip)                                   ║
║  • Offline mode: local rules only, fail-closed on unknowns                       ║
║  • Scale: up to 100K devices per cloud instance                                  ║
║  • Best for: devices with reliable connectivity, smaller fleets                  ║
║  • Infrastructure: minimal (cloud only)                                          ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
```

### 4.3 Physical Architecture — Option B: Edge Gateway

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║               OPTION B: EDGE GATEWAY (Recommended for Production)                 ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────────┐ ║
║  │                            CLOUD TIER                                        │ ║
║  │                                                                             │ ║
║  │  ┌────────────────────────────────────────────────────────────────────────┐ │ ║
║  │  │                DefenseClaw Cloud (Control Plane)                        │ │ ║
║  │  │                                                                        │ │ ║
║  │  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐  │ │ ║
║  │  │  │ Global Fleet │ │ Policy       │ │ Firmware     │ │ Dashboard    │  │ │ ║
║  │  │  │ Manager      │ │ Authority    │ │ Registry     │ │ (Grafana)    │  │ │ ║
║  │  │  │              │ │              │ │              │ │              │  │ │ ║
║  │  │  │ • Edge reg   │ │ • Gold YAML  │ │ • Signed     │ │ • Fleet map  │  │ │ ║
║  │  │  │ • Device inv │ │ • Version    │ │   binaries   │ │ • Health     │  │ │ ║
║  │  │  │ • SLA monitor│ │   control    │ │ • Delta OTA  │ │ • Alerts     │  │ │ ║
║  │  │  │ • Compliance │ │ • Signing    │ │ • Rollback   │ │ • Audit log  │  │ │ ║
║  │  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘  │ │ ║
║  │  │                                                                        │ │ ║
║  │  │  ┌──────────────┐ ┌──────────────┐ ┌───────────────────────────────┐   │ │ ║
║  │  │  │ Threat Intel │ │ Audit        │ │ Fleet Correlator              │   │ │ ║
║  │  │  │ Feed         │ │ Aggregator   │ │ (cross-edge analysis)         │   │ │ ║
║  │  │  │              │ │              │ │                               │   │ │ ║
║  │  │  │ • Hash lists │ │ • Long-term  │ │ • Campaign detection          │   │ │ ║
║  │  │  │ • Bloom gen  │ │   storage    │ │ • Global anomaly scoring      │   │ │ ║
║  │  │  │ • IOC dist   │ │ • Compliance │ │ • Coordinated response        │   │ │ ║
║  │  │  └──────────────┘ └──────────────┘ └───────────────────────────────┘   │ │ ║
║  │  └────────────────────────────────────────────────────────────────────────┘ │ ║
║  └────────────────────────────────────┬────────────────────────────────────────┘ ║
║                                       │                                          ║
║                          HTTPS/gRPC (edge↔cloud sync)                            ║
║                          • Policy distribution                                   ║
║                          • Threat intel updates                                  ║
║                          • Audit batch upload                                    ║
║                          • Firmware distribution                                 ║
║                                       │                                          ║
║  ┌────────────────────────────────────┼────────────────────────────────────────┐ ║
║  │                            EDGE TIER                                         │ ║
║  │                                                                             │ ║
║  │         ┌──────────────────────────┼──────────────────────────┐             │ ║
║  │         │                          │                          │             │ ║
║  │         ▼                          ▼                          ▼             │ ║
║  │  ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐   │ ║
║  │  │  Edge Gateway A │       │  Edge Gateway B │       │  Edge Gateway C │   │ ║
║  │  │  (Site Alpha)   │       │  (Site Beta)    │       │  (Site Gamma)   │   │ ║
║  │  │                 │       │                 │       │                 │   │ ║
║  │  │ ┌─────────────┐ │       │ ┌─────────────┐ │       │ ┌─────────────┐ │   │ ║
║  │  │ │DefenseClaw  │ │       │ │DefenseClaw  │ │       │ │DefenseClaw  │ │   │ ║
║  │  │ │Gateway (Go) │ │       │ │Gateway (Go) │ │       │ │Gateway (Go) │ │   │ ║
║  │  │ │             │ │       │ │             │ │       │ │             │ │   │ ║
║  │  │ │• Full inspect│ │       │ │• Full inspect│ │       │ │• Full inspect│ │   │ ║
║  │  │ │• YARA scan  │ │       │ │• YARA scan  │ │       │ │• YARA scan  │ │   │ ║
║  │  │ │• OPA engine │ │       │ │• OPA engine │ │       │ │• OPA engine │ │   │ ║
║  │  │ │• Verdict $  │ │       │ │• Verdict $  │ │       │ │• Verdict $  │ │   │ ║
║  │  │ │• Local MQTT │ │       │ │• Local MQTT │ │       │ │• Local MQTT │ │   │ ║
║  │  │ └─────────────┘ │       │ └─────────────┘ │       │ └─────────────┘ │   │ ║
║  │  │                 │       │                 │       │                 │   │ ║
║  │  │ HW: Cisco IR1101│       │ HW: x86 mini-PC│       │ HW: Jetson AGX │   │ ║
║  │  │ or equiv.       │       │ 8GB RAM        │       │ edge server    │   │ ║
║  │  └────────┬────────┘       └────────┬────────┘       └────────┬────────┘   │ ║
║  │           │                         │                         │             │ ║
║  └───────────┼─────────────────────────┼─────────────────────────┼─────────────┘ ║
║              │                         │                         │               ║
║     MQTT 5.0 (LAN/site-local)         │                         │               ║
║     Latency: 1-10ms                   │                         │               ║
║              │                         │                         │               ║
║  ┌───────────┼─────────────────────────┼─────────────────────────┼─────────────┐ ║
║  │           │        DEVICE TIER      │                         │             │ ║
║  │           │                         │                         │             │ ║
║  │     ┌─────┼─────┐            ┌─────┼─────┐            ┌─────┼─────┐       │ ║
║  │     │     │     │            │     │     │            │     │     │       │ ║
║  │     ▼     ▼     ▼            ▼     ▼     ▼            ▼     ▼     ▼       │ ║
║  │   ┌───┐ ┌───┐ ┌───┐       ┌───┐ ┌───┐ ┌───┐       ┌───┐ ┌───┐ ┌───┐    │ ║
║  │   │ D │ │ D │ │ D │       │ D │ │ D │ │ D │       │ D │ │ D │ │ D │    │ ║
║  │   │ 1 │ │ 2 │ │ 3 │       │ 4 │ │ 5 │ │ 6 │       │ 7 │ │ 8 │ │ 9 │    │ ║
║  │   └───┘ └───┘ └───┘       └───┘ └───┘ └───┘       └───┘ └───┘ └───┘    │ ║
║  │                                                                           │ ║
║  │   D = IoT Device running DefenseClaw Lite (C agent)                      │ ║
║  └───────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                   ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║  CHARACTERISTICS:                                                                 ║
║  • Verdict latency: 1-10ms (LAN to edge gateway)                                ║
║  • Offline mode: edge has full scan capability, devices operate normally          ║
║  • Scale: 10K devices per edge, unlimited edges per cloud                        ║
║  • Best for: large fleets, unreliable WAN, regulated environments                ║
║  • Infrastructure: edge gateway per site (Cisco IR1101 / mini-PC / VM)           ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 5. Deployment Topologies

### 5.1 Topology Selection Matrix

| Criterion | Option A (Hub-Spoke) | Option B (Edge Gateway) |
|-----------|---------------------|------------------------|
| Fleet size | < 5,000 devices | 5,000 - 1,000,000+ devices |
| WAN reliability | > 99.5% uptime | Any (survives WAN outage) |
| Verdict latency SLA | < 500ms acceptable | < 10ms required |
| Compliance requirements | Standard | Strict (data sovereignty, air-gap capable) |
| Infrastructure budget | Minimal | Moderate (edge hardware) |
| Operational complexity | Low | Medium |
| Security posture | Good | Best (defense in depth) |
| Offline duration tolerance | Minutes | Hours/days |
| Geographic distribution | Single region | Multi-region / multi-site |

### 5.2 Option A Deep Dive: Hub-and-Spoke

**When to use:** Smaller deployments, devices with reliable cellular/WiFi, development/staging environments, single-site installations.

```
Connection Flow:

  Device Boot
      │
      ├─1─► Load device certificate from secure element
      │
      ├─2─► TLS 1.3 handshake with cloud MQTT broker (mTLS)
      │
      ├─3─► Subscribe to device-specific topics:
      │       defenseclaw/fleet/{device_id}/verdict/resp
      │       defenseclaw/fleet/{device_id}/ota/policy
      │       defenseclaw/fleet/{device_id}/ota/firmware
      │       defenseclaw/fleet/{device_id}/cmd
      │
      ├─4─► Publish registration:
      │       defenseclaw/fleet/{device_id}/register
      │       {hw_profile, fw_version, policy_version, capabilities}
      │
      ├─5─► Begin heartbeat loop (every 30s):
      │       defenseclaw/fleet/{device_id}/heartbeat
      │
      └─6─► Enter enforcement loop (event-driven)
```

**Failure handling:**

| Failure | Device Behavior |
|---------|----------------|
| MQTT disconnect | Exponential backoff reconnect (1s, 2s, 4s...300s max) |
| Verdict timeout (5s) | BLOCK unknown, log cloud_unreachable |
| Heartbeat fails | Continue enforcement, retry connect |
| Cloud permanently down | Full local enforcement, ring buffer fills |

### 5.3 Option B Deep Dive: Edge Gateway

**When to use:** Production deployments at scale, sites with unreliable WAN, regulated industries, deployments requiring data sovereignty.

```
Connection Hierarchy:

  CLOUD
    │
    │ HTTPS/gRPC (authenticated, encrypted)
    │ • Policy sync (pull, every 5 min)
    │ • Threat intel sync (push via webhook)
    │ • Audit batch upload (every 5 min)
    │ • Firmware distribution (on demand)
    │
    ▼
  EDGE GATEWAY
    │
    │ MQTT 5.0 (LAN, mTLS)
    │ • Verdict request/response (<10ms)
    │ • Heartbeat collection
    │ • Policy/firmware relay to devices
    │ • Audit collection from devices
    │
    ▼
  IoT DEVICES (up to 10,000 per edge)
```

**Edge Gateway responsibilities:**

| Function | Description |
|----------|-------------|
| Local MQTT broker | Terminates device mTLS, routes topics |
| Verdict cache | 1M+ entries, shared across all local devices |
| Full inspection pipeline | YARA + regex + OPA — no cloud needed for verdicts |
| Audit buffer | 7-day local retention before cloud upload |
| Policy relay | Receives from cloud, distributes to devices |
| Health monitoring | Detects device anomalies at site level |
| Offline operation | Full functionality when WAN is down |

**Edge-to-Cloud sync protocol:**

```
┌─────────────────────────────────────────────────────────────────┐
│  EDGE → CLOUD SYNC (every 5 minutes or on threshold)            │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Policy Pull (cloud → edge)                                   │
│     GET /api/v1/fleet/policy?since={last_version}                │
│     Response: {policies: [...], deny_lists: [...], bloom: "..."}  │
│                                                                   │
│  2. Threat Intel Push (cloud → edge, via webhook)                │
│     POST /api/v1/fleet/edge/{edge_id}/threat-intel               │
│     Body: {new_hashes: [...], revoked_allows: [...]}              │
│                                                                   │
│  3. Audit Upload (edge → cloud)                                  │
│     POST /api/v1/fleet/audit/batch                               │
│     Body: {edge_id, entries: [{device_id, ring_entries}...]}      │
│     Compressed: zstd (typically 10:1 ratio on audit data)         │
│                                                                   │
│  4. Heartbeat Aggregation (edge → cloud)                         │
│     POST /api/v1/fleet/heartbeat/batch                           │
│     Body: {edge_id, device_summaries: [{id, last_seen, ...}]}    │
│                                                                   │
│  5. Firmware Distribution (cloud → edge, on demand)              │
│     GET /api/v1/fleet/firmware/{hw_profile}/{version}             │
│     Response: signed binary blob (delta if possible)              │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Component Specifications

### 6.1 IoT Lite Agent (C)

#### Module Decomposition

```
defenseclaw-lite/
├── src/
│   ├── main.c                    # Entry point, init, event loop
│   ├── decision/
│   │   ├── policy_table.c        # Compiled decision table lookup
│   │   ├── correlator.c          # Session capability FSM
│   │   ├── verdict_cache.c       # LRU cache for cloud verdicts
│   │   └── bloom_filter.c        # Probabilistic known-bad check
│   ├── enforce/
│   │   ├── ipc_hook.c            # Unix socket / JSON-RPC intercept
│   │   ├── netfilter_hook.c      # iptables/nftables rule enforcement
│   │   ├── rate_limiter.c        # Token bucket rate limiting
│   │   └── redactor.c            # Outbound PII regex strip
│   ├── persist/
│   │   ├── audit_ring.c          # HMAC-chained ring buffer
│   │   ├── flash_safe.c          # Wear-leveling safe writes
│   │   └── config_store.c        # Policy + cert storage
│   ├── comms/
│   │   ├── mqtt_client.c         # MQTT 5.0 with QoS 1
│   │   ├── tls_engine.c          # mbedTLS / wolfSSL wrapper
│   │   ├── cbor_codec.c          # CBOR encode/decode
│   │   └── ota_receiver.c        # Firmware + policy OTA handler
│   └── platform/
│       ├── hal.h                  # Hardware abstraction layer
│       ├── hal_linux.c            # Linux (Raspberry Pi, Jetson)
│       ├── hal_zephyr.c           # Zephyr RTOS
│       ├── hal_freertos.c         # FreeRTOS
│       └── hal_baremetal.c        # Bare-metal (ESP32, STM32)
├── include/
│   ├── defenseclaw.h             # Public API
│   ├── policy_types.h            # Generated from YAML (build-time)
│   ├── config.h                  # Build configuration
│   └── platform.h                # Platform detection macros
├── generated/
│   ├── policy_tables.h           # Auto-generated decision tables
│   ├── deny_list.h               # Auto-generated hash deny list
│   └── dest_allowlist.h          # Auto-generated destination list
├── tools/
│   ├── policy_compiler.py        # YAML → C header compiler
│   ├── bloom_generator.py        # Generates bloom filter binary
│   └── cert_provisioner.py       # Device certificate provisioning
├── CMakeLists.txt
└── Kconfig                        # Build-time feature selection
```

#### Build Configuration (Kconfig)

```kconfig
menu "DefenseClaw Lite Configuration"

choice DCLAW_PROFILE
    prompt "Agent Profile"
    default DCLAW_PROFILE_STANDARD

config DCLAW_PROFILE_MINIMAL
    bool "Minimal (30KB, enforcement only)"
    help
      Policy table + firewall rules + audit ring.
      No cloud comms. No verdict cache. No PII redaction.
      For MCUs with <64KB flash.

config DCLAW_PROFILE_STANDARD
    bool "Standard (80KB, full local + cloud verdicts)"
    help
      Full local enforcement + MQTT cloud comms +
      verdict cache + PII redaction.
      For devices with 128KB+ flash, 32KB+ RAM.

config DCLAW_PROFILE_EDGE
    bool "Full Edge (150KB, all features)"
    help
      Standard + bloom filter + extended audit +
      device-to-device mesh capability.
      For Linux SBCs and industrial gateways.
endchoice

config DCLAW_AUDIT_RING_SIZE
    int "Audit ring buffer entries"
    default 64 if DCLAW_PROFILE_MINIMAL
    default 256 if DCLAW_PROFILE_STANDARD
    default 1024 if DCLAW_PROFILE_EDGE

config DCLAW_VERDICT_CACHE_SIZE
    int "Verdict cache entries"
    default 0 if DCLAW_PROFILE_MINIMAL
    default 64 if DCLAW_PROFILE_STANDARD
    default 256 if DCLAW_PROFILE_EDGE

config DCLAW_HEARTBEAT_INTERVAL_SEC
    int "Heartbeat interval (seconds)"
    default 0 if DCLAW_PROFILE_MINIMAL
    default 30 if DCLAW_PROFILE_STANDARD
    default 10 if DCLAW_PROFILE_EDGE

config DCLAW_TLS_LIBRARY
    string "TLS library"
    default "none" if DCLAW_PROFILE_MINIMAL
    default "mbedtls" if DCLAW_PROFILE_STANDARD
    default "wolfssl" if DCLAW_PROFILE_EDGE

config DCLAW_MQTT_ENABLED
    bool "Enable MQTT cloud communication"
    default n if DCLAW_PROFILE_MINIMAL
    default y

config DCLAW_PII_REDACTION
    bool "Enable outbound PII redaction"
    default n if DCLAW_PROFILE_MINIMAL
    default y

config DCLAW_BLOOM_FILTER
    bool "Enable bloom filter for known-bad detection"
    default n if !DCLAW_PROFILE_EDGE
    default y if DCLAW_PROFILE_EDGE

endmenu
```

#### Core Data Structures

```c
/* defenseclaw.h - Public API */

#ifndef DEFENSECLAW_H
#define DEFENSECLAW_H

#include <stdint.h>
#include <stdbool.h>

/* --- Build-time configuration --- */
#include "config.h"

/* --- Enumerations --- */

typedef enum {
    DCLAW_ACTION_ALLOW = 0,
    DCLAW_ACTION_BLOCK = 1,
    DCLAW_ACTION_WARN  = 2,
    DCLAW_ACTION_ESCALATE = 3,  /* ask cloud */
} dclaw_action_t;

typedef enum {
    DCLAW_CAP_UNKNOWN     = 0x00,
    DCLAW_CAP_READ_FS     = 0x01,
    DCLAW_CAP_WRITE_FS    = 0x02,
    DCLAW_CAP_EXEC_SHELL  = 0x04,
    DCLAW_CAP_NET_FETCH   = 0x08,
    DCLAW_CAP_SEND_MSG    = 0x10,
    DCLAW_CAP_ACTUATE     = 0x20,  /* IoT-specific: motor/valve/relay */
    DCLAW_CAP_SENSOR_READ = 0x40,  /* IoT-specific: camera/mic/GPS */
} dclaw_capability_t;

typedef enum {
    DCLAW_SEV_INFO     = 0,
    DCLAW_SEV_LOW      = 1,
    DCLAW_SEV_MEDIUM   = 2,
    DCLAW_SEV_HIGH     = 3,
    DCLAW_SEV_CRITICAL = 4,
} dclaw_severity_t;

typedef enum {
    DCLAW_REASON_POLICY_TABLE   = 0x01,
    DCLAW_REASON_CAP_SEQUENCE   = 0x02,
    DCLAW_REASON_DEST_DENY      = 0x03,
    DCLAW_REASON_HASH_DENY      = 0x04,
    DCLAW_REASON_RATE_LIMIT     = 0x05,
    DCLAW_REASON_CLOUD_BLOCK    = 0x06,
    DCLAW_REASON_CLOUD_TIMEOUT  = 0x07,
    DCLAW_REASON_PII_DETECTED   = 0x08,
    DCLAW_REASON_BLOOM_HIT      = 0x09,
} dclaw_reason_t;

/* --- Core structures --- */

typedef struct {
    uint32_t device_id;
    uint16_t policy_version;
    uint16_t fw_version;
    uint8_t  hw_profile;       /* enum: MCU, RTOS, LINUX_SBC, GATEWAY */
    uint8_t  capabilities;     /* bitmask of supported features */
} dclaw_device_info_t;

typedef struct {
    char     tool_name[64];
    uint8_t  tool_hash[32];    /* SHA-256 of tool binary/manifest */
    uint8_t  cap_flags;        /* dclaw_capability_t bitmask */
    char     destination[128]; /* target URL/IP if network tool */
    uint16_t session_id;       /* correlator session tracking */
} dclaw_tool_request_t;

typedef struct {
    dclaw_action_t  action;
    dclaw_reason_t  reason;
    dclaw_severity_t severity;
    uint16_t        ttl_minutes;  /* 0 = no cache (local decision) */
    bool            from_cache;
} dclaw_verdict_t;

typedef struct {
    uint32_t timestamp;
    uint8_t  action;          /* dclaw_action_t */
    uint8_t  reason;          /* dclaw_reason_t */
    uint16_t target_hash;     /* truncated hash of tool/destination */
    uint16_t session_id;
    uint8_t  hmac[8];         /* truncated HMAC-SHA256, chains to prev */
    uint8_t  _pad[2];         /* alignment to 16 bytes */
} dclaw_audit_entry_t;       /* exactly 16 bytes */

/* --- Session State (Correlator) --- */

#define DCLAW_MAX_SESSIONS 16
#define DCLAW_SESSION_HISTORY_DEPTH 8

typedef struct {
    uint16_t session_id;
    uint8_t  cap_history[DCLAW_SESSION_HISTORY_DEPTH]; /* ring of capabilities */
    uint8_t  cap_head;         /* current position in ring */
    uint8_t  cap_count;        /* total capabilities in session */
    uint32_t started_at;       /* timestamp */
    uint32_t last_activity;    /* timestamp */
    uint8_t  risk_score;       /* 0-255, accumulated risk */
} dclaw_session_t;

/* --- API Functions --- */

/* Initialize the agent. Must be called before any other function. */
int dclaw_init(const dclaw_device_info_t *info);

/* Evaluate a tool call. Returns verdict synchronously. 
 * May block for up to DCLAW_VERDICT_TIMEOUT_MS if cloud escalation needed. */
dclaw_verdict_t dclaw_evaluate(const dclaw_tool_request_t *req);

/* Check if a destination IP/hostname is allowed. */
dclaw_action_t dclaw_check_destination(const char *host, uint16_t port);

/* Report a tool execution result (for post-call correlation). */
void dclaw_report_result(uint16_t session_id, const char *tool_name,
                         bool success, const char *output_summary);

/* Force sync audit ring to cloud (if MQTT enabled). */
int dclaw_flush_audit(void);

/* Apply a new policy blob (from OTA). Returns 0 on success. */
int dclaw_apply_policy(const uint8_t *blob, uint32_t blob_len,
                       const uint8_t *signature);

/* Get current health status for heartbeat. */
void dclaw_get_health(uint8_t *out_heartbeat, uint8_t *out_len);

/* Shutdown cleanly. Flushes audit, disconnects MQTT. */
void dclaw_shutdown(void);

#endif /* DEFENSECLAW_H */
```

### 6.2 Cloud Services (New Components)

#### Fleet Manager Service

```
┌──────────────────────────────────────────────────────────────────┐
│                      Fleet Manager Service                         │
│                      (Go, runs alongside existing gateway)         │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  Responsibilities:                                                 │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │ 1. Device Registry                                         │   │
│  │    • Register new devices (on first MQTT connect)          │   │
│  │    • Track device metadata (hw_profile, fw_version, etc)   │   │
│  │    • Device grouping (by site, hardware, policy profile)   │   │
│  │    • Decommissioning (revoke certificate, purge state)     │   │
│  └────────────────────────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │ 2. Heartbeat Processor                                     │   │
│  │    • Ingest heartbeats from MQTT (or edge batch API)       │   │
│  │    • Compute fleet-wide metrics:                           │   │
│  │      - Online device count                                 │   │
│  │      - Block rate (per device, per site, global)           │   │
│  │      - Policy version distribution                         │   │
│  │      - Audit chain integrity verification                  │   │
│  │    • Detect anomalies:                                     │   │
│  │      - Device silent > 3× heartbeat interval → alert       │   │
│  │      - Block spike (>5× baseline in 5min) → alert          │   │
│  │      - Audit chain break → tamper alert (P1)               │   │
│  └────────────────────────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │ 3. Alert Engine                                            │   │
│  │    • Rules: device_offline, block_spike, tamper_detect,    │   │
│  │      policy_drift, campaign_detected                       │   │
│  │    • Dispatch: webhook (reuse existing WebhookDispatcher), │   │
│  │      Splunk HEC, PagerDuty, Slack                          │   │
│  └────────────────────────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │ 4. Audit Sink                                              │   │
│  │    • Receive audit ring syncs (MQTT or edge batch)         │   │
│  │    • Verify HMAC chain continuity                          │   │
│  │    • Store in existing SQLite/Postgres audit DB            │   │
│  │    • Index by device_id, timestamp, action, reason         │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│  Integration with existing DefenseClaw:                           │
│  • Registers as connector type "iot-lite" in connector matrix     │
│  • Fleet metrics exposed via existing Prometheus endpoint         │
│  • Audit events flow into existing SIEM pipeline                  │
│  • Webhooks use existing WebhookDispatcher infrastructure         │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

#### Verdict Cache Service

```
┌──────────────────────────────────────────────────────────────────┐
│                     Verdict Cache Service                          │
│                     (Go, low-latency path)                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  Purpose: Serve cached scan verdicts to IoT devices without       │
│  re-running the full inspection pipeline for known hashes.         │
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                     Request Flow                            │   │
│  │                                                            │   │
│  │  Device → MQTT verdict/req                                  │   │
│  │       │                                                     │   │
│  │       ▼                                                     │   │
│  │  ┌─────────────────┐                                       │   │
│  │  │ Cache Lookup     │ ← O(1) hash map                      │   │
│  │  │ (in-memory)      │                                       │   │
│  │  └────────┬─────────┘                                       │   │
│  │           │                                                 │   │
│  │     ┌─────┴─────┐                                          │   │
│  │     │           │                                           │   │
│  │    HIT         MISS                                         │   │
│  │     │           │                                           │   │
│  │     ▼           ▼                                           │   │
│  │  Return      ┌──────────────────┐                           │   │
│  │  cached      │ Inspection        │                          │   │
│  │  verdict     │ Pipeline          │                          │   │
│  │  (<1ms)      │ (full 4-stage)    │                          │   │
│  │              │ ~50-200ms         │                          │   │
│  │              └────────┬──────────┘                          │   │
│  │                       │                                     │   │
│  │                       ▼                                     │   │
│  │              Store in cache with TTL                         │   │
│  │              Return verdict to device                        │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│  Cache Policy:                                                    │
│  • ALLOW verdicts: TTL = 24 hours (configurable)                  │
│  • BLOCK verdicts: TTL = 7 days (conservative)                    │
│  • WARN verdicts: TTL = 4 hours (re-evaluate frequently)          │
│  • Max entries: 10M (per edge) / 100M (cloud)                     │
│  • Eviction: LRU when capacity reached                            │
│  • Invalidation: on policy change or threat intel update          │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

#### Policy Compiler

```
┌──────────────────────────────────────────────────────────────────┐
│                      Policy Compiler                               │
│                      (Python, build-time tool)                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  Input:   policies/*.yaml (same files as full DefenseClaw)        │
│  Output:  • policy_tables.h (C header, compile-time embed)        │
│           • policy.bin (signed binary, OTA delivery)               │
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                    Compilation Pipeline                     │   │
│  │                                                            │   │
│  │  policies/default.yaml                                      │   │
│  │       │                                                     │   │
│  │       ▼                                                     │   │
│  │  ┌─────────────────────┐                                   │   │
│  │  │ 1. Parse YAML        │                                   │   │
│  │  │    Extract:          │                                   │   │
│  │  │    • severity→action │                                   │   │
│  │  │    • scanner_overrides│                                  │   │
│  │  │    • admission rules │                                   │   │
│  │  └────────┬─────────────┘                                   │   │
│  │           │                                                 │   │
│  │           ▼                                                 │   │
│  │  ┌─────────────────────┐                                   │   │
│  │  │ 2. Expand sequences  │                                   │   │
│  │  │    Generate all      │                                   │   │
│  │  │    capability        │                                   │   │
│  │  │    sequence rules    │                                   │   │
│  │  │    from Rego logic   │                                   │   │
│  │  └────────┬─────────────┘                                   │   │
│  │           │                                                 │   │
│  │           ▼                                                 │   │
│  │  ┌─────────────────────┐                                   │   │
│  │  │ 3. Generate C        │                                   │   │
│  │  │    • Sorted table    │                                   │   │
│  │  │    • Binary search   │                                   │   │
│  │  │    • Inline consts   │                                   │   │
│  │  └────────┬─────────────┘                                   │   │
│  │           │                                                 │   │
│  │           ▼                                                 │   │
│  │  ┌─────────────────────┐                                   │   │
│  │  │ 4. Sign (Ed25519)    │                                   │   │
│  │  │    • Hash content    │                                   │   │
│  │  │    • Sign with CA    │                                   │   │
│  │  │    • Embed version   │                                   │   │
│  │  └─────────────────────┘                                   │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│  Example output (policy_tables.h):                                │
│                                                                    │
│  static const dclaw_severity_rule_t severity_rules[] = {          │
│      { .severity = DCLAW_SEV_CRITICAL, .action = DCLAW_ACTION_BLOCK },│
│      { .severity = DCLAW_SEV_HIGH,     .action = DCLAW_ACTION_BLOCK },│
│      { .severity = DCLAW_SEV_MEDIUM,   .action = DCLAW_ACTION_WARN  },│
│  };                                                                │
│                                                                    │
│  static const dclaw_sequence_rule_t sequence_rules[] = {          │
│      { .seq = {DCLAW_CAP_NET_FETCH, DCLAW_CAP_EXEC_SHELL},        │
│        .seq_len = 2, .action = DCLAW_ACTION_BLOCK },              │
│      { .seq = {DCLAW_CAP_READ_FS, DCLAW_CAP_SEND_MSG},            │
│        .seq_len = 2, .action = DCLAW_ACTION_WARN },               │
│      { .seq = {DCLAW_CAP_NET_FETCH, DCLAW_CAP_ACTUATE},           │
│        .seq_len = 2, .action = DCLAW_ACTION_BLOCK },              │
│  };                                                                │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

---

## 7. Communication Protocol Design

### 7.1 MQTT Topic Schema

```
defenseclaw/
├── fleet/
│   ├── {device_id}/
│   │   ├── heartbeat          # Device → Cloud/Edge (QoS 0, periodic)
│   │   ├── register           # Device → Cloud/Edge (QoS 1, on boot)
│   │   ├── verdict/
│   │   │   ├── req            # Device → Cloud/Edge (QoS 1, on demand)
│   │   │   └── resp           # Cloud/Edge → Device (QoS 1, response)
│   │   ├── audit/
│   │   │   └── sync           # Device → Cloud/Edge (QoS 1, periodic)
│   │   ├── ota/
│   │   │   ├── policy         # Cloud/Edge → Device (QoS 1, on change)
│   │   │   ├── firmware       # Cloud/Edge → Device (QoS 1, on demand)
│   │   │   └── ack            # Device → Cloud/Edge (QoS 1, confirm)
│   │   └── cmd/
│   │       ├── request        # Cloud/Edge → Device (QoS 1, operator cmds)
│   │       └── response       # Device → Cloud/Edge (QoS 1, cmd result)
│   ├── broadcast/
│   │   ├── emergency-block    # Cloud → ALL devices (QoS 1, kill switch)
│   │   └── policy-update      # Cloud → ALL devices (QoS 0, notification)
│   └── edge/
│       ├── {edge_id}/
│       │   ├── status         # Edge → Cloud (QoS 1, edge health)
│       │   └── sync           # Edge ↔ Cloud (QoS 1, bidirectional)
│       └── announce           # Edge → Cloud (QoS 1, edge registration)
```

### 7.2 Message Formats (CBOR)

All messages use CBOR encoding (RFC 8949) for compact binary representation.

#### Heartbeat (32 bytes)

```
┌──────────────────────────────────────────────────────┐
│ Field              │ Type     │ Bytes │ Description   │
├──────────────────────────────────────────────────────┤
│ device_id          │ uint32   │ 4     │ Fleet-unique  │
│ uptime_sec         │ uint32   │ 4     │ Since boot    │
│ policy_version     │ uint16   │ 2     │ Active policy │
│ fw_version         │ uint16   │ 2     │ Firmware ver  │
│ denied_count       │ uint16   │ 2     │ Since last HB │
│ allowed_count      │ uint16   │ 2     │ Since last HB │
│ warned_count       │ uint16   │ 2     │ Since last HB │
│ escalated_count    │ uint16   │ 2     │ Cloud asks    │
│ cache_hit_pct      │ uint8    │ 1     │ 0-100         │
│ session_count      │ uint8    │ 1     │ Active sesns  │
│ audit_head_hmac    │ uint64   │ 8     │ Chain verify  │
│ flags              │ uint8    │ 1     │ See below     │
│ _reserved          │ uint8    │ 1     │ Alignment     │
├──────────────────────────────────────────────────────┤
│ Total                         │ 32    │               │
└──────────────────────────────────────────────────────┘

Flags byte:
  bit 0: OTA_PENDING      - firmware update waiting to apply
  bit 1: POLICY_STALE     - cloud unreachable, using cached policy
  bit 2: TAMPER_DETECT    - audit chain integrity failure
  bit 3: RING_FULL        - audit ring at capacity, sync needed
  bit 4: CERT_EXPIRING    - device cert expires within 30 days
  bit 5: OFFLINE_MODE     - no cloud connectivity
  bit 6: BOOT_FRESH       - first heartbeat after reboot
  bit 7: RESERVED
```

#### Verdict Request (74 bytes max)

```
┌──────────────────────────────────────────────────────┐
│ Field              │ Type       │ Bytes │ Description │
├──────────────────────────────────────────────────────┤
│ request_id         │ uint16     │ 2     │ Correlate   │
│ sha256             │ bytes[32]  │ 32    │ Tool hash   │
│ tool_name          │ text[32]   │ 1-33  │ CBOR string │
│ cap_flags          │ uint8      │ 1     │ Declared    │
│ session_risk       │ uint8      │ 1     │ 0-255       │
│ session_caps       │ uint8      │ 1     │ Prior caps  │
│ destination        │ text[0-64] │ 0-65  │ Optional    │
├──────────────────────────────────────────────────────┤
│ Typical                         │ ~42   │             │
│ Maximum                         │ ~135  │             │
└──────────────────────────────────────────────────────┘
```

#### Verdict Response (8 bytes)

```
┌──────────────────────────────────────────────────────┐
│ Field              │ Type     │ Bytes │ Description   │
├──────────────────────────────────────────────────────┤
│ request_id         │ uint16   │ 2     │ Correlate     │
│ action             │ uint8    │ 1     │ ALLOW/BLOCK   │
│ severity           │ uint8    │ 1     │ Finding sev   │
│ ttl_minutes        │ uint16   │ 2     │ Cache dur     │
│ reason_code        │ uint8    │ 1     │ For audit     │
│ flags              │ uint8    │ 1     │ See below     │
├──────────────────────────────────────────────────────┤
│ Total                         │ 8     │               │
└──────────────────────────────────────────────────────┘

Flags:
  bit 0: REVOKE_PRIOR   - invalidate any prior ALLOW for this hash
  bit 1: URGENT_SYNC    - device should sync audit immediately
  bit 2: POLICY_PUSH    - new policy available, fetch via OTA topic
```

### 7.3 Protocol State Machine

```
┌──────────────────────────────────────────────────────────────────────┐
│                  DEVICE COMMUNICATION STATE MACHINE                    │
├──────────────────────────────────────────────────────────────────────┤
│                                                                        │
│                          ┌──────────┐                                  │
│                          │  BOOT    │                                  │
│                          └────┬─────┘                                  │
│                               │                                        │
│                    Load certs, init TLS                                 │
│                               │                                        │
│                          ┌────▼─────┐                                  │
│                     ┌────│CONNECTING│────┐                              │
│                     │    └────┬─────┘    │                              │
│                     │         │          │                              │
│               Timeout/fail    │Success   │                              │
│                     │         │          │                              │
│                     ▼         ▼          │                              │
│              ┌──────────┐ ┌──────────┐   │                              │
│              │ OFFLINE  │ │REGISTERING│   │                              │
│              │          │ └────┬─────┘   │                              │
│              │ Local-only│      │         │                              │
│              │ enforce-  │  Reg ACK      │                              │
│              │ ment      │      │         │                              │
│              │          │ ┌────▼─────┐   │                              │
│              │          │ │  ONLINE  │   │                              │
│              │          │ │          │   │                              │
│              │          │ │ • HB loop│   │                              │
│              │          │ │ • Verdict│   │                              │
│              │          │ │ • Audit  │   │                              │
│              │          │ │ • OTA rx │   │                              │
│              │          │ └────┬─────┘   │                              │
│              │          │      │         │                              │
│              │          │  Disconnect    │                              │
│              │          │      │         │                              │
│              │    ┌─────▼──────▼───┐     │                              │
│              └───►│  RECONNECTING  │─────┘                              │
│                   │                │                                    │
│                   │ Exp. backoff:  │                                    │
│                   │ 1,2,4,8..300s  │                                    │
│                   └────────────────┘                                    │
│                                                                        │
│  Key Invariant: Enforcement NEVER stops regardless of comm state.      │
│  OFFLINE and RECONNECTING still evaluate all tool calls locally.       │
│                                                                        │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 8. Security Model

### 8.1 Device Identity and Authentication

```
┌──────────────────────────────────────────────────────────────────────┐
│                    DEVICE PKI ARCHITECTURE                             │
├──────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                    Certificate Hierarchy                         │  │
│  │                                                                 │  │
│  │  ┌─────────────────────────────────────────────────────────┐   │  │
│  │  │  DefenseClaw Root CA (offline, HSM-protected)            │   │  │
│  │  │  • Ed25519 key pair                                      │   │  │
│  │  │  • 10-year validity                                      │   │  │
│  │  │  • Signs: Intermediate CAs only                          │   │  │
│  │  └─────────────────────┬───────────────────────────────────┘   │  │
│  │                        │                                        │  │
│  │           ┌────────────┼────────────┐                           │  │
│  │           │            │            │                           │  │
│  │           ▼            ▼            ▼                           │  │
│  │  ┌──────────────┐ ┌──────────┐ ┌──────────────┐               │  │
│  │  │ Device CA    │ │ Edge CA  │ │ OTA Signing  │               │  │
│  │  │ (per fleet)  │ │          │ │ CA           │               │  │
│  │  │              │ │ Signs:   │ │              │               │  │
│  │  │ Signs:       │ │ edge gw  │ │ Signs:      │               │  │
│  │  │ device certs │ │ certs    │ │ firmware +   │               │  │
│  │  │              │ │          │ │ policy blobs │               │  │
│  │  │ 3-year       │ │ 3-year   │ │ 3-year      │               │  │
│  │  └──────┬───────┘ └────┬─────┘ └──────────────┘               │  │
│  │         │              │                                        │  │
│  │         ▼              ▼                                        │  │
│  │  ┌──────────────┐ ┌──────────────┐                             │  │
│  │  │ Device Cert  │ │ Edge GW Cert │                             │  │
│  │  │              │ │              │                             │  │
│  │  │ • Per-device │ │ • Per-gateway│                             │  │
│  │  │ • 1-year     │ │ • 1-year     │                             │  │
│  │  │ • Auto-renew │ │ • Auto-renew │                             │  │
│  │  │   at 80%     │ │   at 80%     │                             │  │
│  │  └──────────────┘ └──────────────┘                             │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                        │
│  Provisioning:                                                        │
│  • Manufacturing: device key generated in secure element (ATECC608B   │
│    or equivalent). CSR submitted to Device CA. Certificate stored     │
│    in protected flash alongside private key.                          │
│  • Field: Certificate rotation via MQTT cmd topic. New CSR generated  │
│    on-device, signed by Device CA, delivered via cmd/response.        │
│                                                                        │
│  Trust anchors (pinned in firmware):                                  │
│  • Root CA public key (for chain validation)                          │
│  • OTA Signing CA public key (for policy/firmware verification)       │
│  • MQTT broker server certificate fingerprint (anti-MitM)             │
│                                                                        │
└──────────────────────────────────────────────────────────────────────┘
```

### 8.2 Threat Mitigations

| Threat | Mitigation | Layer |
|--------|-----------|-------|
| Compromised cloud pushes malicious policy | Ed25519 signature verification on all OTA payloads. Device rejects unsigned or incorrectly signed updates. | Device |
| Attacker replays old MQTT messages | MQTT 5.0 message expiry + monotonic sequence numbers in verdict responses. Device rejects stale/replayed verdicts. | Protocol |
| Physical device tampering (flash read) | Private keys in secure element (hardware). Audit chain HMAC key derived from hardware-unique ID. | Hardware |
| Rogue device impersonation | mTLS — only devices with valid certificates can connect. Certificate pinning prevents CA compromise. | Transport |
| Cloud unavailable during attack | Fail-closed policy. Unknown tools BLOCKED locally. Attacker gains nothing by disconnecting cloud. | Architecture |
| Verdict cache poisoning (attacker gets ALLOW cached) | BLOCK verdicts have 7-day TTL, ALLOW has 24h. Threat intel push can instantly revoke any ALLOW. REVOKE_PRIOR flag in response. | Cache |
| Lateral movement between IoT devices | Each device's MQTT ACL limits publish/subscribe to its own topic tree. No device-to-device direct communication. | Broker |
| Firmware downgrade attack | Firmware includes monotonic version counter. Device rejects any OTA with version ≤ current. Anti-rollback fuse on supported hardware. | Device |
| Audit log tampering | HMAC chain — each entry's HMAC covers the previous entry. Breaking the chain is detectable by cloud. Hardware-bound HMAC key. | Persistence |
| Denial-of-service (flood MQTT broker) | Per-device rate limits at broker. QoS 1 (not 2) to limit state. Topic ACLs prevent publishing to other devices' topics. | Infrastructure |

### 8.3 Secure Boot Chain

```
┌───────────────────────────────────────────────────────────────┐
│                    SECURE BOOT SEQUENCE                         │
├───────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. ROM Bootloader (immutable)                                 │
│     │ Verify: Stage-2 bootloader signature                     │
│     │ Key: OTP-fused public key                                │
│     ▼                                                          │
│  2. Stage-2 Bootloader                                         │
│     │ Verify: Firmware image signature (Ed25519)               │
│     │ Check: Version counter ≥ stored counter (anti-rollback)  │
│     │ Key: OTA Signing CA public key                           │
│     ▼                                                          │
│  3. DefenseClaw Lite firmware                                  │
│     │ Verify: Policy blob signature                            │
│     │ Verify: Audit chain integrity (HMAC head matches flash)  │
│     │ Init: Load policy tables, open IPC hook, start MQTT      │
│     ▼                                                          │
│  4. AI Agent Runtime (untrusted)                               │
│     │ All tool calls routed through DefenseClaw Lite           │
│     │ DefenseClaw enforces regardless of agent state           │
│                                                                 │
│  Trust boundary: Between step 3 and step 4.                    │
│  DefenseClaw Lite is the TCB (Trusted Computing Base).         │
│  The AI agent is untrusted — it is the thing being secured.    │
│                                                                 │
└───────────────────────────────────────────────────────────────┘
```

---

## 9. Data Flow Analysis

### 9.1 Normal Operation (Tool Call Interception)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    DATA FLOW: TOOL CALL INTERCEPTION                           │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  ┌───────────┐     ┌─────────────────────────────────────────────────┐       │
│  │ AI Agent  │     │          DefenseClaw Lite (C)                    │       │
│  │           │     │                                                 │       │
│  │ Wants to  │     │  ┌─────┐   ┌────────┐   ┌───────┐   ┌──────┐ │       │
│  │ call tool │────►│  │ IPC │──►│Classify │──►│Correlat│──►│Policy│ │       │
│  │ "bash"    │     │  │Hook │   │        │   │       │   │Table │ │       │
│  │           │     │  └─────┘   └────────┘   └───────┘   └──┬───┘ │       │
│  │           │     │                                         │      │       │
│  │           │     │                              ┌──────────┘      │       │
│  │           │     │                              │                 │       │
│  │           │     │                         ┌────▼────┐            │       │
│  │           │     │                         │ Verdict │            │       │
│  │           │◄────│─────────────────────────│ BLOCK   │            │       │
│  │           │     │                         └────┬────┘            │       │
│  │ Receives  │     │                              │                 │       │
│  │ BLOCKED   │     │                         ┌────▼────┐            │       │
│  │           │     │                         │ Audit   │            │       │
│  └───────────┘     │                         │ Ring    │            │       │
│                    │                         └─────────┘            │       │
│                    └─────────────────────────────────────────────────┘       │
│                                                                                │
│  Latency: <5 microseconds (all local, no allocation, no syscall)             │
│  Data touched: 64 bytes tool_name, 8 bytes session state, 16 bytes rule      │
│                                                                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Cloud Escalation (Unknown Tool)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    DATA FLOW: CLOUD VERDICT ESCALATION                         │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  ┌────────┐  ┌──────────────────────┐  ┌───────────┐  ┌──────────────────┐  │
│  │  AI    │  │  DefenseClaw Lite    │  │   MQTT    │  │  Cloud/Edge      │  │
│  │ Agent  │  │  (C agent)           │  │  Broker   │  │  Verdict Cache   │  │
│  └───┬────┘  └───────────┬──────────┘  └─────┬─────┘  └────────┬─────────┘  │
│      │                   │                    │                  │            │
│      │ 1. tool_call      │                    │                  │            │
│      │ "custom-sensor"   │                    │                  │            │
│      │──────────────────►│                    │                  │            │
│      │                   │                    │                  │            │
│      │                   │ 2. Local check:    │                  │            │
│      │                   │    cache MISS      │                  │            │
│      │                   │    deny-list MISS  │                  │            │
│      │                   │    bloom: MAYBE    │                  │            │
│      │                   │                    │                  │            │
│      │                   │ 3. Publish         │                  │            │
│      │                   │    verdict/req     │                  │            │
│      │                   │───────────────────►│                  │            │
│      │                   │                    │ 4. Route to      │            │
│      │                   │                    │    verdict svc   │            │
│      │                   │                    │─────────────────►│            │
│      │                   │                    │                  │            │
│      │                   │                    │                  │ 5. Cache   │
│      │                   │                    │                  │    lookup  │
│      │                   │                    │                  │    MISS    │
│      │                   │                    │                  │            │
│      │                   │                    │                  │ 6. Run     │
│      │                   │                    │                  │    pipeline│
│      │                   │                    │                  │    (50ms)  │
│      │                   │                    │                  │            │
│      │                   │                    │ 7. verdict/resp  │            │
│      │                   │                    │◄─────────────────│            │
│      │                   │ 8. Receive verdict │                  │            │
│      │                   │◄───────────────────│                  │            │
│      │                   │                    │                  │            │
│      │                   │ 9. Cache verdict   │                  │            │
│      │                   │    (TTL: 24h)      │                  │            │
│      │                   │                    │                  │            │
│      │ 10. Return ALLOW  │                    │                  │            │
│      │◄──────────────────│                    │                  │            │
│      │                   │                    │                  │            │
│      │                   │ 11. Audit ring     │                  │            │
│      │                   │     write          │                  │            │
│      │                   │                    │                  │            │
│                                                                                │
│  Total latency: 100-500ms (dominated by network RTT)                         │
│  Device blocked during wait: YES (tool call is synchronous)                  │
│  Timeout: 5 seconds → automatic BLOCK                                        │
│                                                                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 9.3 OTA Policy Update

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    DATA FLOW: OVER-THE-AIR POLICY UPDATE                       │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  ┌─────────────────────┐  │
│  │   Admin     │  │  Policy      │  │  Cloud    │  │  Device             │  │
│  │  (writes    │  │  Compiler    │  │  MQTT     │  │  (DefenseClaw Lite) │  │
│  │   YAML)     │  │  (Python)    │  │  Broker   │  │                     │  │
│  └──────┬──────┘  └──────┬───────┘  └─────┬─────┘  └──────────┬──────────┘  │
│         │                │               │                    │              │
│         │ 1. Commit      │               │                    │              │
│         │ policies/      │               │                    │              │
│         │ strict.yaml    │               │                    │              │
│         │───────────────►│               │                    │              │
│         │                │               │                    │              │
│         │                │ 2. Compile    │                    │              │
│         │                │    YAML→bin   │                    │              │
│         │                │    + sign     │                    │              │
│         │                │               │                    │              │
│         │                │ 3. Publish    │                    │              │
│         │                │    ota/policy │                    │              │
│         │                │──────────────►│                    │              │
│         │                │               │                    │              │
│         │                │               │ 4. Deliver to     │              │
│         │                │               │    subscribed     │              │
│         │                │               │    devices        │              │
│         │                │               │───────────────────►│              │
│         │                │               │                    │              │
│         │                │               │                    │ 5. Verify   │
│         │                │               │                    │    Ed25519  │
│         │                │               │                    │    sig      │
│         │                │               │                    │              │
│         │                │               │                    │ 6. Check    │
│         │                │               │                    │    version  │
│         │                │               │                    │    > current│
│         │                │               │                    │              │
│         │                │               │                    │ 7. Apply    │
│         │                │               │                    │    to flash │
│         │                │               │                    │    (A/B     │
│         │                │               │                    │    partition)│
│         │                │               │                    │              │
│         │                │               │                    │ 8. Self-test│
│         │                │               │                    │    new policy│
│         │                │               │                    │              │
│         │                │               │ 9. ACK            │              │
│         │                │               │◄───────────────────│              │
│         │                │               │                    │              │
│         │                │               │                    │ 10. Heartbeat│
│         │                │               │                    │     shows new│
│         │                │               │                    │     version  │
│                                                                                │
│  Rollback: If self-test fails at step 8, device reverts to previous           │
│  policy partition and reports POLICY_STALE flag in heartbeat.                  │
│                                                                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Hardware Tier Profiles

### 10.1 Tier Definitions

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         HARDWARE TIER MATRIX                                   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  TIER 1: MCU (Bare Metal / RTOS)                                             │
│  ════════════════════════════════                                             │
│  CPU:     ARM Cortex-M4/M7, RISC-V RV32, ESP32                              │
│  Flash:   256 KB - 2 MB                                                       │
│  RAM:     64 KB - 512 KB                                                      │
│  OS:      Zephyr, FreeRTOS, bare metal                                       │
│  Network: WiFi, BLE, LoRa, 802.15.4                                         │
│  Profile: MINIMAL (30KB) or STANDARD (80KB)                                  │
│  Comms:   CoAP/DTLS (for ultra-constrained) or MQTT/TLS                     │
│  Examples: ESP32-S3, STM32H7, nRF5340, RP2040                               │
│                                                                                │
│  Constraints:                                                                 │
│  • No dynamic memory allocation (static pools only)                          │
│  • Single-threaded event loop (no preemption in minimal)                     │
│  • Limited TLS cipher suites (PSK or ECDSA-P256 only)                        │
│  • Flash write endurance limits (100K cycles typical)                         │
│                                                                                │
│  ─────────────────────────────────────────────────────────────────────────── │
│                                                                                │
│  TIER 2: Application Processor (Linux SBC)                                   │
│  ═════════════════════════════════════════                                    │
│  CPU:     ARM Cortex-A53/A72, x86_64 (low-power)                            │
│  Flash:   4 GB - 64 GB (eMMC/SD)                                             │
│  RAM:     512 MB - 4 GB                                                       │
│  OS:      Linux (Yocto, Debian, Ubuntu Core)                                 │
│  Network: Ethernet, WiFi, Cellular (4G/5G)                                   │
│  Profile: STANDARD (80KB) or EDGE (150KB)                                    │
│  Comms:   MQTT 5.0 / TLS 1.3                                                │
│  Examples: Raspberry Pi Zero 2W, BeagleBone, NVIDIA Jetson Nano              │
│                                                                                │
│  Constraints:                                                                 │
│  • Full Linux userspace available                                            │
│  • Can use netfilter/nftables hooks directly                                 │
│  • May run local LLM inference (edge AI)                                     │
│  • Power budget: 2-15W typical                                               │
│                                                                                │
│  ─────────────────────────────────────────────────────────────────────────── │
│                                                                                │
│  TIER 3: Industrial / Network Gateway                                        │
│  ════════════════════════════════════                                         │
│  CPU:     ARM Cortex-A (multi-core), x86_64                                 │
│  Flash:   8 GB - 256 GB (SSD/eMMC)                                           │
│  RAM:     2 GB - 32 GB                                                        │
│  OS:      IOS-XE, Linux (hardened)                                           │
│  Network: Multi-GbE, Cellular, Industrial Ethernet                           │
│  Profile: EDGE (150KB) — may also run Edge Gateway role                      │
│  Comms:   MQTT 5.0 / TLS 1.3 + optional gRPC                                │
│  Examples: Cisco IR1101, IR1800, Cisco Meraki MX, Dell Edge Gateway          │
│                                                                                │
│  Constraints:                                                                 │
│  • May serve dual role: IoT device AND edge gateway                          │
│  • Industrial certifications (IEC 61850, ATEX)                               │
│  • Extended temperature ranges                                               │
│  • High-availability requirements (watchdog, redundant comms)                │
│                                                                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 10.2 Feature Matrix by Tier

| Feature | Tier 1 (MCU) | Tier 2 (SBC) | Tier 3 (Gateway) |
|---------|-------------|-------------|-----------------|
| Policy table enforcement | Yes | Yes | Yes |
| Capability correlator | Yes (4 sessions) | Yes (16 sessions) | Yes (64 sessions) |
| Destination allow/deny | 32 entries | 256 entries | 1024 entries |
| Verdict cache | 16 entries | 64 entries | 256 entries |
| Hash deny-list | 32 hashes | 128 hashes | 512 hashes |
| Bloom filter | No | Optional | Yes |
| PII redaction | No | Yes (regex) | Yes (regex) |
| Firewall rule gen | No (no netfilter) | Yes (iptables) | Yes (nftables) |
| Audit ring | 64 entries | 256 entries | 1024 entries |
| MQTT client | CoAP or MQTT-SN | MQTT 5.0 | MQTT 5.0 |
| TLS | DTLS 1.2 (PSK) | TLS 1.3 (mTLS) | TLS 1.3 (mTLS) |
| OTA firmware | Yes (full image) | Yes (delta) | Yes (delta) |
| OTA policy | Yes | Yes | Yes |
| Secure element | Required | Recommended | Required |
| Watchdog | Hardware | Software | Both |

---

## 11. Failure Modes and Resilience

### 11.1 Failure Mode Analysis

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        FAILURE MODE MATRIX                                     │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  CATEGORY 1: COMMUNICATION FAILURES                                           │
│  ─────────────────────────────────────                                        │
│                                                                                │
│  ┌─────────────────────┬──────────────────┬──────────────────────────────┐   │
│  │ Failure             │ Detection        │ Response                      │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ MQTT disconnect     │ TCP keepalive /  │ Exponential backoff reconnect │   │
│  │ (transient)         │ MQTT PINGRESP    │ (1s→300s). Local enforcement │   │
│  │                     │ timeout          │ continues uninterrupted.      │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Cloud permanently   │ Reconnect fails  │ Enter OFFLINE mode. All      │   │
│  │ unreachable         │ 10 consecutive   │ verdicts from local policy   │   │
│  │                     │ times            │ only. Unknown tools BLOCKED. │   │
│  │                     │                  │ Set OFFLINE flag in state.    │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Edge gateway down   │ Same as above    │ Option B: try direct cloud   │   │
│  │ (Option B)          │ (edge MQTT)      │ fallback if configured.      │   │
│  │                     │                  │ Otherwise: full offline mode. │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Verdict timeout     │ 5-second timer   │ BLOCK the tool call. Log     │   │
│  │ (cloud too slow)    │ on pending req   │ CLOUD_TIMEOUT. Increment     │   │
│  │                     │                  │ denied_count.                 │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ TLS handshake fail  │ mbedTLS error    │ Retry with backoff. If cert  │   │
│  │ (cert expired)      │ code             │ expired: set CERT_EXPIRING   │   │
│  │                     │                  │ flag. Request renewal via     │   │
│  │                     │                  │ out-of-band channel.          │   │
│  └─────────────────────┴──────────────────┴──────────────────────────────┘   │
│                                                                                │
│  CATEGORY 2: DEVICE FAILURES                                                  │
│  ────────────────────────────                                                 │
│                                                                                │
│  ┌─────────────────────┬──────────────────┬──────────────────────────────┐   │
│  │ Failure             │ Detection        │ Response                      │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Power loss during   │ Boot self-check: │ A/B policy partition. Boot   │   │
│  │ policy OTA write    │ CRC of policy    │ from last-known-good if      │   │
│  │                     │ partition fails  │ active partition corrupted.   │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Flash wear-out      │ Write failure    │ Audit ring reduces write     │   │
│  │ (audit writes)      │ error code       │ frequency. Mark sector bad.  │   │
│  │                     │                  │ Migrate to spare sector.     │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Watchdog reset      │ Boot counter     │ If boot_count > 3 in 10min: │   │
│  │ (agent crash loop)  │ increment        │ enter safe mode (BLOCK ALL   │   │
│  │                     │                  │ tool calls, report to cloud) │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Secure element      │ Key operation    │ Fall back to software key    │   │
│  │ failure             │ returns error    │ (if allowed by policy). Or   │   │
│  │                     │                  │ enter lockdown: no comms.    │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Audit chain         │ HMAC verify on   │ Set TAMPER_DETECT flag.      │   │
│  │ corruption          │ boot fails       │ Report immediately. Enter    │   │
│  │                     │                  │ BLOCK-ALL until cloud ACKs.  │   │
│  └─────────────────────┴──────────────────┴──────────────────────────────┘   │
│                                                                                │
│  CATEGORY 3: ATTACK SCENARIOS                                                 │
│  ─────────────────────────────                                                │
│                                                                                │
│  ┌─────────────────────┬──────────────────┬──────────────────────────────┐   │
│  │ Attack              │ Detection        │ Response                      │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ AI agent attempts   │ Policy table     │ BLOCK. Audit log. Heartbeat  │   │
│  │ dangerous cap seq   │ + correlator     │ counter increment.           │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Flood of tool calls │ Rate limiter     │ DROP excess (token bucket).  │   │
│  │ (DoS on decision)   │ (token bucket)   │ Log RATE_LIMIT reason.       │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Agent tries to      │ IPC hook         │ BLOCK direct access. Only    │   │
│  │ bypass IPC hook     │ validates PIDs   │ registered agent PIDs can    │   │
│  │                     │                  │ submit tool calls.           │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Attacker floods     │ MQTT broker rate │ Broker drops excess msgs.    │   │
│  │ MQTT with fake HBs  │ limit + mTLS     │ mTLS prevents unauthd msgs. │   │
│  ├─────────────────────┼──────────────────┼──────────────────────────────┤   │
│  │ Coordinated fleet   │ Fleet Correlator │ Cloud detects N devices      │   │
│  │ attack (campaign)   │ (cloud-side)     │ blocking same pattern.       │   │
│  │                     │                  │ Push emergency-block to all. │   │
│  └─────────────────────┴──────────────────┴──────────────────────────────┘   │
│                                                                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 11.2 Graceful Degradation Ladder

```
FULL OPERATION ──────────────────────────────────────────────► LOCKDOWN
     │                                                              │
     │  Cloud + Edge + Device all healthy                          │
     │  • Full verdict requests                                    │
     │  • Real-time policy updates                                 │
     │  • Full observability                                       │
     │                                                              │
     ▼                                                              │
 DEGRADED-1: Cloud unreachable (edge still available)              │
     │  • Edge serves all verdicts (full pipeline)                 │
     │  • Policy updates stale (using last-synced)                 │
     │  • Audit buffered at edge (7-day local retention)           │
     │                                                              │
     ▼                                                              │
 DEGRADED-2: Edge unreachable (device alone)                        │
     │  • Local policy tables enforce                              │
     │  • Verdict cache serves known hashes                        │
     │  • Unknown tools BLOCKED (fail-closed)                      │
     │  • Audit ring accumulates locally                           │
     │  • Heartbeat flag: OFFLINE_MODE                             │
     │                                                              │
     ▼                                                              │
 DEGRADED-3: Verdict cache cold (fresh boot + no cloud)             │
     │  • Only policy table + correlator + deny-list active        │
     │  • Everything not in deny-list AND matching policy: ALLOW   │
     │  • Everything else: BLOCK                                   │
     │  • Very conservative (many false blocks)                    │
     │                                                              │
     ▼                                                              │
 LOCKDOWN: Tamper detected OR crash loop                            │
     • ALL tool calls BLOCKED                                       │
     • Device reports TAMPER_DETECT if comms available              │
     • Requires human intervention (re-provisioning)               │
```

---

## 12. Scalability Analysis

### 12.1 Option A (Hub-and-Spoke) Scaling

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                  OPTION A SCALING CHARACTERISTICS                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  Load Generators:                                                             │
│  • Heartbeats: N_devices × (1 / heartbeat_interval)                          │
│    = 100,000 × (1/30) = 3,333 msg/sec                                        │
│                                                                                │
│  • Verdict requests (peak): N_devices × tool_calls_per_sec × cache_miss_rate │
│    = 100,000 × 0.1 × 0.05 = 500 msg/sec (P50)                               │
│    = 100,000 × 1.0 × 0.20 = 20,000 msg/sec (P99 burst)                      │
│                                                                                │
│  • Audit syncs: N_devices × (1 / sync_interval)                              │
│    = 100,000 × (1/300) = 333 msg/sec                                         │
│                                                                                │
│  ┌────────────────────────────────────────────────────────────────────────┐   │
│  │  Component          │ Capacity per instance │ Horizontal scale        │   │
│  ├─────────────────────┼───────────────────────┼─────────────────────────┤   │
│  │  MQTT Broker        │ 200K connections      │ Cluster (EMQX/HiveMQ)  │   │
│  │  (EMQX)            │ 1M msg/sec            │                         │   │
│  ├─────────────────────┼───────────────────────┼─────────────────────────┤   │
│  │  Fleet Manager      │ 50K devices           │ Shard by device_id mod N│   │
│  │  (Go service)       │ 10K heartbeats/sec    │                         │   │
│  ├─────────────────────┼───────────────────────┼─────────────────────────┤   │
│  │  Verdict Cache      │ 10M entries in-memory │ Shard by hash prefix    │   │
│  │  (Go + Redis)       │ 50K lookups/sec       │                         │   │
│  ├─────────────────────┼───────────────────────┼─────────────────────────┤   │
│  │  Inspection Pipeline│ 1K full scans/sec     │ Worker pool (Kubernetes)│   │
│  │  (existing gateway) │                       │                         │   │
│  ├─────────────────────┼───────────────────────┼─────────────────────────┤   │
│  │  Audit DB           │ 100M events           │ TimescaleDB partitioning│   │
│  │  (Postgres/Timescale)│ 10K writes/sec       │                         │   │
│  └─────────────────────┴───────────────────────┴─────────────────────────┘   │
│                                                                                │
│  Bottleneck: Verdict requests during burst (P99: 20K/sec)                    │
│  Mitigation: Pre-warm verdict cache from known tool catalogs.                │
│              Cache hit rate target: 95%+ (after warm-up period)               │
│                                                                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 12.2 Option B (Edge Gateway) Scaling

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                  OPTION B SCALING CHARACTERISTICS                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  Edge Gateway Load (per site, 10K devices):                                   │
│  • Heartbeats: 10,000 × (1/30) = 333 msg/sec                                │
│  • Verdict requests: 10,000 × 0.1 × 0.05 = 50 msg/sec (P50)                │
│  • Audit syncs: 10,000 × (1/300) = 33 msg/sec                               │
│                                                                                │
│  Edge-to-Cloud Load (per edge):                                              │
│  • Aggregated heartbeat batch: 1 msg/5min (contains all device summaries)    │
│  • Audit batch upload: 1 msg/5min (compressed)                               │
│  • Policy pull: 1 msg/5min (if-modified-since)                               │
│  • Total: ~0.01 msg/sec per edge → cloud                                     │
│                                                                                │
│  ┌────────────────────────────────────────────────────────────────────────┐   │
│  │  Scaling Dimension     │ Limit              │ Solution                 │   │
│  ├────────────────────────┼────────────────────┼──────────────────────────┤   │
│  │  Devices per edge      │ 10,000             │ Add edge gateways        │   │
│  ├────────────────────────┼────────────────────┼──────────────────────────┤   │
│  │  Edges per cloud       │ Unlimited (cloud   │ Cloud is stateless;      │   │
│  │                        │ scales horizontally)│ edges are independent    │   │
│  ├────────────────────────┼────────────────────┼──────────────────────────┤   │
│  │  Verdict cache (edge)  │ 1M entries (~64MB) │ LRU eviction; cloud      │   │
│  │                        │                    │ refills on miss           │   │
│  ├────────────────────────┼────────────────────┼──────────────────────────┤   │
│  │  Edge gateway RAM      │ 2-4 GB             │ Sufficient for full      │   │
│  │                        │                    │ DefenseClaw + MQTT broker│   │
│  ├────────────────────────┼────────────────────┼──────────────────────────┤   │
│  │  WAN bandwidth         │ ~1 KB/s per edge   │ Negligible               │   │
│  │  (edge↔cloud)          │ (batch syncs only) │                          │   │
│  └────────────────────────┴────────────────────┴──────────────────────────┘   │
│                                                                                │
│  Key advantage: Edge absorbs burst traffic locally.                          │
│  Cloud only sees aggregated summaries → can scale to millions of devices.    │
│                                                                                │
│  Bandwidth comparison (100K devices):                                        │
│  • Option A: 100K × 32B × (1/30) = ~107 KB/s constant (heartbeats alone)   │
│  • Option B: 10 edges × 1KB/5min = ~0.03 KB/s to cloud                      │
│                                                                                │
│  That's a 3,500× bandwidth reduction at the cloud tier.                      │
│                                                                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 13. API Specification

### 13.1 Cloud Fleet Management API (REST)

```
BASE URL: https://defenseclaw.example.com/api/v1/fleet

────────────────────────────────────────────────────────────────────────────────
POST /devices/register
────────────────────────────────────────────────────────────────────────────────
Description: Register a new IoT device in the fleet
Auth: mTLS (device certificate validated by CA chain)

Request:
{
  "device_id": "uint32",
  "hw_profile": "enum(mcu|sbc|gateway)",
  "fw_version": "string (semver)",
  "policy_version": "uint16",
  "capabilities": ["policy_table", "correlator", "mqtt", "pii_redact"],
  "secure_element": "string (manufacturer/model)",
  "site_id": "string (optional, for edge assignment)"
}

Response: 201 Created
{
  "device_id": "uint32",
  "assigned_edge": "string (edge_id, Option B only)",
  "mqtt_broker": "string (connection URL)",
  "initial_policy_version": "uint16",
  "deny_list_version": "uint32"
}

────────────────────────────────────────────────────────────────────────────────
GET /devices/{device_id}
────────────────────────────────────────────────────────────────────────────────
Description: Get device status and metadata
Auth: Bearer token (admin) or mTLS (same device)

Response: 200 OK
{
  "device_id": "uint32",
  "hw_profile": "mcu",
  "status": "online|offline|degraded|lockdown",
  "last_heartbeat": "ISO8601",
  "policy_version": "uint16",
  "fw_version": "string",
  "site_id": "string",
  "assigned_edge": "string",
  "metrics": {
    "denied_total": "uint64",
    "allowed_total": "uint64",
    "uptime_sec": "uint32",
    "cache_hit_rate": "float (0-1)"
  },
  "flags": ["OFFLINE_MODE", "POLICY_STALE"]
}

────────────────────────────────────────────────────────────────────────────────
GET /devices?status={status}&site={site_id}&hw_profile={profile}
────────────────────────────────────────────────────────────────────────────────
Description: List devices with filtering
Auth: Bearer token (admin)

Response: 200 OK
{
  "devices": [...],
  "total": "uint32",
  "page": "uint32",
  "per_page": "uint32"
}

────────────────────────────────────────────────────────────────────────────────
POST /devices/{device_id}/command
────────────────────────────────────────────────────────────────────────────────
Description: Send command to device (via MQTT cmd topic)
Auth: Bearer token (admin)

Request:
{
  "command": "enum(reboot|sync_audit|rotate_cert|enter_lockdown|clear_lockdown)",
  "params": {}
}

Response: 202 Accepted
{
  "command_id": "uuid",
  "status": "pending"
}

────────────────────────────────────────────────────────────────────────────────
POST /policy/compile
────────────────────────────────────────────────────────────────────────────────
Description: Compile YAML policy to binary and distribute
Auth: Bearer token (admin)

Request:
{
  "policy_yaml": "string (YAML content)",
  "target_devices": "all | [device_ids] | {hw_profile: 'mcu'}",
  "staged_rollout": {
    "enabled": true,
    "batch_size_pct": 10,
    "pause_on_failure_pct": 5
  }
}

Response: 202 Accepted
{
  "rollout_id": "uuid",
  "policy_version": "uint16",
  "target_count": "uint32",
  "status": "compiling"
}

────────────────────────────────────────────────────────────────────────────────
GET /policy/rollout/{rollout_id}
────────────────────────────────────────────────────────────────────────────────
Description: Check rollout status
Auth: Bearer token (admin)

Response: 200 OK
{
  "rollout_id": "uuid",
  "status": "in_progress|completed|failed|paused",
  "progress": {
    "total": 10000,
    "applied": 3200,
    "failed": 12,
    "pending": 6788
  },
  "errors": [{"device_id": 42, "error": "signature_verify_failed"}]
}

────────────────────────────────────────────────────────────────────────────────
POST /audit/query
────────────────────────────────────────────────────────────────────────────────
Description: Query aggregated audit logs across fleet
Auth: Bearer token (admin)

Request:
{
  "device_ids": [1, 2, 3] | "all",
  "time_range": {"start": "ISO8601", "end": "ISO8601"},
  "action_filter": ["BLOCK"],
  "reason_filter": ["CAP_SEQUENCE", "HASH_DENY"],
  "limit": 1000
}

Response: 200 OK
{
  "entries": [
    {
      "device_id": 42,
      "timestamp": "ISO8601",
      "action": "BLOCK",
      "reason": "CAP_SEQUENCE",
      "tool_name": "bash",
      "session_id": 7,
      "hmac_valid": true
    }
  ],
  "total": 4521
}

────────────────────────────────────────────────────────────────────────────────
POST /threat-intel/push
────────────────────────────────────────────────────────────────────────────────
Description: Push new threat intelligence to fleet
Auth: Bearer token (admin)

Request:
{
  "new_deny_hashes": ["sha256_hex_strings"],
  "revoke_allow_hashes": ["sha256_hex_strings"],
  "updated_bloom_filter": "base64 (optional)",
  "emergency": false
}

Response: 202 Accepted
{
  "distribution_id": "uuid",
  "target_devices": 100000,
  "method": "mqtt_broadcast | edge_relay"
}

────────────────────────────────────────────────────────────────────────────────
GET /fleet/health
────────────────────────────────────────────────────────────────────────────────
Description: Fleet-wide health dashboard data
Auth: Bearer token (admin)

Response: 200 OK
{
  "total_devices": 100000,
  "online": 98542,
  "offline": 1200,
  "degraded": 250,
  "lockdown": 8,
  "policy_versions": {"23": 95000, "22": 4800, "21": 200},
  "last_hour": {
    "total_blocks": 42000,
    "total_allows": 8900000,
    "top_block_reasons": [
      {"reason": "CAP_SEQUENCE", "count": 28000},
      {"reason": "DEST_DENY", "count": 9000}
    ]
  },
  "alerts_active": 3
}
```

### 13.2 Edge-to-Cloud Sync API (gRPC)

```protobuf
// fleet_sync.proto

syntax = "proto3";
package defenseclaw.fleet;

service FleetSync {
  // Edge pulls latest policies
  rpc PullPolicy(PolicyRequest) returns (PolicyResponse);
  
  // Edge pushes aggregated heartbeats
  rpc PushHeartbeatBatch(HeartbeatBatch) returns (AckResponse);
  
  // Edge pushes aggregated audit logs
  rpc PushAuditBatch(AuditBatch) returns (AuditAckResponse);
  
  // Cloud streams threat intel updates to edge
  rpc StreamThreatIntel(ThreatIntelRequest) returns (stream ThreatIntelUpdate);
  
  // Edge reports its own health
  rpc ReportEdgeHealth(EdgeHealthReport) returns (AckResponse);
}

message PolicyRequest {
  string edge_id = 1;
  uint32 current_version = 2;
}

message PolicyResponse {
  uint32 version = 1;
  bytes policy_blob = 2;        // compiled binary
  bytes signature = 3;          // Ed25519
  bytes deny_list_delta = 4;    // new hashes since edge's version
  bytes bloom_filter = 5;       // full bloom (if changed)
  bool up_to_date = 6;         // true if no changes
}

message HeartbeatBatch {
  string edge_id = 1;
  repeated DeviceSummary devices = 2;
  uint64 batch_timestamp = 3;
}

message DeviceSummary {
  uint32 device_id = 1;
  uint32 last_heartbeat_ts = 2;
  uint32 denied_since_last = 3;
  uint32 allowed_since_last = 4;
  uint64 audit_head_hmac = 5;
  uint32 flags = 6;
}

message AuditBatch {
  string edge_id = 1;
  repeated DeviceAuditChunk chunks = 2;
  bytes batch_hmac = 3;         // HMAC over entire batch
}

message DeviceAuditChunk {
  uint32 device_id = 1;
  uint32 sequence_start = 2;
  repeated bytes entries = 3;   // raw 16-byte audit entries
}

message ThreatIntelUpdate {
  repeated bytes new_deny_hashes = 1;
  repeated bytes revoke_allow_hashes = 2;
  bytes bloom_filter_patch = 3;
  bool emergency = 4;           // if true: apply immediately, flush caches
}
```

---

## 14. Observability and Fleet Management

### 14.1 Metrics (Prometheus)

```
# Cloud-side metrics (aggregated from fleet)

defenseclaw_fleet_devices_total{status="online|offline|degraded|lockdown"} gauge
defenseclaw_fleet_policy_version{version="23"} gauge
defenseclaw_fleet_blocks_total{reason="cap_sequence|dest_deny|..."} counter
defenseclaw_fleet_allows_total counter
defenseclaw_fleet_verdict_latency_seconds{source="cache|pipeline"} histogram
defenseclaw_fleet_audit_chain_breaks_total counter
defenseclaw_fleet_ota_rollout_progress{rollout_id="..."} gauge

# Edge-side metrics (per edge gateway)

defenseclaw_edge_devices_connected gauge
defenseclaw_edge_verdict_cache_hit_rate gauge
defenseclaw_edge_mqtt_messages_total{direction="in|out"} counter
defenseclaw_edge_inspection_duration_seconds histogram
defenseclaw_edge_audit_buffer_entries gauge
defenseclaw_edge_cloud_sync_last_success_timestamp gauge
```

### 14.2 Alerting Rules

```yaml
# alert_rules.yaml

groups:
  - name: defenseclaw_fleet
    rules:
      - alert: DeviceOffline
        expr: time() - defenseclaw_fleet_device_last_seen > 180
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Device {{ $labels.device_id }} offline for >3 minutes"

      - alert: AuditChainTamper
        expr: defenseclaw_fleet_audit_chain_breaks_total > 0
        labels:
          severity: critical
        annotations:
          summary: "Audit chain integrity failure on device {{ $labels.device_id }}"

      - alert: BlockSpike
        expr: rate(defenseclaw_fleet_blocks_total[5m]) > 10 * avg_over_time(defenseclaw_fleet_blocks_total[1h])
        for: 2m
        labels:
          severity: high
        annotations:
          summary: "Block rate 10× above baseline — possible coordinated attack"

      - alert: PolicyDrift
        expr: count(defenseclaw_fleet_policy_version != on() group_left max(defenseclaw_fleet_policy_version)) > 0.1 * defenseclaw_fleet_devices_total
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: ">10% of fleet running outdated policy after 30 minutes"

      - alert: EdgeCloudSyncStale
        expr: time() - defenseclaw_edge_cloud_sync_last_success_timestamp > 600
        labels:
          severity: warning
        annotations:
          summary: "Edge {{ $labels.edge_id }} hasn't synced with cloud for >10 minutes"
```

### 14.3 Dashboard Layout (Grafana)

```
┌────────────────────────────────────────────────────────────────────┐
│                  DefenseClaw IoT Fleet Dashboard                     │
├────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────┐ │
│  │ DEVICES: 98K │ │  ONLINE: 97% │ │ BLOCKS/min:  │ │ ALERTS: 2  │ │
│  │  /100K       │ │              │ │    4,200     │ │  active    │ │
│  └──────────────┘ └──────────────┘ └──────────────┘ └────────────┘ │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │  BLOCK RATE OVER TIME (24h)                                     ││
│  │  ▁▂▂▃▃▃▃▂▂▂▃▃▄▄▃▃▂▂▁▁▂▂▃▃▃▃▂▂▂▁▁▂▂▃▃▃▃▂▂▁▁▁▂▂▃▃          ││
│  └─────────────────────────────────────────────────────────────────┘│
│                                                                      │
│  ┌──────────────────────────┐ ┌────────────────────────────────────┐│
│  │  TOP BLOCK REASONS       │ │  POLICY VERSION DISTRIBUTION       ││
│  │                          │ │                                    ││
│  │  CAP_SEQUENCE   ████ 67% │ │  v23 ████████████████████ 95%     ││
│  │  DEST_DENY      ██  21% │ │  v22 ██                   4.8%    ││
│  │  HASH_DENY      █    8% │ │  v21 ▏                    0.2%    ││
│  │  CLOUD_TIMEOUT  ▏    3% │ │                                    ││
│  │  RATE_LIMIT     ▏    1% │ │                                    ││
│  └──────────────────────────┘ └────────────────────────────────────┘│
│                                                                      │
│  ┌──────────────────────────┐ ┌────────────────────────────────────┐│
│  │  EDGE GATEWAY STATUS     │ │  DEVICE MAP (by site)              ││
│  │                          │ │                                    ││
│  │  Alpha  ● 3,200 dev OK  │ │  [Interactive topology map]        ││
│  │  Beta   ● 4,100 dev OK  │ │                                    ││
│  │  Gamma  ● 2,700 dev OK  │ │  Site Alpha (3200) ──── Cloud      ││
│  │  Delta  ◐ 1 dev offline │ │  Site Beta  (4100) ────┘           ││
│  │                          │ │  Site Gamma (2700) ────┘           ││
│  └──────────────────────────┘ └────────────────────────────────────┘│
│                                                                      │
└────────────────────────────────────────────────────────────────────┘
```

---

## 15. Migration Path from Full DefenseClaw

### 15.1 Integration with Existing Codebase

The IoT fleet services integrate with the existing DefenseClaw gateway as a new connector type:

```
┌──────────────────────────────────────────────────────────────────┐
│                EXISTING DEFENSECLAW GATEWAY                        │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              Connector Matrix (existing)                   │    │
│  │                                                          │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │    │
│  │  │ Claude   │ │ Codex    │ │ Cursor   │ │ iot-lite  │  │    │
│  │  │ Code     │ │          │ │          │ │  (NEW)    │  │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └─────┬─────┘  │    │
│  │                                                │         │    │
│  └────────────────────────────────────────────────┼─────────┘    │
│                                                   │              │
│  ┌────────────────────────────────────────────────▼─────────┐    │
│  │  IoT Fleet Module (NEW, embedded in gateway)              │    │
│  │                                                          │    │
│  │  • Subscribes to MQTT topics (or starts embedded broker) │    │
│  │  • Routes verdict requests to existing inspection pipeline│    │
│  │  • Feeds audit events to existing SIEM pipeline          │    │
│  │  • Exposes fleet REST API on existing HTTP server        │    │
│  │  • Reuses: WebhookDispatcher, audit.Store, policy.Engine │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                    │
│  Reused components (zero modification):                           │
│  • internal/gateway/inspect.go (inspection pipeline)              │
│  • internal/policy/ (OPA engine for verdict evaluation)           │
│  • internal/scanner/ (YARA scanning for verdict requests)         │
│  • internal/audit/ (audit store for fleet events)                 │
│  • internal/redaction/ (PII handling in verdict requests)         │
│  • internal/guardrail/ (correlator logic, reference impl)         │
│  • internal/firewall/ (compiler, generates rules for devices)     │
│                                                                    │
│  New components:                                                  │
│  • internal/fleet/ (fleet manager, heartbeat, OTA)                │
│  • internal/fleet/verdict/ (verdict cache service)                │
│  • internal/fleet/compiler/ (policy YAML→C compiler)              │
│  • internal/fleet/mqtt/ (MQTT broker integration)                 │
│  • cmd/defenseclaw-fleet/ (CLI for fleet management)              │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### 15.2 Shared Policy Format

The same `policies/*.yaml` files used by full DefenseClaw work for IoT:

```yaml
# policies/strict.yaml — works identically for both tiers

name: strict
description: Strict security for production IoT deployments

admission:
  scan_on_install: true
  allow_list_bypass_scan: false    # IoT: always scan via cloud

skill_actions:
  critical:
    file: quarantine
    runtime: disable              # IoT: maps to BLOCK
    install: block
  high:
    file: quarantine
    runtime: disable              # IoT: maps to BLOCK
    install: block
  medium:
    file: none
    runtime: enable               # IoT: maps to ALLOW
    install: none

# IoT-specific extensions (ignored by full gateway)
iot_extensions:
  capability_sequences:
    - sequence: [net_fetch, exec_shell]
      action: block
    - sequence: [read_fs, send_msg]
      action: warn
    - sequence: [net_fetch, actuate]
      action: block
    - sequence: [sensor_read, net_fetch]
      action: warn
  
  destination_allowlist:
    - "api.openai.com"
    - "api.anthropic.com"
    - "*.cisco.com"
  
  rate_limits:
    tool_calls_per_minute: 60
    network_requests_per_minute: 30
    actuations_per_minute: 10
```

---

## 16. Delivery Phases

### Phase 1: Foundation (8 weeks)

**Objective:** Core C agent running on Linux SBC with MQTT cloud connectivity

**Deliverables:**
- DefenseClaw Lite C agent (STANDARD profile)
  - Policy table enforcement
  - Capability correlator (session FSM)
  - IPC hook (Unix socket, JSON-RPC intercept)
  - Audit ring buffer with HMAC chain
  - MQTT 5.0 client with mTLS
  - Heartbeat reporting
- Policy compiler (Python tool, YAML → C headers + binary)
- Cloud fleet manager (device registration, heartbeat processing)
- Verdict request/response protocol
- Integration with existing inspection pipeline for verdict evaluation

**Target hardware:** Raspberry Pi 4, NVIDIA Jetson Nano

**Exit criteria:**
- Agent blocks dangerous capability sequences locally in <5us
- Verdict requests return from cloud in <500ms P95
- Heartbeats aggregate correctly in fleet dashboard
- Audit chain verifiable end-to-end

---

### Phase 2: Edge Gateway + Production Hardening (8 weeks)

**Objective:** Option B topology with edge gateways, full offline operation

**Deliverables:**
- Edge gateway mode (full DefenseClaw + MQTT broker + verdict cache)
- Edge-to-cloud gRPC sync protocol
- Staged OTA rollout (policy + firmware)
- Bloom filter distribution for known-bad detection
- PII redaction module (outbound regex)
- Firewall rule generation (nftables integration)
- Device certificate rotation protocol
- Grafana dashboards + alerting rules
- Failure mode testing (chaos engineering)

**Target hardware:** Cisco IR1101 (edge), Raspberry Pi Zero 2W (device)

**Exit criteria:**
- Edge gateway serves verdicts in <10ms P95
- Fleet operates normally during 1-hour WAN outage
- Policy rollout to 10K devices completes in <15 minutes
- Zero audit entries lost during edge↔cloud sync

---

### Phase 3: MCU Support + Industrial (8 weeks)

**Objective:** Tier 1 (MCU) support, industrial certifications, scale testing

**Deliverables:**
- MINIMAL profile C agent (30KB, Zephyr/FreeRTOS)
- CoAP/DTLS transport (for ultra-constrained devices)
- Secure element integration (ATECC608B, Infineon OPTIGA)
- Anti-rollback enforcement (hardware fuse support)
- Secure boot chain integration (MCUboot)
- Scale testing: 100K simulated devices
- Fleet correlator (cross-device campaign detection)
- Emergency broadcast (fleet-wide kill switch)
- Compliance documentation (NIST AI RMF mapping)

**Target hardware:** ESP32-S3, STM32H7, nRF5340

**Exit criteria:**
- Agent runs within 32KB RAM on Cortex-M7
- 100K simulated devices operate without cloud degradation
- Emergency block propagates to all devices in <30 seconds
- Audit chain survives power cycle on MCU

---

### Phase 4: Advanced Capabilities (8 weeks)

**Objective:** Advanced threat detection, fleet intelligence, Cisco portfolio integration

**Deliverables:**
- Fleet-wide anomaly detection (ML-based, runs on cloud)
- Cisco Umbrella DNS integration (for destination filtering)
- Cisco XDR integration (IoT incidents in XDR console)
- Device-to-device mesh verdict sharing (Tier 3 only)
- IoT-specific guardrail rules (actuator safety, sensor privacy)
- Performance optimization (cache pre-warming, predictive verdicts)
- Multi-tenant fleet isolation
- SOC 2 / ISO 27001 compliance artifacts

**Exit criteria:**
- Campaign detection identifies coordinated attack across 5+ devices in <60s
- Cisco XDR displays IoT defense events alongside network/endpoint events
- Multi-tenant isolation verified (tenant A cannot see tenant B devices)

---

## 17. Decision Log

| # | Decision | Rationale | Alternatives Considered |
|---|----------|-----------|------------------------|
| D1 | C language for IoT agent | Deterministic memory, no GC pauses, runs on bare metal. Critical for sub-microsecond enforcement. | Rust (excellent safety but larger runtime, less MCU toolchain support), Go (too large for MCU), MicroPython (too slow) |
| D2 | MQTT 5.0 as primary IoT protocol | Lightweight, well-supported on constrained devices, QoS levels, topic-based routing, session persistence. MQTT 5.0 adds message expiry and shared subscriptions. | CoAP (used as fallback for Tier 1), AMQP (too heavy), gRPC (requires HTTP/2, too heavy for MCU) |
| D3 | mTLS for device authentication | Strongest identity model. Each device has unique cert from manufacturing. Prevents impersonation and enables zero-trust. | PSK (simpler but key rotation is hard, no individual revocation), JWT (stateless but requires clock sync on constrained devices) |
| D4 | Fail-closed on unknowns | Security invariant: a disconnected device that encounters unknown tools should not allow them. Availability is secondary to security for AI agent governance. | Fail-open (dangerous for safety-critical IoT), Fail-warn (useless without cloud to receive warning) |
| D5 | Compiled policy tables (not embedded Rego) | OPA/Rego requires a VM that won't fit on MCU (OPA Go binary alone is ~20MB). Compiled tables give O(1) lookup in <1us. Trade-off: no hot-reload, requires OTA for policy changes. | Embedded Rego (too large), Lua VM (possible but adds 100KB+), custom DSL interpreter (maintenance burden) |
| D6 | Ed25519 for OTA signatures | Small keys (32 bytes), fast verification (even on MCU), no patent issues, quantum-resistant roadmap (can migrate to Ed448). | RSA-2048 (keys too large for constrained devices), ECDSA-P256 (patent concerns in some jurisdictions, slower verify) |
| D7 | CBOR encoding for messages | Binary, schema-less, compact (~30% smaller than JSON), first-class IETF standard, wide IoT adoption (LwM2M, COSE, SUIT). | Protobuf (excellent but requires codegen tooling per platform), MessagePack (less standardized), FlatBuffers (zero-copy but complex) |
| D8 | A/B partition for policy OTA | Atomic updates: either the new policy is fully applied or the old one remains. Protects against power-loss during write. | Single partition + journal (complex recovery), copy-on-write (requires more flash) |
| D9 | Edge gateway is full DefenseClaw | Reuses 100% of existing inspection pipeline. No new scanning code needed. Edge just runs the gateway binary with an additional MQTT module. | Custom edge binary (maintenance burden), Cloud functions at edge (latency variability) |
| D10 | 16-byte audit entries (fixed size) | Flash-friendly (aligned), predictable ring size, no fragmentation. HMAC chain computed over fixed-size blocks. | Variable-size entries (more flexible but complex ring management), structured log (requires parser on device) |

---

## Appendices

### A. Glossary

| Term | Definition |
|------|-----------|
| **DefenseClaw Lite** | The C-language IoT enforcement agent (this proposal) |
| **DefenseClaw Gateway** | The existing full Go-language security gateway |
| **Edge Gateway** | A site-local server running full DefenseClaw + MQTT broker |
| **Verdict** | The ALLOW/BLOCK/WARN decision for a tool call |
| **Verdict Cache** | In-memory store of hash→verdict mappings with TTL |
| **Policy Table** | Compiled C struct array of enforcement rules |
| **Capability Correlator** | FSM tracking tool capability sequences per session |
| **Audit Ring** | Fixed-size circular buffer of enforcement decisions |
| **HMAC Chain** | Each audit entry's HMAC covers the previous entry (tamper evidence) |
| **OTA** | Over-The-Air update (firmware or policy) |
| **Bloom Filter** | Probabilistic set for known-bad hash pre-screening |
| **Heartbeat** | Periodic 32-byte status packet from device to cloud/edge |
| **Fail-closed** | Unknown tools are BLOCKED when cloud is unreachable |

### B. Related Documents

| Document | Location | Relevance |
|----------|----------|-----------|
| DefenseClaw Architecture | `docs/ARCHITECTURE.md` | Full system architecture (reference) |
| Guardrail Design | `docs/GUARDRAIL.md` | Correlator logic (ported to C) |
| Connector Matrix | `docs/CONNECTOR-MATRIX.md` | IoT-lite connector registration |
| Policy Format | `policies/*.yaml` | Shared policy format |
| Observability Contract | `docs/OBSERVABILITY-CONTRACT.md` | Telemetry standards |

### C. Open Questions

| # | Question | Impact | Owner |
|---|----------|--------|-------|
| Q1 | Should IoT-specific capability classes (ACTUATE, SENSOR_READ) be added to the full gateway's guardrail correlator as well? | Policy portability | Architecture team |
| Q2 | What is the minimum LLM Judge inspection that could run on a Tier 3 gateway device (Cisco IR1101 with 1GB RAM)? | Edge intelligence depth | ML team |
| Q3 | Should the fleet manager be a separate microservice or embedded in the existing gateway binary? | Deployment complexity vs. resource sharing | Platform team |
| Q4 | What secure element should be the reference implementation? ATECC608B vs. Infineon OPTIGA vs. ARM TrustZone? | Hardware partnership, supply chain | Hardware team |
| Q5 | Is MQTT 5.0 shared subscription sufficient for load-balanced edge gateways, or do we need a dedicated message bus? | Edge HA architecture | Infrastructure team |

### D. References

1. MQTT 5.0 Specification (OASIS Standard)
2. RFC 8949 - Concise Binary Object Representation (CBOR)
3. RFC 8152 - CBOR Object Signing and Encryption (COSE)
4. NIST AI RMF 1.0 - AI Risk Management Framework
5. EU AI Act - Article 9 (Risk Management System)
6. SUIT Manifest (RFC 9019) - Software Updates for IoT
7. ARM PSA Certified - Platform Security Architecture
8. Zephyr Project - RTOS for constrained devices
9. EMQX - Scalable MQTT broker
10. DefenseClaw Internal Architecture Documentation

---

*End of Document*
