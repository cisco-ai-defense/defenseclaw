# DefenseClaw Edge Connector

Sub-microsecond AI agent security enforcement for IoT and edge devices.

## Overview

DefenseClaw Edge Connector is a purpose-built C-language enforcement agent (~68KB binary) that
provides local policy enforcement with AI-aware content inspection, delegating complex analysis
(YARA, LLM judge, OPA) to a cloud DefenseClaw instance via MQTT 5.0. Unlike purely rule-based
policy engines, the Edge Connector inspects the actual content of tool call arguments and LLM
responses to detect secrets, PII, credential leakage, data exfiltration, prompt injection, and
dangerous commands before they leave the device.

**Architecture:** See `docs/architecture/defenseclaw-lite-iot-proposal.md` (v1.2)  
**Spec:** See `docs/specs/001-defenseclaw-lite-phase1/`

## Features

- **8-stage evaluation pipeline** with sub-5us latency on ARM Cortex-A
- **Content scanning** — detects secrets, PII, credentials, data exfiltration patterns, injection attempts, and dangerous commands in tool arguments and LLM outputs
- **SSRF validation** — blocks requests to private/internal IP ranges and metadata endpoints before they reach the network
- **Trust boundary inference** — automatically determines trust level from capability flags, destination, and content risk signals
- **Enriched cloud escalation** — forwards actual content snippets (truncated to policy limits) to the cloud DefenseClaw instance for deeper analysis
- **Response interception** — scans LLM responses for leaked secrets, PII, and credential material before they reach the agent
- **Sequence correlation** — FSM-based detection of dangerous multi-step capability patterns
- **Rate limiting** — 3 independent token buckets (tool calls, network, actuations)
- **HMAC-chained audit trail** — tamper-evident ring buffer with write coalescing
- **Verdict caching** — LRU cache with TTL and clock-trust validation
- **Destination filtering** — allowlist/denylist with wildcard domain matching
- **OTA policy updates** — Ed25519-signed, anti-rollback, canary deployment

## Build

```bash
cd edge-connector
mkdir build && cd build
cmake .. -DDCLAW_PROFILE=STANDARD
make
```

Profiles: `MINIMAL` (22KB), `STANDARD` (68KB), `EDGE` (131KB)

## Test

```bash
cd build
ctest --output-on-failure
```

10 test binaries, 100+ assertions covering:
- Input validation (IPC boundary)
- Policy table (hash deny, destination allow/deny, severity)
- Capability correlator (sequence detection)
- Content scanner (secrets, PII, credentials, exfil, injection, commands)
- Audit ring (HMAC chain, write coalescing, BLOCK bypass)
- Rate limiter (3 token buckets)
- Verdict cache (TTL, LRU, clock-trust)
- Full evaluate pipeline (end-to-end, 8 stages)
- Verdict protocol (HMAC verification, dedup, clock sync)
- OTA + Emergency (Ed25519, anti-rollback, canary, sequence replay)
- Acceptance tests (AC-01 through AC-12)

## Benchmark

```bash
cd build
./tests/bench_latency
```

## Policy Compiler

```bash
python3 tools/policy_compiler.py \
  --input policies/strict.yaml \
  --profile standard \
  --version 1 \
  --output-header generated/policy_tables.h \
  --output-binary dist/policy.bin
```

The compiler generates DFA tables from capability sequence definitions and content
pattern rules in the policy YAML, producing both a C header for static linking and
a binary blob for OTA distribution. DFA table generation converts the sequence
patterns and regex-based content rules into compact deterministic finite automata
that can be evaluated in constant time per input symbol.

## Directory Structure

```
edge-connector/
├── src/
│   ├── dclaw_core.c              # Init, evaluate pipeline, state
│   ├── decision/                 # Policy table, correlator, verdict cache
│   │   └── content_scanner.c     # Content inspection (secrets, PII, exfil, injection)
│   ├── enforce/                  # IPC hook, JSON parser, rate limiter
│   ├── persist/                  # Audit ring, flash, config store
│   ├── comms/                    # MQTT, CBOR, verdict protocol, OTA
│   └── platform/                 # HAL (Linux implementation)
├── include/                      # Public headers (defenseclaw.h, platform.h)
│   └── content_scanner.h         # Content scanner API and pattern category flags
├── generated/                    # Compiled policy tables (including DFA tables)
├── policies/                     # YAML policy files
├── tools/                        # Policy compiler (Python)
├── tests/                        # Unit tests, acceptance, benchmark, fuzz
├── dashboards/                   # Grafana dashboard JSON
└── CMakeLists.txt                # Build system
```

## Size

| Profile | Binary | RAM |
|---------|--------|-----|
| `MINIMAL` | ~22KB | ~8KB |
| `STANDARD` | ~68KB | ~14-19KB |
| `EDGE` | ~131KB | ~64KB |

## Cloud Components

Fleet Manager and Verdict Cache implemented in Go at `internal/fleet/`:
- `internal/fleet/manager/` — Device registry, heartbeat, anomaly detection
- `internal/fleet/verdict/` — LRU verdict cache with TTL
- `internal/fleet/api.go` — REST API (`/api/v1/fleet/`)
- `internal/fleet/metrics.go` — Prometheus metrics
