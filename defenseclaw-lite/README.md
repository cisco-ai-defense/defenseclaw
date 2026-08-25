# DefenseClaw Lite

Sub-microsecond AI agent security enforcement for IoT and edge devices.

## Overview

DefenseClaw Lite is a purpose-built C-language enforcement agent (~54KB binary) that
provides local policy enforcement while delegating complex analysis (YARA, LLM judge,
OPA) to a cloud DefenseClaw instance via MQTT 5.0.

**Architecture:** See `docs/architecture/defenseclaw-lite-iot-proposal.md` (v1.2)  
**Spec:** See `docs/specs/001-defenseclaw-lite-phase1/`

## Build

```bash
cd defenseclaw-lite
mkdir build && cd build
cmake .. -DDCLAW_PROFILE=STANDARD
make
```

Profiles: `MINIMAL` (22KB), `STANDARD` (54KB), `EDGE` (131KB)

## Test

```bash
cd build
ctest --output-on-failure
```

10 test binaries, 100+ assertions covering:
- Input validation (IPC boundary)
- Policy table (hash deny, destination allow/deny, severity)
- Capability correlator (sequence detection)
- Audit ring (HMAC chain, write coalescing, BLOCK bypass)
- Rate limiter (3 token buckets)
- Verdict cache (TTL, LRU, clock-trust)
- Full evaluate pipeline (end-to-end)
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

## Directory Structure

```
defenseclaw-lite/
├── src/
│   ├── dclaw_core.c          # Init, evaluate pipeline, state
│   ├── decision/             # Policy table, correlator, verdict cache
│   ├── enforce/              # IPC hook, JSON parser, rate limiter
│   ├── persist/              # Audit ring, flash, config store
│   ├── comms/                # MQTT, CBOR, verdict protocol, OTA
│   └── platform/             # HAL (Linux implementation)
├── include/                  # Public headers (defenseclaw.h, platform.h)
├── generated/                # Compiled policy tables
├── policies/                 # YAML policy files
├── tools/                    # Policy compiler (Python)
├── tests/                    # Unit tests, acceptance, benchmark, fuzz
├── dashboards/               # Grafana dashboard JSON
└── CMakeLists.txt            # Build system
```

## Cloud Components

Fleet Manager and Verdict Cache implemented in Go at `internal/fleet/`:
- `internal/fleet/manager/` — Device registry, heartbeat, anomaly detection
- `internal/fleet/verdict/` — LRU verdict cache with TTL
- `internal/fleet/api.go` — REST API (`/api/v1/fleet/`)
- `internal/fleet/metrics.go` — Prometheus metrics
