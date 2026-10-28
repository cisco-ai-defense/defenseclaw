# DefenseClaw Edge Connector

The Edge Connector is a C enforcement engine for Linux edge devices. It evaluates agent tool calls locally and can request hash-based verdicts from a DefenseClaw Fleet gateway over MQTT 3.1.1. The gateway blocks unknown tool hashes by default; it does not run a remote model over the request content. See the [installation guide](INSTALL.md) for production TLS, device keys, broker ACLs, and the Linux service unit.

The C engine recognizes a fixed set of tool names and capabilities. An unknown name fails closed before the verdict cache or Fleet escalation, even when the caller declares a capability. Custom tool names need a reviewed C capability mapping; a Python adapter mapping alone cannot authorize the daemon.

## Features and limits

- Local policy checks, rate limiting, sequence correlation, verdict caching, and a tamper-evident audit ring.
- Built-in content patterns for secrets, credentials, PII, exfiltration indicators, injection text, and dangerous commands. The policy YAML cannot change or disable these patterns in this release.
- An all-profile SSRF guard for network destinations. Network calls need an allowlisted canonical public IPv4 or globally scoped IPv6 literal (an IPv6 entry is written without brackets); hostnames, private addresses, and numeric aliases are blocked until an enforced egress resolver/proxy exists.
- MQTT verdict requests to the Fleet gateway. Synchronous escalation blocks on timeout; speculative escalation may allow immediately even if publication fails. A later block cannot undo that action.
- Policy and emergency OTA with anti-rollback and a local canary window. The current C receiver supports only explicit HMAC policy signing: build with `-DDCLAW_ALLOW_HMAC_OTA=ON` and provision the matching nonzero `DCLAW_OTA_HMAC_KEY`. Ed25519 compiler output is not accepted by this receiver. Emergency commands use a separate `DCLAW_EMERGENCY_KEY`.
- Signed 72-byte heartbeat and registration frames with a persistent boot counter and last-applied emergency sequence. Upgrade the gateway and devices together; the gateway rejects older 64- and 68-byte keyed frames. Missed emergency commands replay in signed predecessor order from the durable Fleet history.

Measure binary size, memory use, and evaluation latency on your target and build profile. TLS libraries and compiler flags materially affect those values.

## Build and test

```bash
cd edge-connector
mkdir build && cd build
cmake .. -DDCLAW_PROFILE=STANDARD -DDCLAW_DEV_MODE=OFF -DDCLAW_ALLOW_HMAC_OTA=ON
make -j$(nproc)
ctest --output-on-failure
```

Production MQTT requires mbedTLS 3.x development libraries and a broker CA. `MINIMAL` has no MQTT; `STANDARD` and `EDGE` include MQTT. Test counts depend on the selected profile. `./tests/bench_latency` measures a local build when that benchmark target is available.

## Policy compiler

From the `edge-connector/` directory, with Python 3 and PyYAML installed:

```bash
python3 tools/policy_compiler.py \
  --input policies/strict.yaml \
  --profile standard --version 1 \
  --output-header policy_tables.h \
  --output-binary policy.bin
```

The compiler accepts the supported `iot_extensions` fields `capability_sequences`, `destination_allowlist`, and `canary`. Its content DFA is built from fixed compiler constants, not YAML content patterns. It rejects unsupported IoT settings such as `rate_limits`, `escalation_mode`, `content_inspection`, `ssrf_protection`, `destination_denylist`, `trust_boundaries`, `cloud_escalation`, and `broker_fallback`. The compiled rate limits are 60 tool calls, 30 network requests, and 10 actuations per minute; OTA cannot change them. Production uses synchronous escalation by default. Without a signing key, `policy.bin` has a development stub signature and production C devices reject it. For production OTA, use the Fleet policy-push API with matching HMAC secrets.

The [Edge documentation](../docs-site/content/docs/edge-connector/index.mdx) describes policies, integration adapters, the Fleet API, and observability. The Fleet dashboard source is [fleet-dashboard.json](dashboards/fleet-dashboard.json); the provisioned copy ships in the local observability bundle.
