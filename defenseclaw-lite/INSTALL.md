# DefenseClaw Edge Connector — Installation Guide

Secure any AI agent on Linux with sub-microsecond policy enforcement and AI-aware content inspection. Three installation methods: pre-built binary (30 seconds), pip install (1 minute), or build from source (5 minutes).

---

## Quick Start (Pre-Built Binary)

Download and run — no compiler needed.

```bash
# Download latest release for your architecture
curl -fsSL https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/edge-connector-linux-arm64.tar.gz | tar xz

# Or for x86_64:
curl -fsSL https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/edge-connector-linux-amd64.tar.gz | tar xz

# Install
sudo mv edge-connector/libdclaw_core.so /usr/local/lib/
sudo mv edge-connector/edge-connector /usr/local/bin/
sudo mv edge-connector/picoclaw_hook.py /usr/local/lib/defenseclaw/
sudo mv edge-connector/policy_compiler.py /usr/local/lib/defenseclaw/
sudo ldconfig

# Verify
edge-connector --version
python3 -c "import ctypes; ctypes.CDLL('libdclaw_core.so'); print('OK')"
```

### Release Artifacts

| File | Description |
|------|-------------|
| `libdclaw_core.so` | Shared library (77KB) — load from any language via FFI |
| `edge-connector` | Standalone daemon binary (76KB) |
| `picoclaw_hook.py` | PicoClaw integration hook (ready to use) |
| `policy_compiler.py` | YAML→C policy compiler (with DFA table generation) |
| `policies/strict.yaml` | Default policy (edit to customize) |

### Supported Platforms

| Architecture | OS | Tested On |
|---|---|---|
| `linux/arm64` | Debian 12+, Ubuntu 22.04+, Raspberry Pi OS | RPi4, RPi5, Jetson Nano |
| `linux/amd64` | Debian 12+, Ubuntu 22.04+, Alpine 3.19+ | Cloud VMs, dev machines |
| `linux/armv7` | Raspberry Pi OS (32-bit) | RPi3, RPi Zero 2 W |

---

## Install via pip (Python Wrapper)

For Python-based agents, install the wrapper package:

```bash
pip install defenseclaw-edge-connector
```

Usage:

```python
from defenseclaw_edge_connector import DclawEngine, CAP_ACTUATE, CAP_EXEC_SHELL, CAP_NET_FETCH, CAP_SENSOR_READ

engine = DclawEngine()  # auto-finds libdclaw_core.so

# Evaluate a tool call
verdict = engine.evaluate(
    tool_name="drive",
    cap_flags=CAP_ACTUATE,
    destination="",
    session_id=1,
)

if verdict.is_blocked:
    print(f"BLOCKED: {verdict.reason_name}")
else:
    print("ALLOWED")
```

---

## Build From Source

Required: `gcc`, `cmake` (3.22+), `make`.

```bash
git clone https://github.com/cisco-ai-defense/defenseclaw.git
cd defenseclaw/edge-connector
mkdir build && cd build
cmake .. -DDCLAW_PROFILE=STANDARD
make -j$(nproc)

# Run tests
ctest --output-on-failure

# Install system-wide
sudo make install
```

### Build Profiles

| Profile | Binary Size | RAM | Use Case |
|---------|-------------|-----|----------|
| `MINIMAL` | ~22KB | ~8KB | MCUs, ultra-constrained devices |
| `STANDARD` | ~68KB | ~14-19KB | Raspberry Pi, Jetson, SBCs |
| `EDGE` | ~131KB | ~64KB | Edge gateways with bloom filter |

```bash
cmake .. -DDCLAW_PROFILE=MINIMAL   # for tiny devices
cmake .. -DDCLAW_PROFILE=EDGE      # for edge gateways
```

---

## Configuration

### Step 1: Edit the Policy

Copy and customize the default policy:

```bash
mkdir -p ~/.defenseclaw
cp policies/strict.yaml ~/.defenseclaw/policy.yaml
```

Edit `~/.defenseclaw/policy.yaml`:

```yaml
name: my-device-policy
version: 1

# What severity levels to block
skill_actions:
  critical:
    runtime: disable    # BLOCK
  high:
    runtime: disable    # BLOCK
  medium:
    runtime: warn       # WARN (allow but log)

# IoT-specific rules
iot_extensions:
  # Dangerous multi-step patterns to block
  capability_sequences:
    - sequence: [net_fetch, exec_shell]
      action: block
    - sequence: [net_fetch, actuate]
      action: block
    - sequence: [sensor_read, net_fetch, exec_shell]
      action: block

  # Only allow network calls to these destinations
  destination_allowlist:
    - "api.openai.com"
    - "api.anthropic.com"
    - "*.your-company.com"
    # Add your allowed domains here

  # Rate limits
  rate_limits:
    tool_calls_per_minute: 60
    network_requests_per_minute: 30
    actuations_per_minute: 10

  # Which capabilities can proceed without cloud approval
  escalation_mode:
    sensor_read: speculative    # allow immediately (safe, read-only)
    read_fs: speculative        # allow immediately
    net_fetch: speculative      # allow if dest in allowlist
    send_msg: speculative       # allow if dest in allowlist
    actuate: sync_block         # BLOCK without cloud approval
    exec_shell: sync_block      # BLOCK without cloud approval
    write_fs: sync_block        # BLOCK without cloud approval

  canary:
    baseline_blocks_per_min: 5
```

### Step 2: Configure Content Inspection

The Edge Connector inspects tool call arguments and LLM responses for dangerous content patterns. Configure which pattern categories are active in your policy YAML:

```yaml
  # Content inspection settings
  content_inspection:
    enabled: true

    # Enable or disable individual pattern categories
    categories:
      secrets: true        # API keys, tokens, private keys, passwords
      pii: true            # SSN, credit cards, email addresses, phone numbers
      credentials: true    # AWS keys, GCP service accounts, database URIs
      exfiltration: true   # Base64-encoded blobs, hex dumps, data URI payloads
      injection: true      # Prompt injection, jailbreak attempts, system prompt overrides
      commands: true       # Shell commands, SQL statements, code execution patterns

    # SSRF validation for network destinations
    ssrf_validation:
      enabled: true
      block_private_ranges: true    # 10.x, 172.16-31.x, 192.168.x, 127.x
      block_metadata_endpoints: true # 169.254.169.254, metadata.google.internal
      block_link_local: true         # fe80::/10, 169.254.x.x

    # Custom patterns (appended to built-in patterns)
    custom_patterns:
      - name: "internal_project_code"
        category: secrets
        regex: "PROJ-[A-Z]{3}-[0-9]{6}"
        severity: high
      - name: "internal_hostname"
        category: exfiltration
        regex: "[a-z]+-prod-[0-9]+\\.internal\\.corp"
        severity: medium
```

To disable content inspection entirely (not recommended), set `content_inspection.enabled: false`. Individual categories can be toggled independently. Custom patterns follow the same format as built-in patterns and are compiled into the DFA tables by the policy compiler.

### Step 3: Compile the Policy (Optional — for custom policies)

```bash
python3 /usr/local/lib/defenseclaw/policy_compiler.py \
  --input ~/.defenseclaw/policy.yaml \
  --profile standard --version 1 \
  --output-header /tmp/policy_tables.h \
  --output-binary /tmp/policy.bin
```

> Note: If using pre-built binaries, the default policy is already compiled in.
> Recompilation is only needed when you change the policy.

---

## Integration with AI Agents

### PicoClaw (Supported)

PicoClaw is the primary supported agent framework. DefenseClaw Edge Connector integrates via PicoClaw's process hook system, intercepting all tool calls, LLM inputs, and LLM outputs.

```bash
# 1. Copy the hook
cp /usr/local/lib/defenseclaw/picoclaw_hook.py ~/.picoclaw/hooks/defenseclaw_gate.py

# 2. Register in config
picoclaw config edit
```

Add to `hooks.processes`:

```json
{
  "defenseclaw_gate": {
    "enabled": true,
    "priority": 5,
    "transport": "stdio",
    "command": ["python3", "~/.picoclaw/hooks/defenseclaw_gate.py"],
    "env": {
      "DCLAW_LIB_PATH": "/usr/local/lib/libdclaw_core.so",
      "DCLAW_LOG_PATH": "~/edge-connector.log"
    },
    "intercept": ["before_tool", "before_llm", "after_llm"]
  }
}
```

#### What gets intercepted

| Hook | What DefenseClaw Does | Supported Actions |
|------|----------------------|-------------------|
| `before_tool` | 8-stage policy evaluation (rate limit, deny-list, dest filter, content scan, SSRF check, sequence detect, cache, escalation) | `deny_tool` with canned message, `continue` |
| `before_llm` | Pattern-based prompt injection detection (20+ patterns) | `abort_turn` (blocks LLM call entirely), `continue` |
| `after_llm` | PII/credential leakage scanning (SSN, credit cards, API keys, private keys) via content scanner | Detection + logging (redaction not supported in PicoClaw v0.3.x) |

#### Verify the integration

```bash
# Test the hook standalone
echo '{"jsonrpc":"2.0","id":1,"method":"hook.hello","params":{}}' | \
  DCLAW_LIB_PATH=/usr/local/lib/libdclaw_core.so \
  python3 ~/.picoclaw/hooks/defenseclaw_gate.py
# Expected: {"jsonrpc":"2.0","id":1,"result":{"ok":true,"name":"edge-connector-gate"}}

# Test through PicoClaw (should ALLOW — sensor read)
picoclaw agent -m "check battery status"

# Test through PicoClaw (should BLOCK — shell execution)
picoclaw agent -m "run whoami in the shell"

# Watch decisions in real-time
tail -f ~/edge-connector.log
```

---

### Upcoming Integrations (Roadmap)

The following frameworks are planned for future releases. DefenseClaw Edge Connector's shared library (`libdclaw_core.so`) and Unix socket interface make integration straightforward — each framework needs only a thin adapter at its tool-dispatch layer.

| Framework | Type | Integration Point | Status |
|-----------|------|-------------------|--------|
| **Bubbaloop** (Kornia) | Physical AI fleet agent (Rust, 47 MCP tools) | MCP tool authorization layer / Telemetry Watchdog plugin | Planned |
| **IoT-Edge-MCP-Server** | Industrial MQTT/Modbus/PLC gateway (Python) | HTTP middleware on MCP API endpoint | Planned |
| **SimpleTool** (ICML 2026) | Real-time robot control at 16 Hz (Python/vLLM) | FastAPI middleware on `/v1/function_call` | Planned |
| **TinyAgent** | ESP32/Arduino microcontroller agent (C++) | Tool Registry callback wrapper | Planned |
| **Claude Code** | Developer AI agent (hooks system) | `settings.json` hook configuration | Planned |
| **LangChain / LangGraph** | Python agent framework | `pre_tool_hook` callback | Planned |
| **CrewAI** | Multi-agent framework | Tool execution middleware | Planned |

#### Generic Integration (Any Framework)

For frameworks not listed above, DefenseClaw Edge Connector exposes two generic interfaces:

**Shared Library (FFI)** — load `libdclaw_core.so` from any language:
```python
import ctypes
lib = ctypes.CDLL("/usr/local/lib/libdclaw_core.so")
# Call dclaw_evaluate() for every tool call
```

**Unix Socket (JSON-RPC)** — query the daemon from any process:
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"evaluate","params":{
  "tool_name":"exec_shell","cap_flags":4,"destination":"","session_id":1
}}' | socat - UNIX-CONNECT:/var/run/edge-connector.sock
```

If you'd like to contribute an integration adapter for your framework, see [CONTRIBUTING.md](../docs/CONTRIBUTING.md).

---

## IPC Schema

The evaluation request sent over the Unix socket or through the hook uses the following JSON-RPC schema:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "evaluate",
  "params": {
    "tool_name": "call_api",
    "cap_flags": 8,
    "destination": "api.example.com",
    "session_id": 1,
    "direction": "request",
    "content": "Authorization: Bearer sk-proj-abc123..."
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool_name` | string | yes | Name of the tool being called |
| `cap_flags` | int | yes | Capability bitmask (see table below) |
| `destination` | string | yes | Target URL/host (empty string if none) |
| `session_id` | int | yes | Session identifier for sequence correlation |
| `direction` | string | no | `"request"` (tool call args) or `"response"` (LLM/tool output). Defaults to `"request"`. Controls which content patterns are evaluated — request-direction checks for injection and commands, response-direction checks for secrets and PII leakage. |
| `content` | string | no | The actual text payload to inspect (tool arguments, LLM response body, etc.). When provided, the content scanner runs all enabled pattern categories against this field and includes matched findings in the verdict and cloud escalation payload. When omitted, only rule-based policy checks (deny-list, dest filter, rate limit, sequence) are performed. |

---

## Tool-to-Capability Mapping

Each tool your agent calls must be mapped to a capability. This determines how DefenseClaw Edge Connector handles it. When `content` is provided in the evaluation request, the content scanner additionally inspects the payload for secrets, PII, credentials, exfiltration patterns, injection attempts, and dangerous commands. Content findings can elevate a verdict from ALLOW to WARN or BLOCK depending on severity and policy configuration.

| Capability | Flag | Escalation Mode | Behavior |
|---|---|---|---|
| `SENSOR_READ` | 0x40 | speculative | ALLOW immediately (read-only, safe) |
| `READ_FS` | 0x01 | speculative | ALLOW immediately |
| `NET_FETCH` | 0x08 | speculative | ALLOW if destination in allowlist; SSRF validation applied |
| `SEND_MSG` | 0x10 | speculative | ALLOW if destination in allowlist |
| `ACTUATE` | 0x20 | sync_block | BLOCK without cloud (physical world) |
| `EXEC_SHELL` | 0x04 | sync_block | BLOCK without cloud (code execution) |
| `WRITE_FS` | 0x02 | sync_block | BLOCK without cloud (data modification) |

Configure your mapping in the hook:

```python
TOOL_CAP_MAP = {
    # Your tools → capabilities
    "get_temperature":  CAP_SENSOR_READ,   # safe, allow
    "read_log":         CAP_READ_FS,       # safe, allow
    "call_api":         CAP_NET_FETCH,     # allow if dest approved
    "send_email":       CAP_SEND_MSG,      # allow if dest approved
    "start_motor":      CAP_ACTUATE,       # BLOCK without cloud
    "run_script":       CAP_EXEC_SHELL,    # BLOCK without cloud
    "save_config":      CAP_WRITE_FS,      # BLOCK without cloud
}
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DCLAW_LIB_PATH` | `/usr/local/lib/libdclaw_core.so` | Path to shared library |
| `DCLAW_LOG_PATH` | `~/edge-connector.log` | Audit log file |
| `DCLAW_POLICY_PATH` | (compiled in) | Path to custom policy binary |
| `DCLAW_FLASH_DIR` | `/tmp/dclaw-flash/` | Directory for flash emulation |
| `DEFENSECLAW_MAX_ESCALATION_PAYLOAD_BYTES` | `1024` | Maximum size in bytes of the content snippet included in cloud escalation requests. Content exceeding this limit is truncated. Set to `0` to omit content from escalation payloads entirely. |

---

## Verifying the Installation

```bash
# 1. Check library loads
python3 -c "
import ctypes
lib = ctypes.CDLL('/usr/local/lib/libdclaw_core.so')
print('Library loaded OK')
"

# 2. Run built-in tests (if built from source)
cd edge-connector/build && ctest --output-on-failure

# 3. Test the hook standalone
echo '{"jsonrpc":"2.0","id":1,"method":"hook.hello","params":{}}' | \
  DCLAW_LIB_PATH=/usr/local/lib/libdclaw_core.so \
  python3 /usr/local/lib/defenseclaw/picoclaw_hook.py
# Expected: {"jsonrpc":"2.0","id":1,"result":{"ok":true,"name":"edge-connector-gate"}}

# 4. Benchmark performance
edge-connector --benchmark
# Expected: <5μs decisions, >100K/sec throughput
```

---

## Updating

```bash
# Pre-built binary
curl -fsSL https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/edge-connector-linux-$(uname -m).tar.gz | tar xz
sudo mv edge-connector/libdclaw_core.so /usr/local/lib/
sudo ldconfig

# From source
cd defenseclaw && git pull
cd edge-connector/build && cmake .. && make -j$(nproc)
sudo make install
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `libdclaw_core.so: cannot open shared object file` | Run `sudo ldconfig` or set `LD_LIBRARY_PATH` |
| All tools getting blocked | Check TOOL_CAP_MAP — unknown tools default to EXEC_SHELL |
| `CLOUD_TIMEOUT` on tools you want allowed | Change escalation_mode from `sync_block` to `speculative` in policy |
| `DEST_DENY` on valid URLs | Add domain to `destination_allowlist` in policy YAML |
| `CONTENT_BLOCK` false positives | Disable the offending category in `content_inspection.categories` or add an exception pattern |
| `SSRF_BLOCK` on internal services you trust | Add trusted internal hosts to `ssrf_validation.allowlist` in policy YAML |
| Hook not starting | Check `DCLAW_LIB_PATH` points to correct `.so` file |
| Build fails on GCC 14+ | Use latest source — pragma guards for unused warnings included |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Your AI Agent (PicoClaw, Claude Code, LangChain, etc.) │
└────────────────────────┬────────────────────────────────┘
                         │ tool call + content
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Integration Layer (hook / middleware / FFI call)        │
│  • Maps tool_name → capability flag                     │
│  • Extracts destination from arguments                  │
│  • Extracts content for inspection                      │
│  • Sets direction (request / response)                  │
│  • Calls dclaw_evaluate()                               │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  DefenseClaw Edge Connector Engine (libdclaw_core.so)   │
│                                                         │
│  8-Stage Pipeline (~2-3μs on ARM):                      │
│  1. Input validation    5. Content scanning             │
│  2. Rate limiting       6. Sequence correlation         │
│  3. Hash deny-list      7. Verdict cache                │
│  4. Dest filtering      8. Cloud escalation (enriched)  │
│      + SSRF validation                                  │
│                                                         │
│  → ALLOW / BLOCK / WARN / PENDING                       │
└─────────────────────────────────────────────────────────┘
```

---

## What's Included vs. What You Configure

| DefenseClaw Edge Connector Provides | You Configure |
|-------------------------------------|---------------|
| 8-stage evaluation engine | Tool → capability mapping |
| Content scanning (secrets, PII, credentials, exfil, injection, commands) | Pattern categories to enable/disable |
| SSRF validation | Trusted internal hosts (if any) |
| Sequence correlation (FSM) | Destination allowlist |
| Rate limiting (3 buckets) | Rate limit values |
| HMAC-chained audit trail | Log file path |
| Verdict caching (LRU) | — |
| Destination filtering | Allowed domains |
| Hash deny-list | Threat intel hashes (optional) |
| Trust boundary inference | — |
| Enriched cloud escalation with content | Max escalation payload size |
| Response interception | — |
| Pre-built hooks for PicoClaw, Claude Code | Custom hooks for other frameworks |
