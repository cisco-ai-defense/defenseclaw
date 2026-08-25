# DefenseClaw Lite — Installation Guide

Secure any AI agent on Linux with sub-microsecond policy enforcement. Three installation methods: pre-built binary (30 seconds), pip install (1 minute), or build from source (5 minutes).

---

## Quick Start (Pre-Built Binary)

Download and run — no compiler needed.

```bash
# Download latest release for your architecture
curl -fsSL https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/defenseclaw-lite-linux-arm64.tar.gz | tar xz

# Or for x86_64:
curl -fsSL https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/defenseclaw-lite-linux-amd64.tar.gz | tar xz

# Install
sudo mv defenseclaw-lite/libdclaw_core.so /usr/local/lib/
sudo mv defenseclaw-lite/defenseclaw-lite /usr/local/bin/
sudo mv defenseclaw-lite/picoclaw_hook.py /usr/local/lib/defenseclaw/
sudo mv defenseclaw-lite/policy_compiler.py /usr/local/lib/defenseclaw/
sudo ldconfig

# Verify
defenseclaw-lite --version
python3 -c "import ctypes; ctypes.CDLL('libdclaw_core.so'); print('OK')"
```

### Release Artifacts

| File | Description |
|------|-------------|
| `libdclaw_core.so` | Shared library (77KB) — load from any language via FFI |
| `defenseclaw-lite` | Standalone daemon binary (76KB) |
| `picoclaw_hook.py` | PicoClaw integration hook (ready to use) |
| `policy_compiler.py` | YAML→C policy compiler |
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
pip install defenseclaw-lite
```

Usage:

```python
from defenseclaw_lite import DclawEngine, CAP_ACTUATE, CAP_EXEC_SHELL, CAP_NET_FETCH, CAP_SENSOR_READ

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
cd defenseclaw/defenseclaw-lite
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
| `MINIMAL` | ~30KB | ~12KB | MCUs, ultra-constrained devices |
| `STANDARD` | ~76KB | ~25KB | Raspberry Pi, Jetson, SBCs |
| `EDGE` | ~120KB | ~64KB | Edge gateways with bloom filter |

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

### Step 2: Compile the Policy (Optional — for custom policies)

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

PicoClaw is the primary supported agent framework. DefenseClaw Lite integrates via PicoClaw's process hook system, intercepting all tool calls, LLM inputs, and LLM outputs.

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
      "DCLAW_LOG_PATH": "~/defenseclaw-lite.log"
    },
    "intercept": ["before_tool", "before_llm", "after_llm"]
  }
}
```

#### What gets intercepted

| Hook | What DefenseClaw Does | Supported Actions |
|------|----------------------|-------------------|
| `before_tool` | 7-stage policy evaluation (rate limit, deny-list, dest filter, sequence detect, cache) | `deny_tool` with canned message, `continue` |
| `before_llm` | Pattern-based prompt injection detection (20+ patterns) | `abort_turn` (blocks LLM call entirely), `continue` |
| `after_llm` | PII/credential leakage scanning (SSN, credit cards, API keys, private keys) | Detection + logging (redaction not supported in PicoClaw v0.3.x) |

#### Verify the integration

```bash
# Test the hook standalone
echo '{"jsonrpc":"2.0","id":1,"method":"hook.hello","params":{}}' | \
  DCLAW_LIB_PATH=/usr/local/lib/libdclaw_core.so \
  python3 ~/.picoclaw/hooks/defenseclaw_gate.py
# Expected: {"jsonrpc":"2.0","id":1,"result":{"ok":true,"name":"defenseclaw-lite-gate"}}

# Test through PicoClaw (should ALLOW — sensor read)
picoclaw agent -m "check battery status"

# Test through PicoClaw (should BLOCK — shell execution)
picoclaw agent -m "run whoami in the shell"

# Watch decisions in real-time
tail -f ~/defenseclaw-lite.log
```

---

### Upcoming Integrations (Roadmap)

The following frameworks are planned for future releases. DefenseClaw Lite's shared library (`libdclaw_core.so`) and Unix socket interface make integration straightforward — each framework needs only a thin adapter at its tool-dispatch layer.

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

For frameworks not listed above, DefenseClaw Lite exposes two generic interfaces:

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
}}' | socat - UNIX-CONNECT:/var/run/defenseclaw-lite.sock
```

If you'd like to contribute an integration adapter for your framework, see [CONTRIBUTING.md](../docs/CONTRIBUTING.md).

---

## Tool-to-Capability Mapping

Each tool your agent calls must be mapped to a capability. This determines how DefenseClaw Lite handles it:

| Capability | Flag | Escalation Mode | Behavior |
|---|---|---|---|
| `SENSOR_READ` | 0x40 | speculative | ALLOW immediately (read-only, safe) |
| `READ_FS` | 0x01 | speculative | ALLOW immediately |
| `NET_FETCH` | 0x08 | speculative | ALLOW if destination in allowlist |
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
| `DCLAW_LOG_PATH` | `~/defenseclaw-lite.log` | Audit log file |
| `DCLAW_POLICY_PATH` | (compiled in) | Path to custom policy binary |
| `DCLAW_FLASH_DIR` | `/tmp/dclaw-flash/` | Directory for flash emulation |

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
cd defenseclaw-lite/build && ctest --output-on-failure

# 3. Test the hook standalone
echo '{"jsonrpc":"2.0","id":1,"method":"hook.hello","params":{}}' | \
  DCLAW_LIB_PATH=/usr/local/lib/libdclaw_core.so \
  python3 /usr/local/lib/defenseclaw/picoclaw_hook.py
# Expected: {"jsonrpc":"2.0","id":1,"result":{"ok":true,"name":"defenseclaw-lite-gate"}}

# 4. Benchmark performance
defenseclaw-lite --benchmark
# Expected: <5μs decisions, >100K/sec throughput
```

---

## Updating

```bash
# Pre-built binary
curl -fsSL https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/defenseclaw-lite-linux-$(uname -m).tar.gz | tar xz
sudo mv defenseclaw-lite/libdclaw_core.so /usr/local/lib/
sudo ldconfig

# From source
cd defenseclaw && git pull
cd defenseclaw-lite/build && cmake .. && make -j$(nproc)
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
| Hook not starting | Check `DCLAW_LIB_PATH` points to correct `.so` file |
| Build fails on GCC 14+ | Use latest source — pragma guards for unused warnings included |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Your AI Agent (PicoClaw, Claude Code, LangChain, etc.) │
└────────────────────────┬────────────────────────────────┘
                         │ tool call
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Integration Layer (hook / middleware / FFI call)        │
│  • Maps tool_name → capability flag                     │
│  • Extracts destination from arguments                  │
│  • Calls dclaw_evaluate()                               │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  DefenseClaw Lite Engine (libdclaw_core.so, 77KB)       │
│                                                         │
│  7-Stage Pipeline (~2-3μs on ARM):                      │
│  1. Input validation    5. Sequence correlation         │
│  2. Rate limiting       6. Verdict cache                │
│  3. Hash deny-list      7. Cloud escalation             │
│  4. Dest filtering                                      │
│                                                         │
│  → ALLOW / BLOCK / WARN / PENDING                       │
└─────────────────────────────────────────────────────────┘
```

---

## What's Included vs. What You Provide

| DefenseClaw Lite Provides | You Configure |
|---------------------------|---------------|
| 7-stage evaluation engine | Tool → capability mapping |
| Sequence correlation (FSM) | Destination allowlist |
| Rate limiting (3 buckets) | Rate limit values |
| HMAC-chained audit trail | Log file path |
| Verdict caching (LRU) | — |
| Destination filtering | Allowed domains |
| Hash deny-list | Threat intel hashes (optional) |
| Pre-built hooks for PicoClaw, Claude Code | Custom hooks for other frameworks |
