# DefenseClaw Edge Connector — Installation Guide

Secure any AI agent on Linux with sub-microsecond policy enforcement and AI-aware content inspection.

---

## Security Requirements

### MQTT Broker ACL (CRITICAL)

**The MQTT broker MUST enforce per-device topic ACLs in production.** Without
broker-level access control, any authenticated MQTT client can publish to any
device's topic, enabling cross-tenant and cross-device spoofing attacks.

Each device should only be permitted to publish to its own topics:

```
defenseclaw/{tenant_id}/{fleet_id}/{device_id}/heartbeat
defenseclaw/{tenant_id}/{fleet_id}/{device_id}/verdict/req
defenseclaw/{tenant_id}/{fleet_id}/{device_id}/register
```

The fleet manager subscribes to wildcard topics and trusts the topic structure
for routing. HMAC verification provides a second layer of defense, but broker
ACLs are the primary isolation mechanism for multi-tenant deployments.

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

> **Note:** Sizes shown are for stripped Release builds with `-Os -flto`. Debug builds are larger (~79KB MINIMAL, ~265KB STANDARD/EDGE).

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
cp ../policies/strict.yaml ~/.defenseclaw/policy.yaml
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
      secret:              # API keys, tokens, private keys, passwords
        enabled: true
        severity: high
        action: block
      pii:                 # SSN, credit cards, email addresses, phone numbers
        enabled: true
        severity: high
        action: block
      credential:          # AWS keys, GCP service accounts, database URIs
        enabled: true
        severity: high
        action: block
      exfil:               # Base64-encoded blobs, hex dumps, data URI payloads
        enabled: true
        severity: high
        action: block
      injection:           # Prompt injection, jailbreak attempts, system prompt overrides
        enabled: true
        severity: critical
        action: block
      command:             # Shell commands, SQL statements, code execution patterns
        enabled: true
        severity: critical
        action: block

    # SSRF protection for network destinations
    ssrf_protection:
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

The Edge Connector is framework-agnostic. Pick the integration method that fits your stack:

| Method | Best For | File |
|--------|----------|------|
| **Generic Python adapter** | Any Python agent | `tools/generic_hook.py` |
| **MCP proxy** | MCP-based agents (Claude, Codex, ESP-Claw, HA-MCP) | `tools/mcp_proxy.py` |
| **LangChain / LangGraph** | LangChain-based agents | `tools/langchain_hook.py` |
| **HTTP middleware** | FastAPI, Flask, any HTTP API | `tools/http_middleware.py` |
| **PicoClaw hook** | PicoClaw robot agents | `tools/picoclaw_hook.py` |
| **Shared library (FFI)** | Any language via ctypes/cffi | `libdclaw_core.so` |
| **Unix socket (JSON-RPC)** | Any process, any language | `/tmp/defenseclaw.sock` |

---

### Generic Python Adapter (Recommended)

The simplest way to integrate from any Python agent. Works with any framework — just call `evaluate()` before running a tool.

```python
from generic_hook import EdgeConnector

ec = EdgeConnector()  # auto-detects FFI or Unix socket

# Before executing any tool call:
verdict = ec.evaluate(
    tool_name="exec_shell",
    arguments={"command": "rm -rf /"},
)

if verdict.blocked:
    print(f"Blocked: {verdict.reason}")
else:
    # proceed with tool execution
    ...
```

**Features:**
- Auto-detects backend: tries FFI (ctypes) first, falls back to Unix socket
- Configurable fail-open / fail-closed behavior
- Built-in tool-name-to-capability mapping with heuristic fallback
- Automatic destination extraction from URL arguments
- Content scanning when arguments are provided

**Configuration:**

```python
ec = EdgeConnector(
    lib_path="/path/to/libdclaw_core.so",   # override FFI path
    socket_path="/tmp/defenseclaw.sock",     # override socket path
    fail_open=True,                          # allow when engine is down
    tool_cap_map={"my_tool": 0x04},          # custom capability mapping
    session_id=42,                           # session correlation ID
)
```

Or via environment variables: `DCLAW_LIB_PATH`, `DCLAW_SOCKET_PATH`, `DCLAW_FAIL_OPEN`.

---

### MCP Proxy (Model Context Protocol)

A transparent MCP proxy that sits between an LLM client (Claude, Codex, etc.) and a real MCP server, intercepting every `tools/call` request and evaluating it through the 8-stage pipeline. All other MCP messages (`tools/list`, `resources/read`, `prompts/get`, etc.) pass through unchanged.

```
LLM Client (Claude, Codex)
    | MCP (stdio / HTTP)
    v
Edge Connector MCP Proxy (mcp_proxy.py)
    | evaluates via EdgeConnector.evaluate()
    | MCP (stdio / HTTP)
    v
Real MCP Server (ESP-Claw, HA-MCP, etc.)
```

**Quick start (stdio transport):**

```bash
# Proxy an MCP server that speaks stdio
DCLAW_MCP_UPSTREAM='["python3", "-m", "esp_claw.mcp_server"]' \
  python3 -m mcp_proxy
```

**With a config file:**

```bash
python3 -m mcp_proxy --config tools/mcp_proxy_config.yaml
```

**HTTP transport (for remote MCP servers):**

```bash
DCLAW_MCP_UPSTREAM="http://192.168.1.100:8088/mcp" \
DCLAW_MCP_TRANSPORT=http \
  python3 -m mcp_proxy
```

**Using with Claude Desktop or Claude Code:**

Add the proxy to your MCP client configuration. Instead of pointing directly at the MCP server, point at the proxy and configure it to forward to the real server:

```json
{
  "mcpServers": {
    "esp-claw-secured": {
      "command": "python3",
      "args": ["-m", "mcp_proxy"],
      "env": {
        "DCLAW_MCP_UPSTREAM": "[\"python3\", \"-m\", \"esp_claw.mcp_server\"]",
        "DCLAW_LIB_PATH": "/usr/local/lib/libdclaw_core.so"
      }
    }
  }
}
```

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `DCLAW_MCP_UPSTREAM` | (none) | Target server: JSON array of command (stdio) or URL (HTTP) |
| `DCLAW_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `DCLAW_MCP_PORT` | `8089` | HTTP port when proxy serves HTTP |
| `DCLAW_MCP_CONFIG` | (none) | Path to YAML config file |

All standard Edge Connector env vars (`DCLAW_LIB_PATH`, `DCLAW_SOCKET_PATH`, `DCLAW_FAIL_OPEN`) are passed through.

**What gets intercepted:**

| MCP Method | Action | Description |
|---|---|---|
| `tools/call` | Evaluate | Full 8-stage pipeline (input validation, rate limit, content scan, deny-list, dest filter + SSRF, sequence, cache, escalation). Blocked calls return an MCP error. |
| `tools/list`, `resources/*`, `prompts/*`, `initialize`, etc. | Passthrough | Forwarded unchanged to the real server. |

---

### LangChain / LangGraph

Wraps LangChain tools so every invocation passes through the Edge Connector.

**With LangChain:**

```python
from langchain_hook import wrap_tools

# Wrap all tools — blocked calls return an error message instead of executing
tools = wrap_tools(my_tools)
agent = create_react_agent(llm, tools)
```

**With LangGraph (graph node):**

```python
from langchain_hook import edge_connector_node

graph = StateGraph(AgentState)
graph.add_node("agent", agent_node)
graph.add_node("security_gate", edge_connector_node)
graph.add_node("tools", tool_node)
graph.add_edge("agent", "security_gate")
graph.add_edge("security_gate", "tools")
```

Blocked tool calls produce a `ToolMessage` with the block reason so the LLM can respond appropriately.

---

### HTTP Middleware

For agents that expose tool execution via HTTP endpoints (FastAPI, Flask, or any ASGI/WSGI server).

**With FastAPI:**

```python
from fastapi import FastAPI
from http_middleware import EdgeConnectorMiddleware

app = FastAPI()
app.add_middleware(EdgeConnectorMiddleware)
```

**With Flask:**

```python
from flask import Flask
from http_middleware import flask_edge_connector

app = Flask(__name__)
flask_edge_connector(app)
```

The middleware intercepts POST requests to tool-execution endpoints (configurable URL patterns), extracts the tool name and arguments from the JSON body, and returns a `403` response with the block reason when a tool call is denied.

---

### PicoClaw

PicoClaw integrates via its process hook system, intercepting tool calls, LLM inputs, and LLM outputs.

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
| `before_tool` | 8-stage policy evaluation (input validation, rate limit, content scan, deny-list, dest filter + SSRF, sequence detect, cache, escalation) | `deny_tool` with canned message, `continue` |
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

### Low-Level: Shared Library (FFI)

Load `libdclaw_core.so` from any language that supports C FFI:

```python
import ctypes
lib = ctypes.CDLL("/usr/local/lib/libdclaw_core.so")
# Call dclaw_evaluate() for every tool call — see defenseclaw.h for struct definitions
```

### Low-Level: Unix Socket (JSON-RPC)

Query the daemon from any process:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"evaluate","params":{
  "tool_name":"exec_shell","capabilities":4,"destination":"","session_id":1
}}' | socat - UNIX-CONNECT:/tmp/defenseclaw.sock
```

---

### Additional Framework Integrations (Roadmap)

| Framework | Type | Integration Point | Status |
|-----------|------|-------------------|--------|
| **Generic Python** | Any Python agent | `EdgeConnector.evaluate()` | **Available** |
| **MCP Proxy** | Any MCP-based agent (Claude, Codex, ESP-Claw, HA-MCP) | Transparent proxy with tools/call interception | **Available** |
| **LangChain / LangGraph** | Python agent framework | Tool wrapper / graph node | **Available** |
| **HTTP Middleware** | FastAPI, Flask, ASGI/WSGI | Request interception | **Available** |
| **PicoClaw** | Robot agent (JSON-RPC hooks) | Process hook system | **Available** |
| **Bubbaloop** (Kornia) | Physical AI fleet agent (Rust, 47 MCP tools) | MCP tool authorization layer / Telemetry Watchdog plugin | Planned |
| **IoT-Edge-MCP-Server** | Industrial MQTT/Modbus/PLC gateway (Python) | HTTP middleware on MCP API endpoint | Planned |
| **SimpleTool** (ICML 2026) | Real-time robot control at 16 Hz (Python/vLLM) | FastAPI middleware on `/v1/function_call` | Planned |
| **TinyAgent** | ESP32/Arduino microcontroller agent (C++) | Tool Registry callback wrapper | Planned |
| **Claude Code** | Developer AI agent (hooks system) | `settings.json` hook configuration | Planned |
| **CrewAI** | Multi-agent framework | Tool execution middleware | Planned |

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
    "capabilities": 8,
    "destination": "api.example.com",
    "session_id": 1,
    "direction": 0,
    "content": "Authorization: Bearer sk-proj-abc123..."
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool_name` | string | yes | Name of the tool being called |
| `capabilities` | int | yes | Capability bitmask (see table below) |
| `destination` | string | yes | Target URL/host (empty string if none) |
| `session_id` | int | yes | Session identifier for sequence correlation |
| `direction` | int | no | `0` (request — tool call args) or `1` (response — LLM/tool output). Defaults to `0`. Controls which content patterns are evaluated — request-direction checks for injection and commands, response-direction checks for secrets and PII leakage. |
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

**Runtime environment variables** (read by the Python hook at startup):

| Variable | Default | Description |
|---|---|---|
| `DCLAW_LIB_PATH` | `/usr/local/lib/libdclaw_core.so` | Path to shared library |
| `DCLAW_LOG_PATH` | `~/edge-connector.log` | Audit log file |

**Compile-time constants** (set in `CMakeLists.txt`; changing these requires rebuilding the binary):

| Constant | Default | Description |
|---|---|---|
| `DCLAW_POLICY_PATH` | (embedded in binary) | Policy tables are compiled into the binary via `policy_tables.h`. To use a custom policy, recompile with the policy compiler and rebuild. |
| `DCLAW_FLASH_DIR` | `/tmp/dclaw-flash/` | Directory for flash emulation (set via CMake `DCLAW_FLASH_DIR` variable) |
| `DCLAW_ESCALATION_PAYLOAD_MAX` | `1024` | Maximum size in bytes of the content snippet included in cloud escalation requests. Set in `config.h.in` / CMakeLists.txt. |

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
cd edge-connector/build && ./tests/bench_latency
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
| All tools getting blocked | Check TOOL_CAP_MAP — unknown tools default to `SENSOR_READ` (safe); tools with dangerous keywords (`exec`, `shell`, `bash`, `run`, `write`, `delete`, `rm`) upgrade to `EXEC_SHELL` |
| `CLOUD_TIMEOUT` on tools you want allowed | Change escalation_mode from `sync_block` to `speculative` in policy |
| `DEST_DENY` on valid URLs | Add domain to `destination_allowlist` in policy YAML |
| `CONTENT_BLOCK` false positives | Disable the offending category in `content_inspection.categories` or add an exception pattern |
| `SSRF_BLOCK` on internal services you trust | Add trusted internal hosts to `ssrf_protection.private_ip_allowlist` in policy YAML |
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
│  1. Input validation    5. Dest filtering + SSRF        │
│  2. Rate limiting       6. Sequence correlation         │
│  3. Content scanning    7. Verdict cache                │
│  4. Hash deny-list      8. Cloud escalation (enriched)  │
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
| Pre-built adapters (Generic Python, LangChain, HTTP, PicoClaw) | Custom hooks for other frameworks |

---

## Framework Integrations

Pre-built adapters for physical AI frameworks are available in the [`integrations/`](integrations/) directory. Each adapter connects to the framework's MCP endpoint and routes every tool call through the Edge Connector policy engine.

| Framework | Tools | Platform | Directory |
|-----------|-------|----------|-----------|
| **ESP-Claw** (Espressif) | GPIO, I2C, SPI, Lua scripting | ESP32 | [`integrations/espclaw/`](integrations/espclaw/) |
| **Bubbaloop** (Kornia) | 47 tools: vision, robotics, fleet mgmt | Jetson, RPi | [`integrations/bubbaloop/`](integrations/bubbaloop/) |
| **Home Assistant MCP** | 87 tools: smart home control | RPi, NUC, VM | [`integrations/homeassistant/`](integrations/homeassistant/) |

All adapters import from `tools/generic_hook.py` and share the same interface:

```python
result = adapter.call_tool("tool_name", {"arg": "value"})
if not result["allowed"]:
    print(f"Blocked: {result['verdict']['reason']}")
```

See each integration's README for setup instructions and capability mappings.
