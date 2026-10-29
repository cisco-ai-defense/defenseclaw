# DefenseClaw Edge Connector — Installation Guide

Run the Linux Edge Connector alongside an AI agent and connect it to a DefenseClaw Fleet gateway.

For a normal macOS, Linux, or Windows agent install, follow the [core quickstart](../docs-site/content/docs/get-started/quickstart.mdx); Fleet and this separate Linux C daemon stay off. For a broker-free Linux C smoke, build `MINIMAL` with `-DDCLAW_DEV_MODE=ON`, then run CTest and `edge-connector --help` as shown in the [Edge install page](../docs-site/content/docs/edge-connector/install.mdx#local-only-linux-smoke). The production `STANDARD` build below needs broker TLS, per-device registration, and matching secrets before its service can run. The gateway Fleet wizard works on macOS and Windows without installing a local C daemon; on Linux it also provisions the C service environment through `sudo`.

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

Required: `gcc`, `cmake` (3.22+), `make`, and mbedTLS 3.x development libraries for production MQTT over TLS.

```bash
git clone https://github.com/cisco-ai-defense/defenseclaw.git
cd defenseclaw/edge-connector
mkdir build && cd build
cmake .. -DDCLAW_PROFILE=STANDARD -DDCLAW_DEV_MODE=OFF -DDCLAW_ALLOW_HMAC_OTA=ON
make -j$(nproc)

# Run tests
ctest --output-on-failure

# Install system-wide
sudo make install
```

### Build Profiles

| Profile | Features | Use Case |
|---------|----------|----------|
| `MINIMAL` | No MQTT | Constrained builds; not the Linux Fleet service |
| `STANDARD` | MQTT and content inspection | Raspberry Pi, Jetson, SBCs |
| `EDGE` | MQTT, content inspection, bloom filter | Edge gateways |

Binary size depends on toolchain, linked TLS libraries, and build flags. Measure the installed binary for your target.

```bash
cmake .. -DDCLAW_PROFILE=MINIMAL   # for tiny devices
cmake .. -DDCLAW_PROFILE=EDGE      # for edge gateways
```

---

## Production Deployment

### Required Environment Variables

| Variable | Description |
|---|---|
| `DCLAW_AUDIT_KEY` | Hex-encoded 32-byte HMAC key for tamper-evident audit chain |
| `DCLAW_OTA_HMAC_KEY` | Nonzero, hex-encoded 32-byte secret shared with the Fleet gateway's policy signer; requires `-DDCLAW_ALLOW_HMAC_OTA=ON` at build time |
| `DCLAW_EMERGENCY_KEY` | Separate nonzero, hex-encoded 32-byte secret shared with the Fleet gateway for emergency commands |
| `DCLAW_BROKER_URL` | `mqtts://` URL for the MQTT broker (TLS required in production) |
| `DCLAW_CA_CERT_PATH` | Path to a trusted broker CA PEM file |
| `DCLAW_DEVICE_KEY` | Hex-encoded 32-byte per-device HMAC key for verdict signing |

Set `DCLAW_DEVICE_CERT_PATH` and `DCLAW_DEVICE_KEY_PATH` as well when the broker requires client certificates. `DCLAW_OTA_KEY` is reserved for an Ed25519 public key; this build has no Ed25519 verifier, so setting it does not enable OTA verification. Keep the HMAC and emergency secrets distinct. Provision corresponding gateway secrets and enable `fleet.enabled: true` in the gateway's `config.yaml`.

The Fleet gateway rejects missing or invalid device HMAC keys by default. Provision the registration-issued per-device key in the gateway's key store and on the device, or set a nonzero `DCLAW_DEVICE_KEY` fallback for a one-device test. Pre-register every production device through the authenticated Fleet API; MQTT auto-registration is for unmanaged local development only. Only unmanaged development hosts with explicit `DCLAW_DEV_MODE=ON` permit the legacy zero-key fallback; managed deployments always reject it. The device's durable emergency sequence is bound to its tenant/fleet identity. Moving a device to another tenant or fleet requires trusted flash reset and reprovisioning; a changed identity with the old emergency state refuses startup.

Upgrade gateway and devices together: keyed heartbeat and registration messages now carry a durable 4-byte boot counter and 4-byte last-applied emergency sequence in a 40-byte payload, followed by a 32-byte HMAC (72 bytes total). The gateway rejects older 64- and 68-byte signed frames. Confirm heartbeats after each device upgrade before relying on Fleet status. The current C OTA receiver accepts explicit HMAC signing only; Ed25519 output from the compiler's `--signing-key` option is not accepted by this build. A canary rollback restores the previous active policy, but the `policy_version` reported in heartbeats and Fleet health stays at the highest accepted version for anti-rollback; the persistent rollback flag signals that the active partition is older until a newer signed policy installs. The C connector clears its verdict cache on broker reconnect. Authenticated signed registration or heartbeat prompts the gateway to republish a newer stored policy and replay missed signed emergency commands from durable fleet history in sequence, at most 32 per pass; later heartbeats request the next page. The 112-byte emergency frame has a signed predecessor sequence, so a later command cannot silently skip a missed lockdown. MQTT publication does not confirm application; inspect later signed heartbeats and device state. A history gap or unavailable durable store fails closed.

Legacy flash partitions containing unsigned policy payloads are preserved but refused at boot, including in a development build. Do not rely on an in-place metadata migration to make them executable. Back up the device state, then use a trusted re-sign and reprovisioning procedure for the policy/identity before starting the new connector; verify the signed on-flash policy and resumed authenticated heartbeat afterward.

### Required systemd Configuration

The shipped unit at `packaging/edge-connector.service` creates `/run/defenseclaw/` for the IPC socket and `/var/lib/defenseclaw/` for flash state. CMake installs the binary and support files; install the unit separately:

```bash
sudo useradd --system --home-dir /var/lib/defenseclaw --shell /usr/sbin/nologin defenseclaw
sudo install -d -o root -g defenseclaw -m 0750 /etc/defenseclaw
sudo touch /etc/defenseclaw/edge-connector.env
sudo chmod 0600 /etc/defenseclaw/edge-connector.env
# Edit the environment file as root and set every required value above.
sudo install -m 0644 packaging/edge-connector.service /etc/systemd/system/edge-connector.service
sudo systemctl daemon-reload
sudo systemctl enable --now edge-connector.service
sudo systemctl status edge-connector.service
```

If `defenseclaw` already exists, skip `useradd`. Keep the environment file readable only by root; systemd reads it before switching to `User=defenseclaw`. Broker CA and device certificate files under `/etc/defenseclaw` must be readable by that service account; use `root:defenseclaw` ownership and mode `0640` for a private device key. The default CMake install prefix is `/usr/local`, matching the unit's `ExecStart`. For another prefix, adjust the unit. Generate independent keys with `python3 -c "import secrets; print(secrets.token_hex(32))"` and store them securely.

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
    - "1.1.1.1" # illustrative public IP; replace with one approved for your service

  canary:
    baseline_blocks_per_min: 5
```

### Step 2: Check Built-In Inspection and Network Rules

The C engine uses a built-in content scanner and an all-profile SSRF guard. The current policy compiler rejects `content_inspection`, `ssrf_protection`, custom regex patterns, `destination_denylist`, `rate_limits`, and `escalation_mode` in `iot_extensions`; signing them would imply runtime controls that OTA cannot apply. The compiled rate limit defaults are 60 tool calls, 30 network requests, and 10 actuations per minute. Production starts in strict synchronous escalation mode; `DCLAW_STRICT_MODE=0` explicitly permits speculative execution for undecided calls if that build enables it, including when MQTT publication fails. Network capabilities require a nonempty destination and permit only allowlisted canonical public IPv4 or globally scoped IPv6 literals (write an IPv6 entry without brackets; the policy compiler refuses a bracketed one). Hostnames, private or link-local IPs, and numeric aliases are blocked until an enforced egress resolver/proxy exists. Replace the illustrative public IP in the allowlist with the actual approved destination for your service.

### Step 3: Compile the Policy (Optional — for custom policies)

The policy compiler requires Python 3 and PyYAML (`python3 -m pip install PyYAML` in a managed Python environment). CMake installs the compiler script but does not install PyYAML. For a gateway deployed from a raw release tar archive, provision Python 3 and PyYAML before using Fleet policy push. Linux enterprise RPM/DEB packages leave Python/PyYAML optional while Fleet is off; provision a trusted `/usr/bin/python3` and PyYAML before enabling Fleet. Managed Fleet install/ensure checks the prerequisite before service changes. Per-user installers use their bundled Python environment. A managed macOS `.pkg` with Fleet enabled requires **PyYAML 6.0.3** inside a trusted Python.org framework interpreter (3.10–3.14), not Apple's `/usr/bin/python3` or Homebrew PATH. For example, check `/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 -I -c 'import yaml; print(yaml.__version__)'` before install/ensure. The interpreter, framework parents, and installed PyYAML tree must be root-owned and not group/world-writable. The managed lifecycle checks these paths and refuses Fleet-enabled config before service changes if no candidate passes. Managed Windows standalone Setup carries the compiler in its signed Setup payload and activates it only for authenticated Fleet-enabled config, using its admitted scanner runtime Python/PyYAML. Fleet-off Setup/upgrade leaves no active compiler, and disabling Fleet removes a previous active script. Secure Client managed profiles on Windows and macOS reject Fleet-enabled configuration because they do not include the compiler/runtime.

Fleet activation is optional for the gateway. Managed Linux/macOS packages carry `policy_compiler.py` as inert source under `<InstallRoot>/share/fleet/`; validated Fleet-enabled install/ensure copies it into the protected active `<InstallRoot>/lib/defenseclaw/` path. Fleet-off install/upgrade does not activate the compiler or require Python/PyYAML. A Fleet-off raw payload install discards its optional compiler source; supply the staged release `--payload` when enabling Fleet later. The bundled Fleet Grafana dashboard is empty while Fleet is off, and the local Prometheus stack has no Fleet scrape job by default.

The standard per-user `install.sh`/`install.ps1` also leave Fleet off and copy the matching compiler only when an existing config explicitly enables Fleet. `defenseclaw setup edge-connector` installs the optional compiler and enables `fleet.enabled` after its credential setup succeeds. Installing the core gateway does not install or start the separate C Edge Connector service.

```bash
python3 /usr/local/lib/defenseclaw/policy_compiler.py \
  --input ~/.defenseclaw/policy.yaml \
  --profile standard --version 1 \
  --output-header policy_tables.h \
  --output-binary policy.bin
```

The compiler writes both files in the current directory. Its binary output has a development stub signature and cannot be directly applied as production OTA. Use the Fleet policy-push API with matching `DCLAW_OTA_HMAC_KEY` secrets to compile and HMAC-sign production updates. The compiler's Ed25519 `--signing-key` output is not accepted by this C receiver.

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
| **Unix socket (JSON-RPC)** | Any process, any language | `/run/defenseclaw/defenseclaw.sock` |

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
- Auto-detects backend: uses the running daemon's Unix socket first, then FFI (ctypes) when no daemon is available
- Configurable fail-open / fail-closed behavior
- Built-in Python capability hints; the C engine still rejects unknown names without a reviewed C mapping
- Automatic destination extraction from URL arguments
- Content scanning when arguments are provided

**Configuration:**

```python
ec = EdgeConnector(
    lib_path="/path/to/libdclaw_core.so",   # override FFI path
    socket_path="/run/defenseclaw/defenseclaw.sock", # default daemon socket
    fail_open=False,                         # block when engine is down
    session_id=42,                           # session correlation ID
)
```

Or via environment variables: `DCLAW_LIB_PATH`, `DCLAW_SOCKET_PATH`, `DCLAW_FAIL_OPEN`.

---

### MCP Proxy (Model Context Protocol)

A transparent MCP proxy that sits between an LLM client (Claude, Codex, etc.) and a real MCP server, intercepting every `tools/call` request and evaluating it through the C engine's local guards, verdict cache, and optional Fleet escalation. All other MCP messages (`tools/list`, `resources/read`, `prompts/get`, etc.) pass through unchanged.

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

From the `edge-connector/` source directory, quick start with a local stdio MCP server:

```bash
# Proxy an MCP server that speaks stdio
DCLAW_MCP_UPSTREAM='["python3", "-m", "esp_claw.mcp_server"]' \
  python3 tools/mcp_proxy.py
```

**With a config file:**

```bash
python3 tools/mcp_proxy.py --config tools/mcp_proxy_config.yaml
```

Use stdio for a local MCP server: the proxy rejects private and loopback HTTP upstream addresses. For a remote upstream, configure a reviewed public HTTPS endpoint and verify its downstream network behavior.

**Using with Claude Desktop or Claude Code:**

Add the proxy to your MCP client configuration. Instead of pointing directly at the MCP server, point at the proxy and configure it to forward to the real server:

```json
{
  "mcpServers": {
    "esp-claw-secured": {
      "command": "python3",
      "args": ["/usr/local/lib/defenseclaw/mcp_proxy.py"],
      "env": {
        "DCLAW_MCP_UPSTREAM": "[\"python3\", \"-m\", \"esp_claw.mcp_server\"]",
        "DCLAW_LIB_PATH": "/usr/local/lib/libdclaw_core.so"
      }
    }
  }
}
```

Replace `/usr/local/lib` if CMake installed into another library directory. The `esp_claw.mcp_server` module is an upstream example and must be installed separately; substitute your actual stdio MCP server command. For Python imports such as `from generic_hook import EdgeConnector`, set `PYTHONPATH=/usr/local/lib/defenseclaw` (or the source `tools/` directory), because CMake does not add its installed adapter directory to Python's import path.

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `DCLAW_MCP_UPSTREAM` | (none) | Target server: JSON array of command (stdio) or URL (HTTP) |
| `DCLAW_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `DCLAW_MCP_PORT` | `8089` | HTTP port when proxy serves HTTP |

All standard Edge Connector env vars (`DCLAW_LIB_PATH`, `DCLAW_SOCKET_PATH`, `DCLAW_FAIL_OPEN`) are passed through.

**What gets intercepted:**

| MCP Method | Action | Description |
|---|---|---|
| `tools/call` | Evaluate | Input validation, rate limit, content scan, destination and SSRF checks, sequence correlation, cache lookup, then optional Fleet request. Blocked calls return an MCP error. |
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
mkdir -p ~/.picoclaw/hooks
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
    "command": ["python3", "/home/USERNAME/.picoclaw/hooks/defenseclaw_gate.py"],
    "env": {
      "DCLAW_LIB_PATH": "/usr/local/lib/libdclaw_core.so",
      "DCLAW_LOG_PATH": "/home/USERNAME/edge-connector.log"
    },
    "intercept": ["before_tool", "before_llm", "after_llm"]
  }
}
```

Replace `USERNAME` with the actual home directory. A process launcher need not expand `~` in JSON command or environment values.

#### What gets intercepted

| Hook | What DefenseClaw Does | Supported Actions |
|------|----------------------|-------------------|
| `before_tool` | Local guards, verdict cache, then optional Fleet request | `deny_tool` with canned message, `continue` |
| `before_llm` | Pattern-based prompt injection detection (20+ patterns) | `abort_turn` (blocks LLM call entirely), `continue` |
| `after_llm` | PII/credential leakage scanning (SSN, credit cards, API keys, private keys) via content scanner | Detection + logging (redaction not supported in PicoClaw v0.3.x) |

#### Verify the integration

```bash
# Check that the hook protocol responds (this does not evaluate a tool)
echo '{"jsonrpc":"2.0","id":1,"method":"hook.hello","params":{}}' | \
  DCLAW_LIB_PATH=/usr/local/lib/libdclaw_core.so \
  python3 ~/.picoclaw/hooks/defenseclaw_gate.py
# Expected: {"jsonrpc":"2.0","id":1,"result":{"ok":true,"name":"edge-connector-gate"}}

# Observe a sensor-read decision; production waits for a Fleet verdict
picoclaw agent -m "check battery status"

# Observe a shell decision; inspect the actual tool call and audit result
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
tool_hash="$(printf exec_shell | sha256sum | cut -d' ' -f1)"
printf '{"jsonrpc":"2.0","id":1,"method":"evaluate","params":{'\
'"tool_name":"exec_shell","tool_hash":"%s","capabilities":4,'\
'"destination":"","session_id":1}}\n' "$tool_hash" | \
  socat - UNIX-CONNECT:/run/defenseclaw/defenseclaw.sock
```

This optional raw IPC probe requires `socat` and a running daemon. The daemon derives trusted capability flags from the tool name; the caller-supplied `capabilities` value is not authority.

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
    "destination": "1.1.1.1",
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
| `content` | string | no | Text for the built-in content scanner (tool arguments, tool output, etc.). The MQTT verdict request can include a truncated snippet, but the current gateway evaluates only the tool hash and does not run a content model over it. |

---

## Tool-to-Capability Mapping

Each tool your agent calls must have a reviewed mapping in the C engine's trusted table (`src/decision/policy_table.c`). The C engine ignores a conflicting capability supplied by an IPC caller and blocks an unknown tool name before cache lookup or MQTT escalation. A Python adapter map can pass the correct flag but cannot add new names to that C table. When `content` is provided, the built-in scanner also checks it for secrets, PII, credentials, exfiltration indicators, injection attempts, and dangerous commands.

The shipped Home Assistant, Bubbaloop, and ESP-Claw wrappers no longer use their MCP transport host as the delegated network destination. Bubbaloop `http_fetch`/`model_download` and ESP-Claw `http_request` pass a reviewed HTTP(S) public numeric `url` argument through the C SSRF/allowlist check; missing, private, hostname, and ambiguous targets fail closed. Home Assistant webhooks/integration calls and broker/Zenoh network tools remain blocked without a reviewed target schema. The downstream MCP server must independently constrain redirects and actual egress; adapter validation does not prove the server ultimately connects to the checked IP.

| Capability | Flag | Local checks |
|---|---|---|
| `SENSOR_READ` | 0x40 | Content, rate, and sequence checks |
| `READ_FS` | 0x01 | Content, rate, and sequence checks |
| `NET_FETCH` | 0x08 | Destination allowlist, SSRF, content, rate, and sequence checks |
| `SEND_MSG` | 0x10 | Destination allowlist, SSRF, content, rate, and sequence checks |
| `ACTUATE` | 0x20 | Content, rate, and sequence checks |
| `EXEC_SHELL` | 0x04 | Content, rate, and sequence checks |
| `WRITE_FS` | 0x02 | Content, rate, and sequence checks |

The generic hook's mapping includes these names, which are also in the C table:

```python
TOOL_CAP_MAP = {
    # Your tools → capabilities
    "get_temperature":  CAP_SENSOR_READ,   # safe, allow
    "read_file":        CAP_READ_FS,       # local file read
    "call_api":         CAP_NET_FETCH,     # allow if dest approved
    "send_email":       CAP_SEND_MSG,      # allow if dest approved
    "start_motor":      CAP_ACTUATE,       # BLOCK without cloud
    "exec_shell":       CAP_EXEC_SHELL,    # BLOCK without cloud
    "write_file":       CAP_WRITE_FS,      # BLOCK without cloud
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
# Record latency and throughput on the target hardware and build profile.
```

---

## Updating

```bash
# No separate prebuilt C Edge Connector archive is published by this release.
# Update the reviewed source checkout and rebuild the same production profile.
cd defenseclaw
git pull --ff-only
cmake -S edge-connector -B edge-connector/build \
  -DDCLAW_PROFILE=STANDARD -DDCLAW_DEV_MODE=OFF -DDCLAW_ALLOW_HMAC_OTA=ON
cmake --build edge-connector/build -j$(nproc)
ctest --test-dir edge-connector/build --output-on-failure
sudo cmake --install edge-connector/build
sudo ldconfig
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `libdclaw_core.so: cannot open shared object file` | Run `sudo ldconfig` or set `LD_LIBRARY_PATH` |
| All tools getting blocked | Check the C capability table (`src/decision/policy_table.c`). Unknown tool names fail closed before cache or Fleet escalation. A custom name needs a reviewed C mapping; a Python adapter mapping alone cannot authorize it. |
| `CLOUD_TIMEOUT` on undecided tools | Check broker reachability, TLS, device key, and gateway verdict response. Production strict mode blocks on timeout; OTA cannot set per-capability escalation. |
| `DEST_DENY` on a public IP | Add that public IP to `destination_allowlist` in policy YAML |
| `CONTENT_BLOCK` false positives | Review the matched text and fixed scanner patterns; this release has no YAML category toggle or custom exception pattern. |
| `SSRF_BLOCK` on hostnames or private addresses | Use an approved public numeric IP. Hostnames require a controlled egress resolver/proxy; private destinations have no policy bypass |
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
│  7-Stage Evaluation Path:                               │
│  1. Input validation    5. Sequence correlation         │
│  2. Rate limiting       6. Verdict cache                │
│  3. Content scanning    7. Fleet hash verdict request   │
│  4. Dest filtering + SSRF                                │
│                                                         │
│  → ALLOW / BLOCK / WARN / PENDING                       │
└─────────────────────────────────────────────────────────┘
```

---

## What's Included vs. What You Configure

| DefenseClaw Edge Connector Provides | You Configure |
|-------------------------------------|---------------|
| Seven-checkpoint evaluation path | Reviewed tool names in the C capability table |
| Built-in content scanning (secrets, PII, credentials, exfil, injection, commands) | Content text to inspect |
| SSRF validation | Approved public numeric IP destinations |
| Sequence correlation (FSM) | Capability sequences in supported policy YAML |
| Rate limiting (3 buckets) | Built-in rates; OTA policy cannot change them |
| HMAC-chained audit trail | `DCLAW_AUDIT_KEY` and protected flash state |
| Verdict caching (LRU) | — |
| Destination filtering | Allowed public numeric IPs |
| Gateway hash-verdict escalation with a truncated content snippet on the wire | Per-device keys and broker ACLs; no external content model |
| Response evaluation when the integration calls it | Integration's request/response direction |
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
