# DefenseClaw Edge Connector -- Framework Integrations

Pre-built adapters for physical AI frameworks. Each adapter connects to the framework's MCP endpoint and routes every tool call through the Edge Connector policy engine before execution.

## Available Integrations

| Framework | Tools | Platform | Status | Directory |
|-----------|-------|----------|--------|-----------|
| **[ESP-Claw](espclaw/)** (Espressif) | GPIO, I2C, SPI, Lua scripting | ESP32 | Available | `espclaw/` |
| **[Bubbaloop](bubbaloop/)** (Kornia) | 47 tools: vision, robotics, fleet mgmt | Jetson, RPi | Available | `bubbaloop/` |
| **[Home Assistant MCP](homeassistant/)** | 87 tools: smart home control | RPi, NUC, VM | Available | `homeassistant/` |

## How It Works

Each adapter follows the same pattern:

1. Imports `EdgeConnector` from `tools/generic_hook.py` (no logic duplication)
2. Maps framework-specific tool names to Edge Connector capabilities (`SENSOR_READ`, `ACTUATE`, `EXEC_SHELL`, etc.)
3. Evaluates every tool call through the policy engine before forwarding to the framework
4. Returns a structured result with the verdict and the framework's response

```python
# All adapters share this interface:
result = adapter.call_tool("tool_name", {"arg": "value"})

if result["allowed"]:
    data = result["result"]    # Framework response
else:
    reason = result["verdict"]["reason"]  # Why it was blocked
```

## Choosing an Adapter

- **ESP-Claw**: For ESP32 microcontrollers running Lua-scriptable MCP. Includes mDNS device discovery.
- **Bubbaloop**: For Rust-based computer vision and robotics daemons on Jetson/RPi. Includes Zenoh telemetry subscription.
- **Home Assistant MCP**: For smart home control with 87 device tools. Supports read-only mode for monitoring-only deployments.

## Built-in Adapters (in tools/)

These ship with the Edge Connector and work with any framework:

| Adapter | File | Use Case |
|---------|------|----------|
| Generic Python | `tools/generic_hook.py` | Any Python agent |
| LangChain / LangGraph | `tools/langchain_hook.py` | LangChain-based agents |
| HTTP Middleware | `tools/http_middleware.py` | FastAPI, Flask, any HTTP API |
| PicoClaw | `tools/picoclaw_hook.py` | PicoClaw robot agents |

## Adding a New Integration

1. Create a directory under `integrations/` with your framework name
2. Import `EdgeConnector` from `tools/generic_hook.py`
3. Define a `TOOL_CAP_MAP` mapping your framework's tools to capabilities
4. Create an adapter class with `call_tool()` and `list_tools()` methods
5. Provide a `setup_*()` convenience function
6. Add a README with setup instructions and capability mapping table
7. Update this file's table above
