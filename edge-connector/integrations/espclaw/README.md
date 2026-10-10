# ESP-Claw Integration for DefenseClaw Edge Connector

Secure [ESP-Claw](https://github.com/nicholasgasior/esp-claw) (Espressif ESP32 MCP server/client) with DefenseClaw policy enforcement.

ESP-Claw runs on ESP32 microcontrollers and exposes hardware tools (GPIO, I2C, SPI, sensors) via MCP over HTTP. This adapter intercepts every tool call through the Edge Connector before it reaches the device.

## Prerequisites

- DefenseClaw Edge Connector built and installed ([INSTALL.md](../../INSTALL.md))
- ESP-Claw device running on the local network
- Python 3.9+

```bash
pip install requests zeroconf
```

## Quick Start

```python
from defenseclaw_espclaw import setup_espclaw

# Auto-discover ESP-Claw devices on the LAN via mDNS
adapter = setup_espclaw()

# Read a sensor (SENSOR_READ -- allowed by default)
result = adapter.call_tool("temperature_read", {})

# Write to GPIO (ACTUATE -- requires cloud approval in strict mode)
result = adapter.call_tool("gpio_write", {"pin": 5, "value": 1})
if not result["allowed"]:
    print(f"Blocked: {result['verdict']['reason']}")

# Execute Lua code (EXEC_SHELL -- blocked without cloud approval)
result = adapter.call_tool("lua_eval", {"code": "print('hello')"})
```

## Connect to a Known Device

```python
from defenseclaw_espclaw import ESPClawAdapter

adapter = ESPClawAdapter(host="192.168.1.42", port=80)
tools = adapter.list_tools()
info = adapter.get_device_info()
```

Or set the host via environment variable:

```bash
export ESPCLAW_HOST=192.168.1.42
```

## Capability Mapping

| ESP-Claw Tool | Edge Connector Capability | Default Policy |
|---------------|---------------------------|----------------|
| `gpio_read`, `adc_read`, `temperature_read`, `imu_read` | `SENSOR_READ` | Allow |
| `gpio_write`, `pwm_set`, `i2c_write`, `spi_transfer` | `ACTUATE` | Sync-block |
| `wifi_scan`, `http_request`, `mqtt_publish` | `NET_FETCH` | Allow if dest approved |
| `fs_read`, `fs_list`, `config_get` | `READ_FS` | Allow |
| `fs_write`, `config_set` | `WRITE_FS` | Sync-block |
| `lua_eval`, `lua_load`, `reboot`, `ota_update` | `EXEC_SHELL` | Sync-block |

## Policy Recommendations for ESP32

Add to your `~/.defenseclaw/policy.yaml`:

```yaml
iot_extensions:
  # Block download-then-execute on microcontrollers
  capability_sequences:
    - sequence: [net_fetch, exec_shell]
      action: block
    - sequence: [net_fetch, actuate]
      action: block

  # Limit OTA and Lua execution
  rate_limits:
    tool_calls_per_minute: 30
    actuations_per_minute: 5

  # Only allow MQTT to your broker
  destination_allowlist:
    - "mqtt.your-company.com"
    - "api.anthropic.com"
```

## Architecture

```
ESP-Claw Device (ESP32)         This Adapter (Pi / gateway)
+-------------------+           +---------------------------+
| MCP Server (HTTP) | <-------> | ESPClawAdapter            |
| GPIO, I2C, SPI    |   HTTP    |   evaluate() -> forward() |
| Lua scripting     |           | EdgeConnector engine      |
| Sensors           |           |   (libdclaw_core.so)      |
+-------------------+           +---------------------------+
```

The adapter runs on a gateway device (Raspberry Pi, Jetson, or any Linux host) and proxies MCP calls to the ESP32, enforcing policy on every request.
