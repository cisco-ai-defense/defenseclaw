# Home Assistant MCP Integration for DefenseClaw Edge Connector

Secure [HA-MCP](https://github.com/tomlm/ha-mcp) (Home Assistant MCP server with 87 tools) with DefenseClaw policy enforcement.

HA-MCP exposes smart home devices as MCP tools -- lights, locks, thermostats, cameras, alarms, and more. This adapter intercepts every tool call through the Edge Connector engine, preventing unauthorized actuation of physical devices.

## Prerequisites

- DefenseClaw Edge Connector built and installed ([INSTALL.md](../../INSTALL.md))
- Home Assistant instance running (RPi, NUC, VM, or HA OS)
- HA-MCP server configured and running
- Python 3.9+

```bash
pip install requests
```

## Quick Start

```python
from defenseclaw_ha import setup_homeassistant

adapter = setup_homeassistant(host="homeassistant.local")

# Read sensor state (SENSOR_READ -- allowed)
result = adapter.call_tool("get_state", {"entity_id": "sensor.living_room_temp"})

# Turn on a light (ACTUATE -- requires cloud approval in strict mode)
result = adapter.call_tool("turn_on", {"entity_id": "light.kitchen"})
if not result["allowed"]:
    print(f"Blocked: {result['verdict']['reason']}")

# Unlock a door (ACTUATE -- blocked without cloud approval)
result = adapter.call_tool("unlock", {"entity_id": "lock.front_door"})
```

## Authentication

HA-MCP uses Home Assistant Long-Lived Access Tokens. Create one in HA at Profile > Security > Long-Lived Access Tokens.

```python
adapter = setup_homeassistant(
    host="homeassistant.local",
    access_token="eyJhbGciOiJIUzI1NiIs...",
)
```

Or via environment variable:

```bash
export HA_ACCESS_TOKEN=eyJhbGciOiJIUzI1NiIs...
```

## Read-Only Mode

For monitoring-only deployments, enable read-only mode. This blocks all non-SENSOR_READ tools at the adapter level before they even reach the Edge Connector engine:

```python
adapter = setup_homeassistant(
    host="homeassistant.local",
    read_only=True,  # Only get_state, get_history, etc. allowed
)
```

## Capability Mapping

| Tool Category | Example Tools | Capability | Default Policy |
|---------------|---------------|------------|----------------|
| State/History reads | `get_state`, `get_history`, `search_entities`, `get_energy_data` | `SENSOR_READ` | Allow |
| Device control | `turn_on`, `turn_off`, `set_temperature`, `set_brightness` | `ACTUATE` | Sync-block |
| Security | `lock`, `unlock`, `arm_alarm`, `disarm_alarm` | `ACTUATE` | Sync-block |
| Media | `media_play`, `set_volume`, `play_media` | `ACTUATE` | Sync-block |
| Notifications | `send_notification`, `notify` | `SEND_MSG` | Blocked until a reviewed message destination exists |
| Text to speech | `tts_speak` | `ACTUATE` | Sync-block |
| Automations | `run_script`, `trigger_automation`, `restart_ha` | `EXEC_SHELL` | Sync-block |
| Config writes | `create_automation`, `update_automation` | `WRITE_FS` | Sync-block |
| Webhooks/integrations | `register_webhook`, `call_webhook`, `setup_integration` | `NET_FETCH` | Blocked until a reviewed delegated target exists |
| Integration manifest read | `get_integrations_manifest` | `SENSOR_READ` | Allow |

## Policy Recommendations

Add to your `~/.defenseclaw/policy.yaml`:

The shipped adapter tool names have reviewed mappings in the C engine's `src/decision/policy_table.c`. Custom names still need a reviewed C mapping; a Python capability map alone cannot authorize them. The wrapper no longer treats its MCP transport host as a delegated target. Home Assistant webhook/integration calls fail closed with `UNSUPPORTED_NETWORK_DESTINATION` until their argument and redirect behavior has a reviewed egress design; message tools also remain blocked without a destination. An allowlist entry alone cannot enable these calls. OTA cannot change the built-in rate limits.

```yaml
iot_extensions:
  capability_sequences:
    # Block: read sensor -> fetch external -> unlock door
    - sequence: [sensor_read, net_fetch, actuate]
      action: block
    # Block: fetch external -> run script
    - sequence: [net_fetch, exec_shell]
      action: block

  destination_allowlist:
    - "1.1.1.1" # illustrative public IP; replace with an approved endpoint
```

## Architecture

```
Home Assistant Instance        HA-MCP Server       This Adapter
+---------------------+       +-------------+      +------------------------+
| HA Core (8123)      | <---> | MCP (3000)  | <--> | HomeAssistantAdapter   |
| 87 entity domains   |  REST | 87 tools    | HTTP |  evaluate() -> forward |
| Automations/Scripts |       | Auth layer  |      | EdgeConnector engine   |
| Add-ons / HACS      |       +-------------+      |  (libdclaw_core.so)   |
+---------------------+                            +------------------------+
```

The adapter can run on the same RPi as Home Assistant or on a separate gateway host.
