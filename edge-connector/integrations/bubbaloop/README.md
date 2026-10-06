# Bubbaloop Integration for DefenseClaw Edge Connector

Secure [Bubbaloop](https://github.com/kornia/bubbaloop) (Kornia's Rust-based physical AI daemon) with DefenseClaw policy enforcement.

Bubbaloop exposes 47 MCP tools for computer vision, robot control, and fleet management. It supports Zenoh pub/sub telemetry and 3-tier RBAC. This adapter intercepts every MCP tool call through the Edge Connector engine and optionally subscribes to Zenoh telemetry for monitoring.

## Prerequisites

- DefenseClaw Edge Connector built and installed ([INSTALL.md](../../INSTALL.md))
- Bubbaloop daemon running (Jetson, RPi, or Linux host)
- Python 3.9+

```bash
pip install requests
pip install eclipse-zenoh   # optional, for telemetry
```

## Quick Start

```python
from defenseclaw_bubbaloop import setup_bubbaloop

# Connect to a Bubbaloop daemon
adapter = setup_bubbaloop(host="192.168.1.10", port=8088)

# Capture a camera frame (SENSOR_READ -- allowed)
result = adapter.call_tool("camera_capture", {"device_id": 0})

# Move a servo (ACTUATE -- requires cloud approval in strict mode)
result = adapter.call_tool("servo_set_angle", {"servo_id": 1, "angle": 90})
if not result["allowed"]:
    print(f"Blocked: {result['verdict']['reason']}")

# Deploy a pipeline (EXEC_SHELL -- blocked without cloud approval)
result = adapter.call_tool("pipeline_deploy", {"name": "object-tracker"})
```

## Authentication

Bubbaloop uses token-based RBAC with three tiers (viewer, operator, admin). Pass your token via argument or environment variable:

```python
adapter = setup_bubbaloop(
    host="192.168.1.10",
    auth_token="bbloop_tok_abc123",
)
```

```bash
export BUBBALOOP_TOKEN=bbloop_tok_abc123
```

## Zenoh Telemetry

Subscribe to real-time telemetry from Bubbaloop's Zenoh pub/sub bus:

```python
def on_telemetry(topic, payload):
    print(f"[{topic}] {payload.decode()}")

adapter = setup_bubbaloop(
    host="192.168.1.10",
    enable_telemetry=True,
)
# Or subscribe manually with a callback:
adapter.subscribe_telemetry(callback=on_telemetry)
```

Default topics: `bubbaloop/telemetry/system`, `bubbaloop/telemetry/camera`, `bubbaloop/telemetry/sensors`, `bubbaloop/telemetry/network`, `bubbaloop/events/alerts`.

## Capability Mapping

| Tool Category | Example Tools | Capability | Default Policy |
|---------------|---------------|------------|----------------|
| Camera/Vision | `camera_capture`, `image_detect_objects`, `face_detect` | `SENSOR_READ` | Allow |
| Sensors | `imu_read`, `lidar_scan`, `gps_position`, `battery_status` | `SENSOR_READ` | Allow |
| Movement | `motor_set_speed`, `servo_set_angle`, `navigate_to` | `ACTUATE` | Sync-block |
| Gripper | `gripper_open`, `gripper_close`, `arm_move_to` | `ACTUATE` | Sync-block |
| Network | `http_fetch`, `mqtt_publish`, `zenoh_publish` | `NET_FETCH` | Allow if dest approved |
| Filesystem | `file_read`, `model_load`, `config_get` | `READ_FS` | Allow |
| Filesystem (write) | `file_write`, `model_save`, `config_set` | `WRITE_FS` | Sync-block |
| System | `system_restart`, `pipeline_deploy`, `firmware_update` | `EXEC_SHELL` | Sync-block |

## Policy Recommendations

Add to your `~/.defenseclaw/policy.yaml`:

```yaml
iot_extensions:
  capability_sequences:
    - sequence: [net_fetch, exec_shell]
      action: block
    - sequence: [sensor_read, net_fetch, actuate]
      action: block

  rate_limits:
    tool_calls_per_minute: 120
    actuations_per_minute: 30
    network_requests_per_minute: 60

  destination_allowlist:
    - "api.anthropic.com"
    - "mqtt.your-fleet.com"
    - "*.kornia.ai"
```

## Architecture

```
Bubbaloop (Jetson/RPi)          This Adapter (same host or gateway)
+-----------------------+       +-------------------------------+
| Rust daemon           |       | BubbaloopAdapter              |
|   47 MCP tools (8088) | <---> |   evaluate() -> forward()     |
|   Zenoh pub/sub (7447)| <---> |   Zenoh telemetry subscriber  |
|   3-tier RBAC         |       | EdgeConnector engine          |
|   Vision pipelines    |       |   (libdclaw_core.so)          |
+-----------------------+       +-------------------------------+
```
