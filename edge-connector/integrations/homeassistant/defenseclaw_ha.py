"""Home Assistant MCP (HA-MCP) adapter for DefenseClaw Edge Connector.

HA-MCP exposes 87 MCP tools for smart home control. This adapter connects
to a running HA-MCP instance, maps tools to Edge Connector capabilities,
and enforces policy on every call. Supports read-only mode for monitoring.

Usage:
    from defenseclaw_ha import setup_homeassistant
    adapter = setup_homeassistant(host="homeassistant.local")
    result = adapter.call_tool("get_state", {"entity_id": "sensor.temp"})

Requirements: pip install requests
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, List, Optional

_tools_dir = os.path.join(os.path.dirname(__file__), "..", "..", "tools")
if _tools_dir not in sys.path:
    sys.path.insert(0, os.path.abspath(_tools_dir))

from generic_hook import (
    CAP_ACTUATE, CAP_EXEC_SHELL, CAP_NET_FETCH,
    CAP_READ_FS, CAP_SEND_MSG, CAP_SENSOR_READ, CAP_WRITE_FS,
    EdgeConnector,
)

logger = logging.getLogger("defenseclaw.homeassistant")

# HA-MCP tool -> Edge Connector capability mapping
HAMCP_TOOL_CAP_MAP: Dict[str, int] = {
    # State / History reads (SENSOR_READ)
    "get_state": CAP_SENSOR_READ, "get_all_states": CAP_SENSOR_READ,
    "get_entity_state": CAP_SENSOR_READ, "search_entities": CAP_SENSOR_READ,
    "get_history": CAP_SENSOR_READ, "get_logbook": CAP_SENSOR_READ,
    "get_error_log": CAP_SENSOR_READ, "get_entity_history": CAP_SENSOR_READ,
    "get_statistics": CAP_SENSOR_READ, "get_sensor_data": CAP_SENSOR_READ,
    "get_energy_data": CAP_SENSOR_READ, "get_areas": CAP_SENSOR_READ,
    "get_devices": CAP_SENSOR_READ, "get_entities": CAP_SENSOR_READ,
    "get_entity_registry": CAP_SENSOR_READ, "get_device_registry": CAP_SENSOR_READ,
    "get_area_registry": CAP_SENSOR_READ, "get_config": CAP_SENSOR_READ,
    "get_services": CAP_SENSOR_READ, "get_integrations": CAP_SENSOR_READ,
    "get_addons": CAP_SENSOR_READ, "get_addon_info": CAP_SENSOR_READ,
    "get_blueprints": CAP_SENSOR_READ, "get_automations": CAP_SENSOR_READ,
    "get_scenes": CAP_SENSOR_READ, "get_scripts": CAP_SENSOR_READ,
    "get_zones": CAP_SENSOR_READ, "get_persons": CAP_SENSOR_READ,
    "get_calendars": CAP_SENSOR_READ, "get_calendar_events": CAP_SENSOR_READ,
    "get_shopping_list": CAP_SENSOR_READ, "get_todo_items": CAP_SENSOR_READ,
    "get_media_players": CAP_SENSOR_READ, "get_camera_image": CAP_SENSOR_READ,
    "get_notifications": CAP_SENSOR_READ,
    # Device control (ACTUATE)
    "turn_on": CAP_ACTUATE, "turn_off": CAP_ACTUATE, "toggle": CAP_ACTUATE,
    "set_temperature": CAP_ACTUATE, "set_hvac_mode": CAP_ACTUATE,
    "set_fan_mode": CAP_ACTUATE, "set_humidity": CAP_ACTUATE,
    "set_brightness": CAP_ACTUATE, "set_color": CAP_ACTUATE,
    "set_cover_position": CAP_ACTUATE, "open_cover": CAP_ACTUATE,
    "close_cover": CAP_ACTUATE, "lock": CAP_ACTUATE, "unlock": CAP_ACTUATE,
    "arm_alarm": CAP_ACTUATE, "disarm_alarm": CAP_ACTUATE,
    "trigger_alarm": CAP_ACTUATE, "media_play": CAP_ACTUATE,
    "media_pause": CAP_ACTUATE, "media_stop": CAP_ACTUATE,
    "media_next": CAP_ACTUATE, "media_previous": CAP_ACTUATE,
    "set_volume": CAP_ACTUATE, "play_media": CAP_ACTUATE,
    "vacuum_start": CAP_ACTUATE, "vacuum_stop": CAP_ACTUATE,
    "vacuum_return_home": CAP_ACTUATE, "select_option": CAP_ACTUATE,
    "set_value": CAP_ACTUATE, "press_button": CAP_ACTUATE,
    "call_service": CAP_ACTUATE, "fire_event": CAP_ACTUATE,
    "activate_scene": CAP_ACTUATE,
    # Automations / System (EXEC_SHELL)
    "run_script": CAP_EXEC_SHELL, "trigger_automation": CAP_EXEC_SHELL,
    "restart_ha": CAP_EXEC_SHELL, "reload_config": CAP_EXEC_SHELL,
    "reload_automations": CAP_EXEC_SHELL, "reload_scripts": CAP_EXEC_SHELL,
    "reload_scenes": CAP_EXEC_SHELL, "install_addon": CAP_EXEC_SHELL,
    "start_addon": CAP_EXEC_SHELL, "stop_addon": CAP_EXEC_SHELL,
    "update_addon": CAP_EXEC_SHELL,
    # Config writes (WRITE_FS)
    "create_automation": CAP_WRITE_FS, "update_automation": CAP_WRITE_FS,
    "delete_automation": CAP_WRITE_FS,
    # Notifications (SEND_MSG)
    "send_notification": CAP_SEND_MSG, "notify": CAP_SEND_MSG,
    "tts_speak": CAP_SEND_MSG,
    # Network / webhooks (NET_FETCH)
    "register_webhook": CAP_NET_FETCH, "call_webhook": CAP_NET_FETCH,
    "get_integrations_manifest": CAP_NET_FETCH,
    "setup_integration": CAP_NET_FETCH, "remove_integration": CAP_NET_FETCH,
}

_READ_ONLY_TOOLS = {n for n, c in HAMCP_TOOL_CAP_MAP.items() if c == CAP_SENSOR_READ}


class HomeAssistantAdapter:
    """Wraps HA-MCP's endpoint with policy enforcement."""

    def __init__(self, host: str = "homeassistant.local", port: int = 8123,
                 mcp_port: int = 3000, mcp_path: str = "/mcp",
                 access_token: Optional[str] = None, read_only: bool = False,
                 connector: Optional[EdgeConnector] = None,
                 session_id: int = 1, timeout: float = 10.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.read_only = read_only
        self.ha_url = f"http://{host}:{port}"
        self.mcp_url = f"http://{host}:{mcp_port}{mcp_path}"
        self._access_token = access_token or os.environ.get("HA_ACCESS_TOKEN", "")
        self._connector = connector or EdgeConnector(
            fail_open=True, tool_cap_map=HAMCP_TOOL_CAP_MAP, session_id=session_id,
        )
        self._request_id = 0

    def call_tool(self, tool_name: str,
                  arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Evaluate then forward. Returns {allowed, verdict, result}."""
        arguments = arguments or {}
        if self.read_only and tool_name not in _READ_ONLY_TOOLS:
            return {"allowed": False,
                    "verdict": {"action": 1, "reason": "READ_ONLY_MODE"},
                    "result": None}
        verdict = self._connector.evaluate(
            tool_name=tool_name, arguments=arguments, destination=self.host,
        )
        if verdict.blocked:
            logger.warning("HA tool %s blocked: %s", tool_name, verdict.reason)
            return {"allowed": False,
                    "verdict": {"action": verdict.action, "reason": verdict.reason},
                    "result": None}
        result = self._mcp_request("tools/call",
                                   {"name": tool_name, "arguments": arguments})
        return {"allowed": True,
                "verdict": {"action": verdict.action, "reason": verdict.reason},
                "result": result}

    def list_tools(self) -> List[Dict[str, Any]]:
        try:
            return self._mcp_request("tools/list", {}).get("tools", [])
        except Exception as exc:
            logger.error("Failed to list HA-MCP tools: %s", exc)
            return []

    def get_ha_status(self) -> Dict[str, Any]:
        """Check if the Home Assistant instance is reachable."""
        try:
            import requests
            r = requests.get(f"{self.ha_url}/api/", headers=self._auth_headers(),
                             timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            return {"error": str(exc)}

    # -- internal ----------------------------------------------------------

    def _auth_headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"Content-Type": "application/json"}
        if self._access_token:
            h["Authorization"] = f"Bearer {self._access_token}"
        return h

    def _mcp_request(self, method: str, params: Dict[str, Any]) -> Any:
        import requests
        self._request_id += 1
        r = requests.post(self.mcp_url, timeout=self.timeout,
                          headers=self._auth_headers(), json={
            "jsonrpc": "2.0", "id": self._request_id,
            "method": method, "params": params,
        })
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise RuntimeError(f"HA-MCP error: {data['error']}")
        return data.get("result", {})


def setup_homeassistant(host: str = "homeassistant.local", port: int = 8123,
                        mcp_port: int = 3000, access_token: Optional[str] = None,
                        read_only: bool = False,
                        connector: Optional[EdgeConnector] = None
                        ) -> HomeAssistantAdapter:
    """Set up a Home Assistant MCP adapter."""
    adapter = HomeAssistantAdapter(host=host, port=port, mcp_port=mcp_port,
                                   access_token=access_token, read_only=read_only,
                                   connector=connector)
    status = adapter.get_ha_status()
    if "error" in status:
        logger.warning("Could not reach HA at %s:%d -- %s", host, port, status["error"])
    else:
        logger.info("Connected to Home Assistant: %s", status.get("message", "OK"))
    if read_only:
        logger.info("HA adapter in READ-ONLY mode")
    logger.info("Home Assistant adapter ready: %s", adapter.mcp_url)
    return adapter
