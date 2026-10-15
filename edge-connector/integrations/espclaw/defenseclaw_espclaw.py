# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""ESP-Claw (Espressif ESP32) adapter for DefenseClaw Edge Connector.

ESP-Claw exposes MCP tools over HTTP from ESP32 devices. This adapter
discovers devices via mDNS and routes tool calls through the policy engine.

Usage:
    from defenseclaw_espclaw import setup_espclaw
    adapter = setup_espclaw()                           # mDNS auto-discover
    adapter = setup_espclaw(host="192.168.1.42")        # or explicit IP
    result = adapter.call_tool("gpio_write", {"pin": 5, "value": 1})

Requirements: pip install requests zeroconf
"""
from __future__ import annotations

import logging
import os
import secrets
import sys
from typing import Any, Dict, List, Optional

_tools_dir = os.path.join(os.path.dirname(__file__), "..", "..", "tools")
if _tools_dir not in sys.path:
    sys.path.insert(0, os.path.abspath(_tools_dir))

from generic_hook import (
    CAP_ACTUATE, CAP_EXEC_SHELL, CAP_NET_FETCH,
    CAP_READ_FS, CAP_SENSOR_READ, CAP_WRITE_FS,
    EdgeConnector, Verdict, reviewed_adapter_destination,
)

logger = logging.getLogger("defenseclaw.espclaw")

# ESP-Claw tool -> Edge Connector capability mapping
ESPCLAW_TOOL_CAP_MAP: Dict[str, int] = {
    "gpio_read": CAP_SENSOR_READ, "adc_read": CAP_SENSOR_READ,
    "i2c_read": CAP_SENSOR_READ, "temperature_read": CAP_SENSOR_READ,
    "humidity_read": CAP_SENSOR_READ, "pressure_read": CAP_SENSOR_READ,
    "imu_read": CAP_SENSOR_READ, "battery_level": CAP_SENSOR_READ,
    "get_status": CAP_SENSOR_READ, "ble_scan": CAP_SENSOR_READ,
    "gpio_write": CAP_ACTUATE, "pwm_set": CAP_ACTUATE,
    "i2c_write": CAP_ACTUATE, "spi_transfer": CAP_ACTUATE,
    "wifi_scan": CAP_SENSOR_READ, "http_request": CAP_NET_FETCH,
    "mqtt_publish": CAP_NET_FETCH,
    "fs_read": CAP_READ_FS, "fs_list": CAP_READ_FS, "config_get": CAP_READ_FS,
    "fs_write": CAP_WRITE_FS, "config_set": CAP_WRITE_FS,
    "lua_eval": CAP_EXEC_SHELL, "lua_load": CAP_EXEC_SHELL,
    "reboot": CAP_EXEC_SHELL, "ota_update": CAP_EXEC_SHELL,
}

_HTTP_URL_FIELDS = {"http_request": "url"}


class ESPClawAdapter:
    """Wraps an ESP-Claw device's MCP endpoint with policy enforcement."""

    def __init__(self, host: str = "espclaw.local", port: int = 80,
                 mcp_path: str = "/mcp", connector: Optional[EdgeConnector] = None,
                 session_id: int = 1, timeout: float = 5.0):
        self.host, self.port, self.timeout = host, port, timeout
        # Default to HTTPS for non-loopback; explicit opt-in for plaintext
        _is_loopback = host in ("127.0.0.1", "localhost", "::1", "[::1]")
        scheme = "http" if _is_loopback else os.environ.get("DCLAW_EDGE_SCHEME", "https")
        self.base_url = f"{scheme}://{host}:{port}"
        self.mcp_url = f"{self.base_url}{mcp_path}"
        # M-12 fix: Enforce HTTPS for non-loopback hosts in production.
        # Use DCLAW_ESPCLAW_ALLOW_HTTP=1 to explicitly override when needed.
        if host not in ("localhost", "127.0.0.1", "::1"):
            allow_http = os.environ.get("DCLAW_ESPCLAW_ALLOW_HTTP", "")
            prod = os.environ.get("DCLAW_PRODUCTION", "")
            if prod == "1" and allow_http != "1":
                raise ValueError(
                    f"Plaintext HTTP to non-loopback host {host!r} is not allowed in production. "
                    "Set DCLAW_ESPCLAW_ALLOW_HTTP=1 to override."
                )
            if self.mcp_url.startswith("http://"):
                import warnings
                warnings.warn(
                    f"MCP endpoint {self.mcp_url} uses plaintext HTTP on a non-loopback address. "
                    "Auth tokens will be transmitted in cleartext. Use HTTPS in production.",
                    stacklevel=2,
                )
        self._connector = connector or EdgeConnector(
            fail_open=False, tool_cap_map=ESPCLAW_TOOL_CAP_MAP, session_id=session_id,
        )

    def call_tool(self, tool_name: str,
                  arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Evaluate then forward. Returns {allowed, verdict, result}."""
        arguments = arguments or {}
        try:
            destination = reviewed_adapter_destination(
                tool_name, arguments, ESPCLAW_TOOL_CAP_MAP, _HTTP_URL_FIELDS)
        except ValueError as exc:
            verdict = Verdict.error(str(exc))
        else:
            verdict = self._connector.evaluate(
                tool_name=tool_name, arguments=arguments, destination=destination,
            )
        if verdict.blocked:
            logger.warning("ESP-Claw tool %s blocked: %s", tool_name, verdict.reason)
            return {"allowed": False,
                    "verdict": {"action": verdict.action, "reason": verdict.reason},
                    "result": None}
        result = self._mcp_request("tools/call",
                                   {"name": tool_name, "arguments": arguments})
        return {"allowed": True,
                "verdict": {"action": verdict.action, "reason": verdict.reason},
                "result": result}

    def list_tools(self) -> List[Dict[str, Any]]:
        """Query the device for its available MCP tools."""
        try:
            return self._mcp_request("tools/list", {}).get("tools", [])
        except Exception as exc:
            logger.error("Failed to list ESP-Claw tools: %s", exc)
            return []

    def get_device_info(self) -> Dict[str, Any]:
        """Fetch device metadata (firmware, chip, uptime)."""
        try:
            import requests
            r = requests.get(f"{self.base_url}/api/status", timeout=self.timeout, allow_redirects=False)
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            # M-13 fix: Do not leak full URLs/hostnames/tokens in error messages.
            logger.exception("ESP-Claw get_device_info failed")
            return {"error": "connection_failed", "detail": type(exc).__name__}

    def _mcp_request(self, method: str, params: Dict[str, Any]) -> Any:
        import requests
        request_id = secrets.randbelow(2**31)
        r = requests.post(self.mcp_url, timeout=self.timeout, allow_redirects=False, json={
            "jsonrpc": "2.0", "id": request_id,
            "method": method, "params": params,
        })
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise RuntimeError(f"ESP-Claw MCP error: {data['error']}")
        return data.get("result", {})


def discover_espclaw_devices(timeout: float = 3.0) -> List[Dict[str, Any]]:
    """Discover ESP-Claw devices on the local network via mDNS."""
    devices: List[Dict[str, Any]] = []
    try:
        from zeroconf import ServiceBrowser, Zeroconf
        import time

        zc = Zeroconf()
        found: list = []

        class Listener:
            def add_service(self, zc_inst, stype, name):
                info = zc_inst.get_service_info(stype, name)
                if info:
                    found.append(info)
            def remove_service(self, *a): pass
            def update_service(self, *a): pass

        for stype in ["_espclaw._tcp.local.", "_mcp._tcp.local."]:
            ServiceBrowser(zc, stype, Listener())
        time.sleep(timeout)
        zc.close()

        for info in found:
            addrs = info.parsed_addresses() or []
            if addrs:
                devices.append({"host": addrs[0], "port": info.port or 80,
                                "name": info.name})
    except ImportError:
        logger.warning("zeroconf not installed; mDNS discovery unavailable")
    except Exception as exc:
        logger.error("mDNS discovery failed: %s", exc)
    return devices


def setup_espclaw(host: Optional[str] = None, port: int = 80,
                  discover: bool = True,
                  connector: Optional[EdgeConnector] = None) -> ESPClawAdapter:
    """Set up an ESP-Claw adapter, optionally auto-discovering the device."""
    if host is None and discover:
        logger.info("Scanning for ESP-Claw devices via mDNS...")
        devices = discover_espclaw_devices()
        if devices:
            dev = devices[0]
            host, port = dev["host"], dev["port"]
            logger.info("Found ESP-Claw: %s:%d (%s)", host, port, dev["name"])
        else:
            host = os.environ.get("ESPCLAW_HOST", "espclaw.local")
            logger.info("No devices found, using %s:%d", host, port)
    adapter = ESPClawAdapter(host=host or "espclaw.local", port=port,
                             connector=connector)
    logger.info("ESP-Claw adapter ready: %s", adapter.mcp_url)
    return adapter
