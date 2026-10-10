"""Bubbaloop (Kornia) adapter for DefenseClaw Edge Connector.

Bubbaloop is a Rust daemon with 47 MCP tools, Zenoh pub/sub, and 3-tier RBAC.
Runs on Jetson/RPi for computer vision and robotics. This adapter connects to
its MCP endpoint, enforces policy on every tool call, and optionally subscribes
to Zenoh telemetry.

Usage:
    from defenseclaw_bubbaloop import setup_bubbaloop
    adapter = setup_bubbaloop(host="192.168.1.10")
    result = adapter.call_tool("camera_capture", {"device_id": 0})

Requirements: pip install requests
Optional:     pip install eclipse-zenoh   (for telemetry)
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
from typing import Any, Callable, Dict, List, Optional

_tools_dir = os.path.join(os.path.dirname(__file__), "..", "..", "tools")
if _tools_dir not in sys.path:
    sys.path.insert(0, os.path.abspath(_tools_dir))

from generic_hook import (
    CAP_ACTUATE, CAP_EXEC_SHELL, CAP_NET_FETCH,
    CAP_READ_FS, CAP_SENSOR_READ, CAP_WRITE_FS,
    EdgeConnector,
)

logger = logging.getLogger("defenseclaw.bubbaloop")

# Bubbaloop's 47 tools mapped to Edge Connector capabilities
BUBBALOOP_TOOL_CAP_MAP: Dict[str, int] = {
    # Camera / Vision (SENSOR_READ)
    "camera_capture": CAP_SENSOR_READ, "camera_list": CAP_SENSOR_READ,
    "camera_stream_start": CAP_SENSOR_READ, "camera_stream_stop": CAP_SENSOR_READ,
    "image_detect_objects": CAP_SENSOR_READ, "image_classify": CAP_SENSOR_READ,
    "image_segment": CAP_SENSOR_READ, "image_depth_estimate": CAP_SENSOR_READ,
    "image_feature_match": CAP_SENSOR_READ, "video_record_start": CAP_SENSOR_READ,
    "video_record_stop": CAP_SENSOR_READ, "aruco_detect": CAP_SENSOR_READ,
    "face_detect": CAP_SENSOR_READ, "pose_estimate": CAP_SENSOR_READ,
    "optical_flow": CAP_SENSOR_READ, "stereo_depth": CAP_SENSOR_READ,
    # Sensors
    "imu_read": CAP_SENSOR_READ, "lidar_scan": CAP_SENSOR_READ,
    "gps_position": CAP_SENSOR_READ, "temperature_read": CAP_SENSOR_READ,
    "battery_status": CAP_SENSOR_READ, "system_metrics": CAP_SENSOR_READ,
    # Movement / Actuation (ACTUATE)
    "motor_set_speed": CAP_ACTUATE, "motor_stop": CAP_ACTUATE,
    "servo_set_angle": CAP_ACTUATE, "gripper_open": CAP_ACTUATE,
    "gripper_close": CAP_ACTUATE, "navigate_to": CAP_ACTUATE,
    "follow_path": CAP_ACTUATE, "emergency_stop": CAP_ACTUATE,
    "arm_move_to": CAP_ACTUATE, "led_set": CAP_ACTUATE,
    # Network (NET_FETCH)
    "http_fetch": CAP_NET_FETCH, "mqtt_publish": CAP_NET_FETCH,
    "zenoh_publish": CAP_NET_FETCH, "cloud_sync": CAP_NET_FETCH,
    "model_download": CAP_NET_FETCH,
    # Filesystem
    "file_read": CAP_READ_FS, "file_list": CAP_READ_FS,
    "model_load": CAP_READ_FS, "config_get": CAP_READ_FS,
    "file_write": CAP_WRITE_FS, "model_save": CAP_WRITE_FS,
    "config_set": CAP_WRITE_FS,
    # System / Execution (EXEC_SHELL)
    "system_restart": CAP_EXEC_SHELL, "pipeline_deploy": CAP_EXEC_SHELL,
    "plugin_install": CAP_EXEC_SHELL, "firmware_update": CAP_EXEC_SHELL,
}

DEFAULT_ZENOH_TOPICS = [
    "bubbaloop/telemetry/system", "bubbaloop/telemetry/camera",
    "bubbaloop/telemetry/sensors", "bubbaloop/events/alerts",
]


class BubbaloopAdapter:
    """Wraps Bubbaloop's MCP endpoint with policy enforcement."""

    def __init__(self, host: str = "localhost", port: int = 8088,
                 mcp_path: str = "/mcp", auth_token: Optional[str] = None,
                 connector: Optional[EdgeConnector] = None,
                 session_id: int = 1, timeout: float = 10.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.base_url = f"http://{host}:{port}"
        self.mcp_url = f"{self.base_url}{mcp_path}"
        self._auth_token = auth_token or os.environ.get("BUBBALOOP_TOKEN", "")
        if self.mcp_url.startswith("http://") and not self.mcp_url.startswith("http://127.") and not self.mcp_url.startswith("http://localhost"):
            import warnings
            warnings.warn(
                f"MCP endpoint {self.mcp_url} uses plaintext HTTP on a non-loopback address. "
                "Auth tokens will be transmitted in cleartext. Use HTTPS in production.",
                stacklevel=2,
            )
            if os.environ.get("DCLAW_PRODUCTION"):
                raise ValueError(
                    f"Plaintext HTTP to non-loopback host {host} is not allowed in production. "
                    "Use HTTPS or set the URL to https://."
                )
        self._connector = connector or EdgeConnector(
            fail_open=False, tool_cap_map=BUBBALOOP_TOOL_CAP_MAP,
            session_id=session_id,
        )
        self._request_id = 0
        self._zenoh_session = None

    def call_tool(self, tool_name: str,
                  arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Evaluate then forward. Returns {allowed, verdict, result}."""
        arguments = arguments or {}
        verdict = self._connector.evaluate(
            tool_name=tool_name, arguments=arguments, destination=self.host,
        )
        if verdict.blocked:
            logger.warning("Bubbaloop tool %s blocked: %s", tool_name, verdict.reason)
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
            logger.error("Failed to list Bubbaloop tools: %s", exc)
            return []

    def subscribe_telemetry(self, topics: Optional[List[str]] = None,
                            callback: Optional[Callable] = None) -> None:
        """Subscribe to Bubbaloop's Zenoh telemetry (runs in background thread)."""
        topics = topics or DEFAULT_ZENOH_TOPICS
        try:
            import zenoh
        except ImportError:
            logger.warning("eclipse-zenoh not installed; telemetry unavailable")
            return
        cb = callback or (lambda t, p: logger.debug("Zenoh [%s]: %s", t, p[:200]))

        def _run():
            try:
                cfg = zenoh.Config()
                cfg.insert_json5("connect/endpoints",
                                 json.dumps([f"tcp/{self.host}:7447"]))
                session = zenoh.open(cfg)
                self._zenoh_session = session
                for topic in topics:
                    session.declare_subscriber(
                        topic, lambda s, t=topic: cb(t, bytes(s.payload)))
                logger.info("Zenoh subscribed to %d topics", len(topics))
                import time
                while self._zenoh_session is not None:
                    time.sleep(1.0)
            except Exception as exc:
                logger.error("Zenoh subscription failed: %s", exc)

        threading.Thread(target=_run, daemon=True, name="bubbaloop-zenoh").start()

    def close_telemetry(self) -> None:
        if self._zenoh_session:
            try:
                self._zenoh_session.close()
            except Exception:
                pass
            self._zenoh_session = None

    # -- internal ----------------------------------------------------------

    def _auth_headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"Content-Type": "application/json"}
        if self._auth_token:
            h["Authorization"] = f"Bearer {self._auth_token}"
        return h

    def _mcp_request(self, method: str, params: Dict[str, Any]) -> Any:
        import requests
        self._request_id += 1
        r = requests.post(self.mcp_url, timeout=self.timeout,
                          headers=self._auth_headers(), allow_redirects=False, json={
            "jsonrpc": "2.0", "id": self._request_id,
            "method": method, "params": params,
        })
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise RuntimeError(f"Bubbaloop MCP error: {data['error']}")
        return data.get("result", {})


def setup_bubbaloop(host: str = "localhost", port: int = 8088,
                    auth_token: Optional[str] = None,
                    enable_telemetry: bool = False,
                    connector: Optional[EdgeConnector] = None) -> BubbaloopAdapter:
    """Set up a Bubbaloop adapter with optional Zenoh telemetry."""
    adapter = BubbaloopAdapter(host=host, port=port, auth_token=auth_token,
                               connector=connector)
    if enable_telemetry:
        adapter.subscribe_telemetry()
    logger.info("Bubbaloop adapter ready: %s", adapter.mcp_url)
    return adapter
