#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""
DefenseClaw ↔ Muse Gadget SDK executor hook for Linux gadgets.

This module wraps Muse's command Executor so every link.invoke goes through
DefenseClaw's evaluation pipeline before the gadget runs it via the IPC
socket at /tmp/defenseclaw.sock (JSON-RPC over Unix stream).

The edge-connector process must be running alongside the Muse gadget
service. On ESP32, use the C bridge header (muse_bridge.h) directly
instead of this Python module.

Usage:
    from muse_executor_hook import DefenseClawMuseHook

    hook = DefenseClawMuseHook()
    # Before executing each link.invoke:
    verdict = hook.evaluate(command="system.run", params={"cmd": "ls -la"})
    if verdict["action"] == "block":
        return {"error": verdict["reason"]}
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
from typing import Any

logger = logging.getLogger("defenseclaw.muse")

DCLAW_SOCKET_PATH = os.environ.get(
    "DCLAW_IPC_SOCKET", "/tmp/defenseclaw.sock"
)

_IPC_MAX_RESPONSE_BYTES = 65536

COMMAND_CAPS = {
    "system.run": 0x04,      # DCLAW_CAP_EXEC_SHELL
    "file.read": 0x01,       # DCLAW_CAP_READ_FS
    "file.write": 0x02,      # DCLAW_CAP_WRITE_FS
    "device.health": 0x40,   # DCLAW_CAP_SENSOR_READ
}


def _compute_tool_hash(command: str, params: dict[str, Any]) -> bytes:
    """SHA-256 of the canonical command + params representation."""
    canonical = json.dumps({"command": command, "params": params}, sort_keys=True)
    return hashlib.sha256(canonical.encode()).digest()


def _truncate_utf8(text: str, max_bytes: int) -> bytes:
    """Truncate to at most max_bytes without splitting a UTF-8 character."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return encoded
    truncated = encoded[:max_bytes]
    return truncated.decode("utf-8", errors="ignore").encode("utf-8")


class DefenseClawMuseHook:
    """Evaluate Muse commands against DefenseClaw policy via IPC."""

    def __init__(self, session_id: int = 1) -> None:
        self._session_id = session_id
        self._request_counter = 0

    def evaluate(
        self,
        command: str,
        params: dict[str, Any] | None = None,
        content: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate a Muse link.invoke command.

        Returns a dict with at least {"action": "allow"|"block"|"warn"|"escalate"}.
        Unrecognized commands are blocked (fail-closed).
        """
        if params is None:
            params = {}

        caps = COMMAND_CAPS.get(command)
        if caps is None:
            logger.warning("Unrecognized Muse command %r, blocking (fail-closed)", command)
            return {"action": "block", "reason": "unrecognized_command"}

        tool_hash = _compute_tool_hash(command, params)

        return self._evaluate_ipc(command, tool_hash, caps, content)

    def _evaluate_ipc(
        self,
        command: str,
        tool_hash: bytes,
        caps: int,
        content: str | None,
    ) -> dict[str, Any]:
        self._request_counter += 1
        request: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": "evaluate",
            "params": {
                "tool_name": command,
                "tool_hash": tool_hash.hex(),
                "capabilities": caps,
                "session_id": self._session_id,
                "direction": 0,
            },
            "id": self._request_counter,
        }
        if content:
            request["params"]["content"] = _truncate_utf8(content, 511).decode("utf-8")

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.settimeout(5.0)
                sock.connect(DCLAW_SOCKET_PATH)
                payload = json.dumps(request).encode() + b"\n"
                sock.sendall(payload)

                response_data = b""
                while b"\n" not in response_data:
                    if len(response_data) >= _IPC_MAX_RESPONSE_BYTES:
                        raise OSError("IPC response exceeded size limit")
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
            finally:
                sock.close()

            response = json.loads(response_data.strip())
            result = response.get("result", {})
            return {
                "action": result.get("action", "block"),
                "reason": result.get("reason", 0),
                "severity": result.get("severity", 0),
                "cached": result.get("cached", False),
            }
        except (OSError, json.JSONDecodeError, KeyError) as e:
            fail_mode = os.environ.get("DEFENSECLAW_FAIL_MODE", "closed")
            if fail_mode == "open":
                logger.warning("IPC failed, fail-open: %s", e)
                return {"action": "allow", "reason": "ipc_unavailable"}
            logger.error("IPC failed, fail-closed: %s", e)
            return {"action": "block", "reason": "ipc_unavailable"}
