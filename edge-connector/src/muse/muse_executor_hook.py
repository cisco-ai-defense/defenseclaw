#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""
DefenseClaw ↔ Muse Gadget SDK executor hook for Linux gadgets.

This module wraps Muse's command Executor so every link.invoke goes through
DefenseClaw's evaluation pipeline before the gadget runs it. Two integration
paths are supported:

1. FFI (preferred): Load libdclaw_core.so via ctypes and call
   dclaw_evaluate() directly. Sub-microsecond latency, no IPC overhead.

2. IPC socket fallback: POST JSON-RPC to /tmp/defenseclaw.sock when the
   shared library is unavailable (e.g., edge-connector runs as a separate
   systemd service).

Usage:
    from muse_executor_hook import DefenseClawMuseHook

    hook = DefenseClawMuseHook()
    # Before executing each link.invoke:
    verdict = hook.evaluate(command="system.run", params={"cmd": "ls -la"})
    if verdict["action"] == "block":
        return {"error": verdict["reason"]}
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import socket
import struct
from pathlib import Path
from typing import Any

logger = logging.getLogger("defenseclaw.muse")

DCLAW_SOCKET_PATH = os.environ.get(
    "DCLAW_IPC_SOCKET", "/tmp/defenseclaw.sock"
)
DCLAW_LIB_PATHS = [
    "/usr/local/lib/libdclaw_core.so",
    "/usr/lib/libdclaw_core.so",
    str(Path(__file__).parent.parent.parent / "build" / "libdclaw_shared.so"),
]

COMMAND_CAPS = {
    "system.run": 0x04,      # DCLAW_CAP_EXEC_SHELL
    "file.read": 0x01,       # DCLAW_CAP_READ_FS
    "file.write": 0x02,      # DCLAW_CAP_WRITE_FS
    "device.health": 0x40,   # DCLAW_CAP_SENSOR_READ
}

ACTION_NAMES = {0: "allow", 1: "block", 2: "warn", 3: "escalate"}


class _ToolRequest(ctypes.Structure):
    """Mirrors dclaw_tool_request_t from defenseclaw.h."""

    _fields_ = [
        ("tool_name", ctypes.c_char * 64),
        ("tool_hash", ctypes.c_uint8 * 32),
        ("cap_flags", ctypes.c_uint8),
        ("destination", ctypes.c_char * 256),
        ("session_id", ctypes.c_uint16),
        ("direction", ctypes.c_uint8),
        ("content_scope", ctypes.c_uint8),
        ("content_buf", ctypes.c_char * 512),
        ("content", ctypes.c_char_p),
        ("content_len", ctypes.c_uint16),
        ("request_id", ctypes.c_int32),
    ]


class _Verdict(ctypes.Structure):
    """Mirrors dclaw_verdict_t from defenseclaw.h."""

    _fields_ = [
        ("action", ctypes.c_int),
        ("reason", ctypes.c_int),
        ("severity", ctypes.c_int),
        ("mode", ctypes.c_int),
        ("ttl_minutes", ctypes.c_uint16),
        ("from_cache", ctypes.c_bool),
    ]


def _compute_tool_hash(command: str, params: dict[str, Any]) -> bytes:
    """SHA-256 of the canonical command + params representation."""
    canonical = json.dumps({"command": command, "params": params}, sort_keys=True)
    return hashlib.sha256(canonical.encode()).digest()


class DefenseClawMuseHook:
    """Evaluate Muse commands against DefenseClaw policy."""

    def __init__(self, session_id: int = 1) -> None:
        self._session_id = session_id
        self._lib = self._try_load_ffi()
        self._request_counter = 0

    def _try_load_ffi(self) -> ctypes.CDLL | None:
        for lib_path in DCLAW_LIB_PATHS:
            if os.path.exists(lib_path):
                try:
                    lib = ctypes.CDLL(lib_path)
                    lib.dclaw_evaluate.argtypes = [ctypes.POINTER(_ToolRequest)]
                    lib.dclaw_evaluate.restype = _Verdict
                    logger.info("Loaded DefenseClaw FFI from %s", lib_path)
                    return lib
                except OSError as e:
                    logger.debug("Cannot load %s: %s", lib_path, e)
        logger.info("FFI unavailable, will use IPC socket at %s", DCLAW_SOCKET_PATH)
        return None

    def evaluate(
        self,
        command: str,
        params: dict[str, Any] | None = None,
        content: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate a Muse link.invoke command.

        Returns a dict with at least {"action": "allow"|"block"|"warn"|"escalate"}.
        """
        if params is None:
            params = {}

        caps = COMMAND_CAPS.get(command)
        if caps is None:
            return {"action": "allow", "reason": "unrecognized_command"}

        tool_hash = _compute_tool_hash(command, params)

        if self._lib is not None:
            return self._evaluate_ffi(command, tool_hash, caps, content)
        return self._evaluate_ipc(command, tool_hash, caps, content)

    def _evaluate_ffi(
        self,
        command: str,
        tool_hash: bytes,
        caps: int,
        content: str | None,
    ) -> dict[str, Any]:
        req = _ToolRequest()
        req.tool_name = command.encode()[:63]
        hash_array = (ctypes.c_uint8 * 32)(*tool_hash)
        ctypes.memmove(req.tool_hash, hash_array, 32)
        req.cap_flags = caps
        req.session_id = self._session_id
        req.direction = 0  # request
        req.content_scope = 2  # user_input

        if content:
            encoded = content.encode()[:511]
            req.content_buf = encoded
            req.content = ctypes.c_char_p(ctypes.addressof(req.content_buf))
            req.content_len = len(encoded)

        self._request_counter += 1
        req.request_id = self._request_counter

        verdict = self._lib.dclaw_evaluate(ctypes.byref(req))
        return {
            "action": ACTION_NAMES.get(verdict.action, "block"),
            "reason": verdict.reason,
            "severity": verdict.severity,
            "cached": verdict.from_cache,
        }

    def _evaluate_ipc(
        self,
        command: str,
        tool_hash: bytes,
        caps: int,
        content: str | None,
    ) -> dict[str, Any]:
        self._request_counter += 1
        request = {
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
            request["params"]["content"] = content[:511]

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(DCLAW_SOCKET_PATH)
            payload = json.dumps(request).encode() + b"\n"
            sock.sendall(payload)

            response_data = b""
            while b"\n" not in response_data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
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
