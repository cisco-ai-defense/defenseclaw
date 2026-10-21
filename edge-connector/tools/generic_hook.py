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

"""Generic Edge Connector adapter for any Python AI agent framework.

Usage:
    from generic_hook import EdgeConnector

    ec = EdgeConnector()  # daemon Unix socket; fails closed if unavailable

    # Before executing any tool call:
    verdict = ec.evaluate(
        tool_name="exec_shell",
        arguments={"command": "rm -rf /"},
        destination="",
    )

    if verdict.blocked:
        print(f"Blocked: {verdict.reason}")
    else:
        # proceed with tool execution
        ...

Environment variables:
    DCLAW_LIB_PATH    Path to libdclaw_core.so (default: /usr/local/lib/libdclaw_core.so)
    DCLAW_SOCKET_PATH Path to Unix socket (default: /run/defenseclaw/defenseclaw.sock)
    DCLAW_FAIL_OPEN   Set to "1" to allow tool calls when the engine is unavailable
                      (needs DCLAW_DEV_MODE=1 or a valid DCLAW_FAIL_OPEN_TOKEN)
    DCLAW_ALLOW_FFI   Set to "1" to permit the in-process engine (libdclaw_core)
                      when the daemon socket is missing or fails.  Off by
                      default: without it a daemon outage fails closed.  The
                      in-process engine must use its own DCLAW_FLASH_PATH; the
                      daemon holds an exclusive lock on its flash file.
    DCLAW_LOG_PATH    Audit log file (default: ~/edge-connector.log)
"""
from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import socket
import threading
import time
import warnings as _warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("defenseclaw")


_NETWORK_DESTINATION_KEYS = frozenset((
    "url", "href", "endpoint", "uri", "host", "destination",
    "target_url", "broker_url", "webhook_url",
))


def reviewed_adapter_destination(tool_name: str, arguments: dict[str, Any],
                                 cap_map: dict[str, int],
                                 http_url_fields: dict[str, str]) -> str:
    """Return a reviewed tool target, never the adapter's MCP transport host.

    Only the HTTP tools listed by an adapter have an unambiguous delegated
    target. Other network tools stay blocked until their argument schema and
    actual egress behavior can be reviewed. The C SSRF guard checks this value
    again; this early check also prevents a mocked/failed backend from
    forwarding an unsafe target.
    """
    if cap_map.get(tool_name) != CAP_NET_FETCH:
        return ""
    expected_key = http_url_fields.get(tool_name)
    if expected_key is None:
        raise ValueError("UNSUPPORTED_NETWORK_DESTINATION")
    if not isinstance(arguments, dict):
        raise ValueError("NETWORK_DESTINATION_REQUIRED")
    present = [key for key in _NETWORK_DESTINATION_KEYS if key in arguments]
    if present != [expected_key]:
        raise ValueError("NETWORK_DESTINATION_REQUIRED_OR_AMBIGUOUS")
    value = arguments[expected_key]
    if (not isinstance(value, str) or not value or value != value.strip()
            or len(value.encode("utf-8")) >= 128
            or "\\" in value or "\x00" in value):
        raise ValueError("INVALID_NETWORK_DESTINATION")
    parsed = urlparse(value)
    if (parsed.scheme not in ("http", "https") or not parsed.netloc
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("INVALID_NETWORK_DESTINATION")
    try:
        host = parsed.hostname
        port = parsed.port  # also rejects malformed/out-of-range ports
        address = ipaddress.ip_address(host or "")
    except ValueError:
        raise ValueError("PRIVATE_OR_UNRESOLVED_NETWORK_DESTINATION")
    if not address.is_global or port == 0:
        raise ValueError("PRIVATE_OR_UNRESOLVED_NETWORK_DESTINATION")
    if isinstance(address, ipaddress.IPv4Address) and host != str(address):
        raise ValueError("INVALID_NETWORK_DESTINATION")
    if isinstance(address, ipaddress.IPv6Address) and not parsed.netloc.startswith("["):
        raise ValueError("INVALID_NETWORK_DESTINATION")
    return value

# ---------------------------------------------------------------------------
# Fail-open attestation
# ---------------------------------------------------------------------------
_FAIL_OPEN_ENV = os.environ.get("DCLAW_FAIL_OPEN", "")
_FAIL_OPEN_TOKEN = os.environ.get("DCLAW_FAIL_OPEN_TOKEN", "")


def _is_fail_open_authorized() -> bool:
    """Check if fail-open mode is authorized with a valid attestation token."""
    if _FAIL_OPEN_ENV != "1":
        return False
    return fail_open_attested()


def fail_open_attested() -> bool:
    """Return True when fail-open is permitted on this host.

    Fail-open requires either DCLAW_DEV_MODE=1 or a DCLAW_FAIL_OPEN_TOKEN
    that verifies against DCLAW_AUDIT_KEY.  Every component that offers a
    fail-open switch (environment, config file) must pass this check
    before enabling it.
    """
    if os.environ.get("DCLAW_DEV_MODE") == "1":
        return True
    if not _FAIL_OPEN_TOKEN:
        logger.warning(
            "DCLAW_FAIL_OPEN=1 set but DCLAW_FAIL_OPEN_TOKEN missing — "
            "fail-open mode DENIED in production. Set DCLAW_DEV_MODE=1 "
            "or provide a valid attestation token."
        )
        return False
    audit_key = os.environ.get("DCLAW_AUDIT_KEY", "")
    if not audit_key:
        logger.warning(
            "DCLAW_FAIL_OPEN_TOKEN set but DCLAW_AUDIT_KEY missing — "
            "cannot verify attestation token, fail-open DENIED."
        )
        return False
    import hmac as _hmac
    expected = _hmac.new(
        bytes.fromhex(audit_key), b"fail-open-authorized", hashlib.sha256
    ).hexdigest()
    if not _hmac.compare_digest(_FAIL_OPEN_TOKEN, expected):
        logger.warning("DCLAW_FAIL_OPEN_TOKEN verification failed — fail-open DENIED.")
        return False
    return True


def _destination_host(url: str) -> str:
    """Return the host of *url* in the form the C destination guard expects.

    ``urlparse().hostname`` drops the brackets around an IPv6 literal; the
    engine only recognises bracketed IPv6 destinations, so put them back.
    """
    host = urlparse(url).hostname or ""
    if ":" in host:
        return f"[{host}]"
    return host


def _json_escaped_len(ch: str) -> int:
    """Length of *ch* inside a JSON string as produced by json.dumps()."""
    if ch in _TWO_CHAR_ESCAPES:
        return 2
    o = ord(ch)
    if o < 0x20 or 0x7F <= o <= 0xFFFF:
        return 6   # \uXXXX
    if o < 0x80:
        return 1
    return 12  # astral plane: surrogate pair, two \uXXXX escapes


_TWO_CHAR_ESCAPES = frozenset('"\\\b\f\n\r\t')


def production_flag_set(raw: str | None) -> bool:
    """Parse a DCLAW_PRODUCTION value the way the Go fleet does.

    Mirrors ``productionFlagSet`` in internal/fleet/mqtt/bridge.go: the
    value is trimmed and lowercased, and anything other than "", "0",
    "false", "no" or "off" means production.
    """
    value = (raw or "").strip().lower()
    return value not in ("", "0", "false", "no", "off")


def is_production() -> bool:
    """Return True when DCLAW_PRODUCTION selects production mode."""
    return production_flag_set(os.environ.get("DCLAW_PRODUCTION"))


def check_http_production(url: str, context: str = "adapter") -> None:
    """Warn when a non-loopback URL uses plain HTTP in production.

    External endpoints MUST use HTTPS when DCLAW_PRODUCTION is set.
    Loopback addresses (127.0.0.1, localhost, ::1) are exempt since
    they never leave the device.
    """
    if not is_production():
        return
    if not url.startswith("http://"):
        return
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return
    if host in ("127.0.0.1", "localhost", "::1", "[::1]"):
        return
    _warnings.warn(
        f"[DefenseClaw] {context} uses plain HTTP for non-loopback "
        f"endpoint '{url}'. Use HTTPS in production (DCLAW_PRODUCTION is set).",
        stacklevel=2,
    )

# ---------------------------------------------------------------------------
# Capability flags (must match defenseclaw.h)
# ---------------------------------------------------------------------------
CAP_READ_FS = 0x01
CAP_WRITE_FS = 0x02
CAP_EXEC_SHELL = 0x04
CAP_NET_FETCH = 0x08
CAP_SEND_MSG = 0x10
CAP_ACTUATE = 0x20
CAP_SENSOR_READ = 0x40

# Action codes
ACTION_ALLOW = 0
ACTION_BLOCK = 1
ACTION_WARN = 2
ACTION_ESCALATE = 3

# Only these actions let a call proceed.  Every other value, including
# ESCALATE and codes added by a newer engine, is treated as a denial.
_PERMIT_ACTIONS = frozenset((ACTION_ALLOW, ACTION_WARN))


def action_permits(action: Any) -> bool:
    """Return True only for ALLOW and WARN; anything else must deny."""
    return (isinstance(action, int) and not isinstance(action, bool)
            and action in _PERMIT_ACTIONS)

REASON_NAMES = {
    0x01: "POLICY_TABLE",
    0x02: "CAP_SEQUENCE",
    0x03: "DEST_DENY",
    0x04: "HASH_DENY",
    0x05: "RATE_LIMIT",
    0x06: "CLOUD_BLOCK",
    0x07: "CLOUD_TIMEOUT",
    0x08: "PII_DETECTED",
    0x09: "BLOOM_HIT",
    0x0A: "INVALID_INPUT",
    0x0B: "RETROACTIVE",
    0x0C: "CONTENT_BLOCK",
    0x0D: "SSRF_BLOCK",
    0x0E: "HASH_MISMATCH",
}

# ---------------------------------------------------------------------------
# Default tool-name -> capability mapping
# ---------------------------------------------------------------------------
DEFAULT_TOOL_CAP_MAP: dict[str, int] = {
    # Shell / code execution
    "exec": CAP_EXEC_SHELL,
    "shell": CAP_EXEC_SHELL,
    "bash": CAP_EXEC_SHELL,
    "run_command": CAP_EXEC_SHELL,
    "exec_shell": CAP_EXEC_SHELL,
    "execute_code": CAP_EXEC_SHELL,
    "run_python": CAP_EXEC_SHELL,
    "terminal": CAP_EXEC_SHELL,
    # Filesystem write
    "write_file": CAP_WRITE_FS,
    "save": CAP_WRITE_FS,
    "create_file": CAP_WRITE_FS,
    "delete_file": CAP_WRITE_FS,
    "edit_file": CAP_WRITE_FS,
    # Filesystem read
    "read_file": CAP_READ_FS,
    "cat": CAP_READ_FS,
    "list_files": CAP_READ_FS,
    "list_dir": CAP_READ_FS,
    # Network
    "web_search": CAP_NET_FETCH,
    "web_fetch": CAP_NET_FETCH,
    "fetch_url": CAP_NET_FETCH,
    "fetch": CAP_NET_FETCH,
    "http_request": CAP_NET_FETCH,
    "call_api": CAP_NET_FETCH,
    "requests_get": CAP_NET_FETCH,
    "requests_post": CAP_NET_FETCH,
    # Messaging
    "send_message": CAP_SEND_MSG,
    "send_email": CAP_SEND_MSG,
    "notify": CAP_SEND_MSG,
    # Sensors (read-only, safe)
    "get_sensors": CAP_SENSOR_READ,
    "battery_status": CAP_SENSOR_READ,
    "scan_surroundings": CAP_SENSOR_READ,
    # Actuations (physical world)
    "drive": CAP_ACTUATE,
    "start_motor": CAP_ACTUATE,
    "actuate": CAP_ACTUATE,
}

# Keywords that signal a dangerous tool when not in the map
_DANGEROUS_KEYWORDS = ("exec", "shell", "bash", "run", "write", "delete", "rm")


def normalize_tool_name(raw_tool: str) -> str:
    """Strip MCP server prefix from tool names to get canonical form.

    MCP proxies and frameworks (PicoClaw, generic MCP hosts) often prefix
    tool names with ``mcp_<server>_``.  For example:
        mcp_roboclaw_drive        -> drive
        mcp_vision-ai_battery_status -> battery_status
        plain_tool                -> plain_tool

    This normalization ensures consistent capability lookups regardless of
    the MCP server prefix.
    """
    if raw_tool.startswith("mcp_"):
        parts = raw_tool.split("_", 2)  # ['mcp', 'server', 'tool_name']
        if len(parts) >= 3:
            return parts[2]
        elif len(parts) == 2:
            return parts[1]
    return raw_tool


# ---------------------------------------------------------------------------
# Verdict dataclass
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Verdict:
    """Result of an Edge Connector policy evaluation."""

    action: int  # 0=ALLOW, 1=BLOCK, 2=WARN
    blocked: bool
    reason: str
    severity: int
    cached: bool

    @staticmethod
    def from_raw(action: int, reason_code: int, severity: int = 0,
                 cached: bool = False) -> Verdict:
        return Verdict(
            action=action,
            blocked=not action_permits(action),
            reason=REASON_NAMES.get(reason_code, f"UNKNOWN(0x{reason_code:02x})"),
            severity=severity,
            cached=cached,
        )

    @staticmethod
    def allow(*, cached: bool = False) -> Verdict:
        return Verdict(action=ACTION_ALLOW, blocked=False, reason="ALLOW",
                       severity=0, cached=cached)

    @staticmethod
    def error(reason: str) -> Verdict:
        return Verdict(action=ACTION_BLOCK, blocked=True, reason=reason,
                       severity=0, cached=False)


# ---------------------------------------------------------------------------
# ctypes structures (mirror defenseclaw.h)
# ---------------------------------------------------------------------------
class _DclawToolRequest(ctypes.Structure):
    _fields_ = [
        ("tool_name", ctypes.c_char * 64),       # DCLAW_TOOL_NAME_MAX
        ("tool_hash", ctypes.c_uint8 * 32),
        ("cap_flags", ctypes.c_uint8),
        ("destination", ctypes.c_char * 128),     # DCLAW_DESTINATION_MAX
        ("session_id", ctypes.c_uint16),
        ("direction", ctypes.c_uint8),
        ("content_scope", ctypes.c_uint8),
        ("content_buf", ctypes.c_char * 4096),    # Must match DCLAW_CONTENT_MAX
        ("content", ctypes.c_char_p),
        ("content_len", ctypes.c_uint16),
        ("request_id", ctypes.c_int32),
        ("flags", ctypes.c_uint8),                # DCLAW_FLAG_* bitmask
    ]


class _DclawVerdict(ctypes.Structure):
    _fields_ = [
        ("action", ctypes.c_int),
        ("reason", ctypes.c_int),
        ("severity", ctypes.c_int),
        ("mode", ctypes.c_int),
        ("ttl_minutes", ctypes.c_uint16),
        ("from_cache", ctypes.c_bool),
    ]


class _DclawDeviceInfo(ctypes.Structure):
    _fields_ = [
        ("tenant_id", ctypes.c_uint16),
        ("fleet_id", ctypes.c_uint16),
        ("device_id", ctypes.c_uint32),
        ("policy_version", ctypes.c_uint16),
        ("fw_version", ctypes.c_uint16),
        ("hw_profile", ctypes.c_uint8),
        ("capabilities", ctypes.c_uint8),
    ]


# ---------------------------------------------------------------------------
# Backend: FFI (ctypes)
# ---------------------------------------------------------------------------
class _FFIBackend:
    """Calls dclaw_evaluate() directly via ctypes."""

    def __init__(self, lib_path: str):
        self._lib = ctypes.CDLL(lib_path)
        self._lib.dclaw_init.argtypes = [ctypes.POINTER(_DclawDeviceInfo)]
        self._lib.dclaw_init.restype = ctypes.c_int
        self._lib.dclaw_evaluate.argtypes = [ctypes.POINTER(_DclawToolRequest)]
        self._lib.dclaw_evaluate.restype = _DclawVerdict
        self._lib.dclaw_shutdown.argtypes = []
        self._lib.dclaw_shutdown.restype = None

        info = _DclawDeviceInfo(
            tenant_id=int(os.environ.get("DCLAW_TENANT_ID", "1")),
            fleet_id=int(os.environ.get("DCLAW_FLEET_ID", "1")),
            device_id=int(os.environ.get("DCLAW_DEVICE_ID", "1")),
            policy_version=int(os.environ.get("DCLAW_POLICY_VERSION", "0")),
            fw_version=int(os.environ.get("DCLAW_FW_VERSION", "1")),
            hw_profile=int(os.environ.get("DCLAW_HW_PROFILE", "2")),
            capabilities=int(os.environ.get("DCLAW_CAPABILITIES", "0xFF"), 0),
        )
        rc = self._lib.dclaw_init(ctypes.byref(info))
        if rc != 0:
            raise RuntimeError(f"dclaw_init failed: {rc}")

    def evaluate(self, tool_name: str, cap_flags: int,
                 destination: str, session_id: int,
                 content: str | None, direction: int) -> Verdict:
        req = _DclawToolRequest()
        req.tool_name = tool_name.encode("ascii", errors="replace")[:63]
        h = hashlib.sha256(tool_name.encode()).digest()
        for i in range(32):
            req.tool_hash[i] = h[i]
        req.cap_flags = cap_flags
        req.destination = destination.encode("ascii", errors="replace")[:127]
        req.session_id = session_id
        req.direction = direction
        req.content_scope = 0
        if content:
            encoded = content.encode("utf-8", errors="replace")[:4095]
            req.content = encoded
            req.content_len = len(encoded)
        else:
            req.content = None
            req.content_len = 0

        v = self._lib.dclaw_evaluate(ctypes.byref(req))
        return Verdict.from_raw(v.action, v.reason, v.severity, v.from_cache)

    def shutdown(self) -> None:
        self._lib.dclaw_shutdown()


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------
_ACTION_STRING_MAP = {
    "allow": ACTION_ALLOW,
    "block": ACTION_BLOCK,
    "warn": ACTION_WARN,
}


def _parse_action(raw: Any) -> int:
    """Convert a daemon action value to an int.

    The daemon may return the action as a numeric code (0, 1, 2) or as a
    lowercase string ("allow", "block", "warn").  Accept both to avoid
    breakage when the IPC schema evolves.
    """
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        return _ACTION_STRING_MAP.get(raw.lower(), ACTION_BLOCK)
    return ACTION_BLOCK


# ---------------------------------------------------------------------------
# Backend: Unix socket (JSON-RPC)
# ---------------------------------------------------------------------------
class _SocketBackend:
    """Sends evaluate requests over the Edge Connector Unix socket."""

    def __init__(self, socket_path: str):
        self._path = socket_path

    def evaluate(self, tool_name: str, cap_flags: int,
                 destination: str, session_id: int,
                 content: str | None, direction: int) -> Verdict:
        request_id = secrets.randbelow(2**31)
        # Compute a deterministic SHA-256 tool hash (64 hex chars) so the
        # daemon's ipc_json.c handler can look up the tool in its verdict
        # cache.  Callers that already carry a hash can extend this later;
        # for now we derive one from the canonical tool name.
        tool_hash = hashlib.sha256(tool_name.encode()).hexdigest()
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "evaluate",
            "params": {
                "tool_name": tool_name,
                "tool_hash": tool_hash,
                "capabilities": cap_flags,
                "destination": destination,
                "session_id": session_id,
                "direction": direction,
            },
        }
        if content:
            payload["params"]["content"] = content

        MAX_RESPONSE_SIZE = 4096
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(2.0)
            sock.connect(self._path)
            sock.sendall(json.dumps(payload).encode() + b"\n")
            data = b""
            while b"\n" not in data:
                if len(data) >= MAX_RESPONSE_SIZE:
                    raise RuntimeError("response exceeds MAX_RESPONSE_SIZE")
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            sock.close()

        resp = json.loads(data.decode())
        if "error" in resp:
            return Verdict.error(resp["error"].get("message", "RPC_ERROR"))
        r = resp.get("result", {})
        return Verdict.from_raw(
            _parse_action(r.get("action", ACTION_BLOCK)),
            r.get("reason", 0),
            r.get("severity", 0),
            r.get("from_cache", False),
        )

    def shutdown(self) -> None:
        pass


# ---------------------------------------------------------------------------
# EdgeConnector: the public API
# ---------------------------------------------------------------------------
class EdgeConnector:
    """Framework-agnostic Edge Connector client.

    Uses IPC (Unix socket to the daemon), since the daemon is the policy
    authority and applies OTA updates, revocations and emergency lockdown.

    The in-process FFI engine is a separate engine instance with its own
    cache, rate buckets and revocation state, so it is never used silently.
    It is only used when explicitly enabled with ``allow_ffi=True`` or
    ``DCLAW_ALLOW_FFI=1``; then it serves when no daemon socket exists and
    as a fallback when the socket fails.  Otherwise a missing or failing
    daemon makes every call fail closed (or fail open, if attested).
    Set ``fail_open=True`` to allow tool calls when no backend is available.
    """

    def __init__(
        self,
        lib_path: str | None = None,
        socket_path: str | None = None,
        fail_open: bool | None = None,
        tool_cap_map: dict[str, int] | None = None,
        session_id: int = 1,
        allow_ffi: bool | None = None,
    ):
        self._lib_path = lib_path or os.environ.get(
            "DCLAW_LIB_PATH", "/usr/local/lib/libdclaw_core.so"
        )
        self._socket_path = socket_path or os.environ.get(
            "DCLAW_SOCKET_PATH", "/run/defenseclaw/defenseclaw.sock"
        )
        # Using "is not None" (not truthiness) so fail_open=False explicitly
        # disables fail-open, while None falls through to the env var check.
        if fail_open is not None:
            self._fail_open = fail_open
        else:
            self._fail_open = _is_fail_open_authorized()

        if allow_ffi is not None:
            self._allow_ffi = allow_ffi
        else:
            self._allow_ffi = os.environ.get("DCLAW_ALLOW_FFI") == "1"

        self.tool_cap_map: dict[str, int] = dict(DEFAULT_TOOL_CAP_MAP)
        if tool_cap_map:
            self.tool_cap_map.update(tool_cap_map)

        self._session_id = session_id
        self._backend_lock = threading.Lock()
        self._fail_open_count = 0
        self._fail_open_start = None
        self._FAIL_OPEN_MAX_DURATION = 300  # 5 minutes max
        self._FAIL_OPEN_MAX_COUNT = 1000  # max 1000 allows
        self._backend = self._connect()

    @property
    def fail_open(self) -> bool:
        """Public accessor for the fail-open mode setting."""
        return self._fail_open

    # -- connection --------------------------------------------------------

    def _open_ffi(self) -> _FFIBackend:
        """Start the in-process engine (only called when explicitly allowed)."""
        try:
            backend = _FFIBackend(self._lib_path)
        except RuntimeError as exc:
            raise RuntimeError(
                f"{exc} (the in-process engine needs its own DCLAW_FLASH_PATH; "
                f"it cannot share the daemon's flash file)"
            ) from exc
        logger.warning(
            "SECURITY: EdgeConnector using the in-process engine (%s); it does "
            "not share the daemon's revocations, cache or OTA policy",
            self._lib_path,
        )
        return backend

    def _connect(self) -> _FFIBackend | _SocketBackend | None:
        # The daemon socket is the policy authority.
        if Path(self._socket_path).exists():
            logger.info(
                "EdgeConnector: using IPC socket (%s) — daemon is policy authority",
                self._socket_path,
            )
            return _SocketBackend(self._socket_path)

        if self._allow_ffi:
            try:
                return self._open_ffi()
            except (OSError, RuntimeError) as exc:
                logger.error("EdgeConnector: in-process engine unavailable (%s)", exc)

        if self._fail_open:
            logger.warning("EdgeConnector: no backend available — running in fail-open mode")
            return None
        hint = "" if self._allow_ffi else (
            " The in-process engine is disabled (set DCLAW_ALLOW_FFI=1 to permit it)."
        )
        raise ConnectionError(
            f"EdgeConnector: daemon socket {self._socket_path} not found.{hint}"
        )

    # -- backend liveness check -------------------------------------------

    def _check_backend(self) -> None:
        """Re-evaluate the active backend before every evaluate() call.

        * If currently using FFI, check whether the daemon IPC socket has
          appeared since construction — if so, switch to IPC (the daemon is
          the policy authority and receives OTA updates).
        * If currently using IPC and the in-process engine is explicitly
          allowed, verify the socket is still alive with a quick connect
          test — if the daemon has gone away, switch to FFI.  Without the
          opt-in the socket backend is kept and calls fail closed.
        * For FFI specifically: check whether the flash policy version has
          changed since the last evaluate (indicating an OTA was applied
          externally).  If so, call ``dclaw_policy_reload_from_flash()`` so
          the in-process policy tables pick up the new version.
        """
        with self._backend_lock:
            if self._backend is None:
                # Fail-open with no engine: pick up the daemon once it appears.
                if Path(self._socket_path).exists():
                    self._backend = _SocketBackend(self._socket_path)
                return

            if isinstance(self._backend, _FFIBackend):
                # Daemon may have started since we connected — prefer IPC.
                if Path(self._socket_path).exists():
                    try:
                        test_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        test_sock.settimeout(0.5)
                        test_sock.connect(self._socket_path)
                        test_sock.close()
                        # Socket is alive — switch to IPC.
                        logger.info(
                            "EdgeConnector: daemon socket appeared at %s — "
                            "switching from FFI to IPC",
                            self._socket_path,
                        )
                        old = self._backend
                        self._backend = _SocketBackend(self._socket_path)
                        old.shutdown()
                        return
                    except OSError:
                        pass  # Socket file exists but daemon not responding; stay on FFI.

                # Still on FFI — check if the flash policy version changed (OTA
                # applied by an external process).  Reload if necessary.
                try:
                    lib = self._backend._lib
                    if not hasattr(self, "_last_policy_version"):
                        # Bind the helper on first use.
                        try:
                            lib.dclaw_policy_reload_from_flash.argtypes = []
                            lib.dclaw_policy_reload_from_flash.restype = ctypes.c_int
                            lib.dclaw_get_state.argtypes = []
                            lib.dclaw_get_state.restype = ctypes.c_void_p
                        except AttributeError:
                            pass
                        self._last_policy_version = -1

                    # Cast via _DclawDeviceInfo struct to avoid fragile raw pointer arithmetic.
                    state_ptr = lib.dclaw_get_state()
                    if state_ptr:
                        info_ptr = ctypes.cast(
                            state_ptr,
                            ctypes.POINTER(_DclawDeviceInfo),
                        )
                        pv = info_ptr.contents.policy_version
                        if self._last_policy_version >= 0 and pv != self._last_policy_version:
                            logger.info(
                                "EdgeConnector: flash policy version changed (%d -> %d) — reloading",
                                self._last_policy_version, pv,
                            )
                            lib.dclaw_policy_reload_from_flash()
                        self._last_policy_version = pv
                except Exception as exc:
                    logger.debug("EdgeConnector: FFI policy version check failed: %s", exc)

            elif isinstance(self._backend, _SocketBackend) and self._allow_ffi:
                # Verify the daemon socket is still alive.  Only relevant when
                # the in-process engine is permitted; otherwise a dead socket
                # simply makes evaluate() fail closed.
                alive = False
                try:
                    test_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    test_sock.settimeout(0.5)
                    test_sock.connect(self._socket_path)
                    test_sock.close()
                    alive = True
                except OSError:
                    pass
                if not alive:
                    logger.warning(
                        "EdgeConnector: daemon socket at %s is dead — "
                        "switching to the in-process engine (DCLAW_ALLOW_FFI=1)",
                        self._socket_path,
                    )
                    try:
                        self._backend = self._open_ffi()
                    except (OSError, RuntimeError) as exc:
                        logger.error("EdgeConnector: in-process engine unavailable (%s)", exc)

    # -- fail-open accounting -----------------------------------------------

    def _fail_open_verdict(self, tool_name: str) -> Verdict:
        """Return a fail-open allow verdict with auditing and limits.

        Tracks how long fail-open mode has been active and how many calls
        have been allowed.  If either limit is exceeded, switches to
        fail-closed and blocks the call.

        All counter updates are performed under _backend_lock to prevent
        data races from concurrent evaluate() calls.
        """
        with self._backend_lock:
            if self._fail_open_start is None:
                self._fail_open_start = time.monotonic()
                logger.warning("SECURITY: fail-open mode activated, tool calls will be allowed without policy check")

            elapsed = time.monotonic() - self._fail_open_start
            self._fail_open_count += 1

            if elapsed > self._FAIL_OPEN_MAX_DURATION or self._fail_open_count > self._FAIL_OPEN_MAX_COUNT:
                logger.error("SECURITY: fail-open limit exceeded (%.0fs, %d calls), switching to fail-closed",
                             elapsed, self._fail_open_count)
                return Verdict(action=ACTION_BLOCK, blocked=True, reason="FAIL_OPEN_LIMIT_EXCEEDED",
                               severity=0, cached=False)

            logger.warning("SECURITY: fail-open allow #%d (%.0fs elapsed) tool=%s",
                           self._fail_open_count, elapsed, tool_name)
            return Verdict(action=ACTION_ALLOW, blocked=False, reason="FAIL_OPEN",
                           severity=0, cached=False)

    # -- public API --------------------------------------------------------

    def evaluate(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        destination: str = "",
        content: str | None = None,
        direction: str = "request",
        session_id: int | None = None,
    ) -> Verdict:
        """Evaluate a tool call against the Edge Connector policy.

        Args:
            tool_name: Name of the tool being invoked.
            arguments: Tool call arguments (used to extract destination and
                       serialized as content if *content* is not provided).
            destination: Explicit network destination (host or URL).
            content: Text payload for content scanning. If not provided and
                     *arguments* is given, arguments are JSON-serialized.
            direction: ``"request"`` (tool call) or ``"response"`` (tool output).
            session_id: Session to evaluate in (defaults to the connector's).

        Returns:
            A :class:`Verdict` with ``blocked``, ``reason``, etc.
        """
        self._check_backend()

        # Normalize tool name to strip MCP server prefixes (e.g.
        # mcp_roboclaw_drive -> drive) so capability lookups are
        # consistent with picoclaw_hook.py.
        tool_name = normalize_tool_name(tool_name)

        with self._backend_lock:
            backend = self._backend
        if backend is None:
            if self._fail_open:
                return self._fail_open_verdict(tool_name)
            return Verdict.error("NO_BACKEND")

        cap_flags = self._resolve_capability(tool_name)
        dest = destination or self._extract_destination(tool_name, arguments or {})
        dir_code = 0 if direction == "request" else 1

        if content is None and arguments:
            content = json.dumps(arguments, default=str)

        try:
            return self._evaluate_chunked(
                tool_name=tool_name,
                cap_flags=cap_flags,
                destination=dest,
                content=content,
                direction=dir_code,
                session_id=session_id,
            )
        except (ConnectionError, OSError, RuntimeError) as exc:
            # Socket may vanish between _check_backend() and evaluate() (TOCTOU);
            # backend switches happen under _backend_lock to prevent double-free.
            # Without an explicit opt-in the call fails closed below.
            if isinstance(self._backend, _SocketBackend) and self._allow_ffi:
                logger.warning(
                    "EdgeConnector: socket evaluate failed (%s) — falling back "
                    "to the in-process engine (DCLAW_ALLOW_FFI=1)",
                    exc,
                )
                try:
                    ffi_backend = self._open_ffi()
                    with self._backend_lock:
                        self._backend = ffi_backend
                    return self._evaluate_chunked(
                        tool_name=tool_name,
                        cap_flags=cap_flags,
                        destination=dest,
                        content=content,
                        direction=dir_code,
                        session_id=session_id,
                    )
                except (OSError, RuntimeError) as ffi_exc:
                    logger.error("EdgeConnector: FFI fallback also failed: %s", ffi_exc)
                    if self._fail_open:
                        return self._fail_open_verdict(tool_name)
                    return Verdict.error(f"ENGINE_ERROR: {ffi_exc}")
            logger.error("EdgeConnector: evaluate failed: %s", exc)
            if self._fail_open:
                return self._fail_open_verdict(tool_name)
            return Verdict.error(f"ENGINE_ERROR: {exc}")
        except Exception as exc:
            logger.error("EdgeConnector: evaluate failed: %s", exc)
            if self._fail_open:
                return self._fail_open_verdict(tool_name)
            return Verdict.error(f"ENGINE_ERROR: {exc}")

    # Maximum content length per call, measured as the JSON-escaped string
    # the socket backend sends (json.dumps, ensure_ascii).  The daemon
    # flags content as truncated -- and blocks it -- when the escaped
    # string exceeds DCLAW_CONTENT_MAX - 1 (4095) or the unescaped text
    # exceeds DCLAW_CONTENT_MAX - 4 (4092) bytes.  The unescaped UTF-8 length
    # never exceeds the escaped length, so 4092 escaped characters satisfies
    # both limits and also fits the FFI backend's 4095-byte buffer.
    _CONTENT_ESCAPED_MAX = 4092
    # Overlap (in characters) between consecutive content windows so
    # patterns that span a window boundary are still caught.  256 covers
    # the longest pattern the scanner might detect (e.g. base64-encoded
    # secrets, multi-field PII, long credential strings).
    _CONTENT_OVERLAP = 256

    @classmethod
    def _content_windows(cls, content: str) -> list[str]:
        """Split *content* into overlapping windows that each stay within
        :attr:`_CONTENT_ESCAPED_MAX` once JSON-escaped.

        Windows are cut on character boundaries, so multi-byte characters
        are never split.
        """
        costs = [_json_escaped_len(ch) for ch in content]
        windows: list[str] = []
        start = 0
        n = len(content)
        while start < n:
            end = start
            used = 0
            while end < n and used + costs[end] <= cls._CONTENT_ESCAPED_MAX:
                used += costs[end]
                end += 1
            windows.append(content[start:end])
            if end >= n:
                break
            overlap = min(cls._CONTENT_OVERLAP, (end - start) // 2)
            start = end - overlap
        return windows

    def _evaluate_chunked(
        self,
        tool_name: str,
        cap_flags: int,
        destination: str,
        content: str | None,
        direction: int,
        session_id: int | None = None,
    ) -> Verdict:
        """Evaluate content in overlapping windows when it exceeds the
        daemon's content limit after JSON escaping, ensuring patterns near
        window boundaries are still scanned.

        Any verdict that does not permit the call (BLOCK, ESCALATE or an
        unknown action) stops the loop and is returned; WARN verdicts are
        remembered and returned after all chunks so warnings are never
        silently discarded.
        """
        sid = self._session_id if session_id is None else session_id
        # Short-circuit: content fits in a single buffer — no chunking.
        if not content or len(json.dumps(content)) - 2 <= self._CONTENT_ESCAPED_MAX:
            return self._backend.evaluate(
                tool_name=tool_name,
                cap_flags=cap_flags,
                destination=destination,
                session_id=sid,
                content=content,
                direction=direction,
            )

        worst_verdict: Verdict | None = None
        for chunk_str in self._content_windows(content):
            verdict = self._backend.evaluate(
                tool_name=tool_name,
                cap_flags=cap_flags,
                destination=destination,
                session_id=sid,
                content=chunk_str,
                direction=direction,
            )
            # Anything other than ALLOW/WARN denies — return immediately.
            if verdict.blocked or not action_permits(verdict.action):
                return verdict
            # WARN — remember the first (or worst) warning and keep scanning.
            if verdict.action == ACTION_WARN:
                if worst_verdict is None or worst_verdict.action == ACTION_ALLOW:
                    worst_verdict = verdict

        # Return the worst verdict seen (WARN if any chunk warned, else ALLOW).
        if worst_verdict is not None:
            return worst_verdict
        return Verdict.allow()

    def shutdown(self) -> None:
        """Release resources held by the backend."""
        if self._backend is not None:
            self._backend.shutdown()
            self._backend = None

    # -- helpers -----------------------------------------------------------

    def _resolve_capability(self, tool_name: str) -> int:
        """Map a tool name to its capability flag."""
        cap = self.tool_cap_map.get(tool_name)
        if cap is not None:
            return cap
        # Unknown tools default to EXEC_SHELL (fail-closed) to match the
        # C daemon. Only downgrade to SENSOR_READ for known safe prefixes.
        _SAFE_PREFIXES = ("get_", "list_", "check_", "read_", "scan_", "status")
        if any(tool_name.startswith(p) for p in _SAFE_PREFIXES):
            return CAP_SENSOR_READ
        return CAP_EXEC_SHELL

    @staticmethod
    def _extract_destination(tool_name: str, arguments: dict[str, Any]) -> str:
        """Pull a network destination from tool arguments when applicable."""
        for key in ("url", "href", "endpoint", "uri"):
            val = arguments.get(key, "")
            if val and "://" in str(val):
                # Reject backslash URLs to prevent authority-component bypass attacks
                if '\\' in str(val):
                    raise ValueError(f"URL contains backslash (potential authority bypass): {val}")
                try:
                    return _destination_host(str(val))
                except Exception:
                    pass
        return ""
