"""Generic Edge Connector adapter for any Python AI agent framework.

Usage:
    from generic_hook import EdgeConnector

    ec = EdgeConnector()  # auto-detects FFI or Unix socket

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
    DCLAW_LOG_PATH    Audit log file (default: ~/edge-connector.log)
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import secrets
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
import warnings as _warnings
from urllib.parse import urlparse

logger = logging.getLogger("defenseclaw")


def check_http_production(url: str, context: str = "adapter") -> None:
    """M-4 fix: Warn when a non-loopback URL uses plain HTTP in production.

    External endpoints MUST use HTTPS when DCLAW_PRODUCTION is set.
    Loopback addresses (127.0.0.1, localhost, ::1) are exempt since
    they never leave the device.
    """
    if not os.environ.get("DCLAW_PRODUCTION"):
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
        f"[DefenseClaw] M-4: {context} uses plain HTTP for non-loopback "
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
}

# ---------------------------------------------------------------------------
# Default tool-name -> capability mapping
# ---------------------------------------------------------------------------
DEFAULT_TOOL_CAP_MAP: Dict[str, int] = {
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
                 cached: bool = False) -> "Verdict":
        return Verdict(
            action=action,
            blocked=(action == ACTION_BLOCK),
            reason=REASON_NAMES.get(reason_code, f"UNKNOWN(0x{reason_code:02x})"),
            severity=severity,
            cached=cached,
        )

    @staticmethod
    def allow(*, cached: bool = False) -> "Verdict":
        return Verdict(action=ACTION_ALLOW, blocked=False, reason="ALLOW",
                       severity=0, cached=cached)

    @staticmethod
    def error(reason: str) -> "Verdict":
        return Verdict(action=ACTION_BLOCK, blocked=True, reason=reason,
                       severity=0, cached=False)


# ---------------------------------------------------------------------------
# ctypes structures (mirror defenseclaw.h)
# ---------------------------------------------------------------------------
class _DclawToolRequest(ctypes.Structure):
    _fields_ = [
        ("tool_name", ctypes.c_char * 64),
        ("tool_hash", ctypes.c_uint8 * 32),
        ("cap_flags", ctypes.c_uint8),
        ("destination", ctypes.c_char * 128),
        ("session_id", ctypes.c_uint16),
        ("direction", ctypes.c_uint8),
        ("content_scope", ctypes.c_uint8),
        ("content_buf", ctypes.c_char * 512),
        ("content", ctypes.c_char_p),
        ("content_len", ctypes.c_uint16),
        ("request_id", ctypes.c_int32),
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
            policy_version=int(os.environ.get("DCLAW_POLICY_VERSION", "1")),
            fw_version=int(os.environ.get("DCLAW_FW_VERSION", "1")),
            hw_profile=int(os.environ.get("DCLAW_HW_PROFILE", "2")),
            capabilities=int(os.environ.get("DCLAW_CAPABILITIES", "0xFF"), 0),
        )
        rc = self._lib.dclaw_init(ctypes.byref(info))
        if rc != 0:
            raise RuntimeError(f"dclaw_init failed: {rc}")

    def evaluate(self, tool_name: str, cap_flags: int,
                 destination: str, session_id: int,
                 content: Optional[str], direction: int) -> Verdict:
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
            encoded = content.encode("utf-8", errors="replace")[:511]
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
                 content: Optional[str], direction: int) -> Verdict:
        request_id = secrets.randbelow(2**31)
        # Compute a deterministic SHA-256 tool hash (64 hex chars) so the
        # daemon's ipc_json.c handler can look up the tool in its verdict
        # cache.  Callers that already carry a hash can extend this later;
        # for now we derive one from the canonical tool name.
        tool_hash = hashlib.sha256(tool_name.encode()).hexdigest()
        payload: Dict[str, Any] = {
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
                chunk = sock.recv(4096)
                if not chunk:
                    break
                if len(data) + len(chunk) > MAX_RESPONSE_SIZE:
                    raise RuntimeError("IPC response too large")
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

    Prefers IPC (Unix socket to daemon) when a daemon is running, since the
    daemon is the policy authority and applies OTA updates.  Falls back to
    FFI (ctypes, in-process) only when no daemon socket exists.
    Set ``fail_open=True`` to allow tool calls when no backend is available.
    """

    def __init__(
        self,
        lib_path: Optional[str] = None,
        socket_path: Optional[str] = None,
        fail_open: Optional[bool] = None,
        tool_cap_map: Optional[Dict[str, int]] = None,
        session_id: int = 1,
    ):
        self._lib_path = lib_path or os.environ.get(
            "DCLAW_LIB_PATH", "/usr/local/lib/libdclaw_core.so"
        )
        self._socket_path = socket_path or os.environ.get(
            "DCLAW_SOCKET_PATH", "/run/defenseclaw/defenseclaw.sock"
        )
        # M-15: Intentionally using "is not None" (not truthiness) here so
        # that fail_open=False explicitly disables fail-open mode, whereas
        # fail_open=None falls through to the env var check.  This is correct
        # behavior: bool(False) is falsy but the caller explicitly chose it.
        if fail_open is not None:
            self._fail_open = fail_open
        else:
            self._fail_open = os.environ.get("DCLAW_FAIL_OPEN", "0") == "1"

        self.tool_cap_map: Dict[str, int] = dict(DEFAULT_TOOL_CAP_MAP)
        if tool_cap_map:
            self.tool_cap_map.update(tool_cap_map)

        self._session_id = session_id
        self._backend = self._connect()

    @property
    def fail_open(self) -> bool:
        """Public accessor for the fail-open mode setting."""
        return self._fail_open

    # -- connection --------------------------------------------------------

    def _connect(self) -> Optional[_FFIBackend | _SocketBackend]:
        # NEW-2 fix: Prefer IPC (daemon socket) over FFI when a daemon is
        # running.  The daemon is the policy authority — it applies OTA
        # updates and keeps policy state current.  FFI loads policy into
        # the hook's own process memory, which goes stale when the daemon
        # receives an OTA.  Only fall back to FFI when no daemon socket
        # exists (standalone / no-daemon deployments).

        # Try Unix socket first (daemon is the policy authority)
        if Path(self._socket_path).exists():
            try:
                backend = _SocketBackend(self._socket_path)
                logger.info(
                    "EdgeConnector: connected via IPC socket (%s) — "
                    "daemon is policy authority",
                    self._socket_path,
                )
                return backend
            except Exception as exc:
                logger.debug("EdgeConnector: socket unavailable (%s), trying FFI", exc)

        # Fall back to FFI only when no daemon is running
        try:
            backend = _FFIBackend(self._lib_path)
            logger.info("EdgeConnector: connected via FFI (%s) — no daemon detected", self._lib_path)
            return backend
        except (OSError, RuntimeError) as exc:
            logger.debug("EdgeConnector: FFI unavailable (%s)", exc)

        if self._fail_open:
            logger.warning("EdgeConnector: no backend available — running in fail-open mode")
            return None
        raise ConnectionError(
            f"EdgeConnector: cannot connect via FFI ({self._lib_path}) "
            f"or socket ({self._socket_path}). Set DCLAW_FAIL_OPEN=1 to allow fail-open."
        )

    # -- backend liveness check -------------------------------------------

    def _check_backend(self) -> None:
        """Re-evaluate the active backend before every evaluate() call.

        * If currently using FFI, check whether the daemon IPC socket has
          appeared since construction — if so, switch to IPC (the daemon is
          the policy authority and receives OTA updates).
        * If currently using IPC, verify the socket is still alive with a
          quick connect test — if the daemon has gone away, fall back to FFI.
        * For FFI specifically: check whether the flash policy version has
          changed since the last evaluate (indicating an OTA was applied
          externally).  If so, call ``dclaw_policy_reload_from_flash()`` so
          the in-process policy tables pick up the new version.
        """
        if self._backend is None:
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
                except (OSError, socket.error):
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

                # H-7 fix: Read current policy_version from the device info struct
                # using the _DclawDeviceInfo ctypes struct definition instead of
                # raw pointer arithmetic. This avoids unsafe manual offset calculation
                # and is resilient to struct layout changes.
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

        elif isinstance(self._backend, _SocketBackend):
            # Verify the daemon socket is still alive.
            alive = False
            try:
                test_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                test_sock.settimeout(0.5)
                test_sock.connect(self._socket_path)
                test_sock.close()
                alive = True
            except (OSError, socket.error):
                pass
            if not alive:
                logger.warning(
                    "EdgeConnector: daemon socket at %s is dead — "
                    "falling back to FFI",
                    self._socket_path,
                )
                self._backend = None
                try:
                    self._backend = _FFIBackend(self._lib_path)
                    logger.info("EdgeConnector: reconnected via FFI (%s)", self._lib_path)
                except (OSError, RuntimeError) as exc:
                    logger.debug("EdgeConnector: FFI unavailable (%s)", exc)
                    if not self._fail_open:
                        raise ConnectionError(
                            f"EdgeConnector: daemon gone and FFI unavailable ({exc}). "
                            f"Set DCLAW_FAIL_OPEN=1 to allow fail-open."
                        )

    # -- public API --------------------------------------------------------

    def evaluate(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        destination: str = "",
        content: Optional[str] = None,
        direction: str = "request",
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

        Returns:
            A :class:`Verdict` with ``blocked``, ``reason``, etc.
        """
        self._check_backend()

        if self._backend is None:
            return Verdict.allow()

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
            )
        except (ConnectionError, OSError, RuntimeError) as exc:
            # H-4 fix: TOCTOU race — the socket may have disappeared between
            # _check_backend() and the actual evaluate() call.  Fall back to
            # FFI inline instead of failing outright.
            if isinstance(self._backend, _SocketBackend):
                logger.warning(
                    "EdgeConnector: socket evaluate failed (%s) — falling back to FFI",
                    exc,
                )
                try:
                    self._backend = _FFIBackend(self._lib_path)
                    return self._evaluate_chunked(
                        tool_name=tool_name,
                        cap_flags=cap_flags,
                        destination=dest,
                        content=content,
                        direction=dir_code,
                    )
                except (OSError, RuntimeError) as ffi_exc:
                    logger.error("EdgeConnector: FFI fallback also failed: %s", ffi_exc)
                    if self._fail_open:
                        return Verdict.allow()
                    return Verdict.error(f"ENGINE_ERROR: {ffi_exc}")
            logger.error("EdgeConnector: evaluate failed: %s", exc)
            if self._fail_open:
                return Verdict.allow()
            return Verdict.error(f"ENGINE_ERROR: {exc}")
        except Exception as exc:
            logger.error("EdgeConnector: evaluate failed: %s", exc)
            if self._fail_open:
                return Verdict.allow()
            return Verdict.error(f"ENGINE_ERROR: {exc}")

    # Maximum content bytes the C-side buffer accepts per call.
    _CONTENT_BUF_MAX = 511
    # Overlap between consecutive content windows so patterns that span
    # a window boundary are still caught.  64 bytes covers the longest
    # built-in secret/PII regex pattern.
    _CONTENT_OVERLAP = 64

    def _evaluate_chunked(
        self,
        tool_name: str,
        cap_flags: int,
        destination: str,
        content: Optional[str],
        direction: int,
    ) -> Verdict:
        """Evaluate content in overlapping windows when it exceeds the
        C-side 511-byte buffer, ensuring patterns past position 511 are
        still scanned."""
        # Short-circuit: content fits in a single buffer — no chunking.
        if not content or len(content.encode("utf-8", errors="replace")) <= self._CONTENT_BUF_MAX:
            return self._backend.evaluate(
                tool_name=tool_name,
                cap_flags=cap_flags,
                destination=destination,
                session_id=self._session_id,
                content=content,
                direction=direction,
            )

        encoded = content.encode("utf-8", errors="replace")
        step = self._CONTENT_BUF_MAX - self._CONTENT_OVERLAP
        offset = 0
        while offset < len(encoded):
            chunk = encoded[offset:offset + self._CONTENT_BUF_MAX]
            chunk_str = chunk.decode("utf-8", errors="replace")
            verdict = self._backend.evaluate(
                tool_name=tool_name,
                cap_flags=cap_flags,
                destination=destination,
                session_id=self._session_id,
                content=chunk_str,
                direction=direction,
            )
            if verdict.blocked:
                return verdict
            offset += step

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
        # Heuristic for unknown tools
        if any(kw in tool_name for kw in _DANGEROUS_KEYWORDS):
            return CAP_EXEC_SHELL
        return CAP_SENSOR_READ

    @staticmethod
    def _extract_destination(tool_name: str, arguments: Dict[str, Any]) -> str:
        """Pull a network destination from tool arguments when applicable."""
        for key in ("url", "href", "endpoint", "uri"):
            val = arguments.get(key, "")
            if val and "://" in str(val):
                try:
                    return urlparse(str(val)).hostname or ""
                except Exception:
                    pass
        return ""
