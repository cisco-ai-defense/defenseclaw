#!/usr/bin/env python3
"""DefenseClaw Lite hook for PicoClaw.

Bridges PicoClaw's JSON-RPC hook protocol (stdin/stdout) to the DefenseClaw
Lite evaluation engine via ctypes. Every tool call PicoClaw's AI agent makes
passes through dclaw_evaluate() before execution.

Install:
  1. Build libdclaw_core.so on the Pi
  2. Copy this file to ~/.picoclaw/hooks/defenseclaw_gate.py
  3. Register in picoclaw config.json hooks.processes

Tool → Capability mapping (configurable below):
  drive, explore, go_to_room, follow_nearest → ACTUATE (sync_block)
  exec, shell, bash                          → EXEC_SHELL (sync_block)
  web_search, fetch_url                      → NET_FETCH (speculative)
  get_sensors, battery_status, scan_*        → SENSOR_READ (speculative)
  read_file, cat                             → READ_FS (speculative)
  write_file, save                           → WRITE_FS (sync_block)
  send_message, notify                       → SEND_MSG (speculative)
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

LIBDCLAW_PATH = os.environ.get(
    "DCLAW_LIB_PATH",
    str(Path.home() / "defenseclaw-lite" / "build" / "libdclaw_core.so")
)

LOG_FILE = os.environ.get(
    "DCLAW_LOG_PATH",
    str(Path.home() / "defenseclaw-lite" / "dclaw_hook.log")
)

# Capability flags (must match defenseclaw.h)
CAP_READ_FS     = 0x01
CAP_WRITE_FS    = 0x02
CAP_EXEC_SHELL  = 0x04
CAP_NET_FETCH   = 0x08
CAP_SEND_MSG    = 0x10
CAP_ACTUATE     = 0x20
CAP_SENSOR_READ = 0x40

# Tool name → capability mapping for robot tools
TOOL_CAP_MAP = {
    # Robot actuations (sync_block — physical world, irrevocable)
    "drive": CAP_ACTUATE,
    "explore": CAP_ACTUATE,
    "go_to_room": CAP_ACTUATE,
    "follow_nearest": CAP_ACTUATE,
    "follow_start": CAP_ACTUATE,
    "follow_stop": CAP_ACTUATE,
    "stop": CAP_ACTUATE,
    # Sensors (speculative — read-only, low risk)
    "get_sensors": CAP_SENSOR_READ,
    "battery_status": CAP_SENSOR_READ,
    "scan_surroundings": CAP_SENSOR_READ,
    "check_room_state": CAP_SENSOR_READ,
    "enroll_face": CAP_SENSOR_READ,
    # Network (speculative)
    "web_search": CAP_NET_FETCH,
    "web_fetch": CAP_NET_FETCH,
    "fetch_url": CAP_NET_FETCH,
    "fetch": CAP_NET_FETCH,
    # Filesystem
    "read_file": CAP_READ_FS,
    "write_file": CAP_WRITE_FS,
    # Execution (sync_block — dangerous)
    "exec": CAP_EXEC_SHELL,
    "shell": CAP_EXEC_SHELL,
    "bash": CAP_EXEC_SHELL,
    "run_command": CAP_EXEC_SHELL,
    # Messaging
    "send_message": CAP_SEND_MSG,
    "notify": CAP_SEND_MSG,
}

# Actions (must match defenseclaw.h)
ACTION_ALLOW = 0
ACTION_BLOCK = 1
ACTION_WARN  = 2

# Reason codes
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
}


class DclawToolRequest(ctypes.Structure):
    _fields_ = [
        ("tool_name", ctypes.c_char * 64),
        ("tool_hash", ctypes.c_uint8 * 32),
        ("cap_flags", ctypes.c_uint8),
        ("destination", ctypes.c_char * 128),
        ("session_id", ctypes.c_uint16),
    ]


class DclawVerdict(ctypes.Structure):
    _fields_ = [
        ("action", ctypes.c_int),
        ("reason", ctypes.c_int),
        ("severity", ctypes.c_int),
        ("mode", ctypes.c_int),
        ("ttl_minutes", ctypes.c_uint16),
        ("from_cache", ctypes.c_bool),
    ]


class DclawDeviceInfo(ctypes.Structure):
    _fields_ = [
        ("tenant_id", ctypes.c_uint16),
        ("fleet_id", ctypes.c_uint16),
        ("device_id", ctypes.c_uint32),
        ("policy_version", ctypes.c_uint16),
        ("fw_version", ctypes.c_uint16),
        ("hw_profile", ctypes.c_uint8),
        ("capabilities", ctypes.c_uint8),
    ]


class DclawEngine:
    """Wrapper around libdclaw_core shared library."""

    def __init__(self, lib_path: str):
        self.lib = ctypes.CDLL(lib_path)
        self._setup_prototypes()
        self._initialized = False
        self._session_counter = 0

    def _setup_prototypes(self):
        self.lib.dclaw_init.argtypes = [ctypes.POINTER(DclawDeviceInfo)]
        self.lib.dclaw_init.restype = ctypes.c_int

        self.lib.dclaw_evaluate.argtypes = [ctypes.POINTER(DclawToolRequest)]
        self.lib.dclaw_evaluate.restype = DclawVerdict

        self.lib.dclaw_shutdown.argtypes = []
        self.lib.dclaw_shutdown.restype = None

    def init(self):
        info = DclawDeviceInfo(
            tenant_id=1,
            fleet_id=1,
            device_id=42,  # Pi robot device
            policy_version=1,
            fw_version=1,
            hw_profile=2,  # LINUX_SBC
            capabilities=0xFF,
        )
        rc = self.lib.dclaw_init(ctypes.byref(info))
        if rc != 0:
            raise RuntimeError(f"dclaw_init failed: {rc}")
        self._initialized = True

    def evaluate(self, tool_name: str, cap_flags: int,
                 destination: str = "", session_id: int = 0) -> dict:
        if not self._initialized:
            self.init()

        req = DclawToolRequest()
        req.tool_name = tool_name.encode("ascii", errors="replace")[:63]
        tool_hash_bytes = hashlib.sha256(tool_name.encode()).digest()
        for i in range(32):
            req.tool_hash[i] = tool_hash_bytes[i]
        req.cap_flags = cap_flags
        req.destination = destination.encode("ascii", errors="replace")[:127]
        req.session_id = session_id

        verdict = self.lib.dclaw_evaluate(ctypes.byref(req))

        return {
            "action": verdict.action,
            "reason": verdict.reason,
            "reason_name": REASON_NAMES.get(verdict.reason, "UNKNOWN"),
            "severity": verdict.severity,
            "mode": verdict.mode,
            "from_cache": verdict.from_cache,
        }

    def shutdown(self):
        if self._initialized:
            self.lib.dclaw_shutdown()
            self._initialized = False


# Global engine instance
_engine: DclawEngine | None = None
_log_fh = None
_session_map: dict[str, int] = {}
_next_session_id = 1


def log(msg: str):
    global _log_fh
    if _log_fh is None:
        try:
            _log_fh = open(LOG_FILE, "a")
        except Exception:
            return
    ts = time.strftime("%H:%M:%S")
    _log_fh.write(f"[{ts}] {msg}\n")
    _log_fh.flush()


def get_engine() -> DclawEngine:
    global _engine
    if _engine is None:
        log(f"Loading libdclaw from {LIBDCLAW_PATH}")
        _engine = DclawEngine(LIBDCLAW_PATH)
        _engine.init()
        log("DefenseClaw Lite engine initialized")
    return _engine


def get_session_id(params: dict) -> int:
    global _next_session_id
    channel = params.get("channel_id", params.get("session_id", "default"))
    if channel not in _session_map:
        _session_map[channel] = _next_session_id
        _next_session_id += 1
    return _session_map[channel]


def extract_destination(tool: str, arguments: dict) -> str:
    """Extract network destination from tool arguments."""
    # Any tool with network capability should have destination checked
    if TOOL_CAP_MAP.get(tool, 0) & CAP_NET_FETCH or tool in ("web_search", "fetch_url", "fetch", "web_fetch"):
        url = arguments.get("url", arguments.get("query", arguments.get("href", "")))
        if "://" in str(url):
            try:
                from urllib.parse import urlparse
                return urlparse(url).hostname or ""
            except Exception:
                pass
        return str(url) if url else ""
    return ""


def normalize_tool_name(raw_tool: str) -> str:
    """Strip MCP server prefix from tool names.
    PicoClaw sends: mcp_roboclaw_drive, mcp_vision-ai_battery_status
    We need:        drive,              battery_status
    """
    if raw_tool.startswith("mcp_"):
        parts = raw_tool.split("_", 2)  # ['mcp', 'roboclaw', 'drive'] or ['mcp', 'vision-ai', 'battery_status']
        if len(parts) >= 3:
            return parts[2]
        elif len(parts) == 2:
            return parts[1]
    return raw_tool


def handle_before_tool(params: dict[str, Any]) -> dict[str, Any]:
    raw_tool = params.get("tool", "")
    arguments = params.get("arguments") or {}

    tool = normalize_tool_name(raw_tool)
    cap_flags = TOOL_CAP_MAP.get(tool, 0)
    if cap_flags == 0:
        # Unknown tool — default to SENSOR_READ (permissive for unknown MCP tools)
        # Only default to EXEC_SHELL for tools that look dangerous
        if any(kw in tool for kw in ("exec", "shell", "bash", "run", "write", "delete", "rm")):
            cap_flags = CAP_EXEC_SHELL
            log(f"Unknown tool '{raw_tool}' (normalized: '{tool}') — classified as EXEC_SHELL")
        else:
            cap_flags = CAP_SENSOR_READ
            log(f"Unknown tool '{raw_tool}' (normalized: '{tool}') — classified as SENSOR_READ")

    destination = extract_destination(tool, arguments)
    session_id = get_session_id(params)

    engine = get_engine()
    verdict = engine.evaluate(
        tool_name=tool,
        cap_flags=cap_flags,
        destination=destination,
        session_id=session_id,
    )

    action = verdict["action"]
    reason_name = verdict["reason_name"]

    log(f"EVAL raw={raw_tool} tool={tool} caps=0x{cap_flags:02x} dest={destination!r} "
        f"session={session_id} → action={action} reason={reason_name}")

    if action == ACTION_BLOCK:
        reason_explanations = {
            "CLOUD_TIMEOUT": "This action requires cloud security approval, but no cloud connection is available. Fail-closed policy enforced.",
            "CAP_SEQUENCE": "A dangerous capability sequence was detected in this session. This multi-step pattern matches a known attack chain.",
            "DEST_DENY": f"Network destination '{destination}' is not in the approved allowlist. Only pre-approved endpoints are permitted.",
            "RATE_LIMIT": "Tool call rate limit exceeded. Too many requests in the current time window.",
            "HASH_DENY": "This tool's hash matches a known-malicious signature in the threat intelligence deny-list.",
            "INVALID_INPUT": "The tool request failed input validation (payload size, encoding, or format).",
        }
        explanation = reason_explanations.get(reason_name, f"Security policy violation: {reason_name}")

        msg = (
            f"⛔ DefenseClaw Lite — Tool Blocked\n\n"
            f"• Tool: {raw_tool}\n"
            f"• Reason: {reason_name}\n"
            f"• Detail: {explanation}\n"
            f"• Capability: 0x{cap_flags:02x}\n"
            f"• Enforcement: local (<3μs), no cloud round-trip\n\n"
            f"This event has been logged to the tamper-evident audit ring."
        )
        log(f"DENY: {raw_tool} — {reason_name}")
        return {"action": "deny_tool", "message": msg}

    if action == ACTION_WARN:
        log(f"WARN: tool={raw_tool} reason={reason_name} (allowing with warning)")

    return {"action": "continue"}


# === Prompt Injection Detection (before_llm) ===

# Known injection patterns — fast string matching, no ML needed on-device
INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard above",
    "disregard your instructions",
    "forget your rules",
    "forget all prior",
    "you are now",
    "new instructions:",
    "system prompt:",
    "override:",
    "jailbreak",
    "do anything now",
    "developer mode",
    "sudo mode",
    "act as an unrestricted",
    "ignore safety",
    "bypass the filter",
    "bypass safety",
    "pretend you have no restrictions",
    "you have no guidelines",
]

# Sensitive data patterns for output scanning
import re

PII_PATTERNS = [
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "SSN"),
    (re.compile(r'\b\d{16}\b'), "CREDIT_CARD"),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "EMAIL"),
    (re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'), "PRIVATE_KEY"),
    (re.compile(r'(password|passwd|secret|api_key|token)\s*[:=]\s*\S+', re.IGNORECASE), "CREDENTIAL"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS_ACCESS_KEY"),
]


def handle_before_llm(params: dict[str, Any]) -> dict[str, Any]:
    """Inspect user prompt for injection attacks before sending to LLM."""
    messages = params.get("messages", [])
    user_input = ""

    # Extract the latest user message
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                user_input = content
            elif isinstance(content, list):
                user_input = " ".join(
                    p.get("text", "") for p in content if p.get("type") == "text"
                )
            break

    if not user_input:
        return {"action": "continue"}

    input_lower = user_input.lower()

    # Check for injection patterns
    for pattern in INJECTION_PATTERNS:
        if pattern in input_lower:
            log(f"INJECTION_DETECT: matched pattern '{pattern}' in user input")
            log(f"  Input preview: {user_input[:100]!r}")

            # abort_turn stops the LLM from running entirely.
            # PicoClaw shows: "Error: hook requested turn abort"
            # The reason field is logged but not displayed to user in v0.3.1.
            return {
                "action": "abort_turn",
                "reason": (
                    f"DefenseClaw Lite: prompt injection detected "
                    f"(pattern: \"{pattern}\"). LLM call blocked."
                ),
            }

    log(f"LLM_INPUT: length={len(user_input)} — passed injection scan")
    return {"action": "continue"}


def handle_after_llm(params: dict[str, Any]) -> dict[str, Any]:
    """Scan LLM output for PII/credential leakage before showing to user."""
    response = ""

    # Try multiple fields PicoClaw might use
    for field in ("response", "content", "text", "message", "output"):
        val = params.get(field, "")
        if isinstance(val, str) and val:
            response = val
            break
        elif isinstance(val, dict):
            response = val.get("text", val.get("content", str(val)))
            break
        elif isinstance(val, list):
            response = " ".join(
                (p.get("text", "") if isinstance(p, dict) else str(p))
                for p in val
            )
            break

    if not response:
        return {"action": "continue"}

    # Scan for PII/secrets
    findings = []
    for pattern, label in PII_PATTERNS:
        if pattern.search(response):
            findings.append(label)

    if findings:
        log(f"PII_DETECT: found {findings} in LLM response")
        log(f"  Response preview: {response[:100]!r}")
        return {
            "action": "redact",
            "message": (
                "⛔ DefenseClaw Lite — Response Redacted\n\n"
                "The AI's response contained sensitive data that was blocked "
                "from being displayed.\n\n"
                f"• Detected: {', '.join(findings)}\n"
                f"• Action: content redacted before delivery\n"
                f"• Policy: PII/credential leakage prevention\n\n"
                "The original response has been suppressed. "
                "This event has been logged."
            ),
            "findings": findings,
        }

    log(f"LLM_OUTPUT: length={len(response)} — passed PII scan")
    return {"action": "continue"}


def handle_request(method: str, params: dict[str, Any]) -> dict[str, Any]:
    if method == "hook.hello":
        return {"ok": True, "name": "defenseclaw-lite-gate"}
    if method == "hook.before_tool":
        return handle_before_tool(params)
    if method == "hook.before_llm":
        return handle_before_llm(params)
    if method == "hook.after_llm":
        return handle_after_llm(params)
    if method == "hook.approve_tool":
        return {"approved": True}
    if method == "hook.after_tool":
        return {"action": "continue"}
    raise KeyError(f"method not found: {method}")


def send_response(message_id: int, result: Any | None = None,
                  error: str | None = None) -> None:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": message_id}
    if error is not None:
        payload["error"] = {"code": -32000, "message": error}
    else:
        payload["result"] = result if result is not None else {}
    try:
        sys.stdout.write(json.dumps(payload, ensure_ascii=True) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        raise SystemExit(0) from None


def handle_shutdown_signal(signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt(f"received signal {signum}")


def main() -> int:
    log("=== DefenseClaw Lite PicoClaw hook starting ===")

    try:
        get_engine()
    except Exception as exc:
        log(f"FATAL: Failed to load engine: {exc}")
        print(f"defenseclaw-lite hook: failed to load engine: {exc}",
              file=sys.stderr)
        return 1

    try:
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue

            method = message.get("method")
            message_id = message.get("id", 0)
            params = message.get("params") or {}
            if not isinstance(params, dict):
                params = {}
            if not message_id:
                continue

            try:
                result = handle_request(str(method or ""), params)
            except KeyError as exc:
                send_response(int(message_id), error=str(exc))
                continue
            except Exception as exc:
                log(f"ERROR handling {method}: {exc}")
                send_response(int(message_id), error=f"error: {exc}")
                continue
            send_response(int(message_id), result=result)
    except KeyboardInterrupt:
        pass
    finally:
        if _engine:
            _engine.shutdown()
        log("=== DefenseClaw Lite hook shutdown ===")

    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_shutdown_signal)
    signal.signal(signal.SIGTERM, handle_shutdown_signal)
    raise SystemExit(main())
