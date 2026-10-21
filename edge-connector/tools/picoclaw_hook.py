#!/usr/bin/env python3

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

"""Edge Connector hook for PicoClaw.

Bridges PicoClaw's JSON-RPC hook protocol (stdin/stdout) to the Edge
Connector. Every tool call PicoClaw's AI agent makes is evaluated before
execution through generic_hook.EdgeConnector, which talks to the daemon
over its Unix socket (DCLAW_SOCKET_PATH). The daemon is the policy
authority, so OTA policy, revocations and emergency lockdown apply.

If the daemon is not reachable the hook fails closed. The in-process
engine (libdclaw_core via ctypes) is used only when DCLAW_ALLOW_FFI=1 is
set, and then needs its own DCLAW_FLASH_PATH.

Install:
  1. Run the Edge Connector daemon (or build libdclaw_core.so and opt in
     with DCLAW_ALLOW_FFI=1)
  2. Copy this file and generic_hook.py to ~/.picoclaw/hooks/
     (this file as defenseclaw_gate.py)
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

import json
import logging as _logging_mod
import os
import re
import signal
import sys
import threading
import unicodedata
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

# This hook talks to the Edge Connector daemon over its local Unix socket
# (or, when explicitly allowed, an in-process engine).  Network-facing
# transports (MQTT to fleet, cloud escalation) use TLS separately.

try:
    import generic_hook as _generic_hook
except ImportError:
    # Installed layout: `make install` puts the adapters here.
    sys.path.append(os.environ.get("DCLAW_TOOLS_DIR", "/usr/local/lib/defenseclaw"))
    import generic_hook as _generic_hook

EdgeConnector = _generic_hook.EdgeConnector
check_http_production = _generic_hook.check_http_production
_generic_normalize = _generic_hook.normalize_tool_name


LIBDCLAW_PATH = os.environ.get(
    "DCLAW_LIB_PATH",
    str(Path.home() / "edge-connector" / "build" / "libdclaw_core.so")
)

LOG_FILE = os.environ.get(
    "DCLAW_LOG_PATH",
    str(Path.home() / "edge-connector" / "dclaw_hook.log")
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
    "cat": CAP_READ_FS,
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
ACTION_ESCALATE = 3

# Only ALLOW and WARN let a tool run; ESCALATE and any unknown action deny.
_PERMIT_ACTIONS = frozenset((ACTION_ALLOW, ACTION_WARN))


def _permits(action: Any) -> bool:
    return (isinstance(action, int) and not isinstance(action, bool)
            and action in _PERMIT_ACTIONS)

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
    0x0C: "CONTENT_BLOCK",
    0x0D: "SSRF_BLOCK",
    0x0E: "HASH_MISMATCH",
}


# Global engine instance
_engine_lock = threading.Lock()
_engine: EdgeConnector | None = None
_session_map: dict[str, int] = {}
_next_session_id = 1
_SESSION_MAP_MAX = 10000

_picoclaw_logger = _logging_mod.getLogger("defenseclaw.picoclaw_hook")
_picoclaw_logger.setLevel(_logging_mod.DEBUG)
_log_handler_initialized = False


def _ensure_log_handler() -> None:
    global _log_handler_initialized
    if _log_handler_initialized:
        return
    _log_handler_initialized = True
    try:
        handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=1_048_576,  # 1 MB
            backupCount=3,
        )
        handler.setFormatter(_logging_mod.Formatter("[%(asctime)s] %(message)s", datefmt="%H:%M:%S"))
        _picoclaw_logger.addHandler(handler)
    except Exception:
        pass


def log(msg: str):
    _ensure_log_handler()
    _picoclaw_logger.info(msg)


def get_engine() -> EdgeConnector:
    """Return the shared connector (daemon socket first, fail closed)."""
    global _engine
    if _engine is not None:
        return _engine
    with _engine_lock:
        if _engine is None:
            ec = EdgeConnector(lib_path=LIBDCLAW_PATH)
            # Use exactly the PicoClaw map; unknown tools fall back to the
            # shared fail-closed rules (EXEC_SHELL unless a safe prefix).
            ec.tool_cap_map = dict(TOOL_CAP_MAP)
            _engine = ec
            log("Edge Connector client initialized")
        return _engine


def get_session_id(params: dict) -> int:
    global _next_session_id
    channel = params.get("channel_id", params.get("session_id", "default"))
    if channel in _session_map:
        return _session_map[channel]
    if len(_session_map) >= _SESSION_MAP_MAX:
        oldest_key = next(iter(_session_map))
        del _session_map[oldest_key]
    _session_map[channel] = _next_session_id
    _next_session_id += 1
    return _session_map[channel]


def extract_destination(tool: str, arguments: dict) -> str:
    """Extract network destination from tool arguments."""
    # Any tool with network capability should have destination checked
    if TOOL_CAP_MAP.get(tool, 0) & CAP_NET_FETCH or tool in ("web_search", "fetch_url", "fetch", "web_fetch"):
        # Check top-level keys, then nested "params" / "input" dicts
        search_dicts = [arguments]
        for nested_key in ("params", "input", "arguments"):
            nested = arguments.get(nested_key)
            if isinstance(nested, dict):
                search_dicts.append(nested)
        url = ""
        for d in search_dicts:
            for key in ("url", "query", "href", "destination"):
                val = d.get(key)
                if isinstance(val, str) and val:
                    url = val
                    break
            if url:
                break
        if "://" in url:
            try:
                return _generic_hook._destination_host(url)
            except Exception:
                pass
        return url
    return ""


def normalize_tool_name(raw_tool: str) -> str:
    """Strip MCP server prefix from tool names.
    PicoClaw sends: mcp_roboclaw_drive, mcp_vision-ai_battery_status
    We need:        drive,              battery_status

    Delegates to the shared implementation in generic_hook.normalize_tool_name.
    """
    return _generic_normalize(raw_tool)


def handle_before_tool(params: dict[str, Any]) -> dict[str, Any]:
    raw_tool = params.get("tool", "")
    arguments = params.get("arguments") or {}

    tool = normalize_tool_name(raw_tool)
    cap_flags = TOOL_CAP_MAP.get(tool, 0)
    if cap_flags == 0:
        # Unknown tools default to EXEC_SHELL (fail-closed) to match the
        # C daemon. Only downgrade to SENSOR_READ for known safe prefixes.
        # Use startswith() to avoid substring false positives (e.g. "delegate_status" matching "status").
        if any(tool.startswith(p) for p in ("get_", "list_", "check_", "read_", "scan_", "status")):
            cap_flags = CAP_SENSOR_READ
            log(f"Unknown tool '{raw_tool}' (normalized: '{tool}') — classified as SENSOR_READ (safe prefix)")
        else:
            cap_flags = CAP_EXEC_SHELL
            log(f"Unknown tool '{raw_tool}' (normalized: '{tool}') — classified as EXEC_SHELL (fail-closed)")

    destination = extract_destination(tool, arguments)
    session_id = get_session_id(params)

    # P1-8 fix: Serialize tool arguments as JSON and pass as content
    # so the C engine's content scanner can inspect them.
    content = ""
    if arguments:
        try:
            content = json.dumps(arguments, ensure_ascii=True, default=str)
        except (TypeError, ValueError):
            content = ""

    engine = get_engine()
    verdict = engine.evaluate(
        tool_name=tool,
        arguments=arguments if isinstance(arguments, dict) else {},
        destination=destination,
        content=content or None,
        session_id=session_id,
    )

    action = verdict.action
    reason_name = verdict.reason

    log(f"EVAL raw={raw_tool} tool={tool} caps=0x{cap_flags:02x} dest={destination!r} "
        f"session={session_id} → action={action} reason={reason_name}")

    if verdict.blocked or not _permits(action):
        reason_explanations = {
            "CLOUD_TIMEOUT": "This action requires cloud security approval, but no cloud connection is available. Fail-closed policy enforced.",
            "CAP_SEQUENCE": "A dangerous capability sequence was detected in this session. This multi-step pattern matches a known attack chain.",
            "DEST_DENY": f"Network destination '{destination}' is not in the approved allowlist. Only pre-approved endpoints are permitted.",
            "RATE_LIMIT": "Tool call rate limit exceeded. Too many requests in the current time window.",
            "HASH_DENY": "This tool's hash matches a known-malicious signature in the threat intelligence deny-list.",
            "INVALID_INPUT": "The tool request failed input validation (payload size, encoding, or format).",
            "CONTENT_BLOCK": "Content inspection detected dangerous material (secrets, PII, credentials, exfiltration, injection, or commands) in the tool call payload.",
            "SSRF_BLOCK": "The destination targets a private/internal IP range or cloud metadata endpoint. SSRF protection blocked the request.",
        }
        explanation = reason_explanations.get(reason_name, f"Security policy violation: {reason_name}")

        msg = (
            f"⛔ Edge Connector — Tool Blocked\n\n"
            f"• Tool: {raw_tool}\n"
            f"• Reason: {reason_name}\n"
            f"• Detail: {explanation}\n"
            f"• Capability: 0x{cap_flags:02x}\n"
            f"• Enforcement: local decision, no cloud round-trip for this block\n\n"
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

# ---------------------------------------------------------------------------
# PII / credential validation helpers
# ---------------------------------------------------------------------------

def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm (ISO/IEC 7812-1).
    Used to reduce false positives in credit card detection."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _is_valid_ssn(match_str: str) -> bool:
    """Check whether an SSN-like match is in a valid range.
    Excludes known-invalid area numbers: 000, 666, 900-999."""
    digits = "".join(d for d in match_str if d.isdigit())
    if len(digits) != 9:
        return False
    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])
    # Invalid area numbers per SSA rules
    if area == 0 or area == 666 or area >= 900:
        return False
    # Group and serial cannot be all zeros
    if group == 0 or serial == 0:
        return False
    return True


# Raw regex patterns for initial matching
_SSN_RE = re.compile(r'\b\d{3}[\s-]?\d{2}[\s-]?\d{4}\b')
_CC_RE = re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b')

# Sensitive data patterns for output scanning
# Patterns that need post-match validation are handled in _scan_pii()
PII_PATTERNS = [
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "EMAIL"),
    (re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'), "PRIVATE_KEY"),
    (re.compile(r'(password|passwd|secret|api_key|token)\s*[:=]\s*\S+', re.IGNORECASE), "CREDENTIAL"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS_ACCESS_KEY"),
]


def _scan_pii(text: str) -> list[str]:
    """Scan text for PII/credential patterns with validation.
    Returns a list of detected PII type labels."""
    findings = []

    # SSN with exclusion ranges
    for m in _SSN_RE.finditer(text):
        if _is_valid_ssn(m.group()):
            findings.append("SSN")
            break  # one finding per type is enough

    # Credit card with Luhn validation
    for m in _CC_RE.finditer(text):
        if _luhn_check(m.group()):
            findings.append("CREDIT_CARD")
            break

    # Simple regex patterns (no extra validation needed)
    for pattern, label in PII_PATTERNS:
        if pattern.search(text):
            findings.append(label)

    return findings


def _strip_unicode_control(text: str) -> str:
    """Remove zero-width characters and Unicode control chars that could
    be used to evade pattern matching (e.g. zero-width spaces, joiners,
    soft hyphens, bidirectional overrides).

    This is defense-in-depth: the primary control is the pattern list,
    but attackers may insert invisible chars to split patterns like
    'ignore\\u200Bprevious' -> 'ignore previous'.
    """
    # Remove zero-width and format characters (category Cf) and control chars (Cc)
    # except for common whitespace (\n, \r, \t)
    return "".join(
        ch for ch in text
        if ch in ("\n", "\r", "\t")
        or unicodedata.category(ch) not in ("Cf", "Cc")
    )


def handle_before_llm(params: dict[str, Any]) -> dict[str, Any]:
    """Inspect user prompt for injection attacks before sending to LLM.

    NOTE: This is defense-in-depth, not a primary control. Pattern matching
    alone cannot reliably detect all prompt injection attacks. It catches
    common/known injection phrases as an additional layer of protection.
    """
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

    # Normalize: strip zero-width/control Unicode chars to prevent evasion,
    # then lowercase for case-insensitive matching.
    input_lower = _strip_unicode_control(user_input).lower()

    # Check for injection patterns (defense-in-depth, not a primary control)
    for pattern in INJECTION_PATTERNS:
        if pattern in input_lower:
            log(f"INJECTION_DETECT: matched pattern '{pattern}' [input redacted]")

            # abort_turn stops the LLM from running entirely.
            # PicoClaw shows: "Error: hook requested turn abort"
            # The reason field is logged but not displayed to user in v0.3.1.
            return {
                "action": "abort_turn",
                "reason": (
                    f"Edge Connector: prompt injection detected "
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

    # Scan for PII/secrets (with Luhn and SSN validation to reduce false positives)
    findings = _scan_pii(response)

    if findings:
        log(f"PII_DETECT: found {findings} in LLM response")
        log("  Response: [REDACTED — PII/secret patterns detected]")
        return {
            "action": "redact",
            "message": (
                "⛔ Edge Connector — Response Redacted\n\n"
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
        return {"ok": True, "name": "edge-connector-gate"}
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


def send_response(message_id: str | int | float | None, result: Any | None = None,
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
    log("=== Edge Connector PicoClaw hook starting ===")

    try:
        get_engine()
    except Exception as exc:
        log(f"FATAL: Failed to load engine: {exc}")
        print(f"edge-connector hook: failed to load engine: {exc}",
              file=sys.stderr)
        return 1

    try:
        _MAX_LINE = 1024 * 1024  # 1 MB per message
        for raw_line in sys.stdin:
            if len(raw_line) > _MAX_LINE:
                log(f"WARNING: dropping oversized message ({len(raw_line)} bytes)")
                continue
            line = raw_line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(message, dict):
                send_response(None, error="invalid request")
                continue
            method = message.get("method")
            # JSON-RPC ids may be strings or numbers (including 0); a
            # request without an id (or with a null id) is a notification
            # and gets no reply.  The id is echoed back unchanged.
            message_id = message.get("id")
            if message_id is None:
                continue
            if isinstance(message_id, bool) or not isinstance(message_id, (str, int, float)):
                send_response(None, error="invalid request id")
                continue
            params = message.get("params") or {}
            if not isinstance(params, dict):
                params = {}

            try:
                result = handle_request(str(method or ""), params)
            except KeyError as exc:
                send_response(message_id, error=str(exc))
                continue
            except Exception as exc:
                log(f"ERROR handling {method}: {exc}")
                send_response(message_id, error=f"error: {exc}")
                continue
            send_response(message_id, result=result)
    except KeyboardInterrupt:
        pass
    finally:
        if _engine:
            _engine.shutdown()
        log("=== Edge Connector hook shutdown ===")

    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_shutdown_signal)
    signal.signal(signal.SIGTERM, handle_shutdown_signal)
    raise SystemExit(main())
