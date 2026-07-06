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

"""Shared connector-hook metric classification.

The gateway persists both a structured hook envelope and a legacy
``key=value`` details string.  Overview counters must interpret those two
representations identically, without substring matches such as finding
``action=block`` inside ``raw_action=block``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

_BLOCK_ACTIONS = frozenset({"block", "deny"})
_ALERT_ACTIONS = frozenset({"alert", "warn"})


def _iter_detail_tokens(value: str) -> Iterator[tuple[str, str]]:
    """Yield exact whitespace-delimited ``key=value`` tokens."""

    text = str(value or "").strip()
    i = 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        key_start = i
        while i < len(text) and text[i] != "=" and not text[i].isspace():
            i += 1
        if i >= len(text) or text[i] != "=":
            while i < len(text) and not text[i].isspace():
                i += 1
            continue
        key = text[key_start:i]
        i += 1
        if not key:
            continue
        if i < len(text) and text[i] == '"':
            i += 1
            chars: list[str] = []
            while i < len(text):
                if text[i] == '"':
                    i += 1
                    break
                if text[i] == "\\" and i + 1 < len(text):
                    i += 1
                chars.append(text[i])
                i += 1
            yield key, "".join(chars)
            continue
        value_start = i
        while i < len(text) and not text[i].isspace():
            i += 1
        yield key, text[value_start:i]


def parse_detail_tokens(value: str) -> dict[str, str]:
    """Parse exact whitespace-delimited ``key=value`` tokens.

    Quoted values may contain whitespace and escaped quotes.  Malformed tails
    are ignored rather than guessed; the user-facing metric should never turn
    an unrelated substring into an enforcement decision.
    """

    return dict(_iter_detail_tokens(value))


def _structured_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no", ""}:
        return False
    return None


def connector_hook_decision(
    details: str,
    structured: Any = None,
    enforced: Any = None,
) -> str:
    """Return ``allow``, ``alert``, or ``block`` for one hook row.

    Dedicated/structured ``enforced=true`` is authoritative.  Legacy rows
    predate that column, so an effective block outside observe mode remains a
    real block.  A latent block that was downgraded to allow/alert is an alert
    (would-block), never an enforced block.
    """

    tokens = parse_detail_tokens(details)
    payload = _structured_mapping(structured)

    def field(name: str) -> str:
        return str(payload.get(name) or tokens.get(name, "")).strip().lower()

    action = field("action")
    raw_action = field("raw_action")
    mode = field("mode")
    would_block = (
        _optional_bool(payload.get("would_block") if "would_block" in payload else tokens.get("would_block")) is True
    )
    explicit_enforced = _optional_bool(enforced)
    if explicit_enforced is None and "enforced" in payload:
        explicit_enforced = _optional_bool(payload.get("enforced"))

    if explicit_enforced is True:
        return "block"
    if action in _BLOCK_ACTIONS:
        if explicit_enforced is False or mode == "observe":
            return "alert"
        return "block"
    if action in _ALERT_ACTIONS:
        return "alert"
    if raw_action in _ALERT_ACTIONS:
        return "alert"
    if raw_action in _BLOCK_ACTIONS or would_block:
        return "alert"
    return action or "allow"


def aggregate_connector_hook_decision(
    details: str,
    structured: Any = None,
    enforced: Any = None,
) -> str:
    """Fast exact-token classifier for SQLite aggregate scans.

    Current gateway rows always carry the legacy action tokens alongside the
    structured envelope.  Avoiding a JSON decode and full token dictionary for
    that common path keeps the two-second aggregate poll cheap.  Structured-
    only/atypical rows fall back to :func:`connector_hook_decision`.
    """

    explicit_enforced = _optional_bool(enforced)
    if explicit_enforced is None and structured:
        structured_text = (
            json.dumps(structured, separators=(",", ":")) if isinstance(structured, dict) else str(structured)
        )
        if '"enforced"' in structured_text:
            return connector_hook_decision(details, structured, enforced)

    if explicit_enforced is True:
        return "block"
    action = ""
    raw_action = ""
    mode = ""
    would_block: bool | None = None
    for key, value in _iter_detail_tokens(details):
        normalized = value.strip().lower()
        if key == "action":
            action = normalized
        elif key == "raw_action":
            raw_action = normalized
        elif key == "mode":
            mode = normalized
        elif key == "would_block":
            would_block = _optional_bool(normalized)
        else:
            continue

        if action in _ALERT_ACTIONS:
            return "alert"
        if action in _BLOCK_ACTIONS and mode:
            return "alert" if explicit_enforced is False or mode == "observe" else "block"
        if action == "allow" and (raw_action in _BLOCK_ACTIONS or raw_action in _ALERT_ACTIONS):
            return "alert"
        if action == "allow" and raw_action and would_block is not None:
            return "alert" if would_block else "allow"

    if not action:
        return connector_hook_decision(details, structured, enforced)
    if action in _BLOCK_ACTIONS:
        if explicit_enforced is False or mode == "observe":
            return "alert"
        return "block"
    if action in _ALERT_ACTIONS:
        return "alert"
    if raw_action in _BLOCK_ACTIONS or raw_action in _ALERT_ACTIONS:
        return "alert"
    if would_block is True:
        return "alert"
    return "allow"


def connector_hook_connector(
    connector: Any,
    structured: Any,
    details: str,
) -> str:
    """Resolve normalized connector identity from dedicated to legacy data."""

    normalized = str(connector or "").strip().lower()
    if normalized:
        return normalized
    payload = _structured_mapping(structured)
    normalized = str(payload.get("connector") or "").strip().lower()
    if normalized:
        return normalized
    return parse_detail_tokens(details).get("connector", "").strip().lower()
