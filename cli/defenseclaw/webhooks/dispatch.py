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

"""Webhook payload formatters + synthetic test sender.

Structural/functional parity with ``internal/gateway/webhook.go`` — the
Python CLI only uses these formatters for ``defenseclaw setup webhook
test`` and for the parity test in ``cli/tests/test_webhooks.py``. The
Go dispatcher is still the source of truth at runtime.

Note on byte parity: both codebases emit **compact** JSON (no
whitespace, no trailing newline) so any single formatter's bytes are
reproducible for HMAC purposes, but Go's ``encoding/json`` sorts map
keys alphabetically while Python preserves insertion order. That means
the Python structures below line up with Go's output field-for-field,
but the serialized byte order can differ when payloads contain plain
``map[string]any``. Tests verify structural invariants (required keys,
HMAC against a known vector) rather than raw byte equality.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from defenseclaw.webhooks.writer import validate_webhook_url

# ---------------------------------------------------------------------------
# Synthetic event
# ---------------------------------------------------------------------------


@dataclass
class SyntheticEvent:
    """Small Python mirror of ``audit.Event`` — only the fields that
    end up in webhook payloads. Timestamps are emitted as RFC3339 to
    match ``time.Format(time.RFC3339)`` in Go."""

    id: str
    timestamp: str
    action: str
    target: str
    actor: str
    details: str
    severity: str
    run_id: str = ""
    trace_id: str = ""

    def to_go_json_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "action": self.action,
            "target": self.target,
            "actor": self.actor,
            "details": self.details,
            "severity": self.severity,
            "run_id": self.run_id,
            "trace_id": self.trace_id,
        }


def synthetic_event(
    *,
    action: str = "webhook.test",
    target: str = "synthetic-webhook",
    severity: str = "HIGH",
    actor: str = "defenseclaw-cli",
    details: str = "Synthetic test event dispatched from `defenseclaw setup webhook test`",
    event_id: str | None = None,
    timestamp: str | None = None,
) -> SyntheticEvent:
    """Build a deterministic-ish event suitable for dispatch tests."""
    return SyntheticEvent(
        id=event_id or f"synthetic-{uuid.uuid4().hex[:12]}",
        timestamp=timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z",
        ),
        action=action,
        target=target,
        actor=actor,
        details=details,
        severity=severity.upper(),
    )


# ---------------------------------------------------------------------------
# Formatters — must stay structurally in sync with webhook.go. Both
# emit compact JSON, but Go sorts map keys alphabetically so raw byte
# equality is not guaranteed for payloads that contain arbitrary
# maps. Structural invariants (required fields + HMAC vector) are the
# source of truth in tests.
# ---------------------------------------------------------------------------


def _slack_color(severity: str) -> str:
    match severity.upper():
        case "CRITICAL":
            return "#FF0000"
        case "HIGH":
            return "#FF6600"
        case "MEDIUM":
            return "#FFCC00"
        case "LOW":
            return "#36A64F"
        case _:
            return "#439FE0"


def _webex_severity_icon(severity: str) -> str:
    match severity:
        case "CRITICAL":
            return "🔴"
        case "HIGH":
            return "🟠"
        case "MEDIUM":
            return "🟡"
        case "LOW":
            return "🟢"
        case _:
            return "🔵"


def _json_bytes(obj: Any) -> bytes:
    # Go's encoding/json emits compact JSON (no trailing newline, no
    # spaces after separators). Match that exactly so HMAC sigs + byte
    # diffs align between the two codebases.
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def format_slack_payload(event: SyntheticEvent) -> bytes:
    color = _slack_color(event.severity)
    title = f"DefenseClaw: {event.action}"
    fields: list[dict[str, Any]] = [
        {"type": "mrkdwn", "text": f"*Severity:* {event.severity}"},
        {"type": "mrkdwn", "text": f"*Target:* {event.target}"},
    ]
    if event.details:
        details = event.details
        if len(details) > 500:
            details = details[:500] + "..."
        fields.append({"type": "mrkdwn", "text": f"*Details:* {details}"})

    payload: dict[str, Any] = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": title}},
                    {"type": "section", "fields": fields},
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"_Event ID: {event.id} | {event.timestamp}_",
                            },
                        ],
                    },
                ],
            },
        ],
    }
    return _json_bytes(payload)


def format_pagerduty_payload(event: SyntheticEvent, routing_key: str) -> bytes:
    severity = event.severity.upper()
    match severity:
        case "CRITICAL":
            pd_severity = "critical"
        case "HIGH":
            pd_severity = "error"
        case "MEDIUM":
            pd_severity = "warning"
        case _:
            pd_severity = "info"

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": f"defenseclaw-{event.target}-{event.action}",
        "payload": {
            "summary": f"DefenseClaw {event.action}: {event.severity} on {event.target}",
            "source": "defenseclaw",
            "severity": pd_severity,
            "timestamp": event.timestamp,
            "custom_details": {
                "action": event.action,
                "target": event.target,
                "severity": event.severity,
                "details": event.details,
                "event_id": event.id,
            },
        },
    }
    return _json_bytes(payload)


def format_webex_payload(event: SyntheticEvent, room_id: str) -> bytes:
    severity = event.severity.upper()
    icon = _webex_severity_icon(severity)
    markdown = (
        f"{icon} **DefenseClaw: {event.action}**\n\n"
        f"- **Severity:** {severity}\n"
        f"- **Target:** `{event.target}`\n"
        f"- **Actor:** {event.actor}\n"
    )
    if event.details:
        details = event.details
        if len(details) > 500:
            details = details[:500] + "..."
        markdown += f"- **Details:** {details}\n"
    markdown += f"\n_Event ID: {event.id} | {event.timestamp}_"

    payload: dict[str, Any] = {"markdown": markdown}
    if room_id:
        payload["roomId"] = room_id
    return _json_bytes(payload)


def format_generic_payload(event: SyntheticEvent) -> bytes:
    event_data: dict[str, Any] = {
        "id": event.id,
        "timestamp": event.timestamp,
        "action": event.action,
        "target": event.target,
        "actor": event.actor,
        "details": event.details,
        "severity": event.severity,
        "run_id": event.run_id,
        "trace_id": event.trace_id,
    }
    if "block" in event.action.lower():
        event_data["defenseclaw_blocked"] = True
        event_data["defenseclaw_reason"] = event.details
    payload = {
        "webhook_type": "defenseclaw_enforcement",
        "defenseclaw_version": "1.0",
        "event": event_data,
    }
    return _json_bytes(payload)


def compute_hmac(data: bytes, key: str) -> str:
    """Hex-encoded HMAC-SHA256, matching webhook.go::computeHMAC."""
    return hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Synthetic dispatch
# ---------------------------------------------------------------------------


@dataclass
class DispatchResult:
    """Result of a synthetic webhook send — rendered by the CLI."""

    name: str
    type: str
    url: str
    status_code: int | None
    ok: bool
    error: str | None = None
    request_body_preview: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    payload_bytes: int = 0


def send_synthetic(
    *,
    webhook_type: str,
    url: str,
    secret: str = "",
    room_id: str = "",
    event: SyntheticEvent | None = None,
    timeout_seconds: int = 10,
    name: str = "",
    preview_only: bool = False,
) -> DispatchResult:
    """Format and (optionally) deliver a synthetic webhook.

    Unlike the Go runtime we don't retry or sleep — tests should fail
    fast with a clear error. ``preview_only=True`` returns the formatted
    payload without sending (used by ``--dry-run``).
    """
    if webhook_type not in ("slack", "pagerduty", "webex", "generic"):
        raise ValueError(f"unsupported webhook type: {webhook_type!r}")

    # Defense-in-depth: even though every current caller (cmd_setup_
    # webhook.test, cmd_doctor._check_webhooks) validates the URL
    # upstream, this function is a public library entry point and must
    # refuse to deliver to private/loopback/metadata endpoints on its
    # own. The SSRF allow-list toggle
    # (``DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST=1``) is honoured inside
    # ``validate_webhook_url``.
    validate_webhook_url(url)

    evt = event or synthetic_event()

    if webhook_type == "slack":
        payload = format_slack_payload(evt)
    elif webhook_type == "pagerduty":
        if not secret:
            raise ValueError("pagerduty requires a routing key (secret)")
        payload = format_pagerduty_payload(evt, secret)
    elif webhook_type == "webex":
        payload = format_webex_payload(evt, room_id)
    else:
        payload = format_generic_payload(evt)

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": "defenseclaw-cli/webhook-test",
    }
    if secret:
        if webhook_type == "webex":
            headers["Authorization"] = f"Bearer {secret}"
        elif webhook_type == "generic":
            headers["X-Hub-Signature-256"] = "sha256=" + compute_hmac(payload, secret)

    preview = payload[:200].decode("utf-8", errors="replace")

    if preview_only:
        return DispatchResult(
            name=name,
            type=webhook_type,
            url=url,
            status_code=None,
            ok=True,
            error=None,
            request_body_preview=preview,
            request_headers=_redact_headers(headers),
            payload_bytes=len(payload),
        )

    req = urllib.request.Request(  # noqa: S310 - URL is validated upstream
        url, data=payload, headers=headers, method="POST",
    )
    status: int | None = None
    err: str | None = None
    try:
        with urllib.request.urlopen(req, timeout=max(1, int(timeout_seconds))) as resp:  # noqa: S310
            status = int(resp.getcode())
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        err = f"HTTP {exc.code}: {exc.reason}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        err = str(exc)

    ok = status is not None and 200 <= status < 300
    return DispatchResult(
        name=name,
        type=webhook_type,
        url=url,
        status_code=status,
        ok=ok,
        error=None if ok else (err or f"HTTP {status}"),
        request_body_preview=preview,
        request_headers=_redact_headers(headers),
        payload_bytes=len(payload),
    )


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact Authorization / signature values before handing back to
    the CLI render layer — tests and ``--show`` must never print raw
    secrets even if the user sets DEBUG flags."""
    safe: dict[str, str] = {}
    sensitive = {"authorization", "x-hub-signature-256"}
    for key, value in headers.items():
        safe[key] = "<redacted>" if key.lower() in sensitive else value
    return safe


