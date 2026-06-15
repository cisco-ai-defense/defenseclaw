# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Gateway JSONL read models for the Textual Logs and Audit-adjacent panels."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from defenseclaw.tui.services.gateway_events import parse_timestamp

GatewayLogEventType = Literal[
    "verdict",
    "judge",
    "lifecycle",
    "error",
    "diagnostic",
    "scan",
    "scan_finding",
    "activity",
]

EVENT_TYPE_FILTERS: tuple[str, ...] = (
    "",
    "verdict",
    "judge",
    "lifecycle",
    "error",
    "diagnostic",
    "scan",
    "scan_finding",
    "activity",
)
EVENT_TYPE_LABELS: dict[str, str] = {
    "": "All events",
    "verdict": "Verdict",
    "judge": "Judge",
    "lifecycle": "Lifecycle",
    "error": "Error",
    "diagnostic": "Diagnostic",
    "scan": "Scan",
    "scan_finding": "Scan finding",
    "activity": "Activity",
}
ACTION_FILTERS: tuple[str, ...] = ("", "block", "alert", "confirm", "allow")
ACTION_LABELS: dict[str, str] = {
    "": "All actions",
    "block": "Block",
    "alert": "Alert",
    "confirm": "Confirm",
    "allow": "Allow",
}
SEVERITY_FILTERS: tuple[str, ...] = ("", "CRITICAL", "HIGH", "HIGH+", "MEDIUM", "LOW", "INFO")
SEVERITY_LABELS: dict[str, str] = {
    "": "All severities",
    "CRITICAL": "Critical",
    "HIGH": "High",
    "HIGH+": "High+",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
}


@dataclass(frozen=True)
class JudgeFinding:
    """Compact judge finding surfaced in the structured detail view."""

    category: str = ""
    severity: str = ""
    rule: str = ""
    source: str = ""
    confidence: float = 0.0


@dataclass(frozen=True)
class GatewayLogRow:
    """Typed projection of one gateway.jsonl event for Logs-panel views."""

    raw: str
    timestamp: datetime | None = None
    event_type: str = ""
    severity: str = ""
    action: str = ""
    stage: str = ""
    direction: str = ""
    model: str = ""
    reason: str = ""
    kind: str = ""
    request_id: str = ""
    run_id: str = ""
    session_id: str = ""
    provider: str = ""
    agent_id: str = ""
    categories: tuple[str, ...] = ()
    latency_ms: int = 0
    judge_input_bytes: int = 0
    judge_severity: str = ""
    judge_raw: str = ""
    judge_parse_error: str = ""
    judge_findings: tuple[JudgeFinding, ...] = ()
    lifecycle_subsystem: str = ""
    lifecycle_transition: str = ""
    lifecycle_details: dict[str, str] = field(default_factory=dict)
    error_subsystem: str = ""
    error_code: str = ""
    error_message: str = ""
    error_cause: str = ""
    diagnostic_component: str = ""
    diagnostic_message: str = ""
    scan_scanner: str = ""
    scan_target: str = ""
    scan_id: str = ""
    scan_verdict: str = ""
    finding_rule_id: str = ""
    finding_line: int = 0
    activity_actor: str = ""
    activity_action: str = ""
    activity_target: str = ""
    version_from: str = ""
    version_to: str = ""


@dataclass(frozen=True)
class GatewayLogViews:
    """Split gateway.jsonl into operator-facing Verdicts and OTEL streams."""

    verdict_rows: tuple[GatewayLogRow, ...] = ()
    verdict_lines: tuple[str, ...] = ()
    otel_rows: tuple[GatewayLogRow, ...] = ()
    otel_lines: tuple[str, ...] = ()
    error: str = ""


def parse_gateway_log_row(line: str) -> GatewayLogRow | None:
    """Parse one gateway.jsonl line into the Go TUI's structured row shape."""

    stripped = line.strip()
    if not stripped or not stripped.startswith("{"):
        return None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    raw_ts = payload.get("ts")
    timestamp = parse_timestamp(raw_ts)
    if isinstance(raw_ts, str) and raw_ts and timestamp is None:
        return None

    row = GatewayLogRow(
        raw=stripped,
        timestamp=timestamp,
        event_type=_string(payload.get("event_type")),
        severity=_string(payload.get("severity")),
        model=_string(payload.get("model")),
        direction=_string(payload.get("direction")),
        request_id=_string(payload.get("request_id")),
        run_id=_string(payload.get("run_id")),
        session_id=_string(payload.get("session_id")),
        provider=_string(payload.get("provider")),
        agent_id=_string(payload.get("agent_id")),
    )
    row = _with_verdict(row, _mapping(payload.get("verdict")))
    row = _with_judge(row, _mapping(payload.get("judge")))
    row = _with_lifecycle(row, _mapping(payload.get("lifecycle")))
    row = _with_error(row, _mapping(payload.get("error")))
    row = _with_diagnostic(row, _mapping(payload.get("diagnostic")))
    row = _with_scan(row, _mapping(payload.get("scan")))
    row = _with_scan_finding(row, _mapping(payload.get("scan_finding")))
    return _with_activity(row, _mapping(payload.get("activity")))


def load_gateway_log_views(
    path: Path,
    *,
    action_filter: str = "",
    event_type_filter: str = "",
    severity_filter: str = "",
    max_bytes: int = 512 * 1024,
    max_lines: int = 2000,
) -> GatewayLogViews:
    """Load and split the gateway event tail, applying Verdicts chip filters."""

    try:
        raw_lines = _tail_lines(path, max_bytes=max_bytes, max_lines=max_lines)
    except OSError as exc:
        return GatewayLogViews(error=f"Cannot open: {exc}")

    verdict_rows: list[GatewayLogRow] = []
    verdict_lines: list[str] = []
    otel_rows: list[GatewayLogRow] = []
    otel_lines: list[str] = []
    for line in raw_lines:
        row = parse_gateway_log_row(line)
        if row is None:
            continue
        if is_otel_log_row(row):
            otel_rows.append(row)
            otel_lines.append(render_otel_line(row))
            continue
        if not _matches_structured_filters(
            row,
            action_filter=action_filter,
            event_type_filter=event_type_filter,
            severity_filter=severity_filter,
        ):
            continue
        verdict_rows.append(row)
        verdict_lines.append(render_gateway_log_line(row))

    return GatewayLogViews(
        verdict_rows=tuple(verdict_rows),
        verdict_lines=tuple(verdict_lines),
        otel_rows=tuple(otel_rows),
        otel_lines=tuple(otel_lines),
    )


def render_gateway_log_line(row: GatewayLogRow) -> str:
    """Render the compact structured gateway event line used by Logs."""

    ts = timestamp_millis(row.timestamp)
    event_type = row.event_type
    if event_type == "verdict":
        suffix = truncate_text(row.reason, 100)
        if row.categories:
            suffix += " [" + ",".join(trim_categories(row.categories, 2)) + "]"
        if row.latency_ms > 0:
            suffix += f" ({row.latency_ms}ms)"
        return (
            f"{ts} VERDICT {_upper_or(row.action, 'none'):<7} {_upper_or(row.severity, 'info'):<8} "
            f"{_non_empty(row.stage, '-'):<10} {_non_empty(row.direction, '-')} "
            f"{_non_empty(row.model, '-')} -- {suffix}"
        )
    if event_type == "judge":
        suffix = ""
        if row.judge_input_bytes > 0:
            suffix += f" in={row.judge_input_bytes}B"
        if row.latency_ms > 0:
            suffix += f" {row.latency_ms}ms"
        if row.judge_parse_error:
            suffix += " parse=error"
        return (
            f"{ts} JUDGE   {_upper_or(row.action, 'none'):<7} {_upper_or(row.severity, 'info'):<8} "
            f"kind={_non_empty(row.kind, '-'):<10} dir={_non_empty(row.direction, '-')} "
            f"model={_non_empty(row.model, '-')}{suffix}"
        )
    if event_type == "lifecycle":
        if row.lifecycle_subsystem or row.lifecycle_transition:
            return (
                f"{ts} LIFECYCLE {_upper_or(row.lifecycle_subsystem, '-'):<10} "
                f"{_upper_or(row.lifecycle_transition, '-'):<10} "
                f"{render_details_inline(row.lifecycle_details, 3)}"
            ).rstrip()
        return f"{ts} LIFECYCLE {row.raw}"
    if event_type == "error":
        if row.error_code or row.error_message:
            return (
                f"{ts} ERROR     {_upper_or(row.error_subsystem, '-'):<10} "
                f"code={_non_empty(row.error_code, '-')} msg={truncate_text(row.error_message, 120)}"
            )
        return f"{ts} ERROR   {row.raw}"
    if event_type == "diagnostic":
        if row.diagnostic_component or row.diagnostic_message:
            return (
                f"{ts} DIAG      {_upper_or(row.diagnostic_component, '-'):<10} "
                f"{truncate_text(row.diagnostic_message, 120)}"
            ).rstrip()
        return f"{ts} DIAG    {row.raw}"
    if event_type == "scan":
        return (
            f"{ts} SCAN    {_upper_or(row.severity, 'info'):<8} "
            f"scanner={_non_empty(row.scan_scanner, '-')} target={truncate_text(row.scan_target, 40)} "
            f"verdict={_non_empty(row.scan_verdict, '-')} scan_id={_non_empty(row.scan_id, '-')}"
        )
    if event_type == "scan_finding":
        return (
            f"{ts} FINDING {_upper_or(row.severity, 'info'):<8} "
            f"rule={_non_empty(row.finding_rule_id, '-')} line={row.finding_line} "
            f"{truncate_text(row.scan_target, 36)} @ {_non_empty(row.scan_scanner, '-')}"
        )
    if event_type == "activity":
        return (
            f"{ts} ACT     {_upper_or(row.severity, 'info'):<8} "
            f"actor={_non_empty(row.activity_actor, '-')} action={_non_empty(row.activity_action, '-')} "
            f"target={truncate_text(row.activity_target, 36)} "
            f"{_non_empty(row.version_from, 'empty')}->{_non_empty(row.version_to, 'empty')}"
        )
    return f"{ts} {_upper_or(row.event_type, 'event'):<9} {row.raw}"


def render_otel_line(row: GatewayLogRow) -> str:
    """Render connector telemetry and Codex notification rows.

    Connector-hook lifecycle events ship with ``lifecycle.details`` of
    the form ``{action, actor, audit_id, target, details}`` where the
    inner ``details`` is itself a kv-encoded string (``connector=…
    action=allow severity=NONE mode=observe …``). Dumping all of that
    inline produces the nightmare we shipped before:

        subsystem=gateway transition=completed action=connector-hook
        actor=defenseclaw audit_id=43be… details=connector=codex …

    For HOOK rows we instead promote the high-signal fields
    (connector, hook phase, decision, severity if elevated, elapsed)
    into a compact one-liner and drop the audit_id/actor noise. Other
    OTEL/CODEX rows keep the legacy rendering.
    """

    ts = timestamp_millis(row.timestamp)
    action = row.activity_action or row.lifecycle_details.get("action", "")
    target = row.activity_target or row.lifecycle_details.get("target", "")
    stream = "OTEL"
    lowered = action.lower()
    if lowered.startswith("codex.notify"):
        stream = "CODEX"
    elif lowered == "connector-hook":
        stream = "HOOK"

    if row.event_type == "lifecycle":
        if stream == "HOOK":
            return _render_hook_lifecycle_line(ts, row, target)
        return (
            f"{ts} {stream:<6} {_upper_or(row.severity, 'info'):<8} "
            f"subsystem={_non_empty(row.lifecycle_subsystem, '-')} "
            f"transition={_non_empty(row.lifecycle_transition, '-')} "
            f"{render_details_inline(row.lifecycle_details, 4)}"
        ).rstrip()
    if row.event_type == "activity":
        return (
            f"{ts} {stream:<6} {_upper_or(row.severity, 'info'):<8} "
            f"actor={_non_empty(row.activity_actor, '-')} action={_non_empty(action, '-')} "
            f"target={truncate_text(_non_empty(target, '-'), 36)} "
            f"{_non_empty(row.version_from, 'empty')}->{_non_empty(row.version_to, 'empty')}"
        )
    if row.event_type == "diagnostic":
        return (
            f"{ts} {stream:<6} {_upper_or(row.severity, 'info'):<8} "
            f"component={_non_empty(row.diagnostic_component, '-')} "
            f"{truncate_text(row.diagnostic_message, 120)}"
        ).rstrip()
    return f"{ts} {stream:<6} {_upper_or(row.severity, 'info'):<8} {row.raw}"


def _render_hook_lifecycle_line(ts: str, row: GatewayLogRow, target: str) -> str:
    """Render a connector-hook lifecycle line as a compact summary.

    Surfaces ``connector hook · decision · severity? · elapsed`` so the
    log scroll stays scannable. Severity is elided when ``NONE``
    because every passing inspection shares it; elapsed is elided when
    absent so we don't show ``elapsed=-``.
    """

    inner_details = row.lifecycle_details.get("details", "")
    parsed = _parse_log_kv_details(inner_details) if inner_details else {}
    connector = parsed.get("connector", "")
    decision = parsed.get("action", "") or parsed.get("decision", "")
    severity = parsed.get("severity", "")
    mode = parsed.get("mode", "")
    elapsed = parsed.get("elapsed", "") or parsed.get("duration_ms", "")
    head = f"{connector} {target}".strip()
    if not head:
        head = "-"
    pieces: list[str] = []
    if decision:
        pieces.append(decision)
    if severity and severity.upper() != "NONE":
        pieces.append(severity.upper())
    if mode and mode != "observe":
        pieces.append(mode)
    if elapsed:
        pieces.append(elapsed)
    suffix = " · ".join(pieces) if pieces else "-"
    return (
        f"{ts} HOOK   {_upper_or(row.severity, 'info'):<8} "
        f"{truncate_text(head, 36):<36} {suffix}"
    ).rstrip()


def _prettify_log_kv_value(key: str, value: str) -> str:
    """Translate raw kv values for the Logs detail pane.

    Mirrors the audit-panel prettifier so ``raw_payload=<redacted
    len=8 sha=84ed0c96>`` becomes ``redacted · 8 bytes · sha:…`` and
    booleans become yes/no. Kept local so logs and audit can evolve
    independently if the JSONL schema diverges.
    """

    if value.startswith("<") and value.endswith(">"):
        inner = value[1:-1].strip()
        if inner.startswith("redacted"):
            attrs = _parse_log_kv_details(inner[len("redacted") :])
            length = attrs.get("len")
            digest = attrs.get("sha")
            parts: list[str] = []
            if length:
                parts.append(f"{length} bytes")
            if digest:
                parts.append(f"sha:{digest}")
            if parts:
                return "redacted · " + " · ".join(parts)
            return value
        return inner
    if key == "would_block":
        if value == "true":
            return "yes"
        if value == "false":
            return "no"
    return value


def _parse_log_kv_details(value: str) -> dict[str, str]:
    """Parse ``key=value`` style strings nested inside lifecycle details.

    Mirrors the audit-panel parser for HOOK rows whose interesting
    fields are buried inside the ``details`` sub-string. Handles
    quoted values and angle-bracketed placeholders like
    ``<redacted len=8 sha=84ed0c96>`` so the digest stays readable.
    """

    pairs: dict[str, str] = {}
    if not value:
        return pairs
    text = value.strip()
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        key_start = i
        while i < n and text[i] != "=" and not text[i].isspace():
            i += 1
        if i >= n or text[i] != "=":
            break
        key = text[key_start:i]
        i += 1
        if i < n and text[i] == '"':
            i += 1
            val_start = i
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            val = text[val_start:i]
            if i < n:
                i += 1
        elif i < n and text[i] == "<":
            depth = 0
            val_start = i
            while i < n:
                if text[i] == "<":
                    depth += 1
                elif text[i] == ">":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            val = text[val_start:i]
        else:
            val_start = i
            while i < n and not text[i].isspace():
                i += 1
            val = text[val_start:i]
        if key:
            pairs[key] = val
    return pairs


def detail_pairs(row: GatewayLogRow) -> tuple[tuple[str, str], ...]:
    """Return ordered structured-event detail rows for the shared detail surface."""

    pairs: list[tuple[str, str]] = [
        ("Timestamp", row.timestamp.isoformat() if row.timestamp else ""),
        ("Event type", row.event_type),
        ("Severity", row.severity),
        ("Action", row.action),
        ("Stage", row.stage),
        ("Direction", row.direction),
        ("Model", row.model),
    ]
    for label, value in (
        ("Provider", row.provider),
        ("Request ID", row.request_id),
        ("Run ID", row.run_id),
        ("Session ID", row.session_id),
    ):
        if value:
            pairs.append((label, value))
    if row.categories:
        pairs.append(("Categories", ", ".join(row.categories)))
    if row.latency_ms > 0:
        pairs.append(("Latency (ms)", str(row.latency_ms)))
    if row.kind:
        pairs.append(("Judge kind", row.kind))
    if row.reason:
        pairs.append(("Reason", row.reason))
    if row.judge_severity and row.judge_severity.lower() != row.severity.lower():
        pairs.append(("Judge severity", row.judge_severity))
    if row.judge_input_bytes > 0:
        pairs.append(("Judge input bytes", str(row.judge_input_bytes)))
    if row.judge_parse_error:
        pairs.append(("Judge parse error", row.judge_parse_error))
    for index, finding in enumerate(row.judge_findings, start=1):
        value = f"category={finding.category} severity={finding.severity}"
        if finding.rule:
            value += f" rule={finding.rule}"
        if finding.source:
            value += f" source={finding.source}"
        if finding.confidence > 0:
            value += f" conf={finding.confidence:.2f}"
        pairs.append((f"Finding {index}", value))
    for label, value in (
        ("Subsystem", row.lifecycle_subsystem),
        ("Transition", row.lifecycle_transition),
    ):
        if value:
            pairs.append((label, value))
    # For connector-hook lifecycle events we expand the nested kv
    # ``details`` string into individual rows so operators see
    # Connector/Decision/Severity/Elapsed instead of a single opaque
    # ``Detail: details`` line. Other lifecycle detail keys still go
    # through the legacy rendering — they're already structured.
    inner_hook_details = ""
    is_hook_row = (row.lifecycle_details.get("action", "") == "connector-hook")
    if is_hook_row:
        inner_hook_details = row.lifecycle_details.get("details", "")
    for key in sorted(row.lifecycle_details):
        if is_hook_row and key in {"action", "actor", "details", "audit_id", "target"}:
            continue
        pairs.append((f"Detail: {key}", row.lifecycle_details[key]))
    if inner_hook_details:
        parsed = _parse_log_kv_details(inner_hook_details)
        is_observe = parsed.get("mode", "") == "observe"
        for label_key, label in (
            ("connector", "Connector"),
            ("tool", "Tool"),
            ("action", "Decision"),
            ("raw_action", "Decision (raw)"),
            ("severity", "Severity (decision)"),
            ("mode", "Enforcement mode"),
            ("decision", "Decision"),
            ("reason", "Reason"),
            ("would_block", "Would block"),
            ("elapsed", "Elapsed"),
            ("duration_ms", "Elapsed (ms)"),
            ("raw_payload", "Raw payload"),
        ):
            value = parsed.get(label_key, "")
            if not value:
                continue
            if label_key == "severity" and value.upper() == "NONE":
                continue
            if label_key == "would_block" and value == "false" and is_observe:
                continue
            pairs.append((label, _prettify_log_kv_value(label_key, value)))
    for label, value in (
        ("Error subsystem", row.error_subsystem),
        ("Error code", row.error_code),
        ("Error message", row.error_message),
        ("Error cause", row.error_cause),
        ("Diagnostic component", row.diagnostic_component),
        ("Diagnostic message", row.diagnostic_message),
    ):
        if value:
            pairs.append((label, value))
    if row.judge_raw:
        pairs.append(("Judge raw response", row.judge_raw))
    pairs.append(("Raw JSON", row.raw))
    return tuple(pairs)


def is_otel_log_row(row: GatewayLogRow) -> bool:
    """Return true when a structured event belongs in the OTEL/Codex stream."""

    action = row.activity_action.strip().lower()
    if not action:
        action = row.lifecycle_details.get("action", "").strip().lower()
    if (
        action.startswith("otel.ingest.")
        or action.startswith("codex.notify.")
        or action in {"otel.ingest", "codex.notify", "connector-hook"}
    ):
        return True

    subsystem = row.lifecycle_subsystem.strip().lower()
    component = row.diagnostic_component.strip().lower()
    return subsystem in {"otel", "telemetry"} or component in {"otel", "telemetry"}


def severity_rank(severity: str) -> int:
    """Rank severities for the HIGH+ meta-filter."""

    return {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }.get(severity.upper(), 0)


def render_details_inline(details: dict[str, str], limit: int) -> str:
    """Render a stable, capped key=value details suffix."""

    if limit <= 0 or not details:
        return ""
    keys = sorted(details)[:limit]
    return " ".join(f"{key}={details[key]}" for key in keys)


def trim_categories(categories: tuple[str, ...], limit: int) -> tuple[str, ...]:
    """Cap categories and signal hidden remainder with +Nmore."""

    if limit <= 0 or not categories:
        return ()
    if len(categories) <= limit:
        return categories
    return (*categories[:limit], f"+{len(categories) - limit}more")


def truncate_text(value: str, limit: int) -> str:
    """Clip text at a codepoint boundary and use an ASCII ellipsis."""

    if limit <= 0:
        return ""
    if len(value) <= limit:
        return value
    if limit <= 3:
        return "." * limit
    return value[: limit - 3] + "..."


def timestamp_millis(ts: datetime | None) -> str:
    """Return Go-style HH:MM:SS.mmm event timestamps."""

    if ts is None:
        return "--:--:--.---"
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%H:%M:%S.%f")[:12]


def _matches_structured_filters(
    row: GatewayLogRow,
    *,
    action_filter: str,
    event_type_filter: str,
    severity_filter: str,
) -> bool:
    if event_type_filter and row.event_type.lower() != event_type_filter.lower():
        return False
    if severity_filter:
        if severity_filter == "HIGH+":
            if severity_rank(row.severity) < severity_rank("HIGH"):
                return False
        elif row.severity.lower() != severity_filter.lower():
            return False
    if action_filter and (not row.action or row.action.lower() != action_filter.lower()):
        return False
    return True


def _tail_lines(path: Path, *, max_bytes: int, max_lines: int) -> tuple[str, ...]:
    with path.open("rb") as file:
        file.seek(0, 2)
        size = file.tell()
        read_size = min(size, max_bytes)
        file.seek(size - read_size)
        data = file.read(read_size)
    if size > read_size:
        _, _, data = data.partition(b"\n")
    lines = data.decode("utf-8", errors="replace").splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return tuple(lines)


def _with_verdict(row: GatewayLogRow, verdict: dict[str, Any]) -> GatewayLogRow:
    if not verdict:
        return row
    return GatewayLogRow(
        **{
            **row.__dict__,
            "stage": _string(verdict.get("stage")),
            "action": _string(verdict.get("action")),
            "reason": _string(verdict.get("reason")),
            "categories": tuple(_string(item) for item in _sequence(verdict.get("categories"))),
            "latency_ms": _int(verdict.get("latency_ms")),
        }
    )


def _with_judge(row: GatewayLogRow, judge: dict[str, Any]) -> GatewayLogRow:
    if not judge:
        return row
    action = row.action or _string(judge.get("action"))
    latency = row.latency_ms or _int(judge.get("latency_ms"))
    return GatewayLogRow(
        **{
            **row.__dict__,
            "kind": _string(judge.get("kind")),
            "action": action,
            "judge_severity": _string(judge.get("severity")),
            "judge_input_bytes": _int(judge.get("input_bytes")),
            "latency_ms": latency,
            "judge_findings": tuple(_judge_finding(item) for item in _sequence(judge.get("findings"))),
            "judge_raw": _string(judge.get("raw_response")),
            "judge_parse_error": _string(judge.get("parse_error")),
        }
    )


def _with_lifecycle(row: GatewayLogRow, lifecycle: dict[str, Any]) -> GatewayLogRow:
    if not lifecycle:
        return row
    return GatewayLogRow(
        **{
            **row.__dict__,
            "lifecycle_subsystem": _string(lifecycle.get("subsystem")),
            "lifecycle_transition": _string(lifecycle.get("transition")),
            "lifecycle_details": _string_mapping(lifecycle.get("details")),
        }
    )


def _with_error(row: GatewayLogRow, error: dict[str, Any]) -> GatewayLogRow:
    if not error:
        return row
    return GatewayLogRow(
        **{
            **row.__dict__,
            "error_subsystem": _string(error.get("subsystem")),
            "error_code": _string(error.get("code")),
            "error_message": _string(error.get("message")),
            "error_cause": _string(error.get("cause")),
        }
    )


def _with_diagnostic(row: GatewayLogRow, diagnostic: dict[str, Any]) -> GatewayLogRow:
    if not diagnostic:
        return row
    return GatewayLogRow(
        **{
            **row.__dict__,
            "diagnostic_component": _string(diagnostic.get("component")),
            "diagnostic_message": _string(diagnostic.get("message")),
        }
    )


def _with_scan(row: GatewayLogRow, scan: dict[str, Any]) -> GatewayLogRow:
    if not scan:
        return row
    latency = row.latency_ms or _int(scan.get("duration_ms"))
    return GatewayLogRow(
        **{
            **row.__dict__,
            "scan_id": _string(scan.get("scan_id")),
            "scan_scanner": _string(scan.get("scanner")),
            "scan_target": _string(scan.get("target")),
            "scan_verdict": _string(scan.get("verdict")),
            "action": "scan",
            "latency_ms": latency,
        }
    )


def _with_scan_finding(row: GatewayLogRow, finding: dict[str, Any]) -> GatewayLogRow:
    if not finding:
        return row
    severity = _string(finding.get("severity")) or row.severity
    return GatewayLogRow(
        **{
            **row.__dict__,
            "scan_id": _string(finding.get("scan_id")),
            "scan_scanner": _string(finding.get("scanner")),
            "scan_target": _string(finding.get("target")),
            "finding_rule_id": _string(finding.get("rule_id")),
            "finding_line": _int(finding.get("line_number")),
            "severity": severity,
            "action": "finding",
        }
    )


def _with_activity(row: GatewayLogRow, activity: dict[str, Any]) -> GatewayLogRow:
    if not activity:
        return row
    target_type = _string(activity.get("target_type"))
    target_id = _string(activity.get("target_id"))
    target = f"{target_type}:{target_id}" if target_type else target_id
    action = _string(activity.get("action"))
    return GatewayLogRow(
        **{
            **row.__dict__,
            "activity_actor": _string(activity.get("actor")),
            "activity_action": action,
            "activity_target": target,
            "version_from": _string(activity.get("version_from")),
            "version_to": _string(activity.get("version_to")),
            "action": action,
        }
    )


def _judge_finding(raw: object) -> JudgeFinding:
    item = _mapping(raw)
    return JudgeFinding(
        category=_string(item.get("category")),
        severity=_string(item.get("severity")),
        rule=_string(item.get("rule")),
        source=_string(item.get("source")),
        confidence=_float(item.get("confidence")),
    )


def _mapping(raw: object) -> dict[str, Any]:
    return raw if isinstance(raw, dict) else {}


def _string_mapping(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(key): _string(value) for key, value in raw.items()}


def _sequence(raw: object) -> tuple[object, ...]:
    if isinstance(raw, list | tuple):
        return tuple(raw)
    return ()


def _string(raw: object) -> str:
    if raw is None:
        return ""
    return str(raw)


def _int(raw: object) -> int:
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return int(raw)
    if isinstance(raw, str):
        try:
            return int(raw)
        except ValueError:
            return 0
    return 0


def _float(raw: object) -> float:
    if isinstance(raw, int | float):
        return float(raw)
    if isinstance(raw, str):
        try:
            return float(raw)
        except ValueError:
            return 0.0
    return 0.0


def _non_empty(value: str, fallback: str) -> str:
    return value if value else fallback


def _upper_or(value: str, fallback: str) -> str:
    return _non_empty(value, fallback).upper()
