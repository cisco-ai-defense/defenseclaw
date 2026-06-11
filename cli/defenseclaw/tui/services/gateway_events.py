# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Gateway JSONL event parsing for Activity and Logs panels."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

GatewayEventType = Literal["scan", "scan_finding", "activity", "unknown"]


@dataclass(frozen=True)
class GatewayEvent:
    """Normalized gateway event row."""

    event_type: GatewayEventType
    severity: str = ""
    timestamp: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    scan: dict[str, Any] = field(default_factory=dict)
    scan_finding: dict[str, Any] = field(default_factory=dict)
    activity: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActivityMutation:
    """Activity mutation row from gateway JSONL."""

    actor: str = ""
    action: str = ""
    target_type: str = ""
    target_id: str = ""
    version_from: str = ""
    version_to: str = ""
    reason: str = ""
    diff: tuple[dict[str, Any], ...] = ()
    timestamp: datetime | None = None

    @property
    def target_label(self) -> str:
        if self.target_type:
            return f"{self.target_type}:{self.target_id}"
        return self.target_id


@dataclass(frozen=True)
class ScanBlock:
    """Gateway scan roll-up with child findings."""

    scan_id: str
    scanner: str = ""
    target: str = ""
    severity: str = "INFO"
    verdict: str = ""
    duration_ms: int = 0
    total_count: int = 0
    counts: dict[str, int] = field(default_factory=dict)
    timestamp: datetime | None = None
    findings: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class EgressEvent:
    """Parsed gateway egress event from gateway.jsonl.

    Mirrors the Go ``tui.EgressEvent`` struct so the same JSONL file
    drives the silent-bypass tile on both backends.
    """

    timestamp: datetime | None = None
    target_host: str = ""
    target_path: str = ""
    body_shape: str = ""
    looks_like_llm: bool = False
    branch: str = ""
    decision: str = ""
    reason: str = ""
    source: str = ""


def count_recent_silent_bypass(
    events: tuple[EgressEvent, ...] | list[EgressEvent],
    window_seconds: int = 300,
) -> int:
    """Count egress events in the last ``window_seconds`` that represent
    an LLM-shaped request the proxy did NOT route through triage/judge.

    Mirrors ``internal/tui/egress.go::CountRecentSilentBypass`` exactly:

    * ``branch=passthrough`` + ``looks_like_llm=true`` — unknown host
      with an LLM-shaped body that was let through because
      ``allow_unknown_llm_domains`` is on (or the path was ambiguous).
    * ``branch=shape`` — recognized as LLM by body shape but the
      operator opted into the unknown host.

    ``branch=known`` never counts (those go through normal triage),
    and ``decision != allow`` never counts (the proxy rejected them).
    """

    if not events or window_seconds <= 0:
        return 0
    cutoff = datetime.now(timezone.utc).timestamp() - window_seconds
    n = 0
    for ev in events:
        if ev.timestamp is None:
            continue
        ts = ev.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts.timestamp() < cutoff:
            continue
        if ev.decision != "allow":
            continue
        if ev.branch == "passthrough" and ev.looks_like_llm:
            n += 1
        elif ev.branch == "shape":
            n += 1
    return n


def load_gateway_egress(path: Path | str) -> tuple[EgressEvent, ...]:
    """Read the tail of ``gateway.jsonl`` and return egress rows.

    Bounded to the last 512 KiB to match the Go reader's budget; on a
    fresh install the file may not exist yet, in which case we return
    an empty tuple instead of raising.
    """

    p = Path(path)
    try:
        size = p.stat().st_size
    except (OSError, FileNotFoundError):
        return ()
    max_bytes = 512 * 1024
    read_size = min(size, max_bytes)
    offset = size - read_size
    try:
        with p.open("rb") as fh:
            if offset > 0:
                fh.seek(offset)
            chunk = fh.read(read_size)
    except OSError:
        return ()
    text = chunk.decode("utf-8", errors="replace")
    if offset > 0:
        # The first line is almost certainly a half-record; drop it so
        # ``json.loads`` doesn't reject it.
        nl = text.find("\n")
        if nl >= 0:
            text = text[nl + 1 :]
    out: list[EgressEvent] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        if str(payload.get("event_type") or "") != "egress":
            continue
        egress = payload.get("egress")
        if not isinstance(egress, dict):
            continue
        out.append(
            EgressEvent(
                timestamp=parse_timestamp(payload.get("ts")),
                target_host=str(egress.get("target_host") or ""),
                target_path=str(egress.get("target_path") or ""),
                body_shape=str(egress.get("body_shape") or ""),
                looks_like_llm=bool(egress.get("looks_like_llm")),
                branch=str(egress.get("branch") or ""),
                decision=str(egress.get("decision") or ""),
                reason=str(egress.get("reason") or ""),
                source=str(egress.get("source") or ""),
            )
        )
    # Newest first so callers using a sliding window can stop early.
    out.sort(key=lambda e: e.timestamp or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return tuple(out)


def parse_gateway_event(line: str) -> GatewayEvent:
    """Parse one gateway JSONL line.

    A well-formed JSONL row is a JSON object. Non-object payloads (a bare
    number, string, list, or ``null``) are valid JSON but carry no event
    fields, so they are coerced to an empty mapping and surface as an
    ``unknown`` event that callers skip rather than crashing on ``.get``.
    """

    payload = json.loads(line)
    if not isinstance(payload, dict):
        payload = {}
    event_type = str(payload.get("event_type") or "unknown")
    if event_type not in {"scan", "scan_finding", "activity"}:
        event_type = "unknown"
    return GatewayEvent(
        event_type=event_type,  # type: ignore[arg-type]
        severity=str(payload.get("severity") or ""),
        timestamp=parse_timestamp(payload.get("ts")),
        raw=payload,
        scan=_mapping(payload.get("scan")),
        scan_finding=_mapping(payload.get("scan_finding")),
        activity=_mapping(payload.get("activity")),
    )


def parse_timestamp(raw: object) -> datetime | None:
    """Parse RFC3339-ish gateway timestamps."""

    if not isinstance(raw, str) or not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def render_verdict_line(event: GatewayEvent) -> str:
    """Render a compact line equivalent to the Go verdict parser smoke tests."""

    if event.event_type == "scan":
        scan_id = event.scan.get("scan_id", "")
        scanner = event.scan.get("scanner", "")
        target = event.scan.get("target", "")
        return "  ".join(part for part in (event.severity, scanner, scan_id, target) if part)
    if event.event_type == "scan_finding":
        finding = event.scan_finding
        return "  ".join(
            str(part)
            for part in (
                event.severity,
                finding.get("scanner", ""),
                finding.get("rule_id", ""),
                finding.get("line_number", ""),
                finding.get("title", ""),
            )
            if part not in {"", None}
        )
    if event.event_type == "activity":
        activity = event.activity
        return "  ".join(
            str(part)
            for part in (
                activity.get("actor", ""),
                activity.get("action", ""),
                activity.get("target_type", ""),
                activity.get("target_id", ""),
            )
            if part not in {"", None}
        )
    return str(event.raw)


def load_gateway_activity(path: Path) -> tuple[ActivityMutation, ...]:
    """Load activity events from a gateway JSONL file."""

    if not path.exists():
        return ()
    rows: list[ActivityMutation] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = parse_gateway_event(line)
        except json.JSONDecodeError:
            continue
        if event.event_type != "activity" or not event.activity:
            continue
        rows.append(
            ActivityMutation(
                actor=str(event.activity.get("actor") or ""),
                action=str(event.activity.get("action") or ""),
                target_type=str(event.activity.get("target_type") or ""),
                target_id=str(event.activity.get("target_id") or ""),
                version_from=str(event.activity.get("version_from") or ""),
                version_to=str(event.activity.get("version_to") or ""),
                reason=str(event.activity.get("reason") or ""),
                diff=tuple(_mapping(item) for item in event.activity.get("diff", ()) if isinstance(item, dict)),
                timestamp=event.timestamp,
            )
        )
    return tuple(rows)


def load_gateway_scan_blocks(path: Path) -> tuple[ScanBlock, ...]:
    """Load scan summary blocks and attached findings from gateway JSONL."""

    if not path.exists():
        return ()
    blocks: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        # A single malformed gateway row must never break the Alerts
        # refresh: tolerate bad JSON, non-numeric counters, and any other
        # shape surprise by skipping just that row.
        try:
            event = parse_gateway_event(line)
        except json.JSONDecodeError:
            continue
        try:
            if event.event_type == "scan" and event.scan.get("scan_id"):
                scan_id = str(event.scan["scan_id"])
                block = blocks.setdefault(scan_id, {"findings": []})
                block.update(
                    scan_id=scan_id,
                    scanner=str(event.scan.get("scanner") or ""),
                    target=str(event.scan.get("target") or ""),
                    severity=str(event.scan.get("severity_max") or event.severity or "INFO"),
                    verdict=str(event.scan.get("verdict") or ""),
                    duration_ms=_safe_int(event.scan.get("duration_ms")),
                    total_count=_safe_int(event.scan.get("total_count")),
                    counts=_int_mapping(event.scan.get("counts")),
                    timestamp=event.timestamp,
                )
            elif event.event_type == "scan_finding" and event.scan_finding.get("scan_id"):
                scan_id = str(event.scan_finding["scan_id"])
                block = blocks.setdefault(
                    scan_id,
                    {
                        "scan_id": scan_id,
                        "scanner": str(event.scan_finding.get("scanner") or ""),
                        "target": str(event.scan_finding.get("target") or ""),
                        "severity": event.severity or "INFO",
                        "timestamp": event.timestamp,
                        "findings": [],
                    },
                )
                block["findings"].append(event.scan_finding)
                if event.timestamp and (block.get("timestamp") is None or event.timestamp > block["timestamp"]):
                    block["timestamp"] = event.timestamp
        except (AttributeError, TypeError, ValueError):
            continue

    result = [
        ScanBlock(
            scan_id=str(block.get("scan_id") or ""),
            scanner=str(block.get("scanner") or ""),
            target=str(block.get("target") or ""),
            severity=str(block.get("severity") or "INFO"),
            verdict=str(block.get("verdict") or ""),
            duration_ms=_safe_int(block.get("duration_ms")),
            total_count=_safe_int(block.get("total_count")),
            counts=dict(block.get("counts") or {}),
            timestamp=block.get("timestamp"),
            findings=tuple(block.get("findings") or ()),
        )
        for block in blocks.values()
        if block.get("scan_id")
    ]
    return tuple(
        sorted(
            result,
            key=lambda block: block.timestamp or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
    )


def _mapping(raw: object) -> dict[str, Any]:
    return raw if isinstance(raw, dict) else {}


def _safe_int(raw: object) -> int:
    """Best-effort integer coercion for gateway counter fields.

    Gateway rows are produced by a separate process and may carry
    non-numeric values (``"NaN"``, ``null``, objects). Fall back to ``0``
    instead of raising so one bad row cannot crash the Alerts panel.
    """

    if raw is None:
        return 0
    try:
        return int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _int_mapping(raw: object) -> dict[str, int]:
    if not isinstance(raw, dict):
        return {}
    values: dict[str, int] = {}
    for key, value in raw.items():
        try:
            values[str(key)] = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
    return values


def timestamp_label(ts: datetime | None) -> str:
    """Return Go-style HH:MM:SS timestamps for event rows."""

    if ts is None:
        return "--:--:--"
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%H:%M:%S")
