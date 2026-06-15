# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure AI discovery state for the Textual TUI."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

AIDiscoveryState = Literal["new", "changed", "active", "seen", "gone"]


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True)
class AIUsageComponent:
    ecosystem: str = ""
    name: str = ""
    version: str = ""
    framework: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> AIUsageComponent | None:
        if not raw:
            return None
        return cls(
            ecosystem=str(raw.get("ecosystem") or ""),
            name=str(raw.get("name") or ""),
            version=str(raw.get("version") or ""),
            framework=str(raw.get("framework") or ""),
        )


@dataclass(frozen=True)
class AIUsageRuntime:
    pid: int = 0
    ppid: int = 0
    started_at: datetime | None = None
    uptime_sec: int = 0
    user: str = ""
    comm: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> AIUsageRuntime | None:
        if not raw:
            return None
        return cls(
            pid=int(raw.get("pid") or 0),
            ppid=int(raw.get("ppid") or 0),
            started_at=_parse_datetime(raw.get("started_at")),
            uptime_sec=int(raw.get("uptime_sec") or 0),
            user=str(raw.get("user") or ""),
            comm=str(raw.get("comm") or ""),
        )


@dataclass(frozen=True)
class AIUsageSignal:
    signal_id: str = ""
    signature_id: str = ""
    name: str = ""
    vendor: str = ""
    product: str = ""
    category: str = ""
    supported_connector: str = ""
    confidence: float = 0.0
    identity_score: float = 0.0
    identity_band: str = ""
    presence_score: float = 0.0
    presence_band: str = ""
    state: str = ""
    detector: str = ""
    source: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    last_active_at: datetime | None = None
    version: str = ""
    component: AIUsageComponent | None = None
    runtime: AIUsageRuntime | None = None
    evidence_types: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> AIUsageSignal:
        component_raw = raw.get("component")
        runtime_raw = raw.get("runtime")
        evidence = raw.get("evidence_types") or ()
        if isinstance(evidence, str):
            evidence_types = (evidence,)
        else:
            evidence_types = tuple(str(item) for item in evidence)
        return cls(
            signal_id=str(raw.get("signal_id") or ""),
            signature_id=str(raw.get("signature_id") or ""),
            name=str(raw.get("name") or ""),
            vendor=str(raw.get("vendor") or ""),
            product=str(raw.get("product") or ""),
            category=str(raw.get("category") or ""),
            supported_connector=str(raw.get("supported_connector") or ""),
            confidence=float(raw.get("confidence") or 0.0),
            identity_score=float(raw.get("identity_score") or 0.0),
            identity_band=str(raw.get("identity_band") or ""),
            presence_score=float(raw.get("presence_score") or 0.0),
            presence_band=str(raw.get("presence_band") or ""),
            state=str(raw.get("state") or ""),
            detector=str(raw.get("detector") or ""),
            source=str(raw.get("source") or ""),
            first_seen=_parse_datetime(raw.get("first_seen")),
            last_seen=_parse_datetime(raw.get("last_seen")),
            last_active_at=_parse_datetime(raw.get("last_active_at")),
            version=str(raw.get("version") or ""),
            component=AIUsageComponent.from_mapping(component_raw if isinstance(component_raw, Mapping) else None),
            runtime=AIUsageRuntime.from_mapping(runtime_raw if isinstance(runtime_raw, Mapping) else None),
            evidence_types=evidence_types,
        )


@dataclass(frozen=True)
class AIUsageSummary:
    scan_id: str = ""
    scanned_at: datetime | None = None
    privacy_mode: str = ""
    result: str = ""
    total_signals: int = 0
    active_signals: int = 0
    new_signals: int = 0
    changed_signals: int = 0
    gone_signals: int = 0
    files_scanned: int = 0

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> AIUsageSummary:
        if not raw:
            return cls()
        return cls(
            scan_id=str(raw.get("scan_id") or ""),
            scanned_at=_parse_datetime(raw.get("scanned_at")),
            privacy_mode=str(raw.get("privacy_mode") or ""),
            result=str(raw.get("result") or ""),
            total_signals=int(raw.get("total_signals") or 0),
            active_signals=int(raw.get("active_signals") or 0),
            new_signals=int(raw.get("new_signals") or 0),
            changed_signals=int(raw.get("changed_signals") or 0),
            gone_signals=int(raw.get("gone_signals") or 0),
            files_scanned=int(raw.get("files_scanned") or 0),
        )


@dataclass(frozen=True)
class AIUsageSnapshot:
    enabled: bool = False
    summary: AIUsageSummary = field(default_factory=AIUsageSummary)
    signals: tuple[AIUsageSignal, ...] = ()
    fetched_at: datetime | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> AIUsageSnapshot:
        signals_raw = raw.get("signals") or ()
        signals = tuple(
            AIUsageSignal.from_mapping(signal)
            for signal in signals_raw
            if isinstance(signal, Mapping)
        )
        summary_raw = raw.get("summary")
        return cls(
            enabled=bool(raw.get("enabled")),
            summary=AIUsageSummary.from_mapping(summary_raw if isinstance(summary_raw, Mapping) else None),
            signals=signals,
            fetched_at=_parse_datetime(raw.get("fetched_at")) or _parse_datetime(raw.get("fetchedAt")),
        )

    @classmethod
    def from_json(cls, text: str) -> AIUsageSnapshot:
        raw = json.loads(text)
        if not isinstance(raw, Mapping):
            raise ValueError("parse ai usage json: expected object")
        return cls.from_mapping(raw)


@dataclass(frozen=True)
class AIDiscoveryRow:
    state: str = ""
    product: str = ""
    vendor: str = ""
    ecosystem: str = ""
    component: str = ""
    version: str = ""
    categories: tuple[str, ...] = ()
    detectors: tuple[str, ...] = ()
    identity_score: float = 0.0
    identity_band: str = ""
    presence_score: float = 0.0
    presence_band: str = ""
    count: int = 0
    last_active_at: datetime | None = None
    signals: tuple[AIUsageSignal, ...] = ()

    @property
    def component_label(self) -> str:
        if self.ecosystem and self.component:
            return f"{self.component} ({self.ecosystem})"
        return self.component

    @property
    def identity_label(self) -> str:
        return format_confidence(self.identity_score, self.identity_band)

    @property
    def presence_label(self) -> str:
        return format_confidence(self.presence_score, self.presence_band)


@dataclass(frozen=True)
class AIDiscoveryCommandIntent:
    label: str
    args: tuple[str, ...]
    binary: str = "defenseclaw"
    category: str = "info"
    hint: str = ""

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


@dataclass(frozen=True)
class AIDiscoveryPanelAction:
    handled: bool
    intent: AIDiscoveryCommandIntent | None = None
    hint: str = ""
    detail_opened: bool = False
    detail_closed: bool = False


class AIDiscoveryPanelModel:
    """Pure grouped-row model for the AI Discovery panel."""

    def __init__(self) -> None:
        self.snapshot: AIUsageSnapshot | None = None
        self.rows: tuple[AIDiscoveryRow, ...] = ()
        self.filtered: tuple[AIDiscoveryRow, ...] = ()
        self.cursor = 0
        self.width = 0
        self.height = 0
        self.filter_text = ""
        self.filtering = False
        self.detail_open = False
        self.detail_row: AIDiscoveryRow | None = None
        self.message = ""

    def set_snapshot(self, snapshot: AIUsageSnapshot | None) -> None:
        self.snapshot = snapshot
        self._rebuild()

    def set_size(self, width: int, height: int) -> None:
        self.width = width
        self.height = height

    def start_filter(self) -> None:
        self.filtering = True

    def stop_filter(self) -> None:
        self.filtering = False

    def set_filter(self, text: str) -> None:
        self.filter_text = text
        self._apply_filter()

    def clear_filter(self) -> None:
        self.filter_text = ""
        self.filtering = False
        self._apply_filter()

    def selected(self) -> AIDiscoveryRow | None:
        if 0 <= self.cursor < len(self.filtered):
            return self.filtered[self.cursor]
        return None

    def cursor_up(self) -> None:
        if self.cursor > 0:
            self.cursor -= 1

    def cursor_down(self) -> None:
        if self.cursor < len(self.filtered) - 1:
            self.cursor += 1

    def set_cursor(self, index: int) -> None:
        self.cursor = max(0, min(index, max(len(self.filtered) - 1, 0)))

    def cursor_at(self) -> int:
        return self.cursor

    def scroll_offset(self) -> int:
        visible = self.height - 6
        if visible < 5:
            visible = 5
        if visible > len(self.filtered):
            visible = len(self.filtered)
        if visible <= 0:
            return 0
        if self.cursor >= visible:
            return self.cursor - visible + 1
        return 0

    def toggle_detail(self) -> None:
        if self.detail_open:
            self.detail_open = False
            self.detail_row = None
            return
        row = self.selected()
        if row is None:
            return
        self.detail_row = row
        self.detail_open = True

    def load_intent(self) -> AIDiscoveryCommandIntent:
        return AIDiscoveryCommandIntent(
            label="agent usage --json",
            args=("agent", "usage", "--json"),
            hint="Refreshing AI discovery snapshot...",
        )

    def scan_intent(self) -> AIDiscoveryCommandIntent:
        return AIDiscoveryCommandIntent(
            label="agent discover",
            args=("agent", "discover"),
            hint="Starting AI discovery scan...",
        )

    def handle_key(self, key: str) -> AIDiscoveryPanelAction:
        if key in {"j", "down"}:
            self.cursor_down()
            return AIDiscoveryPanelAction(True)
        if key in {"k", "up"}:
            self.cursor_up()
            return AIDiscoveryPanelAction(True)
        if key == "esc" and self.detail_open:
            self.toggle_detail()
            return AIDiscoveryPanelAction(True, detail_closed=True)
        if key == "enter":
            if self.selected() is None:
                return AIDiscoveryPanelAction(True, hint="(no AI discovery row selected)")
            self.toggle_detail()
            return AIDiscoveryPanelAction(True, detail_opened=self.detail_open)
        if key == "r":
            return AIDiscoveryPanelAction(True, self.load_intent())
        if key == "s":
            return AIDiscoveryPanelAction(True, self.scan_intent())
        return AIDiscoveryPanelAction(False)

    def empty_state(self) -> str:
        if self.snapshot is None:
            return (
                "AI discovery snapshot not yet available. "
                "Ensure the gateway is running and DEFENSECLAW_GATEWAY_TOKEN matches the configured token."
            )
        if not self.snapshot.enabled:
            return "AI discovery disabled. Run: defenseclaw agent discovery enable"
        if self.filter_text and not self.filtered:
            return "No matching signals."
        if not self.rows:
            return "No AI agents detected yet. Run: defenseclaw agent discover"
        return ""

    def header_parts(self) -> tuple[str, ...]:
        if self.snapshot is None:
            return ()
        summary = self.snapshot.summary
        parts = [f"active={summary.active_signals}"]
        if summary.new_signals:
            parts.append(f"new={summary.new_signals}")
        if summary.changed_signals:
            parts.append(f"changed={summary.changed_signals}")
        if summary.gone_signals:
            parts.append(f"gone={summary.gone_signals}")
        parts.append(f"files={summary.files_scanned}")
        return tuple(parts)

    def detail_header(self) -> str:
        if self.detail_row is None:
            return ""
        row = self.detail_row
        segments = [row.state, row.product]
        if row.component:
            segments.append(row.component_label)
        return f"{' - '.join(part for part in segments if part)} x {row.count} signal(s)"

    def detail_lines(self, *, limit: int = 50, now: datetime | None = None) -> tuple[str, ...]:
        if self.detail_row is None:
            return ()
        now = now or datetime.now(timezone.utc)
        lines: list[str] = []
        for index, signal in enumerate(self.detail_row.signals):
            if index >= limit:
                lines.append(
                    f"...and {len(self.detail_row.signals) - index} more "
                    "(use `defenseclaw agent usage --detail --json` for the full list)"
                )
                break
            lines.append(sig_id(signal))
            if signal.detector or signal.source:
                source = f" source={signal.source}" if signal.source else ""
                lines.append(f"detector={signal.detector}{source}".strip())
            if signal.runtime and signal.runtime.pid > 0:
                parts = [f"runtime: pid={signal.runtime.pid}"]
                if signal.runtime.user:
                    parts.append(f"user={signal.runtime.user}")
                if signal.runtime.uptime_sec:
                    parts.append(f"up={humanize_age(timedelta(seconds=signal.runtime.uptime_sec))}")
                if signal.runtime.comm:
                    parts.append(f"comm={signal.runtime.comm}")
                lines.append(" ".join(parts))
            if signal.last_active_at:
                lines.append(f"last active: {humanize_age(now - signal.last_active_at)} ago")
            elif signal.last_seen:
                lines.append(f"last seen: {humanize_age(now - signal.last_seen)} ago")
        return tuple(lines)

    def data_table_columns(self) -> tuple[str, ...]:
        return (
            "State",
            "Categories",
            "Product",
            "Component",
            "Version",
            "Vendor",
            "Detectors",
            "Count",
            "Identity",
            "Presence",
        )

    def data_table_rows(self) -> tuple[tuple[str, ...], ...]:
        return tuple(
            (
                row.state,
                format_csv_truncated(row.categories, 2),
                row.product,
                row.component_label,
                row.version,
                row.vendor,
                format_csv_truncated(row.detectors, 2),
                str(row.count),
                row.identity_label,
                row.presence_label,
            )
            for row in self.filtered
        )

    def _rebuild(self) -> None:
        self.rows = ()
        if self.snapshot is None:
            self._apply_filter()
            return

        groups: dict[tuple[str, str, str, str, str, str], _MutableAIDiscoveryRow] = {}
        order: list[tuple[str, str, str, str, str, str]] = []
        for signal in self.snapshot.signals:
            ecosystem = ""
            component_name = ""
            version = signal.version
            if signal.component:
                ecosystem = signal.component.ecosystem.lower()
                component_name = signal.component.name.lower()
                if signal.component.version:
                    version = signal.component.version
            key = (signal.state, signal.product, signal.vendor, ecosystem, component_name, version)
            row = groups.get(key)
            if row is None:
                row = _MutableAIDiscoveryRow(
                    state=signal.state,
                    product=signal.product,
                    vendor=signal.vendor,
                    ecosystem=signal.component.ecosystem if signal.component else "",
                    component=signal.component.name if signal.component else "",
                    version=version,
                )
                groups[key] = row
                order.append(key)
            row.add(signal)

        rows = [groups[key].freeze() for key in order]
        self.rows = tuple(
            sorted(
                rows,
                key=lambda row: (state_weight(row.state), -row.count, row.product),
            )
        )
        self._apply_filter()

    def _apply_filter(self) -> None:
        if not self.filter_text:
            self.filtered = self.rows
        else:
            query = self.filter_text.lower()
            filtered: list[AIDiscoveryRow] = []
            for row in self.rows:
                parts: list[str] = [
                    row.state,
                    row.product,
                    row.vendor,
                    row.ecosystem,
                    row.component,
                    row.version,
                    row.identity_band,
                    row.presence_band,
                    *row.categories,
                    *row.detectors,
                ]
                if query in " ".join(parts).lower():
                    filtered.append(row)
            self.filtered = tuple(filtered)
        self.set_cursor(self.cursor)


@dataclass
class _MutableAIDiscoveryRow:
    state: str = ""
    product: str = ""
    vendor: str = ""
    ecosystem: str = ""
    component: str = ""
    version: str = ""
    categories: list[str] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)
    identity_score: float = 0.0
    identity_band: str = ""
    presence_score: float = 0.0
    presence_band: str = ""
    count: int = 0
    last_active_at: datetime | None = None
    signals: list[AIUsageSignal] = field(default_factory=list)

    def add(self, signal: AIUsageSignal) -> None:
        self.count += 1
        self.signals.append(signal)
        if signal.category and signal.category not in self.categories:
            self.categories.append(signal.category)
        if signal.detector and signal.detector not in self.detectors:
            self.detectors.append(signal.detector)
        if not self.identity_band and signal.identity_band:
            self.identity_band = signal.identity_band
            self.identity_score = signal.identity_score
        if not self.presence_band and signal.presence_band:
            self.presence_band = signal.presence_band
            self.presence_score = signal.presence_score
        if signal.last_active_at and (
            self.last_active_at is None or signal.last_active_at > self.last_active_at
        ):
            self.last_active_at = signal.last_active_at

    def freeze(self) -> AIDiscoveryRow:
        return AIDiscoveryRow(
            state=self.state,
            product=self.product,
            vendor=self.vendor,
            ecosystem=self.ecosystem,
            component=self.component,
            version=self.version,
            categories=tuple(self.categories),
            detectors=tuple(self.detectors),
            identity_score=self.identity_score,
            identity_band=self.identity_band,
            presence_score=self.presence_score,
            presence_band=self.presence_band,
            count=self.count,
            last_active_at=self.last_active_at,
            signals=tuple(self.signals),
        )


def state_weight(state: str) -> int:
    match state.strip().lower():
        case "new":
            return 0
        case "changed":
            return 1
        case "active":
            return 2
        case "seen":
            return 3
        case "gone":
            return 4
        case _:
            return 9


def format_confidence(score: float, band: str) -> str:
    band = band.strip()
    if not band and score == 0:
        return ""
    pct = int(score * 100 + 0.5)
    if not band:
        return f"{pct}%"
    return f"{band} ({pct}%)"


def humanize_age(delta: timedelta) -> str:
    if delta.total_seconds() < 0:
        delta = -delta
    seconds = int(delta.total_seconds())
    if seconds < 1:
        return "0s"
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 24:
        rem_minutes = minutes - hours * 60
        if rem_minutes == 0:
            return f"{hours}h"
        return f"{hours}h{rem_minutes}m"
    days = hours // 24
    rem_hours = hours % 24
    if rem_hours == 0:
        return f"{days}d"
    return f"{days}d{rem_hours}h"


def format_csv_truncated(items: Sequence[str], limit: int) -> str:
    if not items:
        return ""
    if limit <= 0 or limit > len(items):
        return ", ".join(items)
    head = ", ".join(items[:limit])
    extra = len(items) - limit
    if extra > 0:
        return f"{head} (+{extra})"
    return head


def sig_id(signal: AIUsageSignal) -> str:
    for candidate in (signal.signature_id, signal.name, signal.signal_id):
        if candidate.strip():
            return candidate.strip()
    return "(unknown)"


__all__ = [
    "AIDiscoveryCommandIntent",
    "AIDiscoveryPanelAction",
    "AIDiscoveryPanelModel",
    "AIDiscoveryRow",
    "AIDiscoveryState",
    "AIUsageComponent",
    "AIUsageRuntime",
    "AIUsageSignal",
    "AIUsageSnapshot",
    "AIUsageSummary",
    "format_confidence",
    "format_csv_truncated",
    "humanize_age",
    "sig_id",
    "state_weight",
]
