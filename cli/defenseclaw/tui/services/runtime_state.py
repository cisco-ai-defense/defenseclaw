# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure row model for the AI Discovery Runtime panel.

Where the AI Discovery panel renders what is present on the host, this renders
what actually ran. It is deliberately a separate panel rather than more columns
on the existing one: the two answer different questions, they fail
independently, and an operator reading a healthy inventory as evidence of
runtime coverage would draw exactly the wrong conclusion.

No I/O happens here. The panel is fed a decoded snapshot so every rendering
decision is testable from a fixture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

#: Severity order, worst first. Used for sorting and for the scope filter.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}


class RuntimePanelAction(Enum):
    """What a keypress asked the panel to do."""

    NONE = "none"
    REFRESH = "refresh"
    SCAN = "scan"
    OPEN_DETAIL = "open_detail"
    CLOSE_DETAIL = "close_detail"
    TOGGLE_PLANES = "toggle_planes"
    START_FILTER = "start_filter"


@dataclass(frozen=True)
class RuntimeCommandIntent:
    """A CLI command the panel wants the app to run on its behalf."""

    argv: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class PlaneRow:
    """One plane's health, as rendered in the always-visible strip."""

    plane: str
    name: str
    available: bool
    running: bool
    mechanism: str = ""
    reason: str = ""

    @property
    def badge(self) -> str:
        if self.running:
            return "up"
        if self.available:
            return "idle"
        return "blind"

    @property
    def summary(self) -> str:
        """One line an operator can act on.

        A blind or idle plane always states why. This is the whole reason the
        strip is always visible: a detector reporting clean because it was
        never able to look is indistinguishable, on a dashboard, from a host
        that is genuinely clean.
        """
        if self.running:
            return f"{self.name}: up via {self.mechanism or 'unknown mechanism'}"
        detail = self.reason or "no reason reported"
        if self.available:
            return f"{self.name}: available but not running -- {detail}"
        return f"{self.name}: unavailable -- {detail}"


@dataclass(frozen=True)
class RuntimeRow:
    """One scored finding."""

    finding_id: str
    pid: int
    process: str
    cmdline: str
    user: str
    agent_name: str
    score: int
    severity: str
    signals: tuple[tuple[str, str, int], ...]
    providers: tuple[tuple[str, str], ...]
    correlation_verdict: str
    correlation_reason: str
    first_seen: str
    last_seen: str

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK.get(self.severity, len(SEVERITY_ORDER))

    @property
    def provider_summary(self) -> str:
        if not self.providers:
            return "-"
        return ", ".join(hostname for hostname, _category in self.providers)

    @property
    def chain(self) -> str:
        """The observed sequence, when this finding is a chain.

        Rendered as a sequence rather than a set because the order is the
        finding: reading a credential is a lead, and reading a credential then
        minting an identity then uploading is an incident.
        """
        for signal_id, detail, _weight in self.signals:
            if signal_id == "agent_kill_chain":
                return detail
        return ""

    def matches(self, needle: str) -> bool:
        if not needle:
            return True
        lowered = needle.lower()
        haystack = " ".join([
            self.process, self.cmdline, self.user, self.agent_name,
            self.severity, self.provider_summary, self.correlation_verdict,
        ]).lower()
        return lowered in haystack


@dataclass
class RuntimeSnapshot:
    """The decoded runtime-plane snapshot."""

    enabled: bool = False
    scanned_at: str = ""
    rows: tuple[RuntimeRow, ...] = ()
    planes: tuple[PlaneRow, ...] = ()
    processes_observed: int = 0
    processes_skipped: int = 0
    connections_observed: int = 0
    connections_unattributed: int = 0
    degraded: bool = False
    degraded_reasons: tuple[str, ...] = field(default_factory=tuple)


def decode_runtime_snapshot(payload: Any) -> RuntimeSnapshot:
    """Decode the gateway response.

    Tolerant by design: an older gateway that does not send a field yields the
    zero value rather than an exception, because a TUI that crashes on a
    version skew is worse than one that renders less.
    """
    if not isinstance(payload, dict):
        return RuntimeSnapshot()

    planes: list[PlaneRow] = []
    for raw in payload.get("planes") or []:
        if not isinstance(raw, dict):
            continue
        planes.append(PlaneRow(
            plane=str(raw.get("plane") or ""),
            name=str(raw.get("name") or raw.get("plane") or "plane"),
            available=bool(raw.get("available")),
            running=bool(raw.get("running")),
            mechanism=str(raw.get("mechanism") or ""),
            reason=str(raw.get("reason") or ""),
        ))

    rows: list[RuntimeRow] = []
    for raw in payload.get("findings") or []:
        if not isinstance(raw, dict):
            continue
        signals = tuple(
            (str(s.get("id") or ""), str(s.get("detail") or s.get("title") or ""), int(s.get("weight") or 0))
            for s in (raw.get("signals") or []) if isinstance(s, dict)
        )
        providers = tuple(
            (str(p.get("hostname") or ""), str(p.get("category") or ""))
            for p in (raw.get("providers") or []) if isinstance(p, dict)
        )
        correlation = raw.get("correlation") or {}
        rows.append(RuntimeRow(
            finding_id=str(raw.get("finding_id") or ""),
            pid=int(raw.get("pid") or 0),
            process=str(raw.get("process") or ""),
            cmdline=str(raw.get("cmdline") or ""),
            user=str(raw.get("user") or ""),
            agent_name=str(raw.get("agent_name") or ""),
            score=int(raw.get("score") or 0),
            severity=str(raw.get("severity") or "info"),
            signals=signals,
            providers=providers,
            correlation_verdict=str(correlation.get("verdict") or ""),
            correlation_reason=str(correlation.get("reason") or ""),
            first_seen=str(raw.get("first_seen") or ""),
            last_seen=str(raw.get("last_seen") or ""),
        ))
    rows.sort(key=lambda row: (row.rank, -row.score, row.process, row.pid))

    return RuntimeSnapshot(
        enabled=bool(payload.get("enabled")),
        scanned_at=str(payload.get("scanned_at") or ""),
        rows=tuple(rows),
        planes=tuple(planes),
        processes_observed=int(payload.get("processes_observed") or 0),
        processes_skipped=int(payload.get("processes_skipped") or 0),
        connections_observed=int(payload.get("connections_observed") or 0),
        connections_unattributed=int(payload.get("connections_unattributed") or 0),
        degraded=bool(payload.get("degraded")),
        degraded_reasons=tuple(str(reason) for reason in (payload.get("degraded_reasons") or [])),
    )


class RuntimePanelModel:
    """Pure row model for the Runtime panel."""

    def __init__(self) -> None:
        self.snapshot = RuntimeSnapshot()
        self.filtered: tuple[RuntimeRow, ...] = ()
        self.cursor = 0
        self.filter_text = ""
        self.filtering = False
        self.detail_open = False
        self.planes_expanded = False
        self.message = ""

    def set_snapshot(self, payload: Any) -> None:
        self.snapshot = decode_runtime_snapshot(payload)
        self._apply_filter()

    def set_filter(self, text: str) -> None:
        self.filter_text = text
        self._apply_filter()

    def clear_filter(self) -> None:
        self.filter_text = ""
        self.filtering = False
        self._apply_filter()

    def _apply_filter(self) -> None:
        self.filtered = tuple(row for row in self.snapshot.rows if row.matches(self.filter_text))
        if self.cursor >= len(self.filtered):
            self.cursor = max(0, len(self.filtered) - 1)

    def selected(self) -> RuntimeRow | None:
        if not self.filtered or not 0 <= self.cursor < len(self.filtered):
            return None
        return self.filtered[self.cursor]

    def data_table_columns(self) -> tuple[str, ...]:
        return ("Severity", "Score", "Process", "PID", "Agent", "Providers", "Inventory")

    def data_table_rows(self) -> tuple[tuple[str, ...], ...]:
        return tuple(
            (
                row.severity,
                str(row.score),
                row.process,
                str(row.pid),
                row.agent_name or "-",
                row.provider_summary,
                row.correlation_verdict or "-",
            )
            for row in self.filtered
        )

    def empty_state(self) -> str:
        if not self.snapshot.enabled:
            return (
                "The runtime planes are disabled.\n"
                "Enable with: defenseclaw agent discovery runtime enable"
            )
        if not self.snapshot.scanned_at:
            return "The runtime planes have not completed a poll yet."
        return "No findings at or above the reporting floor."

    def header_parts(self) -> tuple[str, ...]:
        """The header line.

        Coverage is part of the header rather than a detail view, because a
        reader who sees only the finding count cannot tell a quiet host from a
        blind sensor.
        """
        parts = [f"{len(self.filtered)}/{len(self.snapshot.rows)} findings"]
        if self.snapshot.scanned_at:
            parts.append(f"polled {self.snapshot.scanned_at}")
        parts.append(
            f"{self.snapshot.processes_observed} processes"
            + (f" ({self.snapshot.processes_skipped} partial)" if self.snapshot.processes_skipped else "")
        )
        parts.append(
            f"{self.snapshot.connections_observed} connections"
            + (
                f" ({self.snapshot.connections_unattributed} unattributed)"
                if self.snapshot.connections_unattributed
                else ""
            )
        )
        if self.snapshot.degraded:
            parts.append("DEGRADED")
        return tuple(parts)

    def plane_strip(self) -> tuple[str, ...]:
        """The always-visible plane strip."""
        if not self.snapshot.planes:
            return ("plane health unavailable: the gateway reported no planes",)
        if self.planes_expanded:
            return tuple(plane.summary for plane in self.snapshot.planes)
        return tuple(f"{plane.name}: {plane.badge}" for plane in self.snapshot.planes)

    def detail_text(self) -> str:
        row = self.selected()
        if row is None:
            return ""
        lines = [
            f"{row.severity.upper()}  score {row.score}",
            f"process   {row.process} (pid {row.pid}, user {row.user or 'unknown'})",
        ]
        if row.agent_name:
            lines.append(f"agent     {row.agent_name}")
        if row.cmdline:
            lines.append(f"cmdline   {row.cmdline}")
        if row.chain:
            lines.append("")
            lines.append(f"chain     {row.chain}")
        if row.providers:
            lines.append("")
            lines.append("providers")
            for hostname, category in row.providers:
                lines.append(f"  {hostname}  ({category or 'uncategorised'})")
        lines.append("")
        lines.append("signals")
        for signal_id, detail, weight in row.signals:
            suffix = f"  {detail}" if detail else ""
            lines.append(f"  +{weight:<3} {signal_id}{suffix}")
        lines.append("")
        # Always shown, including "unobserved". Omitting it would let a reader
        # mistake blindness for agreement.
        lines.append(f"inventory {row.correlation_verdict or 'unknown'}")
        if row.correlation_reason:
            lines.append(f"          {row.correlation_reason}")
        return "\n".join(lines)

    def handle_key(self, key: str) -> RuntimePanelAction:
        if self.detail_open:
            if key in {"escape", "enter", "q"}:
                self.detail_open = False
                return RuntimePanelAction.CLOSE_DETAIL
            return RuntimePanelAction.NONE
        if key == "r":
            return RuntimePanelAction.REFRESH
        if key == "s":
            return RuntimePanelAction.SCAN
        if key == "p":
            self.planes_expanded = not self.planes_expanded
            return RuntimePanelAction.TOGGLE_PLANES
        if key == "/":
            self.filtering = True
            return RuntimePanelAction.START_FILTER
        if key == "enter" and self.selected() is not None:
            self.detail_open = True
            return RuntimePanelAction.OPEN_DETAIL
        if key in {"down", "j"}:
            if self.filtered:
                self.cursor = min(self.cursor + 1, len(self.filtered) - 1)
            return RuntimePanelAction.NONE
        if key in {"up", "k"}:
            self.cursor = max(self.cursor - 1, 0)
            return RuntimePanelAction.NONE
        return RuntimePanelAction.NONE

    def command_for(self, action: RuntimePanelAction) -> RuntimeCommandIntent | None:
        if action is RuntimePanelAction.SCAN:
            return RuntimeCommandIntent(
                argv=("agent", "discovery", "runtime", "scan"),
                description="Poll the runtime planes now",
            )
        if action is RuntimePanelAction.REFRESH:
            return RuntimeCommandIntent(
                argv=("agent", "discovery", "runtime", "status"),
                description="Re-read the last runtime snapshot",
            )
        return None
