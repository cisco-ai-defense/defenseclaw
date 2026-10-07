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

import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from defenseclaw.kernel_sensor import (
    admin_command,
    kernel_controls_line,
    kernel_sensor_summary,
    your_policies_line,
)

#: Severity order, worst first. Used for sorting and for the scope filter.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}


def _selected_plane_gap(plane: PlaneRow) -> bool:
    """True when a down plane was asked to run, not merely left as an opt-in."""

    reason = plane.reason.lower()
    if "not selected" in reason or "enable_host_plane" in reason:
        return False
    return True



def _int(value: object) -> int:
    """Tolerant int: a non-numeric pid or count must not crash the poll."""

    try:
        return int(value or 0)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return 0

class RuntimePanelAction(Enum):
    """What a keypress asked the panel to do."""

    NONE = "none"
    REFRESH = "refresh"
    SCAN = "scan"
    ENABLE = "enable"
    OPEN_DETAIL = "open_detail"
    CLOSE_DETAIL = "close_detail"
    TOGGLE_PLANES = "toggle_planes"
    START_FILTER = "start_filter"
    # The cursor or the filter text changed: redraw the table.
    MOVE = "move"


@dataclass(frozen=True)
class RuntimeCommandIntent:
    """A CLI command the panel wants the app to run on its behalf."""

    argv: tuple[str, ...]
    description: str


#: DefenseClaw's own Tetragon policy names end in an 8-hex digest suffix; the
#: family in front of it is what an operator recognises.
_POLICY_NAME = re.compile(r"^defenseclaw-(observe|connect|controls-burnin|controls)-[0-9a-f]{8}$")

#: Most failing policies listed under the plane, so a bad load cannot push the
#: findings table off an 80x24 screen.
_MAX_POLICY_ERRORS = 2

#: Gateway-supplied free text is clipped before it reaches the screen.
_MAX_DETAIL = 80


def _clip(text: str, limit: int = _MAX_DETAIL) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


@dataclass(frozen=True)
class KernelPolicyRow:
    """One DefenseClaw policy the kernel sensor has loaded."""

    name: str
    mode: str = ""
    state: str = ""
    error: str = ""

    @property
    def family(self) -> str:
        match = _POLICY_NAME.match(self.name)
        return match.group(1) if match else self.name

    @property
    def healthy(self) -> bool:
        return not self.error and self.state in {"", "enabled"}


@dataclass(frozen=True)
class PlaneRow:
    """One plane's health, as rendered in the always-visible strip."""

    plane: str
    name: str
    available: bool
    running: bool
    mechanism: str = ""
    reason: str = ""
    # Kernel sensor behind plane C on a managed Linux host. Only the sensor
    # helper reports it, so every other gateway leaves these at their zero
    # values and the plane reads exactly as before.
    backend_kind: str = ""
    backend_version: str = ""
    backend_mode: str = ""
    kernel_policies: tuple[KernelPolicyRow, ...] = ()
    #: The ``backend`` object as the gateway sent it. The shared formatters in
    #: ``defenseclaw.kernel_sensor`` read it, so this panel, the doctor row and
    #: ``runtime status`` word the same facts the same way.
    backend: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)
    kernel_paused_until: str = ""
    #: ``paused until 14:05Z by alice``; empty when the kernel controls run.
    kernel_paused_label: str = ""

    @property
    def is_tetragon(self) -> bool:
        return self.backend_kind == "tetragon"

    @property
    def backend_label(self) -> str:
        """``Tetragon 1.7.1, observe`` when Tetragon is the Plane C backend."""

        if not self.is_tetragon:
            return ""
        return ", ".join(part for part in (f"Tetragon {self.backend_version}".strip(), self.backend_mode) if part)

    @property
    def strip_label(self) -> str:
        """The badge in the one-line strip: ``agent actions: up (Tetragon, enforce)``."""

        text = f"{self.name}: {self.badge}"
        if self.is_tetragon:
            state = "paused" if self.kernel_paused_until else self.backend_mode
            text += f" (Tetragon, {state})" if state else " (Tetragon)"
        return text

    def detail_lines(self) -> tuple[str, ...]:
        """Kernel sensor facts for the expanded plane view; empty without a backend.

        Plain text: the caller escapes it. Each line is at most 77 columns for
        the longest realistic values, and the whole block is bounded, so it
        never crowds the findings table.
        """

        lines: list[str] = []
        sensor = kernel_sensor_summary(self.backend)
        if sensor:
            lines.append(f"kernel sensor: {sensor}")
        floor = self.backend.get("kernel_floor")
        controls = kernel_controls_line(floor if isinstance(floor, Mapping) else None)
        if controls:
            lines.append(f"kernel controls: {controls}")
        activity = [_blocks_text(floor if isinstance(floor, Mapping) else {}), your_policies_line(self.backend)]
        activity = [part for part in activity if part]
        if activity:
            lines.append("; ".join(activity))
        if self.kernel_policies:
            healthy = [policy for policy in self.kernel_policies if policy.healthy]
            broken = [policy for policy in self.kernel_policies if not policy.healthy]
            parts = [f"{policy.family} {policy.mode or 'loaded'}" for policy in healthy]
            if broken:
                parts.append(f"{len(broken)} not loaded")
            lines.append("policies: " + ", ".join(parts))
            for policy in broken[:_MAX_POLICY_ERRORS]:
                why = _clip(policy.error or policy.state or "not loaded")
                lines.append(f"  {policy.family}: {why}")
        if self.kernel_paused_until:
            # Root runs it, and the binaries are not on PATH: print what runs.
            lines.append(f"{self.kernel_paused_label}; root can resume it with")
            lines.append(admin_command("enterprise", "linux", "tetragon", "resume"))
        return tuple(lines)

    @property
    def badge(self) -> str:
        if self.running:
            # Running with a stated limit (a non-elevated gateway sees only
            # its own sockets) is partial coverage, as selftest says (GAP-1377).
            return "partial" if self.reason else "up"
        if not _selected_plane_gap(self):
            # An opt-in plane nobody selected is off, not a broken sensor
            # (GAP-2102): "blind" read as a failure.
            return "off"
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
            via = self.mechanism or "unknown mechanism"
            sensor = ""
            if self.is_tetragon:
                # The mechanism usually names Tetragon already: add only the mode then.
                named = "tetragon" in via.lower()
                sensor = f" ({self.backend_mode} mode)" if named and self.backend_mode else (
                    "" if named else f" ({self.backend_label})"
                )
            if self.reason:
                return f"{self.name}: partial via {via}{sensor} -- {self.reason}"
            return f"{self.name}: up via {via}{sensor}"
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
    #: What the kernel did to this agent and what the customer's own Tetragon
    #: policies saw, one short line each (at most 3). Empty on older gateways.
    kernel_notes: tuple[str, ...] = ()

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
    host_plane_observations: int = 0
    host_plane_gated: int = 0
    degraded: bool = False
    degraded_reasons: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RuntimeOverview:
    """Compact Runtime facts for Overview. Absence is a zero value, not an error."""

    health_title: str = ""
    enabled: bool = False
    scanned: bool = False
    findings: int = 0
    unobserved: int = 0
    processes: int = 0
    connections: int = 0
    host_observations: int = 0
    host_gated: int = 0
    plane_summary: str = ""
    context: str = ""
    top_findings: tuple[str, ...] = ()
    next_action: str = ""
    # Why the badge says DEGRADED, in a few words (e.g. "partial coverage:
    # shadow-egress idle"), so Overview can say it without the Runtime tab.
    degraded_reason: str = ""


_OUTCOME_WORDS = {"observed": "observed", "would_block": "would have blocked", "blocked": "blocked"}
_OUTCOME_RANK = {"blocked": 0, "would_block": 1, "observed": 2}

#: Notes under a selected finding: the kernel control line(s) and the customer's
#: policy line(s) together stay within this, so the detail never grows with the
#: number of events.
_MAX_KERNEL_NOTES = 3


def _blocks_text(floor: Mapping[str, Any]) -> str:
    """``blocks (1h): 2 denied, 5 would-block``; empty unless the helper reports the counts."""

    if "blocked_1h" not in floor and "would_block_1h" not in floor:
        return ""
    return f"blocks (1h): {_int(floor.get('blocked_1h'))} denied, {_int(floor.get('would_block_1h'))} would-block"


def _paused_label(until: str, by: str, scanned_at: str) -> str:
    """``paused until 14:05Z by alice`` (the date only when it is not the poll's day)."""

    if until == "reboot":
        when = "the next reboot"
    else:
        when = _clip(until, 40)
        if len(until) >= 16 and until[10] == "T" and until.endswith("Z"):
            clock = until[11:16] + "Z"
            when = clock if scanned_at[:10] == until[:10] else f"{until[:10]} {clock}"
    who = _clip(by, 32)
    return f"paused until {when}" + (f" by {who}" if who else "")


def _kernel_activity_notes(raw: Any) -> list[str]:
    """``kernel: blocked kernel.ssh_private_key_read (hook: exact)`` per distinct kernel outcome."""

    notes: list[str] = []
    if not isinstance(raw, list):
        return notes
    for item in raw:
        if not isinstance(item, dict):
            continue
        outcome = str(item.get("kernel_outcome") or "").strip().lower()
        words = _OUTCOME_WORDS.get(outcome)
        if words is None or outcome == "observed":
            continue
        control = _clip(str(item.get("kernel_control") or "a kernel control"), 48)
        join = str(item.get("hook_join") or "").strip().lower()
        if join in {"exact", "temporal"}:
            hook = f" (hook: {join})"
        elif item.get("hook_seen") is False:
            hook = " (no hook decision)"
        else:
            hook = ""
        note = f"kernel: {words} {control}{hook}"
        if note not in notes:
            notes.append(note)
    return notes[:2]


def _decode_customer_events(raw: Any) -> list[dict[str, Any]]:
    """The runtime API's ``customer_kernel_events``: events of the customer's own policies."""

    events: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return events
    for item in raw:
        if not isinstance(item, dict):
            continue
        policy = str(item.get("policy_name") or item.get("policy") or "").strip()
        if not policy:
            continue
        events.append({
            "policy": policy,
            "function": str(item.get("function") or "").strip(),
            "outcome": str(item.get("outcome") or "observed").strip().lower(),
            "process": str(item.get("process") or "").strip(),
            "count": max(1, _int(item.get("count"))),
            "pids": {_int(item.get("pid")), _int(item.get("root_pid"))} - {0},
            "finding_id": str(item.get("finding_id") or ""),
        })
    return events


def _policy_notes(events: list[dict[str, Any]], finding_id: str, pid: int) -> list[str]:
    """``your policy file-sensitive: observed security_file_open by cat``, worst outcome first."""

    folded: dict[tuple[str, str, str, str], int] = {}
    for event in events:
        if event["finding_id"]:
            if event["finding_id"] != finding_id:
                continue
        elif pid not in event["pids"]:
            continue
        key = (event["policy"], event["function"], event["outcome"], event["process"])
        folded[key] = folded.get(key, 0) + event["count"]
    notes: list[tuple[int, str]] = []
    for (policy, function, outcome, process), count in folded.items():
        words = _OUTCOME_WORDS.get(outcome, "saw")
        text = f"your policy {_clip(policy, 40)}: {words}"
        if function:
            text += f" {_clip(function, 32)}"
        if process:
            text += f" by {_clip(process, 24)}"
        if count > 1:
            text += f" (x{count})"
        notes.append((_OUTCOME_RANK.get(outcome, 3), text))
    return [text for _rank, text in sorted(notes, key=lambda note: note[0])]


def _decode_backend(raw: Any, scanned_at: str = "") -> dict[str, Any]:
    """Plane C backend fields from ``planes[].backend``; empty when absent.

    Only the managed Linux sensor helper reports a backend. An older gateway,
    or any other platform, sends none, and a malformed value is ignored the
    same way: the plane then renders exactly as it did before the field existed.
    """

    if not isinstance(raw, dict):
        return {}
    fields: dict[str, Any] = {
        "backend_kind": str(raw.get("kind") or "").strip().lower(),
        "backend_version": str(raw.get("version") or "").strip(),
        "backend_mode": str(raw.get("mode") or "").strip().lower(),
        "backend": dict(raw),
    }
    policies = tuple(
        KernelPolicyRow(
            name=str(item.get("name") or ""),
            mode=str(item.get("mode") or "").strip().lower(),
            state=str(item.get("state") or "").strip().lower(),
            error=str(item.get("error") or ""),
        )
        for item in (raw.get("policies") or [])
        if isinstance(item, dict) and item.get("name")
    )
    if policies:
        fields["kernel_policies"] = policies
    floor = raw.get("kernel_floor")
    if isinstance(floor, dict) and floor:
        paused = str(floor.get("paused_until") or "").strip()
        # "resumed" is the gateway's word for a pause record that has ended.
        if paused and paused != "resumed":
            fields["kernel_paused_until"] = paused
            fields["kernel_paused_label"] = _paused_label(paused, str(floor.get("paused_by") or ""), scanned_at)
    return fields


def decode_runtime_snapshot(payload: Any) -> RuntimeSnapshot:
    """Decode the gateway response.

    Tolerant by design: an older gateway that does not send a field yields the
    zero value rather than an exception, because a TUI that crashes on a
    version skew is worse than one that renders less.
    """
    if not isinstance(payload, dict):
        return RuntimeSnapshot()

    scanned_at = str(payload.get("scanned_at") or "")
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
            **_decode_backend(raw.get("backend"), scanned_at),
        ))

    customer_events = _decode_customer_events(payload.get("customer_kernel_events"))
    rows: list[RuntimeRow] = []
    for raw in payload.get("findings") or []:
        if not isinstance(raw, dict):
            continue
        signals = tuple(
            (str(s.get("id") or ""), str(s.get("detail") or s.get("title") or ""), _int(s.get("weight")))
            for s in (raw.get("signals") or []) if isinstance(s, dict)
        )
        providers = tuple(
            (str(p.get("hostname") or ""), str(p.get("category") or ""))
            for p in (raw.get("providers") or []) if isinstance(p, dict)
        )
        correlation = raw.get("correlation") or {}
        rows.append(RuntimeRow(
            finding_id=str(raw.get("finding_id") or ""),
            pid=_int(raw.get("pid")),
            process=str(raw.get("process") or ""),
            cmdline=str(raw.get("cmdline") or ""),
            user=str(raw.get("user") or ""),
            agent_name=str(raw.get("agent_name") or ""),
            score=_int(raw.get("score")),
            severity=str(raw.get("severity") or "info"),
            signals=signals,
            providers=providers,
            correlation_verdict=str(correlation.get("verdict") or ""),
            correlation_reason=str(correlation.get("reason") or ""),
            first_seen=str(raw.get("first_seen") or ""),
            last_seen=str(raw.get("last_seen") or ""),
            kernel_notes=tuple(
                (
                    _kernel_activity_notes(raw.get("activities"))
                    + _policy_notes(customer_events, str(raw.get("finding_id") or ""), _int(raw.get("pid")))
                )[:_MAX_KERNEL_NOTES]
            ),
        ))
    rows.sort(key=lambda row: (row.rank, -row.score, row.process, row.pid))

    return RuntimeSnapshot(
        enabled=bool(payload.get("enabled")),
        scanned_at=scanned_at,
        rows=tuple(rows),
        planes=tuple(planes),
        processes_observed=_int(payload.get("processes_observed")),
        processes_skipped=_int(payload.get("processes_skipped")),
        connections_observed=_int(payload.get("connections_observed")),
        connections_unattributed=_int(payload.get("connections_unattributed")),
        host_plane_observations=_int(payload.get("host_plane_observations")),
        host_plane_gated=_int(payload.get("host_plane_gated")),
        degraded=bool(payload.get("degraded")),
        degraded_reasons=tuple(str(reason) for reason in (payload.get("degraded_reasons") or [])),
    )


class RuntimePanelModel:
    """Pure row model for the Runtime panel."""

    def __init__(self, platform: str | None = None) -> None:
        # The host plane's grant differs per OS; Linux was told to grant
        # macOS Endpoint Security (GAP-1403).
        self.platform = platform or sys.platform
        self.snapshot = RuntimeSnapshot()
        self._inventory_unobserved = 0
        self.filtered: tuple[RuntimeRow, ...] = ()
        self.cursor = 0
        self.filter_text = ""
        self.filtering = False
        self.detail_open = False
        # Expanded by default: a collapsed "name: idle" strip hides why
        # the host is DEGRADED, which is the question this panel exists
        # to answer.
        self.planes_expanded = True
        # Short terminals (under 32 rows) keep their own choice and start on
        # the one-line strip, so a "p" pressed on a tall screen does not
        # expand the planes over the findings table at 80x24 (GAP-1596).
        self.short_screen = False
        self.planes_expanded_short = False
        self.message = ""

    def set_snapshot(self, payload: Any) -> None:
        self.snapshot = decode_runtime_snapshot(payload)
        self._inventory_unobserved = sum(
            1
            for row in self.snapshot.rows
            if (row.correlation_verdict or "").strip().lower() == "unobserved"
        )
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
                "Click Enable Runtime, or run: defenseclaw agent discovery runtime enable "
                "--no-enable-host-plane"
            )
        if not self.snapshot.scanned_at:
            return "The runtime planes have not completed a poll yet. Click Poll now."
        return (
            "No findings at or above the reporting floor. "
            f"{self.snapshot.processes_observed} processes and "
            f"{self.snapshot.connections_observed} connections were watched. "
            + self._quiet_table_note()
        )

    def _quiet_table_note(self) -> str:
        """Only call a quiet table clean when coverage is not DEGRADED."""

        if self.snapshot.degraded:
            return "Coverage is partial, so a quiet table is not proof of a clean host."
        return "A quiet table is a clean host, not a blind sensor."

    def inventory_unobserved_count(self) -> int:
        return self._inventory_unobserved

    def findings_context(self) -> str:
        """What a sparse or uncorrelated table actually means."""

        if not self.snapshot.enabled or not self.snapshot.scanned_at:
            return self.empty_state().replace("\n", " ")
        watched = (
            f"{self.snapshot.processes_observed} processes and "
            f"{self.snapshot.connections_observed} connections watched"
        )
        if not self.snapshot.rows:
            return (
                f"No findings at or above the reporting floor. {watched}. "
                + self._quiet_table_note()
            )
        unobserved = self.inventory_unobserved_count()
        parts = [f"{len(self.snapshot.rows)} scored finding(s). {watched}."]
        if unobserved:
            parts.append(
                f"{unobserved} not yet correlated with AI Discovery "
                "(inventory unobserved). Open AI Discovery and press Scan now."
            )
        return " ".join(parts)

    def next_action(self) -> str:
        """One operator move that would add information, or empty."""

        if not self.snapshot.enabled:
            return (
                "Click Enable Runtime, or run: defenseclaw agent discovery runtime enable "
                "--no-enable-host-plane"
            )
        if not self.snapshot.scanned_at:
            return "Click Poll now to collect the first runtime snapshot."
        if self.inventory_unobserved_count():
            return "Open AI Discovery and press Scan now so Runtime can correlate findings."
        if self.needs_enable():
            return "Click Enable Runtime to turn on every selected plane."
        return ""

    def overview(self) -> RuntimeOverview:
        """Facts Overview can render without visiting this tab."""

        if not self.snapshot.enabled and not self.snapshot.scanned_at:
            return RuntimeOverview(
                health_title=self.health_title(),
                context="Runtime has not reported a snapshot yet.",
                next_action=self.next_action(),
            )
        top: list[str] = []
        for row in self.snapshot.rows[:3]:
            agent = f"  {row.agent_name}" if row.agent_name else ""
            providers = f"  {row.provider_summary}" if row.provider_summary != "-" else ""
            inventory = row.correlation_verdict or "-"
            top.append(
                f"{row.severity}  {row.process} pid {row.pid}{agent}{providers}  "
                f"inventory {inventory}"
            )
        return RuntimeOverview(
            health_title=self.health_title(),
            enabled=self.snapshot.enabled,
            scanned=bool(self.snapshot.scanned_at),
            findings=len(self.snapshot.rows),
            unobserved=self.inventory_unobserved_count(),
            processes=self.snapshot.processes_observed,
            connections=self.snapshot.connections_observed,
            host_observations=self.snapshot.host_plane_observations,
            host_gated=self.snapshot.host_plane_gated,
            plane_summary="  ".join(plane.strip_label for plane in self.snapshot.planes),
            context=self.findings_context(),
            top_findings=tuple(top),
            next_action=self.next_action(),
            degraded_reason=self.degraded_summary(),
        )

    def degraded_summary(self) -> str:
        """The cause heads only ("shadow egress partially covered"), for Overview.

        The full reasons ran 2-3 lines on Overview and told a standard user to
        run the gateway elevated; the Runtime panel keeps the detail (GAP-2533).
        """

        if self.health_state() != "degraded" or not self.snapshot.degraded_reasons:
            return self.degraded_reason()
        heads = [reason.split(":", 1)[0].strip() for reason in self.snapshot.degraded_reasons]
        return ", ".join(dict.fromkeys(head for head in heads if head))

    def degraded_reason(self) -> str:
        """Short cause for a DEGRADED badge; empty when not degraded."""

        if self.health_state() != "degraded":
            return ""
        if self.snapshot.degraded_reasons:
            return "; ".join(self.snapshot.degraded_reasons)
        gaps = [
            f"{plane.name} {plane.badge}"
            for plane in self.snapshot.planes
            if plane.badge != "up" and _selected_plane_gap(plane)
        ]
        return f"partial coverage: {', '.join(gaps)}" if gaps else "partial coverage"

    def health_state(self) -> str:
        """Operator-facing health: off, waiting, degraded, or healthy."""

        if not self.snapshot.enabled:
            return "off"
        if not self.snapshot.scanned_at:
            return "waiting"
        if self.snapshot.degraded:
            return "degraded"
        return "healthy"

    def health_title(self) -> str:
        return {
            "off": "OFF",
            "waiting": "STARTING",
            "degraded": "DEGRADED",
            "healthy": "HEALTHY",
        }[self.health_state()]

    def health_explanation(self, short: bool = False) -> str:
        """What the badge means, and what a quiet findings table does not mean.

        ``short`` (80x24) keeps only the DEGRADED reasons, so the buttons and
        the findings table stay on screen (GAP-1596).
        """

        state = self.health_state()
        if state == "off":
            return (
                "Runtime is not collecting. HEALTHY means every selected plane "
                "is watching. Click Enable Runtime to turn on the user-level "
                "inference and egress planes."
            )
        if state == "waiting":
            return (
                "Runtime is on but has not finished a poll yet. Click Poll now, "
                "or wait for the next interval. HEALTHY appears after every "
                "selected plane reports up."
            )
        if state == "degraded":
            up = sum(1 for plane in self.snapshot.planes if plane.badge == "up")
            partial = sum(1 for plane in self.snapshot.planes if plane.badge == "partial")
            idle = sum(
                1
                for plane in self.snapshot.planes
                if plane.badge == "idle" and _selected_plane_gap(plane)
            )
            blind = sum(
                1
                for plane in self.snapshot.planes
                if plane.badge == "blind" and _selected_plane_gap(plane)
            )
            parts: list[str] = []
            if up:
                parts.append(f"{up} watching")
            if partial:
                parts.append(f"{partial} partially watching")
            if idle:
                parts.append(f"{idle} selected but not running")
            if blind:
                parts.append(f"{blind} cannot see the host")
            off = [plane for plane in self.snapshot.planes if plane.badge == "off"]
            if off:
                parts.append(f"{len(off)} not selected")
            coverage = ", ".join(parts) or "one or more planes cannot watch the host"
            extra = ""
            if self.snapshot.degraded_reasons:
                extra = " " + "; ".join(self.snapshot.degraded_reasons) + "."
            if short:
                return f"DEGRADED means coverage is partial ({coverage}).{extra}"
            # The how-to-enable hint ends in a command, so it goes last: text
            # run on after it read as part of the command (GAP-2102).
            enable_hint = "".join(
                f" {plane.name.capitalize()} is off (not selected). {self.plane_fix(plane)}"
                for plane in off
            )
            return (
                f"DEGRADED means coverage is partial ({coverage}).{extra} "
                "Findings below are still valid for the planes that are up. "
                "HEALTHY means every selected plane is watching."
                + enable_hint
            )
        unobserved = self.inventory_unobserved_count()
        extra = ""
        if unobserved:
            extra = (
                f" {unobserved} finding(s) are inventory-unobserved: AI Discovery "
                "has no snapshot to correlate yet. Open that tab and press Scan now."
            )
        return (
            "HEALTHY means the user-level inference and egress planes are watching. "
            f"{self._host_plane_note()} "
            "A quiet findings table is a clean host, not a blind sensor."
            + extra
        )

    def needs_enable(self) -> bool:
        """True when the one-click Enable Runtime action would change config."""

        if not self.snapshot.enabled:
            return True
        return any(
            plane.plane != "c"
            and (not plane.running)
            and (
                "not selected" in plane.reason.lower()
                or "enable_host_plane" in plane.reason.lower()
            )
            for plane in self.snapshot.planes
        )

    def _host_plane_note(self) -> str:
        if self.platform.startswith("linux"):
            return "Agent actions (plane C) is optional."
        if self.platform == "darwin":
            return "Endpoint Security is optional and needs an elevated gateway."
        return "Agent actions (plane C) is optional."

    def _host_plane_fix(self) -> str:
        """Next step for the agent-actions plane, in this OS's terms."""

        enable = "defenseclaw agent discovery runtime enable --enable-host-plane"
        if self.platform.startswith("linux"):
            return (
                "Agent actions is optional. Process events need CAP_NET_ADMIN; file events "
                f"need CAP_SYS_ADMIN (fanotify). Turn it on: {enable}"
            )
        if self.platform == "darwin":
            return (
                "Agent actions is optional and needs an elevated gateway. "
                "Use Permissions, then run runtime enable with "
                "--enable-host-plane if you can grant Endpoint Security."
            )
        return f"Agent actions is optional. Use Permissions to see what it needs, then run: {enable}"

    def plane_fix(self, plane: PlaneRow) -> str:
        """Next action for an idle or blind plane. Empty when the plane is up."""

        if plane.running:
            return "Click Permissions for what full coverage needs." if plane.reason else ""
        reason = plane.reason.lower()
        if plane.plane == "c" or "not selected" in reason or "enable_host_plane" in reason:
            if plane.plane == "c":
                return self._host_plane_fix()
            return "Click Enable Runtime to turn on inference and egress."
        if any(
            token in reason
            for token in ("eslogger", "full disk", "privilege", "permission", "tcc")
        ):
            return "Click Permissions for the host grant this plane needs."
        if "connection table" in reason or "lsof" in reason:
            return "Plane B cannot read sockets. Click Permissions, then Poll now."
        if not plane.available:
            return "This plane cannot see the host. Click Permissions."
        return "This plane is available but not running. Click Enable Runtime or Poll now."

    def header_parts(self) -> tuple[str, ...]:
        """The header line.

        Coverage is part of the header rather than a detail view, because a
        reader who sees only the finding count cannot tell a quiet host from a
        blind sensor.
        """
        parts = [self.health_title()]
        parts.append(f"{len(self.filtered)}/{len(self.snapshot.rows)} findings")
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
        return tuple(parts)

    def planes_shown_expanded(self) -> bool:
        """Whether the planes show one line each (with reasons) right now."""

        return self.planes_expanded_short if self.short_screen else self.planes_expanded

    def plane_strip(self) -> tuple[str, ...]:
        """The always-visible plane strip."""
        if not self.snapshot.planes:
            return ("plane health unavailable: the gateway reported no planes",)
        if self.planes_shown_expanded():
            return tuple(plane.summary for plane in self.snapshot.planes)
        return tuple(plane.strip_label for plane in self.snapshot.planes)

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
        lines.extend(row.kernel_notes)
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
        if self.filtering:
            return self._handle_filter_key(key)
        if self.detail_open:
            if key in {"escape", "enter", "q"}:
                self.detail_open = False
                return RuntimePanelAction.CLOSE_DETAIL
            return RuntimePanelAction.NONE
        if key == "r":
            return RuntimePanelAction.REFRESH
        if key == "s":
            return RuntimePanelAction.SCAN
        if key == "e":
            return RuntimePanelAction.ENABLE
        if key == "p":
            if self.short_screen:
                self.planes_expanded_short = not self.planes_expanded_short
            else:
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
            return RuntimePanelAction.MOVE
        if key in {"up", "k"}:
            self.cursor = max(self.cursor - 1, 0)
            return RuntimePanelAction.MOVE
        if key in {"escape", "esc"} and self.filter_text:
            self.clear_filter()
            return RuntimePanelAction.MOVE
        return RuntimePanelAction.NONE

    def _handle_filter_key(self, key: str) -> RuntimePanelAction:
        """Typing after ``/`` edits the filter; it never runs panel keys.

        Without this branch the letters went to the shortcuts, so typing
        ``/se`` polled the planes (``s``) and then enabled them (``e``).
        """

        if key == "enter":
            self.filtering = False
            return RuntimePanelAction.MOVE
        if key in {"escape", "esc"}:
            self.clear_filter()
            return RuntimePanelAction.MOVE
        if key == "backspace":
            self.set_filter(self.filter_text[:-1])
            return RuntimePanelAction.MOVE
        if key == "space":
            self.set_filter(self.filter_text + " ")
            return RuntimePanelAction.MOVE
        if len(key) == 1 and key.isprintable():
            self.set_filter(self.filter_text + key)
            return RuntimePanelAction.MOVE
        # Swallow everything else while filtering (arrows, ctrl keys).
        return RuntimePanelAction.MOVE

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
        if action is RuntimePanelAction.ENABLE:
            return RuntimeCommandIntent(
                argv=(
                    "agent",
                    "discovery",
                    "runtime",
                    "enable",
                    "--yes",
                    "--no-enable-host-plane",
                ),
                description="Enable the user-level inference and egress planes",
            )
        return None
