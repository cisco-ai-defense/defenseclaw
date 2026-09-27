# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure model for the Sandboxes panel.

The panel shows the daemon's OpenShell sandboxes (``/api/v1/sandbox/...``),
the live activity feed (egress allowed and blocked, tool blocks, findings) and
the rare asks. No I/O happens here: the app feeds decoded REST payloads and
activity events in, and the model answers what to render and which action a
key asked for. A failed refresh keeps the last good snapshot, because an empty
list during a daemon restart would read as "no sandboxes" rather than as a lost
connection.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SANDBOX_VIEWS: tuple[str, ...] = ("sandboxes", "activity", "asks")
VIEW_TITLES = {"sandboxes": "Sandboxes", "activity": "Activity", "asks": "Asks"}

# The feed keeps this many events; the daemon's own buffer is the history.
FEED_LIMIT = 500
# A destination blocked again within this window does not toast again.
TOAST_DEDUPE_SECONDS = 60.0

ADMIN_MESSAGE = "blocked by your organization's DefenseClaw policy"
# sandboxapi.HooksUnreachableWarning.
HOOKS_UNREACHABLE_WARNING = "DefenseClaw hooks are not reaching the daemon; every tool call is being blocked"

_RUNNING_PHASES = frozenset({"ready", "running"})


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _time(value: Any) -> datetime | None:
    text = _text(value).strip()
    if not text or text.startswith("0001-01-01"):
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def format_duration(seconds: int) -> str:
    """``59s``, ``12m``, ``3h05m``, ``2d04h``."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, _ = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h{minutes:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d{hours:02d}h"


def host_port(host: str, port: int) -> str:
    if port and port not in (80, 443):
        return f"{host}:{port}"
    return host


@dataclass(frozen=True)
class NestedRepoRow:
    kind: str
    path: str
    quarantined: str = ""
    error: str = ""

    @property
    def line(self) -> str:
        if self.kind == "gitlink":
            return f"gitlink added to the index: {self.path}"
        if self.error:
            return f"new git repository at {self.path} (not quarantined: {self.error})"
        return f"new git repository at {self.path} quarantined as {self.quarantined}"


@dataclass(frozen=True)
class SandboxRow:
    """One sandbox as ``GET /api/v1/sandbox/sandboxes`` describes it."""

    name: str
    harness: str = ""
    harness_name: str = ""
    phase: str = ""
    pack: str = ""
    profile: str = ""
    workdir_mode: str = ""
    project: str = ""
    workdir: str = ""
    yolo: bool = False
    uptime_seconds: int = 0
    created_at: datetime | None = None
    destinations: int = 0
    blocked: int = 0
    pending_approvals: int = 0
    tool_calls: int = 0
    tool_blocked: int = 0
    last_blocked: str = ""
    tampered: int = 0
    hooks_silent: bool = False
    # The session's hooks do not reach DefenseClaw (they fail closed, so the
    # harness can do nothing), and why; hook requests OpenShell refused.
    hooks_unreachable: bool = False
    unreachable_reason: str = ""
    ingress_refused: int = 0
    orphaned: bool = False
    undo_available: bool = False
    nested_repos: tuple[NestedRepoRow, ...] = ()
    warnings: tuple[str, ...] = ()
    violations: tuple[str, ...] = ()

    @property
    def running(self) -> bool:
        return self.phase.lower() in _RUNNING_PHASES

    @property
    def harness_label(self) -> str:
        return self.harness_name or self.harness or "-"

    @property
    def policy_label(self) -> str:
        pack = self.pack or "-"
        if self.profile and self.profile != self.pack:
            return f"{pack}/{self.profile}"
        return pack

    @property
    def uptime_text(self) -> str:
        if not self.running:
            return "-"
        return format_duration(self.uptime_seconds)

    @property
    def alerts(self) -> tuple[str, ...]:
        """Plain alert lines: hook tamper, planted repositories, silent hooks."""
        out: list[str] = []
        if self.tampered:
            out.append(f"hook tamper: {self.tampered} tool call(s) ran without a DefenseClaw verdict")
        out.extend(repo.line for repo in self.nested_repos)
        if self.hooks_unreachable:
            why = f" ({self.unreachable_reason})" if self.unreachable_reason else ""
            out.append(
                f"{HOOKS_UNREACHABLE_WARNING}{why}. Run: defenseclaw sandbox doctor"
            )
        elif self.ingress_refused:
            out.append(f"OpenShell refused {self.ingress_refused} hook request(s) to DefenseClaw")
        if self.hooks_silent:
            out.append("hooks are silent: the harness is active but no DefenseClaw hook has been heard")
        if self.orphaned:
            out.append("no DefenseClaw binding: its hooks cannot authenticate; delete it and run again")
        return tuple(out)

    @property
    def alert_badge(self) -> str:
        parts = []
        if self.tampered:
            parts.append("tamper")
        if self.nested_repos:
            parts.append("nested repo")
        if self.hooks_unreachable:
            parts.append("hooks unreachable")
        if self.hooks_silent:
            parts.append("silent")
        if self.orphaned:
            parts.append("orphaned")
        return ", ".join(parts) or "-"


def decode_sandbox(raw: Any) -> SandboxRow | None:
    item = _dict(raw)
    name = _text(item.get("name")).strip()
    if not name:
        return None
    hooks = _dict(item.get("hooks"))
    egress = _dict(item.get("egress"))
    snapshot = _dict(item.get("snapshot"))
    nested = tuple(
        NestedRepoRow(
            kind=_text(repo.get("kind")),
            path=_text(repo.get("path")),
            quarantined=_text(repo.get("quarantined")),
            error=_text(repo.get("error")),
        )
        for repo in (_dict(r) for r in _list(item.get("nested_repos")))
        if repo.get("path")
    )
    violations = tuple(_text(_dict(v).get("message") or _dict(v).get("detail")) for v in _list(item.get("violations")))
    return SandboxRow(
        name=name,
        harness=_text(item.get("harness")),
        harness_name=_text(item.get("harness_name")),
        phase=_text(item.get("phase")).lower(),
        pack=_text(item.get("pack")),
        profile=_text(item.get("profile")),
        workdir_mode=_text(item.get("workdir_mode")),
        project=_text(item.get("project")),
        workdir=_text(item.get("workdir")),
        yolo=bool(item.get("yolo")),
        uptime_seconds=_int(item.get("uptime_seconds")),
        created_at=_time(item.get("created_at")),
        destinations=_int(egress.get("destinations")),
        blocked=_int(egress.get("blocked")),
        pending_approvals=_int(item.get("pending_approvals")),
        tool_calls=_int(hooks.get("tool_calls")),
        tool_blocked=_int(hooks.get("tool_blocked")),
        last_blocked=_text(hooks.get("last_blocked")),
        tampered=_int(hooks.get("tampered")),
        hooks_silent=bool(hooks.get("silent")),
        hooks_unreachable=bool(hooks.get("unreachable")),
        unreachable_reason=_text(hooks.get("unreachable_reason")),
        ingress_refused=_int(hooks.get("ingress_refused")),
        orphaned=bool(item.get("orphaned")),
        undo_available=bool(snapshot) and _time(snapshot.get("undone_at")) is None,
        nested_repos=nested,
        warnings=tuple(_text(w) for w in _list(item.get("warnings")) if w),
        violations=tuple(v for v in violations if v),
    )


@dataclass(frozen=True)
class ActivityRow:
    """One activity-feed event."""

    seq: int
    time: datetime | None
    kind: str
    sandbox: str = ""
    host: str = ""
    port: int = 0
    category: str = ""
    reason: str = ""
    message: str = ""
    unblockable: bool = False
    approval_id: str = ""
    tool: str = ""
    severity: str = ""
    bytes_up: int = 0

    @property
    def blocked_destination(self) -> bool:
        return self.kind == "egress.blocked" and bool(self.host)

    @property
    def glyph(self) -> str:
        return {
            "egress.allowed": "✓",
            "egress.blocked": "✗",
            "egress.unblocked": "↺",
            "egress.large_upload": "⚠",
            "approval.requested": "?",
            "approval.resolved": "·",
            "tool.blocked": "✗",
            "finding": "⚠",
            "sandbox.lifecycle": "·",
            "workspace": "·",
            "dropped": "…",
        }.get(self.kind, "·")

    @property
    def summary(self) -> str:
        """The display line, without the glyph the daemon's message may carry."""
        text = self.message.strip()
        if text[:1] in {"✓", "✗", "⚠", "?", "↺"}:
            text = text[1:].strip()
        if self.kind == "egress.allowed":
            return host_port(self.host, self.port) or text
        if self.kind == "egress.blocked":
            if not self.host:
                return text or self.reason or "a destination was blocked"
            why = self.category or self.reason
            return host_port(self.host, self.port) + (f" ({why})" if why else "")
        if self.kind == "approval.requested":
            return "asks to reach " + (text or host_port(self.host, self.port))
        if self.kind == "tool.blocked":
            line = f"{self.tool or 'tool call'} blocked"
            return line + (f": {self.reason}" if self.reason else "")
        if self.kind == "sandbox.lifecycle":
            return text or f"now {self.message or self.reason or 'changed'}"
        return text or self.reason or self.kind

    @property
    def time_text(self) -> str:
        if self.time is None:
            return "--:--:--"
        return self.time.astimezone().strftime("%H:%M:%S")


def decode_activity(raw: Any) -> ActivityRow | None:
    item = _dict(raw)
    kind = _text(item.get("kind"))
    if not kind:
        return None
    message = _text(item.get("message"))
    if kind == "sandbox.lifecycle" and not message:
        phase = _text(item.get("phase")).lower()
        message = f"now {phase}" if phase else ""
    return ActivityRow(
        seq=_int(item.get("seq")),
        time=_time(item.get("time")),
        kind=kind,
        sandbox=_text(item.get("sandbox")),
        host=_text(item.get("host")),
        port=_int(item.get("port")),
        category=_text(item.get("category")),
        reason=_text(item.get("reason")),
        message=message,
        unblockable=bool(item.get("unblockable")),
        approval_id=_text(item.get("approval_id")),
        tool=_text(item.get("tool")),
        severity=_text(item.get("severity")),
        bytes_up=_int(item.get("bytes_up")),
    )


@dataclass(frozen=True)
class AskRow:
    """One rare ask (a draft proposal triage would not decide on its own)."""

    id: str
    sandbox: str
    kind: str = ""
    host: str = ""
    port: int = 0
    binary: str = ""
    endpoints: tuple[str, ...] = ()
    risky: bool = False
    reason: str = ""
    rationale: str = ""
    security_notes: str = ""
    hit_count: int = 0
    status: str = ""
    created_at: datetime | None = None

    @property
    def destination(self) -> str:
        return host_port(self.host, self.port) if self.host else "-"

    @property
    def kind_label(self) -> str:
        return {"host_port": "port on this machine", "network_rule": "network"}.get(self.kind, self.kind or "-")


def decode_ask(raw: Any) -> AskRow | None:
    item = _dict(raw)
    ask_id = _text(item.get("id")).strip()
    if not ask_id:
        return None
    endpoints = tuple(
        host_port(_text(e.get("host")), _int(e.get("port")))
        for e in (_dict(x) for x in _list(item.get("endpoints")))
        if e.get("host")
    )
    return AskRow(
        id=ask_id,
        sandbox=_text(item.get("sandbox")),
        kind=_text(item.get("kind")),
        host=_text(item.get("host")),
        port=_int(item.get("port")),
        binary=_text(item.get("binary")),
        endpoints=endpoints,
        risky=bool(item.get("risky")),
        reason=_text(item.get("reason")),
        rationale=_text(item.get("rationale")),
        security_notes=_text(item.get("security_notes")),
        hit_count=_int(item.get("hit_count")),
        status=_text(item.get("status")),
        created_at=_time(item.get("created_at")),
    )


@dataclass(frozen=True)
class SandboxStatus:
    """``GET /api/v1/sandbox/status``."""

    loaded: bool = False
    enabled: bool = False
    available: bool = False
    reason: str = ""
    gateway: str = ""
    ingress_addr: str = ""
    egress_addr: str = ""
    pack: str = ""
    profile: str = ""
    admin_configured: bool = False
    admin_authority: str = ""
    admin_detail: str = ""
    sandboxes: int = 0
    running: int = 0
    pending_approvals: int = 0


def decode_status(raw: Any) -> SandboxStatus:
    item = _dict(raw)
    gateway = _dict(item.get("gateway"))
    admin = _dict(item.get("admin"))
    gateway_text = ""
    if gateway:
        version = _text(gateway.get("version"))
        gateway_text = "OpenShell" + (f" {version}" if version else "") + f" gateway {_text(gateway.get('name'))}"
        if gateway.get("healthy") is False:
            gateway_text += " (unhealthy)"
    return SandboxStatus(
        loaded=True,
        enabled=bool(item.get("enabled")),
        available=bool(item.get("available")),
        reason=_text(item.get("reason")),
        gateway=gateway_text.strip(),
        ingress_addr=_text(item.get("ingress_addr")),
        egress_addr=_text(item.get("egress_addr")),
        pack=_text(item.get("pack")),
        profile=_text(item.get("profile")),
        admin_configured=bool(admin.get("configured")),
        admin_authority=_text(admin.get("authority")),
        admin_detail=_text(admin.get("detail")),
        sandboxes=_int(item.get("sandboxes")),
        running=_int(item.get("running")),
        pending_approvals=_int(item.get("pending_approvals")),
    )


@dataclass(frozen=True)
class AdminPolicy:
    """The openshell.admin switches the panel honours before asking the daemon."""

    allow_unblock: bool | None = None
    allowed_harnesses: tuple[str, ...] = ()
    authoritative: bool = False

    @property
    def unblock_refused(self) -> bool:
        return self.allow_unblock is False


def admin_policy_from_config(cfg: object | None) -> AdminPolicy:
    openshell = getattr(cfg, "openshell", None)
    admin = getattr(openshell, "admin", None)
    if admin is None:
        return AdminPolicy()
    allow_unblock = getattr(admin, "allow_unblock", None)
    harnesses = getattr(admin, "allowed_harnesses", None) or ()
    mode = str(getattr(cfg, "deployment_mode", "") or "").strip().lower()
    return AdminPolicy(
        allow_unblock=allow_unblock if isinstance(allow_unblock, bool) else None,
        allowed_harnesses=tuple(str(h) for h in harnesses if str(h).strip()),
        authoritative=mode in {"managed_enterprise", "managed"},
    )


@dataclass(frozen=True)
class SandboxNotice:
    """A toast the app should raise for a new activity event."""

    level: str
    message: str


@dataclass(frozen=True)
class SandboxPanelAction:
    """What a keypress asked the panel to do.

    ``kind`` is one of: none, refresh, view, detail, unblock, approve, reject,
    undo, review, stop, delete, connect, new_run, wrappers, hint.
    """

    kind: str = "none"
    sandbox: str = ""
    host: str = ""
    approval_id: str = ""
    always: bool = False
    hint: str = ""

    @property
    def handled(self) -> bool:
        return self.kind != "none"


@dataclass
class SandboxesPanelModel:
    """State and key handling for the Sandboxes panel."""

    status: SandboxStatus = field(default_factory=SandboxStatus)
    rows: tuple[SandboxRow, ...] = ()
    asks: tuple[AskRow, ...] = ()
    feed: deque[ActivityRow] = field(default_factory=lambda: deque(maxlen=FEED_LIMIT))
    view: str = "sandboxes"
    cursors: dict[str, int] = field(default_factory=lambda: dict.fromkeys(SANDBOX_VIEWS, 0))
    detail_open: bool = False
    error: str = ""
    fetched_at: datetime | None = None
    last_seq: int = 0
    stream_state: str = "idle"
    admin: AdminPolicy = field(default_factory=AdminPolicy)
    wrappers: tuple[str, ...] = ()
    harnesses: tuple[str, ...] = ()
    _toasted: dict[tuple[str, str], float] = field(default_factory=dict)

    # ---- snapshot ---------------------------------------------------------

    def set_snapshot(
        self,
        status: Any,
        sandboxes: Any = None,
        approvals: Any = None,
        *,
        now: datetime | None = None,
    ) -> None:
        """Replace the snapshot with a successful fetch."""
        self.status = decode_status(status)
        if sandboxes is not None:
            rows = [row for row in (decode_sandbox(raw) for raw in _list(sandboxes)) if row is not None]
            rows.sort(key=lambda row: (not row.running, row.name))
            self.rows = tuple(rows)
        if approvals is not None:
            asks = [ask for ask in (decode_ask(raw) for raw in _list(approvals)) if ask is not None]
            asks = [ask for ask in asks if ask.status in {"", "pending"}]
            asks.sort(key=lambda ask: (ask.created_at or datetime.min.replace(tzinfo=timezone.utc), ask.id))
            self.asks = tuple(asks)
        self.error = ""
        self.fetched_at = now or datetime.now(timezone.utc)
        self._clamp()

    def set_error(self, message: str) -> None:
        """Record a failed refresh; the previous snapshot stays."""
        self.error = message

    def set_config(self, cfg: object | None) -> None:
        self.admin = admin_policy_from_config(cfg)
        openshell = getattr(cfg, "openshell", None)
        self.wrappers = tuple(str(w) for w in (getattr(openshell, "wrappers", None) or ()) if str(w).strip())
        self.harnesses = tuple(str(h) for h in (getattr(openshell, "harnesses", None) or ()) if str(h).strip())

    # ---- activity ---------------------------------------------------------

    def add_events(
        self,
        events: Any,
        *,
        toast: bool = True,
        now: float | None = None,
        live: bool = False,
    ) -> list[SandboxNotice]:
        """Append events and return the toasts to raise.

        Buffered reads skip events at or below the resume point. ``live``
        events come from a stream opened after ``last_seq``, so each one is
        new: a sequence number below the resume point means the daemon
        restarted (its counter starts over), and the resume point follows it.
        """
        notices: list[SandboxNotice] = []
        for raw in _list(events):
            row = decode_activity(raw)
            if row is None:
                continue
            if row.kind != "dropped":
                # A "dropped" marker shares its sequence number with the event
                # after it, so it never advances the resume point.
                if live:
                    self.last_seq = row.seq or self.last_seq
                elif row.seq and row.seq <= self.last_seq:
                    continue
                else:
                    self.last_seq = max(self.last_seq, row.seq)
            self.feed.append(row)
            if toast:
                notice = self._notice_for(row, now=now)
                if notice is not None:
                    notices.append(notice)
            if row.kind in {"approval.requested", "approval.resolved"}:
                self._apply_ask_event(row)
        self._clamp()
        return notices

    def _apply_ask_event(self, row: ActivityRow) -> None:
        if row.kind == "approval.resolved" and row.approval_id:
            self.asks = tuple(ask for ask in self.asks if ask.id != row.approval_id)

    def _notice_for(self, row: ActivityRow, *, now: float | None) -> SandboxNotice | None:
        clock = time.monotonic() if now is None else now
        if row.kind == "egress.blocked" and row.host and row.unblockable:
            key = (row.sandbox, row.host)
            last = self._toasted.get(key)
            if last is not None and clock - last < TOAST_DEDUPE_SECONDS:
                return None
            self._toasted[key] = clock
            why = f" ({row.category or row.reason})" if (row.category or row.reason) else ""
            where = f" in {row.sandbox}" if row.sandbox else ""
            return SandboxNotice(
                "warn", f"✗ {host_port(row.host, row.port)} blocked{where}{why}. Sandboxes panel (7): u to unblock"
            )
        if row.kind == "approval.requested":
            where = f"{row.sandbox} asks" if row.sandbox else "A sandbox asks"
            target = row.message or host_port(row.host, row.port) or "a destination"
            return SandboxNotice("warn", f"? {where} to reach {target}. Sandboxes panel (7): t for Asks")
        if row.kind == "finding" and row.reason == "hooks_unreachable":
            return SandboxNotice("error", f"{row.sandbox}: {row.summary}")
        if row.kind == "finding" and row.reason == "hooks_restored":
            return SandboxNotice("success", f"{row.sandbox}: {row.summary}")
        if row.kind == "finding" and row.reason == "nested_repo":
            return SandboxNotice("warn", f"⚠ {row.sandbox}: {row.summary}")
        return None

    # ---- navigation -------------------------------------------------------

    def _view_len(self, view: str) -> int:
        if view == "sandboxes":
            return len(self.rows)
        if view == "activity":
            return len(self.feed)
        return len(self.asks)

    def _clamp(self) -> None:
        for view in SANDBOX_VIEWS:
            size = self._view_len(view)
            self.cursors[view] = max(0, min(self.cursors.get(view, 0), max(0, size - 1)))

    @property
    def cursor(self) -> int:
        return self.cursors.get(self.view, 0)

    @cursor.setter
    def cursor(self, value: int) -> None:
        self.cursors[self.view] = max(0, min(int(value), max(0, self._view_len(self.view) - 1)))

    def feed_rows(self) -> tuple[ActivityRow, ...]:
        """The feed, newest first."""
        return tuple(reversed(self.feed))

    def selected_sandbox(self) -> SandboxRow | None:
        if self.view == "sandboxes":
            if 0 <= self.cursor < len(self.rows):
                return self.rows[self.cursor]
            return None
        name = ""
        if self.view == "activity":
            event = self.selected_event()
            name = event.sandbox if event else ""
        elif self.view == "asks":
            ask = self.selected_ask()
            name = ask.sandbox if ask else ""
        return next((row for row in self.rows if row.name == name), None)

    def selected_event(self) -> ActivityRow | None:
        rows = self.feed_rows()
        if self.view == "activity" and 0 <= self.cursor < len(rows):
            return rows[self.cursor]
        return None

    def selected_ask(self) -> AskRow | None:
        if self.view == "asks" and 0 <= self.cursor < len(self.asks):
            return self.asks[self.cursor]
        return None

    def latest_unblockable(self, sandbox: str = "") -> ActivityRow | None:
        for row in reversed(self.feed):
            if row.blocked_destination and row.unblockable and (not sandbox or row.sandbox == sandbox):
                return row
        return None

    def unblock_target(self) -> ActivityRow | None:
        """The blocked destination ``u`` acts on.

        The selected feed row when it is a blocked destination; otherwise the
        most recent unblockable block (of the selected sandbox, when one is
        selected), so a toast's "press u" works from any view.
        """
        event = self.selected_event()
        if event is not None and event.blocked_destination:
            return event
        selected = self.selected_sandbox() if self.view == "sandboxes" else None
        if selected is not None:
            own = self.latest_unblockable(selected.name)
            if own is not None:
                return own
        return self.latest_unblockable()

    # ---- keys -------------------------------------------------------------

    def handle_key(self, key: str) -> SandboxPanelAction:
        if self.detail_open:
            if key in {"escape", "enter", "q"}:
                self.detail_open = False
                return SandboxPanelAction("detail")
            return SandboxPanelAction()
        if key in {"down", "j"}:
            self.cursor = self.cursor + 1
            return SandboxPanelAction("move")
        if key in {"up", "k"}:
            self.cursor = self.cursor - 1
            return SandboxPanelAction("move")
        if key == "t":
            index = SANDBOX_VIEWS.index(self.view)
            self.view = SANDBOX_VIEWS[(index + 1) % len(SANDBOX_VIEWS)]
            return SandboxPanelAction("view")
        if key == "enter":
            if self._view_len(self.view):
                self.detail_open = True
                return SandboxPanelAction("detail")
            return SandboxPanelAction()
        if key == "u":
            return self._unblock_action()
        if key in {"a", "A"} or (key == "r" and self.view == "asks"):
            return self._ask_action(key)
        if key == "r":
            return SandboxPanelAction("refresh")
        if key == "n":
            return SandboxPanelAction("new_run")
        if key == "w":
            return SandboxPanelAction("wrappers")
        if key in {"U", "R", "s", "d", "c"}:
            return self._sandbox_action(key)
        return SandboxPanelAction()

    def _unblock_action(self) -> SandboxPanelAction:
        target = self.unblock_target()
        if target is None:
            return SandboxPanelAction("hint", hint="No blocked destination to unblock.")
        if not target.unblockable:
            return SandboxPanelAction(
                "hint",
                hint=f"{target.host} cannot be unblocked here "
                "(private networks, metadata and your organization's blocks stay closed).",
            )
        if self.admin.unblock_refused:
            return SandboxPanelAction("hint", hint=f"Unblocking is {ADMIN_MESSAGE}.")
        return SandboxPanelAction("unblock", sandbox=target.sandbox, host=target.host)

    def _ask_action(self, key: str) -> SandboxPanelAction:
        ask = self.selected_ask()
        if ask is None:
            if not self.asks:
                return SandboxPanelAction("hint", hint="No asks are waiting.")
            self.view = "asks"
            self.cursor = 0
            return SandboxPanelAction(
                "view", hint="Review the ask, then press a to approve, A to always approve, r to reject."
            )
        if key == "r":
            return SandboxPanelAction("reject", sandbox=ask.sandbox, approval_id=ask.id)
        if key == "A" and self.admin.unblock_refused:
            return SandboxPanelAction("hint", hint=f"Always-approve is {ADMIN_MESSAGE}; press a to approve once.")
        return SandboxPanelAction("approve", sandbox=ask.sandbox, approval_id=ask.id, always=key == "A")

    def _sandbox_action(self, key: str) -> SandboxPanelAction:
        row = self.selected_sandbox()
        if row is None:
            return SandboxPanelAction("hint", hint="Select a sandbox first (t switches to the Sandboxes view).")
        kind = {"U": "undo", "R": "review", "s": "stop", "d": "delete", "c": "connect"}[key]
        if kind in {"undo", "review"} and row.workdir_mode == "copy":
            return SandboxPanelAction(
                "hint",
                hint=f"{row.name} works on a copy; bring its work back with: defenseclaw sandbox pull {row.name}",
            )
        if kind == "undo" and not row.undo_available:
            return SandboxPanelAction("hint", hint=f"{row.name} has no snapshot to undo to.")
        if kind == "stop" and not row.running:
            return SandboxPanelAction("hint", hint=f"{row.name} is not running.")
        return SandboxPanelAction(kind, sandbox=row.name)

    # ---- rendering --------------------------------------------------------

    def state(self) -> str:
        """off, unavailable, unreachable, waiting or ready."""
        if not self.status.loaded:
            return "unreachable" if self.error else "waiting"
        if not self.status.enabled:
            return "off"
        if not self.status.available:
            return "unavailable"
        return "ready"

    def headline(self) -> str:
        state = self.state()
        if state == "waiting":
            return "Loading sandboxes from the DefenseClaw daemon..."
        if state == "unreachable":
            return f"The DefenseClaw daemon is not answering: {self.error}"
        if state == "off":
            return "Sandboxes are off. Run the Sandbox wizard (0 Setup, slot 13) or: defenseclaw sandbox setup"
        if state == "unavailable":
            reason = self.status.reason or "the daemon is not connected to OpenShell"
            return f"Sandboxes are unavailable: {reason}. Check: defenseclaw sandbox doctor"
        parts = [f"{self.status.running} running", f"{self.status.sandboxes} total"]
        if self.asks:
            parts.append(f"{len(self.asks)} ask(s) waiting")
        if self.status.gateway:
            parts.append(self.status.gateway)
        return " · ".join(parts)

    def stale_note(self, now: datetime | None = None) -> str:
        if not self.error or not self.status.loaded:
            return ""
        age = ""
        if self.fetched_at is not None:
            seconds = int(((now or datetime.now(timezone.utc)) - self.fetched_at).total_seconds())
            age = f" (last update {format_duration(seconds)} ago)"
        return f"Showing the last good snapshot{age}: {self.error}"

    def admin_line(self) -> str:
        if not self.status.admin_configured:
            return ""
        return f"Organization policy: {self.status.admin_detail or self.status.admin_authority}"

    def keys_line(self) -> str:
        common = "t view  Enter detail  n new run  w sandboxed on/off"
        if self.view == "asks":
            return "Keys: a approve  A always  r reject  " + common
        if self.view == "activity":
            return "Keys: u unblock  r refresh  " + common
        return "Keys: c connect  s stop  d delete  U undo  R review  u unblock  r refresh  " + common

    def data_table_columns(self) -> tuple[str, ...]:
        if self.view == "activity":
            return ("Time", "Sandbox", "", "Event")
        if self.view == "asks":
            return ("Sandbox", "Kind", "Destination", "Binary", "Risk", "Reason")
        return ("Name", "Phase", "Harness", "Pack/Profile", "Mode", "Up", "Sites", "Blocked", "Tools", "Alerts")

    def data_table_rows(self) -> tuple[tuple[str, ...], ...]:
        if self.view == "activity":
            return tuple(
                (
                    row.time_text,
                    row.sandbox or "-",
                    row.glyph,
                    row.summary + ("  (u unblocks)" if row.unblockable else ""),
                )
                for row in self.feed_rows()
            )
        if self.view == "asks":
            return tuple(
                (
                    ask.sandbox,
                    ask.kind_label,
                    ask.destination,
                    ask.binary or "-",
                    "risky" if ask.risky else "-",
                    ask.reason or "-",
                )
                for ask in self.asks
            )
        return tuple(
            (
                row.name,
                row.phase or "-",
                row.harness_label,
                row.policy_label,
                row.workdir_mode or "-",
                row.uptime_text,
                str(row.destinations),
                str(row.blocked),
                f"{row.tool_blocked}/{row.tool_calls}" if row.tool_calls else "0",
                row.alert_badge,
            )
            for row in self.rows
        )

    def empty_state(self) -> str:
        if self.view == "activity":
            return "No activity yet. Destinations, blocks, tool blocks and findings appear here as they happen."
        if self.view == "asks":
            return "No asks are waiting. Only doors into your machine or network (localhost ports, private IPs) ask."
        if self.state() == "ready":
            return "No sandboxes yet. Press n to start one, or run: cd <project> && defenseclaw sandbox run claude"
        return ""

    def recent_blocks(self, limit: int = 3) -> tuple[ActivityRow, ...]:
        out = [row for row in reversed(self.feed) if row.blocked_destination]
        return tuple(out[:limit])

    def detail_pairs(self) -> tuple[str, tuple[tuple[str, str], ...]]:
        """Title and label/value pairs for the detail modal."""
        if self.view == "activity":
            event = self.selected_event()
            if event is None:
                return "", ()
            pairs = [
                ("Time", event.time.isoformat() if event.time else "-"),
                ("Sandbox", event.sandbox or "-"),
                ("Event", event.kind),
                ("Summary", event.summary),
            ]
            if event.host:
                pairs.append(("Destination", host_port(event.host, event.port)))
            if event.category:
                pairs.append(("Category", event.category))
            if event.reason:
                pairs.append(("Reason", event.reason))
            if event.blocked_destination:
                pairs.append(("Unblock", "press u" if event.unblockable else "not unblockable here"))
            return "Activity", tuple(pairs)
        if self.view == "asks":
            ask = self.selected_ask()
            if ask is None:
                return "", ()
            pairs = [
                ("Sandbox", ask.sandbox),
                ("Ask", ask.id),
                ("Kind", ask.kind_label),
                ("Destination", ask.destination),
            ]
            if len(ask.endpoints) > 1:
                pairs.append(("Opens", ", ".join(ask.endpoints)))
            if ask.binary:
                pairs.append(("Binary", ask.binary))
            pairs.append(("Risk", "risky: private, IP-literal or host-local reach" if ask.risky else "-"))
            for label, value in (("Reason", ask.reason), ("Rationale", ask.rationale), ("Notes", ask.security_notes)):
                if value:
                    pairs.append((label, value))
            if ask.hit_count:
                pairs.append(("Attempts", str(ask.hit_count)))
            pairs.append(("Decide", "a approve · A always approve · r reject"))
            return "Ask", tuple(pairs)
        row = self.selected_sandbox()
        if row is None:
            return "", ()
        pairs = [
            ("Name", row.name),
            ("Harness", row.harness_label),
            ("Phase", row.phase or "-"),
            ("Up", row.uptime_text),
            ("Policy", row.policy_label),
            ("Skip-permissions", "on" if row.yolo else "off"),
            ("Project", f"{row.project} → {row.workdir} ({row.workdir_mode or '-'})" if row.project else "-"),
            ("Sites", f"{row.destinations} contacted, {row.blocked} blocked"),
            ("Tool calls", f"{row.tool_calls} ({row.tool_blocked} blocked)"),
        ]
        if row.last_blocked:
            pairs.append(("Last tool block", row.last_blocked))
        if row.pending_approvals:
            pairs.append(("Asks waiting", str(row.pending_approvals)))
        pairs.append(("Undo", "available (U)" if row.undo_available else "no snapshot"))
        for alert in row.alerts:
            pairs.append(("Alert", alert))
        for violation in row.violations:
            pairs.append(("Policy clamp", violation))
        for warning in row.warnings:
            pairs.append(("Warning", warning))
        return f"Sandbox {row.name}", tuple(pairs)

    def total_count(self) -> int:
        """Tab-badge count: asks waiting plus unblockable blocks in the feed."""
        return len(self.asks) + sum(1 for row in self.feed if row.blocked_destination)

    def overview_line(self) -> str:
        """One line for Overview; empty when sandboxes were never set up."""
        state = self.state()
        if state in {"waiting", "off"}:
            return ""
        if state == "unreachable":
            return ""
        if state == "unavailable":
            return f"Sandboxes unavailable: {self.status.reason or 'see defenseclaw sandbox doctor'}"
        line = f"Sandboxes: {self.status.running} running / {self.status.sandboxes}"
        blocks = sum(row.blocked for row in self.rows)
        if blocks:
            line += f" · {blocks} blocked destination(s)"
        if self.asks:
            line += f" · {len(self.asks)} ask(s) waiting (7)"
        return line


def review_pairs(response: Any) -> tuple[tuple[str, str], ...]:
    """Label/value pairs for a ``POST /sandboxes/{name}/review`` answer."""
    data = _dict(response)
    report = _dict(data.get("report"))
    pairs: list[tuple[str, str]] = []
    if data.get("summary"):
        pairs.append(("Summary", _text(data.get("summary"))))
    if data.get("risk_line"):
        pairs.append(("Can run code", _text(data.get("risk_line"))))
    if report:
        pairs.append(
            (
                "Changes",
                f"{_int(report.get('files_changed'))} file(s) (+{_int(report.get('insertions'))} "
                f"−{_int(report.get('deletions'))})",
            )
        )
        for flag in (_dict(f) for f in _list(report.get("flags"))):
            label = _text(flag.get("label") or flag.get("path"))
            severity = _text(flag.get("severity")).upper()
            detail = _text(flag.get("detail"))
            pairs.append((f"⚠ {severity}".strip(), f"{label}: {detail}" if detail else label))
        for finding in (_dict(f) for f in _list(report.get("findings"))[:10]):
            title = _text(finding.get("title") or finding.get("rule_id") or finding.get("scanner"))
            location = _text(finding.get("location") or finding.get("path"))
            pairs.append(("Finding", f"{title} ({location})" if location else title))
        changes = _list(report.get("changes"))
        for change in (_dict(c) for c in changes[:25]):
            pairs.append((f"  {_text(change.get('status'))}", _text(change.get("path"))))
        if len(changes) > 25:
            pairs.append(("", f"… and {len(changes) - 25} more (defenseclaw sandbox review --diff)"))
        for warning in _list(report.get("warnings")):
            pairs.append(("Warning", _text(warning)))
    if not pairs:
        pairs.append(("Summary", "No changes since the session started."))
    return tuple(pairs)


def undo_preview_text(response: Any) -> str:
    """What undo would change, in one short paragraph for the confirmation."""
    data = _dict(response)
    result = _dict(data.get("result"))
    changes = _list(result.get("changes"))
    parts: list[str] = []
    if changes:
        paths = [_text(_dict(c).get("path")) for c in changes[:5]]
        more = f" and {len(changes) - 5} more" if len(changes) > 5 else ""
        parts.append(f"{len(changes)} file(s) go back to the snapshot: {', '.join(paths)}{more}.")
    nested = _list(result.get("nested_repos"))
    if nested:
        parts.append(f"{len(nested)} planted git repositor{'y' if len(nested) == 1 else 'ies'} removed.")
    refs = _list(result.get("ref_changes"))
    if refs:
        parts.append(f"{len(refs)} branch/tag change(s) reset.")
    if data.get("summary"):
        parts.insert(0, _text(data.get("summary")))
    return " ".join(parts) or "Nothing changed since the snapshot; undo has nothing to do."


def undo_is_empty(response: Any) -> bool:
    """Whether the folder already matches the snapshot (``UndoResult.Empty``)."""
    result = _dict(_dict(response).get("result"))
    if not result:
        return True
    lists = ("changes", "ref_changes", "control_changes", "nested_repos", "lost_objects")
    if any(_list(result.get(key)) for key in lists):
        return False
    return _text(result.get("head_before")) == _text(result.get("head_after")) and _text(
        result.get("branch_before")
    ) == _text(result.get("branch_after"))
