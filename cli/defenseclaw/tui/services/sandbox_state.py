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

import ipaddress
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

SANDBOX_VIEWS: tuple[str, ...] = ("sandboxes", "activity", "asks")
VIEW_TITLES = {"sandboxes": "Sandboxes", "activity": "Activity", "asks": "Asks"}
# Keys that act on the selected row in every view (a, A and x act on the
# selected ask in the Asks view).
_SELECTION_KEYS = frozenset({"u", "U", "R", "s", "d", "c"})

# The feed keeps this many events; the daemon's own buffer is the history.
FEED_LIMIT = 500
# A destination blocked again within this window does not toast again.
TOAST_DEDUPE_SECONDS = 60.0
# The header's blocked-destination line shows blocks this recent; older ones
# stay in Activity (t).
BLOCK_BANNER_SECONDS = 15 * 60

ADMIN_MESSAGE = "blocked by your organization's DefenseClaw policy"
# The next step after an openshell.admin.allow_unblock refusal.
ADMIN_UNBLOCK_NEXT = "ask your DefenseClaw administrator (openshell.admin.allow_unblock is off)"
# A saved unblock (openshell.egress.unblocked) the organization's policy ignores.
ADMIN_UNBLOCK_IGNORED = "your saved unblock is off: openshell.admin.allow_unblock"
# u on a tool block: DefenseClaw's rules decided it, not the egress policy.
TOOL_BLOCK_HINT = (
    "u lifts only blocked destinations (✗); DefenseClaw's guardrail rules decide tool calls "
    "(see: defenseclaw policy list)."
)
TOOL_BLOCK_DECIDED_BY = "DefenseClaw's guardrail rules, which u does not change (see: defenseclaw policy list)"
# sandboxapi.HooksUnreachableWarning.
HOOKS_UNREACHABLE_WARNING = "DefenseClaw hooks are not reaching the daemon; every tool call is being blocked"
# The Asks view with nothing waiting. An ask is an OpenShell draft rule for a
# connection that went around DefenseClaw's proxy and that triage does not
# decide on its own (triage.judgeEndpoint): a private-network address with
# every pack, a host off the allowlist with balanced, and every new
# destination with strict. A port on this machine drafts none (OpenShell
# denies the mapping itself), so it is opened with --host-port instead.
NO_ASKS_TEXT = (
    "No asks are waiting. An ask appears when a program connects around DefenseClaw's proxy: "
    "to a private-network address with any pack, to a host off the allowlist with balanced, "
    "and to every new destination with strict. Ports on this machine never ask; run with --host-port PORT."
)

# sandboxcli.reasonTexts, plus the triage reasons of rejected proposals: the
# tokens a blocked destination's category or reason holds, in plain words.
REASON_LABELS: dict[str, str] = {
    "transparent_tcp_policy_denied": "no OpenShell rule allows it",
    "transparent_tcp_mapping_denied": "no OpenShell rule allows this port",
    "policy_dns_ineligible": "no OpenShell rule allows the name",
    "paste_site": "paste site",
    "file_drop": "file-sharing site",
    "webhook_catcher": "webhook catcher",
    "tunnel": "tunnel service",
    "anonymizer": "anonymizer",
    "host_internal": "this machine",
    "host_local": "this machine",
    "private_network": "private network",
    "port_not_allowed": "port not allowed",
    "invalid_destination": "invalid destination",
    "admin_block": "blocked by your organization",
    "admin_allow_only": "not on your organization's allowed list",
    "admin_violation": "blocked by your organization",
    "operator_block": "on your block list",
    "not_allowlisted": "not on the allowlist",
    "rate_limited": "rate limited",
    "ip_literal": "IP address instead of a name",
    "blocklisted": "on the egress blocklist",
    "resolves_to_host": "the name leads to this machine",
    "unresolved": "the name does not resolve",
    "policy_refused": "the sandbox policy refuses it",
    "wildcard_destination": "wildcard destination",
}


def _is_token(text: str) -> bool:
    """A lower-case snake_case token (``webhook_catcher``) rather than a sentence."""
    return text.isidentifier() and text == text.lower()


def reason_label(text: str) -> str:
    """A reason or category token in plain words (sandboxcli.reasonText); other text as is."""
    text = text.strip()
    if not _is_token(text):
        return text
    return REASON_LABELS.get(text, text.replace("_", " "))


# How a sandbox tool verdict's reason starts (gateway.sandboxVerdictReason):
# "Blocked by DefenseClaw rule ID: Title." or "Blocked by DefenseClaw
# policy.", then advice written for the agent ("... or ask the user to ..."),
# which the feed leaves out.
_VERDICT_REASON = re.compile(
    r"^((?:Blocked|Held for approval|Flagged) by DefenseClaw (?:rule \S+.*?|policy))\.(?:\s|$)", re.DOTALL
)


def verdict_reason(text: str) -> str:
    """A tool verdict's reason without the advice addressed to the agent."""
    text = text.strip()
    match = _VERDICT_REASON.match(text)
    return match.group(1) if match else text


_RUNNING_PHASES = frozenset({"ready", "running"})

# Every harness the Go tree runs (harness.Names()) as (connector name, display
# name, command): Claude Code and Codex, setup's defaults, first.
SANDBOX_HARNESS_SPECS: tuple[tuple[str, str, str], ...] = (
    ("claudecode", "Claude Code", "claude"),
    ("codex", "Codex", "codex"),
    ("amp", "Amp", "amp"),
    ("antigravity", "Antigravity", "agy"),
    ("copilot", "GitHub Copilot CLI", "copilot"),
    ("cursor", "Cursor Agent", "cursor-agent"),
    ("devin", "Devin CLI", "devin"),
    ("hermes", "Hermes Agent", "hermes"),
    ("kiro", "Kiro CLI", "kiro-cli-chat"),
    ("omnigent", "OmniGent", "omnigent"),
    ("opencode", "OpenCode", "opencode"),
    ("openhands", "OpenHands", "openhands"),
)
# sandboxcli.defaultHarnesses: the harnesses when openshell.harnesses is empty.
DEFAULT_SANDBOX_HARNESSES: tuple[str, ...] = ("claudecode", "codex")
# Harness command names (what the user types; sandboxcli.ResolveHarness takes them).
_HARNESS_COMMANDS = {name: command for name, _label, command in SANDBOX_HARNESS_SPECS}
# The same table by connector name: name → (command, display name).
HARNESSES: dict[str, tuple[str, str]] = {name: (command, label) for name, label, command in SANDBOX_HARNESS_SPECS}


def resolve_harness(name: str) -> str:
    """The harness ``name`` means, as sandboxcli.ResolveHarness reads it, or "".

    A harness name (``claude-code`` normalized), its command or its display
    name, in any case.
    """
    text = name.strip().lower()
    canonical = {"claude-code": "claudecode", "claude_code": "claudecode"}.get(text, text)
    canonical = {"open-hands": "openhands", "open_hands": "openhands"}.get(canonical, canonical)
    if canonical in HARNESSES:
        return canonical
    for harness, (command, display) in HARNESSES.items():
        if text in {command, display.lower(), display.lower().replace(" ", "")}:
            return harness
    return ""


def harness_command(name: str) -> str:
    """The command a harness runs as (``claudecode`` → ``claude``)."""
    return _HARNESS_COMMANDS.get(name, name)


def sandbox_keys_hint(view: str, *, unblock: bool = True, always: bool = True) -> str:
    """The hint bar's keys for a Sandboxes view (one line at 80 columns).

    ``unblock`` and ``always`` are False when the selected feed row or ask
    does not take ``u`` or ``A``, which the line then leaves out.
    """
    if view == "asks":
        return "KEYS  t view | Enter detail | a approve | " + ("A always | " if always else "") + "x reject | r refresh"
    if view == "activity":
        return (
            "KEYS  t view | Enter detail | "
            + ("u unblock | " if unblock else "")
            + "n new run | w sandboxed | r refresh"
        )
    return "KEYS  t view | c connect | s stop | d delete | U undo | R review | u unblock"


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


def normalize_host(host: str) -> str:
    """triage.NormalizeHost: lower case, no brackets, no trailing dot."""
    text = host.strip().lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return text.removesuffix(".")


def host_matches(pattern: str, host: str) -> bool:
    """Whether an unblock pattern covers ``host`` (exact, or ``*.`` for subdomains)."""
    pattern, host = normalize_host(pattern), normalize_host(host)
    if not pattern or not host:
        return False
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return pattern == host


def _paths_overlap(a: str, b: str) -> bool:
    """workspace.Overlaps: the same folder, or one inside the other."""
    a, b = a.rstrip(os.sep) or os.sep, b.rstrip(os.sep) or os.sep
    return a == b or a.startswith(b.rstrip(os.sep) + os.sep) or b.startswith(a.rstrip(os.sep) + os.sep)


def fit(text: str, width: int) -> str:
    """``text`` cut to ``width`` characters with an ellipsis (0 keeps it whole)."""
    if width <= 0 or len(text) <= width:
        return text
    return text[: max(0, width - 1)].rstrip() + "…"


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
    # Hook posts DefenseClaw answered with an error (a refused route, the
    # rate limit): each failed closed, so the harness did not do it.
    hook_failed: int = 0
    last_hook_failure: str = ""
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
    def hook_failure_alert(self) -> str:
        """The failed hook calls, as the daemon's hook.failed event words them."""
        if not self.hook_failed:
            return ""
        if self.hook_failed == 1:
            line = "1 hook call failed, so the harness's action was blocked (hooks fail closed)"
            answered = "DefenseClaw answered"
        else:
            line = f"{self.hook_failed} hook calls failed, so the harness's actions were blocked (hooks fail closed)"
            answered = "DefenseClaw last answered"
        return line + (f"; {answered} {self.last_hook_failure}" if self.last_hook_failure else "")

    @property
    def alerts(self) -> tuple[str, ...]:
        """Plain alert lines: hook tamper, planted repositories, failing or silent hooks."""
        out: list[str] = []
        if self.tampered:
            out.append(f"hook tamper: {self.tampered} tool call(s) ran without a DefenseClaw verdict")
        out.extend(repo.line for repo in self.nested_repos)
        if self.hooks_unreachable:
            why = f" ({self.unreachable_reason})" if self.unreachable_reason else ""
            out.append(f"{HOOKS_UNREACHABLE_WARNING}{why}. Run: defenseclaw sandbox doctor")
        elif self.ingress_refused:
            out.append(f"OpenShell refused {self.ingress_refused} hook request(s) to DefenseClaw")
        if self.hook_failed:
            out.append(self.hook_failure_alert)
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
        if self.hook_failed:
            parts.append("hook errors")
        if self.hooks_silent:
            parts.append("silent")
        if self.orphaned:
            parts.append("orphaned")
        return ", ".join(parts) or "-"


def _tool_calls_text(row: SandboxRow) -> str:
    """The Tool calls column: "57", or "57 (1 blocked)"."""
    if row.tool_blocked:
        return f"{row.tool_calls} ({row.tool_blocked} blocked)"
    return str(row.tool_calls)


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
        hook_failed=_int(hooks.get("hook_failed")),
        last_hook_failure=_text(hooks.get("last_hook_failure")),
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
    # An unblock (or an approved ask for the same host) lifted this block
    # since it happened; ``lifted_by`` says which.
    unblocked: bool = False
    lifted_by: str = ""

    @property
    def key(self) -> tuple[Any, ...]:
        """What tells this event apart from every other, across daemon restarts too."""
        return (self.seq, self.time, self.kind, self.sandbox, self.host, self.port)

    @property
    def blocked_destination(self) -> bool:
        return self.kind == "egress.blocked" and bool(self.host)

    @property
    def glyph(self) -> str:
        # Tool blocks get their own glyph: u lifts only blocked destinations (✗).
        return {
            "egress.allowed": "✓",
            "egress.blocked": "✗",
            "egress.unblocked": "↺",
            "egress.large_upload": "⚠",
            "approval.requested": "?",
            "approval.resolved": "·",
            "tool.blocked": "⊘",
            "hook.failed": "✗",
            "finding": "⚠",
            "sandbox.lifecycle": "·",
            "workspace": "·",
            "dropped": "…",
        }.get(self.kind, "·")

    @property
    def why(self) -> str:
        """The block's category or reason in plain words ("webhook catcher")."""
        return reason_label(self.category or self.reason)

    @property
    def explanation(self) -> str:
        """Why DefenseClaw blocked the destination, in a sentence when the daemon sent one."""
        reason = self.reason.strip()
        if reason and not _is_token(reason):
            return reason
        return self.why

    @property
    def summary(self) -> str:
        """The display line, without the glyph the daemon's message may carry."""
        text = self.message.strip()
        if text[:1] in {"✓", "✗", "⚠", "?", "↺", "⊘"}:
            text = text[1:].strip()
        if self.kind == "egress.allowed":
            return host_port(self.host, self.port) or text
        if self.kind == "egress.blocked":
            if not self.host:
                return text or reason_label(self.reason) or "a destination was blocked"
            why = self.why
            return host_port(self.host, self.port) + (f" ({why})" if why else "")
        if self.kind == "approval.requested":
            # The daemon's message is a whole sentence ("the sandbox asks to
            # reach port 5432 on your machine"), as the Go CLI prints it; a
            # triage reason that does not say what is asked ("approvals are
            # manual for the strict profile") gets the destination first.
            where = host_port(self.host, self.port)
            if text and (not self.host or self.host in text or "asks to reach" in text):
                return text
            if text:
                return f"asks to reach {where} ({text})"
            return "asks to reach " + (where or "a destination")
        if self.kind == "tool.blocked":
            tool = self.tool or "tool call"
            reason = verdict_reason(self.reason)
            if reason.startswith("Blocked by "):
                return f"{tool} blocked by {reason.removeprefix('Blocked by ')}"
            return f"{tool} blocked" + (f": {reason}" if reason else "")
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


def _approved(row: ActivityRow) -> bool:
    """Whether an approval.resolved event says OpenShell applied the approval.

    Its reason is then who approved it (manager.actorOperator,
    actorAutomatic); a rejection or a failed apply carries another reason.
    """
    return row.reason in {"operator", "automatic"} and row.message.strip().startswith("approved")


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
    allowed_ips: tuple[str, ...] = ()
    endpoint_hosts: tuple[str, ...] = ()

    @property
    def destination(self) -> str:
        return host_port(self.host, self.port) if self.host else "-"

    @property
    def kind_label(self) -> str:
        return {"host_port": "port on this machine", "network_rule": "network"}.get(self.kind, self.kind or "-")

    @property
    def always_refusal(self) -> str:
        """Why "always" is not offered for this ask, or "".

        The daemon opens a port on this machine, a private or IP-literal
        address, and a proposal with allowed IPs for one sandbox only
        (manager.alwaysApprovable); ``risky`` marks exactly that reach.
        """
        hosts = self.endpoint_hosts or ((self.host,) if self.host else ())
        if self.kind == "host_port" or any(_host_local(host) for host in hosts):
            port = f" {self.port}" if self.port else ""
            return f"a port on this machine opens for this sandbox only (future sandboxes: run with --host-port{port})"
        if self.risky or self.allowed_ips or any(_ip_literal(host) for host in hosts):
            return "private, IP-literal and host-local destinations open for this sandbox only"
        return ""

    @property
    def short_reason(self) -> str:
        """The reason without the destination the row already shows, for narrow tables."""
        text = self.reason.strip()
        for pattern, short in _SHORT_ASK_REASONS:
            match = pattern.search(text)
            if match:
                return short.format(*match.groups())
        return text

    @property
    def binary_name(self) -> str:
        return os.path.basename(self.binary.rstrip("/")) or self.binary


# triage.go's ask sentences, shortened to what they add to the destination.
_SHORT_ASK_REASONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"on your private network"), "private network"),
    (re.compile(r"reach port \S+ on your machine"), "port on this machine"),
    (re.compile(r"is not on the allowlist"), "not on the allowlist"),
    (re.compile(r"approvals are manual for the (\S+) profile"), "manual approvals ({0})"),
    (re.compile(r"the (\S+) profile has no web egress"), "no web egress ({0})"),
    (re.compile(r"^OpenShell's policy advisor flagged"), "flagged by OpenShell"),
)


def _host_local(host: str) -> bool:
    """triage.IsHostLocal: this machine's names and loopback or unspecified addresses."""
    text = normalize_host(host)
    if text in {"localhost", "host.openshell.internal", "host.docker.internal", "gateway.docker.internal"}:
        return True
    if text.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback or address.is_unspecified


def _ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(normalize_host(host))
    except ValueError:
        return False
    return True


def decode_ask(raw: Any) -> AskRow | None:
    item = _dict(raw)
    ask_id = _text(item.get("id")).strip()
    if not ask_id:
        return None
    raw_endpoints = [e for e in (_dict(x) for x in _list(item.get("endpoints"))) if e.get("host")]
    endpoints = tuple(host_port(_text(e.get("host")), _int(e.get("port"))) for e in raw_endpoints)
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
        allowed_ips=tuple(_text(ip) for ip in _list(item.get("allowed_ips")) if ip),
        endpoint_hosts=tuple(_text(e.get("host")) for e in raw_endpoints),
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
    # The event last_seq names, which tells a daemon that started its feed
    # over from one that stayed quiet (resume_point_lost).
    _resume_event: ActivityRow | None = None
    stream_state: str = "idle"
    admin: AdminPolicy = field(default_factory=AdminPolicy)
    wrappers: tuple[str, ...] = ()
    harnesses: tuple[str, ...] = ()
    # openshell.egress.unblocked: the hosts every sandbox may reach.
    saved_unblocks: tuple[str, ...] = ()
    _toasted: dict[tuple[str, str], float] = field(default_factory=dict)
    # Views whose selected item went away in a refresh. The cursor moved to
    # another item the operator did not pick, so the next action key there
    # is refused once.
    _selection_lost: set[str] = field(default_factory=set)

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
        selection = self._selection()
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
        self._follow_selection(selection)

    def set_error(self, message: str) -> None:
        """Record a failed refresh; the previous snapshot stays."""
        self.error = message

    def set_config(self, cfg: object | None) -> None:
        self.admin = admin_policy_from_config(cfg)
        openshell = getattr(cfg, "openshell", None)
        self.wrappers = tuple(str(w) for w in (getattr(openshell, "wrappers", None) or ()) if str(w).strip())
        self.harnesses = tuple(str(h) for h in (getattr(openshell, "harnesses", None) or ()) if str(h).strip())
        egress = getattr(openshell, "egress", None)
        self.saved_unblocks = tuple(
            str(h) for h in (getattr(egress, "unblocked", None) or ()) if isinstance(h, str) and h.strip()
        )

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
        selection = self._selection()
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
                if row.seq and row.seq == self.last_seq:
                    self._resume_event = row
            if row.kind == "egress.unblocked" and row.host:
                # Scope "always" lifts the host in every sandbox.
                self.mark_unblocked(row.sandbox, row.host, always=row.reason == "always")
            if row.kind == "approval.resolved" and row.host and _approved(row):
                # OpenShell now allows the host: its earlier blocks in that
                # sandbox are resolved.
                self.mark_unblocked(row.sandbox, row.host, lifted_by="approved")
            self.feed.append(row)
            if toast:
                notice = self._notice_for(row, now=now)
                if notice is not None:
                    notices.append(notice)
            if row.kind in {"approval.requested", "approval.resolved"}:
                self._apply_ask_event(row)
        self._follow_selection(selection)
        return notices

    def resume_point_lost(self, events: Any) -> bool:
        """Whether the daemon's feed started over, from a read of the events after ``last_seq - 1``.

        The feed keeps the event ``last_seq`` names until newer events push it
        out, so a feed that still counts on answers with it (or with newer
        ones). An empty answer, or another event under that number, is a new
        feed: the daemon restarted and numbers its events from one again, so
        resuming after ``last_seq`` would skip its first events.
        """
        if self.last_seq <= 0:
            return False
        rows = [row for row in (decode_activity(raw) for raw in _list(events)) if row and row.kind != "dropped"]
        if not rows:
            return True
        same = next((row for row in rows if row.seq == self.last_seq), None)
        if same is None:
            # Only newer events: they pushed the resume point out of the feed.
            return False
        return self._resume_event is not None and same.key != self._resume_event.key

    def reset_resume_point(self) -> None:
        """Read the daemon's feed from its start again (after resume_point_lost)."""
        self.last_seq = 0
        self._resume_event = None

    def mark_unblocked(self, sandbox: str, host: str, *, always: bool = False, lifted_by: str = "unblocked") -> None:
        """Mark the feed's earlier blocks of ``host`` as lifted.

        ``always`` covers every sandbox; otherwise only ``sandbox``'s blocks.
        A later block of the same host (say, on another port) arrives as a
        new event and is unblockable again. ``lifted_by`` is what the feed
        row says instead of "u unblocks" (unblocked, approved).
        """
        if not host:
            return
        changed = False
        rows: list[ActivityRow] = []
        for row in self.feed:
            if (
                row.blocked_destination
                and not row.unblocked
                and (always or row.sandbox == sandbox)
                and host_matches(host, row.host)
            ):
                row = replace(row, unblocked=True, unblockable=False, lifted_by=lifted_by)
                changed = True
            rows.append(row)
        if changed:
            self.feed = deque(rows, maxlen=FEED_LIMIT)

    def _apply_ask_event(self, row: ActivityRow) -> None:
        if row.kind == "approval.resolved" and row.approval_id:
            self.asks = tuple(ask for ask in self.asks if ask.id != row.approval_id)

    def remove_ask(self, ask_id: str) -> None:
        """Drop an ask the operator just decided; the cursor stays on the ask it was on."""
        selection = self._selection()
        self.asks = tuple(ask for ask in self.asks if ask.id != ask_id)
        if selection.get("asks") == ask_id:
            # The operator's own decision took it away: nothing to warn about.
            del selection["asks"]
        self._follow_selection(selection)

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
            where = f"{row.sandbox}: " if row.sandbox else ""
            return SandboxNotice("warn", f"? {where}{row.summary}. Sandboxes panel (7): press a to review")
        if row.kind == "finding" and row.reason == "hooks_unreachable":
            return SandboxNotice("error", f"{row.sandbox}: {row.summary}")
        if row.kind == "finding" and row.reason == "hooks_restored":
            return SandboxNotice("success", f"{row.sandbox}: {row.summary}")
        if row.kind == "finding" and row.reason == "nested_repo":
            return SandboxNotice("warn", f"⚠ {row.sandbox}: {row.summary}")
        if row.kind == "finding" and row.reason == "hook_tamper":
            return SandboxNotice("error", f"⚠ {row.sandbox}: {row.summary}. Sandboxes panel (7): Enter for details")
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

    def _item_keys(self, view: str) -> list[Any]:
        """Each row's identity, in display order: sandbox name, ask id, event key."""
        if view == "sandboxes":
            return [row.name for row in self.rows]
        if view == "asks":
            return [ask.id for ask in self.asks]
        return [row.key for row in self.feed_rows()]

    def _selection(self) -> dict[str, Any]:
        """The item each view's cursor is on (views with no rows are left out)."""
        out: dict[str, Any] = {}
        for view in SANDBOX_VIEWS:
            keys = self._item_keys(view)
            index = self.cursors.get(view, 0)
            if 0 <= index < len(keys):
                out[view] = keys[index]
        return out

    def _follow_selection(self, before: dict[str, Any]) -> None:
        """Keep each cursor on the item it was on before rows changed.

        Rows come and go (the poll replaces the lists, the feed shows the
        newest event first), so an index alone would point at another item
        after a refresh. When the item itself is gone, the view is marked so
        its next action key is refused rather than applied to a neighbour.
        """
        for view, key in before.items():
            keys = self._item_keys(view)
            if key in keys:
                self.cursors[view] = keys.index(key)
            else:
                self._selection_lost.add(view)
        self._clamp()

    def _take_lost_selection(self) -> str:
        """The refusal for an action key whose selected item went away, once."""
        if self.view not in self._selection_lost:
            return ""
        self._selection_lost.discard(self.view)
        gone = {
            "sandboxes": "The sandbox you selected is gone",
            "asks": "The ask you selected is no longer waiting",
            "activity": "The event you selected has left the feed",
        }[self.view]
        return f"{gone}; nothing was done. Check the selection, then press the key again."

    @property
    def cursor(self) -> int:
        return self.cursors.get(self.view, 0)

    @cursor.setter
    def cursor(self, value: int) -> None:
        self.cursors[self.view] = max(0, min(int(value), max(0, self._view_len(self.view) - 1)))
        # The operator picked the row: it is the selection now.
        self._selection_lost.discard(self.view)

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

    def live_mount_holder(self, folder: str) -> SandboxRow | None:
        """The sandbox that mounts ``folder`` (or a folder inside or around it) live, stopped or not.

        A folder takes one live mount (two would each undo the other's
        work), so the daemon refuses a second (sandboxcli.liveMountHolder).
        """
        if not folder:
            return None
        target = os.path.realpath(os.path.expanduser(folder))
        for row in sorted(self.rows, key=lambda row: row.name):
            if row.workdir_mode != "mount" or not row.project or row.phase == "deleted":
                continue
            if _paths_overlap(target, os.path.realpath(row.project)):
                return row
        return None

    def _sandbox_exists(self, name: str) -> bool:
        # Before the first list read nothing is known to be gone.
        return not name or not self.status.loaded or any(row.name == name for row in self.rows)

    def current_blocks(self, sandbox: str = "") -> tuple[ActivityRow, ...]:
        """Blocked destinations still in force, newest first.

        Blocks an unblock lifted, and blocks of sandboxes that no longer
        exist, are history only.
        """
        return tuple(
            row
            for row in reversed(self.feed)
            if row.blocked_destination
            and not row.unblocked
            and (not sandbox or row.sandbox == sandbox)
            and self._sandbox_exists(row.sandbox)
        )

    def latest_unblockable(self, sandbox: str = "") -> ActivityRow | None:
        return next((row for row in self.current_blocks(sandbox) if row.unblockable), None)

    def block_explanation(self, sandbox: str, host: str) -> str:
        """Why the newest block of ``host`` (in ``sandbox``, when named) happened, for the unblock dialog."""
        row = next(
            (row for row in self.current_blocks(sandbox) if host_matches(host, row.host) and row.explanation),
            None,
        )
        return row.explanation if row is not None else ""

    def _unblock_scope(self) -> tuple[bool, str]:
        """(scoped, sandbox): the sandbox ``u`` is limited to, when one is selected."""
        if self.view == "sandboxes":
            row = self.selected_sandbox()
            return (row is not None, row.name if row is not None else "")
        if self.view == "asks":
            ask = self.selected_ask()
            return (ask is not None and bool(ask.sandbox), ask.sandbox if ask is not None else "")
        return (False, "")

    def unblock_target(self) -> ActivityRow | None:
        """The blocked destination ``u`` acts on.

        In Activity, the selected feed row when it is a blocked destination.
        Elsewhere, the newest unblockable block of the selected sandbox (the
        ask's sandbox in Asks); never another sandbox's block. With no
        sandbox selected, the newest unblockable block.
        """
        if self.view == "activity":
            event = self.selected_event()
            return event if event is not None and event.blocked_destination else None
        scoped, sandbox = self._unblock_scope()
        if scoped:
            return self.latest_unblockable(sandbox)
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
                # The detail names its item: that is the selection now.
                self._selection_lost.discard(self.view)
                return SandboxPanelAction("detail")
            return SandboxPanelAction()
        if key in _SELECTION_KEYS or (key in {"a", "A", "x"} and self.view == "asks"):
            lost = self._take_lost_selection()
            if lost:
                return SandboxPanelAction("hint", hint=lost)
        if key == "u":
            return self._unblock_action()
        if key in {"a", "A"} or (key == "x" and self.view == "asks"):
            return self._ask_action(key)
        if key == "r":
            # Refresh in every view, as in every other panel; x rejects an ask.
            return SandboxPanelAction("refresh")
        if key == "n":
            return SandboxPanelAction("new_run")
        if key == "w":
            return SandboxPanelAction("wrappers")
        if key in {"U", "R", "s", "d", "c"}:
            return self._sandbox_action(key)
        return SandboxPanelAction()

    def _unblock_action(self) -> SandboxPanelAction:
        # openshell.admin.allow_unblock: false makes the daemon report every
        # block as not unblockable, so say why before looking at the flag.
        if self.admin.unblock_refused and self.current_blocks():
            return SandboxPanelAction("hint", hint=f"Unblocking is {ADMIN_MESSAGE}; {ADMIN_UNBLOCK_NEXT}.")
        if self.view == "activity":
            event = self.selected_event()
            if event is not None and event.kind == "tool.blocked":
                return SandboxPanelAction("hint", hint=TOOL_BLOCK_HINT)
            if event is None or not event.blocked_destination:
                return SandboxPanelAction("hint", hint="Select a blocked destination (✗) to unblock it.")
            if event.unblocked:
                where = f" for {event.sandbox}" if event.sandbox else ""
                return SandboxPanelAction("hint", hint=f"{event.host} is already unblocked{where}.")
            if not self._sandbox_exists(event.sandbox):
                return SandboxPanelAction("hint", hint=f"{event.sandbox} no longer exists.")
        target = self.unblock_target()
        if target is None:
            scoped, sandbox = self._unblock_scope()
            other = self.latest_unblockable() if scoped else None
            if other is not None and other.sandbox != sandbox:
                return SandboxPanelAction(
                    "hint",
                    hint=f"No blocked destination in {sandbox}. {other.host} was blocked in {other.sandbox}: "
                    "select that sandbox, or press t for Activity.",
                )
            if scoped:
                return SandboxPanelAction("hint", hint=f"No blocked destination in {sandbox} to unblock.")
            return SandboxPanelAction("hint", hint="No blocked destination to unblock.")
        if not target.unblockable:
            return SandboxPanelAction(
                "hint",
                hint=f"{target.host} cannot be unblocked here "
                "(private networks, metadata and your organization's blocks stay closed).",
            )
        return SandboxPanelAction("unblock", sandbox=target.sandbox, host=target.host)

    def _ask_action(self, key: str) -> SandboxPanelAction:
        ask = self.selected_ask()
        if ask is None:
            if not self.asks:
                return SandboxPanelAction("hint", hint="No asks are waiting.")
            self.view = "asks"
            self.cursor = 0
            return SandboxPanelAction(
                "view", hint="Review the ask, then press a to approve, A to always approve, x to reject."
            )
        if key == "x":
            return SandboxPanelAction("reject", sandbox=ask.sandbox, approval_id=ask.id)
        if key == "A" and self.admin.unblock_refused:
            return SandboxPanelAction("hint", hint=f"Always-approve is {ADMIN_MESSAGE}; press a to approve once.")
        if key == "A" and ask.always_refusal:
            return SandboxPanelAction(
                "hint", hint=f"No always for {ask.destination}: {ask.always_refusal}; press a to approve once."
            )
        return SandboxPanelAction("approve", sandbox=ask.sandbox, approval_id=ask.id, always=key == "A")

    def always_offered(self) -> bool:
        """Whether the selected ask may be approved for every sandbox (A)."""
        ask = self.selected_ask()
        return ask is not None and not ask.always_refusal and not self.admin.unblock_refused

    def unblock_offered(self) -> bool:
        """Whether ``u`` lifts the selected Activity row (a blocked destination still in force)."""
        event = self.selected_event()
        return (
            event is not None
            and event.blocked_destination
            and event.unblockable
            and not event.unblocked
            and not self.admin.unblock_refused
            and self._sandbox_exists(event.sandbox)
        )

    def saved_unblock_ignored(self, row: ActivityRow) -> bool:
        """A block of a host openshell.egress.unblocked lists, while the organization turns unblocks off."""
        return (
            self.admin.unblock_refused
            and row.blocked_destination
            and any(host_matches(pattern, row.host) for pattern in self.saved_unblocks)
        )

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

    def headline(self, max_width: int = 0) -> str:
        """The status line; ``max_width`` drops the gateway name first when short of room."""
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
        line = " · ".join(parts)
        if self.status.gateway:
            full = f"{line} · {self.status.gateway}"
            if not max_width or len(full) <= max_width:
                return full
        return line

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
        """The hint bar's keys for the view and the selected row."""
        if self.view == "activity":
            return sandbox_keys_hint(self.view, unblock=self.unblock_offered())
        if self.view == "asks":
            return sandbox_keys_hint(self.view, always=self.selected_ask() is None or self.always_offered())
        return sandbox_keys_hint(self.view)

    def data_table_columns(self, compact: bool = False) -> tuple[str, ...]:
        """``compact`` (a narrow terminal) leaves out what the Enter detail shows."""
        if self.view == "activity":
            return ("Time", "Sandbox", "", "Event")
        if self.view == "asks":
            if compact:
                return ("Sandbox", "Destination", "Binary", "Risk", "Reason")
            return ("Sandbox", "Kind", "Destination", "Binary", "Risk", "Reason")
        if compact:
            return ("Name", "Phase", "Harness", "Sites", "Blocked", "Tool calls", "Alerts")
        return ("Name", "Phase", "Harness", "Pack/Profile", "Mode", "Up", "Sites", "Blocked", "Tool calls", "Alerts")

    def _feed_suffix(self, row: ActivityRow) -> str:
        if row.unblocked:
            return f"  ({row.lifted_by or 'unblocked'})"
        if self.saved_unblock_ignored(row):
            return f"  ({ADMIN_UNBLOCK_IGNORED})"
        return "  (u unblocks)" if row.unblockable else ""

    def data_table_rows(self, compact: bool = False) -> tuple[tuple[str, ...], ...]:
        if self.view == "activity":
            return tuple(
                (row.time_text, row.sandbox or "-", row.glyph, row.summary + self._feed_suffix(row))
                for row in self.feed_rows()
            )
        if self.view == "asks":
            if compact:
                # The destination names the host, so the reason keeps only what it adds.
                return tuple(
                    (
                        ask.sandbox,
                        ask.destination,
                        ask.binary_name or "-",
                        "risky" if ask.risky else "-",
                        ask.short_reason or "-",
                    )
                    for ask in self.asks
                )
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
        if compact:
            return tuple(
                (
                    row.name,
                    row.phase or "-",
                    harness_command(row.harness) if row.harness in HARNESSES else row.harness_label,
                    str(row.destinations),
                    str(row.blocked),
                    _tool_calls_text(row),
                    row.alert_badge,
                )
                for row in self.rows
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
                _tool_calls_text(row),
                row.alert_badge,
            )
            for row in self.rows
        )

    def empty_state(self) -> str:
        if self.view == "activity":
            return "No activity yet. Destinations, blocks, tool blocks and findings appear here as they happen."
        if self.view == "asks":
            return NO_ASKS_TEXT
        if self.state() == "ready":
            return "No sandboxes yet. Press n to start one, or run: cd <project> && defenseclaw sandbox run claude"
        return ""

    def recent_blocks(self, limit: int = 3) -> tuple[ActivityRow, ...]:
        return self.current_blocks()[:limit]

    def block_notice(self, now: datetime | None = None) -> tuple[str, str, str]:
        """(block, where, note) for the header's one blocked-destination line.

        The newest block still in force from the last BLOCK_BANNER_SECONDS,
        the sandbox it happened in, and whether ``u`` lifts it from here and
        how many more there are. A block an unblock or an approved ask
        resolved, or an old one, is left to Activity. The panel shortens
        ``block`` first when the line is too long.
        """
        clock = now or datetime.now(timezone.utc)
        blocks = tuple(
            block
            for block in self.current_blocks()
            if block.time is None or (clock - block.time).total_seconds() <= BLOCK_BANNER_SECONDS
        )
        if not blocks:
            return "", "", ""
        row = blocks[0]
        where = f" in {row.sandbox}" if row.sandbox else ""
        notes: list[str] = []
        target = self.unblock_target()
        if self.saved_unblock_ignored(row):
            notes.append(ADMIN_UNBLOCK_IGNORED)
        elif self.admin.unblock_refused:
            notes.append(f"unblocking is {ADMIN_MESSAGE}")
        elif target is row:
            notes.append("u unblocks")
        elif row.unblockable and row.sandbox:
            notes.append("select it, then u")
        distinct = {(block.sandbox, block.host) for block in blocks} - {(row.sandbox, row.host)}
        if distinct:
            notes.append(f"{len(distinct)} more in Activity (t)")
        return f"✗ {row.summary}", where, " · ".join(notes)

    def alert_notice(self) -> tuple[str, str]:
        """(alert, note) for the header's one alert line; the rest are in Enter's detail."""
        pairs = [(row, alert) for row in self.rows for alert in row.alerts]
        if not pairs:
            return "", ""
        # Hooks that cannot reach DefenseClaw block every tool call: say that
        # first, then a tool that ran without a verdict (hook tamper).
        urgent = next((pair for pair in pairs if HOOKS_UNREACHABLE_WARNING in pair[1]), None) or next(
            (pair for pair in pairs if pair[1].startswith("hook tamper:")), None
        )
        row, alert = urgent or pairs[0]
        more = len(pairs) - 1
        note = f"+{more} more · Enter" if more else "Enter for details"
        return f"⚠ {row.name}: {alert}", note

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
            category = reason_label(event.category)
            if category:
                pairs.append(("Category", category))
            reason = verdict_reason(event.reason) if event.kind == "tool.blocked" else reason_label(event.reason)
            if reason and reason != category:
                pairs.append(("Reason", reason))
            if event.kind == "tool.blocked":
                pairs.append(("Decided by", TOOL_BLOCK_DECIDED_BY))
            if event.blocked_destination:
                if event.unblocked:
                    unblock = f"{event.lifted_by or 'unblocked'} since"
                elif self.saved_unblock_ignored(event):
                    unblock = f"{ADMIN_UNBLOCK_IGNORED}; {ADMIN_UNBLOCK_NEXT}"
                elif self.admin.unblock_refused:
                    unblock = f"{ADMIN_MESSAGE}; {ADMIN_UNBLOCK_NEXT}"
                elif event.unblockable:
                    unblock = "press u"
                else:
                    unblock = "not unblockable here (private networks, metadata and your organization's blocks)"
                pairs.append(("Unblock", unblock))
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
            if ask.always_refusal:
                decide = f"a approve once · x reject (no always: {ask.always_refusal})"
            elif self.admin.unblock_refused:
                decide = f"a approve once · x reject (always-approve is {ADMIN_MESSAGE})"
            else:
                decide = "a approve · A always approve · x reject"
            pairs.append(("Decide", decide))
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
            pairs.append(("Last tool block", verdict_reason(row.last_blocked)))
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
        """Tab-badge count: asks waiting plus distinct destinations ``u`` could lift."""
        blocks = {(row.sandbox, normalize_host(row.host)) for row in self.current_blocks() if row.unblockable}
        return len(self.asks) + len(blocks)

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
    """Label/value pairs for a ``POST /sandboxes/{name}/review`` answer.

    Scan warnings, flags and findings come before the file list: a skipped
    secret scan is a safety signal and must not sit below 25 file rows.
    """
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
        for warning in _list(report.get("warnings")):
            pairs.append(("Warning", _text(warning)))
        for flag in (_dict(f) for f in _list(report.get("flags"))):
            label = _text(flag.get("label") or flag.get("path"))
            severity = _text(flag.get("severity")).upper()
            detail = _text(flag.get("detail"))
            pairs.append((f"⚠ {severity}".strip(), f"{label}: {detail}" if detail else label))
        findings = _list(report.get("findings"))
        for finding in (_dict(f) for f in findings[:10]):
            title = _text(finding.get("title") or finding.get("rule_id") or finding.get("scanner"))
            location = _text(finding.get("location") or finding.get("path"))
            pairs.append(("Finding", f"{title} ({location})" if location else title))
        if len(findings) > 10:
            pairs.append(("", f"… and {len(findings) - 10} more finding(s) (defenseclaw sandbox review)"))
        changes = _list(report.get("changes"))
        for change in (_dict(c) for c in changes[:25]):
            pairs.append((f"  {_text(change.get('status'))}", _text(change.get("path"))))
        if len(changes) > 25:
            pairs.append(("", f"… and {len(changes) - 25} more (defenseclaw sandbox review --diff)"))
    if not pairs:
        pairs.append(("Summary", "No changes since the session started."))
    return tuple(pairs)


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _first(items: list[str], count: int) -> str:
    """``items`` joined, the first ``count`` of them (sandboxcli.firstN)."""
    shown = items[:count]
    if len(items) > count:
        shown.append(f"(+{len(items) - count} more)")
    return ", ".join(shown)


def _ignored(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [_dict(c) for c in _list(result.get("ignored")) if _dict(c).get("path")]


def undo_unrestored(response: Any) -> tuple[dict[str, Any], ...]:
    """The changes undo cannot put back (``UndoResult.Unrestored``).

    Files the snapshot holds no copy of: what git ignores and, outside git,
    dependency folders. Undo deletes only Python bytecode caches (removed).
    """
    result = _dict(_dict(response).get("result"))
    return tuple(c for c in _ignored(result) if not c.get("removed"))


def undo_unrestored_lines(response: Any, limit: int = 8) -> tuple[str, ...]:
    """One warning per change undo cannot restore, with what to do (sandboxcli.printUnrestored)."""
    unrestored = undo_unrestored(response)
    lines: list[str] = []
    for change in unrestored[:limit]:
        path = _text(change.get("path"))
        parts = []
        if touched := _int(change.get("added")) + _int(change.get("modified")):
            parts.append(f"{_plural(touched, 'file', 'files')} added or changed")
        if deleted := _int(change.get("deleted")):
            parts.append(f"{_plural(deleted, 'file', 'files')} deleted")
        what = ", ".join(parts) + " during the session"
        executables = [_text(e).removeprefix(path) for e in _list(change.get("executables"))]
        count = _int(change.get("executable_count"))
        if count:
            what += ", including " + ", ".join(executables)
            if count > len(executables):
                what += f" and {count - len(executables)} more that run on this machine"
        remedy = _text(change.get("remedy"))
        lines.append(f"undo cannot restore {path} ({what})" + (f": {remedy}" if remedy else ""))
    if len(unrestored) > limit:
        lines.append(
            f"… and {len(unrestored) - limit} more places undo cannot restore (`defenseclaw sandbox review` lists them)"
        )
    return tuple(lines)


def undo_preview_lines(response: Any, unrestored_limit: int = 8) -> tuple[str, ...]:
    """What undo would change and what it cannot put back (sandboxcli.printUndo)."""
    data = _dict(response)
    result = _dict(data.get("result"))
    lines: list[str] = []
    if data.get("summary"):
        lines.append(_text(data.get("summary")))
    changes = _list(result.get("changes"))
    if changes:
        paths = [_text(_dict(c).get("path")) for c in changes[:5]]
        more = f" and {len(changes) - 5} more" if len(changes) > 5 else ""
        lines.append(f"{len(changes)} file(s) go back to the snapshot: {', '.join(paths)}{more}.")
    head_before, head_after = _text(result.get("head_before")), _text(result.get("head_after"))
    branch_before, branch_after = _text(result.get("branch_before")), _text(result.get("branch_after"))
    if branch_before and branch_before != branch_after:
        lines.append(f"Switches back to branch {branch_before} at {head_before[:7] or 'its snapshot commit'}.")
    elif head_before and head_before != head_after:
        on = f" ({branch_before})" if branch_before else ""
        lines.append(
            f"Resets HEAD{on} from {head_after[:7] or 'none'} back to {head_before[:7]} "
            "(undo saves the session's state first)."
        )
    refs = _list(result.get("ref_changes"))
    if refs:
        lines.append(f"{len(refs)} branch/tag change(s) reset.")
    control = [_text(c) for c in _list(result.get("control_changes"))]
    if control:
        lines.append(f"Resets {_plural(len(control), 'git control file', 'git control files')}: {_first(control, 6)}.")
    if lost := len(_list(result.get("lost_objects"))):
        lines.append(f"Brings back {_plural(lost, 'pre-session commit', 'pre-session commits')} the session deleted.")
    if hidden := len(_list(result.get("hidden_removed"))):
        lines.append(f"Removes {_plural(hidden, 'file', 'files')} the session hid from git with changed ignore rules.")
    nested = _list(result.get("nested_repos"))
    if nested:
        lines.append(f"{len(nested)} planted git repositor{'y' if len(nested) == 1 else 'ies'} removed.")
    for change in _ignored(result):
        if change.get("removed"):
            touched = _int(change.get("added")) + _int(change.get("modified"))
            lines.append(
                f"Removes {_plural(touched, 'file', 'files')} the session wrote to {_text(change.get('path'))} "
                "(a Python bytecode cache)."
            )
    for pinned in _list(result.get("pinned_changes")):
        lines.append(f"{_text(pinned)} changed on this machine during the session; it is kept.")
    lines.extend(undo_unrestored_lines(response, unrestored_limit))
    return tuple(lines)


def undo_preview_text(response: Any, unrestored_limit: int = 8) -> str:
    """What undo would change, one line each, for the confirmation."""
    lines = undo_preview_lines(response, unrestored_limit)
    return "\n".join(lines) or "Nothing changed since the snapshot; undo has nothing to do."


def undo_is_empty(response: Any) -> bool:
    """Whether undo has nothing to put back (``UndoResult.Empty``).

    Changes undo cannot restore do not count (undo_unrestored lists them);
    bytecode caches it would delete do.
    """
    result = _dict(_dict(response).get("result"))
    if not result:
        return True
    lists = ("changes", "ref_changes", "control_changes", "nested_repos", "lost_objects")
    if any(_list(result.get(key)) for key in lists):
        return False
    if any(change.get("removed") for change in _ignored(result)):
        return False
    return _text(result.get("head_before")) == _text(result.get("head_after")) and _text(
        result.get("branch_before")
    ) == _text(result.get("branch_after"))


def undo_done_text(response: Any, name: str) -> str:
    """What a finished undo restored, except what it could not (sandboxcli.undoDone)."""
    data = _dict(response)
    message = _text(data.get("summary")) or f"{name}: the project folder is back to its pre-session snapshot"
    left = [_text(c.get("path")) for c in undo_unrestored(response)]
    if left:
        message += f", except {_first(left, 6)} (undo cannot restore them)"
    return message
