# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure Overview state for the Textual TUI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from defenseclaw.connector_paths import hermes_config_path, hermes_home
from defenseclaw.observability.display import redact_endpoint_for_display
from defenseclaw.tui.services import connector_filter
from defenseclaw.tui.services.ai_discovery_state import AIUsageSignal, AIUsageSnapshot

NoticeLevel = Literal["info", "warn", "error"]
STALENESS_WINDOW = timedelta(minutes=15)
MAX_AI_DISCOVERY_OVERVIEW_ROWS = 8


@dataclass(frozen=True)
class SubsystemHealth:
    state: str = ""
    since: str = ""
    last_error: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConnectorHealth:
    name: str = ""
    state: str = ""
    since: str = ""
    last_activity_at: str = ""
    tool_inspection_mode: str = ""
    subprocess_policy: str = ""
    requests: int = 0
    errors: int = 0
    tool_inspections: int = 0
    tool_blocks: int = 0
    subprocess_blocks: int = 0


@dataclass(frozen=True)
class ConnectorOverviewRow:
    """One row of the multi-connector Overview CONNECTORS table.

    Combines config (mode + rule pack), live ``/health`` status, and
    audit-derived activity counts so the operator can monitor every active
    connector's posture and traffic at a glance.
    """

    connector: str
    mode: str
    rule_pack: str
    last_activity: str
    calls: int
    blocks: int
    alerts: int
    status: str


@dataclass(frozen=True)
class HealthSnapshot:
    started_at: str = ""
    uptime_ms: int = 0
    gateway: SubsystemHealth = field(default_factory=SubsystemHealth)
    watcher: SubsystemHealth = field(default_factory=SubsystemHealth)
    api: SubsystemHealth = field(default_factory=SubsystemHealth)
    guardrail: SubsystemHealth = field(default_factory=SubsystemHealth)
    telemetry: SubsystemHealth = field(default_factory=SubsystemHealth)
    ai_discovery: SubsystemHealth = field(default_factory=SubsystemHealth)
    sinks: SubsystemHealth = field(default_factory=SubsystemHealth)
    sandbox: SubsystemHealth | None = None
    # ``connector`` is the primary/active connector (single-connector
    # back-compat). ``connectors`` lists every active connector with its own
    # live counters — the gateway emits this as ``/health``'s ``connectors[]``
    # array (see internal/gateway/health.go). The TUI uses it to render the
    # per-connector CONNECTORS table with live status + counts. Empty for
    # gateways that predate the array, in which case the Overview falls back
    # to the config-derived roster.
    connector: ConnectorHealth | None = None
    connectors: tuple[ConnectorHealth, ...] = ()


@dataclass(frozen=True)
class OverviewConfig:
    data_dir: str = ""
    environment: str = ""
    policy_dir: str = ""
    claw_mode: str = "openclaw"
    guardrail_enabled: bool = False
    guardrail_connector: str = ""
    guardrail_mode: str = "observe"
    guardrail_rule_pack_dir: str = ""
    guardrail_port: int = 0
    guardrail_model: str = ""
    guardrail_strategy: str = "default"
    guardrail_judge_enabled: bool = False
    guardrail_judge_model: str = ""
    hilt_enabled: bool = False
    hilt_min_severity: str = ""
    privacy_disable_redaction: bool = False
    llm_provider: str = ""
    llm_model: str = ""
    inspect_llm_provider: str = ""
    inspect_llm_model: str = ""
    cisco_ai_defense_endpoint: str = ""
    # Multi-connector roster (WU10): ``(connector, effective_mode)`` pairs,
    # populated by the adapter only when more than one connector is active
    # (``Config.active_connectors()`` + ``GuardrailConfig.effective_mode``).
    # Empty for the common single-connector install, so the Overview's
    # single "Agent" line renders unchanged.
    connector_modes: tuple[tuple[str, str], ...] = ()
    # Per-connector effective rule-pack label (basename of
    # ``GuardrailConfig.effective_rule_pack_dir(connector)``, e.g. "strict").
    # Kept as a parallel ``(connector, pack)`` tuple — rather than widening
    # ``connector_modes`` to a 3-tuple — so the many call sites that unpack
    # ``(connector, mode)`` keep working untouched. Empty for single-connector
    # installs. Surfaced on the roster rows so the Overview reflects that
    # connectors can enforce different packs (block thresholds), which the
    # process-global ``guardrail_strategy`` posture line cannot show.
    connector_packs: tuple[tuple[str, str], ...] = ()
    # Connectors that are configured + still in the roster (so their history
    # stays filterable) but have enforcement turned off via
    # ``guardrail disable --connector X`` (``GuardrailConfig.effective_enabled``
    # is False). Stored normalized (lowercase). The Overview marks these
    # DISABLED rather than hiding them; a *fully removed* connector simply
    # leaves ``active_connectors()`` and never reaches the roster at all.
    connector_disabled: tuple[str, ...] = ()
    # N3: scanner action overrides from the *active* policy's synced
    # ``data.json`` (``scanner_overrides`` → scanner_type → severity →
    # ``{install,file,runtime}`` → action). These live only in the active
    # policy YAML / ``data.json``; today only ``policy show`` surfaces them, so
    # ``defenseclaw status`` and the Overview guardrail summary are blind to a
    # policy that, say, downgrades a scanner surface to ``warn``/``allow``.
    # Stored flattened as ``(scanner_type, severity, surface, action)`` so the
    # frozen dataclass stays hashable; empty for the default config → no
    # Overview change. Populated by the adapter (which reads ``data.json``);
    # rendered via :func:`format_scanner_overrides_summary` /
    # :meth:`OverviewPanelModel.scanner_overrides_summary`.
    scanner_overrides: tuple[tuple[str, str, str, str], ...] = ()
    # A2: a non-empty diagnostic when the connector roster could not be fully
    # built — e.g. ``Config.active_connectors()`` raised on a malformed/alias
    # key, so the adapter degraded to a single-connector (or empty) view
    # instead of the full roster. The module-level builder in ``app.py`` can't
    # emit a status-line message itself (the TUI subtree has no stderr logger),
    # so it stuffs the reason here and the Overview surfaces it as a visible
    # error notice via :meth:`OverviewPanelModel.build_notices`, rather than the
    # roster silently collapsing (chip vanishes, ``m`` stops cycling, tiles
    # disappear). Empty (the common case) renders nothing.
    roster_error: str = ""

    def connector_is_disabled(self, name: str) -> bool:
        """True when ``name`` is in the roster but enforcement is disabled."""

        want = (name or "").strip().lower()
        return any(want == d.strip().lower() for d in self.connector_disabled)


@dataclass(frozen=True)
class DoctorCheck:
    status: str
    label: str
    detail: str = ""


@dataclass(frozen=True)
class DoctorCache:
    captured_at: datetime | None = None
    passed: int = 0
    failed: int = 0
    warned: int = 0
    skipped: int = 0
    checks: tuple[DoctorCheck, ...] = ()

    def is_empty(self) -> bool:
        return (
            self.captured_at is None
            and self.passed == 0
            and self.failed == 0
            and self.warned == 0
            and self.skipped == 0
            and not self.checks
        )

    def age(self, *, now: datetime | None = None) -> timedelta:
        if self.captured_at is None:
            return timedelta(seconds=-1)
        now = now or datetime.now(timezone.utc)
        return now - self.captured_at

    def is_stale(self, *, now: datetime | None = None) -> bool:
        if self.captured_at is None:
            return True
        return self.age(now=now) > STALENESS_WINDOW

    def top_failures(self, limit: int) -> tuple[DoctorCheck, ...]:
        if limit <= 0:
            return ()
        failures = [check for check in self.checks if check.status == "fail"]
        warnings = [check for check in self.checks if check.status == "warn"]
        return tuple((*failures, *warnings)[:limit])

    def missing_required_credentials(self) -> tuple[str, ...]:
        out: list[str] = []
        prefix = "credential "
        for check in self.checks:
            if check.status != "fail":
                continue
            if not check.label.startswith(prefix):
                continue
            name = check.label.removeprefix(prefix).strip()
            if name:
                out.append(name)
        return tuple(out)

    def summary_line(self) -> str:
        if self.is_empty():
            return "no data"
        parts: list[str] = []
        if self.passed:
            parts.append(f"{self.passed} pass")
        if self.failed:
            parts.append(f"{self.failed} fail")
        if self.warned:
            parts.append(f"{self.warned} warn")
        if self.skipped:
            parts.append(f"{self.skipped} skip")
        return ", ".join(parts) if parts else "no data"


@dataclass(frozen=True)
class EnforcementCounts:
    blocked_skills: int = 0
    allowed_skills: int = 0
    blocked_mcps: int = 0
    allowed_mcps: int = 0
    total_scans: int = 0
    active_alerts: int = 0


@dataclass(frozen=True)
class OverviewNotice:
    level: NoticeLevel
    message: str


@dataclass(frozen=True)
class ServiceCard:
    key: str
    name: str
    state: str
    detail: str = ""
    since: str = ""
    last_error: str = ""


@dataclass(frozen=True)
class ObservabilityDestinationRow:
    """One runtime-loaded OTel destination or audit sink for Overview."""

    name: str
    target: Literal["otel", "audit_sinks"]
    scope: str
    kind: str
    state: str
    signals: str
    endpoint: str
    routing: str = ""


@dataclass(frozen=True)
class RenderedDoctorCheck:
    badge: str
    label: str
    detail: str = ""
    stale: bool = False


@dataclass(frozen=True)
class DoctorBoxState:
    empty: bool
    summary_parts: tuple[str, ...] = ()
    age_label: str = ""
    stale: bool = False
    recovered: bool = False
    checks: tuple[RenderedDoctorCheck, ...] = ()
    all_green: bool = False


@dataclass(frozen=True)
class KeysStatus:
    available: bool
    missing: tuple[str, ...] = ()
    label: str = ""


@dataclass(frozen=True)
class OverviewAIDiscoveryRow:
    state: str
    state_badge: str
    name: str
    vendor: str
    confidence: str
    seen_label: str


@dataclass(frozen=True)
class OverviewAIDiscoveryBoxState:
    status: Literal["offline", "disabled", "empty", "ready"]
    message: str = ""
    summary_parts: tuple[str, ...] = ()
    rows: tuple[OverviewAIDiscoveryRow, ...] = ()
    overflow: int = 0


@dataclass(frozen=True)
class OverviewCommandIntent:
    label: str
    args: tuple[str, ...]
    binary: str = "defenseclaw"
    category: str = "overview"
    hint: str = ""

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


QUICK_ACTIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("s", "Scan all", ("skill", "scan", "--all")),
    ("d", "Doctor", ("doctor",)),
    ("i", "Inventory", ("aibom", "scan", "--json")),
    ("g", "Guardrail", ("setup", "guardrail")),
    ("m", "Mode", ("setup", "connector")),
    ("p", "Policy", ("policy", "list")),
    ("l", "Logs", ("logs",)),
    ("R", "Redaction", ("setup", "privacy")),
    ("N", "Notify", ("setup", "notifications")),
    ("u", "Upgrade", ("upgrade",)),
    ("X", "Uninstall", ("uninstall",)),
    # NOTE: ``?`` is intentionally NOT mapped here. Routing ``?``
    # through ``defenseclaw help`` (which is not a Click subcommand)
    # produced "No such command 'help'" and silently broke the
    # help key. ``?`` belongs to the App-level ``action_toggle_help``
    # binding that opens the structured in-TUI help overlay.
)


class OverviewPanelModel:
    """Pure Overview state. It exposes render-ready data, not terminal output."""

    def __init__(self, cfg: OverviewConfig | None = None, *, version: str = "") -> None:
        self.cfg = cfg
        self.version = version
        self.health: HealthSnapshot | None = None
        self.doctor: DoctorCache | None = None
        self.enforcement = EnforcementCounts()
        self.silent_bypass = 0
        self.ai_usage: AIUsageSnapshot | None = None
        self.ai_usage_sorted: tuple[AIUsageSignal, ...] = ()
        self.skill_scanner_available = True

    def set_cfg(self, cfg: OverviewConfig | None) -> None:
        """Hot-swap the cached config snapshot (e.g. after ``setup``).

        Mirrors the Go ``reloadConfigAfterSetupCommand`` write to
        ``m.overview.cfg`` — without it the CONFIGURATION box keeps
        showing the snapshot captured at TUI startup forever.
        """

        self.cfg = cfg

    def set_health(self, health: HealthSnapshot | None) -> None:
        self.health = health

    def set_doctor_cache(self, cache: DoctorCache | None) -> None:
        self.doctor = cache

    def set_enforcement_counts(self, counts: EnforcementCounts) -> None:
        self.enforcement = counts

    def set_silent_bypass_count(self, count: int) -> None:
        self.silent_bypass = max(count, 0)

    def set_ai_usage(self, snapshot: AIUsageSnapshot | None) -> None:
        self.ai_usage = snapshot
        self.ai_usage_sorted = sort_ai_discovery_signals_for_overview(snapshot.signals if snapshot else ())

    def set_skill_scanner_available(self, available: bool) -> None:
        self.skill_scanner_available = available

    def action_intent(self, key: str) -> OverviewCommandIntent | None:
        if key == "m":
            return None
        for action_key, label, args in QUICK_ACTIONS:
            if action_key == key:
                return OverviewCommandIntent(label=label, args=args)
        return None

    def build_notices(self, *, now: datetime | None = None) -> tuple[OverviewNotice, ...]:
        now = now or datetime.now(timezone.utc)
        notices: list[OverviewNotice] = []
        gateway_broken = self.health is None or gateway_health_is_broken(self.health.gateway.state)
        gateway_standalone = self.health is not None and self.health.gateway.state.strip().lower() == "disabled"
        guardrail_off = self.cfg is None or not self.cfg.guardrail_enabled

        if gateway_broken and guardrail_off and not self.skill_scanner_available:
            notices.append(
                OverviewNotice(
                    "info",
                    "First time? Head to the Setup tab (press 0) to configure DefenseClaw.",
                )
            )
        if gateway_broken:
            notices.append(OverviewNotice("error", 'Gateway is offline - press : then "start" to launch'))
        elif gateway_standalone:
            hint = self.gateway_standalone_hint()
            if hint:
                notices.append(OverviewNotice("info", hint))
        if self.cfg is not None and self.cfg.roster_error.strip():
            notices.append(
                OverviewNotice(
                    "error",
                    "Connector roster degraded: "
                    f"{self.cfg.roster_error.strip()} - showing a reduced view; "
                    "check your connector config",
                )
            )
        if self.cfg is not None and guardrail_off:
            notices.append(OverviewNotice("warn", "LLM guardrail not configured - press [g] to set up"))
        if not self.skill_scanner_available:
            notices.append(OverviewNotice("warn", "skill-scanner not on PATH - run: pip install skill-scanner"))
        if self.silent_bypass > 0:
            notices.append(
                OverviewNotice(
                    "warn",
                    f"{self.silent_bypass} silent LLM bypass event(s) in the last 5m - see Alerts -> egress",
                )
            )

        if self.doctor is not None and not self.doctor.is_empty():
            _, contradicted = partition_doctor_checks(self.doctor.checks, self.health)
            stale_failures = sum(1 for check in contradicted if check.status == "fail")
            effective_failed = max(self.doctor.failed - stale_failures, 0)
            if effective_failed > 0:
                notices.append(
                    OverviewNotice(
                        "error",
                        f"Doctor found {effective_failed} failure(s) - see the DOCTOR panel or run: defenseclaw doctor",
                    )
                )
            elif contradicted:
                notices.append(
                    OverviewNotice(
                        "info",
                        f"Doctor cache shows {len(contradicted)} stale failure(s) that /health disagrees with - "
                        "press [d] to refresh",
                    )
                )
            elif self.doctor.is_stale(now=now):
                notices.append(OverviewNotice("info", "Doctor cache is stale - press [d] on Overview to re-probe"))

            missing = self.doctor.missing_required_credentials()
            if missing:
                preview = missing[:2]
                notices.append(
                    OverviewNotice(
                        "error",
                        "Missing required API key(s): "
                        f"{', '.join(preview)}{keys_overflow_suffix(len(missing), len(preview))} "
                        "- run: defenseclaw keys fill-missing",
                    )
                )

        if self.health is not None and self.health.connector is not None and self.cfg is not None:
            live = self.health.connector.name.strip()
            configured = self.cfg.claw_mode.strip()
            if live and configured and live != configured:
                notices.append(
                    OverviewNotice(
                        "warn",
                        "Connector drift: configured "
                        f"{friendly_connector_name(configured)} but gateway is routing for "
                        f"{friendly_connector_name(live)} - restart the sidecar after editing claw.mode",
                    )
                )
            uptime = timedelta(milliseconds=self.health.uptime_ms)
            if self.health.connector.requests == 0 and uptime > timedelta(minutes=1):
                notices.append(OverviewNotice("info", zero_connector_requests_notice(live, uptime)))

        return tuple(notices)

    def service_cards(self) -> tuple[ServiceCard, ...]:
        services = (
            ("gateway", "Gateway"),
            ("agent", "Agent"),
            ("watcher", "Watchdog"),
            ("guardrail", "Guardrail"),
            ("api", "API"),
            ("sinks", "Sinks"),
            ("telemetry", "Telemetry"),
            ("ai_discovery", "AI Discovery"),
            ("sandbox", "Sandbox"),
        )
        cards: list[ServiceCard] = []
        for key, name in services:
            health = self.subsystem_health(key)
            cards.append(
                ServiceCard(
                    key=key,
                    name=name,
                    state=self.subsystem_state(key),
                    detail=self.service_detail(key),
                    since=health.since if health else "",
                    last_error=health.last_error if health else "",
                )
            )
        return tuple(cards)

    def doctor_box(self, *, now: datetime | None = None) -> DoctorBoxState:
        now = now or datetime.now(timezone.utc)
        if self.doctor is None or self.doctor.is_empty():
            return DoctorBoxState(empty=True)

        stale_checks = tuple(
            check for check in self.doctor.top_failures(3) if live_health_contradicts(check, self.health)
        )
        stale_failures = sum(
            1 for check in self.doctor.checks if check.status == "fail" and live_health_contradicts(check, self.health)
        )
        stale_warnings = sum(
            1 for check in self.doctor.checks if check.status == "warn" and live_health_contradicts(check, self.health)
        )
        effective_failed = max(self.doctor.failed - stale_failures, 0)
        effective_warned = max(self.doctor.warned - stale_warnings, 0)
        stale_count = stale_failures + stale_warnings

        parts: list[str] = []
        if self.doctor.passed:
            parts.append(f"{self.doctor.passed} pass")
        if effective_failed:
            parts.append(f"{effective_failed} fail")
        if effective_warned:
            parts.append(f"{effective_warned} warn")
        if stale_count:
            parts.append(f"{stale_count} stale")
        if self.doctor.skipped:
            parts.append(f"{self.doctor.skipped} skip")

        rendered: list[RenderedDoctorCheck] = []
        for check in self.doctor.top_failures(3):
            stale = check in stale_checks
            badge = "STALE" if stale else check.status.upper()
            detail = f"{check.detail} (live state OK)" if stale and check.detail else check.detail
            rendered.append(RenderedDoctorCheck(badge=badge, label=check.label, detail=detail, stale=stale))

        return DoctorBoxState(
            empty=False,
            summary_parts=tuple(parts),
            age_label=format_age(self.doctor.age(now=now)),
            stale=self.doctor.is_stale(now=now),
            recovered=stale_count > 0,
            checks=tuple(rendered),
            all_green=not rendered,
        )

    def keys_status(self) -> KeysStatus:
        if self.doctor is None or self.doctor.is_empty():
            return KeysStatus(False)
        missing = self.doctor.missing_required_credentials()
        if not missing:
            return KeysStatus(True, label="all required set")
        preview = missing[:2]
        label = f"{len(missing)} missing: {', '.join(preview)}{keys_overflow_suffix(len(missing), len(preview))}"
        return KeysStatus(True, missing=missing, label=label)

    def ai_discovery_box(self, *, now: datetime | None = None) -> OverviewAIDiscoveryBoxState:
        now = now or datetime.now(timezone.utc)
        if self.ai_usage is None:
            return OverviewAIDiscoveryBoxState(
                "offline",
                "ai discovery offline - run: defenseclaw agent discovery status",
            )
        if not self.ai_usage.enabled:
            return OverviewAIDiscoveryBoxState(
                "disabled",
                "disabled - run: defenseclaw agent discovery enable",
            )

        summary = self.ai_usage.summary
        parts = [f"{summary.active_signals} active"]
        if summary.new_signals:
            parts.append(f"{summary.new_signals} new")
        if summary.changed_signals:
            parts.append(f"{summary.changed_signals} changed")
        if summary.gone_signals:
            parts.append(f"{summary.gone_signals} gone")
        if summary.scanned_at:
            parts.append(f"scanned {format_scan_age(summary.scanned_at, now=now)}")
        if summary.privacy_mode:
            parts.append(f"mode {summary.privacy_mode}")

        if not self.ai_usage.signals:
            return OverviewAIDiscoveryBoxState(
                "empty",
                "no AI agents detected yet - try: defenseclaw agent discover",
                summary_parts=tuple(parts),
            )

        rows = unique_ai_discovery_signals_for_overview(
            self.ai_usage_sorted or sort_ai_discovery_signals_for_overview(self.ai_usage.signals)
        )
        overflow = max(len(rows) - MAX_AI_DISCOVERY_OVERVIEW_ROWS, 0)
        rendered = tuple(
            OverviewAIDiscoveryRow(
                state=signal.state,
                state_badge=ai_discovery_state_badge(signal.state),
                name=display_ai_discovery_name(signal),
                vendor=display_ai_discovery_vendor(signal),
                confidence=f"{clamp_percent(signal.confidence * 100):3d}%",
                seen_label=f"seen {format_scan_age(signal.last_seen, now=now)}",
            )
            for signal in rows[:MAX_AI_DISCOVERY_OVERVIEW_ROWS]
        )
        return OverviewAIDiscoveryBoxState(
            "ready",
            summary_parts=tuple(parts),
            rows=rendered,
            overflow=overflow,
        )

    def subsystem_state(self, key: str) -> str:
        if self.health is None:
            return "unknown"
        match key:
            case "gateway":
                return self.health.gateway.state
            case "agent":
                # 8.13: a multi-connector install rolls the per-connector
                # states up into one aggregate (the per-connector detail lives
                # in the dedicated CONNECTORS table). Single-connector keeps the
                # legacy single-connector state.
                # Delegate to the aggregate when there are live connectors, or
                # when every rostered connector is disabled (the gateway drops
                # disabled connectors, so connectors[] is empty but the right
                # answer is "disabled", not "unknown").
                if self._is_multi_connector() and (self.health.connectors or self._all_connectors_disabled()):
                    return self._aggregate_connector_state()
                if self.health.connector is None:
                    return "unknown"
                return self.health.connector.state or "unknown"
            case "watcher":
                return self.health.watcher.state
            case "guardrail":
                return self.health.guardrail.state
            case "sinks":
                return self.health.sinks.state
            case "telemetry":
                return self.health.telemetry.state
            case "ai_discovery":
                return self.health.ai_discovery.state
            case "api":
                return self.health.api.state
            case "sandbox":
                return self.health.sandbox.state if self.health.sandbox is not None else "disabled"
            case _:
                return "unknown"

    def subsystem_health(self, key: str) -> SubsystemHealth | None:
        if self.health is None:
            return None
        match key:
            case "gateway":
                return self.health.gateway
            case "watcher":
                return self.health.watcher
            case "guardrail":
                return self.health.guardrail
            case "sinks":
                return self.health.sinks
            case "telemetry":
                return self.health.telemetry
            case "ai_discovery":
                return self.health.ai_discovery
            case "api":
                return self.health.api
            case "sandbox":
                return self.health.sandbox
            case _:
                return None

    def service_detail(self, key: str) -> str:
        match key:
            case "gateway":
                return self.gateway_detail()
            case "agent":
                return self.agent_detail()
            case "watcher":
                return self.watchdog_detail()
            case "guardrail":
                return self.guardrail_detail()
            case "api":
                return string_detail(self.health.api.details, "addr") if self.health else ""
            case "ai_discovery":
                return self.ai_discovery_detail()
            case "telemetry":
                return self.telemetry_detail()
            case _:
                return ""

    def gateway_detail(self) -> str:
        if self.health is None:
            return ""
        if self.health.gateway.state.strip().lower() == "disabled":
            if summary := string_detail(self.health.gateway.details, "summary"):
                return summary
        uptime = timedelta(milliseconds=self.health.uptime_ms)
        if uptime.total_seconds() > 0:
            return f"up {format_duration(uptime)}"
        return ""

    def gateway_standalone_hint(self) -> str:
        if self.health is None:
            return ""
        return string_detail(self.health.gateway.details, "hint") or string_detail(
            self.health.gateway.details,
            "summary",
        )

    def active_connector_name(self) -> str:
        """Primary connector name, or ``""`` when none is configured.

        A1 (Root R1, TUI-display-only per fix-plan §10.1): never fabricate
        ``"openclaw"`` for an empty / hook-only state. Precedence: explicit
        singular override (``guardrail.connector``) → the active *set*'s
        primary (``connector_modes`` — the multi-connector roster that the
        singular ``config.active_connector()`` ignores, which is why a
        ``[codex, openclaw]`` map used to surface a phantom ``openclaw``) →
        the singular ``claw.mode`` → ``""`` (none configured). The Go-parity
        ``config.active_connector()`` contract is deliberately left untouched;
        this distinguishes "none configured" at the display layer only.
        Callers treat ``""`` as "no connector present" (e.g. the app's
        ``connector_present`` gate / merged-catalog fallback).

        The genuinely-zero-connector case additionally depends on the adapter
        passing an empty ``claw_mode`` rather than the collapsed ``"openclaw"``
        default — that adapter half lives in ``app.py`` (the ``tui/app`` lane).
        """
        if self.cfg is None:
            return ""
        if self.cfg.guardrail_connector.strip():
            return self.cfg.guardrail_connector.strip().lower()
        primary = connector_filter.active_connector_name(self.cfg.connector_modes)
        if primary:
            return primary.strip().lower()
        if self.cfg.claw_mode.strip():
            return self.cfg.claw_mode.strip().lower()
        return ""

    def scanner_overrides_summary(self) -> str:
        """One-line summary of the active policy's scanner action overrides,
        or ``""`` when there are none (N3).

        Surfaces overrides that today live only in ``policy show`` /
        ``data.json``. Empty (the default config) renders nothing, so the
        Overview is unchanged until the adapter populates
        :attr:`OverviewConfig.scanner_overrides`. See
        :func:`format_scanner_overrides_summary`.
        """
        if self.cfg is None:
            return ""
        return format_scanner_overrides_summary(self.cfg.scanner_overrides)

    def multi_connector_rows(self) -> list[tuple[str, str]]:
        """Per-connector ``(label, detail)`` rows for the Overview.

        WU10: the single "Agent" line names only the primary connector,
        so multi-connector installs get an additional config-derived
        roster sourced from :attr:`OverviewConfig.connector_modes`
        (``Config.active_connectors()`` + ``GuardrailConfig.effective_mode``,
        resolved in the adapter). Returns ``[]`` when fewer than two
        connectors are active, leaving the single-connector layout
        untouched. ``label`` is the empty string so the existing
        ``key:<16`` formatting renders each entry as an indented
        sub-line under "Agent".

        Each row also carries the connector's effective rule-pack label
        (from :attr:`OverviewConfig.connector_packs`) when known, e.g.
        ``Codex (codex) — mode=action, strict``. This is the only place
        the Overview surfaces per-connector packs: the process-global
        ``Policy posture`` line names just one pack and would otherwise
        hide that connectors enforce different block thresholds.
        """
        if self.cfg is None or len(self.cfg.connector_modes) <= 1:
            return []
        packs = dict(self.cfg.connector_packs)
        rows: list[tuple[str, str]] = []
        for connector, mode in self.cfg.connector_modes:
            label = friendly_connector_name(connector)
            detail = f"{label} ({connector}) — mode={mode or '?'}"
            pack = (packs.get(connector) or "").strip()
            if pack:
                detail += f", {pack}"
            rows.append(("", detail))
        return rows

    _RUNNING_STATES = frozenset({"running", "active", "enabled"})

    def _is_multi_connector(self) -> bool:
        return self.cfg is not None and len([c for c, _m in self.cfg.connector_modes if c]) > 1

    def _all_connectors_disabled(self) -> bool:
        """True when every rostered connector has enforcement disabled."""

        if self.cfg is None:
            return False
        rostered = [c for c, _m in self.cfg.connector_modes if c]
        return bool(rostered) and all(self.cfg.connector_is_disabled(c) for c in rostered)

    def _aggregate_connector_state(self) -> str:
        """Roll per-connector states into one SERVICES "Agent" state.

        ``running`` only when every live connector is up; ``degraded`` when
        some (but not all) are up; otherwise the first connector's state (or
        ``unknown``). Mirrors how an operator reads the CONNECTORS table.
        """

        states = [(conn.state or "").strip().lower() for conn in (self.health.connectors if self.health else ())]
        if not states:
            # No live connectors. If every rostered connector is disabled,
            # say so explicitly instead of the generic "unknown".
            if self.cfg is not None:
                rostered = [c for c, _m in self.cfg.connector_modes if c]
                if rostered and all(self.cfg.connector_is_disabled(c) for c in rostered):
                    return "disabled"
            return "unknown"
        running = [state for state in states if state in self._RUNNING_STATES]
        if len(running) == len(states):
            return "running"
        if running:
            return "degraded"
        return states[0] or "unknown"

    def agent_detail(self) -> str:
        configured = self.cfg.claw_mode if self.cfg else ""
        # 8.13: in a multi-connector install the single connector name is
        # misleading and the gateway-wide counters duplicate the CONNECTORS
        # table, so the Agent row collapses to an "N connectors active" roll-up.
        if self._is_multi_connector():
            total = len([c for c, _m in self.cfg.connector_modes if c])
            # Disabled connectors stay in the roster (history) but enforce
            # nothing, so they're reported separately and excluded from the
            # "active" denominator.
            disabled_n = sum(1 for c, _m in self.cfg.connector_modes if c and self.cfg.connector_is_disabled(c))
            enabled_total = max(total - disabled_n, 0)
            live = self.health.connectors if self.health else ()
            running = sum(1 for conn in live if (conn.state or "").strip().lower() in self._RUNNING_STATES)
            if not disabled_n:
                # No kill switches → original phrasing, unchanged.
                if not live:
                    return f"{total} connectors configured"
                if running == total:
                    return f"{total} connectors active"
                return f"{running}/{total} connectors running"
            # One or more connectors disabled: report them separately.
            suffix = f" · {disabled_n} disabled"
            if enabled_total == 0:
                return f"0 active{suffix}"
            if live and running < enabled_total:
                return f"{running}/{enabled_total} running{suffix}"
            return f"{enabled_total} active{suffix}"
        if self.health is None or self.health.connector is None:
            if not configured:
                return ""
            return f"{friendly_connector_name(configured)} (configured, not connected)"
        connector = self.health.connector
        parts = [friendly_connector_name(connector.name)]
        if connector.tool_inspection_mode:
            parts.append(connector.tool_inspection_mode)
        if connector.requests:
            parts.append(f"{connector.requests} req")
        if connector.tool_blocks:
            parts.append(f"{connector.tool_blocks} tool blocks")
        if connector.subprocess_blocks:
            parts.append(f"{connector.subprocess_blocks} subprocess blocks")
        return " - ".join(parts)

    def watchdog_detail(self) -> str:
        if self.health is None:
            return ""
        details = self.health.watcher.details
        parts: list[str] = []
        if "skill_dirs" in details:
            parts.append(f"{details['skill_dirs']} skill dirs")
        if "plugin_dirs" in details:
            parts.append(f"{details['plugin_dirs']} plugin dirs")
        return ", ".join(parts)

    def guardrail_detail(self) -> str:
        if self.cfg is None or not self.cfg.guardrail_enabled:
            return ""
        parts: list[str] = []
        if self.cfg.guardrail_mode:
            parts.append(self.cfg.guardrail_mode)
        if self.cfg.guardrail_port:
            parts.append(f"port {self.cfg.guardrail_port}")
        if self.cfg.guardrail_strategy:
            parts.append(self.cfg.guardrail_strategy)
        if self.cfg.guardrail_judge_enabled and self.cfg.guardrail_judge_model:
            parts.append(f"judge:{self.cfg.guardrail_judge_model}")
        return ", ".join(parts)

    def ai_discovery_detail(self) -> str:
        if self.health is None:
            return ""
        details = self.health.ai_discovery.details
        parts: list[str] = []
        if "active_signals" in details:
            parts.append(f"{details['active_signals']} active")
        if "new_signals" in details:
            parts.append(f"{details['new_signals']} new")
        if "mode" in details:
            parts.append(str(details["mode"]))
        return ", ".join(parts)

    def telemetry_detail(self) -> str:
        """Summarize named OTLP destinations without exposing headers."""

        if self.health is None:
            return ""
        details = self.health.telemetry.details
        destinations = details.get("destinations")
        if isinstance(destinations, list):
            names: list[str] = []
            for item in destinations:
                if not isinstance(item, dict) or not item.get("enabled") or not item.get("name"):
                    continue
                label = str(item["name"])
                if str(item.get("preset", "")).lower() == "galileo" or label.lower() == "galileo":
                    label = "Galileo"
                delivery = item.get("delivery")
                if isinstance(delivery, dict) and delivery.get("attempted"):
                    try:
                        attempted = max(0, int(delivery.get("attempted", 0) or 0))
                        delivered = max(
                            0,
                            int(
                                delivery.get(
                                    "collector_accepted",
                                    delivery.get("delivered", 0),
                                )
                                or 0
                            ),
                        )
                    except (TypeError, ValueError):
                        attempted = delivered = 0
                    if attempted:
                        label += f" ({100 * delivered / attempted:.1f}% delivered)"
                else:
                    routing = item.get("routing")
                    if isinstance(routing, dict) and routing.get("total"):
                        try:
                            percentage = float(
                                routing.get(
                                    "eligibility_percentage",
                                    routing.get("accepted_percentage", 0),
                                )
                            )
                        except (TypeError, ValueError):
                            percentage = 0
                        label += f" ({percentage:.1f}% eligible; awaiting delivery)"
                names.append(label)
            count = details.get("destination_count", len(destinations))
            suffix = f": {', '.join(names)}" if names else ""
            return f"{count} destination{'s' if count != 1 else ''}{suffix}"
        parts: list[str] = []
        if details.get("signals"):
            parts.append(str(details["signals"]))
        if details.get("endpoint"):
            parts.append(
                redact_endpoint_for_display(str(details["endpoint"]), hide_path=True)
            )
        return ", ".join(parts)

    def observability_destination_rows(self) -> tuple[ObservabilityDestinationRow, ...]:
        """Return every runtime-loaded OTel route and audit sink.

        The health API deliberately omits headers and secret values, making it
        the safest source for an always-visible Overview inventory. OTel
        destinations and audit sinks are separate routing planes, so each row
        keeps ``target`` and process/global/connector ``scope`` explicit.
        """

        if self.health is None:
            return ()

        rows: list[ObservabilityDestinationRow] = []
        telemetry = self.health.telemetry.details.get("destinations")
        if isinstance(telemetry, list):
            for item in telemetry:
                if not isinstance(item, dict) or not item.get("name"):
                    continue
                name = str(item["name"])
                preset = str(item.get("preset", "") or "")
                kind = preset or "otlp"
                signals = str(item.get("signals", "") or "none")
                routing_label = ""
                routing = item.get("routing")
                if isinstance(routing, dict):
                    try:
                        accepted = max(0, int(routing.get("accepted", 0) or 0))
                        dropped = max(0, int(routing.get("dropped", 0) or 0))
                    except (TypeError, ValueError):
                        accepted = dropped = 0
                    try:
                        total = max(accepted + dropped, int(routing.get("total", 0) or 0))
                    except (TypeError, ValueError):
                        total = accepted + dropped
                    if total:
                        try:
                            percentage = float(
                                routing.get(
                                    "eligibility_percentage",
                                    routing.get("accepted_percentage", 100 * accepted / total),
                                )
                            )
                        except (TypeError, ValueError):
                            percentage = 0.0
                        routing_label = f"{percentage:.1f}% ({accepted}/{total})"
                    else:
                        routing_label = "waiting"
                delivery = item.get("delivery")
                if isinstance(delivery, dict):
                    try:
                        attempted = max(0, int(delivery.get("attempted", 0) or 0))
                        delivered = max(
                            0,
                            int(delivery.get("collector_accepted", delivery.get("delivered", 0)) or 0),
                        )
                        rejected = max(0, int(delivery.get("rejected", 0) or 0))
                        failed = max(0, int(delivery.get("failed", 0) or 0))
                        pending = max(0, int(delivery.get("pending", 0) or 0))
                    except (TypeError, ValueError):
                        attempted = delivered = rejected = failed = pending = 0
                    if attempted:
                        routing_label = (
                            f"collector accepted {delivered}/{attempted}; pending {pending}; "
                            f"rejected {rejected}; failed {failed}"
                        )
                rows.append(
                    ObservabilityDestinationRow(
                        name="Galileo" if name.lower() == "galileo" else name,
                        target="otel",
                        scope=str(item.get("scope", "") or "process"),
                        kind=kind,
                        state="enabled" if bool(item.get("enabled", False)) else "disabled",
                        signals=signals,
                        endpoint=redact_endpoint_for_display(str(item.get("endpoint", "") or "—")),
                        routing=routing_label,
                    )
                )

        sinks = self.health.sinks.details.get("sinks")
        if isinstance(sinks, list):
            for item in sinks:
                if not isinstance(item, dict) or not item.get("name"):
                    continue
                endpoint = redact_endpoint_for_display(
                    str(item.get("endpoint") or item.get("url") or "—"),
                    hide_path=True,
                )
                rows.append(
                    ObservabilityDestinationRow(
                        name=str(item["name"]),
                        target="audit_sinks",
                        scope=str(item.get("scope", "") or "global"),
                        kind=str(item.get("kind", "") or "unknown"),
                        state="enabled" if bool(item.get("enabled", False)) else "disabled",
                        signals="audit-events",
                        endpoint=str(endpoint),
                    )
                )
        return tuple(rows)


def gateway_health_is_broken(state: str) -> bool:
    return state.strip().lower() not in {"running", "disabled"}


def string_detail(details: dict[str, Any] | None, key: str) -> str:
    if details is None:
        return ""
    value = details.get(key)
    if isinstance(value, str):
        return value.strip()
    return ""


def live_health_contradicts(check: DoctorCheck, health: HealthSnapshot | None) -> bool:
    if health is None:
        return False
    if check.status not in {"fail", "warn"}:
        return False
    label = check.label.strip().lower()
    if label == "sidecar api":
        return health.api.state.lower() == "running"
    if label == "guardrail proxy":
        return health.guardrail.state.lower() == "running"
    if label in {"openclaw gateway", "gateway"}:
        return health.gateway.state.lower() == "running"
    if label.startswith("otel"):
        return health.telemetry.state.lower() == "running"
    return False


def partition_doctor_checks(
    checks: tuple[DoctorCheck, ...],
    health: HealthSnapshot | None,
) -> tuple[tuple[DoctorCheck, ...], tuple[DoctorCheck, ...]]:
    live: list[DoctorCheck] = []
    stale: list[DoctorCheck] = []
    for check in checks:
        if live_health_contradicts(check, health):
            stale.append(check)
        else:
            live.append(check)
    return tuple(live), tuple(stale)


def keys_overflow_suffix(total: int, shown: int) -> str:
    if total <= shown:
        return ""
    return f" (+{total - shown} more)"


def zero_connector_requests_notice(connector_name: str, uptime: timedelta) -> str:
    name = friendly_connector_name(connector_name)
    formatted = format_duration(uptime)
    match connector_name.strip().lower():
        case "codex":
            return (
                f"{name} connector has seen 0 hook events after {formatted} - "
                "normal until Codex emits a hook/notify event; verify ~/.codex hooks if this persists"
            )
        case "claudecode":
            return (
                f"{name} connector has seen 0 hook events after {formatted} - "
                "normal until Claude Code emits a hook event; verify Claude Code hooks if this persists"
            )
        case "omnigent":
            return (
                f"{name} connector has seen 0 policy events after {formatted} - "
                "normal until OmniGent emits a supported policy callback; verify OmniGent policy setup if this persists"
            )
        case "hermes" | "cursor" | "windsurf" | "geminicli" | "copilot" | "openhands" | "antigravity" | "opencode":
            return (
                f"{name} connector has seen 0 hook events after {formatted} - "
                "normal until the agent emits a supported hook; verify connector hook setup if this persists"
            )
        case _:
            return (
                f"{name} connector has seen 0 requests after {formatted} - "
                "verify your agent is dialing the gateway port (gateway.port)"
            )


def friendly_connector_name(connector: str) -> str:
    match (connector or "").strip().lower():
        case "openclaw":
            return "OpenClaw"
        case "zeptoclaw":
            return "ZeptoClaw"
        case "claudecode":
            return "Claude Code"
        case "codex":
            return "Codex"
        case "hermes":
            return "Hermes"
        case "cursor":
            return "Cursor"
        case "windsurf":
            return "Windsurf"
        case "geminicli":
            return "Gemini CLI"
        case "copilot":
            return "GitHub Copilot CLI"
        case "openhands":
            return "OpenHands"
        case "antigravity":
            return "Antigravity"
        case "opencode":
            return "OpenCode"
        case "omnigent":
            return "OmniGent"
        case value:
            return value[:1].upper() + value[1:] if value else "No connector"


def connector_source_label(connector: str, category: str) -> str:
    connector = (connector or "").strip().lower()
    hermes_root = hermes_home()
    hermes_config = hermes_config_path()
    sources = {
        ("openclaw", "skills"): ("./skills", "~/.openclaw/skills"),
        ("claudecode", "skills"): ("~/.claude/skills", "./.claude/skills"),
        ("codex", "skills"): ("~/.codex/skills", "./.codex/skills"),
        ("zeptoclaw", "skills"): ("~/.zeptoclaw/skills", "./.zeptoclaw/skills"),
        ("hermes", "skills"): (os.path.join(hermes_root, "skills"),),
        ("cursor", "skills"): ("./.cursor/skills", "./.agents/skills", "~/.cursor/skills", "~/.agents/skills"),
        ("windsurf", "skills"): ("unsupported/documented paths only",),
        ("geminicli", "skills"): ("./.gemini/skills", "./.agents/skills"),
        ("copilot", "skills"): ("./.github/skills", "./.agents/skills", "~/.copilot/skills"),
        ("openhands", "skills"): ("~/.openhands/skills", "~/.openhands/microagents", "~/.agents/skills"),
        ("antigravity", "skills"): (
            "~/.gemini/config/skills/<skill>/SKILL.md",
            "<workspace>/.agents/skills/<skill>/SKILL.md",
            "~/.gemini/antigravity-cli/skills/*.md (discovery-only)",
        ),
        ("opencode", "skills"): ("unsupported/hooks-only surface",),
        ("omnigent", "skills"): ("unsupported by the OmniGent connector",),
        ("openclaw", "mcps"): ("openclaw config get mcp.servers", "openclaw.json (mcp.servers)"),
        ("claudecode", "mcps"): ("~/.claude/settings.json (mcpServers)", "./.mcp.json"),
        ("codex", "mcps"): ("~/.codex/config.toml ([mcp_servers])", "./.mcp.json"),
        ("zeptoclaw", "mcps"): ("~/.zeptoclaw/config.json (mcp.servers)", "./.mcp.json"),
        ("hermes", "mcps"): (f"{hermes_config} (mcp.servers)",),
        ("cursor", "mcps"): ("./.cursor/mcp.json", "~/.cursor/mcp.json"),
        ("windsurf", "mcps"): ("~/.codeium/windsurf/mcp_config.json", "~/.codeium/windsurf/mcp.json"),
        ("geminicli", "mcps"): ("~/.gemini/settings.json (mcpServers)", "./.mcp.json"),
        ("copilot", "mcps"): ("~/.copilot/mcp-config.json", "./.github/mcp.json", "./.mcp.json"),
        ("openhands", "mcps"): ("~/.openhands/mcp.json",),
        ("antigravity", "mcps"): (
            "~/.gemini/config/mcp_config.json",
            "<workspace>/.agents/mcp_config.json",
            "<plugin>/mcp_config.json (discovery-only)",
        ),
        ("opencode", "mcps"): ("~/.config/opencode/opencode.json (mcp)", "./opencode.json (mcp)"),
        ("omnigent", "mcps"): ("managed by OmniGent; not modified by DefenseClaw",),
        ("openclaw", "plugins"): ("~/.openclaw/extensions",),
        ("claudecode", "plugins"): ("~/.claude/plugins",),
        ("codex", "plugins"): ("~/.codex/plugins",),
        ("zeptoclaw", "plugins"): ("~/.zeptoclaw/plugins",),
        ("hermes", "plugins"): (
            os.path.join(hermes_root, "plugins"),
            "./.hermes/plugins (discovery-only)",
        ),
        ("cursor", "plugins"): ("unsupported",),
        ("windsurf", "plugins"): ("unsupported",),
        ("geminicli", "plugins"): ("./.gemini/extensions",),
        ("copilot", "plugins"): ("copilot plugin list",),
        ("openhands", "plugins"): ("unsupported",),
        ("antigravity", "plugins"): (
            "~/.gemini/config/plugins/<plugin>/ (read/write)",
            "~/.gemini/antigravity-cli/plugins/<plugin>/ (discovery-only)",
            "<workspace>/.agents/plugins/<plugin>/ (read/write)",
        ),
        ("opencode", "plugins"): ("~/.config/opencode/plugins/defenseclaw.js (DefenseClaw bridge)",),
        ("omnigent", "plugins"): ("unsupported by the OmniGent connector",),
        ("openclaw", "config"): ("~/.openclaw/openclaw.json",),
        ("claudecode", "config"): ("~/.claude/settings.json",),
        ("codex", "config"): ("~/.codex/config.toml",),
        ("zeptoclaw", "config"): ("~/.zeptoclaw/config.json",),
        ("hermes", "config"): (hermes_config,),
        ("cursor", "config"): ("~/.cursor/hooks.json",),
        ("windsurf", "config"): ("~/.codeium/windsurf/hooks.json",),
        ("geminicli", "config"): ("~/.gemini/settings.json",),
        ("copilot", "config"): ("./.github/hooks/*.json",),
        ("openhands", "config"): ("~/.openhands/hooks.json",),
        ("antigravity", "config"): ("~/.gemini/config/hooks.json",),
        ("opencode", "config"): ("~/.config/opencode/plugins/defenseclaw.js",),
        ("omnigent", "config"): ("$OMNIGENT_CONFIG_HOME/config.yaml or ~/.omnigent/config.yaml",),
    }
    return ", ".join(sources.get((connector, category), ()))


def active_connector_name(health: HealthSnapshot | None, mode: str) -> str:
    if health is not None and health.connector is not None and health.connector.name.strip():
        return health.connector.name.strip()
    if mode.strip():
        return mode.strip()
    return ""


def format_scanner_overrides_summary(
    overrides: tuple[tuple[str, str, str, str], ...],
) -> str:
    """One-line summary of active-policy scanner action overrides (N3).

    ``overrides`` is the flattened ``(scanner_type, severity, surface, action)``
    view of the active policy's ``scanner_overrides`` (synced into
    ``data.json``; only ``policy show`` surfaces these today). Returns ``""``
    when empty, so the Overview / ``defenseclaw status`` render nothing for the
    common default config. Groups by scanner then severity, e.g.::

        secrets: HIGH file=block, install=warn | pii: MEDIUM runtime=allow

    Malformed entries (not 4 fields, or missing scanner/surface) are skipped so
    a bad adapter payload degrades to a partial line rather than raising.
    """
    grouped: dict[str, dict[str, list[str]]] = {}
    for entry in overrides:
        if len(entry) != 4:
            continue
        scanner, severity, surface, action = (str(part).strip() for part in entry)
        if not scanner or not surface:
            continue
        grouped.setdefault(scanner, {}).setdefault(severity.upper(), []).append(f"{surface}={action}")
    parts: list[str] = []
    for scanner, sevs in grouped.items():
        sev_parts = [
            f"{severity + ' ' if severity else ''}{', '.join(surfaces)}" for severity, surfaces in sevs.items()
        ]
        parts.append(f"{scanner}: {'; '.join(sev_parts)}")
    return " | ".join(parts)


def sort_ai_discovery_signals_for_overview(signals: tuple[AIUsageSignal, ...]) -> tuple[AIUsageSignal, ...]:
    def rank(signal: AIUsageSignal) -> tuple[int, float, float, str]:
        state_rank = {
            "new": 0,
            "changed": 1,
            "active": 2,
            "": 2,
            "gone": 3,
        }.get(signal.state.strip().lower(), 4)
        last_seen = signal.last_seen.timestamp() if signal.last_seen is not None else 0.0
        return (state_rank, -signal.confidence, -last_seen, display_ai_discovery_name(signal).lower())

    return tuple(sorted(signals, key=rank))


def unique_ai_discovery_signals_for_overview(signals: tuple[AIUsageSignal, ...]) -> tuple[AIUsageSignal, ...]:
    """Collapse multiple evidence signals into one Overview row per agent."""

    seen: set[tuple[str, str]] = set()
    rows: list[AIUsageSignal] = []
    for signal in signals:
        key = _ai_discovery_overview_key(signal)
        if key in seen:
            continue
        seen.add(key)
        rows.append(signal)
    return tuple(rows)


def _ai_discovery_overview_key(signal: AIUsageSignal) -> tuple[str, str]:
    connector = signal.supported_connector.strip().lower()
    if connector:
        return ("connector", connector)
    if signal.component is not None:
        ecosystem = signal.component.ecosystem.strip().lower()
        name = signal.component.name.strip().lower()
        if ecosystem or name:
            return ("component", f"{ecosystem}:{name}")
    name = display_ai_discovery_name(signal).strip().lower()
    vendor = display_ai_discovery_vendor(signal).strip().lower()
    return ("display", f"{vendor}:{name}")


def ai_discovery_state_badge(state: str) -> str:
    match state.strip().lower():
        case "new":
            return "[NEW]"
        case "changed":
            return "[CHG]"
        case "gone":
            return "[GONE]"
        case _:
            return "[OK ]"


def display_ai_discovery_name(signal: AIUsageSignal) -> str:
    for candidate in (signal.name, signal.product, signal.signature_id, signal.signal_id):
        if candidate.strip():
            return candidate.strip()
    return "(unknown)"


def display_ai_discovery_vendor(signal: AIUsageSignal) -> str:
    vendor = signal.vendor.strip() or signal.category.strip() or "-"
    parts = [vendor]
    if signal.version.strip():
        parts.append(signal.version.strip())
    label = " ".join(parts)
    if signal.supported_connector.strip():
        label = f"{label} ({signal.supported_connector.strip()})"
    return label


def clamp_percent(value: float) -> int:
    if value < 0:
        return 0
    if value > 100:
        return 100
    return int(value + 0.5)


def format_scan_age(value: datetime | None, *, now: datetime | None = None) -> str:
    if value is None:
        return "-"
    now = now or datetime.now(timezone.utc)
    delta = now - value
    if delta.total_seconds() < 0:
        return "now"
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


def format_age(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "never"
    if seconds < 30:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


def format_duration(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    hours = seconds // 3600
    minutes = (seconds // 60) % 60
    if hours > 0:
        return f"{hours}h {minutes}m"
    if minutes > 0:
        return f"{minutes}m"
    return f"{seconds}s"


__all__ = [
    "ConnectorHealth",
    "DoctorBoxState",
    "DoctorCache",
    "DoctorCheck",
    "EnforcementCounts",
    "HealthSnapshot",
    "KeysStatus",
    "MAX_AI_DISCOVERY_OVERVIEW_ROWS",
    "OverviewAIDiscoveryBoxState",
    "OverviewAIDiscoveryRow",
    "OverviewCommandIntent",
    "OverviewConfig",
    "OverviewNotice",
    "OverviewPanelModel",
    "ObservabilityDestinationRow",
    "QUICK_ACTIONS",
    "RenderedDoctorCheck",
    "STALENESS_WINDOW",
    "ServiceCard",
    "SubsystemHealth",
    "active_connector_name",
    "ai_discovery_state_badge",
    "clamp_percent",
    "connector_source_label",
    "display_ai_discovery_name",
    "display_ai_discovery_vendor",
    "format_age",
    "format_duration",
    "format_scan_age",
    "format_scanner_overrides_summary",
    "friendly_connector_name",
    "gateway_health_is_broken",
    "keys_overflow_suffix",
    "live_health_contradicts",
    "partition_doctor_checks",
    "sort_ai_discovery_signals_for_overview",
    "string_detail",
    "zero_connector_requests_notice",
]
