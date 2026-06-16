# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Overview panel parity tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from defenseclaw.tui.panels.ai_discovery import AIUsageSignal, AIUsageSnapshot, AIUsageSummary
from defenseclaw.tui.panels.overview import (
    MAX_AI_DISCOVERY_OVERVIEW_ROWS,
    STALENESS_WINDOW,
    ConnectorHealth,
    DoctorCache,
    DoctorCheck,
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
    active_connector_name,
    connector_source_label,
    friendly_connector_name,
    gateway_health_is_broken,
    keys_overflow_suffix,
    live_health_contradicts,
    sort_ai_discovery_signals_for_overview,
    string_detail,
)
from defenseclaw.tui.services.overview_state import format_scanner_overrides_summary


def _model() -> OverviewPanelModel:
    return OverviewPanelModel(OverviewConfig(data_dir="/tmp/dc", claw_mode="codex"), version="test")


def test_gateway_health_is_broken_and_string_detail() -> None:
    for state in ("running", "RUNNING", " Running ", "disabled", "DISABLED"):
        assert gateway_health_is_broken(state) is False
    for state in ("reconnecting", "error", "stopped", "starting", "unknown", "", "garbage"):
        assert gateway_health_is_broken(state) is True

    assert string_detail(None, "summary") == ""
    assert string_detail({"summary": 42}, "summary") == ""
    assert string_detail({"summary": "  hello  "}, "summary") == "hello"


def test_overview_standalone_hint_and_notices() -> None:
    model = _model()
    assert model.gateway_standalone_hint() == ""

    model.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(
                state="disabled",
                details={
                    "summary": "no OpenClaw fleet configured (standalone mode)",
                    "hint": "set gateway.host and restart",
                },
            )
        )
    )
    assert model.gateway_standalone_hint() == "set gateway.host and restart"
    notices = model.build_notices()
    assert not any(notice.level == "error" and "Gateway is offline" in notice.message for notice in notices)
    assert any(notice.level == "info" and "set gateway.host" in notice.message for notice in notices)

    model.set_health(HealthSnapshot(gateway=SubsystemHealth(state="reconnecting")))
    notices = model.build_notices()
    assert any(notice.level == "error" and "Gateway is offline" in notice.message for notice in notices)


def test_overview_mode_key_is_modal_owned_not_fake_command() -> None:
    model = _model()

    assert model.action_intent("m") is None


def test_overview_service_cards_agent_detail_and_zero_request_guidance() -> None:
    model = OverviewPanelModel(
        OverviewConfig(claw_mode="codex", guardrail_connector="codex", guardrail_enabled=True),
        version="test",
    )
    model.set_health(
        HealthSnapshot(
            uptime_ms=int(timedelta(minutes=3).total_seconds() * 1000),
            gateway=SubsystemHealth(state="running"),
            connector=ConnectorHealth(name="codex", state="running", requests=0),
            api=SubsystemHealth(state="running", details={"addr": "127.0.0.1:17777"}),
            ai_discovery=SubsystemHealth(state="running", details={"active_signals": 3, "new_signals": 1}),
        )
    )

    cards = {card.key: card for card in model.service_cards()}
    assert cards["gateway"].state == "running"
    assert cards["agent"].detail == "Codex"
    assert cards["api"].detail == "127.0.0.1:17777"
    assert cards["ai_discovery"].detail == "3 active, 1 new"

    notices = model.build_notices()
    assert any("0 hook events" in notice.message for notice in notices)
    assert not any("gateway port" in notice.message for notice in notices)


def test_agent_detail_rolls_up_connectors_in_multi_connector() -> None:
    # 8.13: in a multi-connector install the SERVICES "Agent" row collapses to
    # an "N connectors active" roll-up (per-connector detail lives in the
    # dedicated CONNECTORS table), and its state aggregates the per-connector
    # health. Single-connector keeps the original name + counters.
    single = OverviewPanelModel(
        OverviewConfig(claw_mode="codex", guardrail_connector="codex"),
        version="test",
    )
    single.set_health(
        HealthSnapshot(connector=ConnectorHealth(name="codex", state="running", requests=5, tool_blocks=2))
    )
    assert single.agent_detail() == "Codex - 5 req - 2 tool blocks"
    assert single.subsystem_state("agent") == "running"

    multi = OverviewPanelModel(
        OverviewConfig(
            claw_mode="codex",
            guardrail_connector="codex",
            connector_modes=(("codex", "enforce"), ("cursor", "observe")),
        ),
        version="test",
    )
    # Every connector up -> "running" + "N connectors active".
    multi.set_health(
        HealthSnapshot(
            connector=ConnectorHealth(name="codex", state="running"),
            connectors=(
                ConnectorHealth(name="codex", state="running"),
                ConnectorHealth(name="cursor", state="running"),
            ),
        )
    )
    assert multi.agent_detail() == "2 connectors active"
    assert multi.subsystem_state("agent") == "running"

    # One connector down -> "degraded" + "running/total" roll-up.
    multi.set_health(
        HealthSnapshot(
            connector=ConnectorHealth(name="codex", state="running"),
            connectors=(
                ConnectorHealth(name="codex", state="running"),
                ConnectorHealth(name="cursor", state="stopped"),
            ),
        )
    )
    assert multi.agent_detail() == "1/2 connectors running"
    assert multi.subsystem_state("agent") == "degraded"

    # Older gateway without a connectors[] array -> configured count fallback.
    multi.set_health(HealthSnapshot(connector=ConnectorHealth(name="codex", state="running")))
    assert multi.agent_detail() == "2 connectors configured"


def test_agent_detail_reports_disabled_connectors_separately() -> None:
    # A connector turned off via `guardrail disable --connector X` stays in the
    # roster (history is filterable) but is excluded from the "active" count and
    # reported as disabled. The gateway drops it from connectors[].
    model = OverviewPanelModel(
        OverviewConfig(
            claw_mode="codex",
            guardrail_connector="codex",
            connector_modes=(("antigravity", "action"), ("codex", "action"), ("claudecode", "observe")),
            connector_disabled=("codex",),
        ),
        version="test",
    )
    assert model.cfg.connector_is_disabled("codex") is True
    assert model.cfg.connector_is_disabled("antigravity") is False

    # Only the two enabled connectors are live; codex is disabled.
    model.set_health(
        HealthSnapshot(
            connectors=(
                ConnectorHealth(name="antigravity", state="running"),
                ConnectorHealth(name="claudecode", state="running"),
            ),
        )
    )
    assert model.agent_detail() == "2 active · 1 disabled"
    assert model.subsystem_state("agent") == "running"

    # Every connector disabled -> the Agent row is explicitly "disabled".
    all_off = OverviewPanelModel(
        OverviewConfig(
            claw_mode="codex",
            connector_modes=(("codex", "action"), ("cursor", "observe")),
            connector_disabled=("codex", "cursor"),
        ),
        version="test",
    )
    all_off.set_health(HealthSnapshot(gateway=SubsystemHealth(state="running")))
    assert all_off.agent_detail() == "0 active · 2 disabled"
    assert all_off.subsystem_state("agent") == "disabled"

    openclaw = OverviewPanelModel(
        OverviewConfig(claw_mode="openclaw", guardrail_connector="openclaw", guardrail_enabled=True),
        version="test",
    )
    openclaw.set_health(
        HealthSnapshot(
            uptime_ms=int(timedelta(minutes=3).total_seconds() * 1000),
            connector=ConnectorHealth(name="openclaw", state="running", requests=0),
        )
    )
    assert any("gateway port" in notice.message for notice in openclaw.build_notices())


def test_overview_silent_bypass_count_surfaces_warning_notice() -> None:
    model = _model()

    model.set_silent_bypass_count(-1)
    assert model.silent_bypass == 0

    model.set_silent_bypass_count(2)
    notices = model.build_notices()
    assert model.silent_bypass == 2
    assert any("2 silent LLM bypass" in notice.message for notice in notices)
    assert any("Alerts -> egress" in notice.message for notice in notices)


def test_doctor_cache_missing_required_credentials_and_keys_status() -> None:
    cache = DoctorCache(
        checks=(
            DoctorCheck("pass", "credential IGNORED_PASS"),
            DoctorCheck("warn", "credential IGNORED_WARN"),
            DoctorCheck("fail", "Sidecar API"),
            DoctorCheck("fail", "credentialMISSING_NO_SPACE"),
        )
    )
    assert cache.missing_required_credentials() == ()

    cache = DoctorCache(
        checks=(
            DoctorCheck("fail", "credential OPENCLAW_GATEWAY_TOKEN"),
            DoctorCheck("pass", "Sidecar API"),
            DoctorCheck("fail", "credential CISCO_AI_DEFENSE_API_KEY"),
        )
    )
    assert cache.missing_required_credentials() == ("OPENCLAW_GATEWAY_TOKEN", "CISCO_AI_DEFENSE_API_KEY")

    model = _model()
    model.set_doctor_cache(
        DoctorCache(
            captured_at=datetime.now(timezone.utc),
            failed=4,
            checks=tuple(DoctorCheck("fail", f"credential KEY_{name}") for name in ("A", "B", "C", "D")),
        )
    )
    status = model.keys_status()
    assert status.available is True
    assert status.label == "4 missing: KEY_A, KEY_B (+2 more)"
    assert keys_overflow_suffix(5, 2) == " (+3 more)"


def test_doctor_box_all_green_failures_stale_and_live_recovery() -> None:
    now = datetime(2026, 5, 20, 12, tzinfo=timezone.utc)
    model = _model()
    assert model.doctor_box(now=now).empty is True

    model.set_doctor_cache(DoctorCache(captured_at=now, passed=5))
    green = model.doctor_box(now=now)
    assert green.summary_parts == ("5 pass",)
    assert green.all_green is True

    model.set_doctor_cache(
        DoctorCache(
            captured_at=now,
            passed=3,
            failed=2,
            warned=1,
            checks=(
                DoctorCheck("fail", "Sidecar API", "not reachable"),
                DoctorCheck("warn", "Guardrail", "model empty"),
                DoctorCheck("fail", "LLM key (Anthropic)", "HTTP 401"),
            ),
        )
    )
    box = model.doctor_box(now=now)
    assert box.summary_parts == ("3 pass", "2 fail", "1 warn")
    assert [check.label for check in box.checks] == ["Sidecar API", "LLM key (Anthropic)", "Guardrail"]
    assert any("Doctor found 2 failure(s)" in notice.message for notice in model.build_notices(now=now))

    model.set_doctor_cache(DoctorCache(captured_at=now - STALENESS_WINDOW - timedelta(minutes=5), passed=7))
    assert model.doctor_box(now=now).stale is True
    assert any("Doctor cache is stale" in notice.message for notice in model.build_notices(now=now))

    model.set_doctor_cache(
        DoctorCache(
            captured_at=now - timedelta(days=1),
            passed=6,
            failed=2,
            checks=(
                DoctorCheck("fail", "Sidecar API", "not reachable"),
                DoctorCheck("fail", "Guardrail proxy", "not responding"),
            ),
        )
    )
    model.set_health(HealthSnapshot(api=SubsystemHealth(state="running"), guardrail=SubsystemHealth(state="running")))
    recovered = model.doctor_box(now=now)
    assert "2 stale" in recovered.summary_parts
    assert not any(part.endswith("fail") for part in recovered.summary_parts)
    assert all(check.badge == "STALE" for check in recovered.checks)
    assert not any("Doctor found 2 failure(s)" in notice.message for notice in model.build_notices(now=now))
    assert any("/health disagrees" in notice.message for notice in model.build_notices(now=now))


def test_live_health_contradicts_known_labels() -> None:
    running = SubsystemHealth(state="running")
    stopped = SubsystemHealth(state="stopped")
    assert live_health_contradicts(DoctorCheck("fail", "Sidecar API"), HealthSnapshot(api=running)) is True
    assert live_health_contradicts(DoctorCheck("fail", "Sidecar API"), HealthSnapshot(api=stopped)) is False
    assert live_health_contradicts(DoctorCheck("fail", "Guardrail proxy"), HealthSnapshot(guardrail=running)) is True
    assert live_health_contradicts(DoctorCheck("fail", "OpenClaw gateway"), HealthSnapshot(gateway=running)) is True
    assert live_health_contradicts(DoctorCheck("fail", "otel (OTLP)"), HealthSnapshot(telemetry=running)) is True
    assert live_health_contradicts(DoctorCheck("fail", "otel (OTLP)"), HealthSnapshot(telemetry=stopped)) is False
    assert live_health_contradicts(DoctorCheck("pass", "Sidecar API"), HealthSnapshot(api=running)) is False


def test_overview_ai_discovery_box_states_sort_and_cap() -> None:
    now = datetime(2026, 5, 20, 12, tzinfo=timezone.utc)
    model = _model()
    assert model.ai_discovery_box(now=now).status == "offline"
    assert "agent discovery status" in model.ai_discovery_box(now=now).message

    model.set_ai_usage(AIUsageSnapshot(enabled=False))
    assert model.ai_discovery_box(now=now).status == "disabled"

    model.set_ai_usage(
        AIUsageSnapshot(
            enabled=True,
            summary=AIUsageSummary(scanned_at=now - timedelta(minutes=2), privacy_mode="enhanced"),
        )
    )
    empty = model.ai_discovery_box(now=now)
    assert empty.status == "empty"
    assert "0 active" in empty.summary_parts
    assert "mode enhanced" in empty.summary_parts

    signals = tuple(
        AIUsageSignal(
            signature_id=f"agent-{index}",
            name=f"Agent {index}",
            vendor="VendorCo",
            state="active",
            confidence=0.5 + index * 0.01,
            last_seen=now - timedelta(minutes=index),
        )
        for index in range(MAX_AI_DISCOVERY_OVERVIEW_ROWS + 3)
    )
    model.set_ai_usage(
        AIUsageSnapshot(
            enabled=True,
            summary=AIUsageSummary(scanned_at=now, active_signals=len(signals)),
            signals=signals,
        )
    )
    box = model.ai_discovery_box(now=now)
    assert box.status == "ready"
    assert len(box.rows) == MAX_AI_DISCOVERY_OVERVIEW_ROWS
    assert box.overflow == 3


def test_sort_ai_discovery_signals_for_overview_tiebreakers() -> None:
    now = datetime(2026, 5, 20, 12, tzinfo=timezone.utc)
    signals = (
        AIUsageSignal(name="Bravo", state="active", confidence=0.5, last_seen=now - timedelta(hours=1)),
        AIUsageSignal(name="Alpha", state="active", confidence=0.5, last_seen=now),
        AIUsageSignal(name="Charlie", state="new", confidence=0.1, last_seen=now - timedelta(hours=2)),
    )
    assert [signal.name for signal in sort_ai_discovery_signals_for_overview(signals)] == [
        "Charlie",
        "Alpha",
        "Bravo",
    ]


def test_connector_labels_cover_hook_surface_connectors() -> None:
    cases = {
        "hermes": "Hermes",
        "cursor": "Cursor",
        "windsurf": "Windsurf",
        "geminicli": "Gemini CLI",
        "copilot": "GitHub Copilot CLI",
    }
    for wire, want in cases.items():
        assert friendly_connector_name(wire) == want

    assert ".hermes/config.yaml" in connector_source_label("hermes", "mcps")
    assert ".cursor/skills" in connector_source_label("cursor", "skills")
    assert ".codeium/windsurf/hooks.json" in connector_source_label("windsurf", "config")
    assert ".gemini/extensions" in connector_source_label("geminicli", "plugins")
    assert ".github/mcp.json" in connector_source_label("copilot", "mcps")
    # opencode MCP is now managed by DefenseClaw (read+write via the bridge
    # path layer), so the source label points at its real config and no longer
    # advertises "unmanaged in v1".
    opencode_mcps = connector_source_label("opencode", "mcps")
    assert ".config/opencode/opencode.json" in opencode_mcps
    assert "unmanaged" not in opencode_mcps
    antigravity_mcps = connector_source_label("antigravity", "mcps")
    assert ".gemini/config/mcp_config.json" in antigravity_mcps
    assert ".agents/mcp_config.json" in antigravity_mcps
    assert "hooks-only" not in antigravity_mcps
    assert "unsupported" not in antigravity_mcps
    assert ".gemini/config/skills" in connector_source_label("antigravity", "skills")
    assert "discovery-only" in connector_source_label("antigravity", "plugins")

    health = HealthSnapshot(connector=ConnectorHealth(name="codex"))
    assert active_connector_name(health, "openclaw") == "codex"
    assert active_connector_name(None, "claudecode") == "claudecode"
    assert active_connector_name(None, "") == ""


def test_multi_connector_rows_lists_each_connector_with_mode() -> None:
    """WU10: when more than one connector is active the Overview gains a
    config-derived roster (one indented sub-line per connector with its
    effective mode), reusing ``friendly_connector_name`` for display."""

    model = OverviewPanelModel(
        OverviewConfig(
            claw_mode="codex",
            guardrail_connector="codex",
            connector_modes=(("codex", "enforce"), ("cursor", "observe")),
        ),
        version="test",
    )
    rows = model.multi_connector_rows()
    assert [value for _, value in rows] == [
        "Codex (codex) — mode=enforce",
        "Cursor (cursor) — mode=observe",
    ]
    # Indented sub-lines: blank label so the key:<16 formatting nests
    # them under the single "Agent" line.
    assert all(label == "" for label, _ in rows)
    # A connector with no resolvable mode still renders, marked unknown.
    unknown = OverviewPanelModel(
        OverviewConfig(connector_modes=(("codex", ""), ("cursor", "observe"))),
        version="test",
    )
    assert unknown.multi_connector_rows()[0][1] == "Codex (codex) — mode=?"


def test_multi_connector_rows_append_effective_rule_pack() -> None:
    """Each roster row carries the connector's effective rule pack (from
    ``connector_packs``) so the Overview surfaces per-connector enforcement
    posture that the process-global ``Policy posture`` line cannot show."""

    model = OverviewPanelModel(
        OverviewConfig(
            claw_mode="codex",
            guardrail_connector="codex",
            connector_modes=(("codex", "action"), ("claudecode", "action")),
            connector_packs=(("codex", "strict"), ("claudecode", "permissive")),
        ),
        version="test",
    )
    assert [value for _, value in model.multi_connector_rows()] == [
        "Codex (codex) — mode=action, strict",
        "Claude Code (claudecode) — mode=action, permissive",
    ]
    # A connector missing from connector_packs (or with a blank pack) falls
    # back to the mode-only row — no trailing comma.
    partial = OverviewPanelModel(
        OverviewConfig(
            connector_modes=(("codex", "action"), ("cursor", "observe")),
            connector_packs=(("codex", "strict"),),
        ),
        version="test",
    )
    assert partial.multi_connector_rows() == [
        ("", "Codex (codex) — mode=action, strict"),
        ("", "Cursor (cursor) — mode=observe"),
    ]


def test_multi_connector_rows_noop_for_single_connector() -> None:
    """Single-connector installs (the common case) get no roster, so the
    existing single "Agent" line is untouched."""

    assert _model().multi_connector_rows() == []
    one = OverviewPanelModel(
        OverviewConfig(claw_mode="codex", connector_modes=(("codex", "enforce"),)),
        version="test",
    )
    assert one.multi_connector_rows() == []
    assert OverviewPanelModel(None, version="test").multi_connector_rows() == []


def test_scanner_overrides_summary_formats_and_stays_empty_by_default() -> None:
    # N3 state-layer surface: scanner overrides live only in the active policy
    # YAML / data.json today. The default config has none, so the summary is ""
    # and the Overview renders nothing until the adapter populates the field.
    assert format_scanner_overrides_summary(()) == ""
    assert OverviewPanelModel(None, version="test").scanner_overrides_summary() == ""
    assert (
        OverviewPanelModel(OverviewConfig(claw_mode="codex"), version="test").scanner_overrides_summary()
        == ""
    )

    overrides = (
        ("secrets", "high", "file", "block"),
        ("secrets", "high", "install", "warn"),
        ("pii", "medium", "runtime", "allow"),
    )
    summary = format_scanner_overrides_summary(overrides)
    assert summary == "secrets: HIGH file=block, install=warn | pii: MEDIUM runtime=allow"

    # Surfaced through the panel model once the adapter feeds the field.
    model = OverviewPanelModel(
        OverviewConfig(claw_mode="codex", scanner_overrides=overrides), version="test"
    )
    assert model.scanner_overrides_summary() == summary

    # Malformed entries degrade gracefully instead of raising.
    assert format_scanner_overrides_summary((("", "high", "file", "block"),)) == ""
    assert format_scanner_overrides_summary((("secrets", "low", "file"),)) == ""  # wrong arity
