# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""AI Discovery Runtime panel model."""

from __future__ import annotations

from typing import Any

import pytest
from defenseclaw.tui.app import PANEL_SHORTCUTS, PANELS
from defenseclaw.tui.panels.runtime import (
    RuntimePanelAction,
    RuntimePanelModel,
    decode_runtime_snapshot,
)

_SNAPSHOT: dict[str, Any] = {
    "enabled": True,
    "scanned_at": "2026-09-09T12:00:00Z",
    "processes_observed": 412,
    "processes_skipped": 9,
    "connections_observed": 60,
    "connections_unattributed": 55,
    "degraded": True,
    "degraded_reasons": ["agent actions unavailable: eslogger not found"],
    "planes": [
        {"plane": "a", "name": "inference heartbeat", "available": True, "running": True,
         "mechanism": "ps(1)"},
        {"plane": "b", "name": "shadow egress", "available": True, "running": False,
         "reason": "connection table unreadable"},
        {"plane": "c", "name": "agent actions", "available": False, "running": False,
         "reason": "eslogger not found"},
    ],
    "findings": [
        {
            "finding_id": "run-1", "pid": 10, "process": "python3", "user": "dev",
            "cmdline": "python3 -m langgraph.cli serve", "agent_name": "python3",
            "score": 40, "severity": "medium",
            "signals": [{"id": "inference_heartbeat", "title": "sustained compute", "weight": 25}],
            "correlation": {"verdict": "unobserved", "reason": "no discovery snapshot yet"},
        },
        {
            "finding_id": "run-2", "pid": 20, "process": "claude", "user": "dev",
            "agent_name": "claude", "score": 95, "severity": "critical",
            "signals": [
                {"id": "agent_credential_access", "detail": "~/.aws/credentials", "weight": 30},
                {"id": "agent_kill_chain",
                 "detail": "credential_access -> identity_creation -> exfiltration", "weight": 25},
            ],
            "providers": [{"hostname": "api.anthropic.com", "category": "frontier"}],
            "correlation": {"verdict": "accounted", "reason": "discovery observed the same subject"},
        },
    ],
}


def _model() -> RuntimePanelModel:
    model = RuntimePanelModel()
    model.set_snapshot(_SNAPSHOT)
    return model


def test_panel_is_registered_with_its_own_shortcut() -> None:
    assert ("runtime", "N", "Runtime") in PANELS
    assert PANEL_SHORTCUTS["n"] == "runtime"


def test_findings_sort_worst_first() -> None:
    model = _model()
    assert [row.process for row in model.filtered] == ["claude", "python3"]


def test_plane_strip_is_always_present_and_expands_to_reasons() -> None:
    # Expanded by default so an operator sees why a plane is idle or
    # blind. Collapsed, the strip is a badge per plane. A blind plane
    # that renders as silence is indistinguishable from a clean host.
    model = _model()
    expanded = model.plane_strip()
    assert any("eslogger not found" in line for line in expanded)
    assert any("available but not running" in line for line in expanded)

    assert model.handle_key("p") is RuntimePanelAction.TOGGLE_PLANES
    collapsed = model.plane_strip()
    assert len(collapsed) == 3
    assert "agent actions: blind" in collapsed
    assert "shadow egress: idle" in collapsed


def test_header_carries_coverage_not_just_a_finding_count() -> None:
    header = " ".join(_model().header_parts())
    assert "2/2 findings" in header
    assert "412 processes (9 partial)" in header
    assert "60 connections (55 unattributed)" in header
    assert "DEGRADED" in header


def test_detail_renders_the_chain_as_a_sequence() -> None:
    model = _model()
    assert model.handle_key("enter") is RuntimePanelAction.OPEN_DETAIL
    detail = model.detail_text()
    assert "credential_access -> identity_creation -> exfiltration" in detail
    assert "api.anthropic.com" in detail
    assert "+30  agent_credential_access" in detail


def test_detail_always_states_the_inventory_verdict_including_unobserved() -> None:
    model = _model()
    model.cursor = 1  # the unobserved finding
    model.detail_open = True
    detail = model.detail_text()
    assert "inventory unobserved" in detail
    assert "no discovery snapshot yet" in detail


def test_filter_narrows_rows_without_losing_the_total() -> None:
    model = _model()
    model.set_filter("claude")
    assert [row.process for row in model.filtered] == ["claude"]
    assert "1/2 findings" in " ".join(model.header_parts())
    model.clear_filter()
    assert len(model.filtered) == 2


def test_overview_body_includes_runtime_coverage() -> None:
    from defenseclaw.tui.app import DefenseClawTUI
    from defenseclaw.tui.services.overview_state import OverviewPanelModel

    overview = OverviewPanelModel()
    overview.set_runtime_overview(_model().overview())
    app = DefenseClawTUI(overview_model=overview)
    body = app._overview_body_text(overview.service_cards())  # noqa: SLF001
    assert "[bold" in body and "RUNTIME" in body
    assert "412" in body
    assert "unobserved" in body


def test_overview_notices_explain_unobserved_runtime_and_elevated_sidecar() -> None:
    from defenseclaw.tui.services.overview_state import OverviewPanelModel

    overview = OverviewPanelModel()
    overview.set_gateway_probe(
        "running",
        "elevated sidecar: PID file is root-owned; TUI is using the authenticated API",
    )
    overview.set_runtime_overview(_model().overview())
    messages = [notice.message for notice in overview.build_notices()]
    assert any("elevated" in message.lower() for message in messages)
    assert any("unobserved" in message for message in messages)


def test_overview_summary_names_unobserved_findings_and_the_next_scan() -> None:
    model = _model()
    overview = model.overview()
    assert overview.health_title == "DEGRADED"
    assert overview.findings == 2
    assert overview.unobserved == 1
    assert overview.processes == 412
    assert "unobserved" in overview.context
    assert "AI Discovery" in overview.next_action
    assert any("claude" in line and "inventory accounted" in line for line in overview.top_findings)


def test_findings_context_explains_a_quiet_healthy_host() -> None:
    model = RuntimePanelModel()
    model.set_snapshot({
        "enabled": True,
        "scanned_at": "2026-09-11T12:00:00Z",
        "processes_observed": 743,
        "connections_observed": 146,
        "planes": [
            {"plane": "a", "name": "inference", "available": True, "running": True, "mechanism": "ps"},
            {"plane": "b", "name": "egress", "available": True, "running": True, "mechanism": "lsof"},
            {"plane": "c", "name": "actions", "available": True, "running": True, "mechanism": "eslogger"},
        ],
    })
    assert model.health_title() == "HEALTHY"
    assert "743 processes" in model.findings_context()
    assert "clean host" in model.findings_context()
    assert model.next_action() == ""


def test_empty_state_distinguishes_disabled_from_never_polled_from_clean() -> None:
    disabled = RuntimePanelModel()
    disabled.set_snapshot({"enabled": False})
    assert "disabled" in disabled.empty_state()

    unpolled = RuntimePanelModel()
    unpolled.set_snapshot({"enabled": True})
    assert "not completed a poll" in unpolled.empty_state()

    clean = RuntimePanelModel()
    clean.set_snapshot({"enabled": True, "scanned_at": "2026-09-09T12:00:00Z"})
    assert "No findings" in clean.empty_state()


def test_decode_tolerates_a_gateway_that_omits_fields() -> None:
    # A TUI that crashes on version skew is worse than one that renders less.
    snapshot = decode_runtime_snapshot({"enabled": True, "findings": [{"pid": 1}], "planes": [{}]})
    assert snapshot.rows[0].severity == "info"
    assert snapshot.rows[0].process == ""
    assert snapshot.planes[0].badge == "blind"
    assert decode_runtime_snapshot(None).enabled is False
    assert decode_runtime_snapshot("nonsense").rows == ()


def test_scan_and_refresh_map_to_the_nested_cli_commands() -> None:
    model = _model()
    scan = model.command_for(RuntimePanelAction.SCAN)
    assert scan is not None and scan.argv == ("agent", "discovery", "runtime", "scan")
    refresh = model.command_for(RuntimePanelAction.REFRESH)
    assert refresh is not None and refresh.argv[:3] == ("agent", "discovery", "runtime")
    enable = model.command_for(RuntimePanelAction.ENABLE)
    assert enable is not None
    assert enable.argv == (
        "agent", "discovery", "runtime", "enable", "--yes", "--no-enable-host-plane",
    )
    assert model.handle_key("e") is RuntimePanelAction.ENABLE


def test_health_badge_explains_degraded_versus_healthy() -> None:
    degraded = _model()
    assert degraded.health_state() == "degraded"
    assert degraded.health_title() == "DEGRADED"
    explanation = degraded.health_explanation()
    assert "partial" in explanation
    assert "HEALTHY" in explanation
    assert "eslogger not found" in explanation

    healthy = RuntimePanelModel()
    healthy.set_snapshot({
        "enabled": True,
        "scanned_at": "2026-09-11T21:00:00Z",
        "degraded": False,
        "planes": [
            {"plane": "a", "name": "inference heartbeat", "available": True, "running": True, "mechanism": "ps(1)"},
            {"plane": "b", "name": "shadow egress", "available": True, "running": True, "mechanism": "lsof(8)"},
            {"plane": "c", "name": "agent actions", "available": True, "running": True, "mechanism": "eslogger"},
        ],
    })
    assert healthy.health_state() == "healthy"
    assert healthy.health_title() == "HEALTHY"
    assert "HEALTHY" in " ".join(healthy.header_parts())
    assert "watching" in healthy.health_explanation()


def test_selected_plane_gaps_are_degraded() -> None:
    model = RuntimePanelModel()
    model.set_snapshot({
        "enabled": True,
        "scanned_at": "2026-09-14T13:50:27Z",
        "degraded": True,
        "degraded_reasons": [
            "agent actions available but not running: plane: Endpoint Security needs root; "
            "re-run the gateway elevated",
            "shadow egress partially covered: egress attribution is limited to this "
            "process's own sockets; run the gateway elevated for machine-wide coverage",
        ],
        "processes_observed": 5,
        "connections_observed": 9,
        "planes": [
            {
                "plane": "a",
                "name": "inference heartbeat",
                "available": True,
                "running": True,
                "mechanism": "ps(1)",
            },
            {
                "plane": "b",
                "name": "shadow egress",
                "available": True,
                "running": True,
                "mechanism": "lsof(8)",
                "reason": (
                    "egress attribution is limited to this process's own sockets; "
                    "run the gateway elevated for machine-wide coverage"
                ),
            },
            {
                "plane": "c",
                "name": "agent actions",
                "available": True,
                "running": False,
                "reason": "plane: Endpoint Security needs root; re-run the gateway elevated",
            },
        ],
    })
    assert model.health_title() == "DEGRADED"
    assert model.needs_enable() is False
    assert "partial" in model.health_explanation().lower()


def test_needs_enable_when_plane_c_is_not_selected() -> None:
    model = RuntimePanelModel()
    model.set_snapshot({
        "enabled": True,
        "scanned_at": "2026-09-11T21:00:00Z",
        "degraded": True,
        "planes": [
            {"plane": "a", "name": "inference heartbeat", "available": True, "running": True, "mechanism": "ps(1)"},
            {"plane": "c", "name": "agent actions", "available": True, "running": False,
             "reason": "not selected in ai_discovery.runtime.planes"},
        ],
    })
    assert model.needs_enable() is False
    assert "optional" in model.plane_fix(model.snapshot.planes[1]).lower()

    off = RuntimePanelModel()
    off.set_snapshot({"enabled": False})
    assert off.needs_enable() is True
    assert off.health_title() == "OFF"


@pytest.mark.asyncio
async def test_load_runtime_model_renders_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opening the Runtime panel must not crash the TUI.

    ``_load_runtime_model`` called ``self._render_body()``, which
    ``DefenseClawTUI`` does not define. Textual workers default to
    ``exit_on_error=True``, so the AttributeError after the fetch took the
    whole TUI down. The panel-model tests never touched this method, which is
    why 1043 green TUI tests said nothing about it.
    """
    from types import SimpleNamespace

    from defenseclaw.tui.app import DefenseClawTUI

    payload = {
        "enabled": True,
        "scanned_at": "2026-09-09T12:00:00Z",
        "findings": [],
        "planes": [
            {
                "plane": "a",
                "name": "inference heartbeat",
                "available": True,
                "running": True,
                "mechanism": "ps(1)",
            }
        ],
    }
    monkeypatch.setattr("defenseclaw.tui.app._fetch_ai_runtime", lambda _config: payload)
    config = SimpleNamespace(
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token")
    )
    app = DefenseClawTUI(config=config)

    async with app.run_test(size=(150, 40)) as pilot:
        await app._load_runtime_model()  # noqa: SLF001 - app-level polling contract.
        await pilot.pause()

    assert app.runtime_model.snapshot is not None


def test_the_app_defines_every_render_method_the_runtime_loader_calls() -> None:
    """A cheap guard against the same typo returning under a different name."""
    import inspect

    from defenseclaw.tui.app import DefenseClawTUI

    source = inspect.getsource(DefenseClawTUI._load_runtime_model)
    called = {
        name.split("(")[0]
        for name in source.split("self.")[1:]
        if name.startswith("_render")
    }
    for method in called:
        assert hasattr(DefenseClawTUI, method), (
            f"_load_runtime_model calls self.{method}(), which does not exist; "
            "the worker raises AttributeError and Textual exits the app"
        )
