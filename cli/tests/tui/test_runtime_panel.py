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

from defenseclaw.tui.app import CASE_SENSITIVE_PANEL_SHORTCUTS, PANEL_SHORTCUTS, PANELS
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
        {"plane": "a", "name": "inference heartbeat", "available": True, "running": True, "mechanism": "ps(1)"},
        {
            "plane": "b",
            "name": "shadow egress",
            "available": True,
            "running": False,
            "reason": "connection table unreadable",
        },
        {"plane": "c", "name": "agent actions", "available": False, "running": False, "reason": "eslogger not found"},
    ],
    "findings": [
        {
            "finding_id": "run-1",
            "pid": 10,
            "process": "python3",
            "user": "dev",
            "cmdline": "python3 -m langgraph.cli serve",
            "agent_name": "python3",
            "score": 40,
            "severity": "medium",
            "signals": [{"id": "inference_heartbeat", "title": "sustained compute", "weight": 25}],
            "correlation": {"verdict": "unobserved", "reason": "no discovery snapshot yet"},
        },
        {
            "finding_id": "run-2",
            "pid": 20,
            "process": "claude",
            "user": "dev",
            "agent_name": "claude",
            "score": 95,
            "severity": "critical",
            "signals": [
                {"id": "agent_credential_access", "detail": "~/.aws/credentials", "weight": 30},
                {
                    "id": "agent_kill_chain",
                    "detail": "credential_access -> identity_creation -> exfiltration",
                    "weight": 25,
                },
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
    # Letter panel keys are capitals only (GAP-2438).
    assert CASE_SENSITIVE_PANEL_SHORTCUTS["N"] == "runtime"
    assert "n" not in PANEL_SHORTCUTS


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


def test_quiet_table_is_not_called_clean_while_coverage_is_degraded() -> None:
    # WIN2-U3-13: DEGRADED / "agent actions: blind" sat next to "a quiet table
    # is a clean host, not a blind sensor".
    model = RuntimePanelModel()
    model.set_snapshot({**_SNAPSHOT, "findings": []})
    assert "not proof of a clean host" in model.empty_state()
    assert "is a clean host" not in model.findings_context()


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
    model.set_snapshot(
        {
            "enabled": True,
            "scanned_at": "2026-09-11T12:00:00Z",
            "processes_observed": 743,
            "connections_observed": 146,
            "planes": [
                {"plane": "a", "name": "inference", "available": True, "running": True, "mechanism": "ps"},
                {"plane": "b", "name": "egress", "available": True, "running": True, "mechanism": "lsof"},
                {"plane": "c", "name": "actions", "available": True, "running": True, "mechanism": "eslogger"},
            ],
        }
    )
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
        "agent",
        "discovery",
        "runtime",
        "enable",
        "--yes",
        "--no-enable-host-plane",
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
    healthy.set_snapshot(
        {
            "enabled": True,
            "scanned_at": "2026-09-11T21:00:00Z",
            "degraded": False,
            "planes": [
                {"plane": "a", "name": "inference heartbeat", "available": True, "running": True, "mechanism": "ps(1)"},
                {"plane": "b", "name": "shadow egress", "available": True, "running": True, "mechanism": "lsof(8)"},
                {"plane": "c", "name": "agent actions", "available": True, "running": True, "mechanism": "eslogger"},
            ],
        }
    )
    assert healthy.health_state() == "healthy"
    assert healthy.health_title() == "HEALTHY"
    assert "HEALTHY" in " ".join(healthy.header_parts())
    assert "watching" in healthy.health_explanation()


def test_selected_plane_gaps_are_degraded() -> None:
    model = RuntimePanelModel()
    model.set_snapshot(
        {
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
        }
    )
    assert model.health_title() == "DEGRADED"
    assert model.needs_enable() is False
    assert "partial" in model.health_explanation().lower()


def test_needs_enable_when_plane_c_is_not_selected() -> None:
    model = RuntimePanelModel()
    model.set_snapshot(
        {
            "enabled": True,
            "scanned_at": "2026-09-11T21:00:00Z",
            "degraded": True,
            "planes": [
                {"plane": "a", "name": "inference heartbeat", "available": True, "running": True, "mechanism": "ps(1)"},
                {
                    "plane": "c",
                    "name": "agent actions",
                    "available": True,
                    "running": False,
                    "reason": "not selected in ai_discovery.runtime.planes",
                },
            ],
        }
    )
    assert model.needs_enable() is False
    assert "optional" in model.plane_fix(model.snapshot.planes[1]).lower()

    off = RuntimePanelModel()
    off.set_snapshot({"enabled": False})
    assert off.needs_enable() is True
    assert off.health_title() == "OFF"


def test_linux_host_plane_hint_names_the_capability_cn_proc_needs() -> None:
    # The cn_proc connector refuses an unprivileged subscriber (EPERM).
    model = RuntimePanelModel(platform="linux")
    model.set_snapshot(
        {
            "enabled": True,
            "planes": [
                {"plane": "c", "name": "agent actions", "available": True, "running": False,
                 "reason": "not selected in ai_discovery.runtime.planes"},
            ],
        }
    )
    hint = model.plane_fix(model.snapshot.planes[0])
    assert "CAP_NET_ADMIN" in hint and "CAP_SYS_ADMIN" in hint and "no grant" not in hint


def test_the_app_defines_every_render_method_the_runtime_loader_calls() -> None:
    """A cheap guard against the same typo returning under a different name."""
    import inspect

    from defenseclaw.tui.app import DefenseClawTUI

    source = inspect.getsource(DefenseClawTUI._load_runtime_model)
    called = {name.split("(")[0] for name in source.split("self.")[1:] if name.startswith("_render")}
    for method in called:
        assert hasattr(DefenseClawTUI, method), (
            f"_load_runtime_model calls self.{method}(), which does not exist; "
            "the worker raises AttributeError and Textual exits the app"
        )


def test_a_limited_running_plane_is_partial_not_up() -> None:
    """GAP-1377: Plane B on a non-elevated gateway is PARTIAL, with a next step."""
    model = RuntimePanelModel(platform="win32")
    model.set_snapshot(
        {
            "enabled": True,
            "scanned_at": "2026-10-02T19:00:00Z",
            "degraded": True,
            "planes": [
                {"plane": "a", "name": "inference heartbeat", "available": True, "running": True,
                 "mechanism": "Toolhelp32 snapshot"},
                {"plane": "b", "name": "shadow egress", "available": True, "running": True,
                 "mechanism": "GetExtendedTcpTable",
                 "reason": "egress attribution is limited to this process's own sockets"},
            ],
        }
    )
    plane_a, plane_b = model.snapshot.planes
    assert plane_a.badge == "up" and model.plane_fix(plane_a) == ""
    assert plane_b.badge == "partial"
    assert "partial via GetExtendedTcpTable" in plane_b.summary
    assert "Permissions" in model.plane_fix(plane_b)
    assert "1 partially watching" in model.health_explanation()


def test_an_unselected_plane_is_off_and_says_how_to_turn_it_on() -> None:
    """GAP-2102: a plane left out of ai_discovery.runtime.planes is 'off', not 'blind'."""
    model = RuntimePanelModel(platform="win32")
    model.set_snapshot(
        {
            "enabled": True,
            "scanned_at": "2026-10-03T01:50:53Z",
            "degraded": True,
            "planes": [
                {"plane": "a", "name": "inference heartbeat", "available": True, "running": True,
                 "mechanism": "Toolhelp32 snapshot"},
                {"plane": "c", "name": "agent actions", "available": False, "running": False,
                 "reason": "not selected in ai_discovery.runtime.planes"},
            ],
        }
    )
    model.handle_key("p")
    assert "agent actions: off" in model.plane_strip()
    explanation = model.health_explanation()
    assert "(1 watching, 1 not selected)" in explanation
    assert "Agent actions is off (not selected)" in explanation
    assert "runtime enable --enable-host-plane" in explanation
    assert explanation.endswith("runtime enable --enable-host-plane")
    assert "1 not selected" in model.health_explanation(short=True)
