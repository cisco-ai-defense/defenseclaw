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
    # Collapsed, the strip is a badge per plane; expanded, every non-running
    # plane must say why. A blind plane that renders as silence is
    # indistinguishable from a clean host.
    model = _model()
    collapsed = model.plane_strip()
    assert len(collapsed) == 3
    assert "agent actions: blind" in collapsed
    assert "shadow egress: idle" in collapsed

    assert model.handle_key("p") is RuntimePanelAction.TOGGLE_PLANES
    expanded = model.plane_strip()
    assert any("eslogger not found" in line for line in expanded)
    assert any("available but not running" in line for line in expanded)


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
