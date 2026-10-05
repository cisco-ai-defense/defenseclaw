# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert UX batch 16 (ux2): failing exports in Setup, doctor drawer, SERVICES Sinks,
plugin scan time, registry severity, open-tab name, R on an empty list."""

from __future__ import annotations

import io
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

import pytest
from defenseclaw.observability.v8_status import V8DestinationStatus, V8OperatorStatus
from defenseclaw.tui import app as app_module
from defenseclaw.tui.app import PANELS, DefenseClawTUI
from defenseclaw.tui.command_line import failure_result_summary, suggested_next_action
from defenseclaw.tui.panels import setup_catalog
from defenseclaw.tui.panels.registries import entry_detail_info, entry_severity_label
from defenseclaw.tui.panels.setup import SetupPanelModel
from defenseclaw.tui.services.catalog_state import (
    MCPsPanelModel,
    PluginRow,
    PluginScanSummary,
    SkillsPanelModel,
    _format_plugin_detail,
    _scanned_line,
)
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width
from rich.console import Console
from textual.geometry import Size

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402


def _dest(name: str, *, generated: bool = False, kind: str = "otlp") -> V8DestinationStatus:
    return V8DestinationStatus(
        name=name,
        kind=kind,
        enabled=True,
        generated=generated,
        capabilities=("traces",),
        selected_signals=("traces",),
        policy_form="capability_default",
        endpoint="http://127.0.0.1:19997",
        route_count=1,
        buckets=(),
        redaction_profiles=("none",),
    )


def test_setup_names_a_failing_export() -> None:
    # GAP-2394: Overview said "sf3r9-dead (failing)" while Setup said
    # "✓ 3 exports + local" and readiness passed.
    plan = V8OperatorStatus(
        source="config.yaml",
        data_dir="/tmp/dc",
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=30,
        local_path="/tmp/dc/audit.db",
        judge_bodies_path="/tmp/dc/judge.db",
        destinations=(_dest("local-sqlite", generated=True, kind="sqlite"), _dest("o11y"), _dest("sf3r9-dead")),
        buckets=(),
        warnings=(),
    )
    details = {
        "destinations": [{"name": "o11y", "health_state": "healthy"}, {"name": "sf3r9-dead", "health_state": "failing"}]
    }
    health = SimpleNamespace(telemetry=SimpleNamespace(details=details))
    model = SetupPanelModel({})
    model.set_observability_status(plan)
    model.rebuild_readiness_checks(health=health)
    telemetry = next(check for check in model.readiness_checks if check.title == "Telemetry")
    assert telemetry.status == "warn"
    assert telemetry.detail.startswith("1 of 2 exports failing: sf3r9-dead. Run defenseclaw setup observability test")
    status = setup_catalog.task_status(
        setup_catalog.SetupWizard.OBSERVABILITY,
        {},
        model.readiness_checks,
        observability=plan,
        failing_exports=model.failing_exports,
    )
    assert status.label == "! 1 of 2 failing"
    # Healthy again: back to the count.
    details["destinations"][1]["health_state"] = "healthy"
    model.rebuild_readiness_checks(health=health)
    assert model.failing_exports == ()
    assert setup_catalog._observability_status(plan, "", ()).text == "2 exports + local"


def test_failed_doctor_drawer_names_the_check() -> None:
    # GAP-2395: the drawer read "Fix the failures above" with nothing above it.
    lines = [
        "[FAIL] Destination: sf3r9-dead  -  connection failed",
        "Health: 131 passed, 1 failed",
        "⚠ Fix the failures above, then re-run: defenseclaw doctor",
    ]
    assert failure_result_summary("doctor", lines) == "Health: 131 passed, 1 failed · check: Destination: sf3r9-dead"
    assert suggested_next_action("doctor", 1, lines=lines).startswith("press A (Activity)")
    assert failure_result_summary("keys check", lines) == ""


def _service_names(app: DefenseClawTUI, width: int) -> set[str]:
    console = Console(width=width, record=True, color_system=None, file=io.StringIO())
    console.print(app._overview_renderable())  # noqa: SLF001
    names = {
        line[1:].split("│")[0][1:].lstrip("●○ ").split("  ")[0].strip()
        for line in console.export_text().splitlines()
        if line.startswith(("│ ●", "│ ○"))
    }
    # At 80 columns one space follows "AI Discovery" (GAP-2412).
    return {"AI Discovery" if name.startswith("AI Discovery") else name for name in names}


@pytest.mark.parametrize("width", [160, 80])
def test_services_rows_stay_the_same_when_the_gateway_stops(tmp_path, width) -> None:
    # GAP-2396: a "Sinks offline" row appeared only with the gateway stopped.
    app = snapshot_app(tmp_path)
    with patch.object(DefenseClawTUI, "size", new_callable=PropertyMock, return_value=Size(width, 24)):
        app.overview_model.set_gateway_probe("running")
        running = _service_names(app, width)
        app.overview_model.set_gateway_probe("stopped")
        stopped = _service_names(app, width)
    assert "Gateway" in running and "Sinks" not in running
    assert running == stopped


def test_plugin_detail_says_when_it_was_scanned() -> None:
    # GAP-2401: a 15 h old verdict read as current.
    now = datetime(2026, 10, 3, 8, 0, tzinfo=timezone.utc)
    assert _scanned_line("2026-10-02 16:53:12 UTC", now) == "2026-10-02 16:53Z (15 h ago)"
    assert _scanned_line("2026-09-28 08:00:00 UTC", now) == "2026-09-28 08:00Z (5 d ago)"
    scan = PluginScanSummary.from_mapping(
        {"clean": False, "max_severity": "HIGH", "total_findings": 5, "scanned_at": "2026-10-02 16:53:12 UTC"}
    )
    row = PluginRow(id="photon", name="photon-platform", status="enabled", enabled=True, verdict="rejected", scan=scan)
    detail = _format_plugin_detail(row)
    assert "  Scanned    2026-10-02 16:53Z (" in detail and "press s to rescan with this build" in detail


def test_clean_registry_entry_reads_clean_and_source_id_once() -> None:
    # GAP-2402: "Severity: INFO" for a clean server that mcp list calls CLEAN.
    entry = SimpleNamespace(
        source_id="sf1-local",
        name="deepwiki",
        type="mcp",
        status="clean",
        severity="INFO",
        findings=0,
        approved=True,
        rejected=False,
        transport="streamable-http",
        command="",
        args=(),
        url="https://mcp.deepwiki.com/mcp",
        source_url="",
        location="",
    )
    assert entry_severity_label(entry) == "CLEAN"
    assert dict(entry_detail_info(entry).fields)["Severity"] == "CLEAN"
    assert entry_severity_label(SimpleNamespace(**(vars(entry) | {"status": "pending", "severity": ""}))) == "-"
    assert entry_severity_label(SimpleNamespace(**(vars(entry) | {"severity": "MEDIUM", "findings": 2}))) == "MEDIUM"


@pytest.mark.parametrize("active", ["registries", "ai", "inventory"])
@pytest.mark.parametrize("width", [172, 174, 176, 180])
def test_open_tab_keeps_its_full_name_beside_catalog_counts(monkeypatch, active, width) -> None:
    # GAP-2403: "R Registri…" at 200 columns with Skills/MCPs/Plugins counts.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    key, title = next((key, title) for name, key, title in PANELS if name == active)
    for unread in (
        {"logs": 1000, "audit": 579, "skills": 12, "mcps": 12, "plugins": 3},
        {"alerts": 22, "logs": 48, "audit": 579, "skills": 12, "mcps": 12, "plugins": 3},
    ):
        labels = fit_tab_labels(PANELS, active, unread, width)
        assert labels[active].startswith(f"{key} {title}"), labels
        assert strip_width(tuple(labels.values())) <= width


def test_r_on_an_empty_list_falls_through_to_registries() -> None:
    # GAP-2404: R did nothing and said nothing on an empty Skills/MCPs list.
    for model in (SkillsPanelModel(), MCPsPanelModel()):
        assert model.handle_key("R").handled is False
    assert app_module.CASE_SENSITIVE_PANEL_SHORTCUTS["R"] == "registries"
