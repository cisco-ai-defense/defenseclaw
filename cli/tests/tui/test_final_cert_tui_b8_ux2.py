# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 8 (ux2): tab badges, Overview with the gateway
down, upgrade/doctor results, the confirm modal, config editor and API keys."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest
from defenseclaw.tui.app import PANELS, _validation_label
from defenseclaw.tui.command_line import (
    DOCTOR_DETAILS_HINT,
    READINESS_HINT,
    ParsedCommand,
    command_result_summary,
    suggested_next_action,
)
from defenseclaw.tui.panels import setup_catalog
from defenseclaw.tui.panels.alerts import AlertEvent
from defenseclaw.tui.panels.setup import SetupPanelModel, build_setup_sections
from defenseclaw.tui.screens.command_preview import CommandPreviewScreen, build_command_preview
from defenseclaw.tui.services.setup_state import CredentialRow, CredentialSnapshot, credential_reload_summary
from defenseclaw.tui.widgets import tab_fit
from rich.console import Console
from textual.app import App

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402

_SUPERSCRIPTS = set("⁰¹²³⁴⁵⁶⁷⁸⁹⁺")


def _parsed(args: tuple[str, ...], *, category: str = "other", risk: str = "read-only") -> ParsedCommand:
    return ParsedCommand(
        binary="defenseclaw",
        args=args,
        display_name=" ".join(args),
        category=category,
        needs_preview=True,
        risk=risk,
    )


def _plain(renderable: object) -> str:
    console = Console(file=io.StringIO(), width=120, color_system=None)
    console.print(renderable)
    return console.file.getvalue()


def test_logs_tail_loaded_for_a_visit_never_becomes_unread(tmp_path) -> None:
    # GAP-2244: the tail landed after the seen count was recorded -> Logs(999+).
    app = snapshot_app(tmp_path)
    app._read_snapshot = None  # noqa: SLF001 - count from the logs model alone.
    app.logs_model.lines = {source: [] for source in app.logs_model.lines}
    app.state_store.record_seen_count("logs", 0)
    app.active_panel = "audit"
    before = app._panel_total_count("logs")  # noqa: SLF001
    app.logs_model.lines["gateway"] = ["line"] * 3171
    app._mark_log_tail_seen(before)  # noqa: SLF001
    assert app._panel_unread_count("logs") == 0  # noqa: SLF001
    app.logs_model.lines["gateway"] += ["new", "new"]
    assert app._panel_unread_count("logs") == 2  # noqa: SLF001


def test_alerts_badge_stays_on_the_open_alerts_tab_and_bare_keys_use_brackets(tmp_path, monkeypatch) -> None:
    # GAP-2247: the open Alerts tab dropped its count (relabelling MCP/Plugin),
    # and at 80x24 "2²²" read as an exponent.
    app = snapshot_app(tmp_path)
    app.alerts_model.set_events(
        [AlertEvent(id=f"a{i}", severity="HIGH", action="scan", target="skill://x", details="") for i in range(3)]
    )
    app.active_panel = "alerts"
    assert app._panel_unread_count("alerts") == app.alerts_model.total_count() > 0  # noqa: SLF001
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    labels = tab_fit.fit_tab_labels(PANELS, "overview", {"alerts": 22, "activity": 3}, 66)
    assert labels["alerts"].endswith("(22)"), labels["alerts"]
    for label in labels.values():
        assert " " in label or not _SUPERSCRIPTS & set(label), label
    # Still the count, compact, when brackets don't fit.
    assert tab_fit.fit_tab_labels(PANELS, "registries", {"alerts": 7, "logs": 50, "audit": 27}, 50)["alerts"] == "2⁷"


def test_overview_cards_say_no_data_when_the_gateway_is_stopped(tmp_path) -> None:
    # GAP-2248: Guardrail "ON / action" and RUNTIME "DEGRADED · 17 processes"
    # beside an all-offline SERVICES list.
    app = snapshot_app(tmp_path)
    app.overview_model.set_gateway_probe("stopped")
    guardrail = next(m for m in app._overview_metric_data() if m.key == "guardrail")  # noqa: SLF001
    if app.overview_model.cfg is not None and app.overview_model.cfg.guardrail_enabled:
        assert guardrail.value_text == "DOWN" and "gateway not running" in guardrail.detail
    runtime = _plain(app._overview_runtime_panel())  # noqa: SLF001
    assert "NO DATA - gateway not running" in runtime and "processes" not in runtime


def test_upgrade_and_doctor_results_name_the_outcome() -> None:
    # GAP-2250, GAP-2252.
    upgrade = [
        "✓ DefenseClaw 1.0.1 is up to date (latest release: 0.8.10 is older). Nothing was changed.",
        "To install a specific 1.x release: defenseclaw upgrade --version X.Y.Z",
    ]
    assert command_result_summary("Upgrade", upgrade).startswith("DefenseClaw 1.0.1 is up to date")
    doctor = [
        "[PASS] Gateway",
        "[WARN] Connector OTLP: codex  -  partial drop-only evidence",
        "Health: 129 passed, 1 warning, 29 skipped",
    ]
    assert command_result_summary("Doctor", doctor) == (
        "Health: 129 passed, 1 warning, 29 skipped · check: Connector OTLP: codex"
    )
    assert suggested_next_action("Doctor", 0, lines=doctor) == DOCTOR_DETAILS_HINT
    assert suggested_next_action("Doctor", 0, lines=doctor[:1]) == READINESS_HINT
    summary = build_command_preview(_parsed(("upgrade",))).summary
    assert "Checks the latest release first" in summary and "nothing changes" in summary


@pytest.mark.asyncio
async def test_confirm_modal_left_right_move_between_buttons_at_80x24() -> None:
    # GAP-2251: only Tab moved; palette restart focused Run, Overview u Cancel.
    restart = _parsed(("restart",), category="gateway", risk="restart")
    assert build_command_preview(restart).cancel_by_default

    class _Host(App[None]):
        pass

    host = _Host()
    async with host.run_test(size=(80, 24)) as pilot:
        await host.push_screen(CommandPreviewScreen(restart))
        await pilot.pause()
        assert host.screen.focused.id == "preview-cancel"
        await pilot.press("right")
        assert host.screen.focused.id == "preview-run"
        await pilot.press("right")
        assert host.screen.focused.id == "preview-run"
        await pilot.press("left")
        assert host.screen.focused.id == "preview-cancel"


def test_config_editor_unset_read_only_fields_and_legacy_claw() -> None:
    # GAP-2253.
    agent = next(section for section in build_setup_sections({}) if section.name == "Agent")
    for field in agent.fields:
        assert field.value != "read-only"
        if field.kind == "header":
            assert field.value == "(unset)" and _validation_label(field) == "read-only"
    assert setup_catalog.section_group("Claw") == "Legacy"
    claw = next(section for section in build_setup_sections({}) if section.name == "Claw")
    assert "Legacy" in claw.summary and "Which agent framework" not in claw.summary


def test_api_key_reload_reports_done_and_set_form_names_the_task() -> None:
    # GAP-2255, GAP-2256.
    rows = (
        CredentialRow(env_name="OPENAI_API_KEY", requirement="required", set=True),
        CredentialRow(env_name="SPLUNK_TOKEN", requirement="optional"),
    )
    assert credential_reload_summary(CredentialSnapshot(rows=rows)) == "Credentials reloaded: 2, 1 required, all set"
    assert "missing: OPENAI_API_KEY" in credential_reload_summary(
        CredentialSnapshot(rows=(CredentialRow(env_name="OPENAI_API_KEY", requirement="required"),))
    )
    model = SetupPanelModel({})
    model.set_credential_snapshot(rows)
    model.credential_action("s")
    assert model.active_goal is not None and model.active_goal.label == "Set one API key"
    fields = {field.label: field for field in model.form_fields}
    assert fields["Action"].options == ("set",)
    assert "Action" not in fields["Secret Value"].hint and "stdin" in fields["Secret Value"].hint
