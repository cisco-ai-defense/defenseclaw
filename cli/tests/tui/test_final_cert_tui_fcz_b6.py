# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch fcz-b6: tab bar, plugins detail, Setup goal form and header."""

from __future__ import annotations

import sys
from pathlib import Path

from defenseclaw.tui.app import PANELS
from defenseclaw.tui.panels.setup import SetupWizard, wizard_state_summary
from defenseclaw.tui.services.catalog_state import PluginRow, PluginScanSummary
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import settle_panel, snapshot_app  # noqa: E402


def test_160_columns_on_registries_names_every_tab(monkeypatch) -> None:
    # GAP-2086: a 160-column terminal (146-cell strip) read "A  V  N" bare
    # while Audit kept "(13)" and Policies its long name.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    for badges, width in (({"alerts": 16, "audit": 13}, 146), ({"alerts": 9}, 144), ({"alerts": 9}, 145)):
        labels = fit_tab_labels(PANELS, "registries", badges, width)
        assert strip_width(tuple(labels.values())) <= width
        assert labels["registries"] == "R Registries"
        assert all(
            label.strip("⁰¹²³⁴⁵⁶⁷⁸⁹") != key for (_n, key, _t), label in zip(PANELS, labels.values(), strict=True)
        )


async def test_plugin_detail_scrolls_with_page_down_at_80x24(tmp_path) -> None:
    # GAP-2087: the detail stopped after "Scan" and no key moved it.
    from textual.containers import VerticalScroll

    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("plugins")
        await settle_panel(app, pilot)
        model = app.catalog_models["plugins"]
        row = PluginRow(
            id="photon",
            name="photon-platform",
            description="word " * 80,
            version="0.3.0",
            origin="bundled",
            status="enabled",
            enabled=True,
            verdict="rejected",
            scan=PluginScanSummary(clean=False, max_severity="HIGH", total_findings=7),
            connector="hermes",
        )
        model.loaded = True
        model.apply_loaded([row])
        app._render_chrome()  # noqa: SLF001
        await pilot.press("enter")
        await pilot.pause()
        detail = app.query_one("#detail-panel", VerticalScroll)
        assert detail.max_scroll_y > 0
        await pilot.press("pagedown")
        await pilot.pause()
        assert detail.scroll_y > 0
        assert model.detail_open


def test_esc_in_a_goal_form_returns_to_the_goal_list(tmp_path) -> None:
    # GAP-2091: Esc went back to the Setup task list, not "What do you want to do?".
    app = snapshot_app(tmp_path)
    model = app.setup_model
    assert model.open_goal_menu(SetupWizard.REDACTION)
    model.goal_cursor = 1
    model.select_active_goal()
    action = app._handle_setup_form_key("escape")  # noqa: SLF001
    assert action.hint == "Back to the goal list."
    assert model.goal_active and not model.form_active and model.goal_cursor == 1
    # A form opened without the goal menu still closes to the task list.
    model.close_wizard_form()
    model.open_wizard_form(SetupWizard.REDACTION)
    app._handle_setup_form_key("escape")  # noqa: SLF001
    assert not model.goal_active and not model.form_active


def test_guardrail_header_shows_the_strategy_connectors_run() -> None:
    # GAP-2092: "Strategy: regex_judge" while every connector scanned regex_only.
    def summary(judge: dict) -> str:
        cfg = {
            "claw": {"mode": "codex"},
            "guardrail": {"enabled": True, "mode": "action", "detection_strategy": "regex_judge", "judge": judge},
        }
        return wizard_state_summary(SetupWizard.GUARDRAIL, cfg)

    assert summary({"enabled": False}).endswith("Strategy: regex_only (judge off)")
    assert summary({"enabled": True, "hook_connectors": ["claudecode"]}).endswith(
        "Strategy: regex_only (judge on for no active connector)"
    )
    assert summary({"enabled": True, "hook_connectors": ["*"]}).endswith("Strategy: regex_judge")
