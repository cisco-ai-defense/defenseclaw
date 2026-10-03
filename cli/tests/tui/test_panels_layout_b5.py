# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""TUI panels layout batch 5: tab names, status line, palette, footers, Setup."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from defenseclaw.models import Event
from defenseclaw.tui.app import PANELS, _severity_breakdown_markup
from defenseclaw.tui.command_line import infer_command_risk
from defenseclaw.tui.models import HintState
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, wizard_goals
from defenseclaw.tui.screens.detail import DetailModalModel
from defenseclaw.tui.screens.panel_jumper import PanelChoice, PanelJumperScreen
from defenseclaw.tui.services.catalog_state import ToolsPanelModel
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.hint_bar import HintEngine
from rich.console import Console
from rich.text import Text

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import settle_panel, snapshot_app  # noqa: E402


def _plain(markup: str) -> str:
    return Text.from_markup(markup).plain


def test_every_tab_has_a_name_at_160_columns_and_short_active_names_end_with_an_ellipsis(monkeypatch) -> None:
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    unread = {"alerts": 5, "audit": 5}
    # GAP-1544: 160 columns without the brand leave 146 cells for the strip.
    for active in ("overview", "activity", "registries"):
        labels = tab_fit.fit_tab_labels(PANELS, active, unread, 146)
        assert tab_fit.strip_width(tuple(labels.values())) <= 146
        bare = [name for name, key, _label in PANELS if labels[name] in {key, f"{key}⁵"}]
        # Labels stay put across panels and the counts stay (GAP-2077,
        # GAP-2078): with two counts up only the two least important tabs
        # wait as key letters, so AI Discovery can read in full.
        assert set(bare) <= {"runtime", "registries"}, (active, labels)
        assert labels["inventory"] == "6 Inv" and "⁵" in labels["audit"]
    # GAP-1751: at 80 columns the active tab reads in full when other tabs'
    # names and minor badges make room (an abbreviated one still ends with "…").
    labels = tab_fit.fit_tab_labels(PANELS, "sandboxes", unread, 66)
    assert labels["sandboxes"] == "7 Sandboxes" and "⁵" in labels["alerts"]


def test_palette_enter_uses_the_text_typed_so_far() -> None:
    # GAP-1540: "plugins" + Enter in one burst opened Overview.
    choices = tuple(PanelChoice(name=name, label=label, hotkey=key) for name, key, label in PANELS)
    screen = PanelJumperScreen(choices)
    picked: list[object] = []
    screen.dismiss = lambda value=None: picked.append(value)  # type: ignore[method-assign]
    screen._refresh_list = lambda: None  # type: ignore[method-assign]
    screen.query_one = lambda *_args, **_kwargs: SimpleNamespace(value="plugins")  # type: ignore[method-assign]
    screen.action_choose()
    assert picked == ["plugins"]


def test_status_rows_and_filters_say_what_they_show() -> None:
    # GAP-1584: watchdog status only reads state.
    assert infer_command_risk("daemon", ("watchdog", "status")) == "read-only"
    assert infer_command_risk("daemon", ("watchdog", "start")) == "mutation"

    # GAP-1583: a rejected config reload is not a block.
    stamp = datetime(2026, 10, 2, 12, 44, tzinfo=timezone.utc)
    audit = AuditPanelModel()
    audit.set_events(
        [
            Event(id="c1", timestamp=stamp, action="config.reload.rejected", target="config", severity="INFO"),
            Event(
                id="h1",
                timestamp=stamp,
                action="connector-hook",
                target="UserPromptSubmit",
                details="connector=claudecode result=ok action=block raw_action=block mode=action",
            ),
        ]
    )
    audit.set_common_filter("blocks")
    assert [event.id for event in audit.filtered] == ["h1"]

    # GAP-1545: severity words, not "C5 H2 M0 L0".
    assert _plain(_severity_breakdown_markup(5, 2, 0, 0)) == "Critical 5 · High 2"
    assert _plain(_severity_breakdown_markup(0, 0, 0, 0)) == "none open"

    # GAP-1541: the Tools explanation is said once and the keys are on the
    # hint bar.
    tools = ToolsPanelModel()
    tools.apply_loaded([])
    summary = _plain(tools.summary_text("Tools"))
    assert "Navigate:" not in summary and "unblocked tools disappear" in summary
    assert "disappear" not in tools.empty_state()

    # GAP-1582: the Alerts hint counts the filtered connector's alerts.
    text = HintEngine().hint_for(
        HintState(active_panel="alerts", critical_alerts=1, total_alerts=15, connector_filter="Codex")
    )
    assert text.startswith("1 critical/high alert(s) for Codex.")


def test_setup_rerun_offers_configured_connectors_and_details_keep_names() -> None:
    # GAP-1547: Right on Connector cycled into agents that are not installed.
    cfg = {"guardrail": {"connector": "amp", "connectors": {"codex": {}, "claudecode": {}, "amp": {}}}}
    model = SetupPanelModel(cfg)
    for goal_id in ("rerun", "remove"):
        goal = next(goal for goal in wizard_goals(SetupWizard.CONNECTOR_SETUP, cfg) if goal.id == goal_id)
        model.open_wizard_form(SetupWizard.CONNECTOR_SETUP, goal=goal)
        connector = next(field for field in model.form_fields if field.label == "Connector")
        assert connector.options == ("amp", "claudecode", "codex")
        assert connector.value == "amp"
    # Readiness rows show the whole connector name ("Active Connector: ope…").
    console = Console(width=92, record=True)
    console.print(DetailModalModel.from_pairs("t", [("Active Connector: openhands", "PASS · configured")]).table())
    assert "openhands" in console.export_text()


async def test_short_screen_lists_keep_rows_and_stale_status_clears(tmp_path, monkeypatch) -> None:
    import defenseclaw.tui.app as app_module

    async def listed(_binary, _args, **_kwargs):
        return 0, b"[]", b""

    monkeypatch.setattr(app_module, "_communicate_captured", listed)
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        # GAP-1380: an open detail leaves the header and two rows (plus the
        # sideways scrollbar of a wide table).
        app.action_switch_panel("inventory")
        await settle_panel(app, pilot)
        await pilot.press("l", "enter")
        await settle_panel(app, pilot)
        assert app.query_one("#panel-table").region.height >= 4
        # GAP-1512: a panel's own result does not follow you to the next
        # panel; a command result does.
        app._set_status("Exported 17 audit row(s) from the current view to /tmp/x.json.")  # noqa: SLF001
        app.action_switch_panel("logs")
        assert app.status_text == "Ready."
        app._set_status("Done: alerts acknowledge 1 selected.")  # noqa: SLF001
        app.action_switch_panel("sandboxes")
        assert app.status_text.startswith("Done:")
        # GAP-1581: reloading a loaded table keeps the status line.
        app.action_switch_panel("plugins")
        await settle_panel(app, pilot)
        model = app.catalog_models["plugins"]
        model.loaded = True
        model.apply_json = lambda _text: model.apply_loaded([])
        model.apply_merged = lambda _results: model.apply_loaded([])
        app._set_status("Done: block plugin chronos.")  # noqa: SLF001
        await app._load_catalog_model("plugins")  # noqa: SLF001
        assert app.status_text == "Done: block plugin chronos."


def test_inventory_summary_counts_rules() -> None:
    # GAP-1546: aibom lists "Rules (Hermes 1)"; the Summary now counts them.
    from defenseclaw.tui.services.inventory_state import InventoryPanelModel

    model = InventoryPanelModel()
    model.apply_json(
        '{"version": 4, "summary": {"total_items": 1, "rules": {"count": 1}}, "rules": [{"id": "r1"}]}'
    )
    rows = dict(model.summary_table_rows())
    assert rows["Rules"] == "1 (list them with: defenseclaw aibom scan)"
