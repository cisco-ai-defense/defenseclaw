# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""At 80x24 every Setup view shows its primary content, and the chrome fits.

Two Pilot tests walk the Setup views (task list, goal menu, form, config
editor) and the first-run form at 80x24 and check the first row of each
view's table is on screen under a short body; a third checks a table
painted before it sizes its columns. The tab strip and status line checks
are pure.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw.tui.panels import setup_catalog  # noqa: E402
from defenseclaw.tui.widgets.tab_fit import LABEL_PRIORITY, fit_tab_labels, strip_width  # noqa: E402
from fixtures import screen_text, snapshot_app  # noqa: E402

FIFTEEN_PANELS = (
    ("overview", "1", "Overview"),
    ("alerts", "2", "Alerts"),
    ("skills", "3", "Skills"),
    ("mcps", "4", "MCPs"),
    ("plugins", "5", "Plugins"),
    ("inventory", "6", "Inventory"),
    ("sandboxes", "7", "Sandboxes"),
    ("logs", "8", "Logs"),
    ("audit", "9", "Audit"),
    ("activity", "A", "Activity"),
    ("ai", "V", "AI Discovery"),
    ("runtime", "N", "Runtime"),
    ("registries", "R", "Registries"),
    ("policies", "P", "Policies"),
    ("setup", "0", "Setup"),
)


@pytest.fixture
def hermetic(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    from defenseclaw.inventory import agent_discovery

    empty = agent_discovery.AgentDiscovery(scanned_at="test", agents={}, cache_hit=True)
    monkeypatch.setattr(agent_discovery, "discover_agents", lambda *args, **kwargs: empty)
    return tmp_path


def _table_rows_on_screen(app) -> list[str]:
    from textual.widgets import DataTable

    table = app.query_one("#panel-table", DataTable)
    assert table.display, "Setup table is hidden"
    region = table.region
    screen = screen_text(app).splitlines()
    return [line[region.x : region.right] for line in screen[region.y : region.bottom]]


def _assert_on_screen(app, text: str, *, max_body_lines: int) -> None:
    body_lines = app.body_text.count("\n") + 1
    assert body_lines <= max_body_lines, app.body_text
    assert "Keys:" not in app.body_text
    rows = _table_rows_on_screen(app)
    assert any(text in row for row in rows), f"{text!r} not visible in the Setup table:\n" + "\n".join(rows)


async def test_setup_views_keep_primary_content_on_screen_at_80x24(hermetic) -> None:
    from defenseclaw.config import default_config

    app = snapshot_app(hermetic, setup_config=default_config())
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("setup")
        await pilot.pause()
        await pilot.pause()
        first_task = setup_catalog.wizard_label(setup_catalog.display_order()[0])
        _assert_on_screen(app, first_task, max_body_lines=2)

        await pilot.press("enter")  # goal menu
        await pilot.pause()
        assert app.setup_model.goal_active
        _assert_on_screen(app, app.setup_model.goals[0].label, max_body_lines=2)
        # Goal descriptions wrap instead of being cut at the screen edge.
        assert app.setup_model.goals[0].summary.split()[-1] in screen_text(app)

        await pilot.press("enter")  # form
        await pilot.pause()
        assert app.setup_model.form_active
        _assert_on_screen(app, app.setup_model.form_fields[0].label, max_body_lines=3)

        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("c")  # config editor
        await pilot.pause()
        assert app.setup_model.mode == "config"
        first_field = app.setup_model.current_section().fields[0].label
        _assert_on_screen(app, first_field, max_body_lines=3)
        assert "(1/" in app.body_text

        # g opens the grouped section list; choosing a row jumps there.
        await pilot.press("g")
        await pilot.pause()
        assert "Config sections" in screen_text(app)
        await pilot.press("down", "enter")
        await pilot.pause()
        assert "(2/" in app.body_text


async def test_first_run_shows_its_form_without_the_setup_bar_at_80x24(hermetic) -> None:
    from defenseclaw.tui.app import DefenseClawTUI

    app = DefenseClawTUI(first_run=True)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.pause()
        assert app.first_run_model.active
        _assert_on_screen(app, app.first_run_model.fields[0].label, max_body_lines=2)
        assert app.query_one("#setup-controls").has_class("hidden")
        assert app.query_one("#setup-wizard-controls").has_class("hidden")


async def test_a_table_painted_before_it_measures_its_columns_repaints_them() -> None:
    # Windows CI painted the config table before the DataTable's idle sized
    # its columns, and the cached cells kept showing "Confi" and "(unse".
    from defenseclaw.tui.widgets.data_table import MeasuredDataTable
    from textual.app import App

    class TableApp(App[None]):
        # A set height, like #panel-table's 1fr: new rows do not resize it.
        CSS = "DataTable { height: 6; }"

        def compose(self):
            yield MeasuredDataTable()

    app = TableApp()
    async with app.run_test(size=(80, 10)) as pilot:
        table = app.query_one(MeasuredDataTable)
        table.add_columns("Field", "Value")
        table.add_row("Config Version", "(unset)")
        screen_text(app)  # a paint before the table's idle
        await pilot.pause()
        assert "Config Version  (unset)" in screen_text(app)


@pytest.mark.parametrize("width", (87, 120 - 33))
def test_fifteen_tabs_fit_at_120_columns(width: int) -> None:
    unread = {"alerts": 12, "logs": 3, "audit": 1, "activity": 1, "ai": 2}

    labels = fit_tab_labels(FIFTEEN_PANELS, "setup", unread, width)

    assert strip_width(tuple(labels.values())) <= width
    assert labels["setup"] == "0 Setup"
    for name, key, _label in FIFTEEN_PANELS:
        assert labels[name].startswith(key)
    assert "(12)" in labels["alerts"]


def test_tabs_name_the_most_important_panels_first() -> None:
    full = fit_tab_labels(FIFTEEN_PANELS, "overview", {}, 400)
    wide = fit_tab_labels(FIFTEEN_PANELS, "overview", {}, 180 - 33)

    assert full["policies"] == "P Policies"
    assert wide["overview"] == "1 Overview"
    assert strip_width(tuple(wide.values())) <= 180 - 33
    # A named tab is never less important than a letter-only one.
    named = [name for name in LABEL_PRIORITY if name in wide and wide[name] != wide[name][:1]]
    letter_only = [name for name in LABEL_PRIORITY if name in wide and name not in named]
    assert named and letter_only
    assert max(LABEL_PRIORITY.index(n) for n in named if n != "overview") < min(
        LABEL_PRIORITY.index(n) for n in letter_only
    )
    # Unknown width (before the first layout) keeps the full labels.
    assert fit_tab_labels(FIFTEEN_PANELS, "overview", {}, 0) == full


def test_status_line_has_no_debug_text(hermetic) -> None:
    app = snapshot_app(hermetic)

    assert "backend=" not in app._status_text()  # noqa: SLF001
    assert "hints=" not in app._status_text()  # noqa: SLF001


def test_every_tab_fits_at_80_columns_with_unread_badges(monkeypatch) -> None:
    # 80 columns, no title: 80 - 2 (padding) - 12 (the : and ? buttons).
    unread = {"alerts": 2, "logs": 2, "audit": 1, "activity": 1, "ai": 2}
    for active in ("overview", "policies", "setup"):
        labels = fit_tab_labels(FIFTEEN_PANELS, active, unread, 66)
        assert strip_width(tuple(labels.values())) <= 66, active
        for name, key, _label in FIFTEEN_PANELS:
            assert labels[name].startswith(key)
    # Letter-only tabs keep their badge, as superscript digits.
    monkeypatch.setattr("defenseclaw.tui.widgets.tab_fit._PLAIN_BADGE", False)
    assert fit_tab_labels(FIFTEEN_PANELS, "setup", unread, 66)["logs"] == "8²"
    # Windows consoles draw most superscript digits wrong; use a plain badge.
    monkeypatch.setattr("defenseclaw.tui.widgets.tab_fit._PLAIN_BADGE", True)
    labels = fit_tab_labels(FIFTEEN_PANELS, "setup", unread, 66)
    assert labels["logs"] == "8(2)"
    assert strip_width(tuple(labels.values())) <= 66
    labels = fit_tab_labels(FIFTEEN_PANELS, "overview", unread, 66)
    assert strip_width(tuple(labels.values())) <= 66
    assert labels["alerts"] == "2(2)"


async def test_a_wide_then_80_column_screen_names_tabs_and_keeps_validation(hermetic) -> None:
    """GAP-1283: at 200 columns every tab has a name. GAP-1166: shrinking to
    80x24 rebuilds the config table so the Validation column stays on screen."""

    from defenseclaw.config import default_config

    app = snapshot_app(hermetic, setup_config=default_config())
    async with app.run_test(size=(200, 50)) as pilot:
        await pilot.pause()
        tabs = screen_text(app).splitlines()[0]
        assert "R Registr" in tabs, tabs
        app.action_switch_panel("setup")
        await pilot.pause()
        await pilot.press("c", "/", *"device", "enter")
        await pilot.pause()
        await pilot.resize_terminal(80, 24)
        for _ in range(3):
            await pilot.pause()
        rows = _table_rows_on_screen(app)
        assert "Validation" in rows[0], "\n".join(rows)
