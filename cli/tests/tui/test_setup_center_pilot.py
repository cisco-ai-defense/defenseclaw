# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The Setup center at 80x24: one group of tasks, a Status column, a detail.

Two Pilot tests: the task list fits (first task rows above the fold with
the detail below them, the one-line group switcher clicks), and the keys
walk the tasks across groups even while the table has focus. The wide
layout (nav list and aside) is covered by test_panel_split.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw.tui.panels import setup_catalog  # noqa: E402
from defenseclaw.tui.panels.setup import SetupWizard  # noqa: E402
from fixtures import screen_text, snapshot_app  # noqa: E402


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    from defenseclaw.config import default_config
    from defenseclaw.inventory import agent_discovery

    empty = agent_discovery.AgentDiscovery(scanned_at="test", agents={}, cache_hit=True)
    monkeypatch.setattr(agent_discovery, "discover_agents", lambda *args, **kwargs: empty)
    return snapshot_app(tmp_path, setup_config=default_config())


def _table_lines(app) -> list[str]:
    from textual.widgets import DataTable

    region = app.query_one("#panel-table", DataTable).region
    return [line[region.x : region.right] for line in screen_text(app).splitlines()[region.y : region.bottom]]


async def test_task_list_fits_80x24_and_the_group_switcher_clicks(app) -> None:
    first, second = setup_catalog.GROUP_TITLES[:2]
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("setup")
        await pilot.pause()
        await pilot.pause()

        # Header plus the one-line group switcher; no nav list at 80 columns.
        assert app.body_text.count("\n") == 1
        assert not app.query_one("#panel-nav").display
        assert app.query_one("#setup-controls").has_class("hidden")
        rows = _table_lines(app)
        task = setup_catalog.wizard_label(setup_catalog.group_tasks(first)[0])
        row = next((line for line in rows if task in line), "")
        assert row, "\n".join(rows)
        assert any(glyph in row for glyph in setup_catalog.TASK_GLYPHS.values())
        # The task's detail sits below the table without covering its rows.
        detail = app.query_one("#detail-panel")
        assert detail.display and detail.border_title == task
        assert detail.region.y > app.query_one("#panel-table").region.y + 1

        # Clicking a group name on the switcher shows that group.
        screen = screen_text(app).splitlines()
        y = next(i for i, line in enumerate(screen) if first in line and second in line)
        await pilot.click(offset=(screen[y].index(second) + 1, y))
        await pilot.pause()
        assert setup_catalog.wizard_group(app.setup_model.active_wizard) == second
        assert any(
            setup_catalog.wizard_label(setup_catalog.group_tasks(second)[0]) in line for line in _table_lines(app)
        )


async def test_keys_walk_tasks_across_groups_with_the_table_focused(app) -> None:
    from textual.widgets import DataTable

    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("setup")
        await pilot.pause()
        last_of_first = setup_catalog.group_tasks(setup_catalog.GROUP_TITLES[0])[-1]
        app.setup_model.active_wizard = last_of_first
        app._render_chrome()  # noqa: SLF001
        app.query_one("#panel-table", DataTable).focus()
        await pilot.pause()

        # Down from a group's last task carries on into the next group.
        await pilot.press("down")
        await pilot.pause()
        assert app.setup_model.active_wizard is setup_catalog.step_wizard(last_of_first, 1)
        assert setup_catalog.wizard_group(app.setup_model.active_wizard) == setup_catalog.GROUP_TITLES[1]

        # Left/right switch groups; up walks back into the previous group.
        await pilot.press("right")
        await pilot.pause()
        assert app.setup_model.active_wizard is setup_catalog.group_tasks(setup_catalog.GROUP_TITLES[2])[0]
        await pilot.press("left", "up")
        await pilot.pause()
        assert app.setup_model.active_wizard is last_of_first

        # Enter still opens the task's goal menu, Esc goes back, c opens the editor.
        await pilot.press("enter")
        await pilot.pause()
        assert app.setup_model.goal_active
        await pilot.press("escape", "c")
        await pilot.pause()
        assert app.setup_model.mode == "config"
        assert app.setup_model.active_wizard is SetupWizard(last_of_first)
