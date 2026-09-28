# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The shared split layout: nav list, table, aside.

Pure tests cover the width rules, the nav list (headings, active marker,
badges, windowing, click rows) and the one-line switcher. One Pilot test
drives a panel that opts in through the app hooks at 160x45 (nav and aside
on screen, a click selects an item) and narrows it so the aside moves below
the table.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from rich.console import Console
from rich.text import Text

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw.tui.widgets import panel_split  # noqa: E402
from defenseclaw.tui.widgets.panel_split import Aside, NavItem  # noqa: E402

ITEMS = (
    NavItem("one", "Get protected", "3"),
    NavItem("two", "Guardrail & scanning", "9 !", active=True),
    NavItem("three", "Alerts & telemetry", "6"),
    NavItem("four", "Gateway & advanced", "4"),
)


@pytest.mark.parametrize(
    ("width", "nav", "aside", "below"),
    [
        (0, False, False, True),
        (99, False, False, True),
        (100, True, False, True),
        (119, True, False, True),
        (120, True, True, False),
        (200, True, True, False),
    ],
)
def test_width_rules(width, nav, aside, below) -> None:
    layout = panel_split.split_layout(width, has_nav=True, has_aside=True)

    assert (layout.nav, layout.aside, layout.aside_below) == (nav, aside, below)
    assert panel_split.split_layout(width, has_nav=False, has_aside=False) == panel_split.SplitLayout()


def test_nav_lines_mark_the_active_item_and_keep_badges() -> None:
    lines = panel_split.nav_lines(ITEMS, width=20)
    plain = [line.text.plain for line in lines]

    assert [line.key for line in lines] == ["one", "two", "three", "four"]
    assert plain[1].startswith("▸ ")
    assert not plain[0].startswith("▸")
    assert all(len(text) <= 20 for text in plain)
    # The badge stays whole and right-aligned; the label gives way.
    assert plain[1].endswith("9 !") and "…" in plain[1]
    assert plain[0].endswith("3")


def test_nav_groups_get_headings_that_are_not_clickable() -> None:
    items = (
        NavItem("back", "Back"),
        NavItem("a", "Alpha", group="Core"),
        NavItem("b", "Beta", group="Core", active=True),
        NavItem("c", "Gamma", group="Other"),
    )
    lines = panel_split.nav_lines(items, width=20)

    assert [line.text.plain.strip() for line in lines] == ["Back", "Core", "Alpha", "▸ Beta", "Other", "Gamma"]
    assert [panel_split.nav_key_at(lines, row) for row in range(len(lines) + 1)] == [
        "back",
        None,
        "a",
        "b",
        None,
        "c",
        None,
    ]


def test_a_long_nav_keeps_the_active_item_in_its_window() -> None:
    items = tuple(NavItem(str(i), f"Item {i}", active=i == 25) for i in range(40))
    lines = panel_split.nav_lines(items, width=20, height=9)

    assert len(lines) == 9
    assert "25" in [line.key for line in lines]
    assert lines[0].key is None and "more" in lines[0].text.plain
    assert lines[-1].key is None and "more" in lines[-1].text.plain
    # The whole list fits when there is room.
    assert len(panel_split.nav_lines(items, width=20, height=0)) == 40


def test_switcher_shows_every_item_when_it_fits() -> None:
    switcher = panel_split.nav_switcher(ITEMS, 120)
    plain = Text.from_markup(switcher.markup).plain

    assert plain == "Get protected · ▸Guardrail & scanning ! · Alerts & telemetry · Gateway & advanced"
    for start, end, key in switcher.hits:
        assert switcher.key_at(start) == key == switcher.key_at(end - 1)
        label = next(item.label for item in ITEMS if item.key == key)
        assert plain[start:end].lstrip("▸").startswith(label)


def test_narrow_switcher_keeps_the_active_item_and_points_at_the_rest() -> None:
    switcher = panel_split.nav_switcher(ITEMS, 64)
    plain = Text.from_markup(switcher.markup).plain

    assert len(plain) <= 64
    assert "▸Guardrail & scanning !" in plain
    assert plain.endswith("›")
    # The arrow selects the nearest hidden item.
    assert switcher.key_at(len(plain) - 1) == "four"
    assert switcher.key_at(plain.index("Guardrail")) == "two"


def test_narrow_switcher_shows_as_many_items_as_fit() -> None:
    items = tuple(NavItem(i.key, i.label, i.badge, active=i.key == "three") for i in ITEMS) + (
        NavItem("five", "Config editor"),
    )
    labels = ["Get protected", "Guardrail & scanning", "Alerts & telemetry", "Gateway & advanced", "Config editor"]

    # 84 columns hold every item but the first: the window grows both ways.
    plain = Text.from_markup(panel_split.nav_switcher(items, 84).markup).plain
    assert plain.startswith("‹") and not plain.endswith("›")
    assert [label in plain for label in labels] == [False, True, True, True, True]
    # A little narrower and one item drops off each end, never the neighbours.
    plain = Text.from_markup(panel_split.nav_switcher(items, 70).markup).plain
    assert plain.startswith("‹") and plain.endswith("›")
    assert [label in plain for label in labels] == [False, True, True, True, False]


def test_switcher_escapes_labels() -> None:
    items = (NavItem("x", "[bold]odd[/]", active=True), NavItem("y", "plain [1]"))
    plain = Text.from_markup(panel_split.nav_switcher(items, 80).markup).plain

    assert "[bold]odd[/]" in plain and "plain [1]" in plain


def test_step_nav_wraps_from_the_active_item() -> None:
    assert panel_split.step_nav(ITEMS, 1) == "three"
    assert panel_split.step_nav(ITEMS, -2) == "four"
    assert panel_split.step_nav(ITEMS, 5, wrap=False) == "four"
    assert panel_split.step_nav((), 1) is None


def test_aside_renders_its_title_then_its_body() -> None:
    aside = Aside("Guardrail", Text("Turns on the guardrail."))
    console = Console(width=40, record=True, color_system=None)
    console.print(aside)

    assert console.export_text().splitlines()[:2] == ["Guardrail", "Turns on the guardrail."]
    assert panel_split.split_aside(aside) == ("Guardrail", aside.body)
    assert panel_split.split_aside("plain") == ("", "plain")


async def test_a_panel_with_nav_and_aside_lays_out_and_takes_clicks(tmp_path, monkeypatch) -> None:
    from defenseclaw.tui.widgets.panel_split import PanelNav
    from fixtures import screen_text, snapshot_app
    from textual.widgets import DataTable, Static

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    app = snapshot_app(tmp_path)
    state = {"active": "two", "chosen": []}

    def nav(panel: str) -> tuple[NavItem, ...]:
        if panel != "skills":
            return ()
        return tuple(NavItem(i.key, i.label, i.badge, active=i.key == state["active"]) for i in ITEMS)

    def aside(panel: str):
        return Aside("Selected view", Text(f"Showing {state['active']}")) if panel == "skills" else None

    def select(panel: str, key: str) -> bool:
        state["chosen"].append((panel, key))
        state["active"] = key
        return True

    app._panel_nav = nav  # noqa: SLF001
    app._panel_aside = aside  # noqa: SLF001
    app._select_panel_nav = select  # noqa: SLF001
    async with app.run_test(size=(160, 45)) as pilot:
        app.action_switch_panel("skills")
        await pilot.pause()
        await pilot.pause()
        nav_widget = app.query_one("#panel-nav", PanelNav)
        aside_widget = app.query_one("#panel-aside", Static)
        table = app.query_one("#panel-table", DataTable)
        assert nav_widget.display and aside_widget.display
        assert nav_widget.region.right <= table.region.x < table.region.right <= aside_widget.region.x
        assert table.border_title == "Guardrail & scanning"
        screen = screen_text(app)
        assert "▸ Guardrail" in screen and "Selected view" in screen and "Showing two" in screen

        # Content row 2 of the nav is the third item.
        await pilot.click("#panel-nav", offset=(4, 1 + 2))
        await pilot.pause()
        assert state["chosen"] == [("skills", "three")]
        assert "▸ Alerts &" in screen_text(app)

        # Narrower than the aside threshold: the aside moves below the table.
        await pilot.resize_terminal(110, 45)
        await pilot.pause()
        await pilot.pause()
        detail = app.query_one("#detail-panel")
        assert not aside_widget.display
        assert detail.display and detail.border_title == "Selected view"
        assert "Showing three" in screen_text(app)
