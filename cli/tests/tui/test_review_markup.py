# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Names and details from scanned data show literally, never as Rich markup."""

from __future__ import annotations

import pytest
from defenseclaw.tui.app import DefenseClawTUI, _detail_pairs_markup
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.services.catalog_state import MCPRow, SkillRow, catalog_detail_text
from defenseclaw.tui.widgets.action_menu import ActionMenuScreen, MenuAction
from rich.text import Text
from textual.app import App

HOSTILE = "[red]x[/] [/] [bold]b"


def _styled(markup: str) -> Text:
    """What the detail pane draws; a fallback to plain text means the markup broke."""

    rendered = DefenseClawTUI._safe_body_renderable(markup)
    assert rendered.spans, "detail fell back to unstyled text"
    return rendered


def test_alert_detail_shows_hostile_target_and_details_literally() -> None:
    model = AlertsPanelModel()
    model.set_events([AlertEvent(id="a1", severity="HIGH", action="scan", target=HOSTILE, details=HOSTILE)])
    model.set_severity_filter("")
    model.toggle_expand_or_detail()

    plain = _styled(model.detail_text()).plain

    assert f"Target: {HOSTILE}" in plain
    assert f"Details: {HOSTILE}" in plain


def test_detail_pairs_escape_title_keys_and_values() -> None:
    plain = _styled(_detail_pairs_markup("[/]source", [("Target", HOSTILE)])).plain

    assert plain.splitlines() == ["[/]source", f"Target: {HOSTILE}"]


@pytest.mark.parametrize(
    "row",
    [
        SkillRow(name=HOSTILE, status="active", description=HOSTILE, source=HOSTILE),
        MCPRow(name=HOSTILE, status="blocked", transport="stdio", command=HOSTILE),
    ],
)
def test_catalog_detail_keeps_styles_and_shows_names_literally(row: object) -> None:
    plain = _styled(catalog_detail_text(row)).plain

    assert HOSTILE in plain
    # The key legend reads "[s] Scan", not "Scan" with the "[s]" eaten.
    assert "[s] Scan" in plain


async def test_action_menu_with_a_markup_like_name_opens_instead_of_crashing() -> None:
    class Harness(App[None]):
        def on_mount(self) -> None:
            self.push_screen(ActionMenuScreen("[/] actions", (MenuAction("scan", "Scan"),), subtitle="[/]"))

    app = Harness()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, ActionMenuScreen)


async def test_mcp_form_shows_a_markup_like_validation_error_instead_of_crashing() -> None:
    from defenseclaw.tui.screens.mcp_set_form import MCPSetFormScreen
    from textual.widgets import Input, Static

    class Harness(App[None]):
        def on_mount(self) -> None:
            self.push_screen(MCPSetFormScreen(initial_name="srv"))

    app = Harness()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.screen.query_one("#mcp-command", Input).value = "npx"
        app.screen.query_one("#mcp-env", Input).value = "[/]"
        await pilot.press("ctrl+s")
        await pilot.pause()
        status = app.screen.query_one("#mcp-set-status", Static)
        assert isinstance(app.screen, MCPSetFormScreen)
        assert "[/]" in str(status.render())
