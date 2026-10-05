# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""80x24 smoke tests for the whole TUI, driven through Textual's Pilot.

These are deliberately few and shallow: every panel renders its primary
content on a small terminal, every cheap modal opens and closes, the global
keys route, and one command journey reaches the executor with the right argv.
Behaviour belongs in the per-panel model/service unit tests.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from defenseclaw.tui.app import CASE_SENSITIVE_PANEL_KEYS, PANELS, DefenseClawTUI
from defenseclaw.tui.executor import CommandEvent
from defenseclaw.tui.screens.command_preview import CommandPreviewScreen
from defenseclaw.tui.screens.mode_picker import ModePickerScreen
from defenseclaw.tui.screens.panel_jumper import PanelJumperScreen
from defenseclaw.tui.screens.theme_picker import ThemePickerScreen
from defenseclaw.tui.widgets.action_menu import ActionMenuScreen
from textual.widgets import DataTable, Input

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixtures  # noqa: E402

SIZE = (80, 24)
# Rows reserved at the bottom of the screen for the hint bar and status line.
FOOTER_ROWS = 3

# Panels whose primary content is below the fold at 80x24 today. The owning
# track removes the entry when it fixes the layout (strict xfail fails loudly
# once the panel passes).
KNOWN_BELOW_FOLD: dict[str, str] = {}


def _panel_params() -> list[object]:
    params: list[object] = []
    for name, key, _label in PANELS:
        reason = KNOWN_BELOW_FOLD.get(name)
        marks = [pytest.mark.xfail(strict=True, reason=reason)] if reason else []
        params.append(pytest.param(name, key, id=name, marks=marks))
    return params


def _visible_text(app: DefenseClawTUI, top: int, height: int) -> str:
    lines = fixtures.screen_text(app).splitlines()
    return "\n".join(lines[top : top + height])


class _RecordingRunner:
    """Stands in for ``CommandExecutor.run``: records argv, never spawns."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...], dict[str, object]]] = []

    async def __call__(self, binary: str, args: tuple[str, ...], **kwargs: object) -> AsyncIterator[CommandEvent]:
        self.calls.append((binary, tuple(args), kwargs))
        yield CommandEvent("start", text=" ".join((binary, *args)))
        yield CommandEvent("done", exit_code=0, duration=0.01)


async def _settle(pilot, app: DefenseClawTUI) -> None:
    await pilot.pause()
    await app.workers.wait_for_complete()
    await pilot.pause()


async def _wait_for_panel_render(pilot, app: DefenseClawTUI, panel: str) -> None:
    """Wait for the content render a panel switch defers until after a refresh.

    One pause is not always enough: on Windows the refresh can land after it,
    leaving the switch's placeholder frame (a blank Activity body) on screen.
    """
    deadline = asyncio.get_running_loop().time() + 8.0
    while (
        panel in app._panel_render_queued  # noqa: SLF001
        or panel in app._panel_render_running  # noqa: SLF001
        or panel in app._panel_render_pending  # noqa: SLF001
    ):
        assert asyncio.get_running_loop().time() < deadline, f"{panel}: its content never rendered"
        await pilot.pause()
    await pilot.pause()


@pytest.mark.parametrize(("name", "key"), _panel_params())
async def test_panel_renders_primary_content_at_80x24(tmp_path, name: str, key: str) -> None:
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        if name != app.active_panel:
            await pilot.press(key.lower())
            await pilot.pause()
        if app.active_panel != name:
            app.action_switch_panel(name)
            await pilot.pause()
        assert app.active_panel == name
        assert len(app.screen_stack) == 1
        await _wait_for_panel_render(pilot, app, name)

        fold = app.size.height - FOOTER_ROWS
        table = app.query_one("#panel-table", DataTable)
        if table.row_count > 0:
            assert table.display, f"{name}: table has rows but is hidden"
            assert table.region.height > 0, f"{name}: table has no height"
            assert table.region.y < fold, f"{name}: first table row is below the fold (y={table.region.y})"
        else:
            body = app.query_one("#body")
            assert body.region.height > 0, f"{name}: body has no height"
            assert body.region.y < fold, f"{name}: body starts below the fold (y={body.region.y})"
            visible_rows = min(body.region.height, fold - body.region.y)
            assert _visible_text(app, body.region.y, visible_rows).strip(), f"{name}: body is blank"


# --- modals ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("panel", "keys", "screen_type"),
    [
        pytest.param(
            "overview",
            ("ctrl+p",),
            PanelJumperScreen,
            id="panel-jumper",
        ),
        pytest.param("overview", ("ctrl+backslash",), ThemePickerScreen, id="theme-picker"),
        pytest.param("overview", ("m",), ModePickerScreen, id="mode-picker"),
        pytest.param("skills", ("o",), ActionMenuScreen, id="skills-action-menu"),
    ],
)
async def test_modal_opens_and_escape_dismisses(tmp_path, panel: str, keys: tuple[str, ...], screen_type) -> None:
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        app.action_switch_panel(panel)
        await pilot.pause()
        await pilot.press(*keys)
        await pilot.pause()
        assert isinstance(app.screen, screen_type)
        await pilot.press("escape")
        await _settle(pilot, app)
        assert len(app.screen_stack) == 1
        assert app.active_panel == panel


async def test_alert_enter_opens_detail_and_escape_closes(tmp_path) -> None:
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.press("2")
        await pilot.pause()
        detail = app.query_one("#detail-panel")
        assert not detail.display or detail.has_class("hidden")
        await pilot.press("enter")
        await pilot.pause()
        opened_modal = len(app.screen_stack) > 1
        opened_pane = detail.display and not detail.has_class("hidden")
        assert opened_modal or opened_pane
        await pilot.press("escape")
        await _settle(pilot, app)
        assert len(app.screen_stack) == 1
        assert app.active_panel == "alerts"


async def test_help_overlay_toggles(tmp_path) -> None:
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.press("?")
        await pilot.pause()
        assert app.help_open
        await pilot.press("?")
        await pilot.pause()
        assert not app.help_open
        assert len(app.screen_stack) == 1


async def test_command_drawer_opens_and_escape_closes(tmp_path) -> None:
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        command = app.query_one("#command-input", Input)
        await pilot.press(":")
        await pilot.pause()
        assert command.has_class("open")
        assert command.display
        assert app.focused is command
        await pilot.press("escape")
        await pilot.pause()
        assert not command.has_class("open")
        assert app.focused is not command
        assert len(app.screen_stack) == 1


# --- key routing ------------------------------------------------------------


async def test_every_panel_shortcut_switches_from_overview(tmp_path) -> None:
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        for name, key, _label in PANELS:
            if name == "overview":
                continue
            # Return without a key: several panels use digits for their own
            # chips, which is not what this test is about.
            app.action_switch_panel("overview")
            await pilot.pause()
            assert app.active_panel == "overview"
            # ``T`` (Tools) is case-sensitive: lowercase ``t`` is panel-local.
            await pilot.press(key if key in CASE_SENSITIVE_PANEL_KEYS else key.lower())
            await pilot.pause()
            assert app.active_panel == name, f"shortcut {key!r} did not open {name}"


async def test_shift_p_opens_policies_where_p_is_a_panel_key(tmp_path) -> None:
    # Runtime keeps a local ``p`` (planes strip); Shift+P must still reach the
    # Policies shortcut instead of being folded into ``p``.
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        app.action_switch_panel("runtime")
        await pilot.pause()
        await pilot.press("P")
        await pilot.pause()
        assert app.active_panel == "policies"


async def test_tab_moves_to_next_panel(tmp_path) -> None:
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        # The fake-data app runs OpenClaw, so no panel is connector-hidden.
        names = [name for name, _key, _label in PANELS]
        start = names.index(app.active_panel)
        await pilot.press("tab")
        await pilot.pause()
        assert app.active_panel == names[(start + 1) % len(names)]


@pytest.mark.parametrize("key", ["q", "t"])
async def test_q_and_t_leave_the_app_where_it_was(tmp_path, key: str) -> None:
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        before = app.active_panel
        await pilot.press(key)
        await pilot.pause()
        assert app.is_running
        assert app.return_code is None
        assert app.active_panel == before
        assert len(app.screen_stack) == 1


# --- journeys ---------------------------------------------------------------


async def _type_command(pilot, text: str) -> None:
    await pilot.press(":")
    await pilot.pause()
    await pilot.press(*text)
    await pilot.press("enter")
    await pilot.pause()


async def test_mutating_palette_command_previews_then_runs_argv(tmp_path) -> None:
    app = fixtures.snapshot_app(tmp_path)
    runner = _RecordingRunner()
    app.executor.run = runner  # type: ignore[method-assign]
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await _type_command(pilot, "skill block alpha")
        assert isinstance(app.screen, CommandPreviewScreen)
        assert runner.calls == []
        await pilot.press("enter")
        await _settle(pilot, app)
        assert len(app.screen_stack) == 1
        assert [(binary, args) for binary, args, _kw in runner.calls] == [("defenseclaw", ("skill", "block", "alpha"))]


async def test_read_only_palette_command_runs_without_preview(tmp_path) -> None:
    app = fixtures.snapshot_app(tmp_path)
    runner = _RecordingRunner()
    app.executor.run = runner  # type: ignore[method-assign]
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await _type_command(pilot, "policy list")
        await _settle(pilot, app)
        assert len(app.screen_stack) == 1
        assert [(binary, args) for binary, args, _kw in runner.calls] == [("defenseclaw", ("policy", "list"))]


@pytest.mark.parametrize("close", ["escape", "question_mark", "q"])
async def test_closing_help_returns_to_the_panel_where_it_was(tmp_path, close: str) -> None:
    from textual.containers import VerticalScroll

    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("question_mark")
        await pilot.press("pagedown")
        await pilot.pause()
        await pilot.press(close)
        await pilot.pause()
        await pilot.pause()
        assert app.help_open is False
        assert app.query_one("#body-scroll", VerticalScroll).scroll_y == 0
