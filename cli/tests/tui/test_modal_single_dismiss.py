# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""A quick second Enter must not close a modal twice (rel-1-0-6:GAP-0479)."""

from __future__ import annotations

import importlib
import pkgutil
import sys
from pathlib import Path

import defenseclaw.tui.screens as screens_pkg
from defenseclaw.tui.modal import GuardedModalScreen
from defenseclaw.tui.widgets.action_menu import ActionMenuScreen, MenuAction
from textual import events
from textual.screen import ModalScreen

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixtures  # noqa: E402

SIZE = (80, 24)


async def test_double_enter_in_an_action_menu_chooses_once(tmp_path) -> None:
    app = fixtures.snapshot_app(tmp_path)
    chosen: list[str | None] = []
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        app.push_screen(
            ActionMenuScreen("Filter by connector", (MenuAction("a", "All"), MenuAction("b", "Codex"))),
            chosen.append,
        )
        await pilot.pause()
        assert isinstance(app.screen, ActionMenuScreen)
        # Both Enter keys arrive before the first dismiss pops the screen.
        app.screen.post_message(events.Key("enter", None))
        app.screen.post_message(events.Key("enter", None))
        await pilot.pause()
        await pilot.pause()
        assert app.is_running
        assert chosen == ["a"]
        assert len(app.screen_stack) == 1


def test_every_tui_modal_closes_at_most_once() -> None:
    for module in pkgutil.iter_modules(screens_pkg.__path__):
        importlib.import_module(f"{screens_pkg.__name__}.{module.name}")
    importlib.import_module("defenseclaw.tui.widgets.action_menu")
    importlib.import_module("defenseclaw.tui.policy_panel")

    def subclasses(cls: type) -> set[type]:
        found: set[type] = set()
        for sub in cls.__subclasses__():
            found.add(sub)
            found |= subclasses(sub)
        return found

    unguarded = [
        f"{cls.__module__}.{cls.__name__}"
        for cls in subclasses(ModalScreen)
        if cls.__module__.startswith("defenseclaw.tui") and not issubclass(cls, GuardedModalScreen)
    ]
    assert unguarded == []
