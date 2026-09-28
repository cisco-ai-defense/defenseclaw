# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup text entry goes through FieldEditorScreen and keeps the exact text."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from defenseclaw.tui.panels.setup import SetupWizard, wizard_field_value
from defenseclaw.tui.screens.field_editor import FieldEditorScreen
from textual.app import App

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402

TYPED = "Hello World Q_KEY"


class _Harness(App[None]):
    def __init__(self, screen: FieldEditorScreen) -> None:
        super().__init__()
        self._editor = screen
        self.results: list[str | None] = []

    def on_mount(self) -> None:
        self.push_screen(self._editor, self.results.append)


async def test_editor_commits_exact_text_and_cancel_returns_none() -> None:
    def no_digits(value: str) -> str | None:
        return "no digits" if any(ch.isdigit() for ch in value) else None

    app = _Harness(FieldEditorScreen("Name", value="", validator=no_digits))
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("1", "enter")
        assert app.results == []  # the validator kept it open
        assert app._editor.error == "no digits"
        await pilot.press("backspace", *TYPED, "enter")
        await pilot.pause()
    assert app.results == [TYPED]

    cancelled = _Harness(FieldEditorScreen("Name", value="keep"))
    async with cancelled.run_test(size=(80, 24)) as pilot:
        await pilot.press("x", "escape")
        await pilot.pause()
    assert cancelled.results == [None]


async def test_typing_into_a_wizard_text_field_keeps_the_exact_value(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("setup")
        await pilot.pause()
        app.setup_model.open_wizard_form(SetupWizard.CREDENTIALS)
        fields: list[Any] = app.setup_model.form_fields
        app.setup_model.form_cursor = next(i for i, field in enumerate(fields) if field.label == "Env Name")
        app._render_chrome()
        await pilot.pause()

        # The first key opens the text box seeded with it; the rest (capitals,
        # space, q, underscore) must reach the box unchanged.
        await pilot.press(*TYPED)
        await pilot.pause()
        assert isinstance(app.screen, FieldEditorScreen)
        await pilot.press("enter")
        await pilot.pause()

        assert app.setup_model.form_active is True
        assert wizard_field_value(app.setup_model.form_fields, "Env Name", raw=True) == TYPED
