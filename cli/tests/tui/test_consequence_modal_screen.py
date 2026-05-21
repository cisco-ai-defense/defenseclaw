# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Generic consequence modal screen tests."""

from __future__ import annotations

import pytest
from defenseclaw.tui.screens.consequence import (
    CommandSpec,
    ConsequenceAction,
    ConsequenceModalModel,
    ConsequenceModalScreen,
)
from textual.app import App, ComposeResult
from textual.widgets import Static


class ConsequenceHarness(App[ConsequenceAction | None]):
    def __init__(self, model: ConsequenceModalModel) -> None:
        super().__init__()
        self.model = model
        self.result: ConsequenceAction | None = None

    def compose(self) -> ComposeResult:
        yield Static("consequence harness")

    def on_mount(self) -> None:
        self.push_screen(ConsequenceModalScreen(self.model), self._set_result)

    def _set_result(self, result: ConsequenceAction | None) -> None:
        self.result = result


def _model() -> ConsequenceModalModel:
    return ConsequenceModalModel(
        title="Dangerous action",
        summary="Review the destination state before continuing.",
        details=("First consequence.", "Second consequence."),
        consequence="This is the confirmation step.",
        actions=(
            ConsequenceAction(
                action_id="preview",
                hotkey="p",
                label="Preview",
                description="Dry run only.",
                command=CommandSpec("defenseclaw", ("uninstall", "--dry-run"), "uninstall dry-run"),
            ),
            ConsequenceAction(
                action_id="run",
                hotkey="u",
                label="Run",
                description="Mutates local state.",
                command=CommandSpec("defenseclaw", ("uninstall", "--yes"), "uninstall --yes"),
                danger=True,
            ),
        ),
        default_action_id="preview",
    )


def test_consequence_model_resolves_default_and_hotkey() -> None:
    model = _model()

    assert model.default_action().action_id == "preview"
    assert model.action_for_hotkey("U").action_id == "run"
    assert model.action_for_hotkey("x") is None


def test_consequence_action_display_label_escapes_hotkey_brackets() -> None:
    """Hotkey labels must escape the opening bracket so Rich renders
    ``[p] Preview`` as literal text instead of treating ``p`` as a
    style name (which raises ``MissingStyle`` and crashes the modal).
    """

    action = ConsequenceAction(
        action_id="preview", hotkey="p", label="Preview", description="Dry run only."
    )
    assert action.display_label.startswith("\\[p]")
    assert "Preview" in action.display_label

    bare = ConsequenceAction(action_id="cancel", label="Cancel", description="")
    assert bare.display_label == "Cancel"


@pytest.mark.asyncio
async def test_consequence_modal_enter_confirms_default_action() -> None:
    app = ConsequenceHarness(_model())

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("enter")
        await pilot.pause()

        assert app.result is not None
        assert app.result.action_id == "preview"
        assert app.result.command is not None
        assert app.result.command.args == ("uninstall", "--dry-run")


@pytest.mark.asyncio
async def test_consequence_modal_hotkey_selects_then_enter_confirms() -> None:
    app = ConsequenceHarness(_model())

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("u")
        await pilot.press("enter")
        await pilot.pause()

        assert app.result is not None
        assert app.result.action_id == "run"
        assert app.result.command is not None
        assert app.result.command.args == ("uninstall", "--yes")


@pytest.mark.asyncio
async def test_consequence_modal_click_confirms_selected_row() -> None:
    app = ConsequenceHarness(_model())

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.click("#consequence-action-1")
        await pilot.pause()

        assert app.result is not None
        assert app.result.action_id == "run"


@pytest.mark.asyncio
async def test_consequence_modal_escape_cancels() -> None:
    app = ConsequenceHarness(_model())

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("escape")
        await pilot.pause()

        assert app.result is None
