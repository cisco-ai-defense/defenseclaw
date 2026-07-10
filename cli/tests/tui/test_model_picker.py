# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Searchable model picker modal tests."""

from __future__ import annotations

import pytest
from defenseclaw.tui.screens.model_picker import (
    ModelPickerScreen,
    filter_models,
    picker_rows,
)
from textual.app import App, ComposeResult
from textual.widgets import Input, Static

_MODELS = ("gpt-4o", "gpt-4o-mini", "o3")


class ModelPickerHarness(App[str | None]):
    def __init__(self, models: tuple[str, ...] = _MODELS, *, current: str = "") -> None:
        super().__init__()
        self.models = models
        self.current = current
        self.result: str | None = "__UNSET__"

    def compose(self) -> ComposeResult:
        yield Static("model picker harness")

    def on_mount(self) -> None:
        self.push_screen(
            ModelPickerScreen(self.models, current=self.current, provider="openai"),
            self._set_result,
        )

    def _set_result(self, result: str | None) -> None:
        self.result = result


def test_filter_and_picker_rows_freeform() -> None:
    assert filter_models("", _MODELS) == list(_MODELS)
    assert filter_models("mini", _MODELS) == ["gpt-4o-mini"]
    # An id the catalog doesn't contain is prepended as a free-form row.
    assert picker_rows("gpt[4", _MODELS)[0] == "gpt[4"
    # An exact catalog match is not duplicated as a free-form row.
    assert picker_rows("o3", _MODELS) == ["o3"]


@pytest.mark.asyncio
async def test_model_picker_bracket_in_freeform_does_not_crash_render() -> None:
    # A model id containing ``[`` must be Rich-escaped before it is rendered
    # into the markup=True list, otherwise the render crashes on the bracket.
    app = ModelPickerHarness()

    async with app.run_test(size=(80, 30)) as pilot:
        await pilot.pause()
        app.screen.query_one(Input).value = "gpt[4"
        await pilot.pause()  # forces a re-render; would raise if unescaped

        await pilot.press("enter")
        await pilot.pause()

    # No exception, and Enter selected the verbatim typed id.
    assert app.result == "gpt[4"


@pytest.mark.asyncio
async def test_model_picker_enter_selects_catalog_model() -> None:
    app = ModelPickerHarness(current="gpt-4o-mini")

    async with app.run_test(size=(80, 30)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

    assert app.result == "gpt-4o-mini"
