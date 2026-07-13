# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Config diff modal screen tests."""

from __future__ import annotations

import pytest
from defenseclaw.tui.screens.config_diff import ConfigDiffModalModel, ConfigDiffResult, ConfigDiffScreen
from defenseclaw.tui.services.setup_state import ConfigDiffEntry
from textual.app import App, ComposeResult
from textual.widgets import Static


class ConfigDiffHarness(App[ConfigDiffResult | None]):
    def __init__(self, model: ConfigDiffModalModel) -> None:
        super().__init__()
        self.model = model
        self.result: ConfigDiffResult | None = None

    def compose(self) -> ComposeResult:
        yield Static("config diff harness")

    def on_mount(self) -> None:
        self.push_screen(ConfigDiffScreen(self.model), self._set_result)

    def _set_result(self, result: ConfigDiffResult | None) -> None:
        self.result = result


def _diff_entries() -> tuple[ConfigDiffEntry, ...]:
    return (
        ConfigDiffEntry("gateway.port", "8080", "9090"),
        ConfigDiffEntry("llm.api_key", "****wxyz", "****1234", True),
    )


def test_config_diff_model_renders_mask_marker_and_no_pending_state() -> None:
    model = ConfigDiffModalModel(_diff_entries())
    preview = model.preview_text()

    assert "Review Config Changes" not in preview
    assert "gateway.port" in preview
    assert "before: 8080" in preview
    assert "llm.api_key (masked)" in preview
    assert "****1234" in preview
    assert ConfigDiffModalModel(()).preview_text() == "No pending changes."


def test_config_diff_model_truncates_and_reports_extra_rows() -> None:
    entries = tuple(ConfigDiffEntry(f"field.{index}", "before-value", "after-value") for index in range(3))
    preview = ConfigDiffModalModel(entries).preview_text(max_entries=2, value_width=8)

    assert "before: before-" in preview
    assert "... 1 more changes" in preview


@pytest.mark.asyncio
async def test_config_diff_screen_renders_all_entries_in_scroll() -> None:
    # With >8 changes the screen must render every entry (no "... N more"
    # truncation) inside a bounded VerticalScroll the operator can scroll.
    from textual.containers import VerticalScroll
    from textual.widgets import Static as _Static

    entries = tuple(ConfigDiffEntry(f"field.{index}", "before", "after") for index in range(12))
    app = ConfigDiffHarness(ConfigDiffModalModel(entries))

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.screen.query_one("#config-diff-scroll", VerticalScroll)  # exists
        text = str(app.screen.query_one("#config-diff-preview", _Static).content)

    assert "more changes" not in text
    assert "field.0" in text
    assert "field.11" in text  # the 12th change is present, not truncated


@pytest.mark.asyncio
async def test_config_diff_enter_returns_save_result() -> None:
    app = ConfigDiffHarness(ConfigDiffModalModel(_diff_entries()))

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("enter")
        await pilot.pause()

        assert app.result == ConfigDiffResult(save=True, queue_restart_reason="config saved from Textual TUI")


@pytest.mark.asyncio
async def test_config_diff_save_button_returns_save_result() -> None:
    app = ConfigDiffHarness(ConfigDiffModalModel(_diff_entries()))

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.click("#config-diff-save")
        await pilot.pause()

        assert app.result is not None
        assert app.result.save is True


@pytest.mark.asyncio
async def test_config_diff_cancel_button_dismisses_without_save() -> None:
    app = ConfigDiffHarness(ConfigDiffModalModel(_diff_entries()))

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.click("#config-diff-cancel")
        await pilot.pause()

        assert app.result is None
