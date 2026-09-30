# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""RulePackPickerScreen: scope → pack → validation gate."""

from __future__ import annotations

import pytest
from defenseclaw.tui.screens.rule_pack_picker import PackOption, PackScope, RulePackChoice, RulePackPickerScreen
from defenseclaw.tui.services.policy_state import PackValidation
from textual.app import App, ComposeResult
from textual.widgets import Static

_UNSET = object()

SCOPES = (PackScope("", "Global", "default"), PackScope("codex", "codex", "default"))
OPTIONS = (
    PackOption("default", "default", "/packs/default", True),
    PackOption("strict", "strict", "/packs/strict", True),
    PackOption("mine", "/packs/mine", "/packs/mine", False),
)


class PickerHarness(App[None]):
    def __init__(self, outcomes: dict[str, PackValidation], selected_scope: str = "") -> None:
        super().__init__()
        self.outcomes = outcomes
        self.selected_scope = selected_scope
        self.validated: list[str] = []
        self.result: object = _UNSET

    def compose(self) -> ComposeResult:
        yield Static("rule-pack harness")

    async def validate(self, path: str) -> PackValidation:
        self.validated.append(path)
        return self.outcomes[path]

    def on_mount(self) -> None:
        screen = RulePackPickerScreen(SCOPES, OPTIONS, validate=self.validate, selected_scope=self.selected_scope)
        self.push_screen(screen, self._done)

    def _done(self, result: RulePackChoice | None) -> None:
        self.result = result


@pytest.mark.asyncio
async def test_connector_scope_then_preset_validates_and_returns_the_choice() -> None:
    valid = PackValidation("valid", rule_count=4, enabled_rule_count=4, rule_file_count=1)
    app = PickerHarness({"/packs/strict": valid}, selected_scope="codex")
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("enter")  # keep the preselected codex scope
        await pilot.press("2", "enter")  # strict
        await pilot.pause()
    assert app.validated == ["/packs/strict"]
    assert isinstance(app.result, RulePackChoice)
    assert (app.result.connector, app.result.pack, app.result.validation.state) == ("codex", "strict", "valid")


@pytest.mark.asyncio
async def test_invalid_pack_blocks_and_unavailable_validator_allows_presets_only() -> None:
    app = PickerHarness(
        {
            "/packs/mine": PackValidation("unavailable", "no gateway"),
            "/packs/default": PackValidation("unavailable", "no gateway"),
            "/packs/strict": PackValidation("invalid", "bad regex"),
        }
    )
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("enter")  # global
        await pilot.press("2", "enter")  # strict: invalid, stays
        await pilot.pause()
        assert isinstance(app.screen, RulePackPickerScreen)
        await pilot.press("3", "enter")  # custom pack, validator unavailable: refused
        await pilot.pause()
        assert isinstance(app.screen, RulePackPickerScreen)
        await pilot.press("1", "enter")  # preset with the validator unavailable: allowed
        await pilot.pause()
    assert app.validated == ["/packs/strict", "/packs/mine", "/packs/default"]
    assert isinstance(app.result, RulePackChoice)
    assert (app.result.connector, app.result.pack, app.result.validation.state) == ("", "default", "unavailable")
