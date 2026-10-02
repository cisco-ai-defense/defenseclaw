# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Confirmation modals fit an 80x24 terminal."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from defenseclaw.tui.screens.uninstall import UninstallScreen
from textual.app import App

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import screen_text  # noqa: E402


async def test_uninstall_wipe_shows_its_second_confirmation_at_80x24() -> None:
    results: list[object] = []

    class Harness(App[None]):
        def on_mount(self) -> None:
            self.push_screen(UninstallScreen(), results.append)

    app = Harness()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("a", "enter")
        await pilot.pause()
        text = screen_text(app)
        # The armed hint and the row being confirmed (with what it deletes)
        # are both visible, and the dialog's right border is on screen.
        assert "press enter / click again to confirm" in text
        assert "Uninstall and wipe data" in text and "deletes ~/.defenseclaw" in text
        assert all(len(line.rstrip()) <= 80 for line in text.splitlines())
        assert any(line.rstrip().endswith("╮") for line in text.splitlines()[:3])
    assert results == []


async def test_all_three_toasts_are_visible() -> None:
    from defenseclaw.tui.widgets.toasts import ToastManager, ToastStack

    class Harness(App[None]):
        def compose(self):
            yield ToastStack(id="toasts")

    app = Harness()
    async with app.run_test(size=(80, 24)) as pilot:
        manager = ToastManager()
        for message in ("first", "second", "third"):
            manager.push("info", message)
        app.query_one(ToastStack).render_items(manager.items)
        await pilot.pause()
        text = screen_text(app)
        assert all(message in text for message in ("first", "second", "third"))


def _config_diff_screen():  # type: ignore[no-untyped-def]
    from defenseclaw.tui.screens.config_diff import ConfigDiffScreen
    from defenseclaw.tui.services.setup_state import ConfigDiffEntry

    return ConfigDiffScreen([ConfigDiffEntry(f"guardrail.key_{i}", "a", "b") for i in range(12)])


def _trusted_paths_screen():  # type: ignore[no-untyped-def]
    from defenseclaw.tui.screens.trusted_paths_editor import TrustedPathRow, TrustedPathsEditorScreen

    return TrustedPathsEditorScreen((TrustedPathRow("/usr/bin", "default", "ok", False),))


def _webhooks_screen():  # type: ignore[no-untyped-def]
    from defenseclaw.tui.screens.setup_resource_editor import SetupResourceEditorScreen

    return SetupResourceEditorScreen("webhooks", ())


@pytest.mark.parametrize(
    ("make", "buttons"),
    [
        (_config_diff_screen, "#config-diff-buttons"),
        (_trusted_paths_screen, "#trusted-editor-buttons"),
        (_webhooks_screen, "#resource-editor-buttons"),
    ],
)
async def test_setup_dialogs_keep_their_buttons_on_an_80x24_screen(make, buttons: str, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from defenseclaw.tui.screens import trusted_paths_editor

    monkeypatch.setattr(trusted_paths_editor, "untrusted_connector_dirs", lambda _data_dir=None: [])

    class Harness(App[None]):
        def on_mount(self) -> None:
            self.push_screen(make())

    app = Harness()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        regions = [button.region for button in app.screen.query(f"{buttons} Button")]
        assert regions
        assert all(r.height > 0 and r.right <= 80 and r.bottom <= 24 for r in regions)
