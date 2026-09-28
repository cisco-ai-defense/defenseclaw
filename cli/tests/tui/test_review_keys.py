# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Search keys never fall through to row actions, and cursors stay visible."""

from __future__ import annotations

import sys
from pathlib import Path

from defenseclaw.tui.services.runtime_state import RuntimePanelAction, RuntimePanelModel

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402

_SNAPSHOT = {
    "enabled": True,
    "findings": [
        {"finding_id": "f1", "pid": 42, "process": "python", "severity": "high", "score": 80},
        {"finding_id": "f2", "pid": 43, "process": "node", "severity": "low", "score": 10},
    ],
}


def test_runtime_filter_takes_typed_letters_instead_of_running_commands() -> None:
    model = RuntimePanelModel()
    model.set_snapshot(_SNAPSHOT)

    model.handle_key("/")
    actions = [model.handle_key(key) for key in ("n", "o", "d", "e")]

    assert RuntimePanelAction.SCAN not in actions and RuntimePanelAction.ENABLE not in actions
    assert model.filter_text == "node"
    assert [row.process for row in model.filtered] == ["node"]
    model.handle_key("enter")
    assert not model.filtering and model.filter_text == "node"
    model.handle_key("escape")
    assert model.filter_text == "" and len(model.filtered) == 2


def test_runtime_row_moves_ask_for_a_redraw() -> None:
    model = RuntimePanelModel()
    model.set_snapshot(_SNAPSHOT)

    assert model.handle_key("j") is RuntimePanelAction.MOVE
    assert model.cursor == 1


async def test_slash_on_a_catalog_types_into_its_filter(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    ran: list[object] = []
    app._confirm_and_run_intent = lambda intent: ran.append(intent)  # type: ignore[method-assign]
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel("skills")
        await pilot.pause()
        await pilot.press("slash", "a", "l", "enter")
        await pilot.pause()
        assert app.skills_model.filter_text == "al"
        assert [row.name for row in app.skills_model.filtered] == ["alpha"]
        assert app.focused is app.query_one("#panel-table")
    assert ran == []


def test_registries_move_with_j_and_k(tmp_path) -> None:
    from defenseclaw.config import RegistrySource
    from defenseclaw.tui.panels.registries import RegistriesPanelModel

    model = RegistriesPanelModel(
        data_dir=tmp_path,
        sources=[
            RegistrySource(id="one", kind="http_yaml", content="skill", enabled=True),
            RegistrySource(id="two", kind="http_yaml", content="skill", enabled=True),
        ],
    )

    assert model.handle_key("j").handled
    assert model.selected_source().id == "two"
    assert model.handle_key("k").handled
    assert model.selected_source().id == "one"


async def test_help_sheet_scrolls_to_its_end_at_80x24(tmp_path) -> None:
    from fixtures import screen_text

    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel("sandboxes")
        await pilot.pause()
        await pilot.press("question_mark")
        await pilot.pause()
        assert "Press ? again to close" not in screen_text(app)
        await pilot.press("end")
        await pilot.pause()
        assert "Press ? again to close" in screen_text(app)


async def test_shift_d_runs_the_background_doctor_on_alerts(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    calls: list[str] = []
    app.action_run_diagnose = lambda: calls.append("diagnose")  # type: ignore[method-assign]
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel("alerts")
        await pilot.pause()
        await pilot.press("D")
        await pilot.pause()
        assert calls == ["diagnose"]
        assert len(app.screen_stack) == 1


async def test_a_failed_catalog_load_replaces_the_loading_status(tmp_path, monkeypatch) -> None:
    import defenseclaw.tui.app as app_module

    async def failing(binary, args, **_kwargs):
        return 1, b"", b"skill list exploded"

    monkeypatch.setattr(app_module, "_communicate_captured", failing)
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await app._load_catalog_model("skills")
        assert "Loading" not in app.status_text
        assert "skill list exploded" in app.status_text


async def test_agent_commands_reload_ai_discovery_or_runtime(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    loads: list[str] = []

    async def ai() -> None:
        loads.append("ai")

    async def runtime() -> None:
        loads.append("runtime")

    app._load_ai_discovery_model = ai  # type: ignore[method-assign]
    app._load_runtime_model = runtime  # type: ignore[method-assign]

    await app._handle_successful_command("defenseclaw", ("agent", "discovery", "scan"))
    await app._handle_successful_command("defenseclaw", ("agent", "discovery", "runtime", "enable", "--yes"))

    assert loads == ["ai", "runtime"]
