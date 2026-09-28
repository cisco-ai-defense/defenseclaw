# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Every Setup key the hint bar, ``?`` sheet or a button advertises works.

The keymaps in ``panels/setup_keys.py`` are the one source for all three,
so these tests press each advertised key in its view and check the Setup
handler takes it. Keys whose behaviour belongs to the field editor (Enter
on a text row) are only checked for being routed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw.tui import app as app_module  # noqa: E402
from defenseclaw.tui.models import HintState  # noqa: E402
from defenseclaw.tui.panels import setup_keys  # noqa: E402
from defenseclaw.tui.panels.setup import SetupWizard  # noqa: E402
from defenseclaw.tui.widgets.hint_bar import HintEngine  # noqa: E402
from fixtures import snapshot_app  # noqa: E402

ALL_CONDITIONS = ("restart_pending", "credentials", "list_editor", "secret_field")


def _app(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    from defenseclaw.config import default_config

    return snapshot_app(tmp_path, setup_config=default_config())


def _enter_view(app, view: str, spec: setup_keys.KeySpec) -> None:
    """Put Setup in ``view`` with whatever condition ``spec`` needs."""

    model = app.setup_model
    model.close_wizard_form()
    model.goal_active = False
    model.mode = "wizards"
    model.active_wizard = SetupWizard.CREDENTIALS if spec.when == "credentials" else SetupWizard.CONNECTOR_SETUP
    if spec.when == "restart_pending":
        model.queue_restart("test")
    else:
        model.clear_restart_queue()
    if view == "goals":
        assert model.open_goal_menu(SetupWizard.CONNECTOR_SETUP)
    elif view == "form":
        model.open_wizard_form(SetupWizard.LLM if spec.when == "secret_field" else SetupWizard.CONNECTOR_SETUP)
    elif view == "config":
        model.mode = "config"
        if spec.when == "list_editor":
            model.select_section(next(i for i, s in enumerate(model.sections) if s.name == "Webhooks"))
        else:
            model.select_section(0)
    assert setup_keys.setup_view(model) == view
    if spec.when:
        assert spec.when in setup_keys.setup_conditions(model)


def _cases():
    for view in ("wizards", "goals", "form", "config"):
        for spec in setup_keys.SETUP_KEYMAPS[view]:
            for press in spec.presses:
                yield pytest.param(view, spec, press, id=f"{view}-{spec.key}-{press}")


@pytest.mark.parametrize(("view", "spec", "press"), list(_cases()))
def test_every_advertised_setup_key_is_handled(tmp_path, monkeypatch, view, spec, press) -> None:
    app = _app(tmp_path, monkeypatch)
    _enter_view(app, view, spec)

    action = app._handle_setup_key(press)  # noqa: SLF001

    assert action.handled, f"{press!r} advertised as {spec.key} {spec.label!r} in {view} is not handled"


@pytest.mark.parametrize(
    "press",
    [press for spec in setup_keys.SETUP_KEYMAPS["first-run"] for press in spec.presses],
)
def test_every_first_run_key_is_handled(tmp_path, monkeypatch, press) -> None:
    app = _app(tmp_path, monkeypatch)
    app.first_run_model.active = True

    assert app.first_run_model.handle_key(press).handled


def test_navigation_keys_open_the_right_picker(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    wizards = setup_keys.SETUP_KEYMAPS["wizards"][0]
    _enter_view(app, "wizards", wizards)
    assert app._handle_setup_key("i").open_picker == "detail"  # noqa: SLF001

    _enter_view(app, "config", setup_keys.SETUP_KEYMAPS["config"][0])
    assert app._handle_setup_key("g").open_picker == "sections"  # noqa: SLF001
    assert app._handle_setup_key("/").open_picker == "fields"  # noqa: SLF001


def test_digits_are_left_for_panel_switching(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    _enter_view(app, "wizards", setup_keys.SETUP_KEYMAPS["wizards"][0])
    for digit in "0123456789":
        assert not app._handle_setup_key(digit).handled  # noqa: SLF001
    _enter_view(app, "goals", setup_keys.SETUP_KEYMAPS["goals"][0])
    assert not app._handle_setup_key("1").handled  # noqa: SLF001


def test_wizard_list_moves_in_display_order(tmp_path, monkeypatch) -> None:
    from defenseclaw.tui.panels import setup_catalog

    app = _app(tmp_path, monkeypatch)
    order = setup_catalog.display_order()
    app.setup_model.active_wizard = order[2]

    app._handle_setup_key("down")  # noqa: SLF001

    # The last task of a group hands on to the next group's first task.
    assert setup_catalog.wizard_group(order[2]) != setup_catalog.wizard_group(order[3])
    assert app.setup_model.active_wizard is order[3]
    assert app._setup_cursor() == setup_catalog.task_row(order[3]) == 0  # noqa: SLF001


@pytest.mark.parametrize("view", setup_keys.SETUP_VIEWS)
def test_buttons_press_a_key_their_keyspec_advertises(view) -> None:
    for spec in setup_keys.keymap(view, ALL_CONDITIONS):
        if spec.button_id is None:
            continue
        assert spec.button_id in (*setup_keys.SETUP_BUTTON_IDS, *setup_keys.SETUP_WIZARD_BUTTON_IDS)
        assert app_module._SETUP_BUTTON_KEYS[spec.button_id] in spec.presses  # noqa: SLF001


def test_first_run_shows_no_setup_buttons() -> None:
    assert setup_keys.visible_buttons("first-run", ALL_CONDITIONS) == frozenset()
    assert setup_keys.visible_buttons("goals", ALL_CONDITIONS) == frozenset()


@pytest.mark.parametrize("view", setup_keys.SETUP_VIEWS)
def test_hint_bar_and_help_sheet_come_from_the_keymap(tmp_path, monkeypatch, view) -> None:
    hint = HintEngine().hint_for(HintState(active_panel="setup", panel_view=view))
    assert hint == setup_keys.keys_hint(view)

    app = _app(tmp_path, monkeypatch)
    app.active_panel = "setup"
    spec = setup_keys.SETUP_KEYMAPS[view][0]
    if view == "first-run":
        app.first_run_model.active = True
    else:
        _enter_view(app, view, spec)
    sheet = app._help_sections()[1][1]  # noqa: SLF001
    assert sheet == setup_keys.help_rows(view, setup_keys.setup_conditions(app.setup_model))


def test_conditional_keys_only_show_when_they_apply() -> None:
    plain = {spec.key for spec in setup_keys.keymap("wizards")}
    queued = {spec.key for spec in setup_keys.keymap("wizards", {"restart_pending"})}

    assert "G" not in plain
    assert "G" in queued
    assert "setup-restart" in setup_keys.visible_buttons("config", {"restart_pending"})
    assert "setup-restart" not in setup_keys.visible_buttons("config")
