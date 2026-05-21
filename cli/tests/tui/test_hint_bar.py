# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Hint bar parity tests for Textual panel-specific hints."""

from __future__ import annotations

import pytest
from defenseclaw.tui.models import HintState, ServiceStatus, StatusModel
from defenseclaw.tui.widgets.hint_bar import HintEngine


@pytest.mark.parametrize(
    ("panel", "expected"),
    (
        ("skills", "R registries"),
        ("mcps", "n add server"),
        ("plugins", "plugin install"),
        ("inventory", "h/l switch sub-tabs"),
        ("tools", "tool block"),
        ("ai", "vendor/product/component"),
        ("registries", "S sync all"),
        ("policy", "v validate"),
        ("setup", "choose wizard"),
        ("first-run", "Ctrl+R apply"),
    ),
)
def test_hint_engine_returns_panel_specific_hints(panel: str, expected: str) -> None:
    hint = HintEngine().hint_for(HintState(active_panel=panel))

    assert expected in hint


def test_skills_hint_surfaces_unscanned_count() -> None:
    hint = HintEngine().hint_for(HintState(active_panel="skills", unscanned_skills=3))

    assert "3 skills unscanned" in hint
    assert "scan skill --all" in hint


def test_new_panel_filter_hints_keep_generic_filter_style() -> None:
    hint = HintEngine().hint_for(HintState(active_panel="ai", filter_active="provider=openai"))

    assert hint == "Filtered to: provider=openai. Esc clears the filter, / changes it."


def test_activity_command_running_hint_is_preserved() -> None:
    hint = HintEngine().hint_for(HintState(active_panel="activity", command_running=True))

    assert hint == "Command running. Press Ctrl+C to cancel. Output streams here in real time."


def test_setup_command_running_hint_uses_status() -> None:
    hint = HintEngine().hint_for(HintState(active_panel="setup"), StatusModel(command_running=True))

    # Operators reported the Setup panel looked frozen because the
    # connector wizard sits in a 30-60s `--verify` gateway probe with
    # no progress indicator. The hint now explicitly explains the
    # probe and (when available) surfaces the running argv plus
    # elapsed seconds. Without HintState.command_label/elapsed (this
    # path runs from StatusModel only), we fall back to "Setup
    # command" as the label.
    assert hint.startswith("⟳ Setup command")
    assert "Ctrl+C to cancel" in hint
    assert "verify probes the gateway" in hint


def test_setup_command_running_hint_surfaces_label_and_elapsed() -> None:
    state = HintState(
        active_panel="setup",
        command_running=True,
        command_label="defenseclaw setup claudecode",
        command_elapsed_secs=23,
    )

    hint = HintEngine().hint_for(state)

    assert hint.startswith("⟳ defenseclaw setup claudecode  (23s)")
    assert "verify probes the gateway" in hint


def test_first_run_command_running_hint_uses_state() -> None:
    hint = HintEngine().hint_for(HintState(active_panel="first_run", command_running=True))

    assert hint == "First-run setup is applying. Press Ctrl+C to cancel. Output streams in Activity."


def test_setup_missing_credentials_hint_uses_status_detail() -> None:
    status = StatusModel(
        guardrail=ServiceStatus(
            "Guardrail",
            "error",
            "missing required credential OPENAI_API_KEY",
        ),
    )

    hint = HintEngine().hint_for(HintState(active_panel="setup"), status)

    assert "Required credentials are missing" in hint
    assert "press f to fill missing" in hint


def test_first_run_missing_credentials_hint_uses_status_detail() -> None:
    status = StatusModel(
        gateway=ServiceStatus(
            "Gateway",
            "error",
            "api token not configured",
        ),
    )

    hint = HintEngine().hint_for(HintState(active_panel="first-run"), status)

    assert "Required credentials are missing" in hint
    assert "r refresh" in hint
