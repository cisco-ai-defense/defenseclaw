# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup group strip stays symmetric into the config editor (final-cert TUI batch 25)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures  # noqa: E402
from defenseclaw.tui.panels import setup_catalog  # noqa: E402


def test_left_from_config_editor_returns_to_last_group(tmp_path) -> None:
    # GAP-2559: Right on "Gateway & advanced" opened the editor (on the last
    # used section at 160x45), and Left then wrapped through config sections.
    app = fixtures.snapshot_app(tmp_path)
    model = app.setup_model
    order = setup_catalog.section_order(model.sections)
    last_group = setup_catalog.GROUP_TITLES[-1]
    model.active_wizard = setup_catalog.group_tasks(last_group)[0]
    model.select_section(order[-1])
    app._handle_setup_key("right")  # noqa: SLF001
    assert model.mode == "config" and model.active_section == order[0]
    action = app._handle_setup_key("left")  # noqa: SLF001
    assert model.mode == "wizards" and model.active_wizard in setup_catalog.group_tasks(last_group)
    assert action.hint.startswith(f"Back to {last_group}.")
    # Inside the editor Left still steps sections, and Shift+Tab still wraps.
    app._handle_setup_key("right")  # noqa: SLF001
    app._handle_setup_key("right")  # noqa: SLF001
    assert model.active_section == order[1]
    app._handle_setup_key("left")  # noqa: SLF001
    assert model.mode == "config" and model.active_section == order[0]
    app._handle_setup_key("shift+tab")  # noqa: SLF001
    assert model.mode == "config" and model.active_section == order[-1]
