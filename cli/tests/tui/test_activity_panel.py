# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Activity panel parity tests."""

from __future__ import annotations

from datetime import timedelta

from defenseclaw.tui.panels.activity import ActivityPanelModel


def test_activity_panel_empty_state_matches_go_contract() -> None:
    panel = ActivityPanelModel()

    assert panel.count == 0
    assert panel.is_running is False
    assert panel.last_command == ""
    assert "No commands" in panel.render_text()


def test_activity_panel_command_lifecycle() -> None:
    panel = ActivityPanelModel()

    panel.add_entry("doctor")
    panel.append_output("Checking gateway...")
    panel.append_output("Gateway: running")
    panel.finish_entry(0, timedelta(milliseconds=150))

    assert panel.count == 1
    assert panel.is_running is False
    assert panel.last_command == "doctor"
    rendered = panel.render_text()
    assert "Checking gateway..." in rendered
    assert "exit 0" in rendered


def test_activity_panel_terminal_and_history_key_flow() -> None:
    panel = ActivityPanelModel()
    panel.add_entry("status")
    panel.append_output("line")
    panel.finish_entry(0)

    assert panel.term_mode is True
    panel.handle_key("q")
    assert panel.term_mode is False
    panel.handle_key("enter")
    assert panel.term_mode is True
