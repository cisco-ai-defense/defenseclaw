# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI batch: alerts, plugins and the result drawer."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from defenseclaw.tui.command_line import command_result_summary, suggested_next_action
from defenseclaw.tui.models import HintState
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.services.catalog_state import PluginRow, PluginsPanelModel
from defenseclaw.tui.widgets.hint_bar import HintEngine
from textual.widgets import RichLog

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import snapshot_app  # noqa: E402


def test_acknowledge_confirm_names_the_marked_alert() -> None:
    # GAP-1874: x showed only the alert id; d listed each marked alert.
    model = AlertsPanelModel()
    now = datetime(2026, 10, 2, 18, 11, tzinfo=timezone.utc)
    model.set_events(
        [
            AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://one", timestamp=now),
            AlertEvent(id="a2", severity="HIGH", action="scan", target="skill://two", timestamp=now - timedelta(1)),
        ]
    )
    model.handle_key("space")
    intent = model.handle_key("x").intent
    assert intent is not None and intent.args == ("alerts", "acknowledge", "--id", "a1")
    assert "skill://one" in intent.consequence and "skill://two" not in intent.consequence


def test_all_severities_chip_is_not_called_a_filter() -> None:
    # GAP-1875: "Alerts filtered to All severities. Click All ... to clear".
    hint = HintEngine().hint_for(HintState(active_panel="alerts", total_alerts=3, filter_active="All severities"))
    assert "filtered" not in hint and "Click All" not in hint
    assert "Actionable" in hint


def test_plugins_verdict_comes_before_the_source_path() -> None:
    # GAP-1905: at 80 columns the long Source path pushed Verdict off screen.
    model = PluginsPanelModel(connector="amp")
    model.apply_loaded([PluginRow(id="p", name="defenseclaw", origin="/Users/u/.config/amp", verdict="clean")])
    model.show_connector_column = True
    assert model.data_table_columns()[:5] == ("Connector", "Name", "Status", "Verdict", "Source")
    assert model.data_table_rows()[0][3:5] == ("clean", "/Users/u/.config/amp")


def test_result_drawer_states_the_result_and_names_the_key() -> None:
    # GAP-1910: the drawer showed the table footnote / log path, then
    # "next: rerun readiness" with no key.
    keys_list = [
        "ENV NAME  FEATURE  REQUIREMENT  SOURCE  STATUS",
        "○  DEFENSECLAW_LLM_KEY  llm.default  OPTIONAL  unset  unset",
        "·  VIRUSTOTAL_API_KEY  scanners  NOT_USED  dotenv  ✓ set",
        "●  GALILEO_API_KEY  observability  REQUIRED  dotenv  ✓ set",
        "Managed by DefenseClaw (gateway auth token, do not remove): DEFENSECLAW_GATEWAY_TOKEN",
    ]
    assert command_result_summary("setup Credentials", keys_list) == "3 credentials, 1 required, all set"
    keys_list[3] = "●  GALILEO_API_KEY  observability  REQUIRED  unset  MISSING"
    assert command_result_summary("keys list", keys_list).endswith("missing: GALILEO_API_KEY")
    restart = ["Stopping gateway sidecar (PID 7)... OK", "Starting gateway sidecar daemon... OK (PID 42)", "Log file: x"]
    assert command_result_summary("restart", restart) == "Gateway restarted (PID 42)"
    assert command_result_summary("skill list", ["done"]) == ""
    assert "0" in suggested_next_action("keys list", 0) and "i" in suggested_next_action("keys list", 0)
    assert suggested_next_action("restart", 0) == ""


async def test_activity_output_written_off_panel_keeps_full_width_lines(tmp_path) -> None:
    # GAP-1911: lines written while Activity was hidden wrapped at 78 columns.
    app = snapshot_app(tmp_path)
    line = "Change this connector's mode: " + "x" * 100
    async with app.run_test(size=(160, 45)) as pilot:
        log = app.query_one("#activity", RichLog)
        # The log shows beside the history list, not with a finished
        # command's own output (GAP-2326).
        app.activity_model.term_mode = False
        app.action_switch_panel("activity")
        await pilot.pause()
        app.action_switch_panel("overview")
        await pilot.pause()
        before = len(log.lines)
        app._write_activity_safe(line)  # noqa: SLF001
        assert len(log.lines) == before + 1
        app.action_switch_panel("activity")
        await pilot.pause()
        assert log.virtual_size.width <= log.scrollable_content_region.width
