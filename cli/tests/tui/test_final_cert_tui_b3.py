# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI batch 3: plugin filter and unblock, doctor output, crashed runs."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from defenseclaw.tui.app import _catalog_panel_invalidated_by_command
from defenseclaw.tui.executor import CommandEvent, _hold_incomplete_escape
from defenseclaw.tui.panels.setup import SetupWizard
from defenseclaw.tui.services.catalog_state import (
    PluginRow,
    PluginsPanelModel,
    ToolRow,
    ToolsPanelModel,
    plugin_action_intent,
)

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402

# A doctor line whose colour code lost its ESC at a read boundary (GAP-1543).
_CUT_SGR_LINE = "[90m—  contract=claudecode-hooks-v2 status=known agent=2.1.286 (Claude Code) normalized=2.1.286"


def test_plugin_unblock_runs_plugin_unblock_not_allow() -> None:
    # GAP-1530: ``u`` allow-listed the plugin instead of clearing its block.
    row = PluginRow(id="spotify", name="spotify", status="blocked", verdict="blocked")
    intent = plugin_action_intent("u", row, origin="plugins", connector="hermes")
    assert intent is not None
    assert intent.args == ("plugin", "unblock", "spotify", "--connector", "hermes")
    assert _catalog_panel_invalidated_by_command(intent.args) == "plugins"


def test_plugin_and_tool_filters_narrow_the_rows() -> None:
    # GAP-1520: the Plugins filter kept every row ("60 of 60 filter: xai").
    plugins = PluginsPanelModel(connector="hermes")
    plugins.apply_loaded([PluginRow(id="xai", name="xai"), PluginRow(id="spotify", name="spotify")])
    plugins.set_filter("xai")
    assert [row.id for row in plugins.filtered] == ["xai"]
    plugins.set_filter("zzz")
    assert plugins.filtered == ()
    assert plugins.empty_state() == "No plugins match the filter."
    plugins.clear_filter()
    assert len(plugins.filtered) == 2

    tools = ToolsPanelModel(connector="codex")
    tools.apply_loaded([ToolRow(name="shell", status="blocked"), ToolRow(name="web_fetch", status="allowed")])
    tools.set_filter("shell")
    assert [row.name for row in tools.filtered] == ["shell"]


def test_cut_colour_code_is_held_for_the_next_read() -> None:
    assert _hold_incomplete_escape("ok \x1b[9") == ("ok ", "\x1b[9")
    assert _hold_incomplete_escape("ok \x1b") == ("ok ", "\x1b")
    assert _hold_incomplete_escape("ok \x1b[90mdim") == ("ok \x1b[90mdim", "")
    assert _hold_incomplete_escape("Selection [3]:") == ("Selection [3]:", "")


async def test_doctor_output_and_crashes_finish_in_activity(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    crash = False

    async def run(binary: str, args: tuple[str, ...], **_kwargs: Any):
        yield CommandEvent("start", " ".join((binary, *args)))
        yield CommandEvent("output", "\x1b[32m✓ Mode [amp]\x1b[0m")
        if crash:
            raise RuntimeError("executor broke")
        yield CommandEvent("output", _CUT_SGR_LINE)
        yield CommandEvent("done", exit_code=0, duration=0.5)

    async with app.run_test(size=(80, 24)) as pilot:
        app.executor.run = run  # type: ignore[method-assign]
        # GAP-1543: the strip's live tail crashed the run on Textual markup.
        app._strip_running("Doctor")  # noqa: SLF001
        app._strip_output(_CUT_SGR_LINE)  # noqa: SLF001
        assert await app._run_command("defenseclaw", ("doctor",), display_name="Doctor") == 0  # noqa: SLF001
        entry = app.activity_model.entries[-1]
        assert entry.done and entry.exit_code == 0
        # GAP-1552: a crashed run no longer stays "running" in the history.
        crash = True
        assert await app._run_command("defenseclaw", ("doctor",), display_name="Doctor") is None  # noqa: SLF001
        entry = app.activity_model.entries[-1]
        assert entry.done and entry.exit_code == 1
        await pilot.pause()

    # GAP-1552: cancelling "Remove a stored credential" puts the task row back.
    app.setup_model.wizard_status[SetupWizard.CREDENTIALS] = "running..."
    app.setup_model.mark_wizard_complete(("keys", "remove", "VIRUSTOTAL_API_KEY", "--yes"), success=False, cancelled=True)
    assert app.setup_model.wizard_status.get(SetupWizard.CREDENTIALS) != "running..."


def test_alert_scan_skips_the_hook_classifier_on_rows_that_cannot_block(monkeypatch) -> None:
    # GAP-1487: the per-row Python classifier ran on every legacy filler row of
    # a 1.27 GB audit.db, so the first Overview/Audit read took minutes.
    import sqlite3
    from types import SimpleNamespace

    from defenseclaw.tui.services import v8_event_history

    calls: list[str] = []
    classify = v8_event_history.aggregate_connector_hook_decision

    def counting(details, structured=None, enforced=None):  # type: ignore[no-untyped-def]
        calls.append(details)
        return classify(details, structured, enforced)

    monkeypatch.setattr(v8_event_history, "aggregate_connector_hook_decision", counting)
    db = sqlite3.connect(":memory:")
    db.execute(
        """CREATE TABLE audit_events (
            id TEXT PRIMARY KEY, timestamp TEXT, bucket TEXT, event_name TEXT,
            source TEXT, signal TEXT, severity TEXT, action TEXT, actor TEXT,
            details TEXT, connector TEXT, redaction_profile TEXT, run_id TEXT,
            trace_id TEXT, request_id TEXT, session_id TEXT, turn_id TEXT,
            scan_id TEXT, finding_id TEXT, payload_json TEXT, projected_record_json TEXT
        )"""
    )
    rows = [(f"fill-{i}", "2026-10-01T10:00:00Z", "he5-filler", "ABCDEF0123" * 400) for i in range(50)]
    rows.append(("hook-block", "2026-10-02T10:00:00Z", "connector-hook", "connector=codex action=block"))
    db.executemany(
        "INSERT INTO audit_events (id, timestamp, action, details, severity) VALUES (?, ?, ?, ?, 'INFO')",
        rows,
    )
    reader = v8_event_history.V8EventHistoryReader(SimpleNamespace(db=db))

    alert_ids = {row.id for row in reader.load_alerts(500)}

    assert "hook-block" in alert_ids
    assert not any(alert_id.startswith("fill-") for alert_id in alert_ids)
    assert calls and all("action" in details for details in calls)
