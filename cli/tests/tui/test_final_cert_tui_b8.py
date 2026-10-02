# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch b8: hook-only blocks in Alerts, marked dismiss, audit search, redaction, keys."""

from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import defenseclaw.tui.executor as executor_module
import pytest
from defenseclaw.models import Event
from defenseclaw.tui.executor import CommandExecutor
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel, alerts_from_v8_history
from defenseclaw.tui.panels.audit import _matches_search_query
from defenseclaw.tui.panels.setup import SetupWizard
from defenseclaw.tui.panels.setup_catalog import task_status
from defenseclaw.tui.services import v8_event_history
from defenseclaw.tui.widgets.action_menu import ActionMenuScreen

_HOOK = "connector=claudecode result=ok action={action} raw_action={action} severity={severity} mode=action{extra}"


def _audit_db() -> sqlite3.Connection:
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
    return db


def _hook_row(row_id: str, request_id: str, action: str, *, extra: str = "") -> tuple[str, ...]:
    details = _HOOK.format(action=action, severity="HIGH" if action == "block" else "NONE", extra=extra)
    return (row_id, "2026-10-02T17:31:24Z", request_id, details)


def test_alerts_list_a_hook_block_that_has_no_finding_row() -> None:
    # GAP-1747: current gateways file connector-hook rows under
    # guardrail.evaluation; a static tool block (no finding) never reached Alerts.
    db = _audit_db()
    db.executemany(
        """INSERT INTO audit_events (id, timestamp, request_id, details, bucket, event_name, signal,
                                     severity, action, connector)
           VALUES (?, ?, ?, ?, 'guardrail.evaluation', 'legacy.audit.connector.hook', 'logs',
                   'INFO', 'connector-hook', 'claudecode')""",
        [
            _hook_row("static-block", "req-1", "block", extra=' reason=tool "Write" is on the static block list'),
            _hook_row("rule-block", "req-2", "block"),
            _hook_row("allowed", "req-3", "allow", extra=" would_block=false"),
        ],
    )
    db.execute(
        """INSERT INTO audit_events (id, timestamp, request_id, bucket, event_name, signal, severity, action)
           VALUES ('finding', '2026-10-02T17:31:25Z', 'req-2', 'security.finding', 'finding.observed', 'logs',
                   'HIGH', 'scan-finding')"""
    )
    reader = v8_event_history.V8EventHistoryReader(SimpleNamespace(db=db))

    rows = reader.load_alerts(500)
    ids = {row.id for row in rows}
    assert "static-block" in ids
    # A block a finding explains stays one alert (the finding), as in the CLI.
    assert "rule-block" not in ids
    assert "allowed" not in ids

    events = {event.id: event for event in alerts_from_v8_history(rows)}
    assert events["static-block"].severity == "HIGH"
    assert events["static-block"].connector == "claudecode"


def _two_alerts() -> AlertsPanelModel:
    model = AlertsPanelModel()
    now = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    model.set_events(
        [
            AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://one", timestamp=now),
            AlertEvent(
                id="a2", severity="HIGH", action="scan", target="skill://two", timestamp=now - timedelta(seconds=1)
            ),
        ]
    )
    return model


def test_alert_dismiss_acts_on_marked_rows_and_names_them() -> None:
    # GAP-1777: Space marks a row and moves the cursor down; d dismissed the
    # next (unreviewed) row under the cursor instead of the marked one.
    model = _two_alerts()
    model.handle_key("space")
    assert model.selected_ids == {"a1"}

    dismissed = model.handle_key("d")
    assert dismissed.intent is not None
    assert dismissed.intent.args == ("alerts", "dismiss", "--id", "a1")
    assert "skill://one" in dismissed.intent.consequence
    assert "skill://two" not in dismissed.intent.consequence

    model.deselect_all()
    highlighted = model.handle_key("d")
    assert highlighted.intent is not None
    assert highlighted.intent.args == ("alerts", "dismiss", "--id", "a2")
    assert "skill://two" in highlighted.intent.consequence


def test_audit_search_matches_decisions_not_hidden_flags() -> None:
    # GAP-1780: the hint's own example action:block found nothing, and free
    # text "block" matched allow rows through would_block=false.
    block = Event(id="b", action="connector-hook", details=_HOOK.format(action="block", severity="HIGH", extra=""))
    allow = Event(
        id="a",
        action="connector-hook",
        details=_HOOK.format(action="allow", severity="NONE", extra=" would_block=false"),
    )
    for query in ("action:block", "decision:block", "block"):
        assert _matches_search_query(block, query), query
        assert not _matches_search_query(allow, query), query
    assert _matches_search_query(allow, "action:connector-hook")
    assert _matches_search_query(allow, "decision:allow")


def test_redaction_task_reports_the_effective_posture() -> None:
    # GAP-1773: the catalog said "on" with a green tick while every
    # destination exported unredacted (default profile none).
    unredacted = task_status(SetupWizard.REDACTION, {"observability": {"defaults": {"redaction_profile": "none"}}})
    assert (unredacted.state, unredacted.text) == ("off", "unredacted")

    plan = SimpleNamespace(
        destinations=(SimpleNamespace(redaction_profiles=("default",), enabled=True, generated=False),),
        buckets=(),
    )
    redacted = task_status(SetupWizard.REDACTION, {}, observability=plan)
    assert redacted.state == "ok"
    assert "default" in redacted.text


def test_action_menu_keys_run_in_typing_order() -> None:
    # GAP-1775: a quick "Down Down Enter" chose the old row, because the
    # focused row's Enter ran before the queued Downs moved the selection.
    priorities = {binding.action: binding.priority for binding in ActionMenuScreen.BINDINGS}
    assert priorities["cursor_up"] and priorities["cursor_down"] and priorities["choose"]


@pytest.mark.skipif(os.name != "posix", reason="stdlib PTYs are POSIX-only")
@pytest.mark.asyncio
async def test_pty_output_keeps_a_line_split_across_reads(monkeypatch) -> None:
    # GAP-1772: a read that ended mid-line showed "amp, cl" / "audecode".
    monkeypatch.setattr(executor_module, "_PIPE_FRAGMENT_FLUSH_SECONDS", 2.0)
    script = "import os, time; os.write(1, b'connectors: amp, cl'); time.sleep(0.2); os.write(1, b'audecode, codex\\n')"
    lines = [
        event.text
        async for event in CommandExecutor(use_pty=True).run(sys.executable, ("-c", script))
        if event.kind == "output"
    ]
    if any("Failed to start" in line for line in lines):
        pytest.skip("PTY device pool exhausted; environmental flake, not a regression.")
    assert lines == ["connectors: amp, claudecode, codex"]
