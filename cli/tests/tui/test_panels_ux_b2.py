# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""TUI panels UX batch 2: alerts, audit, logs, activity, registries, config editor."""

from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from defenseclaw.models import Event
from defenseclaw.tui.command_line import ParsedCommand, infer_command_risk
from defenseclaw.tui.panels.activity import ActivityPanelModel, activity_mutations_from_v8_history
from defenseclaw.tui.panels.alerts import _hook_decision_label
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.logs import LogsPanelModel, _line_connector
from defenseclaw.tui.panels.registries import require_entry_intent
from defenseclaw.tui.screens.command_preview import build_command_preview
from defenseclaw.tui.services.registry_cache import RegistryEntryRow
from defenseclaw.tui.services.v8_event_history import V8EventHistoryReader, V8EventHistoryRow

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402

_T0 = datetime(2026, 10, 2, 6, 0, tzinfo=timezone.utc)


def test_alert_ack_preview_is_a_mutation_and_finding_detail_names_the_decision() -> None:
    assert infer_command_risk("alerts", ("alerts", "acknowledge", "--id", "a1")) == "mutation"
    assert infer_command_risk("alerts", ("alerts", "dismiss", "--id", "a1")) == "mutation"

    def store(details: list[str]) -> SimpleNamespace:
        return SimpleNamespace(hook_details_for_alerts=lambda ids: {ids[0]: details})

    blocked = "connector=claudecode result=ok action=block raw_action=block severity=CRITICAL mode=action"
    observed = "connector=claudecode result=ok action=allow raw_action=block mode=observe would_block=true"
    assert _hook_decision_label(store([blocked]), "f1") == "blocked (action mode)"
    assert _hook_decision_label(store([observed]), "f1") == "would block (observe mode)"
    assert _hook_decision_label(store([]), "f1") == ""


def test_registry_require_modal_names_the_consequence() -> None:
    row = RegistryEntryRow(type="mcp", name="srv", source_id="corp", status="approved")
    intent = require_entry_intent(row, currently_required=False)
    preview = build_command_preview(
        ParsedCommand(
            binary="defenseclaw",
            args=intent.args,
            display_name=intent.label,
            category=intent.category,
            risk=intent.risk,
            consequence=intent.consequence,
        )
    )
    assert "any mcp not approved in a registry will be refused" in preview.consequence


def test_audit_blocks_filter_finds_hook_and_guardrail_blocks_and_detail_shows_the_outcome() -> None:
    panel = AuditPanelModel()
    verdict = Event(
        id="v1",
        timestamp=_T0,
        action="guardrail-verdict",
        details="guardrail.evaluation.completed",
        severity="CRITICAL",
        connector="opencode",
        enforced=True,
        structured={
            "defenseclaw.guardrail.decision": "block",
            "defenseclaw.guardrail.rule_ids": ["SEC-AWS-KEY"],
            "defenseclaw.acp.method": "session/prompt",
        },
    )
    hook_block = Event(
        id="h1",
        timestamp=_T0,
        action="connector-hook",
        target="PreToolUse",
        details="connector=claudecode result=ok action=block raw_action=block mode=action",
    )
    would_block = Event(
        id="h2",
        timestamp=_T0,
        action="connector-hook",
        target="PreToolUse",
        details="connector=claudecode result=ok action=allow raw_action=block mode=observe would_block=true",
    )
    panel.set_events([verdict, hook_block, would_block])

    panel.set_common_filter("blocks")
    assert [event.id for event in panel.filtered] == ["v1", "h1"]

    panel.cursor = 0
    pairs = dict(panel.detail_pairs())
    assert pairs["Connector"] == "opencode"
    assert pairs["Decision"] == "block"
    assert pairs["Rules"] == "SEC-AWS-KEY"
    assert pairs["ACP method"] == "session/prompt"
    assert "Target" not in pairs


def test_logs_follow_the_tail_parse_only_real_connector_tags_and_search_keeps_letters() -> None:
    panel = LogsPanelModel()
    panel.source = "gateway"
    panel.show_connector_column = True
    panel.lines["gateway"] = [
        "[audit] applying migration 17: multi-connector: add connector + step_idx",
        "[audit] applying migration 18: multi-connector: per-connector column on actions",
        "12:00:01 HOOK connector=cursor action=block preToolUse",
    ]
    assert [cells[0] for cells in panel.data_table_rows()] == ["—", "—", "cursor"]
    assert _line_connector('{"connector":"codex","action":"allow"}') == "codex"
    assert panel.table_cursor_row() == 2

    panel.handle_key("/")
    for key in ("k", "i", "r", "o", "G", "space", "j"):
        panel.handle_key(key)
    assert panel.search_text == "kiroG j"
    assert panel.searching


def test_activity_mutation_rows_name_the_change() -> None:
    row = V8EventHistoryRow(
        id="m1",
        timestamp=_T0,
        bucket="compliance.activity",
        event_name="config.change.applied",
        source="audit_logger",
        severity="INFO",
        action="config-update",
        actor="audit_logger",
        details="config.change.applied",
        connector="",
        redaction_profile="",
        payload={
            "defenseclaw.admin.actor_ref": "cli:operator",
            "defenseclaw.admin.target_ref": "config:dotenv:VIRUSTOTAL_API_KEY",
            "defenseclaw.admin.diff": '[{"path":"/.env/VIRUSTOTAL_API_KEY","op":"replace","before":"unset","after":"set"}]',
        },
    )
    model = ActivityPanelModel()
    model.apply_mutations(activity_mutations_from_v8_history((row,)))
    model.set_tab("mutations")
    text = model.render_text(height=24)
    assert "cli:operator  config-update  config:dotenv:VIRUSTOTAL_API_KEY  /.env/VIRUSTOTAL_API_KEY: unset -> set" in text
    assert "∅" not in text and "compliance.activity" not in text


async def test_search_keeps_capitals_and_digits_leave_the_config_editor(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.action_switch_panel("alerts")
        await pilot.pause()
        await pilot.press("slash", "K", "J", "K", "m")
        await pilot.pause()
        assert app.alerts_model.filter_text == "KJKm"
        await pilot.press("escape")
        await pilot.pause()

        app.action_open_command()
        await pilot.pause()
        assert app.status_text.startswith("Command palette open")
        app._close_command_palette()
        assert not app.status_text.startswith("Command palette open")

        app.action_switch_panel("setup")
        await pilot.pause()
        await pilot.press("c")
        await pilot.pause()
        assert app.setup_model.mode == "config"
        await pilot.press("1")
        await pilot.pause()
        assert app.active_panel == "overview"


def test_mutation_rows_are_read_past_a_flood_of_newer_events() -> None:
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
    db.execute(
        """INSERT INTO audit_events (id, timestamp, bucket, event_name, source, signal, severity,
               action, actor, details, connector, redaction_profile, payload_json, projected_record_json)
           VALUES ('change-1', '2026-07-01T00:00:00Z', 'compliance.activity', 'config.change.applied',
                   'audit_logger', 'logs', 'INFO', 'config-update', 'audit_logger', '', '', 'none', '{}', '{}')"""
    )
    db.executemany(
        """INSERT INTO audit_events (id, timestamp, bucket, event_name, source, signal, severity,
               action, actor, details, connector, redaction_profile, payload_json, projected_record_json)
           VALUES (?, '2026-07-02T00:00:00Z', 'ai.discovery', 'ai.discovery.completed', 'gateway', 'logs',
                   'INFO', 'ai_discovery', 'gateway', '', '', 'none', '{}', '{}')""",
        ((f"noise-{index}",) for index in range(600)),
    )
    reader = V8EventHistoryReader(SimpleNamespace(db=db))

    history, _alerts, mutations = reader.load_views_and_mutations(500, 500, 500)
    assert "change-1" not in {row.id for row in history}
    assert [row.id for row in mutations] == ["change-1"]
