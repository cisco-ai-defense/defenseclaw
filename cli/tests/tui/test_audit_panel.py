# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Audit panel parity tests for the Textual TUI migration."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from defenseclaw.db import Store
from defenseclaw.models import ActionState, Event
from defenseclaw.tui.panels.audit import (
    AUDIT_TABLE_COLUMNS,
    AUDIT_TABLE_COLUMNS_MULTI,
    AuditPanelModel,
    audit_action_display,
    audit_severity_style_key,
    event_connector,
    export_audit_intent,
)


def test_audit_connector_column_and_filter() -> None:
    """8.13: CONNECTOR column + shared connector filter on the Audit panel."""

    model = AuditPanelModel()
    model.show_all_events = True
    model.set_events(
        [
            Event(id="a", action="connector-hook", target="preToolUse",
                  severity="INFO", details="connector=codex action=allow"),
            Event(id="b", action="connector-hook", target="preToolUse",
                  severity="INFO", details="connector=cursor action=allow"),
        ]
    )

    # Single-connector default: original columns, no CONNECTOR.
    assert model.data_table_columns() == AUDIT_TABLE_COLUMNS

    model.show_connector_column = True
    assert model.data_table_columns() == AUDIT_TABLE_COLUMNS_MULTI
    rows = model.data_table_rows()
    # CONNECTOR is the 4th column (index 3), after TYPE.
    connectors = {row[3] for row in rows}
    assert connectors == {"codex", "cursor"}

    # Shared filter narrows the rows + keeps the count consistent.
    model.set_connector_filter("codex")
    assert len(model.filtered) == 1
    assert all(row[3] == "codex" for row in model.data_table_rows())

    model.set_connector_filter("")
    assert len(model.filtered) == 2


def test_event_connector_helper() -> None:
    assert event_connector(
        Event(id="x", action="connector-hook", target="t", details="connector=codex action=allow")
    ) == "codex"
    assert event_connector(Event(id="y", action="scan", target="t", details="severity=HIGH")) == ""


def test_audit_default_hides_low_signal_rows_until_all_opt_in() -> None:
    panel = AuditPanelModel()
    panel.set_events(
        [
            Event(id="info", action="connector-hook", target="preToolUse", severity="INFO"),
            Event(id="medium", action="scan", target="skill://one", severity="MEDIUM"),
            Event(id="high", action="scan", target="skill://two", severity="HIGH"),
            Event(id="failure", action="sink-failure", target="splunk", severity="INFO"),
        ]
    )

    assert [event.id for event in panel.filtered] == ["high", "failure"]

    assert panel.handle_key("1").handled is True
    assert [event.id for event in panel.filtered] == ["info", "medium", "high", "failure"]


def new_store(tmp_path: Path) -> Store:
    store = Store(str(tmp_path / "audit.db"))
    store.init()
    return store


def test_audit_refresh_filter_selection_and_detail_enrichment(tmp_path) -> None:
    store = new_store(tmp_path)
    try:
        scan_ts = datetime(2026, 4, 16, 12, 0, 0)
        store.insert_scan_result(
            "run-1",
            "skill-scanner",
            "skill://one",
            scan_ts,
            42,
            1,
            "HIGH",
            "{}",
        )
        store.insert_finding(
            "finding-1",
            "run-1",
            "HIGH",
            "Unsafe tool",
            "description",
            "skill.py:3",
            "fix it",
            "skill-scanner",
            "",
        )
        store.set_action(
            "skill",
            "skill://one",
            "",
            ActionState(install="block"),
            "policy",
        )
        store.log_event(
            Event(
                id="event-1",
                timestamp=datetime(2026, 4, 16, 12, 1, 0),
                action="block-skill",
                target="skill://one",
                actor="tester",
                details="Unsafe tool",
                severity="HIGH",
                run_id="run-1",
            )
        )
        store.log_event(
            Event(
                id="event-2",
                timestamp=datetime(2026, 4, 16, 12, 2, 0),
                action="allow-mcp",
                target="mcp://two",
                actor="tester",
                details="clean",
                severity="INFO",
            )
        )

        panel = AuditPanelModel(store)
        panel.show_all_events = True
        panel.refresh()

        assert panel.count == 2
        assert panel.selected() is not None
        assert panel.selected().id == "event-2"

        panel.set_filter("unsafe")
        assert [event.id for event in panel.filtered] == ["event-1"]
        assert panel.selected().target == "skill://one"

        info = panel.get_detail_info()
        assert info is not None
        assert info.findings[0].title == "Unsafe tool"
        assert info.action is not None
        assert info.action.actions.summary() == "blocked"
        assert any(event.id == "event-1" for event in info.related)

        pairs = dict(panel.detail_pairs())
        assert pairs["Run ID"] == "run-1"
        assert pairs["Current State"] == "blocked"
        assert "Unsafe tool" in pairs["Finding 1"]

        detail_rows = panel.detail_rows()
        assert detail_rows[0].key.startswith("detail:0:")
        assert any(row.style_key == "finding" and "Unsafe tool" in row.value for row in detail_rows)
        assert any(row.style_key == "state" and row.value == "blocked" for row in detail_rows)
    finally:
        store.close()


def test_audit_cursor_scroll_empty_and_no_match_states() -> None:
    panel = AuditPanelModel()
    panel.show_all_events = True
    base = datetime(2026, 4, 16, 12, 0, 0)
    panel.set_events(
        [
            Event(
                id=f"event-{index}",
                timestamp=base + timedelta(minutes=index),
                action="scan",
                target=f"target-{index}",
                severity="INFO",
            )
            for index in range(20)
        ]
    )

    panel.set_cursor(12)
    assert panel.scroll_offset(height=10) > 0

    panel.scroll_by(-100)
    assert panel.cursor == 0
    panel.scroll_by(100)
    assert panel.cursor == 19

    panel.set_filter("target-3")
    assert [event.id for event in panel.filtered] == ["event-3"]
    assert panel.cursor == 0

    panel.set_filter("no-such-event")
    assert panel.filtered == []
    assert "No events match the filter." in panel.render_text()

    empty = AuditPanelModel()
    assert "No audit events yet" in empty.render_text()


def test_audit_filter_typing_detail_toggle_and_export_intent_are_data() -> None:
    panel = AuditPanelModel()
    panel.set_events(
        [
            Event(
                id="event-1",
                timestamp=datetime(2026, 4, 16, 12, 0, 0),
                action="block-plugin",
                target="plugin://one",
                severity="HIGH",
            )
        ]
    )

    assert panel.handle_key("/").handled is True
    assert panel.filtering is True
    panel.handle_key("p")
    panel.handle_key("l")
    assert panel.filter_text == "pl"
    assert panel.handle_key("enter").handled is True
    assert panel.filtering is False

    assert panel.handle_key("enter").handled is True
    assert panel.detail_open is True
    assert ("Action", "block-plugin") in panel.detail_pairs()
    assert panel.handle_key("esc").handled is True
    assert panel.detail_open is False

    action = panel.handle_key("e")
    assert action.handled is True
    assert action.intent == export_audit_intent()
    assert action.intent is not None
    assert action.intent.kind == "export"
    assert str(action.intent.path) == "defenseclaw-audit-export.json"

    payload = panel.export_payload()
    assert payload == (
        {
            "id": "event-1",
            "timestamp": "2026-04-16T12:00:00",
            "action": "block-plugin",
            "target": "plugin://one",
            "actor": "defenseclaw",
            "details": "",
            "severity": "HIGH",
            "run_id": "",
        },
    )


def test_audit_refresh_error_is_rendered() -> None:
    class BrokenStore:
        def list_events(self, _limit: int) -> list[Event]:
            raise RuntimeError("db locked")

    panel = AuditPanelModel(BrokenStore())
    panel.refresh()

    assert panel.error_message == "Audit refresh failed: db locked"
    assert panel.render_text() == "Audit refresh failed: db locked"


def test_audit_view_metadata_exposes_toolbar_rows_columns_and_styles() -> None:
    panel = AuditPanelModel()
    panel.set_events(
        [
            Event(
                id="event-1",
                timestamp=datetime(2026, 4, 16, 12, 0, 0),
                action="block-skill",
                target="skill://one-with-a-very-long-identifier-that-will-truncate",
                details="Unsafe tool with a very long detail string",
                severity="HIGH",
            ),
            Event(
                id="event-2",
                timestamp=datetime(2026, 4, 16, 12, 1, 0),
                action="allow-mcp",
                target="mcp://two",
                details="clean",
                severity="INFO",
            ),
        ]
    )
    panel.set_filter("skill")
    panel.filtering = True

    toolbar = panel.toolbar_state()
    assert toolbar.summary_label == "1 shown of 2 events"
    assert toolbar.filter_label == "Showing 1 of 2: search 'skill'"
    assert toolbar.filtered_label == "search 'skill'"
    assert toolbar.search_prompt == "/ skill"
    assert [(action.key, action.label) for action in toolbar.actions] == [("e", "export"), ("/", "filter")]
    assert toolbar.actions[0].intent == export_audit_intent()

    assert panel.data_table_columns() == AUDIT_TABLE_COLUMNS
    rows = panel.row_views()
    assert len(rows) == 1
    assert rows[0].selected is True
    assert rows[0].time_label == "12:00:00"
    assert rows[0].table_key == "audit:event-1"
    assert rows[0].action_label == "BLOCK"
    assert rows[0].action_style_key == "blocked"
    assert rows[0].target_type == "skill"
    assert rows[0].target_label.endswith("...")
    assert rows[0].severity_style_key == "high"
    assert rows[0].run_label == ""
    assert rows[0].details_label.endswith("...")
    assert panel.data_table_rows()[0] == rows[0].cells
    assert panel.data_table_row_models()[0] == rows[0]
    assert panel.selected_detail_title() == "EVENT: block-skill"

    panel.clear_filter()
    assert panel.toolbar_state().summary_label == "2 shown of 2 events"


def test_audit_common_filters_field_search_and_correlation() -> None:
    panel = AuditPanelModel()
    panel.set_events(
        [
            Event(
                id="event-1",
                action="block-skill",
                target="skill://one",
                actor="operator",
                details="token leak",
                severity="HIGH",
                run_id="run-1",
            ),
            Event(
                id="event-2",
                action="scan",
                target="skill://one",
                actor="scanner",
                details="clean",
                severity="INFO",
                run_id="run-1",
            ),
            Event(
                id="event-3",
                action="config-update",
                target="settings",
                actor="operator",
                details="credentials refreshed",
                severity="LOW",
                run_id="run-2",
            ),
        ]
    )

    panel.set_common_filter("risk")
    assert [event.id for event in panel.filtered] == ["event-1"]
    assert panel.active_filter_label() == "Risk"

    panel.set_common_filter("credentials")
    assert [event.id for event in panel.filtered] == ["event-1", "event-3"]

    panel.clear_filter()
    panel.set_filter("actor:operator severity:low")
    assert [event.id for event in panel.filtered] == ["event-3"]

    panel.clear_filter()
    panel.set_cursor(0)
    assert panel.filter_same_target() is True
    assert [event.id for event in panel.filtered] == ["event-1", "event-2"]

    panel.clear_filter()
    panel.set_cursor(0)
    assert panel.filter_same_run() is True
    assert [event.id for event in panel.filtered] == ["event-1", "event-2"]


def test_audit_action_and_severity_style_metadata_matches_go_buckets() -> None:
    assert audit_action_display("block-skill") == ("BLOCK", "blocked")
    assert audit_action_display("allow-mcp") == ("ALLOW", "allowed")
    assert audit_action_display("scan") == ("SCAN", "low")
    assert audit_action_display("quarantine-plugin") == ("QUARANTINE", "quarantined")
    assert audit_action_display("config-update") == ("CONFIG", "medium")
    assert audit_action_display("dismiss-alert") == ("DISMISS", "dimmed")
    assert audit_action_display("custom-event") == ("CUSTOM-EVENT", "info")

    assert audit_severity_style_key("CRITICAL") == "critical"
    assert audit_severity_style_key("high") == "high"
    assert audit_severity_style_key("INFO") == "info"
    assert audit_severity_style_key("UNKNOWN") == "info"


def test_audit_connector_hook_event_renders_structured_detail_rows() -> None:
    """Hook events should be parsed into individual labelled rows.

    Without this, every claudecode/cursor/etc. row in the table looks
    like ``connector-hook · preToolUse · observe connector=claudecode
    action=allow severity=NONE …`` and you can't tell at a glance which
    framework fired or what the decision was. After parsing, the
    detail pane carries discrete ``Connector``, ``Decision``,
    ``Enforcement mode`` rows and the table cells become readable.
    """

    panel = AuditPanelModel()
    panel.set_events(
        [
            Event(
                id="event-hook",
                timestamp=datetime(2026, 5, 21, 6, 27, 34),
                action="connector-hook",
                target="preToolUse",
                actor="defenseclaw",
                details=(
                    "action=allow severity=NONE mode=observe would_block=false "
                    "elapsed=320ms connector=claudecode "
                    "raw_payload=<redacted len=8 sha=84ed0c96>"
                ),
                severity="INFO",
                run_id="run-hook-1",
            )
        ]
    )

    panel.detail_open = True
    rows = panel.row_views()
    assert len(rows) == 1
    # Target column now reveals which framework emitted the hook so
    # operators can scan the table without opening every row.
    assert rows[0].target_label == "claudecode · preToolUse"
    # Details column collapses the kv blob into the highest-signal
    # tokens (decision, severity if elevated, elapsed). Severity=NONE
    # is dropped because it's the default for passing inspections.
    assert rows[0].details_label == "allow · 320ms"

    pairs = dict(panel.detail_pairs())
    # Each kv pair lands on its own labelled row. would_block=false
    # was filtered out because it's redundant in observe mode.
    assert pairs["Connector"] == "claudecode"
    assert pairs["Decision"] == "allow"
    assert pairs["Enforcement mode"] == "observe"
    assert pairs["Elapsed"] == "320ms"
    assert "Would block" not in pairs
    assert "Severity (decision)" not in pairs
    # The raw_payload digest gets translated into something humans can
    # actually read — the original ``<redacted len=8 sha=84ed0c96>``
    # placeholder told operators nothing.
    assert pairs["Raw payload"] == "redacted · 8 bytes · sha:84ed0c96"
    # The legacy ``Details`` blob is replaced by the structured rows;
    # we should not double-up.
    assert "Details" not in pairs

    # Detail-pane title surfaces connector + hook phase so users don't
    # see ``EVENT: connector-hook`` for every row.
    assert panel.selected_detail_title() == "EVENT: claudecode preToolUse"


def test_audit_non_hook_event_keeps_legacy_details_row() -> None:
    """Events without kv-shaped details fall back to the original
    single ``Details`` row so block/scan/config events keep their
    existing rendering."""

    panel = AuditPanelModel()
    panel.set_events(
        [
            Event(
                id="event-block",
                timestamp=datetime(2026, 5, 21, 6, 27, 34),
                action="block-skill",
                target="skill://malicious",
                actor="defenseclaw",
                details="Token leak detected in output",
                severity="HIGH",
            )
        ]
    )
    panel.detail_open = True
    pairs = dict(panel.detail_pairs())
    assert pairs["Details"] == "Token leak detected in output"
    assert panel.selected_detail_title() == "EVENT: block-skill"
    # Non-hook target column keeps its raw value (just truncated).
    assert panel.row_views()[0].target_label == "skill://malicious"


def test_audit_hook_blocked_decision_promotes_severity_in_summary() -> None:
    """When a hook actually blocks something we want the table cell to
    show ``block · HIGH`` so operators see the elevated risk without
    drilling in. The detail pane also keeps ``Would block`` because
    it's no longer just noise in enforce mode."""

    panel = AuditPanelModel()
    panel.set_events(
        [
            Event(
                id="event-block",
                timestamp=datetime(2026, 5, 21, 6, 27, 34),
                action="connector-hook",
                target="preToolUse",
                actor="defenseclaw",
                details=(
                    "action=block severity=HIGH mode=enforce would_block=true "
                    "elapsed=412ms connector=cursor reason=secret-detected"
                ),
                severity="HIGH",
            )
        ]
    )
    panel.detail_open = True
    row = panel.row_views()[0]
    assert row.target_label == "cursor · preToolUse"
    assert row.details_label == "block · HIGH · 412ms"
    pairs = dict(panel.detail_pairs())
    assert pairs["Decision"] == "block"
    # Reason explains *why* the block fired; previously buried in the
    # raw blob.
    assert pairs["Reason"] == "secret-detected"
    # In enforce mode would_block=true is meaningful — keep it.
    assert pairs["Would block"] == "yes"


def test_audit_connector_search_token_filters_by_parsed_connector() -> None:
    """WU10: per-connector filtering reuses the existing field-token
    search. ``connector:cursor`` matches hook rows whose kv ``details``
    carry ``connector=cursor``, so operators with multiple connectors
    can scope the audit feed without a dedicated column or chip."""

    panel = AuditPanelModel()
    base = datetime(2026, 5, 21, 6, 0, 0)
    panel.set_events(
        [
            Event(
                id="hook-cursor",
                timestamp=base,
                action="connector-hook",
                target="preToolUse",
                actor="defenseclaw",
                details="action=allow severity=NONE mode=observe connector=cursor",
                severity="INFO",
            ),
            Event(
                id="hook-codex",
                timestamp=base + timedelta(minutes=1),
                action="connector-hook",
                target="preToolUse",
                actor="defenseclaw",
                details="action=allow severity=NONE mode=observe connector=codex",
                severity="INFO",
            ),
        ]
    )

    panel.set_filter("connector:cursor")
    assert [event.id for event in panel.filtered] == ["hook-cursor"]

    panel.set_filter("connector:codex")
    assert [event.id for event in panel.filtered] == ["hook-codex"]

    # Unknown connector token matches nothing rather than falling back
    # to a loose substring hit elsewhere in the row.
    panel.set_filter("connector:nope")
    assert panel.filtered == []
