# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""One hook decision, one count, whichever rows the store keeps (S8 R4, #1384).

Since 1.0.10 a benign per-user allow keeps only its hook_decision row
locally; every other decision, and all 1.0.9 data, keeps the connector-hook
row and the hook_decision row of the same semantic event.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from defenseclaw.db import Store
from defenseclaw.hook_metrics import count_once_hook_rows, hook_row_decision
from defenseclaw.models import Event
from defenseclaw.tui.panels.audit import AuditPanelModel, _without_duplicate_hook_decisions

_BASE = datetime(2026, 11, 13, 8, 0, 0, tzinfo=timezone.utc)


def _body(action: str, raw: str, *, enforced: bool = False, mode: str = "enforce", reason: object = None) -> dict:
    body = {
        "defenseclaw.hook.event": "PreToolUse",
        "defenseclaw.hook.result": "ok",
        "defenseclaw.guardrail.effective_action": action,
        "defenseclaw.guardrail.raw_action": raw,
        "defenseclaw.guardrail.mode": mode,
        "defenseclaw.guardrail.would_block": False,
        "defenseclaw.guardrail.enforced": enforced,
        "defenseclaw.security.severity": "HIGH" if action == "block" else "INFO",
        "defenseclaw.guardrail.latency_ms": 12,
        "defenseclaw.guardrail.rule_ids": ["SEC-1"] if action == "block" else [],
        "user.id": "1000",
    }
    if reason is not None:
        body["defenseclaw.guardrail.reason"] = reason
    return body


def _projected(sid: str, body: dict | None = None) -> str:
    record: dict = {"correlation": {"semantic_event_id": sid, "session_id": "s-r4"}}
    if body is not None:
        record["body"] = body
    return json.dumps(record)


# The table and trigger a 1.0.10 gateway adds when it opens the store
# (internal/audit/hook_row_tracking.go, rel-1-0-10:GAP-0316); a store no
# 1.0.10 gateway has opened has neither, and the readers fall back to the
# projected records. Every reader test below runs on both kinds of store.
_HOOK_ROW_TRACKING_DDL = """
CREATE TABLE IF NOT EXISTS audit_hook_rows (
    audit_event_id TEXT PRIMARY KEY REFERENCES audit_events(id) ON DELETE CASCADE,
    semantic_event_id TEXT NOT NULL,
    connector_hook INTEGER NOT NULL CHECK (connector_hook IN (0, 1))
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_audit_hook_rows_semantic ON audit_hook_rows(semantic_event_id, connector_hook);
CREATE TRIGGER IF NOT EXISTS trg_audit_hook_rows_insert AFTER INSERT ON audit_events
    WHEN NEW.action IN ('hook_decision','connector-hook','connector-hook-synthetic')
     AND (CASE WHEN json_valid(COALESCE(NEW.projected_record_json,''))
          THEN json_extract(NEW.projected_record_json,'$.correlation.semantic_event_id') END) IS NOT NULL
    BEGIN
        INSERT OR REPLACE INTO audit_hook_rows (audit_event_id, semantic_event_id, connector_hook)
        VALUES (NEW.id, (CASE WHEN json_valid(COALESCE(NEW.projected_record_json,''))
                THEN json_extract(NEW.projected_record_json,'$.correlation.semantic_event_id') END),
                NEW.action <> 'hook_decision');
    END;
"""


@pytest.fixture(params=["records", "hook-row-table"])
def store(tmp_path, request):
    db = Store(str(tmp_path / "audit.db"))
    db.init()
    columns = {row[1] for row in db.db.execute("PRAGMA table_info(audit_events)")}
    for column in ("event_name", "payload_json", "projected_record_json", "bucket"):
        if column not in columns:
            db.db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
    if request.param == "hook-row-table":
        db.db.executescript(_HOOK_ROW_TRACKING_DDL)
    yield db
    db.close()


def _insert_connector_hook(store: Store, row_id: str, sid: str, at: datetime, action: str, *, enforced=None) -> None:
    structured = {"schema": "defenseclaw.hook.v1", "connector": "claudecode", "event": "PreToolUse",
                  "action": action, "raw_action": action, "mode": "action", "would_block": False}
    store.db.execute(
        """INSERT INTO audit_events (id, timestamp, action, target, actor, details, structured_json, severity,
               connector, enforced, bucket, event_name, payload_json, projected_record_json)
           VALUES (?, ?, 'connector-hook', 'PreToolUse', 'defenseclaw', ?, ?, 'INFO', 'claudecode', ?,
               'guardrail.evaluation', 'legacy.audit.connector.hook', NULL, ?)""",
        (row_id, at.isoformat(), f"connector=claudecode result=ok action={action} raw_action={action} mode=action "
         "would_block=false", json.dumps(structured), enforced, _projected(sid)),
    )


def _insert_hook_decision(store: Store, row_id: str, sid: str | None, at: datetime, body: dict, *,
                          enforced=None, payload: bool = True) -> None:
    projected = _projected(sid, body) if sid else json.dumps({"body": body})
    store.db.execute(
        """INSERT INTO audit_events (id, timestamp, action, target, actor, details, severity, connector, enforced,
               bucket, event_name, payload_json, projected_record_json)
           VALUES (?, ?, 'hook_decision', NULL, 'defenseclaw', 'hook_decision', 'INFO', 'claudecode', ?,
               'guardrail.evaluation', 'hook_decision', ?, ?)""",
        (row_id, at.isoformat(), enforced, json.dumps(body) if payload else None, projected),
    )


def _seed(store: Store) -> None:
    # 1.0.10 benign per-user allow: the hook_decision row alone.
    _insert_hook_decision(store, "lone-allow", "sid-a", _BASE, _body("allow", "allow"))
    # The same, with its body only in the projected record.
    _insert_hook_decision(store, "lone-allow-projected", "sid-d", _BASE + timedelta(seconds=1),
                          _body("allow", "allow"), payload=False)
    # A block keeps both rows.
    _insert_connector_hook(store, "block-ch", "sid-b", _BASE + timedelta(seconds=2), "block", enforced=1)
    _insert_hook_decision(store, "block-hd", "sid-b", _BASE + timedelta(seconds=2, milliseconds=3),
                          _body("block", "block", enforced=True), enforced=1)
    # A 1.0.9 allow: both rows.
    _insert_connector_hook(store, "old-allow-ch", "sid-c", _BASE + timedelta(seconds=3), "allow")
    _insert_hook_decision(store, "old-allow-hd", "sid-c", _BASE + timedelta(seconds=3, milliseconds=2),
                          _body("allow", "allow"))
    store.db.commit()


def test_decision_reads_both_row_kinds_alike() -> None:
    assert hook_row_decision("connector-hook", "connector=codex action=block raw_action=block mode=action", None, 1) \
        == "block"
    assert hook_row_decision("hook_decision", "", _body("block", "block", enforced=True)) == "block"
    # The body may come as JSON text (payload_json) too.
    assert hook_row_decision("hook_decision", "", json.dumps(_body("allow", "allow"))) == "allow"
    assert hook_row_decision("hook_decision", "", _body("allow", "alert", reason={"redacted": True})) == "alert"
    # Observe mode turns a block action into an alert, as for connector-hook rows.
    assert hook_row_decision("hook_decision", "", _body("block", "block", mode="observe")) == "alert"
    assert hook_row_decision("scan-finding", "action=block") == ""


def test_count_once_keeps_one_row_per_decision() -> None:
    rows = [
        Event(id="a", action="hook_decision", semantic_event_id="s1"),
        Event(id="b", action="connector-hook", semantic_event_id="s2"),
        Event(id="c", action="hook_decision", semantic_event_id="s2"),
        Event(id="d", action="hook_decision"),
        Event(id="e", action="scan-finding"),
    ]
    assert [row.id for row in count_once_hook_rows(rows)] == ["a", "b", "e"]


def test_hook_stats_count_each_decision_once(store: Store) -> None:
    _seed(store)
    stats = store.connector_hook_event_stats()
    assert stats["claudecode"]["calls"] == 4
    assert stats["claudecode"]["blocks"] == 1
    assert stats["claudecode"]["alerts"] == 0


def test_recent_hook_decisions_list_each_decision_once(store: Store) -> None:
    _seed(store)
    events = store.list_connector_hook_event_summaries(10)
    assert sorted(event.id for event in events) == ["block-ch", "lone-allow", "lone-allow-projected", "old-allow-ch"]
    by_id = {event.id: event for event in events}
    assert by_id["lone-allow"].target == "PreToolUse"
    assert hook_row_decision(by_id["lone-allow"].action, by_id["lone-allow"].details,
                             by_id["lone-allow"].structured, by_id["lone-allow"].enforced) == "allow"
    assert hook_row_decision(by_id["lone-allow-projected"].action, "", by_id["lone-allow-projected"].structured) \
        == "allow"
    assert hook_row_decision(by_id["block-ch"].action, by_id["block-ch"].details, by_id["block-ch"].structured,
                             by_id["block-ch"].enforced) == "block"
    # Newest first, as before.
    assert events[0].id == "old-allow-ch"
    assert len(store.list_connector_hook_event_summaries(2)) == 2


def test_audit_panel_shows_each_decision_once(store: Store) -> None:
    _seed(store)
    events = store.list_event_summaries(50)
    hook_rows = [event for event in _without_duplicate_hook_decisions(events)
                 if event.action in {"connector-hook", "hook_decision"}]
    assert sorted(event.id for event in hook_rows) == ["block-ch", "lone-allow", "lone-allow-projected",
                                                       "old-allow-ch"]
    model = AuditPanelModel(store)
    model.set_events(events)
    model.common_filter = "blocks"
    model.apply_filter()
    assert [event.id for event in model.filtered] == ["block-ch"]
    model.common_filter = ""
    model.show_all_events = True
    model.apply_filter()
    model.cursor = next(i for i, event in enumerate(model.filtered) if event.id == "lone-allow")
    assert model.selected_detail_title() == "EVENT: claudecode PreToolUse"


def test_routine_count_attributes_hook_decision_rows_by_column(store: Store) -> None:
    _seed(store)
    # Every seeded row is routine (INFO) and claudecode's; a hook_decision
    # row names its connector only in the column.
    assert store.count_routine_events() == 6
    assert store.count_routine_events("claudecode") == 6
    assert store.count_routine_events("codex") == 0


def _insert_synthetic_stop(store: Store, row_id: str, sid: str, at: datetime) -> None:
    structured = {"schema": "defenseclaw.hook.v1", "connector": "claudecode", "event": "Stop",
                  "action": "allow", "raw_action": "allow", "mode": "action", "would_block": False}
    store.db.execute(
        """INSERT INTO audit_events (id, timestamp, action, target, actor, details, structured_json, severity,
               connector, bucket, event_name, payload_json, projected_record_json)
           VALUES (?, ?, 'connector-hook-synthetic', 'Stop', 'defenseclaw', ?, ?, 'INFO', 'claudecode',
               'guardrail.evaluation', 'legacy.audit.connector.hook.synthetic', NULL, ?)""",
        (row_id, at.isoformat(), "connector=claudecode result=ok action=allow raw_action=allow mode=action",
         json.dumps(structured), _projected(sid)),
    )


def test_synthetic_stop_is_not_an_extra_decision(store: Store) -> None:
    """A synthetic Stop keeps its connector-hook-synthetic row and its
    hook_decision row (same semantic event): neither the recent list nor the
    overview totals show the hook_decision row as a decision of its own."""

    _seed(store)
    before_stats = store.connector_hook_event_stats()["claudecode"]["calls"]
    before_ids = sorted(event.id for event in store.list_connector_hook_event_summaries(10))
    at = _BASE + timedelta(seconds=5)
    _insert_synthetic_stop(store, "stop-syn", "sid-stop", at)
    body = _body("allow", "allow")
    body["defenseclaw.hook.event"] = "Stop"
    _insert_hook_decision(store, "stop-hd", "sid-stop", at + timedelta(milliseconds=1), body)
    store.db.commit()
    assert store.connector_hook_event_stats()["claudecode"]["calls"] == before_stats
    assert sorted(event.id for event in store.list_connector_hook_event_summaries(10)) == before_ids
    shown = [event.id for event in _without_duplicate_hook_decisions(store.list_event_summaries(50))]
    assert "stop-syn" in shown and "stop-hd" not in shown


def test_a_report_row_written_after_the_decision_pairs_it(store: Store) -> None:
    """The failure report writes a call's connector-hook row after its
    fail-mode hook_decision row: from then on the call counts once, from the
    report row (rel-1-0-10:GAP-0316, any write order)."""

    _insert_hook_decision(store, "late-hd", "sid-late", _BASE, _body("allow", "alert"))
    store.db.commit()
    assert store.connector_hook_event_stats()["claudecode"]["calls"] == 1
    _insert_connector_hook(store, "late-report", "sid-late", _BASE + timedelta(seconds=9), "alert")
    store.db.commit()
    assert store.connector_hook_event_stats()["claudecode"]["calls"] == 1


class _CapturingConnection:
    def __init__(self, connection):
        self._connection = connection
        self.statements: list[tuple[str, tuple]] = []

    def execute(self, sql, *args):
        self.statements.append((sql, args))
        return self._connection.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._connection, name)


def test_overview_counter_reads_the_hook_row_table_not_the_records(tmp_path) -> None:
    """With audit_hook_rows the Overview counter finds lone hook_decision
    rows through that table: no pass over every hook row's projected record
    (on a grown 6.4 GB store that pass read about 1.1 GB, rel-1-0-10:GAP-0316)."""

    db = Store(str(tmp_path / "audit.db"))
    db.init()
    columns = {row[1] for row in db.db.execute("PRAGMA table_info(audit_events)")}
    for column in ("event_name", "payload_json", "projected_record_json", "bucket"):
        if column not in columns:
            db.db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
    db.db.executescript(_HOOK_ROW_TRACKING_DDL)
    _seed(db)
    connection = db.db
    capture = _CapturingConnection(connection)
    db.db = capture
    try:
        assert db.connector_hook_event_stats()["claudecode"]["calls"] == 4
    finally:
        db.db = connection
    counter = [(sql, args) for sql, args in capture.statements if "connector_name" in sql and "hook_decision" in sql]
    assert counter, "the hook counter statement was not captured"
    sql, args = counter[0]
    plan = " | ".join(row[3] for row in connection.execute("EXPLAIN QUERY PLAN " + sql, *args))
    assert "audit_hook_rows" in plan, plan
    assert "LIST SUBQUERY" not in plan, plan
    db.close()
