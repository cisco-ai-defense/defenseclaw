# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The Overview hook counter classifies each audit row once (rel-1-0-10:GAP-0340).

On a grown 6.4 GB store every connector_hook_event_stats call classified
every hook row's records again through the SQLite callbacks: 253 s with a
cold page cache, 18.7 s warm. The counter now keeps its totals by rowid
chunk and classifies only the rows written since its last call, plus the
chunks a retention pass, a purge or a late pairing changed. The counts stay
those of an all-time count (a fresh Store) after every kind of change.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

import defenseclaw.db as db_module
from defenseclaw.db import Store

_BASE = datetime(2026, 11, 17, 8, 0, 0, tzinfo=timezone.utc)

# What a 1.0.10 gateway adds when it opens the store
# (internal/audit/hook_row_tracking.go).
_HOOK_LONE_DDL = """
CREATE TABLE IF NOT EXISTS audit_hook_lone (
    audit_event_id TEXT PRIMARY KEY,
    semantic_event_id TEXT
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_audit_hook_lone_semantic ON audit_hook_lone(semantic_event_id)
    WHERE semantic_event_id IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS trg_audit_hook_lone_delete AFTER DELETE ON audit_events
    WHEN OLD.action = 'hook_decision'
    BEGIN
        DELETE FROM audit_hook_lone WHERE audit_event_id = OLD.id;
    END;
"""


class _Classified:
    """Counts the rows the counter's SQLite callbacks classify."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.rows = 0
        hook, row = db_module.aggregate_connector_hook_decision, db_module.aggregate_hook_row_decision

        def counted_hook(*args):
            self.rows += 1
            return hook(*args)

        def counted_row(*args):
            self.rows += 1
            return row(*args)

        monkeypatch.setattr(db_module, "aggregate_connector_hook_decision", counted_hook)
        monkeypatch.setattr(db_module, "aggregate_hook_row_decision", counted_row)

    def take(self) -> int:
        rows, self.rows = self.rows, 0
        return rows


def _open(path: str, tracked: bool) -> Store:
    store = Store(path)
    store.init()
    columns = {row[1] for row in store.db.execute("PRAGMA table_info(audit_events)")}
    for column in ("event_name", "payload_json", "projected_record_json", "bucket"):
        if column not in columns:
            store.db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
    store.db.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action)")
    if tracked:
        store.db.executescript(_HOOK_LONE_DDL)
    store.db.commit()
    return store


@pytest.fixture(params=["records", "hook-row-table"])
def path_and_kind(tmp_path, request):
    return str(tmp_path / "audit.db"), request.param == "hook-row-table"


def _body(action: str) -> dict:
    return {
        "defenseclaw.hook.event": "PreToolUse",
        "defenseclaw.guardrail.effective_action": action,
        "defenseclaw.guardrail.raw_action": action,
        "defenseclaw.guardrail.mode": "enforce",
        "defenseclaw.guardrail.enforced": action == "block",
    }


def _rows(start: int, count: int, tracked: bool) -> tuple[list[tuple], list[tuple]]:
    """Audit rows of a mixed store: connector-hook decisions of three
    connectors (allow, alert, block), their paired hook_decision rows, lone
    per-user allows, fail-mode lone decisions, proxy rows and unrelated rows."""

    audit: list[tuple] = []
    lone: list[tuple] = []
    for index in range(start, start + count):
        at = (_BASE + timedelta(milliseconds=index)).isoformat()
        kind = index % 7
        sid = f"sid-{index}"
        if kind in (0, 1, 2):
            connector = ("claudecode", "codex", "cursor")[kind]
            action = ("allow", "alert", "block")[index % 3]
            details = f"connector={connector} result=ok action={action} raw_action={action} mode=action"
            projected = json.dumps({"correlation": {"semantic_event_id": sid}})
            audit.append((f"ch-{index}", at, "connector-hook", details, None, connector,
                          1 if action == "block" else 0, None, projected))
            if kind == 0:
                audit.append((f"pair-{index}", at, "hook_decision", "hook_decision", None, connector, 0,
                               json.dumps(_body(action)), projected))
        elif kind in (3, 4):
            # A benign per-user allow (of record), or a fail-mode decision
            # awaiting its report.
            projected = json.dumps({"correlation": {"semantic_event_id": sid}, "body": _body("allow")})
            audit.append((f"lone-{index}", at, "hook_decision", "hook_decision", None, "claudecode", 0,
                           json.dumps(_body("allow" if kind == 3 else "alert")), projected))
            if tracked:
                lone.append((f"lone-{index}", None if kind == 3 else sid))
        elif kind == 5:
            action = ("inspect-tool-allow", "inspect-tool-block", "guardrail-verdict", "block")[index % 4]
            audit.append((f"px-{index}", at, action, "", None, "openclaw", 0, None, None))
        else:
            audit.append((f"other-{index}", at, "scan", "", None, "", 0, None, None))
    return audit, lone


def _insert(path: str, start: int, count: int, tracked: bool) -> None:
    audit, lone = _rows(start, count, tracked)
    connection = sqlite3.connect(path)
    connection.executemany(
        """INSERT INTO audit_events (id, timestamp, action, details, structured_json, connector, enforced,
               payload_json, projected_record_json, actor, severity)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'defenseclaw', 'INFO')""",
        audit,
    )
    if tracked:
        connection.executemany("INSERT OR REPLACE INTO audit_hook_lone VALUES (?, ?)", lone)
    connection.commit()
    connection.close()


def _change(path: str, *statements: str) -> None:
    """Another connection changes the store, as the gateway's retention does."""

    connection = sqlite3.connect(path)
    for statement in statements:
        connection.execute(statement)
    connection.commit()
    connection.close()


def _all_time(path: str) -> dict:
    fresh = Store.open_read_only(path, timeout=1.0)
    try:
        return fresh.connector_hook_event_stats()
    finally:
        fresh.close()


def test_a_second_count_classifies_only_the_rows_written_since(path_and_kind, monkeypatch) -> None:
    path, tracked = path_and_kind
    _open(path, tracked).close()
    _insert(path, 0, 20_000, tracked)
    classified = _Classified(monkeypatch)
    store = Store.open_read_only(path, timeout=1.0)
    try:
        first = store.connector_hook_event_stats()
        assert classified.take() >= 10_000
        assert first["claudecode"]["calls"] > 0 and first["openclaw"]["blocks"] > 0
        _insert(path, 20_000, 14, tracked)
        second = store.connector_hook_event_stats()
        new_rows = classified.take()
        # 14 new rows: only the 10 connector-hook and hook_decision rows
        # among them are classified, each at most twice (once per counted
        # decision column). A store with no audit_hook_lone adds the
        # all-time projected-record pass of its lone rows.
        if tracked:
            assert new_rows <= 2 * 10, new_rows
        assert second == _all_time(path)
        assert second != first
        classified.take()  # the all-time count's own rows
        assert store.connector_hook_event_stats() == second
        if tracked:
            assert classified.take() == 0
    finally:
        store.close()


def test_retention_recounts_only_the_chunks_it_changed(path_and_kind, monkeypatch) -> None:
    path, tracked = path_and_kind
    monkeypatch.setattr(db_module, "_HOOK_STATS_CHUNK_BITS", 8)
    _open(path, tracked).close()
    _insert(path, 0, 4_000, tracked)
    classified = _Classified(monkeypatch)
    store = Store.open_read_only(path, timeout=1.0)
    try:
        store.connector_hook_event_stats()
        classified.take()
        # A retention pass deletes the oldest rows: chunks it empties are
        # dropped unread, the partly deleted chunk is counted again.
        _change(path, "DELETE FROM audit_events WHERE rowid <= 1000")
        stats = store.connector_hook_event_stats()
        recount = classified.take()
        assert stats == _all_time(path)
        if tracked:
            assert recount <= 2 * 256, recount
    finally:
        store.close()


def test_the_counts_match_an_all_time_count_after_every_change(path_and_kind, monkeypatch) -> None:
    path, tracked = path_and_kind
    monkeypatch.setattr(db_module, "_HOOK_STATS_CHUNK_BITS", 6)
    _open(path, tracked).close()
    _insert(path, 0, 1_500, tracked)
    store = Store.open_read_only(path, timeout=1.0)
    try:
        steps = [
            ("first count", ()),
            ("new rows", ("insert", 1_500, 40)),
            ("oldest rows deleted", ("DELETE FROM audit_events WHERE rowid <= 300",)),
            ("rows deleted in the middle", ("DELETE FROM audit_events WHERE rowid % 11 = 0 AND rowid < 1200",)),
            ("one hook row deleted", ("DELETE FROM audit_events WHERE id = 'ch-1400'",)),
            # A connector-hook report row pairs a fail-mode lone decision.
            ("late pairing", ("DELETE FROM audit_hook_lone WHERE semantic_event_id = 'sid-1201'",)
             if tracked else ()),
            ("newest row deleted, its rowid reused",
             ("DELETE FROM audit_events WHERE rowid = (SELECT MAX(rowid) FROM audit_events)", ("insert", 2_000, 3))),
            ("VACUUM renumbers the rows", ("VACUUM",)),
            ("more rows", ("insert", 3_000, 200)),
            ("purge", ("DELETE FROM audit_events",)),
            ("rows after the purge", ("insert", 5_000, 30)),
        ]
        for name, actions in steps:
            if actions and isinstance(actions[0], str) and actions[0] == "insert":
                actions = (actions,)
            for action in actions:
                if isinstance(action, tuple):
                    _insert(path, action[1], action[2], tracked)
                else:
                    _change(path, action)
            got = store.connector_hook_event_stats()
            assert got == _all_time(path), name
    finally:
        store.close()


def test_a_failed_count_leaves_no_partial_totals(path_and_kind, monkeypatch) -> None:
    path, tracked = path_and_kind
    monkeypatch.setattr(db_module, "_HOOK_STATS_CHUNK_BITS", 6)
    _open(path, tracked).close()
    _insert(path, 0, 600, tracked)
    store = Store.open_read_only(path, timeout=1.0)
    try:
        store.connector_hook_event_stats()
        _insert(path, 600, 70, tracked)
        real = store._hook_stats_pass
        calls = {"n": 0}

        def failing(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return real(*args, **kwargs)
            raise sqlite3.OperationalError("interrupted")

        _change(path, "DELETE FROM audit_events WHERE rowid <= 100")
        monkeypatch.setattr(store, "_hook_stats_pass", failing)
        with pytest.raises(sqlite3.OperationalError):
            store.connector_hook_event_stats()
        monkeypatch.setattr(store, "_hook_stats_pass", real)
        assert store.connector_hook_event_stats() == _all_time(path)
    finally:
        store.close()
