"""Shared read-only audit ordering used by doctor and TUI detail panels."""

import sqlite3

from defenseclaw.audit_time_order import audit_time_order
from defenseclaw.tui.panels.alerts import _list_events_by_target as alert_events_by_target
from defenseclaw.tui.panels.audit import _list_events_by_run_id, _list_events_by_target


class _Store:
    def __init__(self, db):
        self.db = db


def test_detail_readers_use_exact_time_and_insert_ties():
    db = sqlite3.connect(":memory:")
    db.execute("""CREATE TABLE audit_events (
        id TEXT PRIMARY KEY, timestamp TEXT, retention_timestamp_unix_nano INTEGER,
        action TEXT, target TEXT, actor TEXT, details TEXT, severity TEXT, run_id TEXT
    )""")
    for name, stamp, instant in (
        ("short", "2026-10-13T12:00:00.12345Z", 1),
        ("long", "2026-10-13T12:00:00.123451Z", 2),
        ("tie-first", "2026-10-13T12:00:01Z", 3),
        ("tie-second", "2026-10-13T12:00:01Z", 3),
        ("offset", "2026-10-13T14:00:02+02:00", 4),
    ):
        db.execute("""INSERT INTO audit_events VALUES (?, ?, ?, 'scan', 'target',
                    'operator', '', 'INFO', 'run')""", (name, stamp, instant))
    store = _Store(db)
    expected = ["offset", "tie-second", "tie-first", "long", "short"]
    assert [row.id for row in _list_events_by_target(store, "target", 5)] == expected
    assert [row.id for row in _list_events_by_run_id(store, "run", 5)] == expected
    assert [row.id for row in alert_events_by_target(store, "target", 5)] == expected
    assert audit_time_order(db) == "retention_timestamp_unix_nano DESC, rowid DESC"
