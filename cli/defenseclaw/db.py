# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""SQLite audit store — mirrors internal/audit/store.go.

Uses the exact same schema so the Go orchestrator and Python CLI
can share the same database file.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from defenseclaw.models import ActionEntry, ActionState, Counts, Event, TargetSnapshot

SCHEMA = """\
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    actor TEXT NOT NULL DEFAULT 'defenseclaw',
    details TEXT,
    severity TEXT,
    run_id TEXT
);

CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    scanner TEXT NOT NULL,
    target TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    duration_ms INTEGER,
    finding_count INTEGER,
    max_severity TEXT,
    raw_json TEXT,
    run_id TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    location TEXT,
    remediation TEXT,
    scanner TEXT NOT NULL,
    tags TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_results(id)
);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_name TEXT NOT NULL,
    source_path TEXT,
    actions_json TEXT NOT NULL DEFAULT '{}',
    reason TEXT,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS network_egress_events (
    id TEXT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    session_id TEXT,
    hostname TEXT NOT NULL,
    url TEXT,
    http_method TEXT,
    protocol TEXT,
    policy_outcome TEXT NOT NULL,
    decision_code TEXT,
    blocked INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'INFO',
    details TEXT
);

CREATE TABLE IF NOT EXISTS target_snapshots (
    id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    dependency_hashes TEXT,
    config_hashes TEXT,
    network_endpoints TEXT,
    scan_id TEXT,
    captured_at DATETIME NOT NULL,
    UNIQUE(target_type, target_path)
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_scan_scanner ON scan_results(scanner);
CREATE INDEX IF NOT EXISTS idx_finding_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_finding_scan ON findings(scan_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_type_name ON actions(target_type, target_name);
CREATE INDEX IF NOT EXISTS idx_egress_timestamp ON network_egress_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_egress_hostname ON network_egress_events(hostname);
CREATE INDEX IF NOT EXISTS idx_egress_blocked ON network_egress_events(blocked);
CREATE INDEX IF NOT EXISTS idx_egress_session ON network_egress_events(session_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_target ON target_snapshots(target_type, target_path);
"""

# v7 tables (mirrors Go migrations 8–9). Created idempotently for CLI tests
# against DBs that were not opened by the Go sidecar yet.
_V7_EXTRA_DDL = """
CREATE TABLE IF NOT EXISTS activity_events (
    id TEXT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    reason TEXT,
    before_json TEXT,
    after_json TEXT,
    diff_json TEXT,
    version_from TEXT,
    version_to TEXT,
    request_id TEXT,
    trace_id TEXT,
    run_id TEXT,
    schema_version INTEGER,
    content_hash TEXT,
    generation INTEGER,
    binary_version TEXT,
    agent_id TEXT,
    sidecar_instance_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_actor ON activity_events(actor);
CREATE INDEX IF NOT EXISTS idx_activity_action ON activity_events(action);
CREATE INDEX IF NOT EXISTS idx_activity_target ON activity_events(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_activity_generation ON activity_events(generation);
CREATE TABLE IF NOT EXISTS sink_health (
    id TEXT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    sink_name TEXT NOT NULL,
    sink_kind TEXT NOT NULL,
    outcome TEXT NOT NULL,
    status_code INTEGER,
    latency_ms INTEGER,
    batch_size INTEGER,
    error TEXT,
    queue_depth INTEGER,
    dropped_count INTEGER,
    schema_version INTEGER,
    content_hash TEXT,
    generation INTEGER,
    binary_version TEXT,
    sidecar_instance_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_sink_health_timestamp ON sink_health(timestamp);
CREATE INDEX IF NOT EXISTS idx_sink_health_sink ON sink_health(sink_name);
CREATE INDEX IF NOT EXISTS idx_sink_health_outcome ON sink_health(outcome);
"""

_VALID_FIELDS: dict[str, set[str]] = {
    "install": {"", "block", "allow", "none"},
    "file": {"", "quarantine", "none"},
    "runtime": {"", "disable", "enable"},
}


def _validate(field: str, value: str) -> None:
    valid = _VALID_FIELDS.get(field)
    if valid is None:
        raise ValueError(f"audit: invalid action field {field!r}")
    if value not in valid:
        raise ValueError(f"audit: invalid {field} action value {value!r}")


class Store:
    def __init__(self, db_path: str) -> None:
        self.db = sqlite3.connect(
            db_path, detect_types=sqlite3.PARSE_DECLTYPES, timeout=5.0,
        )
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")

    def init(self) -> None:
        self.db.executescript(SCHEMA)
        self._ensure_run_id_columns()
        self._migrate_old_lists()
        self._ensure_v7_tables()

    def close(self) -> None:
        self.db.close()

    # -- Old list migration (matches Go migrateOldLists) --

    def _migrate_old_lists(self) -> None:
        cur = self.db.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='block_list'"
        )
        block_exists = cur.fetchone()[0] > 0
        cur = self.db.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='allow_list'"
        )
        allow_exists = cur.fetchone()[0] > 0

        if not block_exists and not allow_exists:
            return

        if block_exists:
            self.db.execute(
                """INSERT OR REPLACE INTO actions
                   (id, target_type, target_name, source_path, actions_json, reason, updated_at)
                   SELECT id, target_type, target_name, NULL, '{"install":"block"}', reason, created_at
                   FROM block_list"""
            )
        if allow_exists:
            self.db.execute(
                """INSERT OR REPLACE INTO actions
                   (id, target_type, target_name, source_path, actions_json, reason, updated_at)
                   SELECT id, target_type, target_name, NULL, '{"install":"allow"}', reason, created_at
                   FROM allow_list"""
            )
        self.db.execute("DROP TABLE IF EXISTS block_list")
        self.db.execute("DROP TABLE IF EXISTS allow_list")
        self.db.commit()

    def _ensure_run_id_columns(self) -> None:
        for table in ("audit_events", "scan_results"):
            columns = {
                row[1]
                for row in self.db.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if "run_id" in columns:
                continue
            self.db.execute(f"ALTER TABLE {table} ADD COLUMN run_id TEXT")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_audit_run_id ON audit_events(run_id)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_scan_run_id ON scan_results(run_id)")
        self.db.commit()

    def _ensure_v7_tables(self) -> None:
        self.db.executescript(_V7_EXTRA_DDL)
        self.db.commit()

    def insert_activity_event(
        self,
        activity_id: str,
        *,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        reason: str = "",
        before_json: str = "",
        after_json: str = "",
        diff_json: str = "",
        version_from: str = "",
        version_to: str = "",
        run_id: str = "",
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        rid = run_id or _current_run_id()
        self.db.execute(
            """INSERT INTO activity_events (
                id, timestamp, actor, action, target_type, target_id, reason,
                before_json, after_json, diff_json, version_from, version_to,
                run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                activity_id,
                ts,
                actor,
                action,
                target_type,
                target_id,
                reason or None,
                before_json or None,
                after_json or None,
                diff_json or None,
                version_from or None,
                version_to or None,
                rid or None,
            ),
        )
        self.db.commit()

    def get_activity_event(self, activity_id: str) -> dict[str, Any] | None:
        cur = self.db.execute(
            """SELECT id, timestamp, actor, action, target_type, target_id, reason,
                      before_json, after_json, diff_json, version_from, version_to, run_id
               FROM activity_events WHERE id = ?""",
            (activity_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {
            "id": row[0],
            "timestamp": row[1],
            "actor": row[2],
            "action": row[3],
            "target_type": row[4],
            "target_id": row[5],
            "reason": row[6] or "",
            "before_json": row[7] or "",
            "after_json": row[8] or "",
            "diff_json": row[9] or "",
            "version_from": row[10] or "",
            "version_to": row[11] or "",
            "run_id": row[12] or "",
        }

    # -- Audit events --

    def log_event(self, event: Event) -> None:
        if not event.id:
            event.id = str(uuid.uuid4())
        if event.timestamp is None:
            event.timestamp = datetime.now(timezone.utc)
        if not event.actor:
            event.actor = "defenseclaw"
        if not event.run_id:
            event.run_id = _current_run_id()
        self.db.execute(
            """INSERT INTO audit_events (id, timestamp, action, target, actor, details, severity, run_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (event.id, event.timestamp.isoformat(), event.action,
             event.target or None, event.actor, event.details or None,
             event.severity or None, event.run_id or None),
        )
        self.db.commit()

    def list_events(self, limit: int = 100) -> list[Event]:
        cur = self.db.execute(
            """SELECT id, timestamp, action, target, actor, details, severity, run_id
               FROM audit_events ORDER BY timestamp DESC LIMIT ?""",
            (max(limit, 1),),
        )
        return [self._row_to_event(r) for r in cur.fetchall()]

    def list_alerts(self, limit: int = 100) -> list[Event]:
        cur = self.db.execute(
            """SELECT id, timestamp, action, target, actor, details, severity, run_id
               FROM audit_events
               WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW','ERROR','INFO')
                 AND action NOT LIKE 'dismiss%'
               ORDER BY timestamp DESC LIMIT ?""",
            (max(limit, 1),),
        )
        return [self._row_to_event(r) for r in cur.fetchall()]

    def acknowledge_alerts(self, severity_filter: str = "all") -> int:
        """Mirror internal/audit/store.go AcknowledgeAlerts — rows updated."""
        if severity_filter in ("", "all"):
            cur = self.db.execute(
                """UPDATE audit_events SET severity = 'ACK'
                   WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW')""",
            )
        else:
            cur = self.db.execute(
                "UPDATE audit_events SET severity = 'ACK' WHERE severity = ?",
                (severity_filter,),
            )
        self.db.commit()
        return int(cur.rowcount or 0)

    def dismiss_alerts_visible(self, severity_filter: str = "all") -> int:
        """Clear visible alerts by downgrading severity (parity with acknowledge for SQLite schema)."""
        return self.acknowledge_alerts(severity_filter)

    # -- Scan results --

    def insert_scan_result(
        self, scan_id: str, scanner: str, target: str,
        ts: datetime, duration_ms: int, finding_count: int,
        max_severity: str, raw_json: str,
    ) -> None:
        run_id = _current_run_id()
        self.db.execute(
            """INSERT INTO scan_results
               (id, scanner, target, timestamp, duration_ms, finding_count, max_severity, raw_json, run_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, scanner, target, ts.isoformat(), duration_ms,
             finding_count, max_severity, raw_json, run_id or None),
        )
        self.db.commit()

    def insert_finding(
        self, finding_id: str, scan_id: str, severity: str,
        title: str, description: str, location: str,
        remediation: str, scanner: str, tags: str,
    ) -> None:
        self.db.execute(
            """INSERT INTO findings
               (id, scan_id, severity, title, description, location, remediation, scanner, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (finding_id, scan_id, severity, title, description,
             location, remediation, scanner, tags),
        )
        self.db.commit()

    # -- Latest scans (for merged skill list) --

    def latest_scans_by_scanner(self, scanner_name: str) -> list[dict[str, Any]]:
        """Return the latest scan result per target for a given scanner.

        Each dict has keys: id, target, timestamp, finding_count, max_severity, raw_json.
        Mirrors Go Store.LatestScansByScanner().
        """
        cur = self.db.execute(
            """SELECT sr.id, sr.target, sr.timestamp, sr.finding_count,
                      sr.max_severity, sr.raw_json
               FROM scan_results sr
               INNER JOIN (
                   SELECT target, MAX(timestamp) as max_ts
                   FROM scan_results
                   WHERE scanner = ?
                   GROUP BY target
               ) latest ON sr.target = latest.target AND sr.timestamp = latest.max_ts
               WHERE sr.scanner = ?""",
            (scanner_name, scanner_name),
        )
        results: list[dict[str, Any]] = []
        for row in cur.fetchall():
            results.append({
                "id": row[0],
                "target": row[1],
                "timestamp": _parse_ts(row[2]),
                "finding_count": row[3] or 0,
                "max_severity": row[4] or "INFO",
                "raw_json": row[5] or "",
            })
        return results

    def get_severity_counts_for_target(
        self, target: str, scanner: str,
    ) -> dict[str, int]:
        """Return {severity: count} from the most recent scan for target+scanner."""
        cur = self.db.execute(
            """SELECT f.severity, COUNT(*) as cnt
               FROM findings f
               INNER JOIN scan_results sr ON f.scan_id = sr.id
               WHERE sr.id = (
                   SELECT id FROM scan_results
                   WHERE target = ? AND scanner = ?
                   ORDER BY timestamp DESC LIMIT 1
               )
               GROUP BY f.severity""",
            (target, scanner),
        )
        return {row[0]: row[1] for row in cur.fetchall()}

    def get_findings_for_target(
        self, target: str, scanner: str,
    ) -> list[dict[str, Any]]:
        """Return findings from the most recent scan for target+scanner."""
        cur = self.db.execute(
            """SELECT f.severity, f.title, f.location
               FROM findings f
               INNER JOIN scan_results sr ON f.scan_id = sr.id
               WHERE sr.id = (
                   SELECT id FROM scan_results
                   WHERE target = ? AND scanner = ?
                   ORDER BY timestamp DESC LIMIT 1
               )
               ORDER BY CASE f.severity
                   WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                   WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END""",
            (target, scanner),
        )
        return [
            {"severity": r[0], "title": r[1], "location": r[2] or ""}
            for r in cur.fetchall()
        ]

    # -- Actions --

    def set_action(
        self, target_type: str, target_name: str,
        source_path: str, state: ActionState, reason: str,
    ) -> None:
        actions_json = json.dumps(state.to_dict())
        aid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute(
            """INSERT INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(target_type, target_name) DO UPDATE SET
                 actions_json = excluded.actions_json,
                 reason = excluded.reason,
                 updated_at = excluded.updated_at,
                 source_path = COALESCE(excluded.source_path, source_path)""",
            (aid, target_type, target_name, source_path or None,
             actions_json, reason, now),
        )
        self.db.commit()

    def set_action_field(
        self, target_type: str, target_name: str,
        field: str, value: str, reason: str,
    ) -> None:
        _validate(field, value)
        aid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        init_json = json.dumps({field: value})
        path = f"$.{field}"
        self.db.execute(
            """INSERT INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)
               VALUES (?, ?, ?, NULL, ?, ?, ?)
               ON CONFLICT(target_type, target_name) DO UPDATE SET
                 actions_json = json_set(actions_json, ?, ?),
                 reason = excluded.reason,
                 updated_at = excluded.updated_at""",
            (aid, target_type, target_name, init_json, reason, now, path, value),
        )
        self.db.commit()

    def clear_action_field(self, target_type: str, target_name: str, field: str) -> None:
        _validate(field, "")
        path = f"$.{field}"
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute(
            """UPDATE actions SET actions_json = json_remove(actions_json, ?), updated_at = ?
               WHERE target_type = ? AND target_name = ?""",
            (path, now, target_type, target_name),
        )
        self.db.execute(
            """DELETE FROM actions WHERE target_type = ? AND target_name = ?
               AND actions_json IN ('{}', 'null', '')""",
            (target_type, target_name),
        )
        self.db.commit()

    def set_source_path(self, target_type: str, target_name: str, path: str) -> None:
        self.db.execute(
            "UPDATE actions SET source_path = ? WHERE target_type = ? AND target_name = ?",
            (path, target_type, target_name),
        )
        self.db.commit()

    def remove_action(self, target_type: str, target_name: str) -> None:
        self.db.execute(
            "DELETE FROM actions WHERE target_type = ? AND target_name = ?",
            (target_type, target_name),
        )
        self.db.commit()

    def get_action(self, target_type: str, target_name: str) -> ActionEntry | None:
        cur = self.db.execute(
            """SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at
               FROM actions WHERE target_type = ? AND target_name = ?""",
            (target_type, target_name),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_action(row)

    def has_action(self, target_type: str, target_name: str, field: str, value: str) -> bool:
        _validate(field, value)
        cur = self.db.execute(
            f"""SELECT COUNT(*) FROM actions
                WHERE target_type = ? AND target_name = ?
                AND json_extract(actions_json, '$.{field}') = ?""",
            (target_type, target_name, value),
        )
        return cur.fetchone()[0] > 0

    def list_by_action(self, field: str, value: str) -> list[ActionEntry]:
        _validate(field, value)
        cur = self.db.execute(
            f"""SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at
                FROM actions WHERE json_extract(actions_json, '$.{field}') = ?
                ORDER BY updated_at DESC""",
            (value,),
        )
        return [self._row_to_action(r) for r in cur.fetchall()]

    def list_by_action_and_type(
        self, field: str, value: str, target_type: str,
    ) -> list[ActionEntry]:
        _validate(field, value)
        cur = self.db.execute(
            f"""SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at
                FROM actions WHERE json_extract(actions_json, '$.{field}') = ? AND target_type = ?
                ORDER BY updated_at DESC""",
            (value, target_type),
        )
        return [self._row_to_action(r) for r in cur.fetchall()]

    def list_actions_by_type(self, target_type: str) -> list[ActionEntry]:
        cur = self.db.execute(
            """SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at
               FROM actions WHERE target_type = ? ORDER BY updated_at DESC""",
            (target_type,),
        )
        return [self._row_to_action(r) for r in cur.fetchall()]

    def list_all_actions(self) -> list[ActionEntry]:
        cur = self.db.execute(
            """SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at
               FROM actions ORDER BY updated_at DESC"""
        )
        return [self._row_to_action(r) for r in cur.fetchall()]

    def get_counts(self) -> Counts:
        def _count(sql: str) -> int:
            return self.db.execute(sql).fetchone()[0]

        q_skill = "SELECT COUNT(*) FROM actions WHERE target_type='skill' AND json_extract(actions_json,'$.install')="
        q_mcp = "SELECT COUNT(*) FROM actions WHERE target_type='mcp' AND json_extract(actions_json,'$.install')="
        return Counts(
            blocked_skills=_count(q_skill + "'block'"),
            allowed_skills=_count(q_skill + "'allow'"),
            blocked_mcps=_count(q_mcp + "'block'"),
            allowed_mcps=_count(q_mcp + "'allow'"),
            alerts=_count(
                "SELECT COUNT(*) FROM audit_events WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW')"
            ),
            total_scans=_count("SELECT COUNT(*) FROM scan_results"),
            blocked_egress_calls=_count(
                "SELECT COUNT(*) FROM network_egress_events WHERE blocked = 1"
            ),
        )

    # -- Row converters --

    @staticmethod
    def _row_to_event(row: tuple[Any, ...]) -> Event:
        return Event(
            id=row[0],
            timestamp=_parse_ts(row[1]),
            action=row[2],
            target=row[3] or "",
            actor=row[4],
            details=row[5] or "",
            severity=row[6] or "",
            run_id=row[7] or "",
        )

    def get_target_snapshot(
        self, target_type: str, target_path: str
    ) -> TargetSnapshot | None:
        row = self.db.execute(
            "SELECT id, target_type, target_path, content_hash,"
            " dependency_hashes, config_hashes, network_endpoints,"
            " scan_id, captured_at"
            " FROM target_snapshots"
            " WHERE target_type = ? AND target_path = ?",
            (target_type, target_path),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_snapshot(row)

    def list_drift_events(self, limit: int = 50) -> list[Event]:
        rows = self.db.execute(
            "SELECT id, timestamp, action, target, actor,"
            " details, severity, run_id"
            " FROM audit_events WHERE action = 'drift'"
            " ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_event(r) for r in rows]

    @staticmethod
    def _row_to_snapshot(row: tuple[Any, ...]) -> TargetSnapshot:
        dep_raw = row[4] or "{}"
        cfg_raw = row[5] or "{}"
        ep_raw = row[6] or "[]"
        try:
            dep = json.loads(dep_raw)
        except (json.JSONDecodeError, TypeError):
            dep = {}
        try:
            cfg = json.loads(cfg_raw)
        except (json.JSONDecodeError, TypeError):
            cfg = {}
        try:
            eps = json.loads(ep_raw)
        except (json.JSONDecodeError, TypeError):
            eps = []
        return TargetSnapshot(
            id=row[0],
            target_type=row[1],
            target_path=row[2],
            content_hash=row[3],
            dependency_hashes=dep,
            config_hashes=cfg,
            network_endpoints=eps,
            scan_id=row[7] or "",
            captured_at=_parse_ts(row[8]),
        )

    @staticmethod
    def _row_to_action(row: tuple[Any, ...]) -> ActionEntry:
        actions_raw = row[4] or "{}"
        try:
            actions_dict = json.loads(actions_raw)
        except (json.JSONDecodeError, TypeError):
            actions_dict = {}
        return ActionEntry(
            id=row[0],
            target_type=row[1],
            target_name=row[2],
            source_path=row[3] or "",
            actions=ActionState.from_dict(actions_dict),
            reason=row[5] or "",
            updated_at=_parse_ts(row[6]),
        )


def _parse_ts(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
    return datetime.now(timezone.utc)


def _current_run_id() -> str:
    return os.environ.get("DEFENSECLAW_RUN_ID", "").strip()
