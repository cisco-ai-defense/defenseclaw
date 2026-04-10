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

from defenseclaw.models import ActionEntry, ActionState, Counts, Event, SignatureEntry

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

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_scan_scanner ON scan_results(scanner);
CREATE INDEX IF NOT EXISTS idx_finding_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_finding_scan ON findings(scan_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_type_name ON actions(target_type, target_name);

CREATE TABLE IF NOT EXISTS signatures (
    id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_name TEXT NOT NULL,
    publisher TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    verified_at DATETIME,
    content_hash TEXT,
    reason TEXT,
    UNIQUE(target_type, target_name)
);

CREATE INDEX IF NOT EXISTS idx_signatures_target ON signatures(target_type, target_name);
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
        self.db = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        self.db.execute("PRAGMA journal_mode=WAL")

    def init(self) -> None:
        self.db.executescript(SCHEMA)
        self._ensure_run_id_columns()
        self._migrate_old_lists()

    def close(self) -> None:
        self.db.close()

    # -- Old list migration (matches Go migrateOldLists) --

    def _migrate_old_lists(self) -> None:
        cur = self.db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='block_list'")
        block_exists = cur.fetchone()[0] > 0
        cur = self.db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='allow_list'")
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
            columns = {row[1] for row in self.db.execute(f"PRAGMA table_info({table})").fetchall()}
            if "run_id" in columns:
                continue
            self.db.execute(f"ALTER TABLE {table} ADD COLUMN run_id TEXT")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_audit_run_id ON audit_events(run_id)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_scan_run_id ON scan_results(run_id)")
        self.db.commit()

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
            (
                event.id,
                event.timestamp.isoformat(),
                event.action,
                event.target or None,
                event.actor,
                event.details or None,
                event.severity or None,
                event.run_id or None,
            ),
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

    # -- Scan results --

    def insert_scan_result(
        self,
        scan_id: str,
        scanner: str,
        target: str,
        ts: datetime,
        duration_ms: int,
        finding_count: int,
        max_severity: str,
        raw_json: str,
    ) -> None:
        run_id = _current_run_id()
        self.db.execute(
            """INSERT INTO scan_results
               (id, scanner, target, timestamp, duration_ms, finding_count, max_severity, raw_json, run_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                scanner,
                target,
                ts.isoformat(),
                duration_ms,
                finding_count,
                max_severity,
                raw_json,
                run_id or None,
            ),
        )
        self.db.commit()

    def insert_finding(
        self,
        finding_id: str,
        scan_id: str,
        severity: str,
        title: str,
        description: str,
        location: str,
        remediation: str,
        scanner: str,
        tags: str,
    ) -> None:
        self.db.execute(
            """INSERT INTO findings
               (id, scan_id, severity, title, description, location, remediation, scanner, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (finding_id, scan_id, severity, title, description, location, remediation, scanner, tags),
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
            results.append(
                {
                    "id": row[0],
                    "target": row[1],
                    "timestamp": _parse_ts(row[2]),
                    "finding_count": row[3] or 0,
                    "max_severity": row[4] or "INFO",
                    "raw_json": row[5] or "",
                }
            )
        return results

    def get_severity_counts_for_target(
        self,
        target: str,
        scanner: str,
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
        self,
        target: str,
        scanner: str,
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
        return [{"severity": r[0], "title": r[1], "location": r[2] or ""} for r in cur.fetchall()]

    # -- Actions --

    def set_action(
        self,
        target_type: str,
        target_name: str,
        source_path: str,
        state: ActionState,
        reason: str,
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
            (aid, target_type, target_name, source_path or None, actions_json, reason, now),
        )
        self.db.commit()

    def set_action_field(
        self,
        target_type: str,
        target_name: str,
        field: str,
        value: str,
        reason: str,
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
        self,
        field: str,
        value: str,
        target_type: str,
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
            alerts=_count("SELECT COUNT(*) FROM audit_events WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW')"),
            total_scans=_count("SELECT COUNT(*) FROM scan_results"),
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

    # --- Signature status ---

    def set_signature_status(
        self,
        target_type: str,
        target_name: str,
        publisher: str,
        fingerprint: str,
        verified: bool,
        content_hash: str,
        reason: str,
    ) -> None:
        sid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        cols = "id, target_type, target_name, publisher, fingerprint, verified, verified_at, content_hash, reason"
        self.db.execute(
            f"""INSERT INTO signatures ({cols})
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(target_type, target_name) DO UPDATE SET
                publisher = excluded.publisher,
                fingerprint = excluded.fingerprint,
                verified = excluded.verified,
                verified_at = excluded.verified_at,
                content_hash = excluded.content_hash,
                reason = excluded.reason""",
            (sid, target_type, target_name, publisher, fingerprint, int(verified), now, content_hash, reason),
        )
        self.db.commit()

    _SIG_COLS = "id, target_type, target_name, publisher, fingerprint, verified, verified_at, content_hash, reason"

    def get_signature_status(self, target_type: str, target_name: str) -> SignatureEntry | None:
        row = self.db.execute(
            f"SELECT {self._SIG_COLS} FROM signatures WHERE target_type = ? AND target_name = ?",
            (target_type, target_name),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_signature(row)

    def list_signatures(self, target_type: str = "") -> list[SignatureEntry]:
        if target_type:
            rows = self.db.execute(
                f"SELECT {self._SIG_COLS} FROM signatures WHERE target_type = ? ORDER BY verified_at DESC",
                (target_type,),
            ).fetchall()
        else:
            rows = self.db.execute(
                f"SELECT {self._SIG_COLS} FROM signatures ORDER BY verified_at DESC",
            ).fetchall()
        return [self._row_to_signature(r) for r in rows]

    @staticmethod
    def _row_to_signature(row: tuple[Any, ...]) -> SignatureEntry:
        return SignatureEntry(
            id=row[0],
            target_type=row[1],
            target_name=row[2],
            publisher=row[3] or "",
            fingerprint=row[4] or "",
            verified=bool(row[5]),
            verified_at=_parse_ts(row[6]),
            content_hash=row[7] or "",
            reason=row[8] or "",
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
