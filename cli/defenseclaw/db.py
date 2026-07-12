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
import math
import os
import sqlite3
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
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
    structured_json TEXT,
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
    updated_at DATETIME NOT NULL,
    connector TEXT NOT NULL DEFAULT ''
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
CREATE INDEX IF NOT EXISTS idx_audit_action_timestamp ON audit_events(action, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_severity_timestamp ON audit_events(severity, timestamp);
CREATE INDEX IF NOT EXISTS idx_scan_scanner ON scan_results(scanner);
CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_results(timestamp);
CREATE INDEX IF NOT EXISTS idx_finding_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_finding_scan ON findings(scan_id);
-- The actions uniqueness index is connector-aware (target_type, target_name,
-- connector) and is created/migrated in _ensure_connector_column(). It is
-- deliberately NOT declared here: executescript(SCHEMA) runs on every init(),
-- so a 2-column UNIQUE index declared here would be recreated each open and
-- would reject per-connector rows (SK-4).
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
_SUMMARY_DETAILS_BYTES = 4096


def _validate(field: str, value: str) -> None:
    valid = _VALID_FIELDS.get(field)
    if valid is None:
        raise ValueError(f"audit: invalid action field {field!r}")
    if value not in valid:
        raise ValueError(f"audit: invalid {field} action value {value!r}")


class Store:
    def __init__(
        self,
        db_path: str,
        *,
        read_only: bool = False,
        timeout: float = 5.0,
    ) -> None:
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("audit: SQLite timeout must be finite and non-negative")
        busy_timeout_ms = int(timeout * 1000)

        self.read_only = read_only
        self._scan_results_has_retention_timestamp: bool | None = None
        newly_created = not read_only and self._db_will_be_created(db_path)
        connect_path = self._read_only_uri(db_path) if read_only else db_path
        self.db = sqlite3.connect(
            connect_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
            timeout=timeout,
            uri=read_only,
        )
        if read_only:
            # ``mode=ro`` prevents file writes while ``query_only`` also
            # rejects accidental mutations through writable attached DBs.
            # In particular, do not run the journal-mode pragma here: a TUI
            # reader must never attempt to change writer-owned journal state.
            self.db.execute("PRAGMA query_only=ON")
        else:
            self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        # The audit DB stores audit events, scan results, findings, raw
        # scanner JSON, target paths, and action decisions, so it must be
        # private to the operator / service account. sqlite3.connect()
        # honours the process umask, which can leave a freshly created DB
        # world- or group-readable (F-0083). Pin the file to owner-only
        # (0600) and, for a DB we just created, drop world access on the
        # parent directory so a different local user cannot traverse to it.
        if not read_only:
            self._harden_permissions(db_path, newly_created)

    @classmethod
    def open_read_only(cls, db_path: str, *, timeout: float = 0.1) -> Store:
        """Open an existing audit database for latency-bounded UI reads.

        The connection is deliberately not initialized or migrated. The
        gateway/writable CLI store owns schema and journal configuration.
        Create this Store in the worker thread that will use it because the
        standard sqlite3 same-thread safety check remains enabled.
        """

        return cls(db_path, read_only=True, timeout=timeout)

    @classmethod
    def _read_only_uri(cls, db_path: str) -> str:
        if not cls._is_disk_path(db_path):
            raise ValueError("audit: read-only Store requires an on-disk database")
        if db_path.startswith("file:"):
            base, _, raw_query = db_path.partition("?")
            query = [
                item
                for item in raw_query.split("&")
                if item and not item.lower().startswith("mode=")
            ]
            query.append("mode=ro")
            return f"{base}?{'&'.join(query)}"
        return f"{Path(os.path.abspath(db_path)).as_uri()}?mode=ro"

    @staticmethod
    def _is_disk_path(db_path: str) -> bool:
        """True for an on-disk DB path (not an in-memory database)."""
        if not db_path or db_path == ":memory:":
            return False
        if db_path.startswith("file:") and (
            db_path.startswith("file::memory:") or "mode=memory" in db_path
        ):
            return False
        return True

    @classmethod
    def _db_will_be_created(cls, db_path: str) -> bool:
        """True when ``sqlite3.connect`` will create a brand-new DB file."""
        return cls._is_disk_path(db_path) and not os.path.exists(db_path)

    def _harden_permissions(self, db_path: str, newly_created: bool) -> None:
        if not self._is_disk_path(db_path):
            return
        # Always tighten the DB file itself to owner read/write only.
        # This is functionally safe for pre-existing DBs (the owner keeps
        # full access) while closing the world/group-readable hole.
        try:
            os.chmod(db_path, 0o600)
        except OSError:
            pass
        # Only adjust the parent directory when we just created the DB,
        # so we never mutate an unrelated directory a caller pointed us
        # at (e.g. a shared temp root holding a pre-existing file).
        if not newly_created:
            return
        parent = os.path.dirname(os.path.abspath(db_path))
        if not parent:
            return
        try:
            current = stat.S_IMODE(os.stat(parent).st_mode)
            hardened = current & ~stat.S_IRWXO
            if hardened != current:
                os.chmod(parent, hardened)
        except OSError:
            pass

    def init(self) -> None:
        if self.read_only:
            raise sqlite3.OperationalError("audit: read-only Store cannot initialize schema")
        self.db.executescript(SCHEMA)
        self._ensure_run_id_columns()
        self._ensure_audit_connector_columns()
        self._ensure_v8_alert_projection_schema()
        # Add the per-connector column + swap the actions uniqueness index to
        # (target_type, target_name, connector) BEFORE migrating the legacy
        # block/allow lists, so the INSERT OR REPLACE block-last-wins ordering
        # in _migrate_old_lists resolves conflicts against the new index and
        # the migrated rows pick up connector='' (global).
        self._ensure_connector_column()
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

        # BLOCK precedence: ``actions`` has a UNIQUE index on
        # (target_type, target_name), so when the same target appears in
        # both legacy tables the INSERT OR REPLACE that runs LAST wins.
        # We therefore migrate allow rows first and block rows last so a
        # conflicting blocked target can never be silently downgraded to
        # an allow entry during migration (F-0082). This matches the
        # admission ordering where explicit blocks override allows.
        if allow_exists:
            self.db.execute(
                """INSERT OR REPLACE INTO actions
                   (id, target_type, target_name, source_path, actions_json, reason, updated_at)
                   SELECT id, target_type, target_name, NULL, '{"install":"allow"}', reason, created_at
                   FROM allow_list"""
            )
        if block_exists:
            self.db.execute(
                """INSERT OR REPLACE INTO actions
                   (id, target_type, target_name, source_path, actions_json, reason, updated_at)
                   SELECT id, target_type, target_name, NULL, '{"install":"block"}', reason, created_at
                   FROM block_list"""
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
        audit_columns = {
            row[1]
            for row in self.db.execute("PRAGMA table_info(audit_events)").fetchall()
        }
        if "structured_json" not in audit_columns:
            self.db.execute("ALTER TABLE audit_events ADD COLUMN structured_json TEXT")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_audit_run_id ON audit_events(run_id)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_scan_run_id ON scan_results(run_id)")
        self.db.commit()

    def _ensure_audit_connector_columns(self) -> None:
        """Mirror Go's additive audit_events connector columns and indexes."""

        columns = {
            row[1]
            for row in self.db.execute("PRAGMA table_info(audit_events)").fetchall()
        }
        for column, ddl in (
            ("connector", "ALTER TABLE audit_events ADD COLUMN connector TEXT"),
            ("step_idx", "ALTER TABLE audit_events ADD COLUMN step_idx INTEGER"),
            ("enforced", "ALTER TABLE audit_events ADD COLUMN enforced INTEGER"),
            ("rule_pack_dir", "ALTER TABLE audit_events ADD COLUMN rule_pack_dir TEXT"),
        ):
            if column not in columns:
                self.db.execute(ddl)
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_audit_connector ON audit_events(connector)")
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_action_connector_timestamp "
            "ON audit_events(action, connector, timestamp DESC)"
        )
        self.db.commit()

    def _ensure_v8_alert_projection_schema(self) -> None:
        """Install the read-only v8 fields used by Python alert views.

        The gateway remains the only writer for protected disposition state.
        This exact additive shape lets a first-run CLI open the shared database
        before the Go process without creating an incompatible placeholder.
        """

        columns = {
            row[1]
            for row in self.db.execute("PRAGMA table_info(audit_events)").fetchall()
        }
        for column in ("bucket", "event_name"):
            if column not in columns:
                self.db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
        self.db.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_audit_bucket_timestamp
                ON audit_events(bucket, timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_event_name_timestamp
                ON audit_events(event_name, timestamp);
            CREATE TABLE IF NOT EXISTS alert_acknowledgement_projection (
                alert_id TEXT PRIMARY KEY,
                disposition TEXT NOT NULL CHECK (disposition IN ('acknowledged','dismissed')),
                actor TEXT NOT NULL,
                disposition_at DATETIME NOT NULL,
                projection_version INTEGER NOT NULL CHECK (projection_version > 0),
                source TEXT NOT NULL CHECK (source IN ('modern','legacy_ack')),
                source_event_id TEXT NOT NULL,
                updated_at DATETIME NOT NULL
            );
            """
        )
        self.db.commit()

    def _ensure_connector_column(self) -> None:
        """Add the per-connector column on ``actions`` and connector-scope its
        uniqueness index (SK-4 foundation).

        Idempotent and PRAGMA-guarded, following the same pattern as
        :meth:`_ensure_run_id_columns`. Mirrors the Go migration
        "multi-connector: per-connector column on actions + 3-col unique index"
        in ``internal/audit/store.go`` so the two stores share one schema.

        Existing rows keep ``connector=''`` — meaning **global / applies to
        every connector** — so every pre-existing block/allow stays in force
        after the upgrade (the back-compat anchor). The uniqueness key moves
        from ``(target_type, target_name)`` to
        ``(target_type, target_name, connector)`` so a target can carry one
        global entry plus one entry per connector without colliding.
        """
        columns = {
            row[1]
            for row in self.db.execute("PRAGMA table_info(actions)").fetchall()
        }
        if "connector" not in columns:
            self.db.execute(
                "ALTER TABLE actions ADD COLUMN connector TEXT NOT NULL DEFAULT ''"
            )
        # Swap the legacy 2-column uniqueness index for the connector-aware one.
        # DROP first so an upgraded DB cannot keep both (the old one would
        # reject per-connector rows). Both statements are guarded so re-running
        # init() on an already-migrated DB is a no-op.
        self.db.execute("DROP INDEX IF EXISTS idx_actions_type_name")
        self.db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_type_name_conn "
            "ON actions(target_type, target_name, connector)"
        )
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
        structured_json = json.dumps(event.structured, separators=(",", ":")) if event.structured else None
        connector = _event_connector_value(event)
        self.db.execute(
            """INSERT INTO audit_events (
                id, timestamp, action, target, actor, details,
                structured_json, severity, run_id, connector
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (event.id, event.timestamp.isoformat(), event.action,
             event.target or None, event.actor, event.details or None,
             structured_json, event.severity or None, event.run_id or None,
             connector or None),
        )
        self.db.commit()

    def list_events(self, limit: int = 100) -> list[Event]:
        cur = self.db.execute(
            """SELECT id, timestamp, action, target, actor, details, severity, run_id, structured_json, connector
               FROM audit_events ORDER BY timestamp DESC, rowid DESC LIMIT ?""",
            (max(limit, 1),),
        )
        return [self._row_to_event(r) for r in cur.fetchall()]

    def list_event_summaries(self, limit: int = 100) -> list[Event]:
        """List recent audit rows without loading large structured payloads."""

        cur = self.db.execute(
            """SELECT id, timestamp, action, target, actor,
                      substr(COALESCE(details, ''), 1, ?) AS details,
                      severity, run_id, NULL AS structured_json, connector
               FROM audit_events ORDER BY timestamp DESC, rowid DESC LIMIT ?""",
            (_SUMMARY_DETAILS_BYTES, max(limit, 1)),
        )
        return [self._row_to_event(r) for r in cur.fetchall()]

    def list_actionable_event_summaries(self, limit: int = 100) -> list[Event]:
        """List high-signal audit rows for the default TUI view."""

        cur = self.db.execute(
            """SELECT id, timestamp, action, target, actor,
                      substr(COALESCE(details, ''), 1, ?) AS details,
                      severity, run_id, NULL AS structured_json, connector
               FROM audit_events
               WHERE (
                   severity IN ('CRITICAL','HIGH','ERROR')
                   OR (
                       action = 'connector-hook'
                       AND (
                           details LIKE '%severity=CRITICAL%'
                           OR details LIKE '%severity=HIGH%'
                       )
                   )
               )
               ORDER BY timestamp DESC, rowid DESC LIMIT ?""",
            (_SUMMARY_DETAILS_BYTES, max(limit, 1)),
        )
        return [self._row_to_event(r) for r in cur.fetchall()]

    def list_connector_hook_event_summaries(self, limit: int = 500) -> list[Event]:
        """List recent connector-hook rows without the actionable filter."""

        cur = self.db.execute(
            """SELECT id, timestamp, action, target, actor,
                      substr(COALESCE(details, ''), 1, ?) AS details,
                      severity, run_id, NULL AS structured_json, connector
               FROM audit_events
               WHERE action = 'connector-hook'
               ORDER BY timestamp DESC, rowid DESC LIMIT ?""",
            (_SUMMARY_DETAILS_BYTES, max(limit, 1)),
        )
        return [self._row_to_event(r) for r in cur.fetchall()]

    def connector_hook_event_stats(self) -> dict[str, dict[str, Any]]:
        """Return all-time connector-hook counters grouped by connector.

        The Overview chart still uses a bounded event window for sparklines
        and target breakdowns, but the CONNECTORS table's ``CALLS`` column
        must not look frozen just because that window is full. Newer sidecar
        schemas populate ``audit_events.connector`` and index it, so use a
        grouped aggregate instead of loading every hook row into the TUI.
        """

        details_expr = "' ' || COALESCE(details, '') || ' '"
        cur = self.db.execute(
            f"""SELECT connector AS connector_name,
                       COUNT(*) AS calls,
                       SUM(CASE
                             WHEN {details_expr} LIKE '% action=block %'
                               OR {details_expr} LIKE '% action=deny %'
                             THEN 1 ELSE 0
                           END) AS blocks,
                       SUM(CASE
                             WHEN {details_expr} LIKE '% action=alert %'
                               OR {details_expr} LIKE '% action=warn %'
                             THEN 1 ELSE 0
                           END) AS alerts,
                       MAX(timestamp) AS newest
                FROM audit_events
                WHERE action = 'connector-hook'
                  AND connector <> ''
                GROUP BY connector"""
        )
        stats: dict[str, dict[str, Any]] = {}
        for connector, calls, blocks, alerts, newest in cur.fetchall():
            key = str(connector or "").strip().lower()
            if not key:
                continue
            entry = stats.setdefault(key, {"calls": 0, "blocks": 0, "alerts": 0, "newest": ""})
            entry["calls"] = int(entry["calls"]) + int(calls or 0)
            entry["blocks"] = int(entry["blocks"]) + int(blocks or 0)
            entry["alerts"] = int(entry["alerts"]) + int(alerts or 0)
            if newest and str(newest) > str(entry["newest"]):
                entry["newest"] = newest
        return stats

    def count_scan_results_since(self, since: datetime | None) -> int:
        """Count scan results in the active Overview session window."""

        if since is None:
            return int(
                self.db.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0] or 0
            )
        if self._scan_results_supports_retention_timestamp():
            cutoff_unix_nano = _datetime_unix_nano(since)
            if -(2**63) <= cutoff_unix_nano <= (2**63) - 1:
                # Current gateway schemas maintain this indexed integer from
                # ``timestamp``. The second branch preserves correctness while
                # a legacy database's additive timestamp backfill is running;
                # the same index restricts that branch to NULL rows.
                return int(
                    self.db.execute(
                        """SELECT
                               (SELECT COUNT(*) FROM scan_results
                                WHERE retention_timestamp_unix_nano >= ?)
                             + (SELECT COUNT(*) FROM scan_results
                                WHERE retention_timestamp_unix_nano IS NULL
                                  AND datetime(timestamp) >= datetime(?))""",
                        (cutoff_unix_nano, since.isoformat()),
                    ).fetchone()[0]
                    or 0
                )
        return int(
            self.db.execute(
                "SELECT COUNT(*) FROM scan_results WHERE datetime(timestamp) >= datetime(?)",
                (since.isoformat(),),
            ).fetchone()[0]
            or 0
        )

    def _scan_results_supports_retention_timestamp(self) -> bool:
        cached = self._scan_results_has_retention_timestamp
        if cached is not None:
            return cached
        columns = {
            row[1]
            for row in self.db.execute("PRAGMA table_info(scan_results)").fetchall()
        }
        supported = "retention_timestamp_unix_nano" in columns
        self._scan_results_has_retention_timestamp = supported
        return supported

    def list_alerts(self, limit: int = 100) -> list[Event]:
        cur = self.db.execute(
            """SELECT id, timestamp, action, target, actor, details, severity, run_id, structured_json, connector
               FROM audit_events
               WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW','ERROR','INFO')
                 AND (bucket IS NULL OR (bucket = 'security.finding' AND event_name = 'finding.observed'))
                 AND action NOT LIKE 'dismiss%'
                 AND NOT EXISTS (
                     SELECT 1 FROM alert_acknowledgement_projection AS projection
                     WHERE projection.alert_id = audit_events.id
                 )
               ORDER BY timestamp DESC, rowid DESC LIMIT ?""",
            (max(limit, 1),),
        )
        return [self._row_to_event(r) for r in cur.fetchall()]

    def list_alert_summaries(self, limit: int = 100) -> list[Event]:
        """List alert rows without loading large structured payloads."""

        cur = self.db.execute(
            """SELECT id, timestamp, action, target, actor,
                      substr(COALESCE(details, ''), 1, ?) AS details,
                      severity, run_id, NULL AS structured_json, connector
               FROM audit_events
               WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW','ERROR','INFO')
                 AND (bucket IS NULL OR (bucket = 'security.finding' AND event_name = 'finding.observed'))
                 AND action NOT LIKE 'dismiss%'
                 AND NOT EXISTS (
                     SELECT 1 FROM alert_acknowledgement_projection AS projection
                     WHERE projection.alert_id = audit_events.id
                 )
               ORDER BY timestamp DESC, rowid DESC LIMIT ?""",
            (_SUMMARY_DETAILS_BYTES, max(limit, 1)),
        )
        return [self._row_to_event(r) for r in cur.fetchall()]

    def list_actionable_alert_summaries(self, limit: int = 100) -> list[Event]:
        """List high-signal alert rows for the default TUI view."""

        cur = self.db.execute(
            """SELECT id, timestamp, action, target, actor,
                      substr(COALESCE(details, ''), 1, ?) AS details,
                      severity, run_id, NULL AS structured_json, connector
               FROM audit_events
               WHERE (
                   severity IN ('CRITICAL','HIGH','ERROR')
                   OR (
                       action = 'connector-hook'
                       AND (
                           details LIKE '%severity=CRITICAL%'
                           OR details LIKE '%severity=HIGH%'
                       )
                   )
               )
                 AND (bucket IS NULL OR (bucket = 'security.finding' AND event_name = 'finding.observed'))
                 AND action NOT LIKE 'dismiss%'
                 AND NOT EXISTS (
                     SELECT 1 FROM alert_acknowledgement_projection AS projection
                     WHERE projection.alert_id = audit_events.id
                 )
               ORDER BY timestamp DESC, rowid DESC LIMIT ?""",
            (_SUMMARY_DETAILS_BYTES, max(limit, 1)),
        )
        return [self._row_to_event(r) for r in cur.fetchall()]

    def get_event(self, event_id: str) -> Event | None:
        cur = self.db.execute(
            """SELECT id, timestamp, action, target, actor, details, severity, run_id, structured_json, connector
               FROM audit_events WHERE id = ?""",
            (event_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_event(row)

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
    #
    # Connector scoping (SK-4): every method below takes a ``connector``
    # argument that defaults to ``""`` (global — applies to every connector),
    # so existing callers are unchanged. Lookups and writes are **exact-match**
    # on connector: the actions table is unique on
    # (target_type, target_name, connector), so a target can hold one global
    # entry plus one entry per connector and they never collide. The store is
    # deliberately a storage primitive — it does NOT implement most-specific-
    # wins resolution (connector then global fallback); the enforcement /
    # admission layer composes the two exact-match lookups it needs.

    def set_action(
        self, target_type: str, target_name: str,
        source_path: str, state: ActionState, reason: str,
        connector: str = "",
    ) -> None:
        actions_json = json.dumps(state.to_dict())
        aid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute(
            """INSERT INTO actions (
                 id, target_type, target_name, source_path, actions_json, reason,
                 updated_at, connector)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(target_type, target_name, connector) DO UPDATE SET
                 actions_json = excluded.actions_json,
                 reason = excluded.reason,
                 updated_at = excluded.updated_at,
                 source_path = COALESCE(excluded.source_path, source_path)""",
            (aid, target_type, target_name, source_path or None,
             actions_json, reason, now, connector),
        )
        self.db.commit()

    def set_action_field(
        self, target_type: str, target_name: str,
        field: str, value: str, reason: str,
        connector: str = "",
    ) -> None:
        _validate(field, value)
        aid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        init_json = json.dumps({field: value})
        path = f"$.{field}"
        self.db.execute(
            """INSERT INTO actions (
                 id, target_type, target_name, source_path, actions_json, reason,
                 updated_at, connector)
               VALUES (?, ?, ?, NULL, ?, ?, ?, ?)
               ON CONFLICT(target_type, target_name, connector) DO UPDATE SET
                 actions_json = json_set(actions_json, ?, ?),
                 reason = excluded.reason,
                 updated_at = excluded.updated_at""",
            (aid, target_type, target_name, init_json, reason, now, connector, path, value),
        )
        self.db.commit()

    def clear_action_field(
        self, target_type: str, target_name: str, field: str,
        connector: str = "",
    ) -> None:
        _validate(field, "")
        path = f"$.{field}"
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute(
            """UPDATE actions SET actions_json = json_remove(actions_json, ?), updated_at = ?
               WHERE target_type = ? AND target_name = ? AND connector = ?""",
            (path, now, target_type, target_name, connector),
        )
        self.db.execute(
            """DELETE FROM actions WHERE target_type = ? AND target_name = ? AND connector = ?
               AND actions_json IN ('{}', 'null', '')""",
            (target_type, target_name, connector),
        )
        self.db.commit()

    def set_source_path(
        self, target_type: str, target_name: str, path: str,
        connector: str = "",
    ) -> None:
        self.db.execute(
            "UPDATE actions SET source_path = ? WHERE target_type = ? AND target_name = ? AND connector = ?",
            (path, target_type, target_name, connector),
        )
        self.db.commit()

    def remove_action(
        self, target_type: str, target_name: str, connector: str = "",
    ) -> None:
        self.db.execute(
            "DELETE FROM actions WHERE target_type = ? AND target_name = ? AND connector = ?",
            (target_type, target_name, connector),
        )
        self.db.commit()

    def get_action(
        self, target_type: str, target_name: str, connector: str = "",
    ) -> ActionEntry | None:
        cur = self.db.execute(
            """SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
               FROM actions WHERE target_type = ? AND target_name = ? AND connector = ?""",
            (target_type, target_name, connector),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_action(row)

    def has_action(
        self, target_type: str, target_name: str, field: str, value: str,
        connector: str = "",
    ) -> bool:
        _validate(field, value)
        cur = self.db.execute(
            f"""SELECT COUNT(*) FROM actions
                WHERE target_type = ? AND target_name = ? AND connector = ?
                AND json_extract(actions_json, '$.{field}') = ?""",
            (target_type, target_name, connector, value),
        )
        return cur.fetchone()[0] > 0

    def list_by_action(self, field: str, value: str) -> list[ActionEntry]:
        _validate(field, value)
        cur = self.db.execute(
            f"""SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
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
            f"""SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
                FROM actions WHERE json_extract(actions_json, '$.{field}') = ? AND target_type = ?
                ORDER BY updated_at DESC""",
            (value, target_type),
        )
        return [self._row_to_action(r) for r in cur.fetchall()]

    def list_actions_by_type(
        self, target_type: str, connector: str | None = None,
    ) -> list[ActionEntry]:
        """List action entries for a target type.

        ``connector=None`` (default) returns entries across **all** connectors
        — every returned :class:`ActionEntry` carries its own ``.connector`` so
        callers can group/resolve in Python. A concrete value (``""`` for
        global, ``"hermes"`` for a peer) filters to exactly that connector.
        """
        if connector is None:
            cur = self.db.execute(
                """SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
                   FROM actions WHERE target_type = ? ORDER BY updated_at DESC""",
                (target_type,),
            )
        else:
            cur = self.db.execute(
                """SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
                   FROM actions WHERE target_type = ? AND connector = ? ORDER BY updated_at DESC""",
                (target_type, connector),
            )
        return [self._row_to_action(r) for r in cur.fetchall()]

    def list_all_actions(self) -> list[ActionEntry]:
        cur = self.db.execute(
            """SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
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
                "SELECT COUNT(*) FROM audit_events "
                "WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW') "
                "AND (bucket IS NULL OR (bucket = 'security.finding' AND event_name = 'finding.observed')) "
                "AND NOT EXISTS (SELECT 1 FROM alert_acknowledgement_projection AS projection "
                "WHERE projection.alert_id = audit_events.id)"
            ),
            total_scans=_count("SELECT COUNT(*) FROM scan_results"),
            blocked_egress_calls=_count(
                "SELECT COUNT(*) FROM network_egress_events WHERE blocked = 1"
            ),
        )

    def get_enforcement_counts(self) -> Counts:
        """Return cheap Overview enforcement counters.

        This intentionally leaves ``alerts`` at zero. Exact alert counts scan
        ``audit_events.severity`` and are still unnecessary for the TUI
        startup/refresh path. The TUI combines these exact policy/scan counts
        with the alert summaries it already loaded for the Alerts panel.
        """

        def _count(sql: str) -> int:
            return self.db.execute(sql).fetchone()[0]

        action_counts = self.db.execute(
            """SELECT
                   COALESCE(SUM(CASE
                       WHEN target_type = 'skill'
                        AND json_extract(actions_json, '$.install') = 'block'
                       THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE
                       WHEN target_type = 'skill'
                        AND json_extract(actions_json, '$.install') = 'allow'
                       THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE
                       WHEN target_type = 'mcp'
                        AND json_extract(actions_json, '$.install') = 'block'
                       THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE
                       WHEN target_type = 'mcp'
                        AND json_extract(actions_json, '$.install') = 'allow'
                       THEN 1 ELSE 0 END), 0)
               FROM actions
               WHERE target_type IN ('skill', 'mcp')"""
        ).fetchone()
        blocked_skills, allowed_skills, blocked_mcps, allowed_mcps = (
            int(value or 0) for value in action_counts
        )
        return Counts(
            blocked_skills=blocked_skills,
            allowed_skills=allowed_skills,
            blocked_mcps=blocked_mcps,
            allowed_mcps=allowed_mcps,
            total_scans=_count("SELECT COUNT(*) FROM scan_results"),
            blocked_egress_calls=_count(
                "SELECT COUNT(*) FROM network_egress_events WHERE blocked = 1"
            ),
        )

    # -- Row converters --

    @staticmethod
    def _row_to_event(row: tuple[Any, ...]) -> Event:
        structured: dict[str, Any] = {}
        if len(row) > 8 and row[8]:
            try:
                decoded = json.loads(row[8])
                if isinstance(decoded, dict):
                    structured = decoded
            except (json.JSONDecodeError, TypeError):
                structured = {}
        return Event(
            id=row[0],
            timestamp=_parse_ts(row[1]),
            action=row[2],
            target=row[3] or "",
            actor=row[4],
            details=row[5] or "",
            severity=row[6] or "",
            run_id=row[7] or "",
            structured=structured,
            connector=(row[9] or "") if len(row) > 9 else "",
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
            " details, severity, run_id, structured_json"
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
            connector=(row[7] or "") if len(row) > 7 else "",
        )


def _event_connector_value(event: Event) -> str:
    connector = (event.connector or "").strip().lower()
    if connector:
        return connector
    raw = event.structured.get("connector") if isinstance(event.structured, dict) else ""
    connector = str(raw or "").strip().lower()
    if connector:
        return connector
    return _details_connector(event.details)


def _details_connector(details: str) -> str:
    marker = "connector="
    text = (details or "").strip()
    if not text:
        return ""
    start = text.find(marker)
    if start < 0:
        return ""
    value_start = start + len(marker)
    if value_start >= len(text):
        return ""
    if text[value_start] == '"':
        value_start += 1
        value_end = text.find('"', value_start)
        if value_end < 0:
            value_end = len(text)
    else:
        value_end = text.find(" ", value_start)
        if value_end < 0:
            value_end = len(text)
    return text[value_start:value_end].strip().lower()


def _parse_ts(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        text = val.strip()
        if text:
            iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
            try:
                return datetime.fromisoformat(iso_text)
            except ValueError:
                pass
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return datetime.now(timezone.utc)


def _datetime_unix_nano(value: datetime) -> int:
    """Convert a datetime to Unix nanoseconds without float precision loss."""

    if value.tzinfo is None:
        normalized = value.replace(tzinfo=timezone.utc)
    else:
        normalized = value.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = normalized - epoch
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _current_run_id() -> str:
    return os.environ.get("DEFENSECLAW_RUN_ID", "").strip()
