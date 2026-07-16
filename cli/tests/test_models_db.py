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

import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.db import Store
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.models import Event, compare_severity


class ModelsDbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)
        self.store.init()

    def tearDown(self):
        self.store.close()
        os.unlink(self.tmp.name)

    def test_compare_severity(self):
        self.assertGreater(compare_severity("CRITICAL", "HIGH"), 0)
        self.assertGreater(compare_severity("HIGH", "MEDIUM"), 0)
        self.assertLess(compare_severity("LOW", "HIGH"), 0)

    def test_policy_engine_block_allow(self):
        pe = PolicyEngine(self.store)

        self.assertFalse(pe.is_blocked("skill", "bad-skill"))
        pe.block("skill", "bad-skill", "test")
        self.assertTrue(pe.is_blocked("skill", "bad-skill"))

        self.assertFalse(pe.is_allowed("skill", "good-skill"))
        pe.allow("skill", "good-skill", "test")
        self.assertTrue(pe.is_allowed("skill", "good-skill"))

        pe.unblock("skill", "bad-skill")
        self.assertFalse(pe.is_blocked("skill", "bad-skill"))

    def test_policy_engine_quarantine_runtime(self):
        pe = PolicyEngine(self.store)

        pe.quarantine("skill", "s1", "bad")
        self.assertTrue(pe.is_quarantined("skill", "s1"))
        pe.clear_quarantine("skill", "s1")
        self.assertFalse(pe.is_quarantined("skill", "s1"))

        pe.disable("skill", "s1", "runtime")
        action = pe.get_action("skill", "s1")
        self.assertIsNotNone(action)
        self.assertEqual(action.actions.runtime, "disable")

        pe.enable("skill", "s1")
        action = pe.get_action("skill", "s1")
        # Row may still exist with empty state depending on previous fields
        if action is not None:
            self.assertEqual(action.actions.runtime, "")

    def test_get_enforcement_counts_skips_alert_count(self):
        pe = PolicyEngine(self.store)
        pe.block("skill", "blocked-skill", "test")
        pe.allow("skill", "allowed-skill", "test")
        pe.block("mcp", "blocked-mcp", "test")
        pe.allow("mcp", "allowed-mcp", "test")

        self.store.insert_scan_result(
            "scan-1",
            "skill-scanner",
            "/tmp/skill",
            datetime.now(timezone.utc),
            50,
            0,
            "INFO",
            "{}",
        )
        self.store.log_event(Event(action="scan", target="/tmp/skill", severity="HIGH"))

        statements = []
        self.store.db.set_trace_callback(statements.append)
        try:
            counts = self.store.get_enforcement_counts()
        finally:
            self.store.db.set_trace_callback(None)

        self.assertEqual(counts.blocked_skills, 1)
        self.assertEqual(counts.allowed_skills, 1)
        self.assertEqual(counts.blocked_mcps, 1)
        self.assertEqual(counts.allowed_mcps, 1)
        self.assertEqual(counts.total_scans, 1)
        self.assertEqual(counts.alerts, 0)
        select_statements = [
            statement
            for statement in statements
            if statement.lstrip().upper().startswith("SELECT")
        ]
        action_selects = [
            statement for statement in select_statements if "FROM actions" in statement
        ]
        self.assertEqual(len(select_statements), 3)
        self.assertEqual(len(action_selects), 1)
        self.assertEqual(action_selects[0].count("SUM(CASE"), 4)

    def test_count_scan_results_since_falls_back_for_legacy_schema(self):
        self.store.insert_scan_result(
            "scan-before",
            "skill-scanner",
            "/tmp/before",
            datetime(2025, 12, 31, tzinfo=timezone.utc),
            1,
            0,
            "INFO",
            "{}",
        )
        self.store.insert_scan_result(
            "scan-after",
            "skill-scanner",
            "/tmp/after",
            datetime(2026, 1, 2, tzinfo=timezone.utc),
            1,
            0,
            "INFO",
            "{}",
        )

        statements = []
        self.store.db.set_trace_callback(statements.append)
        try:
            count = self.store.count_scan_results_since(
                datetime(2026, 1, 1, tzinfo=timezone.utc)
            )
        finally:
            self.store.db.set_trace_callback(None)

        self.assertEqual(count, 1)
        count_queries = [statement for statement in statements if "COUNT(*)" in statement]
        self.assertEqual(len(count_queries), 1)
        self.assertNotIn("retention_timestamp_unix_nano", count_queries[0])

    def test_count_scan_results_since_uses_indexed_retention_timestamp(self):
        self.store.db.execute(
            "ALTER TABLE scan_results ADD COLUMN retention_timestamp_unix_nano INTEGER"
        )
        self.store.db.execute(
            "CREATE INDEX idx_retention_scan_results_timestamp "
            "ON scan_results(retention_timestamp_unix_nano, id)"
        )
        since = datetime(2026, 1, 1, tzinfo=timezone.utc)
        cutoff = int(since.timestamp()) * 1_000_000_000
        self.store.db.executemany(
            """INSERT INTO scan_results
                   (id, scanner, target, timestamp, retention_timestamp_unix_nano)
               VALUES (?, 'skill-scanner', '/tmp/skill', ?, ?)""",
            [
                # The textual timestamps intentionally disagree with the
                # numeric values so this proves the indexed field is primary.
                ("numeric-new", "2000-01-01T00:00:00+00:00", cutoff + 1),
                ("numeric-old", "2099-01-01T00:00:00+00:00", cutoff - 1),
                # NULL rows model an additive v8 backfill in progress.
                ("backfill-new", "2026-01-02T00:00:00+00:00", None),
                ("backfill-old", "2025-12-31T00:00:00+00:00", None),
            ],
        )
        self.store.db.commit()

        statements = []
        self.store.db.set_trace_callback(statements.append)
        try:
            count = self.store.count_scan_results_since(since)
        finally:
            self.store.db.set_trace_callback(None)

        self.assertEqual(count, 2)
        count_queries = [statement for statement in statements if "COUNT(*)" in statement]
        self.assertEqual(len(count_queries), 1)
        self.assertIn("retention_timestamp_unix_nano >=", count_queries[0])
        plan = self.store.db.execute(
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM scan_results "
            "WHERE retention_timestamp_unix_nano >= ?",
            (cutoff,),
        ).fetchall()
        self.assertTrue(
            any("idx_retention_scan_results_timestamp" in row[3] for row in plan)
        )

    def test_open_read_only_uses_ro_query_only_and_short_timeout(self):
        self.store.close()
        # sqlite3.Connection's context manager commits/rolls back but does not
        # close the handle. Explicitly close it so Windows can later delete the
        # temporary database during teardown.
        with closing(sqlite3.connect(self.tmp.name)) as db:
            journal_mode = db.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        self.assertEqual(journal_mode, "delete")
        os.chmod(self.tmp.name, 0o644)

        reader = Store.open_read_only(self.tmp.name, timeout=0.05)
        try:
            self.assertTrue(reader.read_only)
            self.assertEqual(reader.db.execute("PRAGMA query_only").fetchone()[0], 1)
            self.assertEqual(reader.db.execute("PRAGMA busy_timeout").fetchone()[0], 50)
            self.assertEqual(reader.db.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            if os.name != "nt":
                # Windows chmod only toggles the read-only file attribute and
                # reports synthesized rw bits, so exact POSIX modes are not a
                # portable part of this read-only connection contract.
                self.assertEqual(os.stat(self.tmp.name).st_mode & 0o777, 0o644)
            self.assertGreater(
                reader.db.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0],
                0,
            )
            with self.assertRaises(sqlite3.OperationalError):
                reader.init()

            # Turning off query_only proves URI mode=ro independently prevents
            # a write; the connection was not merely opened normally.
            reader.db.execute("PRAGMA query_only=OFF")
            with self.assertRaises(sqlite3.OperationalError):
                reader.db.execute("CREATE TABLE must_not_exist (id INTEGER)")
        finally:
            reader.close()

    def test_open_read_only_does_not_create_a_missing_database(self):
        missing = self.tmp.name + ".missing"

        with self.assertRaises(sqlite3.OperationalError):
            Store.open_read_only(missing)

        self.assertFalse(os.path.exists(missing))

    def test_store_init_creates_network_egress_schema_and_counts(self):
        tables = {
            row[0] for row in self.store.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        self.assertIn("network_egress_events", tables)

        self.store.db.execute(
            """INSERT INTO network_egress_events
               (id, timestamp, hostname, policy_outcome, blocked, severity)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                "egress-1",
                datetime.now(timezone.utc).isoformat(),
                "evil.example",
                "Denied by policy",
                1,
                "HIGH",
            ),
        )
        self.store.db.commit()

        counts = self.store.get_counts()
        self.assertEqual(counts.blocked_egress_calls, 1)

    def test_store_init_migrates_run_id_columns(self):
        self.store.close()
        os.unlink(self.tmp.name)

        conn = sqlite3.connect(self.tmp.name)
        conn.executescript(
            """
            CREATE TABLE audit_events (
                id TEXT PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                actor TEXT NOT NULL DEFAULT 'defenseclaw',
                details TEXT,
                severity TEXT
            );

            CREATE TABLE scan_results (
                id TEXT PRIMARY KEY,
                scanner TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                duration_ms INTEGER,
                finding_count INTEGER,
                max_severity TEXT,
                raw_json TEXT
            );
            """
        )
        conn.commit()
        conn.close()

        self.store = Store(self.tmp.name)
        self.store.init()

        audit_cols = {row[1] for row in self.store.db.execute("PRAGMA table_info(audit_events)").fetchall()}
        scan_cols = {row[1] for row in self.store.db.execute("PRAGMA table_info(scan_results)").fetchall()}

        self.assertIn("run_id", audit_cols)
        self.assertIn("structured_json", audit_cols)
        self.assertIn("run_id", scan_cols)

    def test_log_event_round_trips_structured_payload(self):
        evt = Event(
            action="connector-hook",
            target="PreToolUse",
            severity="INFO",
            structured={
                "schema": "defenseclaw.hook.v1",
                "connector": "codex",
                "event": "PreToolUse",
                "result": "ok",
            },
        )
        self.store.log_event(evt)

        events = self.store.list_events(1)
        self.assertEqual(events[0].structured["schema"], "defenseclaw.hook.v1")
        self.assertEqual(events[0].structured["connector"], "codex")
        self.assertEqual(events[0].connector, "codex")

    def test_connector_hook_stats_aggregate_normalized_connector_names(self):
        self.store.log_event(
            Event(
                id="codex-structured",
                action="connector-hook",
                target="PreToolUse",
                severity="INFO",
                structured={"connector": "Codex"},
                details="action=allow",
            )
        )
        self.store.log_event(
            Event(
                id="codex-details",
                action="connector-hook",
                target="PreToolUse",
                severity="HIGH",
                details="connector=codex action=block",
            )
        )

        stats = self.store.connector_hook_event_stats()

        self.assertEqual(stats["codex"]["calls"], 2)
        self.assertEqual(stats["codex"]["blocks"], 1)

    def test_event_reader_parses_zulu_timestamps(self):
        self.store.db.execute(
            """INSERT INTO audit_events (
                id, timestamp, action, target, actor, details, severity, run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "evt-zulu",
                "2026-06-24T16:46:56.1105Z",
                "connector-hook",
                "PostToolUse",
                "defenseclaw",
                "connector=codex action=block mode=action",
                "INFO",
                "",
            ),
        )
        self.store.db.commit()

        event = self.store.list_connector_hook_event_summaries(1)[0]

        self.assertEqual(event.id, "evt-zulu")
        self.assertEqual(event.timestamp.year, 2026)
        self.assertEqual(event.timestamp.month, 6)
        self.assertEqual(event.timestamp.day, 24)
        self.assertEqual(event.timestamp.hour, 16)
        self.assertEqual(event.timestamp.minute, 46)
        self.assertEqual(event.timestamp.second, 56)
        self.assertEqual(event.timestamp.microsecond, 110500)
        self.assertEqual(event.timestamp.tzinfo, timezone.utc)

    def test_summary_readers_avoid_heavy_payloads_but_get_event_hydrates_full_row(self):
        details = "connector=codex " + ("x" * 6000)
        evt = Event(
            action="connector-hook",
            target="PreToolUse",
            severity="INFO",
            details=details,
            structured={"payload": "y" * 6000},
        )
        self.store.log_event(evt)

        event_summary = self.store.list_event_summaries(1)[0]
        alert_summary = self.store.list_alert_summaries(1)[0]
        full_event = self.store.get_event(event_summary.id)

        self.assertLess(len(event_summary.details), len(details))
        self.assertEqual(event_summary.structured, {})
        self.assertEqual(alert_summary.details, event_summary.details)
        self.assertIsNotNone(full_event)
        assert full_event is not None
        self.assertEqual(full_event.details, details)
        self.assertEqual(full_event.structured["payload"], "y" * 6000)

    def test_actionable_summary_readers_skip_low_signal_rows(self):
        self.store.log_event(Event(id="info", action="connector-hook", target="preToolUse", severity="INFO"))
        self.store.log_event(
            Event(
                id="hook-high",
                action="connector-hook",
                target="preToolUse",
                severity="INFO",
                details="connector=codex action=allow raw_action=alert severity=HIGH mode=observe",
            )
        )
        self.store.log_event(Event(id="medium", action="scan", target="skill://one", severity="MEDIUM"))
        self.store.log_event(Event(id="high", action="scan", target="skill://two", severity="HIGH"))
        self.store.log_event(Event(id="failure", action="sink-failure", target="splunk", severity="ERROR"))

        audit_ids = [event.id for event in self.store.list_actionable_event_summaries(10)]
        alert_ids = [event.id for event in self.store.list_actionable_alert_summaries(10)]

        self.assertEqual(audit_ids, ["failure", "high", "hook-high"])
        self.assertEqual(alert_ids, ["failure", "high", "hook-high"])

    def test_alert_readers_include_v8_findings_and_exclude_other_v8_buckets(self):
        now = datetime.now(timezone.utc).isoformat()
        self.store.db.executemany(
            """INSERT INTO audit_events (
                   id, timestamp, action, actor, details, severity, bucket, event_name
               ) VALUES (?, ?, ?, 'defenseclaw', ?, 'HIGH', ?, ?)""",
            [
                (
                    "v8-finding",
                    now,
                    "scan-finding",
                    "source-backed finding",
                    "security.finding",
                    "finding.observed",
                ),
                (
                    "v8-platform-health",
                    now,
                    "sink-failure",
                    "exporter degraded",
                    "platform.health",
                    "subsystem.degraded",
                ),
            ],
        )
        self.store.db.commit()

        alert_ids = [event.id for event in self.store.list_alerts(10)]
        summary_ids = [event.id for event in self.store.list_alert_summaries(10)]
        actionable_ids = [event.id for event in self.store.list_actionable_alert_summaries(10)]

        self.assertIn("v8-finding", alert_ids)
        self.assertIn("v8-finding", summary_ids)
        self.assertIn("v8-finding", actionable_ids)
        self.assertNotIn("v8-platform-health", alert_ids)
        self.assertNotIn("v8-platform-health", summary_ids)
        self.assertNotIn("v8-platform-health", actionable_ids)

    # -- SK-4: per-connector actions column migration --

    def test_store_init_migrates_connector_column(self):
        """An old DB (no connector column, legacy 2-col unique index) upgrades
        in place without data loss, and the uniqueness index becomes
        connector-aware."""
        self.store.close()
        os.unlink(self.tmp.name)

        # Rebuild the actions table in the pre-SK-4 shape and seed two global
        # rows (a block and an allow) under the legacy 2-column unique index.
        conn = sqlite3.connect(self.tmp.name)
        conn.executescript(
            """
            CREATE TABLE actions (
                id TEXT PRIMARY KEY,
                target_type TEXT NOT NULL,
                target_name TEXT NOT NULL,
                source_path TEXT,
                actions_json TEXT NOT NULL DEFAULT '{}',
                reason TEXT,
                updated_at DATETIME NOT NULL
            );
            CREATE UNIQUE INDEX idx_actions_type_name ON actions(target_type, target_name);
            """
        )
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)"
            " VALUES (?, ?, ?, NULL, ?, ?, ?)",
            ("a1", "skill", "legacy-skill", '{"install":"block"}', "old block", now),
        )
        conn.execute(
            "INSERT INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)"
            " VALUES (?, ?, ?, NULL, ?, ?, ?)",
            ("a2", "mcp", "legacy-mcp", '{"install":"allow"}', "old allow", now),
        )
        conn.commit()
        conn.close()

        # Upgrade.
        self.store = Store(self.tmp.name)
        self.store.init()

        # Column added.
        cols = {row[1] for row in self.store.db.execute("PRAGMA table_info(actions)").fetchall()}
        self.assertIn("connector", cols)

        # Index swapped: legacy 2-col gone, connector-aware 3-col present.
        index_names = {row[1] for row in self.store.db.execute("PRAGMA index_list(actions)").fetchall()}
        self.assertNotIn("idx_actions_type_name", index_names)
        self.assertIn("idx_actions_type_name_conn", index_names)

        # Legacy rows preserved, now global (connector='') — nothing lost.
        block = self.store.get_action("skill", "legacy-skill")
        self.assertIsNotNone(block)
        self.assertEqual(block.actions.install, "block")
        self.assertEqual(block.reason, "old block")
        self.assertEqual(block.connector, "")
        allow = self.store.get_action("mcp", "legacy-mcp")
        self.assertIsNotNone(allow)
        self.assertEqual(allow.actions.install, "allow")
        self.assertEqual(allow.connector, "")
        # Pre-existing global block stays in force.
        self.assertTrue(self.store.has_action("skill", "legacy-skill", "install", "block"))

        # A per-connector row for the SAME (type, name) now coexists with the
        # global one — proving the uniqueness index is connector-aware.
        self.store.set_action_field("skill", "legacy-skill", "install", "allow", "hermes ok", connector="hermes")
        self.assertTrue(self.store.has_action("skill", "legacy-skill", "install", "allow", connector="hermes"))
        # Global entry untouched and still a block; the per-connector lookup
        # does not see the global block (exact-match).
        self.assertTrue(self.store.has_action("skill", "legacy-skill", "install", "block"))
        self.assertFalse(self.store.has_action("skill", "legacy-skill", "install", "block", connector="hermes"))

    def test_connector_scoped_actions_isolation(self):
        """Per-connector and global entries on the same target are isolated for
        exact-match reads/writes, and list_actions_by_type filters by
        connector."""
        self.store.set_action_field("skill", "x", "install", "block", "global block")
        self.store.set_action_field("skill", "x", "install", "allow", "hermes allow", connector="hermes")

        # Exact-match reads are scoped to their connector.
        self.assertTrue(self.store.has_action("skill", "x", "install", "block"))
        self.assertFalse(self.store.has_action("skill", "x", "install", "block", connector="hermes"))
        self.assertTrue(self.store.has_action("skill", "x", "install", "allow", connector="hermes"))
        self.assertFalse(self.store.has_action("skill", "x", "install", "allow"))

        g = self.store.get_action("skill", "x")
        self.assertEqual(g.connector, "")
        self.assertEqual(g.actions.install, "block")
        h = self.store.get_action("skill", "x", connector="hermes")
        self.assertEqual(h.connector, "hermes")
        self.assertEqual(h.actions.install, "allow")

        # Default list returns both connectors; filtered lists return one each.
        all_entries = self.store.list_actions_by_type("skill")
        self.assertEqual({e.connector for e in all_entries}, {"", "hermes"})
        hermes_only = self.store.list_actions_by_type("skill", connector="hermes")
        self.assertEqual([e.connector for e in hermes_only], ["hermes"])
        global_only = self.store.list_actions_by_type("skill", connector="")
        self.assertEqual([e.connector for e in global_only], [""])

        # remove_action is connector-scoped.
        self.store.remove_action("skill", "x")
        self.assertIsNone(self.store.get_action("skill", "x"))
        self.assertIsNotNone(self.store.get_action("skill", "x", connector="hermes"))

    def test_connector_migration_idempotent(self):
        """Re-running init() on an already-migrated DB is a no-op: it must not
        recreate the legacy 2-col index (which would reject per-connector rows)
        nor drop existing per-connector data."""
        self.store.set_action_field("skill", "y", "install", "block", "codex block", connector="codex")
        self.store.init()  # second init on an already-migrated DB

        index_names = {row[1] for row in self.store.db.execute("PRAGMA index_list(actions)").fetchall()}
        self.assertIn("idx_actions_type_name_conn", index_names)
        self.assertNotIn("idx_actions_type_name", index_names)
        self.assertTrue(self.store.has_action("skill", "y", "install", "block", connector="codex"))


if __name__ == "__main__":
    unittest.main()
