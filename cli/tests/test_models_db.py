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
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.db import Store
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.logger import Logger
from defenseclaw.models import ActionState, Finding, ScanResult, compare_severity


class ModelsDbTests(unittest.TestCase):
    class _FakeSplunkCfg:
        enabled = True
        hec_endpoint = "http://127.0.0.1:8088"
        index = "defenseclaw_local"
        source = "defenseclaw"
        sourcetype = "defenseclaw:json"
        verify_tls = False

        def resolved_hec_token(self) -> str:
            return "test-hec-token"

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

    def test_logger_writes_scan_and_alerts(self):
        logger = Logger(self.store)
        result = ScanResult(
            scanner="skill-scanner",
            target="/tmp/skill",
            timestamp=datetime.now(timezone.utc),
            findings=[
                Finding(
                    id="f1",
                    severity="HIGH",
                    title="Test finding",
                    description="desc",
                    scanner="skill-scanner",
                )
            ],
            duration=timedelta(milliseconds=1200),
        )

        logger.log_scan(result)

        counts = self.store.get_counts()
        self.assertEqual(counts.total_scans, 1)
        self.assertEqual(counts.alerts, 1)

        alerts = self.store.list_alerts(10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")

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

        audit_cols = {
            row[1] for row in self.store.db.execute("PRAGMA table_info(audit_events)").fetchall()
        }
        scan_cols = {
            row[1] for row in self.store.db.execute("PRAGMA table_info(scan_results)").fetchall()
        }

        self.assertIn("run_id", audit_cols)
        self.assertIn("run_id", scan_cols)

    def test_logger_uses_run_id_from_env(self):
        old = os.environ.get("DEFENSECLAW_RUN_ID")
        os.environ["DEFENSECLAW_RUN_ID"] = "python-run-id"
        try:
            logger = Logger(self.store)
            result = ScanResult(
                scanner="skill-scanner",
                target="/tmp/skill",
                timestamp=datetime.now(timezone.utc),
                findings=[],
                duration=timedelta(milliseconds=50),
            )

            logger.log_scan(result)
            logger.log_action("skill-block", "bad-skill", "reason=test")

            events = self.store.list_events(10)
            self.assertGreaterEqual(len(events), 2)
            self.assertTrue(all(evt.run_id == "python-run-id" for evt in events[:2]))

            run_id = self.store.db.execute(
                "SELECT run_id FROM scan_results ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()[0]
            self.assertEqual(run_id, "python-run-id")
        finally:
            if old is None:
                os.environ.pop("DEFENSECLAW_RUN_ID", None)
            else:
                os.environ["DEFENSECLAW_RUN_ID"] = old

    @patch("defenseclaw.logger.urllib.request.urlopen")
    def test_logger_forwards_run_id_to_splunk(self, mock_urlopen):
        old = os.environ.get("DEFENSECLAW_RUN_ID")
        os.environ["DEFENSECLAW_RUN_ID"] = "python-splunk-run"
        try:
            response = MagicMock()
            response.status = 200
            cm = MagicMock()
            cm.__enter__.return_value = response
            cm.__exit__.return_value = False
            mock_urlopen.return_value = cm

            logger = Logger(self.store, self._FakeSplunkCfg())
            logger.log_action("skill-block", "bad-skill", "reason=test")

            req = mock_urlopen.call_args[0][0]
            self.assertTrue(req.full_url.endswith("/services/collector/event"))
            payload = json.loads(req.data.decode("utf-8"))
            self.assertEqual(payload["event"]["run_id"], "python-splunk-run")
            self.assertEqual(payload["event"]["action"], "skill-block")
        finally:
            if old is None:
                os.environ.pop("DEFENSECLAW_RUN_ID", None)
            else:
                os.environ["DEFENSECLAW_RUN_ID"] = old


if __name__ == "__main__":
    unittest.main()
