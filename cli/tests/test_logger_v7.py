# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Track 0 stub parity tests for Logger.log_activity / log_alert.

These pin the Python-side contract that downstream tracks rely on
(operator activity wizard + runtime alert bus). The mutations are
lightweight today — they end up in ``audit_events`` — but the rows
must carry a predictable action, actor, target shape, and a
non-empty JSON details blob.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.audit_actions import ACTION_POLICY_RELOAD
from defenseclaw.db import Store
from defenseclaw.logger import Logger


class LoggerActivityAlertTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)
        self.store.init()

    def tearDown(self) -> None:
        self.store.close()
        os.unlink(self.tmp.name)

    def test_log_activity_persists_fields_and_json_details(self) -> None:
        logger = Logger(self.store)
        logger.log_activity(
            actor="cli:alice",
            action=ACTION_POLICY_RELOAD,
            target_type="policy",
            target_id="default",
            before={"mode": "warn"},
            after={"mode": "block"},
            diff=[{"path": "mode", "op": "replace", "before": "warn", "after": "block"}],
            version_from="abc123",
            version_to="def456",
        )
        events = self.store.list_events(1)
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e.action, ACTION_POLICY_RELOAD)
        self.assertEqual(e.actor, "cli:alice")
        self.assertEqual(e.target, "policy:default")

        payload = json.loads(e.details)
        self.assertIn("activity_id", payload)
        aid = payload["activity_id"]
        row = self.store.get_activity_event(aid)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["actor"], "cli:alice")
        self.assertEqual(row["action"], ACTION_POLICY_RELOAD)
        self.assertIn('"mode": "warn"', row["before_json"])
        self.assertIn('"mode": "block"', row["after_json"])
        for key in (
            "actor", "action", "target_type", "target_id",
            "before", "after", "diff", "version_from", "version_to",
        ):
            self.assertIn(key, payload, f"details missing {key}: {e.details}")
        self.assertEqual(payload["version_to"], "def456")

    def test_log_activity_target_defaults_when_type_blank(self) -> None:
        logger = Logger(self.store)
        logger.log_activity(
            actor="system",
            action="config_save",
            target_type="",
            target_id="~/.defenseclaw/config.yaml",
        )
        events = self.store.list_events(1)
        self.assertEqual(events[0].target, "unknown:~/.defenseclaw/config.yaml")

    def test_log_alert_persists_summary_and_action(self) -> None:
        logger = Logger(self.store)
        logger.log_alert(
            "scanner",
            "HIGH",
            "skill-scanner timed out",
            {"scanner": "skill", "duration_ms": 30000},
        )
        events = self.store.list_events(1)
        self.assertEqual(events[0].action, "alert")
        self.assertEqual(events[0].severity, "HIGH")
        payload = json.loads(events[0].details)
        self.assertEqual(payload["source"], "scanner")
        self.assertEqual(payload["summary"], "skill-scanner timed out")
        self.assertEqual(payload["details"]["duration_ms"], 30000)

    def test_log_alert_defaults_severity_to_warn(self) -> None:
        logger = Logger(self.store)
        logger.log_alert("scanner", "", "minor issue", None)
        events = self.store.list_events(1)
        self.assertEqual(events[0].severity, "WARN")


if __name__ == "__main__":
    unittest.main()
