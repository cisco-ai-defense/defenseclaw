# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""rel-1-0-10:GAP-0526: status and doctor count the tool calls the gateway read
only in part (ACTION-PARSE-FAILURE records), which are allowed by default."""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from defenseclaw.commands import cmd_doctor
from defenseclaw.db import Store

# The detail text the gateway writes for a hook verdict with the record
# (internal/gateway/syntax_tail_test.go reads the same finding).
_UNREAD_DETAILS = (
    "connector=claudecode result=ok action=allow raw_action=allow severity=CRITICAL mode=action "
    "reason=detection-only: tool-call patterns alone cannot block; matched: ACTION-PARSE-FAILURE:Part of this "
    "command has a shell syntax error and could not be read, so that part was not checked"
)


class UnreadCallCountTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "audit.db")
        self.store = Store(self.db_path)
        self.store.init()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _add(self, event_id: str, details: str) -> None:
        self.store.db.execute(
            "INSERT INTO audit_events (id, timestamp, action, target, actor, details, severity)"
            " VALUES (?, ?, 'connector-hook', 't', 'a', ?, 'INFO')",
            (event_id, datetime.now(timezone.utc).isoformat(), details),
        )
        self.store.db.commit()

    def test_status_counts_unread_calls(self):
        self.assertEqual(self.store.get_counts().unread_calls, 0)
        self._add("e1", _UNREAD_DETAILS)
        self._add("e2", _UNREAD_DETAILS)
        self._add("e3", "connector=claudecode result=ok action=allow")
        self.assertEqual(self.store.get_counts().unread_calls, 2)
        self.assertEqual(self.store.get_counts(alert_count_seconds=60).unread_calls, 2)

    def test_doctor_reports_unread_calls(self):
        emitted = []
        original = cmd_doctor._emit

        def capture(tag, label, detail="", **kwargs):
            emitted.append((tag, label, detail, kwargs.get("check_id")))

        cmd_doctor._emit = capture
        try:
            cfg = SimpleNamespace(audit_db=self.db_path)
            cmd_doctor._check_unread_calls(cfg, None)
            self._add("e1", _UNREAD_DETAILS)
            cmd_doctor._check_unread_calls(cfg, None)
        finally:
            cmd_doctor._emit = original
        self.assertEqual([e[0] for e in emitted], ["pass", "warn"])
        self.assertIn("1 tool call(s)", emitted[1][2])
        self.assertEqual(emitted[1][3], "doctor.guardrail.unread-calls")


if __name__ == "__main__":
    unittest.main()
