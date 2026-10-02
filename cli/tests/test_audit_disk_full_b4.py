"""Final-cert disk-full b4: status and alerts say when audit events are not
being recorded because the disk is full or the audit database rejects writes
(GAP-1528)."""

from __future__ import annotations

import os
import sys
import unittest
from collections import namedtuple
from unittest import mock

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.audit_capacity import audit_disk_full_notice
from defenseclaw.commands import cmd_status
from defenseclaw.commands.cmd_alerts import alerts

from tests.helpers import cleanup_app, make_app_context

_Usage = namedtuple("_Usage", "total used free")
_FULL = _Usage(1 << 30, 1 << 30, 2 * 1024 * 1024)
_ROOMY = _Usage(1 << 30, 0, 1 << 30)


class AuditDiskFullNoticeTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_notice_names_the_full_disk(self):
        with mock.patch("shutil.disk_usage", return_value=_FULL):
            notice = audit_disk_full_notice(self.db_path)
        self.assertIn(os.path.dirname(os.path.abspath(self.db_path)), notice)
        self.assertIn("2 MiB free", notice)
        self.assertIn("not being recorded", notice)
        with mock.patch("shutil.disk_usage", return_value=_ROOMY):
            self.assertEqual(audit_disk_full_notice(self.db_path), "")

    def test_alerts_warns_that_new_alerts_are_not_recorded(self):
        with mock.patch("shutil.disk_usage", return_value=_FULL):
            result = CliRunner().invoke(alerts, [], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("new alerts and audit events are not being recorded", result.output)

    def test_alerts_warns_when_the_gateway_reports_audit_writes_failing(self):
        # APFS reported 32 MiB free on the full volume, so only the gateway knew.
        health = {
            "telemetry": {
                "state": "error",
                "since": "2026-10-02T19:10:00Z",
                "details": {"event_history_failure": "sqlite_write_failed", "event_history_last_sqlite_class": "full"},
            }
        }
        with (
            mock.patch("shutil.disk_usage", return_value=_ROOMY),
            mock.patch.object(cmd_status, "_fetch_runtime_bound_health", return_value=health),
        ):
            result = CliRunner().invoke(alerts, [], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("since 2026-10-02T19:10:00Z", result.output)
        self.assertIn("new alerts and audit events are not being recorded", result.output)
        with (
            mock.patch("shutil.disk_usage", return_value=_ROOMY),
            mock.patch.object(
                cmd_status, "_fetch_runtime_bound_health", return_value={"telemetry": {"state": "running"}}
            ),
        ):
            result = CliRunner().invoke(alerts, [], obj=self.app)
        self.assertNotIn("not being recorded", result.output)

    def test_status_names_the_audit_write_failure(self):
        health = {
            "telemetry": {
                "state": "error",
                "since": "2026-10-02T11:41:50Z",
                "details": {"event_history_failure": "sqlite_write_failed", "event_history_last_sqlite_class": "other"},
            }
        }
        with mock.patch("shutil.disk_usage", return_value=_ROOMY), mock.patch.object(cmd_status, "_status_row") as row:
            cmd_status._print_audit_log_health(self.app.cfg, health)
            cmd_status._print_audit_log_health(self.app.cfg, {"telemetry": {"state": "running"}})
        self.assertEqual(row.call_count, 1)
        label, value = row.call_args.args
        self.assertEqual(label, "Audit log")
        self.assertIn("events cannot be written", value)
        self.assertIn("since 2026-10-02T11:41:50Z", value)
        with mock.patch("shutil.disk_usage", return_value=_FULL), mock.patch.object(cmd_status, "_status_row") as row:
            cmd_status._print_audit_log_health(self.app.cfg, None)
        self.assertIn("is full", row.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
