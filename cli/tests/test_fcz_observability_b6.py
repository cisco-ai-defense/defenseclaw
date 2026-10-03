"""Final-cert fix-only observability b6: native OTLP custody text reads as
one phrase (GAP-2093), doctor folds idle sandbox connector instances like
status does (GAP-2097), and alerts keep the block decision under the strict
redaction profile (GAP-2096)."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_alerts import alerts
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.models import Event
from defenseclaw.observability.custody_status import (
    ConnectorCustodyReport,
    ConnectorCustodyStatus,
    summarize_native_delivery,
)

from tests.helpers import cleanup_app, make_app_context


def _instance(instance_id: str, *, default: bool, **fields) -> ConnectorCustodyStatus:
    return ConnectorCustodyStatus(
        connector_instance_id=instance_id,
        connector="claudecode",
        custody=fields.pop("custody", "defenseclaw"),
        profile_version="claudecode-v1",
        default=default,
        managed_config_state="verified",
        managed_config_files=1,
        **fields,
    )


def _report(*instances: ConnectorCustodyStatus) -> ConnectorCustodyReport:
    return ConnectorCustodyReport(state="available", reason="", observation_window_hours=24, instances=instances)


class NativeCustodyTextTests(unittest.TestCase):
    def test_unmapped_signals_read_as_one_phrase(self):
        report = _report(
            _instance(
                "019b0000-0000-7000-8000-000000000001",
                default=True,
                normalized_batches=54,
                drop_only_batches=43,
                drop_only_signals=("logs", "metrics"),
                drop_only_reasons=("unsupported_identity",),
            )
        )
        (row,) = summarize_native_delivery(report).connectors
        self.assertIn("54 batches; 43 held only log/metric records that DefenseClaw does not map", row.detail)
        self.assertNotIn("logs, metrics", row.detail)

    def test_doctor_folds_idle_sandbox_instances_into_one_pass_row(self):
        idle = [
            _instance(f"01a0ff{n:02x}-0000-7000-8000-000000000000", default=False, custody="external")
            for n in range(3)
        ]
        report = _report(
            _instance("019b0000-0000-7000-8000-000000000001", default=True, normalized_batches=5),
            *idle,
        )
        r = _DoctorResult()
        cmd_doctor._check_connector_export_custody(report, r)
        self.assertEqual([c["status"] for c in r.checks], ["pass", "pass"])
        self.assertTrue(all("custody=external" not in c["detail"] for c in r.checks))
        self.assertIn("nothing to do", r.checks[-1]["detail"])


class StrictAlertDecisionTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        store = self.app.store
        columns = {row[1] for row in store.db.execute("PRAGMA table_info(audit_events)")}
        for column in ("request_id", "payload_json"):
            if column not in columns:
                store.db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
        self._columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "240"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._columns

    def _log(self, **fields) -> None:
        event = Event(**fields)
        self.app.store.log_event(event)
        self.app.store.db.execute("UPDATE audit_events SET request_id=? WHERE id=?", ("req-1", event.id))
        self.app.store.db.commit()

    def test_strict_profile_block_still_reads_blocked(self):
        # The gateway stores the hook-decision row as "hook_decision" (the
        # audit export shows it as "action"); both names must be read.
        for stored_action in ("hook_decision", "action"):
            with self.subTest(stored_action=stored_action):
                self.app.store.db.execute("DELETE FROM audit_events")
                self.app.store.db.commit()
                self._assert_strict_block_reads_blocked(stored_action)

    def _assert_strict_block_reads_blocked(self, stored_action: str) -> None:
        # Under strict the connector-hook row keeps only its projected
        # details; the hook-decision row still holds the verdict.
        now = datetime.now(timezone.utc)
        self._log(action=stored_action, severity="CRITICAL", connector="claudecode",
                  details="legacy_action=hook_decision | hook_decision", timestamp=now - timedelta(seconds=1),
                  structured={"defenseclaw.guardrail.effective_action": "block",
                              "defenseclaw.guardrail.raw_action": "block",
                              "defenseclaw.guardrail.mode": "enforce"})
        self._log(action="connector-hook", severity="INFO", connector="claudecode",
                  details="legacy.audit.connector.hook", structured={"actor": "defenseclaw"}, timestamp=now)
        self._log(action="scan-finding", severity="CRITICAL", connector="claudecode", details="finding.observed",
                  timestamp=now - timedelta(seconds=2),
                  structured={"defenseclaw.finding.rule_id": "SEC-AWS-KEY", "defenseclaw.scan.scanner": "hook-rules"})

        runner = CliRunner()
        table = runner.invoke(alerts, ["-n", "10"], obj=self.app, catch_exceptions=False).output
        self.assertIn("decision=blocked connector=claudecode rule=SEC-AWS-KEY", table)
        show = runner.invoke(alerts, ["-n", "10", "--show", "1"], obj=self.app, catch_exceptions=False).output
        self.assertIn("Decision:  blocked", show)
