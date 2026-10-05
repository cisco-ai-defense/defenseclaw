"""Final-cert UX alerts-audit-display b9: Location names only a file and line
(GAP-1691), and the TUI Alerts detail of a canonical finding drops the raw
telemetry keys and redaction placeholders (GAP-1743)."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_alerts
from defenseclaw.commands.cmd_alerts import alerts
from defenseclaw.models import Event
from defenseclaw.tui.panels.alerts import AlertsPanelModel, alerts_from_v8_history
from defenseclaw.tui.services.v8_event_history import V8EventHistoryRow

from tests.helpers import cleanup_app, make_app_context

AT = datetime(2026, 10, 2, 17, 50, tzinfo=timezone.utc)


class LocationTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        # The gateway's migrations add these columns; the CLI test schema lacks them.
        columns = {row[1] for row in self.app.store.db.execute("PRAGMA table_info(audit_events)")}
        for column in ("request_id", "scan_id", "enforcement_action_id", "payload_json"):
            if column not in columns:
                self.app.store.db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
        self._columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "240"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._columns

    def test_hook_event_location_is_left_out_of_show(self):
        self.app.store.log_event(Event(
            action="scan-finding", severity="CRITICAL", connector="openclaw", details="finding.observed",
            timestamp=datetime.now(timezone.utc), structured={
                "defenseclaw.finding.rule_id": "MR1-MARKER-BLOCK",
                "defenseclaw.finding.target_ref": "openclaw:exec",
                "defenseclaw.finding.location": "openclaw:exec",
            }))
        result = CliRunner().invoke(alerts, ["-n", "5", "--show", "1"], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Target:    openclaw:exec", result.output)
        self.assertNotIn("Location:", result.output)

    def test_readable_location_keeps_files_only(self):
        readable = cmd_alerts._readable_location  # noqa: SLF001
        self.assertEqual(readable("claudecode:PreToolUse", "claudecode:UserPromptSubmit"), "")
        self.assertEqual(readable("<hashed class=path v=1>"), "")
        for location in ("helper.py:6", "SKILL.md:8", "Makefile:12", "SKILL.md (frontmatter description)"):
            self.assertEqual(readable(location, "/home/u/.claude/skills/s"), location)


def test_tui_finding_detail_has_no_raw_telemetry_line() -> None:
    row = V8EventHistoryRow(
        id="f1", timestamp=AT, bucket="security.finding", event_name="finding.observed", source="scanner",
        severity="CRITICAL", action="scan-finding", actor="gateway", details="", connector="claudecode",
        redaction_profile="none", payload={
            "defenseclaw.finding.rule_id": "SEC-AWS-KEY",
            "defenseclaw.finding.title": "AWS access key",
            "defenseclaw.finding.target_ref": "claudecode:UserPromptSubmit",
            "defenseclaw.guardrail.evidence_summary": "<redacted-sensitive len=20>",
        },
    )
    model = AlertsPanelModel()
    model.set_events(list(alerts_from_v8_history((row,))))
    model.cursor = 0
    model.detail_open = True
    text = model.detail_text()
    pairs = dict(model.detail_pairs())
    copied = model.copy_detail_text()
    for rendered in (text, str(pairs), copied):
        assert "bucket=" not in rendered and "redaction_profile" not in rendered and "<redacted" not in rendered
    assert "Rule: SEC-AWS-KEY: AWS access key" in text and "Details" not in pairs
