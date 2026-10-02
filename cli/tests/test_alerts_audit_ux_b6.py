"""Final-cert UX alerts-audit-display b6: alerts name the decision, route and
target of ACP, OpenClaw, skill-scan and quarantine rows in the table, --show
and --json (GAP-1615, GAP-1616, GAP-1629, GAP-1590), and the TUI Audit list
reads the outcome of v8 rows without loading their full payload (GAP-1510)."""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_alerts import alerts
from defenseclaw.models import Event
from defenseclaw.tui.panels.audit import _row_details_label, _row_target_label

from tests.helpers import cleanup_app, make_app_context

ACP_FINDING = {
    "defenseclaw.finding.rule_id": "SEC-AWS-KEY",
    "defenseclaw.finding.title": "AWS access key",
    "defenseclaw.finding.target_ref": "opencode:acp",
    "defenseclaw.scan.scanner": "inspect-http",
}
ACP_VERDICT = {
    "defenseclaw.guardrail.effective_action": "block",
    "defenseclaw.guardrail.would_block": False,
    "defenseclaw.acp.method": "session/prompt",
    "defenseclaw.acp.client": "zed",
}


class AlertsAuditUxB6Tests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        store = self.app.store
        # The gateway's migrations add these columns; the CLI test schema lacks them.
        columns = {row[1] for row in store.db.execute("PRAGMA table_info(audit_events)")}
        for column in ("request_id", "scan_id", "enforcement_action_id", "payload_json"):
            if column not in columns:
                store.db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
        self.runner = CliRunner()
        self._columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "240"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._columns

    def _log(self, column: str = "", value: str = "", **fields) -> str:
        event = Event(**fields)
        self.app.store.log_event(event)
        if column:
            self.app.store.db.execute(f"UPDATE audit_events SET {column}=? WHERE id=?", (value, event.id))
            self.app.store.db.commit()
        return event.id

    def _invoke(self, *args: str):
        result = self.runner.invoke(alerts, list(args), obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        return result.output

    def test_acp_and_openclaw_blocks_say_blocked_in_table_show_and_json(self):
        now = datetime.now(timezone.utc)
        self._log("request_id", "req-acp", action="guardrail-verdict", severity="CRITICAL", connector="opencode",
                  details="guardrail.evaluation.completed", structured=dict(ACP_VERDICT),
                  timestamp=now - timedelta(seconds=1))
        self._log("request_id", "req-acp", action="scan-finding", severity="CRITICAL", connector="opencode",
                  details="finding.observed", structured=dict(ACP_FINDING), timestamp=now)
        earlier = now - timedelta(seconds=5)
        self._log("request_id", "req-oc", action="inspect-tool-block", target="exec", severity="CRITICAL",
                  details="severity=CRITICAL reason=matched: MR1-MARKER-BLOCK mode=action raw_action=block",
                  timestamp=earlier)
        self._log("request_id", "req-oc", action="scan-finding", severity="CRITICAL", connector="openclaw",
                  details="finding.observed", timestamp=earlier, structured={
                      "defenseclaw.finding.rule_id": "MR1-MARKER-BLOCK",
                      "defenseclaw.finding.title": "E2E marker command (block)",
                      "defenseclaw.finding.target_ref": "openclaw:exec",
                      "defenseclaw.scan.scanner": "inspect-http",
                  })

        table = self._invoke("-n", "10")
        self.assertIn("decision=blocked connector=opencode rule=SEC-AWS-KEY", table)
        self.assertIn("decision=blocked connector=openclaw rule=MR1-MARKER-BLOCK", table)

        show = self._invoke("-n", "10", "--show", "1")
        self.assertIn("Decision:  blocked", show)
        self.assertIn("Route:     ACP session/prompt (client zed)", show)

        rows = json.loads(self._invoke("--json", "-n", "10"))
        acp = next(row for row in rows if row["connector"] == "opencode")
        self.assertEqual(acp["target"], "opencode:acp")
        self.assertEqual(acp["decision"], "blocked")
        self.assertEqual(acp["rule"], "SEC-AWS-KEY: AWS access key")
        self.assertEqual(acp["scanner"], "inspect-http")
        self.assertEqual(acp["route"], "ACP session/prompt (client zed)")
        openclaw = next(row for row in rows if row["connector"] == "openclaw")
        self.assertEqual((openclaw["target"], openclaw["decision"]), ("openclaw:exec", "blocked"))

    def test_skill_scan_and_quarantine_rows_name_the_skill(self):
        now = datetime.now(timezone.utc)
        skill = "C:\\Users\\dcw-fc1\\.claude\\skills\\ws1r2-rev2"
        self.app.store.db.execute(
            "INSERT INTO scan_results (id, scanner, target, timestamp) VALUES (?, ?, ?, ?)",
            ("scan-1", "skill-scanner", skill, now.isoformat()),
        )
        self._log("scan_id", "scan-1", action="scan-finding", severity="CRITICAL", connector="claudecode",
                  details="finding.observed", timestamp=now, structured={
                      "defenseclaw.finding.rule_id": "COMMAND_INJECTION_EVAL",
                      "defenseclaw.finding.title": "Dynamic code evaluation",
                      "defenseclaw.scan.scanner": "skill-scanner",
                  })
        earlier = now - timedelta(seconds=5)
        self._log("enforcement_action_id", "enf-1", action="quarantine", severity="HIGH",
                  details="enforcement.quarantine.applied", timestamp=earlier)
        moved = "C:\\Users\\dcw-fc1\\.defenseclaw\\quarantine\\skills\\ws1r2-rev2"
        asset = self._log("enforcement_action_id", "enf-1", action="quarantine", severity="INFO",
                          details="asset.quarantined", timestamp=earlier - timedelta(seconds=1))
        self.app.store.db.execute(
            "UPDATE audit_events SET payload_json=? WHERE id=?",
            (json.dumps({"defenseclaw.asset.id": "ws1r2-rev2", "defenseclaw.asset.target_path": moved}), asset),
        )
        self.app.store.db.commit()

        table = self._invoke("-n", "10")
        self.assertIn("ws1r2-rev2", table.split("COMMAND_INJECTION_EVAL")[0].splitlines()[-1])
        self.assertIn("quarantined to", table)

        finding = self._invoke("-n", "10", "--show", "1")
        self.assertIn(f"Target:    {skill}", finding)
        quarantine = self._invoke("-n", "10", "--show", "2")
        self.assertIn("Target:    ws1r2-rev2", quarantine)
        self.assertIn(f"Moved to:  {moved}", quarantine)

        rows = json.loads(self._invoke("--json", "-n", "10"))
        self.assertEqual(rows[0]["target"], skill)
        self.assertEqual((rows[1]["target"], rows[1]["decision"]), ("ws1r2-rev2", "quarantined"))

    def test_audit_list_rows_read_the_outcome_without_the_full_payload(self):
        now = datetime.now(timezone.utc)
        self._log(action="hook_decision", severity="HIGH", connector="claudecode", details="hook_decision",
                  timestamp=now, structured={
                      "defenseclaw.hook.event": "UserPromptSubmit",
                      "defenseclaw.guardrail.effective_action": "block",
                      "defenseclaw.guardrail.rule_ids": ["SEC-AWS-KEY"],
                      "large.unused.field": "x" * 4096,
                  })
        self._log(action="llm-judge-response", severity="HIGH", connector="claudecode",
                  details="guardrail.judge.completed", timestamp=now - timedelta(seconds=1),
                  structured={"defenseclaw.judge.kind": "pii", "defenseclaw.judge.action": "block"})

        hook, judge = self.app.store.list_event_summaries(10)[:2]
        self.assertNotIn("large.unused.field", hook.structured)
        self.assertEqual((_row_target_label(hook), _row_details_label(hook)),
                         ("UserPromptSubmit", "block · SEC-AWS-KEY"))
        self.assertEqual((_row_target_label(judge), _row_details_label(judge)), ("pii judge", "judge: block"))


if __name__ == "__main__":
    unittest.main()
