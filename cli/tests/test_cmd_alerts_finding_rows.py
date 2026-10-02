"""GAP-1080/GAP-1081: alert rows for hook-rule findings name what happened,
and ``--show`` prints the alert ID without the raw details_json blob."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_alerts import alerts
from defenseclaw.models import Event

from tests.helpers import cleanup_app, make_app_context

FINDING = {
    "defenseclaw.finding.rule_id": "SF2-MARKER-BLOCK",
    "defenseclaw.finding.title": "Certification marker command (block)",
    "defenseclaw.finding.target_ref": "claudecode:PreToolUse",
    "defenseclaw.scan.scanner": "hook-rules",
}


class AlertFindingRowsTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        # The gateway's migrations add request_id; the CLI test schema lacks it.
        columns = {row[1] for row in self.app.store.db.execute("PRAGMA table_info(audit_events)")}
        if "request_id" not in columns:
            self.app.store.db.execute("ALTER TABLE audit_events ADD COLUMN request_id TEXT")
        self.runner = CliRunner()
        self._columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "240"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._columns

    def _finding(self, request_id: str, hook_details: str, at: datetime) -> str:
        store = self.app.store
        hook = Event(action="connector-hook", target="PreToolUse", severity="INFO",
                     connector="claudecode", details=hook_details, timestamp=at)
        finding = Event(action="scan-finding", target="", severity="CRITICAL", connector="claudecode",
                        details="finding.observed", structured=dict(FINDING), timestamp=at)
        store.log_event(hook)
        store.log_event(finding)
        store.db.execute("UPDATE audit_events SET request_id=? WHERE id IN (?, ?)",
                         (request_id, hook.id, finding.id))
        store.db.commit()
        return finding.id

    def test_finding_rows_show_target_rule_connector_and_decision(self):
        now = datetime.now(timezone.utc)
        self._finding("req-observe", "connector=claudecode result=ok action=allow raw_action=block "
                      "mode=observe would_block=true", now)
        blocked_id = self._finding(
            "req-action",
            'connector=claudecode result=ok action=block raw_action=block mode=action '
            'details_json="{\\"schema\\":\\"x\\",\\"would_block\\":false}"',
            now - timedelta(seconds=5),
        )

        table = self.runner.invoke(alerts, ["-n", "10"], obj=self.app, catch_exceptions=False)
        self.assertEqual(table.exit_code, 0, table.output)
        self.assertNotIn("finding.observed", table.output)
        self.assertIn("decision=would block (observe mode)", table.output)
        self.assertIn("decision=blocked connector=claudecode rule=SF2-MARKER-BLOCK", table.output)

        rows = self.app.store.list_alerts(10)
        index = next(i for i, e in enumerate(rows, 1) if e.id == blocked_id)
        show = self.runner.invoke(alerts, ["--show", str(index)], obj=self.app, catch_exceptions=False)
        self.assertEqual(show.exit_code, 0, show.output)
        for text in (blocked_id, "claudecode:PreToolUse", "blocked", "claudecode",
                     "SF2-MARKER-BLOCK: Certification marker command (block)", "hook-rules",
                     f"alerts acknowledge --id {blocked_id}"):
            self.assertIn(text, show.output)

    def test_show_hook_row_drops_details_json(self):
        self.app.store.log_event(Event(
            action="connector-hook", target="PreToolUse", severity="CRITICAL", connector="claudecode",
            details='connector=claudecode result=ok action=block raw_action=block severity=CRITICAL '
                    'details_json="{\\"schema\\":\\"x\\"}"',
        ))
        show = self.runner.invoke(alerts, ["--show", "1"], obj=self.app, catch_exceptions=False)
        self.assertEqual(show.exit_code, 0, show.output)
        self.assertIn("ID:", show.output)
        self.assertIn("action=block", show.output)
        self.assertNotIn("details_json", show.output)
        self.assertNotIn("schema", show.output)


def test_redacted_secret_title_uses_the_rule_pack_title():
    # GAP-1223: C2-METADATA-AWS is tagged "credential", so the store keeps only
    # "Secret finding"; the bundled pack's title is static text and safe to show.
    from defenseclaw.commands import cmd_alerts

    cmd_alerts._rule_pack_titles.cache_clear()
    try:
        assert cmd_alerts._finding_title("C2-METADATA-AWS", "Secret finding") == "AWS metadata endpoint (SSRF)"
        assert cmd_alerts._finding_title("NO-SUCH-RULE", "Secret finding") == "Secret finding"
        assert cmd_alerts._finding_title("C2-METADATA-AWS", "kept") == "kept"
    finally:
        cmd_alerts._rule_pack_titles.cache_clear()
