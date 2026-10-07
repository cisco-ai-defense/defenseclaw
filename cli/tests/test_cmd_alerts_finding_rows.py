"""GAP-1080/GAP-1081: alert rows for hook-rule findings name what happened,
and ``--show`` prints the alert ID without the raw details_json blob."""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.alert_semantics import copilot_hook_target
from defenseclaw.commands.cmd_alerts import _alert_selector, alerts
from defenseclaw.models import Event

from tests.helpers import cleanup_app, make_app_context

FINDING = {
    "defenseclaw.finding.rule_id": "SF2-MARKER-BLOCK",
    "defenseclaw.finding.title": "Certification marker command (block)",
    "defenseclaw.finding.target_ref": "claudecode:PreToolUse",
    "defenseclaw.scan.scanner": "hook-rules",
}

SANDBOX_FINDING = {
    "defenseclaw.finding.category": "sandbox.ocsf_finding",
    "defenseclaw.finding.rule_id": "SANDBOX-OCSF-FINDING",
    "defenseclaw.finding.title": "Provider credential used at an unauthorized endpoint",
    "defenseclaw.guardrail.evidence_summary": 'FINDING:BLOCKED [HIGH] "Provider credential used at an unauthorized endpoint"',
    "defenseclaw.sandbox.name": "rhs2-sb",
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

    def test_judge_finding_names_the_judge_and_no_repeated_id(self):
        # GAP-1886: a judge finding read "Rule: JUDGE-EXFIL-FILE: JUDGE-EXFIL-FILE"
        # and "Scanner: hook-rules", like a regex rule.
        now = datetime.now(timezone.utc)
        rows = (
            {"defenseclaw.finding.rule_id": "JUDGE-EXFIL-FILE", "defenseclaw.finding.title": "JUDGE-EXFIL-FILE",
             "defenseclaw.finding.tags": ["llm-judge"]},
            {"defenseclaw.finding.rule_id": "JUDGE-EXFIL-CHANNEL", "defenseclaw.finding.title": "Exfiltration Channel",
             "defenseclaw.finding.tags": ["llm-judge"]},
            {"defenseclaw.finding.rule_id": "JUDGE-PII-SSN", "defenseclaw.finding.title": "PII finding",
             "defenseclaw.finding.tags": ["pii", "redacted"]},
        )
        for i, structured in enumerate(rows):
            self.app.store.log_event(Event(
                action="scan-finding", target="", severity="HIGH", connector="claudecode",
                details="finding.observed", timestamp=now - timedelta(seconds=i),
                structured={"defenseclaw.finding.target_ref": "claudecode:UserPromptSubmit",
                            "defenseclaw.scan.scanner": "hook-rules", **structured},
            ))
        shown = self.runner.invoke(alerts, ["--show", "1"], obj=self.app, catch_exceptions=False)
        self.assertEqual(shown.exit_code, 0, shown.output)
        self.assertIn("JUDGE-EXFIL-FILE", shown.output)
        self.assertNotIn("JUDGE-EXFIL-FILE: JUDGE-EXFIL-FILE", shown.output)
        self.assertIn("llm-judge", shown.output)
        self.assertNotIn("hook-rules", shown.output)
        shown = self.runner.invoke(alerts, ["--show", "2"], obj=self.app, catch_exceptions=False)
        self.assertIn("JUDGE-EXFIL-CHANNEL: Exfiltration Channel", shown.output)
        shown = self.runner.invoke(alerts, ["--show", "3"], obj=self.app, catch_exceptions=False)
        self.assertIn("llm-judge", shown.output)
        self.assertNotIn("hook-rules", shown.output)

    def test_detection_only_findings_are_counted_not_listed(self):
        # GAP-0176: rules that matched calls that then ran are detection-only,
        # not alerts (#693), and the list said "All clear" without a word.
        now = datetime.now(timezone.utc)
        tags = json.dumps({"defenseclaw.finding.tags": ["detection-only"]})
        self.app.store.db.executemany(
            """INSERT INTO audit_events (id, timestamp, action, actor, details, severity, bucket, event_name, payload_json)
               VALUES (?, ?, 'scan-finding', 'defenseclaw', '', 'CRITICAL', 'security.finding', 'finding.observed', ?)""",
            [(f"det-{i}", (now - timedelta(hours=h)).isoformat(), tags) for i, h in enumerate((0, 2, 30))],
        )
        self.app.store.db.commit()
        out = self.runner.invoke(alerts, [], obj=self.app, catch_exceptions=False).output
        self.assertIn("No alerts.", out)
        self.assertNotIn("All clear", out)
        self.assertIn("2 detection-only findings of the last 24 hours not listed", out)
        self.assertIn("`defenseclaw audit export --since 24h` lists them", out)

    def test_copilot_local_and_cli_findings_share_one_target(self):
        # GAP-2619: the VS Code Local harness names the hook PreToolUse and the
        # Copilot CLI preToolUse; the table showed one hook point two ways.
        now = datetime.now(timezone.utc)
        for i, ref in enumerate(("copilot:PreToolUse", "copilot:preToolUse")):
            self.app.store.log_event(Event(
                action="scan-finding", target="", severity="CRITICAL", connector="copilot",
                details="finding.observed", timestamp=now - timedelta(seconds=i),
                structured={**FINDING, "defenseclaw.finding.target_ref": ref},
            ))
        table = self.runner.invoke(alerts, ["--connector", "copilot"], obj=self.app, catch_exceptions=False)
        self.assertEqual(table.exit_code, 0, table.output)
        self.assertEqual(table.output.count("preToolUse"), 2, table.output)
        self.assertNotIn("PreToolUse", table.output)
        self.assertEqual(copilot_hook_target("PreToolUse", "copilot"), "preToolUse")
        self.assertEqual(copilot_hook_target("copilot:UserPromptSubmit"), "copilot:userPromptSubmitted")
        self.assertEqual(copilot_hook_target("claudecode:PreToolUse"), "claudecode:PreToolUse")

    def test_target_selector_sends_the_shown_copilot_target(self):
        # GAP-2619: acknowledge/dismiss --target takes the Target alerts print.
        def selector(target, connector=None):
            return _alert_selector(
                alert_ids=(), connector=connector, target=target, severity="all", since=None, before=None
            )["target"]

        self.assertEqual(selector("copilot:PreToolUse"), "copilot:preToolUse")
        self.assertEqual(selector(" PreToolUse ", "copilot"), "preToolUse")
        self.assertEqual(selector("PreToolUse"), "PreToolUse")
        self.assertEqual(selector("skill://one"), "skill://one")

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

    def test_a_block_explained_by_a_finding_is_one_alert(self):
        """GAP-1305: one alert per block, like the TUI; a lone hook block stays."""
        now = datetime.now(timezone.utc)
        finding_id = self._finding(
            "req-pair", "connector=claudecode result=ok action=block raw_action=block mode=action", now
        )
        lone = Event(action="connector-hook", target="PreToolUse", severity="CRITICAL", connector="claudecode",
                     details="connector=claudecode result=ok action=block raw_action=block mode=action")
        self.app.store.log_event(lone)
        self.assertEqual(sorted(e.id for e in self.app.store.list_alerts(10)), sorted([finding_id, lone.id]))

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

    # GAP-1303: sandbox findings name the sandbox, rule and decision; a
    # post-tool finding is not called observe mode.
    def test_sandbox_finding_row_names_sandbox_rule_and_decision(self):
        row = Event(action="sandbox-finding", target="", severity="HIGH", connector="claudecode",
                    details="finding.observed", structured=dict(SANDBOX_FINDING))
        self.app.store.log_event(row)
        # The gateway writes sandbox findings as canonical v8 rows.
        db = self.app.store.db
        columns = {r[1] for r in db.execute("PRAGMA table_info(audit_events)")}
        for column in ("bucket", "event_name"):
            if column not in columns:
                db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
        db.execute("UPDATE audit_events SET bucket='security.finding', event_name='finding.observed' WHERE id=?",
                   (row.id,))
        db.commit()
        table = self.runner.invoke(alerts, ["-n", "10"], obj=self.app, catch_exceptions=False)
        self.assertEqual(table.exit_code, 0, table.output)
        self.assertNotIn("finding.observed", table.output)
        self.assertIn("rhs2-sb", table.output)
        self.assertIn("decision=blocked connector=claudecode rule=SANDBOX-OCSF-FINDING", table.output)
        show = self.runner.invoke(alerts, ["--show", "1"], obj=self.app, catch_exceptions=False)
        self.assertIn("rhs2-sb", show.output)
        self.assertIn("SANDBOX-OCSF-FINDING: Provider credential used at an unauthorized endpoint", show.output)

    def test_post_tool_finding_is_not_called_observe_mode(self):
        store = self.app.store
        at = datetime.now(timezone.utc)
        hook = Event(action="connector-hook", target="PostToolUse", severity="INFO", connector="claudecode",
                     details="connector=claudecode result=ok action=alert raw_action=block mode=action "
                             "would_block=true", timestamp=at)
        finding = Event(action="scan-finding", target="", severity="CRITICAL", connector="claudecode",
                        details="finding.observed", timestamp=at,
                        structured=dict(FINDING, **{"defenseclaw.finding.target_ref": "claudecode:PostToolUse"}))
        store.log_event(hook)
        store.log_event(finding)
        store.db.execute("UPDATE audit_events SET request_id='req-post' WHERE id IN (?, ?)", (hook.id, finding.id))
        store.db.commit()
        table = self.runner.invoke(alerts, ["-n", "10"], obj=self.app, catch_exceptions=False)
        self.assertIn("decision=detected after the tool ran (cannot block)", table.output)
        self.assertNotIn("observe mode", table.output)
        # GAP-1535: a wide terminal shows the whole hook event, not "...tToolUse".
        self.assertIn("| PostToolUse ", table.output.replace("\u2503", "|").replace("\u2502", "|"))

    # GAP-1525: a plugin finding names the plugin (target_ref) and the file.
    def test_plugin_finding_names_plugin_and_file(self):
        structured = {
            "defenseclaw.finding.rule_id": "SRC-EXEC",
            "defenseclaw.finding.title": "Calls exec()",
            "defenseclaw.finding.target_ref": "demo",
            "defenseclaw.finding.location": "dist/index.js:12",
            "defenseclaw.scan.scanner": "plugin-scanner",
        }
        self.app.store.log_event(Event(action="scan-finding", target="", severity="HIGH",
                                       details="finding.observed", structured=structured))
        table = self.runner.invoke(alerts, ["-n", "10"], obj=self.app, catch_exceptions=False)
        self.assertIn("demo", table.output)
        show = self.runner.invoke(alerts, ["--show", "1"], obj=self.app, catch_exceptions=False)
        self.assertIn("demo", show.output)
        self.assertIn("dist/index.js:12", show.output)


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
