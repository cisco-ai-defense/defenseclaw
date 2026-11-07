"""GAP-1080/GAP-1081: alert rows for hook-rule findings name what happened,
and ``--show`` prints the alert ID without the raw details_json blob."""

from __future__ import annotations

import json
import os
import re
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.alert_semantics import copilot_hook_target
from defenseclaw.commands.cmd_alerts import _alert_selector, alerts
from defenseclaw.models import Event

from tests.helpers import cleanup_app, make_app_context

# Rows the gateway writes for a Cowork and a terminal call, with the Target
# alerts print for each Cowork alert (cowork audit M1).
COWORK_TARGET_FIXTURE = (
    Path(__file__).resolve().parents[2] / "internal" / "audit" / "testdata" / "cowork_alert_target.json"
)

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
        for column in ("request_id", "agent_instance_id"):
            if column not in columns:
                self.app.store.db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
        self.runner = CliRunner()
        self._columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "240"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._columns

    def test_alert_identity_does_not_cross_users_with_shared_request_id(self):
        now = datetime.now(timezone.utc)
        store = self.app.store
        alert = Event(action="scan-finding", severity="HIGH", connector="claudecode",
                      structured={"user.id": "alice"}, timestamp=now)
        bob = Event(action="hook_decision", severity="INFO", connector="claudecode",
                    structured={"user.id": "bob", "defenseclaw.agent.identity.id": "agt-bob"},
                    timestamp=now)
        store.log_event(alert)
        store.log_event(bob)
        store.db.execute("UPDATE audit_events SET request_id=?, agent_instance_id=? WHERE id IN (?, ?)",
                         ("shared-request", "ais-occurrence", alert.id, bob.id))
        store.db.commit()
        self.assertEqual(store.agent_facts_for_alerts([alert.id])[alert.id], {"user": "alice", "agent_instance": "ais-occurrence"})

        alice = Event(action="hook_decision", severity="INFO", connector="claudecode",
                      structured={"user.id": "alice", "defenseclaw.agent.identity.id": "agt-alice"},
                      timestamp=now)
        store.log_event(alice)
        store.db.execute("UPDATE audit_events SET request_id=?, agent_instance_id=? WHERE id=?",
                         ("shared-request", "ais-occurrence", alice.id))
        store.db.commit()
        self.assertEqual(store.agent_facts_for_alerts([alert.id])[alert.id],
                         {"user": "alice", "agent_instance": "ais-occurrence", "agent_identity": "agt-alice"})

    def test_openclaw_inspect_identity_joins_its_finding_for_alerts(self):
        now = datetime.now(timezone.utc)
        store = self.app.store
        finding = Event(action="scan-finding", severity="CRITICAL", connector="openclaw",
                        structured={"user.id": "alice", **FINDING}, timestamp=now)
        inspect = Event(action="inspect-tool-block", severity="CRITICAL", connector="openclaw",
                        structured={"user.id": "alice", "defenseclaw.agent.identity.id": "agt-openclaw"},
                        timestamp=now)
        store.log_event(finding)
        store.log_event(inspect)
        store.db.execute("UPDATE audit_events SET request_id=?, agent_instance_id=? WHERE id IN (?, ?)",
                         ("openclaw-request", "ais-occurrence", finding.id, inspect.id))
        store.db.commit()
        self.assertEqual(store.agent_facts_for_alerts([finding.id])[finding.id],
                         {"user": "alice", "agent_instance": "ais-occurrence", "agent_identity": "agt-openclaw"})
        shown = self.runner.invoke(alerts, ["--show", "1"], obj=self.app, catch_exceptions=False)
        self.assertEqual(shown.exit_code, 0)
        self.assertRegex(shown.output, r"Agent:\s+agt-openclaw")

    def test_openclaw_inspect_identity_does_not_cross_users(self):
        now = datetime.now(timezone.utc)
        store = self.app.store
        finding = Event(action="scan-finding", severity="CRITICAL", connector="openclaw",
                        structured={"user.id": "alice", **FINDING}, timestamp=now)
        inspect = Event(action="inspect-tool-block", severity="CRITICAL", connector="openclaw",
                        structured={"user.id": "bob", "defenseclaw.agent.identity.id": "agt-bob"},
                        timestamp=now)
        store.log_event(finding)
        store.log_event(inspect)
        store.db.execute("UPDATE audit_events SET request_id=?, agent_instance_id=? WHERE id IN (?, ?)",
                         ("shared-request", "ais-occurrence", finding.id, inspect.id))
        store.db.commit()
        self.assertEqual(store.agent_facts_for_alerts([finding.id])[finding.id], {"user": "alice", "agent_instance": "ais-occurrence"})

    def test_openclaw_inspect_identity_does_not_cross_connectors(self):
        now = datetime.now(timezone.utc)
        store = self.app.store
        finding = Event(action="scan-finding", severity="CRITICAL", connector="openclaw",
                        structured={"user.id": "alice", **FINDING}, timestamp=now)
        inspect = Event(action="inspect-tool-block", severity="CRITICAL", connector="codex",
                        structured={"user.id": "alice", "defenseclaw.agent.identity.id": "agt-codex"},
                        timestamp=now)
        store.log_event(finding)
        store.log_event(inspect)
        store.db.execute("UPDATE audit_events SET request_id=?, agent_instance_id=? WHERE id IN (?, ?)",
                         ("shared-request", "ais-occurrence", finding.id, inspect.id))
        store.db.commit()
        self.assertEqual(store.agent_facts_for_alerts([finding.id])[finding.id], {"user": "alice", "agent_instance": "ais-occurrence"})

    def test_openclaw_alert_identity_ignores_other_connector_decisions(self):
        now = datetime.now(timezone.utc)
        store = self.app.store
        for action in ("hook_decision", "action"):
            for order in (("other", "finding", "inspect"),
                          ("inspect", "finding", "other"),
                          ("finding", "other", "inspect"),
                          ("finding", "inspect", "other")):
                with self.subTest(action=action, order=order):
                    events = {
                        "finding": Event(action="scan-finding", severity="CRITICAL",
                                         connector="openclaw", structured={"user.id": "alice", **FINDING},
                                         timestamp=now),
                        "inspect": Event(action="inspect-tool-block", severity="CRITICAL",
                                         connector="openclaw",
                                         structured={"user.id": "alice",
                                                     "defenseclaw.agent.identity.id": "agt-openclaw"},
                                         timestamp=now),
                        "other": Event(action=action, severity="INFO", connector="codex",
                                       structured={"user.id": "alice",
                                                   "defenseclaw.agent.identity.id": "agt-codex"},
                                       timestamp=now),
                    }
                    for name in order:
                        store.log_event(events[name])
                    request_id = f"shared-{action}-{'-'.join(order)}"
                    store.db.execute("UPDATE audit_events SET request_id=?, agent_instance_id=? WHERE id IN (?, ?, ?)",
                                     (request_id, "ais-occurrence", *(event.id for event in events.values())))
                    store.db.commit()
                    self.assertEqual(store.agent_facts_for_alerts([events["finding"].id])[events["finding"].id],
                                     {"user": "alice", "agent_instance": "ais-occurrence", "agent_identity": "agt-openclaw"})

    def test_alert_identity_does_not_borrow_from_other_connector_decision(self):
        now = datetime.now(timezone.utc)
        store = self.app.store
        finding = Event(action="scan-finding", severity="CRITICAL", connector="openclaw",
                        structured={"user.id": "alice", **FINDING}, timestamp=now)
        other = Event(action="hook_decision", severity="INFO", connector="codex",
                      structured={"user.id": "alice", "defenseclaw.agent.identity.id": "agt-codex"},
                      timestamp=now)
        store.log_event(finding)
        store.log_event(other)
        store.db.execute("UPDATE audit_events SET request_id=?, agent_instance_id=? WHERE id IN (?, ?)",
                         ("shared-without-inspect", "ais-occurrence", finding.id, other.id))
        store.db.commit()
        self.assertEqual(store.agent_facts_for_alerts([finding.id])[finding.id], {"user": "alice", "agent_instance": "ais-occurrence"})

    def test_alert_identity_prefers_verified_inspect_over_finding_logical_id(self):
        now = datetime.now(timezone.utc)
        store = self.app.store
        columns = {row[1] for row in store.db.execute("PRAGMA table_info(audit_events)")}
        if "agent_id" not in columns:
            store.db.execute("ALTER TABLE audit_events ADD COLUMN agent_id TEXT")
        verified = "agt-1111111111111111"
        for label, claimed in (("prefixed", "agt-2222222222222222"),
                               ("ordinary", "plugin-session-id"), ("absent", None)):
            with self.subTest(label=label):
                finding = Event(action="scan-finding", severity="CRITICAL", connector="openclaw",
                                structured={"user.id": "alice", **FINDING}, timestamp=now)
                inspect = Event(action="inspect-tool-block", severity="CRITICAL", connector="openclaw",
                                structured={"user.id": "alice", "defenseclaw.agent.identity.id": verified},
                                timestamp=now)
                store.log_event(finding)
                store.log_event(inspect)
                request_id = f"same-request-{label}"
                store.db.execute("UPDATE audit_events SET request_id=?, agent_id=?, agent_instance_id=? WHERE id=?",
                                 (request_id, claimed, "ais-occurrence", finding.id))
                store.db.execute("UPDATE audit_events SET request_id=?, agent_instance_id=? WHERE id=?",
                                 (request_id, "ais-occurrence", inspect.id))
                store.db.commit()
                self.assertEqual(store.agent_facts_for_alerts([finding.id])[finding.id],
                                 {"user": "alice", "agent_instance": "ais-occurrence", "agent_identity": verified})
                listed = [e.id for e in store.list_alerts(10)]
                shown = self.runner.invoke(alerts, ["--show", str(listed.index(finding.id) + 1)],
                                           obj=self.app, catch_exceptions=False)
                self.assertEqual(shown.exit_code, 0, shown.output)
                self.assertRegex(shown.output, rf"Agent:\s+{verified}")

    def test_alert_identity_keeps_finding_structured_identity(self):
        now = datetime.now(timezone.utc)
        store = self.app.store
        columns = {row[1] for row in store.db.execute("PRAGMA table_info(audit_events)")}
        if "agent_id" not in columns:
            store.db.execute("ALTER TABLE audit_events ADD COLUMN agent_id TEXT")
        finding = Event(action="scan-finding", severity="CRITICAL", connector="openclaw",
                        structured={"user.id": "alice", "defenseclaw.agent.identity.id": "agt-openclaw",
                                    **FINDING}, timestamp=now)
        store.log_event(finding)
        store.db.execute("UPDATE audit_events SET agent_id=? WHERE id=?", ("agt-other", finding.id))
        store.db.commit()
        self.assertEqual(store.agent_facts_for_alerts([finding.id])[finding.id],
                         {"user": "alice", "agent_identity": "agt-openclaw"})

    def test_alert_identity_survives_request_id_reuse_by_a_later_inspect(self):
        """GAP-0647: a later inspect call that reuses the client request ID
        cannot change or replace an earlier finding's verified Agent. Only a
        row that carries the finding's own gateway-assigned agent instance
        lends its Agent, so a reuse with other or missing run, session or
        instance facts lends nothing, whether or not the finding's own
        inspect row is still present."""
        store = self.app.store
        columns = {row[1] for row in store.db.execute("PRAGMA table_info(audit_events)")}
        for name in ("session_id", "agent_instance_id", "agent_id"):
            if name not in columns:
                store.db.execute(f"ALTER TABLE audit_events ADD COLUMN {name} TEXT")
        current, later = "agt-0000000000000002", "agt-0000000000000001"
        cases = (
            # (label, later row's session and instance, own inspect row present, expected Agent)
            ("other-session", ("session-later", "ais-later"), True, current),
            ("no-session-facts", ("", ""), True, current),
            ("same-session-no-instance", ("session-current", ""), True, current),
            ("other-session-no-current-row", ("session-later", "ais-later"), False, None),
            ("no-session-facts-no-current-row", ("", ""), False, None),
            ("same-session-no-instance-no-current-row", ("session-current", ""), False, None),
            ("no-later-row", None, True, current),
        )
        orders = (("finding", "current", "later"), ("later", "finding", "current"),
                  ("current", "finding", "later"), ("finding", "later", "current"))
        for label, later_context, has_current, expected in cases:
            for order in orders:
                with self.subTest(label=label, order=order):
                    now = datetime.now(timezone.utc)
                    rows = {
                        "finding": (Event(action="scan-finding", severity="CRITICAL", connector="openclaw",
                                          run_id="run-1", structured={"user.id": "alice", **FINDING},
                                          timestamp=now), ("session-current", "ais-current")),
                    }
                    if has_current:
                        rows["current"] = (Event(action="inspect-tool-block", severity="CRITICAL",
                                                 connector="openclaw", run_id="run-1",
                                                 structured={"user.id": "alice",
                                                             "defenseclaw.agent.identity.id": current},
                                                 timestamp=now), ("session-current", "ais-current"))
                    if later_context is not None:
                        rows["later"] = (Event(action="inspect-tool-block", severity="CRITICAL",
                                               connector="openclaw", run_id="run-1",
                                               structured={"user.id": "alice",
                                                           "defenseclaw.agent.identity.id": later},
                                               timestamp=now + timedelta(seconds=1)), later_context)
                    request_id = f"reused-{label}-{'-'.join(order)}"
                    for name in order:
                        if name not in rows:
                            continue
                        event, (session, instance) = rows[name]
                        store.log_event(event)
                        store.db.execute(
                            "UPDATE audit_events SET request_id=?, session_id=?, agent_instance_id=?, agent_id=? "
                            "WHERE id=?",
                            (request_id, session or None, instance or None, "client-session-agent", event.id))
                    store.db.commit()
                    finding = rows["finding"][0]
                    facts = store.agent_facts_for_alerts([finding.id])[finding.id]
                    self.assertEqual(facts.get("agent_identity"), expected)
                    self.assertEqual(facts.get("agent_instance"), "ais-current")
                    listed = [e.id for e in store.list_alerts(50)]
                    shown = self.runner.invoke(alerts, ["--show", str(listed.index(finding.id) + 1)],
                                               obj=self.app, catch_exceptions=False)
                    self.assertEqual(shown.exit_code, 0, shown.output)
                    self.assertNotRegex(shown.output, rf"Agent:\s+{later}")
                    if expected:
                        self.assertRegex(shown.output, rf"Agent:\s+{expected}")

    def test_alert_identity_is_not_borrowed_without_an_agent_instance(self):
        """A finding with no recorded agent instance has no occurrence key, so a
        row that shares only the request ID, user and connector lends nothing."""
        store = self.app.store
        now = datetime.now(timezone.utc)
        finding = Event(action="scan-finding", severity="CRITICAL", connector="openclaw",
                        structured={"user.id": "alice", **FINDING}, timestamp=now)
        inspect = Event(action="inspect-tool-block", severity="CRITICAL", connector="openclaw",
                        structured={"user.id": "alice", "defenseclaw.agent.identity.id": "agt-openclaw"},
                        timestamp=now)
        store.log_event(finding)
        store.log_event(inspect)
        store.db.execute("UPDATE audit_events SET request_id=? WHERE id IN (?, ?)",
                         ("no-instance", finding.id, inspect.id))
        store.db.commit()
        self.assertEqual(store.agent_facts_for_alerts([finding.id])[finding.id], {"user": "alice"})

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

    def test_a_cowork_finding_reads_cowork_like_the_tui(self):
        # Cowork audit P3-1 (GAP-0047): a Cowork call's hook row records
        # surface=cowork. `alerts` labels its finding cowork:PreToolUse, as
        # the TUI does; a Claude Code terminal call keeps claudecode:*.
        now = datetime.now(timezone.utc)
        cowork_id = self._finding(
            "req-cowork",
            "connector=claudecode result=ok action=block raw_action=block mode=action "
            "cowork_session_id=local_1 surface=cowork",
            now,
        )
        cli_id = self._finding(
            "req-cli", "connector=claudecode result=ok action=block raw_action=block mode=action",
            now - timedelta(seconds=5),
        )
        table = self.runner.invoke(alerts, ["-n", "10"], obj=self.app, catch_exceptions=False)
        self.assertEqual(table.exit_code, 0, table.output)
        self.assertIn("cowork:PreToolUse", table.output)
        self.assertIn("claudecode:PreToolUse", table.output)
        shown = self.runner.invoke(alerts, ["--show", "1"], obj=self.app, catch_exceptions=False).output
        self.assertRegex(shown, r"Target:\s+cowork:PreToolUse")
        self.assertRegex(shown, r"Surface:\s+Cowork \(Claude Code\)")
        self.assertRegex(shown, r"Decision:\s+blocked")
        shown = self.runner.invoke(alerts, ["--show", "2"], obj=self.app, catch_exceptions=False).output
        self.assertRegex(shown, r"Target:\s+claudecode:PreToolUse")
        self.assertNotIn("Surface:", shown)
        listed = {row["id"]: row for row in json.loads(
            self.runner.invoke(alerts, ["--json"], obj=self.app, catch_exceptions=False).output
        )}
        # Cowork audit S2: --json keeps the stored target and adds surface.
        self.assertEqual(listed[cowork_id]["target"], "claudecode:PreToolUse")
        self.assertEqual(listed[cowork_id]["surface"], "cowork")
        self.assertEqual(listed[cli_id]["target"], "claudecode:PreToolUse")
        self.assertEqual(listed[cli_id]["surface"], "")

    def test_a_cowork_finding_keeps_its_label_when_the_hook_details_are_dropped(self):
        # Cowork audit S1: a redaction profile can drop the connector-hook
        # row's details (GAP-2096). The hook decision row of the request
        # keeps defenseclaw.agent.surface, which the TUI reads; alerts read
        # it too. A surface= inside details_json or a reason word is not one.
        now = datetime.now(timezone.utc)
        cowork_id = self._finding("req-redacted", "", now)
        decision = Event(action="hook_decision", severity="INFO", connector="claudecode",
                         structured={"defenseclaw.agent.surface": "cowork",
                                     "defenseclaw.guardrail.effective_action": "block"},
                         timestamp=now)
        self.app.store.log_event(decision)
        self.app.store.db.execute("UPDATE audit_events SET request_id=? WHERE id=?", ("req-redacted", decision.id))
        self.app.store.db.commit()
        cli_id = self._finding(
            "req-cli",
            'connector=claudecode result=ok action=block mode=action reason=surface=cowork '
            'details_json="{\\"surface\\":\\"cowork\\"} surface=cowork"',
            now - timedelta(seconds=5),
        )
        details = self.app.store.hook_details_for_alerts([cowork_id, cli_id])
        self.assertIn("surface=cowork", details[cowork_id])
        listed = [e.id for e in self.app.store.list_alerts(10)]
        shown = self.runner.invoke(
            alerts, ["--show", str(listed.index(cowork_id) + 1)], obj=self.app, catch_exceptions=False
        ).output
        self.assertRegex(shown, r"Target:\s+cowork:PreToolUse")
        self.assertRegex(shown, r"Surface:\s+Cowork \(Claude Code\)")
        shown = self.runner.invoke(
            alerts, ["--show", str(listed.index(cli_id) + 1)], obj=self.app, catch_exceptions=False
        ).output
        self.assertRegex(shown, r"Target:\s+claudecode:PreToolUse")
        self.assertNotIn("Surface:", shown)

    def test_an_asset_policy_surface_is_not_an_agent_surface(self):
        # Cowork audit M2: the asset policy writes surface=hook (where the
        # MCP call was seen). That is not an agent surface, so --show prints
        # no Surface line and the target is unchanged.
        self.app.store.log_event(Event(
            action="asset-policy", target="mcp:unregistered", severity="HIGH", connector="claudecode",
            details="action=block source=registry registry_status=unregistered registry_configured=true "
                    "surface=hook hook=PreToolUse tool=mcp__x__y connector=claudecode would_block=false "
                    "reason=not-in-registry",
            timestamp=datetime.now(timezone.utc),
        ))
        listed = self.app.store.list_alerts(10)
        self.assertEqual([e.action for e in listed], ["asset-policy"])
        shown = self.runner.invoke(alerts, ["--show", "1"], obj=self.app, catch_exceptions=False).output
        self.assertRegex(shown, r"Target:\s+mcp:unregistered\n")
        self.assertNotIn("Surface:", shown)
        self.assertNotIn("cowork", shown.lower())
        row = json.loads(self.runner.invoke(alerts, ["--json"], obj=self.app, catch_exceptions=False).output)[0]
        self.assertEqual(row["target"], "mcp:unregistered")
        self.assertEqual(row["surface"], "")

    def test_printed_cowork_target_round_trips_into_dismiss(self):
        # Cowork audit M1: alerts print cowork:PreToolUse for a Cowork finding
        # and "cowork PreToolUse" for a Cowork hook block. dismiss --target
        # sends that Target unchanged; the gateway selects only the Cowork
        # alert for it on the same rows (internal/audit/cowork_alert_target_test.go).
        from unittest.mock import MagicMock, patch

        from defenseclaw.config import default_config, prepare_fresh_v8_config

        fixture = json.loads(COWORK_TARGET_FIXTURE.read_text())
        store = self.app.store
        columns = {row[1] for row in store.db.execute("PRAGMA table_info(audit_events)")}
        base = datetime.now(timezone.utc)
        for offset, row in enumerate(fixture["rows"]):
            store.log_event(Event(
                id=row["id"], action=row["action"], target=row["target"], severity=row["severity"],
                connector=row["connector"], details=row["details"], structured=dict(row["structured"]),
                timestamp=base - timedelta(seconds=offset),
            ))
            store.db.execute("UPDATE audit_events SET request_id=? WHERE id=?", (row["request_id"], row["id"]))
            if "enforced" in columns and row.get("enforced"):
                store.db.execute("UPDATE audit_events SET enforced=1 WHERE id=?", (row["id"],))
        store.db.commit()

        listed = [e.id for e in store.list_alerts(50)]
        table = self.runner.invoke(alerts, ["-n", "50"], obj=self.app, catch_exceptions=False)
        self.assertEqual(table.exit_code, 0, table.output)
        cfg = prepare_fresh_v8_config(default_config())
        cfg.audit_db = self.db_path
        cfg.gateway.token = "test-alert-review-token"
        for selection in fixture["selections"]:
            alert_id, printed = selection["alert"], selection["printed"]
            self.assertIn(alert_id, listed)
            self.assertIn(printed, table.output)
            shown = self.runner.invoke(
                alerts, ["--show", str(listed.index(alert_id) + 1)], obj=self.app, catch_exceptions=False
            ).output
            self.assertRegex(shown, r"Target:\s+" + re.escape(printed) + r"\n")

            client = MagicMock()
            client.set_alert_disposition.return_value = {
                "_http_status": 200,
                "matched": len(selection["selected"]),
                "selection_digest": "sha256:v1:" + "0" * 64,
                "targets": [{"id": i, "projection_version": 0} for i in selection["selected"]],
            }
            saved, self.app.cfg = self.app.cfg, cfg
            try:
                with patch("defenseclaw.commands.cmd_alerts.OrchestratorClient", return_value=client):
                    result = self.runner.invoke(
                        alerts, ["dismiss", "--target", printed, "--dry-run"], obj=self.app, catch_exceptions=False
                    )
            finally:
                self.app.cfg = saved
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(client.set_alert_disposition.call_args.kwargs["selector"], {"target": printed})
            self.assertEqual(selection["selected"], [alert_id])
            self.assertIn(f"  {alert_id}\n", result.output)
            self.assertIn("Preview: 1 alert(s) matched.", result.output)

        # Audit review 2 N1: a terminal row with a structured payload whose
        # reason or raw payload only mentions surface=cowork keeps its stored
        # target and no Surface line; the legacy row above with no payload is
        # Cowork by its surface=cowork detail.
        self.assertTrue(fixture["not_cowork"])
        listed_json = {row["id"]: row for row in json.loads(
            self.runner.invoke(alerts, ["--json", "-n", "50"], obj=self.app, catch_exceptions=False).output
        )}
        self.assertEqual(listed_json["legacy-cowork-hook"]["surface"], "cowork")
        for row in fixture["not_cowork"]:
            alert_id = row["alert"]
            self.assertIn(alert_id, listed)
            shown = self.runner.invoke(
                alerts, ["--show", str(listed.index(alert_id) + 1)], obj=self.app, catch_exceptions=False
            ).output
            self.assertRegex(shown, r"Target:\s+" + re.escape(row["printed"]) + r"\n")
            self.assertNotIn("Surface:", shown)
            self.assertEqual(listed_json[alert_id]["target"], row["printed"])
            self.assertEqual(listed_json[alert_id]["surface"], "")

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

    def test_finding_of_a_sandbox_session_names_the_sandbox(self):
        # GAP-0232: a hook-rule finding raised inside a sandbox did not say
        # which sandbox; only the request's hook decision records it.
        now = datetime.now(timezone.utc)
        finding_id = self._finding("req-sbx", "connector=claudecode action=allow", now)
        self.app.store.db.execute(
            """INSERT INTO audit_events (id, timestamp, action, actor, details, severity, payload_json, request_id)
               VALUES ('hd-sbx', ?, 'hook_decision', 'defenseclaw', '', 'INFO', ?, 'req-sbx')""",
            (now.isoformat(), json.dumps({"defenseclaw.guardrail.effective_action": "allow",
                                          "defenseclaw.sandbox.name": "myapp-um"})),
        )
        self.app.store.db.commit()
        table = self.runner.invoke(alerts, [], obj=self.app, catch_exceptions=False).output
        self.assertIn("sandbox=myapp-um", table)
        shown = self.runner.invoke(alerts, ["--show", "1"], obj=self.app, catch_exceptions=False).output
        self.assertRegex(shown, r"Sandbox:\s+myapp-um")
        listed = json.loads(self.runner.invoke(alerts, ["--json"], obj=self.app, catch_exceptions=False).output)
        self.assertEqual([r.get("sandbox") for r in listed if r.get("id") == finding_id], ["myapp-um"])

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

    def test_opencode_hook_target_keeps_event_name_in_list(self):
        self.app.store.log_event(Event(
            action="scan-finding", target="", severity="HIGH", connector="opencode",
            details="finding.observed", timestamp=datetime.now(timezone.utc),
            structured={**FINDING, "defenseclaw.finding.target_ref": "opencode:tool.execute.before"},
        ))
        table = self.runner.invoke(alerts, ["--connector", "opencode"], obj=self.app, catch_exceptions=False)
        self.assertEqual(table.exit_code, 0, table.output)
        self.assertIn("tool.execute.before", table.output)
        self.assertNotIn("....execute.before", table.output)

    def test_table_target_matches_exact_selector_outside_secure_client(self):
        from unittest.mock import patch

        self.app.store.log_event(Event(
            action="scan-finding", target="", severity="HIGH",
            connector="opencode", details="finding.observed",
            structured={**FINDING, "defenseclaw.finding.target_ref": "opencode:acp"},
            timestamp=datetime.now(timezone.utc),
        ))
        table = self.runner.invoke(alerts, ["--connector", "opencode"], obj=self.app, catch_exceptions=False)
        self.assertEqual(table.exit_code, 0, table.output)
        self.assertIn("opencode:acp", table.output)
        self.assertEqual(
            _alert_selector(alert_ids=(), connector="opencode", target="opencode:acp",
                            severity="all", since=None, before=None)["target"],
            "opencode:acp",
        )
        with patch("defenseclaw.commands.cmd_status._enterprise_profile", return_value="secure_client"):
            legacy = self.runner.invoke(alerts, ["--connector", "opencode"], obj=self.app, catch_exceptions=False)
        self.assertEqual(legacy.exit_code, 0, legacy.output)
        self.assertNotIn("opencode:acp", legacy.output)
        self.assertIn("acp", legacy.output)

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

    def test_show_names_the_user_agent_session_and_depth(self):
        # GAP-0381: an admin goes from a block alert to the agent that caused it.
        for column in ("session_id", "agent_instance_id"):
            if column not in {row[1] for row in self.app.store.db.execute("PRAGMA table_info(audit_events)")}:
                self.app.store.db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
        finding_id = self._finding("req-sub", "connector=claudecode result=ok action=block mode=action",
                                   datetime.now(timezone.utc))
        # The gateway stamps the verified user ID on both rows. A request ID
        # alone must never authorize borrowing the hook's agent identity.
        self.app.store.db.execute(
            """UPDATE audit_events
               SET structured_json=json_set(structured_json, '$."user.id"', 'alice-id')
               WHERE id=?""",
            (finding_id,),
        )
        decision = Event(action="hook_decision", target="PreToolUse", severity="INFO", connector="claudecode",
                         structured={"user.id": "alice-id", "defenseclaw.user.name": "alice",
                                     "defenseclaw.agent.depth": 1,
                                     "defenseclaw.agent.identity.id": "agt-0123456789abcdef"})
        self.app.store.log_event(decision)
        self.app.store.db.execute(
            "UPDATE audit_events SET request_id='req-sub', agent_instance_id='ais-fedcba9876543210' WHERE id=?",
            (decision.id,))
        self.app.store.db.execute("UPDATE audit_events SET session_id=?, agent_instance_id=? WHERE id=?",
                                  ("sess-1\u202e", "ais-fedcba9876543210", finding_id))
        self.app.store.db.commit()

        show = self.runner.invoke(alerts, ["--show", "1"], obj=self.app, catch_exceptions=False)
        self.assertEqual(show.exit_code, 0, show.output)
        for text in ("alice", "agt-0123456789abcdef", "ais-fedcba9876543210", "1 (sub-agent)",
                     "agent identities --user alice --connector claudecode"):
            self.assertIn(text, show.output)
        self.assertIn("sess-1", show.output)
        self.assertNotIn("\u202e", show.output)
        as_json = self.runner.invoke(alerts, ["--json"], obj=self.app, catch_exceptions=False)
        self.assertIn('"agent_depth": 1', as_json.output)

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
        self.assertNotIn("Next step:", show.output)

    # GAP-0377: the daemon's description and remediation say what an
    # OpenShell finding means and what to do; --show and --json carry them.
    def test_sandbox_finding_show_carries_details_and_next_step(self):
        structured = dict(SANDBOX_FINDING, **{
            "defenseclaw.finding.title": "Credential-bearing traffic cannot be inspected",
            "defenseclaw.finding.description": "OpenShell forwards no request that carries a sandbox credential placeholder",
            "defenseclaw.finding.remediation": "start a new conversation (`defenseclaw sandbox connect rhs2-sb`, without --continue)",
        })
        row = Event(action="sandbox-finding", target="", severity="HIGH", connector="claudecode",
                    details="finding.observed", structured=structured)
        self.app.store.log_event(row)
        db = self.app.store.db
        columns = {r[1] for r in db.execute("PRAGMA table_info(audit_events)")}
        for column in ("bucket", "event_name"):
            if column not in columns:
                db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
        db.execute("UPDATE audit_events SET bucket='security.finding', event_name='finding.observed' WHERE id=?",
                   (row.id,))
        db.commit()
        show = self.runner.invoke(alerts, ["--show", "1"], obj=self.app, catch_exceptions=False)
        self.assertEqual(show.exit_code, 0, show.output)
        self.assertIn("Details:   OpenShell forwards no request that carries a sandbox credential placeholder", show.output)
        self.assertIn("Next step: start a new conversation (`defenseclaw sandbox connect rhs2-sb`", show.output)
        rows = json.loads(self.runner.invoke(alerts, ["--json"], obj=self.app, catch_exceptions=False).output)
        self.assertEqual(rows[0]["next_step"], structured["defenseclaw.finding.remediation"])

    # GAP-0025: the finding's own next step is the only one; no second
    # "Next:" pointer to agent identities beside it.
    def test_sandbox_finding_next_step_replaces_the_identities_pointer(self):
        from unittest.mock import patch

        structured = dict(SANDBOX_FINDING, **{
            "defenseclaw.finding.description": "A credential placeholder is bound to its configured endpoint",
            "defenseclaw.finding.remediation": "Check the model provider and endpoint for this sandbox",
        })
        row = Event(action="sandbox-finding", target="", severity="HIGH", connector="claudecode",
                    details="finding.observed", structured=structured)
        self.app.store.log_event(row)
        db = self.app.store.db
        columns = {r[1] for r in db.execute("PRAGMA table_info(audit_events)")}
        for column in ("bucket", "event_name"):
            if column not in columns:
                db.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
        db.execute("UPDATE audit_events SET bucket='security.finding', event_name='finding.observed' WHERE id=?",
                   (row.id,))
        db.commit()
        facts = {row.id: [("User", "dcr-sbx")]}
        with patch("defenseclaw.commands.cmd_alerts.alert_agent_facts", return_value=facts):
            show = self.runner.invoke(alerts, ["--show", "1"], obj=self.app, catch_exceptions=False)
        self.assertEqual(show.exit_code, 0, show.output)
        self.assertIn("User:", show.output)
        self.assertIn("Next step: Check the model provider and endpoint for this sandbox", show.output)
        self.assertNotIn("agent identities", show.output)
        self.assertNotIn("Next:  ", show.output)

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
        self.assertIn("| claudecode:PostToolUse ", table.output.replace("\u2503", "|").replace("\u2502", "|"))
        # GAP-1344: a Codex PostToolUse block held the result back after the call ran; it is not "blocked".
        later = at + timedelta(seconds=1)
        hook = Event(action="connector-hook", target="PostToolUse", severity="INFO", connector="codex",
                     details="connector=codex result=ok action=block mode=action", timestamp=later)
        finding = Event(action="scan-finding", target="", severity="CRITICAL", connector="codex",
                        details="finding.observed", timestamp=later,
                        structured=dict(FINDING, **{"defenseclaw.finding.target_ref": "codex:PostToolUse"}))
        store.log_event(hook)
        store.log_event(finding)
        store.db.execute("UPDATE audit_events SET request_id='req-codex-post' WHERE id IN (?, ?)",
                         (hook.id, finding.id))
        store.db.commit()
        table = self.runner.invoke(alerts, ["-n", "10"], obj=self.app, catch_exceptions=False)
        self.assertNotIn("decision=blocked", table.output)

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
