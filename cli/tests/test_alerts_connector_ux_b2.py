"""Final-cert UX cli-alerts b2: 'alerts --connector' takes the setup name
(claude-code) and an unknown name exits 1 listing the active connectors (GAP-2130)."""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timezone

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_alerts import alerts
from defenseclaw.models import Event

from tests.helpers import cleanup_app, make_app_context


class ConnectorNameTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]
        self.app.store.log_event(
            Event(
                action="scan-finding",
                severity="CRITICAL",
                connector="claudecode",
                details="finding.observed",
                timestamp=datetime.now(timezone.utc),
            )
        )

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _run(self, *args):
        return CliRunner().invoke(alerts, list(args), obj=self.app, catch_exceptions=False)

    def test_setup_name_matches_stored_connector(self):
        result = self._run("--connector", "claude-code", "--json")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual([r["connector"] for r in json.loads(result.output)], ["claudecode"])

    def test_unknown_connector_exits_1_and_lists_active(self):
        result = self._run("--connector", "nosuchconn")
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("No connector matches 'nosuchconn'", result.output)
        self.assertIn("Active connectors: claudecode, codex", result.output)
        self.assertNotIn("No alerts from connector", result.output)

    def test_known_connector_without_alerts_stays_ok(self):
        result = self._run("--connector", "codex")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No alerts from connector 'codex'", result.output)


if __name__ == "__main__":
    unittest.main()
