"""Tests for miscellaneous CLI commands — status, alerts, sidecar, deploy, setup, aibom."""

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.models import Event, Finding, ScanResult
from tests.helpers import make_app_context, cleanup_app


# ---------------------------------------------------------------------------
# Status command
# ---------------------------------------------------------------------------

class TestStatusCommand(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    @patch("defenseclaw.gateway.OrchestratorClient")
    @patch("defenseclaw.commands.cmd_status.shutil.which", return_value=None)
    def test_status_output(self, _mock_which, mock_client_cls):
        from defenseclaw.commands.cmd_status import status

        mock_client = MagicMock()
        mock_client.is_running.return_value = False
        mock_client_cls.return_value = mock_client

        result = self.runner.invoke(status, [], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("DefenseClaw Status", result.output)
        self.assertIn("Environment:", result.output)
        self.assertIn("Scanners:", result.output)
        self.assertIn("Sidecar:", result.output)
        self.assertIn("not running", result.output)

    @patch("defenseclaw.gateway.OrchestratorClient")
    @patch("defenseclaw.commands.cmd_status.shutil.which", return_value=None)
    def test_status_shows_counts(self, _mock_which, mock_client_cls):
        from defenseclaw.commands.cmd_status import status
        from defenseclaw.enforce.policy import PolicyEngine

        mock_client = MagicMock()
        mock_client.is_running.return_value = False
        mock_client_cls.return_value = mock_client

        pe = PolicyEngine(self.app.store)
        pe.block("skill", "bad", "test")
        pe.allow("skill", "good", "test")

        result = self.runner.invoke(status, [], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Blocked skills:", result.output)
        self.assertIn("Allowed skills:", result.output)

    @patch("defenseclaw.gateway.OrchestratorClient")
    @patch("defenseclaw.commands.cmd_status.shutil.which")
    def test_status_sidecar_running(self, mock_which, mock_client_cls):
        from defenseclaw.commands.cmd_status import status

        mock_which.return_value = None
        mock_client = MagicMock()
        mock_client.is_running.return_value = True
        mock_client_cls.return_value = mock_client

        result = self.runner.invoke(status, [], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("running", result.output)


# ---------------------------------------------------------------------------
# Alerts command
# ---------------------------------------------------------------------------

class TestAlertsCommand(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_alerts_empty(self):
        from defenseclaw.commands.cmd_alerts import alerts
        result = self.runner.invoke(alerts, [], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No alerts", result.output)

    def test_alerts_with_data(self):
        from defenseclaw.commands.cmd_alerts import alerts

        self.app.store.log_event(Event(
            action="scan",
            target="/skills/bad",
            severity="HIGH",
            details="found issues",
        ))
        self.app.store.log_event(Event(
            action="scan",
            target="/skills/worse",
            severity="CRITICAL",
            details="major vulnerability",
        ))

        result = self.runner.invoke(alerts, [], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Security Alerts", result.output)
        self.assertIn("HIGH", result.output)
        self.assertIn("CRITICAL", result.output)

    def test_alerts_limit(self):
        from defenseclaw.commands.cmd_alerts import alerts

        for i in range(5):
            self.app.store.log_event(Event(
                action="scan",
                target=f"/skills/s{i}",
                severity="MEDIUM",
                details=f"issue {i}",
            ))

        result = self.runner.invoke(alerts, ["-n", "2"], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Security Alerts", result.output)

    def test_alerts_no_store(self):
        from defenseclaw.commands.cmd_alerts import alerts
        self.app.store = None
        result = self.runner.invoke(alerts, [], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No audit store", result.output)


# ---------------------------------------------------------------------------
# Sidecar command
# ---------------------------------------------------------------------------

class TestSidecarCommand(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_sidecar_help(self):
        from defenseclaw.commands.cmd_sidecar import sidecar
        result = self.runner.invoke(sidecar, ["--help"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("sidecar", result.output)

    def test_sidecar_no_subcommand_shows_info(self):
        from defenseclaw.commands.cmd_sidecar import sidecar
        result = self.runner.invoke(sidecar, [], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Gateway Sidecar", result.output)
        self.assertIn("Go binary", result.output)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_sidecar_status_not_running(self, mock_cls):
        from defenseclaw.commands.cmd_sidecar import sidecar

        mock_client = MagicMock()
        mock_client.is_running.return_value = False
        mock_cls.return_value = mock_client

        result = self.runner.invoke(sidecar, ["status"], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("NOT RUNNING", result.output)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_sidecar_status_running(self, mock_cls):
        from defenseclaw.commands.cmd_sidecar import sidecar

        mock_client = MagicMock()
        mock_client.is_running.return_value = True
        mock_client.health.return_value = {
            "started_at": "2026-01-01T00:00:00Z",
            "uptime_ms": 60000,
            "gateway": {"state": "connected", "since": "2026-01-01"},
            "watcher": {"state": "running", "since": "2026-01-01"},
            "api": {"state": "listening", "since": "2026-01-01"},
        }
        mock_cls.return_value = mock_client

        result = self.runner.invoke(sidecar, ["status"], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Sidecar Health", result.output)
        self.assertIn("CONNECTED", result.output)


class TestSidecarFormatDuration(unittest.TestCase):
    def test_seconds(self):
        from defenseclaw.commands.cmd_sidecar import _format_duration
        self.assertEqual(_format_duration(5000), "5s")

    def test_minutes(self):
        from defenseclaw.commands.cmd_sidecar import _format_duration
        self.assertEqual(_format_duration(90000), "1m 30s")

    def test_hours(self):
        from defenseclaw.commands.cmd_sidecar import _format_duration
        self.assertEqual(_format_duration(3661000), "1h 1m 1s")


# ---------------------------------------------------------------------------
# AIBOM command
# ---------------------------------------------------------------------------

class TestAIBOMCommand(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    @patch("defenseclaw.scanner.aibom.AIBOMScannerWrapper")
    def test_generate_aibom(self, mock_cls):
        from defenseclaw.commands.cmd_aibom import aibom

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            scanner="aibom",
            target="/tmp/project",
            timestamp=datetime.now(timezone.utc),
            findings=[
                Finding(id="aibom-inventory", severity="INFO", title="AIBOM Inventory",
                        description="torch 2.1", scanner="aibom"),
            ],
        )
        mock_cls.return_value = mock_scanner

        result = self.runner.invoke(aibom, ["generate", "/tmp/project"], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Generating AIBOM", result.output)
        self.assertIn("AIBOM Inventory", result.output)

    @patch("defenseclaw.scanner.aibom.AIBOMScannerWrapper")
    def test_generate_json_output(self, mock_cls):
        from defenseclaw.commands.cmd_aibom import aibom

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            scanner="aibom",
            target="/tmp/project",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )
        mock_cls.return_value = mock_scanner

        result = self.runner.invoke(
            aibom, ["generate", "/tmp/project", "--json"],
            obj=self.app, catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        # Output has a status line before the JSON body
        json_start = result.output.index("{")
        data = json.loads(result.output[json_start:])
        self.assertEqual(data["scanner"], "aibom")

    @patch("defenseclaw.scanner.aibom.AIBOMScannerWrapper")
    def test_generate_logs_scan(self, mock_cls):
        from defenseclaw.commands.cmd_aibom import aibom

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            scanner="aibom",
            target="/tmp/project",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )
        mock_cls.return_value = mock_scanner

        self.runner.invoke(aibom, ["generate", "/tmp/project"], obj=self.app, catch_exceptions=False)
        counts = self.app.store.get_counts()
        self.assertEqual(counts.total_scans, 1)


# ---------------------------------------------------------------------------
# Setup command (non-interactive)
# ---------------------------------------------------------------------------

class TestSetupCommand(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_setup_help(self):
        from defenseclaw.commands.cmd_setup import setup
        result = self.runner.invoke(setup, ["--help"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Configure DefenseClaw components", result.output)

    def test_setup_skill_scanner_help(self):
        from defenseclaw.commands.cmd_setup import setup
        result = self.runner.invoke(setup, ["skill-scanner", "--help"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Configure skill-scanner", result.output)

    def test_setup_non_interactive_flags(self):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["skill-scanner", "--non-interactive", "--use-llm", "--policy", "strict"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(self.app.cfg.scanners.skill_scanner.use_llm)
        self.assertEqual(self.app.cfg.scanners.skill_scanner.policy, "strict")

    def test_setup_non_interactive_behavioral(self):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["skill-scanner", "--non-interactive", "--use-behavioral"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(self.app.cfg.scanners.skill_scanner.use_behavioral)


class TestSetupHelpers(unittest.TestCase):
    def test_mask_short_key(self):
        from defenseclaw.commands.cmd_setup import _mask
        self.assertEqual(_mask("abc"), "****")

    def test_mask_long_key(self):
        from defenseclaw.commands.cmd_setup import _mask
        result = _mask("abcdefghijklmnop")
        self.assertTrue(result.startswith("abcd"))
        self.assertTrue(result.endswith("mnop"))
        self.assertIn("...", result)


# ---------------------------------------------------------------------------
# Deploy command
# ---------------------------------------------------------------------------

class TestDeployCommand(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    @patch("defenseclaw.commands.cmd_deploy.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_deploy._run_all_scanners")
    @patch("defenseclaw.commands.cmd_deploy._ensure_init")
    def test_deploy_skip_init(self, mock_init, mock_scanners, _mock_which):
        from defenseclaw.commands.cmd_deploy import deploy

        mock_scanners.return_value = []

        result = self.runner.invoke(
            deploy, ["--skip-init", "."],
            obj=self.app, catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Init skipped", result.output)
        self.assertIn("Deploy Summary", result.output)
        mock_init.assert_not_called()

    @patch("defenseclaw.commands.cmd_deploy.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_deploy._run_all_scanners")
    @patch("defenseclaw.commands.cmd_deploy._ensure_init")
    def test_deploy_logs_action(self, mock_init, mock_scanners, _mock_which):
        from defenseclaw.commands.cmd_deploy import deploy

        mock_scanners.return_value = []

        self.runner.invoke(
            deploy, ["--skip-init", "."],
            obj=self.app, catch_exceptions=False,
        )
        events = self.app.store.list_events(10)
        deploy_events = [e for e in events if e.action == "deploy"]
        self.assertEqual(len(deploy_events), 1)

    @patch("defenseclaw.commands.cmd_deploy.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_deploy._run_all_scanners")
    @patch("defenseclaw.commands.cmd_deploy._ensure_init")
    def test_deploy_auto_blocks_high_findings(self, mock_init, mock_scanners, _mock_which):
        from defenseclaw.commands.cmd_deploy import deploy

        mock_scanners.return_value = [
            ("skill-scanner", ".", ScanResult(
                scanner="skill-scanner", target="/skill/bad",
                timestamp=datetime.now(timezone.utc),
                findings=[Finding(id="f1", severity="HIGH", title="Bad", scanner="skill-scanner")],
            ), ""),
        ]

        result = self.runner.invoke(
            deploy, ["--skip-init", "."],
            obj=self.app, catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Auto-blocked 1", result.output)

    @patch("defenseclaw.commands.cmd_deploy.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_deploy._run_all_scanners")
    @patch("defenseclaw.commands.cmd_deploy._ensure_init")
    def test_deploy_summary_shows_findings(self, mock_init, mock_scanners, _mock_which):
        from defenseclaw.commands.cmd_deploy import deploy

        mock_scanners.return_value = [
            ("skill-scanner", ".", ScanResult(
                scanner="skill-scanner", target="/skill/test",
                timestamp=datetime.now(timezone.utc),
                findings=[
                    Finding(id="f1", severity="MEDIUM", title="Warning", scanner="skill-scanner"),
                    Finding(id="f2", severity="LOW", title="Minor", scanner="skill-scanner"),
                ],
            ), ""),
            ("mcp-scanner", ".", ScanResult(
                scanner="mcp-scanner", target=".",
                timestamp=datetime.now(timezone.utc),
                findings=[],
            ), ""),
        ]

        result = self.runner.invoke(
            deploy, ["--skip-init", "."],
            obj=self.app, catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Total findings:   2", result.output)
        self.assertIn("Max severity:     MEDIUM", result.output)


class TestDeployHelpers(unittest.TestCase):
    def test_auto_block_skips_clean_results(self):
        from defenseclaw.commands.cmd_deploy import _auto_block
        from tests.helpers import make_app_context, cleanup_app

        app, tmp_dir, db_path = make_app_context()
        runs = [
            ("skill-scanner", ".", ScanResult(
                scanner="skill-scanner", target="/clean",
                timestamp=datetime.now(timezone.utc), findings=[],
            ), ""),
        ]
        blocked = _auto_block(app, runs)
        self.assertEqual(blocked, 0)
        cleanup_app(app, db_path, tmp_dir)

    def test_auto_block_skips_errors(self):
        from defenseclaw.commands.cmd_deploy import _auto_block
        from tests.helpers import make_app_context, cleanup_app

        app, tmp_dir, db_path = make_app_context()
        runs = [("skill-scanner", ".", None, "not installed")]
        blocked = _auto_block(app, runs)
        self.assertEqual(blocked, 0)
        cleanup_app(app, db_path, tmp_dir)


if __name__ == "__main__":
    unittest.main()
