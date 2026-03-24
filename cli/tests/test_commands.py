"""Tests for CLI commands — status, alerts, aibom, sidecar, plugin, mcp, deploy, init."""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.context import AppContext
from defenseclaw.config import Config, default_config
from defenseclaw.models import Event, Finding, ScanResult


def _make_app(store=None, logger=None) -> AppContext:
    """Build a minimal AppContext for test injection."""
    app = AppContext()
    app.cfg = default_config()
    app.store = store
    app.logger = logger
    return app


def _invoke(cmd, args=None, app=None):
    """Invoke a Click command with an injected AppContext."""
    runner = CliRunner()
    obj = app or _make_app()
    return runner.invoke(cmd, args or [], obj=obj, catch_exceptions=False)


# ── status ────────────────────────────────────────────────────────────────

class TestStatusCommand(unittest.TestCase):
    @patch("defenseclaw.gateway.OrchestratorClient")
    @patch("shutil.which", return_value=None)
    def test_status_no_store(self, _which, _oc):
        from defenseclaw.commands.cmd_status import status
        _oc.return_value.is_running.return_value = False

        result = _invoke(status, app=_make_app(store=None))
        self.assertEqual(result.exit_code, 0)
        self.assertIn("DefenseClaw Status", result.output)
        self.assertIn("not running", result.output)

    @patch("defenseclaw.gateway.OrchestratorClient")
    @patch("shutil.which", return_value="/usr/bin/openshell")
    def test_status_with_sandbox(self, _which, _oc):
        from defenseclaw.commands.cmd_status import status
        _oc.return_value.is_running.return_value = True

        result = _invoke(status, app=_make_app(store=None))
        self.assertEqual(result.exit_code, 0)
        self.assertIn("running", result.output)


# ── alerts ────────────────────────────────────────────────────────────────

class TestAlertsCommand(unittest.TestCase):
    def test_alerts_no_store(self):
        from defenseclaw.commands.cmd_alerts import alerts
        result = _invoke(alerts, app=_make_app(store=None))
        self.assertEqual(result.exit_code, 0)
        self.assertIn("No audit store", result.output)

    def test_alerts_empty(self):
        from defenseclaw.commands.cmd_alerts import alerts
        store = MagicMock()
        store.list_alerts.return_value = []
        result = _invoke(alerts, app=_make_app(store=store))
        self.assertEqual(result.exit_code, 0)
        self.assertIn("No alerts", result.output)

    def test_alerts_with_data(self):
        from defenseclaw.commands.cmd_alerts import alerts
        store = MagicMock()
        store.list_alerts.return_value = [
            Event(
                id="e1",
                timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
                action="scan",
                target="bad-skill",
                details="found malware",
                severity="HIGH",
            ),
        ]
        result = _invoke(alerts, app=_make_app(store=store))
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Security Alerts", result.output)


# ── aibom ─────────────────────────────────────────────────────────────────

class TestAibomCommand(unittest.TestCase):
    @patch("defenseclaw.scanner.aibom.AIBOMScannerWrapper")
    def test_aibom_clean(self, MockScanner):
        from defenseclaw.commands.cmd_aibom import aibom

        mock_instance = MockScanner.return_value
        mock_instance.scan.return_value = ScanResult(
            scanner="aibom", target=".", timestamp=datetime.now(timezone.utc),
        )

        result = _invoke(aibom, ["generate", "."], app=_make_app())
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Generating AIBOM", result.output)

    @patch("defenseclaw.scanner.aibom.AIBOMScannerWrapper")
    def test_aibom_json_output(self, MockScanner):
        from defenseclaw.commands.cmd_aibom import aibom

        mock_instance = MockScanner.return_value
        mock_instance.scan.return_value = ScanResult(
            scanner="aibom", target=".", timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="INFO", title="Inventory")],
        )

        result = _invoke(aibom, ["generate", ".", "--json"], app=_make_app())
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"scanner": "aibom"', result.output)

    @patch("defenseclaw.scanner.aibom.AIBOMScannerWrapper")
    def test_aibom_scan_failure(self, MockScanner):
        from defenseclaw.commands.cmd_aibom import aibom

        mock_instance = MockScanner.return_value
        mock_instance.scan.side_effect = RuntimeError("scan broke")

        runner = CliRunner()
        result = runner.invoke(aibom, ["generate", "."], obj=_make_app())
        self.assertNotEqual(result.exit_code, 0)


# ── sidecar ───────────────────────────────────────────────────────────────

class TestSidecarCommand(unittest.TestCase):
    def test_sidecar_help(self):
        from defenseclaw.commands.cmd_sidecar import sidecar
        runner = CliRunner()
        result = runner.invoke(sidecar, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("sidecar", result.output)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_sidecar_status_not_running(self, MockClient):
        from defenseclaw.commands.cmd_sidecar import status

        MockClient.return_value.is_running.return_value = False
        result = _invoke(status, app=_make_app())
        self.assertEqual(result.exit_code, 0)
        self.assertIn("NOT RUNNING", result.output)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_sidecar_status_running(self, MockClient):
        from defenseclaw.commands.cmd_sidecar import status

        inst = MockClient.return_value
        inst.is_running.return_value = True
        inst.health.return_value = {
            "started_at": "2025-01-01T00:00:00Z",
            "uptime_ms": 60000,
            "gateway": {"state": "connected", "since": "2025-01-01T00:00:00Z"},
            "watcher": {"state": "running", "since": "2025-01-01T00:00:00Z"},
            "api": {"state": "listening", "since": "2025-01-01T00:00:00Z"},
        }

        result = _invoke(status, app=_make_app())
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Sidecar Health", result.output)
        self.assertIn("1m 0s", result.output)


class TestFormatDuration(unittest.TestCase):
    def test_seconds(self):
        from defenseclaw.commands.cmd_sidecar import _format_duration
        self.assertEqual(_format_duration(5000), "5s")

    def test_minutes(self):
        from defenseclaw.commands.cmd_sidecar import _format_duration
        self.assertEqual(_format_duration(90000), "1m 30s")

    def test_hours(self):
        from defenseclaw.commands.cmd_sidecar import _format_duration
        self.assertEqual(_format_duration(3661000), "1h 1m 1s")


# ── plugin ────────────────────────────────────────────────────────────────

class TestPluginCommands(unittest.TestCase):
    def test_plugin_help(self):
        from defenseclaw.commands.cmd_plugin import plugin
        runner = CliRunner()
        result = runner.invoke(plugin, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("install", result.output)
        self.assertIn("list", result.output)
        self.assertIn("remove", result.output)

    def test_plugin_list_empty(self):
        from defenseclaw.commands.cmd_plugin import list_plugins
        with tempfile.TemporaryDirectory() as tmpdir:
            app = _make_app()
            app.cfg.plugin_dir = tmpdir
            result = _invoke(list_plugins, app=app)
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No plugins", result.output)

    def test_plugin_list_with_plugins(self):
        from defenseclaw.commands.cmd_plugin import list_plugins
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "my-plugin"))
            app = _make_app()
            app.cfg.plugin_dir = tmpdir
            result = _invoke(list_plugins, app=app)
            self.assertEqual(result.exit_code, 0)
            self.assertIn("my-plugin", result.output)

    def test_plugin_install_from_dir(self):
        from defenseclaw.commands.cmd_plugin import install
        with tempfile.TemporaryDirectory() as plugin_src:
            with tempfile.TemporaryDirectory() as plugin_dest:
                with open(os.path.join(plugin_src, "manifest.json"), "w") as f:
                    f.write("{}")

                app = _make_app()
                app.cfg.plugin_dir = plugin_dest
                result = _invoke(install, [plugin_src], app=app)
                self.assertEqual(result.exit_code, 0)
                self.assertIn("Installed plugin", result.output)

    def test_plugin_install_already_exists(self):
        from defenseclaw.commands.cmd_plugin import install
        with tempfile.TemporaryDirectory() as plugin_src:
            with tempfile.TemporaryDirectory() as plugin_dest:
                name = os.path.basename(plugin_src)
                os.makedirs(os.path.join(plugin_dest, name))
                app = _make_app()
                app.cfg.plugin_dir = plugin_dest
                result = _invoke(install, [plugin_src], app=app)
                self.assertEqual(result.exit_code, 0)
                self.assertIn("already installed", result.output)

    def test_plugin_remove_success(self):
        from defenseclaw.commands.cmd_plugin import remove
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "del-me"))
            app = _make_app()
            app.cfg.plugin_dir = tmpdir
            result = _invoke(remove, ["del-me"], app=app)
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Removed", result.output)
            self.assertFalse(os.path.exists(os.path.join(tmpdir, "del-me")))

    def test_plugin_remove_not_found(self):
        from defenseclaw.commands.cmd_plugin import remove
        with tempfile.TemporaryDirectory() as tmpdir:
            app = _make_app()
            app.cfg.plugin_dir = tmpdir
            result = _invoke(remove, ["nonexistent"], app=app)
            self.assertEqual(result.exit_code, 0)
            self.assertIn("not found", result.output)

    def test_plugin_install_from_registry_stub(self):
        from defenseclaw.commands.cmd_plugin import install
        app = _make_app()
        app.cfg.plugin_dir = tempfile.mkdtemp()
        result = _invoke(install, ["some-registry-plugin"], app=app)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("not yet implemented", result.output)


# ── mcp ───────────────────────────────────────────────────────────────────

class TestMCPCommands(unittest.TestCase):
    def test_mcp_help(self):
        from defenseclaw.commands.cmd_mcp import mcp
        runner = CliRunner()
        result = runner.invoke(mcp, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("scan", result.output)
        self.assertIn("block", result.output)
        self.assertIn("allow", result.output)

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper")
    def test_mcp_scan_clean(self, MockScanner):
        from defenseclaw.commands.cmd_mcp import scan

        mock_inst = MockScanner.return_value
        mock_inst.scan.return_value = ScanResult(
            scanner="mcp-scanner", target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
        )

        result = _invoke(scan, ["http://localhost:3000"], app=_make_app())
        self.assertEqual(result.exit_code, 0)
        self.assertIn("CLEAN", result.output)

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper")
    def test_mcp_scan_with_findings(self, MockScanner):
        from defenseclaw.commands.cmd_mcp import scan

        mock_inst = MockScanner.return_value
        mock_inst.scan.return_value = ScanResult(
            scanner="mcp-scanner", target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="m1", severity="HIGH", title="No TLS")],
        )

        result = _invoke(scan, ["http://localhost:3000"], app=_make_app())
        self.assertEqual(result.exit_code, 0)
        self.assertIn("HIGH", result.output)

    def test_mcp_block(self):
        from defenseclaw.commands.cmd_mcp import block

        store = MagicMock()
        store.get_action.return_value = None

        with patch("defenseclaw.enforce.PolicyEngine") as MockPE:
            pe = MockPE.return_value
            pe.is_blocked.return_value = False

            result = _invoke(block, ["http://bad.example.com"], app=_make_app(store=store))
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Blocked", result.output)
            pe.block.assert_called_once()

    def test_mcp_allow(self):
        from defenseclaw.commands.cmd_mcp import allow

        store = MagicMock()
        with patch("defenseclaw.enforce.PolicyEngine") as MockPE:
            pe = MockPE.return_value
            pe.is_allowed.return_value = False

            result = _invoke(allow, ["http://safe.example.com"], app=_make_app(store=store))
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Allowed", result.output)

    def test_mcp_block_already_blocked(self):
        from defenseclaw.commands.cmd_mcp import block

        store = MagicMock()
        with patch("defenseclaw.enforce.PolicyEngine") as MockPE:
            pe = MockPE.return_value
            pe.is_blocked.return_value = True

            result = _invoke(block, ["http://bad.example.com"], app=_make_app(store=store))
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Already blocked", result.output)


# ── init ──────────────────────────────────────────────────────────────────

class TestInitCommand(unittest.TestCase):
    @patch("shutil.which", return_value=None)
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    def test_init_skip_install(self, _env, _which):
        from defenseclaw.commands.cmd_init import init_cmd

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("defenseclaw.config.default_config") as mock_dc:
                cfg = Config(
                    data_dir=tmpdir,
                    audit_db=os.path.join(tmpdir, "audit.db"),
                    quarantine_dir=os.path.join(tmpdir, "quarantine"),
                    plugin_dir=os.path.join(tmpdir, "plugins"),
                    policy_dir=os.path.join(tmpdir, "policies"),
                    environment="macos",
                )
                mock_dc.return_value = cfg

                with patch("defenseclaw.config.config_path") as mock_cp:
                    mock_cp.return_value = os.path.join(tmpdir, "config.yaml")

                    result = _invoke(init_cmd, ["--skip-install"])
                    self.assertEqual(result.exit_code, 0)
                    self.assertIn("Environment: macos", result.output)
                    self.assertIn("Scanners: skipped", result.output)
                    self.assertIn("initialized", result.output)


# ── deploy ────────────────────────────────────────────────────────────────

class TestDeployCommand(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_deploy.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_deploy._run_all_scanners")
    @patch("defenseclaw.commands.cmd_deploy._ensure_init")
    def test_deploy_skip_init(self, mock_init, mock_scanners, _which):
        from defenseclaw.commands.cmd_deploy import deploy

        mock_scanners.return_value = []
        app = _make_app()
        app.cfg.environment = "macos"

        result = _invoke(deploy, [".", "--skip-init"], app=app)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Init skipped", result.output)
        self.assertIn("Deploy Summary", result.output)
        mock_init.assert_not_called()

    @patch("defenseclaw.commands.cmd_deploy.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_deploy._run_all_scanners")
    @patch("defenseclaw.commands.cmd_deploy._ensure_init")
    def test_deploy_with_clean_scanners(self, mock_init, mock_scanners, _which):
        from defenseclaw.commands.cmd_deploy import deploy

        mock_scanners.return_value = [
            ("skill-scanner", ".", ScanResult(
                scanner="skill-scanner", target=".",
                timestamp=datetime.now(timezone.utc),
            ), ""),
        ]
        app = _make_app()
        app.cfg.environment = "macos"

        result = _invoke(deploy, [".", "--skip-init"], app=app)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Total findings:   0", result.output)


if __name__ == "__main__":
    unittest.main()
