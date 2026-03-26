"""Tests for miscellaneous CLI commands — status, alerts, setup, aibom."""

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.models import Event
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
        self._orig_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "200"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._orig_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._orig_columns

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
# AIBOM command
# ---------------------------------------------------------------------------

class TestAIBOMCommand(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _make_inventory(self, skills=None):
        return {
            "version": 3,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "openclaw_config": "~/.openclaw/openclaw.json",
            "claw_home": "/tmp/claw",
            "claw_mode": "openclaw",
            "live": True,
            "skills": skills or [],
            "plugins": [],
            "mcp": [],
            "agents": [],
            "tools": [],
            "model_providers": [],
            "memory": [],
            "errors": [],
            "summary": {"total_items": 0, "skills": {"count": 0, "eligible": 0},
                         "plugins": {"count": 0, "loaded": 0, "disabled": 0},
                         "mcp": {"count": 0}, "agents": {"count": 0},
                         "tools": {"count": 0}, "model_providers": {"count": 0},
                         "memory": {"count": 0}, "errors": 0},
        }

    @patch("defenseclaw.inventory.claw_inventory.enrich_with_policy")
    @patch("defenseclaw.inventory.claw_inventory.claw_aibom_to_scan_result")
    @patch("defenseclaw.inventory.claw_inventory.build_claw_aibom")
    def test_scan_aibom(self, mock_build, mock_to_scan, mock_enrich):
        from defenseclaw.commands.cmd_aibom import aibom
        from defenseclaw.models import Finding, ScanResult

        inv = self._make_inventory(skills=[{"id": "test-skill", "eligible": True}])
        mock_build.return_value = inv
        mock_to_scan.return_value = ScanResult(
            scanner="aibom-claw",
            target="~/.openclaw/openclaw.json",
            timestamp=datetime.now(timezone.utc),
            findings=[
                Finding(id="claw-aibom-skills", severity="INFO", title="Skills (1)",
                        description="[]", scanner="aibom-claw"),
            ],
        )

        result = self.runner.invoke(aibom, ["scan"], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        mock_build.assert_called_once()

    @patch("defenseclaw.inventory.claw_inventory.enrich_with_policy")
    @patch("defenseclaw.inventory.claw_inventory.claw_aibom_to_scan_result")
    @patch("defenseclaw.inventory.claw_inventory.build_claw_aibom")
    def test_scan_json_output(self, mock_build, mock_to_scan, mock_enrich):
        from defenseclaw.commands.cmd_aibom import aibom
        from defenseclaw.models import ScanResult

        inv = self._make_inventory()
        mock_build.return_value = inv
        mock_to_scan.return_value = ScanResult(
            scanner="aibom-claw",
            target="~/.openclaw/openclaw.json",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        result = self.runner.invoke(
            aibom, ["scan", "--json"],
            obj=self.app, catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        json_start = result.output.index("{")
        data = json.loads(result.output[json_start:])
        self.assertIn("version", data)

    @patch("defenseclaw.inventory.claw_inventory.enrich_with_policy")
    @patch("defenseclaw.inventory.claw_inventory.claw_aibom_to_scan_result")
    @patch("defenseclaw.inventory.claw_inventory.build_claw_aibom")
    def test_scan_logs_scan(self, mock_build, mock_to_scan, mock_enrich):
        from defenseclaw.commands.cmd_aibom import aibom
        from defenseclaw.models import ScanResult

        inv = self._make_inventory()
        mock_build.return_value = inv
        mock_to_scan.return_value = ScanResult(
            scanner="aibom-claw",
            target="~/.openclaw/openclaw.json",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        self.runner.invoke(aibom, ["scan"], obj=self.app, catch_exceptions=False)
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


class TestSetupSkillScannerCommonConfig(unittest.TestCase):
    """Verify setup skill-scanner --non-interactive writes to inspect_llm."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_llm_provider_written_to_inspect_llm(self):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["skill-scanner", "--non-interactive", "--use-llm",
             "--llm-provider", "openai", "--llm-model", "gpt-4o"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.app.cfg.inspect_llm.provider, "openai")
        self.assertEqual(self.app.cfg.inspect_llm.model, "gpt-4o")
        self.assertTrue(self.app.cfg.scanners.skill_scanner.use_llm)

    def test_summary_shows_inspect_llm_section(self):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["skill-scanner", "--non-interactive", "--use-llm",
             "--llm-provider", "anthropic"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("inspect_llm.provider", result.output)

    def test_aidefense_flag_still_on_scanner_config(self):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["skill-scanner", "--non-interactive", "--use-aidefense"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(self.app.cfg.scanners.skill_scanner.use_aidefense)


class TestSetupMCPScannerCommonConfig(unittest.TestCase):
    """Verify setup mcp-scanner --non-interactive writes to inspect_llm."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_llm_provider_written_to_inspect_llm(self):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["mcp-scanner", "--non-interactive",
             "--llm-provider", "openai", "--llm-model", "gpt-4o",
             "--analyzers", "yara,llm"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.app.cfg.inspect_llm.provider, "openai")
        self.assertEqual(self.app.cfg.inspect_llm.model, "gpt-4o")

    def test_summary_shows_inspect_llm_section(self):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["mcp-scanner", "--non-interactive",
             "--llm-provider", "anthropic", "--llm-model", "claude-sonnet-4-20250514"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("inspect_llm.provider", result.output)
        self.assertIn("inspect_llm.model", result.output)

    def test_mcp_scanner_no_old_llm_flags(self):
        """The old --endpoint-url, --llm-base-url, --llm-timeout, --llm-max-retries flags are gone."""
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["mcp-scanner", "--help"],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("--endpoint-url", result.output)
        self.assertNotIn("--llm-base-url", result.output)
        self.assertNotIn("--llm-timeout", result.output)
        self.assertNotIn("--llm-max-retries", result.output)


# ---------------------------------------------------------------------------
# Setup Splunk command
# ---------------------------------------------------------------------------

class TestSetupSplunkCommand(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_setup_splunk_help(self):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(setup, ["splunk", "--help"], obj=self.app)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--o11y", result.output)
        self.assertIn("--logs", result.output)

    def test_setup_splunk_o11y_non_interactive(self):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["splunk", "--o11y", "--access-token", "test-tok", "--realm", "eu0",
             "--app-name", "myapp", "--non-interactive"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Splunk O11y configured", result.output)
        self.assertIn("eu0", result.output)

        otel = self.app.cfg.otel
        self.assertTrue(otel.enabled)
        self.assertEqual(otel.traces.endpoint, "ingest.eu0.observability.splunkcloud.com")
        self.assertEqual(otel.traces.protocol, "http")
        self.assertEqual(otel.traces.url_path, "/v2/trace/otlp")
        self.assertEqual(otel.metrics.endpoint, "ingest.eu0.observability.splunkcloud.com")
        self.assertEqual(otel.metrics.url_path, "/v2/datapoint/otlp")
        self.assertEqual(otel.headers.get("X-SF-Token"), "${SPLUNK_ACCESS_TOKEN}")

        dotenv_path = os.path.join(self.tmp_dir, ".env")
        self.assertTrue(os.path.exists(dotenv_path))
        with open(dotenv_path) as f:
            content = f.read()
        self.assertIn("SPLUNK_ACCESS_TOKEN=test-tok", content)
        self.assertIn("OTEL_SERVICE_NAME=myapp", content)

    @patch.dict(os.environ, {}, clear=False)
    def test_setup_splunk_o11y_requires_token(self):
        from defenseclaw.commands.cmd_setup import setup

        os.environ.pop("SPLUNK_ACCESS_TOKEN", None)
        result = self.runner.invoke(
            setup,
            ["splunk", "--o11y", "--non-interactive"],
            obj=self.app,
        )
        self.assertNotEqual(result.exit_code, 0)

    def test_setup_splunk_non_interactive_requires_flag(self):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["splunk", "--non-interactive"],
            obj=self.app,
        )
        self.assertNotEqual(result.exit_code, 0)

    def test_setup_splunk_disable_o11y(self):
        from defenseclaw.commands.cmd_setup import setup

        self.app.cfg.otel.enabled = True
        result = self.runner.invoke(
            setup,
            ["splunk", "--disable", "--o11y"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(self.app.cfg.otel.enabled)
        self.assertIn("O11y (OTLP): disabled", result.output)

    def test_setup_splunk_disable_logs(self):
        from defenseclaw.commands.cmd_setup import setup

        self.app.cfg.splunk.enabled = True
        result = self.runner.invoke(
            setup,
            ["splunk", "--disable", "--logs"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(self.app.cfg.splunk.enabled)
        self.assertIn("HEC): disabled", result.output)

    def test_setup_splunk_disable_both(self):
        from defenseclaw.commands.cmd_setup import setup

        self.app.cfg.otel.enabled = True
        self.app.cfg.splunk.enabled = True
        result = self.runner.invoke(
            setup,
            ["splunk", "--disable"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(self.app.cfg.otel.enabled)
        self.assertFalse(self.app.cfg.splunk.enabled)

    def test_setup_splunk_interactive_o11y(self):
        from defenseclaw.commands.cmd_setup import setup

        user_input = "\n".join([
            "y",           # Enable O11y?
            "us1",         # Realm
            "my-secret",   # Access token
            "test-svc",    # Service name
            "y",           # Traces?
            "y",           # Metrics?
            "n",           # Logs?
            "n",           # Enable local?
        ]) + "\n"

        result = self.runner.invoke(
            setup, ["splunk"], obj=self.app,
            input=user_input, catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(self.app.cfg.otel.enabled)
        self.assertEqual(self.app.cfg.otel.traces.endpoint, "ingest.us1.observability.splunkcloud.com")
        self.assertFalse(self.app.cfg.otel.logs.enabled)


if __name__ == "__main__":
    unittest.main()
