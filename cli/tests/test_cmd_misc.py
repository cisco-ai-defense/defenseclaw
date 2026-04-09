# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

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

    # ------------------------------------------------------------------
    # Helpers: existing tests updated to pass --no-tui (TUI is default)
    # ------------------------------------------------------------------

    def test_alerts_empty(self):
        from defenseclaw.commands.cmd_alerts import alerts
        result = self.runner.invoke(alerts, ["--no-tui"], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No alerts", result.output)

    def test_alerts_with_data(self):
        from defenseclaw.commands.cmd_alerts import alerts

        self.app.store.log_event(Event(action="scan", target="/skills/bad",
                                       severity="HIGH", details="found issues"))
        self.app.store.log_event(Event(action="scan", target="/skills/worse",
                                       severity="CRITICAL", details="major vulnerability"))

        result = self.runner.invoke(alerts, ["--no-tui"], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Security Alerts", result.output)
        self.assertIn("HIGH", result.output)
        self.assertIn("CRITICAL", result.output)

    def test_alerts_limit(self):
        from defenseclaw.commands.cmd_alerts import alerts

        for i in range(5):
            self.app.store.log_event(Event(action="scan", target=f"/skills/s{i}",
                                           severity="MEDIUM", details=f"issue {i}"))

        result = self.runner.invoke(alerts, ["--no-tui", "-n", "2"], obj=self.app,
                                    catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Security Alerts", result.output)

    def test_alerts_no_store(self):
        from defenseclaw.commands.cmd_alerts import alerts
        self.app.store = None
        result = self.runner.invoke(alerts, ["--no-tui"], obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No audit store", result.output)

    # ------------------------------------------------------------------
    # --show N: non-interactive single-alert detail
    # ------------------------------------------------------------------

    def test_alerts_show_prints_full_detail(self):
        from defenseclaw.commands.cmd_alerts import alerts

        self.app.store.log_event(Event(action="scan", target="/skills/bad",
                                       severity="HIGH",
                                       details="scanner=skill-scanner findings=2 max_severity=HIGH"))

        result = self.runner.invoke(alerts, ["--no-tui", "--show", "1"], obj=self.app,
                                    catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Alert #1", result.output)
        self.assertIn("HIGH", result.output)
        self.assertIn("/skills/bad", result.output)

    def test_alerts_show_out_of_range(self):
        from defenseclaw.commands.cmd_alerts import alerts

        self.app.store.log_event(Event(action="scan", target="/skills/x",
                                       severity="LOW", details="scanner=skill-scanner findings=0"))

        result = self.runner.invoke(alerts, ["--no-tui", "--show", "99"], obj=self.app,
                                    catch_exceptions=True)
        self.assertNotEqual(result.exit_code, 0)

    # ------------------------------------------------------------------
    # Helper functions
    # ------------------------------------------------------------------

    def test_trunc_path_short_returns_unchanged(self):
        from defenseclaw.commands.cmd_alerts import _trunc_path
        self.assertEqual(_trunc_path("/skills/foo", 20), "/skills/foo")

    def test_trunc_path_shows_tail(self):
        from defenseclaw.commands.cmd_alerts import _trunc_path
        result = _trunc_path("/Users/nikhil/.openclaw/workspace/skills/codeguard", 20)
        self.assertIn("codeguard", result)
        self.assertTrue(result.startswith("…"))

    def test_trunc_path_two_components_when_one_fits(self):
        from defenseclaw.commands.cmd_alerts import _trunc_path
        # "…/skills/codeguard" = 19 chars; fits in 20 but full path is 34 chars
        result = _trunc_path("/home/user/workspace/skills/codeguard", 20)
        # "codeguard" (9+2=11) fits first; "skills/codeguard" (16+2=18) also fits
        # function returns smallest suffix that fits → "…/codeguard"
        self.assertTrue(result.startswith("…/"))
        self.assertIn("codeguard", result)
        self.assertLessEqual(len(result), 20)

    def test_humanize_details_port_only(self):
        from defenseclaw.commands.cmd_alerts import _humanize_details
        self.assertEqual(_humanize_details("port=4000"), ":4000")

    def test_humanize_details_host_and_port(self):
        from defenseclaw.commands.cmd_alerts import _humanize_details
        self.assertEqual(_humanize_details("host=127.0.0.1 port=18789"), "127.0.0.1:18789")

    def test_humanize_details_mode(self):
        from defenseclaw.commands.cmd_alerts import _humanize_details
        self.assertIn("observe", _humanize_details("mode=observe port=4000"))

    def test_humanize_details_plain_text_unchanged(self):
        from defenseclaw.commands.cmd_alerts import _humanize_details
        self.assertEqual(_humanize_details("starting all subsystems"), "starting all subsystems")

    def test_humanize_details_strips_scanner_and_severity(self):
        from defenseclaw.commands.cmd_alerts import _humanize_details
        result = _humanize_details("scanner=skill-scanner findings=19 max_severity=CRITICAL duration=0.28")
        self.assertNotIn("scanner", result)
        self.assertNotIn("max_severity", result)
        self.assertNotIn("findings", result)
        self.assertIn("duration", result)

    def test_findings_json_fits_all(self):
        from defenseclaw.commands.cmd_alerts import _findings_json
        findings = [{"severity": "HIGH", "title": "Shell exec"}]
        result = _findings_json(findings, 200)
        data = json.loads(result)
        self.assertEqual(data[0]["severity"], "HIGH")
        self.assertEqual(data[0]["title"], "Shell exec")

    def test_findings_json_truncates_with_ellipsis(self):
        from defenseclaw.commands.cmd_alerts import _findings_json
        findings = [
            {"severity": "CRITICAL", "title": "GitHub token detected"},
            {"severity": "HIGH",     "title": "Shell command execution"},
            {"severity": "MEDIUM",   "title": "Code execution"},
        ]
        result = _findings_json(findings, 50)
        self.assertTrue(result.endswith("…") or result.startswith("["))
        self.assertLessEqual(len(result), 50)

    # ------------------------------------------------------------------
    # DB: get_findings_for_target / get_severity_counts_for_target
    # ------------------------------------------------------------------

    def _insert_scan_with_findings(self, target, scanner, findings):
        """Helper: insert a scan_result and its findings into the store."""
        import uuid
        from datetime import timedelta
        scan_id = str(uuid.uuid4())
        max_sev = findings[0]["severity"] if findings else "INFO"
        self.app.store.insert_scan_result(
            scan_id=scan_id, scanner=scanner, target=target,
            ts=datetime.now(timezone.utc), duration_ms=100,
            finding_count=len(findings), max_severity=max_sev, raw_json="{}",
        )
        for f in findings:
            self.app.store.insert_finding(
                finding_id=str(uuid.uuid4()), scan_id=scan_id,
                severity=f["severity"], title=f["title"],
                description="", location=f.get("location", ""),
                remediation="", scanner=scanner, tags="",
            )
        return scan_id

    def test_get_findings_for_target_returns_findings(self):
        self._insert_scan_with_findings(
            "/skills/test", "skill-scanner",
            [{"severity": "CRITICAL", "title": "Token leak", "location": "main.py:5"},
             {"severity": "MEDIUM",   "title": "Code exec",  "location": ""}],
        )
        results = self.app.store.get_findings_for_target("/skills/test", "skill-scanner")
        self.assertEqual(len(results), 2)
        # ordered by severity: CRITICAL first
        self.assertEqual(results[0]["severity"], "CRITICAL")
        self.assertEqual(results[0]["title"], "Token leak")

    def test_get_findings_for_target_only_latest_scan(self):
        """When two scans exist for the same target, only latest scan's findings returned."""
        self._insert_scan_with_findings("/skills/x", "skill-scanner",
                                        [{"severity": "HIGH", "title": "Old finding"}])
        self._insert_scan_with_findings("/skills/x", "skill-scanner",
                                        [{"severity": "LOW", "title": "New finding"}])
        results = self.app.store.get_findings_for_target("/skills/x", "skill-scanner")
        titles = [r["title"] for r in results]
        self.assertIn("New finding", titles)
        self.assertNotIn("Old finding", titles)

    def test_get_findings_for_target_empty(self):
        results = self.app.store.get_findings_for_target("/nonexistent", "skill-scanner")
        self.assertEqual(results, [])

    def test_get_severity_counts_for_target(self):
        self._insert_scan_with_findings(
            "/skills/count", "skill-scanner",
            [{"severity": "CRITICAL", "title": "A"},
             {"severity": "MEDIUM",   "title": "B"},
             {"severity": "MEDIUM",   "title": "C"}],
        )
        counts = self.app.store.get_severity_counts_for_target("/skills/count", "skill-scanner")
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["MEDIUM"], 2)
        self.assertNotIn("HIGH", counts)

    def test_get_severity_counts_empty(self):
        counts = self.app.store.get_severity_counts_for_target("/nothing", "skill-scanner")
        self.assertEqual(counts, {})


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
        self.assertIn("--accept-splunk-license", result.output)

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

    def test_setup_splunk_logs_non_interactive_requires_license_flag(self):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["splunk", "--logs", "--non-interactive"],
            obj=self.app,
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--accept-splunk-license", result.output)

    @patch("defenseclaw.commands.cmd_setup._apply_logs_config")
    @patch("defenseclaw.commands.cmd_setup._preflight_docker", return_value=True)
    def test_setup_splunk_logs_non_interactive_with_license_flag(
        self, _mock_preflight, mock_apply_logs_config,
    ):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["splunk", "--logs", "--non-interactive", "--accept-splunk-license"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Local Splunk configured (Free mode from day 1)", result.output)
        mock_apply_logs_config.assert_called_once()

    @patch("defenseclaw.commands.cmd_setup._preflight_docker", return_value=True)
    @patch("defenseclaw.commands.cmd_setup.subprocess.run")
    @patch("defenseclaw.commands.cmd_setup.splunk_bridge_bin", return_value="/tmp/fake-splunk-claw-bridge")
    def test_setup_splunk_logs_bootstrap_bridge_free_mode(
        self, _mock_bridge_bin, mock_run, _mock_preflight,
    ):
        from defenseclaw.commands.cmd_setup import setup

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                {
                    "splunk_web_url": "http://127.0.0.1:8000",
                    "hec_url": "http://127.0.0.1:8088/services/collector/event",
                    "hec_token": "bootstrap-token",
                    "license_group": "Free",
                    "web_login_required": False,
                    "index": "defenseclaw_local",
                    "source": "defenseclaw",
                    "sourcetype": "defenseclaw:json",
                }
            ),
            stderr="",
        )

        result = self.runner.invoke(
            setup,
            ["splunk", "--logs", "--non-interactive", "--accept-splunk-license"],
            obj=self.app,
            catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(self.app.cfg.splunk.enabled)
        self.assertEqual(self.app.cfg.splunk.hec_endpoint, "http://127.0.0.1:8088/services/collector/event")
        self.assertEqual(self.app.cfg.splunk.hec_token_env, "DEFENSECLAW_SPLUNK_HEC_TOKEN")
        self.assertIn("Local Splunk is ready", result.output)
        self.assertIn("License: Free", result.output)
        self.assertIn("Web login: not required", result.output)
        self.assertNotIn("Username:", result.output)
        self.assertIn("Local Splunk configured (Free mode from day 1)", result.output)
        self.assertIn("Free mode is active, so no local Splunk login is required.", result.output)

    @patch("defenseclaw.commands.cmd_setup._bootstrap_bridge", return_value=None)
    @patch("defenseclaw.commands.cmd_setup._preflight_docker", return_value=True)
    def test_setup_splunk_logs_non_interactive_fails_when_bridge_bootstrap_fails(
        self, _mock_preflight, _mock_bootstrap_bridge,
    ):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["splunk", "--logs", "--non-interactive", "--accept-splunk-license"],
            obj=self.app,
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertFalse(self.app.cfg.splunk.enabled)
        self.assertNotIn("Local Splunk configured (Free mode from day 1)", result.output)

    @patch("defenseclaw.commands.cmd_setup._preflight_docker")
    def test_setup_splunk_logs_interactive_decline_license(self, mock_preflight):
        from defenseclaw.commands.cmd_setup import setup

        user_input = "\n".join([
            "n",           # Enable O11y?
            "y",           # Enable local logs?
            "n",           # Accept Splunk license?
        ]) + "\n"

        result = self.runner.invoke(
            setup, ["splunk"], obj=self.app,
            input=user_input, catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Local Splunk enablement cancelled.", result.output)
        self.assertFalse(self.app.cfg.splunk.enabled)
        mock_preflight.assert_not_called()

    @patch("defenseclaw.commands.cmd_setup._preflight_docker")
    def test_setup_splunk_o11y_and_logs_interactive_decline_logs_preserves_o11y(
        self, mock_preflight,
    ):
        from defenseclaw.commands.cmd_setup import setup

        result = self.runner.invoke(
            setup,
            ["splunk", "--o11y", "--logs", "--access-token", "test-tok", "--realm", "us1"],
            obj=self.app,
            input="n\n",
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Splunk O11y configured", result.output)
        self.assertIn("Local Splunk enablement cancelled.", result.output)
        self.assertIn("Config saved to ~/.defenseclaw/config.yaml", result.output)
        self.assertTrue(self.app.cfg.otel.enabled)
        self.assertFalse(self.app.cfg.splunk.enabled)
        mock_preflight.assert_not_called()

        config_path = os.path.join(self.tmp_dir, "config.yaml")
        self.assertTrue(os.path.exists(config_path))
        with open(config_path) as f:
            content = f.read()
        self.assertIn("otel:", content)

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
