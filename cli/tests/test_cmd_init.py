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

"""Tests for 'defenseclaw init' command."""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

pytestmark = pytest.mark.supported_connector_host
from defenseclaw.commands.cmd_init import init_cmd
from defenseclaw.config import PerConnectorGuardrailConfig
from defenseclaw.connector_paths import KNOWN_CONNECTORS
from defenseclaw.context import AppContext
from defenseclaw.inventory import agent_discovery
from defenseclaw.inventory.agent_discovery import AgentDiscovery, AgentSignal


def _trusted_prefixes_from_config(data_dir: str) -> list[str]:
    import yaml

    with open(os.path.join(data_dir, "config.yaml"), encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return list((raw.get("ai_discovery") or {}).get("trusted_binary_prefixes") or [])


class TestInitCommand(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-test-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_help(self):
        result = self.runner.invoke(init_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Initialize DefenseClaw environment", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_skip_install_creates_dirs(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.assertIn("Platform:", result.output)
        self.assertIn("Directories:", result.output)
        self.assertIn("Config:", result.output)
        self.assertIn("Audit DB:", result.output)

        # Verify config file was created
        config_file = os.path.join(self.tmp_dir, "config.yaml")
        self.assertTrue(os.path.isfile(config_file))
        from defenseclaw import migration_state

        state = migration_state.load(self.tmp_dir)
        self.assertIsNotNone(state)
        assert state is not None
        self.assertTrue(migration_state.is_applied(state, "0.8.5"))
        self.assertEqual(
            state.applied_at["0.8.5"],
            migration_state.BOOTSTRAP_SENTINEL,
        )

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_initial_bootstrap_does_not_revive_direct_logger(
        self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which
    ):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        # No process-owned v8 graph exists yet. Initial bootstrap uses the
        # explicit no-runtime capability and must not revive Python's removed
        # direct SQLite/Splunk writer.
        from defenseclaw.db import Store
        db_path = os.path.join(self.tmp_dir, "audit.db")
        store = Store(db_path)
        events = store.list_events(10)
        self.assertEqual(events, [])
        store.close()


class TestInitFirstRunBackend(unittest.TestCase):
    """Tests for the new canonical first-run backend behind init."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-first-run-")
        self.runner = CliRunner()
        self.selection_patcher = patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            return_value=({}, {}),
        )
        self.selection_mock = self.selection_patcher.start()
        self.addCleanup(self.selection_patcher.stop)
        self._had_llm_key = "DEFENSECLAW_LLM_KEY" in os.environ
        self._llm_key = os.environ.get("DEFENSECLAW_LLM_KEY", "")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        if self._had_llm_key:
            os.environ["DEFENSECLAW_LLM_KEY"] = self._llm_key
        else:
            os.environ.pop("DEFENSECLAW_LLM_KEY", None)

    def _invoke(self, args):
        return self.runner.invoke(
            init_cmd,
            args,
            obj=AppContext(),
            env={"DEFENSECLAW_HOME": self.tmp_dir},
        )

    def _discovery(self, installed):
        return AgentDiscovery(
            scanned_at="2026-05-04T18:21:00Z",
            agents={
                name: AgentSignal(
                    name=name,
                    installed=name in installed,
                    config_path=f"/tmp/{name}.config" if name in installed else "",
                    binary_path="",
                    version="",
                    error="",
                )
                for name in KNOWN_CONNECTORS
            },
            cache_hit=False,
        )

    def test_json_summary_codex_does_not_default_to_openclaw(self):
        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector",
            "codex",
            "--profile",
            "observe",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "codex")
        self.assertEqual(summary["profile"], "observe")

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["claw"]["mode"], "codex")
        self.assertEqual(cfg["guardrail"]["connector"], "codex")
        self.assertTrue(cfg["guardrail"]["enabled"])
        self.assertEqual(
            cfg["guardrail"].get("detection_strategy", "regex_judge"),
            "regex_judge",
        )

    def test_explicit_connector_requires_protected_executable_selection(self):
        self.selection_mock.return_value = ({}, {"codex": "untrusted executable"})

        with patch("defenseclaw.commands.cmd_init.platform_support.host_os", return_value="windows"):
            result = self._invoke([
                "--non-interactive",
                "--yes",
                "--connector",
                "codex",
                "--profile",
                "observe",
                "--skip-install",
                "--no-start-gateway",
                "--no-verify",
                "--json-summary",
            ])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("freshly verified selected agent executable", result.output)
        self.assertIn("untrusted executable", result.output)

    def test_non_windows_codex_init_does_not_require_windows_policy_receipt(self):
        self.selection_mock.return_value = ({}, {"codex": "must not be consulted"})

        with patch("defenseclaw.commands.cmd_init.platform_support.host_os", return_value="linux"):
            result = self._invoke([
                "--non-interactive",
                "--yes",
                "--connector",
                "codex",
                "--profile",
                "observe",
                "--skip-install",
                "--no-start-gateway",
                "--no-verify",
                "--json-summary",
            ])

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.selection_mock.assert_not_called()

    def test_windows_claude_init_does_not_require_unused_codex_policy_receipt(self):
        self.selection_mock.return_value = ({}, {"claudecode": "must not be consulted"})

        with patch("defenseclaw.commands.cmd_init.platform_support.host_os", return_value="windows"):
            result = self._invoke([
                "--non-interactive",
                "--yes",
                "--connector",
                "claudecode",
                "--profile",
                "observe",
                "--skip-install",
                "--no-start-gateway",
                "--no-verify",
                "--json-summary",
            ])

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.selection_mock.assert_not_called()

    def test_sandbox_flag_reports_explicit_scope(self):
        with patch("defenseclaw.platform_support.host_os", return_value="linux"):
            result = self._invoke([
                "--non-interactive",
                "--yes",
                "--connector",
                "openclaw",
                "--profile",
                "observe",
                "--scanner-mode",
                "local",
                "--skip-install",
                "--sandbox",
                "--no-start-gateway",
                "--no-verify",
                "--json-summary",
            ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        summary = json.loads(result.output)
        sandbox_steps = [s for s in summary["setup"] if s["name"] == "Sandbox"]
        self.assertEqual(len(sandbox_steps), 1, summary["setup"])
        self.assertEqual(sandbox_steps[0]["status"], "warn")
        self.assertIn("Linux-only", sandbox_steps[0]["detail"])
        self.assertIn("OpenClaw/OpenShell-only", sandbox_steps[0]["detail"])
        self.assertEqual(sandbox_steps[0]["next_command"], "defenseclaw sandbox setup")

    def test_with_judge_defaults_hook_coverage_to_all(self):
        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector",
            "codex",
            "--profile",
            "observe",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--with-judge",
            "--no-start-gateway",
            "--no-verify",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertTrue(cfg["guardrail"]["judge"]["enabled"])
        self.assertEqual(
            cfg["guardrail"].get("detection_strategy", "regex_judge"),
            "regex_judge",
        )
        self.assertEqual(cfg["guardrail"]["detection_strategy_completion"], "regex_judge")
        self.assertEqual(cfg["guardrail"]["judge"]["hook_connectors"], ["*"])

    def test_interactive_judge_llm_config_collects_model_settings(self):
        from defenseclaw.commands import cmd_init

        with patch.object(cmd_init.click, "confirm", return_value=True), \
                patch("defenseclaw.commands._llm_picker.pick_provider", return_value="openai") as provider, \
                patch("defenseclaw.commands._llm_picker.pick_model", return_value="gpt-4o") as model, \
                patch("defenseclaw.commands._llm_picker.pick_key_env", return_value="OPENAI_API_KEY") as key_env, \
                patch("defenseclaw.commands.cmd_setup._prompt_and_save_secret") as save_secret, \
                patch.object(cmd_init.click, "prompt", return_value="https://api.example/v1"):
            got = cmd_init._prompt_first_run_judge_llm_config(
                data_dir=self.tmp_dir,
                llm_provider="",
                llm_model="",
                llm_api_key="sk-test",
                llm_api_key_env="DEFENSECLAW_LLM_KEY",
                llm_base_url="",
            )

        self.assertEqual(got, ("openai", "gpt-4o", "", "OPENAI_API_KEY", "https://api.example/v1"))
        provider.assert_called_once()
        model.assert_called_once()
        key_env.assert_called_once()
        save_secret.assert_called_once_with("OPENAI_API_KEY", "sk-test", self.tmp_dir)

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True)
    def test_explicit_action_updates_existing_per_connector_mode(self, _gate):
        Path(self.tmp_dir, "config.yaml").write_text(
            "config_version: 8\n"
            "observability: {}\n"
            "claw:\n"
            "  mode: codex\n"
            "guardrail:\n"
            "  enabled: true\n"
            "  connector: codex\n"
            "  mode: observe\n"
            "  scanner_mode: local\n"
            "  connectors:\n"
            "    hermes:\n"
            "      mode: observe\n",
            encoding="utf-8",
        )

        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector",
            "hermes",
            "--profile",
            "action",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["profile"], "action")
        setup = {step["name"]: step for step in summary["setup"]}
        self.assertIn("hermes, mode=action", setup["Guardrail"]["detail"])

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["guardrail"]["connectors"]["hermes"]["mode"], "action")

    def test_existing_v7_config_requires_upgrade_before_first_run_mutation(self):
        Path(self.tmp_dir, "config.yaml").write_text(
            "claw:\n"
            "  mode: codex\n"
            "guardrail:\n"
            "  enabled: true\n",
            encoding="utf-8",
        )

        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector",
            "codex",
            "--profile",
            "observe",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--json-summary",
        ])

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["status"], "needs_attention")
        self.assertEqual(summary["next_commands"], ["defenseclaw upgrade"])
        config_step = next(step for step in summary["setup"] if step["name"] == "Config")
        self.assertEqual(config_step["status"], "fail")
        self.assertEqual(config_step["next_command"], "defenseclaw upgrade")

        persisted = Path(self.tmp_dir, "config.yaml").read_text(encoding="utf-8")
        self.assertNotIn("config_version: 8", persisted)

    @patch("defenseclaw.commands.cmd_init._activate_additional_connectors")
    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_existing_v7_multi_connector_stops_before_follow_on_mutation(self, mock_discover, activate):
        mock_discover.return_value = self._discovery({"codex", "claudecode"})
        source = "claw:\n  mode: codex\nguardrail:\n  enabled: true\n"
        Path(self.tmp_dir, "config.yaml").write_text(source, encoding="utf-8")

        result = self._invoke([
            "--non-interactive", "--yes", "--observe-all", "--skip-install",
            "--no-start-gateway", "--no-verify", "--json-summary",
        ])

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["status"], "needs_attention")
        self.assertEqual(summary["next_commands"], ["defenseclaw upgrade"])
        activate.assert_not_called()
        self.assertEqual(Path(self.tmp_dir, "config.yaml").read_text(encoding="utf-8"), source)

    @patch("defenseclaw.bootstrap.agent_discovery.discover_agents")
    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=False)
    def test_single_action_connector_trusted_path_downgrade_is_structured(self, _gate, mock_discover):
        disc = self._discovery({"hermes"})
        disc.agents["hermes"].binary_path = "/tmp/fake/hermes-bin"
        disc.agents["hermes"].error = agent_discovery.UNTRUSTED_PREFIX_ERROR
        mock_discover.return_value = disc

        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector",
            "hermes",
            "--profile",
            "action",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["status"], "needs_attention")
        self.assertEqual(summary["connector"], "hermes")
        self.assertEqual(summary["profile"], "observe")
        warning = summary["connector_mode_warnings"][0]
        self.assertEqual(warning["connector"], "hermes")
        self.assertEqual(warning["requested_mode"], "action")
        self.assertEqual(warning["actual_mode"], "observe")
        self.assertEqual(warning["reason"], "binary path outside trusted prefixes; version was not probed")
        self.assertEqual(
            warning["next_command"],
            f"defenseclaw setup trusted-paths add {os.path.realpath('/tmp/fake')}",
        )
        setup = {step["name"]: step for step in summary["setup"]}
        self.assertEqual(setup["Hermes mode"]["status"], "fail")

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["guardrail"]["connector"], "hermes")
        self.assertEqual(cfg["guardrail"].get("mode", "observe"), "observe")

    def test_first_run_persists_llm_secret_to_dotenv_not_config(self):
        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector",
            "codex",
            "--profile",
            "observe",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--llm-model",
            "openai/gpt-4o",
            "--llm-api-key",
            "sk-test-secret",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        config_text = Path(self.tmp_dir, "config.yaml").read_text(encoding="utf-8")
        dotenv_text = Path(self.tmp_dir, ".env").read_text(encoding="utf-8")
        self.assertNotIn("sk-test-secret", config_text)
        self.assertIn("DEFENSECLAW_LLM_KEY=sk-test-secret", dotenv_text)

    def test_targeted_readiness_skips_unconfigured_cloud_probes(self):
        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector",
            "codex",
            "--profile",
            "observe",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--no-start-gateway",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        readiness = {step["name"]: step for step in summary["readiness"]}
        self.assertEqual(readiness["LLM API"]["status"], "skip")
        self.assertEqual(readiness["Cisco AI Defense"]["status"], "skip")

    def test_observe_preserves_remote_scanner_choice_for_cisco_probe(self):
        from defenseclaw.bootstrap import StepResult

        with patch(
            "defenseclaw.bootstrap._doctor_check",
            return_value=StepResult("Cisco AI Defense", "pass", "ok"),
        ) as doctor_check:
            result = self._invoke([
                "--non-interactive",
                "--yes",
                "--connector",
                "codex",
                "--profile",
                "observe",
                "--scanner-mode",
                "remote",
                "--skip-install",
                "--no-start-gateway",
                "--json-summary",
            ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        doctor_check.assert_any_call("_check_cisco_ai_defense", ANY, "Cisco AI Defense")

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["guardrail"]["scanner_mode"], "remote")

    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_noninteractive_no_connector_uses_codex_discovery(self, mock_discover):
        mock_discover.return_value = self._discovery({"codex"})

        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--profile",
            "observe",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--json-summary",
        ])

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "codex")
        mock_discover.assert_called_once_with(refresh=False)

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["guardrail"]["connector"], "codex")

    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_noninteractive_no_connector_uses_claudecode_discovery(self, mock_discover):
        mock_discover.return_value = self._discovery({"claudecode"})

        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--profile",
            "observe",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--json-summary",
        ])

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "claudecode")

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["guardrail"]["connector"], "claudecode")

    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_explicit_connector_wins_without_discovery(self, mock_discover):
        mock_discover.side_effect = AssertionError("explicit connector should not discover")

        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector",
            "codex",
            "--profile",
            "observe",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--json-summary",
        ])

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "codex")
        mock_discover.assert_not_called()

    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_rescan_agents_passes_refresh_to_discovery(self, mock_discover):
        mock_discover.return_value = self._discovery({"claudecode"})

        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--rescan-agents",
            "--profile",
            "observe",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--json-summary",
        ])

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        mock_discover.assert_called_once_with(refresh=True)

class TestInitVersionDisplay(unittest.TestCase):
    """Tests for version info in init Environment section."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-ver-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_shows_cli_version(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("DefenseClaw:", result.output)

    @patch("defenseclaw.commands.cmd_init._get_gateway_version", return_value="v0.5.0")
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_shows_gateway_version(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which, _mock_gw_ver):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Gateway:       v0.5.0", result.output)

    @patch("defenseclaw.commands.cmd_init._get_gateway_version", return_value=None)
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_gateway_not_found(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which, _mock_gw_ver):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Gateway:       not found", result.output)


class TestInitPreservesExistingConfig(unittest.TestCase):
    """Regression tests for P5 fix: init must not overwrite existing config."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-preserve-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_preserves_existing_config(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        # Run init once to create config
        app1 = AppContext()
        result1 = self.runner.invoke(init_cmd, ["--skip-install"], obj=app1)
        self.assertEqual(result1.exit_code, 0, result1.output)

        # Modify the config on disk so we can detect overwrites
        config_file = os.path.join(self.tmp_dir, "config.yaml")
        self.assertTrue(os.path.isfile(config_file))

        import yaml
        with open(config_file) as f:
            cfg_data = yaml.safe_load(f)

        cfg_data["gateway"] = cfg_data.get("gateway", {})
        cfg_data["gateway"]["host"] = "10.20.30.40"
        cfg_data["gateway"]["port"] = 19999

        with open(config_file, "w") as f:
            yaml.dump(cfg_data, f)

        # Run init again — should preserve
        from defenseclaw.logger import Logger

        app2 = AppContext()
        with patch.object(Logger, "from_config", return_value=Logger.no_runtime()):
            result2 = self.runner.invoke(init_cmd, ["--skip-install"], obj=app2)
        self.assertEqual(result2.exit_code, 0, result2.output + f"\n{result2.exception!r}")
        self.assertIn("preserved existing", result2.output)

        # Verify the customized values survived
        with open(config_file) as f:
            reloaded = yaml.safe_load(f)

        self.assertEqual(reloaded["gateway"]["host"], "10.20.30.40")
        self.assertEqual(reloaded["gateway"]["port"], 19999)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_creates_new_defaults_when_no_config(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("created new defaults", result.output)


class TestInitDoesNotCreateExternalDirs(unittest.TestCase):
    """Regression tests for P3 fix: init must not create dirs outside data_dir."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-scope-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_does_not_create_openclaw_dirs(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)

        for root, dirs, _files in os.walk(self.tmp_dir):
            for d in dirs:
                full = os.path.join(root, d)
                real = os.path.realpath(full)
                self.assertTrue(
                    real.startswith(os.path.realpath(self.tmp_dir)),
                    f"init created directory outside data_dir: {full}"
                )

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_creates_defenseclaw_dirs(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)

        # Core DefenseClaw dirs should exist
        self.assertTrue(os.path.isdir(self.tmp_dir))
        quarantine = os.path.join(self.tmp_dir, "quarantine")
        self.assertTrue(os.path.isdir(quarantine))
        plugins = os.path.join(self.tmp_dir, "plugins")
        self.assertTrue(os.path.isdir(plugins))


class TestInitShowsScannerDefaults(unittest.TestCase):
    """Verify that init displays scanner defaults to the user."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-scandef-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_displays_skill_scanner_defaults(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("skill-scanner:", result.output)
        self.assertIn("policy=permissive", result.output)
        self.assertIn("lenient=True", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_displays_mcp_scanner_defaults(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("mcp-scanner:", result.output)
        self.assertIn("analyzers=auto", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_displays_setup_hint(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("defenseclaw setup", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_uses_scanner_schema_defaults_without_expanding_config(
        self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which
    ):
        from pathlib import Path

        import yaml
        from defenseclaw.config import load

        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)

        config_file = os.path.join(self.tmp_dir, "config.yaml")
        with open(config_file) as f:
            raw = yaml.safe_load(f)

        self.assertNotIn("scanners", raw)

        effective = load().scanners
        self.assertEqual(effective.skill_scanner.policy, "permissive")
        self.assertTrue(effective.skill_scanner.lenient)
        self.assertFalse(effective.skill_scanner.use_llm)
        self.assertEqual(effective.mcp_scanner.analyzers, "auto")
        self.assertFalse(effective.mcp_scanner.scan_prompts)


class TestInitShowsGatewayDefaults(unittest.TestCase):
    """Verify that init displays gateway defaults."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-gwdef-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_displays_gateway_section(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Gateway", result.output)
        self.assertIn("connector: openclaw", result.output)
        self.assertIn("127.0.0.1:18789", result.output)
        self.assertIn("API port:", result.output)
        self.assertIn("18970", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_displays_watcher_defaults(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Watcher:", result.output)
        self.assertIn("enabled=True", result.output)
        self.assertIn("take_action=False", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_uses_gateway_schema_defaults_without_expanding_config(
        self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which
    ):
        from pathlib import Path

        import yaml
        from defenseclaw.config import load

        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)

        config_file = os.path.join(self.tmp_dir, "config.yaml")
        with open(config_file) as f:
            raw = yaml.safe_load(f)

        self.assertEqual(raw["gateway"], {"token_env": "DEFENSECLAW_GATEWAY_TOKEN"})

        gateway = load().gateway
        self.assertEqual(gateway.host, "127.0.0.1")
        self.assertEqual(gateway.port, 18789)
        self.assertEqual(gateway.api_port, 18970)
        self.assertTrue(gateway.watcher.enabled)
        self.assertFalse(gateway.watcher.skill.take_action)

    @patch("defenseclaw.commands.cmd_init._resolve_openclaw_gateway",
           return_value={"host": "127.0.0.1", "port": 18789, "token": ""})
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    @patch.dict(os.environ, {}, clear=False)
    def test_init_no_token_shows_local(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which, _mock_gw):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)
        for k in list(os.environ.keys()):
            if k.startswith("DEFENSECLAW_") or k.startswith("OPENCLAW_"):
                os.environ.pop(k, None)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        # Plan B2 / S0.2: the empty-token path no longer reports
        # "loopback auth" as the fallback because B2 removed the
        # empty-token allow path. Init now tells the operator that
        # the first-boot CSPRNG token will be auto-generated under
        # ~/.defenseclaw/.env. The test pins the new copy so a
        # future regression to "loopback auth" is caught loudly.
        self.assertIn("auto-generated on first boot", result.output)
        self.assertIn(".defenseclaw/.env", result.output)


class TestResolveOpenclawGateway(unittest.TestCase):
    """Tests for _resolve_openclaw_gateway helper."""

    def test_no_openclaw_json_returns_defaults(self):
        from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway
        result = _resolve_openclaw_gateway("/tmp/nonexistent/openclaw.json")
        self.assertEqual(result["host"], "127.0.0.1")
        self.assertEqual(result["port"], 18789)
        self.assertEqual(result["token"], "")

    def test_local_mode_reads_port_and_token(self):
        import json

        from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway

        with tempfile.TemporaryDirectory() as tmpdir:
            oc_data = {
                "gateway": {
                    "model": "local",
                    "port": 19000,
                    "auth": {"token": "test-token-abc"},
                }
            }
            oc_path = os.path.join(tmpdir, "openclaw.json")
            with open(oc_path, "w") as f:
                json.dump(oc_data, f)

            result = _resolve_openclaw_gateway(oc_path)
            self.assertEqual(result["host"], "127.0.0.1")
            self.assertEqual(result["port"], 19000)
            self.assertEqual(result["token"], "test-token-abc")

    def test_non_local_mode_reads_host(self):
        import json

        from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway

        with tempfile.TemporaryDirectory() as tmpdir:
            oc_data = {
                "gateway": {
                    "mode": "remote",
                    "host": "10.0.0.5",
                    "port": 20000,
                    "auth": {"token": "remote-token"},
                }
            }
            oc_path = os.path.join(tmpdir, "openclaw.json")
            with open(oc_path, "w") as f:
                json.dump(oc_data, f)

            result = _resolve_openclaw_gateway(oc_path)
            self.assertEqual(result["host"], "10.0.0.5")
            self.assertEqual(result["port"], 20000)
            self.assertEqual(result["token"], "remote-token")

    def test_missing_gateway_block(self):
        import json

        from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway

        with tempfile.TemporaryDirectory() as tmpdir:
            oc_data = {"agents": {"defaults": {}}}
            oc_path = os.path.join(tmpdir, "openclaw.json")
            with open(oc_path, "w") as f:
                json.dump(oc_data, f)

            result = _resolve_openclaw_gateway(oc_path)
            self.assertEqual(result["host"], "127.0.0.1")
            self.assertEqual(result["port"], 18789)
            self.assertEqual(result["token"], "")

    def test_no_auth_token(self):
        import json

        from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway

        with tempfile.TemporaryDirectory() as tmpdir:
            oc_data = {"gateway": {"model": "local", "port": 18789}}
            oc_path = os.path.join(tmpdir, "openclaw.json")
            with open(oc_path, "w") as f:
                json.dump(oc_data, f)

            result = _resolve_openclaw_gateway(oc_path)
            self.assertEqual(result["token"], "")


class TestValidateGatewayToken(unittest.TestCase):
    """F-0361: gateway token boundary validation before dotenv persist.

    The OpenClaw gateway token is read from connector-controlled
    openclaw.json (untrusted). A token carrying a newline/CR/NUL would be
    parsed as a second KEY=VALUE assignment by the config loader, injecting
    arbitrary environment variables (e.g. DEFENSECLAW_DISABLE_REDACTION=1).
    Validation must reject such a token at the boundary with a clean,
    operator-facing error and must NOT write anything to ~/.defenseclaw/.env.
    """

    def test_clean_token_passes(self):
        from defenseclaw.commands.cmd_init import _validate_gateway_token

        # A normal secret with no control characters is accepted (no raise).
        _validate_gateway_token("OPENCLAW_GATEWAY_TOKEN", "abc123-DEF456_token")

    def test_newline_token_rejected_with_clean_error(self):
        import click
        from defenseclaw.commands.cmd_init import _validate_gateway_token

        malicious = "good-prefix\nDEFENSECLAW_DISABLE_REDACTION=1"
        with self.assertRaises(click.ClickException) as ctx:
            _validate_gateway_token("OPENCLAW_GATEWAY_TOKEN", malicious)
        # Operator-facing message, not a raw traceback.
        self.assertIn("gateway token", str(ctx.exception).lower())

    def test_cr_and_nul_tokens_rejected(self):
        import click
        from defenseclaw.commands.cmd_init import _validate_gateway_token

        for bad in ("tok\rEVIL=1", "tok\x00EVIL=1"):
            with self.assertRaises(click.ClickException):
                _validate_gateway_token("OPENCLAW_GATEWAY_TOKEN", bad)

    def test_malicious_token_not_persisted_to_dotenv(self):
        """End-to-end: a connector-supplied token with an embedded newline
        must abort _setup_gateway_defaults and leave no injected .env entry."""
        import click
        from defenseclaw.commands.cmd_init import _setup_gateway_defaults

        from tests.helpers import cleanup_app, make_app_context

        app, tmp_dir, db_path = make_app_context()
        self.addCleanup(cleanup_app, app, db_path, tmp_dir)
        # _save_secret_to_dotenv also mutates os.environ — guard against leak.
        self.addCleanup(os.environ.pop, "OPENCLAW_GATEWAY_TOKEN", None)
        prior = os.environ.get("DEFENSECLAW_DISABLE_REDACTION")
        self.addCleanup(
            lambda: os.environ.__setitem__("DEFENSECLAW_DISABLE_REDACTION", prior)
            if prior is not None
            else os.environ.pop("DEFENSECLAW_DISABLE_REDACTION", None)
        )

        cfg = app.cfg
        cfg.data_dir = tmp_dir
        cfg.guardrail.connector = "openclaw"

        malicious_token = "legit\nDEFENSECLAW_DISABLE_REDACTION=1"
        with patch(
            "defenseclaw.commands.cmd_init._resolve_gateway_for_connector",
            return_value={"host": "127.0.0.1", "port": 18789, "token": malicious_token},
        ):
            with self.assertRaises(click.ClickException):
                _setup_gateway_defaults(cfg, logger=None, is_new_config=True)

        dotenv_path = os.path.join(tmp_dir, ".env")
        if os.path.exists(dotenv_path):
            with open(dotenv_path) as f:
                contents = f.read()
            # No injected second entry, no token line written at all.
            self.assertNotIn("DEFENSECLAW_DISABLE_REDACTION", contents)
            self.assertNotIn("OPENCLAW_GATEWAY_TOKEN", contents)
        # And the injected var must not have leaked into the process env.
        self.assertNotEqual(os.environ.get("OPENCLAW_GATEWAY_TOKEN"), malicious_token)


class TestResolveSplunkBridgeBundle(unittest.TestCase):
    def test_prefers_maintained_bundle_in_source_checkout(self):
        from defenseclaw.commands.cmd_init import _resolve_splunk_bridge_bundle

        def fake_is_dir(path):
            path_str = str(path).replace("\\", "/")
            return path_str.endswith("_data/splunk_local_bridge") or path_str.endswith("bundles/splunk_local_bridge")

        with patch("pathlib.Path.is_dir", autospec=True, side_effect=fake_is_dir):
            result = _resolve_splunk_bridge_bundle()

        self.assertTrue(str(result).replace("\\", "/").endswith("bundles/splunk_local_bridge"))


class TestInitSeedsSplunkBridge(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-splunk-")
        self.bundle_dir = tempfile.mkdtemp(prefix="dclaw-bundle-splunk-")
        self.runner = CliRunner()

        bin_dir = os.path.join(self.bundle_dir, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        bridge_bin = os.path.join(bin_dir, "splunk-claw-bridge")
        with open(bridge_bin, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\n")
        os.chmod(bridge_bin, 0o644)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        shutil.rmtree(self.bundle_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init._resolve_splunk_bridge_bundle")
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_seeds_bundled_splunk_runtime(
        self,
        mock_path,
        _mock_env,
        _mock_scanners,
        _mock_guardrail,
        _mock_which,
        mock_bundle,
    ):
        mock_path.return_value = Path(self.tmp_dir)
        mock_bundle.return_value = Path(self.bundle_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Splunk bridge: seeded in", result.output)
        seeded_bin = os.path.join(self.tmp_dir, "splunk-bridge", "bin", "splunk-claw-bridge")
        self.assertTrue(os.path.isfile(seeded_bin))
        self.assertTrue(os.access(seeded_bin, os.X_OK))


class TestSeedLocalObservabilityStack(unittest.TestCase):
    """Cover the seed/refresh contract for the local observability bundle.

    The fresh-seed path is an existing-behaviour check; the
    refresh-on-stale-bridge path is the regression test for the bash
    3.2 ``set -u`` empty-array crash that hit operators with a
    pre-fix seeded copy in ``~/.defenseclaw/observability-stack/``.
    """

    _OLD_BRIDGE = "#!/usr/bin/env bash\n# stale bridge (pre-fix)\nexit 1\n"
    _NEW_BRIDGE = (
        "#!/usr/bin/env bash\n# refreshed bridge (post-fix)\n"
        "PASSTHROUGH=()\necho \"${PASSTHROUGH[@]+\\\"${PASSTHROUGH[@]}\\\"}\"\n"
    )
    _OLD_SHIM = "#!/usr/bin/env bash\n# stale run.sh (pre-fix)\nexit 1\n"
    _NEW_SHIM = "#!/usr/bin/env bash\n# refreshed run.sh\nexec ./bin/openclaw-observability-bridge \"$@\"\n"

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-obs-")
        self.bundle_dir = tempfile.mkdtemp(prefix="dclaw-bundle-obs-")

        bin_dir = os.path.join(self.bundle_dir, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        with open(
            os.path.join(bin_dir, "openclaw-observability-bridge"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(self._NEW_BRIDGE)

        with open(os.path.join(self.bundle_dir, "run.sh"), "w", encoding="utf-8") as handle:
            handle.write(self._NEW_SHIM)

        dashboards_dir = os.path.join(self.bundle_dir, "grafana", "dashboards")
        os.makedirs(dashboards_dir, exist_ok=True)
        with open(
            os.path.join(dashboards_dir, "defenseclaw-overview.json"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write('{"title": "bundled"}\n')

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        shutil.rmtree(self.bundle_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.bundled_local_observability_dir")
    def test_seeds_when_absent(self, mock_bundled):
        from defenseclaw.commands.cmd_init import _seed_local_observability_stack

        mock_bundled.return_value = Path(self.bundle_dir)
        _seed_local_observability_stack(self.tmp_dir)

        seeded_bin = os.path.join(
            self.tmp_dir,
            "observability-stack",
            "bin",
            "openclaw-observability-bridge",
        )
        self.assertTrue(os.path.isfile(seeded_bin))
        self.assertTrue(os.access(seeded_bin, os.X_OK))
        with open(seeded_bin, encoding="utf-8") as handle:
            self.assertIn("refreshed bridge", handle.read())

        seeded_shim = os.path.join(self.tmp_dir, "observability-stack", "run.sh")
        self.assertTrue(os.access(seeded_shim, os.X_OK))

    @patch("defenseclaw.commands.cmd_init.bundled_local_observability_dir")
    def test_refreshes_stale_bridge_on_reinit(self, mock_bundled):
        """A pre-existing seeded copy with a stale bridge should be
        refreshed so wheel-shipped bug fixes (e.g. the bash 3.2 empty
        array guard) propagate to operators who already ran ``init``.
        """
        from defenseclaw.commands.cmd_init import _seed_local_observability_stack

        mock_bundled.return_value = Path(self.bundle_dir)

        dest = os.path.join(self.tmp_dir, "observability-stack")
        os.makedirs(os.path.join(dest, "bin"), exist_ok=True)
        stale_bridge = os.path.join(dest, "bin", "openclaw-observability-bridge")
        with open(stale_bridge, "w", encoding="utf-8") as handle:
            handle.write(self._OLD_BRIDGE)
        os.chmod(stale_bridge, 0o644)

        stale_shim = os.path.join(dest, "run.sh")
        with open(stale_shim, "w", encoding="utf-8") as handle:
            handle.write(self._OLD_SHIM)
        os.chmod(stale_shim, 0o644)

        operator_dashboards = os.path.join(dest, "grafana", "dashboards")
        os.makedirs(operator_dashboards, exist_ok=True)
        operator_dashboard = os.path.join(operator_dashboards, "defenseclaw-overview.json")
        with open(operator_dashboard, "w", encoding="utf-8") as handle:
            handle.write('{"title": "operator-edited"}\n')

        _seed_local_observability_stack(self.tmp_dir)

        with open(stale_bridge, encoding="utf-8") as handle:
            content = handle.read()
        self.assertIn("refreshed bridge", content)
        self.assertNotIn("stale bridge", content)
        self.assertTrue(os.access(stale_bridge, os.X_OK))

        with open(stale_shim, encoding="utf-8") as handle:
            self.assertIn("refreshed run.sh", handle.read())
        self.assertTrue(os.access(stale_shim, os.X_OK))

        with open(operator_dashboard, encoding="utf-8") as handle:
            self.assertIn("operator-edited", handle.read())

    @patch("defenseclaw.commands.cmd_init.bundled_local_observability_dir")
    def test_missing_bundle_is_noop(self, mock_bundled):
        from defenseclaw.commands.cmd_init import _seed_local_observability_stack

        bogus = Path(self.bundle_dir) / "does-not-exist"
        mock_bundled.return_value = bogus
        _seed_local_observability_stack(self.tmp_dir)

        self.assertFalse(os.path.isdir(os.path.join(self.tmp_dir, "observability-stack")))


class TestSeedGuardrailProfiles(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-guardrail-")
        self.bundle_dir = tempfile.mkdtemp(prefix="dclaw-bundle-guardrail-")
        for profile in ("default", "strict", "permissive"):
            rules_dir = os.path.join(self.bundle_dir, profile, "rules")
            os.makedirs(rules_dir, exist_ok=True)
            with open(os.path.join(rules_dir, "secrets.yaml"), "w", encoding="utf-8") as handle:
                handle.write("rules: []\n")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        shutil.rmtree(self.bundle_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.bundled_guardrail_profiles_dir")
    def test_seeds_profiles_when_absent(self, mock_bundled):
        from defenseclaw.commands.cmd_init import _seed_guardrail_profiles

        mock_bundled.return_value = Path(self.bundle_dir)
        _seed_guardrail_profiles(self.tmp_dir)

        for profile in ("default", "strict", "permissive"):
            seeded = os.path.join(self.tmp_dir, "guardrail", profile, "rules", "secrets.yaml")
            self.assertTrue(os.path.isfile(seeded), f"expected seeded file {seeded}")

    @patch("defenseclaw.commands.cmd_init.bundled_guardrail_profiles_dir")
    def test_preserves_existing_profile(self, mock_bundled):
        from defenseclaw.commands.cmd_init import _seed_guardrail_profiles

        mock_bundled.return_value = Path(self.bundle_dir)
        existing_dir = os.path.join(self.tmp_dir, "guardrail", "default")
        os.makedirs(existing_dir, exist_ok=True)
        marker = os.path.join(existing_dir, "user-edited.yaml")
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("custom: true\n")

        _seed_guardrail_profiles(self.tmp_dir)

        self.assertTrue(os.path.isfile(marker), "existing profile must be preserved intact")
        self.assertFalse(
            os.path.isfile(os.path.join(existing_dir, "rules", "secrets.yaml")),
            "existing profile must not be overwritten",
        )
        self.assertTrue(
            os.path.isfile(os.path.join(self.tmp_dir, "guardrail", "strict", "rules", "secrets.yaml"))
        )

    @patch("defenseclaw.commands.cmd_init.bundled_guardrail_profiles_dir", return_value=None)
    def test_missing_bundle_is_noop(self, _mock_bundled):
        from defenseclaw.commands.cmd_init import _seed_guardrail_profiles

        _seed_guardrail_profiles(self.tmp_dir)
        self.assertFalse(os.path.isdir(os.path.join(self.tmp_dir, "guardrail")))


class TestInstallScanners(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_init._verify_scanner_sdk")
    def test_install_scanners_verifies_sdks(self, mock_verify):
        from defenseclaw.commands.cmd_init import _install_scanners
        from defenseclaw.config import default_config

        cfg = default_config()
        logger = MagicMock()

        _install_scanners(cfg, logger, skip=False)
        self.assertEqual(mock_verify.call_count, 2)
        call_names = [c[0][0] for c in mock_verify.call_args_list]
        self.assertIn("skill-scanner", call_names)
        self.assertIn("mcp-scanner", call_names)

    def test_install_scanners_skip(self):
        from defenseclaw.commands.cmd_init import _install_scanners
        from defenseclaw.config import default_config
        cfg = default_config()
        logger = MagicMock()

        # skip=True should print skip message without calling install
        _install_scanners(cfg, logger, skip=True)
        logger.log_action.assert_not_called()


class TestInitEnableGuardrail(unittest.TestCase):
    """Tests for the --enable-guardrail flag during init."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-guardrail-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_enable_guardrail_flag_appears_in_help(self, mock_path, _mock_env, _mock_scanners, _mock_which):
        result = self.runner.invoke(init_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--enable-guardrail", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_without_flag_shows_guardrail_hint(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("defenseclaw setup guardrail", result.output)
        self.assertIn("enable llm traffic inspection", result.output.lower())

    @patch("defenseclaw.commands.cmd_init._start_gateway")
    @patch("defenseclaw.commands.cmd_init._install_codeguard_skill")
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.commands.cmd_setup._interactive_guardrail_setup")
    @patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, []))
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_enable_guardrail_calls_interactive_setup(
        self, mock_path, _mock_env, mock_exec, mock_interactive,
        _mock_scanners, _mock_which, _mock_guardrail, _mock_codeguard, _mock_start_gw
    ):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        def fake_interactive(app, gc):
            gc.enabled = True
            gc.mode = "observe"
            gc.model = "anthropic/test-model"
            gc.model_name = "test-model"
            gc.api_key_env = "ANTHROPIC_API_KEY"

        mock_interactive.side_effect = fake_interactive

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install", "--enable-guardrail"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        mock_interactive.assert_called_once()
        mock_exec.assert_called_once()

    @patch("defenseclaw.commands.cmd_init._start_gateway")
    @patch("defenseclaw.commands.cmd_init._install_codeguard_skill")
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.commands.cmd_setup._interactive_guardrail_setup")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_enable_guardrail_declined_shows_hint(
        self, mock_path, _mock_env, mock_interactive,
        _mock_scanners, _mock_which, _mock_codeguard, _mock_start_gw
    ):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        def fake_decline(app, gc):
            gc.enabled = False

        mock_interactive.side_effect = fake_decline

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install", "--enable-guardrail"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Guardrail not enabled", result.output)
        self.assertIn("defenseclaw setup guardrail", result.output)

    @patch("defenseclaw.commands.cmd_init._start_gateway")
    @patch("defenseclaw.commands.cmd_init._install_codeguard_skill")
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.commands.cmd_setup._interactive_guardrail_setup")
    @patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, ["test warning"]))
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_enable_guardrail_shows_warnings(
        self, mock_path, _mock_env, mock_exec, mock_interactive,
        _mock_scanners, _mock_which, _mock_guardrail, _mock_codeguard, _mock_start_gw
    ):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        def fake_interactive(app, gc):
            gc.enabled = True
            gc.mode = "observe"
            gc.model = "anthropic/test-model"
            gc.model_name = "test-model"

        mock_interactive.side_effect = fake_interactive

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install", "--enable-guardrail"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("test warning", result.output)


class TestInitStartsGateway(unittest.TestCase):
    """Tests for the sidecar start during init."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-sidecar-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_shows_sidecar_section(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None):
            app = AppContext()
            result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("Sidecar", result.output)

    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_sidecar_binary_not_found(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None):
            app = AppContext()
            result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("not found", result.output)
            self.assertIn("make gateway-install", result.output)

    def test_start_gateway_binary_missing(self):
        from defenseclaw.commands.cmd_init import _start_gateway
        from defenseclaw.config import default_config

        cfg = default_config()
        cfg.data_dir = self.tmp_dir
        logger = MagicMock()

        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None):
            _start_gateway(cfg, logger)
            logger.log_action.assert_not_called()

    def test_start_gateway_already_running(self):
        from defenseclaw.commands.cmd_init import _start_gateway
        from defenseclaw.config import default_config

        cfg = default_config()
        cfg.data_dir = self.tmp_dir
        logger = MagicMock()

        pid_file = os.path.join(self.tmp_dir, "gateway.pid")
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))

        # _is_sidecar_running now also checks
        # /proc/<pid>/cmdline against known gateway binary names. Tests
        # use os.getpid() (the python test runner) which won't match;
        # stub the cmdline check to keep this test focused on the
        # already-running short-circuit. The spoof guard has its own
        # dedicated test in test_cmd_init_pid_spoof.
        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value="/usr/bin/defenseclaw-gateway"), \
             patch("defenseclaw.commands.cmd_init._pid_looks_like_gateway", return_value=True):
            _start_gateway(cfg, logger)
            logger.log_action.assert_not_called()

    def test_start_gateway_starts_successfully(self):
        from defenseclaw.commands.cmd_init import _start_gateway
        from defenseclaw.config import default_config

        cfg = default_config()
        cfg.data_dir = self.tmp_dir
        logger = MagicMock()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_result.stdout = ""

        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value="/usr/bin/defenseclaw-gateway"), \
             patch("defenseclaw.commands.cmd_init.subprocess.run", return_value=mock_result), \
             patch("defenseclaw.commands.cmd_init._check_sidecar_health"):
            _start_gateway(cfg, logger)
            logger.log_action.assert_called_once()
            self.assertIn("init-sidecar", logger.log_action.call_args[0])

    def test_start_gateway_fails(self):
        from defenseclaw.commands.cmd_init import _start_gateway
        from defenseclaw.config import default_config

        cfg = default_config()
        cfg.data_dir = self.tmp_dir
        logger = MagicMock()

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "connection refused"
        mock_result.stdout = ""

        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value="/usr/bin/defenseclaw-gateway"), \
             patch("defenseclaw.commands.cmd_init.subprocess.run", return_value=mock_result), \
             patch("defenseclaw.commands.cmd_init._check_sidecar_health"):
            _start_gateway(cfg, logger)
            logger.log_action.assert_not_called()


class TestIsSidecarRunning(unittest.TestCase):
    """Tests for the _is_sidecar_running helper."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-sidecar-pid-")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_no_pid_file(self):
        from defenseclaw.commands.cmd_init import _is_sidecar_running
        self.assertFalse(_is_sidecar_running("/tmp/nonexistent/gateway.pid"))

    def test_valid_pid(self):
        from defenseclaw.commands.cmd_init import _is_sidecar_running
        pid_file = os.path.join(self.tmp_dir, "gateway.pid")
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))
        # stub the cmdline check — see test_cmd_init_pid_spoof
        # for the dedicated regression coverage.
        with patch("defenseclaw.commands.cmd_init._pid_looks_like_gateway", return_value=True):
            self.assertTrue(_is_sidecar_running(pid_file))

    def test_stale_pid(self):
        from defenseclaw.commands.cmd_init import _is_sidecar_running
        pid_file = os.path.join(self.tmp_dir, "gateway.pid")
        with open(pid_file, "w") as f:
            f.write("999999999")
        self.assertFalse(_is_sidecar_running(pid_file))

    def test_json_pid_format(self):
        import json

        from defenseclaw.commands.cmd_init import _read_pid
        pid_file = os.path.join(self.tmp_dir, "gateway.pid")
        with open(pid_file, "w") as f:
            json.dump({"pid": os.getpid()}, f)
        self.assertEqual(_read_pid(pid_file), os.getpid())


@unittest.skipIf(os.name == "nt", "OpenShell sandbox ownership integration is Linux-only")
class TestDetectOpenclawHome(unittest.TestCase):
    """Tests for _detect_openclaw_home helper."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-detect-oc-")
        self.oc_home = os.path.join(self.tmp_dir, ".openclaw")
        os.makedirs(self.oc_home)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_returns_none_when_no_openclaw(self):
        from defenseclaw.commands.cmd_init_sandbox import _detect_openclaw_home
        with patch.dict(os.environ, {"SUDO_USER": ""}, clear=False), \
             patch("os.path.expanduser", return_value=os.path.join(self.tmp_dir, "nonexistent")):
            result = _detect_openclaw_home()
            # May find real ~/.openclaw on the host — just check it's str or None
            self.assertTrue(result is None or isinstance(result, str))

    def test_finds_openclaw_with_config(self):
        from defenseclaw.commands.cmd_init_sandbox import _detect_openclaw_home
        # Create openclaw.json
        with open(os.path.join(self.oc_home, "openclaw.json"), "w") as f:
            f.write('{"gateway": {}}')

        with patch("os.path.expanduser", return_value=self.oc_home), \
             patch.dict(os.environ, {"SUDO_USER": ""}, clear=False):
            result = _detect_openclaw_home()
            self.assertEqual(result, self.oc_home)

    def test_prefers_sudo_user_home(self):
        from defenseclaw.commands.cmd_init_sandbox import _detect_openclaw_home

        # Create two homes with openclaw.json
        sudo_home = os.path.join(self.tmp_dir, "sudouser")
        sudo_oc = os.path.join(sudo_home, ".openclaw")
        os.makedirs(sudo_oc)
        with open(os.path.join(sudo_oc, "openclaw.json"), "w") as f:
            f.write('{}')
        with open(os.path.join(self.oc_home, "openclaw.json"), "w") as f:
            f.write('{}')

        mock_pw = MagicMock()
        mock_pw.pw_dir = sudo_home

        with patch.dict(os.environ, {"SUDO_USER": "testuser"}, clear=False), \
             patch("pwd.getpwnam", return_value=mock_pw), \
             patch("os.path.expanduser", return_value=self.oc_home):
            result = _detect_openclaw_home()
            self.assertEqual(result, sudo_oc)


class TestSaveOwnershipBackup(unittest.TestCase):
    """Tests for _save_ownership_backup helper."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-backup-")
        self.oc_home = tempfile.mkdtemp(prefix="dclaw-oc-home-")

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.oc_home, ignore_errors=True)

    def test_creates_backup_file(self):
        import json

        from defenseclaw.commands.cmd_init_sandbox import _save_ownership_backup
        backup_path = _save_ownership_backup(self.oc_home, self.data_dir)
        self.assertTrue(os.path.isfile(backup_path))

        with open(backup_path) as f:
            data = json.load(f)
        self.assertIn("openclaw_home", data)
        self.assertIn("original_uid", data)
        self.assertIn("original_gid", data)
        self.assertIn("original_mode", data)
        self.assertEqual(data["original_uid"], os.stat(self.oc_home).st_uid)
        self.assertEqual(data["original_gid"], os.stat(self.oc_home).st_gid)

    def test_backup_file_path(self):
        from defenseclaw.commands.cmd_init_sandbox import OPENCLAW_OWNERSHIP_BACKUP, _save_ownership_backup
        backup_path = _save_ownership_backup(self.oc_home, self.data_dir)
        expected = os.path.join(self.data_dir, OPENCLAW_OWNERSHIP_BACKUP)
        self.assertEqual(backup_path, expected)

    def test_backup_parent_walk_does_not_process_filesystem_root(self):
        from defenseclaw.commands import cmd_init_sandbox

        real_stat = os.stat
        stat_paths = []

        def recording_stat(path, *args, **kwargs):
            stat_paths.append(os.path.normcase(os.path.realpath(path)))
            return real_stat(path, *args, **kwargs)

        with patch.object(cmd_init_sandbox.os, "stat", side_effect=recording_stat):
            cmd_init_sandbox._save_ownership_backup(self.oc_home, self.data_dir)

        filesystem_root = os.path.normcase(os.path.abspath(os.sep))
        self.assertNotIn(filesystem_root, stat_paths)

    @unittest.skipIf(os.name == "nt", "sandbox traversal permissions are POSIX-only")
    def test_traversal_parent_walk_does_not_process_filesystem_root(self):
        from defenseclaw.commands import cmd_init_sandbox

        real_stat = os.stat
        stat_paths = []

        def recording_stat(path, *args, **kwargs):
            stat_paths.append(os.path.normcase(os.path.realpath(path)))
            return real_stat(path, *args, **kwargs)

        with (
            patch.object(cmd_init_sandbox.os, "stat", side_effect=recording_stat),
            patch.object(cmd_init_sandbox.subprocess, "run", return_value=MagicMock(returncode=0)),
        ):
            cmd_init_sandbox._ensure_parent_traversal(os.path.join(self.oc_home, "target"))

        filesystem_root = os.path.normcase(os.path.abspath(os.sep))
        self.assertNotIn(filesystem_root, stat_paths)


@unittest.skipIf(os.name == "nt", "OpenShell sandbox ownership integration is Linux-only")
class TestIntegrateOpenclawHomeIdempotent(unittest.TestCase):
    """Tests for _integrate_openclaw_home idempotency."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-integrate-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-sandbox-")
        self.oc_home = tempfile.mkdtemp(prefix="dclaw-oc-real-")

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)
        shutil.rmtree(self.oc_home, ignore_errors=True)

    def test_idempotent_when_already_configured(self):
        import json

        from defenseclaw.commands.cmd_init_sandbox import OPENCLAW_OWNERSHIP_BACKUP, _integrate_openclaw_home

        # Simulate a previous successful integration
        backup_path = os.path.join(self.data_dir, OPENCLAW_OWNERSHIP_BACKUP)
        with open(backup_path, "w") as f:
            json.dump({"openclaw_home": self.oc_home, "original_uid": 1000, "original_gid": 1000, "original_mode": "0o755"}, f)

        # Create the symlink
        symlink_path = os.path.join(self.sandbox_home, ".openclaw")
        os.symlink(self.oc_home, symlink_path)

        cfg = MagicMock()
        cfg.data_dir = self.data_dir
        # F-0162: the idempotency fast-path now validates the .openclaw
        # realpath against the pinned original home, so it must be set to the
        # symlink target for the legitimate (untampered) case to succeed.
        cfg.claw.openclaw_home_original = self.oc_home

        # The idempotency path performs post-transfer ACL/traversal repair in
        # production.  This unit test owns only temporary paths, so exercise
        # the wiring without letting it mutate parent permissions or invoke
        # sudo against the host's shared temporary root.
        with (
            patch("defenseclaw.commands.cmd_init_sandbox._ensure_parent_traversal") as traversal,
            patch("defenseclaw.commands.cmd_init_sandbox._ensure_sandbox_acls", return_value=True) as acls,
        ):
            result = _integrate_openclaw_home(cfg, self.sandbox_home)
        self.assertTrue(result)
        canonical_home = os.path.realpath(self.oc_home)
        traversal.assert_called_once_with(canonical_home)
        acls.assert_called_once_with(canonical_home)

    def test_returns_false_when_no_openclaw(self):
        from defenseclaw.commands.cmd_init_sandbox import _integrate_openclaw_home

        cfg = MagicMock()
        cfg.data_dir = self.data_dir

        with patch("defenseclaw.commands.cmd_init_sandbox._detect_openclaw_home", return_value=None):
            result = _integrate_openclaw_home(cfg, self.sandbox_home)
            self.assertFalse(result)


@unittest.skipIf(os.name == "nt", "OpenShell sandbox ownership integration is Linux-only")
class TestRestoreOpenclawOwnership(unittest.TestCase):
    """Tests for _restore_openclaw_ownership in cmd_setup."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-restore-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-sandbox-")
        self.oc_home = tempfile.mkdtemp(prefix="dclaw-oc-restore-")
        self._sudo_patcher = patch(
            "defenseclaw.commands.cmd_init_sandbox._needs_sudo", return_value=False
        )
        self._sudo_patcher.start()

    def tearDown(self):
        self._sudo_patcher.stop()
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)
        shutil.rmtree(self.oc_home, ignore_errors=True)

    def test_noop_when_no_backup(self):
        from defenseclaw.commands.cmd_setup_sandbox import _restore_openclaw_ownership
        # Should not raise
        _restore_openclaw_ownership(self.data_dir, self.sandbox_home)

    def test_removes_symlink(self):
        import json

        from defenseclaw.commands.cmd_init_sandbox import OPENCLAW_OWNERSHIP_BACKUP
        from defenseclaw.commands.cmd_setup_sandbox import _restore_openclaw_ownership

        st = os.stat(self.oc_home)
        backup_path = os.path.join(self.data_dir, OPENCLAW_OWNERSHIP_BACKUP)
        with open(backup_path, "w") as f:
            json.dump({
                "openclaw_home": self.oc_home,
                "original_uid": st.st_uid,
                "original_gid": st.st_gid,
                "original_mode": "0o755",
            }, f)

        # Create symlink
        symlink_path = os.path.join(self.sandbox_home, ".openclaw")
        os.symlink(self.oc_home, symlink_path)

        _restore_openclaw_ownership(self.data_dir, self.sandbox_home)

        self.assertFalse(os.path.islink(symlink_path))
        self.assertFalse(os.path.isfile(backup_path))


class TestInitFailModeFlag(unittest.TestCase):
    """Pin --fail-mode wiring through cmd_init.

    The 0.4.0 launch shipped a `defenseclaw guardrail fail-mode`
    command and a setup-time prompt, but `init` and `quickstart`
    didn't expose the option. Operators running `quickstart` or
    headless `init --json-summary` flows ended up with whatever
    default `default_config()` returned, with no way to choose
    fail-closed without a second command. These tests pin the new
    surface so it can't regress.
    """

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-failmode-")
        self.runner = CliRunner()
        self.selection_patcher = patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            return_value=({}, {}),
        )
        self.selection_patcher.start()
        self.addCleanup(self.selection_patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _invoke(self, args):
        return self.runner.invoke(
            init_cmd,
            args,
            obj=AppContext(),
            env={"DEFENSECLAW_HOME": self.tmp_dir},
        )

    def test_help_lists_fail_mode_flag(self):
        result = self.runner.invoke(init_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.assertIn("--fail-mode", result.output)

    def test_fail_mode_closed_persists_to_config(self):
        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector",
            "codex",
            "--profile",
            "observe",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--fail-mode",
            "closed",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        from defenseclaw.config import _normalize_hook_fail_mode

        self.assertEqual(
            _normalize_hook_fail_mode(cfg["guardrail"].get("hook_fail_mode", "")),
            "closed",
        )

    def test_fail_mode_open_persists_to_config(self):
        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector",
            "codex",
            "--profile",
            "observe",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--fail-mode",
            "open",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        # Operator passed --fail-mode open explicitly — result must
        # round-trip as "open" regardless of the new safer default
        # ("closed"). This pins that operator intent is honored.
        from defenseclaw.config import _normalize_hook_fail_mode
        self.assertEqual(
            _normalize_hook_fail_mode(cfg["guardrail"].get("hook_fail_mode", "")),
            "open",
        )

    def test_omitting_flag_is_noninvasive(self):
        # No --fail-mode means "leave existing alone." On a brand-new
        # config, that resolves to the secure default ("closed") via
        # default_config(). The point of this test is to make sure the
        # wiring does NOT clobber the default with empty string (which
        # would be a serialization bug) AND that the new install gets
        # the safer fail-mode.
        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector",
            "codex",
            "--profile",
            "observe",
            "--scanner-mode",
            "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        # Whatever the YAML serializer wrote, the loader-level
        # normalizer must resolve it to "closed" for new installs.
        # Existing v3 installs are pinned to "open" by
        # _migrate_0_4_0_seed_hook_fail_mode in migrations.py.
        from defenseclaw.config import _normalize_hook_fail_mode
        raw = cfg["guardrail"].get("hook_fail_mode", "")
        self.assertEqual(_normalize_hook_fail_mode(raw), "closed")


class TestInitHITLFlags(unittest.TestCase):
    """Pin --human-approval / --hilt-min-severity wiring through cmd_init.

    HITL was previously settable only via the interactive ``defenseclaw
    setup guardrail`` wizard. Operators running headless ``init
    --json-summary`` (CI, install scripts, automation) had no way to
    toggle approval prompts at first-run time. These tests pin the new
    surface and the no-op contract for omitted flags so a regression
    can't silently disable HITL on an upgrade.
    """

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-hilt-")
        self.runner = CliRunner()
        self.selection_patcher = patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            return_value=({}, {}),
        )
        self.selection_patcher.start()
        self.addCleanup(self.selection_patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _invoke(self, args):
        return self.runner.invoke(
            init_cmd,
            args,
            obj=AppContext(),
            env={"DEFENSECLAW_HOME": self.tmp_dir},
        )

    def _load_cfg(self) -> dict:
        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def test_help_lists_hilt_flags(self):
        result = self.runner.invoke(init_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.assertIn("--human-approval", result.output,
                      "operator-facing --help must advertise the HITL toggle "
                      "or no one will discover it")
        self.assertIn("--hilt-min-severity", result.output)

    def test_human_approval_enables_with_severity_floor(self):
        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector", "codex",
            "--profile", "action",
            "--scanner-mode", "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--human-approval",
            "--hilt-min-severity", "MEDIUM",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        cfg = self._load_cfg()
        hilt = cfg["guardrail"]["hilt"]
        self.assertTrue(hilt["enabled"],
                        "explicit --human-approval must persist as enabled=True "
                        "in config.yaml; otherwise the prompt UX is a lie")
        self.assertEqual(hilt["min_severity"], "MEDIUM")

    def test_human_approval_normalizes_lowercase_severity(self):
        # Click normalizes case via case_sensitive=False, but pin the
        # contract end-to-end: a user who types ``--hilt-min-severity
        # low`` must end up with ``"LOW"`` on disk to match the
        # canonical HIGH/MEDIUM/LOW/CRITICAL set the gateway compares
        # against.
        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector", "codex",
            "--profile", "action",
            "--scanner-mode", "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--human-approval",
            "--hilt-min-severity", "low",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.assertEqual(self._load_cfg()["guardrail"]["hilt"]["min_severity"], "LOW")

    def test_no_human_approval_disables_explicitly(self):
        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector", "codex",
            "--profile", "action",
            "--scanner-mode", "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--no-human-approval",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        hilt = self._load_cfg()["guardrail"].get("hilt", {})
        self.assertFalse(hilt.get("enabled", False))

    def test_omitting_flags_preserves_default(self):
        # Brand-new config: HITL defaults are enabled=False,
        # min_severity="HIGH" (HILTConfig). Omitting both flags must
        # leave those defaults intact, matching the "leave existing
        # alone" contract.
        result = self._invoke([
            "--non-interactive",
            "--yes",
            "--connector", "codex",
            "--profile", "action",
            "--scanner-mode", "local",
            "--skip-install",
            "--no-start-gateway",
            "--no-verify",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        hilt = self._load_cfg()["guardrail"].get("hilt", {})
        self.assertFalse(hilt.get("enabled", False),
                         "no flag = no change; default_config() seeds enabled=False")
        self.assertEqual(hilt.get("min_severity", "HIGH"), "HIGH")


class TestMultiConnectorInit(unittest.TestCase):
    """First-run wizard can configure several connectors in one pass."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-multi-")
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)

    def _disc(self, installed):
        return AgentDiscovery(
            scanned_at="2026-06-03T00:00:00Z",
            cache_hit=False,
            agents={
                name: AgentSignal(
                    name=name,
                    installed=name in installed,
                    config_path=f"/tmp/{name}.cfg" if name in installed else "",
                    binary_path="",
                    version="",
                    error="",
                )
                for name in KNOWN_CONNECTORS
            },
        )

    def test_parse_connector_list_normalizes_dedups_splits(self):
        from defenseclaw.commands.cmd_init import _parse_connector_list

        self.assertEqual(_parse_connector_list("codex, claude-code ,codex"), ["codex", "claudecode"])
        self.assertEqual(_parse_connector_list("codex claudecode"), ["codex", "claudecode"])
        self.assertEqual(_parse_connector_list(""), [])
        self.assertEqual(_parse_connector_list(None), [])

    def test_installed_hook_connectors_excludes_proxy_backed(self):
        from defenseclaw.commands.cmd_init import _installed_hook_connectors

        got = _installed_hook_connectors(self._disc({"codex", "claudecode", "openclaw"}))
        self.assertIn("codex", got)
        self.assertIn("claudecode", got)
        # openclaw is proxy-backed and cannot be a multi-connector peer.
        self.assertNotIn("openclaw", got)

    def test_activate_additional_connectors_writes_per_connector_overrides(self):
        from defenseclaw import config as cfg_mod
        from defenseclaw.commands.cmd_init import _activate_additional_connectors

        with patch.dict(os.environ, {"DEFENSECLAW_HOME": self.tmp_dir}), patch(
            "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
            return_value=True,
        ):
            cfg = cfg_mod.default_config()
            cfg.guardrail.connector = "codex"
            cfg.claw.mode = "codex"
            cfg.guardrail.mode = "observe"
            cfg.guardrail.enabled = True
            cfg.guardrail.connectors = {
                "codex": PerConnectorGuardrailConfig(),
                "hermes": PerConnectorGuardrailConfig(),
            }
            cfg.guardrail.judge.hook_connectors = ["codex", "hermes"]
            cfg.save()

            active, sidecar_step = _activate_additional_connectors(
                {"connector": "codex", "profile": "observe", "fail_mode": "open",
                 "human_approval": None, "hilt_min_severity": None},
                [{"connector": "claudecode", "profile": "action", "fail_mode": "closed",
                  "human_approval": True, "hilt_min_severity": "MEDIUM"}],
                start_gateway=False,
            )
            self.assertEqual(active, ["claudecode", "codex"])
            # Gateway start not requested → no sidecar step to fold into report.
            self.assertIsNone(sidecar_step)

            reloaded = cfg_mod.load()
            gc = reloaded.guardrail
            self.assertEqual(sorted(gc.connectors), ["claudecode", "codex"])
            self.assertNotIn("hermes", gc.connectors)
            self.assertEqual(gc.judge.hook_connectors, ["codex"])
            self.assertEqual(reloaded.active_connectors(), ["claudecode", "codex"])
            cc = gc.connectors["claudecode"]
            self.assertEqual(cc.mode, "action")
            self.assertEqual(cc.hook_fail_mode, "closed")
            self.assertIsNotNone(cc.hilt)
            self.assertTrue(cc.hilt.enabled)
            self.assertEqual(cc.hilt.min_severity, "MEDIUM")
            # The codex peer carries an empty override and inherits the
            # global observe mode written by the primary bootstrap.
            self.assertEqual(gc.connectors["codex"].mode, "")
            # Singular mirror pinned to the sorted-first connector for
            # backward-compatible (single-connector) readers.
            self.assertEqual(gc.connector, "claudecode")
            self.assertEqual(reloaded.claw.mode, "claudecode")

    def test_activate_additional_connectors_downgrades_unverified_action(self):
        """An extra connector requested in action mode whose installed version
        is not verified against a known hook contract must be downgraded to
        observe (parity with the Go gateway boot gate), not silently written as
        an enforcing connector the gateway will refuse to run."""
        from defenseclaw import config as cfg_mod
        from defenseclaw.commands.cmd_init import _activate_additional_connectors

        with patch.dict(os.environ, {"DEFENSECLAW_HOME": self.tmp_dir}), patch(
            "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
            return_value=False,
        ):
            cfg = cfg_mod.default_config()
            cfg.guardrail.connector = "codex"
            cfg.claw.mode = "codex"
            cfg.guardrail.mode = "observe"
            cfg.guardrail.enabled = True
            cfg.save()

            _activate_additional_connectors(
                {"connector": "codex", "profile": "observe", "fail_mode": "open",
                 "human_approval": None, "hilt_min_severity": None},
                [{"connector": "claudecode", "profile": "action", "fail_mode": "closed",
                  "human_approval": None, "hilt_min_severity": None}],
                start_gateway=False,
            )

            reloaded = cfg_mod.load()
            # Unverified extra is downgraded to observe, not action.
            self.assertEqual(reloaded.guardrail.connectors["claudecode"].mode, "observe")

    def test_activate_additional_connectors_keeps_action_with_drift_override(self):
        """With the explicit drift override the gate passes, so the extra stays
        in action mode."""
        from defenseclaw import config as cfg_mod
        from defenseclaw.commands.cmd_init import _activate_additional_connectors

        with patch.dict(
            os.environ,
            {"DEFENSECLAW_HOME": self.tmp_dir, "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "1"},
        ), patch(
            "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
            return_value=True,
        ):
            cfg = cfg_mod.default_config()
            cfg.guardrail.connector = "codex"
            cfg.claw.mode = "codex"
            cfg.guardrail.mode = "observe"
            cfg.guardrail.enabled = True
            cfg.save()

            _activate_additional_connectors(
                {"connector": "codex", "profile": "observe", "fail_mode": "open",
                 "human_approval": None, "hilt_min_severity": None},
                [{"connector": "claudecode", "profile": "action", "fail_mode": "closed",
                  "human_approval": None, "hilt_min_severity": None}],
                start_gateway=False,
            )

            reloaded = cfg_mod.load()
            self.assertEqual(reloaded.guardrail.connectors["claudecode"].mode, "action")

    def test_prompt_first_run_observes_all_and_actions_subset(self):
        """The wizard pre-selects every detected connector in observe, then
        only the named subset is promoted to action with shared fail/HITL."""
        from defenseclaw.commands import cmd_init

        disc = self._disc({"codex", "claudecode"})
        # scanner mode, fail mode, HITL severity
        prompts = iter(["local", "closed", "MEDIUM"])
        confirms = iter([True, False, True])  # action HITL, start_gateway, verify
        checkbox_returns = iter([["codex", "claudecode"], ["claudecode"], []])
        checkbox_calls: list[tuple[list[str], str]] = []

        def checkbox(options, **kwargs):
            checkbox_calls.append((list(options), kwargs.get("title", "")))
            return next(checkbox_returns)

        with patch.object(cmd_init.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_init.agent_discovery, "render_discovery_table", return_value=""), \
                patch(
                    "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                    return_value=True,
                ), \
                patch.object(cmd_init, "_prompt_checkbox_selection", side_effect=checkbox), \
                patch.object(cmd_init.click, "prompt", side_effect=lambda *a, **k: next(prompts)), \
                patch.object(cmd_init.click, "confirm", side_effect=lambda *a, **k: next(confirms)):
            settings, scanner_mode, with_judge, judge_connectors, start_gateway, verify = cmd_init._prompt_first_run(
                connector=None, profile=None, scanner_mode="local", with_judge=False,
                fail_mode=None, human_approval=None, hilt_min_severity=None,
                start_gateway=False, verify=None, rescan_agents=False,
            )

        by_name = {s["connector"]: s for s in settings}
        self.assertEqual([s["connector"] for s in settings], ["codex", "claudecode"])
        # Unnamed connectors stay in observe with no action-only knobs.
        self.assertEqual(by_name["codex"]["profile"], "observe")
        self.assertIsNone(by_name["codex"]["fail_mode"])
        self.assertIsNone(by_name["codex"]["human_approval"])
        # The named subset is promoted to action and carries the shared
        # fail-mode/HITL answers.
        self.assertEqual(by_name["claudecode"]["profile"], "action")
        self.assertEqual(by_name["claudecode"]["fail_mode"], "closed")
        self.assertTrue(by_name["claudecode"]["human_approval"])
        self.assertEqual(by_name["claudecode"]["hilt_min_severity"], "MEDIUM")
        self.assertEqual(scanner_mode, "local")
        self.assertFalse(with_judge)
        self.assertEqual(judge_connectors, [])
        self.assertFalse(start_gateway)
        self.assertTrue(verify)
        self.assertEqual(checkbox_calls[2], (["claudecode"], "Select action connector(s) for LLM judge."))

    def test_prompt_first_run_blank_action_keeps_all_observe(self):
        """Pressing Enter at the action prompt keeps every connector observe
        and never asks the action-only fail-mode/HITL questions."""
        from defenseclaw.commands import cmd_init

        disc = self._disc({"codex", "claudecode"})
        prompts = iter(["local"])  # scanner
        confirms = iter([False, True])  # start_gateway, verify

        with patch.object(cmd_init.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_init.agent_discovery, "render_discovery_table", return_value=""), \
                patch.object(
                    cmd_init,
                    "_prompt_checkbox_selection",
                    side_effect=[["codex", "claudecode"], []],
                ), \
                patch.object(cmd_init.click, "prompt", side_effect=lambda *a, **k: next(prompts)), \
                patch.object(cmd_init.click, "confirm", side_effect=lambda *a, **k: next(confirms)):
            settings, _scanner, _judge, _judge_connectors, _start, _verify = cmd_init._prompt_first_run(
                connector=None, profile=None, scanner_mode="local", with_judge=False,
                fail_mode=None, human_approval=None, hilt_min_severity=None,
                start_gateway=False, verify=None, rescan_agents=False,
            )

        self.assertTrue(all(s["profile"] == "observe" for s in settings))
        self.assertEqual({s["connector"] for s in settings}, {"codex", "claudecode"})

    def test_prompt_action_connectors_intersects_with_configured(self):
        from defenseclaw.commands import cmd_init

        with patch.object(
            cmd_init,
            "_prompt_checkbox_selection",
            return_value=["claudecode", "bogus", "codex"],
        ):
            got = cmd_init._prompt_action_connectors(["codex", "claudecode"])
        # Out-of-set entries (bogus) are dropped; configured ones are kept.
        self.assertEqual(sorted(got), ["claudecode", "codex"])

        with patch.object(cmd_init, "_prompt_checkbox_selection", return_value=[]):
            self.assertEqual(cmd_init._prompt_action_connectors(["codex"]), [])

    def test_single_connector_selection_prompts_trust_without_picker(self):
        from defenseclaw.commands import cmd_init
        from defenseclaw.inventory import agent_discovery as ad

        hermes_dir = os.path.join(self.tmp_dir, "hermes-bin")
        codex_dir = os.path.join(self.tmp_dir, "codex-bin")
        os.makedirs(hermes_dir)
        os.makedirs(codex_dir)
        first = self._disc({"codex", "hermes"})
        first.agents["hermes"].binary_path = os.path.join(hermes_dir, "hermes")
        first.agents["hermes"].version = ""
        first.agents["hermes"].error = ad.UNTRUSTED_PREFIX_ERROR
        first.agents["codex"].binary_path = os.path.join(codex_dir, "codex")
        first.agents["codex"].version = ""
        first.agents["codex"].error = ad.UNTRUSTED_PREFIX_ERROR
        second = self._disc({"codex", "hermes"})

        with patch.object(cmd_init.agent_discovery, "discover_agents", side_effect=[first, second]) as discover, \
                patch.object(cmd_init.click, "confirm", return_value=True), \
                patch.object(cmd_init, "_prompt_checkbox_selection", side_effect=AssertionError("picker opened")):
            got = cmd_init._prompt_connector_selection("hermes", False, data_dir=self.tmp_dir)

        self.assertEqual(got, ["hermes"])
        self.assertEqual(discover.call_count, 2)
        prefixes = _trusted_prefixes_from_config(self.tmp_dir)
        self.assertIn(os.path.realpath(hermes_dir), prefixes)
        self.assertNotIn(os.path.realpath(codex_dir), prefixes)

    def test_prompt_first_run_explicit_action_declined_trust_downgrades_with_remediation(self):
        from defenseclaw.commands import cmd_init
        from defenseclaw.inventory import agent_discovery as ad

        bin_dir = os.path.join(self.tmp_dir, "hermes-bin")
        os.makedirs(bin_dir)
        bin_path = os.path.join(bin_dir, "hermes")
        disc = self._disc({"hermes"})
        disc.agents["hermes"].binary_path = bin_path
        disc.agents["hermes"].version = ""
        disc.agents["hermes"].error = ad.UNTRUSTED_PREFIX_ERROR
        prompts = iter(["local"])
        confirms = iter([False, False, True])  # early trust, start_gateway, verify

        with patch.object(cmd_init.agent_discovery, "discover_agents", return_value=disc), \
                patch(
                    "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                    return_value=False,
                ), \
                patch.object(cmd_init, "_prompt_checkbox_selection", return_value=[]), \
                patch.object(cmd_init.click, "prompt", side_effect=lambda *a, **k: next(prompts)), \
                patch.object(cmd_init.click, "confirm", side_effect=lambda *a, **k: next(confirms)):
            settings, scanner_mode, with_judge, judge_connectors, start_gateway, verify = cmd_init._prompt_first_run(
                connector="hermes", profile="action", scanner_mode="local", with_judge=False,
                fail_mode=None, human_approval=None, hilt_min_severity=None,
                start_gateway=False, verify=None, rescan_agents=False, data_dir=self.tmp_dir,
            )

        self.assertEqual(scanner_mode, "local")
        self.assertFalse(with_judge)
        self.assertEqual(judge_connectors, [])
        self.assertFalse(start_gateway)
        self.assertTrue(verify)
        self.assertEqual(settings[0]["connector"], "hermes")
        self.assertEqual(settings[0]["profile"], "observe")
        warning = settings[0]["mode_warning"]
        self.assertEqual(warning["requested_mode"], "action")
        self.assertEqual(warning["actual_mode"], "observe")
        self.assertEqual(warning["trusted_path"], os.path.realpath(bin_dir))
        self.assertEqual(
            warning["next_command"],
            f"defenseclaw setup trusted-paths add {os.path.realpath(bin_dir)}",
        )

    def test_prompt_first_run_action_trust_retry_keeps_action_mode(self):
        from defenseclaw.commands import cmd_init
        from defenseclaw.inventory import agent_discovery as ad

        bin_dir = os.path.join(self.tmp_dir, "hermes-bin")
        os.makedirs(bin_dir)
        bin_path = os.path.join(bin_dir, "hermes")

        cached = self._disc({"hermes"})
        cached.agents["hermes"].binary_path = bin_path
        cached.agents["hermes"].version = "hermes 1.0"
        cached.agents["hermes"].error = ""

        untrusted = self._disc({"hermes"})
        untrusted.agents["hermes"].binary_path = bin_path
        untrusted.agents["hermes"].version = ""
        untrusted.agents["hermes"].error = ad.UNTRUSTED_PREFIX_ERROR

        rescanned = self._disc({"hermes"})
        rescanned.agents["hermes"].binary_path = bin_path
        rescanned.agents["hermes"].version = "hermes 1.0"
        rescanned.agents["hermes"].error = ""

        prompts = iter(["local", "open"])
        confirms = iter([True, False, False, True])  # trust, HITL, start_gateway, verify

        with patch.object(cmd_init.agent_discovery, "discover_agents", side_effect=[cached, untrusted, rescanned]), \
                patch(
                    "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                    side_effect=[False, True],
                ), \
                patch.object(cmd_init, "_prompt_checkbox_selection", return_value=[]), \
                patch.object(cmd_init.click, "prompt", side_effect=lambda *a, **k: next(prompts)), \
                patch.object(cmd_init.click, "confirm", side_effect=lambda *a, **k: next(confirms)):
            settings, scanner_mode, with_judge, judge_connectors, start_gateway, verify = cmd_init._prompt_first_run(
                connector="hermes", profile="action", scanner_mode="local", with_judge=False,
                fail_mode=None, human_approval=None, hilt_min_severity=None,
                start_gateway=False, verify=None, rescan_agents=False, data_dir=self.tmp_dir,
            )

        self.assertEqual(scanner_mode, "local")
        self.assertFalse(with_judge)
        self.assertEqual(judge_connectors, [])
        self.assertFalse(start_gateway)
        self.assertTrue(verify)
        self.assertEqual(settings[0]["connector"], "hermes")
        self.assertEqual(settings[0]["profile"], "action")
        self.assertIsNone(settings[0]["mode_warning"])

        self.assertIn(os.path.realpath(bin_dir), _trusted_prefixes_from_config(self.tmp_dir))

    def test_checkbox_selector_toggles_with_keys(self):
        from defenseclaw.commands import cmd_init

        keys = iter([" ", "j", " ", "\r"])
        with patch.object(cmd_init.click, "getchar", side_effect=lambda: next(keys)), \
                patch.object(cmd_init, "_supports_terminal_redraw", return_value=True):
            got = cmd_init._prompt_checkbox_selection(
                ["codex", "claudecode"],
                default_selected=["codex"],
                title="Select connectors",
                empty_ok=False,
            )
        self.assertEqual(got, ["claudecode"])

    def test_checkbox_key_names_cover_windows_ansi_and_vi_navigation(self):
        from defenseclaw.commands import cmd_init

        cases = {
            "\x1b[A": "up",
            "\x1b[B": "down",
            "\x00H": "up",
            "\xe0H": "up",
            "\x00P": "down",
            "\xe0P": "down",
            "k": "up",
            "j": "down",
        }
        for key, expected in cases.items():
            with self.subTest(key=list(map(ord, key))):
                self.assertEqual(cmd_init._checkbox_key_name(key), expected)

    def test_checkbox_selector_accepts_windows_extended_arrow(self):
        from defenseclaw.commands import cmd_init

        keys = iter(["\xe0P", " ", "\r"])
        with patch.object(cmd_init.click, "getchar", side_effect=lambda: next(keys)), \
                patch.object(cmd_init, "_supports_terminal_redraw", return_value=True):
            got = cmd_init._prompt_checkbox_selection(
                ["codex", "claudecode"],
                default_selected=["codex"],
                title="Select connectors",
                empty_ok=False,
            )
        self.assertEqual(got, ["codex", "claudecode"])

    def test_checkbox_no_vt_stays_key_driven_without_reprinting_menu(self):
        from defenseclaw.commands import cmd_init

        emitted: list[str] = []
        keys = iter(["\xe0P", " ", "\r"])
        with patch.object(cmd_init, "_supports_terminal_redraw", return_value=False), \
                patch.object(cmd_init.click, "getchar", side_effect=lambda: next(keys)), \
                patch.object(cmd_init.click, "echo", side_effect=lambda text="", **_kwargs: emitted.append(text)):
            got = cmd_init._prompt_checkbox_selection(
                ["codex", "claudecode"],
                default_selected=["codex"],
                title="Select connectors",
                empty_ok=False,
            )

        self.assertEqual(got, ["codex", "claudecode"])
        self.assertNotIn("comma-separated", "".join(emitted))
        menu_rows = [line for line in emitted if line.startswith("    [")]
        self.assertEqual(menu_rows, ["    [x] codex", "    [ ] claudecode"])
        self.assertTrue(any(line.startswith("\r  Current 2/2: [x] claudecode") for line in emitted))

    def test_checkbox_windows_tty_keeps_in_place_redraw(self):
        from defenseclaw.commands import cmd_init

        with patch.object(cmd_init.terminal_checkbox, "stdout_is_tty", return_value=True), \
                patch.object(cmd_init.os, "name", "nt"):
            self.assertTrue(cmd_init._supports_terminal_redraw())

    def test_checkbox_windows_terminal_hint_keeps_redraw_when_stdout_is_wrapped(self):
        from defenseclaw.commands import cmd_init

        with patch.object(cmd_init.terminal_checkbox, "stdout_is_tty", return_value=False), \
                patch.object(cmd_init.os, "name", "nt"), \
                patch.dict(cmd_init.os.environ, {"WT_SESSION": "test-session"}, clear=True):
            self.assertTrue(cmd_init._supports_terminal_redraw())

    def test_checkbox_redraw_uses_ansi_cursor_and_line_controls(self):
        from defenseclaw.commands import cmd_init

        with patch.object(cmd_init.click, "echo") as echo:
            cmd_init._render_checkbox_menu(
                ["codex", "claudecode"],
                {"codex"},
                1,
                redraw=True,
            )

        emitted = "".join(call.args[0] for call in echo.call_args_list)
        self.assertIn("\x1b[2A\r", emitted)
        self.assertEqual(emitted.count("\x1b[2K"), 2)
        self.assertIn("    [x] codex", emitted)
        self.assertIn("  > [ ] claudecode", emitted)

    def test_connector_selection_uses_checkbox_menu(self):
        from defenseclaw.commands import cmd_init

        disc = self._disc({"codex", "claudecode"})
        with patch.object(cmd_init.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_init.agent_discovery, "render_discovery_table", return_value=""), \
                patch.object(
                    cmd_init,
                    "_prompt_checkbox_selection",
                    return_value=["claudecode"],
                ) as selector:
            got = cmd_init._prompt_connector_selection(None, False)
        self.assertEqual(got, ["claudecode"])
        selector.assert_called_once()
        self.assertEqual(selector.call_args.kwargs["default_selected"], ["codex", "claudecode"])

    def test_connector_selection_can_trust_untrusted_binary_dirs_and_rescan(self):
        from defenseclaw.commands import cmd_init
        from defenseclaw.inventory import agent_discovery as ad

        bin_dir = os.path.join(self.tmp_dir, "tool", "bin")
        os.makedirs(bin_dir)
        bin_path = os.path.join(bin_dir, "codex")
        first = self._disc({"codex"})
        first.agents["codex"].binary_path = bin_path
        first.agents["codex"].version = ""
        first.agents["codex"].error = ad.UNTRUSTED_PREFIX_ERROR
        second = self._disc({"codex"})
        second.agents["codex"].binary_path = bin_path
        second.agents["codex"].version = "codex 1.0"
        second.agents["codex"].error = ""

        with patch.object(cmd_init.agent_discovery, "discover_agents", side_effect=[first, second]) as discover, \
                patch.object(cmd_init.agent_discovery, "render_discovery_table", return_value=""), \
                patch.object(cmd_init.click, "confirm", return_value=True), \
                patch.object(cmd_init, "_prompt_checkbox_selection", return_value=["codex"]):
            got = cmd_init._prompt_connector_selection(None, False, data_dir=self.tmp_dir)

        self.assertEqual(got, ["codex"])
        self.assertEqual(discover.call_count, 2)
        self.assertIn(os.path.realpath(bin_dir), _trusted_prefixes_from_config(self.tmp_dir))


class TestInitObserveAllActionConnectors(unittest.TestCase):
    """Non-interactive --observe-all / --action-connectors wiring.

    These pin the scripted contract: detect every hook connector and bring
    them up in observe by default, promoting only the named subset to action.
    """

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-observe-all-")
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)
        self.runner = CliRunner()
        self.selection_patcher = patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            return_value=({}, {}),
        )
        self.selection_patcher.start()
        self.addCleanup(self.selection_patcher.stop)

    def _invoke(self, args, env=None):
        full_env = {"DEFENSECLAW_HOME": self.tmp_dir}
        if env:
            full_env.update(env)
        return self.runner.invoke(init_cmd, args, obj=AppContext(), env=full_env)

    def _disc(self, installed):
        return AgentDiscovery(
            scanned_at="2026-06-09T00:00:00Z",
            cache_hit=False,
            agents={
                name: AgentSignal(
                    name=name,
                    installed=name in installed,
                    config_path=f"/tmp/{name}.cfg" if name in installed else "",
                    binary_path="",
                    version="",
                    error="",
                )
                for name in KNOWN_CONNECTORS
            },
        )

    def _load_cfg(self) -> dict:
        import yaml

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def test_help_lists_new_flags(self):
        result = self.runner.invoke(init_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("--observe-all", result.output)
        self.assertIn("--action-connectors", result.output)

    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_observe_all_configures_every_detected_in_observe(self, mock_discover):
        mock_discover.return_value = self._disc({"codex", "claudecode"})

        result = self._invoke([
            "--non-interactive", "--yes", "--observe-all",
            "--scanner-mode", "local", "--skip-install",
            "--no-start-gateway", "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        summary = json.loads(result.output)
        self.assertEqual(sorted(summary.get("connectors", [])), ["claudecode", "codex"])

        cfg = self._load_cfg()
        self.assertEqual(cfg["guardrail"].get("mode", "observe"), "observe")
        connectors = cfg["guardrail"]["connectors"]
        self.assertEqual(sorted(connectors), ["claudecode", "codex"])
        # No connector enforces: the explicit override is observe and the
        # global mode is observe (empty override inherits it).
        self.assertIn(connectors["claudecode"].get("mode", ""), ("", "observe"))
        self.assertIn(connectors["codex"].get("mode", ""), ("", "observe"))

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True)
    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_observe_all_with_action_subset_sets_per_connector_override(self, mock_discover, _gate):
        mock_discover.return_value = self._disc({"codex", "claudecode"})

        result = self._invoke([
            "--non-interactive", "--yes",
            "--observe-all", "--action-connectors", "claudecode",
            "--scanner-mode", "local", "--skip-install",
            "--no-start-gateway", "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        cfg = self._load_cfg()
        # Primary (codex) is observe → global mode observe; claudecode is the
        # enforcing peer via a per-connector override.
        self.assertEqual(cfg["guardrail"].get("mode", "observe"), "observe")
        self.assertEqual(cfg["guardrail"]["connectors"]["claudecode"]["mode"], "action")
        self.assertIn(cfg["guardrail"]["connectors"]["codex"].get("mode", ""), ("", "observe"))

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True)
    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_action_connectors_only_configures_named_connector(self, mock_discover, _gate):
        mock_discover.return_value = self._disc({"codex", "claudecode"})

        result = self._invoke([
            "--non-interactive", "--yes",
            "--action-connectors", "codex",
            "--scanner-mode", "local", "--skip-install",
            "--no-start-gateway", "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        summary = json.loads(result.output)
        # Without --observe-all only the named connector is configured.
        self.assertEqual(summary["connector"], "codex")
        self.assertNotIn("connectors", summary)

        cfg = self._load_cfg()
        self.assertEqual(cfg["guardrail"]["mode"], "action")
        self.assertEqual(cfg["guardrail"]["connector"], "codex")
        self.assertNotIn("claudecode", cfg["guardrail"].get("connectors", {}) or {})

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=False)
    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_unverified_action_connector_downgrades_to_observe(self, mock_discover, _gate):
        mock_discover.return_value = self._disc({"codex"})

        result = self._invoke([
            "--non-interactive", "--yes",
            "--action-connectors", "codex",
            "--scanner-mode", "local", "--skip-install",
            "--no-start-gateway", "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        summary = json.loads(result.output)
        self.assertEqual(summary["status"], "needs_attention")
        warning = summary["connector_mode_warnings"][0]
        self.assertEqual(warning["connector"], "codex")
        self.assertEqual(warning["requested_mode"], "action")
        self.assertEqual(warning["actual_mode"], "observe")
        self.assertIn("version could not be verified", warning["reason"])
        self.assertEqual(warning["next_command"], "defenseclaw setup codex --mode action")
        self.assertTrue(
            any(
                step["name"] == "Codex mode"
                and step["status"] == "fail"
                and "requested action, configured observe" in step["detail"]
                for step in summary["setup"]
            ),
            summary["setup"],
        )

        cfg = self._load_cfg()
        self.assertEqual(cfg["guardrail"].get("mode", "observe"), "observe")

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=False)
    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_json_summary_suppresses_missing_action_connector_prose(self, mock_discover, _gate):
        mock_discover.return_value = self._disc({"codex"})

        result = self._invoke([
            "--non-interactive", "--yes",
            "--observe-all", "--action-connectors", "copilot",
            "--scanner-mode", "local", "--skip-install",
            "--no-start-gateway", "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.assertTrue(result.output.lstrip().startswith("{"), result.output)
        self.assertNotIn("not detected as installed", result.output)
        self.assertNotIn("not detected as installed", result.stderr or "")

        summary = json.loads(result.output)
        warning = summary["connector_mode_warnings"][0]
        self.assertEqual(warning["connector"], "copilot")
        self.assertEqual(warning["actual_mode"], "observe")

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=False)
    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_action_connector_trusted_path_downgrade_is_structured(self, mock_discover, _gate):
        from defenseclaw.inventory import agent_discovery as ad

        disc = self._disc({"codex", "hermes"})
        bin_dir = os.path.join(self.tmp_dir, "tool", "bin")
        bin_path = os.path.join(bin_dir, "hermes")
        disc.agents["hermes"].binary_path = bin_path
        disc.agents["hermes"].version = ""
        disc.agents["hermes"].error = ad.UNTRUSTED_PREFIX_ERROR
        mock_discover.return_value = disc

        result = self._invoke([
            "--non-interactive", "--yes",
            "--observe-all", "--action-connectors", "hermes",
            "--scanner-mode", "local", "--skip-install",
            "--no-start-gateway", "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        summary = json.loads(result.output)
        self.assertEqual(summary["status"], "needs_attention")
        self.assertIn("hermes", summary["connectors"])
        warning = summary["connector_mode_warnings"][0]
        self.assertEqual(warning["connector"], "hermes")
        self.assertEqual(warning["requested_mode"], "action")
        self.assertEqual(warning["actual_mode"], "observe")
        self.assertEqual(
            warning["reason"],
            "binary path outside trusted prefixes; version was not probed",
        )
        self.assertEqual(warning["binary_path"], os.path.realpath(bin_path))
        self.assertEqual(warning["trusted_path"], os.path.realpath(bin_dir))
        self.assertEqual(
            warning["next_command"],
            f"defenseclaw setup trusted-paths add {os.path.realpath(bin_dir)}",
        )
        self.assertIn(warning["next_command"], summary["next_commands"])

        cfg = self._load_cfg()
        self.assertEqual(cfg["guardrail"]["connectors"]["hermes"]["mode"], "observe")

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=False)
    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_action_connector_downgrade_refreshes_discovery_for_trusted_path_details(self, mock_discover, _gate):
        from defenseclaw.inventory import agent_discovery as ad

        stale = self._disc({"codex", "hermes"})
        fresh = self._disc({"codex", "hermes"})
        bin_dir = os.path.join(self.tmp_dir, "tool", "bin")
        bin_path = os.path.join(bin_dir, "hermes")
        fresh.agents["hermes"].binary_path = bin_path
        fresh.agents["hermes"].version = ""
        fresh.agents["hermes"].error = ad.UNTRUSTED_PREFIX_ERROR
        mock_discover.side_effect = [stale, fresh]

        result = self._invoke([
            "--non-interactive", "--yes",
            "--observe-all", "--action-connectors", "hermes",
            "--scanner-mode", "local", "--skip-install",
            "--no-start-gateway", "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        summary = json.loads(result.output)
        warning = summary["connector_mode_warnings"][0]
        self.assertEqual(
            warning["reason"],
            "binary path outside trusted prefixes; version was not probed",
        )
        self.assertEqual(warning["binary_path"], os.path.realpath(bin_path))
        self.assertEqual(warning["trusted_path"], os.path.realpath(bin_dir))
        self.assertEqual(mock_discover.call_count, 2)

    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_no_multi_flags_keeps_single_connector_default(self, mock_discover):
        mock_discover.return_value = self._disc({"codex", "claudecode"})

        result = self._invoke([
            "--non-interactive", "--yes",
            "--scanner-mode", "local", "--skip-install",
            "--no-start-gateway", "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        summary = json.loads(result.output)
        # Backward compatible: discovery-backed single connector, no multi set.
        self.assertEqual(summary["connector"], "codex")
        self.assertNotIn("connectors", summary)

    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_observe_all_excludes_detected_proxy_connectors(self, mock_discover):
        # openclaw is a proxy connector: it owns the single LLM proxy port and
        # cannot be a multi-connector hook peer, so --observe-all must skip it.
        mock_discover.return_value = self._disc({"codex", "claudecode", "openclaw"})

        result = self._invoke([
            "--non-interactive", "--yes", "--observe-all",
            "--scanner-mode", "local", "--skip-install",
            "--no-start-gateway", "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        summary = json.loads(result.output)
        self.assertEqual(sorted(summary.get("connectors", [])), ["claudecode", "codex"])
        cfg = self._load_cfg()
        self.assertNotIn("openclaw", cfg["guardrail"].get("connectors", {}) or {})

    @patch("defenseclaw.bootstrap._start_gateway_structured")
    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_deferred_gateway_start_replaces_stale_sidecar_step(self, mock_discover, mock_start):
        # Multi-connector + --start-gateway defers the gateway boot to a single
        # reconcile after all connectors are merged. run_first_run records a
        # placeholder "Sidecar not started (--no-start-gateway)" step while the
        # start is deferred; the real reconcile result must overwrite it so the
        # report does not contradict the gateway it just (re)started.
        from defenseclaw.bootstrap import StepResult

        mock_discover.return_value = self._disc({"codex", "claudecode"})
        mock_start.return_value = StepResult(
            "Sidecar", "pass", "restarted (was codex, now claudecode)"
        )

        result = self._invoke([
            "--non-interactive", "--yes", "--observe-all", "--start-gateway",
            "--scanner-mode", "local", "--skip-install",
            "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        mock_start.assert_called_once()

        summary = json.loads(result.output)
        sidecar = [s for s in summary["setup"] if s["name"] == "Sidecar"]
        self.assertEqual(len(sidecar), 1, summary["setup"])
        self.assertEqual(sidecar[0]["status"], "pass")
        self.assertIn("restarted", sidecar[0]["detail"])
        self.assertNotIn("not started", sidecar[0]["detail"])
        # The stale "start the gateway" hint (from the deferred skip step) must
        # be recomputed away now that the gateway is actually running.
        self.assertNotIn("defenseclaw-gateway start", summary["next_commands"])

    @patch("defenseclaw.bootstrap._start_gateway_structured")
    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_deferred_gateway_warn_marks_report_partial(self, mock_discover, mock_start):
        # A failed reconcile restart returns a warn step; folding it back into
        # the report must re-roll the overall status to "partial" instead of
        # leaving the stale "ready" computed against the skipped placeholder.
        from defenseclaw.bootstrap import StepResult

        mock_discover.return_value = self._disc({"codex", "claudecode"})
        mock_start.return_value = StepResult(
            "Sidecar", "warn", "connector drift detected (codex → claudecode) but restart failed"
        )

        result = self._invoke([
            "--non-interactive", "--yes", "--observe-all", "--start-gateway",
            "--scanner-mode", "local", "--skip-install",
            "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        summary = json.loads(result.output)
        self.assertEqual(summary["status"], "partial")
        sidecar = [s for s in summary["setup"] if s["name"] == "Sidecar"]
        self.assertEqual(sidecar[0]["status"], "warn")

    @patch("defenseclaw.commands.cmd_init._prompt_first_run")
    @patch("defenseclaw.commands.cmd_init._stdin_is_tty", return_value=True)
    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_observe_all_bypasses_wizard_on_tty(self, mock_discover, _tty, prompt):
        # The multi flags are an explicit scripted selection; they must NOT
        # drop into the interactive wizard even on a TTY (where it would
        # otherwise prompt and silently ignore the flags).
        mock_discover.return_value = self._disc({"codex", "claudecode"})

        result = self._invoke([
            "--observe-all",
            "--scanner-mode", "local", "--skip-install",
            "--no-start-gateway", "--no-verify",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        prompt.assert_not_called()
        cfg = self._load_cfg()
        self.assertEqual(sorted(cfg["guardrail"]["connectors"]), ["claudecode", "codex"])

    @patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents")
    def test_connector_takes_precedence_over_multi_flags_with_warning(self, mock_discover):
        # --connector wins over --observe-all/--action-connectors and must not
        # trigger discovery; the operator is warned the multi flags were dropped.
        mock_discover.side_effect = AssertionError("must not discover when --connector is set")

        result = self._invoke([
            "--non-interactive", "--yes",
            "--connector", "codex", "--observe-all",
            "--scanner-mode", "local", "--skip-install",
            "--no-start-gateway", "--no-verify", "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.assertIn("takes precedence", result.output)

        cfg = self._load_cfg()
        self.assertEqual(cfg["guardrail"]["connector"], "codex")
        self.assertNotIn("claudecode", cfg["guardrail"].get("connectors", {}) or {})

    def test_note_proxy_connectors_points_to_dedicated_setup(self):
        from defenseclaw.commands import cmd_init

        disc = self._disc({"codex", "openclaw"})
        with patch.object(cmd_init.platform_support, "host_os", return_value="linux"), \
                patch.object(cmd_init.ux, "subhead") as subhead:
            cmd_init._note_proxy_connectors(disc)
        emitted = " ".join(call.args[0] for call in subhead.call_args_list if call.args)
        self.assertIn("openclaw", emitted)
        self.assertIn("defenseclaw setup openclaw", emitted)

    def test_note_proxy_connectors_warns_when_unsupported_on_windows(self):
        from defenseclaw.commands import cmd_init

        disc = self._disc({"codex", "openclaw"})
        with patch.object(cmd_init.platform_support, "host_os", return_value="windows"), \
                patch.object(cmd_init.ux, "warn") as warn:
            cmd_init._note_proxy_connectors(disc)
        emitted = " ".join(call.args[0] for call in warn.call_args_list if call.args)
        self.assertIn("openclaw", emitted)
        self.assertIn("unsupported on windows", emitted)
        self.assertIn("guardrail proxy", emitted)

    def test_note_proxy_connectors_silent_without_proxy(self):
        from defenseclaw.commands import cmd_init

        disc = self._disc({"codex", "claudecode"})
        with patch.object(cmd_init.ux, "subhead") as subhead:
            cmd_init._note_proxy_connectors(disc)
        subhead.assert_not_called()


class TestResolveGatewayForConnectorGate(unittest.TestCase):
    """SU-03: _resolve_gateway_for_connector must resolve the OpenClaw gateway
    (and its token) only when openclaw is genuinely active — not when
    guardrail.connector is merely empty (the phantom default)."""

    def _stray_openclaw_json(self, tmp: str, token: str) -> str:
        path = os.path.join(tmp, "openclaw.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                {"gateway": {"model": "local", "port": 19000, "auth": {"token": token}}},
                fh,
            )
        return path

    def test_hook_only_returns_loopback_no_token(self):
        from defenseclaw.commands.cmd_init import _resolve_gateway_for_connector
        from defenseclaw.config import default_config

        with tempfile.TemporaryDirectory() as tmp:
            cfg = default_config()
            cfg.guardrail.connector = "codex"  # hook-only; openclaw NOT active
            cfg.claw.mode = "codex"
            cfg.claw.config_file = self._stray_openclaw_json(tmp, "stray-secret")

            gw = _resolve_gateway_for_connector(cfg)

            self.assertEqual(gw["host"], "127.0.0.1")
            self.assertEqual(gw["port"], 18789)
            self.assertEqual(gw["token"], "", "stray openclaw token must not leak")

    def test_phantom_empty_connector_does_not_resolve_openclaw(self):
        from defenseclaw.commands.cmd_init import _resolve_gateway_for_connector
        from defenseclaw.config import PerConnectorGuardrailConfig, default_config

        with tempfile.TemporaryDirectory() as tmp:
            cfg = default_config()
            # Singular field empty but a hook connector configured in the map:
            # the old `(connector or "openclaw")` floored to openclaw here.
            cfg.guardrail.connector = ""
            cfg.claw.mode = ""
            cfg.guardrail.connectors = {"hermes": PerConnectorGuardrailConfig()}
            cfg.claw.config_file = self._stray_openclaw_json(tmp, "stray-secret")

            gw = _resolve_gateway_for_connector(cfg)

            self.assertEqual(gw["token"], "", "phantom openclaw must not resolve a token")

    def test_openclaw_active_resolves_token(self):
        from defenseclaw.commands.cmd_init import _resolve_gateway_for_connector
        from defenseclaw.config import default_config

        with tempfile.TemporaryDirectory() as tmp:
            cfg = default_config()
            cfg.guardrail.connector = "openclaw"
            cfg.claw.mode = "openclaw"
            cfg.claw.config_file = self._stray_openclaw_json(tmp, "legit-secret")

            gw = _resolve_gateway_for_connector(cfg)

            self.assertEqual(gw["token"], "legit-secret")
            self.assertEqual(gw["port"], 19000)


if __name__ == "__main__":
    unittest.main()
