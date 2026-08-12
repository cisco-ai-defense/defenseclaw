# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the quickstart compatibility wrapper."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner, Result
from defenseclaw.bootstrap import StepResult
from defenseclaw.commands.cmd_quickstart import quickstart_cmd
from defenseclaw.connector_paths import KNOWN_CONNECTORS
from defenseclaw.inventory import agent_discovery
from defenseclaw.inventory.agent_discovery import AgentDiscovery, AgentSignal


class QuickstartProfileDefaultsTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-quickstart-")
        self.home_dir = os.path.join(self.tmp_dir, "home")
        self.empty_path = os.path.join(self.tmp_dir, "empty-bin")
        os.makedirs(self.home_dir, exist_ok=True)
        os.makedirs(self.empty_path, exist_ok=True)
        self.runner = CliRunner()
        self.credential_setup_patcher = patch(
            "defenseclaw.bootstrap._setup_credential_protection_structured",
            return_value=StepResult("Credential protection", "pass", "s-gw fixture ready"),
        )
        self.credential_default_patcher = patch(
            "defenseclaw.credential_protection.credential_protection_default_enabled",
            return_value=True,
        )
        self.credential_readiness_patcher = patch(
            "defenseclaw.bootstrap._credential_protection_readiness",
            return_value=StepResult("Credential protection", "pass", "s-gw fixture ready"),
        )
        self.credential_setup = self.credential_setup_patcher.start()
        self.credential_readiness = self.credential_readiness_patcher.start()
        self.credential_default_patcher.start()

    def tearDown(self):
        self.credential_default_patcher.stop()
        self.credential_readiness_patcher.stop()
        self.credential_setup_patcher.stop()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _invoke(self, args):
        return self.runner.invoke(
            quickstart_cmd,
            args,
            env={
                "DEFENSECLAW_HOME": self.tmp_dir,
                "HOME": self.home_dir,
                "USERPROFILE": self.home_dir,
                "PATH": self.empty_path,
            },
        )

    def _discovery(self, installed):
        return AgentDiscovery(
            scanned_at="2026-06-22T16:00:00Z",
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

    def test_codex_defaults_to_observe_profile(self):
        result = self._invoke(
            [
                "--connector",
                "codex",
                "--skip-gateway",
                "--json-summary",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "codex")
        self.assertEqual(summary["profile"], "observe")
        from defenseclaw import migration_state

        state = migration_state.load(self.tmp_dir)
        self.assertIsNotNone(state)
        assert state is not None
        self.assertTrue(migration_state.is_applied(state, "0.8.5"))

    def test_openclaw_defaults_to_observe_profile(self):
        result = self._invoke(
            [
                "--connector",
                "openclaw",
                "--skip-gateway",
                "--json-summary",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "openclaw")
        self.assertEqual(summary["profile"], "observe")

    def test_fresh_install_enables_credential_protection_by_default(self):
        result = self._invoke(
            [
                "--connector",
                "codex",
                "--skip-gateway",
                "--json-summary",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["credential_protection"], {"enabled": True})

    def test_source_install_without_staged_module_defaults_off(self):
        self.credential_setup.reset_mock()
        with patch(
            "defenseclaw.credential_protection.credential_protection_default_enabled",
            return_value=False,
        ):
            result = self._invoke(
                [
                    "--connector",
                    "codex",
                    "--skip-gateway",
                    "--json-summary",
                ]
            )

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.credential_setup.assert_not_called()
        import yaml

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertNotIn("credential_protection", cfg)
        summary = json.loads(result.output)
        step = next(item for item in summary["setup"] if item["name"] == "Credential broker")
        self.assertIn("release artifacts are not installed", step["detail"])

    def test_explicit_source_opt_in_still_runs_broker_setup(self):
        self.credential_setup.reset_mock()
        with patch(
            "defenseclaw.credential_protection.credential_protection_default_enabled",
            return_value=False,
        ):
            result = self._invoke(
                [
                    "--connector",
                    "codex",
                    "--skip-gateway",
                    "--credential-protection",
                    "--json-summary",
                ]
            )

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.credential_setup.assert_called_once()
        import yaml

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["credential_protection"], {"enabled": True})

    def test_fresh_install_can_opt_out_of_credential_protection(self):
        result = self._invoke(
            [
                "--connector",
                "codex",
                "--skip-gateway",
                "--no-credential-protection",
                "--json-summary",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertNotIn("credential_protection", cfg)
        self.credential_setup.assert_not_called()

    def test_missing_node_blocks_default_credential_protection_setup(self):
        self.credential_setup.return_value = StepResult(
            "Credential protection",
            "fail",
            "Node.js 20 or newer is required for credential protection.",
            "defenseclaw setup credential-protection",
        )
        self.credential_readiness.return_value = StepResult(
            "Credential protection",
            "fail",
            "node missing",
            "Install Node.js 20 or newer.",
        )

        result = self._invoke(
            [
                "--connector",
                "codex",
                "--skip-gateway",
                "--json-summary",
            ]
        )

        self.assertEqual(result.exit_code, 1, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["status"], "needs_attention")
        setup = {step["name"]: step for step in summary["setup"]}
        self.assertEqual(setup["Credential protection"]["status"], "fail")

        import yaml

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertNotIn("credential_protection", cfg)

    def test_gateway_does_not_start_after_credential_setup_failure(self):
        self.credential_setup.return_value = StepResult(
            "Credential protection",
            "fail",
            "MCP codex=conflict",
            "defenseclaw setup credential-protection --yes",
        )
        self.credential_readiness.return_value = StepResult(
            "Credential protection",
            "fail",
            "MCP codex=conflict",
            "defenseclaw setup credential-protection --yes",
        )

        with patch("defenseclaw.bootstrap._start_gateway_structured") as start_gateway:
            result = self._invoke(["--connector", "codex", "--json-summary"])

        self.assertEqual(result.exit_code, 1, result.output + (result.stderr or ""))
        start_gateway.assert_not_called()
        summary = json.loads(result.output)
        sidecar = next(step for step in summary["setup"] if step["name"] == "Sidecar")
        self.assertIn("credential-protection setup did not complete", sidecar["detail"])

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True)
    def test_rerun_does_not_enable_credential_protection_implicitly(self, _gate):
        with open(os.path.join(self.tmp_dir, "config.yaml"), "w", encoding="utf-8") as fh:
            fh.write(
                "config_version: 8\n"
                "observability: {}\n"
                "claw:\n"
                "  mode: codex\n"
                "guardrail:\n"
                "  enabled: true\n"
                "  connector: codex\n"
                "  mode: observe\n"
            )

        result = self._invoke(
            [
                "--connector",
                "codex",
                "--skip-gateway",
                "--json-summary",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertNotIn("credential_protection", cfg)

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True)
    def test_existing_enabled_broker_reconciles_after_connector_change(self, _gate):
        with open(os.path.join(self.tmp_dir, "config.yaml"), "w", encoding="utf-8") as fh:
            fh.write(
                "config_version: 8\n"
                "observability: {}\n"
                "credential_protection:\n"
                "  enabled: true\n"
                "claw:\n"
                "  mode: codex\n"
                "guardrail:\n"
                "  enabled: true\n"
                "  connector: codex\n"
                "  mode: observe\n"
            )

        self.credential_setup.reset_mock()
        result = self._invoke(
            [
                "--connector",
                "claudecode",
                "--skip-gateway",
                "--json-summary",
            ]
        )

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.credential_setup.assert_called_once()
        configured = self.credential_setup.call_args.args[0]
        self.assertIn("claudecode", configured.active_connectors())
        self.assertEqual(
            self.credential_setup.call_args.kwargs["removed_connectors"],
            ["codex"],
        )

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True)
    def test_existing_enabled_broker_repair_restarts_same_connector_gateway(self, _gate):
        with open(os.path.join(self.tmp_dir, "config.yaml"), "w", encoding="utf-8") as fh:
            fh.write(
                "config_version: 8\n"
                "observability: {}\n"
                "credential_protection:\n"
                "  enabled: true\n"
                "claw:\n"
                "  mode: codex\n"
                "guardrail:\n"
                "  enabled: true\n"
                "  connector: codex\n"
                "  mode: observe\n"
            )

        with (
            patch(
                "defenseclaw.bootstrap._start_gateway_structured",
                return_value=StepResult(
                    "Sidecar",
                    "pass",
                    "restarted after credential-protection service",
                ),
            ) as start_gateway,
            patch("defenseclaw.bootstrap._pid_file_running", return_value=True),
            patch(
                "defenseclaw.bootstrap._connector_readiness",
                return_value=StepResult("Connector", "pass", "Codex config found"),
            ),
        ):
            result = self._invoke(
                [
                    "--connector",
                    "codex",
                    "--json-summary",
                ]
            )

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        start_gateway.assert_called_once()
        self.assertTrue(start_gateway.call_args.kwargs["restart_if_running"])

    def test_explicit_mode_overrides_connector_default(self):
        result = self._invoke(
            [
                "--connector",
                "codex",
                "--mode",
                "observe",
                "--skip-gateway",
                "--json-summary",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["profile"], "observe")

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True)
    def test_explicit_action_updates_existing_per_connector_mode(self, _gate):
        with open(os.path.join(self.tmp_dir, "config.yaml"), "w", encoding="utf-8") as fh:
            fh.write(
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
                "      mode: observe\n"
            )

        result = self._invoke(
            [
                "--connector",
                "hermes",
                "--mode",
                "action",
                "--skip-gateway",
                "--json-summary",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["profile"], "action")
        setup = {step["name"]: step for step in summary["setup"]}
        self.assertIn("hermes, mode=action", setup["Guardrail"]["detail"])

        import yaml

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["guardrail"]["connectors"]["hermes"]["mode"], "action")

    @patch("defenseclaw.bootstrap.agent_discovery.discover_agents")
    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=False)
    def test_action_mode_trusted_path_downgrade_is_structured(self, _gate, mock_discover):
        disc = self._discovery({"hermes"})
        disc.agents["hermes"].binary_path = "/tmp/fake/hermes-bin"
        disc.agents["hermes"].error = agent_discovery.UNTRUSTED_PREFIX_ERROR
        mock_discover.return_value = disc

        result = self._invoke(
            [
                "--connector",
                "hermes",
                "--mode",
                "action",
                "--skip-gateway",
                "--json-summary",
            ]
        )
        self.assertEqual(result.exit_code, 1, result.output + (result.stderr or ""))
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

        import yaml

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["guardrail"]["connector"], "hermes")
        self.assertEqual(cfg["guardrail"].get("mode", "observe"), "observe")

    def test_help_lists_fail_mode_flag(self):
        # Quickstart is the headless path most likely to be wired
        # into installers and CI. If --fail-mode disappears from
        # help, scripts that opt into fail-closed silently regress.
        result = self.runner.invoke(quickstart_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--fail-mode", result.output)

    def test_fail_mode_closed_persists_to_config(self):
        result = self._invoke(
            [
                "--connector",
                "codex",
                "--skip-gateway",
                "--fail-mode",
                "closed",
                "--json-summary",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        from defenseclaw.config import _normalize_hook_fail_mode

        self.assertEqual(
            _normalize_hook_fail_mode(cfg["guardrail"].get("hook_fail_mode", "")),
            "closed",
        )

    def test_omitting_fail_mode_resolves_to_closed(self):
        # Closes when the operator omits ``--fail-mode``
        # at quickstart, the resulting config must default to the safer
        # "closed" sentinel so response-layer failures (4xx, malformed
        # JSON, missing action) BLOCK the tool/prompt rather than
        # silently allowing it. Existing v3 installs are protected by
        # _migrate_0_4_0_seed_hook_fail_mode (migrations.py), so this
        # behavior change is new-install-only.
        result = self._invoke(
            [
                "--connector",
                "codex",
                "--skip-gateway",
                "--json-summary",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        from defenseclaw.config import _normalize_hook_fail_mode

        raw = cfg["guardrail"].get("hook_fail_mode", "")
        self.assertEqual(_normalize_hook_fail_mode(raw), "closed")

    def test_requested_gateway_start_failure_is_nonzero_in_human_and_json(self):
        def invoke(args: list[str]) -> Result:
            failed_start = StepResult(
                "Sidecar",
                "warn",
                "simulated gateway start failure",
                "defenseclaw-gateway status",
            )
            with (
                patch(
                    "defenseclaw.bootstrap._start_gateway_structured",
                    return_value=failed_start,
                ),
                patch("defenseclaw.bootstrap._pid_file_running", return_value=False),
            ):
                return self._invoke(args)

        human = invoke(["--connector", "codex"])
        self.assertEqual(human.exit_code, 1, human.output + (human.stderr or ""))
        self.assertIn("status=needs_attention", human.output)
        self.assertIn("simulated gateway start failure", human.output)

        structured = invoke(
            [
                "--connector",
                "codex",
                "--json-summary",
                "--force",
            ]
        )
        self.assertEqual(
            structured.exit_code,
            1,
            structured.output + (structured.stderr or ""),
        )
        summary = json.loads(structured.output)
        self.assertEqual(summary["status"], "needs_attention")
        sidecars = [step for step in summary["setup"] + summary["readiness"] if step["name"] == "Sidecar"]
        self.assertTrue(sidecars)
        self.assertTrue(all(step["status"] == "fail" for step in sidecars))

    def test_gateway_start_success_but_readiness_failure_is_nonzero(self):
        with (
            patch(
                "defenseclaw.bootstrap._start_gateway_structured",
                return_value=StepResult("Sidecar", "pass", "started"),
            ),
            patch("defenseclaw.bootstrap._pid_file_running", return_value=False),
        ):
            result = self._invoke(
                [
                    "--connector",
                    "codex",
                    "--json-summary",
                ]
            )

        self.assertEqual(result.exit_code, 1, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["status"], "needs_attention")
        readiness = {step["name"]: step for step in summary["readiness"]}
        self.assertEqual(readiness["Sidecar"]["status"], "fail")
        self.assertEqual(readiness["Sidecar"]["detail"], "not confirmed after start")

    def test_selected_connector_establishment_failure_is_nonzero(self):
        missing_connector = StepResult(
            "Connector",
            "warn",
            "Codex config not found yet",
            "defenseclaw setup codex",
        )
        with (
            patch(
                "defenseclaw.bootstrap._connector_readiness",
                return_value=missing_connector,
            ),
            patch(
                "defenseclaw.bootstrap._start_gateway_structured",
                return_value=StepResult("Sidecar", "pass", "started"),
            ),
            patch(
                "defenseclaw.bootstrap._pid_file_running",
                return_value=True,
            ),
        ):
            result = self._invoke(
                [
                    "--connector",
                    "codex",
                    "--json-summary",
                ]
            )

        self.assertEqual(result.exit_code, 1, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["status"], "needs_attention")
        readiness = {step["name"]: step for step in summary["readiness"]}
        self.assertEqual(readiness["Connector"]["status"], "fail")
        self.assertEqual(readiness["Connector"]["detail"], "Codex config not found yet")

    def test_optional_warning_only_remains_partial_and_zero(self):
        advisory = [StepResult("Skill scanner", "warn", "optional scanner unavailable")]
        with (
            patch("defenseclaw.bootstrap._scanner_availability", return_value=advisory),
            patch(
                "defenseclaw.bootstrap._connector_readiness",
                return_value=StepResult("Connector", "pass", "Codex config found"),
            ),
        ):
            result = self._invoke(
                [
                    "--connector",
                    "codex",
                    "--skip-gateway",
                    "--json-summary",
                ]
            )

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["status"], "partial")
        self.assertFalse(any(step["status"] == "fail" for step in summary["setup"] + summary["readiness"]))

    def test_fully_healthy_report_is_ready_and_zero(self):
        available = [StepResult("Skill scanner", "pass", "found")]
        with (
            patch("defenseclaw.bootstrap._scanner_availability", return_value=available),
            patch(
                "defenseclaw.bootstrap._connector_readiness",
                return_value=StepResult("Connector", "pass", "Codex config found"),
            ),
            patch("defenseclaw.bootstrap.shutil.which", return_value="available"),
        ):
            result = self._invoke(
                [
                    "--connector",
                    "codex",
                    "--skip-gateway",
                    "--json-summary",
                ]
            )

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["status"], "ready")

    # --- SU-12: never silently default to codex ------------------------
    def test_no_connector_no_detection_errors_not_codex(self):
        # No --connector, no installer hint, nothing installed (empty HOME):
        # quickstart must error rather than silently configuring codex.
        with patch(
            "defenseclaw.commands.cmd_setup._detect_installed_connectors",
            return_value=[],
        ):
            result = self._invoke(["--skip-gateway", "--json-summary"])
        self.assertNotEqual(result.exit_code, 0)
        # No connector was configured, so no JSON summary is emitted at all.
        self.assertNotIn('"connector": "codex"', result.output)
        self.assertIn("Could not detect", result.output + (result.stderr or ""))

    def test_single_detected_connector_is_used(self):
        # Exactly one agent installed -> quickstart uses it, no flag needed.
        with patch(
            "defenseclaw.commands.cmd_setup._detect_installed_connectors",
            return_value=["codex"],
        ):
            result = self._invoke(["--skip-gateway", "--json-summary"])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "codex")

    def test_ambiguous_detection_errors(self):
        # Two agents installed -> ambiguous -> explicit error, never a guess.
        with patch(
            "defenseclaw.commands.cmd_setup._detect_installed_connectors",
            return_value=["claudecode", "codex"],
        ):
            result = self._invoke(["--skip-gateway", "--json-summary"])
        self.assertNotEqual(result.exit_code, 0)
        output = result.output + (result.stderr or "")
        self.assertIn("Multiple connectors detected/configured", output)
        self.assertIn("claudecode, codex", output)
        self.assertIn("Re-run with --connector <name>", output)

    def test_picked_hint_does_not_mask_ambiguous_detection(self):
        # The installer's picked_connector hint is advisory; it must not hide
        # that a bare quickstart would be choosing among several connectors.
        with open(os.path.join(self.tmp_dir, "picked_connector"), "w", encoding="utf-8") as fh:
            fh.write("codex")
        with patch(
            "defenseclaw.commands.cmd_setup._detect_installed_connectors",
            return_value=["claudecode", "codex"],
        ):
            result = self._invoke(["--skip-gateway", "--json-summary"])
        self.assertNotEqual(result.exit_code, 0)
        output = result.output + (result.stderr or "")
        self.assertIn("Multiple connectors detected/configured", output)
        self.assertIn("claudecode, codex", output)
        self.assertNotIn('"connector": "codex"', result.output)

    def test_picked_hint_without_detection_is_reported_in_json(self):
        with open(os.path.join(self.tmp_dir, "picked_connector"), "w", encoding="utf-8") as fh:
            fh.write("codex")
        with patch(
            "defenseclaw.commands.cmd_setup._detect_installed_connectors",
            return_value=[],
        ):
            result = self._invoke(["--skip-gateway", "--json-summary"])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "codex")
        self.assertEqual(
            summary["connector_source"],
            {
                "type": "picked_connector",
                "connector": "codex",
                "path": os.path.join(self.tmp_dir, "picked_connector"),
            },
        )

    def test_multiple_configured_connectors_error_even_with_picked_hint(self):
        with open(os.path.join(self.tmp_dir, "config.yaml"), "w", encoding="utf-8") as fh:
            fh.write(
                "config_version: 8\n"
                "observability: {}\n"
                "claw:\n"
                "  mode: codex\n"
                "guardrail:\n"
                "  enabled: true\n"
                "  connector: codex\n"
                "  mode: observe\n"
                "  connectors:\n"
                "    codex:\n"
                "      mode: observe\n"
                "    hermes:\n"
                "      mode: observe\n"
            )
        with open(os.path.join(self.tmp_dir, "picked_connector"), "w", encoding="utf-8") as fh:
            fh.write("codex")
        with patch(
            "defenseclaw.commands.cmd_setup._detect_installed_connectors",
            return_value=[],
        ):
            result = self._invoke(["--skip-gateway", "--json-summary"])
        self.assertNotEqual(result.exit_code, 0)
        output = result.output + (result.stderr or "")
        self.assertIn("Multiple connectors detected/configured", output)
        self.assertIn("codex, hermes", output)
        self.assertNotIn('"connector": "codex"', result.output)


if __name__ == "__main__":
    unittest.main()
