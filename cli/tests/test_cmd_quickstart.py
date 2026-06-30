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

from click.testing import CliRunner
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

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _invoke(self, args):
        return self.runner.invoke(
            quickstart_cmd,
            args,
            env={
                "DEFENSECLAW_HOME": self.tmp_dir,
                "HOME": self.home_dir,
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
        result = self._invoke([
            "--connector",
            "codex",
            "--skip-gateway",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "codex")
        self.assertEqual(summary["profile"], "observe")

    def test_openclaw_defaults_to_observe_profile(self):
        result = self._invoke([
            "--connector",
            "openclaw",
            "--skip-gateway",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "openclaw")
        self.assertEqual(summary["profile"], "observe")

    def test_explicit_mode_overrides_connector_default(self):
        result = self._invoke([
            "--connector",
            "codex",
            "--mode",
            "observe",
            "--skip-gateway",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["profile"], "observe")

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True)
    def test_explicit_action_updates_existing_per_connector_mode(self, _gate):
        with open(os.path.join(self.tmp_dir, "config.yaml"), "w", encoding="utf-8") as fh:
            fh.write(
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

        result = self._invoke([
            "--connector",
            "hermes",
            "--mode",
            "action",
            "--skip-gateway",
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

    @patch("defenseclaw.bootstrap.agent_discovery.discover_agents")
    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=False)
    def test_action_mode_trusted_path_downgrade_is_structured(self, _gate, mock_discover):
        disc = self._discovery({"hermes"})
        disc.agents["hermes"].binary_path = "/tmp/fake/hermes-bin"
        disc.agents["hermes"].error = agent_discovery.UNTRUSTED_PREFIX_ERROR
        mock_discover.return_value = disc

        result = self._invoke([
            "--connector",
            "hermes",
            "--mode",
            "action",
            "--skip-gateway",
            "--json-summary",
        ])
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
        self.assertEqual(cfg["guardrail"]["mode"], "observe")

    def test_help_lists_fail_mode_flag(self):
        # Quickstart is the headless path most likely to be wired
        # into installers and CI. If --fail-mode disappears from
        # help, scripts that opt into fail-closed silently regress.
        result = self.runner.invoke(quickstart_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--fail-mode", result.output)

    def test_fail_mode_closed_persists_to_config(self):
        result = self._invoke([
            "--connector",
            "codex",
            "--skip-gateway",
            "--fail-mode",
            "closed",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["guardrail"]["hook_fail_mode"], "closed")

    def test_omitting_fail_mode_resolves_to_closed(self):
        # Closes when the operator omits ``--fail-mode``
        # at quickstart, the resulting config must default to the safer
        # "closed" sentinel so response-layer failures (4xx, malformed
        # JSON, missing action) BLOCK the tool/prompt rather than
        # silently allowing it. Existing v3 installs are protected by
        # _migrate_0_4_0_seed_hook_fail_mode (migrations.py), so this
        # behavior change is new-install-only.
        result = self._invoke([
            "--connector",
            "codex",
            "--skip-gateway",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        from defenseclaw.config import _normalize_hook_fail_mode
        raw = cfg["guardrail"].get("hook_fail_mode", "")
        self.assertEqual(_normalize_hook_fail_mode(raw), "closed")

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
