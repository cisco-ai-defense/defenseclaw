# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""First run does not write a connector whose version has no hook contract (GAP-0554).

`init` downgraded such an action connector to observe and did not check
observe selections at all. Setup refuses that version in observe mode too,
and the gateway refuses it at start and stays down for every connector.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

import yaml
from click.testing import CliRunner
from defenseclaw.commands.cmd_init import init_cmd
from defenseclaw.connector_paths import KNOWN_CONNECTORS
from defenseclaw.context import AppContext
from defenseclaw.inventory.agent_discovery import AgentDiscovery, AgentSignal

NO_CONTRACT_CLAUDE = "2.1.100 (Claude Code)"
SUPPORTED_CODEX = "codex-cli 0.200.0"
NO_DRIFT = {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": ""}


class FirstRunNoContractGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = os.path.realpath(tempfile.mkdtemp(prefix="dclaw-init-no-contract-"))
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)
        selection = patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            return_value=({name: object() for name in ("amp", "claudecode", "codex", "hermes", "opencode")}, {}),
        )
        selection.start()
        self.addCleanup(selection.stop)
        # Native Windows binds those records to its protected receipt, in the
        # first-run preflight and again in setup. The stand-in records above
        # are no real selection, so both run as on the other hosts here; the
        # receipt has its own Windows tests (test_guardrail patches setup's).
        for target, value in (
            ("defenseclaw.bootstrap._preflight_first_run_agent_selections", (None, "")),
            ("defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections", None),
        ):
            windows_selection = patch(target, return_value=value)
            windows_selection.start()
            self.addCleanup(windows_selection.stop)
        # Setup's own gate is covered by test_setup_hook_contract_gate; here it
        # accepts, so only the first-run gate can keep the connector out.
        gate = patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True)
        gate.start()
        self.addCleanup(gate.stop)

    def _disc(self, versions: dict[str, str]) -> AgentDiscovery:
        return AgentDiscovery(
            scanned_at="2026-10-22T00:00:00Z",
            cache_hit=False,
            agents={
                name: AgentSignal(
                    name=name,
                    installed=name in versions,
                    config_path=f"/tmp/{name}.cfg" if name in versions else "",
                    binary_path=f"/usr/local/bin/{name}" if name in versions else "",
                    version=versions.get(name, ""),
                    error="",
                )
                for name in KNOWN_CONNECTORS
            },
        )

    def _invoke(self, versions: dict[str, str], args: list[str], env: dict[str, str] | None = None):
        full_env = {"DEFENSECLAW_HOME": self.tmp_dir, **NO_DRIFT, **(env or {})}
        with (
            patch.dict(os.environ, full_env),
            patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents", return_value=self._disc(versions)),
        ):
            return CliRunner().invoke(
                init_cmd,
                [
                    "--non-interactive",
                    "--yes",
                    *args,
                    "--scanner-mode",
                    "local",
                    "--skip-install",
                    "--no-start-gateway",
                    "--no-verify",
                    "--json-summary",
                ],
                obj=AppContext(),
                env=full_env,
            )

    def _cfg(self) -> dict:
        path = os.path.join(self.tmp_dir, "config.yaml")
        if not os.path.exists(path):
            return {}
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    def _configured(self) -> set[str]:
        guardrail = self._cfg().get("guardrail") or {}
        return set(guardrail.get("connectors") or {}) | {guardrail.get("connector") or ""} - {""}

    def test_a_lone_connector_with_no_contract_is_refused_in_both_modes(self):
        for profile in ("observe", "action"):
            with self.subTest(profile=profile):
                result = self._invoke(
                    {"claudecode": NO_CONTRACT_CLAUDE},
                    ["--connector", "claudecode", "--profile", profile],
                )
                summary = json.loads(result.output)
                self.assertEqual(summary["status"], "needs_attention", result.output)
                step = next(s for s in summary["setup"] if s["name"] == "Hook contract")
                self.assertEqual(step["status"], "fail")
                self.assertIn(
                    "installed version 2.1.100 (Claude Code) is not covered by a known hook contract", step["detail"]
                )
                self.assertIn("Setup refuses it in observe and action mode", step["detail"])
                self.assertIn("Then run: defenseclaw init.", step["detail"])
                self.assertEqual(summary["next_commands"], ["defenseclaw init"])
                self.assertIn("Nothing was changed.", step["detail"])
                self.assertNotIn("connector_mode_warnings", summary)
                self.assertNotIn("claudecode", self._configured())

    def test_a_no_contract_connector_is_left_out_of_a_multi_connector_run(self):
        # Selected in action (was downgraded to observe) and selected in
        # observe (was not checked at all).
        for args in (
            ["--observe-all", "--action-connectors", "claudecode"],
            ["--observe-all"],
        ):
            with self.subTest(args=args):
                result = self._invoke({"codex": SUPPORTED_CODEX, "claudecode": NO_CONTRACT_CLAUDE}, args)
                summary = json.loads(result.output)
                self.assertNotIn("connector_mode_warnings", summary)
                step = next(s for s in summary["setup"] if s["name"] == "Hook contract")
                self.assertEqual(step["status"], "warn")
                self.assertIn("left out claudecode:", step["detail"])
                configured = self._configured()
                self.assertIn("codex", configured)
                self.assertNotIn("claudecode", configured)

    def test_an_unverified_version_still_downgrades_to_observe(self):
        # Only a version with no contract is left out; an unprobed one keeps
        # the observe downgrade setup and the gateway accept.
        with patch(
            "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
            side_effect=lambda _c, mode="observe", **_kw: mode != "action",
        ):
            result = self._invoke(
                {"codex": SUPPORTED_CODEX, "claudecode": ""}, ["--observe-all", "--action-connectors", "claudecode"]
            )
        summary = json.loads(result.output)
        self.assertEqual(summary["connector_mode_warnings"][0]["connector"], "claudecode")
        self.assertEqual(summary["connector_mode_warnings"][0]["actual_mode"], "observe")
        self.assertIn("claudecode", self._configured())

    def test_the_drift_override_still_lets_first_run_continue(self):
        result = self._invoke(
            {"claudecode": NO_CONTRACT_CLAUDE},
            ["--connector", "claudecode", "--profile", "observe"],
            env={"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "1"},
        )
        summary = json.loads(result.output)
        self.assertFalse(any(s["name"] == "Hook contract" for s in summary["setup"]), result.output)
        self.assertIn("claudecode", self._configured())

    def test_the_first_run_backend_refuses_before_writing_config(self):
        # quickstart and the TUI call run_first_run directly.
        from defenseclaw.bootstrap import FirstRunOptions, run_first_run

        for profile in ("observe", "action"):
            with (
                self.subTest(profile=profile),
                patch.dict(os.environ, {"DEFENSECLAW_HOME": self.tmp_dir, **NO_DRIFT}),
                patch(
                    "defenseclaw.inventory.agent_discovery.discover_agents",
                    return_value=self._disc({"claudecode": NO_CONTRACT_CLAUDE}),
                ),
                patch("defenseclaw.bootstrap._quiet_guardrail_setup") as guardrail_setup,
            ):
                report = run_first_run(
                    FirstRunOptions(
                        connector="claudecode",
                        profile=profile,
                        skip_install=True,
                        start_gateway=False,
                        verify=False,
                    )
                )
                self.assertEqual(report.status, "needs_attention")
                self.assertEqual([s.name for s in report.setup if s.status == "fail"], ["Hook contract"])
                guardrail_setup.assert_not_called()
                self.assertFalse(os.path.exists(os.path.join(self.tmp_dir, "config.yaml")))


if __name__ == "__main__":
    unittest.main()
