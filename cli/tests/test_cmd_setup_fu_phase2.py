#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""FU-SETUP Phase-2 tests: the interactive UX cluster + per-connector
guardrail write-surface for ``setup`` (cmd_setup.py only).

Covers:

* B3 / E4d — per-connector guardrail write-surface from the setup path
  (block-message / fail-mode / human-approval+hilt / judge), in addition
  to the mode + rule-pack that already landed per-connector.
* SU-06 — interactive observe/action prompt in the hook setup flow.
* SU-07 — interactive judge-enable prompt in the hook setup flow.
* SU-08 — the untrusted-binary-prefix remediation prompt now fires in
  observe mode too (previously action-mode only).
* SU-09 — one standard "connector not detected locally" message.
* SU-10 — hook setup commands expose the judge/HILT/block-message/fail-mode
  options (parity with the proxy factory) + a hook/proxy help epilog.
* SU-11 — bare ``setup`` is repurposed to an interactive multi-connector
  picker + scripting flags (``-c/--connector`` / ``--detected`` / ``--all``).
* ND-3 — ``setup mode`` help disambiguates connector-switch vs ``--mode``.
* J3 — opt-in per-direction detection-strategy flags on ``setup guardrail``
  (OFF by default).
"""

from __future__ import annotations

import contextlib
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands import cmd_setup
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.config import PerConnectorGuardrailConfig

from tests.helpers import cleanup_app, make_app_context


def _invoke(args, app, catch=False):
    runner = CliRunner()
    return runner.invoke(setup_group, args, obj=app, catch_exceptions=catch)


@contextlib.contextmanager
def _stub_side_effects():
    """Stub the heavyweight setup side effects so commands run in CI."""
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_services", return_value=None))
        stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True))
        stack.enter_context(patch("defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack", return_value=None))
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            )
        )
        yield


class _BaseSetup(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")
        # Lightweight save shim: tests assert on the in-memory config object.
        self.app.cfg.save = lambda: open(self.cfg_path, "w").write("x\n")  # type: ignore[assignment]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _seed_map(self, *connectors):
        gc = self.app.cfg.guardrail
        gc.connectors = {c: PerConnectorGuardrailConfig() for c in connectors}
        gc.connector = sorted(connectors)[0]
        self.app.cfg.claw.mode = sorted(connectors)[0]


# ---------------------------------------------------------------------------
# B3 / E4d — per-connector guardrail write-surface
# ---------------------------------------------------------------------------
class TestPerConnectorWriteSurface(_BaseSetup):
    def test_all_fields_land_per_connector_and_peer_untouched(self):
        self._seed_map("codex", "hermes")
        with _stub_side_effects():
            res = _invoke(
                [
                    "hermes", "--yes", "--no-restart", "--mode", "action",
                    "--block-message", "custom-hermes",
                    "--fail-mode", "closed",
                    "--human-approval", "--hilt-min-severity", "CRITICAL",
                    "--enable-judge",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        gc = self.app.cfg.guardrail
        h = gc.connectors["hermes"]
        self.assertEqual(h.mode, "action")
        self.assertEqual(h.block_message, "custom-hermes")
        self.assertEqual(h.hook_fail_mode, "closed")
        self.assertIsNotNone(h.hilt)
        self.assertTrue(h.hilt.enabled)
        self.assertEqual(h.hilt.min_severity, "CRITICAL")
        # Judge enablement is global + gated; strategy bumped off regex_only.
        self.assertTrue(gc.judge.enabled)
        self.assertNotEqual(gc.detection_strategy, "regex_only")
        self.assertTrue(gc.judge.hook_connectors == ["*"] or "hermes" in gc.judge.hook_connectors)
        # Peer left completely untouched (inherits global).
        codex = gc.connectors["codex"]
        self.assertEqual(codex.mode, "")
        self.assertEqual(codex.block_message, "")
        self.assertEqual(codex.hook_fail_mode, "")
        self.assertIsNone(codex.hilt)

    def test_sole_connector_writes_global_fields(self):
        # Clean config -> replace shape -> global fields (effective_* falls back).
        with _stub_side_effects():
            res = _invoke(
                ["codex", "--yes", "--no-restart", "--block-message", "g", "--fail-mode", "closed"],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.connectors, {})
        self.assertEqual(gc.block_message, "g")
        self.assertEqual(gc.hook_fail_mode, "closed")

    def test_setup_guardrail_connector_flag_writes_existing_override_fields(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.mode = "observe"
        gc.block_message = ""
        with _stub_side_effects():
            res = _invoke(
                [
                    "guardrail",
                    "--non-interactive",
                    "--no-restart",
                    "--no-verify",
                    "--connector",
                    "codex",
                    "--mode",
                    "action",
                    "--block-message",
                    "codex-only",
                    "--human-approval",
                    "--hilt-min-severity",
                    "CRITICAL",
                    "--rule-pack",
                    "strict",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(gc.mode, "observe")
        self.assertEqual(gc.block_message, "")
        self.assertFalse(gc.hilt.enabled)

        codex = gc.connectors["codex"]
        hermes = gc.connectors["hermes"]
        self.assertEqual(codex.mode, "action")
        self.assertEqual(codex.block_message, "codex-only")
        self.assertTrue(codex.rule_pack_dir.endswith(os.path.join("policies", "guardrail", "strict")))
        self.assertIsNotNone(codex.hilt)
        self.assertTrue(codex.hilt.enabled)
        self.assertEqual(codex.hilt.min_severity, "CRITICAL")
        self.assertEqual(hermes.mode, "")
        self.assertEqual(hermes.block_message, "")
        self.assertEqual(hermes.rule_pack_dir, "")
        self.assertIsNone(hermes.hilt)

    def test_omitting_flags_preserves_existing(self):
        # SU-02/J1 preserve-don't-clobber: a re-run without flags keeps judge.
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["*"]
        gc.detection_strategy = "regex_judge"
        gc.connectors["hermes"].block_message = "keep-me"
        with _stub_side_effects():
            res = _invoke(["hermes", "--yes", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.connectors["hermes"].block_message, "keep-me")

    def test_no_enable_judge_opts_connector_out_of_concrete_gate(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["codex", "hermes"]
        with _stub_side_effects():
            res = _invoke(["hermes", "--yes", "--no-restart", "--no-enable-judge"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertNotIn("hermes", gc.judge.hook_connectors)
        self.assertIn("codex", gc.judge.hook_connectors)


# ---------------------------------------------------------------------------
# SU-06 / SU-07 — interactive mode + judge prompts
# ---------------------------------------------------------------------------
class TestInteractiveModeJudgePrompts(_BaseSetup):
    def test_mode_prompt_selects_action(self):
        # Clean config, interactive: "Configure now?" + judge confirms -> True,
        # mode prompt -> "2" (action).
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=True), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="2"):
            res = _invoke(["codex", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        # Sole connector (replace shape) -> global mode.
        self.assertEqual(self.app.cfg.guardrail.mode, "action")

    def test_judge_prompt_enables_judge(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=True), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="1"):
            res = _invoke(["codex", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(self.app.cfg.guardrail.judge.enabled)

    def test_non_interactive_does_not_prompt(self):
        # --yes path: no prompts fire (would error on EOF if they did).
        with _stub_side_effects():
            res = _invoke(["codex", "--yes", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        # Default observe, judge untouched (off).
        self.assertEqual(self.app.cfg.guardrail.mode, "observe")
        self.assertFalse(self.app.cfg.guardrail.judge.enabled)


# ---------------------------------------------------------------------------
# SU-08 — trusted-prefix prompt in observe mode
# ---------------------------------------------------------------------------
class TestTrustedPrefixObservePrompt(unittest.TestCase):
    def _run(self, mode):
        signal = SimpleNamespace(
            version="",
            installed=True,
            error=cmd_setup.agent_discovery.UNTRUSTED_PREFIX_ERROR,
            binary_path="/tmp/fake/hermes-bin",
        )
        disc = SimpleNamespace(agents={"hermes": signal})
        contract = SimpleNamespace(status=cmd_setup.STATUS_UNVERSIONED, contract=None, reason="unversioned")
        with patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_setup, "resolve_connector_contract", return_value=contract), \
                patch.object(cmd_setup.sys.stdin, "isatty", return_value=True), \
                patch.object(cmd_setup.sys.stdout, "isatty", return_value=True), \
                patch.object(cmd_setup, "_add_trusted_bin_prefix", return_value=True) as add_mock, \
                patch.object(cmd_setup.click, "confirm", return_value=True) as confirm_mock:
            ok = cmd_setup._check_connector_version_supported_for_setup("hermes", mode=mode)
        return ok, add_mock, confirm_mock

    def test_observe_mode_offers_trusted_prefix_prompt(self):
        ok, add_mock, confirm_mock = self._run("observe")
        # Observe continues regardless, and the prompt fired (the SU-08 fix).
        self.assertTrue(ok)
        self.assertTrue(confirm_mock.called)
        self.assertTrue(add_mock.called)

    def test_action_mode_still_offers_prompt(self):
        _ok, add_mock, confirm_mock = self._run("action")
        self.assertTrue(confirm_mock.called)
        self.assertTrue(add_mock.called)


# ---------------------------------------------------------------------------
# SU-09 — single standard not-detected message
# ---------------------------------------------------------------------------
class TestNotDetectedMessage(unittest.TestCase):
    def test_helper_is_single_source(self):
        msg = cmd_setup._connector_not_detected_message("Hermes")
        self.assertIn("not detected locally", msg)
        self.assertIn("Hermes", msg)

    def test_check_emits_helper_message_when_not_installed(self):
        signal = SimpleNamespace(version="", installed=False, error="", binary_path="")
        disc = SimpleNamespace(agents={"hermes": signal})
        contract = SimpleNamespace(status=cmd_setup.STATUS_UNVERSIONED, contract=None, reason="")
        captured = []
        with patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_setup, "resolve_connector_contract", return_value=contract), \
                patch.object(cmd_setup.ux, "warn", side_effect=lambda m: captured.append(m)):
            ok = cmd_setup._check_connector_version_supported_for_setup("hermes", mode="observe")
        self.assertTrue(ok)
        self.assertIn(cmd_setup._connector_not_detected_message("Hermes"), captured)


# ---------------------------------------------------------------------------
# SU-10 — option parity / help epilog
# ---------------------------------------------------------------------------
class TestHelpParity(unittest.TestCase):
    def _help(self, args):
        return CliRunner().invoke(setup_group, args, catch_exceptions=False).output

    def test_codex_help_exposes_judge_hilt_block_fail_options(self):
        out = self._help(["codex", "--help"])
        for opt in ("--enable-judge", "--judge-hook-connectors", "--human-approval", "--hilt-min-severity", "--block-message", "--fail-mode"):
            self.assertIn(opt, out, msg=f"{opt} missing from `setup codex --help`")

    def test_factory_connector_help_exposes_options(self):
        out = self._help(["hermes", "--help"])
        self.assertIn("--enable-judge", out)
        self.assertIn("--block-message", out)

    def test_help_epilog_mentions_proxy_distinction(self):
        out = self._help(["codex", "--help"])
        self.assertIn("proxy", out.lower())


# ---------------------------------------------------------------------------
# SU-11 — bare `setup` picker + scripting flags
# ---------------------------------------------------------------------------
class TestBareSetupBatch(_BaseSetup):
    def test_scripting_flags_configure_multiple(self):
        with _stub_side_effects():
            res = _invoke(["-c", "hermes", "-c", "codex", "--mode", "action", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(set(gc.connectors), {"hermes", "codex"})
        self.assertEqual(gc.connectors["hermes"].mode, "action")

    def test_detected_filters_to_hook_connectors(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._detect_installed_connectors", return_value=["hermes", "openclaw"]):
            res = _invoke(["--detected", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(set(self.app.cfg.guardrail.connectors), {"hermes"})

    def test_all_selects_every_hook_connector(self):
        with _stub_side_effects():
            res = _invoke(["--all", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(set(self.app.cfg.guardrail.connectors), set(cmd_setup._HOOK_ENFORCED_CONNECTORS))

    def test_invalid_connector_flag_errors(self):
        with _stub_side_effects():
            res = _invoke(["-c", "not-a-real-connector", "--no-restart"], self.app, catch=True)
        self.assertNotEqual(res.exit_code, 0)

    def test_bare_non_tty_prints_help(self):
        with _stub_side_effects(), patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=False):
            res = _invoke([], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertIn("Configure DefenseClaw components", res.output)
        self.assertEqual(self.app.cfg.guardrail.connectors, {})

    def test_picker_applies_selection(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch("defenseclaw.commands.cmd_setup._detect_installed_connectors", return_value=["hermes"]), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="2"), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=False):
            res = _invoke(["--yes"], self.app)
        # --yes => no per-connector prompts; picker prompt (click.prompt) picks
        # candidate #2. The exact connector depends on sorted order; just assert
        # exactly one connector was configured from the picker.
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(len(self.app.cfg.guardrail.connectors), 1)

    def test_flags_ignored_with_subcommand_warns(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._apply_connector_mode_switch", return_value=True):
            res = _invoke(["-c", "hermes", "mode", "codex", "--no-restart"], self.app)
        self.assertIn("are ignored when a setup", res.output)


# ---------------------------------------------------------------------------
# ND-3 — setup mode help disambiguation
# ---------------------------------------------------------------------------
class TestSetupModeHelp(unittest.TestCase):
    def test_mode_help_disambiguates(self):
        out = CliRunner().invoke(setup_group, ["mode", "--help"], catch_exceptions=False).output
        # Mentions both senses of "mode" to disambiguate.
        self.assertIn("--mode observe|action", out)
        self.assertIn("active", out.lower())


# ---------------------------------------------------------------------------
# J3 — per-direction detection-strategy flags (opt-in, off by default)
# ---------------------------------------------------------------------------
class TestJ3PerDirectionStrategy(_BaseSetup):
    def test_help_exposes_per_direction_flags(self):
        out = CliRunner().invoke(setup_group, ["guardrail", "--help"], catch_exceptions=False).output
        for opt in ("--detection-strategy-prompt", "--detection-strategy-completion", "--detection-strategy-tool-call"):
            self.assertIn(opt, out)

    def test_completion_flag_writes_field(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
            res = _invoke(
                [
                    "guardrail", "--non-interactive", "--connector", "codex", "--no-restart", "--no-verify",
                    "--detection-strategy-completion", "regex_judge",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(self.app.cfg.guardrail.detection_strategy_completion, "regex_judge")

    def test_off_by_default_tool_call_unset(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
            res = _invoke(
                ["guardrail", "--non-interactive", "--connector", "codex", "--no-restart", "--no-verify"],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        # Never written unless the operator opts in.
        self.assertEqual(self.app.cfg.guardrail.detection_strategy_tool_call, "")


if __name__ == "__main__":
    unittest.main()
