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
* ND-3 — legacy ``setup mode`` is removed; use ``setup <connector> --mode``.
* J3 — opt-in per-direction detection-strategy flags on ``setup guardrail``
  (OFF by default).
"""

from __future__ import annotations

import contextlib
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

pytestmark = pytest.mark.supported_connector_host
from defenseclaw.commands import cmd_setup
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.config import PerConnectorGuardrailConfig
from defenseclaw.logger import CanonicalObservabilityUnavailableError

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
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")
        self.assertEqual(gc.judge.hook_connectors, ["hermes"])
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

    def test_setup_guardrail_unscoped_mode_updates_all_active_overrides(self):
        self._seed_map("claudecode", "hermes", "opencode", "openhands")
        gc = self.app.cfg.guardrail
        gc.mode = "action"
        for connector in gc.connectors:
            gc.connectors[connector].mode = "action"

        with _stub_side_effects():
            res = _invoke(
                [
                    "guardrail",
                    "--yes",
                    "--no-restart",
                    "--no-verify",
                    "--mode",
                    "observe",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(gc.mode, "observe")
        for connector in ("claudecode", "hermes", "opencode", "openhands"):
            self.assertEqual(gc.connectors[connector].mode, "observe")
            self.assertEqual(gc.effective_mode(connector), "observe")

    def test_setup_guardrail_unscoped_block_message_updates_all_active_overrides(self):
        self._seed_map("geminicli", "hermes")
        gc = self.app.cfg.guardrail
        gc.block_message = "Global block"
        gc.connectors["geminicli"].block_message = "Gemini scoped block"

        with _stub_side_effects():
            res = _invoke(
                [
                    "guardrail",
                    "--yes",
                    "--no-restart",
                    "--no-verify",
                    "--block-message",
                    "Global block 2",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(gc.block_message, "Global block 2")
        for connector in ("geminicli", "hermes"):
            self.assertEqual(gc.connectors[connector].block_message, "Global block 2")
            self.assertEqual(gc.effective_block_message(connector), "Global block 2")

    def test_setup_guardrail_unscoped_without_mode_preserves_active_overrides(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.mode = "observe"
        gc.connectors["codex"].mode = "action"
        gc.connectors["hermes"].mode = "observe"

        with _stub_side_effects():
            res = _invoke(
                ["guardrail", "--yes", "--no-restart", "--no-verify"],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(gc.connectors["codex"].mode, "action")
        self.assertEqual(gc.connectors["hermes"].mode, "observe")

    def test_omitting_judge_flags_preserves_existing_action_judge(self):
        # SU-02/J1 preserve-don't-clobber: an action-mode re-run without judge
        # flags keeps the connector's existing judge selection.
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["*"]
        gc.detection_strategy = "regex_judge"
        gc.connectors["hermes"].block_message = "keep-me"
        with _stub_side_effects():
            res = _invoke(["hermes", "--yes", "--no-restart", "--mode", "action"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.connectors["hermes"].block_message, "keep-me")

    def test_enable_judge_adds_connector_to_existing_narrow_gate(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["codex"]
        gc.detection_strategy = "regex_judge"
        with _stub_side_effects():
            res = _invoke(
                ["hermes", "--yes", "--no-restart", "--mode", "action", "--enable-judge"],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, ["codex", "hermes"])

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

    def test_direct_action_missing_connector_falls_back_to_observe(self):
        signal = SimpleNamespace(version="", installed=False, error="", binary_path="")
        disc = SimpleNamespace(agents={"copilot": signal})
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["copilot"]
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"
        saved_judge_states: list[tuple[bool, list[str], str]] = []

        def capture_save():
            saved_judge_states.append(
                (
                    bool(gc.judge.enabled),
                    list(gc.judge.hook_connectors or []),
                    gc.detection_strategy,
                )
            )

        self.app.cfg.save = capture_save  # type: ignore[assignment]

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_services", return_value=None))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack", return_value=None))
            stack.enter_context(
                patch("defenseclaw.commands.cmd_setup.agent_discovery.discover_agents", return_value=disc)
            )
            res = _invoke(
                ["copilot", "--yes", "--no-restart", "--mode", "action"],
                self.app,
            )

        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertIn("GitHub Copilot CLI: connector was not detected locally", res.output)
        self.assertIn("GitHub Copilot CLI: requested action mode was refused", res.output)
        self.assertEqual(self.app.cfg.guardrail.connector, "copilot")
        self.assertEqual(self.app.cfg.guardrail.mode, "observe")
        self.assertEqual(saved_judge_states[-1], (False, [], "regex_only"))
        self.assertFalse(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, [])

    def test_guardrail_action_fallback_prunes_only_refused_connector_from_judge(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.connectors["codex"].mode = "action"
        gc.connectors["hermes"].mode = "action"
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["codex", "hermes"]
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        def version_gate(connector, **_kwargs):
            return connector != "hermes"

        with patch(
            "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
            side_effect=version_gate,
        ):
            ok = cmd_setup._check_guardrail_setup_connector_versions(
                self.app,
                gc,
                explicit_connector=None,
                allow_prompt=False,
            )

        self.assertTrue(ok)
        self.assertEqual(gc.effective_mode("codex"), "action")
        self.assertEqual(gc.effective_mode("hermes"), "observe")
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, ["codex"])


# ---------------------------------------------------------------------------
# SU-06 / SU-07 — interactive mode + judge prompts
# ---------------------------------------------------------------------------
class TestInteractiveModeJudgePrompts(_BaseSetup):
    def test_guardrail_multi_selectors_stay_key_driven_without_vt(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.mode = "observe"
        for connector in gc.connectors.values():
            connector.mode = "observe"

        # Action picker: Windows Down, Space, Enter selects Hermes.
        # Judge picker: Enter accepts the empty default.
        keys = iter(["\xe0P", " ", "\r", "\r"])
        confirms = iter([True, False])  # enable guardrail, advanced options
        emitted: list[str] = []

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._supports_terminal_redraw", return_value=False), \
                patch("defenseclaw.commands.cmd_setup.click.getchar", side_effect=lambda: next(keys)), \
                patch("defenseclaw.commands.cmd_setup.click.echo", side_effect=lambda text="", **_kwargs: emitted.append(text)), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=lambda *a, **k: next(confirms)), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="1"), \
                patch("defenseclaw.commands.cmd_setup._prompt_hook_fail_mode", return_value=None), \
                patch("defenseclaw.commands.cmd_setup._configure_hilt_interactive", return_value=None), \
                patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config") as model_prompt:
            cmd_setup._interactive_guardrail_setup(self.app, gc)

        self.assertEqual(gc.connectors["codex"].mode, "observe")
        self.assertEqual(gc.connectors["hermes"].mode, "action")
        self.assertFalse(gc.judge.enabled)
        self.assertNotIn("comma-separated", "".join(emitted))
        self.assertTrue(any("Current 2/2: [x] Hermes" in line for line in emitted))
        model_prompt.assert_not_called()

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
        confirms = iter([True, True, True])
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=lambda *a, **k: next(confirms)), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="2"), \
                patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config") as model_prompt:
            res = _invoke(["codex", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(self.app.cfg.guardrail.judge.enabled)
        self.assertEqual(self.app.cfg.guardrail.judge.hook_connectors, ["codex"])
        model_prompt.assert_called_once()

    def test_observe_mode_skips_judge_prompt_and_removes_connector_from_gate(self):
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["codex"]
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        confirms = iter([True])
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=lambda *a, **k: next(confirms)), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="1"), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_enable_judge",
                    side_effect=AssertionError("observe mode should not ask for judge"),
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_judge_model_config",
                    side_effect=AssertionError("observe mode should not configure judge model"),
                ):
            res = _invoke(["codex", "--no-restart"], self.app)

        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertFalse(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, [])
        self.assertEqual(gc.detection_strategy, "regex_only")

    def test_scoped_guardrail_setup_preserves_unscoped_judge_gate(self):
        targets = ["antigravity", "claudecode", "hermes", "openhands"]
        self._seed_map(*targets)
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.mode = "observe"
        for connector in targets:
            gc.connectors[connector].mode = "observe"
        gc.judge.enabled = True
        gc.judge.hook_connectors = list(targets)
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        confirms = iter([True, False])

        def confirm(*_args, **kwargs):
            try:
                return next(confirms)
            except StopIteration:
                return kwargs.get("default", False)

        def accept_defaults(_options, *, default_selected=None, **_kwargs):
            return list(default_selected or [])

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=confirm), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="1"), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "action"},
                ), \
                patch("defenseclaw.commands.cmd_setup._prompt_hook_fail_mode", return_value=None), \
                patch("defenseclaw.commands.cmd_setup._configure_hilt_interactive", return_value=None), \
                patch("defenseclaw.commands.cmd_setup._prompt_checkbox_selection", side_effect=accept_defaults), \
                patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config") as model_prompt, \
                patch("defenseclaw.commands.cmd_setup._print_connector_info", return_value=None):
            cmd_setup._interactive_guardrail_setup(self.app, gc, agent_name="hermes")

        self.assertEqual(gc.connectors["hermes"].mode, "action")
        self.assertEqual(gc.connectors["antigravity"].mode, "observe")
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, sorted(targets))
        model_prompt.assert_called_once()

    def test_multi_guardrail_setup_action_defaults_ignore_stale_global_mode(self):
        targets = ["antigravity", "claudecode", "geminicli", "hermes", "opencode", "openhands", "windsurf"]
        self._seed_map(*targets)
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.mode = "action"
        for connector in targets:
            gc.connectors[connector].mode = "observe"
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["antigravity", "claudecode", "hermes", "openhands"]
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        default_selections: list[list[str]] = []
        confirms = iter([True, False, False])

        def confirm(*_args, **kwargs):
            try:
                return next(confirms)
            except StopIteration:
                return kwargs.get("default", False)

        def checkbox(_options, *, default_selected=None, title="", **_kwargs):
            if title == "Select connector(s) for action enforcement.":
                default_selections.append(list(default_selected or []))
                return []
            return list(default_selected or [])

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=confirm), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="1"), \
                patch("defenseclaw.commands.cmd_setup._prompt_checkbox_selection", side_effect=checkbox), \
                patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config", return_value=None), \
                patch("defenseclaw.commands.cmd_setup._print_connector_info", return_value=None):
            cmd_setup._interactive_guardrail_setup(self.app, gc)

        self.assertEqual(default_selections, [[]])
        for connector in targets:
            self.assertEqual(gc.connectors[connector].mode, "observe")
            self.assertEqual(gc.effective_mode(connector), "observe")
        self.assertFalse(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, [])
        self.assertEqual(gc.detection_strategy, "regex_only")

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

    def test_noninteractive_observe_suppresses_prompt_but_emits_remediation(self):
        signal = SimpleNamespace(
            version="",
            installed=True,
            error=cmd_setup.agent_discovery.UNTRUSTED_PREFIX_ERROR,
            binary_path="/tmp/fake/hermes-bin",
        )
        disc = SimpleNamespace(agents={"hermes": signal})
        contract = SimpleNamespace(status=cmd_setup.STATUS_UNVERSIONED, contract=None, reason="unversioned")
        hints = []
        with patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_setup, "resolve_connector_contract", return_value=contract), \
                patch.object(cmd_setup.sys.stdin, "isatty", return_value=True), \
                patch.object(cmd_setup.sys.stdout, "isatty", return_value=True), \
                patch.object(cmd_setup, "_add_trusted_bin_prefix", return_value=True) as add_mock, \
                patch.object(cmd_setup.click, "confirm", side_effect=AssertionError("prompted")), \
                patch.object(cmd_setup.ux, "subhead", side_effect=lambda message: hints.append(message)):
            ok = cmd_setup._check_connector_version_supported_for_setup(
                "hermes",
                mode="observe",
                _allow_prompt=False,
            )
        self.assertTrue(ok)
        add_mock.assert_not_called()
        self.assertIn("trusted-paths add", " ".join(hints))


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

    def test_check_refuses_action_when_not_installed(self):
        signal = SimpleNamespace(version="", installed=False, error="", binary_path="")
        disc = SimpleNamespace(agents={"hermes": signal})
        captured = []
        with patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_setup.ux, "err", side_effect=lambda m: captured.append(m)):
            ok = cmd_setup._check_connector_version_supported_for_setup("hermes", mode="action")
        self.assertFalse(ok)
        self.assertIn(
            "Hermes: connector was not detected locally; refusing action-mode hook setup.",
            captured,
        )

    def test_contract_drift_override_allows_action_when_not_installed(self):
        signal = SimpleNamespace(version="", installed=False, error="", binary_path="")
        disc = SimpleNamespace(agents={"hermes": signal})
        contract = SimpleNamespace(status=cmd_setup.STATUS_UNVERSIONED, contract=None, reason="")
        captured = []
        with patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "1"}), \
                patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_setup, "resolve_connector_contract", return_value=contract), \
                patch.object(cmd_setup.ux, "warn", side_effect=lambda m: captured.append(m)):
            ok = cmd_setup._check_connector_version_supported_for_setup("hermes", mode="action")
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
    def test_detected_connectors_require_installed_application_signal(self):
        disc = SimpleNamespace(
            agents={
                "hermes": SimpleNamespace(installed=False, configured=True),
                "cursor": SimpleNamespace(installed=True, configured=False),
            }
        )
        with patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc) as discover:
            detected = cmd_setup._detect_installed_connectors()

        self.assertEqual(detected, ["cursor"])
        discover.assert_called_once_with(use_cache=False)

    def test_scripting_flags_configure_multiple(self):
        with _stub_side_effects():
            res = _invoke(["-c", "hermes", "-c", "codex", "--mode", "action", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(set(gc.connectors), {"hermes", "codex"})
        self.assertEqual(gc.connectors["hermes"].mode, "action")

    def test_batch_no_restart_allows_explicit_offline_staging(self):
        self.app.logger = MagicMock()
        self.app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
        with _stub_side_effects():
            res = _invoke(["-c", "codex", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertIn("canonical setup audit event was not recorded", res.output)

    def test_batch_default_restart_does_not_inherit_internal_offline_mode(self):
        self.app.logger = MagicMock()
        self.app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
        with _stub_side_effects(), self.assertRaises(CanonicalObservabilityUnavailableError):
            _invoke(["-c", "codex"], self.app)

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
        expected = cmd_setup.platform_support.supported_connectors(
            cmd_setup._HOOK_ENFORCED_CONNECTORS
        )
        self.assertEqual(set(self.app.cfg.guardrail.connectors), set(expected))

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
                patch("defenseclaw.commands.cmd_setup._supports_terminal_redraw", return_value=False), \
                patch("defenseclaw.commands.cmd_setup.click.getchar", return_value="\n"):
            res = _invoke(["--yes"], self.app)
        # --yes => no mode/judge prompts, but bare setup still needs the
        # connector picker. Enter accepts the detected default selection.
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertNotIn("comma-separated", res.output)
        self.assertEqual(len(self.app.cfg.guardrail.connectors), 1)
        self.assertIn("hermes", self.app.cfg.guardrail.connectors)

    def test_picker_preselects_active_not_detected_inactive_connectors(self):
        self._seed_map("hermes", "windsurf")
        captured = {}

        def choose(options, *, default_selected, title, empty_ok):
            captured["options"] = options
            captured["default_selected"] = default_selected
            return default_selected

        with patch(
            "defenseclaw.commands.cmd_setup._detect_installed_connectors",
            return_value=["cursor"],
        ), patch(
            "defenseclaw.commands.cmd_setup._prompt_checkbox_selection",
            side_effect=choose,
        ), patch("defenseclaw.commands.cmd_setup.ux.subhead") as subhead:
            selected = cmd_setup._run_setup_picker(self.app)

        self.assertEqual(set(selected), {"hermes", "windsurf"})
        cursor_option = next(option for option in captured["options"] if "Cursor" in option)
        self.assertNotIn(cursor_option, captured["default_selected"])
        subhead.assert_any_call(
            "Active connectors are pre-selected. Detected inactive connectors remain unchecked."
        )

    def test_batch_prompts_trusted_prefix_before_judge_picker(self):
        signal = SimpleNamespace(
            version="",
            installed=True,
            error=cmd_setup.agent_discovery.UNTRUSTED_PREFIX_ERROR,
            binary_path="/tmp/fake/hermes-bin",
        )
        disc = SimpleNamespace(agents={"hermes": signal})

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "action"},
                ), \
                patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch("defenseclaw.commands.cmd_setup._add_trusted_bin_prefix") as add_mock, \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    side_effect=lambda targets, gc: self.assertTrue(add_mock.called) or set(),
                ):
            res = _invoke(["-c", "hermes", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        add_mock.assert_called_once()

    def test_batch_action_refusal_downgrades_saved_mode_to_observe(self):
        def version_gate(connector, *, mode="observe", **_kwargs):
            return (mode or "").strip().lower() != "action"

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_services", return_value=None))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack", return_value=None))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"geminicli": "action", "windsurf": "action"},
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes", return_value={}))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    return_value=set(),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                    side_effect=version_gate,
                )
            )
            res = _invoke(
                ["-c", "geminicli", "-c", "windsurf", "--no-restart"],
                self.app,
            )

        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertIn("Gemini CLI: requested action mode was refused", res.output)
        self.assertIn("Windsurf: requested action mode was refused", res.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.effective_mode("geminicli"), "observe")
        self.assertEqual(gc.effective_mode("windsurf"), "observe")
        self.assertEqual(gc.connectors["geminicli"].mode, "observe")
        self.assertEqual(gc.connectors["windsurf"].mode, "observe")

    def test_interactive_batch_selects_judge_connectors_without_strategy_prompt(self):
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["*"]

        def choose_codex(targets, gc_arg):
            self.assertEqual(targets, ["codex"])
            cmd_setup._merge_batch_judge_selection(gc_arg, targets, {"codex"})
            return {"codex"}

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "observe", "codex": "action"},
                ) as mode_picker, \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_scan_strategy",
                    side_effect=AssertionError("bare setup should not ask for scan strategy"),
                ), \
                patch("defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes", return_value={}), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    side_effect=choose_codex,
                ) as judge_picker, \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=False) as confirm_mock, \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_judge_model_config",
                    side_effect=AssertionError("model prompt should be skipped when declined"),
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_connector_mode",
                    side_effect=AssertionError("per-connector mode prompt should not run"),
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_enable_judge",
                    side_effect=AssertionError("per-connector judge prompt should not run"),
                ):
            res = _invoke(["-c", "hermes", "-c", "codex", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        mode_picker.assert_called_once()
        judge_picker.assert_called_once()
        confirm_mock.assert_called_once()
        self.assertEqual(gc.connectors["hermes"].mode, "observe")
        self.assertEqual(gc.connectors["codex"].mode, "action")
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")
        self.assertEqual(gc.judge.hook_connectors, ["codex"])

    def test_batch_judge_selection_drops_unselected_existing_connectors(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["*"]

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "observe"},
                ), \
                patch("defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes", return_value={}), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    side_effect=AssertionError("judge picker should be skipped without action connectors"),
                ) as judge_picker, \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=False):
            res = _invoke(["-c", "hermes", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        judge_picker.assert_not_called()
        self.assertEqual(gc.judge.hook_connectors, [])
        self.assertNotIn("codex", gc.judge.hook_connectors)

    def test_scoped_judge_selection_preserves_outside_existing_gate(self):
        targets = ["antigravity", "claudecode", "hermes", "openhands"]
        self._seed_map(*targets)
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = list(targets)
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        cmd_setup._merge_batch_judge_selection(
            gc,
            ["hermes"],
            {"hermes"},
            preserve_outside_targets=True,
        )

        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, sorted(targets))
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")

    def test_scoped_judge_selection_removes_only_unchecked_target(self):
        targets = ["antigravity", "claudecode", "hermes", "openhands"]
        self._seed_map(*targets)
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = list(targets)
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        cmd_setup._merge_batch_judge_selection(
            gc,
            ["hermes"],
            set(),
            preserve_outside_targets=True,
        )

        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, ["antigravity", "claudecode", "openhands"])
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")

    def test_scoped_judge_selection_preserves_wildcard_when_target_checked(self):
        self._seed_map("antigravity", "claudecode", "hermes", "openhands")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["*"]

        cmd_setup._merge_batch_judge_selection(
            gc,
            ["hermes"],
            {"hermes"},
            preserve_outside_targets=True,
        )

        self.assertEqual(gc.judge.hook_connectors, ["*"])

    def test_batch_setup_reconciles_active_connectors_to_selected_set(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["codex", "hermes"]

        with _stub_side_effects():
            res = _invoke(
                ["-c", "hermes", "--yes", "--no-restart", "--mode", "action"],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(sorted(gc.connectors), ["hermes"])
        self.assertEqual(gc.connector, "hermes")
        self.assertEqual(self.app.cfg.claw.mode, "hermes")
        self.assertEqual(gc.judge.hook_connectors, ["hermes"])

    def test_batch_setup_does_not_seed_unselected_legacy_single_connector(self):
        gc = self.app.cfg.guardrail
        gc.connector = "codex"
        self.app.cfg.claw.mode = "codex"
        gc.connectors = {}

        with _stub_side_effects():
            res = _invoke(["-c", "hermes", "--yes", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(sorted(gc.connectors), ["hermes"])
        self.assertNotIn("codex", gc.connectors)
        self.assertEqual(gc.connector, "hermes")

    def test_empty_batch_judge_selection_skips_model_and_uses_regex_only(self):
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["hermes"]

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "observe", "codex": "observe"},
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_scan_strategy",
                    side_effect=AssertionError("bare setup should not ask for scan strategy"),
                ), \
                patch("defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes", return_value={}), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    side_effect=AssertionError("judge picker should be skipped without action connectors"),
                ) as judge_picker, \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_judge_model_config",
                    side_effect=AssertionError("judge model prompt should not run with no judge connectors"),
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup.click.confirm",
                    side_effect=AssertionError("judge model confirm should not run with no judge connectors"),
                ):
            res = _invoke(["-c", "hermes", "-c", "codex", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        judge_picker.assert_not_called()
        self.assertFalse(gc.judge.enabled)
        self.assertEqual(gc.detection_strategy, "regex_only")
        self.assertEqual(gc.detection_strategy_completion, "regex_only")
        self.assertEqual(gc.judge.hook_connectors, [])

    def test_batch_judge_selection_can_configure_model(self):
        def choose_hermes(targets, gc_arg):
            cmd_setup._merge_batch_judge_selection(gc_arg, targets, {"hermes"})
            return {"hermes"}

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "action"},
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_scan_strategy",
                    side_effect=AssertionError("bare setup should not ask for scan strategy"),
                ), \
                patch("defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes", return_value={}), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    side_effect=choose_hermes,
                ), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=True) as confirm_mock, \
                patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config") as model_prompt:
            res = _invoke(["-c", "hermes", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        confirm_mock.assert_called_once()
        model_prompt.assert_called_once()
        self.assertTrue(self.app.cfg.guardrail.judge.enabled)
        self.assertEqual(self.app.cfg.guardrail.detection_strategy, "regex_judge")
        self.assertEqual(self.app.cfg.guardrail.detection_strategy_completion, "regex_judge")
        self.assertEqual(self.app.cfg.guardrail.judge.hook_connectors, ["hermes"])

    def test_flags_ignored_with_subcommand_warns(self):
        with _stub_side_effects(), patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=SimpleNamespace(destinations=(), retention_days=0, plan_digest="test"),
        ):
            res = _invoke(["-c", "hermes", "observability", "list"], self.app)
        self.assertIn("are ignored when a setup", res.output)


# ---------------------------------------------------------------------------
# ND-3 — setup mode removal
# ---------------------------------------------------------------------------
class TestSetupModeHelp(unittest.TestCase):
    def test_mode_subcommand_is_removed(self):
        res = CliRunner().invoke(setup_group, ["mode", "--help"])
        self.assertNotEqual(res.exit_code, 0)
        self.assertIn("No such command 'mode'", res.output)

    def test_setup_help_keeps_enforcement_mode_flag(self):
        out = CliRunner().invoke(setup_group, ["--help"], catch_exceptions=False).output
        self.assertIn("--mode [observe|action]", out)
        self.assertNotIn("setup mode", out)


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

    def test_judge_strategy_flag_enables_judge_with_all_hook_coverage(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
            res = _invoke(
                [
                    "guardrail", "--non-interactive", "--connector", "codex", "--no-restart", "--no-verify",
                    "--mode", "action",
                    "--detection-strategy", "regex_judge",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(self.app.cfg.guardrail.judge.enabled)
        self.assertEqual(self.app.cfg.guardrail.detection_strategy, "regex_judge")
        self.assertEqual(self.app.cfg.guardrail.detection_strategy_completion, "regex_judge")
        self.assertEqual(self.app.cfg.guardrail.judge.hook_connectors, ["*"])

    def test_scoped_mode_update_preserves_empty_judge_gate(self):
        self._seed_map("antigravity", "hermes", "opencode")
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.mode = "observe"
        gc.connectors["antigravity"].mode = "observe"
        gc.connectors["hermes"].mode = "action"
        gc.connectors["opencode"].mode = "action"
        gc.judge.enabled = True
        gc.judge.hook_connectors = []
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
            res = _invoke(
                [
                    "guardrail", "--non-interactive", "--connector", "hermes",
                    "--mode", "observe", "--no-restart", "--no-verify",
                ],
                self.app,
            )

        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(gc.effective_mode("antigravity"), "observe")
        self.assertEqual(gc.effective_mode("hermes"), "observe")
        self.assertEqual(gc.effective_mode("opencode"), "action")
        self.assertEqual(sorted(gc.connectors), ["antigravity", "hermes", "opencode"])
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, [])
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")

    def test_explicit_completion_regex_only_preserved_when_judge_enabled(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
            res = _invoke(
                [
                    "guardrail", "--non-interactive", "--connector", "codex", "--no-restart", "--no-verify",
                    "--mode", "action",
                    "--detection-strategy", "regex_judge",
                    "--detection-strategy-completion", "regex_only",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(self.app.cfg.guardrail.judge.enabled)
        self.assertEqual(self.app.cfg.guardrail.detection_strategy, "regex_judge")
        self.assertEqual(self.app.cfg.guardrail.detection_strategy_completion, "regex_only")
        self.assertEqual(self.app.cfg.guardrail.judge.hook_connectors, ["*"])

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
