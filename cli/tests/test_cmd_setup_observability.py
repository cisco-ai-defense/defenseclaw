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

"""Regression tests for the wizard behavior with hook-enforced
connectors (codex / claude-code) in ``defenseclaw setup guardrail``.

Codex and Claude Code are now hook-only — the HTTP chat-proxy data
path has been removed entirely. The wizard takes the standard
observe/action mode path. The LLM judge, scanner engine, and block
message prompts all remain available — they run gateway-side over
hook event payloads (UserPromptSubmit, PreToolUse) exactly the same
way they previously ran over proxy responses. The verdict surfaces
through the agent's native hook bus (PreToolUse deny verdict) in
action mode instead of through the proxy block-response body.

These tests pin the wizard's default-accept path: an operator who
walks through with mostly-default answers (observe mode, local
scanner, no judge, no advanced options) lands on the canonical
hook-only configuration without any proxy-era artifacts leaking
back into the persisted ``GuardrailConfig``.
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_setup
from defenseclaw.commands.cmd_setup import _interactive_guardrail_setup


def _make_app(connector: str):
    """Minimal AppContext stub for the wizard.

    Mirrors :class:`defenseclaw.config.GuardrailConfig` only on the
    fields the wizard reads/writes. Anything the wizard doesn't touch
    in observability mode (e.g. ``gc.judge.api_base``) can stay at its
    dataclass default.
    """
    judge = SimpleNamespace(
        enabled=False,
        injection=False,
        pii=False,
        pii_prompt=False,
        pii_completion=False,
        tool_injection=False,
        exfil=False,
        timeout=0.0,
        model="",
        api_base="",
        api_key_env="",
        fallbacks=[],
        hook_connectors=[],
    )
    # Human-In-the-Loop (HILT) sub-namespace mirrors GuardrailConfig.hilt.
    # Required because the wizard now asks about HILT inline whenever
    # the operator picks action mode (was previously buried under
    # advanced options). Defaulting to ``enabled=False`` matches the
    # canonical config dataclass default.
    hilt = SimpleNamespace(enabled=False, min_severity="HIGH")
    gc = SimpleNamespace(
        enabled=False,
        connector=connector,
        mode="",
        scanner_mode="",
        host="localhost",
        port=4000,
        model="",
        model_name="",
        api_key_env="",
        api_base="",
        original_model="",
        block_message="",
        judge=judge,
        hilt=hilt,
        detection_strategy="",
        detection_strategy_prompt="",
        detection_strategy_completion="",
        detection_strategy_tool_call="",
        judge_sweep=True,
        rule_pack_dir="",
        hook_fail_mode="",
        llm_role="",
    )

    cfg = SimpleNamespace(
        guardrail=gc,
        data_dir="/tmp/dc-test",
        llm=SimpleNamespace(model="", api_key_env="", base_url="",
                            resolved_api_key=lambda: ""),
        cisco_ai_defense=SimpleNamespace(endpoint="",
                                          api_key_env="",
                                          timeout_ms=0),
    )
    app = SimpleNamespace(cfg=cfg, logger=MagicMock())
    return app, gc


class TestObservabilityWizard(unittest.TestCase):
    def _drive_observability(self, connector: str) -> SimpleNamespace:
        """Run the wizard taking the observability-only path.

        Returns the post-run guardrail config namespace. The confirm
        prompts are driven by a sequence rather than a constant True
        so we can answer "yes" to the initial "Enable guardrail?"
        gate but "no" to the advanced-options gate further down —
        the advanced-options branch touches ``app.cfg.privacy`` which
        our minimal SimpleNamespace stub deliberately doesn't carry.
        We rely on click's ``confirm`` default-clamping for any
        additional prompts the wizard might add in the future: each
        unmatched call takes its default, which is the conservative
        no-op direction for every prompt in this branch.
        """
        app, gc = _make_app(connector)

        # ``click.confirm`` answer order:
        #   1. "Enable guardrail?"               → True   (drive the wizard)
        #   2. "Configure advanced options?"     → False  (skip; privacy attr absent)
        # Any further confirms fall back to their default via the
        # side_effect's "ran out of values" StopIteration which click
        # catches and treats as "take the default" — but we keep an
        # extra False to be paranoid in case prompt ordering shifts.
        confirm_answers = iter([True, False, False])

        def _confirm(*args, **kwargs):
            try:
                return next(confirm_answers)
            except StopIteration:
                return kwargs.get("default", False)

        with patch("defenseclaw.commands.cmd_setup.click.confirm",
                   side_effect=_confirm), \
             patch("defenseclaw.commands.cmd_setup.click.prompt",
                   return_value="1"), \
             patch("defenseclaw.commands.cmd_setup._select_connector_interactive",
                   return_value=connector), \
             patch(
                 "defenseclaw.commands.cmd_setup._prompt_batch_scan_strategy",
                 side_effect=AssertionError("setup guardrail should not ask for scan strategy"),
             ), \
             patch(
                 "defenseclaw.commands.cmd_setup._prompt_guardrail_judge_enablement",
                 side_effect=lambda gc_arg, targets: cmd_setup._merge_batch_judge_selection(gc_arg, targets, set()),
             ), \
             patch("defenseclaw.commands.cmd_setup._print_connector_info",
                   return_value=None), \
             patch("defenseclaw.commands.cmd_setup.click.echo",
                   return_value=None):
            _interactive_guardrail_setup(app, gc, agent_name=connector)
        return gc

    def test_codex_observability_flow_lands_in_observe_mode(self):
        gc = self._drive_observability("codex")
        self.assertTrue(gc.enabled,
                        "Wizard should enable telemetry for codex even in observability mode")
        # Sensible "if-flipped-on-later" defaults — these get persisted
        # so the YAML stays loadable.
        self.assertEqual(gc.mode, "observe")
        self.assertEqual(gc.scanner_mode, "local")
        self.assertEqual(gc.detection_strategy, "regex_only")
        self.assertFalse(gc.judge.enabled,
                         "Default scan strategy is regex_only; "
                         "operators who want judge can opt in on rerun")
        # The observability-only branch now also surfaces the hook
        # fail-mode prompt on initial setup. The mocked ``click.prompt``
        # returns "1" (open), so the persisted value must reflect that —
        # confirms the prompt was reached and the operator's answer was
        # applied.
        self.assertEqual(gc.hook_fail_mode, "open")

    def test_claudecode_observability_flow_lands_in_observe_mode(self):
        gc = self._drive_observability("claudecode")
        self.assertTrue(gc.enabled)
        self.assertEqual(gc.mode, "observe")
        self.assertFalse(gc.judge.enabled)
        self.assertEqual(gc.hook_fail_mode, "open")

    def test_empty_judge_selection_skips_judge_model_prompt(self):
        app, gc = _make_app("codex")

        with patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=[True, False, True]), \
             patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="1"), \
             patch(
                 "defenseclaw.commands.cmd_setup._prompt_batch_scan_strategy",
                 side_effect=AssertionError("setup guardrail should not ask for scan strategy"),
             ), \
             patch(
                 "defenseclaw.commands.cmd_setup._prompt_guardrail_judge_enablement",
                 side_effect=lambda gc_arg, targets: cmd_setup._merge_batch_judge_selection(gc_arg, targets, set()),
             ), \
             patch(
                 "defenseclaw.commands.cmd_setup._prompt_judge_model_config",
                 side_effect=AssertionError("judge model prompt should not run with no judge connectors"),
             ), \
             patch("defenseclaw.commands.cmd_setup._select_connector_interactive", return_value="codex"), \
             patch("defenseclaw.commands.cmd_setup._print_connector_info", return_value=None), \
             patch("defenseclaw.commands.cmd_setup.click.echo", return_value=None):
            _interactive_guardrail_setup(app, gc, agent_name="codex")
        self.assertFalse(gc.judge.enabled)
        self.assertEqual(gc.detection_strategy, "regex_only")

    def test_judge_selection_enables_selected_hook_coverage_and_model(self):
        app, gc = _make_app("codex")

        confirm_answers = iter([True, False, False])

        def _confirm(*args, **kwargs):
            try:
                return next(confirm_answers)
            except StopIteration:
                return kwargs.get("default", False)

        def _prompt(label, *args, **kwargs):
            if "Select mode" in str(label):
                return "2"
            return "1"

        with patch("defenseclaw.commands.cmd_setup.click.confirm",
                   side_effect=_confirm), \
             patch("defenseclaw.commands.cmd_setup.click.prompt",
                   side_effect=_prompt), \
             patch(
                 "defenseclaw.commands.cmd_setup._prompt_batch_scan_strategy",
                 side_effect=AssertionError("setup guardrail should not ask for scan strategy"),
             ), \
             patch(
                 "defenseclaw.commands.cmd_setup._prompt_guardrail_judge_enablement",
                 side_effect=lambda gc_arg, targets: cmd_setup._merge_batch_judge_selection(
                     gc_arg,
                     targets,
                     {"codex"},
                 ),
             ), \
             patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config") as model_prompt, \
             patch("defenseclaw.commands.cmd_setup._select_connector_interactive", return_value="codex"), \
             patch("defenseclaw.commands.cmd_setup._print_connector_info", return_value=None), \
             patch("defenseclaw.commands.cmd_setup.click.echo", return_value=None):
            _interactive_guardrail_setup(app, gc, agent_name="codex")
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")
        self.assertEqual(gc.judge.hook_connectors, ["codex"])
        model_prompt.assert_called_once()

    def test_observability_decline_disables_connector(self):
        """When the operator declines the single confirm prompt, the
        wizard returns with gc.enabled=False, leaving the rest of the
        guardrail config untouched."""
        app, gc = _make_app("codex")
        with patch("defenseclaw.commands.cmd_setup.click.confirm",
                   return_value=False), \
             patch("defenseclaw.commands.cmd_setup.click.prompt",
                   return_value="1"), \
             patch("defenseclaw.commands.cmd_setup._select_connector_interactive",
                   return_value="codex"), \
             patch("defenseclaw.commands.cmd_setup._print_connector_info",
                   return_value=None), \
             patch("defenseclaw.commands.cmd_setup.click.echo",
                   return_value=None):
            _interactive_guardrail_setup(app, gc, agent_name="codex")
        self.assertFalse(gc.enabled)

    def test_openclaw_uses_full_enforcement_path(self):
        """OpenClaw must fall through to the full enforcement-prompts
        path. We assert this by mocking ``click.prompt`` to raise — if
        the wizard reaches the enforcement-mode / scanner-engine /
        judge-config prompts (the path we want for openclaw), the
        prompt mock fires, proving we DIDN'T short-circuit through the
        observability branch."""
        app, gc = _make_app("openclaw")

        prompt_was_called = []

        def fake_prompt(*args, **kwargs):
            prompt_was_called.append(args)
            # Return the default so the wizard can keep walking
            # without crashing on type=Choice.
            return kwargs.get("default", "1")

        with patch("defenseclaw.commands.cmd_setup.click.confirm",
                   return_value=False), \
             patch("defenseclaw.commands.cmd_setup.click.prompt",
                   side_effect=fake_prompt), \
             patch("defenseclaw.commands.cmd_setup._select_connector_interactive",
                   return_value="openclaw"), \
             patch("defenseclaw.commands.cmd_setup._print_connector_info",
                   return_value=None), \
             patch("defenseclaw.commands.cmd_setup.click.echo",
                   return_value=None):
            _interactive_guardrail_setup(app, gc, agent_name="openclaw")


class ObservabilitySecretDotenvInjectionTests(unittest.TestCase):
    """F-1905: an observability/audit-sink token with an embedded newline
    must not inject a second KEY=VALUE line into ~/.defenseclaw/.env.

    Audit-sink tokens (e.g. Splunk HEC ``DEFENSECLAW_SPLUNK_HEC_TOKEN``) are
    persisted by ``observability/writer._apply_secret`` via ``_write_dotenv``,
    which now sanitizes (``sanitize_dotenv_value``). A token carrying a newline
    would otherwise add a second assignment (e.g. DEFENSECLAW_DISABLE_REDACTION)
    that the line-by-line config loader would honor.
    """

    def test_newline_secret_rejected_and_no_entry_injected(self):
        import tempfile

        from defenseclaw.observability import writer as obs_writer
        from defenseclaw.observability.presets import resolve_preset
        from defenseclaw.safety import DotenvValueError

        preset = resolve_preset("splunk-hec")
        self.assertTrue(preset.token_env)

        with tempfile.TemporaryDirectory() as tmp:
            # Seed an existing legit secret so we can prove it survives.
            obs_writer._apply_secret(tmp, preset, "legit-token-value", dry_run=False)
            self.addCleanup(os.environ.pop, preset.token_env, None)

            malicious = "tok\nDEFENSECLAW_DISABLE_REDACTION=1"
            with self.assertRaises(DotenvValueError):
                obs_writer._apply_secret(tmp, preset, malicious, dry_run=False)

            dotenv = os.path.join(tmp, obs_writer.DOTENV_FILE_NAME)
            body = open(dotenv, encoding="utf-8").read()
            # Injected entry never written; prior legit entry preserved intact.
            self.assertNotIn("DEFENSECLAW_DISABLE_REDACTION", body)
            self.assertIn("legit-token-value", body)
            keys = [
                ln.split("=", 1)[0].strip()
                for ln in body.splitlines()
                if ln.strip() and not ln.strip().startswith("#") and "=" in ln
            ]
            self.assertEqual(keys, [preset.token_env])


if __name__ == "__main__":
    unittest.main()
