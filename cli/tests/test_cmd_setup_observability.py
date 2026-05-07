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

"""Regression tests for the codex / claude-code observability default
in ``defenseclaw setup guardrail``.

These tests pin the contract that selecting Codex or Claude Code as the
connector flips the wizard into observability-only mode: the operator
sees a single yes/no prompt and the wizard returns with sensible
defaults, never asking about enforcement mode, scanner engine, or LLM
judge config. A regression that quietly re-engaged those prompts would
silently revive the proxy data path (because gc.codex_enforcement_enabled
would default-flip somewhere in that branch) and break the
"no traffic interception for codex / claude-code" architectural goal.
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

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
        codex_enforcement_enabled=False,
        claudecode_enforcement_enabled=False,
        hook_fail_mode="",
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
        """Run the wizard with a "yes, enable observability" reply.

        Returns the post-run guardrail config namespace. We mock
        ``click.confirm`` to always say yes so the wizard takes the
        enabling path; if it ever tried to ask any *other* question,
        ``click.prompt`` would raise (it's not mocked) and the test
        would fail loudly.
        """
        app, gc = _make_app(connector)

        with patch("defenseclaw.commands.cmd_setup.click.confirm",
                   return_value=True), \
             patch("defenseclaw.commands.cmd_setup.click.prompt",
                   return_value="1"), \
             patch("defenseclaw.commands.cmd_setup._select_connector_interactive",
                   return_value=connector), \
             patch("defenseclaw.commands.cmd_setup._print_connector_info",
                   return_value=None), \
             patch("defenseclaw.commands.cmd_setup.click.echo",
                   return_value=None):
            _interactive_guardrail_setup(app, gc, agent_name=connector)
        return gc

    def test_codex_observability_flow_sets_enforcement_false(self):
        gc = self._drive_observability("codex")
        self.assertTrue(gc.enabled,
                        "Wizard should enable telemetry for codex even in observability mode")
        self.assertFalse(gc.codex_enforcement_enabled,
                         "codex_enforcement_enabled MUST default false in the wizard")
        # Sensible "if-flipped-on-later" defaults — these get persisted
        # so the YAML stays loadable, not because the gateway reads
        # them in observability mode.
        self.assertEqual(gc.mode, "observe")
        self.assertEqual(gc.scanner_mode, "local")
        self.assertEqual(gc.detection_strategy, "regex_only")
        self.assertFalse(gc.judge.enabled,
                         "Judge must default off in observability mode (no proxy → no judge)")
        # The observability-only branch now also surfaces the
        # hook fail-mode prompt on initial setup. The mocked
        # ``click.prompt`` returns "1" (open), so the persisted value
        # must reflect that — confirms the prompt was reached and the
        # operator's answer was applied. Previously this branch
        # bypassed the prompt entirely, leaving operators with no
        # opportunity to set hook_fail_mode at first-time setup.
        self.assertEqual(gc.hook_fail_mode, "open")

    def test_claudecode_observability_flow_sets_enforcement_false(self):
        gc = self._drive_observability("claudecode")
        self.assertTrue(gc.enabled)
        self.assertFalse(gc.claudecode_enforcement_enabled,
                         "claudecode_enforcement_enabled MUST default false in the wizard")
        # Sibling flag must NOT cross over — this is the same
        # isolation guarantee the Go-side helper test pins.
        self.assertFalse(gc.codex_enforcement_enabled,
                         "claudecode wizard run must not flip codex enforcement")
        self.assertEqual(gc.mode, "observe")
        self.assertFalse(gc.judge.enabled)
        # See test_codex_observability_flow_sets_enforcement_false
        # for the rationale: hook_fail_mode prompt now fires in the
        # observability-only path too on initial setup.
        self.assertEqual(gc.hook_fail_mode, "open")

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

    def test_claudecode_action_flow_sets_enforcement_true(self):
        app, gc = _make_app("claudecode")

        # Prompt order in the guardrail-setup branch (integration=2)
        # for action mode:
        #   1. integration mode ("2" = guardrail setup w/ proxy)
        #   2. enforcement mode ("2" = action)
        #   3. hook fail-mode prompt ("1" = open) — fires because
        #      gc.mode starts empty (initial setup) AND we flipped
        #      to action.
        #   4. NEW (post-HITL-hoist) HILT severity prompt — fires
        #      only when the prior ``Human approval?`` confirm
        #      returned True. We answer NO to that confirm below
        #      so this severity prompt does NOT fire here.
        #   5. scanner engine ("1" = local)
        #
        # Confirms (in order):
        #   a. "Enable guardrail?" → True
        #   b. NEW: "Human approval for risky actions?" → False
        #      (so no HILT severity prompt fires next)
        #   c. "Enable LLM judge?" → False
        #   d. "Configure advanced options?" → False
        prompts = iter(["2", "2", "1", "1"])
        confirms = iter([True, False, False, False])

        with patch("defenseclaw.commands.cmd_setup.click.prompt",
                   side_effect=lambda *args, **kwargs: next(prompts)), \
             patch("defenseclaw.commands.cmd_setup.click.confirm",
                   side_effect=lambda *args, **kwargs: next(confirms)), \
             patch("defenseclaw.commands.cmd_setup._select_connector_interactive",
                   return_value="claudecode"), \
             patch("defenseclaw.commands.cmd_setup._print_connector_info",
                   return_value=None), \
             patch("defenseclaw.commands.cmd_setup.click.echo",
                   return_value=None):
            _interactive_guardrail_setup(app, gc, agent_name="claudecode")

        self.assertTrue(gc.enabled)
        self.assertTrue(gc.claudecode_enforcement_enabled)
        self.assertEqual(gc.mode, "action")
        self.assertEqual(gc.scanner_mode, "local")
        self.assertFalse(gc.judge.enabled)
        # The fail-mode prompt persisted "open" — confirming the
        # wizard's interactive choice survives without the operator
        # having to hand-edit YAML afterward.
        self.assertEqual(gc.hook_fail_mode, "open")
        # HILT was offered (action mode) and declined — gc.hilt
        # stays at the fixture default. This pins the new inline-
        # HILT contract: action-mode runs ALWAYS get a HILT
        # confirm, but declining it is a no-op rather than a
        # second prompt cascade.
        self.assertFalse(gc.hilt.enabled)

    def test_codex_guardrail_observe_flow_sets_enforcement_true(self):
        app, gc = _make_app("codex")

        # Prompt order in the guardrail-setup branch (integration=2):
        #   1. integration mode ("2" = guardrail setup w/ proxy)
        #   2. enforcement mode ("1" = observe)
        #   3. NEW v3 hook fail-mode prompt ("1" = open) — fires on
        #      initial setup even when mode stays observe, because
        #      gc.mode starts empty in the fixture.
        #   4. scanner engine ("1" = local)
        prompts = iter(["2", "1", "1", "1"])
        confirms = iter([True, False, False])

        with patch("defenseclaw.commands.cmd_setup.click.prompt",
                   side_effect=lambda *args, **kwargs: next(prompts)), \
             patch("defenseclaw.commands.cmd_setup.click.confirm",
                   side_effect=lambda *args, **kwargs: next(confirms)), \
             patch("defenseclaw.commands.cmd_setup._select_connector_interactive",
                   return_value="codex"), \
             patch("defenseclaw.commands.cmd_setup._print_connector_info",
                   return_value=None), \
             patch("defenseclaw.commands.cmd_setup.click.echo",
                   return_value=None):
            _interactive_guardrail_setup(app, gc, agent_name="codex")

        self.assertTrue(gc.enabled)
        self.assertTrue(gc.codex_enforcement_enabled)
        self.assertEqual(gc.mode, "observe")
        self.assertEqual(gc.scanner_mode, "local")
        self.assertFalse(gc.judge.enabled)
        self.assertEqual(gc.hook_fail_mode, "open")

    def test_openclaw_does_not_use_observability_path(self):
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

        # Either the wizard exited at "Enable guardrail?" (fine — first
        # confirm was False) OR it walked into the prompt section. The
        # critical guarantee is that ``codex_enforcement_enabled`` /
        # ``claudecode_enforcement_enabled`` remain False (we never
        # accidentally flip them ON for an openclaw install).
        self.assertFalse(gc.codex_enforcement_enabled)
        self.assertFalse(gc.claudecode_enforcement_enabled)


if __name__ == "__main__":
    unittest.main()
