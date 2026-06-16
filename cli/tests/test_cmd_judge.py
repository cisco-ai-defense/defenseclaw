# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw guardrail judge {add,remove,list}`` and the
``setup guardrail`` hook-lane judge prompt.

The hook gate (``guardrail.judge.hook_connectors``) is the only judge
setting that is per-connector and default-off, so the authoring surface
must (a) never widen or clear the gate on a no-op path, (b) reject
targets the gate can never apply to (proxy-backed / unknown connectors),
and (c) restart the gateway on real changes — the judge's hook wiring is
built at sidecar startup.
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import click
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_judge, cmd_setup
from defenseclaw.context import AppContext


def make_ctx(
    *,
    guardrail_enabled: bool = True,
    judge_enabled: bool = True,
    hook_connectors: list[str] | None = None,
    hook_timeout: float = 0.0,
    connectors: list[str] | None = None,
):
    """Minimal AppContext for the judge gate commands.

    ``connectors`` is the active multi-connector set (defaults to a
    hermes + opencode hook install, matching the scenario the command
    exists for).
    """
    actives = connectors if connectors is not None else ["hermes", "opencode"]
    judge_cfg = SimpleNamespace(
        enabled=judge_enabled,
        hook_connectors=list(hook_connectors or []),
        hook_timeout=hook_timeout,
    )
    guardrail_cfg = SimpleNamespace(
        enabled=guardrail_enabled,
        connector=actives[0] if actives else "openclaw",
        judge=judge_cfg,
    )
    cfg = SimpleNamespace(
        guardrail=guardrail_cfg,
        data_dir="/tmp/dc",
        gateway=SimpleNamespace(host="127.0.0.1", port=18789),
    )
    cfg.active_connectors = lambda: list(actives)
    cfg.active_connector = lambda: actives[0] if actives else "openclaw"
    cfg.save = MagicMock()

    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    app.logger.log_action = MagicMock()
    return app


def invoke(app, args):
    return CliRunner().invoke(cmd_judge.judge, args, obj=app)


class JudgeAddTests(unittest.TestCase):
    @patch.object(cmd_setup, "_restart_services")
    def test_add_appends_and_restarts(self, restart):
        app = make_ctx()
        result = invoke(app, ["add", "hermes"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["hermes"])
        app.cfg.save.assert_called_once()
        restart.assert_called_once()
        app.logger.log_action.assert_called_once()

    @patch.object(cmd_setup, "_restart_services")
    def test_add_normalizes_case(self, restart):
        app = make_ctx()
        result = invoke(app, ["add", "Hermes"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["hermes"])

    @patch.object(cmd_setup, "_restart_services")
    def test_add_star_replaces_explicit_list(self, restart):
        app = make_ctx(hook_connectors=["hermes"])
        result = invoke(app, ["add", "*"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["*"])
        app.cfg.save.assert_called_once()

    @patch.object(cmd_setup, "_restart_services")
    def test_add_all_alias_writes_star(self, restart):
        # "all" is the primary CLI form (no shell quoting); the config
        # value stays the literal "*" the Go gate understands.
        app = make_ctx()
        result = invoke(app, ["add", "all"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["*"])

    @patch.object(cmd_setup, "_restart_services")
    def test_add_all_alias_case_insensitive(self, restart):
        app = make_ctx()
        result = invoke(app, ["add", "ALL"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["*"])

    @patch.object(cmd_setup, "_restart_services")
    def test_add_name_under_star_is_noop(self, restart):
        app = make_ctx(hook_connectors=["*"])
        result = invoke(app, ["add", "hermes"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["*"])
        app.cfg.save.assert_not_called()
        restart.assert_not_called()
        self.assertIn("already covered", result.output)

    @patch.object(cmd_setup, "_restart_services")
    def test_add_duplicate_is_noop(self, restart):
        app = make_ctx(hook_connectors=["hermes"])
        result = invoke(app, ["add", "hermes"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["hermes"])
        app.cfg.save.assert_not_called()
        restart.assert_not_called()

    def test_add_proxy_backed_rejected(self):
        app = make_ctx()
        result = invoke(app, ["add", "openclaw"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("proxy-backed", result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, [])
        app.cfg.save.assert_not_called()

    def test_add_unknown_rejected(self):
        app = make_ctx()
        result = invoke(app, ["add", "notaconnector"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("unknown connector", result.output)
        app.cfg.save.assert_not_called()

    def test_add_blank_rejected(self):
        app = make_ctx()
        result = invoke(app, ["add", "  "])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("required", result.output)

    @patch.object(cmd_setup, "_restart_services")
    def test_add_with_timeout_sets_hook_timeout(self, restart):
        app = make_ctx()
        result = invoke(app, ["add", "hermes", "--timeout", "8"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_timeout, 8)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["hermes"])

    @patch.object(cmd_setup, "_restart_services")
    def test_add_timeout_above_hook_budget_warns(self, restart):
        app = make_ctx()
        result = invoke(app, ["add", "hermes", "--timeout", "9"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("10s", result.output)

    def test_add_negative_timeout_rejected(self):
        app = make_ctx()
        result = invoke(app, ["add", "hermes", "--timeout", "-1"])
        self.assertNotEqual(result.exit_code, 0)
        app.cfg.save.assert_not_called()

    @patch.object(cmd_setup, "_restart_services")
    def test_add_timeout_alone_persists_without_gate_change(self, restart):
        # Re-running add for an existing member with a new --timeout is a
        # real change (the timeout), so it must save even though the
        # gate itself didn't move — and the output must say that's what
        # is happening, never "nothing to do" right before a save+restart.
        app = make_ctx(hook_connectors=["hermes"])
        result = invoke(app, ["add", "hermes", "--timeout", "3"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_timeout, 3)
        app.cfg.save.assert_called_once()
        self.assertNotIn("nothing to do", result.output)
        self.assertIn("saving hook_timeout only", result.output)

    @patch.object(cmd_setup, "_restart_services")
    def test_add_all_with_timeout_under_star_gate_is_not_a_noop_message(self, restart):
        # gate already "*" + --timeout change: saves and restarts, so the
        # gate no-op reason is reported as timeout-only, not "nothing to do".
        app = make_ctx(hook_connectors=["*"])
        result = invoke(app, ["add", "all", "--timeout", "7"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_timeout, 7)
        app.cfg.save.assert_called_once()
        self.assertNotIn("nothing to do", result.output)

    @patch.object(cmd_setup, "_restart_services")
    def test_add_no_restart_flag(self, restart):
        app = make_ctx()
        result = invoke(app, ["add", "hermes", "--no-restart"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        app.cfg.save.assert_called_once()
        restart.assert_not_called()

    @patch.object(cmd_setup, "_restart_services")
    def test_add_skips_restart_when_guardrail_disabled(self, restart):
        app = make_ctx(guardrail_enabled=False)
        result = invoke(app, ["add", "hermes"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["hermes"])
        restart.assert_not_called()
        self.assertIn("guardrail is currently disabled", result.output)

    @patch.object(cmd_setup, "_restart_services")
    def test_add_warns_when_judge_disabled(self, restart):
        app = make_ctx(judge_enabled=False)
        result = invoke(app, ["add", "hermes"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("judge", result.output)
        self.assertIn("no effect", result.output)
        # The gate is still written — it becomes live when the judge is
        # enabled, matching the wizard's separation of concerns.
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["hermes"])

    @patch.object(cmd_setup, "_restart_services")
    def test_add_unconfigured_connector_warns_but_persists(self, restart):
        app = make_ctx(connectors=["hermes"])
        result = invoke(app, ["add", "codex"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("not a configured connector", result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["codex"])

    @patch.object(cmd_setup, "_restart_services")
    def test_add_enable_flips_judge_enabled(self, restart):
        # J1: --enable turns the judge on as part of the add, so a freshly
        # gated connector isn't left inert behind judge.enabled=false.
        app = make_ctx(judge_enabled=False)
        result = invoke(app, ["add", "hermes", "--enable"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(app.cfg.guardrail.judge.enabled)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["hermes"])
        app.cfg.save.assert_called_once()
        restart.assert_called_once()
        # With the judge now on, the inert "no effect" warning must not fire.
        self.assertNotIn("no effect", result.output)

    @patch.object(cmd_setup, "_restart_services")
    def test_add_without_enable_leaves_judge_disabled(self, restart):
        # Default is preserved: add never flips judge.enabled, and the inert
        # warning still fires so the operator knows the gate is dormant.
        app = make_ctx(judge_enabled=False)
        result = invoke(app, ["add", "hermes"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(app.cfg.guardrail.judge.enabled)
        self.assertIn("no effect", result.output)

    @patch.object(cmd_setup, "_restart_services")
    def test_add_enable_when_already_enabled_is_idempotent(self, restart):
        # --enable on an already-enabled judge is not itself a change: with
        # the gate also a no-op there is nothing to save or restart.
        app = make_ctx(judge_enabled=True, hook_connectors=["hermes"])
        result = invoke(app, ["add", "hermes", "--enable"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(app.cfg.guardrail.judge.enabled)
        app.cfg.save.assert_not_called()
        restart.assert_not_called()
        self.assertIn("nothing to do", result.output)

    @patch.object(cmd_setup, "_restart_services")
    def test_add_enable_alone_persists_without_gate_change(self, restart):
        # Gate no-op (already gated) but judge was off + --enable: a real
        # change (judge.enabled off→on), so it saves and reports the enable,
        # never "nothing to do" right before a save+restart.
        app = make_ctx(judge_enabled=False, hook_connectors=["hermes"])
        result = invoke(app, ["add", "hermes", "--enable"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(app.cfg.guardrail.judge.enabled)
        app.cfg.save.assert_called_once()
        self.assertNotIn("nothing to do", result.output)
        self.assertIn("judge.enabled", result.output)


class JudgeRemoveTests(unittest.TestCase):
    @patch.object(cmd_setup, "_restart_services")
    def test_remove_member(self, restart):
        app = make_ctx(hook_connectors=["hermes", "opencode"])
        result = invoke(app, ["remove", "opencode"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["hermes"])
        app.cfg.save.assert_called_once()
        restart.assert_called_once()

    @patch.object(cmd_setup, "_restart_services")
    def test_remove_last_member_notes_lane_off(self, restart):
        app = make_ctx(hook_connectors=["hermes"])
        result = invoke(app, ["remove", "hermes"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, [])
        self.assertIn("hook lane off", result.output)

    @patch.object(cmd_setup, "_restart_services")
    def test_remove_star_clears_gate(self, restart):
        app = make_ctx(hook_connectors=["*"])
        result = invoke(app, ["remove", "*"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, [])
        app.cfg.save.assert_called_once()

    @patch.object(cmd_setup, "_restart_services")
    def test_remove_all_alias_clears_gate(self, restart):
        app = make_ctx(hook_connectors=["*"])
        result = invoke(app, ["remove", "all"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, [])

    @patch.object(cmd_setup, "_restart_services")
    def test_remove_name_under_star_expands_minus_removed(self, restart):
        # J6: removing one connector from `*` materializes the wildcard into
        # the canonical hook roster minus that connector rather than
        # erroring, so "every hook connector except hermes" stays
        # expressible from the CLI.
        app = make_ctx(hook_connectors=["*"])
        result = invoke(app, ["remove", "hermes"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        expected = sorted(cmd_setup._HOOK_ENFORCED_CONNECTORS - {"hermes"})
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, expected)
        self.assertNotIn("hermes", app.cfg.guardrail.judge.hook_connectors)
        self.assertIn("expanded", result.output)
        app.cfg.save.assert_called_once()
        restart.assert_called_once()

    @patch.object(cmd_setup, "_restart_services")
    def test_remove_padded_star_expands(self, restart):
        # Hand-edited ' * ' is live on the Go gate (TrimSpace + EqualFold),
        # so removing a member from it must expand too, not no-op.
        app = make_ctx(hook_connectors=[" * "])
        result = invoke(app, ["remove", "opencode"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        expected = sorted(cmd_setup._HOOK_ENFORCED_CONNECTORS - {"opencode"})
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, expected)

    @patch.object(cmd_setup, "_restart_services")
    def test_remove_nonmember_is_noop(self, restart):
        app = make_ctx(hook_connectors=["hermes"])
        result = invoke(app, ["remove", "opencode"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["hermes"])
        app.cfg.save.assert_not_called()
        restart.assert_not_called()

    @patch.object(cmd_setup, "_restart_services")
    def test_remove_star_when_empty_is_noop(self, restart):
        app = make_ctx(hook_connectors=[])
        result = invoke(app, ["remove", "*"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        app.cfg.save.assert_not_called()
        restart.assert_not_called()

    def test_remove_unknown_connector_rejected(self):
        # remove must validate like add: `remove claude-code` (the
        # spelling `setup claude-code` teaches) exiting 0 with "nothing
        # to do" would leave the operator believing the judge is off
        # while 'claudecode' stays gated.
        app = make_ctx(hook_connectors=["claudecode"])
        result = invoke(app, ["remove", "claude-code"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("unknown connector", result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["claudecode"])
        app.cfg.save.assert_not_called()

    def test_remove_proxy_backed_rejected(self):
        app = make_ctx()
        result = invoke(app, ["remove", "openclaw"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("proxy-backed", result.output)


class GateCaseFoldTests(unittest.TestCase):
    """CLI gate matching must mirror the Go gate (TrimSpace + EqualFold,
    internal/config/config.go HookConnectorEnabled) so a hand-edited
    'Hermes' or ' * ' entry that is live on the gateway is never
    reported as un-gated by the CLI."""

    def test_list_treats_mixed_case_entry_as_gated(self):
        app = make_ctx(hook_connectors=["Hermes"])
        result = invoke(app, ["list"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("hermes: judged (hook lane)", result.output)

    @patch.object(cmd_setup, "_restart_services")
    def test_remove_matches_mixed_case_entry(self, restart):
        app = make_ctx(hook_connectors=["Hermes"])
        result = invoke(app, ["remove", "hermes"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, [])
        app.cfg.save.assert_called_once()

    @patch.object(cmd_setup, "_restart_services")
    def test_add_does_not_duplicate_mixed_case_entry(self, restart):
        app = make_ctx(hook_connectors=["Hermes"])
        result = invoke(app, ["add", "hermes"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.judge.hook_connectors, ["Hermes"])
        app.cfg.save.assert_not_called()
        self.assertIn("already in hook_connectors", result.output)

    def test_padded_star_treated_as_all(self):
        app = make_ctx(hook_connectors=[" * "])
        result = invoke(app, ["list"])
        self.assertIn("hook_connectors:", result.output)
        self.assertIn("opencode: judged (hook lane)", result.output)


class JudgeListTests(unittest.TestCase):
    def test_list_gated_and_ungated(self):
        app = make_ctx(hook_connectors=["hermes"])
        result = invoke(app, ["list"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("hermes: judged (hook lane)", result.output)
        self.assertIn("opencode: regex + AID only", result.output)
        self.assertIn("guardrail judge add opencode", result.output)

    def test_list_star_covers_all(self):
        app = make_ctx(hook_connectors=["*"])
        result = invoke(app, ["list"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("hermes: judged (hook lane)", result.output)
        self.assertIn("opencode: judged (hook lane)", result.output)

    def test_list_star_displayed_as_all(self):
        # The CLI's input language is "all"; the display must match it.
        # (config.yaml still stores the literal "*" the Go gate reads.)
        app = make_ctx(hook_connectors=["*"])
        result = invoke(app, ["list"])
        self.assertIn("hook_connectors:", result.output)
        self.assertIn("all", result.output)
        self.assertNotIn("['*']", result.output)
        self.assertNotIn("stored as", result.output)

    def test_list_empty_gate_shows_lane_off(self):
        app = make_ctx()
        result = invoke(app, ["list"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("hook lane off", result.output)

    def test_list_judge_disabled_shows_inactive(self):
        app = make_ctx(judge_enabled=False, hook_connectors=["hermes"])
        result = invoke(app, ["list"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("gated on, judge inactive", result.output)
        self.assertIn("judge disabled", result.output)

    def test_list_proxy_connector_labeled(self):
        app = make_ctx(connectors=["openclaw"])
        result = invoke(app, ["list"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("openclaw: judged (proxy lane)", result.output)

    def test_list_default_timeout_labeled(self):
        app = make_ctx()
        result = invoke(app, ["list"])
        self.assertIn("5s (gateway default)", result.output)

    def test_list_custom_timeout_shown(self):
        app = make_ctx(hook_timeout=8.0)
        result = invoke(app, ["list"])
        self.assertIn("8s", result.output)


class WizardHookPromptTests(unittest.TestCase):
    """``cmd_setup._prompt_judge_hook_connectors`` — the wizard touch."""

    def _gc(self, connectors=("hermes", "opencode"), gate=()):
        return SimpleNamespace(
            connectors={c: SimpleNamespace() for c in connectors},
            connector=connectors[0] if connectors else "",
            judge=SimpleNamespace(hook_connectors=list(gate)),
        )

    def test_proxy_only_install_skips_prompt(self):
        gc = self._gc(connectors=("openclaw",))
        with patch.object(click, "prompt") as prompt:
            cmd_setup._prompt_judge_hook_connectors(gc)
        prompt.assert_not_called()
        self.assertEqual(gc.judge.hook_connectors, [])

    def test_fresh_install_defaults_to_none(self):
        gc = self._gc()
        with patch.object(click, "prompt", return_value="none") as prompt:
            cmd_setup._prompt_judge_hook_connectors(gc)
        self.assertEqual(prompt.call_args.kwargs.get("default"), "none")
        self.assertEqual(gc.judge.hook_connectors, [])

    def test_choice_all_writes_star(self):
        gc = self._gc()
        with patch.object(click, "prompt", return_value="all"):
            cmd_setup._prompt_judge_hook_connectors(gc)
        self.assertEqual(gc.judge.hook_connectors, ["*"])

    def test_choice_single_connector(self):
        gc = self._gc()
        with patch.object(click, "prompt", return_value="hermes"):
            cmd_setup._prompt_judge_hook_connectors(gc)
        self.assertEqual(gc.judge.hook_connectors, ["hermes"])

    def test_rerun_with_star_defaults_to_all(self):
        gc = self._gc(gate=("*",))
        with patch.object(click, "prompt", return_value="all") as prompt:
            cmd_setup._prompt_judge_hook_connectors(gc)
        self.assertEqual(prompt.call_args.kwargs.get("default"), "all")
        self.assertEqual(gc.judge.hook_connectors, ["*"])

    def test_rerun_with_single_entry_defaults_to_it(self):
        gc = self._gc(gate=("hermes",))
        with patch.object(click, "prompt", return_value="hermes") as prompt:
            cmd_setup._prompt_judge_hook_connectors(gc)
        self.assertEqual(prompt.call_args.kwargs.get("default"), "hermes")
        self.assertEqual(gc.judge.hook_connectors, ["hermes"])

    def test_rerun_with_multi_entry_defaults_to_keep(self):
        # An explicit two-connector gate can't be expressed as one
        # choice — Enter must preserve it, never clear it.
        gc = self._gc(connectors=("hermes", "opencode", "codex"), gate=("hermes", "codex"))
        with patch.object(click, "prompt", return_value="keep") as prompt:
            cmd_setup._prompt_judge_hook_connectors(gc)
        self.assertEqual(prompt.call_args.kwargs.get("default"), "keep")
        self.assertEqual(gc.judge.hook_connectors, ["hermes", "codex"])

    def test_choice_none_clears_gate(self):
        gc = self._gc(gate=("hermes",))
        with patch.object(click, "prompt", return_value="none"):
            cmd_setup._prompt_judge_hook_connectors(gc)
        self.assertEqual(gc.judge.hook_connectors, [])


if __name__ == "__main__":
    unittest.main()
