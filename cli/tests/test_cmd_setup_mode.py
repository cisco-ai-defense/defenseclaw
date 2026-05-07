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

"""Regression tests for ``defenseclaw setup mode <connector>``.

The TUI Overview's [m] action shells out to this command, so the
inheritance contract must be airtight or operators see surprising
behavior when switching connectors. The four invariants under test:

1. **openclaw ↔ zeptoclaw inherits the entire guardrail block**.
   Mode != action mode, scanner_mode != local, judge enabled, custom
   port — all must survive the switch unchanged.

2. **Switching INTO codex/claudecode forces observability-only**.
   ``*_enforcement_enabled`` becomes False even if it was True;
   ``gc.enabled`` stays True (so the Go gateway wires hooks + OTel)
   but ``gc.mode`` is pinned to ``observe``.

3. **Switching OUT of codex/claudecode into openclaw/zeptoclaw lands
   in observe mode**. We never auto-promote to enforcing — that
   requires a separate ``defenseclaw setup guardrail`` run.

4. **No-op when target equals current**. The command must succeed
   without rewriting config or restarting the gateway when the user
   re-selects the active mode.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_setup import setup as setup_group
from tests.helpers import cleanup_app, make_app_context


def _invoke(args: list[str], app):
    runner = CliRunner()
    return runner.invoke(setup_group, args, obj=app, catch_exceptions=False)


class _ModeBase(unittest.TestCase):
    """Common test scaffolding: temp app, no-op cfg.save, no-op restart."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")
        self.save_calls = 0

        def _save():
            self.save_calls += 1
            with open(self.cfg_path, "w") as fh:
                fh.write(
                    f"claw_mode: {self.app.cfg.claw.mode}\n"
                    f"guardrail_connector: {self.app.cfg.guardrail.connector}\n"
                    f"guardrail_enabled: {self.app.cfg.guardrail.enabled}\n"
                    f"guardrail_mode: {self.app.cfg.guardrail.mode}\n"
                )

        self.app.cfg.save = _save  # type: ignore[assignment]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _run(self, target: str, *extra):
        # Mock everything that would touch a real gateway, OS process,
        # or file outside tmp_dir. We want to assert on the in-memory
        # cfg + the cfg.yaml written by our injected save shim only.
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services",
            return_value=None,
        ), patch(
            "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
            return_value=None,
        ), patch(
            "defenseclaw.commands.cmd_setup._write_guardrail_runtime",
            return_value=None,
        ), patch(
            "defenseclaw.commands.cmd_setup._write_picked_connector_hint",
            return_value=None,
        ):
            return _invoke(["mode", target, *extra], self.app)


class TestSetupMode_OpenClawZeptoClawInheritance(_ModeBase):
    """Switching openclaw ↔ zeptoclaw must inherit guardrail config."""

    def test_openclaw_to_zeptoclaw_keeps_action_mode_and_scanner(self):
        gc = self.app.cfg.guardrail
        # Start with a heavy enforcement posture so we can prove every
        # field survives the switch.
        self.app.cfg.claw.mode = "openclaw"
        gc.connector = "openclaw"
        gc.enabled = True
        gc.mode = "action"           # enforcing!
        gc.scanner_mode = "both"     # local+remote
        gc.port = 4242               # non-default
        gc.detection_strategy = "regex_judge"

        result = self._run("zeptoclaw")

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.claw.mode, "zeptoclaw")
        self.assertEqual(gc.connector, "zeptoclaw")
        # Inheritance proof: every guardrail knob unchanged.
        self.assertTrue(gc.enabled)
        self.assertEqual(gc.mode, "action")
        self.assertEqual(gc.scanner_mode, "both")
        self.assertEqual(gc.port, 4242)
        self.assertEqual(gc.detection_strategy, "regex_judge")

    def test_zeptoclaw_to_openclaw_keeps_judge_enabled(self):
        gc = self.app.cfg.guardrail
        self.app.cfg.claw.mode = "zeptoclaw"
        gc.connector = "zeptoclaw"
        gc.enabled = True
        gc.mode = "observe"
        gc.judge.enabled = True

        result = self._run("openclaw")

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.claw.mode, "openclaw")
        self.assertTrue(gc.judge.enabled, "judge config must inherit")


class TestSetupMode_IntoObservabilityOnly(_ModeBase):
    """Switching → codex / claudecode forces observability-only."""

    def test_openclaw_to_codex_disables_codex_enforcement(self):
        gc = self.app.cfg.guardrail
        self.app.cfg.claw.mode = "openclaw"
        gc.connector = "openclaw"
        # Pre-seed the codex enforcement flag to True so we can prove
        # the alias zeroes it.
        gc.codex_enforcement_enabled = True
        gc.mode = "action"

        result = self._run("codex")

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.claw.mode, "codex")
        self.assertEqual(gc.connector, "codex")
        self.assertFalse(
            gc.codex_enforcement_enabled,
            "codex_enforcement_enabled must come back False",
        )
        # Observability-only forces ``observe`` mode.
        self.assertEqual(gc.mode, "observe")
        # gc.enabled stays True so Go gateway wires hooks + OTel.
        self.assertTrue(gc.enabled)

    def test_zeptoclaw_to_claudecode_disables_claudecode_enforcement(self):
        gc = self.app.cfg.guardrail
        self.app.cfg.claw.mode = "zeptoclaw"
        gc.connector = "zeptoclaw"
        gc.claudecode_enforcement_enabled = True

        result = self._run("claude-code" if False else "claudecode")
        # ^ Click choice list normalizes case-insensitively but the
        # canonical literal is ``claudecode`` (no hyphen). The
        # ``setup claude-code`` ALIAS exists separately.

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.claw.mode, "claudecode")
        self.assertFalse(gc.claudecode_enforcement_enabled)


class TestSetupMode_OutOfObservabilityOnly(_ModeBase):
    """codex / claudecode → openclaw / zeptoclaw lands in observe mode."""

    def test_codex_to_openclaw_pins_observe_mode(self):
        gc = self.app.cfg.guardrail
        # Coming from codex observability-only setup.
        self.app.cfg.claw.mode = "codex"
        gc.connector = "codex"
        gc.codex_enforcement_enabled = False
        gc.enabled = True
        gc.mode = "observe"   # what _apply_connector_observability_only
                              # would have written
        gc.port = 0           # codex observability path leaves it 0
                              # if user never set one

        result = self._run("openclaw")

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.claw.mode, "openclaw")
        self.assertEqual(gc.connector, "openclaw")
        # Proxy must be enabled in observe mode so traffic flows.
        self.assertTrue(gc.enabled)
        self.assertEqual(gc.mode, "observe")
        # Default port populated when previously unset.
        self.assertEqual(gc.port, 4000)

    def test_claudecode_to_zeptoclaw_does_not_auto_enforce(self):
        """Even if user previously had `action`-mode posture, going
        out of observability-only must NOT silently re-enable
        enforcement — operators have to opt-in via
        `defenseclaw setup guardrail`.
        """
        gc = self.app.cfg.guardrail
        self.app.cfg.claw.mode = "claudecode"
        gc.connector = "claudecode"
        gc.enabled = True
        gc.mode = "action"  # stale value from a long-ago openclaw run

        result = self._run("zeptoclaw")

        self.assertEqual(result.exit_code, 0, msg=result.output)
        # The transition path explicitly forces observe — the user
        # must run `setup guardrail` to enforce.
        self.assertEqual(gc.mode, "observe")


class TestSetupMode_NoOp(_ModeBase):
    """Switching to the current mode is a clean no-op."""

    def test_already_on_target_does_not_save(self):
        gc = self.app.cfg.guardrail
        self.app.cfg.claw.mode = "openclaw"
        gc.connector = "openclaw"
        gc.mode = "action"

        result = self._run("openclaw")

        self.assertEqual(result.exit_code, 0, msg=result.output)
        # No persistence step on a no-op switch.
        self.assertEqual(self.save_calls, 0)
        # State unchanged.
        self.assertEqual(self.app.cfg.claw.mode, "openclaw")
        self.assertEqual(gc.mode, "action")
        # Friendly no-op message visible in stdout.
        self.assertIn("Already on OpenClaw", result.output)


class TestSetupMode_InvalidArguments(_ModeBase):
    """Click-level validation rejects non-connector inputs."""

    def test_unknown_connector_rejected_by_click(self):
        result = _invoke(["mode", "bogus"], self.app)
        # Click's ``Choice`` enforces this — exit 2 == usage error.
        self.assertEqual(result.exit_code, 2)


if __name__ == "__main__":
    unittest.main()
