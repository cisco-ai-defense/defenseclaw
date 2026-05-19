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
   port — all must survive the switch unchanged. Both connectors
   share the same proxy enforcement surface.

2. **Switching INTO a hook-enforced connector preserves
   ``guardrail.mode``**. Codex / Claude Code / Hermes / Cursor /
   Windsurf / GeminiCLI / Copilot all enforce via the agent's
   native hook bus (PreToolUse deny verdict). An operator on
   ``action`` keeps action mode — the destination connector wires
   the deny verdict instead of the proxy. ``gc.enabled`` stays
   True so the gateway provisions hooks + native OTel; only the
   proxy listener stops binding.

3. **Switching OUT of a hook-enforced connector into
   openclaw/zeptoclaw lands in observe mode**. We never auto-
   promote to proxy enforcement — flipping that on requires a
   separate ``defenseclaw setup guardrail`` run. The asymmetry is
   deliberate: re-binding the proxy listener can break the
   operator's existing upstream wiring, so we keep the
   destination passive until they confirm.

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
        ), patch(
            "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
            return_value=True,
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


class TestSetupMode_IntoHookEnforcedConnector(_ModeBase):
    """Switching → hook-enforced connectors preserves ``guardrail.mode``.

    The destination's native hook bus (PreToolUse deny verdict)
    becomes the enforcement surface in place of the proxy. The
    operator's posture carries over verbatim; switching connectors
    is a topology change, not a policy change.
    """

    def test_openclaw_action_to_codex_preserves_action(self):
        """Proxy → codex must NOT silently downgrade to observe.

        An operator running action mode through OpenClaw expects
        action to keep firing after the switch — only the surface
        changes (proxy ⇒ Codex PreToolUse deny verdict).
        """
        gc = self.app.cfg.guardrail
        self.app.cfg.claw.mode = "openclaw"
        gc.connector = "openclaw"
        gc.mode = "action"

        result = self._run("codex")

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.claw.mode, "codex")
        self.assertEqual(gc.connector, "codex")
        # The deliberate contract: action mode persists; Codex's
        # PreToolUse hook is now the deny surface.
        self.assertEqual(gc.mode, "action")
        # gc.enabled stays True so the gateway wires hooks + OTel.
        self.assertTrue(gc.enabled)

    def test_zeptoclaw_default_observe_to_claudecode_stays_observe(self):
        """No starting mode set → observe (defensive fallback)."""
        gc = self.app.cfg.guardrail
        self.app.cfg.claw.mode = "zeptoclaw"
        gc.connector = "zeptoclaw"
        # gc.mode left at its dataclass default; the switch should
        # downgrade to "observe" rather than carrying an empty value
        # through to the destination YAML.

        result = self._run("claudecode")

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.claw.mode, "claudecode")
        self.assertEqual(gc.mode, "observe")
        self.assertTrue(gc.enabled)

    def test_openclaw_action_to_cursor_preserves_action(self):
        """Same contract for the other hook-enforced connectors."""
        gc = self.app.cfg.guardrail
        self.app.cfg.claw.mode = "openclaw"
        gc.connector = "openclaw"
        gc.mode = "action"

        result = self._run("cursor")

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.claw.mode, "cursor")
        self.assertEqual(gc.connector, "cursor")
        # Cursor honors action via its hook bus on the destination.
        self.assertEqual(gc.mode, "action")
        self.assertTrue(gc.enabled)

    def test_openclaw_observe_to_codex_stays_observe(self):
        """Observe → observe (the obvious case, asserted explicitly)."""
        gc = self.app.cfg.guardrail
        self.app.cfg.claw.mode = "openclaw"
        gc.connector = "openclaw"
        gc.mode = "observe"

        result = self._run("codex")

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.claw.mode, "codex")
        self.assertEqual(gc.mode, "observe")
        self.assertTrue(gc.enabled)


class TestSetupMode_OutOfObservabilityOnly(_ModeBase):
    """hook/observability connectors → openclaw / zeptoclaw lands in observe mode."""

    def test_codex_to_openclaw_pins_observe_mode(self):
        gc = self.app.cfg.guardrail
        # Coming from codex observability-only setup.
        self.app.cfg.claw.mode = "codex"
        gc.connector = "codex"
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

    def test_geminicli_to_openclaw_pins_observe_mode(self):
        gc = self.app.cfg.guardrail
        self.app.cfg.claw.mode = "geminicli"
        gc.connector = "geminicli"
        gc.enabled = True
        gc.mode = "action"
        gc.port = 0

        result = self._run("openclaw")

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(gc.connector, "openclaw")
        self.assertEqual(gc.mode, "observe")
        self.assertEqual(gc.port, 4000)


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
