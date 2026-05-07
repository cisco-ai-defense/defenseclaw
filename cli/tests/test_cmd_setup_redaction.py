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

"""Regression tests for ``defenseclaw setup redaction <on|off|status>``.

The redaction kill-switch is a deliberate, persistent operator
choice that violates the unconditional-redaction contract
documented in OBSERVABILITY.md. A bug here lets raw user prompts /
judge bodies / verdict reasons leak into audit DB, OTel logs,
Splunk HEC, and webhooks — the exact failure mode the contract
exists to prevent. The four invariants under test:

1. **``status`` reports both the persisted flag and the env-var
   override** so an operator inspecting a misbehaving install can
   tell which surface flipped redaction off.

2. **``off`` requires explicit consent** unless ``--yes`` is set.
   Defaults to redacted — flipping it off without acknowledging
   the privacy implications is the bug.

3. **``off``/``on`` round-trips through ``cfg.save()``** so the
   choice survives sidecar restarts. The Go ``applyPrivacyConfig``
   hook reads the same flag at boot.

4. **No-op when desired state matches current**. Re-running ``off``
   on a config that already has redaction off must not rewrite
   the file or trigger a restart.
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


class _RedactionBase(unittest.TestCase):
    """Common scaffolding: temp app, no-op cfg.save, no-op restart."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.save_calls = 0

        def _save():
            self.save_calls += 1

        self.app.cfg.save = _save  # type: ignore[assignment]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _run(self, *extra):
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services",
            return_value=None,
        ):
            return _invoke(["redaction", *extra], self.app)


class TestSetupRedaction_Status(_RedactionBase):
    """``status`` must surface both the config flag and env override."""

    def test_default_state_reports_redaction_on(self):
        result = self._run("status")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("ON (redacted)", result.output)
        # No env override set in test process — must show unset.
        self.assertIn("(unset)", result.output)
        # Status must not write or restart.
        self.assertEqual(self.save_calls, 0)

    def test_config_off_reports_off(self):
        self.app.cfg.privacy.disable_redaction = True
        result = self._run("status")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("OFF (raw passthrough)", result.output)
        self.assertEqual(self.save_calls, 0)

    def test_env_override_reports_set_value(self):
        # Even with config ON, an env override must be visible so an
        # operator debugging "why is the audit DB plaintext?" can
        # spot the override at a glance.
        with patch.dict(os.environ, {"DEFENSECLAW_DISABLE_REDACTION": "1"}, clear=False):
            result = self._run("status")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("set (1)", result.output)
        self.assertIn("OFF — raw content will be persisted to ALL sinks", result.output)


class TestSetupRedaction_Off(_RedactionBase):
    """``off`` flips the flag only after explicit consent / --yes."""

    def test_off_with_yes_persists_and_restarts(self):
        self.assertFalse(self.app.cfg.privacy.disable_redaction)
        result = self._run("off", "--yes")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(self.app.cfg.privacy.disable_redaction)
        self.assertEqual(self.save_calls, 1)
        self.assertIn("set to True", result.output)
        self.assertIn("Restarting gateway", result.output)

    def test_off_without_yes_aborts_without_save(self):
        # When stdin is empty / non-tty, click.confirm with abort=True
        # raises Abort → exit code 1, no save.
        runner = CliRunner()
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services",
            return_value=None,
        ):
            result = runner.invoke(
                setup_group, ["redaction", "off"],
                obj=self.app, input="\n", catch_exceptions=False,
            )
        self.assertNotEqual(result.exit_code, 0)
        self.assertFalse(self.app.cfg.privacy.disable_redaction)
        self.assertEqual(self.save_calls, 0)

    def test_off_no_restart_skips_gateway_bounce(self):
        result = self._run("off", "--yes", "--no-restart")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(self.app.cfg.privacy.disable_redaction)
        self.assertIn("Skipped restart", result.output)
        self.assertEqual(self.save_calls, 1)

    def test_off_when_already_off_is_noop(self):
        self.app.cfg.privacy.disable_redaction = True
        result = self._run("off", "--yes")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("already OFF", result.output)
        self.assertEqual(self.save_calls, 0, "no-op must not rewrite config")


class TestSetupRedaction_On(_RedactionBase):
    """``on`` flips the flag back to redacting state without prompt."""

    def test_on_when_off_persists_and_restarts(self):
        self.app.cfg.privacy.disable_redaction = True
        result = self._run("on")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(self.app.cfg.privacy.disable_redaction)
        self.assertEqual(self.save_calls, 1)
        self.assertIn("ON (redacted)", result.output)

    def test_on_when_already_on_is_noop(self):
        self.assertFalse(self.app.cfg.privacy.disable_redaction)
        result = self._run("on")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("already ON", result.output)
        self.assertEqual(self.save_calls, 0)

    def test_on_does_not_require_consent_prompt(self):
        # Turning redaction back ON is the safe direction; no prompt
        # required even without --yes. The command also must not
        # block on stdin in a non-tty CI runner.
        self.app.cfg.privacy.disable_redaction = True
        result = self._run("on")  # no --yes
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(self.app.cfg.privacy.disable_redaction)


class TestSetupRedaction_ConfigRoundTrip(unittest.TestCase):
    """The privacy block must round-trip through YAML so the choice
    survives a load → save → reload cycle. Without this, a setup
    redaction command appears to succeed but the next sidecar boot
    silently re-enables redaction because the YAML never carried
    the flag.
    """

    def test_disable_true_roundtrips_through_yaml(self):
        from defenseclaw.config import (
            Config, PrivacyConfig, _config_to_dict, _merge_privacy,
        )

        cfg = Config()
        cfg.privacy = PrivacyConfig(disable_redaction=True)
        d = _config_to_dict(cfg)
        # The non-default value MUST appear in the serialized dict.
        self.assertIn("privacy", d)
        self.assertTrue(d["privacy"]["disable_redaction"])

        # Reload via _merge_privacy should reproduce the value.
        rebuilt = _merge_privacy(d["privacy"])
        self.assertTrue(rebuilt.disable_redaction)

    def test_default_block_is_stripped_for_yaml_minimalism(self):
        # The omitempty contract: when the privacy block carries
        # only defaults, the YAML must NOT contain it. Otherwise
        # every round-tripped config grows a privacy block and
        # diff'ing existing configs against the docs becomes noisy.
        from defenseclaw.config import Config, _config_to_dict

        cfg = Config()  # default PrivacyConfig
        d = _config_to_dict(cfg)
        self.assertNotIn("privacy", d, "default privacy block must be stripped")


if __name__ == "__main__":
    unittest.main()
