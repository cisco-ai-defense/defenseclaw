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

"""Tests for ``defenseclaw setup notifications-set`` and
``defenseclaw setup registry``.

The two commands cover the "tweak notification scope without flipping
the master switch" and "drop into the registry wizard from the setup
group" UX gaps surfaced during the registries+notifications review.
Both wrap existing primitives, so the tests focus on the integration
points: argument parsing, config-mutation correctness for every
slot, the master-switch warning, and the wizard delegation path.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner  # noqa: E402,I001
from defenseclaw.commands.cmd_setup import setup as setup_group  # noqa: E402,I001
from defenseclaw.logger import CanonicalObservabilityUnavailableError  # noqa: E402,I001
from tests.helpers import cleanup_app, make_app_context  # noqa: E402,I001


class _NotificationsSetBase(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        # The CLI calls cfg.save() — point at a real path so the
        # write succeeds, but we don't actually care about the
        # bytes on disk for these tests.
        self.app.cfg.config_path = os.path.join(self.tmp_dir, "config.yaml")
        self.app.cfg.save()
        # Default master switch so platform-specific defaults don't
        # cloud the warn-message assertion.
        self.app.cfg.notifications.enabled = True

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _run(self, *args):
        runner = CliRunner()
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services",
            return_value=None,
        ):
            return runner.invoke(
                setup_group, list(args),
                obj=self.app, catch_exceptions=False,
            )


class TestNotificationsSetCategory(_NotificationsSetBase):
    """Categories live on the NotificationsConfig object directly.
    Flipping one must persist to the typed attribute and surface a
    confirmation in the output.
    """

    def test_set_block_enforced_off(self):
        self.app.cfg.notifications.block_enforced = True
        result = self._run(
            "notifications-set", "block_enforced", "off",
            "--no-restart",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(self.app.cfg.notifications.block_enforced)
        self.assertIn("notifications.block_enforced", result.output)

    def test_set_hitl_approval_on_idempotent(self):
        # The default is True; setting it to ``on`` must short-circuit
        # without surfacing a misleading "changed" message.
        self.app.cfg.notifications.hitl_approval = True
        result = self._run(
            "notifications-set", "hitl_approval", "on",
            "--no-restart",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("already on", result.output)

    def test_no_restart_allows_explicit_offline_staging(self):
        self.app.cfg.notifications.block_enforced = True
        self.app.logger = MagicMock()
        self.app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
        result = self._run(
            "notifications-set", "block_enforced", "off",
            "--no-restart",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(self.app.cfg.notifications.block_enforced)
        self.assertIn("canonical setup audit event was not recorded", result.output)


class TestNotificationsToggle(_NotificationsSetBase):
    def test_no_restart_allows_explicit_offline_staging(self):
        self.app.cfg.notifications.enabled = True
        self.app.logger = MagicMock()
        self.app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
        result = self._run("notifications", "off", "--yes", "--no-restart")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(self.app.cfg.notifications.enabled)
        self.assertIn("canonical setup audit event was not recorded", result.output)


class TestNotificationsSetSource(_NotificationsSetBase):
    """Sources live under the nested ``sources`` filter struct. The
    dotted form (``sources.hook``) and the friendlier short alias
    (``hook``) must both land on the same attribute so an operator
    copying from ``status`` output and an operator typing the short
    form get the same outcome.
    """

    def test_dotted_form_flips_source(self):
        self.app.cfg.notifications.sources.hook = True
        result = self._run(
            "notifications-set", "sources.hook", "off",
            "--no-restart",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(self.app.cfg.notifications.sources.hook)

    def test_short_form_flips_source(self):
        self.app.cfg.notifications.sources.guardrail = True
        result = self._run(
            "notifications-set", "guardrail", "off",
            "--no-restart",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(self.app.cfg.notifications.sources.guardrail)

    def test_asset_policy_short_form(self):
        self.app.cfg.notifications.sources.asset_policy = True
        result = self._run(
            "notifications-set", "asset_policy", "off",
            "--no-restart",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(self.app.cfg.notifications.sources.asset_policy)


class TestNotificationsSetMasterSwitchWarning(_NotificationsSetBase):
    def test_warns_when_master_off(self):
        self.app.cfg.notifications.enabled = False
        result = self._run(
            "notifications-set", "hook", "off",
            "--no-restart",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        # Operator-friendly hint that the change is invisible until
        # they flip the master switch back on.
        self.assertIn("notifications.enabled is OFF", result.output)


class TestNotificationsSetUnknownSlot(_NotificationsSetBase):
    def test_unknown_slot_rejected_by_choice(self):
        # click's Choice catches typos before our handler runs so the
        # error message lists the legal values.
        runner = CliRunner()
        result = runner.invoke(
            setup_group,
            ["notifications-set", "made_up", "on", "--no-restart"],
            obj=self.app, catch_exceptions=True,
        )
        self.assertNotEqual(result.exit_code, 0)


class TestSetupRegistryWizard(_NotificationsSetBase):
    """``setup registry`` wraps ``registry wizard`` so first-run
    operators discover registries inside the setup help. We don't
    drive the interactive wizard here; we just confirm the
    delegation lands on the underlying command and produces the
    expected non-TTY error.
    """

    def test_setup_registry_delegates_to_wizard(self):
        # Wizard refuses non-TTY input — perfect smoke for delegation:
        # if the wrapper is wired wrong the test would see a click
        # ``no such command`` error instead.
        with patch("defenseclaw.commands.cmd_registry.sys.stdin") as stdin:
            stdin.isatty.return_value = False
            result = self._run("registry")
        self.assertNotEqual(result.exit_code, 0, result.output)
        self.assertIn("interactive terminal", result.output)


if __name__ == "__main__":
    unittest.main()
