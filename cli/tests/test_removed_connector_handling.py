# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Connector names this build does not ship must never strand an operator.

An older release may have registered a connector that a later release no
longer ships. ``setup remove`` and ``uninstall`` must drop it without guessing
at that agent's config files. The name used here is made up on purpose.
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands import cmd_setup, cmd_uninstall
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.config import PerConnectorGuardrailConfig

from tests.helpers import cleanup_app, make_app_context

RETIRED_EXAMPLE = "retired-example"


def _invoke(args, app):
    return CliRunner().invoke(setup_group, args, obj=app, catch_exceptions=False)


class RemovedConnectorSetupTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_setup_remove_unknown_configured_connector(self):
        gc = self.app.cfg.guardrail
        gc.connectors = {
            "codex": PerConnectorGuardrailConfig(),
            RETIRED_EXAMPLE: PerConnectorGuardrailConfig(),
        }
        gc.connector = "codex"
        self.app.cfg.claw.mode = "codex"
        runtime = cmd_setup._SetupAppliedRuntimeEvidence(
            lifecycle="running",
            generation="generation-before",
            invariants=(),
        )
        with (
            patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True) as bounce,
            patch("defenseclaw.commands.cmd_setup._capture_setup_applied_runtime", return_value=runtime),
        ):
            result = _invoke(["remove", RETIRED_EXAMPLE, "--yes", "--no-restart"], self.app)

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(set(gc.connectors), {"codex"})
        self.assertEqual(gc.connector, "codex")
        self.assertIn("not a connector this DefenseClaw build ships", result.output)
        self.assertIn("Renamed and removed connectors", result.output)
        bounce.assert_not_called()

        self.assertIn("drops the removed connector's DefenseClaw state", result.output)
        self.assertNotIn("hooks are still installed", result.output)

        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            saved = fh.read()
        self.assertNotIn(RETIRED_EXAMPLE, saved)

    def test_setup_remove_last_unknown_connector_needs_no_force(self):
        gc = self.app.cfg.guardrail
        gc.connectors = {RETIRED_EXAMPLE: PerConnectorGuardrailConfig()}
        gc.connector = RETIRED_EXAMPLE
        self.app.cfg.claw.mode = RETIRED_EXAMPLE
        with patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True) as bounce:
            result = _invoke(["remove", RETIRED_EXAMPLE, "--yes", "--no-restart"], self.app)

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotIn("Refusing to remove the last connector", result.output)
        self.assertEqual(gc.connectors, {})
        self.assertEqual(gc.connector, "")
        self.assertEqual(self.app.cfg.claw.mode, "")
        bounce.assert_not_called()

    def test_setup_remove_last_shipped_connector_still_needs_force(self):
        gc = self.app.cfg.guardrail
        gc.connectors = {"codex": PerConnectorGuardrailConfig()}
        gc.connector = "codex"
        self.app.cfg.claw.mode = "codex"
        result = CliRunner().invoke(setup_group, ["remove", "codex", "--yes", "--no-restart"], obj=self.app)

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Refusing to remove the last connector", result.output)
        self.assertEqual(set(gc.connectors), {"codex"})


class RemovedConnectorUninstallTests(unittest.TestCase):
    def _plan(self) -> cmd_uninstall.UninstallPlan:
        return cmd_uninstall.UninstallPlan(
            connector="codex",
            connectors=(RETIRED_EXAMPLE, "codex"),
            data_dir="/tmp/dc",
            openclaw_config_file="/tmp/openclaw.json",
            openclaw_home="/tmp/.openclaw",
        )

    def test_uninstall_continues_past_unknown_connector(self):
        def teardown(name, **_kwargs):
            return name == "codex"

        with (
            patch.object(cmd_uninstall, "_gateway_supports_connector_teardown", return_value=True),
            patch.object(cmd_uninstall, "_run_gateway_connector_teardown", side_effect=teardown) as run_mock,
            patch.object(cmd_uninstall, "_gateway_connector_is_unknown", return_value=True) as unknown,
            patch.object(cmd_uninstall.ux, "warn") as warn,
        ):
            cmd_uninstall._connector_teardown(self._plan())

        self.assertEqual([c.args[0] for c in run_mock.call_args_list], [RETIRED_EXAMPLE, "codex"])
        unknown.assert_called_once()
        self.assertEqual(unknown.call_args.args[0], RETIRED_EXAMPLE)
        self.assertTrue(
            any("not a connector this DefenseClaw build ships" in str(c.args[0]) for c in warn.call_args_list)
        )

    def test_uninstall_still_aborts_when_a_shipped_connector_fails(self):
        import click

        with (
            patch.object(cmd_uninstall, "_gateway_supports_connector_teardown", return_value=True),
            patch.object(cmd_uninstall, "_run_gateway_connector_teardown", return_value=False),
            patch.object(cmd_uninstall, "_gateway_connector_is_unknown", return_value=False),
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_uninstall._connector_teardown(self._plan())
        self.assertIn("aborting uninstall", str(raised.exception))

    def test_unknown_probe_requires_the_gateway_unknown_verdict(self):
        class Completed:
            def __init__(self, returncode, stderr):
                self.returncode = returncode
                self.stdout = ""
                self.stderr = stderr

        cases = [
            (Completed(2, 'connector verify: unknown connector "retired-example" (known: codex)\n'), True),
            (Completed(1, "residue\n"), False),
            (Completed(2, "some other config error\n"), False),
        ]
        for completed, want in cases:
            with (
                patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"),
                patch("subprocess.run", return_value=completed) as run_mock,
            ):
                self.assertIs(cmd_uninstall._gateway_connector_is_unknown(RETIRED_EXAMPLE), want)
            argv = run_mock.call_args.args[0]
            self.assertEqual(argv[1:5], ["connector", "verify", "--connector", RETIRED_EXAMPLE])
        with patch("shutil.which", return_value=None):
            self.assertFalse(cmd_uninstall._gateway_connector_is_unknown(RETIRED_EXAMPLE))


if __name__ == "__main__":
    unittest.main()
