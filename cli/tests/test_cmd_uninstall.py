# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw uninstall`` / ``reset``.

We focus on the planning surface (``_build_plan`` + ``--dry-run``) rather
than actual destructive removals — the latter are covered indirectly via
the helpers they call (gateway stop, openclaw revert), which have their
own tests elsewhere.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_uninstall


class BuildPlanTests(unittest.TestCase):
    def test_defaults_preserve_data_and_binaries(self):
        plan = cmd_uninstall._build_plan(
            wipe_data=False,
            binaries=False,
            revert_openclaw=True,
            remove_plugin=True,
        )
        self.assertFalse(plan.remove_data_dir)
        self.assertFalse(plan.remove_binaries)
        self.assertTrue(plan.revert_openclaw)
        self.assertTrue(plan.remove_plugin)
        # Defaults should always fill in data_dir / openclaw paths so
        # renderers never hit an empty string.
        self.assertTrue(plan.data_dir)
        self.assertTrue(plan.openclaw_config_file)

    def test_keep_openclaw_leaves_plugin_alone(self):
        plan = cmd_uninstall._build_plan(
            wipe_data=True,
            binaries=True,
            revert_openclaw=False,
            remove_plugin=False,
        )
        self.assertTrue(plan.remove_data_dir)
        self.assertTrue(plan.remove_binaries)
        self.assertFalse(plan.revert_openclaw)
        self.assertFalse(plan.remove_plugin)


class UninstallCommandTests(unittest.TestCase):
    def test_dry_run_does_not_execute(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_uninstall._execute_plan") as exec_mock:
            result = runner.invoke(
                cmd_uninstall.uninstall_cmd,
                ["--dry-run"],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn("dry-run", result.output)
            exec_mock.assert_not_called()

    def test_confirmation_declined_aborts(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_uninstall._execute_plan") as exec_mock:
            result = runner.invoke(
                cmd_uninstall.uninstall_cmd,
                [],
                input="n\n",
            )
            self.assertNotEqual(result.exit_code, 0)
            exec_mock.assert_not_called()
            self.assertIn("Cancelled", result.output)

    def test_yes_flag_skips_prompt(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_uninstall._execute_plan") as exec_mock:
            result = runner.invoke(
                cmd_uninstall.uninstall_cmd,
                ["--yes"],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            exec_mock.assert_called_once()

    def test_stop_gateway_uses_resolver_path(self):
        with patch(
            "defenseclaw.commands.cmd_uninstall.resolve_gateway_binary",
            return_value="/custom/defenseclaw-gateway",
        ), patch(
            "defenseclaw.commands.cmd_uninstall.subprocess.run",
        ) as run_mock:
            cmd_uninstall._stop_gateway()

        run_mock.assert_called_once()
        self.assertEqual(
            run_mock.call_args.args[0],
            ["/custom/defenseclaw-gateway", "stop"],
        )

    def test_stop_gateway_skips_when_binary_missing(self):
        with patch(
            "defenseclaw.commands.cmd_uninstall.resolve_gateway_binary",
            return_value=None,
        ), patch(
            "defenseclaw.commands.cmd_uninstall.subprocess.run",
        ) as run_mock:
            cmd_uninstall._stop_gateway()

        run_mock.assert_not_called()


class ResetCommandTests(unittest.TestCase):
    def test_reset_yes_executes_plan_with_wipe_and_keep_plugin(self):
        runner = CliRunner()
        captured = {}

        def fake_execute(plan):
            captured["plan"] = plan

        with patch("defenseclaw.commands.cmd_uninstall._execute_plan",
                   side_effect=fake_execute):
            result = runner.invoke(cmd_uninstall.reset_cmd, ["--yes"])
            self.assertEqual(result.exit_code, 0, msg=result.output)
            plan = captured["plan"]
            # reset = wipe data + keep plugin, don't touch binaries.
            self.assertTrue(plan.remove_data_dir)
            self.assertFalse(plan.remove_plugin)
            self.assertFalse(plan.remove_binaries)


if __name__ == "__main__":
    unittest.main()
