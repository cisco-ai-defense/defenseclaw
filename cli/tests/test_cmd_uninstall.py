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

import contextlib
import io
import os
import sys
import unittest
from unittest.mock import patch

from click.testing import CliRunner


@contextlib.contextmanager
def capture_click_output():
    """Capture click.echo output for direct (non-CliRunner) calls.

    click.echo writes to ``sys.stdout`` by default unless an explicit file
    is given, so swapping the stream is enough for our render-only
    assertions and avoids the version-skew between CliRunner.isolation()
    return shapes (Click 8.0 returns (stdout, stderr); Click 8.1+ adds
    a third element).
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        yield buf

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_uninstall  # noqa: E402


class BuildPlanTests(unittest.TestCase):
    def test_defaults_preserve_data_and_binaries(self):
        plan = cmd_uninstall._build_plan(
            wipe_data=False,
            binaries=False,
            remove_plugin=True,
        )
        self.assertFalse(plan.remove_data_dir)
        self.assertFalse(plan.remove_binaries)
        self.assertTrue(plan.remove_plugin)
        self.assertEqual(
            plan.connectors,
            ("openclaw", "codex", "claudecode", "zeptoclaw"),
        )
        # Defaults should always fill in data_dir / openclaw paths so
        # renderers never hit an empty string.
        self.assertTrue(plan.data_dir)
        self.assertTrue(plan.openclaw_config_file)

    def test_all_and_binaries_do_not_change_connector_teardown_set(self):
        plan = cmd_uninstall._build_plan(
            wipe_data=True,
            binaries=True,
            remove_plugin=True,
        )
        self.assertTrue(plan.remove_data_dir)
        self.assertTrue(plan.remove_binaries)
        self.assertTrue(plan.remove_plugin)
        self.assertEqual(
            plan.connectors,
            ("openclaw", "codex", "claudecode", "zeptoclaw"),
        )


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


class ResetCommandTests(unittest.TestCase):
    def test_reset_yes_executes_plan_with_wipe_and_connector_teardown(self):
        runner = CliRunner()
        captured = {}

        def fake_execute(plan):
            captured["plan"] = plan

        with patch("defenseclaw.commands.cmd_uninstall._execute_plan",
                   side_effect=fake_execute):
            result = runner.invoke(cmd_uninstall.reset_cmd, ["--yes"])
            self.assertEqual(result.exit_code, 0, msg=result.output)
            plan = captured["plan"]
            # reset = wipe data + connector teardown, don't touch binaries.
            self.assertTrue(plan.remove_data_dir)
            self.assertTrue(plan.remove_plugin)
            self.assertFalse(plan.remove_binaries)


class ResolveActiveConnectorTests(unittest.TestCase):
    def test_uses_active_connector_method(self):
        class Cfg:
            def active_connector(self):
                return "Codex"
        self.assertEqual(cmd_uninstall._resolve_active_connector(Cfg()), "codex")

    def test_falls_back_to_guardrail_connector(self):
        class Guardrail:
            connector = "claudecode"
        class Cfg:
            guardrail = Guardrail()
        self.assertEqual(cmd_uninstall._resolve_active_connector(Cfg()), "claudecode")

    def test_method_exception_falls_back(self):
        class Guardrail:
            connector = "zeptoclaw"
        class Cfg:
            guardrail = Guardrail()
            def active_connector(self):
                raise RuntimeError("boom")
        self.assertEqual(cmd_uninstall._resolve_active_connector(Cfg()), "zeptoclaw")

    def test_none_cfg_defaults_to_openclaw(self):
        self.assertEqual(cmd_uninstall._resolve_active_connector(None), "openclaw")


class BuildPlanConnectorTests(unittest.TestCase):
    def test_plan_records_active_connector(self):
        class Guardrail:
            connector = "codex"
        class Claw:
            home_dir = "~/.codex"
            config_file = "~/.codex/config.toml"
        class Cfg:
            guardrail = Guardrail()
            claw = Claw()

        with patch("defenseclaw.commands.cmd_uninstall.config_module.load",
                   return_value=Cfg()):
            plan = cmd_uninstall._build_plan(
                wipe_data=False,
                binaries=False,
                remove_plugin=True,
            )
        self.assertEqual(plan.connector, "codex")
        self.assertEqual(
            plan.connectors,
            ("openclaw", "codex", "claudecode", "zeptoclaw"),
        )

    def test_safe_active_plugin_connector_is_appended(self):
        connectors = cmd_uninstall._planned_teardown_connectors("myplugin")
        self.assertEqual(
            connectors,
            ("openclaw", "codex", "claudecode", "zeptoclaw", "myplugin"),
        )

    def test_invalid_active_plugin_connector_is_skipped(self):
        connectors = cmd_uninstall._planned_teardown_connectors("bad connector")
        self.assertEqual(
            connectors,
            ("openclaw", "codex", "claudecode", "zeptoclaw"),
        )

    def test_plan_defaults_to_openclaw_when_load_fails(self):
        with patch("defenseclaw.commands.cmd_uninstall.config_module.load",
                   side_effect=Exception("boom")):
            plan = cmd_uninstall._build_plan(
                wipe_data=False,
                binaries=False,
                remove_plugin=True,
            )
        self.assertEqual(plan.connector, "openclaw")
        self.assertEqual(
            plan.connectors,
            ("openclaw", "codex", "claudecode", "zeptoclaw"),
        )


class RenderPlanConnectorTests(unittest.TestCase):
    def test_render_shows_connector_specific_line_for_codex(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="codex",
            connectors=("openclaw", "codex", "claudecode", "zeptoclaw"),
            data_dir="/tmp/dc",
        )
        with capture_click_output() as buf:
            cmd_uninstall._render_plan(plan, dry_run=True)
        text = buf.getvalue()
        self.assertIn("active connector:    codex", text)
        self.assertIn("teardown connectors: yes", text)
        self.assertIn("openclaw, codex, claudecode, zeptoclaw", text)
        self.assertIn("revert openclaw.json: yes", text)

    def test_render_shows_openclaw_revert_for_openclaw(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="openclaw",
            connectors=("openclaw",),
            data_dir="/tmp/dc",
            openclaw_config_file="/tmp/openclaw.json",
        )
        with capture_click_output() as buf:
            cmd_uninstall._render_plan(plan, dry_run=True)
        text = buf.getvalue()
        self.assertIn("revert openclaw.json", text)


class ConnectorTeardownDispatchTests(unittest.TestCase):
    def _plan(self, connector: str) -> cmd_uninstall.UninstallPlan:
        return cmd_uninstall.UninstallPlan(
            connector=connector,
            connectors=(connector,),
            data_dir="/tmp/dc",
            openclaw_config_file="/tmp/openclaw.json",
            openclaw_home="/tmp/.openclaw",
        )

    def test_uses_gateway_sentinel_when_supported(self):
        with patch.object(cmd_uninstall, "_gateway_supports_connector_teardown",
                          return_value=True), \
             patch.object(cmd_uninstall, "_run_gateway_connector_teardown",
                          return_value=True) as run_mock, \
             patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback:
            cmd_uninstall._connector_teardown(self._plan("codex"))
            run_mock.assert_called_once_with("codex")
            fallback.assert_not_called()

    def test_uses_gateway_sentinel_for_each_planned_connector(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="codex",
            connectors=("openclaw", "codex", "claudecode", "zeptoclaw"),
            data_dir="/tmp/dc",
            openclaw_config_file="/tmp/openclaw.json",
            openclaw_home="/tmp/.openclaw",
        )
        with patch.object(cmd_uninstall, "_gateway_supports_connector_teardown",
                          return_value=True), \
             patch.object(cmd_uninstall, "_run_gateway_connector_teardown",
                          return_value=True) as run_mock, \
             patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback:
            cmd_uninstall._connector_teardown(plan)
        self.assertEqual(
            [c.args[0] for c in run_mock.call_args_list],
            ["openclaw", "codex", "claudecode", "zeptoclaw"],
        )
        fallback.assert_not_called()

    def test_falls_back_to_python_for_openclaw_when_gateway_old(self):
        with patch.object(cmd_uninstall, "_gateway_supports_connector_teardown",
                          return_value=False), \
             patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback:
            cmd_uninstall._connector_teardown(self._plan("openclaw"))
            fallback.assert_called_once()

    def test_hard_fails_when_non_openclaw_and_gateway_old(self):
        with capture_click_output() as buf, \
             patch.object(cmd_uninstall, "_gateway_supports_connector_teardown",
                          return_value=False), \
             patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback:
            cmd_uninstall._connector_teardown(self._plan("codex"))
        text = buf.getvalue()
        fallback.assert_not_called()
        self.assertIn("no Python fallback", text)
        self.assertIn("codex", text)
        self.assertIn("connector teardown", text)

    def test_falls_back_when_gateway_sentinel_errors_for_openclaw(self):
        with patch.object(cmd_uninstall, "_gateway_supports_connector_teardown",
                          return_value=True), \
             patch.object(cmd_uninstall, "_run_gateway_connector_teardown",
                          return_value=False), \
             patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback:
            cmd_uninstall._connector_teardown(self._plan("openclaw"))
            fallback.assert_called_once()

    def test_does_not_fall_back_for_codex_when_sentinel_errors(self):
        with capture_click_output() as buf, \
             patch.object(cmd_uninstall, "_gateway_supports_connector_teardown",
                          return_value=True), \
             patch.object(cmd_uninstall, "_run_gateway_connector_teardown",
                          return_value=False), \
             patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback:
            cmd_uninstall._connector_teardown(self._plan("codex"))
        fallback.assert_not_called()
        self.assertIn("reported errors", buf.getvalue())


class GatewaySupportProbeTests(unittest.TestCase):
    def test_returns_false_when_gateway_missing(self):
        with patch("shutil.which", return_value=None):
            self.assertFalse(cmd_uninstall._gateway_supports_connector_teardown())

    def test_returns_true_for_modern_gateway(self):
        with patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"), \
             patch("subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0
            run_mock.return_value.stdout = (
                "Available Commands:\n  list-backups ...\n  teardown ...\n  verify ...\n"
            )
            run_mock.return_value.stderr = ""
            self.assertTrue(cmd_uninstall._gateway_supports_connector_teardown())

    def test_returns_false_when_help_lacks_subcommand(self):
        with patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"), \
             patch("subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0
            run_mock.return_value.stdout = "Usage:\n  defenseclaw-gateway [command]\n"
            run_mock.return_value.stderr = ""
            self.assertFalse(cmd_uninstall._gateway_supports_connector_teardown())

    def test_returns_false_when_help_exits_nonzero(self):
        with patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"), \
             patch("subprocess.run") as run_mock:
            run_mock.return_value.returncode = 1
            run_mock.return_value.stdout = ""
            run_mock.return_value.stderr = "unknown command \"connector\""
            self.assertFalse(cmd_uninstall._gateway_supports_connector_teardown())

    def test_gateway_teardown_rejects_invalid_connector_name(self):
        with capture_click_output() as buf, \
             patch("subprocess.run") as run_mock:
            self.assertFalse(
                cmd_uninstall._run_gateway_connector_teardown("bad connector")
            )
        run_mock.assert_not_called()
        self.assertIn("refusing invalid connector name", buf.getvalue())


class ExecutePlanConnectorTests(unittest.TestCase):
    """Lock down the polymorphic _execute_plan ordering: stop → teardown
    → (openclaw plugin remove only when openclaw) → wipe → binaries.
    """

    def _common_patches(self):
        return [
            patch.object(cmd_uninstall, "_stop_gateway"),
            patch.object(cmd_uninstall, "_connector_teardown"),
            patch.object(cmd_uninstall, "_remove_plugin"),
            patch.object(cmd_uninstall, "_remove_data_dir"),
            patch.object(cmd_uninstall, "_remove_binaries"),
        ]

    def test_codex_skips_remove_plugin_step(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="codex",
            connectors=("codex",),
            data_dir="/tmp/dc",
        )
        ctx_mgrs = self._common_patches()
        try:
            mocks = [c.__enter__() for c in ctx_mgrs]
            stop_mock, teardown_mock, plugin_mock, wipe_mock, bin_mock = mocks
            cmd_uninstall._execute_plan(plan)
            stop_mock.assert_called_once()
            teardown_mock.assert_called_once_with(plan)
            plugin_mock.assert_not_called()
            wipe_mock.assert_not_called()
            bin_mock.assert_not_called()
        finally:
            for c in ctx_mgrs:
                c.__exit__(None, None, None)

    def test_openclaw_runs_remove_plugin_step(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="openclaw",
            connectors=("openclaw",),
            data_dir="/tmp/dc",
            remove_plugin=True,
        )
        ctx_mgrs = self._common_patches()
        try:
            mocks = [c.__enter__() for c in ctx_mgrs]
            _, teardown_mock, plugin_mock, _, _ = mocks
            cmd_uninstall._execute_plan(plan)
            teardown_mock.assert_called_once()
            plugin_mock.assert_called_once_with(plan)
        finally:
            for c in ctx_mgrs:
                c.__exit__(None, None, None)

    def test_all_connector_plan_runs_openclaw_plugin_step(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="codex",
            connectors=("openclaw", "codex", "claudecode", "zeptoclaw"),
            data_dir="/tmp/dc",
            remove_plugin=True,
        )
        ctx_mgrs = self._common_patches()
        try:
            mocks = [c.__enter__() for c in ctx_mgrs]
            _, teardown_mock, plugin_mock, _, _ = mocks
            cmd_uninstall._execute_plan(plan)
            teardown_mock.assert_called_once()
            plugin_mock.assert_called_once_with(plan)
        finally:
            for c in ctx_mgrs:
                c.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
