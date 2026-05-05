# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw guardrail {enable,disable,status}``.

These commands are connector-agnostic: every code path that *modifies*
state (config save, gateway restart) must work with all 4 built-in
connectors and never silently corrupt config for a non-OpenClaw
connector.
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_guardrail
from defenseclaw.context import AppContext


def make_ctx(*, enabled: bool = True, connector: str = "openclaw",
             model: str = "openai/gpt-4o", llm_model: str = "",
             hook_fail_mode: str = "open"):
    """Build a minimal AppContext that the guardrail commands can drive.

    ``hook_fail_mode`` mirrors the v3 ``guardrail.hook_fail_mode`` field
    (defaults to "open" so fixtures without explicit fail-mode wiring
    behave like a fresh, user-friendly install).
    """
    guardrail_cfg = SimpleNamespace(
        enabled=enabled,
        connector=connector,
        mode="observe",
        port=4000,
        model=model,
        hook_fail_mode=hook_fail_mode,
    )
    cfg = SimpleNamespace(
        guardrail=guardrail_cfg,
        data_dir="/tmp/dc",
        gateway=SimpleNamespace(host="127.0.0.1", port=18789),
        llm=SimpleNamespace(model=llm_model, api_key_env=""),
    )

    def active_connector():
        return guardrail_cfg.connector

    cfg.active_connector = active_connector
    cfg.save = MagicMock()

    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    app.logger.log_action = MagicMock()
    return app


class ResolveActiveConnectorTests(unittest.TestCase):
    def test_uses_active_connector_method(self):
        cfg = SimpleNamespace()
        cfg.active_connector = lambda: "Codex"
        self.assertEqual(cmd_guardrail._resolve_active_connector(cfg), "codex")

    def test_falls_back_to_guardrail_connector(self):
        cfg = SimpleNamespace()
        cfg.guardrail = SimpleNamespace(connector="claudecode")
        self.assertEqual(cmd_guardrail._resolve_active_connector(cfg), "claudecode")

    def test_method_exception_falls_back(self):
        cfg = SimpleNamespace()
        cfg.guardrail = SimpleNamespace(connector="zeptoclaw")
        cfg.active_connector = lambda: (_ for _ in ()).throw(RuntimeError("x"))
        self.assertEqual(cmd_guardrail._resolve_active_connector(cfg), "zeptoclaw")

    def test_none_cfg_defaults_to_openclaw(self):
        self.assertEqual(cmd_guardrail._resolve_active_connector(None), "openclaw")


class StatusCommandTests(unittest.TestCase):
    def test_status_enabled_openclaw(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="openclaw")
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("enabled:    yes", result.output)
        self.assertIn("OpenClaw (openclaw)", result.output)
        self.assertIn("disable", result.output)

    def test_status_disabled_codex(self):
        runner = CliRunner()
        app = make_ctx(enabled=False, connector="codex")
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("enabled:    no", result.output)
        self.assertIn("Codex (codex)", result.output)
        self.assertIn("Enable with", result.output)

    def test_status_surfaces_hook_fail_mode(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="openclaw", hook_fail_mode="closed")
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # The fail mode is the most-asked-about UX knob now that hooks
        # default open: status MUST surface it so operators can sanity-
        # check their posture without grep-ing config.yaml.
        self.assertIn("fail mode:  closed", result.output)


class FailModeCommandTests(unittest.TestCase):
    def test_show_current_value_open(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, hook_fail_mode="open")
        result = runner.invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("guardrail.hook_fail_mode: open", result.output)
        # Must explain the on-call-friendly behavior so an operator
        # reading the output understands what "open" means without
        # leaving the terminal.
        self.assertIn("ALLOW", result.output)
        app.cfg.save.assert_not_called()

    def test_show_current_value_closed(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, hook_fail_mode="closed")
        result = runner.invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("guardrail.hook_fail_mode: closed", result.output)
        self.assertIn("BLOCK", result.output)

    def test_set_open_to_closed_persists_and_restarts(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="codex", hook_fail_mode="open")
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.hook_fail_mode, "closed")
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        # Active connector must propagate so hooks for the right
        # connector get rewritten.
        kwargs = restart_mock.call_args.kwargs
        self.assertEqual(kwargs.get("connector"), "codex")

    def test_set_same_value_is_noop(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, hook_fail_mode="closed")
        result = runner.invoke(
            cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("already 'closed'", result.output)
        app.cfg.save.assert_not_called()

    def test_set_with_no_restart_skips_gateway(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, hook_fail_mode="open")
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd,
                ["closed", "--yes", "--no-restart"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.hook_fail_mode, "closed")
        restart_mock.assert_not_called()

    def test_set_when_guardrail_disabled_persists_without_restart(self):
        """Operator can pre-stage a fail-mode choice while the
        guardrail is disabled. The value persists; the actual hook
        scripts get regenerated whenever the operator re-enables the
        guardrail."""
        runner = CliRunner()
        app = make_ctx(enabled=False, hook_fail_mode="open")
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.hook_fail_mode, "closed")
        # Restart was skipped because guardrail is disabled — the
        # config write is the value-add here, not the gateway bounce.
        restart_mock.assert_not_called()
        self.assertIn("currently disabled", result.output)

    def test_set_save_failure_aborts(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, hook_fail_mode="open")
        app.cfg.save.side_effect = OSError("disk full")
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app
            )
        self.assertNotEqual(result.exit_code, 0)
        # Config write failed → must NOT restart the gateway, or the
        # sidecar would re-render hooks from the on-disk old value
        # while we believe we just changed it.
        restart_mock.assert_not_called()

    def test_set_declined_aborts(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, hook_fail_mode="open")
        result = runner.invoke(
            cmd_guardrail.fail_mode_cmd, ["closed"], input="n\n", obj=app
        )
        self.assertNotEqual(result.exit_code, 0)
        # Must not have flipped or saved.
        self.assertEqual(app.cfg.guardrail.hook_fail_mode, "open")
        app.cfg.save.assert_not_called()


class DisableCommandTests(unittest.TestCase):
    def test_disable_already_disabled(self):
        runner = CliRunner()
        app = make_ctx(enabled=False, connector="codex")
        result = runner.invoke(cmd_guardrail.disable_cmd, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("already disabled", result.output)
        app.cfg.save.assert_not_called()

    def test_disable_persists_and_restarts_for_codex(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="codex")
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services"
        ) as restart_mock:
            result = runner.invoke(cmd_guardrail.disable_cmd, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(app.cfg.guardrail.enabled)
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        # Restart must propagate the active connector — otherwise the
        # gateway would teardown the wrong adapter.
        kwargs = restart_mock.call_args.kwargs
        self.assertEqual(kwargs.get("connector"), "codex")
        app.logger.log_action.assert_called_once()

    def test_disable_no_restart_skips_gateway_call(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="claudecode")
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services"
        ) as restart_mock:
            result = runner.invoke(
                cmd_guardrail.disable_cmd, ["--yes", "--no-restart"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(app.cfg.guardrail.enabled)
        restart_mock.assert_not_called()
        self.assertIn("--no-restart", result.output)

    def test_disable_save_failure_aborts(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="zeptoclaw")
        app.cfg.save.side_effect = OSError("disk full")
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services"
        ) as restart_mock:
            result = runner.invoke(cmd_guardrail.disable_cmd, ["--yes"], obj=app)
        self.assertNotEqual(result.exit_code, 0)
        # When config save fails we must NOT restart the gateway, or
        # the sidecar will see stale config and tear down a connector
        # the operator hasn't actually disabled yet.
        restart_mock.assert_not_called()

    def test_disable_declined_aborts(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="openclaw")
        result = runner.invoke(cmd_guardrail.disable_cmd, [], input="n\n", obj=app)
        self.assertNotEqual(result.exit_code, 0)
        # Must not have flipped enabled or saved.
        self.assertTrue(app.cfg.guardrail.enabled)
        app.cfg.save.assert_not_called()


class EnableCommandTests(unittest.TestCase):
    def test_enable_already_enabled(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="codex")
        result = runner.invoke(cmd_guardrail.enable_cmd, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("already enabled", result.output)
        app.cfg.save.assert_not_called()

    def test_enable_persists_and_restarts(self):
        runner = CliRunner()
        app = make_ctx(enabled=False, connector="codex")
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services"
        ) as restart_mock:
            result = runner.invoke(cmd_guardrail.enable_cmd, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(app.cfg.guardrail.enabled)
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        kwargs = restart_mock.call_args.kwargs
        self.assertEqual(kwargs.get("connector"), "codex")

    def test_enable_aborts_when_no_model_configured(self):
        runner = CliRunner()
        app = make_ctx(enabled=False, connector="openclaw", model="", llm_model="")
        result = runner.invoke(cmd_guardrail.enable_cmd, ["--yes"], obj=app)
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("guardrail.model is not set", result.output)
        # Must NOT silently flip enabled to True.
        self.assertFalse(app.cfg.guardrail.enabled)
        app.cfg.save.assert_not_called()

    def test_enable_uses_top_level_llm_model_as_fallback(self):
        runner = CliRunner()
        app = make_ctx(enabled=False, connector="codex", model="", llm_model="openai/gpt-4o")
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
            result = runner.invoke(cmd_guardrail.enable_cmd, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(app.cfg.guardrail.enabled)


class CommandRegistrationTests(unittest.TestCase):
    def test_guardrail_group_exposes_subcommands(self):
        names = set(cmd_guardrail.guardrail.commands.keys())
        # status / enable / disable are the day-1 lifecycle controls;
        # fail-mode was added in v3 to let operators flip response-
        # layer fail behavior without re-running the full setup
        # wizard. Keep this assertion exact so accidental command
        # removal (e.g. a careless `del`) is caught immediately.
        self.assertEqual(names, {"enable", "disable", "status", "fail-mode"})


if __name__ == "__main__":
    unittest.main()
