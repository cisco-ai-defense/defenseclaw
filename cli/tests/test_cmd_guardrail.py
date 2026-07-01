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
             hook_fail_mode: str = "closed"):
    """Build a minimal AppContext that the guardrail commands can drive.

    ``hook_fail_mode`` mirrors the v4 ``guardrail.hook_fail_mode`` field
    (defaults to "closed" so fixtures without explicit fail-mode wiring
    behave like a fresh, secure-by-default install — closes ). Tests that need to exercise the legacy fail-open path
    pass ``hook_fail_mode="open"`` explicitly.
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

    def test_resolve_member_connector_accepts_aliases(self):
        app = make_ctx(enabled=True, connector="codex")
        app.cfg.guardrail.connectors = {
            "claudecode": SimpleNamespace(),
            "openhands": SimpleNamespace(),
        }
        self.assertEqual(
            cmd_guardrail._resolve_member_connector(app, "claude-code"),
            "claudecode",
        )
        self.assertEqual(
            cmd_guardrail._resolve_member_connector(app, "open-hands"),
            "openhands",
        )


class StatusCommandTests(unittest.TestCase):
    def test_status_enabled_openclaw(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="openclaw")
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("enabled:    yes", result.output)
        self.assertIn("OpenClaw", result.output)
        self.assertIn("openclaw", result.output)
        self.assertIn("disable", result.output)

    def test_status_disabled_codex(self):
        runner = CliRunner()
        app = make_ctx(enabled=False, connector="codex")
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("enabled:    no", result.output)
        self.assertIn("Codex", result.output)
        self.assertIn("codex", result.output)
        self.assertIn("Enable with", result.output)

    def test_status_surfaces_hook_fail_mode(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="openclaw", hook_fail_mode="closed")
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # The fail mode is a key posture knob: status MUST surface it so
        # operators can sanity-check their posture without grep-ing
        # config.yaml. It is folded into the (uniform) per-connector
        # block as the Fail column.
        self.assertIn("Fail", result.output)
        self.assertIn("closed", result.output)

    def test_status_single_connector_uses_uniform_per_connector_block(self):
        # A single-connector install renders the SAME per-connector block
        # layout as a fan-out install: one connector roster table, no
        # redundant "connectors:" label plus table header.
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="openclaw")
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotIn("connectors:", result.output)
        # Uniform per-connector table: label + key + posture fields.
        self.assertIn("Connector", result.output)
        self.assertIn("Key", result.output)
        self.assertIn("OpenClaw", result.output)
        self.assertIn("openclaw", result.output)
        self.assertIn("observe", result.output)
        # Default fail mode is the safer "closed" (response-layer
        # failures block); see _normalize_hook_fail_mode / default_config.
        self.assertIn("closed", result.output)
        # The retired singular lines (and the "multi-connector"-only
        # footer hint) must NOT appear — there is exactly one rendering.
        self.assertNotIn("• connector:", result.output)
        self.assertNotIn("• mode:", result.output)
        self.assertNotIn("• fail mode:", result.output)
        self.assertNotIn("scan strategy:", result.output)
        self.assertNotIn("judge coverage:", result.output)
        self.assertNotIn("--connector", result.output)

    def test_status_multi_connector_uses_same_layout(self):
        # The fan-out install lists EVERY active connector with its own
        # effective mode / fail mode, using the identical layout as the
        # single-connector case — one block per connector, no count
        # banner, no "primary" line, no special footer.
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="codex")
        gc = app.cfg.guardrail
        gc.effective_mode = lambda name="": {"codex": "action", "claudecode": "observe"}.get(name, "observe")
        gc.effective_hook_fail_mode = lambda name="": "open"
        # Forcing active_connectors INSIDE the test method (setUp does not
        # reliably stick): two active connectors must both be listed.
        self.app = app  # keep a handle for parity with the harness idiom
        app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # Both connectors' blocks are present, each tagged by name.
        self.assertIn("Claude Code", result.output)
        self.assertIn("claudecode", result.output)
        self.assertIn("Codex", result.output)
        self.assertIn("codex", result.output)
        self.assertIn("action", result.output)
        self.assertIn("observe", result.output)
        # No count banner, no singular lines, no per-connector footer hint.
        self.assertNotIn("2 active", result.output)
        self.assertNotIn("• connector:", result.output)
        self.assertNotIn("• mode:", result.output)
        self.assertNotIn("• fail mode:", result.output)
        self.assertNotIn("scan strategy:", result.output)
        self.assertNotIn("judge coverage:", result.output)
        self.assertNotIn("--connector", result.output)

    def test_status_uses_stacked_connector_blocks_when_narrow(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="codex")
        app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        with patch("defenseclaw.commands.cmd_guardrail._terminal_width", return_value=60):
            result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("- Codex", result.output)
        self.assertIn("key:       codex", result.output)
        self.assertNotIn("connector: codex", result.output)
        self.assertIn("rule-pack:", result.output)
        self.assertIn("scan:", result.output)
        self.assertIn("judge:", result.output)


class GroupHelpTests(unittest.TestCase):
    def test_group_help_lists_policy_subcommands_and_connector(self):
        runner = CliRunner()
        result = runner.invoke(cmd_guardrail.guardrail, ["--help"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        for token in ("fail-mode", "hilt", "block-message", "--connector"):
            self.assertIn(token, result.output)


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

    def test_managed_disable_rejects_before_confirmation_prompt(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="codex")
        denial = PermissionError(
            "managed_enterprise config changes require operating-system "
            "administrator privileges"
        )
        with (
            patch.object(
                cmd_guardrail,
                "_assert_config_write_allowed",
                side_effect=denial,
            ),
            patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock,
        ):
            result = runner.invoke(cmd_guardrail.disable_cmd, [], obj=app)

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Failed to save config", result.output)
        self.assertIn("administrator privileges", result.output)
        self.assertNotIn("Proceed?", result.output)
        self.assertTrue(app.cfg.guardrail.enabled)
        app.cfg.save.assert_not_called()
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


def make_multi_ctx(connectors, *, enabled: bool = True):
    """AppContext whose guardrail is a real GuardrailConfig with a
    populated connectors map, so ``effective_enabled`` resolves correctly.

    ``connectors`` maps connector name -> enabled state, where ``None``
    means "present but unset" (inherits the default = enabled).
    """
    from defenseclaw import config as dcconfig

    gc = dcconfig.GuardrailConfig()
    gc.enabled = enabled
    gc.mode = "observe"
    gc.connector = ""
    gc.port = 4000
    gc.model = "openai/gpt-4o"
    gc.hook_fail_mode = "open"
    conns: dict[str, object] = {}
    for name, on in connectors.items():
        pc = dcconfig.PerConnectorGuardrailConfig()
        if on is not None:
            pc.enabled = on
        conns[name] = pc
    gc.connectors = conns

    cfg = SimpleNamespace(
        guardrail=gc,
        data_dir="/tmp/dc",
        gateway=SimpleNamespace(host="127.0.0.1", port=18789),
        llm=SimpleNamespace(model="", api_key_env=""),
    )
    cfg.active_connector = lambda: (sorted(conns)[0] if conns else "openclaw")
    cfg.active_connectors = lambda: (sorted(conns) if conns else ["openclaw"])
    cfg.save = MagicMock()

    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    app.logger.log_action = MagicMock()
    return app


class PerConnectorToggleTests(unittest.TestCase):
    """`guardrail {enable,disable} --connector X` — scoped per-connector."""

    def test_disable_one_connector_persists_and_restarts_only_it(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services"
        ) as restart_mock:
            result = runner.invoke(
                cmd_guardrail.disable_cmd, ["--connector", "codex", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # Only codex's flag flips; claudecode is untouched.
        self.assertFalse(app.cfg.guardrail.effective_enabled("codex"))
        self.assertTrue(app.cfg.guardrail.effective_enabled("claudecode"))
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        self.assertEqual(restart_mock.call_args.kwargs.get("connector"), "codex")

    def test_enable_one_connector_flips_back(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": False, "claudecode": None})
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
            result = runner.invoke(
                cmd_guardrail.enable_cmd, ["--connector", "codex", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(app.cfg.guardrail.effective_enabled("codex"))
        app.cfg.save.assert_called_once()

    def test_disable_already_disabled_is_noop(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": False, "claudecode": None})
        result = runner.invoke(
            cmd_guardrail.disable_cmd, ["--connector", "codex", "--yes"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("already disabled", result.output)
        app.cfg.save.assert_not_called()

    def test_managed_disable_one_connector_rejects_before_prompt(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        with patch.object(
            cmd_guardrail,
            "_assert_config_write_allowed",
            side_effect=PermissionError("administrator privileges required"),
        ):
            result = runner.invoke(
                cmd_guardrail.disable_cmd,
                ["--connector", "codex"],
                obj=app,
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("administrator privileges required", result.output)
        self.assertNotIn("Proceed?", result.output)
        self.assertTrue(app.cfg.guardrail.effective_enabled("codex"))
        app.cfg.save.assert_not_called()

    def test_case_insensitive_member_match(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
            result = runner.invoke(
                cmd_guardrail.disable_cmd, ["--connector", "CODEX", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(app.cfg.guardrail.effective_enabled("codex"))

    def test_connector_flag_rejected_on_single_connector_install(self):
        runner = CliRunner()
        app = make_multi_ctx({})  # empty connectors map = single-connector
        result = runner.invoke(
            cmd_guardrail.disable_cmd, ["--connector", "codex", "--yes"], obj=app
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("only valid on multi-connector", result.output)
        app.cfg.save.assert_not_called()

    def test_unknown_connector_rejected(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        result = runner.invoke(
            cmd_guardrail.disable_cmd, ["--connector", "windsurf", "--yes"], obj=app
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not configured", result.output)
        app.cfg.save.assert_not_called()

    def test_disabling_last_enabled_connector_warns(self):
        runner = CliRunner()
        # claudecode already off → codex is the only enabled one.
        app = make_multi_ctx({"codex": None, "claudecode": False})
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
            result = runner.invoke(
                cmd_guardrail.disable_cmd, ["--connector", "codex", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("only enabled connector", result.output)
        self.assertFalse(app.cfg.guardrail.effective_enabled("codex"))

    def test_no_restart_persists_but_skips_gateway(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services"
        ) as restart_mock:
            result = runner.invoke(
                cmd_guardrail.disable_cmd,
                ["--connector", "codex", "--yes", "--no-restart"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(app.cfg.guardrail.effective_enabled("codex"))
        restart_mock.assert_not_called()

    def test_global_disable_unchanged_without_flag(self):
        # The global kill switch must behave exactly as before when no
        # --connector is passed: flip guardrail.enabled, leave the
        # per-connector flags alone.
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None}, enabled=True)
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
            result = runner.invoke(cmd_guardrail.disable_cmd, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(app.cfg.guardrail.enabled)
        self.assertTrue(app.cfg.guardrail.effective_enabled("codex"))

    def test_global_disable_message_names_every_active_connector(self):
        # The global kill switch tears down EVERY active connector, so the
        # upfront message must name them all — not just the primary. Regression
        # for the single-connector-blind display (it printed only "codex").
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None}, enabled=True)
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
            result = runner.invoke(cmd_guardrail.disable_cmd, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Disabling guardrail for", result.output)
        self.assertIn("Claude Code (claudecode)", result.output)
        self.assertIn("Codex (codex)", result.output)

    def test_global_enable_message_names_every_active_connector(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None}, enabled=False)
        app.cfg.guardrail.model = "gpt-4o"
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
            result = runner.invoke(cmd_guardrail.enable_cmd, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Enabling guardrail for", result.output)
        self.assertIn("Claude Code (claudecode)", result.output)
        self.assertIn("Codex (codex)", result.output)

    def test_status_roster_shows_disabled_state(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": False, "claudecode": None})
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # Both connectors get their own block in the uniform roster, each
        # tagged by name with its own effective enabled state: codex was
        # turned off (disabled), claudecode inherits the default (enabled).
        self.assertIn("Codex", result.output)
        self.assertIn("codex", result.output)
        self.assertIn("Claude Code", result.output)
        self.assertIn("claudecode", result.output)
        self.assertIn("disabled", result.output)
        self.assertIn("enabled", result.output)

    def test_status_roster_shows_per_connector_rule_pack_and_hilt(self):
        # Each connector can scan against its OWN rule pack AND HILT policy; the
        # roster surfaces both. codex gets a custom pack + per-connector HILT;
        # claudecode inherits the defaults.
        from defenseclaw import config as dcconfig
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.connectors["codex"].rule_pack_dir = "/packs/strict"
        app.cfg.guardrail.connectors["codex"].hilt = dcconfig.HILTConfig(
            enabled=True, min_severity="LOW"
        )
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Rule pack", result.output)
        self.assertIn("strict", result.output)    # codex's own pack
        self.assertIn("default", result.output)   # claudecode inherits
        self.assertIn("on@LOW", result.output)    # codex's own HILT

    def test_status_global_disable_overrides_per_connector_enabled(self):
        # Regression: when the GLOBAL guardrail kill switch is off, no
        # connector may render a green "enabled" line — the gateway tears
        # every connector down, so the per-connector effective_enabled
        # (which only tracks individual overrides) must not contradict the
        # top-level "enabled: no". Both connectors should read as disabled
        # with an explicit "(guardrail off)" reason.
        runner = CliRunner()
        app = make_multi_ctx({"codex": True, "claudecode": None}, enabled=False)
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("enabled:    no", result.output)
        self.assertIn("Codex", result.output)
        self.assertIn("codex", result.output)
        self.assertIn("Claude Code", result.output)
        self.assertIn("claudecode", result.output)
        # The off-because-global reason is shown and NOT a bare green enabled.
        self.assertIn("disabled (guardrail off)", result.output)
        # Sanity: the roster must not render a standalone "enabled" state for
        # any connector while global is off (it would be misleading).
        for line in result.output.splitlines():
            if "codex" in line or "claudecode" in line:
                self.assertNotIn(" enabled ", line, msg=line)


class PerConnectorFailModeTests(unittest.TestCase):
    """`guardrail fail-mode [open|closed] --connector X` — scoped override."""

    def test_set_one_connector_closed_persists_and_restarts_only_it(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services"
        ) as restart_mock:
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd,
                ["closed", "--connector", "codex", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # Only codex gets the override; claudecode keeps the global default.
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("codex"), "closed")
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("claudecode"), "open")
        # Global default is untouched.
        self.assertEqual(app.cfg.guardrail.hook_fail_mode, "open")
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        self.assertEqual(restart_mock.call_args.kwargs.get("connector"), "codex")

    def test_show_per_connector_value_without_mode(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.connectors["codex"].hook_fail_mode = "closed"
        result = runner.invoke(
            cmd_guardrail.fail_mode_cmd, ["--connector", "codex"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("closed", result.output)
        self.assertIn("override", result.output)
        app.cfg.save.assert_not_called()

    def test_show_inherited_value_when_no_override(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        result = runner.invoke(
            cmd_guardrail.fail_mode_cmd, ["--connector", "claudecode"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("inherited", result.output)
        app.cfg.save.assert_not_called()

    def test_connector_flag_rejected_on_single_connector_install(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="codex")
        result = runner.invoke(
            cmd_guardrail.fail_mode_cmd,
            ["closed", "--connector", "codex", "--yes"],
            obj=app,
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("multi-connector", result.output)

    def test_unknown_connector_errors(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        result = runner.invoke(
            cmd_guardrail.fail_mode_cmd,
            ["closed", "--connector", "nope", "--yes"],
            obj=app,
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not configured", result.output)
        app.cfg.save.assert_not_called()

    def test_bare_set_fans_out_to_all_active_connectors(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.hook_fail_mode, "open")
        self.assertEqual(app.cfg.guardrail.connectors["codex"].hook_fail_mode, "closed")
        self.assertEqual(app.cfg.guardrail.connectors["claudecode"].hook_fail_mode, "closed")
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("codex"), "closed")
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("claudecode"), "closed")

    def test_bare_set_open_reconciles_closed_connector_override(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "geminicli": None})
        app.cfg.guardrail.hook_fail_mode = "open"
        app.cfg.guardrail.connectors["geminicli"].hook_fail_mode = "closed"
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd, ["open", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotIn("nothing to do", result.output)
        self.assertEqual(app.cfg.guardrail.connectors["codex"].hook_fail_mode, "open")
        self.assertEqual(app.cfg.guardrail.connectors["geminicli"].hook_fail_mode, "open")
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("geminicli"), "open")
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()

    def test_bare_show_fans_out_to_all_active_connectors(self):
        # No value AND no --connector: the bare read MUST show EVERY active
        # connector's effective fail mode (not just the global/active one),
        # so a 3-connector install shows all three.
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.connectors["codex"].hook_fail_mode = "closed"
        result = runner.invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("per connector", result.output)
        self.assertIn("(codex)", result.output)
        self.assertIn("(claudecode)", result.output)
        # codex carries a closed override; claudecode inherits the open global.
        self.assertIn("closed", result.output)
        app.cfg.save.assert_not_called()


class HILTCommandTests(unittest.TestCase):
    """`guardrail hilt [on|off] [--min-severity X] [--connector Y]`."""

    def test_show_global_when_no_args(self):
        runner = CliRunner()
        app = make_multi_ctx({})  # single-connector / global path
        app.cfg.guardrail.hilt.enabled = True
        app.cfg.guardrail.hilt.min_severity = "HIGH"
        result = runner.invoke(cmd_guardrail.hilt_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("min_severity", result.output)
        self.assertIn("HIGH", result.output)
        app.cfg.save.assert_not_called()

    def test_bare_show_fans_out_to_all_active_connectors(self):
        # Bare read on a multi-connector install MUST list each active
        # connector's effective HILT posture, not just the global default.
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.hilt.enabled = True
        app.cfg.guardrail.hilt.min_severity = "HIGH"
        result = runner.invoke(cmd_guardrail.hilt_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("per connector", result.output)
        self.assertIn("(codex)", result.output)
        self.assertIn("(claudecode)", result.output)
        app.cfg.save.assert_not_called()

    def test_set_global_on_with_min_severity(self):
        runner = CliRunner()
        app = make_multi_ctx({})
        app.cfg.guardrail.hilt.enabled = False
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, patch(
            "defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa"
        ) as sync_mock:
            result = runner.invoke(
                cmd_guardrail.hilt_cmd,
                ["on", "--min-severity", "MEDIUM", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(app.cfg.guardrail.hilt.enabled)
        self.assertEqual(app.cfg.guardrail.hilt.min_severity, "MEDIUM")
        app.cfg.save.assert_called_once()
        sync_mock.assert_called_once()
        restart_mock.assert_called_once()

    def test_partial_change_preserves_other_field(self):
        runner = CliRunner()
        app = make_multi_ctx({})
        app.cfg.guardrail.hilt.enabled = True
        app.cfg.guardrail.hilt.min_severity = "HIGH"
        with patch("defenseclaw.commands.cmd_setup._restart_services"), patch(
            "defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa"
        ):
            result = runner.invoke(
                cmd_guardrail.hilt_cmd, ["--min-severity", "LOW", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # enabled stays True; only severity changed.
        self.assertTrue(app.cfg.guardrail.hilt.enabled)
        self.assertEqual(app.cfg.guardrail.hilt.min_severity, "LOW")

    def test_noop_when_unchanged(self):
        runner = CliRunner()
        app = make_multi_ctx({})
        app.cfg.guardrail.hilt.enabled = True
        app.cfg.guardrail.hilt.min_severity = "HIGH"
        result = runner.invoke(
            cmd_guardrail.hilt_cmd, ["on", "--min-severity", "HIGH", "--yes"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("nothing to do", result.output)
        app.cfg.save.assert_not_called()

    def test_bare_set_on_fans_out_to_all_active_connectors(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "geminicli": None})
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, patch(
            "defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa"
        ) as sync_mock:
            result = runner.invoke(
                cmd_guardrail.hilt_cmd,
                ["on", "--min-severity", "MEDIUM", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(app.cfg.guardrail.hilt.enabled)
        for connector in ("codex", "geminicli"):
            eff = app.cfg.guardrail.effective_hilt(connector)
            self.assertTrue(eff.enabled)
            self.assertEqual(eff.min_severity, "MEDIUM")
        app.cfg.save.assert_called_once()
        sync_mock.assert_not_called()
        restart_mock.assert_called_once()

    def test_bare_set_off_reconciles_enabled_connector_override(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "geminicli": None})
        from defenseclaw import config as dcconfig

        app.cfg.guardrail.hilt.enabled = False
        app.cfg.guardrail.hilt.min_severity = "HIGH"
        app.cfg.guardrail.connectors["geminicli"].hilt = dcconfig.HILTConfig(
            enabled=True, min_severity="MEDIUM"
        )
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, patch(
            "defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa"
        ) as sync_mock:
            result = runner.invoke(cmd_guardrail.hilt_cmd, ["off", "--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotIn("nothing to do", result.output)
        for connector in ("codex", "geminicli"):
            eff = app.cfg.guardrail.effective_hilt(connector)
            self.assertFalse(eff.enabled)
        self.assertEqual(app.cfg.guardrail.connectors["geminicli"].hilt.min_severity, "MEDIUM")
        app.cfg.save.assert_called_once()
        sync_mock.assert_not_called()
        restart_mock.assert_called_once()

    def test_set_one_connector_persists_and_restarts_only_it(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services"
        ) as restart_mock:
            result = runner.invoke(
                cmd_guardrail.hilt_cmd,
                ["on", "--min-severity", "MEDIUM", "--connector", "codex", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        eff = app.cfg.guardrail.effective_hilt("codex")
        self.assertTrue(eff.enabled)
        self.assertEqual(eff.min_severity, "MEDIUM")
        # claudecode still inherits the (disabled-by-default) global block.
        self.assertIsNone(app.cfg.guardrail.connectors["claudecode"].hilt)
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        self.assertEqual(restart_mock.call_args.kwargs.get("connector"), "codex")
        # No OPA mirror for the per-connector path (data.json is global).

    def test_show_per_connector_override(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        from defenseclaw import config as dcconfig

        app.cfg.guardrail.connectors["codex"].hilt = dcconfig.HILTConfig(
            enabled=True, min_severity="LOW"
        )
        result = runner.invoke(
            cmd_guardrail.hilt_cmd, ["--connector", "codex"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("override", result.output)
        self.assertIn("LOW", result.output)
        app.cfg.save.assert_not_called()

    def test_show_inherited_per_connector(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        result = runner.invoke(
            cmd_guardrail.hilt_cmd, ["--connector", "claudecode"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("inherited", result.output)
        app.cfg.save.assert_not_called()

    def test_connector_flag_rejected_on_single_connector_install(self):
        runner = CliRunner()
        app = make_multi_ctx({})
        result = runner.invoke(
            cmd_guardrail.hilt_cmd,
            ["on", "--connector", "codex", "--yes"],
            obj=app,
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("multi-connector", result.output)
        app.cfg.save.assert_not_called()

    def test_unknown_connector_errors(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None})
        result = runner.invoke(
            cmd_guardrail.hilt_cmd,
            ["on", "--connector", "nope", "--yes"],
            obj=app,
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not configured", result.output)
        app.cfg.save.assert_not_called()


class BlockMessageCommandTests(unittest.TestCase):
    """`guardrail block-message [TEXT] [--clear] [--connector X]`."""

    def test_show_global_default_when_empty(self):
        runner = CliRunner()
        app = make_multi_ctx({})
        result = runner.invoke(cmd_guardrail.block_message_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("default", result.output)
        app.cfg.save.assert_not_called()

    def test_bare_show_fans_out_to_all_active_connectors(self):
        # Bare read on a multi-connector install MUST list each active
        # connector's effective block message, not just the global one.
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.block_message = "global msg"
        app.cfg.guardrail.connectors["codex"].block_message = "codex msg"
        result = runner.invoke(cmd_guardrail.block_message_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("per connector", result.output)
        self.assertIn("(codex)", result.output)
        self.assertIn("(claudecode)", result.output)
        # codex shows its override; claudecode inherits the global message.
        self.assertIn("codex msg", result.output)
        app.cfg.save.assert_not_called()

    def test_set_global_message(self):
        runner = CliRunner()
        app = make_multi_ctx({})
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.block_message_cmd,
                ["Blocked by Acme Security", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.block_message, "Blocked by Acme Security")
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()

    def test_bare_set_message_fans_out_to_all_active_connectors(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "geminicli": None})
        app.cfg.guardrail.block_message = "Old global"
        app.cfg.guardrail.connectors["geminicli"].block_message = "Gemini scoped block"
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.block_message_cmd,
                ["Global block", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.block_message, "Global block")
        for connector in ("codex", "geminicli"):
            self.assertEqual(app.cfg.guardrail.connectors[connector].block_message, "Global block")
            self.assertEqual(app.cfg.guardrail.effective_block_message(connector), "Global block")
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()

    def test_clear_global_message(self):
        runner = CliRunner()
        app = make_multi_ctx({})
        app.cfg.guardrail.block_message = "old"
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
            result = runner.invoke(
                cmd_guardrail.block_message_cmd, ["--clear", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.block_message, "")
        app.cfg.save.assert_called_once()

    def test_bare_clear_message_fans_out_to_all_active_connectors(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "geminicli": None})
        app.cfg.guardrail.block_message = "Global block"
        app.cfg.guardrail.connectors["codex"].block_message = "Codex scoped block"
        app.cfg.guardrail.connectors["geminicli"].block_message = "Gemini scoped block"
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.block_message_cmd,
                ["--clear", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.block_message, "")
        for connector in ("codex", "geminicli"):
            self.assertEqual(app.cfg.guardrail.connectors[connector].block_message, "")
            self.assertEqual(app.cfg.guardrail.effective_block_message(connector), "")
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()

    def test_message_and_clear_are_mutually_exclusive(self):
        runner = CliRunner()
        app = make_multi_ctx({})
        result = runner.invoke(
            cmd_guardrail.block_message_cmd, ["hi", "--clear", "--yes"], obj=app
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not both", result.output)
        app.cfg.save.assert_not_called()

    def test_set_one_connector_persists_and_restarts_only_it(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services"
        ) as restart_mock:
            result = runner.invoke(
                cmd_guardrail.block_message_cmd,
                ["Codex blocked", "--connector", "codex", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(
            app.cfg.guardrail.effective_block_message("codex"), "Codex blocked"
        )
        # claudecode keeps the global (empty) message.
        self.assertEqual(app.cfg.guardrail.connectors["claudecode"].block_message, "")
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        self.assertEqual(restart_mock.call_args.kwargs.get("connector"), "codex")

    def test_show_per_connector_override(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None})
        app.cfg.guardrail.connectors["codex"].block_message = "Codex policy"
        result = runner.invoke(
            cmd_guardrail.block_message_cmd, ["--connector", "codex"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("override", result.output)
        self.assertIn("Codex policy", result.output)
        app.cfg.save.assert_not_called()

    def test_clear_one_connector(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None})
        app.cfg.guardrail.connectors["codex"].block_message = "Codex policy"
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
            result = runner.invoke(
                cmd_guardrail.block_message_cmd,
                ["--clear", "--connector", "codex", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.connectors["codex"].block_message, "")
        app.cfg.save.assert_called_once()

    def test_connector_flag_rejected_on_single_connector_install(self):
        runner = CliRunner()
        app = make_multi_ctx({})
        result = runner.invoke(
            cmd_guardrail.block_message_cmd,
            ["msg", "--connector", "codex", "--yes"],
            obj=app,
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("multi-connector", result.output)
        app.cfg.save.assert_not_called()

    def test_unknown_connector_errors(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None})
        result = runner.invoke(
            cmd_guardrail.block_message_cmd,
            ["msg", "--connector", "nope", "--yes"],
            obj=app,
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not configured", result.output)
        app.cfg.save.assert_not_called()


class CommandRegistrationTests(unittest.TestCase):
    def test_guardrail_group_exposes_subcommands(self):
        names = set(cmd_guardrail.guardrail.commands.keys())
        # status / enable / disable are the day-1 lifecycle controls;
        # fail-mode was added in v3 to let operators flip response-
        # layer fail behavior without re-running the full setup
        # wizard. hilt + block-message expose the remaining
        # per-connector guardrail policy knobs (HILT approval gate and
        # the custom block message) without hand-editing config.yaml.
        # judge gates the hook-lane LLM judge per connector
        # (guardrail.judge.hook_connectors) — registered from cmd_judge.
        # list-packs is the read-only listing surface for guardrail rule
        # packs (built-in presets + the dir each connector enforces) — the
        # day-to-day counterpart to `setup <connector> --rule-pack` (R2).
        # Keep this assertion exact so accidental command removal
        # (e.g. a careless `del`) is caught immediately.
        self.assertEqual(
            names,
            {
                "enable",
                "disable",
                "status",
                "fail-mode",
                "hilt",
                "block-message",
                "judge",
                "list-packs",
            },
        )


class StatusStrategyJudgeTests(unittest.TestCase):
    """G3 / J5 — status surfaces effective scan strategy per connector."""

    def _rich(self, *, enabled=True, connector="hermes", judge_enabled=True,
              gate=None, strategy="regex_judge", prompt="", completion="", tool_call=""):
        app = make_ctx(enabled=enabled, connector=connector)
        gc = app.cfg.guardrail
        gc.detection_strategy = strategy
        gc.detection_strategy_prompt = prompt
        gc.detection_strategy_completion = completion
        gc.detection_strategy_tool_call = tool_call
        gc.judge = SimpleNamespace(enabled=judge_enabled, hook_connectors=list(gate or []))
        return app, gc

    def test_status_puts_effective_scan_in_connector_row(self):
        # Explicit completion regex_only remains visible as partial hook-lane
        # coverage, using hook vocabulary rather than proxy-lane "completion"
        # wording.
        app, _ = self._rich(strategy="regex_judge", completion="regex_only", gate=["hermes"])
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotIn("scan strategy:", result.output)
        self.assertNotIn("judge coverage:", result.output)
        self.assertIn("Hermes", result.output)
        self.assertIn("hermes", result.output)
        self.assertIn(
            "prompt:regex_judge, tool-call:regex_judge, tool-output:regex_only",
            result.output,
        )

    def test_status_collapses_full_hook_judge_coverage(self):
        app, _ = self._rich(strategy="regex_judge", completion="regex_judge", gate=["hermes"])
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Hermes", result.output)
        self.assertIn("regex_judge", result.output)
        self.assertNotIn("tool-output:", result.output)

    def test_status_judge_enabled_and_selected(self):
        app, _ = self._rich(judge_enabled=True, gate=["hermes"])
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Hermes", result.output)
        self.assertIn("hermes", result.output)
        self.assertIn("regex_judge", result.output)
        self.assertIn("Judge", result.output)
        self.assertIn("on", result.output)

    def test_status_judge_off_when_disabled(self):
        app, _ = self._rich(judge_enabled=False, gate=["hermes"])
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertNotIn("judge coverage:", result.output)
        self.assertIn("regex_only", result.output)
        self.assertIn("Judge", result.output)
        self.assertIn("off", result.output)
        self.assertNotIn("judge=on", result.output)

    def test_status_judge_off_when_not_gated(self):
        # Judge enabled globally but this connector isn't selected: the
        # effective hook strategy is regex_only, so there is no separate
        # top-level explanation to reconcile.
        app, _ = self._rich(judge_enabled=True, gate=[])
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertIn("Hermes", result.output)
        self.assertIn("hermes", result.output)
        self.assertIn("regex_only", result.output)
        self.assertIn("off", result.output)

    def test_status_all_gate_judges_every_connector(self):
        app, _ = self._rich(judge_enabled=True, gate=["*"])
        app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertIn("Codex", result.output)
        self.assertIn("codex", result.output)
        self.assertIn("Hermes", result.output)
        self.assertIn("hermes", result.output)
        self.assertEqual(result.output.count("regex_judge"), 2)
        self.assertIn("Judge", result.output)

    def test_status_regex_only_does_not_overstate(self):
        # J5 anti-overstatement: judge enabled AND gated, but the global
        # strategy is regex_only → the judge never runs. The row should simply
        # show the effective strategy and judge state once.
        app, _ = self._rich(judge_enabled=True, gate=["*"], strategy="regex_only")
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("regex_only", result.output)
        self.assertIn("off", result.output)
        self.assertNotIn("judge=on", result.output)
        self.assertNotIn("will not run", result.output)


class StatusConnectorScopeTests(unittest.TestCase):
    """G3 — `guardrail status --connector X` narrows the roster."""

    def _multi(self):
        app = make_ctx(enabled=True, connector="codex")
        gc = app.cfg.guardrail
        gc.effective_mode = lambda name="": {"codex": "action"}.get(name, "observe")
        app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        return app

    def test_scopes_to_named_connector(self):
        app = self._multi()
        result = CliRunner().invoke(
            cmd_guardrail.status_cmd, ["--connector", "hermes"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Hermes", result.output)
        self.assertIn("hermes", result.output)
        self.assertNotIn("Codex", result.output)
        self.assertNotIn("codex", result.output)

    def test_scopes_case_insensitively(self):
        app = self._multi()
        result = CliRunner().invoke(
            cmd_guardrail.status_cmd, ["--connector", "HERMES"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Hermes", result.output)
        self.assertIn("hermes", result.output)

    def test_scoped_status_does_not_show_other_connector_gate_as_active(self):
        app = self._multi()
        app.cfg.guardrail.judge = SimpleNamespace(
            enabled=False,
            hook_connectors=["hermes"],
        )
        result = CliRunner().invoke(
            cmd_guardrail.status_cmd, ["--connector", "codex"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("regex_only", result.output)
        self.assertIn("off", result.output)
        self.assertNotIn("judge coverage:", result.output)
        self.assertNotIn("hook gate: hermes", result.output)
        self.assertIn("Codex", result.output)
        self.assertIn("codex", result.output)
        self.assertNotIn("Hermes", result.output)
        self.assertNotIn("hermes", result.output)

    def test_scoped_status_shows_selected_judge_connector(self):
        app = self._multi()
        app.cfg.guardrail.judge = SimpleNamespace(
            enabled=True,
            hook_connectors=["hermes"],
        )
        result = CliRunner().invoke(
            cmd_guardrail.status_cmd, ["--connector", "hermes"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("regex_judge", result.output)
        self.assertIn("on", result.output)
        self.assertIn("Hermes", result.output)
        self.assertIn("hermes", result.output)
        self.assertNotIn("Codex", result.output)
        self.assertNotIn("codex", result.output)

    def test_scoped_status_shows_unselected_judge_connector(self):
        app = self._multi()
        app.cfg.guardrail.judge = SimpleNamespace(
            enabled=True,
            hook_connectors=["hermes"],
        )
        result = CliRunner().invoke(
            cmd_guardrail.status_cmd, ["--connector", "codex"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("regex_only", result.output)
        self.assertIn("off", result.output)
        self.assertNotIn("judge coverage:", result.output)
        self.assertIn("Codex", result.output)
        self.assertIn("codex", result.output)
        self.assertNotIn("Hermes", result.output)
        self.assertNotIn("hermes", result.output)

    def test_unknown_connector_errors(self):
        app = make_ctx(enabled=True, connector="codex")
        app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        result = CliRunner().invoke(
            cmd_guardrail.status_cmd, ["--connector", "hermes"], obj=app
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("not active", result.output)


class StatusPhantomTests(unittest.TestCase):
    """G5 — no phantom openclaw row when nothing is configured."""

    def test_no_connector_configured_shows_empty_state(self):
        app = make_ctx(enabled=False, connector="openclaw")
        # Simulate "all connectors removed": active_connectors() empty AND
        # has_connector_configured() false (the post-`setup remove` state).
        app.cfg.active_connectors = lambda: []  # type: ignore[method-assign]
        app.cfg.has_connector_configured = lambda: False  # type: ignore[method-assign]
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("none configured", result.output)
        # The phantom openclaw roster row must NOT appear.
        self.assertNotIn("OpenClaw (openclaw):", result.output)
        self.assertNotIn("- OpenClaw", result.output)

    def test_configured_install_still_renders_roster(self):
        # Guard against over-correction: a real single-connector install
        # (has_connector_configured true) must still render its block.
        app = make_ctx(enabled=True, connector="openclaw")
        app.cfg.active_connectors = lambda: ["openclaw"]  # type: ignore[method-assign]
        app.cfg.has_connector_configured = lambda: True  # type: ignore[method-assign]
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("OpenClaw", result.output)
        self.assertIn("openclaw", result.output)
        self.assertNotIn("none configured", result.output)


class ListPacksTests(unittest.TestCase):
    """R2 — `guardrail list-packs` lists presets + per-connector dirs."""

    def test_lists_presets_and_per_connector_dirs(self):
        app = make_ctx(enabled=True, connector="codex")
        gc = app.cfg.guardrail
        gc.rule_pack_dir = ""
        gc.effective_rule_pack_dir = lambda name="": {"codex": "/etc/dc/strict"}.get(name, "")
        app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        result = CliRunner().invoke(cmd_guardrail.list_packs_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        for preset in ("default", "strict", "permissive"):
            self.assertIn(preset, result.output)
        self.assertIn("Codex (codex):", result.output)
        self.assertIn("/etc/dc/strict", result.output)

    def test_global_dir_default_when_unset(self):
        app = make_ctx(enabled=True, connector="codex")
        gc = app.cfg.guardrail
        gc.rule_pack_dir = ""
        gc.effective_rule_pack_dir = lambda name="": ""
        app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        result = CliRunner().invoke(cmd_guardrail.list_packs_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("built-in default", result.output)

    def test_no_connector_configured(self):
        app = make_ctx(enabled=False, connector="openclaw")
        app.cfg.active_connectors = lambda: []  # type: ignore[method-assign]
        app.cfg.has_connector_configured = lambda: False  # type: ignore[method-assign]
        result = CliRunner().invoke(cmd_guardrail.list_packs_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("none configured", result.output)


if __name__ == "__main__":
    unittest.main()
