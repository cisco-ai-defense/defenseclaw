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

import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import click
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_guardrail
from defenseclaw.context import AppContext
from tests.fail_mode_tier import policy_tier_follows_the_saved_fail_mode  # noqa: F401 - autouse fixture

import pytest


@pytest.fixture(autouse=True)
def _per_user_set_mechanics(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Let the persistence and refresh tests set any value per user.

    A per-user ``guardrail fail-mode`` refuses a value its policy tier does not
    give (oss-outage-open). These tests exercise the write, refresh, rollback
    and message mechanics of that command, which Secure Client keeps for both
    values; the tests named ``*refused*`` check the refusal itself.
    """
    if "refused" not in request.node.name:
        monkeypatch.setattr(cmd_guardrail, "_refuse_a_mode_the_policy_tier_does_not_give", lambda *_a, **_k: None)


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


# Status draws a table or per-connector blocks by the terminal width, which
# other tests in the same process (a pytest worker, a CI shard) can leave
# narrowed. These tests assume 120 columns unless one patches it itself.
_TERMINAL_WIDTH = patch("defenseclaw.commands.cmd_guardrail._terminal_width", return_value=120)
# On Windows, enable verifies the agent executable first (GAP-0069); the CI
# runner has none installed. Tests of that check patch it themselves.
_AGENT_VERIFY = patch("defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections", return_value=None)


def setUpModule():
    _TERMINAL_WIDTH.start()
    _AGENT_VERIFY.start()


def tearDownModule():
    _AGENT_VERIFY.stop()
    _TERMINAL_WIDTH.stop()


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

    def test_none_cfg_has_no_connector(self):
        self.assertEqual(cmd_guardrail._resolve_active_connector(None), "")

    def test_resolve_member_connector_accepts_aliases(self):
        app = make_ctx(enabled=True, connector="codex")
        app.cfg.guardrail.connectors = {
            "claudecode": SimpleNamespace(),
        }
        self.assertEqual(
            cmd_guardrail._resolve_member_connector(app, "claude-code"),
            "claudecode",
        )


def _native_deny_state(connector: str, runtime: str):
    from defenseclaw.fail_mode import ConnectorFailModeState, upstream_hook_limit

    return ConnectorFailModeState(
        connector=connector,
        desired="closed",
        configured="closed",
        runtime=runtime,
        sources=(("config", "closed"), ("hook-script", runtime)),
        drift=() if runtime == "closed" else (f"hook-script-{runtime}",),
        limit=upstream_hook_limit(connector),
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
        as_json = runner.invoke(cmd_guardrail.status_cmd, ["--json"], obj=app)
        self.assertEqual(as_json.exit_code, 0, as_json.output)
        self.assertIsNone(json.loads(as_json.output)["connectors"][0]["fail_mode"])

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

    def test_status_secure_client_hermes_reports_upstream_fail_open_not_configured_closed(self):
        # Under Secure Client the Hermes hook fails open whatever is configured.
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="hermes", hook_fail_mode="closed")
        app.cfg.deployment_mode = "managed_enterprise"
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Hermes", result.output)
        self.assertIn("open", result.output)
        self.assertIn("upstream-enforced fail-open", result.output)
        self.assertIn("configured provenance: closed", result.output)

    def test_status_hermes_reports_the_configured_mode_on_every_os(self):
        # GAP-0150 (Linux, macOS) and GAP-0269 (Windows): the per-user Hermes
        # hook blocks in fail mode closed.
        for windows in (False, True):
            runner = CliRunner()
            app = make_ctx(enabled=True, connector="hermes", hook_fail_mode="closed")
            with patch("defenseclaw.fail_mode._is_windows", return_value=windows):
                result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertNotIn("upstream-enforced fail-open", result.output)
            self.assertIn("closed", result.output)

    def test_status_copilot_reports_its_rendered_mode_in_text_and_json(self):
        # A per-user Copilot hook follows its fail mode; text and JSON agree
        # (GAP-1246) and name the vendor limit of a closed hook. Under Secure
        # Client it stays upstream fail-open.
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode",
                   return_value=_native_deny_state("copilot", "closed")):
            app = make_ctx(enabled=True, connector="copilot", hook_fail_mode="closed")
            result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertNotIn("upstream-enforced fail-open", result.output)
            self.assertIn("Copilot itself lets a call run when the hook times out or cannot start", result.output)
            app = make_ctx(enabled=True, connector="copilot", hook_fail_mode="closed")
            result = runner.invoke(cmd_guardrail.status_cmd, ["--json"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn('"fail_mode": "closed"', result.output)
            self.assertNotIn('"fail_mode": "open"', result.output)
        app = make_ctx(enabled=True, connector="copilot", hook_fail_mode="closed")
        app.cfg.deployment_mode = "managed_enterprise"
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("upstream-enforced fail-open", result.output)

    def test_secure_client_status_keeps_main_enabled_and_warnings(self):
        from defenseclaw.commands import cmd_status

        app = make_ctx(enabled=True, connector="kiro", hook_fail_mode="open")
        app.cfg.guardrail.mode = "action"
        app.cfg.guardrail.effective_enabled = lambda name: False
        with (
            patch.object(cmd_status, "_enterprise_profile", return_value="secure_client"),
            patch("defenseclaw.gateway.current_user_guardrail_profile", side_effect=AssertionError("profile queried")),
        ):
            result = CliRunner().invoke(cmd_guardrail.status_cmd, ["--json"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(result.output)
            self.assertIs(payload["enabled"], True)
            self.assertEqual(payload["warnings"], [])
            self.assertNotIn("profile", payload)

            text = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
            self.assertEqual(text.exit_code, 0, msg=text.output)
            self.assertIn("enabled:    yes", text.output)
            self.assertNotIn("action mode with fail mode open", text.output)

    def test_status_flags_action_connector_on_fail_open(self):
        # GAP-0415: an upgrade keeps the fail mode an older setup chose.
        app = make_ctx(enabled=True, connector="kiro", hook_fail_mode="open")
        app.cfg.guardrail.mode = "action"
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("action mode with fail mode open", result.output)
        self.assertIn("defenseclaw guardrail use-pack strict", result.output)

    def test_status_flags_fail_open_connector_an_action_profile_enforces(self):
        # GAP-1282: base mode observe, a guardrail profile puts the connector
        # in action mode for its accounts, fail mode open.
        from defenseclaw.config import GuardrailProfile, PerConnectorGuardrailConfig

        for profile in (
            GuardrailProfile(mode="action"),
            GuardrailProfile(connectors={"kiro": PerConnectorGuardrailConfig(mode="action")}),
        ):
            app = make_ctx(enabled=True, connector="kiro", hook_fail_mode="open")
            app.cfg.guardrail.mode = "observe"
            app.cfg.guardrail.profiles = {"engineering": profile}
            with patch("defenseclaw.gateway.current_user_guardrail_profile", return_value=None):
                result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn("action mode for guardrail profile(s) engineering with fail mode open", result.output)
            self.assertIn("defenseclaw guardrail use-pack strict", result.output)
        # A profile that keeps observe (or sets action for another connector)
        # adds no warning.
        app = make_ctx(enabled=True, connector="kiro", hook_fail_mode="open")
        app.cfg.guardrail.profiles = {
            "ops": GuardrailProfile(mode="action", connectors={"kiro": PerConnectorGuardrailConfig(mode="observe")}),
            "dev": GuardrailProfile(connectors={"codex": PerConnectorGuardrailConfig(mode="action")}),
        }
        with patch("defenseclaw.gateway.current_user_guardrail_profile", return_value=None):
            result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertNotIn("with fail mode open", result.output)

    def test_fail_mode_view_reports_antigravity_and_copilot_rendered_mode(self):
        # The view says what their hooks render: closed with the vendor
        # limit, or the drift when a hook still renders open. Under Secure
        # Client they stay upstream fail-open (GAP-0336).
        for connector, label in (("antigravity", "Antigravity"), ("copilot", "Copilot")):
            app = make_ctx(enabled=True, connector=connector, hook_fail_mode="closed")
            # The strict tier, whose outage mode is closed (oss-outage-open).
            app.cfg.guardrail.hook_policy_tier = lambda _name: "strict"
            app.cfg.guardrail.effective_hook_fail_mode = lambda _name: "closed"
            with patch("defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode",
                       return_value=_native_deny_state(connector, "closed")):
                result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            row = next(line for line in result.output.splitlines() if f"({connector}):" in line)
            self.assertIn(
                f"closed (strict tier; DefenseClaw failures block; {label} itself lets a call run when the hook "
                "times out or cannot start)", row)
            self.assertNotIn("remains fail-open", result.output)
            with patch("defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode",
                       return_value=_native_deny_state(connector, "open")):
                result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
            row = next(line for line in result.output.splitlines() if f"({connector}):" in line)
            self.assertIn("(installed open; drift: hook-script-open)", row)
            del app.cfg.guardrail.hook_policy_tier
            del app.cfg.guardrail.effective_hook_fail_mode
            app.cfg.deployment_mode = "managed_enterprise"
            result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
            row = next(line for line in result.output.splitlines() if f"({connector}):" in line)
            self.assertIn("upstream; configured provenance: closed", row)
            self.assertIn("remains fail-open", result.output)

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
        self.assertRegex(result.output, r"key:\s+codex")
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
        app.cfg.deployment_mode = "managed_enterprise"
        app.cfg.managed_outside_secure_client = lambda: True
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
        # A per-user install shows the policy-tier rule, not the saved value
        # (oss-outage-open).
        self.assertIn("gateway outage: follows the policy tier", result.output)
        self.assertIn("strict blocks it", " ".join(result.output.split()))
        self.assertIn("defenseclaw guardrail use-pack strict", result.output)

    def test_single_connector_observe_mode_outside_secure_client_names_the_fail_mode_fix(self):
        # B-01 (owner rule): outside Secure Client observe mode never keeps a
        # hook fail-open; an open hook is closed with fail-mode, not a mode
        # switch.
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="claudecode", hook_fail_mode="closed")
        app.cfg.guardrail.connectors = {}
        app.cfg.guardrail.effective_mode = lambda _name: "observe"
        app.cfg.guardrail.effective_hook_fail_mode = lambda _name: "open"
        state = SimpleNamespace(current=True, runtime="open", desired="open", drift=())
        with patch("defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode", return_value=state):
            result = runner.invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotIn("observe mode keeps hooks fail-open", result.output)
        # The default tier's open is the rule, not drift to close.
        self.assertIn("Claude Code (claudecode): open (default tier)", result.output)
        self.assertNotIn("Still fail-open", result.output)

    def test_show_hermes_closed_is_closed_on_every_os(self):
        # GAP-0150 (Linux, macOS) and GAP-0269 (Windows): no upstream
        # fail-open claim, the hook blocks.
        for windows in (False, True):
            runner = CliRunner()
            app = make_ctx(enabled=True, connector="hermes", hook_fail_mode="closed")
            with patch("defenseclaw.fail_mode._is_windows", return_value=windows):
                result = runner.invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertNotIn("Hermes upstream", result.output)
            self.assertNotIn("Hermes remains fail-open", result.output)

    def test_closed_view_omits_hermes_when_not_configured(self):
        # GAP-2116: the Hermes sentence only shows when Hermes is configured.
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="codex", hook_fail_mode="closed")
        result = runner.invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("follows the policy tier", result.output)
        self.assertNotIn("Hermes", result.output)

    def test_set_closed_omits_hermes_when_not_configured(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="codex", hook_fail_mode="open")
        with patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"):
            result = runner.invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("native fail-closed surface.", result.output)
        self.assertNotIn("Hermes", result.output)

    def test_set_open_to_closed_persists_and_restarts(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="codex", hook_fail_mode="open")
        with patch(
            "defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"
        ) as restart_mock:
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.hook_fail_mode, "closed")
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        # Active connector must propagate so hooks for the right
        # connector get rewritten.
        self.assertEqual(restart_mock.call_args.args[1], "codex")

    def test_set_same_value_is_noop(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, hook_fail_mode="closed")
        state = SimpleNamespace(
            current=True, runtime="closed", desired="closed", drift=()
        )
        with patch(
            "defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode",
            return_value=state,
        ):
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
        self.assertEqual(app.cfg.guardrail.hook_fail_mode, "open")
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
        docs = Path(__file__).resolve().parents[2] / "docs-site/content/docs/connectors"
        for connector in ("openclaw", "zeptoclaw"):
            runner = CliRunner()
            app = make_ctx(enabled=False, connector=connector, model="", llm_model="")
            result = runner.invoke(cmd_guardrail.enable_cmd, ["--yes"], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("Cannot enable: guardrail.model is not set.", result.output)
            # Must NOT silently flip enabled to True.
            self.assertFalse(app.cfg.guardrail.enabled)
            app.cfg.save.assert_not_called()
            # The page turns it back on with what works (GAP-0667).
            page = " ".join((docs / f"{connector}.mdx").read_text(encoding="utf-8").split())
            self.assertNotIn("Turn it back on with `defenseclaw guardrail enable`", page)
            self.assertIn(f"Turn it back on by running the Set up command again, for example `defenseclaw setup {connector} ", page)
            self.assertIn("`Cannot enable: guardrail.model is not set.`", page)

    def test_enable_hook_connector_without_model(self):
        # GAP-1562: hook connectors were enabled by init without a model,
        # so enable must stay the inverse of disable for them.
        runner = CliRunner()
        app = make_ctx(enabled=False, connector="claudecode", model="", llm_model="")
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
            result = runner.invoke(cmd_guardrail.enable_cmd, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotIn("guardrail.model is not set", result.output)
        self.assertTrue(app.cfg.guardrail.enabled)

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


def test_amp_open_preview_and_help_scope_failure_rows_to_per_user_outages() -> None:
    """An eligible per-user Amp outage is recorded; managed and sandbox calls are not."""
    app = make_multi_ctx({"amp": None, "codex": None})
    app.cfg.guardrail.hook_fail_mode = "closed"
    state = SimpleNamespace(
        desired="closed", current=True, runtime="closed", effective="closed", drift=(), limit=None,
    )
    with (
        patch.object(cmd_guardrail, "resolve_connector_fail_mode", return_value=state),
        patch.object(cmd_guardrail, "_apply_scoped_fail_mode_transaction"),
        patch.object(cmd_guardrail, "_apply_global_fail_mode_transaction"),
        patch.object(cmd_guardrail, "_log_guardrail_action"),
    ):
        scoped = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["open", "--connector", "amp", "--yes"], obj=app)
        global_result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["open", "--yes"], obj=app)
    for result in (scoped, global_result):
        assert result.exit_code == 0, result.output
        assert "Amp" in result.output
        assert "per-user" in result.output and "hook-failures.jsonl" in result.output
        assert "guardrail-degraded" in result.output
    help_result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["--help"])
    assert help_result.exit_code == 0, help_result.output
    assert "Amp" in help_result.output and "per-user" in help_result.output
    assert "hook-failures.jsonl" in help_result.output
    page = (Path(__file__).resolve().parents[2] / "docs-site/content/docs/reference/fail-modes.mdx")
    page_text = page.read_text(encoding="utf-8")
    reporting = page_text.split("## Reporting and diagnosis", 1)[1]
    assert "Amp plugin writes a record only for a call an outage let run" in reporting
    assert "guardrail-degraded" in reporting
    assert "managed and sandbox Amp plugins write no record" in reporting
    for prefix in (
        "On a per-user install the outage behavior",
        "| `default` (balanced",
        "| Gateway service not running",
        "When the gateway is down or answers 5xx",
    ):
        line = next(line for line in page_text.splitlines() if line.startswith(prefix))
        assert "hook-failures.jsonl" in line, line
        assert "except for Amp" not in line and "Amp has no such writer" not in line, line


def test_per_user_amp_outage_open_template_records_an_actionable_call() -> None:
    source = (Path(__file__).resolve().parents[2] / "internal/gateway/connector/hooks/amp-plugin.ts").read_text(
        encoding="utf-8"
    )
    branch = source.split("if (await perUserOutageOpen(error)) {", 1)[1].split("\n\t\t\t\t}", 1)[0]
    assert branch.index('if (actionable) await logFailOpen("gateway unreachable")') < branch.index(
        'return { action: "allow"'
    )
    writer = source.split("async function logFailOpen(", 1)[1].split("async function perUserGatewayDownText", 1)[0]
    for field in ('"hook-failures.jsonl"', 'connector: "amp"', 'fail_mode: "open"', 'outcome: "fail_open"'):
        assert field in writer


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

    def test_enable_one_connector_after_global_disable_says_run_enable(self):
        # GAP-0550: after `setup guardrail --disable` this said "Connector
        # Codex is already enabled." and left every agent off.
        runner = CliRunner()
        for own in (None, False):
            app = make_multi_ctx({"codex": own, "claudecode": None}, enabled=False)
            with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
                result = runner.invoke(
                    cmd_guardrail.enable_cmd, ["--connector", "codex", "--yes"], obj=app
                )
            self.assertEqual(result.exit_code, 1, msg=result.output)
            self.assertNotIn("already enabled", result.output)
            out = " ".join(result.output.split())
            # The global enable keeps a connector disabled on its own off, so
            # that case names both steps in order.
            steps = (
                "'defenseclaw guardrail enable', then 'defenseclaw guardrail enable --connector codex'"
                if own is False
                else "'defenseclaw guardrail enable' to turn it back on"
            )
            self.assertIn(f"Run {steps}", out)
            self.assertIn("nothing was changed", out)
            self.assertFalse(app.cfg.guardrail.enabled)
            self.assertEqual(app.cfg.guardrail.connectors["codex"].enabled, own)
            app.cfg.save.assert_not_called()
            restart_mock.assert_not_called()

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

    def test_enable_one_connector_verifies_its_agent_first_and_waits_for_the_gateway(self):
        """Windows refuses a connector it holds no verified agent executable for, and
        disable dropped that proof (GAP-0069): enable records it before saving, and
        reports success only once the restarted gateway admitted the connector."""
        runner = CliRunner()
        app = make_multi_ctx({"codex": False, "claudecode": None})
        with (
            patch("defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections") as record,
            patch("defenseclaw.commands.cmd_setup._restart_services") as restart,
        ):
            result = runner.invoke(
                cmd_guardrail.enable_cmd, ["--connector", "codex", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(list(record.call_args.args[1]), ["codex"])
        self.assertTrue(restart.call_args.kwargs["wait_for_connector_ready"])
        # The wait covers the whole enabled roster, so an active peer is not an
        # unexpected lock entry (GAP-0163).
        self.assertEqual(restart.call_args.kwargs["connectors"], ["claudecode", "codex"])

        app = make_multi_ctx({"codex": False, "claudecode": None})
        with (
            patch(
                "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                side_effect=click.ClickException("cannot verify the agent executable"),
            ),
            patch("defenseclaw.commands.cmd_setup._restart_services") as restart,
        ):
            result = runner.invoke(
                cmd_guardrail.enable_cmd, ["--connector", "codex", "--yes"], obj=app
            )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("cannot verify the agent executable", result.output)
        app.cfg.save.assert_not_called()
        restart.assert_not_called()

    def test_enable_no_restart_verifies_agent_before_hot_reload(self):
        app = make_multi_ctx({"codex": False, "claudecode": None})
        with (
            patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=True),
            patch("defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections") as record,
            patch("defenseclaw.commands.cmd_setup._restart_services") as restart,
        ):
            result = CliRunner().invoke(
                cmd_guardrail.enable_cmd,
                ["--connector", "codex", "--yes", "--no-restart"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        record.assert_called_once_with(app.cfg.data_dir, ["codex"])
        restart.assert_not_called()
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
            cmd_guardrail.disable_cmd, ["--connector", "cursor", "--yes"], obj=app
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

    def test_disable_one_connector_says_a_stopped_gateway_is_started(self):
        # GAP-1370: the single-connector form says plainly that it starts the gateway.
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        with (
            patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=False),
            patch("defenseclaw.commands.cmd_setup._restart_services"),
        ):
            result = runner.invoke(
                cmd_guardrail.disable_cmd, ["--connector", "codex", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("The gateway is stopped; it will be started so the Codex connector teardown", result.output)
        self.assertNotIn("Will restart the gateway", result.output)

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

    def test_global_enable_waits_for_enabled_peers_when_one_stays_disabled(self):
        app = make_multi_ctx({"codex": None, "claudecode": None, "cursor": False}, enabled=False)
        app.cfg.guardrail.model = "gpt-4o"
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart:
            result = CliRunner().invoke(cmd_guardrail.enable_cmd, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(restart.call_args.kwargs["wait_for_connector_ready"])
        self.assertEqual(set(restart.call_args.kwargs["connectors"]), {"codex", "claudecode"})
        self.assertIn("cursor", result.output)

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

    def test_status_all_connectors_disabled_uses_enable_hint(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": False, "claudecode": False})
        result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("enabled:    no", result.output)
        self.assertIn("Enable with", result.output)
        self.assertNotIn("Disable with", result.output)
        machine = runner.invoke(cmd_guardrail.status_cmd, ["--json"], obj=app)
        self.assertFalse(json.loads(machine.output)["enabled"])

    def test_status_global_off_suggests_global_enable(self):
        app = make_multi_ctx({"codex": True, "claudecode": None}, enabled=False)
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("defenseclaw guardrail enable\n", result.output)
        self.assertNotIn("guardrail enable --connector", result.output)

    def test_status_roster_shows_per_connector_rule_pack_and_hilt(self):
        # Each connector can scan against its OWN rule pack AND HILT policy; the
        # roster surfaces both. codex gets a custom pack + per-connector HILT;
        # claudecode inherits the defaults.
        from defenseclaw import config as dcconfig
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None, "copilot": None})
        app.cfg.guardrail.connectors["codex"].rule_pack = "strict"
        app.cfg.guardrail.connectors["codex"].hilt = dcconfig.HILTConfig(
            enabled=True, min_severity="LOW"
        )
        app.cfg.guardrail.custom_packs["protected-copilot"] = dcconfig.CustomRulePack(
            path="/packs/protected-copilot/default"
        )
        app.cfg.guardrail.connectors["copilot"].rule_pack = "protected-copilot"
        app.cfg.guardrail.block_at = "HIGH"
        with patch("defenseclaw.commands.cmd_guardrail._terminal_width", return_value=200):  # the table layout
            result = runner.invoke(cmd_guardrail.status_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Rule pack", result.output)
        self.assertIn("strict", result.output)    # codex's own pack
        self.assertIn("default", result.output)   # claudecode inherits
        self.assertIn("on@LOW", result.output)    # codex's own HILT
        self.assertIn("protected-copilot", result.output)  # a composed pack by its scope
        # Tool-call levels: the global block_at over each connector's pack.
        self.assertIn("HIGH+/LOW+", result.output)     # codex: strict alerts LOW+
        self.assertIn("HIGH+/MEDIUM+", result.output)  # claudecode: default alerts MEDIUM+

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


class CursorModePostureTests(unittest.TestCase):
    def test_action_restarts_and_normalizes_stored_fail_mode(self):
        app = make_multi_ctx({"cursor": None, "codex": None})
        app.cfg.guardrail.connectors["cursor"].hook_fail_mode = "open"
        with (
            patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=True),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            ),
            patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True) as restart,
        ):
            result = CliRunner().invoke(
                cmd_guardrail.mode_cmd, ["action", "--connector", "cursor"], obj=app
            )
        self.assertEqual(result.exit_code, 0, result.output)
        # The guardrail mode no longer pins Cursor's fail mode: its outage
        # mode follows the policy tier (here the saved open's default tier).
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("cursor"), "open")
        self.assertEqual(app.cfg.guardrail.connectors["cursor"].hook_fail_mode, "open")


class PerConnectorFailModeTests(unittest.TestCase):
    """`guardrail fail-mode [open|closed] --connector X` — scoped override."""

    def setUp(self):
        # These cases restart a running gateway; a stopped one is left
        # stopped (GAP-1370).
        patcher = patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Transaction snapshots include agent config. Never snapshot or restore
        # a developer's real ~/.codex or ~/.claude during rollback tests.
        import tempfile

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        environment = patch.dict(os.environ, {"HOME": directory.name, "USERPROFILE": directory.name})
        environment.start()
        self.addCleanup(environment.stop)

    def test_per_user_value_the_tier_does_not_give_is_refused_before_changing_config(self):
        # The strict tier (a saved closed, fail_mode_tier) refuses open, the
        # default tier refuses closed (oss-outage-open).
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.hook_fail_mode = "closed"
        runner = CliRunner()
        for args in (["open", "--yes"], ["open", "--connector", "codex", "--yes"]):
            result = runner.invoke(cmd_guardrail.fail_mode_cmd, args, obj=app)
            self.assertNotEqual(result.exit_code, 0, result.output)
            self.assertIn("follows the policy tier", " ".join(result.output.split()))
        app.cfg.guardrail.hook_fail_mode = "open"
        result = runner.invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--connector", "codex", "--yes"], obj=app)
        self.assertNotEqual(result.exit_code, 0, result.output)
        self.assertIn("use-pack strict", result.output)
        app.cfg.save.assert_not_called()

    def test_set_one_connector_closed_persists_and_restarts_only_it(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.connectors["codex"].mode = "action"
        with patch(
            "defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"
        ) as restart_mock:
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd,
                ["closed", "--connector", "codex", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # Only codex gets the override; claudecode keeps the global default
        # (open, the default tier).
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("codex"), "closed")
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("claudecode"), "open")
        # Global default is untouched.
        self.assertEqual(app.cfg.guardrail.hook_fail_mode, "open")
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        self.assertEqual(restart_mock.call_args.args[1], "codex")

    def test_show_per_connector_value_without_mode(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.connectors["codex"].hook_fail_mode = "closed"
        result = runner.invoke(
            cmd_guardrail.fail_mode_cmd, ["--connector", "codex"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        if os.name == "nt":
            # The native Windows hook reads its mode from hooks/.hookcfg alone
            # and fails closed without it (readHookSidecar), so that is the
            # installed mode, reported with the missing sidecar as drift.
            self.assertIn("hook_fail_mode: closed", result.output)
            self.assertIn("windows-sidecar-missing", result.output)
        else:
            self.assertIn("unknown", result.output)
        self.assertIn("desired closed", result.output)
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

    def test_show_secure_client_hermes_value_reports_upstream_fail_open(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "hermes": None})
        app.cfg.deployment_mode = "managed_enterprise"
        app.cfg.guardrail.connectors["hermes"].hook_fail_mode = "closed"
        result = runner.invoke(
            cmd_guardrail.fail_mode_cmd, ["--connector", "hermes"], obj=app
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn(
            "open (Hermes upstream; failures cannot be made fail-closed; configured provenance: closed)",
            result.output,
        )
        self.assertIn("per-connector override", result.output)

    def test_set_secure_client_hermes_closed_warns_that_runtime_remains_open(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "hermes": None})
        app.cfg.deployment_mode = "managed_enterprise"
        with patch(
            "defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"
        ):
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd,
                ["closed", "--connector", "hermes", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.connectors["hermes"].hook_fail_mode, "closed")
        self.assertIn("Hermes will remain fail-open", result.output)
        self.assertNotIn("will now BLOCK Hermes", result.output)

    def test_set_hermes_closed_on_linux_and_macos_blocks_gateway_failures(self):
        # GAP-0150: closed applies to the Linux and macOS Hermes hook.
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "hermes": None})
        with patch(
            "defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"
        ), patch("defenseclaw.fail_mode._is_windows", return_value=False):
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd,
                ["closed", "--connector", "hermes", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotIn("Hermes will remain fail-open", result.output)
        self.assertIn("will now BLOCK Hermes tool calls", result.output)
        self.assertIn("hook times out", result.output)

    def test_set_native_deny_connector_closed_names_its_native_deny(self):
        # Review round 3: closed Copilot and Antigravity hooks block with the
        # agent's own deny and exit 0; the guidance said they exit 2.
        expected = {
            "copilot": "Copilot's own deny for preToolUse and permissionRequest",
            "antigravity": "Antigravity's PreToolUse deny ({\"decision\":\"deny\"})",
            "codex": "will exit 2 from this connector's hooks",
        }
        for connector, signal in expected.items():
            with self.subTest(connector=connector):
                app = make_multi_ctx({"claudecode": None, connector: None})
                with patch(
                    "defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"
                ), patch("defenseclaw.fail_mode._is_windows", return_value=False):
                    result = CliRunner().invoke(
                        cmd_guardrail.fail_mode_cmd,
                        ["closed", "--connector", connector, "--yes"],
                        obj=app,
                    )
                self.assertEqual(result.exit_code, 0, msg=result.output)
                output = " ".join(result.output.split())
                self.assertIn(signal, output)
                if connector != "codex":
                    self.assertNotIn("exit 2", output)
                    self.assertIn("exits 0", output)
                    self.assertIn("hook times out", output)

    def test_per_connector_closed_for_copilot_and_antigravity_is_provenance_not_a_block(self):
        # 1.0.4 review (loop round 2): under Secure Client their hooks render
        # open under closed, so the setter must not promise a block or an
        # exit 2, and the view must say upstream fail-open, as the unscoped
        # view, status and doctor do (GAP-0336). Per-user hooks follow the
        # closed mode (w3-g3-hooks), see the per-user test below.
        for connector, label in (("copilot", "GitHub Copilot CLI"), ("antigravity", "Antigravity")):
            with self.subTest(connector=connector):
                runner = CliRunner()
                app = make_multi_ctx({"codex": None, connector: None})
                app.cfg.deployment_mode = "managed_enterprise"
                app.cfg.managed_outside_secure_client = lambda: False
                with patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"):
                    result = runner.invoke(
                        cmd_guardrail.fail_mode_cmd,
                        ["closed", "--connector", connector, "--yes"],
                        obj=app,
                    )
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertEqual(app.cfg.guardrail.connectors[connector].hook_fail_mode, "closed")
                self.assertIn(f"{label} will remain fail-open", result.output)
                self.assertIn("stored only as requested policy provenance", result.output)
                self.assertIn(f"{label} has no fail-closed hook contract", result.output)
                self.assertNotIn("BLOCK", result.output)
                self.assertNotIn("exit 2", result.output)

                result = runner.invoke(cmd_guardrail.fail_mode_cmd, ["--connector", connector], obj=app)
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertIn(
                    f"open ({label} upstream; failures cannot be made fail-closed; configured provenance: closed)",
                    result.output,
                )

    def test_per_connector_closed_for_a_managed_standalone_copilot_still_blocks(self):
        # Outside Secure Client a managed Copilot blocks through its native
        # deny, so it is not upstream fail-open there and the block warning
        # stays.
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "copilot": None})
        app.cfg.managed_outside_secure_client = lambda: True
        with patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"):
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd,
                ["closed", "--connector", "copilot", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("will now BLOCK GitHub Copilot CLI", result.output)
        self.assertNotIn("will remain fail-open", result.output)

    def test_bare_closed_names_every_upstream_fail_open_connector(self):
        # The unscoped setter named only Hermes; under Secure Client Copilot
        # and Antigravity stay fail-open too.
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "copilot": None, "antigravity": None})
        app.cfg.deployment_mode = "managed_enterprise"
        app.cfg.managed_outside_secure_client = lambda: False
        with (
            patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=False),
            patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"),
        ):
            result = runner.invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("BLOCK supported connectors", result.output)
        self.assertIn("Antigravity, GitHub Copilot CLI remain fail-open.", result.output)

    def test_bare_closed_per_user_names_no_upstream_fail_open_connector(self):
        # Per user, Copilot and Antigravity follow the closed mode
        # (w3-g3-hooks), so the unscoped setter names none of them as
        # remaining fail-open (hooks-upg loop 2 with the T3 train).
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "copilot": None, "antigravity": None})
        with patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"):
            result = runner.invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("BLOCK supported connectors", result.output)
        self.assertNotIn("remain fail-open", result.output)

    def test_bare_closed_on_a_copilot_only_install_is_provenance_not_a_block(self):
        runner = CliRunner()
        app = make_ctx(enabled=True, connector="copilot", hook_fail_mode="open")
        app.cfg.deployment_mode = "managed_enterprise"
        app.cfg.managed_outside_secure_client = lambda: False
        result = runner.invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes", "--no-restart"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("GitHub Copilot CLI will remain fail-open; closed is stored only", result.output)
        self.assertNotIn("BLOCK", result.output)

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
        app.cfg.guardrail.connectors["codex"].mode = "action"
        app.cfg.guardrail.connectors["claudecode"].mode = "action"
        with patch(
            "defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"
        ):
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.hook_fail_mode, "closed")
        self.assertEqual(app.cfg.guardrail.connectors["codex"].hook_fail_mode, "closed")
        self.assertEqual(app.cfg.guardrail.connectors["claudecode"].hook_fail_mode, "closed")
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("codex"), "closed")
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("claudecode"), "closed")

    def test_bare_set_open_reconciles_closed_connector_override(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "cursor": None})
        app.cfg.deployment_mode = "managed_enterprise"
        app.cfg.guardrail._secure_client = True
        app.cfg.guardrail.hook_fail_mode = "open"
        app.cfg.guardrail.connectors["cursor"].hook_fail_mode = "closed"
        state = SimpleNamespace(current=True, drift=())
        with (
            patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock,
            patch(
                "defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode",
                return_value=state,
            ),
        ):
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd, ["open", "--yes"], obj=app
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotIn("nothing to do", result.output)
        self.assertEqual(app.cfg.guardrail.connectors["codex"].hook_fail_mode, "open")
        self.assertEqual(app.cfg.guardrail.connectors["cursor"].hook_fail_mode, "open")
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("cursor"), "open")
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        self.assertEqual(
            set(restart_mock.call_args.kwargs["connectors"]),
            {"codex", "cursor"},
        )

    def test_bare_set_open_is_refused_on_per_user_action_cursor(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "cursor": None})
        app.cfg.guardrail.hook_fail_mode = "closed"
        for name in ("codex", "cursor"):
            app.cfg.guardrail.connectors[name].mode = "action"
            app.cfg.guardrail.connectors[name].hook_fail_mode = "closed"
        state = SimpleNamespace(current=True, drift=(), desired="closed")
        with (
            patch("defenseclaw.commands.cmd_setup._restart_services"),
            patch("defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode", return_value=state),
        ):
            result = runner.invoke(cmd_guardrail.fail_mode_cmd, ["open", "--yes"], obj=app)
        self.assertNotEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.connectors["codex"].hook_fail_mode, "closed")
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("cursor"), "closed")
        self.assertIn("follows the policy tier", " ".join(result.output.split()))

        result = runner.invoke(cmd_guardrail.fail_mode_cmd, ["open", "--connector", "cursor", "--yes"], obj=app)
        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn("follows the policy tier", " ".join(result.output.split()))
        self.assertEqual(app.cfg.guardrail.effective_hook_fail_mode("cursor"), "closed")

    def test_confirm_refuses_when_output_is_piped(self):
        # GAP-1432: `fail-mode open 2>&1 | tail` hid the prompt in the pipe
        # and the command looked hung; it now refuses and names --yes.
        import sys

        runner = CliRunner()
        app = make_multi_ctx({"codex": None})
        app.cfg.deployment_mode = "managed_enterprise"
        app.cfg.managed_outside_secure_client = lambda: True
        app.cfg.guardrail.hook_fail_mode = "closed"
        app.cfg.guardrail.connectors["codex"].hook_fail_mode = "closed"
        state = SimpleNamespace(current=True, drift=(), desired="closed")
        with (
            patch.object(cmd_guardrail, "_isatty", side_effect=lambda stream: stream is sys.stdin),
            patch("defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode", return_value=state),
        ):
            result = runner.invoke(cmd_guardrail.fail_mode_cmd, ["open"], obj=app)
        self.assertEqual(result.exit_code, 2, msg=result.output)
        self.assertIn("Re-run it with --yes", result.output)
        app.cfg.save.assert_not_called()

    def test_bare_set_reload_failure_restores_config_and_runtime(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "cursor": None})
        app.cfg.guardrail.hook_fail_mode = "open"
        with (
            patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"),
            patch(
                "defenseclaw.commands.cmd_setup._restart_services",
                side_effect=[OSError("reload failed"), None],
            ) as restart_mock,
        ):
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app
            )
        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(app.cfg.guardrail.hook_fail_mode, "open")
        self.assertEqual(app.cfg.guardrail.connectors["codex"].hook_fail_mode, "")
        self.assertEqual(app.cfg.guardrail.connectors["cursor"].hook_fail_mode, "")
        self.assertEqual(restart_mock.call_count, 2)
        self.assertIn("restored", result.output)

    def test_connector_open_clears_dormant_closed_override_in_observe_mode(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.deployment_mode = "managed_enterprise"
        app.cfg.guardrail._secure_client = True
        app.cfg.guardrail.connectors["codex"].hook_fail_mode = "closed"
        with patch(
            "defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"
        ):
            result = runner.invoke(
                cmd_guardrail.fail_mode_cmd,
                ["open", "--connector", "codex", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotIn("nothing to do", result.output)
        self.assertRegex(result.output, r"closed (?:→|->) open")
        self.assertNotIn("open → open", result.output)
        self.assertEqual(app.cfg.guardrail.connectors["codex"].hook_fail_mode, "open")
        app.cfg.save.assert_called_once()

    def test_bare_show_fans_out_to_all_active_connectors(self):
        # No value AND no --connector: the bare read MUST show EVERY active
        # connector's effective fail mode (not just the global/active one),
        # so a 3-connector install shows all three.
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.connectors["codex"].mode = "action"
        app.cfg.guardrail.connectors["codex"].hook_fail_mode = "closed"
        result = runner.invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("per connector", result.output)
        self.assertIn("(codex)", result.output)
        self.assertIn("(claudecode)", result.output)
        # codex carries a closed override; claudecode inherits the open global.
        self.assertIn("closed", result.output)
        app.cfg.save.assert_not_called()


def _fake_hilt_preview(base_mode: str, profiles: dict | None = None, calls: list | None = None):
    """A stand-in for the gateway's connector hilt-preview answer.

    *profiles* maps a profile name to ``(mode, own_hilt)``, where *own_hilt*
    is ``None`` when the profile follows the connector's HILT block, else the
    ``(enabled, min_severity)`` of its own.
    """
    from defenseclaw.config_inspect import ConnectorHILTPreview, HILTPreviewScope

    def fake(connector, *, enabled, min_severity, config_path, gateway_binary=None):
        if calls is not None:
            calls.append((connector, enabled, min_severity, config_path))
        scopes = []
        for name, (mode, own_hilt) in sorted((profiles or {}).items()):
            own_enabled, own_min = own_hilt if own_hilt is not None else (enabled, min_severity)
            scopes.append(HILTPreviewScope(name, mode, own_enabled, own_min, own_hilt is None))
        base = HILTPreviewScope("", base_mode, enabled, min_severity, True)
        return ConnectorHILTPreview(connector, base, tuple(scopes))

    return fake


class HILTCommandTests(unittest.TestCase):
    """`guardrail hilt [on|off] [--min-severity X] [--connector Y]`."""

    def setUp(self):
        # The per-connector preview asks the gateway binary; no test reaches
        # an installed one.
        from defenseclaw.config_inspect import ConfigInspectError

        patcher = patch(
            "defenseclaw.config_inspect.connector_hilt_preview",
            side_effect=ConfigInspectError("defenseclaw-gateway is not installed; run defenseclaw upgrade"),
        )
        self.hilt_preview = patcher.start()
        self.addCleanup(patcher.stop)

    def test_connector_preview_explains_effective_observe_mode(self):
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.mode = "action"
        app.cfg.guardrail.connectors["claudecode"].mode = "observe"
        self.hilt_preview.side_effect = _fake_hilt_preview("observe")
        result = CliRunner().invoke(
            cmd_guardrail.hilt_cmd, ["on", "--connector", "claudecode"], obj=app, input="n\n",
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("observe mode", result.output)
        self.assertIn("does not pause actions for approval", result.output)
        self.assertNotIn("will prompt for approval", result.output)
        app.cfg.save.assert_not_called()

        app.cfg.guardrail.connectors["claudecode"].mode = "action"
        self.hilt_preview.side_effect = _fake_hilt_preview("action")
        result = CliRunner().invoke(
            cmd_guardrail.hilt_cmd, ["on", "--connector", "claudecode"], obj=app, input="n\n",
        )
        self.assertIn("will prompt for approval", result.output)

    def test_connector_preview_uses_the_gateway_hook_mode(self):
        """A legacy claude_code.mode: action wins over an observe guardrail mode (gateway precedence)."""
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.mode = "observe"
        app.cfg.guardrail.connectors["claudecode"].mode = "observe"
        calls: list = []
        # What the gateway resolves for this config.yaml plus claude_code.mode: action.
        self.hilt_preview.side_effect = _fake_hilt_preview("action", calls=calls)
        result = CliRunner().invoke(
            cmd_guardrail.hilt_cmd,
            ["on", "--min-severity", "medium", "--connector", "Claude-Code"],
            obj=app,
            input="n\n",
        )
        out = " ".join(result.output.split())
        self.assertIn("Claude Code will prompt for approval on supported confirmable actions at/above MEDIUM", out)
        self.assertNotIn("does not pause", out)
        # The command passes the normalized path (backslashes on Windows).
        config_path = os.path.normpath(os.path.join("/tmp/dc", "config.yaml"))
        self.assertEqual(calls, [("claudecode", True, "MEDIUM", config_path)])
        app.cfg.save.assert_not_called()

        self.hilt_preview.side_effect = _fake_hilt_preview("action")
        result = CliRunner().invoke(
            cmd_guardrail.hilt_cmd, ["off", "--connector", "claudecode"], obj=app, input="n\n",
        )
        self.assertIn("Claude Code will NOT prompt", result.output)

    def test_connector_preview_promises_nothing_without_the_gateway(self):
        app = make_multi_ctx({"codex": None, "claudecode": None})
        app.cfg.guardrail.connectors["claudecode"].mode = "action"
        result = CliRunner().invoke(
            cmd_guardrail.hilt_cmd, ["on", "--connector", "claudecode"], obj=app, input="n\n",
        )
        out = " ".join(result.output.split())
        self.assertIn("Could not resolve Claude Code's hook mode with the gateway", out)
        self.assertIn("defenseclaw guardrail profile explain --user <name> --connector claudecode", out)
        self.assertNotIn("will prompt for approval", out)
        self.assertNotIn("does not pause", out)
        app.cfg.save.assert_not_called()

    def test_connector_preview_names_action_mode_profiles(self):
        """An observe connector still prompts accounts a profile puts in action mode."""
        from defenseclaw.config import GuardrailProfile, HILTConfig, PerConnectorGuardrailConfig

        app = make_multi_ctx({"codex": None, "claudecode": None})
        gc = app.cfg.guardrail
        gc.profiles = {
            "ops": GuardrailProfile(mode="action"),
            "dev": GuardrailProfile(connectors={"claude-code": PerConnectorGuardrailConfig(mode="action")}),
            "own": GuardrailProfile(mode="action", hilt=HILTConfig(enabled=False)),
            "own-conn": GuardrailProfile(
                connectors={"claudecode": PerConnectorGuardrailConfig(mode="action", hilt=HILTConfig())}
            ),
            "codex-only": GuardrailProfile(connectors={"codex": PerConnectorGuardrailConfig(mode="action")}),
            "quiet": GuardrailProfile(mode="action", connectors={"claudecode": PerConnectorGuardrailConfig(mode="observe")}),
        }
        # The gateway's answer for those profiles.
        self.hilt_preview.side_effect = _fake_hilt_preview(
            "observe",
            {
                "ops": ("action", None),
                "dev": ("action", None),
                "own": ("action", (False, "HIGH")),
                "own-conn": ("action", (False, "")),
                "codex-only": ("observe", None),
                "quiet": ("observe", None),
            },
        )
        result = CliRunner().invoke(
            cmd_guardrail.hilt_cmd,
            ["on", "--min-severity", "MEDIUM", "--connector", "claudecode"],
            obj=app,
            input="n\n",
        )
        out = " ".join(result.output.split())
        self.assertIn("does not pause actions for approval", out)
        self.assertIn(
            "Guardrail profile(s) dev, ops put Claude Code in action mode: their accounts will be prompted "
            "for approval on confirmable actions at/above MEDIUM",
            out,
        )
        self.assertIn("Guardrail profile(s) own, own-conn set their own HILT policy", out)
        self.assertNotIn("codex-only", out)
        self.assertNotIn("quiet", out)
        app.cfg.save.assert_not_called()

        result = CliRunner().invoke(
            cmd_guardrail.hilt_cmd, ["off", "--connector", "claudecode"], obj=app, input="n\n",
        )
        out = " ".join(result.output.split())
        self.assertIn("Guardrail profile(s) dev, ops put Claude Code in action mode: their accounts will NOT be prompted", out)

    def test_connector_preview_names_observe_mode_profiles(self):
        """An action connector does not prompt accounts a profile puts in observe mode."""
        from defenseclaw.config import GuardrailProfile

        app = make_multi_ctx({"codex": None, "claudecode": None})
        gc = app.cfg.guardrail
        gc.connectors["claudecode"].mode = "action"
        gc.profiles = {
            "audit": GuardrailProfile(mode="observe"),
            "same": GuardrailProfile(mode="action"),
            "plain": GuardrailProfile(block_at="HIGH"),
        }
        self.hilt_preview.side_effect = _fake_hilt_preview(
            "action", {"audit": ("observe", None), "same": ("action", None), "plain": ("action", None)}
        )
        result = CliRunner().invoke(
            cmd_guardrail.hilt_cmd, ["on", "--connector", "claudecode"], obj=app, input="n\n",
        )
        out = " ".join(result.output.split())
        self.assertIn("Claude Code will prompt for approval", out)
        self.assertIn(
            "Guardrail profile(s) audit put Claude Code in observe mode: their accounts are not paused for approval.",
            out,
        )
        self.assertNotIn("same", out)
        self.assertNotIn("plain", out)
        self.assertNotIn("in action mode:", out)

    def test_copilot_enable_notice_matches_effective_mode(self):
        runner = CliRunner()
        for global_mode, copilot_mode, secure_client, expected in (
            ("observe", "action", False, "denied and audited as block (raw_action=confirm)"),
            ("action", "observe", False, "observe mode"),
            ("observe", "action", True, "Secure Client will prompt for approval"),
        ):
            with self.subTest(global_mode=global_mode, copilot_mode=copilot_mode, secure_client=secure_client):
                app = make_multi_ctx({"copilot": None, "codex": None})
                app.cfg.guardrail.mode = global_mode
                app.cfg.guardrail.connectors["copilot"].mode = copilot_mode
                # The train's preview reads the hook mode from the gateway.
                self.hilt_preview.side_effect = _fake_hilt_preview(copilot_mode)
                with (
                    patch.object(cmd_guardrail, "_report_hot_hilt"),
                    patch.object(cmd_guardrail.asset_lists, "is_secure_client", return_value=secure_client),
                    patch("defenseclaw.commands.cmd_setup._restart_services"),
                ):
                    result = runner.invoke(
                        cmd_guardrail.hilt_cmd,
                        ["on", "--min-severity", "HIGH", "--connector", "copilot", "--yes"],
                        obj=app,
                    )
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertIn(expected, result.output)
                if copilot_mode == "action" and not secure_client:
                    self.assertNotIn("produce alerts", result.output)
                app.cfg.save.assert_called_once()

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
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.hilt_cmd,
                ["on", "--min-severity", "MEDIUM", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(app.cfg.guardrail.hilt.enabled)
        self.assertEqual(app.cfg.guardrail.hilt.min_severity, "MEDIUM")
        app.cfg.save.assert_called_once()
        # The gateway applies HILT from the new config generation (GAP-0056).
        restart_mock.assert_not_called()

    def test_partial_change_preserves_other_field(self):
        runner = CliRunner()
        app = make_multi_ctx({})
        app.cfg.guardrail.hilt.enabled = True
        app.cfg.guardrail.hilt.min_severity = "HIGH"
        with patch("defenseclaw.commands.cmd_setup._restart_services"):
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
        app = make_multi_ctx({"codex": None, "cursor": None})
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.hilt_cmd,
                ["on", "--min-severity", "MEDIUM", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(app.cfg.guardrail.hilt.enabled)
        for connector in ("codex", "cursor"):
            eff = app.cfg.guardrail.effective_hilt(connector)
            self.assertTrue(eff.enabled)
            self.assertEqual(eff.min_severity, "MEDIUM")
        app.cfg.save.assert_called_once()
        restart_mock.assert_not_called()

    def test_bare_set_off_reconciles_enabled_connector_override(self):
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "cursor": None})
        from defenseclaw import config as dcconfig

        app.cfg.guardrail.hilt.enabled = False
        app.cfg.guardrail.hilt.min_severity = "HIGH"
        app.cfg.guardrail.connectors["cursor"].hilt = dcconfig.HILTConfig(
            enabled=True, min_severity="MEDIUM"
        )
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(cmd_guardrail.hilt_cmd, ["off", "--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotIn("nothing to do", result.output)
        for connector in ("codex", "cursor"):
            eff = app.cfg.guardrail.effective_hilt(connector)
            self.assertFalse(eff.enabled)
        self.assertEqual(app.cfg.guardrail.connectors["cursor"].hilt.min_severity, "MEDIUM")
        app.cfg.save.assert_called_once()
        restart_mock.assert_not_called()

    def test_set_one_connector_persists_and_restarts_only_it_on_secure_client(self):
        # Secure Client keeps the restart of main (issue #1092, GAP-0056).
        runner = CliRunner()
        app = make_multi_ctx({"codex": None, "claudecode": None})
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services"
        ) as restart_mock, patch("defenseclaw.enforce.asset_lists.is_secure_client", return_value=True):
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


    def test_documented_default_reset_turns_human_approval_off(self):
        # GAP-0544: reference/policy/defaults.mdx "go back to the defaults"
        # must also clear a per-connector override from `setup guardrail
        # --connector X --human-approval`.
        import re
        from pathlib import Path

        from defenseclaw import config as dcconfig
        from defenseclaw.commands import cmd_setup

        page = Path(__file__).resolve().parents[2] / "docs-site/content/docs/policies/defaults.mdx"
        block = re.search(r"go back to the defaults:\n\n```bash\n(.*?)```", page.read_text(), re.S)
        self.assertIsNotNone(block)
        app = make_multi_ctx({"claudecode": None})
        gc = app.cfg.guardrail
        gc.hilt = dcconfig.HILTConfig(enabled=True, min_severity="HIGH")
        gc.connectors["claudecode"].hilt = dcconfig.HILTConfig(enabled=True, min_severity="HIGH")
        for line in block[1].splitlines():
            args = line.split()[1:]
            if args[:2] == ["setup", "guardrail"]:
                self.assertNotIn("--connector", args)
                approval = {"--human-approval": True, "--no-human-approval": False}
                cmd_setup._apply_guardrail_extra_options(
                    gc,
                    rule_pack=None,
                    human_approval=next((approval[a] for a in args if a in approval), None),
                    hilt_min_severity=None,
                )
            elif args[:2] == ["guardrail", "hilt"]:
                result = CliRunner().invoke(cmd_guardrail.hilt_cmd, args[2:], obj=app, input="")
                self.assertEqual(result.exit_code, 0, msg=result.output)
            else:
                # `policy activate` does not copy a preset's hilt section.
                self.assertEqual(args[:2], ["policy", "activate"], msg=line)
        self.assertFalse(gc.effective_hilt("claudecode").enabled)
        flag_doc = page.parents[1] / "guardrail/index.mdx"
        self.assertIn("Without --connector it changes only the global guardrail.hilt", flag_doc.read_text())


class BlockMessageCommandTests(unittest.TestCase):
    """`guardrail block-message [TEXT] [--clear] [--connector X]`."""

    def setUp(self):
        # These cases restart a running gateway; a stopped one is left
        # stopped (GAP-1370).
        patcher = patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

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
        app = make_multi_ctx({"codex": None, "cursor": None})
        app.cfg.guardrail.block_message = "Old global"
        app.cfg.guardrail.connectors["cursor"].block_message = "Cursor scoped block"
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.block_message_cmd,
                ["Global block", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.block_message, "Global block")
        for connector in ("codex", "cursor"):
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
        app = make_multi_ctx({"codex": None, "cursor": None})
        app.cfg.guardrail.block_message = "Global block"
        app.cfg.guardrail.connectors["codex"].block_message = "Codex scoped block"
        app.cfg.guardrail.connectors["cursor"].block_message = "Cursor scoped block"
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_guardrail.block_message_cmd,
                ["--clear", "--yes"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.guardrail.block_message, "")
        for connector in ("codex", "cursor"):
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
        # validate-pack delegates strict offline validation to the installed
        # gateway helper without starting the runtime. mode flips observe /
        # action without re-running setup, and protection turns the opt-in
        # protection packs on and off per scope. block-at / alert-at set the
        # tool-call block and alert levels, globally or per connector.
        # allow-private-upstream records private upstream hosts the
        # gateway may reach (guardrail.allow_private_upstreams). profile
        # lists and explains the identity-based guardrail profiles. rule and
        # suppress edit guardrail.rules (enable/disable/severity, suppressions).
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
                "block-at",
                "alert-at",
                "allow-private-upstream",
                "judge",
                "list-packs",
                "mode",
                "profile",
                "protection",
                "rule",
                "suppress",
                "use-pack",
                "validate-pack",
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

    def test_scoped_summary_matches_json(self):
        app = self._multi()
        app.cfg.guardrail.effective_enabled = lambda name: name == "hermes"
        runner = CliRunner()
        text = runner.invoke(cmd_guardrail.status_cmd, ["--connector", "codex"], obj=app)
        machine = runner.invoke(cmd_guardrail.status_cmd, ["--connector", "codex", "--json"], obj=app)
        self.assertEqual(text.exit_code, 0, text.output)
        self.assertEqual(machine.exit_code, 0, machine.output)
        self.assertIn("enabled:    no", text.output)
        self.assertFalse(json.loads(machine.output)["enabled"])

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
