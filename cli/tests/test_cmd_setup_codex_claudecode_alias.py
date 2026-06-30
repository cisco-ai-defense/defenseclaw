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

"""Regression tests for the ``setup codex`` / ``setup claude-code`` aliases.

These aliases configure DefenseClaw for hook-only operation against a
connector set (Codex / Claude Code) so the rest of the CLI/TUI surfaces
the matching connector's source-of-truth files (``~/.codex`` /
``~/.claude``).

The tests pin two architectural invariants:

1. **Connector identity flows everywhere.** Both
   ``cfg.guardrail.connector`` and ``cfg.claw.mode`` must be set so
   downstream consumers (Go ``activeConnector()``, Python
   ``Config.active_connector``, the TUI's
   ``ActiveConnectorName``, plus skill / MCP / plugin readers) all
   agree on which framework is active.
2. **Persistence + hint.** Running an alias must persist
   ``config.yaml`` and update ``<data_dir>/picked_connector`` so a
   subsequent ``defenseclaw setup guardrail`` defaults to the same
   connector.

The tests stub out the gateway restart and any local-stack bring-up so
they run cleanly in CI without Docker / a built sidecar binary.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw import platform_support
from defenseclaw.commands.cmd_setup import setup as setup_group

from tests.helpers import cleanup_app, make_app_context

HOOK_ALIAS_CONNECTORS = (
    "hermes",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
    "opencode",
    "omnigent",
)


def _invoke(args: list[str], app):
    """Run a `defenseclaw setup ...` subcommand against *app* via CliRunner.

    We always set ``catch_exceptions=False`` so an unexpected exception
    inside the command surfaces as a real test failure rather than a
    masked non-zero exit code — these tests want to validate the happy
    path and any regression should be loud, not silent.
    """
    runner = CliRunner()
    return runner.invoke(setup_group, args, obj=app, catch_exceptions=False)


class TestSetupCodexAlias(unittest.TestCase):
    """`defenseclaw setup codex` should always land in observability mode."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        # Defaults shouldn't matter — the alias is meant to be safe
        # regardless of where the operator is starting from. We
        # deliberately seed *non*-default values so a regression that
        # silently leaves these alone is caught.
        self.app.cfg.claw.mode = "openclaw"
        self.app.cfg.guardrail.connector = "openclaw"
        # Make ``cfg.save()`` a fast no-op disk write to a temp file
        # so the alias's persistence step actually runs and we can
        # assert on the post-write state.
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")

        def _save():
            with open(self.cfg_path, "w") as fh:
                fh.write(
                    f"claw_mode: {self.app.cfg.claw.mode}\nguardrail_connector: {self.app.cfg.guardrail.connector}\n"
                )

        self.app.cfg.save = _save  # type: ignore[assignment]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _run(self, *extra_args):
        with (
            patch(
                "defenseclaw.commands.cmd_setup._restart_services",
                return_value=None,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
                return_value=None,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            ),
        ):
            return _invoke(["codex", "--yes", *extra_args], self.app)

    def test_pins_connector_and_claw_mode(self):
        """Active-connector resolution must flip to codex everywhere."""
        result = self._run()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.guardrail.connector, "codex")
        self.assertEqual(self.app.cfg.claw.mode, "codex")
        # ``Config.active_connector`` must agree.
        self.assertEqual(self.app.cfg.active_connector(), "codex")

    def test_observability_defaults_are_loadable(self):
        """The persisted observability defaults must be sensible.

        These never get *read* by the gateway in observability mode
        (the Go connector setup short-circuits before they matter), but
        the YAML still has to round-trip cleanly when the operator
        eventually flips enforcement on.
        """
        result = self._run()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertTrue(gc.enabled)
        self.assertEqual(gc.mode, "observe")
        self.assertEqual(gc.scanner_mode, "local")
        # SU-02/ND-1: hook setup no longer clobbers detection_strategy down to
        # regex_only — it preserves the documented dataclass default
        # (regex_judge), so a later `guardrail judge add` survives a setup
        # re-run. The per-direction completion strategy is still seeded
        # (regex_only) only when unset.
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.detection_strategy_completion, "regex_only")
        self.assertFalse(gc.judge.enabled)

    def test_writes_picked_connector_hint(self):
        """``<data_dir>/picked_connector`` must round-trip the choice."""
        result = self._run()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        hint_path = os.path.join(self.app.cfg.data_dir, "picked_connector")
        self.assertTrue(os.path.isfile(hint_path), "picked_connector hint missing")
        with open(hint_path) as fh:
            self.assertEqual(fh.read().strip(), "codex")

    def test_persists_config_to_disk(self):
        """The alias must call cfg.save(); the cfg.yaml file should exist."""
        result = self._run()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(
            os.path.isfile(self.cfg_path),
            "expected setup codex to persist config.yaml via cfg.save()",
        )

    def test_no_restart_flag_skips_gateway_bounce(self):
        """``--no-restart`` must not invoke the restart helper.

        Regression: an earlier draft restarted unconditionally, which
        broke installs running on systems without the gateway binary
        on PATH.
        """
        with (
            patch(
                "defenseclaw.commands.cmd_setup._restart_services",
                return_value=None,
            ) as restart_mock,
            patch(
                "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
                return_value=None,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            ),
        ):
            result = _invoke(["codex", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        restart_mock.assert_not_called()


class TestSetupClaudeCodeAlias(unittest.TestCase):
    """`defenseclaw setup claude-code` mirrors the codex alias for Claude Code."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.claw.mode = "openclaw"
        self.app.cfg.guardrail.connector = "openclaw"
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")

        def _save():
            with open(self.cfg_path, "w") as fh:
                fh.write("placeholder\n")

        self.app.cfg.save = _save  # type: ignore[assignment]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _run(self, *extra_args):
        with (
            patch(
                "defenseclaw.commands.cmd_setup._restart_services",
                return_value=None,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
                return_value=None,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            ),
        ):
            return _invoke(["claude-code", "--yes", *extra_args], self.app)

    def test_pins_connector_and_claw_mode_to_claudecode(self):
        result = self._run()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.guardrail.connector, "claudecode")
        self.assertEqual(self.app.cfg.claw.mode, "claudecode")
        self.assertEqual(self.app.cfg.active_connector(), "claudecode")

    def test_writes_picked_connector_hint(self):
        result = self._run()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        hint_path = os.path.join(self.app.cfg.data_dir, "picked_connector")
        self.assertTrue(os.path.isfile(hint_path), "picked_connector hint missing")
        with open(hint_path) as fh:
            self.assertEqual(fh.read().strip(), "claudecode")

    def test_observability_defaults(self):
        result = self._run()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertTrue(gc.enabled)
        self.assertEqual(gc.mode, "observe")
        self.assertEqual(gc.scanner_mode, "local")
        self.assertFalse(gc.judge.enabled)


class TestSetupNewConnectorAliases(unittest.TestCase):
    """The hook-first connectors expose the same observability alias contract."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")

        def _save():
            with open(self.cfg_path, "w") as fh:
                fh.write(
                    f"claw_mode: {self.app.cfg.claw.mode}\nguardrail_connector: {self.app.cfg.guardrail.connector}\n"
                )

        self.app.cfg.save = _save  # type: ignore[assignment]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_new_aliases_pin_observability_connector(self):
        for connector in platform_support.supported_connectors(HOOK_ALIAS_CONNECTORS):
            with (
                self.subTest(connector=connector),
                patch(
                    "defenseclaw.commands.cmd_setup._restart_services",
                    return_value=None,
                ) as restart_mock,
                patch(
                    "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
                    return_value=None,
                ),
                patch(
                    "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                    return_value=True,
                ),
            ):
                self.app.cfg.claw.mode = "openclaw"
                self.app.cfg.guardrail.connector = "openclaw"
                result = _invoke([connector, "--yes", "--no-restart"], self.app)

                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertEqual(self.app.cfg.guardrail.connector, connector)
                self.assertEqual(self.app.cfg.claw.mode, connector)
                self.assertEqual(self.app.cfg.claw.workspace_dir, "")
                self.assertIn("Scope: global user config", result.output)
                self.assertTrue(self.app.cfg.guardrail.enabled)
                self.assertEqual(self.app.cfg.guardrail.mode, "observe")
                self.assertEqual(self.app.cfg.guardrail.scanner_mode, "local")
                self.assertFalse(self.app.cfg.guardrail.judge.enabled)
                self.assertIn(f"Connector {connector!r} configured", result.output)
                self.assertNotIn("claw.mode=", result.output)
                self.assertNotIn("claw.mode:", result.output)
                self.assertIn(f"{connector} mode=observe", result.output)
                self.assertIn(f"defenseclaw setup {connector} --mode action", result.output)
                self.assertNotIn("Active connector set", result.output)
                self.assertNotIn("guardrail.mode=observe", result.output)
                self.assertNotIn("guardrail.mode:", result.output)
                self.assertNotIn("set guardrail.mode=action", result.output)
                restart_mock.assert_not_called()

                hint_path = os.path.join(self.app.cfg.data_dir, "picked_connector")
                with open(hint_path) as fh:
                    self.assertEqual(fh.read().strip(), connector)

    def test_new_aliases_support_hook_action_mode(self):
        for connector in platform_support.supported_connectors(HOOK_ALIAS_CONNECTORS):
            with (
                self.subTest(connector=connector),
                patch(
                    "defenseclaw.commands.cmd_setup._restart_services",
                    return_value=None,
                ) as restart_mock,
                patch(
                    "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
                    return_value=None,
                ),
                patch(
                    "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                    return_value=True,
                ) as version_mock,
            ):
                self.app.cfg.claw.mode = "openclaw"
                self.app.cfg.guardrail.connector = "openclaw"
                self.app.cfg.guardrail.mode = "observe"
                result = _invoke([connector, "--yes", "--mode", "action", "--no-restart"], self.app)

                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertEqual(self.app.cfg.guardrail.connector, connector)
                self.assertEqual(self.app.cfg.claw.mode, connector)
                self.assertEqual(self.app.cfg.claw.workspace_dir, "")
                self.assertTrue(self.app.cfg.guardrail.enabled)
                self.assertEqual(self.app.cfg.guardrail.mode, "action")
                self.assertIn(f"{connector} mode=action", result.output)
                self.assertNotIn("guardrail.mode=action", result.output)
                self.assertNotIn("guardrail.mode:", result.output)
                self.assertIn(f"defenseclaw setup {connector} --mode observe", result.output)
                self.assertNotIn("set guardrail.mode=observe", result.output)
                version_mock.assert_called_with(
                    connector,
                    mode="action",
                    data_dir=self.app.cfg.data_dir,
                    _allow_prompt=False,
                )
                restart_mock.assert_not_called()

    def test_yes_no_restart_setup_does_not_reference_missing_interactive_flag(self):
        for connector in ["hermes", "codex", "opencode"]:
            with (
                self.subTest(connector=connector),
                patch(
                    "defenseclaw.commands.cmd_setup._restart_services",
                    return_value=None,
                ),
                patch(
                    "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
                    return_value=None,
                ),
                patch(
                    "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                    return_value=True,
                ) as version_mock,
            ):
                self.app.cfg.claw.mode = "openclaw"
                self.app.cfg.guardrail.connector = "openclaw"
                self.app.cfg.guardrail.connectors = {}
                result = _invoke([connector, "--yes", "--no-restart"], self.app)

                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertEqual(self.app.cfg.guardrail.connector, connector)
                self.assertNotIn("NameError", result.output)
                version_mock.assert_called_with(
                    connector,
                    mode="observe",
                    data_dir=self.app.cfg.data_dir,
                    _allow_prompt=False,
                )

    def test_alias_workspace_option_pins_workspace(self):
        workspace = os.path.join(self.tmp_dir, "repo")
        os.makedirs(workspace)
        with (
            patch("defenseclaw.platform_support.host_os", return_value="linux"),
            patch("defenseclaw.commands.cmd_setup._restart_services", return_value=None),
            patch("defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack", return_value=None),
            patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True),
        ):
            result = _invoke(["openhands", "--yes", "--no-restart", "--workspace", workspace], self.app)

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.claw.workspace_dir, os.path.realpath(workspace))
        self.assertIn("Workspace root pinned", result.output)

    def test_antigravity_alias_rejects_workspace(self):
        """Antigravity is global-only by design: agy merges every hooks
        file it discovers, so a workspace-scoped install would silently
        fire the same hook multiple times per tool call. The alias must
        reject --workspace rather than accept it and quietly do the
        wrong thing.
        """
        workspace = os.path.join(self.tmp_dir, "repo")
        os.makedirs(workspace)
        with (
            patch("defenseclaw.commands.cmd_setup._restart_services", return_value=None),
            patch("defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack", return_value=None),
            patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True),
        ):
            result = _invoke(
                ["antigravity", "--yes", "--no-restart", "--workspace", workspace],
                self.app,
            )

        self.assertNotEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("does not support --workspace", result.output)
        # Sanity: the rejected setup must not have mutated config.
        self.assertEqual(self.app.cfg.claw.workspace_dir, "")
        self.assertNotEqual(self.app.cfg.claw.mode, "antigravity")

    def test_setup_help_lists_new_alias_commands(self):
        result = _invoke(["--help"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        for connector in HOOK_ALIAS_CONNECTORS:
            self.assertIn(connector, result.output)
        self.assertIn("codex, claudecode", result.output)
        self.assertIn("hermes, antigravity", result.output)
        self.assertIn("OpenClaw/ZeptoClaw use the proxy path", result.output)
        self.assertNotIn("antigravity, openclaw", result.output)
        self.assertNotIn("openclaw) tracked under guardrail.connectors", result.output)

    def test_hook_help_uses_connector_set_wording(self):
        for connector in ("codex", "claude-code", *HOOK_ALIAS_CONNECTORS):
            with self.subTest(connector=connector):
                result = _invoke([connector, "--help"], self.app)
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertIn("hook connector set", result.output)
                self.assertNotIn("Pins the active connector", result.output)
                self.assertNotIn("Pins claw.mode", result.output)
                self.assertNotIn("OpenClaw default layout", result.output)

    def test_omnigent_help_describes_policy_api_not_pretool_hooks(self):
        result = _invoke(["omnigent", "--help"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("custom policy API", result.output)
        self.assertIn("approval verdict", result.output)
        self.assertNotIn("PreToolUse deny", result.output)
        self.assertNotIn("pre-tool hook", result.output)

    def test_guardrail_help_mentions_new_connector_choices(self):
        result = _invoke(["guardrail", "--help"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        for connector in platform_support.supported_connectors(HOOK_ALIAS_CONNECTORS):
            self.assertIn(connector, result.output)
        choice_text = result.output.split("--connector, --agent [", 1)[1].split("]", 1)[0]
        for connector in platform_support.WINDOWS_UNSUPPORTED_CONNECTORS:
            self.assertNotIn(connector, choice_text)
        self.assertNotIn("openclaw, claudecode, codex, zeptoclaw", result.output)

    def test_rotate_token_help_is_connector_agnostic(self):
        result = _invoke(["rotate-token", "--help"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # Connector-agnostic: the refresh spans every active connector and
        # never pins to a specific one (the token is a shared secret).
        self.assertIn("active connector", result.output)
        self.assertNotIn("Claude", result.output)
        self.assertNotIn("Codex", result.output)


class TestSetupCodexAliasInteractiveDecline(unittest.TestCase):
    """When the operator declines the confirm prompt, the alias is a no-op."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.claw.mode = "openclaw"
        self.app.cfg.guardrail.connector = "openclaw"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_decline_leaves_state_unchanged(self):
        with (
            patch(
                "defenseclaw.commands.cmd_setup.click.confirm",
                return_value=False,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._restart_services",
                return_value=None,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
                return_value=None,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            ),
        ):
            result = _invoke(["codex"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # No mutation: connector / claw mode untouched.
        self.assertEqual(self.app.cfg.claw.mode, "openclaw")
        self.assertEqual(self.app.cfg.guardrail.connector, "openclaw")
        # Hint file must not be written when the operator aborted.
        hint_path = os.path.join(self.app.cfg.data_dir, "picked_connector")
        self.assertFalse(
            os.path.isfile(hint_path),
            "decline path must not write picked_connector hint",
        )


class TestApplyConnectorObservabilityHelper(unittest.TestCase):
    """Direct unit test for the shared helper.

    Both Click commands defer to ``_apply_connector_observability_only``
    which is the single decision point. Pinning its contract here
    means a regression in the helper fails this test loudly even if a
    future Click refactor renames either alias.
    """

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")

        def _save():
            with open(self.cfg_path, "w") as fh:
                fh.write("placeholder\n")

        self.app.cfg.save = _save  # type: ignore[assignment]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_rejects_unsupported_connector(self):
        """OpenClaw / ZeptoClaw must not slip through this code path.

        They have full enforcement integrations and don't have an
        observability-only equivalent yet — see docs/OBSERVABILITY.md.
        """
        from defenseclaw.commands.cmd_setup import (
            _apply_connector_observability_only,
        )

        ok = _apply_connector_observability_only(
            self.app,
            connector="openclaw",
            restart=False,
        )
        self.assertFalse(ok)

    def test_idempotent(self):
        """Running the helper twice yields the same on-disk state."""
        from defenseclaw.commands.cmd_setup import (
            _apply_connector_observability_only,
        )

        with (
            patch(
                "defenseclaw.commands.cmd_setup._restart_services",
                return_value=None,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            ),
        ):
            ok1 = _apply_connector_observability_only(
                self.app,
                connector="codex",
                restart=False,
            )
            self.assertTrue(ok1)
            snapshot_first = (
                self.app.cfg.claw.mode,
                self.app.cfg.guardrail.connector,
                self.app.cfg.guardrail.mode,
            )

            ok2 = _apply_connector_observability_only(
                self.app,
                connector="codex",
                restart=False,
            )
            self.assertTrue(ok2)
            snapshot_second = (
                self.app.cfg.claw.mode,
                self.app.cfg.guardrail.connector,
                self.app.cfg.guardrail.mode,
            )

        self.assertEqual(snapshot_first, snapshot_second)


class TestPickedConnectorHintAtomicity(unittest.TestCase):
    """The hint writer must be atomic — partial writes break the picker."""

    def test_replaces_existing_hint(self):
        from defenseclaw.commands.cmd_setup import (
            _write_picked_connector_hint,
        )

        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "picked_connector")
            with open(target, "w") as fh:
                fh.write("openclaw\n")

            _write_picked_connector_hint(tmp, "codex")

            with open(target) as fh:
                self.assertEqual(fh.read().strip(), "codex")
            # The .tmp scratch file must not linger.
            self.assertFalse(
                os.path.exists(target + ".tmp"),
                "atomic-replace tmp file should be cleaned up by os.replace",
            )

    def test_rejects_unknown_connector(self):
        """Reject unrecognised names so a typo can't poison the hint."""
        from defenseclaw.commands.cmd_setup import (
            _write_picked_connector_hint,
        )

        with tempfile.TemporaryDirectory() as tmp:
            _write_picked_connector_hint(tmp, "definitely-not-a-connector")
            self.assertFalse(
                os.path.exists(os.path.join(tmp, "picked_connector")),
                "unknown connector names must not produce a hint file",
            )

    def test_handles_missing_data_dir(self):
        from defenseclaw.commands.cmd_setup import (
            _write_picked_connector_hint,
        )

        # Should not raise — None / empty data_dir is a soft no-op.
        _write_picked_connector_hint(None, "codex")
        _write_picked_connector_hint("", "codex")


class TestConnectorRulePackFlag(unittest.TestCase):
    """`setup <connector> --rule-pack` parity with single-connector.

    Single-connector parity: in single-connector mode the operator
    selects the connector's rule pack with ``setup guardrail --rule-pack``.
    The multi-connector equivalent is being able to give *each* connector
    its own pack. These tests pin both shapes of the new flag:

      * sole connector  -> writes the GLOBAL ``guardrail.rule_pack_dir``
        (identical to single-connector behavior)
      * one of several  -> writes a PER-CONNECTOR override so peers keep
        their own pack / the global default, and each connector's
        ``effective_rule_pack_dir`` resolves independently.
    """

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        # Start from a proxy-backed single connector so the first hook
        # alias resolves write_mode="replace" (no hook peer present).
        self.app.cfg.claw.mode = "openclaw"
        self.app.cfg.guardrail.connector = "openclaw"
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")

        def _save():
            with open(self.cfg_path, "w") as fh:
                fh.write("placeholder\n")

        self.app.cfg.save = _save  # type: ignore[assignment]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _run(self, *args):
        with (
            patch(
                "defenseclaw.commands.cmd_setup._restart_services",
                return_value=None,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
                return_value=None,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            ),
        ):
            return _invoke([*args], self.app)

    def test_sole_connector_sets_global_rule_pack(self):
        # Codex is the only (hook) connector -> replace -> global pack,
        # matching single-connector `setup guardrail --rule-pack`.
        result = self._run("codex", "--yes", "--no-restart", "--rule-pack", "strict")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertTrue(
            gc.rule_pack_dir.endswith(os.path.join("guardrail", "strict")),
            f"global rule_pack_dir not set: {gc.rule_pack_dir!r}",
        )
        # No per-connector block written in the sole-connector shape.
        self.assertEqual(gc.connectors, {})

    def test_per_connector_packs_resolve_independently(self):
        # codex strict (sole -> global), then claude-code permissive
        # (now a peer -> per-connector override). Result: codex inherits
        # the global strict pack, claudecode runs permissive.
        r1 = self._run("codex", "--yes", "--no-restart", "--rule-pack", "strict")
        self.assertEqual(r1.exit_code, 0, msg=r1.output)
        r2 = self._run(
            "claude-code", "--yes", "--no-restart", "--rule-pack", "permissive"
        )
        self.assertEqual(r2.exit_code, 0, msg=r2.output)

        gc = self.app.cfg.guardrail
        # Both connectors are in the multi map (codex seeded on the add).
        self.assertEqual(set(gc.connectors), {"codex", "claudecode"})
        # codex has no override -> inherits the global strict pack.
        self.assertEqual(gc.connectors["codex"].rule_pack_dir, "")
        # claudecode carries its own permissive override.
        self.assertTrue(
            gc.connectors["claudecode"].rule_pack_dir.endswith(
                os.path.join("guardrail", "permissive")
            )
        )
        # The resolver is what the gateway uses at boot — assert it.
        self.assertTrue(
            gc.effective_rule_pack_dir("codex").endswith(
                os.path.join("guardrail", "strict")
            )
        )
        self.assertTrue(
            gc.effective_rule_pack_dir("claudecode").endswith(
                os.path.join("guardrail", "permissive")
            )
        )

    def test_rule_pack_omitted_leaves_packs_untouched(self):
        # No --rule-pack -> neither global nor per-connector pack is set
        # by the alias (regression guard against accidental writes).
        result = self._run("codex", "--yes", "--no-restart")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.rule_pack_dir, "")
        self.assertEqual(gc.connectors, {})

    # ------------------------------------------------------------------
    # R1 — free-text --rule-pack-dir (CLI parity with the TUI's free-text
    # field). The directory follows the SAME global-vs-per-connector
    # scoping as the preset --rule-pack.
    # ------------------------------------------------------------------

    def test_rule_pack_dir_sets_global_on_sole_connector(self):
        # Codex is the only (hook) connector -> replace -> the free-text
        # dir lands on the GLOBAL rule_pack_dir, anchored absolute.
        custom = os.path.join(self.tmp_dir, "my-pack")
        os.makedirs(custom, exist_ok=True)
        result = self._run(
            "codex", "--yes", "--no-restart", "--rule-pack-dir", custom
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.rule_pack_dir, os.path.abspath(custom))
        self.assertEqual(gc.connectors, {})

    def test_rule_pack_dir_per_connector_override(self):
        # codex (sole -> global preset), then claude-code with a free-text
        # dir (now a peer -> per-connector override). codex inherits the
        # global strict pack; claudecode runs the custom dir.
        custom = os.path.join(self.tmp_dir, "cc-pack")
        os.makedirs(custom, exist_ok=True)
        r1 = self._run("codex", "--yes", "--no-restart", "--rule-pack", "strict")
        self.assertEqual(r1.exit_code, 0, msg=r1.output)
        r2 = self._run(
            "claude-code", "--yes", "--no-restart", "--rule-pack-dir", custom
        )
        self.assertEqual(r2.exit_code, 0, msg=r2.output)

        gc = self.app.cfg.guardrail
        self.assertEqual(set(gc.connectors), {"codex", "claudecode"})
        # codex has no override -> inherits the global strict pack.
        self.assertEqual(gc.connectors["codex"].rule_pack_dir, "")
        # claudecode carries its own free-text dir override (absolute).
        self.assertEqual(
            gc.connectors["claudecode"].rule_pack_dir, os.path.abspath(custom)
        )
        # The resolver the gateway uses at boot reflects both.
        self.assertTrue(
            gc.effective_rule_pack_dir("codex").endswith(
                os.path.join("guardrail", "strict")
            )
        )
        self.assertEqual(
            gc.effective_rule_pack_dir("claudecode"), os.path.abspath(custom)
        )

    def test_rule_pack_dir_missing_is_rejected(self):
        custom = os.path.join(self.tmp_dir, "missing-pack")
        result = self._run(
            "codex", "--yes", "--no-restart", "--rule-pack-dir", custom
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--rule-pack-dir", result.output)
        self.assertIn("does not exist", result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.rule_pack_dir, "")
        self.assertEqual(gc.connectors, {})

    def test_rule_pack_and_rule_pack_dir_are_mutually_exclusive(self):
        # Naming a pack two ways in one invocation is the one-input-two-
        # meanings ambiguity R3 removes — reject it loudly, write nothing.
        result = self._run(
            "codex",
            "--yes",
            "--no-restart",
            "--rule-pack",
            "strict",
            "--rule-pack-dir",
            os.path.join(self.tmp_dir, "x"),
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("mutually exclusive", result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.rule_pack_dir, "")
        self.assertEqual(gc.connectors, {})

    def test_rule_pack_dir_empty_string_clears_global(self):
        # Seed a global pack, then `--rule-pack-dir ""` explicitly clears
        # the override back to the inherited/built-in default.
        r1 = self._run("codex", "--yes", "--no-restart", "--rule-pack", "strict")
        self.assertEqual(r1.exit_code, 0, msg=r1.output)
        self.assertTrue(self.app.cfg.guardrail.rule_pack_dir)
        r2 = self._run("codex", "--yes", "--no-restart", "--rule-pack-dir", "")
        self.assertEqual(r2.exit_code, 0, msg=r2.output)
        self.assertEqual(self.app.cfg.guardrail.rule_pack_dir, "")


class TestGuardrailRulePackScoping(unittest.TestCase):
    """R3 — ``setup guardrail --connector X --rule-pack`` scopes per-connector.

    The hook aliases (``setup codex`` etc.) already write a per-connector
    override when the connector is a multi-install peer. R3 makes the proxy/
    global ``setup guardrail`` command agree: a named connector that owns an
    override block gets the pack written there, not silently onto the global
    field. Tested at the shared ``_apply_guardrail_extra_options`` helper so
    the scoping rule is pinned independent of the heavy command machinery.
    """

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _apply(self, **kwargs):
        from defenseclaw.commands.cmd_setup import _apply_guardrail_extra_options

        _apply_guardrail_extra_options(
            self.app,
            self.app.cfg.guardrail,
            human_approval=None,
            hilt_min_severity=None,
            **kwargs,
        )

    def test_named_peer_with_block_scopes_per_connector(self):
        from defenseclaw.config import PerConnectorGuardrailConfig

        gc = self.app.cfg.guardrail
        # Simulate a multi-install where hermes owns an override block.
        gc.connectors = {"hermes": PerConnectorGuardrailConfig()}
        self._apply(rule_pack="strict", connector="hermes")
        # Pack went to the per-connector block, NOT the global field (R3).
        self.assertEqual(gc.rule_pack_dir, "")
        self.assertTrue(
            gc.connectors["hermes"].rule_pack_dir.endswith(
                os.path.join("guardrail", "strict")
            )
        )

    def test_named_connector_without_block_falls_back_to_global(self):
        gc = self.app.cfg.guardrail
        # No per-connector block (single-connector / proxy shape) -> global,
        # matching the pre-R3 behavior so single installs are unchanged.
        self._apply(rule_pack="permissive", connector="openclaw")
        self.assertEqual(gc.connectors, {})
        self.assertTrue(
            gc.rule_pack_dir.endswith(os.path.join("guardrail", "permissive"))
        )

    def test_rule_pack_dir_scopes_like_preset(self):
        from defenseclaw.config import PerConnectorGuardrailConfig

        gc = self.app.cfg.guardrail
        gc.connectors = {"hermes": PerConnectorGuardrailConfig()}
        custom = os.path.join(self.tmp_dir, "hermes-pack")
        os.makedirs(custom, exist_ok=True)
        self._apply(rule_pack=None, rule_pack_dir=custom, connector="hermes")
        self.assertEqual(gc.rule_pack_dir, "")
        self.assertEqual(
            gc.connectors["hermes"].rule_pack_dir, os.path.abspath(custom)
        )

    def test_no_connector_keeps_global_scope(self):
        # Callers that don't pass a connector (e.g. the TUI wizard) keep the
        # historical global write — the new param is opt-in.
        gc = self.app.cfg.guardrail
        self._apply(rule_pack="default")
        self.assertTrue(
            gc.rule_pack_dir.endswith(os.path.join("guardrail", "default"))
        )


if __name__ == "__main__":
    unittest.main()
