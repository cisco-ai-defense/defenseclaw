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

These aliases configure DefenseClaw for observability-only operation
against a single connector (Codex / Claude Code) and flip ``claw.mode``
so the rest of the CLI/TUI surfaces the matching connector's source-of-
truth files (``~/.codex`` / ``~/.claude``) instead of the OpenClaw
default layout.

The tests pin three architectural invariants:

1. **No proxy data path.** The matching ``*_enforcement_enabled`` flag
   must come back from the alias as ``False`` no matter what its
   previous value was.
2. **Connector identity flows everywhere.** Both
   ``cfg.guardrail.connector`` and ``cfg.claw.mode`` must be set so
   downstream consumers (Go ``activeConnector()``, Python
   ``Config.active_connector``, the TUI's
   ``ActiveConnectorName``, plus skill / MCP / plugin readers) all
   agree on which framework is active.
3. **Persistence + hint.** Running an alias must persist
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

from defenseclaw.commands.cmd_setup import setup as setup_group
from tests.helpers import cleanup_app, make_app_context


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
        self.app.cfg.guardrail.codex_enforcement_enabled = True
        self.app.cfg.guardrail.claudecode_enforcement_enabled = True
        # Make ``cfg.save()`` a fast no-op disk write to a temp file
        # so the alias's persistence step actually runs and we can
        # assert on the post-write state.
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")

        def _save():
            with open(self.cfg_path, "w") as fh:
                fh.write(
                    f"claw_mode: {self.app.cfg.claw.mode}\n"
                    f"guardrail_connector: {self.app.cfg.guardrail.connector}\n"
                )

        self.app.cfg.save = _save  # type: ignore[assignment]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _run(self, *extra_args):
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services",
            return_value=None,
        ), patch(
            "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
            return_value=None,
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

    def test_disables_codex_enforcement(self):
        """Even when the previous flag was True, the alias must zero it."""
        # Pre-seed claudecode enforcement to False so we can prove the
        # codex alias doesn't accidentally toggle the sibling flag in
        # either direction.
        self.app.cfg.guardrail.claudecode_enforcement_enabled = False

        result = self._run()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(
            self.app.cfg.guardrail.codex_enforcement_enabled,
            "setup codex must disable enforcement (no proxy data path)",
        )
        # Sibling flag stayed False — codex alias never touches
        # claudecode enforcement.
        self.assertFalse(
            self.app.cfg.guardrail.claudecode_enforcement_enabled,
            "setup codex must not enable claudecode enforcement",
        )

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
        self.assertEqual(gc.detection_strategy, "regex_only")
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
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services",
            return_value=None,
        ) as restart_mock, patch(
            "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
            return_value=None,
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
        self.app.cfg.guardrail.codex_enforcement_enabled = True
        self.app.cfg.guardrail.claudecode_enforcement_enabled = True
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")

        def _save():
            with open(self.cfg_path, "w") as fh:
                fh.write("placeholder\n")

        self.app.cfg.save = _save  # type: ignore[assignment]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _run(self, *extra_args):
        with patch(
            "defenseclaw.commands.cmd_setup._restart_services",
            return_value=None,
        ), patch(
            "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
            return_value=None,
        ):
            return _invoke(["claude-code", "--yes", *extra_args], self.app)

    def test_pins_connector_and_claw_mode_to_claudecode(self):
        result = self._run()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.guardrail.connector, "claudecode")
        self.assertEqual(self.app.cfg.claw.mode, "claudecode")
        self.assertEqual(self.app.cfg.active_connector(), "claudecode")

    def test_disables_claudecode_enforcement(self):
        result = self._run()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(
            self.app.cfg.guardrail.claudecode_enforcement_enabled,
            "setup claude-code must disable enforcement (no proxy data path)",
        )
        # Codex enforcement is unrelated and must not be touched in
        # the direction it was previously set.
        self.assertTrue(
            self.app.cfg.guardrail.codex_enforcement_enabled,
            "setup claude-code must not clear codex enforcement",
        )

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


class TestSetupCodexAliasInteractiveDecline(unittest.TestCase):
    """When the operator declines the confirm prompt, the alias is a no-op."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.claw.mode = "openclaw"
        self.app.cfg.guardrail.connector = "openclaw"
        self.app.cfg.guardrail.codex_enforcement_enabled = True

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_decline_leaves_state_unchanged(self):
        with patch(
            "defenseclaw.commands.cmd_setup.click.confirm",
            return_value=False,
        ), patch(
            "defenseclaw.commands.cmd_setup._restart_services",
            return_value=None,
        ), patch(
            "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
            return_value=None,
        ):
            result = _invoke(["codex"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # No mutation: connector/claw mode untouched, enforcement
        # flag preserved.
        self.assertEqual(self.app.cfg.claw.mode, "openclaw")
        self.assertEqual(self.app.cfg.guardrail.connector, "openclaw")
        self.assertTrue(self.app.cfg.guardrail.codex_enforcement_enabled)
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
            self.app, connector="openclaw", restart=False,
        )
        self.assertFalse(ok)

    def test_idempotent(self):
        """Running the helper twice yields the same on-disk state."""
        from defenseclaw.commands.cmd_setup import (
            _apply_connector_observability_only,
        )

        with patch(
            "defenseclaw.commands.cmd_setup._restart_services",
            return_value=None,
        ):
            ok1 = _apply_connector_observability_only(
                self.app, connector="codex", restart=False,
            )
            self.assertTrue(ok1)
            snapshot_first = (
                self.app.cfg.claw.mode,
                self.app.cfg.guardrail.connector,
                self.app.cfg.guardrail.codex_enforcement_enabled,
                self.app.cfg.guardrail.mode,
            )

            ok2 = _apply_connector_observability_only(
                self.app, connector="codex", restart=False,
            )
            self.assertTrue(ok2)
            snapshot_second = (
                self.app.cfg.claw.mode,
                self.app.cfg.guardrail.connector,
                self.app.cfg.guardrail.codex_enforcement_enabled,
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


if __name__ == "__main__":
    unittest.main()
