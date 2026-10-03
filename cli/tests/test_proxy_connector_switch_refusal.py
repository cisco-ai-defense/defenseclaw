# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-2455: no command silently switches a guarded OpenClaw to a hook connector."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import click
from click.testing import CliRunner
from defenseclaw import config as cfg_mod
from defenseclaw.commands.cmd_init import init_cmd
from defenseclaw.commands.cmd_quickstart import quickstart_cmd
from defenseclaw.commands.cmd_setup import _refuse_hook_switch_over_proxy
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.context import AppContext

from tests.helpers import cleanup_app, make_app_context


class RefuseHelperTests(unittest.TestCase):
    def _gc(self, connector="openclaw", enabled=True, connectors=None):
        return SimpleNamespace(connector=connector, enabled=enabled, connectors=connectors or {})

    def test_refuses_hook_connector_over_guarded_openclaw(self):
        with self.assertRaises(click.ClickException) as raised:
            _refuse_hook_switch_over_proxy(self._gc(), "claude-code")
        self.assertIn("No changes made", raised.exception.message)
        self.assertIn("defenseclaw setup claude-code --replace", raised.exception.message)

    def test_allows_proxy_targets_unguarded_and_hook_rosters(self):
        for gc, wanted in (
            (self._gc(), "openclaw"),
            (self._gc(), "zeptoclaw"),
            (self._gc(), "none"),
            (self._gc(enabled=False), "codex"),
            (self._gc(connector="codex"), "claudecode"),
            (self._gc(connectors={"codex": object()}), "claudecode"),
        ):
            with self.subTest(gc=gc, wanted=wanted):
                self.assertIsNone(_refuse_hook_switch_over_proxy(gc, wanted))


class GuardedOpenClawSwitchTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = os.path.realpath(tempfile.mkdtemp(prefix="dclaw-gap2455-"))
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        with patch.dict(os.environ, {"DEFENSECLAW_HOME": self.tmp_dir}):
            cfg = cfg_mod.default_config()
            cfg_mod.prepare_fresh_v8_config(cfg)
            cfg.guardrail.connector = "openclaw"
            cfg.claw.mode = "openclaw"
            cfg.guardrail.enabled = True
            cfg.save()
        self.cfg_file = Path(self.tmp_dir, "config.yaml")
        self.before = self.cfg_file.read_bytes()

    def _assert_refused(self, result, slug="codex"):
        output = result.output + (result.stderr or "")
        self.assertNotEqual(result.exit_code, 0, output)
        self.assertIn("OpenClaw", output)
        self.assertIn("No changes made", output)
        self.assertIn(f"defenseclaw setup {slug} --replace", output)
        self.assertEqual(self.cfg_file.read_bytes(), self.before)

    def test_quickstart_connector_codex_is_refused(self):
        forbidden = AssertionError("quickstart replaced a guarded OpenClaw")
        with patch("defenseclaw.bootstrap.run_first_run", side_effect=forbidden) as first_run:
            result = CliRunner().invoke(
                quickstart_cmd,
                ["--connector", "codex", "--non-interactive", "--yes", "--skip-gateway"],
                env={"DEFENSECLAW_HOME": self.tmp_dir},
            )
        self._assert_refused(result)
        first_run.assert_not_called()

    def test_init_connector_codex_is_refused(self):
        forbidden = AssertionError("init replaced a guarded OpenClaw")
        with patch("defenseclaw.bootstrap.run_first_run", side_effect=forbidden) as first_run:
            result = CliRunner().invoke(
                init_cmd,
                ["--connector", "claude-code", "--yes"],
                obj=AppContext(),
                env={"DEFENSECLAW_HOME": self.tmp_dir},
            )
        self._assert_refused(result, slug="claude-code")
        first_run.assert_not_called()


class SetupGuardrailSwitchTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.addCleanup(cleanup_app, self.app, self.db_path, self.tmp_dir)
        self.app.cfg.claw.mode = "openclaw"
        self.app.cfg.guardrail.connector = "openclaw"
        self.app.cfg.guardrail.connectors = {}
        self.app.cfg.guardrail.enabled = True
        self.app.cfg.save = lambda: self.fail("setup guardrail saved a refused switch")  # type: ignore[assignment]

    def test_setup_guardrail_connector_codex_is_refused(self):
        for extra in (["--non-interactive"], []):
            with self.subTest(extra=extra):
                result = CliRunner().invoke(
                    setup_group,
                    ["guardrail", "--connector", "codex", "--no-restart", *extra],
                    obj=self.app,
                    input="\n" * 10,
                )
                self.assertNotEqual(result.exit_code, 0, result.output)
                self.assertIn("No changes made", result.output)
                self.assertIn("defenseclaw setup codex --replace", result.output)
                self.assertEqual(self.app.cfg.guardrail.connector, "openclaw")
                self.assertEqual(self.app.cfg.claw.mode, "openclaw")

    def test_setup_guardrail_ignores_stale_picked_hint_on_guarded_openclaw(self):
        Path(self.app.cfg.data_dir, "picked_connector").write_text("codex\n", encoding="utf-8")
        with patch(
            "defenseclaw.commands.cmd_setup._ensure_connector_available",
            side_effect=click.ClickException("stop after connector resolution"),
        ) as available:
            CliRunner().invoke(setup_group, ["guardrail", "--non-interactive", "--no-restart"], obj=self.app)
        available.assert_called_once_with("openclaw")
        self.assertEqual(self.app.cfg.guardrail.connector, "openclaw")


if __name__ == "__main__":
    unittest.main()
