# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Plan E2 / item 5 — guardrail enable/disable/status round-trip
parameterized across all built-in connectors.

Asserts that:

* ``status`` reports the right connector label and shape for X.
* ``enable`` for connector X writes the right config (enabled=True,
  connector still X) and triggers ``_restart_services`` with
  ``connector=X``.
* ``disable`` for X clears the flag and triggers teardown with
  ``connector=X``.

We mock ``_restart_services`` so the test never spawns the gateway
binary; the assertion is purely on the *intent* (right connector
passed in, right enabled flag persisted).
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_guardrail import guardrail
from tests.helpers import cleanup_app, make_app_context


_CONNECTORS = (
    "openclaw", "zeptoclaw", "claudecode", "codex",
    "hermes", "cursor", "windsurf", "geminicli", "copilot",
)
_CONNECTOR_LABELS = {
    "openclaw": "OpenClaw",
    "zeptoclaw": "ZeptoClaw",
    "claudecode": "Claude Code",
    "codex": "Codex",
    "hermes": "Hermes",
    "cursor": "Cursor",
    "windsurf": "Windsurf",
    "geminicli": "Gemini CLI",
    "copilot": "GitHub Copilot CLI",
}


def _build_app_for(connector: str):
    app, tmp_dir, db_path = make_app_context()
    app.cfg.guardrail.connector = connector
    app.cfg.guardrail.model = "anthropic/claude-3-5-sonnet"
    app.cfg.guardrail.api_key_env = "ANTHROPIC_API_KEY"
    app.cfg.guardrail.enabled = False
    app.cfg.save()
    return app, tmp_dir, db_path


class GuardrailStatusMatrixTests(unittest.TestCase):
    def test_status_emits_connector_label_for_each(self):
        for connector in _CONNECTORS:
            with self.subTest(connector=connector):
                app, tmp_dir, db_path = _build_app_for(connector)
                try:
                    runner = CliRunner()
                    result = runner.invoke(
                        guardrail, ["status"], obj=app, catch_exceptions=False
                    )
                    self.assertEqual(result.exit_code, 0, msg=result.output)
                    self.assertIn(_CONNECTOR_LABELS[connector], result.output)
                    self.assertIn(connector, result.output)
                    self.assertIn("enabled:", result.output.lower())
                    self.assertIn("no", result.output.lower())
                finally:
                    cleanup_app(app, db_path, tmp_dir)


class GuardrailEnableMatrixTests(unittest.TestCase):
    def test_enable_persists_and_invokes_restart_per_connector(self):
        for connector in _CONNECTORS:
            with self.subTest(connector=connector):
                app, tmp_dir, db_path = _build_app_for(connector)
                try:
                    runner = CliRunner()
                    with patch(
                        "defenseclaw.commands.cmd_setup._restart_services"
                    ) as mock_restart:
                        result = runner.invoke(
                            guardrail,
                            ["enable", "--yes"],
                            obj=app,
                            catch_exceptions=False,
                        )
                    self.assertEqual(result.exit_code, 0, msg=result.output)
                    self.assertTrue(app.cfg.guardrail.enabled)
                    self.assertEqual(app.cfg.guardrail.connector, connector)
                    mock_restart.assert_called_once()
                    _, kwargs = mock_restart.call_args
                    self.assertEqual(kwargs.get("connector"), connector)
                finally:
                    cleanup_app(app, db_path, tmp_dir)


class GuardrailDisableMatrixTests(unittest.TestCase):
    def test_disable_persists_and_invokes_teardown_per_connector(self):
        for connector in _CONNECTORS:
            with self.subTest(connector=connector):
                app, tmp_dir, db_path = _build_app_for(connector)
                app.cfg.guardrail.enabled = True
                app.cfg.save()
                try:
                    runner = CliRunner()
                    with patch(
                        "defenseclaw.commands.cmd_setup._restart_services"
                    ) as mock_restart:
                        result = runner.invoke(
                            guardrail,
                            ["disable", "--yes"],
                            obj=app,
                            catch_exceptions=False,
                        )
                    self.assertEqual(result.exit_code, 0, msg=result.output)
                    self.assertFalse(app.cfg.guardrail.enabled)
                    self.assertEqual(app.cfg.guardrail.connector, connector)
                    mock_restart.assert_called_once()
                    _, kwargs = mock_restart.call_args
                    self.assertEqual(kwargs.get("connector"), connector)
                finally:
                    cleanup_app(app, db_path, tmp_dir)


class GuardrailIdempotencyMatrixTests(unittest.TestCase):
    def test_disable_when_already_disabled_is_noop(self):
        for connector in _CONNECTORS:
            with self.subTest(connector=connector):
                app, tmp_dir, db_path = _build_app_for(connector)
                try:
                    runner = CliRunner()
                    with patch(
                        "defenseclaw.commands.cmd_setup._restart_services"
                    ) as mock_restart:
                        result = runner.invoke(
                            guardrail,
                            ["disable", "--yes"],
                            obj=app,
                            catch_exceptions=False,
                        )
                    self.assertEqual(result.exit_code, 0, msg=result.output)
                    self.assertFalse(app.cfg.guardrail.enabled)
                    mock_restart.assert_not_called()
                    self.assertIn("already disabled", result.output)
                finally:
                    cleanup_app(app, db_path, tmp_dir)


if __name__ == "__main__":
    unittest.main()
