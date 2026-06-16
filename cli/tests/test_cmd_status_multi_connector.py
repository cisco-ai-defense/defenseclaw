# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw status`` multi-connector "Agents" roster.

``_print_agents`` is config-derived (``active_connectors()`` +
``GuardrailConfig.effective_mode``) so it renders whether or not the sidecar
is running. The standalone ``Connectors:`` row was folded into a single
``Agents`` section. These tests pin:

* One line per connector with its effective mode under a single ``Agents``
  header, for ANY connector count — a single-connector install renders the
  same section (one row), not a separate legacy ``Agent:`` block.
* Called with no host/port (config-only), no ``/health`` fetch occurs, so the
  roster lists connectors + mode without live counters.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands import cmd_status
from defenseclaw.commands.cmd_status import _print_agents
from defenseclaw.commands.cmd_status import status as status_cmd

from tests.helpers import cleanup_app, make_app_context


def _cfg(actives, *, modes=None, disabled=None):
    modes = modes or {}
    disabled = set(disabled or ())
    cfg = MagicMock()
    cfg.active_connectors.return_value = list(actives)
    cfg.guardrail.effective_mode.side_effect = lambda c: modes.get(c, "observe")
    cfg.guardrail.effective_enabled.side_effect = lambda c: c not in disabled
    return cfg


def _render(cfg) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        # No host/port → config-only roster, no /health fetch.
        _print_agents(cfg)
    return buf.getvalue()


class TestPrintAgentsRoster(unittest.TestCase):
    def test_single_connector_uses_same_roster(self):
        # Uniform UX: a single-connector install renders the SAME "Agents"
        # section as a fan-out install (one row), not a special "Agent:" block.
        out = _render(_cfg(["codex"], modes={"codex": "action"}))
        self.assertIn("Agents", out)
        self.assertIn("1 active", out)
        self.assertIn("Codex (codex)", out)
        self.assertIn("mode=action", out)

    def test_zero_connectors_shows_no_active(self):
        out = _render(_cfg([]))
        self.assertIn("Agents", out)
        self.assertIn("no active connector", out)

    def test_multi_lists_each_connector_with_mode(self):
        out = _render(_cfg(["codex", "cursor"], modes={"codex": "observe", "cursor": "action"}))
        # The section is now labeled "Agents", not "Connectors".
        self.assertIn("Agents", out)
        self.assertNotIn("Connectors", out)
        self.assertIn("2 active", out)
        self.assertIn("Codex (codex)", out)
        self.assertIn("mode=observe", out)
        self.assertIn("Cursor (cursor)", out)
        self.assertIn("mode=action", out)

    def test_blank_connector_names_filtered(self):
        out = _render(_cfg(["codex", "", "cursor"]))
        # The empty entry is dropped, leaving two real connectors.
        self.assertIn("2 active", out)

    def test_effective_mode_exception_falls_back_to_placeholder(self):
        cfg = _cfg(["codex", "cursor"])
        cfg.guardrail.effective_mode.side_effect = RuntimeError("boom")
        out = _render(cfg)
        # The helper must not raise; it renders a placeholder mode.
        self.assertIn("mode=?", out)

    def test_disabled_connector_marked_and_excluded_from_active_count(self):
        # ``guardrail disable --connector codex`` sets enabled=false; the roster
        # must (a) count only the still-enforcing connector as active and report
        # the disabled one separately, and (b) mark it DISABLED rather than
        # letting it read like a connector the sidecar merely hasn't surfaced.
        out = _render(
            _cfg(
                ["codex", "cursor"],
                modes={"codex": "action", "cursor": "action"},
                disabled={"codex"},
            )
        )
        self.assertIn("1 active", out)
        self.assertIn("1 disabled", out)
        self.assertIn("DISABLED", out)
        self.assertIn("Codex (codex)", out)


def _render_live(cfg, health: dict) -> str:
    """Render with the sidecar up: patch the raw /health fetch so the real
    ``_fetch_health_connectors`` parsing path runs against ``health``."""
    buf = io.StringIO()
    with patch.object(cmd_status, "_fetch_health", return_value=health):
        with contextlib.redirect_stdout(buf):
            cmd_status._print_agents(cfg, "127.0.0.1", 8787)
    return buf.getvalue()


class TestPrintAgentsLiveCounters(unittest.TestCase):
    """With ``/health`` ``connectors[]`` present, every active agent renders its
    own live counters — there is no privileged "primary" tally."""

    def test_each_connector_renders_its_own_counters(self):
        health = {
            "connectors": [
                {"name": "codex", "state": "running", "requests": 5, "tool_blocks": 2},
                {"name": "cursor", "state": "running", "requests": 9, "tool_blocks": 1},
            ]
        }
        cfg = _cfg(["codex", "cursor"], modes={"codex": "observe", "cursor": "action"})
        out = _render_live(cfg, health)
        # Distinct per-connector tallies (not a single shared/global number).
        self.assertIn("requests: 5", out)
        self.assertIn("requests: 9", out)
        self.assertIn("tool blocks: 2", out)
        self.assertIn("tool blocks: 1", out)

    def test_connector_without_health_entry_falls_back_to_config_line(self):
        # Only codex has a live entry; cursor must still appear (config-only).
        health = {"connectors": [{"name": "codex", "state": "running", "requests": 3}]}
        cfg = _cfg(["codex", "cursor"])
        out = _render_live(cfg, health)
        self.assertIn("requests: 3", out)
        self.assertIn("Cursor (cursor)", out)

    def test_old_gateway_singular_connector_is_folded_in(self):
        # Pre-multi gateway reports only the singular `connector`; it still gets
        # counters via the fallback in _fetch_health_connectors.
        health = {"connector": {"name": "codex", "state": "running", "requests": 7}}
        cfg = _cfg(["codex", "cursor"])
        out = _render_live(cfg, health)
        self.assertIn("requests: 7", out)


class TestStatusDbErrorSurfacing(unittest.TestCase):
    """SU-05: an audit-DB read error must surface in the Enforcement + Activity
    sections, never silently drop them."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _invoke(self):
        runner = CliRunner()
        with patch("defenseclaw.gateway.OrchestratorClient.is_running", return_value=False):
            return runner.invoke(status_cmd, [], obj=self.app, catch_exceptions=False)

    def test_db_error_surfaces_and_stays_exit_zero(self):
        self.app.store.get_counts = MagicMock(side_effect=RuntimeError("disk I/O error"))
        result = self._invoke()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # Section headers still render, with a visible error instead of nothing.
        self.assertIn("Enforcement", result.output)
        self.assertIn("Activity", result.output)
        self.assertIn("unavailable", result.output)
        self.assertIn("disk I/O error", result.output)

    def test_healthy_db_shows_counts(self):
        result = self._invoke()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Enforcement", result.output)
        self.assertIn("Blocked skills", result.output)
        self.assertNotIn("unavailable", result.output)


class TestStatusJson(unittest.TestCase):
    """SU-13: ``status --json`` emits a machine-readable document."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        from defenseclaw.config import PerConnectorGuardrailConfig

        gc = self.app.cfg.guardrail
        gc.connector = "codex"
        gc.connectors = {
            "codex": PerConnectorGuardrailConfig(mode="action"),
            "hermes": PerConnectorGuardrailConfig(mode="observe"),
        }

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _invoke_json(self):
        runner = CliRunner()
        with patch("defenseclaw.gateway.OrchestratorClient.is_running", return_value=False):
            return runner.invoke(status_cmd, ["--json"], obj=self.app, catch_exceptions=False)

    def test_json_is_valid_and_has_core_keys(self):
        result = self._invoke_json()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        doc = json.loads(result.output)
        for key in ("environment", "scanners", "enforcement", "activity", "connectors", "sidecar"):
            self.assertIn(key, doc)
        self.assertFalse(doc["sidecar"]["running"])

    def test_json_roster_has_per_connector_mode(self):
        result = self._invoke_json()
        doc = json.loads(result.output)
        by_name = {c["name"]: c for c in doc["connectors"]}
        self.assertEqual(by_name["codex"]["mode"], "action")
        self.assertEqual(by_name["hermes"]["mode"], "observe")
        self.assertTrue(by_name["codex"]["enabled"])

    def test_json_db_error_is_explicit_null_not_dropped(self):
        self.app.store.get_counts = MagicMock(side_effect=RuntimeError("locked"))
        result = self._invoke_json()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        doc = json.loads(result.output)
        self.assertIsNone(doc["enforcement"])
        self.assertIsNone(doc["activity"])
        self.assertEqual(doc["audit_db_error"], "locked")


if __name__ == "__main__":
    unittest.main()
