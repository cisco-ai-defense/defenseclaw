# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""S6.5 — per-connector doctor checks.

These tests pin the new per-connector inventory and scan-coverage
sections that S6.5 added to ``defenseclaw doctor``. The checks are
deliberately narrow: they exercise the helpers in isolation rather
than the whole 1000-line doctor flow, so we can lock the contract
without smoke-testing every probe.

Coverage:

* ``_active_connector`` resolves the connector name in the same
  shape ``cfg.active_connector()`` exposes — including the
  legacy-config fallback when the method isn't present.
* ``_check_connector_inventory`` emits PASS for known connectors,
  WARN for unknown connectors, and surfaces the per-connector
  skill / plugin / MCP path lists.
* ``_check_scan_coverage`` mirrors the bullet list from
  ``_scan_ui.categories_for`` so the doctor and the scanner
  preambles agree on what each scanner checks.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import (
    _DoctorResult,
    _active_connector,
    _check_connector_inventory,
    _check_scan_coverage,
)


class TestActiveConnectorResolver(unittest.TestCase):
    """``_active_connector`` is the single source of truth used by every
    per-connector doctor branch (inventory, fix_gateway_token,
    fix_pristine_backup). A regression here cascades through all of
    them, so the helper has its own tests.
    """

    def test_active_connector_uses_method_when_available(self) -> None:
        cfg = MagicMock()
        cfg.active_connector.return_value = "Codex"
        self.assertEqual(_active_connector(cfg), "codex")

    def test_active_connector_falls_back_to_guardrail_field(self) -> None:
        cfg = MagicMock(spec=["guardrail"])  # no active_connector method
        cfg.guardrail = MagicMock()
        cfg.guardrail.connector = "claudecode"
        self.assertEqual(_active_connector(cfg), "claudecode")

    def test_active_connector_defaults_to_openclaw_when_unset(self) -> None:
        cfg = MagicMock(spec=["guardrail"])
        cfg.guardrail = MagicMock()
        cfg.guardrail.connector = ""
        self.assertEqual(_active_connector(cfg), "openclaw")

    def test_active_connector_lowercases_method_result(self) -> None:
        """ZeptoClaw, OpenClaw, etc. — display casing varies, but the
        downstream connector switches all use lowercase.
        """
        cfg = MagicMock()
        cfg.active_connector.return_value = "ZeptoClaw"
        self.assertEqual(_active_connector(cfg), "zeptoclaw")

    def test_active_connector_swallows_method_exception(self) -> None:
        """A broken ``active_connector()`` must not abort the doctor —
        fall back to the legacy field.
        """
        cfg = MagicMock()
        cfg.active_connector.side_effect = RuntimeError("bad config")
        cfg.guardrail = MagicMock()
        cfg.guardrail.connector = "openclaw"
        self.assertEqual(_active_connector(cfg), "openclaw")


class TestCheckConnectorInventory(unittest.TestCase):
    """The new "── Connector ──" section surfaces the active connector
    plus the directories it points at."""

    def _cfg(self, *, skill_dirs: list[str], plugin_dirs: list[str], servers: list) -> MagicMock:
        cfg = MagicMock()
        cfg.skill_dirs.return_value = skill_dirs
        cfg.plugin_dirs.return_value = plugin_dirs
        cfg.mcp_servers.return_value = servers
        return cfg

    def test_known_connector_passes(self) -> None:
        cfg = self._cfg(skill_dirs=[], plugin_dirs=[], servers=[])
        r = _DoctorResult()
        _check_connector_inventory(cfg, "openclaw", r)
        # First check is the connector label itself.
        first = r.checks[0]
        self.assertEqual(first["status"], "pass")
        self.assertEqual(first["label"], "Active connector")
        self.assertEqual(first["detail"], "OpenClaw")

    def test_unknown_connector_warns(self) -> None:
        cfg = self._cfg(skill_dirs=[], plugin_dirs=[], servers=[])
        r = _DoctorResult()
        _check_connector_inventory(cfg, "totallymadeupclaw", r)
        first = r.checks[0]
        self.assertEqual(first["status"], "warn")
        self.assertEqual(first["label"], "Active connector")
        self.assertIn("unknown connector", first["detail"])

    def test_skill_paths_pass_when_directory_exists(self) -> None:
        # Use the cwd as a guaranteed-real directory.
        cfg = self._cfg(
            skill_dirs=[os.getcwd()],
            plugin_dirs=[],
            servers=[],
        )
        r = _DoctorResult()
        _check_connector_inventory(cfg, "openclaw", r)
        skill_check = next(c for c in r.checks if c["label"] == "Skill paths")
        self.assertEqual(skill_check["status"], "pass")
        self.assertIn("1/1 present", skill_check["detail"])

    def test_skill_paths_warn_when_no_directory_exists(self) -> None:
        cfg = self._cfg(
            skill_dirs=["/nonexistent/path/for/test"],
            plugin_dirs=[],
            servers=[],
        )
        r = _DoctorResult()
        _check_connector_inventory(cfg, "codex", r)
        skill_check = next(c for c in r.checks if c["label"] == "Skill paths")
        self.assertEqual(skill_check["status"], "warn")
        self.assertIn("0/1 present", skill_check["detail"])

    def test_skill_paths_skip_when_empty_list(self) -> None:
        cfg = self._cfg(skill_dirs=[], plugin_dirs=[], servers=[])
        r = _DoctorResult()
        _check_connector_inventory(cfg, "claudecode", r)
        skill_check = next(c for c in r.checks if c["label"] == "Skill paths")
        self.assertEqual(skill_check["status"], "skip")

    def test_mcp_server_summary_truncates_after_five(self) -> None:
        servers = [MagicMock(name=f"srv-{i}") for i in range(7)]
        for i, s in enumerate(servers):
            s.name = f"srv-{i}"
        cfg = self._cfg(skill_dirs=[], plugin_dirs=[], servers=servers)
        r = _DoctorResult()
        _check_connector_inventory(cfg, "openclaw", r)
        mcp_check = next(c for c in r.checks if c["label"] == "MCP servers")
        self.assertEqual(mcp_check["status"], "pass")
        self.assertIn("7 configured", mcp_check["detail"])
        self.assertIn("(+2 more)", mcp_check["detail"])

    def test_paths_swallow_exception_as_warn(self) -> None:
        cfg = MagicMock()
        cfg.skill_dirs.side_effect = RuntimeError("kaboom")
        cfg.plugin_dirs.return_value = []
        cfg.mcp_servers.return_value = []

        r = _DoctorResult()
        _check_connector_inventory(cfg, "openclaw", r)

        skill_check = next(c for c in r.checks if c["label"] == "Skill paths")
        self.assertEqual(skill_check["status"], "warn")
        self.assertIn("kaboom", skill_check["detail"])


class TestCheckScanCoverage(unittest.TestCase):
    """``_check_scan_coverage`` advertises what each scanner will check.

    The categories are owned by ``_scan_ui.categories_for``; this test
    just locks the round-trip from doctor through to that helper, so a
    drift between doctor and the scan preamble shows up in CI.
    """

    def test_all_components_emit_a_pass_check(self) -> None:
        from defenseclaw.commands import _scan_ui

        r = _DoctorResult()
        _check_scan_coverage(MagicMock(), r)

        labels_seen = {c["label"] for c in r.checks if c["status"] == "pass"}
        # One Scanner-coverage row per supported component.
        for component in _scan_ui.supported_components():
            sing = _scan_ui._COMPONENT_LABELS[component][0]  # type: ignore[attr-defined]
            self.assertIn(f"Scanner coverage ({sing})", labels_seen)

    def test_categories_match_scan_ui_source_of_truth(self) -> None:
        from defenseclaw.commands import _scan_ui

        r = _DoctorResult()
        _check_scan_coverage(MagicMock(), r)

        # Plugin row should literally contain every plugin category from
        # _scan_ui — locking the contract that doctor and the scanner
        # preamble can never disagree on what's being checked.
        plugin_row = next(
            c for c in r.checks if c["label"] == "Scanner coverage (plugin)"
        )
        for cat in _scan_ui.categories_for("plugin"):
            self.assertIn(cat, plugin_row["detail"])


if __name__ == "__main__":
    unittest.main()
