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

"""S6.2 — UX contract tests for ``defenseclaw plugin scan``.

The existing ``test_cmd_plugin.py`` already exercises the install /
list / governance commands; this file is dedicated to the *scan*
command's user-visible output. The scan command was rewritten in
S6.2 to use ``defenseclaw.commands._scan_ui``: these tests pin the
new wording so future drift between ``plugin scan`` and ``skill
scan`` / ``mcp scan`` (rewritten in S6.3 / S6.4) is caught in CI.

Coverage:

* Preamble announces what is being scanned and on which connector
* Scan-category bullet points appear (so users know what's being
  checked)
* Per-target verdict line uses the ``[ok]`` / ``[BLOCKED]`` glyphs
  from ``_scan_ui``
* Summary line shows clean / blocked counts and a duration
* ``--json`` mode silences all of the above and emits the unchanged
  ``ScanResult.to_json()`` contract — *not* the new
  ``render_json_payload`` shape, because automation still parses
  the legacy contract.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_plugin import plugin
from defenseclaw.models import Finding, ScanResult
from tests.helpers import cleanup_app, make_app_context


class _PluginScanUXBase(unittest.TestCase):
    """Sets up a temp plugin dir and a runnable plugin payload."""

    def setUp(self) -> None:
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.plugin_dir = os.path.join(self.tmp_dir, "plugins")
        os.makedirs(self.app.cfg.plugin_dir, exist_ok=True)

        # Drop a plugin on disk so _resolve_plugin_dir resolves it.
        self.plugin_name = "demo-plugin"
        self.plugin_path = os.path.join(self.app.cfg.plugin_dir, self.plugin_name)
        os.makedirs(self.plugin_path)
        with open(os.path.join(self.plugin_path, "plugin.py"), "w") as f:
            f.write("# noop\n")

        self.runner = CliRunner()

    def tearDown(self) -> None:
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args: list[str]):
        return self.runner.invoke(plugin, args, obj=self.app, catch_exceptions=False)

    @staticmethod
    def _clean_result() -> ScanResult:
        return ScanResult(
            scanner="plugin-scanner",
            target="demo-plugin",
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(milliseconds=42),
        )

    @staticmethod
    def _blocked_result() -> ScanResult:
        return ScanResult(
            scanner="plugin-scanner",
            target="demo-plugin",
            timestamp=datetime.now(timezone.utc),
            findings=[
                Finding(
                    id="P1",
                    title="Hardcoded API key",
                    severity="HIGH",
                    location="plugin.py:1",
                    remediation="Move to env var",
                ),
            ],
            duration=timedelta(milliseconds=120),
        )


class TestScanUXPreamble(_PluginScanUXBase):
    """The new preamble surfaces what's being scanned and where."""

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_preamble_includes_count_label_connector(self, mock_scan) -> None:
        mock_scan.return_value = self._clean_result()
        result = self.invoke(["scan", self.plugin_name])
        self.assertEqual(result.exit_code, 0, result.output)
        # Preamble: "Scanning 1 plugin on <connector> for:"
        self.assertIn("Scanning 1 plugin on ", result.output)
        self.assertIn("for:", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_preamble_lists_default_categories(self, mock_scan) -> None:
        mock_scan.return_value = self._clean_result()
        result = self.invoke(["scan", self.plugin_name])
        self.assertEqual(result.exit_code, 0, result.output)
        # Default plugin categories from _scan_ui._DEFAULT_CATEGORIES
        self.assertIn("malicious code patterns", result.output)
        self.assertIn("prompt injection attempts", result.output)
        self.assertIn("hardcoded secrets", result.output)
        self.assertIn("supply-chain risk indicators", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_preamble_includes_source_path(self, mock_scan) -> None:
        mock_scan.return_value = self._clean_result()
        result = self.invoke(["scan", self.plugin_name])
        self.assertEqual(result.exit_code, 0, result.output)
        # The preamble should expose the resolved scan dir under "Source:"
        self.assertIn("Source:", result.output)
        self.assertIn(self.plugin_path, result.output)


class TestScanUXVerdictLines(_PluginScanUXBase):
    """The per-target verdict line uses the shared ``_scan_ui`` glyphs."""

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_clean_emits_ok_glyph(self, mock_scan) -> None:
        mock_scan.return_value = self._clean_result()
        result = self.invoke(["scan", self.plugin_name])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("[ok]", result.output)
        self.assertIn(self.plugin_name, result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_finding_emits_blocked_glyph(self, mock_scan) -> None:
        mock_scan.return_value = self._blocked_result()
        result = self.invoke(["scan", self.plugin_name])
        # Exit code is still zero — scan only reports; install --action enforces.
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("[BLOCKED]", result.output)
        # Finding count must be visible.
        self.assertIn("1 finding", result.output)
        # Severity surfaced via the "max severity:" detail string.
        self.assertIn("max severity: HIGH", result.output)
        # Finding details still rendered.
        self.assertIn("[HIGH]", result.output)
        self.assertIn("Hardcoded API key", result.output)


class TestScanUXSummary(_PluginScanUXBase):
    """The summary line aggregates clean / blocked / errored counts."""

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_summary_clean(self, mock_scan) -> None:
        mock_scan.return_value = self._clean_result()
        result = self.invoke(["scan", self.plugin_name])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Summary: 1 plugin scanned", result.output)
        self.assertIn("clean=1", result.output)
        self.assertIn("blocked=0", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_summary_blocked(self, mock_scan) -> None:
        mock_scan.return_value = self._blocked_result()
        result = self.invoke(["scan", self.plugin_name])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Summary: 1 plugin scanned", result.output)
        self.assertIn("clean=0", result.output)
        self.assertIn("blocked=1", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_summary_includes_duration_ms(self, mock_scan) -> None:
        mock_scan.return_value = self._clean_result()
        result = self.invoke(["scan", self.plugin_name])
        self.assertEqual(result.exit_code, 0, result.output)
        # ScanResult.duration is 42ms, summary should report "in 42ms".
        self.assertIn("in 42ms", result.output)


class TestScanUXJsonMode(_PluginScanUXBase):
    """``--json`` silences human helpers and preserves the legacy contract."""

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_json_mode_silences_preamble_and_summary(self, mock_scan) -> None:
        mock_scan.return_value = self._clean_result()
        result = self.invoke(["scan", "--json", self.plugin_name])
        self.assertEqual(result.exit_code, 0, result.output)
        # No human banner.
        self.assertNotIn("Scanning ", result.output)
        self.assertNotIn("Summary:", result.output)
        self.assertNotIn("[ok]", result.output)
        # Output must be parsable as the legacy ScanResult.to_json()
        # shape — automation depends on these keys.
        payload = json.loads(result.output.strip())
        self.assertIn("scanner", payload)
        self.assertIn("target", payload)
        self.assertIn("findings", payload)


class TestScanUXErrorPath(_PluginScanUXBase):
    """Resolution failures still emit a clear error before any UX."""

    def test_missing_plugin_returns_error(self) -> None:
        result = self.invoke(["scan", "no-such-plugin"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("plugin not found", result.output)
        # And the new preamble must NOT have run for a target that
        # never resolved.
        self.assertNotIn("Scanning 1 plugin", result.output)


if __name__ == "__main__":
    unittest.main()
