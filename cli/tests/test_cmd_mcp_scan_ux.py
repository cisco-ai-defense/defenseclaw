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

"""S6.4 — UX contract tests for ``defenseclaw mcp scan``.

The existing ``test_cmd_mcp.py`` covers the install / set / unset
flows plus the basic scan happy path. This file pins the *shared*
``_scan_ui`` preamble + per-target glyph + summary that S6.4 wired
into both the single-target and ``--all`` paths.

Coverage:

* Single-target preamble: count, label ("MCP server"), connector,
  default categories
* Single-target verdict: ``[ok]`` / ``[BLOCKED]`` glyph + finding
  count + max severity detail
* Single-target summary: clean / blocked counts + duration
* ``--all`` preamble: target count and source URLs
* ``--all`` summary: aggregated clean / blocked / errored counts
* ``--all`` no-servers path
* ``--json`` mode silences all human helpers and preserves the
  legacy ``ScanResult.to_json()`` contract
* Error path: ``_run_scan`` returning None bumps the ``errored``
  count visible in the summary
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_mcp import mcp
from defenseclaw.config import MCPServerEntry
from defenseclaw.models import Finding, ScanResult
from tests.helpers import cleanup_app, make_app_context


class _MCPScanUXBase(unittest.TestCase):
    def setUp(self) -> None:
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self._orig_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "200"
        self.runner = CliRunner()

    def tearDown(self) -> None:
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._orig_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._orig_columns

    def invoke(self, args: list[str]):
        return self.runner.invoke(mcp, args, obj=self.app, catch_exceptions=False)

    @staticmethod
    def _clean_result(target: str) -> ScanResult:
        return ScanResult(
            scanner="mcp-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

    @staticmethod
    def _blocked_result(target: str) -> ScanResult:
        return ScanResult(
            scanner="mcp-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=[
                Finding(id="f1", severity="HIGH", title="No auth", scanner="mcp-scanner"),
            ],
        )


class TestSingleTargetUX(_MCPScanUXBase):
    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_preamble_singular_label_and_categories(self, mock_scan) -> None:
        mock_scan.return_value = self._clean_result("http://localhost:3000")
        result = self.invoke(["scan", "http://localhost:3000"])
        self.assertEqual(result.exit_code, 0, result.output)
        # Singular label.
        self.assertIn("Scanning 1 MCP server on ", result.output)
        # Default MCP categories from _scan_ui._DEFAULT_CATEGORIES.
        self.assertIn("untrusted command paths", result.output)
        self.assertIn("outbound URL allow-listing", result.output)
        self.assertIn("tool-name spoofing", result.output)
        self.assertIn("auth-token handling", result.output)

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_clean_target_uses_ok_glyph(self, mock_scan) -> None:
        mock_scan.return_value = self._clean_result("http://localhost:3000")
        result = self.invoke(["scan", "http://localhost:3000"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("[ok] http://localhost:3000", result.output)
        self.assertIn("Summary: 1 MCP server scanned", result.output)
        self.assertIn("clean=1", result.output)
        self.assertIn("blocked=0", result.output)

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_blocked_target_shows_severity(self, mock_scan) -> None:
        mock_scan.return_value = self._blocked_result("http://localhost:3000")
        result = self.invoke(["scan", "http://localhost:3000"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("[BLOCKED] http://localhost:3000", result.output)
        self.assertIn("max severity: HIGH", result.output)
        self.assertIn("(1 finding)", result.output)
        # Detailed finding still appears.
        self.assertIn("[HIGH]", result.output)
        self.assertIn("No auth", result.output)
        # Summary.
        self.assertIn("Summary: 1 MCP server scanned", result.output)
        self.assertIn("clean=0", result.output)
        self.assertIn("blocked=1", result.output)


class TestSingleTargetJsonMode(_MCPScanUXBase):
    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_json_mode_silences_human_output(self, mock_scan) -> None:
        mock_scan.return_value = self._clean_result("http://localhost:3000")
        result = self.invoke(["scan", "http://localhost:3000", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        # Human banner suppressed.
        self.assertNotIn("Scanning ", result.output)
        self.assertNotIn("Summary:", result.output)
        self.assertNotIn("[ok]", result.output)
        # Legacy contract: JSON object with the canonical keys.
        json_start = result.output.index("{")
        import json as _json
        payload = _json.loads(result.output[json_start:])
        self.assertEqual(payload["scanner"], "mcp-scanner")


class TestScanAllUX(_MCPScanUXBase):
    """``--all`` builds the target list up front and aggregates results."""

    def _patch_servers(self, names_urls: list[tuple[str, str]]) -> None:
        servers = [
            MCPServerEntry(name=n, url=u) for n, u in names_urls
        ]
        self.app.cfg.mcp_servers = lambda: servers

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_all_renders_preamble_and_summary(self, mock_scan) -> None:
        self._patch_servers([
            ("alpha", "http://a.example/mcp"),
            ("beta", "http://b.example/mcp"),
            ("gamma", "http://c.example/mcp"),
        ])
        responses = {
            "http://a.example/mcp": self._clean_result("http://a.example/mcp"),
            "http://b.example/mcp": self._blocked_result("http://b.example/mcp"),
            "http://c.example/mcp": self._clean_result("http://c.example/mcp"),
        }
        mock_scan.side_effect = lambda target, server_entry=None: responses[target]

        result = self.invoke(["scan", "--all"])
        self.assertEqual(result.exit_code, 0, result.output)
        # Plural preamble.
        self.assertIn("Scanning 3 MCP servers on ", result.output)
        # Per-target glyphs.
        self.assertIn("[ok] alpha", result.output)
        self.assertIn("[BLOCKED] beta", result.output)
        self.assertIn("[ok] gamma", result.output)
        # Summary.
        self.assertIn("Summary: 3 MCP servers scanned", result.output)
        self.assertIn("clean=2", result.output)
        self.assertIn("blocked=1", result.output)

    @patch("defenseclaw.commands.cmd_mcp._run_scan", return_value=None)
    def test_scan_all_counts_run_scan_failures_as_errored(self, _mock_run) -> None:
        """``_run_scan`` returning None means a fatal error during the scan."""
        self._patch_servers([
            ("only", "http://only.example/mcp"),
        ])
        result = self.invoke(["scan", "--all"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("[ERROR] only", result.output)
        # errored=N appears only when there's at least one error.
        self.assertIn("errored=1", result.output)
        self.assertIn("Summary: 1 MCP server scanned", result.output)

    def test_scan_all_no_servers_message(self) -> None:
        self.app.cfg.mcp_servers = lambda: []
        result = self.invoke(["scan", "--all"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No MCP servers configured", result.output)
        # Preamble must not be rendered for an empty target list.
        self.assertNotIn("Scanning 0", result.output)


if __name__ == "__main__":
    unittest.main()
