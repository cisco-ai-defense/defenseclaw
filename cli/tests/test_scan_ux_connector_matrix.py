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

"""S6.6 — connector × scan-command matrix smoke tests.

Each scan command must announce the *active connector* in its
preamble so operators paging through "plugin scan", "skill scan",
"mcp scan" on different agent frameworks know which framework's
config the scanner is reading. This file runs each command with
the connector mocked to every supported value (openclaw / codex /
claudecode / zeptoclaw) and asserts the connector name shows up in
the preamble verbatim.

Why this matters
----------------
The S6.x preambles all read ``cfg.active_connector()`` and pass the
result through ``_scan_ui.ScanContext``. If anything in that chain
regresses — e.g. a future refactor that swaps ``active_connector()``
for the raw ``cfg.guardrail.connector`` field — these tests fire
because the connector name vanishes from the preamble line.

What this file does NOT cover
-----------------------------
* Live scanner behavior — every scanner is mocked.
* Connector-specific paths — that's tested in
  ``test_cmd_doctor_connector.py`` (S6.5) and the dedicated
  per-connector path tests under ``tests/test_config_connector*.py``.
* Network probes — covered in ``test_cmd_doctor.py``.
"""

from __future__ import annotations

import os
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_mcp import mcp
from defenseclaw.commands.cmd_plugin import plugin
from defenseclaw.commands.cmd_skill import skill
from defenseclaw.config import MCPServerEntry
from defenseclaw.models import Finding, ScanResult
from tests.helpers import cleanup_app, make_app_context


# Supported connector names — keep in lockstep with
# ``Config.active_connector`` and ``cmd_doctor._CONNECTOR_LABELS``.
SUPPORTED_CONNECTORS = ("openclaw", "codex", "claudecode", "zeptoclaw")


class _MatrixBase(unittest.TestCase):
    """Shared scaffolding: app context + temp dirs + connector toggle."""

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

    def _force_connector(self, name: str) -> None:
        """Patch ``Config.active_connector`` on the live app context.

        Using a closure (not ``MagicMock(return_value=...)``) so the
        method signature looks identical to the real one — some call
        sites use ``hasattr(app.cfg, "active_connector")`` which a
        MagicMock would pass through unconditionally even when we
        want to test the fallback.
        """
        self.app.cfg.active_connector = lambda: name


class TestPluginScanConnectorMatrix(_MatrixBase):
    """``defenseclaw plugin scan`` × every connector."""

    def setUp(self) -> None:
        super().setUp()
        self.app.cfg.plugin_dir = os.path.join(self.tmp_dir, "plugins")
        os.makedirs(self.app.cfg.plugin_dir, exist_ok=True)
        self.plugin_path = os.path.join(self.app.cfg.plugin_dir, "demo")
        os.makedirs(self.plugin_path)
        with open(os.path.join(self.plugin_path, "plugin.py"), "w") as f:
            f.write("# noop\n")

    @staticmethod
    def _clean_result() -> ScanResult:
        return ScanResult(
            scanner="plugin-scanner",
            target="demo",
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(milliseconds=10),
        )

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_preamble_shows_connector_for_every_supported_value(self, mock_scan) -> None:
        mock_scan.return_value = self._clean_result()

        for connector in SUPPORTED_CONNECTORS:
            with self.subTest(connector=connector):
                self._force_connector(connector)
                result = self.runner.invoke(
                    plugin, ["scan", "demo"], obj=self.app,
                    catch_exceptions=False,
                )
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertIn(
                    f"Scanning 1 plugin on {connector} for:",
                    result.output,
                    f"connector {connector!r} missing from preamble",
                )


class TestSkillScanConnectorMatrix(_MatrixBase):
    """``defenseclaw skill scan`` × every connector."""

    def setUp(self) -> None:
        super().setUp()
        self.skill_dir = os.path.join(self.tmp_dir, "demo-skill")
        os.makedirs(self.skill_dir)
        with open(os.path.join(self.skill_dir, "SKILL.md"), "w") as f:
            f.write("# demo\n")

    @staticmethod
    def _clean_result(target: str) -> ScanResult:
        return ScanResult(
            scanner="skill-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(milliseconds=10),
        )

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_preamble_shows_connector_for_every_supported_value(
        self, mock_cls, _mock_info,
    ) -> None:
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = self._clean_result(self.skill_dir)
        mock_cls.return_value = mock_scanner

        for connector in SUPPORTED_CONNECTORS:
            with self.subTest(connector=connector):
                self._force_connector(connector)
                result = self.runner.invoke(
                    skill, ["scan", "demo-skill", "--path", self.skill_dir],
                    obj=self.app, catch_exceptions=False,
                )
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertIn(
                    f"Scanning 1 skill on {connector} for:",
                    result.output,
                    f"connector {connector!r} missing from preamble",
                )


class TestMCPScanConnectorMatrix(_MatrixBase):
    """``defenseclaw mcp scan`` × every connector."""

    @staticmethod
    def _clean_result(target: str) -> ScanResult:
        return ScanResult(
            scanner="mcp-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_single_target_preamble_shows_connector_for_every_supported_value(
        self, mock_scan,
    ) -> None:
        mock_scan.return_value = self._clean_result("http://localhost:3000")

        for connector in SUPPORTED_CONNECTORS:
            with self.subTest(connector=connector):
                self._force_connector(connector)
                result = self.runner.invoke(
                    mcp, ["scan", "http://localhost:3000"], obj=self.app,
                    catch_exceptions=False,
                )
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertIn(
                    f"Scanning 1 MCP server on {connector} for:",
                    result.output,
                    f"connector {connector!r} missing from preamble",
                )

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_all_preamble_shows_connector_for_every_supported_value(
        self, mock_scan,
    ) -> None:
        servers = [MCPServerEntry(name="alpha", url="http://a.example/mcp")]
        self.app.cfg.mcp_servers = lambda: servers
        mock_scan.return_value = self._clean_result("http://a.example/mcp")

        for connector in SUPPORTED_CONNECTORS:
            with self.subTest(connector=connector):
                self._force_connector(connector)
                result = self.runner.invoke(
                    mcp, ["scan", "--all"], obj=self.app, catch_exceptions=False,
                )
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertIn(
                    f"Scanning 1 MCP server on {connector} for:",
                    result.output,
                    f"connector {connector!r} missing from preamble",
                )


class TestSummaryAcrossConnectorsAlwaysRendersV1Schema(_MatrixBase):
    """The summary line is identical across connectors — connector
    name only appears in the preamble, never in the summary, so this
    pins the contract.
    """

    def setUp(self) -> None:
        super().setUp()
        self.app.cfg.plugin_dir = os.path.join(self.tmp_dir, "plugins")
        os.makedirs(self.app.cfg.plugin_dir, exist_ok=True)
        self.plugin_path = os.path.join(self.app.cfg.plugin_dir, "demo")
        os.makedirs(self.plugin_path)
        with open(os.path.join(self.plugin_path, "plugin.py"), "w") as f:
            f.write("# noop\n")

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_summary_format_is_connector_invariant(self, mock_scan) -> None:
        mock_scan.return_value = ScanResult(
            scanner="plugin-scanner", target="demo",
            timestamp=datetime.now(timezone.utc),
            findings=[
                Finding(
                    id=str(uuid.uuid4()), severity="HIGH", title="x",
                    scanner="plugin-scanner",
                ),
            ],
            duration=timedelta(milliseconds=20),
        )

        summaries: list[str] = []
        for connector in SUPPORTED_CONNECTORS:
            self._force_connector(connector)
            result = self.runner.invoke(
                plugin, ["scan", "demo"], obj=self.app, catch_exceptions=False,
            )
            self.assertEqual(result.exit_code, 0, result.output)
            for line in result.output.splitlines():
                if "Summary:" in line:
                    summaries.append(line.strip())
                    break

        # Every connector renders the *same* summary template.
        self.assertEqual(len(summaries), len(SUPPORTED_CONNECTORS))
        # Strip duration to compare the invariant skeleton.
        skeletons = {s.split(", in ")[0] for s in summaries}
        self.assertEqual(
            len(skeletons), 1,
            f"Summary line drifted across connectors: {summaries!r}",
        )


if __name__ == "__main__":
    unittest.main()
