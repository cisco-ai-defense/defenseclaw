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

"""Tests for 'defenseclaw mcp' command group — scan, block, allow, list."""

import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import uuid

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_mcp import mcp, _parse_args, _build_mcp_scan_map
from defenseclaw.config import MCPServerEntry
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.models import Finding, ScanResult
from tests.helpers import make_app_context, cleanup_app


class MCPCommandTestBase(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self._orig_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "200"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._orig_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._orig_columns

    def invoke(self, args: list[str]):
        return self.runner.invoke(mcp, args, obj=self.app, catch_exceptions=False)


class TestMCPBlock(MCPCommandTestBase):
    def test_block_mcp(self):
        result = self.invoke(["block", "http://evil.example.com", "--reason", "unsafe"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Blocked", result.output)

        pe = PolicyEngine(self.app.store)
        self.assertTrue(pe.is_blocked("mcp", "http://evil.example.com"))

    def test_block_already_blocked(self):
        pe = PolicyEngine(self.app.store)
        pe.block("mcp", "http://blocked.com", "test")

        result = self.invoke(["block", "http://blocked.com"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Already blocked", result.output)

    def test_block_logs_action(self):
        self.invoke(["block", "http://bad-server.com", "--reason", "dangerous"])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "block-mcp"]
        self.assertEqual(len(actions), 1)


class TestMCPAllow(MCPCommandTestBase):
    def test_allow_mcp(self):
        result = self.invoke(["allow", "http://trusted.example.com", "--reason", "verified"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Allowed", result.output)

        pe = PolicyEngine(self.app.store)
        self.assertTrue(pe.is_allowed("mcp", "http://trusted.example.com"))

    def test_allow_already_allowed(self):
        pe = PolicyEngine(self.app.store)
        pe.allow("mcp", "http://already.com", "test")

        result = self.invoke(["allow", "http://already.com"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Already allowed", result.output)


class TestMCPUnblock(MCPCommandTestBase):
    def test_unblock_clears_blocked(self):
        pe = PolicyEngine(self.app.store)
        pe.block("mcp", "http://evil.com", "bad")

        result = self.invoke(["unblock", "http://evil.com"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("cleared", result.output)
        self.assertFalse(pe.is_blocked("mcp", "http://evil.com"))

    def test_unblock_no_state(self):
        result = self.invoke(["unblock", "http://clean.com"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("no enforcement state", result.output)

    def test_unblock_does_not_add_to_allow_list(self):
        pe = PolicyEngine(self.app.store)
        pe.block("mcp", "http://evil.com", "bad")

        self.invoke(["unblock", "http://evil.com"])
        self.assertFalse(pe.is_allowed("mcp", "http://evil.com"))

    def test_unblock_logs_action(self):
        pe = PolicyEngine(self.app.store)
        pe.block("mcp", "http://log-me.com", "test")

        self.invoke(["unblock", "http://log-me.com"])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "mcp-unblock"]
        self.assertEqual(len(actions), 1)


class TestMCPScan(MCPCommandTestBase):
    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_clean(self, mock_scan):
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        result = self.invoke(["scan", "http://localhost:3000"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("CLEAN", result.output)

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_with_findings(self, mock_scan):
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[
                Finding(id="f1", severity="HIGH", title="No auth", scanner="mcp-scanner"),
            ],
        )

        result = self.invoke(["scan", "http://localhost:3000"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("HIGH", result.output)
        self.assertIn("No auth", result.output)

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_json_output(self, mock_scan):
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        result = self.invoke(["scan", "http://localhost:3000", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        json_start = result.output.index("{")
        data = json.loads(result.output[json_start:])
        self.assertEqual(data["scanner"], "mcp-scanner")

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_logs_result(self, mock_scan):
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        self.invoke(["scan", "http://localhost:3000"])
        counts = self.app.store.get_counts()
        self.assertEqual(counts.total_scans, 1)

    def test_scan_blocked_url_skipped(self):
        pe = PolicyEngine(self.app.store)
        pe.block("mcp", "http://evil.com", "unsafe")

        result = self.invoke(["scan", "http://evil.com"])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("BLOCKED", result.output)

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_allowed_url_still_scans(self, mock_scan):
        """Allowed servers should still be scannable via explicit 'mcp scan'."""
        pe = PolicyEngine(self.app.store)
        pe.allow("mcp", "http://safe.com", "trusted")

        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://safe.com",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        result = self.invoke(["scan", "http://safe.com"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("CLEAN", result.output)
        self.assertNotIn("ALLOWED", result.output)
        mock_scan.assert_called_once()


class TestMCPList(MCPCommandTestBase):
    @patch("defenseclaw.config.Config.mcp_servers", return_value=[])
    def test_list_empty(self, _mock):
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No MCP servers", result.output)

    @patch("defenseclaw.config.Config.mcp_servers")
    def test_list_with_entries(self, mock_servers):
        mock_servers.return_value = [
            MCPServerEntry(name="my-server", command="uvx", args=["my-mcp"], url="", transport="stdio"),
            MCPServerEntry(name="remote", command="", args=[], url="https://example.com/mcp", transport="sse"),
        ]

        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("my-server", result.output)
        self.assertIn("remote", result.output)

    @patch("defenseclaw.config.Config.mcp_servers")
    def test_list_json(self, mock_servers):
        mock_servers.return_value = [
            MCPServerEntry(name="test-srv", command="npx", args=[], url="", transport="stdio"),
        ]

        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["name"], "test-srv")


# ---------------------------------------------------------------------------
# _parse_args
# ---------------------------------------------------------------------------

class TestParseArgs(unittest.TestCase):
    def test_json_array(self):
        result = _parse_args('["-y", "@modelcontextprotocol/server-filesystem", "~/Documents"]')
        self.assertEqual(result, ["-y", "@modelcontextprotocol/server-filesystem", "~/Documents"])

    def test_comma_separated(self):
        result = _parse_args("-y,@modelcontextprotocol/server-filesystem,~/Documents")
        self.assertEqual(result, ["-y", "@modelcontextprotocol/server-filesystem", "~/Documents"])

    def test_single_arg(self):
        result = _parse_args("context7-mcp")
        self.assertEqual(result, ["context7-mcp"])

    def test_json_array_with_spaces(self):
        result = _parse_args('  ["-y", "my-server"]  ')
        self.assertEqual(result, ["-y", "my-server"])

    def test_invalid_json_falls_back_to_comma(self):
        result = _parse_args("[not-valid-json")
        self.assertEqual(result, ["[not-valid-json"])

    def test_empty_string(self):
        result = _parse_args("")
        self.assertEqual(result, [])

    def test_json_array_with_numbers(self):
        result = _parse_args('["-y", 42, "server"]')
        self.assertEqual(result, ["-y", "42", "server"])


# ---------------------------------------------------------------------------
# _build_mcp_scan_map
# ---------------------------------------------------------------------------

class TestBuildMCPScanMap(MCPCommandTestBase):
    def test_empty_store(self):
        servers: list[MCPServerEntry] = []
        scan_map = _build_mcp_scan_map(self.app.store, servers)
        self.assertEqual(scan_map, {})

    def test_none_store(self):
        scan_map = _build_mcp_scan_map(None, [])
        self.assertEqual(scan_map, {})

    def test_url_target_mapped_to_server_name(self):
        """Scan stored with URL target should map back to server name."""
        servers = [
            MCPServerEntry(name="deepwiki", command="", args=[], url="https://mcp.deepwiki.com/mcp", transport="sse"),
        ]
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "mcp-scanner", "https://mcp.deepwiki.com/mcp",
            datetime.now(timezone.utc), 500, 0, None, "{}",
        )
        scan_map = _build_mcp_scan_map(self.app.store, servers)
        self.assertIn("deepwiki", scan_map)
        self.assertEqual(scan_map["deepwiki"]["max_severity"], "CLEAN")
        self.assertTrue(scan_map["deepwiki"]["clean"])

    def test_plain_name_target(self):
        """Scan stored with plain name target should map directly."""
        servers = [
            MCPServerEntry(name="context7", command="npx", args=[], url="", transport="stdio"),
        ]
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "mcp-scanner", "context7",
            datetime.now(timezone.utc), 800, 2, "HIGH", "{}",
        )
        scan_map = _build_mcp_scan_map(self.app.store, servers)
        self.assertIn("context7", scan_map)
        self.assertEqual(scan_map["context7"]["max_severity"], "HIGH")
        self.assertEqual(scan_map["context7"]["total_findings"], 2)
        self.assertFalse(scan_map["context7"]["clean"])

    def test_unmatched_url_excluded(self):
        """URL targets that don't match any server are excluded."""
        servers = [
            MCPServerEntry(name="my-server", command="uvx", args=[], url="https://other.com", transport="sse"),
        ]
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "mcp-scanner", "https://unknown.com/mcp",
            datetime.now(timezone.utc), 300, 0, None, "{}",
        )
        scan_map = _build_mcp_scan_map(self.app.store, servers)
        self.assertEqual(scan_map, {})

    def test_clean_scan_shows_clean_not_info(self):
        """Zero-finding scans should show CLEAN, not INFO."""
        servers = [
            MCPServerEntry(name="clean-srv", command="npx", args=[], url="", transport="stdio"),
        ]
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "mcp-scanner", "clean-srv",
            datetime.now(timezone.utc), 200, 0, None, "{}",
        )
        scan_map = _build_mcp_scan_map(self.app.store, servers)
        self.assertEqual(scan_map["clean-srv"]["max_severity"], "CLEAN")

    def test_dirty_scan_uses_actual_severity(self):
        """Scans with findings should use the DB severity, not CLEAN."""
        servers = [
            MCPServerEntry(name="dirty-srv", command="npx", args=[], url="", transport="stdio"),
        ]
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "mcp-scanner", "dirty-srv",
            datetime.now(timezone.utc), 400, 3, "CRITICAL", "{}",
        )
        scan_map = _build_mcp_scan_map(self.app.store, servers)
        self.assertEqual(scan_map["dirty-srv"]["max_severity"], "CRITICAL")


# ---------------------------------------------------------------------------
# _attach_error_handler
# ---------------------------------------------------------------------------

class TestAttachErrorHandler(unittest.TestCase):
    def test_attaches_to_three_loggers(self):
        import logging
        from defenseclaw.scanner.mcp import _attach_error_handler, _ErrorCapture

        errors: list[str] = []
        handler = _ErrorCapture(errors)
        loggers = _attach_error_handler(handler)

        self.assertEqual(len(loggers), 3)
        logger_names = [lgr.name for lgr in loggers]
        self.assertIn("mcpscanner", logger_names)
        self.assertIn("mcpscanner.core", logger_names)
        self.assertIn("mcpscanner.core.scanner", logger_names)

        for lgr in loggers:
            self.assertIn(handler, lgr.handlers)

        for lgr in loggers:
            lgr.removeHandler(handler)

    def test_captures_error_from_child_logger(self):
        import logging
        from defenseclaw.scanner.mcp import _attach_error_handler, _ErrorCapture

        errors: list[str] = []
        handler = _ErrorCapture(errors)
        loggers = _attach_error_handler(handler)

        child = logging.getLogger("mcpscanner.core.scanner")
        child.error("Error connecting to stdio server npx: Connection closed")

        self.assertTrue(len(errors) >= 1)
        self.assertTrue(any("connecting" in e.lower() for e in errors))

        for lgr in loggers:
            lgr.removeHandler(handler)

    def test_error_capture_filters_by_level(self):
        import logging
        from defenseclaw.scanner.mcp import _ErrorCapture

        errors: list[str] = []
        handler = _ErrorCapture(errors)

        logger = logging.getLogger("test.error_capture_filter")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        logger.info("info message")
        logger.warning("warning message")
        logger.error("error message")

        self.assertEqual(len(errors), 1)
        self.assertIn("error message", errors[0])

        logger.removeHandler(handler)


if __name__ == "__main__":
    unittest.main()
