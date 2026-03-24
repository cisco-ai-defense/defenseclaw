"""Tests for 'defenseclaw mcp' command group — scan, block, allow, list."""

import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_mcp import mcp
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.models import Finding, ScanResult
from tests.helpers import make_app_context, cleanup_app


class MCPCommandTestBase(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

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


class TestMCPScan(MCPCommandTestBase):
    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper")
    def test_scan_clean(self, mock_cls):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "http://localhost:3000"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("CLEAN", result.output)

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper")
    def test_scan_with_findings(self, mock_cls):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[
                Finding(id="f1", severity="HIGH", title="No auth", scanner="mcp-scanner"),
            ],
        )
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "http://localhost:3000"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("HIGH", result.output)
        self.assertIn("No auth", result.output)

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper")
    def test_scan_json_output(self, mock_cls):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "http://localhost:3000", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        # Output has a status line before the JSON body
        json_start = result.output.index("{")
        data = json.loads(result.output[json_start:])
        self.assertEqual(data["scanner"], "mcp-scanner")

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper")
    def test_scan_logs_result(self, mock_cls):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )
        mock_cls.return_value = mock_scanner

        self.invoke(["scan", "http://localhost:3000"])
        counts = self.app.store.get_counts()
        self.assertEqual(counts.total_scans, 1)


class TestMCPList(MCPCommandTestBase):
    def test_list_empty(self):
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No MCP servers", result.output)

    def test_list_with_entries(self):
        pe = PolicyEngine(self.app.store)
        pe.block("mcp", "http://bad.com", "test")
        pe.allow("mcp", "http://good.com", "test")

        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("http://bad.com", result.output)
        self.assertIn("http://good.com", result.output)


if __name__ == "__main__":
    unittest.main()
