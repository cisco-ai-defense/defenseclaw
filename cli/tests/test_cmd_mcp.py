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
import sys
import unittest
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import click
from click.testing import CliRunner
from defenseclaw.commands.cmd_mcp import (
    _build_mcp_scan_map,
    _parse_args,
    _route_mcpscanner_logs_to_stderr,
    mcp,
)
from defenseclaw.config import MCPServerEntry
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.models import Finding, ScanResult

from tests.helpers import cleanup_app, make_app_context, make_separate_stderr_runner


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


class TestMCPConnectorScope(MCPCommandTestBase):
    """N2: per-connector MCP policy; bare allow/unblock fan out, --connector narrows."""

    def setUp(self):
        super().setUp()
        # Two configured connectors so `scan --connector <name>` validates.
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

    def test_block_connector_scopes_to_peer(self):
        result = self.invoke(["block", "http://demo.example.com", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=codex", result.output)

        pe = PolicyEngine(self.app.store)
        self.assertTrue(pe.is_blocked_for_connector("mcp", "http://demo.example.com", "codex"))
        self.assertFalse(pe.is_blocked_for_connector("mcp", "http://demo.example.com", "claudecode"))
        # Bare/global check is untouched — no global row was written.
        self.assertFalse(pe.is_blocked("mcp", "http://demo.example.com"))

    def test_block_connector_alias_writes_canonical_connector(self):
        result = self.invoke(["block", "jira", "--connector", "claude-code"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=claudecode", result.output)
        self.assertTrue(
            self.app.store.has_action("mcp", "jira", "install", "block", "claudecode")
        )
        self.assertFalse(
            self.app.store.has_action("mcp", "jira", "install", "block", "claude-code")
        )

    def test_connector_mutators_reject_unknown_without_policy_row(self):
        for args in (
            ["block", "jira", "--connector", "nope"],
            ["allow", "jira", "--connector", "nope"],
            ["unblock", "jira", "--connector", "nope"],
        ):
            with self.subTest(args=args):
                result = self.invoke(args)
                self.assertEqual(result.exit_code, 2, result.output)
                self.assertIn("not configured", result.output)

        self.assertIsNone(self.app.store.get_action("mcp", "jira", "nope"))

    def test_global_block_applies_to_every_connector(self):
        result = self.invoke(["block", "http://demo.example.com"])
        self.assertEqual(result.exit_code, 0, result.output)
        pe = PolicyEngine(self.app.store)
        self.assertTrue(pe.is_blocked_for_connector("mcp", "http://demo.example.com", "codex"))
        self.assertTrue(pe.is_blocked_for_connector("mcp", "http://demo.example.com", "claudecode"))
        self.assertTrue(pe.is_blocked("mcp", "http://demo.example.com"))

    def test_block_connector_redundant_when_globally_blocked(self):
        pe = PolicyEngine(self.app.store)
        pe.block("mcp", "http://demo.example.com", "global")
        result = self.invoke(["block", "http://demo.example.com", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("globally", result.output)
        # No redundant codex-scoped row is created.
        self.assertFalse(
            self.app.store.has_action("mcp", "http://demo.example.com", "install", "block", "codex")
        )

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_honors_per_connector_block(self, mock_scan):
        # Fix-plan verification: block --connector codex → scanning codex is
        # blocked, scanning a different connector still scans.
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner", target="http://demo.example.com",
            timestamp=datetime.now(timezone.utc), findings=[],
        )
        self.invoke(["block", "http://demo.example.com", "--connector", "codex"])

        blocked = self.invoke(["scan", "http://demo.example.com", "--connector", "codex"])
        self.assertEqual(blocked.exit_code, 2, blocked.output)
        self.assertIn("BLOCKED", blocked.output)

        ok = self.invoke(["scan", "http://demo.example.com", "--connector", "claudecode"])
        self.assertEqual(ok.exit_code, 0, ok.output)
        self.assertIn("clean=1", ok.output)
        mock_scan.assert_called_once()

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_honors_global_block_on_every_connector(self, mock_scan):
        self.invoke(["block", "http://demo.example.com"])  # global
        for connector in ("codex", "claudecode"):
            r = self.invoke(["scan", "http://demo.example.com", "--connector", connector])
            self.assertEqual(r.exit_code, 2, r.output)
            self.assertIn("BLOCKED", r.output)
        mock_scan.assert_not_called()

    def test_allow_connector_scopes_to_peer(self):
        result = self.invoke(["allow", "http://demo.example.com", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=codex", result.output)
        pe = PolicyEngine(self.app.store)
        self.assertTrue(pe.is_allowed_for_connector("mcp", "http://demo.example.com", "codex"))
        self.assertFalse(pe.is_allowed_for_connector("mcp", "http://demo.example.com", "claudecode"))

    def test_bare_allow_fans_out_to_matching_connector_servers(self):
        def _servers(connector=None):
            if connector in ("claudecode", "codex"):
                return [
                    MCPServerEntry(
                        name="ctx7",
                        url=f"https://{connector}.example/mcp",
                        transport="sse",
                    )
                ]
            return []

        self.app.cfg.mcp_servers = _servers  # type: ignore[method-assign]
        pe = PolicyEngine(self.app.store)
        pe.block_for_connector("mcp", "ctx7", "codex", "scoped")

        result = self.invoke(["allow", "ctx7"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Allowed: ctx7 (connector=claudecode)", result.output)
        self.assertIn("Allowed: ctx7 (connector=codex)", result.output)

        self.assertTrue(pe.is_allowed_for_connector("mcp", "ctx7", "claudecode"))
        self.assertTrue(pe.is_allowed_for_connector("mcp", "ctx7", "codex"))
        self.assertFalse(self.app.store.has_action("mcp", "ctx7", "install", "block", "codex"))
        self.assertFalse(pe.is_allowed("mcp", "ctx7"))

    def test_unblock_connector_scopes_to_peer(self):
        pe = PolicyEngine(self.app.store)
        pe.block_for_connector("mcp", "http://demo.example.com", "codex", "x")
        pe.block_for_connector("mcp", "http://demo.example.com", "claudecode", "x")

        result = self.invoke(["unblock", "http://demo.example.com", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("cleared", result.output)
        self.assertFalse(pe.is_blocked_for_connector("mcp", "http://demo.example.com", "codex"))
        # claudecode's scoped block survives the codex-scoped unblock.
        self.assertTrue(
            self.app.store.has_action("mcp", "http://demo.example.com", "install", "block", "claudecode")
        )

    def test_bare_unblock_clears_connector_scoped_block(self):
        pe = PolicyEngine(self.app.store)
        pe.block_for_connector("mcp", "http://demo.example.com", "codex", "x")
        result = self.invoke(["unblock", "http://demo.example.com"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("all enforcement state cleared (connector=codex)", result.output)
        self.assertFalse(
            self.app.store.has_action("mcp", "http://demo.example.com", "install", "block", "codex")
        )

    def test_bare_unblock_clears_unscoped_and_connector_block(self):
        pe = PolicyEngine(self.app.store)
        pe.block("mcp", "http://demo.example.com", "global")
        pe.block_for_connector("mcp", "http://demo.example.com", "codex", "scoped")
        result = self.invoke(["unblock", "http://demo.example.com"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(pe.is_blocked("mcp", "http://demo.example.com"))
        self.assertFalse(
            self.app.store.has_action("mcp", "http://demo.example.com", "install", "block", "codex")
        )

    def test_bare_allow_and_unblock_clear_scoped_final_state(self):
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]

        def _servers(connector=None):
            if connector in ("codex", "hermes"):
                return [
                    MCPServerEntry(
                        name="ctx7",
                        url=f"https://{connector}.example/mcp",
                        transport="sse",
                    )
                ]
            return []

        self.app.cfg.mcp_servers = _servers  # type: ignore[method-assign]
        pe = PolicyEngine(self.app.store)

        scoped_block = self.invoke(["block", "ctx7", "--connector", "codex"])
        self.assertEqual(scoped_block.exit_code, 0, scoped_block.output)
        self.assertIn("connector=codex", scoped_block.output)
        self.assertFalse(pe.is_blocked_for_connector("mcp", "ctx7", "hermes"))

        bare_allow = self.invoke(["allow", "ctx7"])
        self.assertEqual(bare_allow.exit_code, 0, bare_allow.output)
        self.assertIn("Allowed: ctx7 (connector=codex)", bare_allow.output)
        self.assertIn("Allowed: ctx7 (connector=hermes)", bare_allow.output)

        bare_unblock = self.invoke(["unblock", "ctx7"])
        self.assertEqual(bare_unblock.exit_code, 0, bare_unblock.output)
        self.assertIn("all enforcement state cleared (connector=codex)", bare_unblock.output)
        self.assertIn("all enforcement state cleared (connector=hermes)", bare_unblock.output)

        self.assertIsNone(self.app.store.get_action("mcp", "ctx7", "codex"))
        self.assertIsNone(self.app.store.get_action("mcp", "ctx7", "hermes"))
        self.assertFalse(pe.is_blocked_for_connector("mcp", "ctx7", "codex"))
        self.assertFalse(pe.is_allowed_for_connector("mcp", "ctx7", "codex"))
        self.assertFalse(pe.is_blocked_for_connector("mcp", "ctx7", "hermes"))
        self.assertFalse(pe.is_allowed_for_connector("mcp", "ctx7", "hermes"))


class TestMCPScan(MCPCommandTestBase):
    @patch("defenseclaw.commands.cmd_mcp._run_scan")
    def test_scan_all_flag_without_target(self, mock_run_scan):
        self.app.cfg.mcp_servers = MagicMock(return_value=[
            MCPServerEntry(name="context7", url="http://localhost:3000", transport="sse"),
        ])
        mock_run_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        result = self.invoke(["scan", "--all"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_run_scan.assert_called_once()

    @patch("defenseclaw.commands.cmd_mcp._scan_all_mcp")
    def test_scan_all_multi_connector_fans_out(self, mock_scan_all):
        # D2 parity: `mcp scan --all` scans every active connector's servers.
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all"])

        self.assertEqual(result.exit_code, 0, result.output)
        fanned = {c.args[1] for c in mock_scan_all.call_args_list}
        self.assertEqual(fanned, {"claudecode", "codex"})

    @patch("defenseclaw.commands.cmd_mcp._scan_all_mcp")
    def test_scan_all_no_configured_connectors_exits_without_openclaw_fallback(self, mock_scan_all):
        self.app.cfg.has_connector_configured = lambda: False  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: []  # type: ignore[method-assign]
        self.app.cfg.active_connector = MagicMock(side_effect=AssertionError("must not resolve active connector"))

        result = self.invoke(["scan", "--all"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("no connector configured", result.output)
        mock_scan_all.assert_not_called()

    @patch("defenseclaw.commands.cmd_mcp._scan_all_mcp")
    def test_scan_all_connector_flag_targets_one(self, mock_scan_all):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_scan_all.assert_called_once()
        self.assertEqual(mock_scan_all.call_args.args[1], "codex")

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_all_connector_json_error_includes_connector(self, mock_scan):
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = lambda connector=None: [  # type: ignore[method-assign]
            MCPServerEntry(
                name="node_repl",
                command="npx",
                args=["node-repl"],
                transport="stdio",
            )
        ]
        mock_scan.side_effect = ValueError("connection refused")

        runner = make_separate_stderr_runner()
        result = runner.invoke(
            mcp,
            ["scan", "--all", "--connector", "codex", "--json"],
            obj=self.app,
            catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 1, result.output)
        data = json.loads(result.stdout)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        row = data[0]
        self.assertEqual(row["scanner"], "mcp-scanner")
        self.assertEqual(row["connector"], "codex")
        self.assertEqual(row["target"], "node_repl")
        self.assertIn("connection refused", row["error"])
        self.assertEqual(row["findings"], [])

    def test_invalid_package_runner_config_is_concise_and_nonzero(self):
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = lambda connector=None: [  # type: ignore[method-assign]
            MCPServerEntry(name="broken", command="uvx", args=[], transport="stdio")
        ]

        result = self.invoke(["scan", "broken", "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("launcher 'uvx' requires a package/server argument", result.output)
        self.assertEqual(result.output.count("error: scan failed:"), 1)
        self.assertNotIn("Traceback", result.output)
        self.assertNotIn("ValidationError", result.output)
        self.assertNotIn("mcpscanner.", result.output)

    def test_scan_all_returns_nonzero_when_a_configured_server_errors(self):
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = lambda connector=None: [  # type: ignore[method-assign]
            MCPServerEntry(name="broken", command="uvx", args=[], transport="stdio")
        ]

        result = self.invoke(["scan", "--all", "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("errored=1", result.output)
        self.assertNotIn("Traceback", result.output)
        self.assertNotIn("ValidationError", result.output)

    def test_scan_all_connector_flag_rejects_unknown(self):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all", "--connector", "nope"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not configured", result.output)

    @staticmethod
    def _split_brain_servers():
        # ``ctx7`` lives only in codex; the active connector (claudecode)
        # has a different server. Used to prove --connector scopes the
        # named-target lookup to the chosen connector's config.
        def fake_servers(connector=None):
            if connector == "codex":
                return [MCPServerEntry(name="ctx7", url="http://codex-ctx7", transport="sse")]
            return [MCPServerEntry(name="other", url="http://cc-other", transport="sse")]

        return fake_servers

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_named_target_uses_connector_config(self, mock_scan):
        # Option A: `mcp scan <name> --connector X` resolves the server
        # name against X's MCP config (not the active connector's), so a
        # server registered only to a non-active connector is scannable.
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = self._split_brain_servers()  # type: ignore[method-assign]
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://codex-ctx7",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        result = self.invoke(["scan", "ctx7", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("clean=1", result.output)
        # Resolved against codex's config ⇒ codex's URL was scanned.
        self.assertEqual(mock_scan.call_args.args[0], "http://codex-ctx7")

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_named_target_json_includes_connector(self, mock_scan):
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = self._split_brain_servers()  # type: ignore[method-assign]
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://codex-ctx7",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        result = self.invoke(["scan", "ctx7", "--connector", "codex", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(data["scanner"], "mcp-scanner")
        self.assertEqual(data["connector"], "codex")
        self.assertEqual(data["target"], "http://codex-ctx7")

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_bare_name_fans_out_to_owning_connector(self, mock_scan):
        # M3 (locked: scan all matches): without --connector a bare name is
        # searched across EVERY active connector, so a server registered only
        # on a non-active peer (codex) is found and scanned instead of erroring
        # "not found for connector <active>". Supersedes the pre-M3 control that
        # pinned the single-active-connector lookup.
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = self._split_brain_servers()  # type: ignore[method-assign]
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://codex-ctx7",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        result = self.invoke(["scan", "ctx7"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("clean=1", result.output)
        # Found + scanned against codex's config (its URL), not active claudecode.
        self.assertEqual(mock_scan.call_args.args[0], "http://codex-ctx7")
        self.assertNotIn("openclaw.json", result.output)

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_stdio_launcher_scan_scope_matrix(self, mock_scan):
        """WIN-AUD-064: scoped and unscoped paths retain the stdio entry."""
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        def servers(connector=None):
            command = "npx" if connector == "codex" else "uvx"
            return [
                MCPServerEntry(
                    name="launcher-fixture",
                    command=command,
                    args=["fixture-package"],
                    transport="stdio",
                )
            ]

        self.app.cfg.mcp_servers = servers  # type: ignore[method-assign]
        mock_scan.side_effect = lambda target, **_kwargs: ScanResult(
            scanner="mcp-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        for connector in ("codex", "claudecode"):
            result = self.invoke(
                ["scan", "launcher-fixture", "--connector", connector]
            )
            self.assertEqual(result.exit_code, 0, result.output)

        unscoped = self.invoke(["scan", "launcher-fixture"])
        self.assertEqual(unscoped.exit_code, 0, unscoped.output)

        commands = [
            call.kwargs["server_entry"].command
            for call in mock_scan.call_args_list
        ]
        self.assertEqual(commands.count("npx"), 2)
        self.assertEqual(commands.count("uvx"), 2)

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_bare_name_multi_owner_scans_all(self, mock_scan):
        # M3 (locked decision): a bare name owned by MULTIPLE active connectors
        # is scanned on each, labeled per connector.
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        def both(connector=None):
            url = "http://cc-ctx7" if connector == "claudecode" else "http://codex-ctx7"
            return [MCPServerEntry(name="ctx7", url=url, transport="sse")]

        self.app.cfg.mcp_servers = both  # type: ignore[method-assign]
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner", target="x",
            timestamp=datetime.now(timezone.utc), findings=[],
        )

        result = self.invoke(["scan", "ctx7"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector: claudecode", result.output)
        self.assertIn("connector: codex", result.output)
        self.assertEqual(mock_scan.call_count, 2)
        scanned = {c.args[0] for c in mock_scan.call_args_list}
        self.assertEqual(scanned, {"http://cc-ctx7", "http://codex-ctx7"})

    def test_scan_bare_name_not_found_on_any_connector(self):
        # M3: a name owned by no active connector errors clearly, naming the
        # connectors searched (not the legacy hardcoded "openclaw.json").
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = lambda connector=None: []  # type: ignore[method-assign]

        result = self.invoke(["scan", "ghost"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not found", result.output)
        self.assertIn("claudecode", result.output)
        self.assertIn("codex", result.output)
        self.assertNotIn("openclaw.json", result.output)

    @patch("defenseclaw.commands.cmd_mcp._scan_all_mcp")
    def test_scan_connector_flag_no_target_scans_that_connector(self, mock_scan_all):
        # M4: `mcp scan --connector X` (no --all, no target) scans every server
        # on X — a discoverable single-connector form.
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_scan_all.assert_called_once()
        self.assertEqual(mock_scan_all.call_args.args[1], "codex")

    def test_scan_no_args_prints_usage_hint(self):
        # M4: bare `mcp scan` (no target/--all/--connector) prints a usage hint
        # naming the modes instead of a bare "Missing argument 'TARGET'".
        result = self.invoke(["scan"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--all", result.output)
        self.assertIn("--connector", result.output)

    def test_scan_and_set_help_have_no_stale_openclaw_wording(self):
        # M4: scan/set help must not imply a single "openclaw.json" source.
        scan_help = self.runner.invoke(mcp, ["scan", "--help"]).output
        self.assertNotIn("openclaw.json", scan_help)
        set_help = self.runner.invoke(mcp, ["set", "--help"]).output
        self.assertNotIn("OpenClaw config", set_help)

    def test_empty_list_warning_names_selected_connector_source(self):
        self.app.cfg.active_connectors = lambda: ["opencode"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = lambda connector=None: []  # type: ignore[method-assign]

        result = self.invoke(["list", "--connector", "opencode"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector='opencode'", result.output)
        self.assertIn("OpenCode MCP config", result.output)
        self.assertNotIn("OpenClaw", result.output)

    @patch("defenseclaw.commands.cmd_mcp._unset_mcp_via_connector")
    def test_unset_connector_flag_targets_one(self, mock_unset):
        # D2 parity: `mcp unset --connector X` removes from X's config.
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = MagicMock(
            return_value=[MCPServerEntry(name="ctx7", url="http://x", transport="sse")]
        )

        result = self.invoke(["unset", "ctx7", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(mock_unset.call_args.kwargs.get("connector"), "codex")

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_set_fans_out_to_all_active_connectors(self, mock_set):
        # Without --connector, `mcp set` writes the server to EVERY active
        # connector's config (parity with codeguard install / the list reads).
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["set", "ctx7", "--url", "https://x/mcp", "--skip-scan"])

        self.assertEqual(result.exit_code, 0, result.output)
        called = {c.kwargs.get("connector") for c in mock_set.call_args_list}
        self.assertEqual(called, {"claudecode", "codex"})

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    def test_set_stdio_runs_install_time_scan_with_full_launcher_definition(
        self, mock_admit, mock_scan, mock_set,
    ):
        """WIN-AUD-064: mcp set scans command, args, and env before writing."""
        from defenseclaw.config import SeverityAction
        from defenseclaw.enforce.admission import AdmissionDecision

        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="launcher-fixture",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        def decide(_pe, *, scan_result=None, **_kwargs):
            if scan_result is None:
                return AdmissionDecision("scan", "scan required")
            return AdmissionDecision(
                "warning",
                "within policy",
                action=SeverityAction(install="allow"),
            )

        mock_admit.side_effect = decide
        result = self.invoke(
            [
                "set",
                "launcher-fixture",
                "--command",
                "uvx",
                "--args",
                '["--from", "fixture-package", "fixture-command"]',
                "--env",
                "MCP_FIXTURE_REQUIRED=present",
                "--connector",
                "codex",
            ]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        scan_entry = mock_scan.call_args.kwargs["server_entry"]
        self.assertEqual(scan_entry.command, "uvx")
        self.assertEqual(
            scan_entry.args,
            ["--from", "fixture-package", "fixture-command"],
        )
        self.assertEqual(scan_entry.env, {"MCP_FIXTURE_REQUIRED": "present"})
        mock_set.assert_called_once()

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_set_connector_flag_targets_one(self, mock_set):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(
            ["set", "ctx7", "--url", "https://x/mcp", "--skip-scan", "--connector", "codex"]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        called = {c.kwargs.get("connector") for c in mock_set.call_args_list}
        self.assertEqual(called, {"codex"})

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_set_rejects_mixed_command_and_url(self, mock_set):
        # F-1821: An entry carrying BOTH --command and --url takes the REMOTE
        # scan path (is_local = command and not url -> False) so the URL is
        # scanned while the local command is what gets installed/run. Reject
        # the mismatch so the scanned thing is the installed thing.
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]

        result = self.invoke(
            ["set", "ctx7", "--command", "uvx", "--args", "ctx7-mcp",
             "--url", "https://x/mcp", "--skip-scan"]
        )

        self.assertNotEqual(result.exit_code, 0, result.output)
        self.assertIn("exactly one of --command or --url", result.output)
        # The mixed entry must never reach a connector write.
        mock_set.assert_not_called()

    @patch("defenseclaw.commands.cmd_mcp._unset_mcp_via_connector")
    def test_unset_fans_out_to_all_connectors_with_the_server(self, mock_unset):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = MagicMock(
            return_value=[MCPServerEntry(name="ctx7", url="http://x", transport="sse")]
        )

        result = self.invoke(["unset", "ctx7"])

        self.assertEqual(result.exit_code, 0, result.output)
        called = {c.kwargs.get("connector") for c in mock_unset.call_args_list}
        self.assertEqual(called, {"claudecode", "codex"})

    @patch("defenseclaw.commands.cmd_mcp._unset_mcp_via_connector")
    def test_unset_skips_connectors_without_the_server(self, mock_unset):
        # Fan-out with isolation: a connector that doesn't have the server is
        # skipped, not an error, so one missing entry never blocks the rest.
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        def _servers(connector=None):
            if connector == "codex":
                return [MCPServerEntry(name="ctx7", url="http://x", transport="sse")]
            return []

        self.app.cfg.mcp_servers = _servers  # type: ignore[method-assign]

        result = self.invoke(["unset", "ctx7"])

        self.assertEqual(result.exit_code, 0, result.output)
        called = [c.kwargs.get("connector") for c in mock_unset.call_args_list]
        self.assertEqual(called, ["codex"])

    @patch("defenseclaw.commands.cmd_mcp._unset_mcp_via_connector")
    def test_unset_missing_bare_is_idempotent_noop(self, mock_unset):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = lambda connector=None: []  # type: ignore[method-assign]

        result = self.invoke(["unset", "ctx7"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("not configured", result.output)
        self.assertIn("nothing to remove", result.output)
        self.assertIn("claudecode", result.output)
        self.assertIn("codex", result.output)
        mock_unset.assert_not_called()

    @patch("defenseclaw.commands.cmd_mcp._unset_mcp_via_connector")
    def test_unset_missing_scoped_is_idempotent_noop(self, mock_unset):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = lambda connector=None: []  # type: ignore[method-assign]

        result = self.invoke(["unset", "ctx7", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("not configured", result.output)
        self.assertIn("nothing to remove", result.output)
        self.assertIn("codex", result.output)
        self.assertNotIn("claudecode", result.output)
        mock_unset.assert_not_called()

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_set_skips_unsupported_connector_and_applies_to_rest(self, mock_set):
        # Fan-out resilience: a connector with no MCP write surface
        # must be skipped, not abort the whole command — the writable
        # connectors still get the server.
        from defenseclaw.connector_paths import MCPWriteUnsupportedError

        self.app.cfg.active_connectors = lambda: ["claudecode", "codex", "zeptoclaw"]  # type: ignore[method-assign]

        def _side_effect(cfg, name, entry, connector=None):
            if connector == "zeptoclaw":
                raise MCPWriteUnsupportedError("zeptoclaw has no MCP write surface")

        mock_set.side_effect = _side_effect

        result = self.invoke(["set", "ctx7", "--url", "https://x/mcp", "--skip-scan"])

        self.assertEqual(result.exit_code, 0, result.output)
        applied = {
            c.kwargs.get("connector")
            for c in mock_set.call_args_list
        }
        # write was attempted on all three, but only claudecode/codex succeeded
        self.assertEqual(applied, {"claudecode", "codex", "zeptoclaw"})
        self.assertIn("skipped", result.output)
        self.assertIn("zeptoclaw", result.output)
        self.assertIn("claudecode", result.output)
        self.assertIn("codex", result.output)

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_set_errors_only_when_no_connector_supports_writes(self, mock_set):
        from defenseclaw.connector_paths import MCPWriteUnsupportedError

        self.app.cfg.active_connectors = lambda: ["windsurf", "zeptoclaw"]  # type: ignore[method-assign]
        mock_set.side_effect = MCPWriteUnsupportedError("no MCP write surface")

        result = self.invoke(["set", "ctx7", "--url", "https://x/mcp", "--skip-scan"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("no connector accepted", result.output)
        self.assertIn("no MCP write surface", result.output)

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    def test_set_per_connector_policy_block_skips_only_that_connector(self, mock_admit, mock_set):
        # The core correctness fix: admission is evaluated PER connector, so a
        # connector-scoped policy block (here: codex) skips only that connector
        # while the server is still written to the others.
        from defenseclaw.enforce.admission import AdmissionDecision

        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        def _decide(pe, *, connector="", scan_result=None, **kwargs):
            if connector == "codex":
                return AdmissionDecision("blocked", "blocked on codex by asset rule", source="asset-policy-block")
            return AdmissionDecision("allowed", "allow override", source="manual-allow")

        mock_admit.side_effect = _decide

        result = self.invoke(["set", "ctx7", "--url", "https://x/mcp"])

        self.assertEqual(result.exit_code, 0, result.output)
        written = {c.kwargs.get("connector") for c in mock_set.call_args_list}
        # codex was blocked by policy → never written; claudecode written.
        self.assertEqual(written, {"claudecode"})
        self.assertIn("blocked [codex]", result.output)
        self.assertIn("claudecode", result.output)

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    @patch("defenseclaw.commands.cmd_mcp._run_scan")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    def test_set_post_scan_allow_records_connector_scoped_allow(
        self, mock_admit, mock_run_scan, mock_set,
    ):
        from defenseclaw.config import SeverityAction
        from defenseclaw.enforce.admission import AdmissionDecision

        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        mock_run_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="https://x/mcp",
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="LOW", title="warn", scanner="mcp-scanner")],
        )

        def _decide(pe, *, connector="", scan_result=None, **kwargs):
            if scan_result is None:
                return AdmissionDecision("scan", "scan required")
            return AdmissionDecision(
                "warning",
                "within policy",
                action=SeverityAction(install="allow"),
                source="scan-warning",
            )

        mock_admit.side_effect = _decide

        result = self.invoke(["set", "ctx7", "--url", "https://x/mcp", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(mock_set.call_args.kwargs.get("connector"), "codex")
        self.assertEqual(mock_run_scan.call_args.kwargs.get("audit_target"), "mcp://codex/ctx7")
        self.assertTrue(
            self.app.store.has_action("mcp", "ctx7", "install", "allow", "codex")
        )
        self.assertFalse(self.app.store.has_action("mcp", "ctx7", "install", "allow"))
        self.assertFalse(
            self.app.store.has_action("mcp", "ctx7", "install", "allow", "hermes")
        )

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    @patch("defenseclaw.commands.cmd_mcp._run_scan")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    def test_set_scan_rejection_records_connector_scoped_block(
        self, mock_admit, mock_run_scan, mock_set,
    ):
        from defenseclaw.config import SeverityAction
        from defenseclaw.enforce.admission import AdmissionDecision

        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        mock_run_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="https://x/mcp",
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="bad", scanner="mcp-scanner")],
        )

        def _decide(pe, *, connector="", scan_result=None, **kwargs):
            if scan_result is None:
                return AdmissionDecision("scan", "scan required")
            return AdmissionDecision(
                "rejected",
                "too risky",
                action=SeverityAction(install="block"),
                source="scan-block",
            )

        mock_admit.side_effect = _decide

        result = self.invoke(["set", "ctx7", "--url", "https://x/mcp", "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        mock_set.assert_not_called()
        self.assertTrue(
            self.app.store.has_action("mcp", "ctx7", "install", "block", "codex")
        )
        self.assertFalse(self.app.store.has_action("mcp", "ctx7", "install", "block"))
        self.assertFalse(
            self.app.store.has_action("mcp", "ctx7", "install", "block", "hermes")
        )

    @patch("defenseclaw.commands.cmd_mcp._unset_mcp_via_connector")
    def test_unset_skips_unsupported_write_surface(self, mock_unset):
        # A connector can expose the server via its READ surface yet have no
        # writable surface (e.g. zeptoclaw). Removal must skip it, not abort,
        # so a writable peer that has the server is still cleaned up.
        from defenseclaw.connector_paths import MCPWriteUnsupportedError

        self.app.cfg.active_connectors = lambda: ["codex", "zeptoclaw"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = MagicMock(
            return_value=[MCPServerEntry(name="ctx7", url="http://x", transport="sse")]
        )

        def _side_effect(cfg, name, connector=None):
            if connector == "zeptoclaw":
                raise MCPWriteUnsupportedError("zeptoclaw has no MCP write surface")

        mock_unset.side_effect = _side_effect

        result = self.invoke(["unset", "ctx7"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Removed MCP server: ctx7", result.output)
        self.assertIn("codex", result.output)
        self.assertIn("skipped", result.output)

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_set_multi_applied_summary_names_not_applied(self, mock_set):
        # Partial fan-out: 2 connectors get the server, 1 has no write surface.
        # The green summary must NAME the connector that didn't get it instead
        # of only reporting "Added ... to 2 connectors" and hiding the gap.
        from defenseclaw.connector_paths import MCPWriteUnsupportedError

        self.app.cfg.active_connectors = lambda: ["claudecode", "codex", "zeptoclaw"]  # type: ignore[method-assign]

        def _side_effect(cfg, name, entry, connector=None):
            if connector == "zeptoclaw":
                raise MCPWriteUnsupportedError("zeptoclaw has no MCP write surface")

        mock_set.side_effect = _side_effect

        result = self.invoke(["set", "ctx7", "--url", "https://x/mcp", "--skip-scan"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Added MCP server: ctx7 to 2 connectors", result.output)
        self.assertIn("not applied: zeptoclaw", result.output)

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_set_isolates_unexpected_write_failure_and_exits_nonzero(self, mock_set):
        # Distinct from MCPWriteUnsupportedError (a benign skip, exit 0): an
        # *unexpected* write error (disk full, locked config) on one connector
        # must not abort the rest or leave a silent partial write. The writable
        # peer still gets the server, but the command exits non-zero so
        # scripts/CI notice the partial application.
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        def _fail_first(cfg, name, entry, connector=None):
            if connector == "claudecode":
                raise OSError("disk full")

        mock_set.side_effect = _fail_first

        result = self.invoke(["set", "ctx7", "--url", "https://x/mcp", "--skip-scan"])

        self.assertNotEqual(result.exit_code, 0)
        attempted = {c.kwargs.get("connector") for c in mock_set.call_args_list}
        self.assertEqual(attempted, {"claudecode", "codex"})  # loop not aborted
        self.assertIn("Added MCP server: ctx7", result.output)  # codex landed
        self.assertIn("failed [claudecode]", result.output)

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_set_single_connector_failure_propagates_verbatim(self, mock_set):
        # A single-connector target keeps fail-loud, pre-fan-out behavior: the
        # original error propagates as-is, with no multi-connector
        # "failed [...]" isolation wrapping.
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        mock_set.side_effect = click.ClickException("write surface unsupported")

        result = self.invoke(
            ["set", "ctx7", "--url", "https://x/mcp", "--skip-scan", "--connector", "codex"]
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("write surface unsupported", result.output)
        self.assertNotIn("failed [", result.output)

    @patch("defenseclaw.commands.cmd_mcp._unset_mcp_via_connector")
    def test_unset_isolates_unexpected_write_failure_and_exits_nonzero(self, mock_unset):
        # Symmetric with mcp set: an unexpected removal failure on one connector
        # must not block removal on the others, but still exits non-zero.
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = MagicMock(
            return_value=[MCPServerEntry(name="ctx7", url="http://x", transport="sse")]
        )

        def _fail_first(cfg, name, connector=None):
            if connector == "claudecode":
                raise OSError("config locked")

        mock_unset.side_effect = _fail_first

        result = self.invoke(["unset", "ctx7"])

        self.assertNotEqual(result.exit_code, 0)
        attempted = {c.kwargs.get("connector") for c in mock_unset.call_args_list}
        self.assertEqual(attempted, {"claudecode", "codex"})  # loop not aborted
        self.assertIn("Removed MCP server: ctx7", result.output)  # codex removed
        self.assertIn("failed [claudecode]", result.output)

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
        # S6.4 — the shared scan UX renders "[ok] <target>" instead of
        # the old "Status: CLEAN" line. The summary line carries the
        # canonical clean count.
        self.assertIn("[ok] http://localhost:3000", result.output)
        self.assertIn("clean=1", result.output)

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
        self.assertEqual(data["connector"], "openclaw")

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_allow_private_reaches_direct_url_scanner(self, mock_scan):
        mock_scan.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://127.0.0.1:59994/mcp",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        result = self.invoke(["scan", "http://127.0.0.1:59994/mcp", "--allow-private"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(mock_scan.call_args.kwargs.get("allow_private"))

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan")
    def test_scan_json_error_output_is_parseable(self, mock_scan):
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = lambda connector=None: [  # type: ignore[method-assign]
            MCPServerEntry(
                name="node_repl",
                command="npx",
                args=["node-repl"],
                transport="stdio",
            )
        ]

        def _fail(*args, **kwargs):
            print("2026-06-22 21:11:17,419 - mcpscanner.core.scanner - ERROR - boom")
            os.write(
                1,
                b"2026-06-22 21:11:17,420 - mcpscanner.core.scanner - ERROR - raw fd boom\n",
            )
            raise ValueError("connection refused")

        mock_scan.side_effect = _fail

        runner = make_separate_stderr_runner()
        result = runner.invoke(
            mcp,
            ["scan", "node_repl", "--connector", "codex", "--json"],
            obj=self.app,
            catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertNotIn("mcpscanner.core.scanner", result.stdout)
        self.assertIn("mcpscanner.core.scanner", result.stderr)
        self.assertIn("raw fd boom", result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["scanner"], "mcp-scanner")
        self.assertEqual(data["connector"], "codex")
        self.assertEqual(data["target"], "node_repl")
        self.assertIn("connection refused", data["error"])
        self.assertEqual(data["findings"], [])

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
        # S6.4 — clean verdict shown via shared `[ok]` glyph + summary.
        self.assertIn("[ok] http://safe.com", result.output)
        self.assertIn("clean=1", result.output)
        self.assertNotIn("ALLOWED", result.output)
        mock_scan.assert_called_once()


class TestMCPSetOpencodeGate(MCPCommandTestBase):
    """M5: `mcp set --connector opencode` writes an executable opencode RUNS,
    so the CLI validates/sanitises the server name + command and blocks an
    untrusted command prefix unless explicitly forced — on TOP of admission,
    scoped to opencode."""

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_opencode_rejects_bad_server_name(self, mock_set):
        self.app.cfg.active_connectors = lambda: ["opencode"]  # type: ignore[method-assign]

        result = self.invoke(
            ["set", "../evil", "--command", "npx", "--connector", "opencode", "--skip-scan"]
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("invalid opencode server name", result.output)
        mock_set.assert_not_called()  # the bad entry is never written

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_opencode_rejects_whitespace_command(self, mock_set):
        self.app.cfg.active_connectors = lambda: ["opencode"]  # type: ignore[method-assign]

        result = self.invoke(
            ["set", "demo", "--command", "   ", "--connector", "opencode", "--skip-scan"]
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("non-empty --command", result.output)
        mock_set.assert_not_called()

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    @patch("defenseclaw.commands.cmd_mcp.shutil.which", return_value="/tmp/untrusted/npx")
    @patch("defenseclaw.inventory.agent_discovery._is_trusted_binary_path", return_value=False)
    def test_opencode_blocks_untrusted_command_by_default(self, _trust, _which, mock_set):
        self.app.cfg.active_connectors = lambda: ["opencode"]  # type: ignore[method-assign]

        result = self.invoke(
            ["set", "demo", "--command", "npx", "--connector", "opencode", "--skip-scan"]
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not in a trusted install prefix", result.output)
        self.assertIn("--force-untrusted-command", result.output)
        mock_set.assert_not_called()

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    @patch("defenseclaw.commands.cmd_mcp.shutil.which", return_value="/tmp/untrusted/npx")
    @patch("defenseclaw.inventory.agent_discovery._is_trusted_binary_path", return_value=False)
    def test_opencode_force_untrusted_command_warns_and_writes(self, _trust, _which, mock_set):
        self.app.cfg.active_connectors = lambda: ["opencode"]  # type: ignore[method-assign]

        result = self.invoke(
            [
                "set", "demo", "--command", "npx", "--connector", "opencode",
                "--skip-scan", "--force-untrusted-command",
            ]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("not in a trusted install prefix", result.output)
        self.assertIn("--force-untrusted-command was supplied", result.output)
        self.assertEqual(mock_set.call_args.kwargs.get("connector"), "opencode")

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    @patch("defenseclaw.commands.cmd_mcp.shutil.which", return_value="/usr/bin/trustedcmd")
    @patch("defenseclaw.inventory.agent_discovery._is_trusted_binary_path", return_value=True)
    def test_opencode_trusted_command_no_warning(self, _trust, _which, mock_set):
        self.app.cfg.active_connectors = lambda: ["opencode"]  # type: ignore[method-assign]

        result = self.invoke(
            ["set", "demo", "--command", "trustedcmd", "--connector", "opencode", "--skip-scan"]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("trusted install prefix", result.output)
        self.assertEqual(mock_set.call_args.kwargs.get("connector"), "opencode")

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_opencode_remote_url_server_skips_command_gate(self, mock_set):
        # A remote (url) opencode server has no command to execute → only the
        # name is validated, no trusted-prefix warning.
        self.app.cfg.active_connectors = lambda: ["opencode"]  # type: ignore[method-assign]

        result = self.invoke(
            ["set", "api", "--url", "https://x.example/mcp",
             "--connector", "opencode", "--skip-scan"]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("trusted install prefix", result.output)
        self.assertEqual(mock_set.call_args.kwargs.get("connector"), "opencode")

    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_gate_is_opencode_scoped_not_applied_to_other_connectors(self, mock_set):
        # The opencode name rule must NOT gate other connectors (owned by their
        # own lanes): a name opencode would refuse ("ns/demo") still writes to
        # codex unchanged.
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]

        result = self.invoke(
            ["set", "ns/demo", "--command", "npx", "--connector", "codex", "--skip-scan"]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("invalid opencode server name", result.output)
        self.assertEqual(mock_set.call_args.kwargs.get("connector"), "codex")


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


class TestMcpListUnconfigured(MCPCommandTestBase):
    """Zero-config ``mcp list`` must NOT fabricate a phantom openclaw.

    After ``setup remove`` drops the last connector the config persists
    every connector marker empty (claw.mode='', guardrail.connector='',
    connectors={}). ``mcp list`` should then print a no-connector pointer
    and exit cleanly rather than listing an openclaw table / silently
    targeting ~/.openclaw (finding M1)."""

    def _unconfigure(self):
        self.app.cfg.claw.mode = ""
        self.app.cfg.guardrail.connector = ""
        self.app.cfg.guardrail.connectors = {}

    def test_unconfigured_prints_message_and_exits_clean(self):
        self._unconfigure()
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("no connector configured", result.output)
        # No phantom openclaw table.
        self.assertNotIn("connector=openclaw", result.output)
        self.assertNotIn("MCP Servers", result.output)

    def test_unconfigured_set_does_not_touch_phantom(self):
        # The mutator path shares the resolver, so `mcp set` with nothing
        # configured must also refuse rather than write to ~/.openclaw.
        self._unconfigure()
        result = self.invoke(["set", "ctx7", "--url", "https://x/mcp", "--skip-scan"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("no connector configured", result.output)

    @patch("defenseclaw.config.Config.mcp_servers", return_value=[])
    def test_explicit_openclaw_still_lists(self, _mock):
        # A real openclaw install pins the marker, so it stays listable.
        self.app.cfg.claw.mode = "openclaw"
        self.app.cfg.guardrail.connector = ""
        self.app.cfg.guardrail.connectors = {}
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("no connector configured", result.output)
        self.assertIn("openclaw", result.output)


class TestMcpListMultiConnectorDefault(MCPCommandTestBase):
    """Default ``mcp list`` (no --connector) fans out across every active
    connector — one connector-tagged table each — mirroring ``skill list``
    and ``plugin list``. A single-connector install keeps its flat JSON
    shape."""

    @staticmethod
    def _one_server():
        return [
            MCPServerEntry(name="ctx7", command="uvx", args=["context7-mcp"], url="", transport="stdio"),
        ]

    def test_default_lists_every_active_connector(self):
        self.app.cfg.mcp_servers = lambda connector=None: self._one_server()  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["list"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=claudecode", result.output)
        self.assertIn("connector=codex", result.output)

    def test_default_json_groups_by_connector(self):
        self.app.cfg.mcp_servers = lambda connector=None: self._one_server()  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["list", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertIsInstance(payload, list)
        self.assertEqual({g["connector"] for g in payload}, {"claudecode", "codex"})
        # Each group carries its own server list under "mcp_servers".
        for g in payload:
            self.assertIn("mcp_servers", g)
            self.assertEqual(g["mcp_servers"][0]["name"], "ctx7")
            self.assertEqual(g["mcp_servers"][0]["connector"], g["connector"])

    def test_connector_flag_still_narrows_to_one(self):
        self.app.cfg.mcp_servers = lambda connector=None: self._one_server()  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["list", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=codex", result.output)
        self.assertNotIn("connector=claudecode", result.output)

    def test_single_connector_install_keeps_flat_json(self):
        self.app.cfg.mcp_servers = lambda connector=None: self._one_server()  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]

        result = self.invoke(["list", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertIsInstance(payload, list)
        # Flat list of server dicts (no per-connector grouping wrapper).
        self.assertEqual(payload[0]["name"], "ctx7")
        self.assertEqual(payload[0]["connector"], "claudecode")
        self.assertTrue(all("mcp_servers" not in item for item in payload))

    def test_url_backed_server_without_transport_lists_as_http_not_stdio(self):
        self.app.cfg.active_connectors = lambda: ["antigravity"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = lambda connector=None: [  # type: ignore[method-assign]
            MCPServerEntry(
                name="dc-tui-mcp-antigravity",
                url="http://127.0.0.1:59994/mcp",
            )
        ]

        result = self.invoke(["list", "--json", "--connector", "antigravity"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["connector"], "antigravity")
        self.assertEqual(payload["mcp_servers"][0]["connector"], "antigravity")
        self.assertEqual(payload["mcp_servers"][0]["transport"], "http")
        self.assertEqual(payload["mcp_servers"][0]["url"], "http://127.0.0.1:59994/mcp")

    def test_empty_scoped_json_keeps_connector_metadata(self):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = lambda connector=None: []  # type: ignore[method-assign]

        result = self.invoke(["list", "--json", "--connector", "claudecode"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload, {"connector": "claudecode", "mcp_servers": []})

    def test_list_actions_are_connector_specific_json(self):
        self.app.cfg.mcp_servers = lambda connector=None: self._one_server()  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        pe = PolicyEngine(self.app.store)
        pe.block_for_connector("mcp", "ctx7", "codex", "manual")

        result = self.invoke(["list", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = {g["connector"]: g["mcp_servers"][0] for g in json.loads(result.output)}
        self.assertEqual(payload["codex"]["actions"]["install"], "block")
        self.assertEqual(payload["codex"]["verdict"], "blocked")
        self.assertNotIn("actions", payload["hermes"])
        self.assertNotEqual(payload["hermes"]["verdict"], "blocked")

    def test_list_actions_use_unscoped_fallback_and_scoped_override_json(self):
        self.app.cfg.mcp_servers = lambda connector=None: self._one_server()  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        pe = PolicyEngine(self.app.store)
        pe.block("mcp", "ctx7", "global")
        pe.allow_for_connector("mcp", "ctx7", "hermes", "peer override")

        result = self.invoke(["list", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = {g["connector"]: g["mcp_servers"][0] for g in json.loads(result.output)}
        self.assertEqual(payload["codex"]["actions"]["install"], "block")
        self.assertEqual(payload["codex"]["verdict"], "blocked")
        self.assertEqual(payload["hermes"]["actions"]["install"], "allow")
        self.assertEqual(payload["hermes"]["verdict"], "allowed")

    def test_list_scan_history_is_connector_specific_for_same_named_servers(self):
        self.app.cfg.mcp_servers = lambda connector=None: self._one_server()  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "mcp-scanner", "ctx7",
            datetime.now(timezone.utc), 100, 1, "LOW", "{}",
        )
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "mcp-scanner", "mcp://codex/ctx7",
            datetime.now(timezone.utc), 100, 1, "HIGH", "{}",
        )

        result = self.invoke(["list", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = {g["connector"]: g["mcp_servers"][0] for g in json.loads(result.output)}
        self.assertEqual(payload["codex"]["severity"], "HIGH")
        self.assertEqual(payload["codex"]["verdict"], "rejected")
        self.assertNotIn("severity", payload["hermes"])
        self.assertNotEqual(payload["hermes"]["verdict"], "rejected")


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

    def test_json_array_preserves_literal_comma(self):
        result = _parse_args('["--message", "hello, world"]')
        self.assertEqual(result, ["--message", "hello, world"])

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

    def test_scoped_scan_target_requires_matching_connector(self):
        servers = [
            MCPServerEntry(name="ctx7", command="uvx", args=[], url="", transport="stdio"),
        ]
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "mcp-scanner", "ctx7",
            datetime.now(timezone.utc), 400, 1, "LOW", "{}",
        )
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "mcp-scanner", "mcp://codex/ctx7",
            datetime.now(timezone.utc), 400, 1, "HIGH", "{}",
        )

        self.assertEqual(
            _build_mcp_scan_map(self.app.store, servers, "codex")["ctx7"]["max_severity"],
            "HIGH",
        )
        self.assertEqual(_build_mcp_scan_map(self.app.store, servers, "hermes"), {})
        self.assertEqual(
            _build_mcp_scan_map(
                self.app.store, servers, "hermes", allow_legacy_plain=True,
            )["ctx7"]["max_severity"],
            "LOW",
        )


# ---------------------------------------------------------------------------
# JSON-mode mcpscanner log routing
# ---------------------------------------------------------------------------

class TestMCPJsonLogRouting(unittest.TestCase):
    def test_routes_mcpscanner_stream_handlers_to_stderr_temporarily(self):
        import io
        import logging

        logger = logging.getLogger("mcpscanner.core.scanner")
        root_logger = logging.getLogger("mcpscanner")
        original_propagate = root_logger.propagate
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger.addHandler(handler)

        try:
            with _route_mcpscanner_logs_to_stderr():
                self.assertIs(handler.stream, sys.stderr)
                self.assertFalse(root_logger.propagate)

            self.assertIs(handler.stream, stream)
            self.assertEqual(root_logger.propagate, original_propagate)
        finally:
            logger.removeHandler(handler)
            root_logger.propagate = original_propagate


# ---------------------------------------------------------------------------
# _attach_error_handler
# ---------------------------------------------------------------------------

class TestAttachErrorHandler(unittest.TestCase):
    def test_attaches_to_expected_loggers(self):
        from defenseclaw.scanner.mcp import _attach_error_handler, _ErrorCapture

        errors: list[tuple[str, str]] = []
        handler = _ErrorCapture(errors)
        loggers = _attach_error_handler(handler)

        # The transport loggers plus the LLM analyzer's own logger, so an
        # unreachable LLM backend is captured (and surfaced as a skip
        # notice) even when its logger does not propagate.
        self.assertEqual(len(loggers), 6)
        logger_names = [lgr.name for lgr in loggers]
        self.assertIn("mcpscanner", logger_names)
        self.assertIn("mcpscanner.core", logger_names)
        self.assertIn("mcpscanner.core.scanner", logger_names)
        self.assertIn("mcpscanner.core.analyzers.llm_analyzer", logger_names)
        self.assertIn("mcp", logger_names)

        for lgr in loggers:
            self.assertIn(handler, lgr.handlers)

        for lgr in loggers:
            lgr.removeHandler(handler)

    def test_captures_error_from_child_logger(self):
        import logging

        from defenseclaw.scanner.mcp import _attach_error_handler, _ErrorCapture

        # Captured entries are ``(logger_name, message)`` pairs so the
        # caller can tell the LLM lane apart from the MCP transport.
        errors: list[tuple[str, str]] = []
        handler = _ErrorCapture(errors)
        loggers = _attach_error_handler(handler)

        child = logging.getLogger("mcpscanner.core.scanner")
        child.error("Error connecting to stdio server npx: Connection closed")

        self.assertTrue(len(errors) >= 1)
        self.assertTrue(any("connecting" in msg.lower() for (_name, msg) in errors))
        self.assertTrue(any(name == "mcpscanner.core.scanner" for (name, _msg) in errors))

        for lgr in loggers:
            lgr.removeHandler(handler)

    def test_error_capture_filters_by_level(self):
        import logging

        from defenseclaw.scanner.mcp import _ErrorCapture

        errors: list[tuple[str, str]] = []
        handler = _ErrorCapture(errors)

        logger = logging.getLogger("test.error_capture_filter")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        logger.info("info message")
        logger.warning("warning message")
        logger.error("error message")

        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0][0], "test.error_capture_filter")
        self.assertIn("error message", errors[0][1])

        logger.removeHandler(handler)

    def test_sdk_error_capture_suppresses_exception_traceback(self):
        import contextlib
        import io
        import logging

        from defenseclaw.scanner.mcp import _capture_sdk_error_logs

        errors: list[tuple[str, str]] = []
        stderr = io.StringIO()
        logger = logging.getLogger("mcp.client.stdio")

        with contextlib.redirect_stderr(stderr), _capture_sdk_error_logs(errors):
            try:
                raise ValueError("invalid JSON-RPC payload")
            except ValueError:
                logger.error("Failed to parse JSONRPC message from server", exc_info=True)

        self.assertEqual(
            errors,
            [("mcp.client.stdio", "Failed to parse JSONRPC message from server")],
        )
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
