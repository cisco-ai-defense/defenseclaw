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

"""Tests for 'defenseclaw tool' command group — block, allow, unblock, list, status."""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_tool import tool
from defenseclaw.enforce.policy import PolicyEngine

from tests.helpers import cleanup_app, make_app_context


class ToolCommandTestBase(unittest.TestCase):
    """Base class with a temp AppContext for tool command tests."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args: list[str]):
        return self.runner.invoke(tool, args, obj=self.app, catch_exceptions=False)

    def pe(self) -> PolicyEngine:
        return PolicyEngine(self.app.store)


# ---------------------------------------------------------------------------
# block
# ---------------------------------------------------------------------------

class TestToolBlock(ToolCommandTestBase):
    def test_block_adds_to_block_list(self):
        result = self.invoke(["block", "delete_file", "--reason", "destructive"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("delete_file", result.output)
        self.assertIn("block list", result.output)
        self.assertIn("connector=codex", result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertTrue(self.pe().is_tool_blocked("delete_file"))

    def test_block_scoped_writes_both_global_and_scoped_audit(self):
        """scoped tool blocks were silently never
        enforced because the runtime only consults unscoped rows. Until
        scope-aware enforcement lands, --source requests upgrade to
        the global block (with a scoped audit row preserved)."""
        result = self.invoke(["block", "write_file", "--source", "filesystem"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("filesystem", result.output)
        # Scoped audit entry exists for operator visibility.
        self.assertTrue(self.pe().is_tool_blocked("write_file", source="filesystem"))
        # global block IS now set so the runtime actually
        # enforces — operators that genuinely want a scope-only
        # block must wait for runtime support.
        self.assertTrue(self.pe().is_tool_blocked("write_file"))

    def test_block_scoped_blocks_unrelated_source_for_safety(self):
        """with the runtime not honouring scoped blocks, a
        --source request must fail closed and block ALL sources for
        that tool name."""
        self.invoke(["block", "write_file", "--source", "filesystem"])
        # Defense-in-depth: any source resolves to blocked because the
        # global row exists. A future runtime upgrade can tighten this.
        self.assertTrue(self.pe().is_tool_blocked("write_file", source="other-source"))

    def test_block_default_reason(self):
        self.invoke(["block", "exec_cmd"])
        entry = self.pe().get_action("tool", "exec_cmd")
        self.assertIsNotNone(entry)
        self.assertIn("manual", entry.reason)

    def test_block_logs_audit_event(self):
        self.invoke(["block", "shell_exec", "--reason", "dangerous"])
        events = self.app.store.list_events(10)
        matched = [e for e in events if e.action == "tool-block"]
        self.assertEqual(len(matched), 1)
        self.assertIn("dangerous", matched[0].details)


# ---------------------------------------------------------------------------
# allow
# ---------------------------------------------------------------------------

class TestToolAllow(ToolCommandTestBase):
    def test_allow_adds_to_allow_list(self):
        result = self.invoke(["allow", "search", "--reason", "vetted"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("search", result.output)
        self.assertIn("allow list", result.output)
        self.assertIn("connector=codex", result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertTrue(self.pe().is_tool_allowed("search"))

    def test_allow_scoped(self):
        self.invoke(["allow", "search", "--source", "web-search"])
        self.assertTrue(self.pe().is_tool_allowed("search", source="web-search"))
        self.assertFalse(self.pe().is_tool_allowed("search"))

    def test_allow_logs_audit_event(self):
        self.invoke(["allow", "read_file", "--reason", "read-only ok"])
        events = self.app.store.list_events(10)
        matched = [e for e in events if e.action == "tool-allow"]
        self.assertEqual(len(matched), 1)


# ---------------------------------------------------------------------------
# unblock
# ---------------------------------------------------------------------------

class TestToolUnblock(ToolCommandTestBase):
    def test_unblock_removes_global_entry(self):
        self.pe().block_tool("delete_file", "", "test")
        self.assertTrue(self.pe().is_tool_blocked("delete_file"))

        result = self.invoke(["unblock", "delete_file"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(self.pe().is_tool_blocked("delete_file"))

    def test_unblock_scoped(self):
        self.pe().block_tool("write_file", "filesystem", "test")
        self.assertTrue(self.pe().is_tool_blocked("write_file", source="filesystem"))

        self.invoke(["unblock", "write_file", "--source", "filesystem"])
        self.assertFalse(self.pe().is_tool_blocked("write_file", source="filesystem"))

    def test_unblock_nonexistent_does_not_error(self):
        result = self.invoke(["unblock", "nonexistent_tool"])
        self.assertEqual(result.exit_code, 0, result.output)

    def test_unblock_logs_audit_event(self):
        self.pe().block_tool("exec_cmd", "", "test")
        self.invoke(["unblock", "exec_cmd"])
        events = self.app.store.list_events(10)
        matched = [e for e in events if e.action == "tool-unblock"]
        self.assertEqual(len(matched), 1)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

class TestToolList(ToolCommandTestBase):
    def test_list_empty(self):
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No", result.output)

    def test_list_shows_blocked_tools(self):
        self.pe().block_tool("delete_file", "", "dangerous")
        self.pe().allow_tool("read_file", "", "safe")

        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("delete_file", result.output)
        self.assertIn("read_file", result.output)

    def test_list_filter_blocked(self):
        self.pe().block_tool("delete_file", "", "dangerous")
        self.pe().allow_tool("read_file", "", "safe")

        result = self.invoke(["list", "--blocked"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("delete_file", result.output)
        self.assertNotIn("read_file", result.output)

    def test_list_filter_allowed(self):
        self.pe().block_tool("delete_file", "", "dangerous")
        self.pe().allow_tool("read_file", "", "safe")

        result = self.invoke(["list", "--allowed"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("delete_file", result.output)
        self.assertIn("read_file", result.output)

    def test_list_json(self):
        self.pe().block_tool("shell_exec", "", "exec tool")

        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertIsInstance(data, list)
        names = [
            row["name"]
            for group in data
            for row in group.get("tools", [])
        ]
        self.assertIn("shell_exec", names)

    def test_list_scoped_entry_appears(self):
        self.pe().block_tool("write_file", "filesystem", "read-only env")
        result = self.invoke(["list"])
        self.assertIn("filesystem/write_file", result.output)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

class TestToolStatus(ToolCommandTestBase):
    def test_status_no_entry(self):
        result = self.invoke(["status", "unknown_tool"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("none", result.output)

    def test_status_global_block(self):
        self.pe().block_tool("delete_file", "", "dangerous")
        result = self.invoke(["status", "delete_file"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("block", result.output)

    def test_status_source_block_does_not_decide_effective(self):
        """T4: a --source block is audit-only — the runtime never reads it, so
        it must NOT flip the Effective verdict. A global allow stands; the
        source 'block' row is displayed but Effective stays 'allow', matching
        the gateway's real resolution order."""
        self.pe().allow_tool("write_file", "", "global allow")
        self.pe().block_tool("write_file", "filesystem", "scoped block")  # S/T audit row

        result = self.invoke(["status", "write_file", "--source", "filesystem"])
        self.assertEqual(result.exit_code, 0, result.output)
        # The source audit row is still shown (it reads 'block')…
        self.assertIn("filesystem", result.output)
        self.assertIn("block", result.output)
        # …but the connector cards still show the global allow as effective.
        self.assertIn("Connector: codex", result.output)
        self.assertIn("Connector: hermes", result.output)
        self.assertIn("Status: allow", result.output)
        self.assertIn("Scope: global", result.output)

    def test_status_connector_block_wins_over_global_allow(self):
        """Runtime-aligned: a connector-scoped block resolves before the global
        allow for that connector (block @C/T → ... → allow T)."""
        self.pe().allow_tool("write_file", "", "global allow")
        self.pe().block_tool_for_connector("write_file", "hermes", "scoped block")

        result = self.invoke(["status", "write_file", "--connector", "hermes"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Connector: hermes", result.output)
        self.assertIn("Status: block", result.output)
        self.assertIn("Scope: connector", result.output)

    def test_status_connector_allow_wins_over_global_block(self):
        self.pe().block_tool("write_file", "", "global block")
        self.pe().allow_tool_for_connector("write_file", "hermes", "scoped allow")

        result = self.invoke(["status", "write_file", "--connector", "hermes"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Connector: hermes", result.output)
        self.assertIn("Status: allow", result.output)
        self.assertIn("Scope: connector", result.output)

    def test_status_without_connector_fans_out_active_connectors(self):
        self.pe().allow_tool("write_file", "", "global allow")
        self.pe().block_tool_for_connector("write_file", "hermes", "scoped block")

        result = self.invoke(["status", "write_file"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Connector: codex", result.output)
        self.assertIn("Connector: hermes", result.output)
        self.assertIn("Status: allow", result.output)
        self.assertIn("Scope: global", result.output)
        self.assertIn("Status: block", result.output)
        self.assertIn("Scope: connector", result.output)
        self.assertIn("Overall: mixed", result.output)

    def test_status_write_tool_allow_notes_codeguard(self):
        """An allowed WRITE tool still runs CodeGuard (D2) — status says so."""
        self.pe().allow_tool("write_file", "", "vetted")
        result = self.invoke(["status", "write_file"])
        self.assertIn("Status: allow", result.output)
        self.assertIn("CodeGuard", result.output)

    def test_status_json(self):
        self.pe().block_tool("exec_cmd", "", "dangerous")
        result = self.invoke(["status", "exec_cmd", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(data["name"], "exec_cmd")  # unified key (was "tool")
        self.assertIsNone(data["connector"])
        self.assertEqual(data["global"]["status"], "block")
        self.assertEqual(data["effective"], "block")
        self.assertEqual({row["connector"] for row in data["connectors"]}, {"codex", "hermes"})

    def test_status_json_connector_scoped(self):
        self.pe().block_tool_for_connector("exec_cmd", "hermes", "scoped")
        result = self.invoke(["status", "exec_cmd", "--connector", "hermes", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(data["name"], "exec_cmd")
        self.assertEqual(data["connector"], "hermes")
        self.assertEqual(data["connector_scoped"]["status"], "block")
        self.assertEqual(data["effective"], "block")


# ---------------------------------------------------------------------------
# is_tool_blocked does not interfere with skill-level decisions
# ---------------------------------------------------------------------------

class TestToolBlockIsolation(ToolCommandTestBase):
    def test_tool_block_does_not_affect_skill_block(self):
        """Blocking a tool must not register as a skill block."""
        self.pe().block_tool("delete_file", "", "dangerous")
        self.assertFalse(self.pe().is_blocked("skill", "delete_file"))

    def test_tool_allow_does_not_affect_mcp_allow(self):
        """Allowing a tool must not register as an MCP allow."""
        self.pe().allow_tool("search", "", "vetted")
        self.assertFalse(self.pe().is_allowed("mcp", "search"))


# ---------------------------------------------------------------------------
# --connector scoping (T1) wired to the merged @C/T PolicyEngine gate (T2)
# ---------------------------------------------------------------------------

class TestToolConnectorScoping(ToolCommandTestBase):
    def test_block_connector_scoped_isolated(self):
        result = self.invoke(["block", "delete_file", "--connector", "hermes"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("hermes", result.output)
        self.assertTrue(self.pe().is_tool_blocked_for_connector("delete_file", "hermes"))
        # Isolated: a different connector and the global tier are untouched.
        self.assertFalse(self.pe().is_tool_blocked_for_connector("delete_file", "codex"))
        self.assertFalse(self.pe().is_tool_blocked("delete_file"))

    def test_block_global_hits_all_connectors(self):
        self.invoke(["block", "delete_file"])
        for conn in ("hermes", "codex", "claudecode"):
            self.assertTrue(self.pe().is_tool_blocked_for_connector("delete_file", conn))

    def test_allow_connector_scoped_isolated(self):
        result = self.invoke(["allow", "search", "--connector", "hermes"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(self.pe().is_tool_allowed_for_connector("search", "hermes"))
        self.assertFalse(self.pe().is_tool_allowed_for_connector("search", "codex"))
        self.assertFalse(self.pe().is_tool_allowed("search"))

    def test_unblock_connector_scoped(self):
        self.pe().block_tool_for_connector("delete_file", "hermes", "test")
        self.assertTrue(self.pe().is_tool_blocked_for_connector("delete_file", "hermes"))

        result = self.invoke(["unblock", "delete_file", "--connector", "hermes"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(self.pe().is_tool_blocked_for_connector("delete_file", "hermes"))

    def test_unblock_global_clears_connector_scoped_rows(self):
        self.pe().block_tool("delete_file", "", "global")
        self.pe().block_tool_for_connector("delete_file", "hermes", "scoped")

        result = self.invoke(["unblock", "delete_file"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=codex", result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertFalse(self.pe().is_tool_blocked("delete_file"))
        self.assertFalse(self.app.store.has_action("tool", "@hermes/delete_file", "install", "block"))

    def test_connector_normalized(self):
        """A connector value is canonicalized (e.g. 'Hermes' → 'hermes') so the
        CLI write surface matches the runtime's lowercase connector keys."""
        self.invoke(["block", "delete_file", "--connector", "Hermes"])
        self.assertTrue(self.pe().is_tool_blocked_for_connector("delete_file", "hermes"))

    def test_invalid_connector_rejected(self):
        result = self.invoke(["block", "delete_file", "--connector", "bogus"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not configured", result.output.lower())
        self.assertIsNone(self.app.store.get_action("tool", "@bogus/delete_file"))

    def test_unknown_connector_rejected_for_all_connector_commands(self):
        commands = [
            ["block", "delete_file", "--connector", "bogus"],
            ["allow", "delete_file", "--connector", "bogus"],
            ["unblock", "delete_file", "--connector", "bogus"],
            ["list", "--connector", "bogus"],
            ["status", "delete_file", "--connector", "bogus"],
        ]

        for args in commands:
            with self.subTest(args=args):
                result = self.invoke(args)
                self.assertEqual(result.exit_code, 2, result.output)
                self.assertIn("not configured", result.output)

        self.assertIsNone(self.app.store.get_action("tool", "@bogus/delete_file"))

    def test_connector_and_source_mutually_exclusive(self):
        result = self.invoke(
            ["block", "delete_file", "--connector", "hermes", "--source", "fs"]
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("cannot be combined", result.output.lower())

    def test_list_connector_column_and_filter(self):
        self.pe().block_tool_for_connector("delete_file", "hermes", "scoped")
        self.pe().block_tool("exec_cmd", "", "global")
        self.pe().block_tool_for_connector("other_tool", "codex", "x")

        # Default list: one connector-scoped section per active connector;
        # @C/T rows are shown by bare tool name.
        result = self.invoke(["list"])
        self.assertIn("SCOPE", result.output)
        self.assertIn("Tools (connector=codex)", result.output)
        self.assertIn("Tools (connector=hermes)", result.output)
        self.assertIn("global", result.output)
        self.assertIn("connector", result.output)
        self.assertIn("hermes", result.output)
        self.assertIn("delete_file", result.output)
        self.assertNotIn("@hermes/delete_file", result.output)

        # --connector hermes: its own rows + global, never another connector's.
        result = self.invoke(["list", "--connector", "hermes"])
        self.assertIn("Tools (connector=hermes)", result.output)
        self.assertIn("delete_file", result.output)   # @hermes/ row
        self.assertIn("exec_cmd", result.output)       # global applies to hermes
        self.assertIn("global", result.output)
        self.assertIn("connector", result.output)
        self.assertNotIn("other_tool", result.output)  # @codex/ row excluded

    def test_list_json_has_connector_field(self):
        self.pe().block_tool_for_connector("delete_file", "hermes", "scoped")
        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        hermes_group = next(g for g in data if g["connector"] == "hermes")
        row = next(r for r in hermes_group["tools"] if r["name"] == "delete_file")
        self.assertEqual(row["connector"], "hermes")
        self.assertEqual(row["scope"], "connector")
        self.assertEqual(row["status"], "block")

    def test_list_json_connector_filter_marks_global_fallback_scope(self):
        self.pe().block_tool("exec_cmd", "", "global")

        result = self.invoke(["list", "--connector", "hermes", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(data["connector"], "hermes")
        row = next(r for r in data["tools"] if r["name"] == "exec_cmd")
        self.assertEqual(row["connector"], "hermes")
        self.assertEqual(row["scope"], "global")
        self.assertEqual(row["status"], "block")

    def test_list_connector_empty_names_connector(self):
        result = self.invoke(["list", "--connector", "hermes"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector='hermes'", result.output)

    def test_bare_allow_clears_connector_specific_block_override(self):
        self.pe().block_tool_for_connector("search", "hermes", "scoped block")

        result = self.invoke(["allow", "search"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Cleared connector-specific overrides for connector=hermes", result.output)
        self.assertTrue(self.pe().is_tool_allowed("search"))
        self.assertTrue(self.pe().is_tool_allowed_for_connector("search", "hermes"))
        self.assertFalse(self.app.store.has_action("tool", "@hermes/search", "install", "block"))

    def test_bare_block_clears_connector_specific_allow_override(self):
        self.pe().allow_tool_for_connector("search", "hermes", "scoped allow")

        result = self.invoke(["block", "search"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Cleared connector-specific overrides for connector=hermes", result.output)
        self.assertTrue(self.pe().is_tool_blocked("search"))
        self.assertTrue(self.pe().is_tool_blocked_for_connector("search", "hermes"))
        self.assertFalse(self.app.store.has_action("tool", "@hermes/search", "install", "allow"))


if __name__ == "__main__":
    unittest.main()
