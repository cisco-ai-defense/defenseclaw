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
        self.assertTrue(self.pe().is_tool_blocked("delete_file"))

    def test_block_scoped_writes_both_global_and_scoped_audit(self):
        """Avarice F-2347: scoped tool blocks were silently never
        enforced because the runtime only consults unscoped rows. Until
        scope-aware enforcement lands, --source requests upgrade to
        the global block (with a scoped audit row preserved)."""
        result = self.invoke(["block", "write_file", "--source", "filesystem"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("filesystem", result.output)
        # Scoped audit entry exists for operator visibility.
        self.assertTrue(self.pe().is_tool_blocked("write_file", source="filesystem"))
        # F-2347: global block IS now set so the runtime actually
        # enforces — operators that genuinely want a scope-only
        # block must wait for runtime support.
        self.assertTrue(self.pe().is_tool_blocked("write_file"))

    def test_block_scoped_blocks_unrelated_source_for_safety(self):
        """F-2347: with the runtime not honouring scoped blocks, a
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
        names = [row["name"] for row in data]
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

    def test_status_scoped_wins_over_global_allow(self):
        self.pe().allow_tool("write_file", "", "global allow")
        self.pe().block_tool("write_file", "filesystem", "scoped block")

        result = self.invoke(["status", "write_file", "--source", "filesystem"])
        self.assertIn("block", result.output)
        self.assertIn("Effective", result.output)

    def test_status_json(self):
        self.pe().block_tool("exec_cmd", "", "dangerous")
        result = self.invoke(["status", "exec_cmd", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(data["tool"], "exec_cmd")
        self.assertEqual(data["global"]["status"], "block")


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


if __name__ == "__main__":
    unittest.main()
