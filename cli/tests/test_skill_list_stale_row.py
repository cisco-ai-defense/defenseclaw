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

"""`skill list` and the TUI Skills panel drop a row once nothing is left to show (GAP-2606)."""

from __future__ import annotations

import json
import os
import shutil
import unittest

from click.testing import CliRunner
from defenseclaw.commands.cmd_skill import skill
from defenseclaw.tui.services.catalog_state import SkillsPanelModel

from tests.helpers import cleanup_app, make_app_context


class TestSkillListStaleRow(unittest.TestCase):
    def setUp(self) -> None:
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self.root = os.path.join(self.tmp_dir, "claude-skills")
        os.makedirs(self.root)
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: [self.root]  # type: ignore[method-assign]
        self.path = os.path.join(self.root, "risky")
        os.makedirs(self.path)
        with open(os.path.join(self.path, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("test fixture\n")

    def tearDown(self) -> None:
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args: list[str]) -> str:
        result = self.runner.invoke(skill, args, obj=self.app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, result.output)
        return result.output

    def listed(self) -> list[dict]:
        return json.loads(self.invoke(["list", "--json"]))

    def test_restored_then_removed_skill_leaves_no_row(self) -> None:
        self.invoke(["quarantine", "risky", "--connector", "claudecode"])
        self.invoke(["restore", "risky"])
        # A restored skill is a plain active skill again: no leftover quarantine reason.
        row = self.listed()[0]
        self.assertEqual(row["status"], "active")
        self.assertNotIn("reason", row)

        self.invoke(["unblock", "risky"])
        shutil.rmtree(self.path)
        self.assertEqual(self.listed(), [])

    def test_quarantine_copy_deleted_by_hand_leaves_no_row(self) -> None:
        self.invoke(["quarantine", "risky", "--connector", "claudecode"])
        self.invoke(["unblock", "risky"])
        # While the held copy exists the row stays: restore is still possible.
        self.assertEqual(self.listed()[0]["actions"]["file"], "quarantine")

        for record in self.app.store.list_quarantine_records("skill"):
            shutil.rmtree(record.quarantine_path)

        self.assertEqual(self.listed(), [])
        panel = SkillsPanelModel(connector="claudecode")
        panel.apply_json(self.invoke(["list", "--json"]))
        self.assertEqual(panel.count(), 0)

    def test_quarantine_copy_deleted_by_hand_while_blocked_is_not_listed_quarantined(self) -> None:
        self.invoke(["quarantine", "risky", "--connector", "claudecode"])
        for record in self.app.store.list_quarantine_records("skill"):
            shutil.rmtree(record.quarantine_path)

        for row in self.listed():
            self.assertNotEqual(row.get("actions", {}).get("file"), "quarantine", row)
            self.assertNotEqual(row.get("actions", {}).get("runtime"), "disable", row)
            self.assertFalse(row.get("disabled"), row)
        panel = SkillsPanelModel(connector="claudecode")
        panel.apply_json(self.invoke(["list", "--json"]))
        self.assertTrue(all("quarantine" not in (row.actions or "") for row in panel.items))

    def test_unblock_after_hand_deleted_copy_does_not_say_files_remain(self) -> None:
        self.invoke(["quarantine", "risky", "--connector", "claudecode"])
        for record in self.app.store.list_quarantine_records("skill"):
            shutil.rmtree(record.quarantine_path)
        self.assertNotIn("remain quarantined", self.invoke(["unblock", "risky"]))


if __name__ == "__main__":
    unittest.main()
