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

"""rel-1-0-6:GAP-0289: a quarantined Claude Code plugin shows as disabled.

``plugin quarantine`` left Claude Code's ``enabledPlugins`` entry ``true``,
so ``claude plugin list`` still showed the quarantined plugin enabled.
Quarantine turns the plugin's entries off, restore turns exactly those back
on, and the user's other entries and settings stay as they were.
"""

import json
import os
import unittest
from unittest.mock import patch

from defenseclaw.enforce import claude_plugin_enablement as enablement
from tests.test_cmd_plugin import PluginCommandTestBase


class ClaudePluginQuarantineShowsDisabled(PluginCommandTestBase):
    def setUp(self):
        super().setUp()
        self.app.cfg.claw.mode = "claudecode"
        self.claude_dir = os.path.join(self.tmp_dir, "claude-home")
        os.makedirs(self.claude_dir)
        env = patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": self.claude_dir})
        env.start()
        self.addCleanup(env.stop)
        self.settings = os.path.join(self.claude_dir, "settings.json")
        self.write_settings(
            {
                "model": "haiku",
                "enabledPlugins": {"usm-kit@vs7mp": True, "usm-kit-ok@vs7mp": True, "old@vs7mp": False},
                "hooks": {"PreToolUse": []},
            }
        )
        plugins_root = os.path.join(self.tmp_dir, "claude-plugins")
        mapping = {"claudecode": [plugins_root]}
        self.app.cfg.plugin_dirs = lambda connector=None: mapping.get(connector or "claudecode", [])  # type: ignore[method-assign]
        self.plugin_path = os.path.join(plugins_root, "usm-kit")
        os.makedirs(self.plugin_path)
        with open(os.path.join(self.plugin_path, "plugin.json"), "w") as handle:
            json.dump({"id": "usm-kit"}, handle)

    def write_settings(self, doc):
        with open(self.settings, "w") as handle:
            json.dump(doc, handle, indent=2)

    def read_settings(self):
        with open(self.settings) as handle:
            return json.load(handle)

    def test_quarantine_disables_and_restore_enables_each_round(self):
        for _ in range(3):
            result = self.invoke(["quarantine", "usm-kit", "--connector", "claudecode"])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("usm-kit@vs7mp disabled in Claude Code settings", result.output)
            doc = self.read_settings()
            self.assertEqual(
                doc["enabledPlugins"], {"usm-kit@vs7mp": False, "usm-kit-ok@vs7mp": True, "old@vs7mp": False}
            )
            self.assertEqual((doc["model"], doc["hooks"]), ("haiku", {"PreToolUse": []}))

            result = self.invoke(["restore", "usm-kit", "--connector", "claudecode"])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("usm-kit@vs7mp enabled again in Claude Code settings", result.output)
            doc = self.read_settings()
            self.assertEqual(
                doc["enabledPlugins"], {"usm-kit@vs7mp": True, "usm-kit-ok@vs7mp": True, "old@vs7mp": False}
            )
            self.assertEqual(list(doc), ["model", "enabledPlugins", "hooks"])

    def test_restore_keeps_what_the_user_changed_while_quarantined(self):
        quarantine_dir = self.app.cfg.quarantine_dir
        self.assertEqual(enablement.disable_for_quarantine("usm-kit", quarantine_dir), ["usm-kit@vs7mp"])
        doc = self.read_settings()
        del doc["enabledPlugins"]["usm-kit@vs7mp"]
        doc["enabledPlugins"]["new@vs7mp"] = True
        self.write_settings(doc)
        self.assertEqual(enablement.restore_after_quarantine("usm-kit", quarantine_dir), [])
        self.assertEqual(self.read_settings()["enabledPlugins"], {"usm-kit-ok@vs7mp": True, "old@vs7mp": False, "new@vs7mp": True})
        # The record is gone: a later restore changes nothing.
        self.assertEqual(enablement.restore_after_quarantine("usm-kit", quarantine_dir), [])

    def test_a_disabled_entry_is_not_enabled_by_restore(self):
        quarantine_dir = self.app.cfg.quarantine_dir
        self.assertEqual(enablement.disable_for_quarantine("old", quarantine_dir), [])
        self.assertEqual(enablement.restore_after_quarantine("old", quarantine_dir), [])
        self.assertIs(self.read_settings()["enabledPlugins"]["old@vs7mp"], False)

    def test_settings_that_are_not_a_json_object_are_left_alone(self):
        with open(self.settings, "w") as handle:
            handle.write("{not json")
        self.assertEqual(enablement.disable_for_quarantine("usm-kit", self.app.cfg.quarantine_dir), [])
        with open(self.settings) as handle:
            self.assertEqual(handle.read(), "{not json")


if __name__ == "__main__":
    unittest.main()
