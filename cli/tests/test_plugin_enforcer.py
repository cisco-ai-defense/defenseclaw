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

"""Tests for PluginEnforcer — filesystem quarantine and restore operations."""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.enforce.plugin_enforcer import PluginEnforcer


class TestPluginEnforcer(unittest.TestCase):
    def setUp(self):
        self.quarantine_root = tempfile.mkdtemp(prefix="dclaw-quarantine-")
        self.plugins_root = tempfile.mkdtemp(prefix="dclaw-plugins-")
        self.enforcer = PluginEnforcer(self.quarantine_root)

    def tearDown(self):
        shutil.rmtree(self.quarantine_root, ignore_errors=True)
        shutil.rmtree(self.plugins_root, ignore_errors=True)

    def _create_plugin(self, name: str) -> str:
        plugin_dir = os.path.join(self.plugins_root, name)
        os.makedirs(plugin_dir, exist_ok=True)
        with open(os.path.join(plugin_dir, "plugin.py"), "w") as f:
            f.write("# plugin code\n")
        return plugin_dir

    def test_quarantine_moves_directory(self):
        plugin_path = self._create_plugin("bad-plugin")
        dest = self.enforcer.quarantine("bad-plugin", plugin_path)

        self.assertIsNotNone(dest)
        self.assertFalse(os.path.exists(plugin_path))
        self.assertTrue(os.path.exists(dest))
        self.assertTrue(os.path.isfile(os.path.join(dest, "plugin.py")))

    def test_quarantine_returns_none_for_nonexistent(self):
        dest = self.enforcer.quarantine("ghost", "/nonexistent/path")
        self.assertIsNone(dest)

    def test_quarantine_refuses_to_overwrite_existing(self):
        plugin_path = self._create_plugin("dup-plugin")
        first_dest = self.enforcer.quarantine("dup-plugin", plugin_path)

        plugin_path2 = self._create_plugin("dup-plugin")
        with open(os.path.join(plugin_path2, "extra.txt"), "w") as f:
            f.write("new content")
        dest = self.enforcer.quarantine("dup-plugin", plugin_path2)

        self.assertIsNone(dest)
        self.assertTrue(os.path.isdir(plugin_path2))
        self.assertFalse(os.path.isfile(os.path.join(first_dest, "extra.txt")))

    def test_is_quarantined(self):
        self.assertFalse(self.enforcer.is_quarantined("my-plugin"))
        plugin_path = self._create_plugin("my-plugin")
        self.enforcer.quarantine("my-plugin", plugin_path)
        self.assertTrue(self.enforcer.is_quarantined("my-plugin"))

    def test_restore_moves_back(self):
        plugin_path = self._create_plugin("restore-me")
        self.enforcer.quarantine("restore-me", plugin_path)
        self.assertFalse(os.path.exists(plugin_path))

        success = self.enforcer.restore("restore-me", plugin_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(plugin_path))
        self.assertTrue(os.path.isfile(os.path.join(plugin_path, "plugin.py")))
        self.assertFalse(self.enforcer.is_quarantined("restore-me"))

    def test_restore_nonexistent_returns_false(self):
        success = self.enforcer.restore("doesnt-exist", "/tmp/wherever")
        self.assertFalse(success)

    def test_full_quarantine_restore_cycle(self):
        plugin_path = self._create_plugin("cycle-plugin")
        self.assertFalse(self.enforcer.is_quarantined("cycle-plugin"))

        self.enforcer.quarantine("cycle-plugin", plugin_path)
        self.assertTrue(self.enforcer.is_quarantined("cycle-plugin"))
        self.assertFalse(os.path.exists(plugin_path))

        self.enforcer.restore("cycle-plugin", plugin_path)
        self.assertFalse(self.enforcer.is_quarantined("cycle-plugin"))
        self.assertTrue(os.path.exists(plugin_path))


if __name__ == "__main__":
    unittest.main()
