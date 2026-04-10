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

"""Tests for 'defenseclaw plugin' command group — install, list, remove, governance."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_plugin import (
    _build_plugin_actions_map,
    _build_plugin_scan_map,
    _resolve_openclaw_plugin_id,
    _resolve_plugin_dir,
    plugin,
)
from defenseclaw.enforce import PolicyEngine
from defenseclaw.enforce.plugin_enforcer import PluginEnforcer
from tests.helpers import make_app_context, cleanup_app


class PluginCommandTestBase(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.plugin_dir = os.path.join(self.tmp_dir, "plugins")
        os.makedirs(self.app.cfg.plugin_dir, exist_ok=True)
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args: list[str]):
        return self.runner.invoke(plugin, args, obj=self.app, catch_exceptions=False)

    def _create_plugin_dir(self, name: str) -> str:
        """Create a fake plugin directory to install from."""
        plugin_src = os.path.join(self.tmp_dir, "plugin-sources", name)
        os.makedirs(plugin_src, exist_ok=True)
        with open(os.path.join(plugin_src, "plugin.py"), "w") as f:
            f.write("# plugin code\n")
        return plugin_src

    def _install_plugin(self, name: str) -> str:
        """Directly copy a plugin into plugin_dir, bypassing the install command.

        Use this when a test needs a plugin as a prerequisite but is not testing
        the install command itself.
        """
        src = self._create_plugin_dir(name)
        dest = os.path.join(self.app.cfg.plugin_dir, name)
        shutil.copytree(src, dest)
        return dest


class TestPluginInstall(PluginCommandTestBase):
    """Local directory installs — scanner mocked to return clean."""

    def _invoke_install(self, args: list[str]):
        return self.runner.invoke(
            plugin, args, obj=self.app, catch_exceptions=True,
        )

    @staticmethod
    def _clean_result():
        from datetime import datetime, timedelta, timezone
        from defenseclaw.models import ScanResult
        return ScanResult(
            scanner="plugin-scanner", target="x",
            timestamp=datetime.now(timezone.utc),
            findings=[], duration=timedelta(seconds=0.1),
        )

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_install_from_directory(self, mock_scan):
        mock_scan.return_value = self._clean_result()
        src = self._create_plugin_dir("my-plugin")
        result = self._invoke_install(["install", src])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: my-plugin", result.output)

        installed = os.path.join(self.app.cfg.plugin_dir, "my-plugin")
        self.assertTrue(os.path.isdir(installed))
        self.assertTrue(os.path.isfile(os.path.join(installed, "plugin.py")))

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_install_duplicate_without_force(self, mock_scan):
        mock_scan.return_value = self._clean_result()
        src = self._create_plugin_dir("dup-plugin")
        self._invoke_install(["install", src])
        result = self._invoke_install(["install", src])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("already installed", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_install_force_overwrites(self, mock_scan):
        mock_scan.return_value = self._clean_result()
        src = self._create_plugin_dir("force-plugin")
        self._invoke_install(["install", src])
        result = self._invoke_install(["install", "--force", src])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: force-plugin", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_install_logs_action(self, mock_scan):
        mock_scan.return_value = self._clean_result()
        src = self._create_plugin_dir("logged-plugin")
        self._invoke_install(["install", src])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "plugin-install"]
        self.assertEqual(len(actions), 1)


class TestPluginList(PluginCommandTestBase):
    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_list_empty(self, _mock_oc):
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No plugins found", result.output)

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_list_with_plugins(self, _mock_oc):
        for name in ["alpha", "beta"]:
            dest = os.path.join(self.app.cfg.plugin_dir, name)
            os.makedirs(dest)

        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("alpha", result.output)
        self.assertIn("beta", result.output)


class TestPluginRemove(PluginCommandTestBase):
    def test_remove_installed_plugin(self):
        self._install_plugin("removable")

        result = self.invoke(["remove", "removable"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Removed plugin: removable", result.output)
        self.assertFalse(os.path.exists(os.path.join(self.app.cfg.plugin_dir, "removable")))

    def test_remove_nonexistent(self):
        result = self.invoke(["remove", "ghost-plugin"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("not found", result.output)

    def test_remove_logs_action(self):
        self._install_plugin("to-remove")
        self.invoke(["remove", "to-remove"])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "plugin-remove"]
        self.assertEqual(len(actions), 1)


class TestPluginRemovePathTraversal(PluginCommandTestBase):
    """Regression tests for path-traversal in plugin remove (P1 fix)."""

    def test_remove_rejects_parent_traversal(self):
        """../../etc -> basename 'etc' -> resolves safely inside plugin_dir -> not found."""
        result = self.invoke(["remove", "../../etc"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("not found", result.output)

    def test_remove_rejects_dotdot(self):
        result = self.invoke(["remove", ".."])
        self.assertEqual(result.exit_code, 1)

    def test_remove_rejects_dot(self):
        result = self.invoke(["remove", "."])
        self.assertEqual(result.exit_code, 1)

    def test_remove_rejects_absolute_path_component(self):
        result = self.invoke(["remove", "/tmp/evil"])
        # os.path.basename("/tmp/evil") == "evil" which is fine as a name,
        # but it should just say "not found" since it doesn't exist
        self.assertIn("not found", result.output)

    def test_remove_rejects_slash_only(self):
        result = self.invoke(["remove", "/"])
        self.assertEqual(result.exit_code, 1)

    def test_remove_strips_path_to_basename(self):
        """Traversal like 'subdir/../other' should be reduced to basename 'other'."""
        result = self.invoke(["remove", "subdir/../other"])
        # basename("subdir/../other") == "other", which just won't exist
        self.assertIn("not found", result.output)

    def test_remove_does_not_delete_outside_plugin_dir(self):
        """Create a dir outside plugin_dir and verify it survives a traversal attempt."""
        outside_dir = os.path.join(self.tmp_dir, "precious-data")
        os.makedirs(outside_dir)
        sentinel = os.path.join(outside_dir, "keep.txt")
        with open(sentinel, "w") as f:
            f.write("do not delete")

        self.invoke(["remove", "../precious-data"])
        self.assertTrue(os.path.isfile(sentinel), "file outside plugin_dir must survive")


class TestPluginLifecycle(PluginCommandTestBase):
    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_install_list_remove_list(self, _mock_oc):
        self._install_plugin("lifecycle")

        result = self.invoke(["list", "--json"])
        self.assertIn("lifecycle", result.output)

        self.invoke(["remove", "lifecycle"])

        result = self.invoke(["list"])
        self.assertIn("No plugins found", result.output)


class TestPluginBlock(PluginCommandTestBase):
    def test_block_happy_path(self):
        result = self.invoke(["block", "blocked-one"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("added to block list", result.output)
        self.assertIn("blocked-one", result.output)
        self.assertTrue(PolicyEngine(self.app.store).is_blocked("plugin", "blocked-one"))
        events = [e for e in self.app.store.list_events(10) if e.action == "plugin-block"]
        self.assertEqual(len(events), 1)

    def test_block_custom_reason_in_audit_log(self):
        self.invoke(["block", "r1", "--reason", "CVE-1234"])
        ev = [e for e in self.app.store.list_events(10) if e.action == "plugin-block"][0]
        self.assertIn("CVE-1234", ev.details)


class TestPluginAllow(PluginCommandTestBase):
    def test_allow_happy_path(self):
        result = self.invoke(["allow", "allowed-one"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("added to allow list", result.output)
        self.assertIn("allowed-one", result.output)
        self.assertTrue(PolicyEngine(self.app.store).is_allowed("plugin", "allowed-one"))
        events = [e for e in self.app.store.list_events(10) if e.action == "plugin-allow"]
        self.assertEqual(len(events), 1)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_allow_reenables_runtime_disable_before_clearing_db(self, mock_cls):
        pe = PolicyEngine(self.app.store)
        pe.disable("plugin", "safe-plugin", "runtime blocked")

        mock_cls.return_value.enable_plugin.return_value = {"status": "enabled"}

        result = self.invoke(["allow", "safe-plugin", "--reason", "reviewed"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(pe.is_allowed("plugin", "safe-plugin"))
        self.assertFalse(self.app.store.has_action("plugin", "safe-plugin", "runtime", "disable"))
        mock_cls.return_value.enable_plugin.assert_called_once_with("safe-plugin")

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_allow_preserves_runtime_disable_when_gateway_enable_fails(self, mock_cls):
        pe = PolicyEngine(self.app.store)
        pe.disable("plugin", "safe-plugin", "runtime blocked")

        mock_cls.return_value.enable_plugin.side_effect = Exception("timeout")

        result = self.invoke(["allow", "safe-plugin", "--reason", "reviewed"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("gateway enable failed", result.output)
        self.assertIn("runtime disable remains until the gateway is reachable", result.output)
        self.assertTrue(pe.is_allowed("plugin", "safe-plugin"))
        self.assertTrue(self.app.store.has_action("plugin", "safe-plugin", "runtime", "disable"))

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins")
    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_allow_scoped_name_clears_resolved_runtime_disable(self, mock_cls, mock_list):
        mock_list.return_value = [{"id": "xai", "name": "@openclaw/xai-plugin"}]
        pe = PolicyEngine(self.app.store)
        pe.disable("plugin", "xai", "runtime blocked")

        mock_cls.return_value.enable_plugin.return_value = {"status": "enabled"}

        result = self.invoke(["allow", "@openclaw/xai-plugin", "--reason", "reviewed"])
        self.assertEqual(result.exit_code, 0, result.output)
        mock_cls.return_value.enable_plugin.assert_called_once_with("xai")
        self.assertFalse(self.app.store.has_action("plugin", "xai", "runtime", "disable"))
        self.assertTrue(pe.is_allowed("plugin", "xai-plugin"))


class TestResolveOpenclawPluginId(unittest.TestCase):
    """Tests for _resolve_openclaw_plugin_id name resolution."""

    MOCK_PLUGINS = [
        {"id": "xai", "name": "@openclaw/xai-plugin"},
        {"id": "whatsapp", "name": "@openclaw/whatsapp-plugin"},
        {"id": "deepgram", "name": "@openclaw/deepgram-provider"},
        {"id": "defenseclaw", "name": "DefenseClaw Security"},
    ]

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins")
    def test_scoped_npm_name_resolves_to_id(self, mock_list):
        mock_list.return_value = self.MOCK_PLUGINS
        self.assertEqual(_resolve_openclaw_plugin_id("@openclaw/xai-plugin"), "xai")

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins")
    def test_bare_name_with_suffix_resolves_to_id(self, mock_list):
        mock_list.return_value = self.MOCK_PLUGINS
        self.assertEqual(_resolve_openclaw_plugin_id("xai-plugin"), "xai")

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins")
    def test_provider_suffix_resolves(self, mock_list):
        mock_list.return_value = self.MOCK_PLUGINS
        self.assertEqual(_resolve_openclaw_plugin_id("deepgram-provider"), "deepgram")

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins")
    def test_exact_id_match_unchanged(self, mock_list):
        mock_list.return_value = self.MOCK_PLUGINS
        self.assertEqual(_resolve_openclaw_plugin_id("whatsapp"), "whatsapp")

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins")
    def test_display_name_match(self, mock_list):
        mock_list.return_value = self.MOCK_PLUGINS
        self.assertEqual(_resolve_openclaw_plugin_id("DefenseClaw Security"), "defenseclaw")

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins")
    def test_unknown_plugin_returns_bare(self, mock_list):
        mock_list.return_value = self.MOCK_PLUGINS
        self.assertEqual(_resolve_openclaw_plugin_id("nonexistent"), "nonexistent")

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins")
    def test_empty_plugin_list_returns_bare(self, mock_list):
        mock_list.return_value = []
        self.assertEqual(_resolve_openclaw_plugin_id("@openclaw/xai-plugin"), "xai-plugin")


@patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
class TestPluginDisableEnable(PluginCommandTestBase):
    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_disable_happy_path(self, mock_cls, _mock_list):
        mock_cls.return_value.disable_plugin.return_value = {"status": "disabled"}
        result = self.invoke(["disable", "any-plugin"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("disabled via gateway RPC", result.output)
        self.assertTrue(self.app.store.has_action("plugin", "any-plugin", "runtime", "disable"))
        events = [e for e in self.app.store.list_events(20) if e.action == "plugin-disable"]
        self.assertEqual(len(events), 1)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_disable_rejects_unexpected_gateway_response(self, mock_cls, _mock_list):
        mock_cls.return_value.disable_plugin.return_value = {"status": "unknown"}
        result = self.invoke(["disable", "p"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("unexpected response", result.output)
        self.assertFalse(self.app.store.has_action("plugin", "p", "runtime", "disable"))

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_enable_happy_path_and_clears_runtime_disable(self, mock_cls, _mock_list):
        mock_inst = mock_cls.return_value
        mock_inst.disable_plugin.return_value = {"status": "disabled"}
        self.invoke(["disable", "toggle-me"])
        self.assertTrue(self.app.store.has_action("plugin", "toggle-me", "runtime", "disable"))
        mock_inst.enable_plugin.return_value = {"status": "enabled"}
        result = self.invoke(["enable", "toggle-me"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("enabled via gateway RPC", result.output)
        self.assertFalse(self.app.store.has_action("plugin", "toggle-me", "runtime", "disable"))
        events = [e for e in self.app.store.list_events(20) if e.action == "plugin-enable"]
        self.assertEqual(len(events), 1)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_enable_rejects_unexpected_gateway_response(self, mock_cls, _mock_list):
        mock_cls.return_value.enable_plugin.return_value = {"status": "broken"}
        result = self.invoke(["enable", "x"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("unexpected response", result.output)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_enable_resolves_scoped_name(self, mock_cls, mock_list):
        """Enable with @openclaw/xai-plugin should resolve to id 'xai'."""
        mock_list.return_value = [{"id": "xai", "name": "@openclaw/xai-plugin"}]
        mock_cls.return_value.enable_plugin.return_value = {"status": "enabled"}
        result = self.invoke(["enable", "@openclaw/xai-plugin"])
        self.assertEqual(result.exit_code, 0, result.output)
        mock_cls.return_value.enable_plugin.assert_called_once_with("xai")

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_disable_resolves_scoped_name(self, mock_cls, mock_list):
        """Disable with @openclaw/xai-plugin should resolve to id 'xai'."""
        mock_list.return_value = [{"id": "xai", "name": "@openclaw/xai-plugin"}]
        mock_cls.return_value.disable_plugin.return_value = {"status": "disabled"}
        result = self.invoke(["disable", "@openclaw/xai-plugin"])
        self.assertEqual(result.exit_code, 0, result.output)
        mock_cls.return_value.disable_plugin.assert_called_once_with("xai")


class TestPluginQuarantineRestore(PluginCommandTestBase):
    def test_quarantine_moves_plugin_and_records_policy(self):
        self._install_plugin("qplug")
        result = self.invoke(["quarantine", "qplug"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("quarantined", result.output)
        self.assertFalse(os.path.isdir(os.path.join(self.app.cfg.plugin_dir, "qplug")))
        qpath = os.path.join(self.app.cfg.quarantine_dir, "plugins", "qplug")
        self.assertTrue(os.path.isdir(qpath))
        self.assertTrue(PolicyEngine(self.app.store).is_quarantined("plugin", "qplug"))
        events = [e for e in self.app.store.list_events(20) if e.action == "plugin-quarantine"]
        self.assertEqual(len(events), 1)

    def test_quarantine_rejects_absolute_path_outside_plugin_dir(self):
        outside = os.path.join(self.tmp_dir, "not-in-plugin-dir")
        os.makedirs(outside)
        abs_out = os.path.realpath(outside)
        result = self.invoke(["quarantine", abs_out])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("must be within plugin directory", result.output)

    def test_restore_roundtrip(self):
        self._install_plugin("rt")
        self.invoke(["quarantine", "rt"])
        result = self.invoke(["restore", "rt"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("restored", result.output)
        restored = os.path.join(self.app.cfg.plugin_dir, "rt")
        self.assertTrue(os.path.isdir(restored))
        events = [e for e in self.app.store.list_events(20) if e.action == "plugin-restore"]
        self.assertEqual(len(events), 1)

    def test_restore_rejects_path_outside_plugin_dir(self):
        self._install_plugin("rplug")
        self.invoke(["quarantine", "rplug"])
        bad_path = os.path.join(self.tmp_dir, "outside-restore-target")
        os.makedirs(bad_path, exist_ok=True)
        result = self.invoke(["restore", "rplug", "--path", bad_path])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("restore path must be within plugin directory", result.output)
        self.assertTrue(os.path.isdir(os.path.join(self.app.cfg.quarantine_dir, "plugins", "rplug")))


class TestPluginInfo(PluginCommandTestBase):
    def test_info_installed_plugin(self):
        self._install_plugin("infoplug")
        result = self.invoke(["info", "infoplug"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("infoplug", result.output)
        self.assertIn("Installed:   True", result.output)
        self.assertIn("Quarantined: False", result.output)

    def test_info_not_installed(self):
        result = self.invoke(["info", "ghost-plugin"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("ghost-plugin", result.output)
        self.assertIn("Installed:   False", result.output)

    def test_info_json_installed(self):
        self._install_plugin("jsonplug")
        result = self.invoke(["info", "jsonplug", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output.strip())
        self.assertTrue(data["installed"])
        self.assertEqual(data["name"], "jsonplug")
        self.assertIn("path", data)

    def test_info_json_not_installed(self):
        result = self.invoke(["info", "missing-plug", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output.strip())
        self.assertFalse(data["installed"])
        self.assertEqual(data["name"], "missing-plug")


@patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
class TestPluginDisableEnableErrors(PluginCommandTestBase):
    """Edge cases for disable/enable: gateway errors, missing status, empty response."""

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_disable_gateway_exception(self, mock_cls, _mock_list):
        """When disable_plugin raises, exit 1 and no policy row created."""
        mock_cls.return_value.disable_plugin.side_effect = Exception("connection refused")
        result = self.invoke(["disable", "err-plugin"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("gateway disable failed", result.output)
        self.assertFalse(self.app.store.has_action("plugin", "err-plugin", "runtime", "disable"))

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_enable_gateway_exception(self, mock_cls, _mock_list):
        """When enable_plugin raises, exit 1."""
        mock_cls.return_value.enable_plugin.side_effect = Exception("timeout")
        result = self.invoke(["enable", "err-plugin"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("gateway enable failed", result.output)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_disable_empty_response(self, mock_cls, _mock_list):
        """Gateway returns {} — missing 'status' key."""
        mock_cls.return_value.disable_plugin.return_value = {}
        result = self.invoke(["disable", "empty-resp"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("unexpected response", result.output)
        self.assertFalse(self.app.store.has_action("plugin", "empty-resp", "runtime", "disable"))

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_enable_empty_response(self, mock_cls, _mock_list):
        """Gateway returns {} — missing 'status' key."""
        mock_cls.return_value.enable_plugin.return_value = {}
        result = self.invoke(["enable", "empty-resp"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("unexpected response", result.output)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_disable_none_status(self, mock_cls, _mock_list):
        """Gateway returns {"status": None}."""
        mock_cls.return_value.disable_plugin.return_value = {"status": None}
        result = self.invoke(["disable", "none-status"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("unexpected response", result.output)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_enable_none_status(self, mock_cls, _mock_list):
        """Gateway returns {"status": None}."""
        mock_cls.return_value.enable_plugin.return_value = {"status": None}
        result = self.invoke(["enable", "none-status"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("unexpected response", result.output)


class TestPluginQuarantineEdgeCases(PluginCommandTestBase):
    """Edge cases for quarantine: not installed, abs path inside dir, enforcer failure."""

    def test_quarantine_not_installed(self):
        """Quarantine a name that doesn't exist as an installed plugin."""
        result = self.invoke(["quarantine", "ghost-plugin"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("could not locate plugin", result.output)

    def test_quarantine_absolute_path_inside_plugin_dir(self):
        """Absolute path pointing inside plugin_dir should succeed."""
        self._install_plugin("abs-plug")
        abs_path = os.path.realpath(os.path.join(self.app.cfg.plugin_dir, "abs-plug"))
        result = self.invoke(["quarantine", abs_path])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("quarantined", result.output)
        self.assertFalse(os.path.isdir(abs_path))

    @patch("defenseclaw.enforce.plugin_enforcer.PluginEnforcer.quarantine", return_value=None)
    def test_quarantine_enforcer_returns_none(self, mock_q):
        """When PluginEnforcer.quarantine returns None, exit 1."""
        self._install_plugin("fail-q")
        result = self.invoke(["quarantine", "fail-q"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("plugin path does not exist", result.output)

    def test_quarantine_with_custom_reason(self):
        """Quarantine with --reason records the reason in the audit log."""
        self._install_plugin("reason-plug")
        self.invoke(["quarantine", "reason-plug", "--reason", "CVE-2025-1234"])
        events = [e for e in self.app.store.list_events(20) if e.action == "plugin-quarantine"]
        self.assertEqual(len(events), 1)
        self.assertIn("CVE-2025-1234", events[0].details)


class TestPluginRestoreEdgeCases(PluginCommandTestBase):
    """Edge cases for restore: not quarantined, no path, enforcer failure, path=plugin root."""

    def test_restore_not_quarantined(self):
        """Restore a plugin that was never quarantined."""
        result = self.invoke(["restore", "never-quarantined"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("is not quarantined", result.output)

    def test_restore_no_stored_path_no_flag(self):
        """Quarantine via enforcer directly (bypassing CLI source_path recording), then restore without --path."""
        self._install_plugin("no-path-plug")
        # Quarantine directly via enforcer (no policy engine source_path recording)
        enforcer = PluginEnforcer(self.app.cfg.quarantine_dir)
        plugin_path = os.path.join(self.app.cfg.plugin_dir, "no-path-plug")
        enforcer.quarantine("no-path-plug", plugin_path)
        result = self.invoke(["restore", "no-path-plug"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("no stored path", result.output)

    @patch("defenseclaw.enforce.plugin_enforcer.PluginEnforcer.restore", return_value=False)
    def test_restore_enforcer_returns_false(self, mock_restore):
        """When PluginEnforcer.restore returns False, exit 1."""
        self._install_plugin("fail-restore")
        self.invoke(["quarantine", "fail-restore"])
        restore_dest = os.path.join(self.app.cfg.plugin_dir, "fail-restore")
        result = self.invoke(["restore", "fail-restore", "--path", restore_dest])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("restore failed", result.output)

    def test_restore_path_is_plugin_dir_root(self):
        """--path pointing exactly at plugin_dir itself should be accepted (edge case)."""
        self._install_plugin("root-restore")
        self.invoke(["quarantine", "root-restore"])
        plugin_dir = self.app.cfg.plugin_dir
        result = self.invoke(["restore", "root-restore", "--path", plugin_dir])
        # The path equals plugin_dir which the code allows (real_restore == real_plugin_dir)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("restored", result.output)


class TestPluginInfoHelpers(PluginCommandTestBase):
    """Test _build_plugin_scan_map and _build_plugin_actions_map exception handling."""

    def test_build_scan_map_none_store(self):
        """_build_plugin_scan_map with None store returns empty dict."""
        result = _build_plugin_scan_map(None)
        self.assertEqual(result, {})

    def test_build_actions_map_none_store(self):
        """_build_plugin_actions_map with None store returns empty dict."""
        result = _build_plugin_actions_map(None)
        self.assertEqual(result, {})

    def test_build_scan_map_exception(self):
        """_build_plugin_scan_map logs warning and returns empty on exception."""

        class BrokenStore:
            def latest_scans_by_scanner(self, scanner):
                raise RuntimeError("db error")

        result = _build_plugin_scan_map(BrokenStore())
        self.assertEqual(result, {})

    def test_build_actions_map_exception(self):
        """_build_plugin_actions_map logs warning and returns empty on exception."""

        class BrokenStore:
            def list_actions_by_type(self, t):
                raise RuntimeError("db error")

        result = _build_plugin_actions_map(BrokenStore())
        self.assertEqual(result, {})

    def test_info_with_package_json_metadata(self):
        """Plugin info reads version and description from package.json."""
        self._install_plugin("pkg-info")
        pkg_path = os.path.join(self.app.cfg.plugin_dir, "pkg-info", "package.json")
        with open(pkg_path, "w") as f:
            json.dump({"version": "1.2.3", "description": "A test plugin"}, f)
        result = self.invoke(["info", "pkg-info"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("1.2.3", result.output)
        self.assertIn("A test plugin", result.output)

    def test_info_json_with_package_json(self):
        """Plugin info --json includes version and description from package.json."""
        self._install_plugin("pkg-json")
        pkg_path = os.path.join(self.app.cfg.plugin_dir, "pkg-json", "package.json")
        with open(pkg_path, "w") as f:
            json.dump({"version": "2.0.0", "description": "JSON test"}, f)
        result = self.invoke(["info", "pkg-json", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output.strip())
        self.assertEqual(data["version"], "2.0.0")
        self.assertEqual(data["description"], "JSON test")

    def test_info_quarantined_plugin(self):
        """Plugin info shows quarantined=True for quarantined plugin."""
        self._install_plugin("q-info")
        self.invoke(["quarantine", "q-info"])
        result = self.invoke(["info", "q-info", "--json"])
        data = json.loads(result.output.strip())
        self.assertTrue(data["quarantined"])


class TestPluginRegistryInstall(PluginCommandTestBase):
    """Integration tests for registry-based plugin install (npm, clawhub, HTTP)."""

    def _invoke_install(self, args: list[str]):
        return self.runner.invoke(
            plugin, args, obj=self.app, catch_exceptions=True,
        )

    def _clean_scan_result(self, target="x"):
        from datetime import datetime, timedelta, timezone
        from defenseclaw.models import ScanResult
        return ScanResult(
            scanner="plugin-scanner", target=target,
            timestamp=datetime.now(timezone.utc),
            findings=[], duration=timedelta(seconds=0.1),
        )

    def _critical_scan_result(self, target="x"):
        from datetime import datetime, timedelta, timezone
        from defenseclaw.models import Finding, ScanResult
        return ScanResult(
            scanner="plugin-scanner", target=target,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(
                id="test-finding", severity="CRITICAL", title="Dangerous code",
                description="Found eval()", scanner="plugin-scanner",
            )],
            duration=timedelta(seconds=0.5),
        )

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_npm_package(self, mock_fetch, mock_scan):
        mock_scan.return_value = self._clean_scan_result()
        src = self._create_plugin_dir("voice-call")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "@openclasw/voice-call"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: voice-call", result.output)
        self.assertTrue(os.path.isdir(os.path.join(self.app.cfg.plugin_dir, "voice-call")))

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_npm_scoped_package(self, mock_fetch, mock_scan):
        mock_scan.return_value = self._clean_scan_result()
        src = self._create_plugin_dir("my-plugin")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "@scope/my-plugin"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: my-plugin", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_from_clawhub")
    def test_install_clawhub_uri(self, mock_fetch, mock_scan):
        mock_scan.return_value = self._clean_scan_result()
        src = self._create_plugin_dir("voice-call")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "clawhub://voice-call"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: voice-call", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_from_url")
    def test_install_http_url(self, mock_fetch, mock_scan):
        mock_scan.return_value = self._clean_scan_result()
        src = self._create_plugin_dir("http-plugin")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "https://example.com/plugin.tgz"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: http-plugin", result.output)

    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_blocked_plugin(self, mock_fetch):
        pe = PolicyEngine(self.app.store)
        pe.block("plugin", "blocked-pkg", "testing")

        result = self._invoke_install(["install", "blocked-pkg"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("block list", result.output)
        mock_fetch.assert_not_called()

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_allowed_plugin_skips_scan(self, mock_fetch, mock_scan):
        pe = PolicyEngine(self.app.store)
        pe.allow("plugin", "trusted-pkg", "testing")

        src = self._create_plugin_dir("trusted-pkg")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "trusted-pkg"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("allow list", result.output)
        self.assertIn("skipping scan", result.output)
        mock_scan.assert_not_called()

    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_duplicate_without_force(self, mock_fetch):
        self._install_plugin("dup-npm")
        src = self._create_plugin_dir("dup-npm-source")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "dup-npm"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("already installed", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_force_overwrites(self, mock_fetch, mock_scan):
        mock_scan.return_value = self._clean_scan_result()
        self._install_plugin("force-npm")
        src = self._create_plugin_dir("force-npm")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "--force", "force-npm"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: force-npm", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_action_policy_defaults_block_critical(self, mock_fetch, mock_scan):
        """Without explicit policy data, seeded admission defaults still block CRITICAL plugins."""
        mock_scan.return_value = self._critical_scan_result()
        src = self._create_plugin_dir("danger-pkg")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "--action", "danger-pkg"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("added to block list", result.output)
        self.assertIn("quarantined", result.output)
        self.assertFalse(os.path.exists(os.path.join(self.app.cfg.plugin_dir, "danger-pkg")))

    @patch("defenseclaw.gateway.OrchestratorClient.disable_plugin")
    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_action_strict_config_quarantines_critical(self, mock_fetch, mock_scan, mock_disable):
        """With strict plugin_actions config, --action on CRITICAL quarantines and blocks."""
        from defenseclaw.config import PluginActionsConfig, SeverityAction
        self.app.cfg.plugin_actions = PluginActionsConfig(
            critical=SeverityAction(file="quarantine", runtime="disable", install="block"),
            high=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )
        mock_scan.return_value = self._critical_scan_result()
        src = self._create_plugin_dir("strict-danger-pkg")
        mock_fetch.return_value = src
        mock_disable.return_value = {"status": "disabled"}

        result = self._invoke_install(["install", "--action", "strict-danger-pkg"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("quarantined", result.output)
        self.assertIn("block list", result.output)
        pe = PolicyEngine(self.app.store)
        self.assertTrue(pe.is_blocked("plugin", "strict-danger-pkg"))

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_action_clean_scan_installs(self, mock_fetch, mock_scan):
        mock_scan.return_value = self._clean_scan_result()
        src = self._create_plugin_dir("clean-pkg")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "--action", "clean-pkg"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: clean-pkg", result.output)

    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_post_scan_allow_skips_warning_and_installs(self, mock_fetch, mock_scan, mock_eval):
        from defenseclaw.enforce.admission import AdmissionDecision

        mock_scan.return_value = self._critical_scan_result()
        src = self._create_plugin_dir("late-allow-plugin")
        mock_fetch.return_value = src
        mock_eval.side_effect = [
            AdmissionDecision("scan", "scan required"),
            AdmissionDecision("allowed", "approved during scan", source="manual-allow"),
        ]

        result = self._invoke_install(["install", "late-allow-plugin"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("became allow-listed", result.output)
        self.assertNotIn("no action taken", result.output)
        self.assertIn("Installed plugin: late-allow-plugin", result.output)
        events = [e for e in self.app.store.list_events(20) if e.action == "install-allowed"]
        self.assertEqual(len(events), 1)
        self.assertIn("allow-listed-post-scan", events[0].details)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_no_action_warns_but_installs(self, mock_fetch, mock_scan):
        mock_scan.return_value = self._critical_scan_result()
        src = self._create_plugin_dir("warn-pkg")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "warn-pkg"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("findings", result.output)
        self.assertIn("no action taken", result.output)
        self.assertIn("Installed plugin: warn-pkg", result.output)

    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_network_error(self, mock_fetch):
        from defenseclaw.registry import RegistryError
        mock_fetch.side_effect = RegistryError("connection refused")

        result = self._invoke_install(["install", "net-fail-pkg"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("connection refused", result.output)

    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_npm_registry_404(self, mock_fetch):
        from defenseclaw.registry import RegistryError
        mock_fetch.side_effect = RegistryError("npm registry lookup failed: 404")

        result = self._invoke_install(["install", "nonexistent-pkg"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("npm registry lookup failed", result.output)

    def test_install_nonexistent_local_directory(self):
        result = self._invoke_install(["install", "/tmp/does-not-exist-at-all"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("directory not found", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_scan_failure_exits(self, mock_fetch, mock_scan):
        """When the scanner raises an exception, install should fail."""
        mock_scan.side_effect = RuntimeError("scanner binary crashed")
        src = self._create_plugin_dir("scan-crash-pkg")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "scan-crash-pkg"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("scan failed", result.output)
        self.assertFalse(
            os.path.exists(os.path.join(self.app.cfg.plugin_dir, "scan-crash-pkg")),
        )

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_from_url")
    def test_install_plugin_name_derived_from_extracted_path(self, mock_fetch, mock_scan):
        """When source is HTTP, plugin_name is empty and should be derived from the extracted dir name."""
        mock_scan.return_value = self._clean_scan_result()
        src = self._create_plugin_dir("derived-name")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "https://example.com/pkg.tgz"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: derived-name", result.output)

    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_tmpdir_cleaned_on_registry_error(self, mock_fetch):
        """Temp directory should be cleaned up after a RegistryError."""
        from defenseclaw.registry import RegistryError
        created_tmpdirs = []
        real_mkdtemp = tempfile.mkdtemp

        def tracking_mkdtemp(*args, **kwargs):
            d = real_mkdtemp(*args, **kwargs)
            created_tmpdirs.append(d)
            return d

        mock_fetch.side_effect = RegistryError("network down")
        with patch("tempfile.mkdtemp", side_effect=tracking_mkdtemp):
            result = self._invoke_install(["install", "fail-pkg"])

        self.assertEqual(result.exit_code, 1)
        for d in created_tmpdirs:
            self.assertFalse(os.path.exists(d), f"tmpdir not cleaned up: {d}")

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_action_with_medium_severity_no_enforcement(self, mock_fetch, mock_scan):
        """Medium severity with default config has no file/runtime/install actions."""
        from datetime import datetime, timedelta, timezone
        from defenseclaw.models import Finding, ScanResult
        mock_scan.return_value = ScanResult(
            scanner="plugin-scanner", target="x",
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(
                id="med-1", severity="MEDIUM", title="Moderate issue",
                description="Something medium", scanner="plugin-scanner",
            )],
            duration=timedelta(seconds=0.2),
        )
        src = self._create_plugin_dir("med-pkg")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "--action", "med-pkg"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: med-pkg", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_audit_log_on_success(self, mock_fetch, mock_scan):
        """Verify audit logger is called on successful install."""
        mock_scan.return_value = self._clean_scan_result()
        src = self._create_plugin_dir("audit-pkg")
        mock_fetch.return_value = src

        with patch.object(self.app.logger, "log_action") as mock_log:
            result = self._invoke_install(["install", "audit-pkg"])

        self.assertEqual(result.exit_code, 0, result.output)
        log_calls = [c[0] for c in mock_log.call_args_list]
        actions = [c[0] for c in log_calls]
        self.assertIn("install-clean", actions)
        self.assertIn("plugin-install", actions)


class TestResolvePluginDir(unittest.TestCase):
    """Unit tests for _resolve_plugin_dir — OpenClaw source-path resolution."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.plugin_dir = os.path.join(self.tmp, "plugins")
        os.makedirs(self.plugin_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_plugin_root(self, *parts, manifest="package.json"):
        """Create a fake plugin root directory with a manifest file."""
        root = os.path.join(self.tmp, *parts)
        os.makedirs(root, exist_ok=True)
        with open(os.path.join(root, manifest), "w") as f:
            f.write('{"name": "test-plugin"}')
        return root

    def _mock_info(self, source_path):
        return {"id": "test", "source": source_path}

    # ------------------------------------------------------------------
    # Literal path passthrough
    # ------------------------------------------------------------------

    def test_literal_directory_returned_as_is(self):
        root = self._make_plugin_root("myplugin")
        self.assertEqual(_resolve_plugin_dir(root, self.plugin_dir), root)

    def test_nonexistent_literal_path_falls_through(self):
        self.assertIsNone(
            _resolve_plugin_dir("/does/not/exist", self.plugin_dir)
        )

    # ------------------------------------------------------------------
    # DefenseClaw plugin_dir subdirectory
    # ------------------------------------------------------------------

    def test_subdirectory_under_plugin_dir(self):
        dest = os.path.join(self.plugin_dir, "myplugin")
        os.makedirs(dest)
        self.assertEqual(_resolve_plugin_dir("myplugin", self.plugin_dir), dest)

    # ------------------------------------------------------------------
    # OpenClaw resolution: source is a file — dirname fallback
    # ------------------------------------------------------------------

    @patch("defenseclaw.commands.cmd_plugin._get_openclaw_plugin_info")
    def test_resolves_root_when_source_is_file_in_plugin_dir(self, mock_info):
        """source points to a file directly in the plugin root — returns parent dir."""
        root = self._make_plugin_root("whatsapp")
        source = os.path.join(root, "index.ts")
        open(source, "w").close()
        mock_info.return_value = self._mock_info(source)

        result = _resolve_plugin_dir("whatsapp", self.plugin_dir)
        self.assertEqual(result, root)

    @patch("defenseclaw.commands.cmd_plugin._get_openclaw_plugin_info")
    def test_resolves_root_when_source_is_file_in_dist_subdir(self, mock_info):
        """source is dist/index.js — walks up past dist/ to find package.json."""
        root = self._make_plugin_root("defenseclaw")
        dist = os.path.join(root, "dist")
        os.makedirs(dist)
        source = os.path.join(dist, "index.js")
        open(source, "w").close()
        mock_info.return_value = self._mock_info(source)

        result = _resolve_plugin_dir("defenseclaw", self.plugin_dir)
        self.assertEqual(result, root)

    @patch("defenseclaw.commands.cmd_plugin._get_openclaw_plugin_info")
    def test_accepts_openclaw_plugin_json_as_manifest_sentinel(self, mock_info):
        """openclaw.plugin.json also counts as a valid plugin root marker."""
        root = self._make_plugin_root("myplug", manifest="openclaw.plugin.json")
        dist = os.path.join(root, "dist")
        os.makedirs(dist)
        source = os.path.join(dist, "index.js")
        open(source, "w").close()
        mock_info.return_value = self._mock_info(source)

        result = _resolve_plugin_dir("myplug", self.plugin_dir)
        self.assertEqual(result, root)

    @patch("defenseclaw.commands.cmd_plugin._get_openclaw_plugin_info")
    def test_returns_none_when_no_manifest_found_in_tree(self, mock_info):
        """No package.json or openclaw.plugin.json anywhere — returns None."""
        orphan = os.path.join(self.tmp, "orphan", "dist")
        os.makedirs(orphan)
        source = os.path.join(orphan, "index.js")
        open(source, "w").close()
        mock_info.return_value = self._mock_info(source)

        result = _resolve_plugin_dir("orphan", self.plugin_dir)
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # Case-insensitive fallback
    # ------------------------------------------------------------------

    @patch("defenseclaw.commands.cmd_plugin._get_openclaw_plugin_info")
    def test_case_insensitive_fallback_to_lowercase(self, mock_info):
        """Uppercase name fails first; lowercase succeeds on retry."""
        root = self._make_plugin_root("whatsapp")
        source = os.path.join(root, "index.ts")
        open(source, "w").close()

        def info_side_effect(name):
            return self._mock_info(source) if name == "whatsapp" else None

        mock_info.side_effect = info_side_effect

        result = _resolve_plugin_dir("Whatsapp", self.plugin_dir)
        self.assertEqual(result, root)

    @patch("defenseclaw.commands.cmd_plugin._get_openclaw_plugin_info")
    def test_no_fallback_when_lowercase_also_fails(self, mock_info):
        mock_info.return_value = None
        self.assertIsNone(_resolve_plugin_dir("Unknown", self.plugin_dir))


if __name__ == "__main__":
    unittest.main()
