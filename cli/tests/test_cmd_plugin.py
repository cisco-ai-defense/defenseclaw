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
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

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

from tests.helpers import cleanup_app, make_app_context


def _seed_scan(store, result) -> None:
    """Seed a forensic read-model fixture without a telemetry runtime."""
    store.insert_scan_result(
        str(uuid.uuid4()),
        result.scanner,
        result.target,
        result.timestamp,
        int(result.duration.total_seconds() * 1000),
        len(result.findings),
        result.max_severity(),
        result.to_json(),
    )


class PluginConnectorFlagTest(unittest.TestCase):
    """D3: --connector targeting for plugin scan (+ inconsistency fix)."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.plugin_dir = os.path.join(self.tmp_dir, "plugins")
        os.makedirs(self.app.cfg.plugin_dir, exist_ok=True)
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args: list[str]):
        return self.runner.invoke(plugin, args, obj=self.app, catch_exceptions=False)

    @patch("defenseclaw.commands.cmd_plugin._resolve_plugin_dir", return_value=None)
    def test_scan_connector_flag_resolves_target(self, mock_resolve):
        # The resolved connector (not bare guardrail.connector) must drive
        # plugin-dir resolution; an invalid plugin still exits 1.
        result = self.invoke(["scan", "ghost", "--connector", "codex"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(mock_resolve.call_args.args[2], "codex")

    def test_scan_connector_flag_rejects_unknown(self):
        result = self.invoke(["scan", "ghost", "--connector", "nope"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not configured", result.output)


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

    def _connector_plugin_path(self, name: str, connector: str = "openclaw") -> str:
        return os.path.join(self.app.cfg.plugin_dirs(connector)[0], name)

    def _install_connector_plugin(self, name: str, connector: str = "openclaw") -> str:
        src = self._create_plugin_dir(name)
        dest = self._connector_plugin_path(name, connector)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
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

        installed = self._connector_plugin_path("my-plugin")
        self.assertTrue(os.path.isdir(installed))
        self.assertTrue(os.path.isfile(os.path.join(installed, "plugin.py")))

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_install_duplicate_without_force(self, mock_scan):
        mock_scan.return_value = self._clean_result()
        src = self._create_plugin_dir("dup-plugin")
        self._invoke_install(["install", src])
        result = self._invoke_install(["install", src])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("already exists", result.output)

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


class TestPluginInstallConnectorHelp(unittest.TestCase):
    """``install --connector`` narrows placement and policy to one peer."""

    def test_plugin_help_describes_bare_connector_fan_out(self):
        runner = CliRunner()
        result = runner.invoke(plugin, ["--help"])
        self.assertEqual(result.exit_code, 0, result.output)
        normalized = " ".join(result.output.split())
        self.assertIn(
            "With no --connector, commands that operate on plugin copies run "
            "across configured connectors where the plugin or plugin directory applies",
            normalized,
        )
        self.assertNotIn("active connector", normalized)
        self.assertNotIn("global when bare", normalized)

    def test_connector_scoped_help_avoids_legacy_scope_wording(self):
        runner = CliRunner()
        help_commands = [
            "scan",
            "install",
            "list",
            "remove",
            "block",
            "unblock",
            "allow",
            "disable",
            "enable",
            "quarantine",
            "restore",
        ]
        for command in help_commands:
            with self.subTest(command=command):
                result = runner.invoke(plugin, [command, "--help"])
                self.assertEqual(result.exit_code, 0, result.output)
                normalized = " ".join(result.output.split())
                self.assertNotIn("active connector", normalized)
                self.assertNotIn("active connectors", normalized)
                self.assertNotIn("global when bare", normalized)

    def test_install_connector_help_clarifies_scope_not_location(self):
        runner = CliRunner()
        result = runner.invoke(plugin, ["install", "--help"])
        self.assertEqual(result.exit_code, 0, result.output)
        # Collapse Click's line-wrapping so multi-word phrases match
        # regardless of where the help column breaks them.
        normalized = " ".join(result.output.split())
        self.assertIn("Install into one configured connector", normalized)
        self.assertIn(
            "Default: every configured connector that exposes a plugin directory",
            normalized,
        )


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

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_list_table_title_shows_connector_in_scope(self, _mock_oc):
        # Mirror the MCP/Skills tables: the list title names the connector
        # in scope so the active-connector default is discoverable.
        dest = os.path.join(self.app.cfg.plugin_dir, "alpha")
        os.makedirs(dest)
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=openclaw", result.output)


class TestPluginListMultiConnectorDefault(PluginCommandTestBase):
    """Default ``plugin list`` (no --connector) fans out across every active
    connector — one connector-tagged table each — mirroring ``skill list``.
    A single-connector install keeps its flat JSON shape."""

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_default_lists_every_active_connector(self, _mock_oc):
        # A DC-managed plugin lives in the shared plugin_dir, so it surfaces for
        # each active connector; the per-connector tables must both appear.
        os.makedirs(os.path.join(self.app.cfg.plugin_dir, "alpha"))
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["list"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=claudecode", result.output)
        self.assertIn("connector=codex", result.output)

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_default_json_groups_by_connector(self, _mock_oc):
        os.makedirs(os.path.join(self.app.cfg.plugin_dir, "alpha"))
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["list", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertIsInstance(payload, list)
        self.assertEqual({g["connector"] for g in payload}, {"claudecode", "codex"})

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_connector_flag_still_narrows_to_one(self, _mock_oc):
        os.makedirs(os.path.join(self.app.cfg.plugin_dir, "alpha"))
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["list", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=codex", result.output)
        self.assertNotIn("connector=claudecode", result.output)

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_connector_flag_json_rows_include_connector(self, _mock_oc):
        codex_dir = os.path.join(self.tmp_dir, "codex-plugins")
        os.makedirs(os.path.join(codex_dir, "alpha"))
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.plugin_dirs = lambda connector=None: [codex_dir] if connector == "codex" else []  # type: ignore[method-assign]

        result = self.invoke(["list", "--connector", "codex", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload[0]["id"], "alpha")
        self.assertEqual(payload[0]["connector"], "codex")

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_connector_json_uses_connector_scoped_scan_target(self, _mock_oc):
        from datetime import datetime, timedelta, timezone

        from defenseclaw.models import ScanResult

        opencode_dir = os.path.join(self.tmp_dir, "opencode-plugins")
        hermes_dir = os.path.join(self.tmp_dir, "hermes-plugins")
        plugin_name = "dc-plugin-overview"
        opencode_path = os.path.join(opencode_dir, plugin_name)
        hermes_path = os.path.join(hermes_dir, plugin_name)
        os.makedirs(opencode_path)
        os.makedirs(hermes_path)
        self.app.cfg.active_connectors = lambda: ["opencode", "hermes"]  # type: ignore[method-assign]
        self.app.cfg.plugin_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "opencode": [opencode_dir],
            "hermes": [hermes_dir],
        }.get(connector or "opencode", [])
        now = datetime.now(timezone.utc)
        _seed_scan(
            self.app.store,
            ScanResult(
                scanner="plugin-scanner",
                target=opencode_path,
                timestamp=now,
                findings=[],
                duration=timedelta(seconds=0.1),
            ),
        )
        _seed_scan(
            self.app.store,
            ScanResult(
                scanner="plugin-scanner",
                target=hermes_path,
                timestamp=now + timedelta(seconds=1),
                findings=[],
                duration=timedelta(seconds=0.1),
            ),
        )

        scoped = self.invoke(["list", "--connector", "hermes", "--json"])
        self.assertEqual(scoped.exit_code, 0, scoped.output)
        scoped_row = json.loads(scoped.output)[0]
        self.assertEqual(scoped_row["connector"], "hermes")
        self.assertEqual(scoped_row["scan"]["target"], hermes_path)

        bare = self.invoke(["list", "--json"])
        self.assertEqual(bare.exit_code, 0, bare.output)
        groups = {group["connector"]: group["plugins"] for group in json.loads(bare.output)}
        hermes_row = next(item for item in groups["hermes"] if item["id"] == plugin_name)
        self.assertEqual(hermes_row["scan"]["target"], hermes_path)

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_table_title_counts_effectively_enabled_plugins(self, _mock_oc):
        codex_dir = os.path.join(self.tmp_dir, "codex-plugins")
        os.makedirs(os.path.join(codex_dir, "dc-plugin-alpha"))
        os.makedirs(os.path.join(codex_dir, "dc-plugin-scope"))
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        self.app.cfg.plugin_dirs = lambda connector=None: [codex_dir]  # type: ignore[method-assign]
        PolicyEngine(self.app.store).disable_for_connector(
            "plugin",
            "dc-plugin-scope",
            "codex",
            "test runtime disable",
        )

        result = self.invoke(["list", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Plugins (connector=codex) (1/2 enabled)", result.output)
        self.assertIn("\u2717", result.output)
        self.assertIn("disabl", result.output)

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_single_connector_install_keeps_flat_json(self, _mock_oc):
        os.makedirs(os.path.join(self.app.cfg.plugin_dir, "alpha"))
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]

        result = self.invoke(["list", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertIsInstance(payload, list)
        # Flat list of plugin dicts (no per-connector grouping wrapper).
        self.assertTrue(all("connector" not in item or "plugins" not in item for item in payload))

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_default_shows_empty_connectors_without_install_warning(self, _mock_oc):
        self.app.cfg.active_connectors = lambda: ["antigravity", "codex", "hermes", "opencode"]  # type: ignore[method-assign]
        self.app.cfg.active_connector = lambda: "antigravity"  # type: ignore[method-assign]
        codex_dir = os.path.join(self.tmp_dir, "codex-plugins")
        hermes_dir = os.path.join(self.tmp_dir, "hermes-plugins")
        mapping = {
            "antigravity": [],
            "codex": [codex_dir],
            "hermes": [hermes_dir],
            "opencode": [],
        }
        self.app.cfg.plugin_dirs = lambda connector=None: mapping.get(connector or "antigravity", [])  # type: ignore[method-assign]
        os.makedirs(os.path.join(codex_dir, "alpha"))
        os.makedirs(os.path.join(hermes_dir, "beta"))

        result = self.invoke(["list"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Plugins (connector=antigravity): no plugins found", result.output)
        self.assertIn("connector=codex", result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertIn("Plugins (connector=opencode): no plugins found", result.output)
        self.assertNotIn("Check your antigravity", result.output)
        self.assertNotIn("Check your opencode", result.output)


class TestPluginRemove(PluginCommandTestBase):
    def test_remove_installed_plugin(self):
        self._install_plugin("removable")

        result = self.invoke(["remove", "removable"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("'removable' removed", result.output)
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

    def test_remove_bare_removes_matching_plugin_from_all_active_connectors(self):
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        codex_dir = os.path.join(self.tmp_dir, "codex-plugins")
        hermes_dir = os.path.join(self.tmp_dir, "hermes-plugins")
        mapping = {"codex": [codex_dir], "hermes": [hermes_dir]}
        self.app.cfg.plugin_dirs = lambda connector=None: mapping.get(connector or "codex", [])  # type: ignore[method-assign]
        os.makedirs(os.path.join(codex_dir, "scoped"))
        os.makedirs(os.path.join(hermes_dir, "scoped"))

        result = self.invoke(["remove", "scoped"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=codex", result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertFalse(os.path.exists(os.path.join(codex_dir, "scoped")))
        self.assertFalse(os.path.exists(os.path.join(hermes_dir, "scoped")))

    def test_remove_connector_flag_only_removes_that_connector(self):
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        codex_dir = os.path.join(self.tmp_dir, "codex-plugins")
        hermes_dir = os.path.join(self.tmp_dir, "hermes-plugins")
        mapping = {"codex": [codex_dir], "hermes": [hermes_dir]}
        self.app.cfg.plugin_dirs = lambda connector=None: mapping.get(connector or "codex", [])  # type: ignore[method-assign]
        os.makedirs(os.path.join(codex_dir, "scoped"))
        os.makedirs(os.path.join(hermes_dir, "scoped"))

        result = self.invoke(["remove", "scoped", "--connector", "hermes"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertNotIn("connector=codex", result.output)
        self.assertTrue(os.path.exists(os.path.join(codex_dir, "scoped")))
        self.assertFalse(os.path.exists(os.path.join(hermes_dir, "scoped")))

    def test_remove_connector_flag_rejects_unknown_connector(self):
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]

        result = self.invoke(["remove", "scoped", "--connector", "nope"])

        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("not configured", result.output)


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

    @patch("defenseclaw.commands.cmd_plugin._plugin_runtime_candidates", return_value=[])
    def test_allow_uses_active_connector_for_runtime_candidate_lookup(self, mock_candidates):
        self.app.cfg.guardrail.connector = ""
        self.app.cfg.claw.mode = "claudecode"
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]

        result = self.invoke(["allow", "allowed-one"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(mock_candidates.call_args.args[1], "claudecode")

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


class TestPluginRuntimeToggleConnectorGuard(PluginCommandTestBase):
    """N5: hook connectors store runtime-disable policy rows. Connectors
    without a plugin runtime probe must get an explicit advisory warning."""

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_disable_on_non_openclaw_active_connector_records_advisory(self, mock_cls):
        self.app.cfg.guardrail.connector = "hermes"
        hermes_dir = os.path.join(self.tmp_dir, "hermes-plugins")
        os.makedirs(os.path.join(hermes_dir, "any-plugin"))
        self.app.cfg.plugin_dirs = lambda connector=None: [hermes_dir]  # type: ignore[method-assign]
        result = self.invoke(["disable", "any-plugin"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("runtime disable recorded (connector=hermes)", result.output)
        self.assertIn("advisory", result.output)
        self.assertIn("quarantine", result.output)
        mock_cls.return_value.disable_plugin.assert_not_called()
        self.assertTrue(
            self.app.store.has_action("plugin", "any-plugin", "runtime", "disable", "hermes")
        )
        self.assertFalse(
            self.app.store.has_action("plugin", "any-plugin", "runtime", "disable")
        )

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_disable_bare_fans_out_to_matching_connector_copies(self, mock_cls):
        self.app.cfg.active_connectors = lambda: ["antigravity", "codex", "hermes"]  # type: ignore[method-assign]
        antigravity_dir = os.path.join(self.tmp_dir, "antigravity-plugins")
        codex_dir = os.path.join(self.tmp_dir, "codex-plugins")
        hermes_dir = os.path.join(self.tmp_dir, "hermes-plugins")
        os.makedirs(antigravity_dir)
        os.makedirs(os.path.join(codex_dir, "dc-plugin-scope"))
        os.makedirs(os.path.join(hermes_dir, "dc-plugin-scope"))
        mapping = {
            "antigravity": [antigravity_dir],
            "codex": [codex_dir],
            "hermes": [hermes_dir],
        }
        self.app.cfg.plugin_dirs = lambda connector=None: mapping.get(connector or "antigravity", [])  # type: ignore[method-assign]

        result = self.invoke(["disable", "dc-plugin-scope"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("runtime disable recorded (connector=codex)", result.output)
        self.assertIn("runtime disable recorded (connector=hermes)", result.output)
        self.assertNotIn("connector=antigravity", result.output)
        self.assertNotIn("globally", result.output)
        mock_cls.return_value.disable_plugin.assert_not_called()
        self.assertTrue(
            self.app.store.has_action("plugin", "dc-plugin-scope", "runtime", "disable", "codex")
        )
        self.assertTrue(
            self.app.store.has_action("plugin", "dc-plugin-scope", "runtime", "disable", "hermes")
        )
        self.assertFalse(
            self.app.store.has_action("plugin", "dc-plugin-scope", "runtime", "disable")
        )

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_enable_on_non_openclaw_active_connector_clears_without_gateway(self, mock_cls):
        self.app.cfg.guardrail.connector = "hermes"
        hermes_dir = os.path.join(self.tmp_dir, "hermes-plugins")
        os.makedirs(os.path.join(hermes_dir, "any-plugin"))
        self.app.cfg.plugin_dirs = lambda connector=None: [hermes_dir]  # type: ignore[method-assign]
        PolicyEngine(self.app.store).disable("plugin", "any-plugin", "manual")
        result = self.invoke(["enable", "any-plugin"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("runtime disable cleared (connector=hermes)", result.output)
        mock_cls.return_value.enable_plugin.assert_not_called()
        self.assertFalse(
            self.app.store.has_action("plugin", "any-plugin", "runtime", "disable")
        )

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_enable_bare_fans_out_across_matching_connector_copies(self, mock_cls):
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        codex_dir = os.path.join(self.tmp_dir, "codex-plugins")
        hermes_dir = os.path.join(self.tmp_dir, "hermes-plugins")
        os.makedirs(os.path.join(codex_dir, "dc-plugin-scope"))
        os.makedirs(os.path.join(hermes_dir, "dc-plugin-scope"))
        mapping = {"codex": [codex_dir], "hermes": [hermes_dir]}
        self.app.cfg.plugin_dirs = lambda connector=None: mapping.get(connector or "codex", [])  # type: ignore[method-assign]
        pe = PolicyEngine(self.app.store)
        pe.disable_for_connector("plugin", "dc-plugin-scope", "codex", "manual")
        pe.disable_for_connector("plugin", "dc-plugin-scope", "hermes", "manual")

        result = self.invoke(["enable", "dc-plugin-scope"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("runtime disable cleared (connector=codex)", result.output)
        self.assertIn("runtime disable cleared (connector=hermes)", result.output)
        mock_cls.return_value.enable_plugin.assert_not_called()
        self.assertFalse(
            self.app.store.has_action("plugin", "dc-plugin-scope", "runtime", "disable", "codex")
        )
        self.assertFalse(
            self.app.store.has_action("plugin", "dc-plugin-scope", "runtime", "disable", "hermes")
        )
        codex_actions = _build_plugin_actions_map(self.app.store, "codex")
        hermes_actions = _build_plugin_actions_map(self.app.store, "hermes")
        self.assertNotIn("dc-plugin-scope", codex_actions)
        self.assertNotIn("dc-plugin-scope", hermes_actions)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_enable_bare_reports_not_found_without_matching_connector_copy(self, mock_cls):
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        codex_dir = os.path.join(self.tmp_dir, "codex-plugins")
        hermes_dir = os.path.join(self.tmp_dir, "hermes-plugins")
        os.makedirs(codex_dir)
        os.makedirs(hermes_dir)
        mapping = {"codex": [codex_dir], "hermes": [hermes_dir]}
        self.app.cfg.plugin_dirs = lambda connector=None: mapping.get(connector or "codex", [])  # type: ignore[method-assign]
        PolicyEngine(self.app.store).disable("plugin", "missing-plugin", "legacy global")

        result = self.invoke(["enable", "missing-plugin"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("plugin not found", result.output)
        self.assertTrue(
            self.app.store.has_action("plugin", "missing-plugin", "runtime", "disable")
        )
        mock_cls.return_value.enable_plugin.assert_not_called()

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_disable_connector_without_probe_records_scoped_advisory(self, mock_cls):
        self.app.cfg.active_connectors = lambda: ["openclaw", "codex", "claudecode"]  # type: ignore[method-assign]
        result = self.invoke(["disable", "any-plugin", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=codex", result.output)
        self.assertIn("advisory", result.output)
        mock_cls.return_value.disable_plugin.assert_not_called()
        self.assertTrue(
            self.app.store.has_action("plugin", "any-plugin", "runtime", "disable", "codex")
        )

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_disable_connector_with_probe_records_scoped_enforced(self, mock_cls):
        self.app.cfg.active_connectors = lambda: ["openclaw", "codex", "claudecode"]  # type: ignore[method-assign]
        result = self.invoke(["disable", "any-plugin", "--connector", "claudecode"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=claudecode", result.output)
        self.assertIn("Enforced by hook runtime gate", result.output)
        self.assertNotIn("advisory", result.output)
        mock_cls.return_value.disable_plugin.assert_not_called()
        self.assertTrue(
            self.app.store.has_action("plugin", "any-plugin", "runtime", "disable", "claudecode")
        )

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_enable_connector_clears_scoped_disable_without_gateway(self, mock_cls):
        self.app.cfg.active_connectors = lambda: ["openclaw", "codex", "claudecode"]  # type: ignore[method-assign]
        PolicyEngine(self.app.store).disable_for_connector(
            "plugin", "any-plugin", "codex", "manual",
        )
        result = self.invoke(["enable", "any-plugin", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("runtime disable cleared", result.output)
        mock_cls.return_value.enable_plugin.assert_not_called()
        self.assertFalse(
            self.app.store.has_action("plugin", "any-plugin", "runtime", "disable", "codex")
        )

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_enable_connector_overrides_global_disable_for_that_connector(self, mock_cls):
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        codex_dir = os.path.join(self.tmp_dir, "codex-plugins")
        hermes_dir = os.path.join(self.tmp_dir, "hermes-plugins")
        os.makedirs(os.path.join(codex_dir, "dc-plugin-scope"))
        os.makedirs(os.path.join(hermes_dir, "dc-plugin-scope"))
        mapping = {"codex": [codex_dir], "hermes": [hermes_dir]}
        self.app.cfg.plugin_dirs = lambda connector=None: mapping.get(connector or "codex", [])  # type: ignore[method-assign]
        PolicyEngine(self.app.store).disable("plugin", "dc-plugin-scope", "manual global")

        result = self.invoke(["enable", "dc-plugin-scope", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("runtime disable cleared", result.output)
        mock_cls.return_value.enable_plugin.assert_not_called()
        codex_actions = _build_plugin_actions_map(self.app.store, "codex")
        hermes_actions = _build_plugin_actions_map(self.app.store, "hermes")
        self.assertEqual(codex_actions["dc-plugin-scope"].actions.runtime, "enable")
        self.assertEqual(hermes_actions["dc-plugin-scope"].actions.runtime, "disable")

        codex_info = self.invoke(["info", "dc-plugin-scope", "--connector", "codex"])
        self.assertEqual(codex_info.exit_code, 0, codex_info.output)
        self.assertNotIn("Actions:     disabled", codex_info.output)

        hermes_info = self.invoke(["info", "dc-plugin-scope", "--connector", "hermes"])
        self.assertEqual(hermes_info.exit_code, 0, hermes_info.output)
        self.assertIn("Actions:     disabled", hermes_info.output)

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_disable_still_works_on_openclaw_default(self, mock_cls, _mock_list):
        # Regression guard: the default OpenClaw active connector path is
        # unchanged by the N5 guard (claw.mode=openclaw in the test config).
        mock_cls.return_value.disable_plugin.return_value = {"status": "disabled"}
        result = self.invoke(["disable", "oc-plugin"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("disabled via gateway RPC", result.output)
        self.assertTrue(
            self.app.store.has_action("plugin", "oc-plugin", "runtime", "disable")
        )


class TestPluginQuarantineRestore(PluginCommandTestBase):
    def test_quarantine_moves_plugin_and_records_policy(self):
        self._install_plugin("qplug")
        result = self.invoke(["quarantine", "qplug"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("quarantined", result.output)
        self.assertFalse(os.path.isdir(os.path.join(self.app.cfg.plugin_dir, "qplug")))
        qpath = os.path.join(self.app.cfg.quarantine_dir, "plugins", "openclaw", "qplug")
        self.assertTrue(os.path.isdir(qpath))
        self.assertTrue(
            PolicyEngine(self.app.store).is_quarantined_for_connector(
                "plugin", "qplug", "openclaw",
            )
        )
        events = [e for e in self.app.store.list_events(20) if e.action == "plugin-quarantine"]
        self.assertEqual(len(events), 1)

    def test_quarantine_rejects_absolute_path_outside_plugin_dir(self):
        outside = os.path.join(self.tmp_dir, "not-in-plugin-dir")
        os.makedirs(outside)
        abs_out = os.path.realpath(outside)
        result = self.invoke(["quarantine", abs_out])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("not inside a configured plugin directory", result.output)

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
        self.assertIn("restore path must be within configured plugin directories", result.output)
        self.assertTrue(
            os.path.isdir(
                os.path.join(self.app.cfg.quarantine_dir, "plugins", "openclaw", "rplug")
            )
        )


class TestPluginInfo(PluginCommandTestBase):
    def test_info_installed_plugin(self):
        self._install_plugin("infoplug")
        result = self.invoke(["info", "infoplug"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("infoplug", result.output)
        self.assertIn("Installed:   True", result.output)
        self.assertIn("Quarantined: False", result.output)

    def test_info_not_installed(self):
        # P-D: a plugin that exists nowhere (not installed, no scan/enforcement
        # record, not quarantined) errors with a not-found message instead of
        # rendering a phantom "Installed: False" card. Mirrors skill SK-2.
        result = self.invoke(["info", "ghost-plugin"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("not found", result.output)

    def test_info_json_installed(self):
        self._install_plugin("jsonplug")
        result = self.invoke(["info", "jsonplug", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output.strip())
        self.assertTrue(data["installed"])
        self.assertEqual(data["name"], "jsonplug")
        self.assertIn("path", data)

    def test_info_json_not_installed(self):
        # P-D: even with --json, a true miss errors rather than emitting a
        # phantom not-installed card.
        result = self.invoke(["info", "missing-plug", "--json"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("not found", result.output)


class TestPluginMultiConnectorSemantics(PluginCommandTestBase):
    def setUp(self):
        super().setUp()
        self.codex_root = os.path.join(self.tmp_dir, "codex", "plugins")
        self.hermes_root = os.path.join(self.tmp_dir, "hermes", "plugins")
        os.makedirs(self.codex_root)
        os.makedirs(self.hermes_root)
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        mapping = {"codex": [self.codex_root], "hermes": [self.hermes_root]}
        self.app.cfg.plugin_dirs = lambda connector=None: mapping.get(connector or "codex", [])  # type: ignore[method-assign]

    def _seed_connector_plugin(self, connector: str, name: str) -> str:
        root = self.codex_root if connector == "codex" else self.hermes_root
        path = os.path.join(root, name)
        os.makedirs(path)
        with open(os.path.join(path, "plugin.py"), "w") as fh:
            fh.write("# plugin code\n")
        return path

    @staticmethod
    def _clean_scan_result(target: str):
        from datetime import datetime, timedelta, timezone

        from defenseclaw.models import ScanResult
        return ScanResult(
            scanner="plugin-scanner", target=target,
            timestamp=datetime.now(timezone.utc),
            findings=[], duration=timedelta(seconds=0.1),
        )

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_bare_scan_duplicate_scans_every_connector_copy(self, mock_scan):
        codex_path = self._seed_connector_plugin("codex", "shared")
        hermes_path = self._seed_connector_plugin("hermes", "shared")
        mock_scan.side_effect = lambda path, **_kwargs: self._clean_scan_result(path)

        result = self.invoke(["scan", "shared"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector: codex", result.output)
        self.assertIn("connector: hermes", result.output)
        self.assertEqual(mock_scan.call_count, 2)
        scanned = {call.args[0] for call in mock_scan.call_args_list}
        self.assertEqual(scanned, {codex_path, hermes_path})

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_scoped_scan_json_includes_connector_metadata(self, mock_scan):
        codex_path = self._seed_connector_plugin("codex", "shared")
        self._seed_connector_plugin("hermes", "shared")
        mock_scan.side_effect = lambda path, **_kwargs: self._clean_scan_result(path)

        result = self.invoke(["scan", "shared", "--connector", "codex", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["connector"], "codex")
        self.assertEqual(payload["target"], codex_path)
        self.assertEqual(payload["target_metadata"]["connector"], "codex")
        self.assertEqual(payload["target_metadata"]["path"], codex_path)

    def test_info_shows_real_cards_scoped_actions_and_scans(self):
        codex_path = self._seed_connector_plugin("codex", "shared")
        hermes_path = self._seed_connector_plugin("hermes", "shared")
        _seed_scan(self.app.store, self._clean_scan_result(codex_path))
        _seed_scan(self.app.store, self._clean_scan_result(hermes_path))
        PolicyEngine(self.app.store).block_for_connector(
            "plugin", "shared", "hermes", "manual",
        )

        result = self.invoke(["info", "shared"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Connector:   codex", result.output)
        self.assertIn("Connector:   hermes", result.output)
        self.assertIn(codex_path, result.output)
        self.assertIn(hermes_path, result.output)
        self.assertIn("Actions:     -", result.output)
        self.assertIn("Actions:     blocked", result.output)

    def test_scoped_info_labels_connector_for_installed_plugin(self):
        codex_path = self._seed_connector_plugin("codex", "shared")
        self._seed_connector_plugin("hermes", "shared")

        result = self.invoke(["info", "shared", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Connector:   codex", result.output)
        self.assertIn(codex_path, result.output)
        self.assertNotIn("Connector:   hermes", result.output)

    def test_scoped_info_labels_connector_for_not_installed_action_card(self):
        self._seed_connector_plugin("codex", "removed")
        PolicyEngine(self.app.store).disable_for_connector(
            "plugin", "removed", "codex", "manual",
        )
        remove_result = self.invoke(["remove", "removed", "--connector", "codex"])
        self.assertEqual(remove_result.exit_code, 0, remove_result.output)

        result = self.invoke(["info", "removed", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Connector:   codex", result.output)
        self.assertIn("Installed:   False", result.output)
        self.assertIn("Actions:     disabled", result.output)

    def test_info_global_action_does_not_create_phantom_card(self):
        PolicyEngine(self.app.store).block("plugin", "ghost", "manual")

        result = self.invoke(["info", "ghost"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("not found", result.output)

    def test_bare_allow_and_unblock_clear_scoped_final_state(self):
        self._seed_connector_plugin("codex", "dc-plugin-final-state")
        self._seed_connector_plugin("hermes", "dc-plugin-final-state")

        scoped_disable = self.invoke(
            ["disable", "dc-plugin-final-state", "--connector", "codex"]
        )
        self.assertEqual(scoped_disable.exit_code, 0, scoped_disable.output)
        self.assertIn("connector=codex", scoped_disable.output)

        hermes_after_disable = self.invoke(
            ["info", "dc-plugin-final-state", "--connector", "hermes"]
        )
        self.assertEqual(hermes_after_disable.exit_code, 0, hermes_after_disable.output)
        self.assertIn("Actions:     -", hermes_after_disable.output)

        bare_enable = self.invoke(["enable", "dc-plugin-final-state"])
        self.assertEqual(bare_enable.exit_code, 0, bare_enable.output)
        self.assertIn("runtime disable cleared (connector=codex)", bare_enable.output)
        self.assertIn("runtime disable cleared (connector=hermes)", bare_enable.output)

        scoped_block = self.invoke(
            ["block", "dc-plugin-final-state", "--connector", "codex"]
        )
        self.assertEqual(scoped_block.exit_code, 0, scoped_block.output)
        self.assertIn("connector=codex", scoped_block.output)

        bare_allow = self.invoke(["allow", "dc-plugin-final-state"])
        self.assertEqual(bare_allow.exit_code, 0, bare_allow.output)
        self.assertIn("added to allow list (connector=codex)", bare_allow.output)
        self.assertIn("added to allow list (connector=hermes)", bare_allow.output)

        bare_unblock = self.invoke(["unblock", "dc-plugin-final-state"])
        self.assertEqual(bare_unblock.exit_code, 0, bare_unblock.output)
        self.assertIn("all enforcement state cleared (connector=codex)", bare_unblock.output)
        self.assertIn("all enforcement state cleared (connector=hermes)", bare_unblock.output)

        codex_info = self.invoke(
            ["info", "dc-plugin-final-state", "--connector", "codex"]
        )
        self.assertEqual(codex_info.exit_code, 0, codex_info.output)
        self.assertIn("Connector:   codex", codex_info.output)
        self.assertIn("Actions:     -", codex_info.output)

        hermes_info = self.invoke(
            ["info", "dc-plugin-final-state", "--connector", "hermes"]
        )
        self.assertEqual(hermes_info.exit_code, 0, hermes_info.output)
        self.assertIn("Connector:   hermes", hermes_info.output)
        self.assertIn("Actions:     -", hermes_info.output)

    def test_bare_unblock_clears_all_scoped_enforcement_fields(self):
        self._seed_connector_plugin("codex", "shared")
        self._seed_connector_plugin("hermes", "shared")
        pe = PolicyEngine(self.app.store)
        pe.block_for_connector("plugin", "shared", "codex", "manual block")
        pe.disable_for_connector("plugin", "shared", "codex", "manual disable")
        pe.allow_for_connector("plugin", "shared", "hermes", "manual allow")
        pe.quarantine_for_connector("plugin", "shared", "hermes", "manual quarantine")

        result = self.invoke(["unblock", "shared"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("all enforcement state cleared (connector=codex)", result.output)
        self.assertIn("all enforcement state cleared (connector=hermes)", result.output)
        self.assertIsNone(self.app.store.get_action("plugin", "shared", "codex"))
        self.assertIsNone(self.app.store.get_action("plugin", "shared", "hermes"))

    def test_bare_quarantine_and_restore_apply_to_every_connector_copy(self):
        codex_path = self._seed_connector_plugin("codex", "shared")
        hermes_path = self._seed_connector_plugin("hermes", "shared")

        result = self.invoke(["quarantine", "shared"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(os.path.isdir(codex_path))
        self.assertFalse(os.path.isdir(hermes_path))
        self.assertTrue(os.path.isdir(os.path.join(self.app.cfg.quarantine_dir, "plugins", "codex", "shared")))
        self.assertTrue(os.path.isdir(os.path.join(self.app.cfg.quarantine_dir, "plugins", "hermes", "shared")))
        self.assertTrue(
            self.app.store.has_action("plugin", "shared", "file", "quarantine", "codex")
        )
        self.assertTrue(
            self.app.store.has_action("plugin", "shared", "file", "quarantine", "hermes")
        )

        codex_list = self.invoke(["list", "--connector", "codex"])
        self.assertEqual(codex_list.exit_code, 0, codex_list.output)
        self.assertIn("shared", codex_list.output)
        self.assertIn("quarant", codex_list.output)

        hermes_list = self.invoke(["list", "--connector", "hermes"])
        self.assertEqual(hermes_list.exit_code, 0, hermes_list.output)
        self.assertIn("shared", hermes_list.output)
        self.assertIn("quarant", hermes_list.output)

        codex_json = self.invoke(["list", "--connector", "codex", "--json"])
        self.assertEqual(codex_json.exit_code, 0, codex_json.output)
        row = next(item for item in json.loads(codex_json.output) if item["id"] == "shared")
        self.assertEqual(row["status"], "quarantined")
        self.assertEqual(row["connector"], "codex")
        self.assertEqual(row["actions"], {"file": "quarantine"})
        self.assertFalse(row["enabled"])

        rerun = self.invoke(["quarantine", "shared", "--connector", "codex"])
        self.assertEqual(rerun.exit_code, 0, rerun.output)
        self.assertIn("already quarantined", rerun.output)
        self.assertIn("connector=codex", rerun.output)
        self.assertNotIn("could not locate", rerun.output)

        result = self.invoke(["restore", "shared"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isdir(codex_path))
        self.assertTrue(os.path.isdir(hermes_path))
        self.assertFalse(
            self.app.store.has_action("plugin", "shared", "file", "quarantine", "codex")
        )
        self.assertFalse(
            self.app.store.has_action("plugin", "shared", "file", "quarantine", "hermes")
        )

    def test_restore_path_with_multiple_quarantines_is_ambiguous(self):
        self._seed_connector_plugin("codex", "shared")
        self._seed_connector_plugin("hermes", "shared")
        self.invoke(["quarantine", "shared"])

        result = self.invoke([
            "restore", "shared", "--path", os.path.join(self.codex_root, "manual"),
        ])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("ambiguous", result.output)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_bare_install_materializes_every_connector_dir(self, mock_scan):
        mock_scan.side_effect = lambda path, **_kwargs: self._clean_scan_result(path)
        src = self._create_plugin_dir("fresh")

        result = self.invoke(["install", src])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isdir(os.path.join(self.codex_root, "fresh")))
        self.assertTrue(os.path.isdir(os.path.join(self.hermes_root, "fresh")))
        self.assertEqual(mock_scan.call_count, 2)

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    def test_install_connector_narrows_materialization(self, mock_scan):
        mock_scan.side_effect = lambda path, **_kwargs: self._clean_scan_result(path)
        src = self._create_plugin_dir("narrow")

        result = self.invoke(["install", src, "--connector", "hermes"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(os.path.isdir(os.path.join(self.codex_root, "narrow")))
        self.assertTrue(os.path.isdir(os.path.join(self.hermes_root, "narrow")))
        self.assertEqual(mock_scan.call_count, 1)

    def test_install_antigravity_remains_unsupported_despite_discovery_dirs(self):
        antigravity_root = os.path.join(self.tmp_dir, "antigravity", "plugins")
        os.makedirs(antigravity_root)
        self.app.cfg.active_connector = lambda: "antigravity"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["antigravity"]  # type: ignore[method-assign]
        self.app.cfg.plugin_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "antigravity": [antigravity_root],
        }.get(connector or "antigravity", [])
        src = self._create_plugin_dir("agy-plugin")

        result = self.invoke(["install", src, "--connector", "antigravity"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("does not expose a plugin install directory", result.output)
        self.assertFalse(os.path.exists(os.path.join(antigravity_root, "agy-plugin")))

    def test_policy_verbs_reject_unknown_connector_without_writing_rows(self):
        commands = [
            ["block", "sample", "--connector", "nope"],
            ["allow", "sample", "--connector", "nope"],
            ["unblock", "sample", "--connector", "nope"],
            ["disable", "sample", "--connector", "nope"],
            ["enable", "sample", "--connector", "nope"],
        ]

        for args in commands:
            with self.subTest(args=args):
                result = self.invoke(args)
                self.assertEqual(result.exit_code, 2, result.output)
                self.assertIn("not configured", result.output)

        self.assertIsNone(self.app.store.get_action("plugin", "sample", "nope"))


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
        self.assertTrue(os.path.isdir(self._connector_plugin_path("voice-call")))

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
        self._install_connector_plugin("dup-npm")
        src = self._create_plugin_dir("dup-npm-source")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "dup-npm"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("already exists", result.output)

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
        self.assertTrue(
            pe.is_blocked_for_connector("plugin", "strict-danger-pkg", "openclaw")
        )

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
    def test_install_no_action_refuses_critical_findings(self, mock_fetch, mock_scan):
        """the legacy code printed "no action taken" and
        STILL fell through to copytree() when a CRITICAL was found
        without --action. We now refuse the install (fail closed) until
        the operator either passes --action or explicitly allow-lists."""
        mock_scan.return_value = self._critical_scan_result()
        src = self._create_plugin_dir("warn-pkg")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "warn-pkg"])
        self.assertNotEqual(result.exit_code, 0, result.output)
        self.assertIn("refusing to install", result.output)
        # The plugin must NOT have landed on disk.
        self.assertFalse(
            os.path.exists(os.path.join(self.app.cfg.plugin_dir, "warn-pkg")),
            "regression: critical plugin was installed without --action",
        )

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_npm_package")
    def test_install_no_action_allows_low_severity_findings(self, mock_fetch, mock_scan):
        """must not over-block: LOW/INFO scan findings without
        --action still install with a warning so existing operator
        workflows don't break."""
        from datetime import datetime, timedelta, timezone

        from defenseclaw.models import Finding, ScanResult
        mock_scan.return_value = ScanResult(
            scanner="plugin-scanner", target="x",
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(
                id="info-finding", severity="LOW", title="minor",
                description="lint", scanner="plugin-scanner",
            )],
            duration=timedelta(seconds=0.1),
        )
        src = self._create_plugin_dir("low-warn-pkg")
        mock_fetch.return_value = src

        result = self._invoke_install(["install", "low-warn-pkg"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: low-warn-pkg", result.output)

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

    @patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
    @patch("defenseclaw.registry.fetch_from_url")
    def test_install_url_blocked_after_name_derived(self, mock_fetch, mock_scan):
        """F-0481/F-1461: a URL install whose DERIVED name is on the block list
        must be blocked.

        For HTTP/URL sources the plugin name is empty before the fetch, so the
        pre-install admission gate is skipped. The real name is only known after
        fetch_from_url() derives it from the extracted source. The post-fetch
        admission re-evaluation must catch a blocked verdict on that derived name
        and abort BEFORE shutil.copytree — even though the scanner returns clean.
        """
        # Scanner returns clean so the only thing that can stop the install is
        # the admission gate (proving the gate, not the scan, does the blocking).
        mock_scan.return_value = self._clean_scan_result()
        src = self._create_plugin_dir("evil-url-plugin")
        mock_fetch.return_value = src

        # Block the DERIVED name (basename of the fetched source dir).
        pe = PolicyEngine(self.app.store)
        pe.block("plugin", "evil-url-plugin", "testing url admission bypass")

        result = self._invoke_install(["install", "https://evil.example.com/pkg.tgz"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("block list", result.output)
        # The blocked plugin must NOT have been copied into plugin_dir.
        self.assertFalse(
            os.path.isdir(os.path.join(self.app.cfg.plugin_dir, "evil-url-plugin")),
            "blocked URL plugin was installed — admission bypass not fixed",
        )

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

    @patch("defenseclaw.commands.cmd_plugin._get_openclaw_plugin_info")
    def test_bare_name_ignores_cwd_relative_directory(self, mock_info):
        """Regression: a bare plugin name MUST NOT be resolved as a
        cwd-relative path even when a directory of the same name
        happens to exist in the current working directory.

        The pre-fix behavior was: ``os.path.isdir("defenseclaw")``
        returns True from any cwd that contains a ``defenseclaw/``
        folder (e.g. running pytest from the workspace's ``cli/``
        which has ``cli/defenseclaw/``). The literal-path branch
        leaked that relative path back, skipping plugin lookup
        entirely. Operationally that meant ``defenseclaw plugin
        install foo`` from a workspace with a ``./foo`` folder would
        silently install whatever was in that folder rather than the
        published plugin — a real-world correctness/security bug,
        not just a test artifact.
        """
        cwd = os.getcwd()
        cwd_collision = os.path.join(cwd, "defenseclaw-bare-name-collision")
        os.makedirs(cwd_collision, exist_ok=True)
        try:
            # The mocked plugin info points at a real, distinct
            # plugin root in /tmp. The bare-name lookup must use that
            # path, not the same-named folder we just planted in cwd.
            real_root = self._make_plugin_root("defenseclaw-bare-name-collision")
            source = os.path.join(real_root, "index.ts")
            open(source, "w").close()
            mock_info.return_value = self._mock_info(source)

            result = _resolve_plugin_dir(
                "defenseclaw-bare-name-collision", self.plugin_dir
            )
            self.assertEqual(
                result, real_root,
                "Bare names must resolve via plugin lookup, not cwd",
            )
            self.assertNotEqual(
                result, "defenseclaw-bare-name-collision",
                "MUST NOT echo back the bare name as a relative path",
            )
        finally:
            shutil.rmtree(cwd_collision, ignore_errors=True)

    def test_explicit_relative_path_still_honored(self):
        """A relative path the operator typed deliberately
        (``./my-plugin``) MUST still be honored — the cwd-coincidence
        guard only fires for *bare* names without a separator. We
        change cwd into the tmp tree so the relative path resolves
        unambiguously."""
        plugin_root = self._make_plugin_root("explicit-rel-plugin")
        prev = os.getcwd()
        try:
            os.chdir(self.tmp)
            result = _resolve_plugin_dir(
                "./explicit-rel-plugin", self.plugin_dir
            )
            self.assertEqual(
                os.path.realpath(result),
                os.path.realpath(plugin_root),
            )
        finally:
            os.chdir(prev)

    # ------------------------------------------------------------------
    # Case-insensitive fallback
    # ------------------------------------------------------------------

    @patch("defenseclaw.commands.cmd_plugin._get_openclaw_plugin_info")
    def test_case_insensitive_fallback_to_lowercase(self, mock_info):
        """Uppercase name fails first; lowercase succeeds on retry."""
        root = self._make_plugin_root("whatsapp")
        source = os.path.join(root, "index.ts")
        open(source, "w").close()

        def info_side_effect(name, connector=""):
            return self._mock_info(source) if name == "whatsapp" else None

        mock_info.side_effect = info_side_effect

        result = _resolve_plugin_dir("Whatsapp", self.plugin_dir)
        self.assertEqual(result, root)

    @patch("defenseclaw.commands.cmd_plugin._get_openclaw_plugin_info")
    def test_no_fallback_when_lowercase_also_fails(self, mock_info):
        mock_info.return_value = None
        self.assertIsNone(_resolve_plugin_dir("Unknown", self.plugin_dir))


# ---------------------------------------------------------------------------
# Plan C6 / matrix #3 — host-agent plugin enumeration tests.
#
# These exercise the new _list_host_plugins + _scan_plugin_dir helpers
# in cmd_plugin.py. The contract is:
#
#   1. For non-OpenClaw connectors, plugins on the host's plugin_dirs()
#      get surfaced through `defenseclaw plugin list` with provenance
#      "host:<connector>".
#   2. A plugin id collision between DefenseClaw-managed and host
#      directories preserves the DefenseClaw entry (we never mask our
#      own copy).
#   3. Malformed manifests do not crash list — the broken plugin is
#      simply skipped, the rest still surface.
#   4. OpenClaw connector skips host enumeration (the openclaw binary
#      already enumerates via _list_openclaw_plugins).
# ---------------------------------------------------------------------------


class HostPluginEnumerationTests(unittest.TestCase):
    """Plan C6 host-plugin enumeration."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dc-host-plugins-")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _seed(self, plugin_name: str, manifest: dict | None) -> str:
        """Create a host plugin dir with optional manifest."""
        d = os.path.join(self.tmp_dir, plugin_name)
        os.makedirs(d, exist_ok=True)
        if manifest is not None:
            with open(os.path.join(d, "plugin.json"), "w") as fh:
                json.dump(manifest, fh)
        return d

    def test_scan_plugin_dir_picks_up_manifest(self):
        from defenseclaw.commands.cmd_plugin import _scan_plugin_dir

        self._seed("hello-host", {
            "id": "hello-host",
            "name": "Hello Host",
            "version": "1.2.3",
            "description": "from claudecode",
        })

        out = _scan_plugin_dir(self.tmp_dir, "claudecode")
        self.assertEqual(len(out), 1, out)
        entry = out[0]
        self.assertEqual(entry["id"], "hello-host")
        self.assertEqual(entry["name"], "Hello Host")
        self.assertEqual(entry["version"], "1.2.3")
        self.assertEqual(entry["source"], "host:claudecode")

    def test_scan_plugin_dir_falls_back_to_directory_name(self):
        """No manifest at all — id defaults to the directory name."""
        from defenseclaw.commands.cmd_plugin import _scan_plugin_dir

        self._seed("bare-plugin", manifest=None)

        out = _scan_plugin_dir(self.tmp_dir, "codex")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "bare-plugin")
        self.assertEqual(out[0]["source"], "host:codex")

    def test_scan_plugin_dir_skips_malformed_manifest(self):
        """A broken manifest must not crash the whole list."""
        from defenseclaw.commands.cmd_plugin import _scan_plugin_dir

        broken = self._seed("broken-plugin", manifest=None)
        with open(os.path.join(broken, "plugin.json"), "w") as fh:
            fh.write("{not valid json")

        self._seed("good-plugin", {"id": "good-plugin", "name": "Good"})

        out = _scan_plugin_dir(self.tmp_dir, "zeptoclaw")
        ids = sorted(p["id"] for p in out)
        # Both directories surface — broken-plugin via name fallback,
        # good-plugin via manifest.
        self.assertIn("broken-plugin", ids)
        self.assertIn("good-plugin", ids)

    def test_scan_plugin_dir_returns_empty_for_missing_dir(self):
        from defenseclaw.commands.cmd_plugin import _scan_plugin_dir

        out = _scan_plugin_dir("/nonexistent/path/that/should/not/exist", "claudecode")
        self.assertEqual(out, [])

    def test_scan_plugin_dir_skips_cache_and_dotdirs(self):
        """N6: a ``cache`` working dir and dot-prefixed dirs are not plugins
        and must not surface as phantom rows; real plugins still list."""
        from defenseclaw.commands.cmd_plugin import _scan_plugin_dir

        # codex/zeptoclaw seed a sibling ``cache`` dir next to real plugins;
        # version control / OS cruft seeds dot-prefixed dirs.
        os.makedirs(os.path.join(self.tmp_dir, "cache"))
        os.makedirs(os.path.join(self.tmp_dir, ".git"))
        self._seed("real-plugin", {"id": "real-plugin", "name": "Real"})

        out = _scan_plugin_dir(self.tmp_dir, "codex")
        ids = sorted(p["id"] for p in out)
        self.assertEqual(ids, ["real-plugin"])
        self.assertNotIn("cache", ids)
        self.assertNotIn(".git", ids)

    def test_list_host_plugins_skips_openclaw(self):
        """OpenClaw enumeration goes through the openclaw binary, not us."""
        from defenseclaw.commands.cmd_plugin import _list_host_plugins

        class FakeCfg:
            def plugin_dirs(self, connector=None):
                return [self.tmp_dir]  # would normally contain plugins

        out = _list_host_plugins("openclaw", FakeCfg())
        self.assertEqual(out, [])

        out = _list_host_plugins("", FakeCfg())
        self.assertEqual(out, [])

    def test_list_host_plugins_dedups_across_dirs(self):
        """Two plugin dirs with the same id surface only once."""
        from defenseclaw.commands.cmd_plugin import _list_host_plugins

        a = os.path.join(self.tmp_dir, "user-scope")
        b = os.path.join(self.tmp_dir, "workspace-scope")
        os.makedirs(a)
        os.makedirs(b)
        for d in (a, b):
            sub = os.path.join(d, "shared-plugin")
            os.makedirs(sub)
            with open(os.path.join(sub, "plugin.json"), "w") as fh:
                json.dump({"id": "shared-plugin", "name": "Shared"}, fh)

        outer_self = self

        class FakeCfg:
            def plugin_dirs(self, connector=None):
                return [a, b]  # noqa: F823 — closure over outer scope

        out = _list_host_plugins("claudecode", FakeCfg())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "shared-plugin")


class MergeAllPluginsHostBranchTests(unittest.TestCase):
    """Plan C6 — _merge_all_plugins integrates host-side plugins."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dc-merge-host-")
        self.host_dir = os.path.join(self.tmp_dir, "host-plugins")
        self.dc_plugin_dir = os.path.join(self.tmp_dir, "dc-plugins")
        os.makedirs(self.host_dir)
        os.makedirs(self.dc_plugin_dir)
        # DefenseClaw-managed plugin: just a directory under plugin_dir
        os.makedirs(os.path.join(self.dc_plugin_dir, "my-managed-plugin"))
        # Host plugin with a different id
        sub = os.path.join(self.host_dir, "host-only-plugin")
        os.makedirs(sub)
        with open(os.path.join(sub, "plugin.json"), "w") as fh:
            json.dump(
                {"id": "host-only-plugin", "name": "Host Only", "version": "0.1"},
                fh,
            )
        # Host plugin that COLLIDES with the managed id
        clash = os.path.join(self.host_dir, "my-managed-plugin")
        os.makedirs(clash)
        with open(os.path.join(clash, "plugin.json"), "w") as fh:
            json.dump({"id": "my-managed-plugin", "name": "Host Clash"}, fh)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _make_cfg(self):
        outer = self

        class FakeCfg:
            def plugin_dirs(self, connector=None):
                return [outer.host_dir]

        return FakeCfg()

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_merge_includes_host_plugins_for_claudecode(self, _mock):
        from defenseclaw.commands.cmd_plugin import _merge_all_plugins

        merged = _merge_all_plugins(
            self.dc_plugin_dir, "claudecode", cfg=self._make_cfg(),
        )
        ids = {p["id"]: p for p in merged}
        # DefenseClaw-managed entry is present.
        self.assertIn("my-managed-plugin", ids)
        self.assertEqual(ids["my-managed-plugin"]["source"], "defenseclaw")
        # Host-only plugin surfaces with provenance label.
        self.assertIn("host-only-plugin", ids)
        self.assertEqual(ids["host-only-plugin"]["source"], "host:claudecode")
        # The collision did NOT replace the managed entry.
        self.assertNotEqual(ids["my-managed-plugin"]["source"], "host:claudecode")

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_merge_skips_host_plugins_when_cfg_is_none(self, _mock):
        """Back-compat: callers without cfg get only DC-managed + openclaw."""
        from defenseclaw.commands.cmd_plugin import _merge_all_plugins

        merged = _merge_all_plugins(self.dc_plugin_dir, "claudecode")
        ids = {p["id"] for p in merged}
        self.assertIn("my-managed-plugin", ids)
        self.assertNotIn("host-only-plugin", ids)


if __name__ == "__main__":
    unittest.main()
