"""Tests for 'defenseclaw plugin' command group — install, list, remove."""

import os
import shutil
import tempfile
import unittest

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_plugin import plugin
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


class TestPluginInstall(PluginCommandTestBase):
    def test_install_from_directory(self):
        src = self._create_plugin_dir("my-plugin")
        result = self.invoke(["install", src])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Installed plugin: my-plugin", result.output)

        installed = os.path.join(self.app.cfg.plugin_dir, "my-plugin")
        self.assertTrue(os.path.isdir(installed))
        self.assertTrue(os.path.isfile(os.path.join(installed, "plugin.py")))

    def test_install_duplicate(self):
        src = self._create_plugin_dir("dup-plugin")
        self.invoke(["install", src])
        result = self.invoke(["install", src])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("already installed", result.output)

    def test_install_from_registry_not_supported(self):
        result = self.invoke(["install", "some-registry-name"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("not yet implemented", result.output)

    def test_install_logs_action(self):
        src = self._create_plugin_dir("logged-plugin")
        self.invoke(["install", src])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "plugin-install"]
        self.assertEqual(len(actions), 1)


class TestPluginList(PluginCommandTestBase):
    def test_list_empty(self):
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No plugins installed", result.output)

    def test_list_with_plugins(self):
        for name in ["alpha", "beta"]:
            dest = os.path.join(self.app.cfg.plugin_dir, name)
            os.makedirs(dest)

        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("alpha", result.output)
        self.assertIn("beta", result.output)


class TestPluginRemove(PluginCommandTestBase):
    def test_remove_installed_plugin(self):
        src = self._create_plugin_dir("removable")
        self.invoke(["install", src])

        result = self.invoke(["remove", "removable"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Removed plugin: removable", result.output)
        self.assertFalse(os.path.exists(os.path.join(self.app.cfg.plugin_dir, "removable")))

    def test_remove_nonexistent(self):
        result = self.invoke(["remove", "ghost-plugin"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("not found", result.output)

    def test_remove_logs_action(self):
        src = self._create_plugin_dir("to-remove")
        self.invoke(["install", src])
        self.invoke(["remove", "to-remove"])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "plugin-remove"]
        self.assertEqual(len(actions), 1)


class TestPluginLifecycle(PluginCommandTestBase):
    def test_install_list_remove_list(self):
        src = self._create_plugin_dir("lifecycle")
        self.invoke(["install", src])

        result = self.invoke(["list"])
        self.assertIn("lifecycle", result.output)

        self.invoke(["remove", "lifecycle"])

        result = self.invoke(["list"])
        self.assertIn("No plugins installed", result.output)


if __name__ == "__main__":
    unittest.main()
