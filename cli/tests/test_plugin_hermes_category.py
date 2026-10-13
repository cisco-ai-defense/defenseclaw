# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Hermes category-folder plugins in plugin list and restore (GAP-2463, GAP-2464, GAP-2470)."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

from defenseclaw.enforce import PolicyEngine

from tests.test_cmd_plugin import PluginCommandTestBase


def _write_plugin(path: str, name: str) -> None:
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "plugin.yaml"), "w", encoding="utf-8") as handle:
        handle.write(f"name: {name}\nversion: 0.1.0\n")
    with open(os.path.join(path, "__init__.py"), "w", encoding="utf-8") as handle:
        handle.write("def register(ctx):\n    return None\n")


@patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
class TestHermesCategoryPlugins(PluginCommandTestBase):
    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp_dir, "hermes-home")
        self.user = os.path.join(self.home, "plugins")
        self.bundled = os.path.join(self.home, "hermes-agent", "plugins")
        os.makedirs(self.user)
        os.makedirs(self.bundled)
        self.app.cfg.active_connectors = lambda: ["hermes"]  # type: ignore[method-assign]
        self.app.cfg.plugin_dirs = lambda connector=None: [self.user, self.bundled]  # type: ignore[method-assign]
        env = patch.dict(os.environ, {"HERMES_HOME": self.home, "HERMES_BUNDLED_PLUGINS": ""})
        env.start()
        self.addCleanup(env.stop)

    def test_list_with_category_folder_shared_by_both_roots(self, _mock_oc):
        """GAP-2463: a user category folder named like a bundled one is no identity conflict."""
        _write_plugin(os.path.join(self.user, "platforms", "demo"), "demo")
        _write_plugin(os.path.join(self.user, "web", "extra"), "extra")
        _write_plugin(os.path.join(self.bundled, "platforms", "a2a"), "a2a")
        _write_plugin(os.path.join(self.bundled, "web", "ddgs"), "ddgs")
        result = self.invoke(["list", "--connector", "hermes", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        ids = {item["id"] for item in json.loads(result.output)}
        self.assertTrue({"platforms/demo", "web/extra", "a2a", "web/ddgs"} <= ids, ids)

    def _watcher_quarantine(self, listed_id: str) -> str:
        """The state the gateway watcher leaves: a global action, the copy under hermes/."""
        source = os.path.join(self.user, *listed_id.split("/"))
        tree = "plugin-categories" if "/" in listed_id else "plugins"
        _write_plugin(
            os.path.join(self.app.cfg.quarantine_dir, tree, "hermes", *listed_id.split("/")), listed_id.split("/")[-1]
        )
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.quarantine("plugin", listed_id, "auto-block: watch detected HIGH findings")
        pe.set_source_path("plugin", listed_id, source)
        return source

    def test_restore_category_plugin_quarantined_by_watcher(self, _mock_oc):
        """GAP-2464: restore finds web/dup and memx/dup apart from a flat dup."""
        web = self._watcher_quarantine("web/dup")
        memx = self._watcher_quarantine("memx/dup")
        flat = self._watcher_quarantine("dup")

        result = self.invoke(["restore", "web/dup"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isfile(os.path.join(web, "plugin.yaml")))
        self.assertFalse(os.path.exists(memx))
        self.assertFalse(os.path.exists(flat))
        self.assertFalse(PolicyEngine(self.app.store, self.app.cfg).is_quarantined("plugin", "web/dup"))

        result = self.invoke(["restore", "dup"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isfile(os.path.join(flat, "plugin.yaml")))
        self.assertFalse(os.path.exists(memx))

        result = self.invoke(["restore", "memx/dup"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isfile(os.path.join(memx, "plugin.yaml")))
        self.assertEqual(os.listdir(os.path.join(self.app.cfg.quarantine_dir, "plugin-categories", "hermes", "memx")), [])

    def test_restore_category_plugin_by_folder_name(self, _mock_oc):
        """GAP-2464: the bare folder name restores a unique category plugin."""
        source = self._watcher_quarantine("memx/flagtwo")
        result = self.invoke(["restore", "flagtwo"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isfile(os.path.join(source, "plugin.yaml")))

    def test_restore_flat_plugin_leaves_category_plugin_of_same_name(self, _mock_oc):
        """GAP-2470: restoring flat coll leaves the separately quarantined coll/inner quarantined."""
        flat = self._watcher_quarantine("coll")
        inner = self._watcher_quarantine("coll/inner")

        result = self.invoke(["restore", "coll"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isfile(os.path.join(flat, "plugin.yaml")))
        self.assertFalse(os.path.exists(inner))
        self.assertTrue(PolicyEngine(self.app.store, self.app.cfg).is_quarantined("plugin", "coll/inner"))

        result = self.invoke(["restore", "coll/inner"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isfile(os.path.join(inner, "plugin.yaml")))
