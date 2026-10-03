# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert UX batch 10, plugin/MCP CLI (GAP-2308, GAP-2310, GAP-2311, GAP-2313, GAP-2317)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import click
from click.testing import CliRunner
from defenseclaw.config import MCPServerEntry
from defenseclaw.tui.command_line import command_result_summary
from defenseclaw.tui.services.catalog_state import PluginRow, plugin_action_intent

from tests.test_cmd_mcp import MCPCommandTestBase
from tests.test_cmd_plugin import PluginCommandTestBase, _seed_scan


def _walk(command: click.Command, path: str = ""):
    yield path, command
    for name, sub in (getattr(command, "commands", None) or {}).items():
        yield from _walk(sub, f"{path} {name}".strip())


def test_help_has_no_markdown_bold() -> None:
    # GAP-2310: '**every configured connector's**' printed with asterisks.
    from defenseclaw.main import cli

    bold = [path for path, cmd in _walk(cli) if "**" in (cmd.help or "")]
    assert bold == []
    # The root group needs an initialised home; the cleaned help is shared.
    result = CliRunner().invoke(cli.commands["mcp"], ["list", "--help"], terminal_width=80)
    assert result.exit_code == 0, result.output
    assert "List MCP servers for every configured connector." in result.output
    assert "**" not in result.output


def test_plugin_block_of_a_disabled_plugin_in_the_tui() -> None:
    # GAP-2313: confirm and result card said the disabled copy still loads.
    row = PluginRow(id="cron_providers/chronos", name="chronos", status="disabled", enabled=False)
    block = plugin_action_intent("b", row, origin="plugins", connector="hermes")
    assert block is not None
    assert "is disabled, so it does not load" in block.consequence
    assert "keeps loading" not in block.consequence
    lines = [
        "[plugin] Blocked 'cron_providers/chronos' (hermes).",
        "  The installed copy is disabled, so it does not load; new installs are refused.",
    ]
    summary = command_result_summary("plugin block cron_providers/chronos --connector hermes", lines)
    assert summary == "New installs blocked; the installed copy is disabled."


class TestFinalCertUx2B10Mcp(MCPCommandTestBase):
    @patch("defenseclaw.commands.hint")
    @patch("defenseclaw.commands.cmd_mcp._unset_mcp_via_connector")
    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_set_and_unset_read_like_block(self, _mock_set, _mock_unset, mock_hint):
        # GAP-2311: "Added MCP server: X" / "Removed MCP server: X"; hint dropped --connector.
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        added = self.invoke(["set", "sf1", "--url", "https://x/mcp", "--connector", "codex", "--skip-scan"])
        self.app.cfg.mcp_servers = MagicMock(
            return_value=[MCPServerEntry(name="sf1", url="https://x/mcp", transport="sse")]
        )
        removed = self.invoke(["unset", "sf1", "--connector", "codex"])

        self.assertEqual(added.exit_code, 0, added.output)
        self.assertIn("[mcp] Added 'sf1' (codex).", added.output)
        mock_hint.assert_called_once_with("Scan it now:  defenseclaw mcp scan sf1 --connector codex")
        self.assertEqual(removed.exit_code, 0, removed.output)
        self.assertIn("[mcp] Removed 'sf1' (codex).", removed.output)


class TestFinalCertUx2B10Plugin(PluginCommandTestBase):
    def test_block_of_a_disabled_plugin_does_not_say_it_loads(self):
        # GAP-2313
        self._install_plugin("off-one")
        rows = [{"id": "off-one", "name": "off-one", "enabled": False}]
        with patch("defenseclaw.commands.cmd_plugin._merge_all_plugins", return_value=rows):
            result = self.invoke(["block", "off-one"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("The installed copy is disabled, so it does not load", result.output)
        self.assertNotIn("still loads", result.output)
        self.assertNotIn("To stop it", result.output)

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_empty_claude_registry_is_one_plain_line(self, _mock_oc):
        # GAP-2317: valid, empty installed_plugins.json printed the raw diagnostic.
        plugin_root = os.path.join(self.tmp_dir, "emptyclaude", "plugins")
        os.makedirs(plugin_root)
        with open(os.path.join(plugin_root, "installed_plugins.json"), "w", encoding="utf-8") as handle:
            json.dump({"version": 2, "plugins": {}}, handle)
        self.app.cfg.active_connectors = lambda: ["claudecode", "hermes"]  # type: ignore[method-assign]
        self.app.cfg.plugin_dirs = lambda connector=None: [plugin_root] if connector == "claudecode" else []  # type: ignore[method-assign]

        scoped = self.invoke(["list", "--connector", "claudecode"])
        unscoped = self.invoke(["list"])

        self.assertEqual(scoped.exit_code, 0, scoped.output)
        self.assertEqual(scoped.output.strip(), "claudecode has no installed plugins.")
        self.assertEqual(unscoped.exit_code, 0, unscoped.output)
        self.assertEqual(
            unscoped.output.splitlines()[:2],
            ["Plugins (connector=claudecode): no installed plugins", "Plugins (connector=hermes): no plugins found"],
            unscoped.output,
        )
        self.assertNotIn("entries=0", unscoped.output)

    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_nested_hermes_quarantine_answers_in_the_listed_id(self, _mock_oc):
        # GAP-2308: output/audit used photon-platform; info by that name had no Last Scan.
        from defenseclaw.models import Finding, ScanResult

        root = os.path.join(self.tmp_dir, "hermes-agent", "plugins")
        path = os.path.join(root, "platforms", "photon")
        os.makedirs(path)
        with open(os.path.join(path, "plugin.yaml"), "w", encoding="utf-8") as handle:
            handle.write("name: photon-platform\n")
        _seed_scan(
            self.app.store,
            ScanResult(
                scanner="plugin-scanner",
                target=path,
                timestamp=datetime.now(timezone.utc),
                findings=[Finding(id="f1", severity="MEDIUM", title="t", scanner="plugin-scanner")],
                duration=timedelta(seconds=0.1),
            ),
        )
        self.app.cfg.active_connectors = lambda: ["hermes"]  # type: ignore[method-assign]
        self.app.cfg.plugin_dirs = lambda connector=None: [root]  # type: ignore[method-assign]
        rows = [
            {
                "id": "photon",
                "name": "photon-platform",
                "description": "",
                "version": "",
                "origin": "bundled",
                "enabled": True,
                "source": "host:hermes",
                "host_path": path,
            }
        ]
        env = {"HERMES_HOME": self.tmp_dir, "COLUMNS": "200"}
        with (
            patch.dict(os.environ, env),
            patch("defenseclaw.commands.cmd_plugin._list_hermes_plugins", return_value=rows),
        ):
            quarantined = self.invoke(["quarantine", "photon", "--connector", "hermes"])
        with (
            patch.dict(os.environ, env),
            patch("defenseclaw.commands.cmd_plugin._list_hermes_plugins", return_value=[]),
        ):
            by_id = self.invoke(["info", "photon", "--connector", "hermes"])
            by_name = self.invoke(["info", "photon-platform", "--connector", "hermes"])
            restored = self.invoke(["restore", "photon", "--connector", "hermes"])

        self.assertEqual(quarantined.exit_code, 0, quarantined.output)
        self.assertIn("[plugin] 'photon' (photon-platform) quarantined to", quarantined.output)
        self.assertIn("Last Scan:", by_id.output)
        self.assertIn("Last Scan:", by_name.output)
        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertIn("[plugin] 'photon' (photon-platform) restored to", restored.output)
        events = [e for e in self.app.store.list_events(20) if e.action in ("plugin-quarantine", "plugin-restore")]
        self.assertEqual({e.target for e in events}, {"photon"})
        self.assertTrue(all("quarantine_id=photon-platform" in e.details for e in events))
