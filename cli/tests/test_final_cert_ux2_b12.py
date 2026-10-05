# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert UX batch 12, plugin CLI (GAP-2355, GAP-2363, GAP-2364)."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

from rich.console import Console

from tests.test_cmd_plugin import PluginCommandTestBase


def test_scan_hint_keeps_the_command_whole_on_narrow_terminals(capsys) -> None:
    # GAP-2363: at 45 columns "Scan a plugin:  defenseclaw plugin scan <name>" split as "<name" / ">".
    from defenseclaw.commands import hint

    text = "Scan a plugin:  defenseclaw plugin scan <name>"
    for columns, expected in (
        ("80", [text]),
        ("45", ["Scan a plugin:", "  defenseclaw plugin scan <name>"]),
    ):
        with patch.dict(os.environ, {"COLUMNS": columns}), patch.object(sys.stdout, "isatty", return_value=True):
            hint(text)
        lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
        assert [click_unstyle(line) for line in lines] == expected


def click_unstyle(line: str) -> str:
    import click

    return click.unstyle(line)


def test_plugin_list_at_45_columns_keeps_whole_ids() -> None:
    # GAP-2364: the squeezed ID column broke "whatsapp" into "whatsap" / "p".
    from defenseclaw.commands.cmd_plugin import _fit_plugin_list_table

    rows = [
        {
            "Status": status,
            "ID": pid,
            "Plugin": pid,
            "Description": "A plugin",
            "Origin": "bundled",
            "Severity": sev,
            "Verdict": verdict,
            "Actions": "-",
        }
        for status, pid, sev, verdict in (
            ("[green]✓ enabled[/green]", "whatsapp", "[yellow]MEDIUM[/yellow]", "warning"),
            ("[red]✗ quarantined[/red]", "dashboard_auth/self_hosted", "-", "-"),
        )
    ]
    for width, stacked in ((45, True), (80, False)):
        console = Console(width=width, record=True)
        table, hidden = _fit_plugin_list_table(console, "Plugins (connector=hermes)", rows)
        console.print(table)
        text = console.export_text()
        lines = text.splitlines()
        assert all(len(line) <= width for line in lines), text
        if stacked:
            assert hidden == ["Description", "Origin", "Plugin", "Actions"]
        assert ("│" not in text) is stacked, text
        if stacked:
            assert "whatsapp" in lines and "dashboard_auth/self_hosted" in lines, text
            assert "ID, then Status · Severity · Verdict" in lines, text
            assert "  ✓ enabled · MEDIUM · warning" in lines, text
        else:
            assert any("│ whatsapp " in line for line in lines), text


class TestFinalCertUx2B12Plugin(PluginCommandTestBase):
    @patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
    def test_quarantined_hermes_plugin_info_header_uses_the_listed_id(self, _mock_oc):
        # GAP-2355: info photon-platform on the quarantined copy said "Plugin: photon-platform".
        root = os.path.join(self.tmp_dir, "hermes-agent", "plugins")
        path = os.path.join(root, "platforms", "photon")
        os.makedirs(path)
        with open(os.path.join(path, "plugin.yaml"), "w", encoding="utf-8") as handle:
            handle.write("name: photon-platform\n")
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
            installed = self.invoke(["info", "photon-platform", "--connector", "hermes"])
            quarantined = self.invoke(["quarantine", "photon", "--connector", "hermes"])
        self.assertEqual(quarantined.exit_code, 0, quarantined.output)
        with (
            patch.dict(os.environ, env),
            patch("defenseclaw.commands.cmd_plugin._list_hermes_plugins", return_value=[]),
        ):
            outputs = [self.invoke(["info", name, "--connector", "hermes"]) for name in ("photon", "photon-platform")]
            restored = self.invoke(["restore", "photon", "--connector", "hermes"])
        for result in [installed, *outputs]:
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(result.output.splitlines()[0], "Plugin:      photon", result.output)
        for result in outputs:
            self.assertIn("Quarantined: yes", result.output)
        self.assertEqual(restored.exit_code, 0, restored.output)
