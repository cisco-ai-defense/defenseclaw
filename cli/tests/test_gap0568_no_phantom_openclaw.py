# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0568: defaults never select an OpenClaw the user does not have.

A plain ``defenseclaw init`` (no terminal, no flags) on a fresh account wrote a
config without a ``claw`` block, so every later load named OpenClaw through the
``claw.mode`` default: the gateway watched ``~/.openclaw`` folders it created,
and ``uninstall --all`` planned and ran an OpenClaw teardown. Configs an older
release wrote that way get the same answer from the uninstall plan.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands import cmd_uninstall
from defenseclaw.commands.cmd_init import init_cmd
from defenseclaw.context import AppContext


class _FreshHome(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="dclaw-gap0568-")))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = self.root / "home"
        self.data_dir = self.home / ".defenseclaw"
        self.home.mkdir()
        for patcher in (
            patch.dict(os.environ, {"HOME": str(self.home), "USERPROFILE": str(self.home)}),
            patch("defenseclaw.config.default_data_path", return_value=self.data_dir),
            patch("defenseclaw.openclaw_presence.openclaw_binary_installed", return_value=False),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _plant_openclaw(self) -> None:
        config = self.home / ".openclaw" / "openclaw.json"
        config.parent.mkdir(parents=True)
        config.write_text("{}\n", encoding="utf-8")

    def _legacy_init(self):
        with (
            patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None),
            patch("defenseclaw.commands.cmd_init._install_guardrail"),
            patch("defenseclaw.commands.cmd_init._install_scanners"),
            patch("defenseclaw.commands.cmd_init._start_gateway"),
            patch("defenseclaw.commands.cmd_init._stdin_is_tty", return_value=False),
        ):
            result = CliRunner().invoke(init_cmd, ["--skip-install"], obj=AppContext())
        self.assertEqual(result.exit_code, 0, result.output)
        return result

    def _plan(self):
        return cmd_uninstall._build_plan(wipe_data=True, binaries=False, revert_openclaw=True, remove_plugin=True)


class FreshInitWithoutOpenClawTests(_FreshHome):
    def test_init_without_openclaw_selects_no_connector(self):
        from defenseclaw.config import load

        result = self._legacy_init()
        cfg = load()

        self.assertFalse(cfg.has_connector_configured())
        self.assertEqual(cfg.active_connectors(), [])
        self.assertNotIn("connector: openclaw", result.output)
        self.assertNotIn(".openclaw", result.output)

    def test_uninstall_after_init_without_openclaw_plans_no_openclaw_teardown(self):
        self._legacy_init()
        plan = self._plan()

        self.assertEqual(plan.connector, "")
        self.assertEqual(plan.connectors, ())
        self.assertFalse(plan.revert_openclaw)
        self.assertFalse(plan.remove_plugin)
        self.assertEqual(plan.openclaw_config_file, "")
        self.assertEqual(plan.openclaw_home, "")

    def test_init_with_openclaw_installed_keeps_the_openclaw_default(self):
        from defenseclaw.config import load

        self._plant_openclaw()
        self._legacy_init()

        self.assertEqual(load().active_connectors(), ["openclaw"])
        self.assertIn("openclaw", self._plan().connectors)


class OlderConfigWithoutClawBlockTests(_FreshHome):
    """A config an older init wrote with no claw block (upgrade path)."""

    def setUp(self) -> None:
        super().setUp()
        from defenseclaw.config import CURRENT_CONFIG_VERSION

        self.data_dir.mkdir(parents=True)
        (self.data_dir / "config.yaml").write_text(
            f"config_version: {CURRENT_CONFIG_VERSION}\nobservability: {{}}\n", encoding="utf-8"
        )

    def test_load_without_openclaw_selects_no_connector(self):
        from defenseclaw.config import load

        cfg = load()

        self.assertFalse(cfg.has_connector_configured())
        self.assertEqual(cfg.active_connectors(), [])

    def test_remote_fleet_keeps_legacy_openclaw_without_local_install(self):
        from defenseclaw.config import load

        original = (self.data_dir / "config.yaml").read_text(encoding="utf-8")
        (self.data_dir / "config.yaml").write_text(
            original + "gateway:\n  host: 10.0.0.5\n  fleet_mode: auto\n",
            encoding="utf-8",
        )

        cfg = load()
        self.assertTrue(cfg.has_connector_configured())
        self.assertEqual(cfg.active_connector(), "openclaw")
        self.assertEqual(cfg.active_connectors(), ["openclaw"])

    def test_explicit_loopback_fleet_keeps_legacy_openclaw_without_local_install(self):
        from defenseclaw.config import load

        original = (self.data_dir / "config.yaml").read_text(encoding="utf-8")
        for fleet_mode in ("enabled", "enabledd"):
            with self.subTest(fleet_mode=fleet_mode):
                (self.data_dir / "config.yaml").write_text(
                    original + f"gateway:\n  host: 127.0.0.1\n  fleet_mode: {fleet_mode}\n",
                    encoding="utf-8",
                )
                cfg = load()
                self.assertTrue(cfg.has_connector_configured())
                self.assertEqual(cfg.active_connector(), "openclaw")
                self.assertEqual(cfg.active_connectors(), ["openclaw"])

    def test_v8_upgrade_without_claw_block_selects_no_agent(self):
        from defenseclaw.config import load

        (self.data_dir / "config.yaml").write_text("config_version: 8\n", encoding="utf-8")
        cfg = load()

        self.assertEqual(cfg.active_connector(), "")
        self.assertEqual(cfg.active_connectors(), [])

    def test_load_with_openclaw_installed_keeps_openclaw(self):
        from defenseclaw.config import load

        self._plant_openclaw()

        self.assertEqual(load().active_connectors(), ["openclaw"])

    def test_singular_resolution_and_paths_name_no_agent(self):
        from defenseclaw import config as config_module
        from defenseclaw.commands import cmd_quickstart
        from defenseclaw.config import load

        cfg = load()
        self.assertEqual(cfg.active_connector(), "")
        self.assertEqual(cfg.claw_home_dir(), "")
        self.assertEqual(cfg.skill_dirs(), [])
        self.assertEqual(cfg.plugin_dirs(), [])
        self.assertEqual(cfg.mcp_source_locations(), [])
        self.assertEqual(cmd_quickstart._configured_quickstart_connectors(config_module), [])

    def test_roster_without_claw_block_selects_the_configured_agent(self):
        from defenseclaw import config as config_module
        from defenseclaw.commands import cmd_quickstart
        from defenseclaw.config import load
        from defenseclaw.openclaw_presence import openclaw_implied_but_not_installed, openclaw_only_implied

        (self.data_dir / "config.yaml").write_text(
            "config_version: 9\nguardrail:\n  connectors:\n    codex: {}\n",
            encoding="utf-8",
        )
        cfg = load()
        self.assertEqual(cfg.active_connector(), "codex")
        self.assertEqual(cfg.active_connectors(), ["codex"])
        self.assertFalse(openclaw_only_implied(cfg))
        self.assertFalse(openclaw_implied_but_not_installed(cfg))
        self.assertEqual(cmd_quickstart._configured_quickstart_connectors(config_module), ["codex"])

    def test_secure_client_roster_does_not_select_stale_openclaw(self):
        from defenseclaw.config import PerConnectorGuardrailConfig, load

        cfg = load()
        cfg.deployment_mode = "managed_enterprise"
        cfg.enterprise_profile = "secure_client"
        cfg.guardrail._secure_client = True
        cfg.claw.mode = "openclaw"
        cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig()}
        self.assertEqual(cfg.active_connector(), "codex")

    def test_cli_discovery_and_scan_helpers_name_no_agent(self):
        from defenseclaw import codeguard_skill
        from defenseclaw.commands import _scan_ui, cmd_agent, cmd_doctor, cmd_guardrail, cmd_plugin, cmd_skill
        from defenseclaw.config import load

        app = AppContext()
        app.cfg = load()
        self.assertEqual(cmd_doctor._active_connector(app.cfg), "")
        self.assertEqual(cmd_guardrail._resolve_active_connector(app.cfg), "")
        self.assertEqual(cmd_agent._resolve_connector_for_restart(app.cfg), "")
        self.assertEqual(codeguard_skill._resolve_connector(app.cfg, None), "")
        self.assertEqual(cmd_skill._active_skill_connectors(app), [])
        self.assertEqual(cmd_plugin._active_plugin_connectors(app), [])
        self.assertEqual(cmd_skill._active_connector_name(app), "")
        self.assertEqual(cmd_plugin._normalize_runtime_connector(""), "")
        self.assertEqual(_scan_ui.ScanContext(component="skill", connector="").connector, "")
        with patch.object(cmd_skill, "_run_openclaw") as run_openclaw:
            self.assertEqual(cmd_skill._list_openclaw_skills_full(app), {"skills": []})
        run_openclaw.assert_not_called()

    def test_aibom_builder_does_not_inventory_an_unconfigured_agent(self):
        from defenseclaw.config import load
        from defenseclaw.inventory import claw_inventory

        cfg = load()
        with (
            patch.object(claw_inventory, "_collect_filesystem_category") as collect,
            patch.object(claw_inventory, "_fetch_all") as fetch,
        ):
            inv = claw_inventory.build_claw_aibom(cfg, live=True)
        collect.assert_not_called()
        fetch.assert_not_called()
        self.assertEqual(inv["connector"], "")
        self.assertFalse(inv["live"])
        self.assertEqual(inv["summary"]["total_items"], 0)
        self.assertEqual(inv["categories_collected"], [])
        self.assertFalse(inv["summary"]["skills"]["collected"])
        self.assertEqual(inv["connector_home"], "")
        self.assertEqual(inv["connector_config_files"], [])
        self.assertNotIn("openclaw_config", inv)
        rendered = StringIO()
        with redirect_stdout(rendered):
            claw_inventory.format_claw_aibom_human(inv, summary_only=True)
        self.assertIn("Agent AIBOM", rendered.getvalue())
        self.assertNotIn("OpenClaw AIBOM", rendered.getvalue())

    def test_credentials_do_not_infer_an_openclaw_proxy(self):
        from defenseclaw import credentials
        from defenseclaw.config import load

        cfg = load()
        cfg.guardrail.enabled = True
        self.assertFalse(credentials._guardrail_proxy_uses_llm(cfg))
        cfg.guardrail.connector = "openclaw"
        self.assertTrue(credentials._guardrail_proxy_uses_llm(cfg))

    def test_a_connector_set_after_load_is_configured(self):
        from defenseclaw.config import load

        cfg = load()
        cfg.claw.mode = "codex"

        self.assertEqual(cfg.active_connectors(), ["codex"])

    def test_uninstall_plans_no_openclaw_teardown_without_openclaw(self):
        plan = self._plan()

        self.assertEqual(plan.connectors, ())
        self.assertFalse(plan.revert_openclaw)
        self.assertEqual(plan.openclaw_home, "")

    def test_uninstall_still_tears_down_an_installed_openclaw(self):
        self._plant_openclaw()

        plan = self._plan()

        self.assertEqual(plan.connectors, ("openclaw",))
        self.assertTrue(plan.revert_openclaw)

    def test_uninstall_still_tears_down_openclaw_with_a_backup_marker(self):
        marker = self.data_dir / "connector_backups" / "openclaw" / "openclaw.json.json"
        marker.parent.mkdir(parents=True)
        marker.write_text("{}", encoding="utf-8")

        self.assertIn("openclaw", self._plan().connectors)


    def _overview_model(self):
        from defenseclaw.config import load
        from defenseclaw.tui.app import _active_connector, _overview_config
        from defenseclaw.tui.services.overview_state import OverviewPanelModel

        cfg = load()
        return _active_connector(cfg), OverviewPanelModel(_overview_config(cfg))

    def test_tui_names_no_agent_without_openclaw(self):
        active, model = self._overview_model()

        self.assertEqual(active, "")
        self.assertEqual(model.active_connector_name(), "")

    def test_tui_still_names_an_installed_openclaw(self):
        self._plant_openclaw()

        active, model = self._overview_model()

        self.assertEqual(active, "openclaw")
        self.assertEqual(model.active_connector_name(), "openclaw")

    def test_tui_setup_names_no_agent_or_openclaw_paths(self):
        from defenseclaw.config import load
        from defenseclaw.tui.panels.setup import (
            SetupPanelModel,
            _active_connector_names_for_setup,
            _openclaw_path_field,
            connector_setup_wizard_fields,
            wizard_field_value,
        )
        from defenseclaw.tui.services.overview_state import OverviewConfig, OverviewPanelModel

        cfg = load()
        self.assertEqual(_active_connector_names_for_setup(cfg), [])
        field = _openclaw_path_field(cfg, "Home", "claw.home_dir", "")
        self.assertIn("not used", field.value)
        self.assertFalse(SetupPanelModel(cfg, os_name="linux").has_changes())
        self.assertEqual(OverviewPanelModel(OverviewConfig()).active_connector_name(), "")
        self.assertEqual(wizard_field_value(connector_setup_wizard_fields(cfg), "Connector"), "")


class OlderInitClawModeTests(OlderConfigWithoutClawBlockTests):
    """The claw.mode openclaw default an init before 1.0.4 saved (upgrade path)."""

    def setUp(self) -> None:
        super().setUp()
        from defenseclaw.config import CURRENT_CONFIG_VERSION

        (self.data_dir / "config.yaml").write_text(
            f"config_version: {CURRENT_CONFIG_VERSION}\nclaw:\n  mode: openclaw\n"
            "  home_dir: ~/.openclaw\n  config_file: ~/.openclaw/openclaw.json\n",
            encoding="utf-8",
        )


class FirstRunDefaultConnectorTests(unittest.TestCase):
    """init --yes / --non-interactive and the prompt pick no absent agent."""

    def test_backend_defaults_to_no_agent_without_a_choice(self):
        from defenseclaw.bootstrap import FirstRunOptions, _normalize_connector

        self.assertEqual(FirstRunOptions().connector, "none")
        self.assertEqual(_normalize_connector(None), "none")
        self.assertEqual(_normalize_connector("  "), "none")

    @staticmethod
    def _discovery(**installed: bool):
        from types import SimpleNamespace

        return SimpleNamespace(agents={name: SimpleNamespace(installed=flag) for name, flag in installed.items()})

    def _default(self, disc) -> str:
        from defenseclaw.commands.cmd_init import _normalize_connector_arg

        with patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents", return_value=disc):
            return _normalize_connector_arg(None, discover_default=True)

    def test_nothing_installed_defaults_to_no_connector(self):
        self.assertEqual(self._default(self._discovery(codex=False, claudecode=False)), "none")

    def test_failed_discovery_defaults_to_no_connector(self):
        from defenseclaw.commands.cmd_init import _normalize_connector_arg

        with patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents", side_effect=OSError("scan")):
            self.assertEqual(_normalize_connector_arg(None, discover_default=True), "none")

    def test_an_installed_agent_is_still_picked(self):
        self.assertEqual(self._default(self._discovery(codex=False, claudecode=True)), "claudecode")
        self.assertEqual(self._default(self._discovery(codex=True, claudecode=True)), "codex")

    def test_explicit_codex_still_works(self):
        from defenseclaw.commands.cmd_init import _normalize_connector_arg

        self.assertEqual(_normalize_connector_arg("codex"), "codex")

class SetupMenuDefaultTests(unittest.TestCase):
    """The setup connector menu defaults only to an installed agent."""

    def _menu_default(self, current: str, installed: list[str], picked: str | None):
        from defenseclaw.commands import cmd_setup

        with (
            patch.object(cmd_setup, "_detect_installed_connectors", return_value=installed),
            patch.object(cmd_setup, "_read_picked_connector", return_value=picked),
            patch.object(cmd_setup.click, "prompt", return_value=1) as prompt,
        ):
            cmd_setup._select_connector_interactive(current, data_dir="/unused")
        default = prompt.call_args.kwargs["default"]
        return None if default is None else cmd_setup._CONNECTOR_NAMES[default - 1]

    def test_no_installed_agent_has_no_default(self):
        self.assertIsNone(self._menu_default("openclaw", [], None))
        self.assertIsNone(self._menu_default("", [], None))

    def test_a_picked_agent_that_is_not_installed_is_not_the_default(self):
        # An older installer recorded codex when it had no terminal to ask on.
        self.assertIsNone(self._menu_default("openclaw", [], "codex"))
        self.assertEqual(self._menu_default("openclaw", ["claudecode"], "codex"), "claudecode")

    def test_an_installed_agent_is_the_default(self):
        self.assertEqual(self._menu_default("openclaw", ["claudecode", "codex"], "codex"), "codex")
        self.assertEqual(self._menu_default("openclaw", ["claudecode"], None), "claudecode")
        self.assertEqual(self._menu_default("openclaw", ["openclaw"], None), "openclaw")

    def test_a_configured_connector_stays_the_default(self):
        self.assertEqual(self._menu_default("cursor", [], None), "cursor")


if __name__ == "__main__":
    unittest.main()
