# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The retired Desktop connector ID moves to devin everywhere config is read."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from defenseclaw import legacy_connector, migrations
from defenseclaw.commands import cmd_uninstall
from defenseclaw.config import load

RETIRED = legacy_connector.RETIRED_DESKTOP_ID
DEVIN = legacy_connector.REPLACEMENT


class MigrateRawConfigTests(unittest.TestCase):
    def test_primary_and_claw_mode(self):
        raw = {"claw": {"mode": RETIRED.upper()}, "guardrail": {"connector": f" {RETIRED} "}}
        notices = legacy_connector.migrate_raw_config(raw, "/etc/dc/config.yaml")
        self.assertEqual(raw["guardrail"]["connector"], DEVIN)
        self.assertEqual(raw["claw"]["mode"], DEVIN)
        self.assertEqual(len(notices), 1)
        self.assertIn(legacy_connector.HEADLINE, notices[0])
        self.assertIn("/etc/dc/config.yaml", notices[0])

    def test_map_block_is_renamed_with_its_settings(self):
        raw = {"guardrail": {"connector": "codex", "connectors": {"codex": {}, RETIRED: {"mode": "action"}}}}
        legacy_connector.migrate_raw_config(raw)
        self.assertEqual(raw["guardrail"]["connectors"], {"codex": {}, DEVIN: {"mode": "action"}})

    def test_explicit_devin_block_wins(self):
        raw = {"guardrail": {"connectors": {DEVIN: {"mode": "observe"}, RETIRED: {"mode": "action"}}}}
        notices = legacy_connector.migrate_raw_config(raw)
        self.assertEqual(raw["guardrail"]["connectors"], {DEVIN: {"mode": "observe"}})
        self.assertIn(repr(RETIRED), notices[0])

    def test_other_per_connector_maps_are_renamed(self):
        raw = {
            "guardrail": {"connector": DEVIN},
            "asset_policy": {"connectors": {RETIRED: {"mode": "action"}}},
            "application_protection": {"connectors": {RETIRED: {"min_confidence": 0.7}}},
            "observability": {"connectors": {DEVIN: {"webhooks": []}, RETIRED: {"webhooks": []}}},
        }
        notices = legacy_connector.migrate_raw_config(raw)
        self.assertEqual(raw["asset_policy"]["connectors"], {DEVIN: {"mode": "action"}})
        self.assertEqual(raw["application_protection"]["connectors"], {DEVIN: {"min_confidence": 0.7}})
        self.assertEqual(raw["observability"]["connectors"], {DEVIN: {"webhooks": []}})
        self.assertEqual(len(notices), 1)
        self.assertIn(repr(f"observability.connectors.{RETIRED}"), notices[0])

    def test_connector_settings_and_lists_are_renamed(self):
        raw = {"guardrail": {"connector": DEVIN}, "connector_hooks": {RETIRED: {"enabled": True, "mode": "action"}}}
        notices = legacy_connector.migrate_raw_config(raw, "/etc/dc/config.yaml")
        self.assertEqual(raw["connector_hooks"], {DEVIN: {"enabled": True, "mode": "action"}})
        self.assertEqual(len(notices), 1)
        self.assertIn("connector_hooks of /etc/dc/config.yaml", notices[0])
        # An explicit devin entry wins, and each list names devin once.
        raw = {
            "connector_hooks": {DEVIN: {"mode": "observe"}, RETIRED: {"mode": "action"}},
            "guardrail": {"judge": {"enabled": True, "hook_connectors": ["codex", RETIRED, DEVIN]}},
            "application_protection": {
                "include_connectors": [RETIRED, "cursor"],
                "exclude_connectors": [RETIRED.capitalize(), RETIRED],
            },
        }
        notices = "\n".join(legacy_connector.migrate_raw_config(raw))
        self.assertEqual(raw["connector_hooks"], {DEVIN: {"mode": "observe"}})
        self.assertEqual(raw["guardrail"]["judge"]["hook_connectors"], ["codex", DEVIN])
        self.assertEqual(raw["application_protection"]["include_connectors"], [DEVIN, "cursor"])
        self.assertEqual(raw["application_protection"]["exclude_connectors"], [DEVIN])
        for setting in (repr(f"connector_hooks.{RETIRED}"), "guardrail.judge.hook_connectors",
                        "application_protection.include_connectors", "application_protection.exclude_connectors"):
            self.assertIn(setting, notices)

    def test_asset_policy_rules_and_route_selectors_are_renamed(self):
        raw = {
            "guardrail": {"connector": RETIRED},
            "asset_policy": {
                "mcp": {
                    "registry": [{"name": "approved-server", "connector": RETIRED}],
                    "denied": [{"name": "marker-server", "connector": f" {RETIRED.upper()} "}, {"name": "other"}],
                },
                "skill": {"allowed": [{"name": "marker-skill", "connector": "codex"}]},
            },
            "observability": {
                "destinations": [
                    {
                        "name": "console",
                        "routes": [
                            {"name": "codex-only", "selector": {"connectors": ["codex"]}},
                            {"name": "desktop", "selector": {"connectors": ["codex", RETIRED, DEVIN]}},
                        ],
                    }
                ]
            },
        }
        notices = legacy_connector.migrate_raw_config(raw, "config.yaml")
        self.assertEqual(raw["asset_policy"]["mcp"]["registry"][0]["connector"], DEVIN)
        self.assertEqual(raw["asset_policy"]["mcp"]["denied"][0]["connector"], DEVIN)
        self.assertNotIn("connector", raw["asset_policy"]["mcp"]["denied"][1])
        self.assertEqual(raw["asset_policy"]["skill"]["allowed"][0]["connector"], "codex")
        routes = raw["observability"]["destinations"][0]["routes"]
        self.assertEqual(routes[0]["selector"]["connectors"], ["codex"])
        self.assertEqual(routes[1]["selector"]["connectors"], ["codex", DEVIN])
        for setting in ("asset_policy.mcp.registry, asset_policy.mcp.denied",
                        "observability.destinations[0].routes[1].selector.connectors of config.yaml"):
            self.assertIn(setting, notices[0])

    def test_unaffected_config_is_untouched(self):
        raw = {"claw": {"mode": "cursor"}, "guardrail": {"connector": "cursor", "connectors": {"cursor": {}}}}
        before = yaml.safe_dump(raw)
        self.assertEqual(legacy_connector.migrate_raw_config(raw), [])
        self.assertEqual(yaml.safe_dump(raw), before)
        self.assertEqual(legacy_connector.migrate_raw_config(None), [])

    def test_canonical(self):
        self.assertEqual(legacy_connector.canonical("Wind Surf"), (DEVIN, True))
        self.assertEqual(legacy_connector.canonical("devin"), ("devin", False))
        self.assertFalse(legacy_connector.is_retired("codeium"))


class ConfigLoadTests(unittest.TestCase):
    def _load(self, body: str):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = os.path.realpath(tmpdir)
            Path(data_dir, "config.yaml").write_text(
                f"config_version: 8\ndata_dir: {data_dir}\n{body}", encoding="utf-8"
            )
            env = {k: v for k, v in os.environ.items() if k != "DEFENSECLAW_CONFIG"}
            with patch.dict(os.environ, env, clear=True):
                return load(data_dir=data_dir)

    def test_load_sees_devin(self):
        cfg = self._load(f"claw:\n  mode: {RETIRED}\nguardrail:\n  connector: {RETIRED}\n")
        self.assertEqual(cfg.guardrail.connector, DEVIN)
        self.assertEqual(cfg.claw.mode, DEVIN)

    def test_save_persists_the_rename(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = os.path.realpath(tmpdir)
            path = Path(data_dir, "config.yaml")
            path.write_text(
                f"config_version: 8\ndata_dir: {data_dir}\nclaw:\n  mode: {RETIRED}\n"
                f"guardrail:\n  connector: {RETIRED}\n  connectors:\n    {RETIRED}:\n      mode: action\n",
                encoding="utf-8",
            )
            env = {k: v for k, v in os.environ.items() if k != "DEFENSECLAW_CONFIG"}
            with patch.dict(os.environ, env, clear=True):
                cfg = load(data_dir=data_dir)
                cfg.save()
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.assertEqual(doc["guardrail"]["connector"], DEVIN)
        self.assertEqual(doc["claw"]["mode"], DEVIN)
        self.assertEqual(set(doc["guardrail"]["connectors"]), {DEVIN})
        self.assertEqual(doc["guardrail"]["connectors"][DEVIN]["mode"], "action")

    def test_both_keys_present_is_not_a_duplicate_error(self):
        cfg = self._load(
            f"guardrail:\n  connector: {DEVIN}\n  connectors:\n    {DEVIN}:\n      mode: observe\n"
            f"    {RETIRED}:\n      mode: action\n"
        )
        self.assertEqual(set(cfg.guardrail.connectors), {DEVIN})
        self.assertEqual(cfg.guardrail.connectors[DEVIN].mode, "observe")


class UpgradeMigrationTests(unittest.TestCase):
    def _run(self, body: str) -> tuple[str, list[str]]:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.yaml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
            ctx = migrations.MigrationContext(openclaw_home=tmpdir, data_dir=tmpdir, config_path=path)
            migrations._migrate_retired_desktop_connector(ctx)
            first_changes = list(ctx.changes)
            migrations._migrate_retired_desktop_connector(ctx)
            self.assertEqual(ctx.changes, first_changes, "second run must be a no-op")
            with open(path, encoding="utf-8") as fh:
                return fh.read(), first_changes

    def test_migration_persists_and_reports_once(self):
        body = (
            "# operator comment kept\n"
            f"claw:\n  mode: {RETIRED}  # inline kept\n"
            "guardrail:\n"
            f"  connector: '{RETIRED}'\n"
            "  connectors:\n"
            "    codex:\n      mode: observe\n"
            f"    {RETIRED}:\n      mode: action\n      hook_fail_mode: open\n"
            "gateway:\n  api_port: 18970\n"
        )
        text, changes = self._run(body)
        self.assertEqual(len(changes), 1)
        self.assertIn(legacy_connector.HEADLINE, changes[0])
        self.assertIn("# operator comment kept", text)
        self.assertIn("# inline kept", text)
        self.assertNotIn(RETIRED, text)
        doc = yaml.safe_load(text)
        self.assertEqual(doc["claw"]["mode"], DEVIN)
        self.assertEqual(doc["guardrail"]["connector"], DEVIN)
        self.assertEqual(doc["guardrail"]["connectors"][DEVIN], {"mode": "action", "hook_fail_mode": "open"})
        self.assertEqual(doc["gateway"], {"api_port": 18970})

    def test_migration_drops_retired_block_when_devin_exists(self):
        body = (
            "guardrail:\n  connector: devin\n  connectors:\n"
            f"    devin:\n      mode: observe\n    {RETIRED}:\n      mode: action\n"
            "    codex: {}\n"
        )
        text, changes = self._run(body)
        self.assertEqual(len(changes), 1)
        doc = yaml.safe_load(text)
        self.assertEqual(doc["guardrail"]["connectors"], {DEVIN: {"mode": "observe"}, "codex": {}})

    def test_migration_renames_other_per_connector_maps_in_place(self):
        body = (
            "guardrail:\n  connector: devin\n  connectors:\n    devin: {}\n"
            "asset_policy:\n  # asset comment kept\n  connectors:\n"
            f"    {RETIRED}:\n      mode: action\n"
            "observability:\n  destinations:\n    - name: local\n      select:\n        connectors:\n          - codex\n"
            f"  connectors:\n    {RETIRED}:\n      webhooks: []\n"
        )
        text, changes = self._run(body)
        self.assertEqual(len(changes), 1)
        self.assertIn("# asset comment kept", text)
        self.assertNotIn(RETIRED, text)
        doc = yaml.safe_load(text)
        self.assertEqual(doc["asset_policy"]["connectors"], {DEVIN: {"mode": "action"}})
        self.assertEqual(doc["observability"]["connectors"], {DEVIN: {"webhooks": []}})
        self.assertEqual(doc["observability"]["destinations"][0]["select"]["connectors"], ["codex"])

    def test_migration_renames_connector_settings_lists_and_rules_in_place(self):
        body = (
            "# operator comment kept\n"
            "guardrail:\n  connector: codex\n  judge:\n    enabled: true\n"
            f"    hook_connectors: [codex, {RETIRED}]  # judge comment kept\n"
            "connector_hooks:\n"
            f"  {RETIRED}:\n    enabled: true\n    mode: action\n"
            "application_protection:\n  include_connectors:\n    - cursor\n"
            f"    - {RETIRED}\n  exclude_connectors:\n  - '{RETIRED}'\n"
            "asset_policy:\n  enabled: true\n  mcp:\n    denied:\n"
            f"      - name: marker-server\n        connector: {RETIRED}  # rule comment kept\n"
            f"    registry:\n      - connector: '{RETIRED}'\n        name: approved-server\n"
            "observability:\n  destinations:\n    - name: console\n      kind: console\n      routes:\n"
            "        - name: desktop\n          signals: [logs]\n          selector:\n"
            f"            connectors: [codex, {RETIRED}]\n"
        )
        text, changes = self._run(body)
        self.assertEqual(len(changes), 1)
        for setting in ("connector_hooks", "asset_policy.mcp.registry, asset_policy.mcp.denied",
                        "observability.destinations[0].routes[0].selector.connectors"):
            self.assertIn(setting, changes[0])
        for comment in ("# operator comment kept", "# judge comment kept", "# rule comment kept"):
            self.assertIn(comment, text)
        self.assertNotIn(RETIRED, text)
        doc = yaml.safe_load(text)
        self.assertEqual(doc["guardrail"]["judge"]["hook_connectors"], ["codex", DEVIN])
        self.assertEqual(doc["connector_hooks"], {DEVIN: {"enabled": True, "mode": "action"}})
        self.assertEqual(doc["application_protection"]["include_connectors"], ["cursor", DEVIN])
        self.assertEqual(doc["application_protection"]["exclude_connectors"], [DEVIN])
        self.assertEqual(doc["asset_policy"]["mcp"]["denied"][0]["connector"], DEVIN)
        self.assertEqual(doc["asset_policy"]["mcp"]["registry"][0]["connector"], DEVIN)
        self.assertEqual(doc["observability"]["destinations"][0]["routes"][0]["selector"]["connectors"], ["codex", DEVIN])

    def test_migration_deduplicates_a_list_that_already_names_devin(self):
        body = f"guardrail:\n  connector: codex\n  judge:\n    hook_connectors:\n      - {DEVIN}\n      - {RETIRED}\n"
        text, changes = self._run(body)
        self.assertEqual(len(changes), 1)
        self.assertEqual(yaml.safe_load(text)["guardrail"]["judge"]["hook_connectors"], [DEVIN])

    def test_migration_leaves_unaffected_config_alone(self):
        body = "guardrail:\n  connector: cursor\n"
        text, changes = self._run(body)
        self.assertEqual(text, body)
        self.assertEqual(changes, [])

    def test_migrate_runs_the_step_for_a_retired_name_only_in_a_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.yaml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(
                    f"config_version: 8\nguardrail:\n  connector: codex\napplication_protection:\n  exclude_connectors: [{RETIRED}]\n"
                )
            steps = migrations._pending_migration_steps(8, None, tmpdir, path, 8)
            self.assertEqual([fn for _name, fn in steps], [migrations._migrate_connector_roster])

    def test_migrate_runs_the_step_only_when_the_config_names_the_old_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.yaml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(f"config_version: 8\nguardrail:\n  connector: {RETIRED}\n")
            steps = migrations._pending_migration_steps(8, None, tmpdir, path, 8)
            self.assertEqual([fn for _name, fn in steps], [migrations._migrate_connector_roster])
            self.assertNotIn(RETIRED, steps[0][0].lower())
            with patch.object(migrations, "_refresh_local_observability_bundle", lambda *_args: None):
                result = migrations.migrate(tmpdir)
            self.assertTrue(result.changed)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(yaml.safe_load(fh)["guardrail"]["connector"], DEVIN)
            self.assertEqual(migrations._pending_migration_steps(8, None, tmpdir, path, 8), [])

    def test_the_frozen_0x_chain_does_not_grow(self):
        chain = [fn for _ver, _desc, fn in migrations.MIGRATIONS]
        self.assertNotIn(migrations._migrate_retired_desktop_connector, chain)
        self.assertNotIn(migrations._migrate_connector_roster, chain)


class UninstallMarkerTests(unittest.TestCase):
    def test_uninstall_includes_the_retired_marker(self):
        self.assertEqual(
            cmd_uninstall._CONNECTOR_BACKUP_MARKERS[RETIRED],
            legacy_connector.BACKUP_MARKERS[RETIRED],
        )
        with tempfile.TemporaryDirectory() as data_dir:
            marker = os.path.join(data_dir, legacy_connector.BACKUP_MARKERS[RETIRED][0])
            os.makedirs(os.path.dirname(marker))
            Path(marker).write_text("{}", encoding="utf-8")
            selected = cmd_uninstall._teardown_connectors(
                ("codex",),
                data_dir=data_dir,
                openclaw_config_file=os.path.join(data_dir, "openclaw.json"),
                include_openclaw=False,
            )
        self.assertEqual(selected, ("codex", RETIRED))


if __name__ == "__main__":
    unittest.main()
