# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw registry`` CLI subcommands.

Covers:

* non-interactive add / edit / list / show / remove (the surface the
  TUI and CI/CD pipelines call)
* validation of source ids, kinds, content types, and auth env names
* sync end-to-end with a stubbed adapter (no real HTTP)
* approve / reject / require admin verbs
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_registry import registry
from defenseclaw.models import Finding, ScanResult
from defenseclaw.registries.manifest import parse_manifest

from tests.helpers import cleanup_app, make_app_context


def _scan_clean(name: str) -> ScanResult:
    return ScanResult(
        scanner="test", target=name,
        timestamp=datetime.now(timezone.utc),
        findings=[],
    )


def _scan_high(name: str) -> ScanResult:
    return ScanResult(
        scanner="test", target=name,
        timestamp=datetime.now(timezone.utc),
        findings=[Finding(id="bad", severity="HIGH", title="bad",
                          scanner="test")],
    )


def _make_skill_manifest():
    return parse_manifest(json.dumps({
        "schema_version": 1,
        "publisher": "acme",
        "entries": [
            {
                "name": "demo-skill",
                "type": "skill",
                "source_url": "https://catalog.example.com/demo.tgz",
                "connector": "openclaw",
                "sha256": "a" * 64,
            }
        ],
    }))


class RegistryCommandTestBase(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        # Make sure save() actually has a path.
        self.app.cfg.config_path = os.path.join(self.tmp_dir, "config.yaml")
        # Save once so subsequent saves succeed.
        self.app.cfg.save()
        self._orig_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "200"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._orig_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._orig_columns

    def invoke(self, args):
        return self.runner.invoke(
            registry, args, obj=self.app, catch_exceptions=False,
        )


class TestRegistryAdd(RegistryCommandTestBase):
    def test_add_non_interactive_minimal(self):
        result = self.invoke([
            "add", "corp-skills",
            "--kind", "http_yaml",
            "--content", "skill",
            "--url", "https://catalog.example.com/skills.yaml",
            "--non-interactive",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        ids = [s.id for s in self.app.cfg.registries.sources]
        self.assertIn("corp-skills", ids)

    def test_add_clawhub_does_not_require_url(self):
        result = self.invoke([
            "add", "clawhub",
            "--kind", "clawhub",
            "--content", "skill",
            "--non-interactive",
        ])
        self.assertEqual(result.exit_code, 0, result.output)

    def test_add_smithery_does_not_require_url(self):
        result = self.invoke([
            "add", "smithery-public",
            "--kind", "smithery",
            "--content", "mcp",
            "--non-interactive",
        ])
        self.assertEqual(result.exit_code, 0, result.output)

    def test_add_http_yaml_requires_url(self):
        result = self.invoke([
            "add", "missing",
            "--kind", "http_yaml",
            "--content", "skill",
            "--non-interactive",
        ])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--url is required", result.output)

    def test_add_rejects_invalid_id(self):
        result = self.runner.invoke(registry, [
            "add", "Bad/ID",
            "--kind", "clawhub",
            "--content", "skill",
            "--non-interactive",
        ], obj=self.app, catch_exceptions=True)
        self.assertNotEqual(result.exit_code, 0)

    def test_add_rejects_unknown_kind(self):
        result = self.runner.invoke(registry, [
            "add", "x",
            "--kind", "made-up",
            "--content", "skill",
            "--non-interactive",
        ], obj=self.app, catch_exceptions=True)
        self.assertNotEqual(result.exit_code, 0)

    def test_add_rejects_invalid_auth_env(self):
        # auth_env must be an UPPERCASE_NAME, not a literal token.
        result = self.runner.invoke(registry, [
            "add", "corp-skills",
            "--kind", "http_yaml",
            "--content", "skill",
            "--url", "https://x/y.yaml",
            "--auth-env", "actual-secret-token-value",
            "--non-interactive",
        ], obj=self.app, catch_exceptions=True)
        self.assertNotEqual(result.exit_code, 0)

    def test_add_duplicate_rejected(self):
        self.invoke([
            "add", "dup",
            "--kind", "clawhub",
            "--content", "skill",
            "--non-interactive",
        ])
        result = self.invoke([
            "add", "dup",
            "--kind", "clawhub",
            "--content", "skill",
            "--non-interactive",
        ])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("already exists", result.output)

    def test_add_emits_json(self):
        result = self.invoke([
            "add", "corp-skills",
            "--kind", "clawhub",
            "--content", "skill",
            "--non-interactive",
            "--json",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["action"], "add")
        self.assertEqual(payload["source"]["id"], "corp-skills")


class TestRegistryListShow(RegistryCommandTestBase):
    def setUp(self):
        super().setUp()
        self.invoke([
            "add", "corp-skills",
            "--kind", "clawhub",
            "--content", "skill",
            "--non-interactive",
        ])

    def test_list_json(self):
        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["id"], "corp-skills")

    def test_show_json_includes_index_block(self):
        result = self.invoke(["show", "corp-skills", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertIn("source", payload)
        self.assertIn("index", payload)

    def test_show_unknown_source_errors(self):
        result = self.runner.invoke(
            registry, ["show", "nope"],
            obj=self.app, catch_exceptions=True,
        )
        self.assertNotEqual(result.exit_code, 0)


class TestRegistryEdit(RegistryCommandTestBase):
    def setUp(self):
        super().setUp()
        self.invoke([
            "add", "corp-skills",
            "--kind", "http_yaml",
            "--content", "skill",
            "--url", "https://catalog.example.com/skills.yaml",
            "--non-interactive",
        ])

    def test_edit_changes_kind(self):
        result = self.invoke([
            "edit", "corp-skills",
            "--kind", "http_json",
            "--non-interactive",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        src = next(s for s in self.app.cfg.registries.sources if s.id == "corp-skills")
        self.assertEqual(src.kind, "http_json")

    def test_edit_disable(self):
        self.invoke([
            "edit", "corp-skills",
            "--disabled",
            "--non-interactive",
        ])
        src = next(s for s in self.app.cfg.registries.sources if s.id == "corp-skills")
        self.assertFalse(src.enabled)

    def test_edit_clear_auth_env(self):
        self.invoke([
            "edit", "corp-skills",
            "--auth-env", "DEFENSECLAW_TOKEN",
            "--non-interactive",
        ])
        self.invoke([
            "edit", "corp-skills",
            "--clear-auth-env",
            "--non-interactive",
        ])
        src = next(s for s in self.app.cfg.registries.sources if s.id == "corp-skills")
        self.assertEqual(src.auth_env, "")


class TestRegistryRemove(RegistryCommandTestBase):
    def setUp(self):
        super().setUp()
        self.invoke([
            "add", "corp-skills",
            "--kind", "clawhub",
            "--content", "skill",
            "--non-interactive",
        ])

    def test_remove_drops_source(self):
        result = self.invoke([
            "remove", "corp-skills", "--non-interactive",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        ids = [s.id for s in self.app.cfg.registries.sources]
        self.assertNotIn("corp-skills", ids)

    def test_remove_clears_associated_asset_policy_rules(self):
        from defenseclaw.config import AssetPolicyRule

        # Pretend a prior sync had promoted a rule with our source's
        # reason. The remove command must wipe it.
        self.app.cfg.asset_policy.skill.registry.append(AssetPolicyRule(
            name="demo-skill",
            reason="registry:corp-skills",
        ))
        self.app.cfg.asset_policy.skill.registry.append(AssetPolicyRule(
            name="other",
            reason="registry:other-source",
        ))
        self.app.cfg.save()

        self.invoke(["remove", "corp-skills", "--non-interactive"])
        names = [r.name for r in self.app.cfg.asset_policy.skill.registry]
        self.assertNotIn("demo-skill", names)
        self.assertIn("other", names)


class TestRegistrySync(RegistryCommandTestBase):
    def setUp(self):
        super().setUp()
        self.invoke([
            "add", "corp-skills",
            "--kind", "http_yaml",
            "--content", "skill",
            "--url", "https://catalog.example.com/skills.yaml",
            "--non-interactive",
        ])

    def test_sync_promotes_clean_entry(self):
        manifest = _make_skill_manifest()
        raw = json.dumps(manifest.to_dict()).encode("utf-8")

        def _fetch(_source, *, allow_private=False):
            return manifest, raw

        with patch("defenseclaw.registries.sync.fetch_manifest", _fetch):
            with patch(
                "defenseclaw.commands.cmd_registry._make_scan_callback",
                return_value=lambda src, entry: _scan_clean(entry.name),
            ):
                result = self.invoke([
                    "sync", "corp-skills", "--json",
                ])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["promoted_skills"], 1)
        names = {r.name for r in self.app.cfg.asset_policy.skill.registry}
        self.assertEqual(names, {"demo-skill"})

    def test_sync_no_promote_skips_asset_policy(self):
        manifest = _make_skill_manifest()
        raw = json.dumps(manifest.to_dict()).encode("utf-8")

        def _fetch(_source, *, allow_private=False):
            return manifest, raw

        with patch("defenseclaw.registries.sync.fetch_manifest", _fetch):
            with patch(
                "defenseclaw.commands.cmd_registry._make_scan_callback",
                return_value=lambda src, entry: _scan_clean(entry.name),
            ):
                result = self.invoke([
                    "sync", "corp-skills", "--no-promote", "--json",
                ])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(self.app.cfg.asset_policy.skill.registry)

    def test_sync_all_and_explicit_id_mutually_exclusive(self):
        result = self.invoke([
            "sync", "corp-skills", "--all",
        ])
        self.assertNotEqual(result.exit_code, 0)


class TestRegistryApproveReject(RegistryCommandTestBase):
    def setUp(self):
        super().setUp()
        self.invoke([
            "add", "corp-skills",
            "--kind", "http_yaml",
            "--content", "skill",
            "--url", "https://catalog.example.com/skills.yaml",
            "--non-interactive",
        ])
        # Populate the cache via a sync first.
        manifest = _make_skill_manifest()
        raw = json.dumps(manifest.to_dict()).encode("utf-8")

        def _fetch(_source, *, allow_private=False):
            return manifest, raw

        with patch("defenseclaw.registries.sync.fetch_manifest", _fetch):
            with patch(
                "defenseclaw.commands.cmd_registry._make_scan_callback",
                return_value=lambda src, entry: _scan_clean(entry.name),
            ):
                self.invoke(["sync", "corp-skills"])

    def test_approve_marks_entry(self):
        result = self.invoke([
            "approve", "corp-skills", "demo-skill",
            "--type", "skill",
            "--no-repromote",
            "--json",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertTrue(payload["verdict"]["approved"])

    def test_reject_marks_entry(self):
        result = self.invoke([
            "reject", "corp-skills", "demo-skill",
            "--type", "skill",
            "--no-repromote",
            "--json",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertTrue(payload["verdict"]["rejected"])

    def test_approve_unknown_entry_errors(self):
        result = self.runner.invoke(registry, [
            "approve", "corp-skills", "missing",
            "--type", "skill", "--no-repromote",
        ], obj=self.app, catch_exceptions=True)
        self.assertNotEqual(result.exit_code, 0)


class TestRegistryRequire(RegistryCommandTestBase):
    def test_require_skill(self):
        result = self.invoke([
            "require", "--type", "skill", "--enabled", "--json",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(self.app.cfg.asset_policy.skill.registry_required)

    def test_require_disable(self):
        self.app.cfg.asset_policy.mcp.registry_required = True
        self.app.cfg.save()
        result = self.invoke([
            "require", "--type", "mcp", "--disabled", "--json",
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(self.app.cfg.asset_policy.mcp.registry_required)

    def test_require_plugin_rejected(self):
        # OTHER-5: --type plugin is no longer a valid choice. Nothing can
        # populate asset_policy.plugin.registry, so arming require here
        # would default-deny every plugin with no CLI recovery path.
        result = self.invoke([
            "require", "--type", "plugin", "--enabled",
        ])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not one of", result.output)
        # The command body never ran, so the flag stays untouched.
        self.assertFalse(self.app.cfg.asset_policy.plugin.registry_required)

    # -- OTHER-7: per-connector --connector write surface ------------------

    def _reload_cfg(self):
        """Save-and-reload the config from disk to assert the YAML round-trip
        (mirrors test_config's _save_and_reload)."""
        import defenseclaw.config as config_mod
        with patch.dict(os.environ, {"DEFENSECLAW_HOME": self.tmp_dir}):
            return config_mod.load()

    def _activate(self, *connectors):
        from defenseclaw.config import PerConnectorGuardrailConfig

        self.app.cfg.guardrail.connectors = {
            connector: PerConnectorGuardrailConfig()
            for connector in connectors
        }

    def test_require_per_connector_write(self):
        # --connector writes the per-connector override, NOT the global scalar.
        result = self.invoke([
            "require", "--type", "mcp", "--enabled",
            "--connector", "codex", "--json",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        ap = self.app.cfg.asset_policy
        self.assertIn("codex", ap.connectors)
        self.assertTrue(ap.connectors["codex"].mcp.registry_required)
        # Global scalar untouched — back-compat path is independent.
        self.assertFalse(ap.mcp.registry_required)
        out = json.loads(result.output)
        self.assertEqual(out["connector"], "codex")
        self.assertTrue(out["registry_required"])

    def test_require_global_reports_null_connector(self):
        # The bare (global) path keeps emitting connector=None.
        result = self.invoke([
            "require", "--type", "mcp", "--enabled", "--json",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        out = json.loads(result.output)
        self.assertIsNone(out["connector"])
        self.assertTrue(self.app.cfg.asset_policy.mcp.registry_required)
        self.assertEqual(self.app.cfg.asset_policy.connectors, {})

    def test_require_per_connector_roundtrip_preserves_global_and_peers(self):
        # A per-connector write must survive a save/reload AND leave the
        # global block + every other connector untouched.
        from defenseclaw.config import (
            PerConnectorAssetPolicy,
            PerConnectorAssetTypePolicy,
        )
        ap = self.app.cfg.asset_policy
        ap.enabled = True
        ap.skill.registry_required = True  # global scalar pre-armed
        ap.connectors["hermes"] = PerConnectorAssetPolicy(
            mode="observe",
            mcp=PerConnectorAssetTypePolicy(registry_required=False),
        )
        self.app.cfg.save()

        result = self.invoke([
            "require", "--type", "mcp", "--enabled", "--connector", "codex",
        ])
        self.assertEqual(result.exit_code, 0, result.output)

        reloaded = self._reload_cfg().asset_policy
        # New write survived the YAML round-trip.
        self.assertTrue(reloaded.connectors["codex"].mcp.registry_required)
        # Global scalar preserved.
        self.assertTrue(reloaded.skill.registry_required)
        # Peer connector preserved, not clobbered.
        self.assertIn("hermes", reloaded.connectors)
        self.assertEqual(reloaded.connectors["hermes"].mode, "observe")
        self.assertFalse(reloaded.connectors["hermes"].mcp.registry_required)
        # Config still validates (no alias collisions introduced).
        reloaded.validate()

    def test_require_per_connector_alias_reuse(self):
        # Writing via an alias-cased connector name must REUSE the existing
        # normalized key, not mint a colliding second entry that validate()
        # would reject on the next load.
        from defenseclaw.config import PerConnectorAssetPolicy
        self.app.cfg.asset_policy.connectors["codex"] = PerConnectorAssetPolicy(
            mode="action",
        )
        self.app.cfg.save()

        result = self.invoke([
            "require", "--type", "mcp", "--enabled", "--connector", "Codex",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        ap = self.app.cfg.asset_policy
        self.assertEqual(list(ap.connectors), ["codex"])  # no duplicate key
        self.assertEqual(ap.connectors["codex"].mode, "action")  # mode kept
        self.assertTrue(ap.connectors["codex"].mcp.registry_required)
        ap.validate()  # no alias collision raised

    def test_require_per_connector_disable(self):
        from defenseclaw.config import (
            PerConnectorAssetPolicy,
            PerConnectorAssetTypePolicy,
        )
        self.app.cfg.asset_policy.connectors["codex"] = PerConnectorAssetPolicy(
            mcp=PerConnectorAssetTypePolicy(registry_required=True),
        )
        self.app.cfg.save()
        result = self.invoke([
            "require", "--type", "mcp", "--disabled",
            "--connector", "codex", "--json",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(
            self.app.cfg.asset_policy.connectors["codex"].mcp.registry_required
        )

    def test_require_unscoped_reconciles_skill_and_mcp_both_directions(self):
        from defenseclaw.config import (
            AssetPolicyConfig,
            PerConnectorAssetPolicy,
            PerConnectorAssetTypePolicy,
        )

        cases = (
            ("skill", False, True, "codex"),
            ("skill", True, False, "codex"),
            ("mcp", False, True, "claudecode"),
            ("mcp", True, False, "claudecode"),
        )
        for asset_type, initial, requested, opposite_connector in cases:
            with self.subTest(
                asset_type=asset_type,
                initial=initial,
                requested=requested,
                opposite_connector=opposite_connector,
            ):
                self.app.cfg.asset_policy = AssetPolicyConfig()
                self._activate("codex", "claudecode")
                global_policy = getattr(self.app.cfg.asset_policy, asset_type)
                global_policy.registry_required = initial
                peer = "claudecode" if opposite_connector == "codex" else "codex"
                setattr(
                    self.app.cfg.asset_policy.connectors.setdefault(
                        opposite_connector, PerConnectorAssetPolicy(),
                    ),
                    asset_type,
                    PerConnectorAssetTypePolicy(registry_required=initial),
                )
                setattr(
                    self.app.cfg.asset_policy.connectors.setdefault(
                        peer, PerConnectorAssetPolicy(),
                    ),
                    asset_type,
                    PerConnectorAssetTypePolicy(registry_required=requested),
                )
                self.app.cfg.save()

                flag = "--enabled" if requested else "--disabled"
                result = self.invoke(["require", "--type", asset_type, flag, "--json"])

                self.assertEqual(result.exit_code, 0, result.output)
                payload = json.loads(result.output)
                self.assertEqual(payload["changed_connectors"], [opposite_connector])
                self.assertEqual(payload["already_compliant_connectors"], [peer])
                self.assertEqual(payload["failed_connectors"], [])
                self.assertEqual(payload["active_connectors"], ["claudecode", "codex"])
                self.assertEqual(
                    getattr(self.app.cfg.asset_policy, asset_type).registry_required,
                    requested,
                )
                for connector in ("codex", "claudecode"):
                    effective = self.app.cfg.asset_policy.effective_asset_type_policy(
                        connector, asset_type,
                    )
                    self.assertEqual(effective.registry_required, requested)
                    block = getattr(self.app.cfg.asset_policy.connectors[connector], asset_type)
                    self.assertIsNone(block.registry_required)

    def test_require_unscoped_preserves_unrelated_fields_rules_filters_and_inactive_override(self):
        from defenseclaw.config import (
            AssetPolicyRule,
            PerConnectorAssetPolicy,
            PerConnectorAssetTypePolicy,
        )

        self._activate("codex", "claudecode")
        ap = self.app.cfg.asset_policy
        ap.mode = "action"
        ap.skill.registry_required = False
        ap.skill.registry = [AssetPolicyRule(name="approved", connector="codex", reason="registry:corp")]
        ap.skill.allowed = [AssetPolicyRule(name="manual", connector="claudecode")]
        ap.skill.denied = [AssetPolicyRule(name="blocked", connector="codex")]
        ap.connectors = {
            "codex": PerConnectorAssetPolicy(
                mode="observe",
                skill=PerConnectorAssetTypePolicy(
                    default="deny",
                    registry_required=False,
                    registry_empty_action="warn",
                ),
                mcp=PerConnectorAssetTypePolicy(
                    default="allow",
                    registry_required=True,
                    registry_empty_action="allow",
                ),
            ),
            "claudecode": PerConnectorAssetPolicy(
                skill=PerConnectorAssetTypePolicy(registry_required=False),
            ),
            "cursor": PerConnectorAssetPolicy(
                mode="action",
                skill=PerConnectorAssetTypePolicy(
                    default="deny",
                    registry_required=False,
                    registry_empty_action="deny",
                ),
            ),
        }
        self.app.cfg.save()

        result = self.invoke(["require", "--type", "skill", "--enabled", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["preserved_inactive_connectors"], ["cursor"])
        reloaded = self._reload_cfg().asset_policy
        self.assertTrue(reloaded.skill.registry_required)
        self.assertEqual(reloaded.skill.registry[0].connector, "codex")
        self.assertEqual(reloaded.skill.registry[0].reason, "registry:corp")
        self.assertEqual(reloaded.skill.allowed[0].connector, "claudecode")
        self.assertEqual(reloaded.skill.denied[0].connector, "codex")
        codex = reloaded.connectors["codex"]
        self.assertEqual(codex.mode, "observe")
        self.assertEqual(codex.skill.default, "deny")
        self.assertEqual(codex.skill.registry_empty_action, "warn")
        self.assertIsNone(codex.skill.registry_required)
        self.assertTrue(codex.mcp.registry_required)
        self.assertEqual(codex.mcp.registry_empty_action, "allow")
        cursor = reloaded.connectors["cursor"]
        self.assertEqual(cursor.mode, "action")
        self.assertFalse(cursor.skill.registry_required)
        self.assertEqual(cursor.skill.default, "deny")

    def test_require_scoped_updates_only_selected_connector_for_codex_and_claude(self):
        from defenseclaw.config import (
            AssetPolicyConfig,
            PerConnectorAssetPolicy,
            PerConnectorAssetTypePolicy,
        )

        for selected, peer in (("codex", "claudecode"), ("claudecode", "codex")):
            with self.subTest(selected=selected):
                self.app.cfg.asset_policy = AssetPolicyConfig()
                self._activate("codex", "claudecode")
                self.app.cfg.asset_policy.skill.registry_required = False
                self.app.cfg.asset_policy.connectors = {
                    "codex": PerConnectorAssetPolicy(
                        mode="action",
                        skill=PerConnectorAssetTypePolicy(
                            default="deny", registry_required=False, registry_empty_action="warn",
                        ),
                    ),
                    "claudecode": PerConnectorAssetPolicy(
                        mode="observe",
                        skill=PerConnectorAssetTypePolicy(
                            default="allow", registry_required=False, registry_empty_action="allow",
                        ),
                    ),
                }
                self.app.cfg.save()
                peer_before = self.app.cfg.asset_policy.connectors[peer].skill

                result = self.invoke([
                    "require", "--type", "skill", "--enabled",
                    "--connector", selected, "--json",
                ])

                self.assertEqual(result.exit_code, 0, result.output)
                payload = json.loads(result.output)
                self.assertEqual(payload["connector"], selected)
                self.assertEqual(payload["changed_connectors"], [selected])
                self.assertFalse(self.app.cfg.asset_policy.skill.registry_required)
                selected_block = self.app.cfg.asset_policy.connectors[selected].skill
                self.assertTrue(selected_block.registry_required)
                self.assertEqual(selected_block.default, "deny" if selected == "codex" else "allow")
                peer_after = self.app.cfg.asset_policy.connectors[peer].skill
                self.assertEqual(peer_after, peer_before)

    def test_require_unscoped_is_idempotent_and_reports_already_compliant(self):
        self._activate("codex", "claudecode")

        first = self.invoke(["require", "--type", "mcp", "--enabled", "--json"])
        second = self.invoke(["require", "--type", "mcp", "--enabled", "--json"])

        self.assertEqual(first.exit_code, 0, first.output)
        self.assertEqual(second.exit_code, 0, second.output)
        payload = json.loads(second.output)
        self.assertEqual(payload["changed_connectors"], [])
        self.assertEqual(payload["already_compliant_connectors"], ["claudecode", "codex"])
        self.assertFalse(payload["global_changed"])

    def test_require_uses_normalized_active_roster_and_existing_alias_key(self):
        from defenseclaw.config import (
            PerConnectorAssetPolicy,
            PerConnectorAssetTypePolicy,
        )

        self._activate("Codex", "open-hands")
        self.app.cfg.asset_policy.connectors = {
            "codex": PerConnectorAssetPolicy(
                mcp=PerConnectorAssetTypePolicy(registry_required=False),
            ),
            "open_hands": PerConnectorAssetPolicy(
                mcp=PerConnectorAssetTypePolicy(registry_required=False),
            ),
        }
        self.app.cfg.save()

        result = self.invoke(["require", "--type", "mcp", "--enabled", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["active_connectors"], ["codex", "openhands"])
        self.assertIsNone(self.app.cfg.asset_policy.connectors["codex"].mcp.registry_required)
        self.assertIsNone(self.app.cfg.asset_policy.connectors["open_hands"].mcp.registry_required)
        self.assertNotIn("openhands", self.app.cfg.asset_policy.connectors)

    def test_require_verification_failure_rolls_back_and_reports_failed_connectors(self):
        import yaml
        from defenseclaw.config import (
            PerConnectorAssetPolicy,
            PerConnectorAssetTypePolicy,
        )

        self._activate("codex", "claudecode")
        self.app.cfg.asset_policy.skill.registry_required = False
        self.app.cfg.asset_policy.connectors["codex"] = PerConnectorAssetPolicy(
            skill=PerConnectorAssetTypePolicy(registry_required=False),
        )
        self.app.cfg.save()
        config_path = os.path.join(self.tmp_dir, "config.yaml")
        with open(config_path, encoding="utf-8") as stream:
            before = yaml.safe_load(stream)

        with patch(
            "defenseclaw.registry_policy._verify_registry_required",
            side_effect=RuntimeError("verification fixture"),
        ):
            result = self.invoke(["require", "--type", "skill", "--enabled", "--json"])

        self.assertEqual(result.exit_code, 1, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["failed_connectors"], ["claudecode", "codex"])
        self.assertEqual(payload["changed_connectors"], [])
        with open(config_path, encoding="utf-8") as stream:
            self.assertEqual(yaml.safe_load(stream), before)
        self.assertFalse(self.app.cfg.asset_policy.skill.registry_required)
        self.assertFalse(
            self.app.cfg.asset_policy.effective_asset_type_policy("codex", "skill").registry_required
        )

    def test_require_write_failure_keeps_previous_configuration_and_exits_nonzero(self):
        import yaml

        self._activate("codex", "claudecode")
        self.app.cfg.asset_policy.mcp.registry_required = False
        self.app.cfg.save()
        config_path = os.path.join(self.tmp_dir, "config.yaml")
        with open(config_path, encoding="utf-8") as stream:
            before = yaml.safe_load(stream)

        with patch(
            "defenseclaw.config.write_config_yaml_secure",
            side_effect=OSError("write fixture"),
        ):
            result = self.invoke(["require", "--type", "mcp", "--enabled", "--json"])

        self.assertEqual(result.exit_code, 1, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["failed_connectors"], ["claudecode", "codex"])
        with open(config_path, encoding="utf-8") as stream:
            self.assertEqual(yaml.safe_load(stream), before)
        self.assertFalse(self.app.cfg.asset_policy.mcp.registry_required)


class TestFileAdapterPathValidation(RegistryCommandTestBase):
    """``kind=file`` requires an absolute path so ``manifest.yaml`` is
    found regardless of the gateway's CWD. The check must fire at
    add/edit time so a misconfigured source is caught up-front rather
    than ten minutes later when cron tries to sync.
    """

    def test_add_file_kind_rejects_relative_path(self):
        result = self.runner.invoke(registry, [
            "add", "local",
            "--kind", "file",
            "--content", "skill",
            "--url", "manifest.yaml",
            "--non-interactive",
        ], obj=self.app, catch_exceptions=True)
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("absolute", str(result.output) + str(result.exception))

    def test_add_file_kind_accepts_absolute_path(self):
        result = self.invoke([
            "add", "local",
            "--kind", "file",
            "--content", "skill",
            "--url", "/tmp/manifest.yaml",
            "--non-interactive",
        ])
        self.assertEqual(result.exit_code, 0, result.output)

    def test_add_file_kind_accepts_tilde_expansion(self):
        # ``~/manifest.yaml`` expands to an absolute path so it should
        # pass; the file adapter does the same expansion on read.
        result = self.invoke([
            "add", "local",
            "--kind", "file",
            "--content", "skill",
            "--url", "~/manifest.yaml",
            "--non-interactive",
        ])
        self.assertEqual(result.exit_code, 0, result.output)

    def test_edit_to_file_kind_rejects_relative_url(self):
        # Start with an http_yaml source, then flip to kind=file with
        # a relative URL — the post-edit pair is invalid and must be
        # rejected before save().
        self.invoke([
            "add", "local",
            "--kind", "http_yaml",
            "--content", "skill",
            "--url", "https://catalog.example.com/skills.yaml",
            "--non-interactive",
        ])
        result = self.runner.invoke(registry, [
            "edit", "local",
            "--kind", "file",
            "--url", "relative/path.yaml",
            "--non-interactive",
        ], obj=self.app, catch_exceptions=True)
        self.assertNotEqual(result.exit_code, 0)


class TestRegistryEntriesFilters(RegistryCommandTestBase):
    """``entries --approved`` / ``--rejected`` filter on the operator
    override bits independently of ``--status``. Both filters together
    return the empty set because approve/reject are mutually exclusive.
    """

    def setUp(self):
        super().setUp()
        self.invoke([
            "add", "corp-skills",
            "--kind", "http_yaml",
            "--content", "skill",
            "--url", "https://catalog.example.com/skills.yaml",
            "--non-interactive",
        ])
        # Populate two entries, one to approve and one to reject.
        manifest = parse_manifest(json.dumps({
            "schema_version": 1,
            "entries": [
                {"name": "approved-one", "type": "skill",
                 "source_url": "https://x/1"},
                {"name": "rejected-one", "type": "skill",
                 "source_url": "https://x/2"},
            ],
        }))
        raw = json.dumps(manifest.to_dict()).encode("utf-8")
        with patch(
            "defenseclaw.registries.sync.fetch_manifest",
            lambda src, *, allow_private=False: (manifest, raw),
        ), patch(
            "defenseclaw.commands.cmd_registry._make_scan_callback",
            return_value=lambda src, entry: _scan_clean(entry.name),
        ):
            self.invoke(["sync", "corp-skills"])

        # Approve one, reject the other (no repromote so we don't
        # need the scanner stub here).
        self.invoke([
            "approve", "corp-skills", "approved-one",
            "--type", "skill", "--no-repromote",
        ])
        self.invoke([
            "reject", "corp-skills", "rejected-one",
            "--type", "skill", "--no-repromote",
        ])

    def test_entries_approved_only(self):
        result = self.invoke([
            "entries", "corp-skills", "--approved", "--json",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        names = {row["name"] for row in json.loads(result.output)}
        self.assertEqual(names, {"approved-one"})

    def test_entries_rejected_only(self):
        result = self.invoke([
            "entries", "corp-skills", "--rejected", "--json",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        rows = json.loads(result.output)
        names = {row["name"] for row in rows}
        self.assertEqual(names, {"rejected-one"})
        # The reject path also flips ``status`` to ``blocked`` so the
        # operator's call survives both filter shapes.
        self.assertEqual(rows[0]["status"], "blocked")

    def test_entries_status_blocked_includes_rejected(self):
        # Cross-check: the reject above should land on the
        # ``--status blocked`` filter as well, not just on
        # ``--rejected``. This is the regression the
        # ``manual_set_verdict`` fix targets.
        result = self.invoke([
            "entries", "corp-skills",
            "--status", "blocked",
            "--json",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        names = {row["name"] for row in json.loads(result.output)}
        self.assertEqual(names, {"rejected-one"})

    def test_entries_approved_and_rejected_returns_empty(self):
        # Mutual exclusivity by definition.
        result = self.invoke([
            "entries", "corp-skills",
            "--approved", "--rejected",
            "--json",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(result.output), [])


class TestRegistryListEntryCounts(RegistryCommandTestBase):
    """``registry list --json`` should embed the cached entry count
    summary so the TUI / CI can show "10 (8/1/1)" without hitting the
    network. A source that has never synced reports no ``entries``
    sub-block.
    """

    def setUp(self):
        super().setUp()
        self.invoke([
            "add", "corp-skills",
            "--kind", "http_yaml",
            "--content", "skill",
            "--url", "https://catalog.example.com/skills.yaml",
            "--non-interactive",
        ])

    def test_list_json_includes_entry_summary_after_sync(self):
        manifest = _make_skill_manifest()
        raw = json.dumps(manifest.to_dict()).encode("utf-8")
        with patch(
            "defenseclaw.registries.sync.fetch_manifest",
            lambda src, *, allow_private=False: (manifest, raw),
        ), patch(
            "defenseclaw.commands.cmd_registry._make_scan_callback",
            return_value=lambda src, entry: _scan_clean(entry.name),
        ):
            self.invoke(["sync", "corp-skills"])

        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(len(payload), 1)
        self.assertIn("entries", payload[0])
        self.assertEqual(payload[0]["entries"]["total"], 1)
        self.assertEqual(payload[0]["entries"]["clean"], 1)


class TestRegistryTest(RegistryCommandTestBase):
    """``registry test`` should fetch + parse without writing any
    cache or asset_policy state, and surface a structured summary
    so CI checks can gate a sync on a clean dry-run.
    """

    def setUp(self):
        super().setUp()
        self.invoke([
            "add", "corp-skills",
            "--kind", "http_yaml",
            "--content", "skill",
            "--url", "https://catalog.example.com/skills.yaml",
            "--non-interactive",
        ])

    def test_test_does_not_write_cache_or_policy(self):
        from defenseclaw.registries.cache import index_path, manifest_path

        manifest = _make_skill_manifest()
        raw = json.dumps(manifest.to_dict()).encode("utf-8")

        def _fetch(_source, *, allow_private=False):
            return manifest, raw

        with patch("defenseclaw.registries.adapters.fetch_manifest", _fetch):
            with patch(
                "defenseclaw.commands.cmd_registry.fetch_manifest", _fetch,
            ):
                result = self.invoke(["test", "corp-skills", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["entries"]["total"], 1)
        self.assertEqual(payload["entries"]["skills"], 1)
        # Critical: no on-disk side effects.
        self.assertFalse(index_path(self.app.cfg.data_dir, "corp-skills").exists())
        self.assertFalse(manifest_path(self.app.cfg.data_dir, "corp-skills").exists())
        # And asset_policy is untouched.
        self.assertEqual(self.app.cfg.asset_policy.skill.registry, [])

    def test_test_surfaces_fetch_error_with_nonzero_exit(self):
        from defenseclaw.registries.adapters import IngestError

        def _bad(_source, *, allow_private=False):
            raise IngestError("synthetic")

        with patch(
            "defenseclaw.commands.cmd_registry.fetch_manifest", _bad,
        ):
            result = self.runner.invoke(registry, [
                "test", "corp-skills", "--json",
            ], obj=self.app, catch_exceptions=True)
        self.assertNotEqual(result.exit_code, 0)
        # Output may be on stdout (--json branch) or stderr.
        stream = result.output or ""
        if stream.strip().startswith("{"):
            payload = json.loads(stream)
            self.assertFalse(payload["ok"])
            self.assertIn("synthetic", payload["error"])

    def test_test_show_entries_lists_rows(self):
        manifest = _make_skill_manifest()
        raw = json.dumps(manifest.to_dict()).encode("utf-8")
        with patch(
            "defenseclaw.commands.cmd_registry.fetch_manifest",
            lambda src, *, allow_private=False: (manifest, raw),
        ):
            result = self.invoke([
                "test", "corp-skills",
                "--show-entries", "--limit", "5", "--json",
            ])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertIn("rows", payload["entries"])
        self.assertEqual(len(payload["entries"]["rows"]), 1)
        self.assertEqual(payload["entries"]["rows"][0]["name"], "demo-skill")


class TestRegistryEditPromptShortCircuit(RegistryCommandTestBase):
    """Per the ``edit`` docstring, only the flags you pass are changed.
    When **any** mutating flag is provided we must skip the interactive
    prompts entirely so a non-TTY caller (TUI, cron, CI) doesn't hang
    waiting for stdin even without ``--non-interactive``.
    """

    def setUp(self):
        super().setUp()
        self.invoke([
            "add", "corp-skills",
            "--kind", "http_yaml",
            "--content", "skill",
            "--url", "https://catalog.example.com/skills.yaml",
            "--non-interactive",
        ])

    def test_edit_with_single_flag_does_not_prompt(self):
        # Run without --non-interactive but with a mutating flag. The
        # CliRunner's stdin is closed by default; if the command tries
        # to prompt for any other field, the click.prompt call would
        # raise and the exit code would be non-zero.
        result = self.invoke([
            "edit", "corp-skills",
            "--disabled",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        src = next(
            s for s in self.app.cfg.registries.sources
            if s.id == "corp-skills"
        )
        self.assertFalse(src.enabled)
        # And nothing else changed.
        self.assertEqual(src.kind, "http_yaml")
        self.assertEqual(src.url, "https://catalog.example.com/skills.yaml")


if __name__ == "__main__":
    unittest.main()
