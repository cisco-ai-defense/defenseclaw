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


if __name__ == "__main__":
    unittest.main()
