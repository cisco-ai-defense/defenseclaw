# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests for the registry sync pipeline.

We bypass the live HTTP / git adapters by injecting a stub
``fetch_manifest`` so the tests are hermetic. The verdict-promotion
logic, manual approve/reject overrides, and ``asset_policy`` mutation
are all exercised against an in-memory :class:`Config` and a temp
``data_dir``.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# All imports live below the sys.path tweak above so the test runner
# resolves `defenseclaw.*` against the repo source rather than any
# globally-installed copy. The E402 noqa keeps ruff quiet about the
# intentional ordering — see the BuildPlanTests block in
# test_cmd_uninstall.py for the same idiom.
from defenseclaw.config import RegistrySource  # noqa: E402
from defenseclaw.models import Finding, ScanResult  # noqa: E402
from defenseclaw.registries.cache import (  # noqa: E402
    EntryVerdict,
    SourceIndex,
    load_index,
    save_index,
)
from defenseclaw.registries.manifest import parse_manifest  # noqa: E402
from defenseclaw.registries.sync import (  # noqa: E402
    manual_set_verdict,
    sync_all,
    sync_source,
)

from tests.helpers import make_temp_config  # noqa: E402


def _scan_result(target: str, findings=None) -> ScanResult:
    return ScanResult(
        scanner="test",
        target=target,
        timestamp=datetime.now(timezone.utc),
        findings=list(findings or []),
    )


def _finding(severity: str, target: str = "x") -> Finding:
    return Finding(
        id=f"FND-{target}-{severity}",
        severity=severity,
        title=f"{severity} demo",
        scanner="test",
    )


def _fresh_skill_manifest():
    return parse_manifest(json.dumps({
        "schema_version": 1,
        "publisher": "acme",
        "entries": [
            {
                "name": "demo-skill",
                "type": "skill",
                "source_url": "clawhub://demo-skill",
                "connector": "openclaw",
            },
            {
                "name": "another-skill",
                "type": "skill",
                "source_url": "clawhub://another-skill",
            },
        ],
    }))


def _fresh_mcp_manifest():
    return parse_manifest(json.dumps({
        "schema_version": 1,
        "entries": [
            {
                "name": "demo-mcp",
                "type": "mcp",
                "transport": "stdio",
                "command": "npx",
                "args": ["-y", "@scope/server"],
            }
        ],
    }))


def _patch_fetch(monkeypatch, manifest):
    """Inject a stub fetch_manifest that returns *manifest* every time."""
    raw = json.dumps(manifest.to_dict()).encode("utf-8")

    def _stub(_source, *, allow_private=False):
        return manifest, raw

    monkeypatch.setattr(
        "defenseclaw.registries.sync.fetch_manifest",
        _stub,
    )


class SyncTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-reg-test-")
        self.cfg = make_temp_config(self.tmp_dir)
        self.source = RegistrySource(
            id="demo",
            kind="http_yaml",
            url="https://catalog.example.com/m.yaml",
            content="both",
            enabled=True,
        )
        self.cfg.registries.sources.append(self.source)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def stub_fetch(self, manifest):
        raw = json.dumps(manifest.to_dict()).encode("utf-8")
        patcher = patch(
            "defenseclaw.registries.sync.fetch_manifest",
            lambda source, *, allow_private=False: (manifest, raw),
        )
        patcher.start()
        self.addCleanup(patcher.stop)


class TestPromotion(SyncTestBase):
    def test_clean_skill_promoted_to_asset_policy(self):
        self.stub_fetch(_fresh_skill_manifest())
        report = sync_source(
            self.cfg, self.cfg.data_dir, self.source,
            scan_callback=None,
            auto_promote=True,
            save=False,
        )
        # No scanner attached → entries stay pending → not promoted.
        self.assertEqual(report.promoted_skills, 0)

    def test_clean_scan_result_drives_promotion(self):
        manifest = _fresh_skill_manifest()
        self.stub_fetch(manifest)

        def _scan(_src, entry):
            return _scan_result(entry.name)

        report = sync_source(
            self.cfg, self.cfg.data_dir, self.source,
            scan_callback=_scan,
            auto_promote=True,
            save=False,
        )
        self.assertEqual(report.promoted_skills, 2)
        self.assertEqual(report.scanned, 2)
        self.assertEqual(report.blocked, 0)
        self.assertEqual(
            {r.name for r in self.cfg.asset_policy.skill.registry},
            {"demo-skill", "another-skill"},
        )
        for rule in self.cfg.asset_policy.skill.registry:
            self.assertEqual(rule.reason, f"registry:{self.source.id}")

    def test_high_severity_blocks_entry(self):
        manifest = _fresh_skill_manifest()
        self.stub_fetch(manifest)

        def _scan(_src, entry):
            findings = []
            if entry.name == "demo-skill":
                findings = [_finding("HIGH", entry.name)]
            return _scan_result(entry.name, findings)

        report = sync_source(
            self.cfg, self.cfg.data_dir, self.source,
            scan_callback=_scan,
            auto_promote=True,
            save=False,
        )
        # Only the clean entry promoted, the HIGH one blocked.
        self.assertEqual(report.promoted_skills, 1)
        self.assertEqual(report.blocked, 1)
        names = {r.name for r in self.cfg.asset_policy.skill.registry}
        self.assertEqual(names, {"another-skill"})

    def test_rejected_entry_never_promoted(self):
        manifest = _fresh_skill_manifest()
        self.stub_fetch(manifest)

        def _scan(_src, entry):
            return _scan_result(entry.name)

        # First sync to populate the index, then reject one entry.
        sync_source(self.cfg, self.cfg.data_dir, self.source,
                    scan_callback=_scan, auto_promote=False, save=False)
        manual_set_verdict(
            self.cfg.data_dir, self.source.id, "skill", "demo-skill",
            rejected=True,
        )

        report = sync_source(
            self.cfg, self.cfg.data_dir, self.source,
            scan_callback=_scan,
            auto_promote=True,
            save=False,
        )
        self.assertEqual(report.promoted_skills, 1)
        names = {r.name for r in self.cfg.asset_policy.skill.registry}
        self.assertEqual(names, {"another-skill"})

    def test_approved_entry_promoted_without_scanner(self):
        manifest = _fresh_skill_manifest()
        self.stub_fetch(manifest)

        # First, baseline sync with no scanner — entries stay pending.
        sync_source(self.cfg, self.cfg.data_dir, self.source,
                    scan_callback=None, auto_promote=True, save=False)
        # Operator manually approves one entry.
        manual_set_verdict(
            self.cfg.data_dir, self.source.id, "skill", "demo-skill",
            approved=True,
        )

        report = sync_source(
            self.cfg, self.cfg.data_dir, self.source,
            scan_callback=None,
            auto_promote=True,
            save=False,
        )
        self.assertEqual(report.promoted_skills, 1)
        names = {r.name for r in self.cfg.asset_policy.skill.registry}
        self.assertEqual(names, {"demo-skill"})


class TestPromotionWipeBeforeReplace(SyncTestBase):
    def test_remove_from_manifest_clears_old_rule(self):
        manifest_v1 = _fresh_skill_manifest()
        manifest_v2 = parse_manifest(json.dumps({
            "schema_version": 1,
            "entries": [{
                "name": "another-skill", "type": "skill",
                "source_url": "clawhub://another-skill",
            }],
        }))

        # Switchable stub — drive the same patch through two phases so
        # we don't have to juggle cleanup callbacks.
        state = {"manifest": manifest_v1}

        def _stub(_source, *, allow_private=False):
            m = state["manifest"]
            return m, json.dumps(m.to_dict()).encode("utf-8")

        with patch("defenseclaw.registries.sync.fetch_manifest", _stub):
            def _scan(_src, entry):
                return _scan_result(entry.name)

            sync_source(self.cfg, self.cfg.data_dir, self.source,
                        scan_callback=_scan, auto_promote=True, save=False)
            self.assertEqual(len(self.cfg.asset_policy.skill.registry), 2)

            state["manifest"] = manifest_v2
            sync_source(self.cfg, self.cfg.data_dir, self.source,
                        scan_callback=_scan, auto_promote=True, save=False)
            names = {r.name for r in self.cfg.asset_policy.skill.registry}
            self.assertEqual(names, {"another-skill"})


class TestErrorPath(SyncTestBase):
    def test_fetch_failure_recorded_on_source(self):
        from defenseclaw.registries.adapters import IngestError

        def _bad_fetch(_source, *, allow_private=False):
            raise IngestError("boom")

        with patch("defenseclaw.registries.sync.fetch_manifest", _bad_fetch):
            report = sync_source(
                self.cfg, self.cfg.data_dir, self.source,
                scan_callback=None,
                auto_promote=True,
                save=False,
            )
        self.assertFalse(report.ok())
        self.assertTrue(report.errors)
        self.assertIn("error:", self.source.last_status)


class TestSyncAll(SyncTestBase):
    def test_disabled_sources_skipped_by_default(self):
        self.source.enabled = False
        manifest = _fresh_skill_manifest()
        self.stub_fetch(manifest)
        reports = sync_all(self.cfg, self.cfg.data_dir, scan_callback=None)
        self.assertEqual(reports, [])

    def test_include_disabled_runs_them(self):
        self.source.enabled = False
        manifest = _fresh_skill_manifest()
        self.stub_fetch(manifest)
        reports = sync_all(
            self.cfg, self.cfg.data_dir,
            scan_callback=None, include_disabled=True,
        )
        self.assertEqual(len(reports), 1)


class TestCacheIO(unittest.TestCase):
    def test_save_then_load_round_trip(self):
        tmp_dir = tempfile.mkdtemp(prefix="dclaw-reg-cache-")
        try:
            idx = SourceIndex(
                source_id="demo",
                fetched_at="2026-05-07T00:00:00Z",
                publisher="acme",
                verdicts=[
                    EntryVerdict(name="x", type="skill", status="clean"),
                    EntryVerdict(name="y", type="mcp", status="warning",
                                 severity="MEDIUM", findings=2),
                ],
            )
            save_index(tmp_dir, "demo", idx)
            loaded = load_index(tmp_dir, "demo")
            self.assertEqual(loaded.source_id, "demo")
            self.assertEqual(loaded.publisher, "acme")
            self.assertEqual(loaded.entry_count, 2)
            self.assertEqual(loaded.clean_count, 1)
            self.assertEqual(loaded.warning_count, 1)
            self.assertEqual({v.name for v in loaded.verdicts}, {"x", "y"})
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_corrupt_index_returns_empty(self):
        tmp_dir = tempfile.mkdtemp(prefix="dclaw-reg-cache-")
        try:
            d = os.path.join(tmp_dir, "registries", "demo")
            os.makedirs(d, mode=0o700, exist_ok=True)
            with open(os.path.join(d, "index.json"), "w") as f:
                f.write("not json")
            idx = load_index(tmp_dir, "demo")
            self.assertEqual(idx.entry_count, 0)
            self.assertEqual(idx.source_id, "demo")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_unsafe_source_id_rejected(self):
        from defenseclaw.registries.cache import source_dir

        with self.assertRaises(ValueError):
            source_dir(tempfile.gettempdir(), "../escape")
        with self.assertRaises(ValueError):
            source_dir(tempfile.gettempdir(), "a/b")


if __name__ == "__main__":
    unittest.main()
