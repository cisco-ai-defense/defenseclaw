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

"""Tests for 'defenseclaw skill' command group — block, allow, scan, quarantine, restore, list, info, search."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import click

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_skill import (
    _apply_scan_enforcement,
    _build_scan_map,
    _get_openclaw_skill_info,
    _skill_display_name,
    _skill_install_targets,
    _skill_status_display,
    skill,
)
from defenseclaw.config import SeverityAction
from defenseclaw.enforce import asset_lists
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.hermes_skills import directory_md5
from defenseclaw.models import ActionState, Finding, ScanResult

from tests.environment import requires_symlink_privilege
from tests.helpers import cleanup_app, make_app_context


def _installed_path(path):
    """The install path of a copy an install staged in its own
    ``.dclaw-stage-*`` directory (scanners see the staged copy, or a
    connector's own copy inside it when connectors share the path)."""
    parent = os.path.dirname(path)
    while os.path.basename(parent).startswith(".dclaw-stage-"):
        path = os.path.join(os.path.dirname(parent), os.path.basename(path))
        parent = os.path.dirname(path)
    return path


class SkillCommandTestBase(unittest.TestCase):
    """Base class that sets up an AppContext with temp store for skill command tests."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self._orig_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "200"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._orig_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._orig_columns

    def invoke(self, args: list[str]):
        return self.runner.invoke(skill, args, obj=self.app, catch_exceptions=False)


class TestOpenClawSkillInfo(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_skill._run_openclaw", return_value='{"error": ""}')
    def test_empty_error_field_is_still_an_error(self, _mock_run):
        self.assertIsNone(_get_openclaw_skill_info("missing"))


class TestSkillInstallTargets(unittest.TestCase):
    def test_uses_connector_write_scope_instead_of_discovery_precedence(self):
        cfg = SimpleNamespace(
            skill_dirs=lambda _connector: ["/global/discovery"],
            skill_write_dirs=lambda _connector: ["/workspace/.agents/skills"],
        )
        app = SimpleNamespace(cfg=cfg)

        self.assertEqual(
            _skill_install_targets(app, ["amp"], explicit_connector=True),
            [("amp", "/workspace/.agents/skills")],
        )

        self.assertEqual(
            _skill_install_targets(app, ["opencode"], explicit_connector=True),
            [("opencode", "/workspace/.agents/skills")],
        )


class TestSkillBlock(SkillCommandTestBase):
    def test_block_adds_to_block_list(self):
        result = self.invoke(["block", "evil-skill", "--reason", "malware detected"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("evil-skill", result.output)
        self.assertIn("[skill] Blocked 'evil-skill' (every connector).", result.output)

        pe = PolicyEngine(self.app.store, self.app.cfg)
        self.assertTrue(pe.is_blocked("skill", "evil-skill"))

    def test_block_logs_action(self):
        self.invoke(["block", "evil-skill", "--reason", "test"])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "skill-block"]
        self.assertEqual(len(actions), 1)
        self.assertIn("test", actions[0].details)

    def test_block_and_allow_refuse_blank_and_path_names(self):
        # GAP-0416: '' and ' ' wrote rules that match nothing, and a path was
        # quietly cut to its last part.
        for verb in ("block", "allow"):
            for name in ("", " ", "../../etc/x", "/path/to/evil-skill"):
                with self.subTest(verb=verb, name=name):
                    result = self.invoke([verb, name])
                    self.assertEqual(result.exit_code, 2, result.output)
        self.assertEqual(self.app.cfg.asset_policy.skill.denied, [])
        self.assertEqual(self.app.cfg.asset_policy.skill.allowed, [])

    def test_hermes_unchanged_bundled_skill_cannot_be_blocked_or_quarantined(self):
        hermes_home = os.path.join(self.tmp_dir, "hermes")
        skill_root = os.path.join(hermes_home, "skills")
        skill_dir = os.path.join(skill_root, "productivity", "vendor-docs")
        os.makedirs(skill_dir)
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("---\nname: vendor-docs\n---\n")
        source_dir = os.path.join(
            hermes_home,
            "hermes-agent",
            "skills",
            "productivity",
            "vendor-docs",
        )
        os.makedirs(source_dir)
        with open(os.path.join(source_dir, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("---\nname: vendor-docs\n---\n")
        origin_hash = directory_md5(skill_dir)
        self.assertTrue(origin_hash)
        with open(os.path.join(skill_root, ".bundled_manifest"), "w", encoding="utf-8") as handle:
            handle.write(f"vendor-docs:{origin_hash}\n")

        self.app.cfg.active_connector = lambda: "hermes"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["hermes"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda _connector=None: [skill_root]  # type: ignore[method-assign]
        with patch.dict(os.environ, {"HERMES_HOME": hermes_home}):
            blocked = self.invoke(["block", "vendor-docs", "--connector", "hermes"])
            quarantined = self.invoke(
                ["quarantine", "vendor-docs", "--connector", "hermes"]
            )

        self.assertEqual(blocked.exit_code, 2, blocked.output)
        self.assertEqual(quarantined.exit_code, 2, quarantined.output)
        self.assertTrue(os.path.isfile(os.path.join(skill_dir, "SKILL.md")))
        self.assertFalse(
            self.app.store.has_action(
                "skill",
                "vendor-docs",
                "install",
                "block",
                "hermes",
            )
        )
        self.assertEqual(
            self.app.store.list_quarantine_records(
                "skill",
                "vendor-docs",
                "hermes",
            ),
            [],
        )


class TestSkillAllow(SkillCommandTestBase):
    def test_allow_adds_to_allow_list(self):
        result = self.invoke(["allow", "trusted-skill", "--reason", "vetted"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("trusted-skill", result.output)
        self.assertIn("allow list", result.output)

        pe = PolicyEngine(self.app.store, self.app.cfg)
        self.assertTrue(pe.is_allowed("skill", "trusted-skill"))

    def test_allow_logs_action(self):
        self.invoke(["allow", "safe-skill", "--reason", "reviewed"])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "skill-allow"]
        self.assertEqual(len(actions), 1)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_allow_reenables_runtime_disable_before_clearing_db(self, mock_cls):
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.disable("skill", "safe-skill", "runtime blocked")

        mock_cls.return_value.enable_skill.return_value = {"status": "enabled"}

        result = self.invoke(["allow", "safe-skill", "--reason", "reviewed"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(pe.is_allowed("skill", "safe-skill"))
        self.assertFalse(self.app.store.has_action("skill", "safe-skill", "runtime", "disable"))
        mock_cls.return_value.enable_skill.assert_called_once_with("safe-skill")

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_allow_preserves_runtime_disable_when_gateway_enable_fails(self, mock_cls):
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.disable("skill", "safe-skill", "runtime blocked")

        mock_cls.return_value.enable_skill.side_effect = Exception("timeout")

        result = self.invoke(["allow", "safe-skill", "--reason", "reviewed"])
        # GAP-0358: an error line with exit 0 read as success; the rule is
        # written, but OpenClaw keeps the skill disabled, so the exit is 1.
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("gateway enable failed", result.output)
        self.assertIn("OpenClaw still has it disabled", result.output)
        self.assertTrue(pe.is_allowed("skill", "safe-skill"))
        self.assertTrue(self.app.store.has_action("skill", "safe-skill", "runtime", "disable"))

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_allow_quarantined_copy_pins_its_destination_without_the_gateway(self, mock_cls):
        # GAP-0358/GAP-0359: Claude Code has no /skill/enable route (allow
        # printed its 404), and a quarantined copy has no installed path, so
        # allow wrote a global name-only rule and never said restore is needed.
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]
        destination = os.path.join(self.tmp_dir, "claude-skills", "docx")
        self.app.store.create_quarantine_record(
            "skill", "docx", destination, os.path.join(self.tmp_dir, "q", "docx"), "h", "scan", "claudecode",
            state="active",
        )
        PolicyEngine(self.app.store, self.app.cfg).disable("skill", "docx", "scan")

        result = self.invoke(["allow", "docx", "--reason", "vetted"])
        self.assertEqual(result.exit_code, 0, result.output)
        mock_cls.return_value.enable_skill.assert_not_called()
        rules = [(r.connector, r.source_path_contains) for r in self.app.cfg.asset_policy.skill.allowed]
        self.assertEqual(rules, [("claudecode", [destination])])
        self.assertIn(f"covers the copy at {destination} only", result.output)
        self.assertIn("Restore them with: defenseclaw skill restore docx", result.output)
        self.assertFalse(self.app.store.has_action("skill", "docx", "runtime", "disable"))


class TestSkillAllowScannedCopy(SkillCommandTestBase):
    def test_allow_of_a_skill_known_from_scan_path_pins_the_scanned_copy(self):
        # GAP-1579: a skill scanned with "skill scan --path" and not installed
        # got a name-only allow, so skill info kept "Policy: rejected" and any
        # same-named skill skipped the scan. The allow now pins the scanned
        # folder and skill info reads allowed.
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]
        scanned = os.path.realpath(os.path.join(self.tmp_dir, "code", "risky-skill"))
        os.makedirs(scanned)
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", scanned,
            datetime.now(timezone.utc), 100, 5, "CRITICAL", "{}",
        )

        result = self.invoke(["allow", "risky-skill", "--reason", "reviewed"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("matches the name only", result.output)
        self.assertIn(f"covers the copy at {scanned} only", result.output)
        rules = [r.source_path_contains for r in self.app.cfg.asset_policy.skill.allowed]
        self.assertEqual(rules, [[scanned]])
        info = self.invoke(["info", "risky-skill"])
        self.assertIn("Policy: allowed", " ".join(info.output.split()), info.output)

    def test_allow_after_a_url_scan_keeps_the_name_only_rule(self):
        # GAP-1974: "skill scan <url>" scans a temporary copy and removes it.
        # An allow must not pin that deleted folder; it keeps the name-only
        # rule and its note. A fetch folder that still exists is not pinned
        # either.
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]
        fetch = tempfile.mkdtemp(prefix="defenseclaw-skill-")
        self.addCleanup(shutil.rmtree, fetch, True)
        live = os.path.realpath(os.path.join(fetch, "skill", "fetched-skill"))
        os.makedirs(live)
        gone = os.path.realpath(os.path.join(self.tmp_dir, "removed", "gone-skill"))
        for name, target in (("fetched-skill", live), ("gone-skill", gone)):
            self.app.store.insert_scan_result(
                str(uuid.uuid4()), "skill-scanner", target,
                datetime.now(timezone.utc), 100, 5, "CRITICAL", "{}",
            )
            result = self.invoke(["allow", name, "--reason", "reviewed"])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("matches the name only", result.output)
            self.assertNotIn("covers the copy at", result.output)
        rules = [r.source_path_contains for r in self.app.cfg.asset_policy.skill.allowed]
        self.assertNotIn([live], rules)
        self.assertNotIn([gone], rules)

    def test_two_scanned_folders_keep_the_name_only_note(self):
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]
        for parent in ("a", "b"):
            self.app.store.insert_scan_result(
                str(uuid.uuid4()), "skill-scanner", os.path.join(self.tmp_dir, parent, "twin"),
                datetime.now(timezone.utc), 100, 1, "HIGH", "{}",
            )
        result = self.invoke(["allow", "twin", "--reason", "reviewed"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("matches the name only", result.output)


class TestSkillUnblock(SkillCommandTestBase):
    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_unblock_reenables_runtime_disable_before_clearing_state(self, mock_cls):
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.block("skill", "blocked-skill", "manual block")
        pe.disable("skill", "blocked-skill", "runtime blocked")

        mock_cls.return_value.enable_skill.return_value = {"status": "enabled"}

        result = self.invoke(["unblock", "blocked-skill"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIsNone(pe.get_action("skill", "blocked-skill"))
        mock_cls.return_value.enable_skill.assert_called_once_with("blocked-skill")

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_unblock_preserves_state_when_gateway_enable_fails(self, mock_cls):
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.block("skill", "blocked-skill", "manual block")
        pe.disable("skill", "blocked-skill", "runtime blocked")

        mock_cls.return_value.enable_skill.side_effect = Exception("timeout")

        result = self.invoke(["unblock", "blocked-skill"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("gateway enable failed", result.output)
        self.assertIn("runtime disable remains until the gateway is reachable", result.output)
        self.assertFalse(pe.is_blocked("skill", "blocked-skill"))
        self.assertFalse(pe.is_quarantined("skill", "blocked-skill"))
        self.assertTrue(self.app.store.has_action("skill", "blocked-skill", "runtime", "disable"))


class TestSkillScan(SkillCommandTestBase):
    @patch("defenseclaw.commands.cmd_skill._run_openclaw", return_value=None)
    def test_scan_blocked_skill_shows_blocked(self, _mock_oc):
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.block("skill", "blocked-one", "test")

        skill_dir = os.path.join(self.tmp_dir, "blocked-one")
        os.makedirs(skill_dir)

        result = self.invoke(["scan", "blocked-one", "--path", skill_dir])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("BLOCKED", result.output)

    @patch("defenseclaw.commands.cmd_skill._run_openclaw", return_value=None)
    def test_scan_allowed_skill_shows_allowed(self, _mock_oc):
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.allow("skill", "allow-me", "test")

        skill_dir = os.path.join(self.tmp_dir, "allow-me")
        os.makedirs(skill_dir)

        result = self.invoke(["scan", "allow-me", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("ALLOWED", result.output)

    @patch("defenseclaw.commands.cmd_skill._run_openclaw", return_value=None)
    def test_scan_connector_allow_overrides_global_block(self, _mock_oc):
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.block("skill", "scoped-skill", "global block")
        pe.allow_for_connector("skill", "scoped-skill", "codex", "codex allow")
        skill_dir = os.path.join(self.tmp_dir, "scoped-skill")
        os.makedirs(skill_dir)

        result = self.invoke(["scan", "scoped-skill", "--path", skill_dir, "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("ALLOWED", result.output)

    @patch("defenseclaw.commands.cmd_skill._run_openclaw", return_value=None)
    def test_scan_connector_block_overrides_global_allow(self, _mock_oc):
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.allow("skill", "scoped-block", "global allow")
        pe.block_for_connector("skill", "scoped-block", "codex", "codex block")
        skill_dir = os.path.join(self.tmp_dir, "scoped-block")
        os.makedirs(skill_dir)

        result = self.invoke(["scan", "scoped-block", "--path", skill_dir, "--connector", "codex"])

        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("BLOCKED", result.output)

    def test_scan_action_writes_connector_scoped_enforcement_rows(self):
        rego_dir = os.path.join(self.app.cfg.policy_dir, "rego")
        os.makedirs(rego_dir, exist_ok=True)
        with open(os.path.join(rego_dir, "data.json"), "w", encoding="utf-8") as f:
            json.dump(
                {
                    "config": {"allow_list_bypass_scan": True, "scan_on_install": True},
                    "actions": {
                        "HIGH": {"runtime": "allow", "file": "none", "install": "block"},
                    },
                },
                f,
            )
        skill_dir = os.path.join(self.tmp_dir, "dirty-skill")
        os.makedirs(skill_dir)
        result = ScanResult(
            scanner="skill-scanner",
            target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="Shell injection", scanner="skill-scanner")],
            duration=timedelta(seconds=0.5),
        )
        pe = PolicyEngine(self.app.store, self.app.cfg)

        _apply_scan_enforcement(self.app, pe, "dirty-skill", skill_dir, result, connector="codex")

        self.assertTrue(
            self.app.store.has_action("skill", "dirty-skill", "install", "block", "codex")
        )
        self.assertFalse(self.app.store.has_action("skill", "dirty-skill", "install", "block"))

    @patch("defenseclaw.commands.cmd_skill._sidecar_client")
    @patch("defenseclaw.commands.cmd_skill._quarantine_skill_with_provenance")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    def test_scan_action_hook_connector_records_all_scoped_actions(
        self, mock_admission, mock_quarantine, mock_client,
    ):
        mock_admission.return_value = MagicMock(
            verdict="blocked",
            action=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )
        def quarantine_side_effect(_app, pe, name, _path, connector, reason):
            pe.quarantine_for_connector("skill", name, connector, reason)
            return os.path.join(self.tmp_dir, "quarantined")
        mock_quarantine.side_effect = quarantine_side_effect
        skill_dir = os.path.join(self.tmp_dir, "dirty-skill")
        os.makedirs(skill_dir)
        result = ScanResult(
            scanner="skill-scanner", target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="inert", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )

        _apply_scan_enforcement(
            self.app, PolicyEngine(self.app.store, self.app.cfg), "dirty-skill", skill_dir, result,
            connector="codex",
        )

        mock_client.assert_not_called()
        self.assertTrue(self.app.store.has_action(
            "skill", "dirty-skill", "runtime", "disable", "codex",
        ))
        self.assertTrue(self.app.store.has_action(
            "skill", "dirty-skill", "install", "block", "codex",
        ))
        self.assertIsNone(self.app.store.get_action("skill", "dirty-skill", "claudecode"))

    @patch("defenseclaw.commands.cmd_skill._sidecar_client")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    def test_scan_action_claude_alias_is_canonical_and_never_uses_gateway(
        self, mock_admission, mock_client,
    ):
        mock_admission.return_value = MagicMock(
            verdict="blocked",
            action=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )
        skill_dir = os.path.join(self.tmp_dir, "alias-skill")
        os.makedirs(skill_dir)
        result = ScanResult(
            scanner="skill-scanner", target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="inert", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )

        _apply_scan_enforcement(
            self.app, PolicyEngine(self.app.store, self.app.cfg), "alias-skill", skill_dir, result,
            connector="claude-code",
        )

        mock_client.assert_not_called()
        self.assertTrue(self.app.store.has_action(
            "skill", "alias-skill", "runtime", "disable", "claudecode",
        ))
        self.assertTrue(self.app.store.has_action(
            "skill", "alias-skill", "install", "block", "claudecode",
        ))
        self.assertTrue(self.app.store.has_action(
            "skill", "alias-skill", "file", "quarantine", "claudecode",
        ))
        records = self.app.store.list_quarantine_records(
            "skill", "alias-skill", "claudecode",
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].connectors, ("claudecode",))
        self.assertIsNone(self.app.store.get_action("skill", "alias-skill", "claude-code"))

    @patch("defenseclaw.commands.cmd_skill._sidecar_client")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    def test_scan_action_openclaw_runtime_disable_remains_rpc_backed(
        self, mock_admission, mock_client,
    ):
        mock_admission.return_value = MagicMock(
            verdict="blocked",
            action=SeverityAction(file="none", runtime="disable", install="none"),
        )
        skill_dir = os.path.join(self.tmp_dir, "openclaw-skill")
        os.makedirs(skill_dir)
        result = ScanResult(
            scanner="skill-scanner", target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="inert", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )

        _apply_scan_enforcement(
            self.app, PolicyEngine(self.app.store, self.app.cfg), "openclaw-skill", skill_dir, result,
            connector="openclaw",
        )

        mock_client.return_value.disable_skill.assert_called_once_with("openclaw-skill")
        self.assertTrue(self.app.store.has_action(
            "skill", "openclaw-skill", "runtime", "disable", "openclaw",
        ))

    @patch("defenseclaw.commands.cmd_skill._quarantine_skill_with_provenance", return_value=None)
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    def test_scan_action_partial_failure_raises_after_other_actions(
        self, mock_admission, _mock_quarantine,
    ):
        mock_admission.return_value = MagicMock(
            verdict="blocked",
            action=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )
        skill_dir = os.path.join(self.tmp_dir, "partial-skill")
        os.makedirs(skill_dir)
        result = ScanResult(
            scanner="skill-scanner", target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="inert", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )
        pe = PolicyEngine(self.app.store, self.app.cfg)

        with self.assertRaises(click.ClickException):
            _apply_scan_enforcement(
                self.app, pe, "partial-skill", skill_dir, result, connector="codex",
            )

        self.assertTrue(self.app.store.has_action(
            "skill", "partial-skill", "runtime", "disable", "codex",
        ))
        self.assertTrue(self.app.store.has_action(
            "skill", "partial-skill", "install", "block", "codex",
        ))

    @patch("defenseclaw.enforce.admission.evaluate_admission")
    def test_scan_action_policy_persistence_failures_preserve_other_action(
        self, mock_admission,
    ):
        mock_admission.return_value = MagicMock(
            verdict="blocked",
            action=SeverityAction(file="none", runtime="disable", install="block"),
        )
        result = ScanResult(
            scanner="skill-scanner", target="inert",
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="inert", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )

        runtime_skill = "runtime-persistence-failure"
        runtime_dir = os.path.join(self.tmp_dir, runtime_skill)
        os.makedirs(runtime_dir)
        runtime_pe = PolicyEngine(self.app.store, self.app.cfg)
        with patch.object(
            runtime_pe, "disable_for_connector", side_effect=OSError("runtime db unavailable"),
        ), self.assertRaises(click.ClickException):
            _apply_scan_enforcement(
                self.app, runtime_pe, runtime_skill, runtime_dir, result, connector="codex",
            )
        self.assertTrue(self.app.store.has_action(
            "skill", runtime_skill, "install", "block", "codex",
        ))

        install_skill = "install-persistence-failure"
        install_dir = os.path.join(self.tmp_dir, install_skill)
        os.makedirs(install_dir)
        install_pe = PolicyEngine(self.app.store, self.app.cfg)
        with patch.object(
            install_pe, "record_scan_block", side_effect=OSError("install db unavailable"),
        ), self.assertRaises(click.ClickException):
            _apply_scan_enforcement(
                self.app, install_pe, install_skill, install_dir, result, connector="codex",
            )
        self.assertTrue(self.app.store.has_action(
            "skill", install_skill, "runtime", "disable", "codex",
        ))

    @patch("defenseclaw.commands.cmd_skill._quarantine_skill_with_provenance", return_value=None)
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    def test_scan_action_partial_failure_returns_nonzero(
        self, mock_scan, mock_admission, _mock_quarantine,
    ):
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        mock_admission.return_value = MagicMock(
            verdict="blocked",
            action=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )
        skill_dir = os.path.join(self.tmp_dir, "cli-partial-skill")
        os.makedirs(skill_dir)
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner", target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="inert", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )

        result = self.invoke([
            "scan", "cli-partial-skill", "--path", skill_dir,
            "--connector", "codex", "--action", "--no-use-llm",
        ])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("configured enforcement incomplete", result.output)
        self.assertTrue(self.app.store.has_action(
            "skill", "cli-partial-skill", "runtime", "disable", "codex",
        ))
        self.assertTrue(self.app.store.has_action(
            "skill", "cli-partial-skill", "install", "block", "codex",
        ))

    @patch("defenseclaw.enforce.admission.evaluate_admission")
    def test_scan_action_missing_store_and_silent_noop_fail_closed(self, mock_admission):
        mock_admission.return_value = MagicMock(
            verdict="blocked",
            action=SeverityAction(file="none", runtime="disable", install="block"),
        )
        result = ScanResult(
            scanner="skill-scanner", target="inert",
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="inert", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )
        skill_dir = os.path.join(self.tmp_dir, "missing-store-skill")
        os.makedirs(skill_dir)

        missing_store_app = MagicMock(cfg=self.app.cfg, store=None, logger=None)
        noop_pe = MagicMock()
        with self.assertRaises(click.ClickException):
            _apply_scan_enforcement(
                missing_store_app, noop_pe, "missing-store-skill", skill_dir, result,
                connector="codex",
            )
        noop_pe.disable_for_connector.assert_called_once()
        noop_pe.record_scan_block.assert_called_once()

        silent_name = "silent-noop-skill"
        silent_dir = os.path.join(self.tmp_dir, silent_name)
        os.makedirs(silent_dir)
        silent_pe = MagicMock()
        with self.assertRaises(click.ClickException):
            _apply_scan_enforcement(
                self.app, silent_pe, silent_name, silent_dir, result, connector="codex",
            )
        self.assertIsNone(self.app.store.get_action("skill", silent_name, "codex"))
        silent_pe.disable_for_connector.assert_called_once()
        silent_pe.record_scan_block.assert_called_once()

    @patch("defenseclaw.commands.cmd_skill._sidecar_client")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    def test_scan_action_cli_claude_alias_uses_one_canonical_scope(
        self, mock_scan, mock_admission, mock_client,
    ):
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]
        mock_admission.return_value = MagicMock(
            verdict="blocked",
            action=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )
        skill_dir = os.path.join(self.tmp_dir, "cli-alias-skill")
        os.makedirs(skill_dir)
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner", target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="inert", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )

        result = self.invoke([
            "scan", "cli-alias-skill", "--path", skill_dir,
            "--connector", "claude-code", "--action", "--no-use-llm",
        ])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_client.assert_not_called()
        entry = self.app.store.get_action("skill", "cli-alias-skill", "claudecode")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.actions.file, "quarantine")
        self.assertEqual(entry.actions.runtime, "disable")
        self.assertEqual(entry.actions.install, "block")
        self.assertIsNone(self.app.store.get_action("skill", "cli-alias-skill", "claude-code"))
        records = self.app.store.list_quarantine_records(
            "skill", "cli-alias-skill", "claudecode",
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].connectors, ("claudecode",))

    def _configure_two_scan_connectors(self, skill_name):
        roots = {
            "codex": os.path.join(self.tmp_dir, "codex", "skills"),
            "claudecode": os.path.join(self.tmp_dir, "claudecode", "skills"),
        }
        paths = {}
        for connector, root in roots.items():
            paths[connector] = os.path.join(root, skill_name)
            os.makedirs(paths[connector])
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "claude-code"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: [  # type: ignore[method-assign]
            roots["claudecode" if connector == "claude-code" else (connector or "codex")]
        ]
        return paths

    @patch("defenseclaw.commands.cmd_skill._sidecar_client")
    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    def test_scan_action_global_two_hook_connectors_are_isolated(
        self, mock_scan, mock_admission, mock_list, mock_client,
    ):
        name = "global-skill"
        paths = self._configure_two_scan_connectors(name)
        mock_list.side_effect = lambda _app, connector=None: {
            "skills": [{"name": name, "baseDir": paths[
                "claudecode" if connector == "claude-code" else connector
            ]}]
        }
        mock_scan.side_effect = lambda path: ScanResult(
            scanner="skill-scanner", target=path,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="inert", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )
        mock_admission.return_value = MagicMock(
            verdict="blocked",
            action=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )

        result = self.invoke(["scan", "--action", "--no-use-llm"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(mock_scan.call_count, 2)
        mock_client.assert_not_called()
        for connector in ("codex", "claudecode"):
            entry = self.app.store.get_action("skill", name, connector)
            self.assertEqual(entry.actions.file, "quarantine")
            self.assertEqual(entry.actions.runtime, "disable")
            self.assertEqual(entry.actions.install, "block")
        self.assertIsNone(self.app.store.get_action("skill", name))
        self.assertIsNone(self.app.store.get_action("skill", name, "claude-code"))

    @patch("defenseclaw.commands.cmd_skill._sidecar_client")
    @patch("defenseclaw.commands.cmd_skill._quarantine_skill_with_provenance")
    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    def test_scan_action_global_peer_failure_continues_and_returns_nonzero(
        self, mock_scan, mock_admission, mock_list, mock_quarantine, mock_client,
    ):
        name = "global-partial-skill"
        paths = self._configure_two_scan_connectors(name)
        mock_list.side_effect = lambda _app, connector=None: {
            "skills": [{"name": name, "baseDir": paths[
                "claudecode" if connector == "claude-code" else connector
            ]}]
        }
        mock_scan.side_effect = lambda path: ScanResult(
            scanner="skill-scanner", target=path,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="inert", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )
        mock_admission.return_value = MagicMock(
            verdict="blocked",
            action=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )
        def quarantine_side_effect(_app, pe, skill, _path, connector, reason):
            if connector == "codex":
                return None
            pe.quarantine_for_connector("skill", skill, connector, reason)
            return os.path.join(self.tmp_dir, "mock-quarantine")
        mock_quarantine.side_effect = quarantine_side_effect

        result = self.invoke(["scan", "--action", "--no-use-llm"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(mock_scan.call_count, 2)
        mock_client.assert_not_called()
        codex_entry = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(codex_entry.actions.runtime, "disable")
        self.assertEqual(codex_entry.actions.install, "block")
        claude_entry = self.app.store.get_action("skill", name, "claudecode")
        self.assertEqual(claude_entry.actions.file, "quarantine")
        self.assertEqual(claude_entry.actions.runtime, "disable")
        self.assertEqual(claude_entry.actions.install, "block")

    @patch("defenseclaw.commands.cmd_skill._sidecar_client")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    def test_scan_enforcement_restore_and_scoped_unblock_preserve_peer(
        self, mock_scan, mock_admission, mock_client,
    ):
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: [self.tmp_dir]  # type: ignore[method-assign]
        name = "lifecycle-skill"
        skill_dir = os.path.join(self.tmp_dir, name)
        os.makedirs(skill_dir)
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner", target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="inert", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )
        mock_admission.return_value = MagicMock(
            verdict="blocked",
            action=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.disable_for_connector("skill", name, "codex", "peer state")

        scan_result = self.invoke([
            "scan", name, "--path", skill_dir, "--connector", "claude-code",
            "--action", "--no-use-llm",
        ])
        self.assertEqual(scan_result.exit_code, 0, scan_result.output)
        restore_result = self.invoke(["restore", name, "--connector", "claude-code"])
        self.assertEqual(restore_result.exit_code, 0, restore_result.output)
        restored = self.app.store.get_action("skill", name, "claudecode")
        self.assertEqual(restored.actions.file, "")
        self.assertEqual(restored.actions.runtime, "disable")
        self.assertEqual(restored.actions.install, "block")

        unblock_result = self.invoke(["unblock", name, "--connector", "claude-code"])
        self.assertEqual(unblock_result.exit_code, 0, unblock_result.output)
        self.assertIsNone(self.app.store.get_action("skill", name, "claudecode"))
        self.assertTrue(self.app.store.has_action(
            "skill", name, "runtime", "disable", "codex",
        ))
        mock_client.assert_not_called()

    @patch("defenseclaw.scanner.rulepack.maybe_wrap", new=lambda scanner, *args, **kwargs: scanner)
    @patch("defenseclaw.commands.cmd_skill._scan_all")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_flag_uses_bulk_scan_path(self, mock_scanner_cls, mock_scan_all):
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner

        result = self.invoke(["scan", "--all"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_scan_all.assert_called_once_with(self.app, mock_scanner, False, enforce=False, connector=None)

    @patch("defenseclaw.scanner.rulepack.maybe_wrap", new=lambda scanner, *args, **kwargs: scanner)
    @patch("defenseclaw.commands.cmd_skill._scan_all")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_without_target_uses_bulk_scan_path(self, mock_scanner_cls, mock_scan_all):
        # `skill scan` is the natural no-target spelling for scanning
        # configured skills; --all remains only an explicit alias.
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner

        result = self.invoke(["scan"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_scan_all.assert_called_once_with(self.app, mock_scanner, False, enforce=False, connector=None)

    @patch("defenseclaw.commands.cmd_skill._scan_all")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_multi_connector_fans_out_per_connector(self, mock_scanner_cls, mock_scan_all):
        # D1 parity: in a multi-connector install `scan --all` must scan
        # EVERY active connector's skills, not just the primary's.
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all"])

        self.assertEqual(result.exit_code, 0, result.output)
        called = {c.kwargs["connector"] for c in mock_scan_all.call_args_list}
        self.assertEqual(called, {"claudecode", "codex"})

    @patch("defenseclaw.commands.cmd_skill._scan_all")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_multi_connector_continues_after_scanner_system_exit(
        self, mock_scanner_cls, mock_scan_all
    ):
        mock_scanner_cls.return_value = MagicMock()
        mock_scan_all.side_effect = [SystemExit(23), []]
        self.app.cfg.active_connectors = lambda: [  # type: ignore[method-assign]
            "claudecode",
            "codex",
        ]

        result = self.invoke(["scan", "--all"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(
            [call.kwargs["connector"] for call in mock_scan_all.call_args_list],
            ["claudecode", "codex"],
        )

    @patch("defenseclaw.commands.cmd_skill._scan_all")
    @patch("defenseclaw.commands.cmd_skill._build_skill_scanner")
    def test_scan_all_multi_connector_reuses_rule_pack_cache(self, mock_build, _mock_scan_all):
        mock_build.return_value = MagicMock()
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all"])

        self.assertEqual(result.exit_code, 0, result.output)
        caches = [call.kwargs["pack_cache"] for call in mock_build.call_args_list]
        self.assertEqual(len(caches), 2)
        self.assertIs(caches[0], caches[1])

    @patch("defenseclaw.scanner.rulepack.maybe_wrap", new=lambda scanner, *args, **kwargs: scanner)
    @patch("defenseclaw.commands.cmd_skill._scan_all")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_connector_flag_targets_one(self, mock_scanner_cls, mock_scan_all):
        # --connector targets exactly one connector even in a multi install.
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_scan_all.assert_called_once_with(self.app, mock_scanner, False, enforce=False, connector="codex")

    @patch("defenseclaw.scanner.rulepack.maybe_wrap", new=lambda scanner, *args, **kwargs: scanner)
    @patch("defenseclaw.commands.cmd_skill._scan_all")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_connector_without_target_scans_that_connector(self, mock_scanner_cls, mock_scan_all):
        # MCP parity: `skill scan --connector X` is the natural shorthand
        # for scanning all skills configured on that connector.
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        self.app.cfg.active_connectors = lambda: ["claudecode", "hermes"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--connector", "hermes"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_scan_all.assert_called_once_with(self.app, mock_scanner, False, enforce=False, connector="hermes")

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_connector_flag_rejects_unknown(self, mock_scanner_cls):
        # A typo'd --connector must fail loudly, not silently scan the primary.
        mock_scanner_cls.return_value = MagicMock()
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all", "--connector", "nope"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not configured", result.output)

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_connector_without_target_rejects_unknown(self, mock_scanner_cls):
        # The shorthand path validates the connector the same way --all does.
        mock_scanner_cls.return_value = MagicMock()
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--connector", "nope"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not configured", result.output)

    @patch("defenseclaw.commands.cmd_skill._scan_all_remote")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_remote_fans_out_per_connector(self, mock_scanner_cls, mock_remote):
        # Parity with the local --all path: --all --remote must scan EVERY
        # active connector's skills, not just the primary's.
        mock_scanner_cls.return_value = MagicMock()
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all", "--remote"])

        self.assertEqual(result.exit_code, 0, result.output)
        called = {c.kwargs.get("connector") for c in mock_remote.call_args_list}
        self.assertEqual(called, {"claudecode", "codex"})

    @patch("defenseclaw.commands.cmd_skill._scan_all_remote")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_remote_connector_flag_targets_one(self, mock_scanner_cls, mock_remote):
        mock_scanner_cls.return_value = MagicMock()
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all", "--remote", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_remote.assert_called_once_with(self.app, False, connector="codex")

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    @patch("defenseclaw.commands.cmd_skill._sidecar_client")
    def test_scan_all_remote_json_mixed_multi_connector_failure_is_nonzero(
        self, mock_client_factory, mock_list,
    ):
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        skill_paths = {
            "claudecode": ["/remote/claudecode/alpha"],
            "codex": ["/remote/codex/beta", "/remote/codex/gamma"],
        }

        def list_skills(_app, connector=None):
            return {
                "skills": [
                    {"name": os.path.basename(path), "baseDir": path}
                    for path in skill_paths[connector]
                ]
            }

        def scan_skill(*, target, name, timeout):
            if name == "beta":
                raise RuntimeError("codex sidecar unavailable")
            return {
                "scanner": "skill-scanner",
                "target": target,
                "findings": [],
            }

        mock_list.side_effect = list_skills
        mock_client_factory.return_value.scan_skill.side_effect = scan_skill

        result = self.invoke(["scan", "--all", "--remote", "--json"])

        self.assertEqual(result.exit_code, 1, result.output)
        payload = json.loads(result.output)
        self.assertEqual(
            [(row["connector"], row["target"]) for row in payload],
            [
                ("claudecode", "/remote/claudecode/alpha"),
                ("codex", "/remote/codex/beta"),
                ("codex", "/remote/codex/gamma"),
            ],
        )
        self.assertIn("codex sidecar unavailable", payload[1]["error"])
        self.assertEqual(mock_client_factory.return_value.scan_skill.call_count, 3)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_info_connector_flag_threads_connector(self, mock_info):
        # D4 parity: `skill info --connector X` must inspect X's skill.
        mock_info.return_value = {"name": "x"}
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["info", "x", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(mock_info.call_args.kwargs.get("connector"), "codex")

    def test_info_connector_flag_rejects_unknown(self):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["info", "x", "--connector", "nope"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not configured", result.output)

    @patch("defenseclaw.config.Config.skill_dirs")
    def test_scan_all_accepts_connector_filesystem_path_field(self, mock_skill_dirs):
        from defenseclaw.commands.cmd_skill import _scan_all

        skill_root = os.path.join(self.tmp_dir, ".zeptoclaw", "skills")
        skill_dir = os.path.join(skill_root, "zepto-skill")
        os.makedirs(skill_dir)
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write("# Zepto skill\n")
        mock_skill_dirs.return_value = [skill_root]
        self.app.cfg.active_connector = lambda: "zeptoclaw"  # type: ignore[method-assign]
        scanner = MagicMock()
        scanner.scan.return_value = ScanResult(
            scanner="skill-scanner",
            target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(seconds=0.1),
        )

        _scan_all(self.app, scanner, as_json=False)

        scanner.scan.assert_called_once_with(skill_dir)

    def test_scan_all_nonactive_codex_discovers_but_does_not_scan_system_skills(self):
        from defenseclaw.commands.cmd_skill import _scan_all

        codex_root = os.path.join(self.tmp_dir, ".codex", "skills")
        regular = os.path.join(codex_root, "operator-skill")
        system_root = os.path.join(codex_root, ".system")
        child_a = os.path.join(system_root, "imagegen")
        child_b = os.path.join(system_root, "skill-installer")
        for path in (regular, child_a, child_b):
            os.makedirs(path, exist_ok=True)
            with open(os.path.join(path, "SKILL.md"), "w", encoding="utf-8") as f:
                f.write(f"# {os.path.basename(path)}\n")
        os.makedirs(os.path.join(system_root, "not-a-skill"), exist_ok=True)

        self.app.cfg.active_connector = lambda: "antigravity"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["antigravity", "codex"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: (  # type: ignore[method-assign]
            [codex_root] if connector == "codex" else []
        )

        scanner = MagicMock()
        scanner.scan.side_effect = lambda path: ScanResult(
            scanner="skill-scanner",
            target=path,
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(seconds=0.1),
        )

        with patch.dict(
            os.environ,
            {"CODEX_HOME": os.path.join(self.tmp_dir, ".codex")},
        ):
            _scan_all(self.app, scanner, as_json=False, connector="codex")

        scanned = [call.args[0] for call in scanner.scan.call_args_list]
        self.assertEqual(scanned, [regular])
        self.assertNotIn(system_root, scanned)
        self.assertNotIn(child_a, scanned)
        self.assertNotIn(child_b, scanned)
        self.assertNotIn(os.path.join(system_root, "not-a-skill"), scanned)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_scan_all_remote_skips_bundled_entries(self, mock_list):
        from defenseclaw.commands.cmd_skill import _scan_all_remote

        regular = os.path.join(self.tmp_dir, ".codex", "skills", "operator-skill")
        bundled = os.path.join(self.tmp_dir, ".codex", "skills", ".system", "imagegen")
        mock_list.return_value = {
            "skills": [
                {"name": "operator-skill", "baseDir": regular, "bundled": False},
                {"name": "imagegen", "baseDir": bundled, "bundled": True},
            ]
        }
        client = MagicMock()
        client.scan_skill.return_value = {"findings": [], "max_severity": "INFO"}

        with patch("defenseclaw.commands.cmd_skill._sidecar_client", return_value=client):
            _scan_all_remote(self.app, as_json=False, connector="codex")

        client.scan_skill.assert_called_once_with(target=regular, name="operator-skill", timeout=330)

    def test_explicit_bundled_skill_scan_is_skipped_without_scanner_or_action(self):
        bundled = os.path.join(
            self.tmp_dir, ".codex", "skills", ".system", "imagegen"
        )
        os.makedirs(bundled, exist_ok=True)
        with open(os.path.join(bundled, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("# bundled\n")
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: [  # type: ignore[method-assign]
            os.path.join(self.tmp_dir, ".codex", "skills")
        ]

        with (
            patch.dict(
                os.environ,
                {"CODEX_HOME": os.path.join(self.tmp_dir, ".codex")},
            ),
            patch("defenseclaw.scanner.skill.SkillScannerWrapper") as scanner_cls,
        ):
            result = self.invoke(["scan", "imagegen", "--path", bundled, "--action"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("vendor-bundled skills are discovery-only", result.output)
        scanner_cls.return_value.scan.assert_not_called()
        self.assertIsNone(self.app.store.get_action("skill", "imagegen"))

    def test_explicit_arbitrary_system_directory_remains_scan_eligible(self):
        target = os.path.join(self.tmp_dir, "workspace", ".system", "operator-skill")
        os.makedirs(target, exist_ok=True)
        with open(os.path.join(target, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("# operator\n")
        codex_home = os.path.join(self.tmp_dir, "real-codex-home")
        clean = ScanResult(
            scanner="skill-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(seconds=0.1),
        )

        with (
            patch.dict(os.environ, {"CODEX_HOME": codex_home}),
            patch("defenseclaw.scanner.skill.SkillScannerWrapper") as scanner_cls,
        ):
            scanner_cls.return_value.scan.return_value = clean
            result = self.invoke(["scan", "operator-skill", "--path", target])

        self.assertEqual(result.exit_code, 0, result.output)
        scanner_cls.return_value.scan.assert_called_once_with(target)


class TestSkillScanContainment(SkillCommandTestBase):
    """F-0501/F-0502: scan must not trust a connector-reported baseDir or a
    symlinked entry that escapes the configured skill roots."""

    @patch("defenseclaw.commands.cmd_skill._run_openclaw", return_value=None)
    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_f0501_rejects_connector_basedir_outside_skill_roots(
        self, mock_info, _mock_oc
    ):
        # A malicious connector reports a baseDir OUTSIDE the configured
        # skill directories (here: a sibling temp dir).
        evil_dir = os.path.join(self.tmp_dir, "evil-outside")
        os.makedirs(evil_dir)
        mock_info.return_value = {"name": "pwn", "baseDir": evil_dir}

        result = self.invoke(["scan", "pwn"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("outside the configured skill", result.output)

    @patch("defenseclaw.commands.cmd_skill._run_openclaw", return_value=None)
    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_f0501_allows_basedir_inside_skill_root(
        self, mock_scanner_cls, _mock_info, _mock_oc
    ):
        # A skill that genuinely lives under a configured skill root scans.
        skill_root = self.app.cfg.skill_dirs()[1]  # <home>/skills
        skill_dir = os.path.join(skill_root, "legit")
        os.makedirs(skill_dir)
        scanner = MagicMock()
        scanner.scan.return_value = ScanResult(
            scanner="skill-scanner", target=skill_dir,
            timestamp=datetime.now(timezone.utc), findings=[],
            duration=timedelta(seconds=0.1),
        )
        mock_scanner_cls.return_value = scanner

        result = self.invoke(["scan", "legit"])
        self.assertEqual(result.exit_code, 0, result.output)
        # _resolve_path freezes to realpath (F-0503), so compare canonically.
        scanner.scan.assert_called_once_with(os.path.realpath(skill_dir))

    @patch("defenseclaw.commands.cmd_skill._run_openclaw", return_value=None)
    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_f0501_explicit_path_override_is_exempt(
        self, mock_scanner_cls, _mock_info, _mock_oc
    ):
        # The operator's explicit --path bypasses containment (trusted).
        outside = os.path.join(self.tmp_dir, "operator-chosen")
        os.makedirs(outside)
        scanner = MagicMock()
        scanner.scan.return_value = ScanResult(
            scanner="skill-scanner", target=outside,
            timestamp=datetime.now(timezone.utc), findings=[],
            duration=timedelta(seconds=0.1),
        )
        mock_scanner_cls.return_value = scanner

        result = self.invoke(["scan", "anything", "--path", outside])
        self.assertEqual(result.exit_code, 0, result.output)
        scanner.scan.assert_called_once_with(outside)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_scan_all_rejects_list_adapter_path_outside_skill_roots(
        self, mock_list,
    ):
        from defenseclaw.commands.cmd_skill import _scan_all

        skill_root = os.path.join(self.tmp_dir, "skills")
        outside = os.path.join(self.tmp_dir, "outside-target")
        os.makedirs(skill_root)
        os.makedirs(outside)
        mock_list.return_value = {
            "skills": [{"name": "outside", "path": outside, "baseDir": outside}]
        }
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: [skill_root]  # type: ignore[method-assign]
        scanner = MagicMock()

        _scan_all(self.app, scanner, as_json=False, connector="codex")

        scanner.scan.assert_not_called()

    @patch("defenseclaw.config.Config.skill_dirs")
    @requires_symlink_privilege
    def test_f0502_scan_all_skips_symlinked_entry(self, mock_skill_dirs):
        from defenseclaw.commands.cmd_skill import _scan_all

        skill_root = os.path.join(self.tmp_dir, "skills")
        real_skill = os.path.join(skill_root, "real")
        os.makedirs(real_skill)
        with open(os.path.join(real_skill, "SKILL.md"), "w") as f:
            f.write("# real\n")
        # A symlinked entry under the skill root pointing OUTSIDE it.
        outside = os.path.join(self.tmp_dir, "outside-target")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(skill_root, "evil-link"))

        mock_skill_dirs.return_value = [skill_root]
        self.app.cfg.active_connector = lambda: "openclaw"  # type: ignore[method-assign]
        # Force the filesystem fallback (no openclaw skill list).
        scanned: list[str] = []
        scanner = MagicMock()

        def _scan(path):
            scanned.append(path)
            return ScanResult(
                scanner="skill-scanner", target=path,
                timestamp=datetime.now(timezone.utc), findings=[],
                duration=timedelta(seconds=0.1),
            )

        scanner.scan.side_effect = _scan

        with patch(
            "defenseclaw.commands.cmd_skill._list_openclaw_skills_full",
            return_value=None,
        ):
            _scan_all(self.app, scanner, as_json=False)

        # Only the real skill was scanned; the symlinked entry was skipped.
        self.assertIn(real_skill, scanned)
        self.assertNotIn(os.path.join(skill_root, "evil-link"), scanned)
        self.assertNotIn(outside, scanned)


class TestResolvePathFreezesSymlinks(SkillCommandTestBase):
    """F-0503: _resolve_path must reject symlinked candidates and return a
    frozen realpath so a pinned allow entry cannot be retargeted later."""

    @requires_symlink_privilege
    def test_f0503_rejects_symlinked_target(self):
        from defenseclaw.commands.cmd_skill import _resolve_path

        outside = os.path.join(self.tmp_dir, "secret-dir")
        os.makedirs(outside)
        link = os.path.join(self.tmp_dir, "link-skill")
        os.symlink(outside, link)

        # A symlinked directory target must NOT be resolved (frozen-only).
        self.assertIsNone(_resolve_path(self.app, link))

    def test_f0503_returns_realpath_for_regular_dir(self):
        from defenseclaw.commands.cmd_skill import _resolve_path

        skill_root = self.app.cfg.skill_dirs()[1]
        skill_dir = os.path.join(skill_root, "frozen")
        os.makedirs(skill_dir)

        resolved = _resolve_path(self.app, "frozen")
        self.assertEqual(resolved, os.path.realpath(skill_dir))

    @requires_symlink_privilege
    def test_f0503_rejects_symlinked_candidate(self):
        from defenseclaw.commands.cmd_skill import _resolve_path

        # Candidate path (<root>/<name>) is itself a symlink to elsewhere.
        skill_root = self.app.cfg.skill_dirs()[1]
        os.makedirs(skill_root)
        outside = os.path.join(self.tmp_dir, "elsewhere")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(skill_root, "swapme"))

        self.assertIsNone(_resolve_path(self.app, "swapme"))


class TestClawHubWindowsLauncher(unittest.TestCase):
    def test_windows_resolver_prefers_cmd_over_extensionless_wrapper(self):
        from defenseclaw.commands.cmd_skill import _resolve_windows_launcher

        with tempfile.TemporaryDirectory(prefix="clawhub bin with spaces-") as bin_dir:
            unix_wrapper = os.path.join(bin_dir, "clawhub")
            windows_wrapper = os.path.join(bin_dir, "ClAwHuB.CmD")
            with open(unix_wrapper, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 99\n")
            with open(windows_wrapper, "w", encoding="utf-8") as handle:
                handle.write("@exit /b 0\r\n")

            resolved = _resolve_windows_launcher(
                "clawhub",
                search_path=bin_dir,
                pathext=".CMD;.EXE;.BAT;.COM",
            )

            self.assertEqual(resolved, os.path.abspath(windows_wrapper))
            self.assertNotEqual(resolved, unix_wrapper)

    def test_windows_resolver_honors_pathext_order(self):
        from defenseclaw.commands.cmd_skill import _resolve_windows_launcher

        with tempfile.TemporaryDirectory() as bin_dir:
            cmd = os.path.join(bin_dir, "clawhub.cmd")
            exe = os.path.join(bin_dir, "clawhub.exe")
            open(cmd, "wb").close()
            open(exe, "wb").close()

            self.assertEqual(
                _resolve_windows_launcher(
                    "CLawHub",
                    search_path=bin_dir,
                    pathext=".EXE;.CMD",
                ),
                os.path.abspath(exe),
            )
            self.assertEqual(
                _resolve_windows_launcher(
                    "CLawHub",
                    search_path=bin_dir,
                    pathext=".CMD;.EXE",
                ),
                os.path.abspath(cmd),
            )

    def test_windows_resolver_rejects_extensionless_only_wrapper(self):
        from defenseclaw.commands.cmd_skill import _resolve_windows_launcher

        with tempfile.TemporaryDirectory() as bin_dir:
            with open(os.path.join(bin_dir, "clawhub"), "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\n")
            self.assertIsNone(_resolve_windows_launcher("clawhub", search_path=bin_dir, pathext=".CMD"))

    def test_staged_skill_path_alias_is_rejected(self):
        from defenseclaw.commands.cmd_skill import _find_clawhub_staged_skill

        with tempfile.TemporaryDirectory() as stage:
            candidate = os.path.join(stage, "skills", "benign-skill")
            os.makedirs(candidate)
            with open(os.path.join(candidate, "SKILL.md"), "w", encoding="utf-8") as handle:
                handle.write("# benign\n")
            with patch(
                "defenseclaw.commands.cmd_skill._is_path_alias",
                side_effect=lambda path: os.path.normcase(path) == os.path.normcase(candidate),
            ):
                self.assertIsNone(_find_clawhub_staged_skill(stage, "benign-skill"))

    def test_connector_copy_revalidates_tree_after_copy(self):
        from defenseclaw.commands.cmd_skill import _stage_skill_tree_for_connector

        with tempfile.TemporaryDirectory() as root:
            source = os.path.join(root, "source")
            install_root = os.path.join(root, "installed")
            os.makedirs(source)
            with open(os.path.join(source, "SKILL.md"), "w", encoding="utf-8") as handle:
                handle.write("# benign\n")

            with (
                patch(
                    "defenseclaw.commands.cmd_skill._validate_staged_skill_tree",
                    side_effect=[True, False],
                ) as validate_tree,
                self.assertRaises(SystemExit),
            ):
                _stage_skill_tree_for_connector(
                    source,
                    install_root,
                    "benign-skill",
                    force=False,
                    stages={},
                )

            self.assertEqual(validate_tree.call_count, 2)
            self.assertFalse(os.path.exists(os.path.join(install_root, "benign-skill")))
            self.assertEqual(os.listdir(install_root), [])

    @unittest.skipUnless(os.name == "nt", "native Windows resolver/CLI test")
    def test_extensionless_only_wrapper_is_concise_cli_error(self):
        with tempfile.TemporaryDirectory() as bin_dir:
            with open(os.path.join(bin_dir, "clawhub"), "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 99\n")
            with (
                patch.dict(os.environ, {"PATH": bin_dir, "PATHEXT": ".CMD;.EXE"}),
                patch(
                    "defenseclaw.commands.cmd_skill.os.getcwd",
                    return_value=bin_dir,
                ),
            ):
                app, root, database = make_app_context()
                try:
                    result = CliRunner().invoke(
                        skill,
                        ["install", "benign-skill"],
                        obj=app,
                        catch_exceptions=False,
                    )
                finally:
                    cleanup_app(app, database, root)

            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("neither a launchable clawhub nor npx", result.output)
            self.assertNotIn("Traceback", result.output)

    @patch("defenseclaw.commands.cmd_skill.shutil.which", return_value="/opt/bin/clawhub")
    @patch("defenseclaw.commands.cmd_skill.os.name", "posix")
    def test_non_windows_resolver_keeps_extensionless_executable(self, _which):
        from defenseclaw.commands.cmd_skill import _resolve_command

        self.assertEqual(_resolve_command("clawhub"), os.path.abspath("/opt/bin/clawhub"))

    def test_external_output_capture_is_bounded(self):
        from defenseclaw.commands.cmd_skill import _CLAWHUB_OUTPUT_LIMIT, _run_clawhub_process

        result = _run_clawhub_process(
            [os.path.abspath(sys.executable), "-c", "import sys; sys.stderr.write('x' * 100000)"],
            timeout=30,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stderr.encode("utf-8")), _CLAWHUB_OUTPUT_LIMIT)

    @unittest.skipUnless(os.name == "nt", "native Windows command-script test")
    def test_cmd_argument_metacharacters_are_not_commands(self):
        from defenseclaw.commands.cmd_skill import _run_clawhub_process

        with tempfile.TemporaryDirectory(prefix="clawhub argv ") as fixture:
            helper = os.path.join(fixture, "capture.py")
            launcher = os.path.join(fixture, "clawhub.cmd")
            captured = os.path.join(fixture, "captured.txt")
            injected = os.path.join(fixture, "injected.txt")
            with open(helper, "w", encoding="utf-8") as handle:
                handle.write(
                    "import pathlib, sys\npathlib.Path(sys.argv[1]).write_text(sys.argv[2], encoding='utf-8')\n"
                )
            with open(launcher, "w", encoding="utf-8") as handle:
                handle.write(f'@"{sys.executable}" "{helper}" %*\n')
            payload = f"space & echo injected>{injected} | more ^ 100% ! (safe)"

            result = _run_clawhub_process(
                [os.path.abspath(launcher), captured, payload],
                timeout=30,
                cwd=fixture,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            with open(captured, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), payload)
            self.assertFalse(os.path.exists(injected))



class TestSkillInstall(SkillCommandTestBase):
    def _fake_clawhub_install(self, skill_name: str, _force: bool, cwd: str | None = None):
        stage_root = cwd or self.tmp_dir
        skill_dir = os.path.join(stage_root, "skills", skill_name)
        os.makedirs(skill_dir, exist_ok=True)
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(f"# {skill_name}\n")

    def test_install_help_describes_configured_connector_targets(self):
        result = self.invoke(["install", "--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        output = re.sub(r"\s+", " ", result.output)
        self.assertIn("configured connector skill dirs", output)
        self.assertIn("default: every configured connector", output)
        self.assertNotIn("OpenClaw skill", output)

    @patch("defenseclaw.commands.cmd_skill._run_clawhub_install")
    def test_install_rejects_traversal_before_launcher(self, mock_install):
        result = self.invoke(["install", "../benign-skill"])

        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("invalid ClawHub skill name", result.output)
        mock_install.assert_not_called()

    @patch("defenseclaw.commands.cmd_skill._resolve_command", return_value="C:\\bin\\clawhub.cmd")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_launch_oserror_is_concise_and_staging_is_cleaned(self, mock_run, _resolve):
        staged: list[str] = []

        def fail_launch(_argv, **kwargs):
            staged.append(kwargs["cwd"])
            raise OSError(193, "not a valid application")

        mock_run.side_effect = fail_launch
        result = self.invoke(["install", "benign-skill"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("could not launch clawhub install", result.output)
        self.assertNotIn("Traceback", result.output)
        self.assertNotIn("installed 'benign-skill' ->", result.output)
        self.assertEqual(len(staged), 1)
        self.assertFalse(os.path.exists(staged[0]))

    @patch("defenseclaw.commands.cmd_skill._resolve_command", return_value="C:\\bin\\clawhub.cmd")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_launch_access_denied_and_disappeared_are_concise(self, mock_run, _resolve):
        for failure in (PermissionError(13, "access denied"), FileNotFoundError("disappeared")):
            with self.subTest(failure=type(failure).__name__):
                mock_run.side_effect = failure
                result = self.invoke(["install", "benign-skill"])
                self.assertEqual(result.exit_code, 1, result.output)
                self.assertIn("could not launch clawhub install", result.output)
                self.assertNotIn("Traceback", result.output)
                self.assertNotIn("installed 'benign-skill' ->", result.output)

    @patch("defenseclaw.commands.cmd_skill._resolve_command", return_value="C:\\bin\\clawhub.cmd")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_child_nonzero_preserves_bounded_diagnostic(self, mock_run, _resolve):
        mock_run.return_value = subprocess.CompletedProcess(
            ["clawhub"],
            7,
            "",
            "registry rejected package",
        )

        result = self.invoke(["install", "benign-skill"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("registry rejected package", result.output)
        self.assertNotIn("installed 'benign-skill' ->", result.output)

    @unittest.skipUnless(os.name == "nt", "native Windows ClawHub acceptance test")
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    def test_native_windows_cmd_installs_codex_skill_once(self, mock_scan, mock_eval):
        from defenseclaw.enforce.admission import AdmissionDecision

        bin_dir = os.path.join(self.tmp_dir, "npm bin with spaces")
        codex_root = os.path.join(self.tmp_dir, "codex home", "skills")
        os.makedirs(bin_dir)
        os.makedirs(codex_root)
        extensionless = os.path.join(bin_dir, "clawhub")
        launcher = os.path.join(bin_dir, "clawhub.cmd")
        helper = os.path.join(bin_dir, "stage_skill.py")
        marker = os.path.join(bin_dir, "calls.txt")
        with open(extensionless, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\nexit 99\n")
        with open(helper, "w", encoding="utf-8") as handle:
            handle.write(
                "import os, pathlib, sys\n"
                "name = sys.argv[2]\n"
                "root = pathlib.Path.cwd() / 'skills' / name\n"
                "root.mkdir(parents=True)\n"
                "(root / 'SKILL.md').write_text('# benign fixture\\n', encoding='utf-8')\n"
                "marker = pathlib.Path(os.environ['DEFENSECLAW_TEST_MARKER'])\n"
                "marker.write_text(marker.read_text() + '1' if marker.exists() else '1')\n"
            )
        with open(launcher, "w", encoding="utf-8") as handle:
            handle.write(f'@"{sys.executable}" "{helper}" %*\n')

        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: [codex_root]  # type: ignore[method-assign]
        destination = os.path.join(codex_root, "benign-skill")
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner", target=destination,
            timestamp=datetime.now(timezone.utc), findings=[],
            duration=timedelta(seconds=0.1),
        )
        mock_eval.return_value = AdmissionDecision("clean", "clean")

        with patch.dict(
            os.environ,
            {
                "PATH": bin_dir,
                "PATHEXT": ".CMD;.EXE;.BAT;.COM",
                "DEFENSECLAW_TEST_MARKER": marker,
            },
        ):
            result = self.invoke(["install", "benign-skill", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("Traceback", result.output)
        self.assertTrue(os.path.isfile(os.path.join(destination, "SKILL.md")))
        with open(marker, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "1")

    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_install")
    def test_install_post_scan_allow_skips_warning(self, mock_install, mock_scan, mock_eval):
        from defenseclaw.enforce.admission import AdmissionDecision

        mock_install.side_effect = self._fake_clawhub_install
        skill_dir = os.path.join(self.tmp_dir, "skills", "late-allow")
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner",
            target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="Shell injection", scanner="skill-scanner")],
            duration=timedelta(seconds=0.5),
        )
        mock_eval.side_effect = [
            AdmissionDecision("scan", "scan required"),
            AdmissionDecision("allowed", "approved during scan", source="manual-allow"),
        ]

        result = self.invoke(["install", "late-allow"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("became allow-listed", result.output)
        self.assertNotIn("no action taken", result.output)
        events = [e for e in self.app.store.list_events(20) if e.action == "install-allowed"]
        self.assertEqual(len(events), 1)
        self.assertIn("allow-listed-post-scan", events[0].details)

    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_install")
    def test_install_audit_names_the_config_generation_of_its_decision(self, mock_install, mock_scan, mock_eval):
        # r103 GAP-0021: the install-allowed row said generation 0 while a
        # reload applied a newer generation during the install.
        from defenseclaw.enforce.admission import AdmissionDecision

        mock_install.side_effect = self._fake_clawhub_install
        skill_dir = os.path.join(self.tmp_dir, "skills", "gen-stamp")
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner", target=skill_dir, timestamp=datetime.now(timezone.utc),
            findings=[], duration=timedelta(seconds=0.1),
        )
        mock_eval.side_effect = [AdmissionDecision("allowed", "on the allow list", source="manual-allow")]
        self.app.cfg._loaded_generation = 6

        result = self.invoke(["install", "gen-stamp"])

        self.assertEqual(result.exit_code, 0, result.output)
        events = [e for e in self.app.store.list_events(20) if e.action == "install-allowed"]
        self.assertEqual(len(events), 1)
        self.assertIn("config_generation=6", events[0].details)

    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_install")
    def test_install_findings_the_admission_action_allows_are_not_an_allow_list_hit(
        self, mock_install, mock_scan, mock_eval
    ):
        from defenseclaw.enforce.admission import AdmissionDecision

        mock_install.side_effect = self._fake_clawhub_install
        skill_dir = os.path.join(self.tmp_dir, "skills", "low-finding")
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner",
            target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="LOW", title="Minor", scanner="skill-scanner")],
            duration=timedelta(seconds=0.5),
        )
        mock_eval.side_effect = [
            AdmissionDecision("scan", "scan required"),
            AdmissionDecision("allowed", "1 finding, max LOW", source="scan-allowed"),
        ]

        result = self.invoke(["install", "low-finding"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("allow-listed", result.output)
        events = [e for e in self.app.store.list_events(20) if e.action == "install-allowed"]
        self.assertEqual(len(events), 1)
        self.assertIn("admission-action-allow", events[0].details)

    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_install")
    def test_install_connector_resolves_installed_skill_on_that_connector(
        self, mock_install, mock_scan, mock_eval,
    ):
        from defenseclaw.enforce.admission import AdmissionDecision

        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        codex_root = os.path.join(self.tmp_dir, "codex", "skills")
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        os.makedirs(codex_root)
        os.makedirs(hermes_root)
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "codex": [codex_root],
            "hermes": [hermes_root],
        }.get(connector, [codex_root])
        skill_dir = os.path.join(hermes_root, "late-allow")
        mock_install.side_effect = self._fake_clawhub_install
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner",
            target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(seconds=0.5),
        )
        mock_eval.side_effect = [
            AdmissionDecision("scan", "scan required"),
            AdmissionDecision("clean", "clean"),
        ]

        result = self.invoke(["install", "late-allow", "--connector", "hermes"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_scan.assert_called_once()
        self.assertEqual(_installed_path(mock_scan.call_args.args[0]), skill_dir)
        self.assertTrue(os.path.isfile(os.path.join(skill_dir, "SKILL.md")))

    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_install")
    def test_install_bare_name_installs_every_connector_copy(
        self, mock_install, mock_scan, mock_eval,
    ):
        from defenseclaw.enforce.admission import AdmissionDecision

        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        codex_root = os.path.join(self.tmp_dir, "codex", "skills")
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        os.makedirs(codex_root)
        os.makedirs(hermes_root)
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "codex": [codex_root],
            "hermes": [hermes_root],
        }.get(connector, [codex_root])
        mock_install.side_effect = self._fake_clawhub_install
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner",
            target="late-allow",
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(seconds=0.5),
        )
        mock_eval.side_effect = [
            AdmissionDecision("scan", "scan required"),
            AdmissionDecision("scan", "scan required"),
            AdmissionDecision("clean", "clean"),
            AdmissionDecision("clean", "clean"),
        ]

        result = self.invoke(["install", "late-allow"])

        self.assertEqual(result.exit_code, 0, result.output)
        codex_skill = os.path.join(codex_root, "late-allow")
        hermes_skill = os.path.join(hermes_root, "late-allow")
        self.assertTrue(os.path.isfile(os.path.join(codex_skill, "SKILL.md")))
        self.assertTrue(os.path.isfile(os.path.join(hermes_skill, "SKILL.md")))
        self.assertEqual(
            [_installed_path(call.args[0]) for call in mock_scan.call_args_list],
            [codex_skill, hermes_skill],
        )

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_clean_skill(self, mock_scanner_cls, _mock_info):
        skill_dir = os.path.join(self.tmp_dir, "clean-skill")
        os.makedirs(skill_dir)

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            scanner="skill-scanner",
            target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(seconds=0.5),
        )
        mock_scanner_cls.return_value = mock_scanner

        result = self.invoke(["scan", "clean-skill", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("CLEAN", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_dirty_skill(self, mock_scanner_cls, _mock_info):
        skill_dir = os.path.join(self.tmp_dir, "dirty-skill")
        os.makedirs(skill_dir)

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            scanner="skill-scanner",
            target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[
                Finding(id="f1", severity="HIGH", title="Shell injection", scanner="skill-scanner"),
            ],
            duration=timedelta(seconds=1.2),
        )
        mock_scanner_cls.return_value = mock_scanner

        result = self.invoke(["scan", "dirty-skill", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("HIGH", result.output)
        self.assertIn("Shell injection", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_json_output(self, mock_scanner_cls, _mock_info):
        skill_dir = os.path.join(self.tmp_dir, "json-skill")
        os.makedirs(skill_dir)
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            scanner="skill-scanner",
            target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(seconds=0.3),
        )
        mock_scanner_cls.return_value = mock_scanner

        result = self.invoke(["scan", "json-skill", "--path", skill_dir, "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(data["scanner"], "skill-scanner")
        self.assertNotIn("connector", data)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    def test_scan_unresolvable_skill_errors(self, _mock_info):
        result = self.invoke(["scan", "nonexistent-skill"])
        self.assertNotEqual(result.exit_code, 0)


class TestSkillQuarantine(SkillCommandTestBase):
    def test_quarantine_and_restore_cycle(self):
        skill_dir = os.path.join(self.tmp_dir, "skills", "qskill")
        os.makedirs(skill_dir)
        with open(os.path.join(skill_dir, "main.py"), "w") as f:
            f.write("pass\n")

        # Set up quarantine dir in config
        self.app.cfg.quarantine_dir = os.path.join(self.tmp_dir, "quarantine")

        result = self.invoke(["quarantine", skill_dir, "--reason", "sus"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("quarantined", result.output)
        self.assertFalse(os.path.exists(skill_dir))

        pe = PolicyEngine(self.app.store, self.app.cfg)
        self.assertTrue(pe.is_quarantined("skill", "qskill"))

        result = self.invoke(["restore", "qskill", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("restored", result.output)
        self.assertTrue(os.path.exists(skill_dir))
        self.assertTrue(os.path.isfile(os.path.join(skill_dir, "main.py")))

    def test_quarantine_nonexistent_skill_errors(self):
        self.app.cfg.quarantine_dir = os.path.join(self.tmp_dir, "quarantine")
        result = self.invoke(["quarantine", "/nonexistent/path/ghost-skill"])
        self.assertNotEqual(result.exit_code, 0)

    def test_quarantine_rejects_skill_root_path(self):
        skill_root = os.path.join(self.tmp_dir, "skills")
        os.makedirs(os.path.join(skill_root, "child-skill"), exist_ok=True)

        self.app.cfg.quarantine_dir = os.path.join(self.tmp_dir, "quarantine")

        result = self.invoke(["quarantine", skill_root])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("specific skill directory", result.output)
        self.assertTrue(os.path.isdir(skill_root))

    def test_restore_non_quarantined_errors(self):
        self.app.cfg.quarantine_dir = os.path.join(self.tmp_dir, "quarantine")
        result = self.invoke(["restore", "not-quarantined"])
        self.assertNotEqual(result.exit_code, 0)

    def _wire_two_connectors(self):
        """Point skill_dirs at per-connector dirs for codex + claudecode."""
        codex_dir = os.path.join(self.tmp_dir, ".codex", "skills")
        claude_dir = os.path.join(self.tmp_dir, ".claude", "skills")
        os.makedirs(codex_dir, exist_ok=True)
        os.makedirs(claude_dir, exist_ok=True)
        self.app.cfg.quarantine_dir = os.path.join(self.tmp_dir, "quarantine")
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "codex": [codex_dir],
            "claudecode": [claude_dir],
        }.get(connector, [codex_dir])
        return codex_dir, claude_dir

    def test_quarantine_finds_skill_in_non_primary_connector(self):
        # A skill living ONLY in a non-primary connector's dir must still be
        # quarantine-able by name (union search across active connectors).
        _codex_dir, claude_dir = self._wire_two_connectors()
        peer = os.path.join(claude_dir, "peer-skill")
        os.makedirs(peer)
        with open(os.path.join(peer, "main.py"), "w") as f:
            f.write("pass\n")

        result = self.invoke(["quarantine", "peer-skill", "--reason", "sus"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("quarantined", result.output)
        self.assertFalse(os.path.isdir(peer))

    def test_quarantine_bare_name_quarantines_every_connector_copy(self):
        codex_dir, claude_dir = self._wire_two_connectors()
        for d in (codex_dir, claude_dir):
            os.makedirs(os.path.join(d, "dup-skill"))

        result = self.invoke(["quarantine", "dup-skill"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=claudecode", result.output)
        self.assertIn("connector=codex", result.output)
        self.assertFalse(os.path.isdir(os.path.join(codex_dir, "dup-skill")))
        self.assertFalse(os.path.isdir(os.path.join(claude_dir, "dup-skill")))
        self.assertTrue(os.path.isdir(
            os.path.join(self.app.cfg.quarantine_dir, "skills", "codex", "dup-skill")
        ))
        self.assertTrue(os.path.isdir(
            os.path.join(self.app.cfg.quarantine_dir, "skills", "claudecode", "dup-skill")
        ))
        pe = PolicyEngine(self.app.store, self.app.cfg)
        self.assertTrue(pe.is_quarantined_for_connector("skill", "dup-skill", "codex"))
        self.assertTrue(pe.is_quarantined_for_connector("skill", "dup-skill", "claudecode"))
        self.assertFalse(pe.is_quarantined("skill", "dup-skill"))

    def test_quarantine_connector_scopes_to_one_copy(self):
        codex_dir, claude_dir = self._wire_two_connectors()
        for d in (codex_dir, claude_dir):
            os.makedirs(os.path.join(d, "dup-skill"))

        result = self.invoke(["quarantine", "dup-skill", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(os.path.isdir(os.path.join(codex_dir, "dup-skill")))
        self.assertTrue(os.path.isdir(os.path.join(claude_dir, "dup-skill")))
        pe = PolicyEngine(self.app.store, self.app.cfg)
        self.assertTrue(pe.is_quarantined_for_connector("skill", "dup-skill", "codex"))
        self.assertFalse(pe.is_quarantined_for_connector("skill", "dup-skill", "claudecode"))
        self.assertFalse(pe.is_quarantined("skill", "dup-skill"))
        self.assertEqual(
            pe.get_action("skill", "dup-skill", "codex").source_path,
            os.path.realpath(os.path.join(codex_dir, "dup-skill")),
        )

    def test_restore_connector_scoped_quarantine_clears_scoped_row(self):
        codex_dir, _claude_dir = self._wire_two_connectors()
        skill_dir = os.path.join(codex_dir, "restore-skill")
        os.makedirs(skill_dir)
        with open(os.path.join(skill_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write("pass\n")

        result = self.invoke(["quarantine", "restore-skill", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(os.path.isdir(skill_dir))
        pe = PolicyEngine(self.app.store, self.app.cfg)
        self.assertTrue(pe.is_quarantined_for_connector("skill", "restore-skill", "codex"))

        result = self.invoke(["restore", "restore-skill", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isdir(skill_dir))
        self.assertFalse(pe.is_quarantined_for_connector("skill", "restore-skill", "codex"))
        self.assertFalse(self.app.store.has_action("skill", "restore-skill", "file", "quarantine", "codex"))

    def test_restore_bare_name_resolves_single_connector_scoped_quarantine(self):
        codex_dir, _claude_dir = self._wire_two_connectors()
        skill_dir = os.path.join(codex_dir, "restore-skill")
        os.makedirs(skill_dir)
        with open(os.path.join(skill_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write("pass\n")

        result = self.invoke(["quarantine", "restore-skill", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)

        result = self.invoke(["restore", "restore-skill"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isdir(skill_dir))
        self.assertFalse(
            self.app.store.has_action("skill", "restore-skill", "file", "quarantine", "codex")
        )

    def test_restore_bare_name_restores_every_connector_scoped_quarantine(self):
        codex_dir, claude_dir = self._wire_two_connectors()
        codex_skill = os.path.join(codex_dir, "restore-skill")
        claude_skill = os.path.join(claude_dir, "restore-skill")
        os.makedirs(codex_skill)
        os.makedirs(claude_skill)
        with open(os.path.join(codex_skill, "main.py"), "w", encoding="utf-8") as f:
            f.write("pass\n")
        with open(os.path.join(claude_skill, "main.py"), "w", encoding="utf-8") as f:
            f.write("pass\n")

        result = self.invoke(["quarantine", "restore-skill"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(os.path.isdir(codex_skill))
        self.assertFalse(os.path.isdir(claude_skill))

        result = self.invoke(["restore", "restore-skill"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isdir(codex_skill))
        self.assertTrue(os.path.isdir(claude_skill))
        self.assertFalse(
            self.app.store.has_action("skill", "restore-skill", "file", "quarantine", "codex")
        )
        self.assertFalse(
            self.app.store.has_action("skill", "restore-skill", "file", "quarantine", "claudecode")
        )

    def test_restore_rejects_unknown_connector_before_quarantine_lookup(self):
        self._wire_two_connectors()

        result = self.invoke(["restore", "restore-skill", "--connector", "nope"])

        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("not configured", result.output)


class TestSkillList(SkillCommandTestBase):
    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full", return_value=None)
    def test_list_no_skills(self, _mock):
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No skills found", result.output)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_list_with_skills(self, mock_list):
        mock_list.return_value = {
            "skills": [
                {"name": "web-search", "description": "Search the web", "emoji": "",
                 "eligible": True, "disabled": False, "blockedByAllowlist": False,
                 "source": "bundled", "bundled": True, "homepage": ""},
                {"name": "code-review", "description": "Review code", "emoji": "",
                 "eligible": True, "disabled": False, "blockedByAllowlist": False,
                 "source": "user", "bundled": False, "homepage": ""},
            ]
        }
        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("web-search", result.output)
        self.assertIn("code-review", result.output)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_list_marks_vendor_bundled_skills_discovery_only(self, mock_list):
        """GAP-1085: bundled skills looked scannable in skill list."""
        mock_list.return_value = {
            "skills": [
                {"name": "imagegen", "description": "", "emoji": "",
                 "eligible": True, "disabled": False, "blockedByAllowlist": False,
                 "source": "bundled", "bundled": True, "homepage": ""},
            ]
        }
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(
            "1 vendor-bundled skill(s) are discovery-only",
            " ".join(result.output.split()),
        )

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_bundled_skill_ignores_a_verdict_on_another_copy(self, mock_list):
        """GAP-0393: another connector's quarantined skill-creator marked the
        vendor-bundled skill-creator quarantined and disabled."""
        mock_list.return_value = {
            "skills": [
                {"name": "skill-creator", "description": "", "emoji": "",
                 "eligible": True, "disabled": False, "blockedByAllowlist": False,
                 "source": "bundled", "bundled": True, "homepage": ""},
            ]
        }
        self.app.store.set_action_field("skill", "skill-creator", "file", "quarantine", "watcher")
        self.app.store.set_action_field("skill", "skill-creator", "runtime", "disable", "watcher")
        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        [item] = json.loads(result.output)
        self.assertFalse(item["disabled"])
        self.assertNotIn("actions", item)
        self.assertEqual(item["verdict"], "-")

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_list_says_quarantine_failed_when_the_move_failed(self, mock_list):
        """GAP-0394: a blocked skill the watcher could not move read as quarantined."""
        mock_list.return_value = {
            "skills": [
                {"name": "aws-deploy", "description": "", "emoji": "",
                 "eligible": True, "disabled": False, "blockedByAllowlist": False,
                 "source": "user", "bundled": False, "homepage": ""},
            ]
        }
        self.app.store.set_action_field(
            "skill", "aws-deploy", "install", "block", "quarantine failed: permission denied",
        )
        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        [item] = json.loads(result.output)
        self.assertEqual(item["verdict"], "quarantine failed")
        self.assertEqual(item["reason"], "quarantine failed: permission denied")
        with patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=mock_list.return_value["skills"][0]):
            info = self.invoke(["info", "aws-deploy", "--json"])
            self.assertEqual(info.exit_code, 0, info.output)
            self.assertEqual(json.loads(info.output)["reason"], item["reason"])
            card = self.invoke(["info", "aws-deploy"])
            self.assertIn("permission denied", card.output)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_list_shows_a_skill_the_watcher_has_not_scanned_as_pending(self, mock_list):
        """GAP-0341: an unscanned skill read active/ready, as if clean."""
        base = os.path.join(self.tmp_dir, "skills", "bulk-7")
        mock_list.return_value = {
            "skills": [
                {"name": "bulk-7", "description": "", "emoji": "", "baseDir": base,
                 "eligible": True, "disabled": False, "blockedByAllowlist": False,
                 "source": "user", "bundled": False, "homepage": ""},
            ]
        }
        with open(os.path.join(self.app.cfg.data_dir, "watcher-admission.json"), "w", encoding="utf-8") as fh:
            json.dump({"assets": [{"type": "skill", "name": "bulk-7", "path": base, "state": "pending"}]}, fh)
        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        [item] = json.loads(result.output)
        self.assertEqual(item["status"], "pending")

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_list_table_title_shows_connector_in_scope(self, mock_list):
        # Mirror the MCP table's (connector=...) banner so the active
        # connector the list is scoped to is discoverable.
        mock_list.return_value = {
            "skills": [
                {"name": "web-search", "description": "Search", "emoji": "",
                 "eligible": True, "disabled": False, "blockedByAllowlist": False,
                 "source": "bundled", "bundled": True, "homepage": ""},
            ]
        }
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=openclaw", result.output)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_list_uses_single_visual_row_per_skill_on_narrow_terminals(self, mock_list):
        mock_list.return_value = {
            "skills": [
                {
                    "name": "apple-notes",
                    "description": (
                        "Manage Apple Notes via the memo CLI on macOS "
                        "(create, search, update) with a longer text to force wrapping"
                    ),
                    "emoji": "📝",
                    "eligible": False,
                    "disabled": False,
                    "blockedByAllowlist": False,
                    "source": "openclaw-bundled",
                    "bundled": True,
                    "homepage": "",
                },
            ]
        }

        old_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "80"
        try:
            result = self.invoke(["list"])
        finally:
            if old_columns is None:
                os.environ.pop("COLUMNS", None)
            else:
                os.environ["COLUMNS"] = old_columns

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("apple", result.output)
        self.assertNotIn("\n│           │", result.output)

    def test_skill_display_name_puts_emoji_after_name(self):
        self.assertEqual(
            _skill_display_name({"name": "apple-notes", "emoji": "📝"}),
            "apple-notes 📝",
        )
        self.assertEqual(
            _skill_display_name({"name": "healthcheck", "emoji": ""}),
            "healthcheck",
        )

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_list_json(self, mock_list):
        mock_list.return_value = {
            "skills": [
                {"name": "test-skill", "description": "Test", "emoji": "",
                 "eligible": True, "disabled": False, "blockedByAllowlist": False,
                 "source": "user", "bundled": False, "homepage": ""},
            ]
        }
        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["name"], "test-skill")
        self.assertEqual(data[0]["status"], "active")

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_list_merges_enforcement_only_entries(self, mock_list):
        """Skills only in the actions DB (quarantined/blocked) should appear in list."""
        mock_list.return_value = {
            "skills": [
                {"name": "visible-skill", "description": "Still here", "emoji": "",
                 "eligible": True, "disabled": False, "blockedByAllowlist": False,
                 "source": "user", "bundled": False, "homepage": ""},
            ]
        }
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.block("skill", "removed-skill", "quarantined after scan")

        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("visible-skill", result.output)
        self.assertIn("removed-skill", result.output)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_list_merges_scan_only_entries(self, mock_list):
        """Skills with scan history but no longer in OpenClaw should appear."""
        mock_list.return_value = {"skills": []}

        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/old/path/ghost-skill",
            datetime.now(timezone.utc), 500, 1, "MEDIUM", "{}",
        )

        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("ghost-skill", result.output)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_list_unblocked_skill_with_quarantined_files_is_quarantined(self, mock_list):
        # GAP-2008: after a bare unblock the files stay in quarantine until an
        # explicit restore, so the row says quarantined, not removed.
        mock_list.return_value = {"skills": []}
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/h/.claude/skills/held-skill",
            datetime.now(timezone.utc), 500, 1, "CRITICAL", "{}",
        )
        self.app.store.create_quarantine_record(
            "skill", "held-skill", "/h/.claude/skills/held-skill",
            "/h/.defenseclaw/quarantine/skills/amp/held-skill", "sha256:x",
            "watcher enforcement", "amp", state="active",
        )

        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("quarantined", result.output)
        self.assertNotIn("removed", result.output)

    def test_failed_quarantine_with_a_kept_record_is_not_quarantined(self):
        # A quarantine that published its copy but could not remove the
        # source keeps its pending record; the skill is still in place, so
        # the journal's "quarantine failed" wins over the record.
        from defenseclaw.commands.cmd_skill import _build_actions_map
        from defenseclaw.models import ActionState

        self.app.store.set_action(
            "skill", "stuck-skill", "/h/.claude/skills/stuck-skill",
            ActionState(install="block"), "quarantine failed: remove quarantined source: permission denied",
        )
        self.app.store.create_quarantine_record(
            "skill", "stuck-skill", "/h/.claude/skills/stuck-skill",
            "/h/.defenseclaw/quarantine/skills/stuck-skill", "sha256:x",
            "watcher enforcement", "",
        )

        entry = _build_actions_map(self.app.store)["stuck-skill"]
        self.assertEqual(entry.actions.install, "block")
        self.assertNotEqual(entry.actions.file, "quarantine")
        self.assertTrue(entry.reason.startswith("quarantine failed: "), entry.reason)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_list_no_duplicate_entries(self, mock_list):
        """If a skill is in both OpenClaw list and actions DB, it shouldn't appear twice."""
        mock_list.return_value = {
            "skills": [
                {"name": "my-skill", "description": "Active", "emoji": "",
                 "eligible": True, "disabled": False, "blockedByAllowlist": False,
                 "source": "user", "bundled": False, "homepage": ""},
            ]
        }
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.allow("skill", "my-skill", "trusted")

        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        names = [d["name"] for d in data]
        self.assertEqual(names.count("my-skill"), 1)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full", return_value=None)
    def test_list_enforcement_only_shows_blocked_status(self, _mock):
        """Blocked-only entries (no OpenClaw data) should show blocked status."""
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.block("skill", "banned-skill", "dangerous")

        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("banned-skill", result.output)
        self.assertIn("blocked", result.output)


class TestSkillInfo(SkillCommandTestBase):
    def _configure_native_info_fixture(self, skill_name: str) -> dict[str, str]:
        roots = {
            connector: os.path.join(self.tmp_dir, connector, "skills")
            for connector in ("claudecode", "codex")
        }
        for root in roots.values():
            skill_dir = os.path.join(root, skill_name)
            os.makedirs(skill_dir)
            with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as marker:
                marker.write("---\ndescription: synthetic status fixture\n---\n")
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: [  # type: ignore[method-assign]
            roots[connector or "claudecode"]
        ] if (connector or "claudecode") in roots else []
        return roots

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    def test_info_unknown_skill_errors(self, _mock):
        # SK-2: a true miss errors (exit 1) instead of rendering a blank card
        # that implies the skill exists.
        result = self.invoke(["info", "definitely-not-a-skill"])
        self.assertEqual(result.exit_code, 1, result.output)
        # GAP-2003: same shape as policy show / mcp scan misses, with a next step.
        self.assertIn(
            "Error: skill 'definitely-not-a-skill' not found. "
            "Run `defenseclaw skill list` to see installed skills.",
            result.output,
        )

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    def test_info_renders_scan_history_phantom(self, _mock):
        # SK-2 open decision: a name present only in scan history stays
        # inspectable (a removed-but-scanned skill), not an error.
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/path/to/ghost-skill",
            datetime.now(timezone.utc), 400, 3, "HIGH", "{}",
        )
        result = self.invoke(["info", "ghost-skill"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("ghost-skill", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    def test_info_renders_enforcement_phantom(self, _mock):
        # A name present only as an enforcement action also stays inspectable.
        PolicyEngine(self.app.store, self.app.cfg).block("skill", "blocked-ghost", "test")
        result = self.invoke(["info", "blocked-ghost"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("blocked-ghost", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_info_severity_labels_max_not_count(self, mock_info):
        # SK-3: the count is labelled plainly and the *severity word* carries
        # the colour — no "{n} CRITICAL findings" conflation.
        mock_info.return_value = {"name": "mixed-skill", "eligible": True}
        self.app.cfg.skill_dirs = lambda connector=None: ["/path/to"]  # type: ignore[method-assign]
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/path/to/mixed-skill",
            datetime.now(timezone.utc), 500, 5, "CRITICAL", "{}",
        )
        result = self.invoke(["info", "mixed-skill"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("5 findings", result.output)
        self.assertIn("max severity:", result.output)
        self.assertNotIn("5 CRITICAL findings", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_info_states_policy_verdict_and_singular_finding(self, mock_info):
        mock_info.return_value = {"name": "one-skill", "eligible": True}
        self.app.cfg.skill_dirs = lambda connector=None: ["/path/to"]  # type: ignore[method-assign]
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/path/to/one-skill",
            datetime.now(timezone.utc), 500, 1, "CRITICAL", "{}",
        )
        result = self.invoke(["info", "one-skill"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("1 finding ", result.output)
        self.assertNotIn("1 findings", result.output)
        self.assertIn("Policy:", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_info_known_skill(self, mock_info):
        mock_info.return_value = {
            "name": "web-search",
            "description": "Search the web",
            "source": "bundled",
            "baseDir": "/path/to/skill",
            "eligible": True,
            "bundled": True,
        }
        result = self.invoke(["info", "web-search"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("web-search", result.output)
        self.assertIn("Search the web", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_info_bare_name_resolves_non_active_peer(self, mock_info):
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]

        def info_impl(_name, app=None, connector=None):
            if connector == "hermes":
                return {
                    "name": "peer-skill",
                    "description": "Hermes only",
                    "source": "user",
                    "baseDir": "/hermes/peer-skill",
                    "eligible": True,
                    "bundled": False,
                }
            return None

        mock_info.side_effect = info_impl

        result = self.invoke(["info", "peer-skill"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Hermes only", result.output)
        self.assertIn("/hermes/peer-skill", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_info_connector_scope_still_prints_connector_label(self, mock_info):
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]

        def info_impl(_name, app=None, connector=None):
            return {
                "name": "dup-skill",
                "description": f"{connector} copy",
                "baseDir": f"/{connector}/dup-skill",
                "eligible": True,
                "bundled": False,
            }

        mock_info.side_effect = info_impl

        codex = self.invoke(["info", "dup-skill", "--connector", "codex"])
        hermes = self.invoke(["info", "dup-skill", "--connector", "hermes"])

        self.assertEqual(codex.exit_code, 0, codex.output)
        self.assertIn("Connector:   codex", codex.output)
        self.assertIn("codex copy", codex.output)
        self.assertNotIn("Connector:   hermes", codex.output)

        self.assertEqual(hermes.exit_code, 0, hermes.output)
        self.assertIn("Connector:   hermes", hermes.output)
        self.assertIn("hermes copy", hermes.output)
        self.assertNotIn("Connector:   codex", hermes.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_info_bare_name_shows_every_connector_copy(self, mock_info):
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]

        def info_impl(_name, app=None, connector=None):
            if connector in {"codex", "hermes"}:
                return {
                    "name": "dup-skill",
                    "description": f"{connector} copy",
                    "baseDir": f"/{connector}/dup-skill",
                    "eligible": True,
                    "bundled": False,
                }
            return None

        mock_info.side_effect = info_impl
        PolicyEngine(self.app.store, self.app.cfg).block_for_connector(
            "skill",
            "dup-skill",
            "hermes",
            "scoped test",
        )

        result = self.invoke(["info", "dup-skill"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Connector:   codex", result.output)
        self.assertIn("Connector:   hermes", result.output)
        self.assertIn("codex copy", result.output)
        self.assertIn("hermes copy", result.output)
        self.assertRegex(
            result.output,
            r"(?s)Connector:\s+codex.*?Actions:\s+-.*?"
            r"Connector:\s+hermes.*?Actions:\s+blocked",
        )

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_info_global_action_does_not_create_missing_connector_cards(self, mock_info):
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: [  # type: ignore[method-assign]
            "antigravity",
            "codex",
            "hermes",
            "opencode",
        ]

        def info_impl(_name, app=None, connector=None):
            if connector in {"codex", "hermes"}:
                return {
                    "name": "dup-skill",
                    "description": f"{connector} copy",
                    "baseDir": f"/{connector}/dup-skill",
                    "eligible": True,
                    "bundled": False,
                }
            return None

        mock_info.side_effect = info_impl
        PolicyEngine(self.app.store, self.app.cfg).block("skill", "dup-skill", "global test")

        result = self.invoke(["info", "dup-skill"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("Connector:   antigravity", result.output)
        self.assertIn("Connector:   codex", result.output)
        self.assertIn("Connector:   hermes", result.output)
        self.assertNotIn("Connector:   opencode", result.output)
        self.assertRegex(
            result.output,
            r"(?s)Connector:\s+codex.*?Actions:\s+blocked.*?"
            r"Connector:\s+hermes.*?Actions:\s+blocked",
        )

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    def test_info_connector_does_not_show_other_connector_scan_history(self, _mock_info):
        codex_root = os.path.join(self.tmp_dir, "codex", "skills")
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        os.makedirs(codex_root)
        os.makedirs(os.path.join(hermes_root, "dc-scope-skill"))
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "codex": [codex_root],
            "hermes": [hermes_root],
        }.get(connector, [codex_root])
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner",
            os.path.join(hermes_root, "dc-scope-skill"),
            datetime.now(timezone.utc), 400, 1, "INFO", "{}",
        )

        result = self.invoke(["info", "dc-scope-skill", "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("not found", result.output)
        self.assertNotIn("Last Scan", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_info_bare_name_shows_each_connector_scan_history(self, mock_info):
        codex_root = os.path.join(self.tmp_dir, "codex", "skills")
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        os.makedirs(os.path.join(codex_root, "dc-scope-skill"))
        os.makedirs(os.path.join(hermes_root, "dc-scope-skill"))
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "codex": [codex_root],
            "hermes": [hermes_root],
        }.get(connector, [codex_root])

        def info_impl(_name, app=None, connector=None):
            root = {"codex": codex_root, "hermes": hermes_root}.get(connector)
            if root:
                return {
                    "name": "dc-scope-skill",
                    "baseDir": os.path.join(root, "dc-scope-skill"),
                    "eligible": True,
                    "bundled": False,
                }
            return None

        mock_info.side_effect = info_impl
        codex_target = os.path.join(codex_root, "dc-scope-skill")
        hermes_target = os.path.join(hermes_root, "dc-scope-skill")
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", codex_target,
            datetime.now(timezone.utc), 400, 1, "LOW", "{}",
        )
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", hermes_target,
            datetime.now(timezone.utc), 400, 2, "MEDIUM", "{}",
        )

        result = self.invoke(["info", "dc-scope-skill"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertRegex(
            result.output,
            rf"(?s)Connector:\s+codex.*?Target:\s+{re.escape(codex_target)}.*?"
            rf"Connector:\s+hermes.*?Target:\s+{re.escape(hermes_target)}",
        )

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_info_json(self, mock_info):
        mock_info.return_value = {
            "name": "my-skill",
            "description": "desc",
            "eligible": True,
            "bundled": False,
        }
        result = self.invoke(["info", "my-skill", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(data["name"], "my-skill")

    def test_info_reports_scoped_runtime_disable_and_reenable_for_native_connectors(self):
        skill_name = "runtime-status-skill"
        self._configure_native_info_fixture(skill_name)

        for disabled_connector, peer_connector in (
            ("claudecode", "codex"),
            ("codex", "claudecode"),
        ):
            with self.subTest(disabled_connector=disabled_connector):
                disabled = self.invoke([
                    "disable", skill_name, "--connector", disabled_connector,
                ])
                self.assertEqual(disabled.exit_code, 0, disabled.output)

                scoped_json = self.invoke([
                    "info", skill_name, "--connector", disabled_connector, "--json",
                ])
                self.assertEqual(scoped_json.exit_code, 0, scoped_json.output)
                scoped_data = json.loads(scoped_json.output)
                self.assertIs(scoped_data["disabled"], True)
                self.assertEqual(scoped_data["actions"]["runtime"], "disable")

                peer_json = self.invoke([
                    "info", skill_name, "--connector", peer_connector, "--json",
                ])
                self.assertEqual(peer_json.exit_code, 0, peer_json.output)
                self.assertIs(json.loads(peer_json.output)["disabled"], False)

                listed = self.invoke([
                    "list", "--connector", disabled_connector, "--json",
                ])
                self.assertEqual(listed.exit_code, 0, listed.output)
                listed_item = next(
                    item for item in json.loads(listed.output)["skills"]
                    if item["name"] == skill_name
                )
                self.assertIs(listed_item["disabled"], True)
                self.assertEqual(listed_item["status"], "disabled")

                scoped_text = self.invoke([
                    "info", skill_name, "--connector", disabled_connector,
                ])
                peer_text = self.invoke([
                    "info", skill_name, "--connector", peer_connector,
                ])
                self.assertIn("Disabled:    True", scoped_text.output)
                self.assertIn("Disabled:    False", peer_text.output)

                enabled = self.invoke([
                    "enable", skill_name, "--connector", disabled_connector,
                ])
                self.assertEqual(enabled.exit_code, 0, enabled.output)
                restored = self.invoke([
                    "info", skill_name, "--connector", disabled_connector, "--json",
                ])
                self.assertEqual(restored.exit_code, 0, restored.output)
                self.assertIs(json.loads(restored.output)["disabled"], False)

    def test_info_reports_global_runtime_disable_with_per_field_scoped_fallback(self):
        skill_name = "global-runtime-status-skill"
        self._configure_native_info_fixture(skill_name)
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.disable("skill", skill_name, "global fixture")
        pe.allow_for_connector("skill", skill_name, "codex", "unrelated scoped field")

        for connector in ("claudecode", "codex"):
            with self.subTest(connector=connector):
                result = self.invoke([
                    "info", skill_name, "--connector", connector, "--json",
                ])
                self.assertEqual(result.exit_code, 0, result.output)
                data = json.loads(result.output)
                self.assertIs(data["disabled"], True)
                self.assertEqual(data["actions"]["runtime"], "disable")
        codex = json.loads(self.invoke([
            "info", skill_name, "--connector", "codex", "--json",
        ]).output)
        self.assertEqual(codex["actions"]["install"], "allow")

        pe.enable("skill", skill_name)
        for connector in ("claudecode", "codex"):
            result = self.invoke([
                "info", skill_name, "--connector", connector, "--json",
            ])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIs(json.loads(result.output)["disabled"], False)

    def test_info_normalizes_claude_connector_alias_for_runtime_state(self):
        skill_name = "alias-runtime-status-skill"
        claude_config_dir = os.path.join(self.tmp_dir, "alias-claude-config")
        claude_skill_dir = os.path.join(claude_config_dir, "skills", skill_name)
        openclaw_skill_dir = os.path.join(self.tmp_dir, "skills", "openclaw-only")
        os.makedirs(claude_skill_dir)
        os.makedirs(openclaw_skill_dir)
        with open(os.path.join(claude_skill_dir, "SKILL.md"), "w", encoding="utf-8") as marker:
            marker.write("---\ndescription: canonical Claude fixture\n---\n")
        with open(os.path.join(openclaw_skill_dir, "SKILL.md"), "w", encoding="utf-8") as marker:
            marker.write("---\ndescription: wrong connector fixture\n---\n")
        self.app.cfg.active_connector = lambda: "claude-code"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claude-code", "codex"]  # type: ignore[method-assign]

        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": claude_config_dir}):
            listed = self.invoke(["list", "--connector", "claude-code", "--json"])
            self.assertEqual(listed.exit_code, 0, listed.output)
            listed_names = {
                item["name"] for item in json.loads(listed.output)["skills"]
            }
            self.assertIn(skill_name, listed_names)
            self.assertNotIn("openclaw-only", listed_names)

            disabled = self.invoke([
                "disable", skill_name, "--connector", "claude-code",
            ])
            self.assertEqual(disabled.exit_code, 0, disabled.output)
            self.assertTrue(self.app.store.has_action(
                "skill", skill_name, "runtime", "disable", "claudecode",
            ))

            reported = self.invoke([
                "info", skill_name, "--connector", "claude-code", "--json",
            ])
            self.assertEqual(reported.exit_code, 0, reported.output)
            reported_data = json.loads(reported.output)
            self.assertIs(reported_data["disabled"], True)
            self.assertEqual(reported_data["description"], "canonical Claude fixture")

            enabled = self.invoke([
                "enable", skill_name, "--connector", "claude-code",
            ])
            self.assertEqual(enabled.exit_code, 0, enabled.output)
            restored = self.invoke([
                "info", skill_name, "--connector", "claude-code", "--json",
            ])
            self.assertEqual(restored.exit_code, 0, restored.output)
            restored_data = json.loads(restored.output)
            self.assertIs(restored_data["disabled"], False)
            self.assertEqual(restored_data["description"], "canonical Claude fixture")


# ---------------------------------------------------------------------------
# _skill_status_display with action entries
# ---------------------------------------------------------------------------

class TestSkillStatusDisplay(unittest.TestCase):
    def test_ready(self):
        self.assertIn("ready", _skill_status_display({"eligible": True}))

    def test_disabled_from_openclaw(self):
        self.assertIn("disabled", _skill_status_display({"disabled": True}))

    def test_blocked_from_openclaw(self):
        self.assertIn("blocked", _skill_status_display({"blockedByAllowlist": True}))

    def test_quarantined_from_actions(self):
        ae = MagicMock()
        ae.actions = ActionState(file="quarantine", runtime="", install="")
        result = _skill_status_display({}, ae)
        self.assertIn("quarantined", result)

    def test_blocked_from_actions(self):
        ae = MagicMock()
        ae.actions = ActionState(file="", runtime="", install="block")
        result = _skill_status_display({}, ae)
        self.assertIn("blocked", result)

    def test_disabled_from_actions(self):
        ae = MagicMock()
        ae.actions = ActionState(file="", runtime="disable", install="")
        result = _skill_status_display({}, ae)
        self.assertIn("disabled", result)

    def test_removed_for_enforcement_source(self):
        result = _skill_status_display({"source": "enforcement"})
        self.assertIn("removed", result)

    def test_removed_for_scan_history_source(self):
        result = _skill_status_display({"source": "scan-history"})
        self.assertIn("removed", result)

    def test_missing_when_no_info(self):
        result = _skill_status_display({})
        self.assertIn("missing", result)

    def test_scan_findings_do_not_change_state(self):
        # Findings are the Verdict column; Status says whether it is loaded.
        scan = {"max_severity": "CRITICAL"}
        self.assertIn("ready", _skill_status_display({"eligible": True}, None, scan))
        self.assertIn("removed", _skill_status_display({"source": "scan-history"}, None, scan))

    def test_openclaw_disabled_takes_precedence_over_actions(self):
        ae = MagicMock()
        ae.actions = ActionState(file="quarantine", runtime="disable", install="block")
        result = _skill_status_display({"disabled": True}, ae)
        self.assertIn("disabled", result)
        self.assertNotIn("quarantined", result)


# ---------------------------------------------------------------------------
# _build_scan_map (CLEAN severity)
# ---------------------------------------------------------------------------

class TestBuildScanMap(SkillCommandTestBase):
    def test_build_scan_map_empty(self):
        scan_map = _build_scan_map(self.app.store)
        self.assertEqual(scan_map, {})

    def test_build_scan_map_with_findings(self):
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/path/to/my-skill",
            datetime.now(timezone.utc), 500, 2, "HIGH", "{}",
        )
        scan_map = _build_scan_map(self.app.store)
        self.assertIn("my-skill", scan_map)
        self.assertEqual(scan_map["my-skill"]["max_severity"], "HIGH")
        self.assertEqual(scan_map["my-skill"]["total_findings"], 2)
        self.assertFalse(scan_map["my-skill"]["clean"])

    def test_build_scan_map_clean_shows_clean(self):
        """Zero-finding scans should show CLEAN, not INFO."""
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/path/to/clean-skill",
            datetime.now(timezone.utc), 300, 0, None, "{}",
        )
        scan_map = _build_scan_map(self.app.store)
        self.assertIn("clean-skill", scan_map)
        self.assertEqual(scan_map["clean-skill"]["max_severity"], "CLEAN")
        self.assertTrue(scan_map["clean-skill"]["clean"])

    def test_build_scan_map_none_store(self):
        scan_map = _build_scan_map(None)
        self.assertEqual(scan_map, {})


class TestBuildActionsMap(SkillCommandTestBase):
    def test_build_actions_map_empty(self):
        from defenseclaw.commands.cmd_skill import _build_actions_map
        actions_map = _build_actions_map(self.app.store)
        self.assertEqual(actions_map, {})

    def test_build_actions_map_with_data(self):
        from defenseclaw.commands.cmd_skill import _build_actions_map
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.block("skill", "bad-skill", "test")
        actions_map = _build_actions_map(self.app.store, cfg=self.app.cfg)
        self.assertIn("bad-skill", actions_map)
        self.assertEqual(actions_map["bad-skill"].actions.install, "block")


# ---------------------------------------------------------------------------
# skill search
# ---------------------------------------------------------------------------

class TestSkillSearch(SkillCommandTestBase):
    # F-1481: `skill search` must not let `npx` fetch+execute the third-party
    # clawhub package from the network on every read-only search. The default
    # path prefers a locally-installed clawhub binary, and otherwise uses
    # `npx --no-install` (cached only, never network-fetched). Plain `npx`
    # (network fetch + execute) is gated behind explicit --allow-remote-fetch.

    @patch("defenseclaw.commands.cmd_skill._resolve_command")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_search_default_uses_npx_no_install_no_network_fetch(self, mock_run, mock_resolve):
        # No local clawhub binary, no opt-in: must use `npx --no-install` so npx
        # refuses to download+execute the package from the network.
        mock_resolve.side_effect = lambda name, **_kwargs: None if name == "clawhub" else "/bin/npx"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="wiki  Wiki  (3.504)\nwiki-local  WikiLocal  (3.392)\n",
            stderr="",
        )
        result = self.invoke(["search", "wiki"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("wiki", result.output)
        self.assertIn("wiki-local", result.output)
        mock_run.assert_called_once_with(
            ["/bin/npx", "--no-install", "clawhub", "search", "wiki"],
            timeout=30,
        )
        # Must never invoke the network-fetching plain `npx clawhub`.
        self.assertNotIn(
            ["/bin/npx", "clawhub", "search", "wiki"],
            [c.args[0] for c in mock_run.call_args_list],
        )

    @patch("defenseclaw.commands.cmd_skill._resolve_command", return_value="/usr/local/bin/clawhub")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_search_prefers_local_clawhub_binary(self, mock_run, _resolve):
        # A locally-installed pinned binary is run directly — no npx, no fetch.
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="wiki  Wiki  (3.504)\n",
            stderr="",
        )
        result = self.invoke(["search", "wiki"])
        self.assertEqual(result.exit_code, 0, result.output)
        mock_run.assert_called_once_with(
            ["/usr/local/bin/clawhub", "search", "wiki"],
            timeout=30,
        )

    @patch("defenseclaw.commands.cmd_skill._resolve_command")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_search_allow_remote_fetch_opts_into_npx_network_fetch(self, mock_run, mock_resolve):
        # Explicit opt-in re-enables the original fetch+execute behavior.
        mock_resolve.side_effect = lambda name, **_kwargs: None if name == "clawhub" else "/bin/npx"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="wiki  Wiki  (3.504)\n",
            stderr="",
        )
        result = self.invoke(["search", "wiki", "--allow-remote-fetch"])
        self.assertEqual(result.exit_code, 0, result.output)
        mock_run.assert_called_once_with(
            ["/bin/npx", "clawhub", "search", "wiki"],
            timeout=30,
        )

    @patch("defenseclaw.commands.cmd_skill._resolve_command", return_value="/bin/clawhub")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_search_no_results(self, mock_run, _resolve):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = self.invoke(["search", "zzz_nonexistent"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No skills found", result.output)

    @patch("defenseclaw.commands.cmd_skill._resolve_command", return_value="/bin/clawhub")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_search_json_no_results_outputs_empty_array(self, mock_run, _resolve):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = self.invoke(["search", "dc-skill-does-not-exist", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(result.output), [])
        self.assertNotIn("No skills found", result.output)

    @patch("defenseclaw.commands.cmd_skill._resolve_command", return_value="/bin/clawhub")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_search_json_output(self, mock_run, _resolve):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="wiki  Wiki  (3.504)\n",
            stderr="",
        )
        result = self.invoke(["search", "wiki", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertIsInstance(data, list)
        self.assertTrue(len(data) >= 1)

    @patch("defenseclaw.commands.cmd_skill._resolve_command", return_value=None)
    def test_search_npx_not_found(self, _resolve):
        result = self.invoke(["search", "wiki"])
        self.assertNotEqual(result.exit_code, 0)

    @patch("defenseclaw.commands.cmd_skill._resolve_command")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_search_clawhub_failure_hints_at_remote_fetch(self, mock_run, mock_resolve):
        # `npx --no-install` fails when clawhub isn't cached; the error must
        # point at --allow-remote-fetch rather than silently fetching.
        mock_resolve.side_effect = lambda name, **_kwargs: None if name == "clawhub" else "/bin/npx"
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="npm ERR! could not determine executable",
        )
        result = self.invoke(["search", "wiki"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--allow-remote-fetch", result.output)

    @patch("defenseclaw.commands.cmd_skill._resolve_command", return_value="/bin/clawhub")
    @patch(
        "defenseclaw.commands.cmd_skill._run_clawhub_process",
        side_effect=__import__("subprocess").TimeoutExpired(cmd="clawhub", timeout=30),
    )
    def test_search_timeout(self, _mock, _resolve):
        result = self.invoke(["search", "wiki"])
        self.assertNotEqual(result.exit_code, 0)


class TestSkillScanRemote(SkillCommandTestBase):
    """Tests for remote scan via sidecar API."""

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.gateway.OrchestratorClient.scan_skill")
    def test_scan_remote_returns_results(self, mock_scan_skill, _mock_info):
        skill_dir = os.path.join(self.tmp_dir, "remote-skill")
        os.makedirs(skill_dir)

        mock_scan_skill.return_value = {
            "scanner": "skill-scanner",
            "target": "/home/ubuntu/.openclaw/skills/remote-skill",
            "findings": [
                {"severity": "HIGH", "title": "Shell injection", "id": "f1"},
            ],
            "max_severity": "HIGH",
        }

        result = self.invoke(["scan", "remote-skill", "--path", skill_dir, "--remote"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("remote", result.output)
        self.assertIn("HIGH", result.output)
        self.assertIn("Shell injection", result.output)
        mock_scan_skill.assert_called_once()

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.gateway.OrchestratorClient.scan_skill")
    def test_scan_remote_clean(self, mock_scan_skill, _mock_info):
        skill_dir = os.path.join(self.tmp_dir, "clean-remote")
        os.makedirs(skill_dir)

        mock_scan_skill.return_value = {
            "scanner": "skill-scanner",
            "target": skill_dir,
            "findings": [],
            "max_severity": "INFO",
        }

        result = self.invoke(["scan", "clean-remote", "--path", skill_dir, "--remote"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("CLEAN", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.gateway.OrchestratorClient.scan_skill")
    def test_scan_remote_json_output(self, mock_scan_skill, _mock_info):
        skill_dir = os.path.join(self.tmp_dir, "json-remote")
        os.makedirs(skill_dir)

        expected = {
            "scanner": "skill-scanner",
            "target": skill_dir,
            "findings": [],
        }
        mock_scan_skill.return_value = expected

        result = self.invoke(["scan", "json-remote", "--path", skill_dir, "--remote", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(data["scanner"], "skill-scanner")

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.gateway.OrchestratorClient.scan_skill", side_effect=Exception("connection refused"))
    def test_scan_remote_failure(self, _mock_scan, _mock_info):
        skill_dir = os.path.join(self.tmp_dir, "fail-remote")
        os.makedirs(skill_dir)

        result = self.invoke(["scan", "fail-remote", "--path", skill_dir, "--remote"])
        self.assertNotEqual(result.exit_code, 0)


class TestSkillScanURL(SkillCommandTestBase):
    """Tests for fetch-to-temp scan from URL."""

    def test_is_url_target(self):
        from defenseclaw.commands.cmd_skill import _is_url_target

        self.assertTrue(_is_url_target("https://example.com/skill.tar.gz"))
        self.assertTrue(_is_url_target("http://example.com/skill.tar.gz"))
        self.assertTrue(_is_url_target("clawhub://my-skill@1.2.3"))
        self.assertFalse(_is_url_target("my-skill"))
        self.assertFalse(_is_url_target("/path/to/skill"))

    def test_parse_clawhub_uri(self):
        from defenseclaw.commands.cmd_skill import _parse_clawhub_uri

        name, version = _parse_clawhub_uri("clawhub://my-skill@1.2.3")
        self.assertEqual(name, "my-skill")
        self.assertEqual(version, "1.2.3")

    def test_parse_clawhub_uri_latest(self):
        from defenseclaw.commands.cmd_skill import _parse_clawhub_uri

        name, version = _parse_clawhub_uri("clawhub://my-skill")
        self.assertEqual(name, "my-skill")
        self.assertIsNone(version)

    @patch("defenseclaw.registries.adapters._base.http_get")
    def test_versioned_clawhub_scan_refuses_before_fetch(self, mock_http_get):
        result = self.invoke(["scan", "clawhub://weather@1.0.0"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("version", result.output.lower())
        mock_http_get.assert_not_called()

        mock_http_get.return_value = b'{"dist":{"tarball":"https://other.example/openclaw.tgz"}}'
        result = self.invoke(["scan", "clawhub://weather"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("untrusted", result.output.lower())
        self.assertEqual(mock_http_get.call_count, 1)

    @patch("defenseclaw.registries.adapters._base.http_get")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_from_url_tar(self, mock_scanner_cls, mock_http_get):
        import tarfile

        # Create a tar.gz with a skill inside
        skill_tmpdir = tempfile.mkdtemp()
        skill_dir = os.path.join(skill_tmpdir, "test-skill")
        os.makedirs(skill_dir)
        with open(os.path.join(skill_dir, "skill.yaml"), "w") as f:
            f.write("name: test-skill\n")

        tar_path = os.path.join(skill_tmpdir, "skill.tar.gz")
        with tarfile.open(tar_path, "w:gz") as tf:
            tf.add(skill_dir, arcname="test-skill")

        with open(tar_path, "rb") as f:
            tar_bytes = f.read()

        shutil.rmtree(skill_tmpdir)

        mock_http_get.return_value = tar_bytes

        # Mock scanner
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            scanner="skill-scanner",
            target="/tmp/test-skill",
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(seconds=0.1),
        )
        mock_scanner_cls.return_value = mock_scanner

        result = self.invoke(["scan", "https://example.com/skill.tar.gz"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("CLEAN", result.output)
        mock_scanner.scan.assert_called_once()


class TestVerdictBreakdown(SkillCommandTestBase):
    """Verdict line shows per-severity counts, not the total finding count."""

    def _scan_result(self, skill_dir, findings):
        return ScanResult(
            scanner="skill-scanner",
            target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            duration=timedelta(seconds=0.2),
        )

    def _finding(self, severity, title="finding"):
        return Finding(
            id=str(uuid.uuid4()), severity=severity, title=title,
            scanner="skill-scanner",
        )

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_verdict_shows_breakdown_not_total(self, mock_cls, _mock_info):
        """Mixed severities: verdict label is max severity with per-severity counts."""
        skill_dir = os.path.join(self.tmp_dir, "mixed-skill")
        os.makedirs(skill_dir)
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = self._scan_result(skill_dir, [
            self._finding("CRITICAL", "Token leak"),
            self._finding("HIGH", "Shell exec"),
            self._finding("MEDIUM", "Code exec A"),
            self._finding("MEDIUM", "Code exec B"),
            self._finding("INFO", "No license"),
        ])
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "mixed-skill", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("CRITICAL", result.output)
        # The detailed verdict line still includes the per-severity
        # breakdown — that's the contract this test was originally
        # protecting. The new S6.3 top-line "(5 findings)" sits *above*
        # the breakdown so users still see both.
        self.assertIn("1 critical", result.output)
        self.assertIn("1 high", result.output)
        self.assertIn("2 medium", result.output)
        self.assertIn("1 info", result.output)
        # The breakdown line itself must not be the bare-count form —
        # check that "Verdict: CRITICAL (5 findings)" is NOT how we
        # surface the verdict (we want the per-severity counts there).
        self.assertNotIn("Verdict:  CRITICAL (5 findings)", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_verdict_single_severity(self, mock_cls, _mock_info):
        """Only one severity present — shows just that count."""
        skill_dir = os.path.join(self.tmp_dir, "high-only")
        os.makedirs(skill_dir)
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = self._scan_result(skill_dir, [
            self._finding("HIGH", "Issue A"),
            self._finding("HIGH", "Issue B"),
            self._finding("HIGH", "Issue C"),
        ])
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "high-only", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("HIGH", result.output)
        self.assertIn("3 high", result.output)
        self.assertNotIn("critical", result.output)
        self.assertNotIn("medium", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_verdict_label_is_max_severity(self, mock_cls, _mock_info):
        """Verdict label reflects worst severity even when it has only 1 finding."""
        skill_dir = os.path.join(self.tmp_dir, "one-critical")
        os.makedirs(skill_dir)
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = self._scan_result(skill_dir, [
            self._finding("CRITICAL", "Token leaked"),
            self._finding("MEDIUM", "Risky call"),
            self._finding("MEDIUM", "Risky call 2"),
        ])
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "one-critical", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        # Label should be CRITICAL (worst), not MEDIUM (most common)
        self.assertIn("CRITICAL", result.output)
        self.assertIn("1 critical", result.output)
        self.assertIn("2 medium", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_verdict_clean_unchanged(self, mock_cls, _mock_info):
        """No findings still shows CLEAN — breakdown logic doesn't affect clean path."""
        skill_dir = os.path.join(self.tmp_dir, "clean-skill2")
        os.makedirs(skill_dir)
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = self._scan_result(skill_dir, [])
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "clean-skill2", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("CLEAN", result.output)
        self.assertNotIn("findings", result.output)


class TestSkillListConnectorFlag(SkillCommandTestBase):
    """WU13 L1: ``skill list --connector`` validates and threads the
    override into the data fetch (TUI focus selector relies on this)."""

    def test_unknown_connector_rejected(self):
        result = self.invoke(["list", "--connector", "definitely-not-a-connector"])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("not configured", result.output)

    @patch(
        "defenseclaw.commands.cmd_skill._list_openclaw_skills_full",
        return_value={"skills": []},
    )
    def test_active_connector_threaded(self, mock_full):
        active = self.app.cfg.active_connector()
        result = self.invoke(["list", "--connector", active, "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(mock_full.call_args.kwargs.get("connector"), active)
        data = json.loads(result.output)
        self.assertEqual(data, {"connector": active, "skills": []})


class TestSkillListMultiConnectorDefault(SkillCommandTestBase):
    """Default ``skill list`` (no --connector) fans out across every active
    connector on a multi-connector install, while a single-connector install
    keeps its single-table behaviour."""

    @staticmethod
    def _per_connector_skills(app=None, connector=None):
        return {
            "skills": [
                {
                    "name": f"{connector}-skill",
                    "description": f"{connector} only",
                    "emoji": "",
                    "eligible": True,
                    "disabled": False,
                    "blockedByAllowlist": False,
                    "source": "user",
                    "bundled": False,
                    "homepage": "",
                }
            ]
        }

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_default_lists_every_active_connector(self, mock_list):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        mock_list.side_effect = self._per_connector_skills

        result = self.invoke(["list"])

        self.assertEqual(result.exit_code, 0, result.output)
        # Each connector gets its own connector-tagged table (skill names
        # themselves may be ellipsized by rich's column width — the exact
        # per-connector names are asserted in the --json test below).
        self.assertIn("connector=claudecode", result.output)
        self.assertIn("connector=codex", result.output)
        fetched = {c.kwargs.get("connector") for c in mock_list.call_args_list}
        self.assertEqual(fetched, {"claudecode", "codex"})

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_default_json_groups_by_connector(self, mock_list):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        mock_list.side_effect = self._per_connector_skills

        result = self.invoke(["list", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual([g["connector"] for g in data], ["claudecode", "codex"])
        self.assertEqual(data[0]["skills"][0]["name"], "claudecode-skill")
        self.assertEqual(data[0]["skills"][0]["connector"], "claudecode")
        self.assertEqual(data[1]["skills"][0]["name"], "codex-skill")
        self.assertEqual(data[1]["skills"][0]["connector"], "codex")

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_connector_flag_still_narrows_to_one(self, mock_list):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        mock_list.side_effect = self._per_connector_skills

        result = self.invoke(["list", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("codex-skill", result.output)
        self.assertNotIn("claudecode-skill", result.output)
        fetched = {c.kwargs.get("connector") for c in mock_list.call_args_list}
        self.assertEqual(fetched, {"codex"})

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_connector_flag_json_uses_envelope(self, mock_list):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        mock_list.side_effect = self._per_connector_skills

        result = self.invoke(["list", "--json", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(data["connector"], "codex")
        self.assertEqual(data["skills"][0]["name"], "codex-skill")
        self.assertEqual(data["skills"][0]["connector"], "codex")

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_single_connector_install_keeps_flat_json(self, mock_list):
        # Default single-connector install: active_connectors() returns one
        # name, so JSON stays a flat list (no per-connector grouping).
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]
        mock_list.side_effect = self._per_connector_skills

        result = self.invoke(["list", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertIsInstance(data, list)
        self.assertEqual(data[0]["name"], "claudecode-skill")
        self.assertNotIn("connector", data[0])

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full")
    def test_identical_skill_names_use_each_connector_latest_scan(self, mock_list):
        roots = {
            connector: os.path.join(self.tmp_dir, connector, "skills")
            for connector in ("codex", "devin")
        }
        for root in roots.values():
            os.makedirs(os.path.join(root, "codeguard"))
        self.app.cfg.active_connectors = lambda: ["codex", "devin"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: [roots[connector]]  # type: ignore[method-assign]
        mock_list.return_value = {
            "skills": [{
                "name": "codeguard",
                "description": "connector-local copy",
                "eligible": True,
                "source": "user",
            }],
        }

        codex_target = os.path.join(roots["codex"], "codeguard")
        devin_target = os.path.join(roots["devin"], "codeguard")
        now = datetime.now(timezone.utc)
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", codex_target,
            now - timedelta(minutes=1), 400, 1, "LOW", "{}",
        )
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", devin_target,
            now, 400, 7, "HIGH", "{}",
        )

        result = self.invoke(["list", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        groups = {group["connector"]: group["skills"] for group in json.loads(result.output)}
        codex_scan = groups["codex"][0]["scan"]
        devin_scan = groups["devin"][0]["scan"]
        self.assertEqual(codex_scan["target"], codex_target)
        self.assertEqual(codex_scan["total_findings"], 1)
        self.assertEqual(devin_scan["target"], devin_target)
        self.assertEqual(devin_scan["total_findings"], 7)


    @unittest.skipUnless(os.name == "nt", "Windows path casing semantics")
    @patch(
        "defenseclaw.commands.cmd_skill._list_openclaw_skills_full",
        return_value={"skills": []},
    )
    def test_removed_skill_scan_matches_connector_root_case_insensitively(self, _mock_list):
        codex_root = os.path.join(self.tmp_dir, "Codex", "skills")
        os.makedirs(codex_root)
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda _connector=None: [codex_root]  # type: ignore[method-assign]
        target = os.path.join(codex_root.swapcase(), "removed-skill")
        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", target,
            datetime.now(timezone.utc), 400, 2, "MEDIUM", "{}",
        )

        result = self.invoke(["list", "--json", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        self.assertEqual(data["skills"][0]["name"], "removed-skill")
        self.assertEqual(data["skills"][0]["scan"]["target"], target)


class TestSkillListOpencodeNative(SkillCommandTestBase):
    def test_opencode_lists_native_skill_not_openclaw_paths(self):
        root = os.path.join(self.tmp_dir, ".opencode", "skills")
        skill_dir = os.path.join(root, "reviewer")
        os.makedirs(skill_dir)
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("---\nname: reviewer\ndescription: Review code\n---\n")
        self.app.cfg.active_connector = lambda: "opencode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["opencode"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: [root] if connector == "opencode" else []  # type: ignore[method-assign]

        result = self.invoke(["list", "--connector", "opencode"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("reviewer", result.output)
        self.assertNotIn(".openclaw", result.output)


class TestSkillDisableHonesty(SkillCommandTestBase):
    """SK-5b: runtime-disable output describes only native enforceable gates."""

    def test_disable_on_hook_connector_records_global_advisory(self):
        self.app.cfg.active_connector = lambda: "hermes"  # type: ignore[method-assign]

        with patch("defenseclaw.commands.cmd_skill._sidecar_client") as mock_client:
            result = self.invoke(["disable", "some-skill"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("runtime disable recorded globally", result.output)
        self.assertIn("advisory", result.output)
        self.assertIn("quarantine", result.output)
        self.assertTrue(self.app.store.has_action("skill", "some-skill", "runtime", "disable"))
        mock_client.assert_not_called()

    def test_disable_connector_without_probe_records_scoped_advisory(self):
        self.app.cfg.active_connectors = lambda: ["hermes", "codex"]  # type: ignore[method-assign]
        with patch("defenseclaw.commands.cmd_skill._sidecar_client") as mock_client:
            result = self.invoke(["disable", "some-skill", "--connector", "hermes"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertIn("advisory", result.output)
        self.assertTrue(
            self.app.store.has_action("skill", "some-skill", "runtime", "disable", "hermes")
        )
        mock_client.assert_not_called()

    def test_disable_connector_with_native_gate_records_scoped_enforced(self):
        self.app.cfg.active_connectors = lambda: ["hermes", "codex"]  # type: ignore[method-assign]
        with patch("defenseclaw.commands.cmd_skill._sidecar_client") as mock_client:
            result = self.invoke(["disable", "some-skill", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=codex", result.output)
        self.assertIn("Codex UserPromptSubmit gate", result.output)
        self.assertNotIn("advisory", result.output)
        self.assertTrue(
            self.app.store.has_action("skill", "some-skill", "runtime", "disable", "codex")
        )
        mock_client.assert_not_called()

    def test_disable_claudecode_claims_only_native_expansion_gate(self):
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        with patch("defenseclaw.commands.cmd_skill._sidecar_client") as mock_client:
            result = self.invoke(
                ["disable", "some-skill", "--connector", "claudecode"]
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Claude Code UserPromptExpansion gate", result.output)
        self.assertNotIn("hook runtime gate", result.output)
        self.assertNotIn("advisory", result.output)
        self.assertTrue(
            self.app.store.has_action(
                "skill", "some-skill", "runtime", "disable", "claudecode"
            )
        )
        mock_client.assert_not_called()

    def test_enable_connector_clears_scoped_disable_without_gateway(self):
        self.app.cfg.active_connectors = lambda: ["hermes", "codex"]  # type: ignore[method-assign]
        PolicyEngine(self.app.store, self.app.cfg).disable_for_connector(
            "skill", "some-skill", "hermes", "manual",
        )

        with patch("defenseclaw.commands.cmd_skill._sidecar_client") as mock_client:
            result = self.invoke(["enable", "some-skill", "--connector", "hermes"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("runtime disable cleared", result.output)
        self.assertFalse(
            self.app.store.has_action("skill", "some-skill", "runtime", "disable", "hermes")
        )
        mock_client.assert_not_called()

    def test_disable_bare_name_records_every_matching_connector_copy(self):
        self.app.cfg.active_connectors = lambda: ["hermes", "codex"]  # type: ignore[method-assign]
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        codex_root = os.path.join(self.tmp_dir, "codex", "skills")
        os.makedirs(os.path.join(hermes_root, "sample"))
        os.makedirs(os.path.join(codex_root, "sample"))
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "hermes": [hermes_root],
            "codex": [codex_root],
        }.get(connector, [hermes_root])

        with patch("defenseclaw.commands.cmd_skill._sidecar_client") as mock_client:
            result = self.invoke(["disable", "sample"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertIn("connector=codex", result.output)
        self.assertTrue(
            self.app.store.has_action("skill", "sample", "runtime", "disable", "hermes")
        )
        self.assertTrue(
            self.app.store.has_action("skill", "sample", "runtime", "disable", "codex")
        )
        self.assertFalse(self.app.store.has_action("skill", "sample", "runtime", "disable"))
        mock_client.assert_not_called()

    def test_enable_bare_name_clears_every_matching_connector_copy(self):
        self.app.cfg.active_connectors = lambda: ["hermes", "codex"]  # type: ignore[method-assign]
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        codex_root = os.path.join(self.tmp_dir, "codex", "skills")
        os.makedirs(os.path.join(hermes_root, "sample"))
        os.makedirs(os.path.join(codex_root, "sample"))
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "hermes": [hermes_root],
            "codex": [codex_root],
        }.get(connector, [hermes_root])
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.disable("skill", "sample", "legacy global")
        pe.disable_for_connector("skill", "sample", "hermes", "manual")
        pe.disable_for_connector("skill", "sample", "codex", "manual")

        with patch("defenseclaw.commands.cmd_skill._sidecar_client") as mock_client:
            result = self.invoke(["enable", "sample"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertIn("connector=codex", result.output)
        self.assertFalse(
            self.app.store.has_action("skill", "sample", "runtime", "disable", "hermes")
        )
        self.assertFalse(
            self.app.store.has_action("skill", "sample", "runtime", "disable", "codex")
        )
        self.assertFalse(self.app.store.has_action("skill", "sample", "runtime", "disable"))
        mock_client.assert_not_called()

    @patch("defenseclaw.commands.cmd_skill._sidecar_client")
    def test_disable_on_openclaw_still_calls_gateway(self, mock_client):
        self.app.cfg.active_connector = lambda: "openclaw"  # type: ignore[method-assign]
        mock_client.return_value.disable_skill.return_value = {"status": "disabled"}

        result = self.invoke(["disable", "some-skill"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_client.return_value.disable_skill.assert_called_once_with("some-skill")


class TestSkillConnectorPolicyValidation(SkillCommandTestBase):
    def setUp(self):
        super().setUp()
        self.app.cfg.active_connectors = lambda: ["hermes", "codex"]  # type: ignore[method-assign]


    def test_block_is_refused_on_a_managed_standalone_device(self):
        # config_version 9: the admin config is the only block/allow source
        # on a managed device, so a local block writes nothing.
        self.app.cfg.deployment_mode = "managed_enterprise"
        with patch.dict(os.environ, {"DEFENSECLAW_ENTERPRISE_PROFILE": "standalone"}):
            result = self.runner.invoke(skill, ["block", "sample"], obj=self.app)
        self.assertEqual(result.exit_code, 3, result.output)
        self.assertIn("This device is managed", result.output)
        self.assertEqual(self.app.cfg.asset_policy.skill.denied, [])

    def test_unblock_is_refused_and_audited_on_a_managed_standalone_device(self):
        # The journal's runtime disable is still enforced by the gateway, so a
        # local unblock must not delete it; the refused attempt is audited.
        self.app.store.set_action_field("skill", "sample", "runtime", "disable", "scan verdict", "")
        self.app.cfg.deployment_mode = "managed_enterprise"
        with patch.dict(os.environ, {"DEFENSECLAW_ENTERPRISE_PROFILE": "standalone"}), \
                patch.object(self.app.logger, "log_action") as log_action:
            result = self.runner.invoke(skill, ["unblock", "sample"], obj=self.app)
        self.assertEqual(result.exit_code, 3, result.output)
        self.assertTrue(self.app.store.has_action("skill", "sample", "runtime", "disable"))
        log_action.assert_called_once_with(
            "skill-unblock", "sample", "outcome=refused reason=managed_device type=skill",
        )
    def test_bare_unblock_clears_global_allow_row(self):
        PolicyEngine(self.app.store, self.app.cfg).allow("skill", "sample", "manual")

        result = self.invoke(["unblock", "sample"])

        self.assertEqual(result.exit_code, 0, result.output)
        # GAP-2085: the bare unblock names the scope a bare block names.
        self.assertIn("[skill] Unblocked 'sample' (every connector).", result.output)
        self.assertIn("It will be scanned on the next check.", result.output)
        self.assertFalse(asset_lists.has_entry(self.app.cfg, self.app.store, "skill", "sample", "", "allow"))
        self.assertIsNone(self.app.store.get_action("skill", "sample"))

    def test_bare_block_output_names_matching_connector_copies(self):
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        codex_root = os.path.join(self.tmp_dir, "codex", "skills")
        os.makedirs(os.path.join(hermes_root, "sample"))
        os.makedirs(os.path.join(codex_root, "sample"))
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "hermes": [hermes_root],
            "codex": [codex_root],
        }.get(connector, [hermes_root])

        result = self.invoke(["block", "sample"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(
            "[skill] Blocked 'sample' (every connector).\n"
            "  Copies found for connector=hermes, connector=codex.",
            result.output,
        )
        self.assertTrue(asset_lists.has_entry(self.app.cfg, self.app.store, "skill", "sample", "", "block"))
        self.assertFalse(
            asset_lists.has_entry(self.app.cfg, self.app.store, "skill", "sample", "hermes", "block")
        )
        self.assertFalse(
            asset_lists.has_entry(self.app.cfg, self.app.store, "skill", "sample", "codex", "block")
        )

        # GAP-2085: bare unblock names the same scope the bare block did.
        unblocked = self.invoke(["unblock", "sample"])
        self.assertEqual(unblocked.exit_code, 0, unblocked.output)
        self.assertIn("[skill] Unblocked 'sample' (every connector).", unblocked.output)
        self.assertIn("It will be scanned on the next check.", unblocked.output)

    def test_scoped_block_uses_unblock_line_style(self):
        with patch("defenseclaw.commands.hint") as hint:
            result = self.invoke(["block", "sample", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("[skill] Blocked 'sample' (codex).", result.output)
        # GAP-2085: the unblock hint and the scoped unblock keep the scope.
        hint.assert_called_once_with("Unblock later:  defenseclaw skill unblock sample --connector codex")
        unblocked = self.invoke(["unblock", "sample", "--connector", "codex"])
        self.assertEqual(unblocked.exit_code, 0, unblocked.output)
        self.assertIn("[skill] Unblocked 'sample' (codex).", unblocked.output)
        self.assertIn("It will be scanned on the next check.", unblocked.output)

    def test_bare_allow_fans_out_to_matching_connector_copies(self):
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        codex_root = os.path.join(self.tmp_dir, "codex", "skills")
        os.makedirs(os.path.join(hermes_root, "sample"))
        os.makedirs(os.path.join(codex_root, "sample"))
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "hermes": [hermes_root],
            "codex": [codex_root],
        }.get(connector, [hermes_root])
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.block_for_connector("skill", "sample", "hermes", "bad")
        pe.block_for_connector("skill", "sample", "codex", "bad")

        result = self.invoke(["allow", "sample"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertIn("connector=codex", result.output)
        self.assertTrue(asset_lists.has_entry(self.app.cfg, self.app.store, "skill", "sample", "hermes", "allow"))
        self.assertTrue(asset_lists.has_entry(self.app.cfg, self.app.store, "skill", "sample", "codex", "allow"))
        self.assertFalse(asset_lists.has_entry(self.app.cfg, self.app.store, "skill", "sample", "", "allow"))

    def test_bare_unblock_clears_scoped_rows_for_matching_connector_copies(self):
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        codex_root = os.path.join(self.tmp_dir, "codex", "skills")
        os.makedirs(os.path.join(hermes_root, "sample"))
        os.makedirs(os.path.join(codex_root, "sample"))
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "hermes": [hermes_root],
            "codex": [codex_root],
        }.get(connector, [hermes_root])
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.block_for_connector("skill", "sample", "hermes", "bad")
        pe.quarantine_for_connector("skill", "sample", "codex", "bad")
        pe.disable_for_connector("skill", "sample", "codex", "bad")

        result = self.invoke(["unblock", "sample"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("[skill] Unblocked 'sample' (hermes).", result.output)
        self.assertIn("[skill] Unblocked 'sample' (codex).", result.output)
        self.assertIsNone(self.app.store.get_action("skill", "sample", "hermes"))
        self.assertIsNone(self.app.store.get_action("skill", "sample", "codex"))

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

        self.assertIsNone(self.app.store.get_action("skill", "sample", "nope"))


class TestSkillScannerLLMDefault(SkillCommandTestBase):
    """SK-6: the unified LLM lane defaults on whenever a model resolves, with
    --use-llm/--no-use-llm overriding the auto behaviour."""

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    @patch("defenseclaw.scanner._llm_env.litellm_model", return_value="bedrock/anthropic.claude-3-5-haiku")
    def test_auto_on_when_model_resolves(self, _mock_model, mock_wrapper):
        from defenseclaw.commands.cmd_skill import _build_skill_scanner
        _build_skill_scanner(self.app, None)
        cfg = mock_wrapper.call_args.args[0]
        self.assertTrue(cfg.use_llm)

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    @patch("defenseclaw.scanner._llm_env.litellm_model", return_value="")
    def test_auto_off_when_no_model(self, _mock_model, mock_wrapper):
        from defenseclaw.commands.cmd_skill import _build_skill_scanner
        _build_skill_scanner(self.app, None)
        cfg = mock_wrapper.call_args.args[0]
        self.assertFalse(cfg.use_llm)
        with patch("defenseclaw.commands.cmd_skill.asset_lists.is_secure_client", return_value=True):
            _build_skill_scanner(self.app, None)
        self.assertTrue(mock_wrapper.call_args.args[0].use_llm)
        self.assertTrue(mock_wrapper.call_args.kwargs["secure_client"])

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    @patch("defenseclaw.scanner._llm_env.litellm_model", return_value="some/model")
    def test_config_use_llm_false_wins_over_auto(self, _mock_model, mock_wrapper):
        # GAP-0055: scanners.skill_scanner.use_llm: false is honoured when a model resolves.
        from defenseclaw.commands.cmd_skill import _build_skill_scanner
        self.app.cfg.scanners.skill_scanner.use_llm = False
        _build_skill_scanner(self.app, None)
        self.assertFalse(mock_wrapper.call_args.args[0].use_llm)
        _build_skill_scanner(self.app, True)
        self.assertTrue(mock_wrapper.call_args.args[0].use_llm)

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    @patch("defenseclaw.scanner._llm_env.litellm_model", return_value="some/model")
    def test_no_use_llm_forces_off_despite_model(self, _mock_model, mock_wrapper):
        from defenseclaw.commands.cmd_skill import _build_skill_scanner
        _build_skill_scanner(self.app, False)
        cfg = mock_wrapper.call_args.args[0]
        self.assertFalse(cfg.use_llm)

    @patch("defenseclaw.scanner.rulepack.maybe_wrap")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    @patch("defenseclaw.scanner._llm_env.litellm_model", return_value="")
    def test_builder_threads_connector_and_pack_cache(
        self,
        _mock_model,
        _mock_wrapper,
        mock_maybe_wrap,
    ):
        from defenseclaw.commands.cmd_skill import _build_skill_scanner

        cache = {}
        _build_skill_scanner(
            self.app,
            None,
            connector="hermes",
            pack_cache=cache,
        )

        self.assertEqual(mock_maybe_wrap.call_args.args[2], "hermes")
        self.assertIs(mock_maybe_wrap.call_args.kwargs["pack_cache"], cache)

    @patch("defenseclaw.commands.cmd_skill._scan_all")
    @patch("defenseclaw.commands.cmd_skill._build_skill_scanner")
    def test_scan_threads_no_use_llm_flag(self, mock_build, _mock_scan_all):
        mock_build.return_value = MagicMock()
        result = self.invoke(["scan", "--all", "--no-use-llm"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIs(mock_build.call_args.args[1], False)


class TestSkillSearchUX(SkillCommandTestBase):
    """SK-7: search is a remote ClawHub registry query (labelled as such), and
    a broken/missing clawhub package degrades to a concise hint."""

    @patch("defenseclaw.commands.cmd_skill._resolve_command", return_value="/bin/clawhub")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_clawhub_broken_gives_concise_error(self, mock_run, _resolve):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr=("node:internal/modules/esm/resolve:1\nError [ERR_MODULE_NOT_FOUND]: Cannot find package 'chalk'"),
        )
        result = self.invoke(["search", "wiki"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("skill registry unavailable", result.output)
        self.assertNotIn("ERR_MODULE_NOT_FOUND", result.output)

    @patch("defenseclaw.commands.cmd_skill._resolve_command", return_value="/bin/clawhub")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_process")
    def test_results_labelled_as_registry(self, mock_run, _resolve):
        mock_run.return_value = MagicMock(returncode=0, stdout="wiki  Wiki  (3.5)\n", stderr="")
        result = self.invoke(["search", "wiki"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("registry", result.output.lower())


class TestSkillBareNameResolution(SkillCommandTestBase):
    """ND-1: a bare ``skill scan <name>`` resolves across every configured
    connector and scans every matching copy."""

    def _fake_dirs(self, mapping: dict, active: str):
        def skill_dirs(connector=None):
            return list(mapping.get(connector if connector else active, []))
        return skill_dirs

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    def test_bare_name_resolves_non_active_peer(self, mock_scan, _mock_info):
        active_root = os.path.join(self.tmp_dir, "codex", "skills")
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        os.makedirs(active_root)
        os.makedirs(os.path.join(hermes_root, "lone-skill"))

        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = self._fake_dirs(  # type: ignore[method-assign]
            {"codex": [active_root], "hermes": [hermes_root]}, "codex",
        )
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner", target="lone-skill",
            timestamp=datetime.now(timezone.utc), findings=[],
            duration=timedelta(seconds=0.1),
        )

        result = self.invoke(["scan", "lone-skill"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Scanning 1 skill on hermes", result.output)
        self.assertIn("hermes", str(mock_scan.call_args.args[0]))

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    def test_bare_name_uses_matched_connector_for_policy(self, mock_scan, _mock_info):
        active_root = os.path.join(self.tmp_dir, "codex", "skills")
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        os.makedirs(active_root)
        os.makedirs(os.path.join(hermes_root, "lone-skill"))

        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = self._fake_dirs(  # type: ignore[method-assign]
            {"codex": [active_root], "hermes": [hermes_root]}, "codex",
        )
        PolicyEngine(self.app.store, self.app.cfg).block_for_connector(
            "skill",
            "lone-skill",
            "hermes",
            "connector-specific block",
        )

        result = self.invoke(["scan", "lone-skill"])

        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("BLOCKED: lone-skill", result.output)
        mock_scan.assert_not_called()

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    def test_bare_name_duplicate_scans_every_connector_copy(self, mock_scan, _mock_info):
        a_root = os.path.join(self.tmp_dir, "codex", "skills")
        b_root = os.path.join(self.tmp_dir, "hermes", "skills")
        os.makedirs(os.path.join(a_root, "dup"))
        os.makedirs(os.path.join(b_root, "dup"))

        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = self._fake_dirs(  # type: ignore[method-assign]
            {"codex": [a_root], "hermes": [b_root]}, "codex",
        )
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner", target="dup",
            timestamp=datetime.now(timezone.utc), findings=[],
            duration=timedelta(seconds=0.1),
        )

        result = self.invoke(["scan", "dup"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertRegex(result.output, r"(?:──|--) connector: codex (?:──|--)")
        self.assertIn("Scanning 1 skill on codex", result.output)
        self.assertRegex(result.output, r"(?:──|--) connector: hermes (?:──|--)")
        self.assertIn("Scanning 1 skill on hermes", result.output)
        self.assertEqual(mock_scan.call_count, 2)

    @patch("defenseclaw.commands.cmd_skill._scan_one_local_skill")
    @patch("defenseclaw.commands.cmd_skill._build_skill_scanner")
    def test_bare_name_duplicate_reuses_rule_pack_cache(self, mock_build, _mock_scan):
        a_root = os.path.join(self.tmp_dir, "codex", "skills")
        b_root = os.path.join(self.tmp_dir, "hermes", "skills")
        os.makedirs(os.path.join(a_root, "dup"))
        os.makedirs(os.path.join(b_root, "dup"))

        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = self._fake_dirs(  # type: ignore[method-assign]
            {"codex": [a_root], "hermes": [b_root]}, "codex",
        )
        mock_build.return_value = MagicMock()

        result = self.invoke(["scan", "dup"])

        self.assertEqual(result.exit_code, 0, result.output)
        caches = [call.kwargs["pack_cache"] for call in mock_build.call_args_list]
        self.assertEqual(len(caches), 2)
        self.assertIs(caches[0], caches[1])

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    def test_bare_name_duplicate_fans_out_before_active_info(
        self, mock_scan, mock_info,
    ):
        a_root = os.path.join(self.tmp_dir, "antigravity", "skills")
        h_root = os.path.join(self.tmp_dir, "hermes", "skills")
        o_root = os.path.join(self.tmp_dir, "opencode", "skills")
        a_skill = os.path.join(a_root, "dc-skill-final")
        h_skill = os.path.join(h_root, "dc-skill-final")
        o_skill = os.path.join(o_root, "dc-skill-final")
        os.makedirs(a_skill)
        os.makedirs(h_skill)
        os.makedirs(o_skill)

        self.app.cfg.active_connector = lambda: "antigravity"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: [  # type: ignore[method-assign]
            "antigravity",
            "hermes",
            "opencode",
        ]
        self.app.cfg.skill_dirs = self._fake_dirs(  # type: ignore[method-assign]
            {
                "antigravity": [a_root],
                "hermes": [h_root],
                "opencode": [o_root],
            },
            "antigravity",
        )
        mock_info.return_value = {
            "name": "dc-skill-final",
            "baseDir": a_skill,
            "eligible": True,
        }
        mock_scan.return_value = ScanResult(
            scanner="skill-scanner", target="dc-skill-final",
            timestamp=datetime.now(timezone.utc), findings=[],
            duration=timedelta(seconds=0.1),
        )

        result = self.invoke(["scan", "dc-skill-final", "--no-use-llm"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertRegex(
            result.output,
            r"(?:──|--) connector: antigravity (?:──|--)",
        )
        self.assertIn("Scanning 1 skill on antigravity", result.output)
        self.assertRegex(result.output, r"(?:──|--) connector: hermes (?:──|--)")
        self.assertIn("Scanning 1 skill on hermes", result.output)
        self.assertRegex(result.output, r"(?:──|--) connector: opencode (?:──|--)")
        self.assertIn("Scanning 1 skill on opencode", result.output)
        self.assertEqual(
            [call.args[0] for call in mock_scan.call_args_list],
            [os.path.realpath(a_skill), os.path.realpath(h_skill), os.path.realpath(o_skill)],
        )
        mock_info.assert_not_called()


class TestSkillBareUnblockConfigScopes(SkillCommandTestBase):
    """GAP-1307: a bare unblock fans out to connector rules in config.yaml alone."""

    def test_bare_unblock_clears_a_config_only_connector_allow(self):
        from defenseclaw.enforce import asset_lists

        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.allow_for_connector("skill", "sample", "codex", "manual")
        # The allow lives in config.yaml only: no journal row, no copy on disk.
        self.assertIsNone(self.app.store.get_action("skill", "sample", "codex"))
        self.assertTrue(asset_lists.has_entry(self.app.cfg, self.app.store, "skill", "sample", "codex", "allow"))

        result = self.invoke(["unblock", "sample"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("[skill] Unblocked 'sample' (codex).", result.output)
        self.assertFalse(asset_lists.has_entry(self.app.cfg, self.app.store, "skill", "sample", "codex", "allow"))



if __name__ == "__main__":
    unittest.main()


def test_info_card_eligible_says_defenseclaw_keeps_blocked_skill_off(capsys):
    # GAP-1320: "Eligible: True" alone read wrong for a blocked skill.
    from defenseclaw.commands.cmd_skill import _print_skill_info_card

    _print_skill_info_card({"name": "fs1", "eligible": True, "disabled": True, "verdict": "blocked"}, "fs1")
    out = capsys.readouterr().out
    assert "True (the connector would load it; DefenseClaw keeps it off)" in out
    assert "defenseclaw skill unblock fs1" in out

    _print_skill_info_card({"name": "ok", "eligible": True}, "ok")
    assert "keeps it off" not in capsys.readouterr().out


def test_info_card_block_list_only_points_at_disable(capsys):
    # GAP-1320 (b4): a skill that is only on the install block list still
    # loads, so the card must not claim DefenseClaw keeps it off.
    from defenseclaw.commands.cmd_skill import _print_skill_info_card

    _print_skill_info_card(
        {"name": "fsav", "eligible": True, "disabled": False, "verdict": "blocked",
         "actions": {"install": "block"}},
        "fsav",
    )
    out = capsys.readouterr().out
    assert "keeps it off" not in out
    assert "keeps it disabled" not in out
    assert "defenseclaw skill disable fsav" in out


def test_info_card_policy_steps_one_per_line_with_connector(capsys):
    # GAP-1559: each next step on its own line, with --connector.
    from defenseclaw.commands.cmd_skill import _print_skill_info_card

    _print_skill_info_card(
        {"name": "fsav", "eligible": True, "verdict": "blocked", "connector": "claudecode",
         "actions": {"install": "block"}},
        "fsav",
    )
    lines = capsys.readouterr().out.splitlines()
    assert "  Turn it off: defenseclaw skill disable fsav --connector claudecode" in lines
    assert "  Unblock it: defenseclaw skill unblock fsav --connector claudecode" in lines


class TestSkillInstallQuarantineNeverWarns(SkillCommandTestBase):
    """GAP-1466/GAP-1457: a skill the admission policy rejects (a quarantine
    or block at any severity) is refused, rolled back, with an
    install-rejected row, with or without --action, also when the
    quarantine move or the gateway disable fails. Never an install-warning."""

    FILE_ONLY = {"install": "none", "file": "quarantine", "runtime": "enable"}
    RUNTIME_ONLY = {"install": "none", "file": "none", "runtime": "disable"}

    def _fake_clawhub_install(self, skill_name, _force, cwd=None):
        skill_dir = os.path.join(cwd or self.tmp_dir, "skills", skill_name)
        os.makedirs(skill_dir, exist_ok=True)
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(f"# {skill_name}\n")

    def _install(self, name, args, action, *, scan_exc=None, clean_root=None):
        self.seen_at_scan: list = []
        self.app.cfg.admission.skill.actions["medium"] = action
        scanned: list[str] = []

        def scan(_self, path, *a, **kw):
            scanned.append(_installed_path(path))
            installed = os.path.join(_installed_path(path), "SKILL.md")
            if os.path.isfile(installed):
                with open(installed, encoding="utf-8") as f:
                    self.seen_at_scan.append(f.read())
            else:
                self.seen_at_scan.append(None)
            if scan_exc is not None:
                raise scan_exc
            clean = clean_root is not None and path.startswith(clean_root + os.sep)
            return ScanResult(
                scanner="skill-scanner", target=path, timestamp=datetime.now(timezone.utc),
                findings=[] if clean else [
                    Finding(id="m1", severity="MEDIUM", title="broad permissions", scanner="skill-scanner"),
                ],
                duration=timedelta(seconds=0.1),
            )

        with patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan", new=scan), \
                patch("defenseclaw.commands.cmd_skill._run_clawhub_install", side_effect=self._fake_clawhub_install):
            result = self.runner.invoke(skill, ["install", *args, name], obj=self.app, catch_exceptions=True)
        return result, scanned

    def _assert_refused(self, result, scanned, reason):
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("refusing to install", result.output)
        self.assertTrue(scanned)
        for path in scanned:
            self.assertFalse(os.path.exists(path), f"refused skill left installed at {path}")
        events = self.app.store.list_events(50)
        self.assertFalse([e for e in events if e.action == "install-warning"], "a refusal logged install-warning")
        rejected = [e for e in events if e.action == "install-rejected"]
        self.assertTrue(rejected and reason in rejected[0].details, [e.details for e in rejected])

    def test_no_action_refuses_a_medium_file_only_quarantine(self):
        result, scanned = self._install("fq-skill", [], self.FILE_ONLY)
        self._assert_refused(result, scanned, "reason=rejected-without-action")

    def test_no_action_refuses_the_quarantine_shorthand(self):
        result, scanned = self._install("q-skill", [], "quarantine")
        self._assert_refused(result, scanned, "reason=rejected-without-action")

    def test_action_refuses_when_the_quarantine_move_fails(self):
        with patch("defenseclaw.commands.cmd_skill._quarantine_skill_with_provenance", return_value=None):
            result, scanned = self._install("qfail-skill", ["--action"], self.FILE_ONLY)
        self._assert_refused(result, scanned, "reason=enforcement-failed failed=quarantine")

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), "POSIX mode bits as non-root")
    def test_action_refuses_with_one_line_when_the_quarantine_folder_is_unwritable(self):
        # GAP-1740: with ~/.defenseclaw/quarantine not writable, --action
        # printed a raw PermissionError traceback from SkillEnforcer(). It
        # is the failed-quarantine refusal: one clear line, rolled back.
        quarantine = self.app.cfg.quarantine_dir
        os.makedirs(quarantine, exist_ok=True)
        os.chmod(quarantine, 0o500)
        try:
            result, scanned = self._install("qperm-skill", ["--action"], self.FILE_ONLY)
        finally:
            os.chmod(quarantine, 0o700)
        self.assertNotIn("Traceback", result.output)
        self.assertIsNone(result.exception if not isinstance(result.exception, SystemExit) else None, result.output)
        self.assertIn("quarantine of 'qperm-skill' failed", result.output)
        self._assert_refused(result, scanned, "reason=enforcement-failed failed=quarantine")

    def test_action_refuses_when_the_gateway_disable_fails(self):
        with patch("defenseclaw.commands.cmd_skill._normalize_runtime_connector", return_value="openclaw"), \
                patch("defenseclaw.gateway.OrchestratorClient.disable_skill", side_effect=RuntimeError("down")):
            result, scanned = self._install("dfail-skill", ["--action"], self.RUNTIME_ONLY)
        self._assert_refused(result, scanned, "reason=enforcement-failed failed=runtime-disable")

    def test_a_medium_warn_still_installs_with_a_warning(self):
        result, scanned = self._install("warn-skill", [], {"install": "none", "file": "none", "runtime": "enable"})
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(os.path.isdir(scanned[0]))
        self.assertTrue([e for e in self.app.store.list_events(50) if e.action == "install-warning"])

    WARN = {"install": "none", "file": "none", "runtime": "enable"}

    def _connector_roots(self, hermes_root=None):
        roots = {
            "openclaw": os.path.join(self.tmp_dir, "openclaw-skills"),
            "hermes": hermes_root or os.path.join(self.tmp_dir, "hermes-skills"),
        }
        self.app.cfg.active_connectors = lambda: list(roots)  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: [roots[connector or "openclaw"]]  # type: ignore[method-assign]
        return roots

    def _seed_old_copy(self, name, args=()):
        result, scanned = self._install(name, list(args), self.WARN)
        self.assertEqual(result.exit_code, 0, result.output)
        for path in scanned:
            with open(os.path.join(path, "SKILL.md"), "w", encoding="utf-8") as f:
                f.write("# old copy\n")
        return sorted(set(scanned))

    def _assert_no_backup_left(self, paths):
        for parent in {os.path.dirname(path) for path in paths}:
            self.assertEqual([e for e in os.listdir(parent) if e.startswith(".dclaw-")], [], parent)

    def _assert_old_copy_restored(self, result, paths):
        self.assertEqual(result.exit_code, 1, result.output)
        for path in paths:
            with open(os.path.join(path, "SKILL.md"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "# old copy\n", f"{path}: the replaced skill was not restored")
        self._assert_no_backup_left(paths)

    def test_a_refused_force_install_restores_the_replaced_skill(self):
        """A --force install that is refused puts the replaced skill back,
        on every refusal path (no --action, failed quarantine move, failed
        gateway disable, failed scan), never deleting it with the new copy."""
        cases = {
            "no-action": ([], self.FILE_ONLY, {}, None),
            "quarantine-move-fails": (["--action"], self.FILE_ONLY, {}, patch(
                "defenseclaw.commands.cmd_skill._quarantine_skill_with_provenance", return_value=None,
            )),
            "gateway-disable-fails": (["--action"], self.RUNTIME_ONLY, {}, patch(
                "defenseclaw.gateway.OrchestratorClient.disable_skill", side_effect=RuntimeError("down"),
            )),
            "scan-fails": ([], self.FILE_ONLY, {"scan_exc": RuntimeError("scanner down")}, None),
        }
        for label, (args, action, kw, ctx) in cases.items():
            with self.subTest(label):
                name = f"old-{label}"
                paths = self._seed_old_copy(name)
                with patch("defenseclaw.commands.cmd_skill._normalize_runtime_connector", return_value="openclaw"):
                    if ctx is None:
                        result, _ = self._install(name, ["--force", *args], action, **kw)
                    else:
                        with ctx:
                            result, _ = self._install(name, ["--force", *args], action, **kw)
                self._assert_old_copy_restored(result, paths)

    def test_a_refusal_on_a_later_connector_restores_every_replaced_copy(self):
        roots = self._connector_roots()
        paths = self._seed_old_copy("old-two")
        self.assertEqual(len(paths), 2)
        result, _ = self._install("old-two", ["--force"], self.FILE_ONLY, clean_root=roots["openclaw"])
        self.assertIn("refusing to install", result.output)
        self._assert_old_copy_restored(result, paths)

    def test_a_shared_root_refusal_restores_only_the_copy_that_was_there(self):
        shared = os.path.join(self.tmp_dir, "openclaw-skills")
        self._connector_roots(hermes_root=shared)
        # Two connectors sharing a root need --force for the second copy.
        paths = self._seed_old_copy("old-shared", ["--force"])
        result, _ = self._install("old-shared", ["--force"], self.FILE_ONLY)
        self._assert_old_copy_restored(result, paths)
        # Without a prior copy, the first connector's new copy is never
        # put back as if it had been there.
        result, scanned = self._install("new-shared", ["--force"], self.FILE_ONLY)
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertFalse(os.path.exists(os.path.join(shared, "new-shared")))
        self._assert_no_backup_left(scanned)

    def test_a_force_install_that_stands_drops_the_replaced_copy(self):
        paths = self._seed_old_copy("old-stands")
        result, _ = self._install("old-stands", ["--force"], self.WARN)
        self.assertEqual(result.exit_code, 0, result.output)
        with open(os.path.join(paths[0], "SKILL.md"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "# old-stands\n")
        self._assert_no_backup_left(paths)
        # An applied quarantine stands too: the staged new copy is
        # quarantined, the installed skill is untouched, nothing is left.
        result, _ = self._install("old-stands", ["--force", "--action"], self.FILE_ONLY)
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("quarantined", result.output)
        with open(os.path.join(paths[0], "SKILL.md"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "# old-stands\n")
        self.assertTrue(self.app.store.list_quarantine_records("skill", "old-stands"))
        self._assert_no_backup_left(paths)

    BLOCK_ONLY = {"install": "block", "file": "none", "runtime": "enable"}

    def test_a_thrown_enforcement_error_restores_the_replaced_skill(self):
        """GAP-1483: an exception while the quarantine moves the copy, while
        a disable or install block is recorded, or while the scanner is
        built is a refused install: the rejected copy is gone, no quarantine
        record is left, and the replaced skill is back byte for byte."""
        from defenseclaw.enforce.skill_enforcer import SkillEnforcer

        cases = {
            "quarantine-move-raises": (self.FILE_ONLY, patch.object(
                SkillEnforcer, "quarantine", side_effect=OSError("no space left on device"),
            ), "failed=quarantine"),
            "disable-record-raises": (self.RUNTIME_ONLY, patch.object(
                PolicyEngine, "disable_for_connector", side_effect=RuntimeError("database is locked"),
            ), "failed=runtime-disable"),
            "block-record-raises": (self.BLOCK_ONLY, patch.object(
                PolicyEngine, "record_scan_block", side_effect=RuntimeError("database is locked"),
            ), "failed=install-block"),
            "scanner-build-raises": (self.FILE_ONLY, patch(
                "defenseclaw.commands.cmd_skill._build_skill_scanner", side_effect=RuntimeError("bad rule pack"),
            ), None),
        }
        for label, (action, ctx, reason) in cases.items():
            with self.subTest(label):
                name = f"thrown-{label}"
                paths = self._seed_old_copy(name)
                with patch("defenseclaw.commands.cmd_skill._normalize_runtime_connector", return_value="hermes"), ctx:
                    result, _ = self._install(name, ["--force", "--action"], action)
                self._assert_old_copy_restored(result, paths)
                if reason:
                    details = [e.details for e in self.app.store.list_events(50) if e.action == "install-rejected"]
                    self.assertTrue([d for d in details if reason in d], details)
                self.assertEqual(self.app.store.list_quarantine_records("skill", name), [])

    def test_an_error_after_the_quarantine_keeps_it_and_the_installed_skill(self):
        """Once the quarantine moved the staged copy out, a later error (here
        the source-path record) fails the install; the quarantine record
        stands and the installed skill was never touched."""
        actions = {
            "file-only": self.FILE_ONLY,
            "file-and-disable": {"install": "none", "file": "quarantine", "runtime": "disable"},
        }
        for label, action in actions.items():
            with self.subTest(label):
                name = f"after-q-{label}"
                paths = self._seed_old_copy(name)
                with patch("defenseclaw.commands.cmd_skill._normalize_runtime_connector", return_value="hermes"), \
                        patch.object(PolicyEngine, "set_source_path", side_effect=RuntimeError("database is locked")):
                    result, _ = self._install(name, ["--force", "--action"], action)
                self._assert_old_copy_restored(result, paths)
                self.assertTrue(self.app.store.list_quarantine_records("skill", name), "the quarantine record is gone")

    def test_an_earlier_quarantine_still_decides_every_later_connector(self):
        """A quarantine applied on the first connector does not end the
        install before the second connector is decided: the second one's
        failed quarantine refuses, the first one's quarantine stands, and no
        installed copy is touched."""
        from defenseclaw.commands import cmd_skill as cmd_skill_module

        self._connector_roots()
        paths = dict(zip(["hermes", "openclaw"], self._seed_old_copy("old-q2")))
        real = cmd_skill_module._quarantine_skill_with_provenance
        calls: list[str] = []

        def quarantine(app, pe, skill_name, skill_path, connector, reason, **kw):
            calls.append(connector)
            if len(calls) == 1:
                return real(app, pe, skill_name, skill_path, connector, reason, **kw)
            return None

        with patch("defenseclaw.commands.cmd_skill._quarantine_skill_with_provenance", new=quarantine):
            result, _ = self._install("old-q2", ["--force", "--action"], self.FILE_ONLY)
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(calls, ["openclaw", "hermes"])
        self._assert_old_copy_restored(result, list(paths.values()))
        self.assertTrue(self.app.store.list_quarantine_records("skill", "old-q2"))

    def test_an_earlier_quarantine_lets_a_clean_later_connector_stand(self):
        roots = self._connector_roots()
        paths = dict(zip(["hermes", "openclaw"], self._seed_old_copy("old-q3")))
        result, scanned = self._install("old-q3", ["--force", "--action"], self.FILE_ONLY, clean_root=roots["hermes"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(len(scanned), 2, "the later connector was never scanned")
        with open(os.path.join(paths["openclaw"], "SKILL.md"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "# old copy\n")
        with open(os.path.join(paths["hermes"], "SKILL.md"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "# old-q3\n")
        self._assert_no_backup_left(list(paths.values()))

    def test_one_transaction_decides_the_staged_copy_before_any_swap(self):
        """ONE TRANSACTION RULE (1)-(3): the scanner sees the staged new copy
        while the installed skill is in place; a quarantine moves the staged
        copy, records the install path as where it belongs, and the
        installed skill stays as it was."""
        name = "tx-quarantine"
        paths = self._seed_old_copy(name)
        result, _ = self._install(name, ["--force", "--action"], self.FILE_ONLY)
        self.assertEqual(self.seen_at_scan, ["# old copy\n"], "the new copy was installed before it was decided")
        self._assert_old_copy_restored(result, paths)
        records = self.app.store.list_quarantine_records("skill", name)
        self.assertTrue(records)
        self.assertEqual(records[0].original_path, os.path.realpath(paths[0]))

    def test_an_install_only_block_never_replaces_the_installed_skill(self):
        """GAP-1494: an install block (or a runtime disable) that applied
        refuses the new copy; the installed skill is untouched and the
        refused copy is never live."""
        cases = {
            "block-only": self.BLOCK_ONLY,
            "block-and-disable": {"install": "block", "file": "none", "runtime": "disable"},
            "runtime-only-disable": self.RUNTIME_ONLY,
        }
        for label, action in cases.items():
            with self.subTest(label):
                name = f"tx-{label}"
                paths = self._seed_old_copy(name)
                with patch("defenseclaw.commands.cmd_skill._normalize_runtime_connector", return_value="hermes"):
                    result, _ = self._install(name, ["--force", "--action"], action)
                self._assert_old_copy_restored(result, paths)

    def test_a_shared_root_refusal_never_leaves_the_new_copy_live(self):
        """GAP-1495: two connectors share one skill path. When either one
        refuses (its disable applied, its disable record failed, or it alone
        quarantines or blocks), the shared new copy is never swapped in."""
        shared = os.path.join(self.tmp_dir, "openclaw-skills")
        real_disable = PolicyEngine.disable_for_connector

        def second_disable_fails(pe_self, kind, name, connector, *a, **kw):
            if connector == "hermes":
                raise RuntimeError("database is locked")
            return real_disable(pe_self, kind, name, connector, *a, **kw)

        cases = {
            "first-disables-second-record-fails": (self.RUNTIME_ONLY, patch.object(
                PolicyEngine, "disable_for_connector", new=second_disable_fails)),
            "both-block": (self.BLOCK_ONLY, None),
        }
        for label, (action, ctx) in cases.items():
            for seeded in (True, False):
                with self.subTest(label, seeded=seeded):
                    self._connector_roots(hermes_root=shared)
                    name = f"sh-{label}-{'s' if seeded else 'f'}"
                    paths = self._seed_old_copy(name) if seeded else [os.path.join(shared, name)]
                    with patch("defenseclaw.commands.cmd_skill._normalize_runtime_connector", return_value="hermes"):
                        if ctx is None:
                            result, _ = self._install(name, ["--force", "--action"], action)
                        else:
                            with ctx:
                                result, _ = self._install(name, ["--force", "--action"], action)
                    self.assertEqual(result.exit_code, 1, result.output)
                    if seeded:
                        self._assert_old_copy_restored(result, paths)
                    else:
                        self.assertFalse(os.path.lexists(paths[0]), "the refused shared copy is live")
                        self._assert_no_backup_left(paths)

    def test_a_shared_root_refusal_still_decides_and_enforces_every_connector(self):
        """Two connectors share one skill path. A quarantine or refusal on
        the first never takes the second one's input: each connector is
        scanned and gets its own quarantine, disable and block records, the
        installed skill stays as it was, and the new copy is never live."""
        shared = os.path.join(self.tmp_dir, "openclaw-skills")
        cases = {
            "quarantine": ("quarantine", ("file", "runtime", "install")),
            "file-and-disable": ({"install": "none", "file": "quarantine", "runtime": "disable"}, ("file", "runtime")),
            "install-only-block": (self.BLOCK_ONLY, ("install",)),
            "runtime-only-disable": (self.RUNTIME_ONLY, ("runtime",)),
        }
        expected = {"file": "quarantine", "runtime": "disable", "install": "block"}
        for label, (action, fields) in cases.items():
            for order in (["openclaw", "hermes"], ["hermes", "openclaw"]):
                with self.subTest(label, order=order):
                    self._connector_roots(hermes_root=shared)
                    self.app.cfg.active_connectors = lambda order=order: list(order)  # type: ignore[method-assign]
                    name = f"shd-{label}-{order[0]}"
                    paths = self._seed_old_copy(name)
                    with patch("defenseclaw.commands.cmd_skill._normalize_runtime_connector", return_value="hermes"):
                        result, scanned = self._install(name, ["--force", "--action"], action)
                    self.assertEqual(scanned, [os.path.join(shared, name)] * 2, "a connector was never decided")
                    self._assert_old_copy_restored(result, paths)
                    for connector in order:
                        entry = self.app.store.get_action("skill", name, connector)
                        self.assertIsNotNone(entry, f"no enforcement record for connector={connector}")
                        for field_name in fields:
                            self.assertEqual(getattr(entry.actions, field_name), expected[field_name],
                                             f"connector={connector} {field_name}")
                        if "file" in fields:
                            self.assertTrue(
                                self.app.store.list_quarantine_records("skill", name, connector=connector),
                                f"no quarantine for connector={connector}",
                            )

    def test_a_shared_root_allow_and_refusal_never_swaps_the_copy_in(self):
        """GAP-1495: one connector finds the shared copy clean, the other
        (sharing the path) refuses it: the shared copy is never swapped in."""
        shared = os.path.join(self.tmp_dir, "openclaw-skills")
        self._connector_roots(hermes_root=shared)
        paths = self._seed_old_copy("sh-mixed")
        self.app.cfg.admission.skill.actions["medium"] = self.RUNTIME_ONLY

        class Scanner:
            def __init__(self, connector):
                self.connector = connector

            def scan(self, path):
                findings = [] if self.connector == "openclaw" else [
                    Finding(id="m1", severity="MEDIUM", title="broad permissions", scanner="skill-scanner"),
                ]
                return ScanResult(scanner="skill-scanner", target=path, timestamp=datetime.now(timezone.utc),
                                  findings=findings, duration=timedelta(seconds=0.1))

        for order in (["openclaw", "hermes"], ["hermes", "openclaw"]):
            with self.subTest(order=order):
                self.app.cfg.active_connectors = lambda order=order: list(order)  # type: ignore[method-assign]
                with patch("defenseclaw.commands.cmd_skill._build_skill_scanner",
                           side_effect=lambda app, *, connector, pack_cache: Scanner(connector)),                         patch("defenseclaw.commands.cmd_skill._run_clawhub_install",
                              side_effect=self._fake_clawhub_install),                         patch("defenseclaw.commands.cmd_skill._normalize_runtime_connector", return_value="hermes"):
                    result = self.runner.invoke(
                        skill, ["install", "--force", "--action", "sh-mixed"], obj=self.app, catch_exceptions=True,
                    )
                self._assert_old_copy_restored(result, paths)

    def test_staging_never_touches_paths_another_operation_made(self):
        """ONE TRANSACTION RULE (1), (5): staging and backups are private to
        this install; a stage or backup another install left in the root is
        never reused or removed."""
        name = "tx-private"
        paths = self._seed_old_copy(name)
        root = os.path.dirname(paths[0])
        theirs = [os.path.join(root, f".dclaw-stage-{name}-theirs"),
                  os.path.join(root, f".dclaw-backup-{name}-{os.getpid()}-0")]
        for path in theirs:
            os.makedirs(path)
            with open(os.path.join(path, "theirs.txt"), "w", encoding="utf-8") as f:
                f.write("other operation\n")
        try:
            result, _ = self._install(name, ["--force"], self.WARN)
            self.assertEqual(result.exit_code, 0, result.output)
            for path in theirs:
                with open(os.path.join(path, "theirs.txt"), encoding="utf-8") as f:
                    self.assertEqual(f.read(), "other operation\n")
            self.assertEqual(sorted(e for e in os.listdir(root) if e.startswith(".dclaw-")),
                             sorted(os.path.basename(p) for p in theirs))
        finally:
            for path in theirs:
                shutil.rmtree(path, ignore_errors=True)

    def test_a_failed_swap_restores_only_the_copies_installed_before(self):
        """ONE TRANSACTION RULE (4): when the second connector's swap fails,
        the first one's swap is undone; both get back exactly the copy that
        was installed before, never a staged one."""
        self._connector_roots()
        paths = self._seed_old_copy("tx-swapfail")
        real_replace = os.replace
        second = os.path.join(self.tmp_dir, "hermes-skills", "tx-swapfail")

        def replace(src, dst, *a, **kw):
            if os.path.abspath(dst) == os.path.abspath(second) and os.path.basename(src) == "tx-swapfail":
                raise OSError("disk full")
            return real_replace(src, dst, *a, **kw)

        with patch("defenseclaw.commands.cmd_skill.os.replace", side_effect=replace):
            result, _ = self._install("tx-swapfail", ["--force"], self.WARN)
        self.assertIn("rolled back", result.output)
        self._assert_old_copy_restored(result, paths)

    def test_post_scan_first_party_content_is_the_staged_copy(self):
        """The first-party content check reads the staged new copy, never
        the installed one, while path rules use the install path."""
        from defenseclaw.enforce import admission as admission_module

        seen: list[tuple[str, str]] = []

        class Policy:
            first_party_allow = {"tx-content": []}
            allow_list_bypass_scan = True
            scan_on_install = False
            field_sources: dict = {}

        def own(target_type, name, path):
            seen.append((name, path))
            return False

        installed = os.path.join(self.tmp_dir, "skills", "tx-content")
        staged = os.path.join(self.tmp_dir, "skills", ".dclaw-stage-x", "tx-content")
        with patch.object(admission_module, "_own_first_party_content", new=own),                 patch.object(admission_module, "_content_verified_first_party", return_value=True),                 patch.object(admission_module, "compile_admission", return_value=Policy()):
            admission_module.evaluate_admission(
                PolicyEngine(self.app.store, self.app.cfg), config=self.app.cfg, target_type="skill",
                name="tx-content", source_path=installed, content_path=staged, connector="openclaw",
            )
        self.assertEqual(seen, [("tx-content", staged)])

    def test_skill_scan_reports_a_file_only_quarantine_as_blocking(self):
        from defenseclaw.commands.cmd_skill import _skill_scan_would_install_block

        self.app.cfg.admission.skill.actions["medium"] = self.FILE_ONLY
        result = ScanResult(
            scanner="skill-scanner", target="x", timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="m1", severity="MEDIUM", title="t", scanner="skill-scanner")],
            duration=timedelta(seconds=0.1),
        )
        pe = PolicyEngine(self.app.store, self.app.cfg)
        self.assertTrue(_skill_scan_would_install_block(self.app, pe, "x", self.tmp_dir, result, connector="openclaw"))
