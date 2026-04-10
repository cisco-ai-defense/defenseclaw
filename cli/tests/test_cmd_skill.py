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
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import uuid

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_skill import skill, _skill_status_display, _build_scan_map
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.models import ActionEntry, ActionState, Finding, ScanResult
from tests.helpers import make_app_context, cleanup_app


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


class TestSkillBlock(SkillCommandTestBase):
    def test_block_adds_to_block_list(self):
        result = self.invoke(["block", "evil-skill", "--reason", "malware detected"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("evil-skill", result.output)
        self.assertIn("block list", result.output)

        pe = PolicyEngine(self.app.store)
        self.assertTrue(pe.is_blocked("skill", "evil-skill"))

    def test_block_logs_action(self):
        self.invoke(["block", "evil-skill", "--reason", "test"])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "skill-block"]
        self.assertEqual(len(actions), 1)
        self.assertIn("test", actions[0].details)

    def test_block_uses_basename(self):
        self.invoke(["block", "/path/to/evil-skill"])
        pe = PolicyEngine(self.app.store)
        self.assertTrue(pe.is_blocked("skill", "evil-skill"))


class TestSkillAllow(SkillCommandTestBase):
    def test_allow_adds_to_allow_list(self):
        result = self.invoke(["allow", "trusted-skill", "--reason", "vetted"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("trusted-skill", result.output)
        self.assertIn("allow list", result.output)

        pe = PolicyEngine(self.app.store)
        self.assertTrue(pe.is_allowed("skill", "trusted-skill"))

    def test_allow_logs_action(self):
        self.invoke(["allow", "safe-skill", "--reason", "reviewed"])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "skill-allow"]
        self.assertEqual(len(actions), 1)

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_allow_reenables_runtime_disable_before_clearing_db(self, mock_cls):
        pe = PolicyEngine(self.app.store)
        pe.disable("skill", "safe-skill", "runtime blocked")

        mock_cls.return_value.enable_skill.return_value = {"status": "enabled"}

        result = self.invoke(["allow", "safe-skill", "--reason", "reviewed"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(pe.is_allowed("skill", "safe-skill"))
        self.assertFalse(self.app.store.has_action("skill", "safe-skill", "runtime", "disable"))
        mock_cls.return_value.enable_skill.assert_called_once_with("safe-skill")

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_allow_preserves_runtime_disable_when_gateway_enable_fails(self, mock_cls):
        pe = PolicyEngine(self.app.store)
        pe.disable("skill", "safe-skill", "runtime blocked")

        mock_cls.return_value.enable_skill.side_effect = Exception("timeout")

        result = self.invoke(["allow", "safe-skill", "--reason", "reviewed"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("gateway enable failed", result.output)
        self.assertIn("runtime disable remains until the gateway is reachable", result.output)
        self.assertTrue(pe.is_allowed("skill", "safe-skill"))
        self.assertTrue(self.app.store.has_action("skill", "safe-skill", "runtime", "disable"))


class TestSkillUnblock(SkillCommandTestBase):
    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_unblock_reenables_runtime_disable_before_clearing_state(self, mock_cls):
        pe = PolicyEngine(self.app.store)
        pe.block("skill", "blocked-skill", "manual block")
        pe.disable("skill", "blocked-skill", "runtime blocked")

        mock_cls.return_value.enable_skill.return_value = {"status": "enabled"}

        result = self.invoke(["unblock", "blocked-skill"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIsNone(pe.get_action("skill", "blocked-skill"))
        mock_cls.return_value.enable_skill.assert_called_once_with("blocked-skill")

    @patch("defenseclaw.gateway.OrchestratorClient")
    def test_unblock_preserves_state_when_gateway_enable_fails(self, mock_cls):
        pe = PolicyEngine(self.app.store)
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
        pe = PolicyEngine(self.app.store)
        pe.block("skill", "blocked-one", "test")

        skill_dir = os.path.join(self.tmp_dir, "blocked-one")
        os.makedirs(skill_dir)

        result = self.invoke(["scan", "blocked-one", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("BLOCKED", result.output)

    @patch("defenseclaw.commands.cmd_skill._run_openclaw", return_value=None)
    def test_scan_allowed_skill_shows_allowed(self, _mock_oc):
        pe = PolicyEngine(self.app.store)
        pe.allow("skill", "allow-me", "test")

        skill_dir = os.path.join(self.tmp_dir, "allow-me")
        os.makedirs(skill_dir)

        result = self.invoke(["scan", "allow-me", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("ALLOWED", result.output)


class TestSkillInstall(SkillCommandTestBase):
    @patch("defenseclaw.enforce.admission.evaluate_admission")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper.scan")
    @patch("defenseclaw.commands.cmd_skill._resolve_path")
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_install")
    def test_install_post_scan_allow_skips_warning(self, mock_install, mock_resolve, mock_scan, mock_eval):
        from defenseclaw.enforce.admission import AdmissionDecision

        skill_dir = os.path.join(self.tmp_dir, "late-allow")
        os.makedirs(skill_dir)
        mock_install.return_value = None
        mock_resolve.return_value = skill_dir
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

        pe = PolicyEngine(self.app.store)
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

    def test_restore_non_quarantined_errors(self):
        self.app.cfg.quarantine_dir = os.path.join(self.tmp_dir, "quarantine")
        result = self.invoke(["restore", "not-quarantined"])
        self.assertNotEqual(result.exit_code, 0)


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
        pe = PolicyEngine(self.app.store)
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
    def test_list_no_duplicate_entries(self, mock_list):
        """If a skill is in both OpenClaw list and actions DB, it shouldn't appear twice."""
        mock_list.return_value = {
            "skills": [
                {"name": "my-skill", "description": "Active", "emoji": "",
                 "eligible": True, "disabled": False, "blockedByAllowlist": False,
                 "source": "user", "bundled": False, "homepage": ""},
            ]
        }
        pe = PolicyEngine(self.app.store)
        pe.allow("skill", "my-skill", "trusted")

        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output)
        names = [d["name"] for d in data]
        self.assertEqual(names.count("my-skill"), 1)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full", return_value=None)
    def test_list_enforcement_only_shows_blocked_status(self, _mock):
        """Blocked-only entries (no OpenClaw data) should show blocked status."""
        pe = PolicyEngine(self.app.store)
        pe.block("skill", "banned-skill", "dangerous")

        result = self.invoke(["list", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("banned-skill", result.output)
        self.assertIn("blocked", result.output)


class TestSkillInfo(SkillCommandTestBase):
    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    def test_info_unknown_skill(self, _mock):
        result = self.invoke(["info", "unknown-skill"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("unknown-skill", result.output)

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
        pe = PolicyEngine(self.app.store)
        pe.block("skill", "bad-skill", "test")
        actions_map = _build_actions_map(self.app.store)
        self.assertIn("bad-skill", actions_map)


# ---------------------------------------------------------------------------
# skill search
# ---------------------------------------------------------------------------

class TestSkillSearch(SkillCommandTestBase):
    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_search_success(self, mock_run):
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
            ["npx", "clawhub", "search", "wiki"],
            capture_output=True, text=True, timeout=30,
        )

    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_search_no_results(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = self.invoke(["search", "zzz_nonexistent"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No skills found", result.output)

    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_search_json_output(self, mock_run):
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

    @patch("defenseclaw.commands.cmd_skill.subprocess.run", side_effect=FileNotFoundError)
    def test_search_npx_not_found(self, _mock):
        result = self.invoke(["search", "wiki"])
        self.assertNotEqual(result.exit_code, 0)

    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_search_clawhub_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="network error")
        result = self.invoke(["search", "wiki"])
        self.assertNotEqual(result.exit_code, 0)

    @patch("defenseclaw.commands.cmd_skill.subprocess.run",
           side_effect=__import__("subprocess").TimeoutExpired(cmd="npx", timeout=30))
    def test_search_timeout(self, _mock):
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

    @patch("requests.get")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_from_url_tar(self, mock_scanner_cls, mock_requests_get):
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

        # Mock HTTP response
        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "application/gzip"}
        mock_resp.iter_content.return_value = [tar_bytes]
        mock_resp.raise_for_status.return_value = None
        mock_requests_get.return_value = mock_resp

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
        self.assertIn("1 critical", result.output)
        self.assertIn("1 high", result.output)
        self.assertIn("2 medium", result.output)
        self.assertIn("1 info", result.output)
        # Must NOT show raw total "5 findings"
        self.assertNotIn("5 findings", result.output)

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


if __name__ == "__main__":
    unittest.main()
