"""Tests for 'defenseclaw skill' command group — block, allow, scan, quarantine, restore, list, info."""

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_skill import skill
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.models import Finding, ScanResult
from tests.helpers import make_app_context, cleanup_app


class SkillCommandTestBase(unittest.TestCase):
    """Base class that sets up an AppContext with temp store for skill command tests."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

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
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("web-search", result.output)
        self.assertIn("code-review", result.output)

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


class TestSkillStatusHelpers(unittest.TestCase):
    def test_skill_status_disabled(self):
        from defenseclaw.commands.cmd_skill import _skill_status
        self.assertEqual(_skill_status({"disabled": True}), "disabled")

    def test_skill_status_blocked(self):
        from defenseclaw.commands.cmd_skill import _skill_status
        self.assertEqual(_skill_status({"blockedByAllowlist": True}), "blocked")

    def test_skill_status_active(self):
        from defenseclaw.commands.cmd_skill import _skill_status
        self.assertEqual(_skill_status({"eligible": True}), "active")

    def test_skill_status_inactive(self):
        from defenseclaw.commands.cmd_skill import _skill_status
        self.assertEqual(_skill_status({}), "inactive")

    def test_skill_status_display_ready(self):
        from defenseclaw.commands.cmd_skill import _skill_status_display
        self.assertIn("ready", _skill_status_display({"eligible": True}))

    def test_skill_status_display_disabled(self):
        from defenseclaw.commands.cmd_skill import _skill_status_display
        self.assertIn("disabled", _skill_status_display({"disabled": True}))


class TestBuildScanMap(SkillCommandTestBase):
    def test_build_scan_map_empty(self):
        from defenseclaw.commands.cmd_skill import _build_scan_map
        scan_map = _build_scan_map(self.app.store)
        self.assertEqual(scan_map, {})

    def test_build_scan_map_with_data(self):
        from defenseclaw.commands.cmd_skill import _build_scan_map
        import uuid

        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/path/to/my-skill",
            datetime.now(timezone.utc), 500, 2, "HIGH", "{}",
        )
        scan_map = _build_scan_map(self.app.store)
        self.assertIn("my-skill", scan_map)
        self.assertEqual(scan_map["my-skill"]["max_severity"], "HIGH")
        self.assertEqual(scan_map["my-skill"]["total_findings"], 2)


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


if __name__ == "__main__":
    unittest.main()
