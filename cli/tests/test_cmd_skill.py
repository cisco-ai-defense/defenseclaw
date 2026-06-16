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
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_skill import _build_scan_map, _skill_display_name, _skill_status_display, skill
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.models import ActionState, Finding, ScanResult

from tests.helpers import cleanup_app, make_app_context


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
        self.assertEqual(result.exit_code, 2, result.output)
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

    @patch("defenseclaw.commands.cmd_skill._scan_all")
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_flag_uses_bulk_scan_path(self, mock_scanner_cls, mock_scan_all):
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner

        result = self.invoke(["scan", "--all"])

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
    def test_scan_all_connector_flag_targets_one(self, mock_scanner_cls, mock_scan_all):
        # --connector targets exactly one connector even in a multi install.
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_scan_all.assert_called_once_with(self.app, mock_scanner, False, enforce=False, connector="codex")

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_connector_flag_rejects_unknown(self, mock_scanner_cls):
        # A typo'd --connector must fail loudly, not silently scan the primary.
        mock_scanner_cls.return_value = MagicMock()
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all", "--connector", "nope"])

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

    @patch("defenseclaw.config.Config.skill_dirs")
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

    def test_f0503_rejects_symlinked_candidate(self):
        from defenseclaw.commands.cmd_skill import _resolve_path

        # Candidate path (<root>/<name>) is itself a symlink to elsewhere.
        skill_root = self.app.cfg.skill_dirs()[1]
        os.makedirs(skill_root)
        outside = os.path.join(self.tmp_dir, "elsewhere")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(skill_root, "swapme"))

        self.assertIsNone(_resolve_path(self.app, "swapme"))


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

    def test_quarantine_ambiguous_name_requires_connector(self):
        # Same skill name under two connectors → refuse and ask for --connector
        # rather than silently quarantining one.
        codex_dir, claude_dir = self._wire_two_connectors()
        for d in (codex_dir, claude_dir):
            os.makedirs(os.path.join(d, "dup-skill"))

        result = self.invoke(["quarantine", "dup-skill"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("multiple connectors", result.output)
        # Both copies untouched.
        self.assertTrue(os.path.isdir(os.path.join(codex_dir, "dup-skill")))
        self.assertTrue(os.path.isdir(os.path.join(claude_dir, "dup-skill")))

        # --connector resolves the ambiguity and quarantines just that one.
        result2 = self.invoke(["quarantine", "dup-skill", "--connector", "codex"])
        self.assertEqual(result2.exit_code, 0, result2.output)
        self.assertFalse(os.path.isdir(os.path.join(codex_dir, "dup-skill")))
        self.assertTrue(os.path.isdir(os.path.join(claude_dir, "dup-skill")))


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
    def test_info_unknown_skill_errors(self, _mock):
        # SK-2: a true miss errors (exit 1) instead of rendering a blank card
        # that implies the skill exists.
        result = self.invoke(["info", "definitely-not-a-skill"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("not found", result.output)

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
        PolicyEngine(self.app.store).block("skill", "blocked-ghost", "test")
        result = self.invoke(["info", "blocked-ghost"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("blocked-ghost", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info")
    def test_info_severity_labels_max_not_count(self, mock_info):
        # SK-3: the count is labelled plainly and the *severity word* carries
        # the colour — no "{n} CRITICAL findings" conflation.
        mock_info.return_value = {"name": "mixed-skill", "eligible": True}
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
    # F-1481: `skill search` must not let `npx` fetch+execute the third-party
    # clawhub package from the network on every read-only search. The default
    # path prefers a locally-installed clawhub binary, and otherwise uses
    # `npx --no-install` (cached only, never network-fetched). Plain `npx`
    # (network fetch + execute) is gated behind explicit --allow-remote-fetch.

    @patch("defenseclaw.commands.cmd_skill.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_search_default_uses_npx_no_install_no_network_fetch(self, mock_run, _which):
        # No local clawhub binary, no opt-in: must use `npx --no-install` so npx
        # refuses to download+execute the package from the network.
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
            ["npx", "--no-install", "clawhub", "search", "wiki"],
            capture_output=True, text=True, timeout=30,
        )
        # Must never invoke the network-fetching plain `npx clawhub`.
        self.assertNotIn(
            ["npx", "clawhub", "search", "wiki"],
            [c.args[0] for c in mock_run.call_args_list],
        )

    @patch("defenseclaw.commands.cmd_skill.shutil.which", return_value="/usr/local/bin/clawhub")
    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_search_prefers_local_clawhub_binary(self, mock_run, _which):
        # A locally-installed pinned binary is run directly — no npx, no fetch.
        mock_run.return_value = MagicMock(
            returncode=0, stdout="wiki  Wiki  (3.504)\n", stderr="",
        )
        result = self.invoke(["search", "wiki"])
        self.assertEqual(result.exit_code, 0, result.output)
        mock_run.assert_called_once_with(
            ["/usr/local/bin/clawhub", "search", "wiki"],
            capture_output=True, text=True, timeout=30,
        )

    @patch("defenseclaw.commands.cmd_skill.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_search_allow_remote_fetch_opts_into_npx_network_fetch(self, mock_run, _which):
        # Explicit opt-in re-enables the original fetch+execute behavior.
        mock_run.return_value = MagicMock(
            returncode=0, stdout="wiki  Wiki  (3.504)\n", stderr="",
        )
        result = self.invoke(["search", "wiki", "--allow-remote-fetch"])
        self.assertEqual(result.exit_code, 0, result.output)
        mock_run.assert_called_once_with(
            ["npx", "clawhub", "search", "wiki"],
            capture_output=True, text=True, timeout=30,
        )

    @patch("defenseclaw.commands.cmd_skill.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_search_no_results(self, mock_run, _which):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = self.invoke(["search", "zzz_nonexistent"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No skills found", result.output)

    @patch("defenseclaw.commands.cmd_skill.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_search_json_output(self, mock_run, _which):
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

    @patch("defenseclaw.commands.cmd_skill.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_skill.subprocess.run", side_effect=FileNotFoundError)
    def test_search_npx_not_found(self, _mock, _which):
        result = self.invoke(["search", "wiki"])
        self.assertNotEqual(result.exit_code, 0)

    @patch("defenseclaw.commands.cmd_skill.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_search_clawhub_failure_hints_at_remote_fetch(self, mock_run, _which):
        # `npx --no-install` fails when clawhub isn't cached; the error must
        # point at --allow-remote-fetch rather than silently fetching.
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="npm ERR! could not determine executable",
        )
        result = self.invoke(["search", "wiki"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--allow-remote-fetch", result.output)

    @patch("defenseclaw.commands.cmd_skill.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_skill.subprocess.run",
           side_effect=__import__("subprocess").TimeoutExpired(cmd="npx", timeout=30))
    def test_search_timeout(self, _mock, _which):
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
        self.assertEqual(data[1]["skills"][0]["name"], "codex-skill")

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


class TestSkillListOpencodeEmpty(SkillCommandTestBase):
    """SK-1 (re-scope): opencode exposes no skills surface — listing it must
    say so and never fall back to OpenClaw's skill directories. The path arm
    itself lives in connector_paths (already returns []); this guards the
    CLI-visible behaviour from regressing."""

    def test_opencode_lists_no_skills_not_openclaw_paths(self):
        self.app.cfg.active_connector = lambda: "opencode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["opencode"]  # type: ignore[method-assign]

        result = self.invoke(["list", "--connector", "opencode"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No skills found for connector='opencode'", result.output)
        self.assertNotIn(".openclaw", result.output)


class TestSkillDisableHonesty(SkillCommandTestBase):
    """SK-5b: hook connectors store runtime-disable policy rows. Connectors
    without a skill runtime probe must get an explicit advisory warning."""

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
        with patch("defenseclaw.commands.cmd_skill._sidecar_client") as mock_client:
            result = self.invoke(["disable", "some-skill", "--connector", "hermes"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertIn("advisory", result.output)
        self.assertTrue(
            self.app.store.has_action("skill", "some-skill", "runtime", "disable", "hermes")
        )
        mock_client.assert_not_called()

    def test_disable_connector_with_probe_records_scoped_enforced(self):
        with patch("defenseclaw.commands.cmd_skill._sidecar_client") as mock_client:
            result = self.invoke(["disable", "some-skill", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=codex", result.output)
        self.assertIn("Enforced by hook runtime gate", result.output)
        self.assertNotIn("advisory", result.output)
        self.assertTrue(
            self.app.store.has_action("skill", "some-skill", "runtime", "disable", "codex")
        )
        mock_client.assert_not_called()

    def test_enable_connector_clears_scoped_disable_without_gateway(self):
        PolicyEngine(self.app.store).disable_for_connector(
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

    @patch("defenseclaw.commands.cmd_skill._sidecar_client")
    def test_disable_on_openclaw_still_calls_gateway(self, mock_client):
        self.app.cfg.active_connector = lambda: "openclaw"  # type: ignore[method-assign]
        mock_client.return_value.disable_skill.return_value = {"status": "disabled"}

        result = self.invoke(["disable", "some-skill"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_client.return_value.disable_skill.assert_called_once_with("some-skill")


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

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    @patch("defenseclaw.scanner._llm_env.litellm_model", return_value="some/model")
    def test_no_use_llm_forces_off_despite_model(self, _mock_model, mock_wrapper):
        from defenseclaw.commands.cmd_skill import _build_skill_scanner
        _build_skill_scanner(self.app, False)
        cfg = mock_wrapper.call_args.args[0]
        self.assertFalse(cfg.use_llm)

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

    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_clawhub_broken_gives_concise_error(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr=(
                "node:internal/modules/esm/resolve:1\n"
                "Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'chalk'"
            ),
        )
        result = self.invoke(["search", "wiki"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("skill registry unavailable", result.output)
        self.assertNotIn("ERR_MODULE_NOT_FOUND", result.output)

    @patch("defenseclaw.commands.cmd_skill.subprocess.run")
    def test_results_labelled_as_registry(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="wiki  Wiki  (3.5)\n", stderr="")
        result = self.invoke(["search", "wiki"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("registry", result.output.lower())


class TestSkillBareNameResolution(SkillCommandTestBase):
    """ND-1: a bare ``skill scan <name>`` resolves across every active
    connector, and refuses (asking for --connector) when a name is ambiguous."""

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
        self.assertIn("hermes", str(mock_scan.call_args.args[0]))

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    def test_bare_name_ambiguous_refuses(self, _mock_info):
        a_root = os.path.join(self.tmp_dir, "codex", "skills")
        b_root = os.path.join(self.tmp_dir, "hermes", "skills")
        os.makedirs(os.path.join(a_root, "dup"))
        os.makedirs(os.path.join(b_root, "dup"))

        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = self._fake_dirs(  # type: ignore[method-assign]
            {"codex": [a_root], "hermes": [b_root]}, "codex",
        )

        result = self.invoke(["scan", "dup"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("multiple connectors", result.output)
        self.assertIn("--connector", result.output)


if __name__ == "__main__":
    unittest.main()
