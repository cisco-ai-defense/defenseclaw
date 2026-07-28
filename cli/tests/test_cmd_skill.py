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
from unittest.mock import MagicMock, patch

import click

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_skill import (
    _apply_scan_enforcement,
    _build_scan_map,
    _get_openclaw_skill_info,
    _skill_display_name,
    _skill_status_display,
    skill,
)
from defenseclaw.config import SeverityAction
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.models import ActionState, Finding, ScanResult

from tests.environment import requires_symlink_privilege
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


class TestOpenClawSkillInfo(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_skill._run_openclaw", return_value='{"error": ""}')
    def test_empty_error_field_is_still_an_error(self, _mock_run):
        self.assertIsNone(_get_openclaw_skill_info("missing"))


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

    @patch("defenseclaw.commands.cmd_skill._run_openclaw", return_value=None)
    def test_scan_connector_allow_overrides_global_block(self, _mock_oc):
        self.app.cfg.active_connector = lambda: "claudecode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        pe = PolicyEngine(self.app.store)
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
        pe = PolicyEngine(self.app.store)
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
        self.app.cfg.skill_actions.high = SeverityAction(file="none", runtime="enable", install="block")
        skill_dir = os.path.join(self.tmp_dir, "dirty-skill")
        os.makedirs(skill_dir)
        result = ScanResult(
            scanner="skill-scanner",
            target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="f1", severity="HIGH", title="Shell injection", scanner="skill-scanner")],
            duration=timedelta(seconds=0.5),
        )
        pe = PolicyEngine(self.app.store)

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
            self.app, PolicyEngine(self.app.store), "dirty-skill", skill_dir, result,
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
            self.app, PolicyEngine(self.app.store), "alias-skill", skill_dir, result,
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
            self.app, PolicyEngine(self.app.store), "openclaw-skill", skill_dir, result,
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
        pe = PolicyEngine(self.app.store)

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
        runtime_pe = PolicyEngine(self.app.store)
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
        install_pe = PolicyEngine(self.app.store)
        with patch.object(
            install_pe, "block_for_connector", side_effect=OSError("install db unavailable"),
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
        noop_pe.block_for_connector.assert_called_once()

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
        silent_pe.block_for_connector.assert_called_once()

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
        pe = PolicyEngine(self.app.store)
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
    def test_scan_all_connector_flag_targets_one(self, mock_scanner_cls, mock_scan_all):
        # --connector targets exactly one connector even in a multi install.
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]

        result = self.invoke(["scan", "--all", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_scan_all.assert_called_once_with(self.app, mock_scanner, False, enforce=False, connector="codex")

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

    def test_scan_all_nonactive_codex_expands_system_child_skills(self):
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

        _scan_all(self.app, scanner, as_json=False, connector="codex")

        scanned = [call.args[0] for call in scanner.scan.call_args_list]
        self.assertEqual(scanned, [regular, child_a, child_b])
        self.assertNotIn(system_root, scanned)
        self.assertNotIn(os.path.join(system_root, "not-a-skill"), scanned)


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
        from defenseclaw.commands.cmd_skill import _copy_skill_tree_to_connector

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
                _copy_skill_tree_to_connector(
                    source,
                    install_root,
                    "benign-skill",
                    force=False,
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
        mock_scan.assert_called_once_with(skill_dir)
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
            [call.args[0] for call in mock_scan.call_args_list],
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
        self.assertEqual(data["connector"], "codex")

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
        pe = PolicyEngine(self.app.store)
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
        pe = PolicyEngine(self.app.store)
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
        pe = PolicyEngine(self.app.store)
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
        PolicyEngine(self.app.store).block_for_connector(
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
        PolicyEngine(self.app.store).block("skill", "dup-skill", "global test")

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
        pe = PolicyEngine(self.app.store)
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


class TestSkillListOpencodeEmpty(SkillCommandTestBase):
    """SK-1 (re-scope): opencode exposes no skills surface — listing it must
    say so and never fall back to OpenClaw's skill directories. The path arm
    itself lives in connector_paths (already returns []); this guards the
    CLI-visible behaviour from regressing."""

    @patch(
        "defenseclaw.commands.cmd_skill._list_openclaw_skills_full",
        return_value={"skills": []},
    )
    def test_opencode_lists_no_skills_not_openclaw_paths(self, _mock_list):
        self.app.cfg.active_connector = lambda: "opencode"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["opencode"]  # type: ignore[method-assign]

        result = self.invoke(["list", "--connector", "opencode"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No skills found for connector='opencode'", result.output)
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
        pe = PolicyEngine(self.app.store)
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

    def test_bare_unblock_clears_global_allow_row(self):
        PolicyEngine(self.app.store).allow("skill", "sample", "manual")

        result = self.invoke(["unblock", "sample"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("allow/block/quarantine/disable", result.output)
        self.assertFalse(self.app.store.has_action("skill", "sample", "install", "allow"))
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
            "[skill] 'sample' added to block list for connector=hermes, connector=codex",
            result.output,
        )
        self.assertTrue(self.app.store.has_action("skill", "sample", "install", "block"))
        self.assertFalse(
            self.app.store.has_action("skill", "sample", "install", "block", "hermes")
        )
        self.assertFalse(
            self.app.store.has_action("skill", "sample", "install", "block", "codex")
        )

    def test_bare_allow_fans_out_to_matching_connector_copies(self):
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        codex_root = os.path.join(self.tmp_dir, "codex", "skills")
        os.makedirs(os.path.join(hermes_root, "sample"))
        os.makedirs(os.path.join(codex_root, "sample"))
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "hermes": [hermes_root],
            "codex": [codex_root],
        }.get(connector, [hermes_root])
        pe = PolicyEngine(self.app.store)
        pe.block_for_connector("skill", "sample", "hermes", "bad")
        pe.block_for_connector("skill", "sample", "codex", "bad")

        result = self.invoke(["allow", "sample"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertIn("connector=codex", result.output)
        self.assertTrue(self.app.store.has_action("skill", "sample", "install", "allow", "hermes"))
        self.assertTrue(self.app.store.has_action("skill", "sample", "install", "allow", "codex"))
        self.assertFalse(self.app.store.has_action("skill", "sample", "install", "allow"))

    def test_bare_unblock_clears_scoped_rows_for_matching_connector_copies(self):
        hermes_root = os.path.join(self.tmp_dir, "hermes", "skills")
        codex_root = os.path.join(self.tmp_dir, "codex", "skills")
        os.makedirs(os.path.join(hermes_root, "sample"))
        os.makedirs(os.path.join(codex_root, "sample"))
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "hermes": [hermes_root],
            "codex": [codex_root],
        }.get(connector, [hermes_root])
        pe = PolicyEngine(self.app.store)
        pe.block_for_connector("skill", "sample", "hermes", "bad")
        pe.quarantine_for_connector("skill", "sample", "codex", "bad")
        pe.disable_for_connector("skill", "sample", "codex", "bad")

        result = self.invoke(["unblock", "sample"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=hermes", result.output)
        self.assertIn("connector=codex", result.output)
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
        PolicyEngine(self.app.store).block_for_connector(
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
        self.assertIn("── connector: codex ──", result.output)
        self.assertIn("Scanning 1 skill on codex", result.output)
        self.assertIn("── connector: hermes ──", result.output)
        self.assertIn("Scanning 1 skill on hermes", result.output)
        self.assertEqual(mock_scan.call_count, 2)

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
        self.assertIn("── connector: antigravity ──", result.output)
        self.assertIn("Scanning 1 skill on antigravity", result.output)
        self.assertIn("── connector: hermes ──", result.output)
        self.assertIn("Scanning 1 skill on hermes", result.output)
        self.assertIn("── connector: opencode ──", result.output)
        self.assertIn("Scanning 1 skill on opencode", result.output)
        self.assertEqual(
            [call.args[0] for call in mock_scan.call_args_list],
            [os.path.realpath(a_skill), os.path.realpath(h_skill), os.path.realpath(o_skill)],
        )
        mock_info.assert_not_called()


if __name__ == "__main__":
    unittest.main()
