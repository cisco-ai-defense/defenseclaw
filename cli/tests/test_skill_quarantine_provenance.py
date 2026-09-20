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

"""WIN-AUD-063 physical quarantine provenance and recovery regressions."""

from __future__ import annotations

import json
import os
import shutil
import unittest
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands.cmd_skill import skill
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.enforce.skill_enforcer import SkillEnforcer
from defenseclaw.tui.services.catalog_state import SkillsPanelModel

from tests.environment import requires_symlink_privilege
from tests.helpers import cleanup_app, make_app_context


class TestSkillQuarantineProvenance(unittest.TestCase):
    def setUp(self) -> None:
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self.codex_root = os.path.join(self.tmp_dir, "codex-skills")
        self.claude_root = os.path.join(self.tmp_dir, "claude-skills")
        os.makedirs(self.codex_root)
        os.makedirs(self.claude_root)
        self.app.cfg.active_connector = lambda: "codex"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["codex", "claudecode"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "codex": [self.codex_root],
            "claudecode": [self.claude_root],
        }.get(connector, [self.codex_root])

    def tearDown(self) -> None:
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args: list[str]):
        return self.runner.invoke(skill, args, obj=self.app, catch_exceptions=False)

    def create_skill(self, connector: str, name: str = "dangerous") -> str:
        root = self.codex_root if connector == "codex" else self.claude_root
        path = os.path.join(root, name)
        os.makedirs(path)
        with open(os.path.join(path, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("test fixture\n")
        return path

    def records(self, connector: str | None = None):
        return self.app.store.list_quarantine_records(
            "skill", "dangerous", connector,
        )

    def test_codex_quarantine_unblock_restore_without_path_real_filesystem(self) -> None:
        original = self.create_skill("codex")

        quarantined = self.invoke(["quarantine", "dangerous", "--connector", "codex"])
        self.assertEqual(quarantined.exit_code, 0, quarantined.output)
        record = self.records("codex")[0]
        self.assertFalse(os.path.exists(original))
        self.assertTrue(os.path.isdir(record.quarantine_path))
        self.assertEqual(record.original_path, os.path.realpath(original))
        self.assertEqual(record.connectors, ("codex",))
        self.assertTrue(record.reason)
        self.assertLessEqual(record.created_at, record.updated_at)
        self.assertIn("mode", json.loads(record.ownership_json))
        self.assertEqual(
            SkillEnforcer(self.app.cfg.quarantine_dir).content_hash(record.quarantine_path),
            record.content_hash,
        )

        unblocked = self.invoke(["unblock", "dangerous", "--connector", "codex"])
        self.assertEqual(unblocked.exit_code, 0, unblocked.output)
        self.assertIn("files remain quarantined", unblocked.output)
        self.assertIsNone(self.app.store.get_action("skill", "dangerous", "codex"))
        self.assertEqual(len(self.records("codex")), 1)

        restored = self.invoke(["restore", "dangerous", "--connector", "codex"])
        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        self.assertFalse(os.path.exists(record.quarantine_path))
        self.assertEqual(self.records("codex"), [])

        repeated = self.invoke(["restore", "dangerous", "--connector", "codex"])
        self.assertEqual(repeated.exit_code, 0, repeated.output)
        self.assertIn("already restored", repeated.output)

    def test_legacy_codex_action_only_quarantine_is_upgraded_before_unblock(self) -> None:
        """Reproduce the original connector-row/global-directory defect."""
        original = self.create_skill("codex")
        enforcer = SkillEnforcer(self.app.cfg.quarantine_dir)
        legacy_quarantine = enforcer.quarantine("dangerous", original)
        pe = PolicyEngine(self.app.store)
        pe.quarantine_for_connector("skill", "dangerous", "codex", "legacy scan")
        pe.set_source_path("skill", "dangerous", original, "codex")
        self.assertEqual(self.records("codex"), [])

        unblocked = self.invoke(["unblock", "dangerous", "--connector", "codex"])

        self.assertEqual(unblocked.exit_code, 0, unblocked.output)
        record = self.records("codex")[0]
        self.assertEqual(record.quarantine_path, legacy_quarantine)
        self.assertIsNone(self.app.store.get_action("skill", "dangerous", "codex"))
        restored = self.invoke(["restore", "dangerous", "--connector", "codex"])
        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))

    def test_claude_quarantine_unblock_restore_without_path(self) -> None:
        original = self.create_skill("claudecode")

        self.assertEqual(
            self.invoke(["quarantine", "dangerous", "--connector", "claudecode"]).exit_code,
            0,
        )
        unblocked = self.invoke(["unblock", "dangerous", "--connector", "claudecode"])
        self.assertEqual(unblocked.exit_code, 0, unblocked.output)
        restored = self.invoke(["restore", "dangerous", "--connector", "claudecode"])

        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        self.assertEqual(self.records("claudecode"), [])

    def test_codex_unblock_leaves_claude_enforcement_and_recovery_unchanged(self) -> None:
        self.create_skill("codex")
        self.create_skill("claudecode")
        self.assertEqual(self.invoke(["quarantine", "dangerous"]).exit_code, 0)
        claude_before = self.records("claudecode")[0]

        result = self.invoke(["unblock", "dangerous", "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIsNone(self.app.store.get_action("skill", "dangerous", "codex"))
        self.assertTrue(
            self.app.store.has_action(
                "skill", "dangerous", "file", "quarantine", "claudecode",
            )
        )
        claude_after = self.records("claudecode")[0]
        self.assertEqual(claude_after.id, claude_before.id)
        self.assertTrue(os.path.isdir(claude_after.quarantine_path))

    def test_shared_physical_record_keeps_all_connector_associations(self) -> None:
        original = self.create_skill("codex")
        self.assertEqual(
            self.invoke(["quarantine", "dangerous", "--connector", "codex"]).exit_code,
            0,
        )
        record = self.records("codex")[0]
        self.app.store.associate_quarantine_connector(record.id, "claudecode")
        pe = PolicyEngine(self.app.store)
        pe.quarantine_for_connector("skill", "dangerous", "claudecode", "shared quarantine")
        pe.set_source_path("skill", "dangerous", original, "claudecode")

        self.invoke(["unblock", "dangerous", "--connector", "codex"])

        shared = self.app.store.get_quarantine_record(record.id)
        self.assertEqual(shared.connectors, ("claudecode", "codex"))
        self.assertTrue(
            self.app.store.has_action(
                "skill", "dangerous", "file", "quarantine", "claudecode",
            )
        )
        restored = self.invoke(["restore", "dangerous"])
        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isdir(original))
        self.assertIsNone(self.app.store.get_quarantine_record(record.id))

    def test_repeated_unblock_is_truthful_and_preserves_provenance(self) -> None:
        self.create_skill("codex")
        self.invoke(["quarantine", "dangerous", "--connector", "codex"])
        self.invoke(["unblock", "dangerous", "--connector", "codex"])

        repeated = self.invoke(["unblock", "dangerous", "--connector", "codex"])

        self.assertEqual(repeated.exit_code, 0, repeated.output)
        self.assertIn("already unblocked", repeated.output)
        self.assertIn("files remain quarantined", repeated.output)
        self.assertEqual(len(self.records("codex")), 1)

    def test_restore_collision_preserves_physical_files_and_provenance(self) -> None:
        original = self.create_skill("codex")
        self.invoke(["quarantine", "dangerous", "--connector", "codex"])
        record = self.records("codex")[0]
        os.makedirs(original)

        result = self.invoke(["restore", "dangerous", "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("destination already exists", result.output)
        self.assertTrue(os.path.isdir(record.quarantine_path))
        self.assertEqual(len(self.records("codex")), 1)

    def test_tampered_quarantine_hash_preserves_provenance(self) -> None:
        original = self.create_skill("codex")
        self.invoke(["quarantine", "dangerous", "--connector", "codex"])
        record = self.records("codex")[0]
        with open(os.path.join(record.quarantine_path, "SKILL.md"), "a", encoding="utf-8") as handle:
            handle.write("tampered\n")

        result = self.invoke(["restore", "dangerous", "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("integrity check failed", result.output)
        self.assertFalse(os.path.exists(original))
        self.assertEqual(len(self.records("codex")), 1)

    def test_missing_quarantine_files_preserve_provenance(self) -> None:
        self.create_skill("codex")
        self.invoke(["quarantine", "dangerous", "--connector", "codex"])
        record = self.records("codex")[0]
        shutil.rmtree(record.quarantine_path)

        result = self.invoke(["restore", "dangerous", "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("files are missing", result.output)
        self.assertEqual(self.records("codex")[0].id, record.id)

    def test_restore_copy_failure_preserves_quarantine_and_provenance(self) -> None:
        original = self.create_skill("codex")
        self.invoke(["quarantine", "dangerous", "--connector", "codex"])
        record = self.records("codex")[0]

        with patch.object(SkillEnforcer, "_copy_path", side_effect=PermissionError("denied")):
            result = self.invoke(["restore", "dangerous", "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertTrue(os.path.isdir(record.quarantine_path))
        self.assertFalse(os.path.exists(original))
        self.assertEqual(self.records("codex")[0].state, "active")

    def test_metadata_failure_after_verified_restore_is_recoverable(self) -> None:
        original = self.create_skill("codex")
        self.invoke(["quarantine", "dangerous", "--connector", "codex"])
        record = self.records("codex")[0]

        with patch.object(
            self.app.store,
            "complete_quarantine_restore",
            side_effect=OSError("write failed"),
        ):
            failed = self.invoke(["restore", "dangerous", "--connector", "codex"])

        self.assertEqual(failed.exit_code, 1, failed.output)
        self.assertTrue(os.path.isdir(original))
        self.assertFalse(os.path.exists(record.quarantine_path))
        self.assertEqual(self.records("codex")[0].state, "restoring")

        retried = self.invoke(["restore", "dangerous", "--connector", "codex"])
        self.assertEqual(retried.exit_code, 0, retried.output)
        self.assertIn("restore finalized", retried.output)
        self.assertEqual(self.records("codex"), [])

    def test_provenance_write_failure_does_not_move_files(self) -> None:
        original = self.create_skill("codex")
        with patch.object(
            self.app.store,
            "create_quarantine_record",
            side_effect=OSError("write failed"),
        ):
            result = self.invoke(["quarantine", "dangerous", "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertTrue(os.path.isdir(original))
        self.assertEqual(self.records("codex"), [])

    def test_restore_path_traversal_is_rejected_with_provenance_intact(self) -> None:
        self.create_skill("codex")
        self.invoke(["quarantine", "dangerous", "--connector", "codex"])
        record = self.records("codex")[0]
        outside = os.path.join(self.tmp_dir, "outside", "dangerous")

        result = self.invoke([
            "restore", "dangerous", "--connector", "codex", "--path", outside,
        ])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("configured skill directory", result.output)
        self.assertTrue(os.path.isdir(record.quarantine_path))
        self.assertEqual(len(self.records("codex")), 1)

    @requires_symlink_privilege
    def test_restore_through_symlinked_parent_is_rejected(self) -> None:
        self.create_skill("codex")
        self.invoke(["quarantine", "dangerous", "--connector", "codex"])
        outside = os.path.join(self.tmp_dir, "outside")
        os.makedirs(outside)
        link = os.path.join(self.codex_root, "linked")
        os.symlink(outside, link, target_is_directory=True)

        result = self.invoke([
            "restore",
            "dangerous",
            "--connector",
            "codex",
            "--path",
            os.path.join(link, "dangerous"),
        ])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(len(self.records("codex")), 1)

    def test_cli_and_tui_report_physical_quarantine_after_unblock(self) -> None:
        self.create_skill("codex")
        self.invoke(["quarantine", "dangerous", "--connector", "codex"])
        self.invoke(["unblock", "dangerous", "--connector", "codex"])

        listed = self.invoke(["list", "--json", "--connector", "codex"])

        self.assertEqual(listed.exit_code, 0, listed.output)
        payload = json.loads(listed.output)
        self.assertEqual(payload["skills"][0]["actions"]["file"], "quarantine")
        panel = SkillsPanelModel(connector="codex")
        panel.apply_json(listed.output)
        self.assertEqual(panel.selected().status, "quarantined")
        intent = panel.action_intent("r", origin="skills")
        self.assertEqual(
            intent.args,
            ("skill", "restore", "dangerous", "--connector", "codex"),
        )


if __name__ == "__main__":
    unittest.main()
