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

    def records_for(self, name: str, connector: str | None = None):
        return self.app.store.list_quarantine_records(
            "skill",
            name,
            connector,
        )

    def test_codex_disable_moves_skill_and_records_hard_runtime_isolation(self) -> None:
        name = "runtime-skill"
        original = self.create_skill("codex", name)

        result = self.invoke(
            [
                "disable",
                name,
                "--connector",
                "codex",
                "--reason",
                "runtime test",
            ]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("runtime disable enforced (connector=codex)", result.output)
        self.assertIn("managed file quarantine", result.output)
        self.assertNotIn("advisory", result.output)
        self.assertFalse(os.path.exists(original))
        entry = self.app.store.get_action("skill", name, "codex")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.actions.runtime, "disable")
        self.assertEqual(entry.actions.file, "quarantine")
        self.assertEqual(entry.actions.install, "")
        self.assertEqual(entry.source_path, os.path.realpath(original))
        record = self.records_for(name, "codex")[0]
        self.assertEqual(record.original_path, os.path.realpath(original))
        self.assertEqual(record.connectors, ("codex",))
        self.assertEqual(record.state, "active")
        self.assertEqual(record.purpose, "runtime-isolation")
        self.assertTrue(os.path.isfile(os.path.join(record.quarantine_path, "SKILL.md")))
        self.assertEqual(
            SkillEnforcer(self.app.cfg.quarantine_dir).content_hash(
                record.quarantine_path,
            ),
            record.content_hash,
        )

    def test_codex_disable_missing_skill_records_no_success(self) -> None:
        name = "missing-runtime-skill"

        result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("no canonical installed skill directory", result.output)
        self.assertNotIn("runtime disable enforced", result.output)
        self.assertIsNone(self.app.store.get_action("skill", name, "codex"))
        self.assertEqual(self.records_for(name, "codex"), [])

    def test_codex_disable_ambiguous_installed_copies_records_no_success(self) -> None:
        name = "ambiguous-runtime-skill"
        first = self.create_skill("codex", name)
        second_root = os.path.join(self.tmp_dir, "codex-workspace-skills")
        second = os.path.join(second_root, name)
        os.makedirs(second)
        with open(os.path.join(second, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("second inert test fixture\n")
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "codex": [self.codex_root, second_root],
            "claudecode": [self.claude_root],
        }.get(connector, [self.codex_root, second_root])

        result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("ambiguous skill", result.output)
        self.assertIn("found 2 installed copies", result.output)
        self.assertTrue(os.path.isdir(first))
        self.assertTrue(os.path.isdir(second))
        self.assertIsNone(self.app.store.get_action("skill", name, "codex"))
        self.assertEqual(self.records_for(name, "codex"), [])

    def test_codex_disable_existing_quarantine_destination_fails_closed(self) -> None:
        name = "destination-collision-skill"
        original = self.create_skill("codex", name)
        enforcer = SkillEnforcer(self.app.cfg.quarantine_dir)
        destination = enforcer.quarantine_path(
            name,
            "codex",
            purpose="runtime-isolation",
            allowed_roots=[self.codex_root],
        )
        self.assertIsNotNone(destination)
        os.makedirs(destination)
        with open(os.path.join(destination, "SKILL.md"), "w", encoding="utf-8") as handle:
            # Hash equality does not establish ownership of a destination
            # created after its random name was allocated.
            handle.write("test fixture\n")

        with patch.object(
            SkillEnforcer,
            "runtime_isolation_path",
            return_value=destination,
        ):
            result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("managed runtime isolation failed", result.output)
        self.assertNotIn("runtime disable enforced", result.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        with open(os.path.join(destination, "SKILL.md"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "test fixture\n")
        self.assertIsNone(self.app.store.get_action("skill", name, "codex"))
        self.assertEqual(self.records_for(name, "codex"), [])

    def test_codex_disable_discloses_active_session_ambiguous_token_limit(self) -> None:
        name = "HOME"
        original = self.create_skill("codex", name)

        result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(os.path.exists(original))
        self.assertIn("Observable canonical $skill selections", result.output)
        self.assertIn("cached use without an unambiguous", result.output)
        self.assertIn("Restart them", result.output)

    def test_codex_disable_retains_pending_record_after_source_replacement_race(self) -> None:
        name = "source-replacement-race"
        original = self.create_skill("codex", name)
        original_rename = SkillEnforcer._rename_no_replace

        def move_then_replace(
            source: str,
            destination: str,
            source_parent_fd: int | None,
            destination_parent_fd: int | None,
        ) -> None:
            original_rename(
                source,
                destination,
                source_parent_fd,
                destination_parent_fd,
            )
            os.makedirs(source)
            with open(os.path.join(source, "SKILL.md"), "w", encoding="utf-8") as handle:
                handle.write("test fixture\n")

        with patch.object(
            SkillEnforcer,
            "_rename_no_replace",
            side_effect=move_then_replace,
        ):
            result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertNotIn("runtime disable enforced", result.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        records = self.records_for(name, "codex")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].state, "pending")
        self.assertTrue(os.path.isfile(os.path.join(
            records[0].quarantine_path, "SKILL.md",
        )))
        self.assertIsNone(self.app.store.get_action("skill", name, "codex"))

    def test_codex_disable_refuses_a_skill_shared_with_peer_discovery(self) -> None:
        name = "shared-discovery-skill"
        shared_root = os.path.join(self.tmp_dir, "shared-skills")
        os.makedirs(shared_root)
        original = os.path.join(shared_root, name)
        os.makedirs(original)
        with open(os.path.join(original, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("test fixture\n")
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "codex": [shared_root],
            "claudecode": [shared_root],
        }.get(connector, [shared_root])

        result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("also discoverable by another connector", result.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        self.assertEqual(self.records_for(name, "codex"), [])
        self.assertIsNone(self.app.store.get_action("skill", name, "codex"))

    def test_codex_disable_refuses_peer_root_nested_inside_skill(self) -> None:
        name = "nested-peer-root-skill"
        original = self.create_skill("codex", name)
        nested_peer_root = os.path.join(original, "claude-skills")
        peer_skill = os.path.join(nested_peer_root, "peer-fixture")
        os.makedirs(peer_skill)
        with open(
            os.path.join(peer_skill, "SKILL.md"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("peer connector fixture\n")
        self.app.cfg.skill_dirs = lambda connector=None: {  # type: ignore[method-assign]
            "codex": [self.codex_root],
            "claudecode": [nested_peer_root],
        }.get(connector, [self.codex_root])

        result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("also discoverable by another connector", result.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        self.assertTrue(os.path.isfile(os.path.join(peer_skill, "SKILL.md")))
        self.assertEqual(self.records_for(name, "codex"), [])
        self.assertIsNone(self.app.store.get_action("skill", name, "codex"))

    def test_codex_disable_refuses_isolation_inside_a_peer_discovery_root(self) -> None:
        name = "overlapping-isolation-root"
        original = self.create_skill("codex", name)
        self.app.cfg.quarantine_dir = os.path.join(
            self.claude_root, "nested-quarantine",
        )

        result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("managed runtime isolation failed", result.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        self.assertEqual(self.records_for(name, "codex"), [])
        self.assertIsNone(self.app.store.get_action("skill", name, "codex"))

    def test_codex_disable_runtime_persistence_failure_never_claims_success(self) -> None:
        name = "persistence-failure-skill"
        original = self.create_skill("codex", name)

        with patch.object(
            PolicyEngine,
            "disable_for_connector",
            side_effect=OSError("runtime database unavailable"),
        ):
            result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("runtime disable persistence failed", result.output)
        self.assertNotIn("runtime disable enforced", result.output)
        self.assertFalse(os.path.exists(original))
        entry = self.app.store.get_action("skill", name, "codex")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.actions.file, "quarantine")
        self.assertEqual(entry.actions.runtime, "")
        self.assertEqual(entry.source_path, os.path.realpath(original))
        record = self.records_for(name, "codex")[0]
        self.assertEqual(record.purpose, "runtime-isolation")

    def test_codex_disable_file_policy_persistence_failure_never_records_runtime(self) -> None:
        name = "file-policy-persistence-skill"
        original = self.create_skill("codex", name)

        with patch.object(
            PolicyEngine,
            "quarantine_for_connector",
            side_effect=OSError("file policy database unavailable"),
        ):
            result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("enforcement metadata update failed", result.output)
        self.assertIn("provenance could not be verified", result.output)
        self.assertNotIn("runtime disable enforced", result.output)
        self.assertFalse(os.path.exists(original))
        self.assertIsNone(self.app.store.get_action("skill", name, "codex"))
        record = self.records_for(name, "codex")[0]
        self.assertEqual(record.state, "active")
        self.assertEqual(record.purpose, "runtime-isolation")
        self.assertTrue(os.path.isdir(record.quarantine_path))

    def test_codex_disable_provenance_finalization_failure_never_records_runtime(self) -> None:
        name = "provenance-finalization-skill"
        original = self.create_skill("codex", name)

        with patch.object(
            self.app.store,
            "update_quarantine_record_state",
            side_effect=OSError("provenance database unavailable"),
        ):
            result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("provenance finalization is pending", result.output)
        self.assertIn("could not be verified from durable provenance", result.output)
        self.assertNotIn("runtime disable enforced", result.output)
        self.assertFalse(os.path.exists(original))
        entry = self.app.store.get_action("skill", name, "codex")
        self.assertIsNone(entry)
        record = self.records_for(name, "codex")[0]
        self.assertEqual(record.state, "pending")
        self.assertEqual(record.purpose, "runtime-isolation")
        self.assertTrue(os.path.isdir(record.quarantine_path))

        retried = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(retried.exit_code, 0, retried.output)
        self.assertIn("runtime disable enforced", retried.output)
        entry = self.app.store.get_action("skill", name, "codex")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.actions.file, "quarantine")
        self.assertEqual(entry.actions.runtime, "disable")
        self.assertEqual(entry.source_path, os.path.realpath(original))
        record = self.records_for(name, "codex")[0]
        self.assertEqual(record.state, "active")
        self.assertTrue(
            SkillEnforcer.matches_runtime_ownership_marker(
                record.quarantine_path,
                record.ownership_json,
                isolated=True,
            )
        )

    def test_pending_runtime_isolation_can_be_restored_without_false_disable(self) -> None:
        name = "pending-runtime-restore-skill"
        original = self.create_skill("codex", name)

        with patch.object(
            self.app.store,
            "update_quarantine_record_state",
            side_effect=OSError("provenance database unavailable"),
        ):
            failed = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(failed.exit_code, 1, failed.output)
        self.assertIsNone(self.app.store.get_action("skill", name, "codex"))
        self.assertFalse(os.path.exists(original))
        self.assertEqual(self.records_for(name, "codex")[0].state, "pending")

        restored = self.invoke(["restore", name, "--connector", "codex"])

        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        self.assertEqual(self.records_for(name, "codex"), [])
        entry = self.app.store.get_action("skill", name, "codex")
        self.assertIsNotNone(entry)
        self.assertTrue(entry.actions.is_empty())
        self.assertEqual(entry.source_path, os.path.realpath(original))

    @unittest.skipUnless(os.name == "nt", "Windows canonical casing contract")
    def test_codex_disable_uses_installed_canonical_case(self) -> None:
        canonical_name = "CanonicalCaseSkill"
        requested_name = canonical_name.lower()
        original = self.create_skill("codex", canonical_name)

        result = self.invoke(
            [
                "disable",
                requested_name,
                "--connector",
                "codex",
            ]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(os.path.exists(original))
        self.assertIsNone(
            self.app.store.get_action("skill", requested_name, "codex"),
        )
        entry = self.app.store.get_action("skill", canonical_name, "codex")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.actions.runtime, "disable")
        self.assertEqual(entry.actions.file, "quarantine")
        self.assertEqual(len(self.records_for(canonical_name, "codex")), 1)

    def test_scoped_codex_disable_isolates_same_named_claude_skill(self) -> None:
        name = "shared-runtime-skill"
        codex_original = self.create_skill("codex", name)
        claude_original = self.create_skill("claudecode", name)

        result = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(os.path.exists(codex_original))
        self.assertTrue(os.path.isfile(os.path.join(claude_original, "SKILL.md")))
        codex_entry = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(codex_entry.actions.file, "quarantine")
        self.assertEqual(codex_entry.actions.runtime, "disable")
        self.assertIsNone(self.app.store.get_action("skill", name, "claudecode"))
        self.assertEqual(
            self.records_for(name, "codex")[0].purpose,
            "runtime-isolation",
        )
        self.assertEqual(self.records_for(name, "claudecode"), [])

    def test_bare_disable_fans_out_without_creating_global_runtime_state(self) -> None:
        name = "bare-runtime-skill"
        codex_original = self.create_skill("codex", name)
        claude_original = self.create_skill("claudecode", name)

        result = self.invoke(["disable", name])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector=codex", result.output)
        self.assertIn("connector=claudecode", result.output)
        self.assertFalse(os.path.exists(codex_original))
        self.assertTrue(os.path.isdir(claude_original))
        codex_entry = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(codex_entry.actions.file, "quarantine")
        self.assertEqual(codex_entry.actions.runtime, "disable")
        claude_entry = self.app.store.get_action("skill", name, "claudecode")
        self.assertEqual(claude_entry.actions.file, "")
        self.assertEqual(claude_entry.actions.runtime, "disable")
        self.assertIsNone(self.app.store.get_action("skill", name))
        self.assertEqual(
            self.records_for(name, "codex")[0].purpose,
            "runtime-isolation",
        )
        self.assertEqual(self.records_for(name, "claudecode"), [])

    @unittest.skipUnless(os.name == "nt", "Windows cross-root casing contract")
    def test_bare_disable_and_enable_use_each_connector_canonical_case(self) -> None:
        codex_name = "CaseSplitSkill"
        claude_name = codex_name.lower()
        self.create_skill("codex", codex_name)
        self.create_skill("claudecode", claude_name)

        disabled = self.invoke(["disable", claude_name])

        self.assertEqual(disabled.exit_code, 0, disabled.output)
        self.assertEqual(
            self.app.store.get_action("skill", codex_name, "codex").actions.runtime,
            "disable",
        )
        self.assertEqual(
            self.app.store.get_action(
                "skill", claude_name, "claudecode",
            ).actions.runtime,
            "disable",
        )
        self.assertIsNone(
            self.app.store.get_action("skill", claude_name, "codex"),
        )
        self.assertIsNone(
            self.app.store.get_action("skill", codex_name, "claudecode"),
        )

        enabled = self.invoke(["enable", claude_name])

        self.assertEqual(enabled.exit_code, 0, enabled.output)
        self.assertEqual(
            self.app.store.get_action("skill", codex_name, "codex").actions.runtime,
            "",
        )
        self.assertIsNone(
            self.app.store.get_action("skill", claude_name, "claudecode"),
        )

        restored = self.invoke([
            "restore", claude_name, "--connector", "codex",
        ])
        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(
            self.codex_root, codex_name, "SKILL.md",
        )))

    def test_codex_allow_clears_policy_but_requires_explicit_restore(self) -> None:
        name = "runtime-allow-lifecycle"
        original = self.create_skill("codex", name)
        disabled = self.invoke(["disable", name, "--connector", "codex"])
        self.assertEqual(disabled.exit_code, 0, disabled.output)

        allowed = self.invoke(["allow", name, "--connector", "codex"])

        self.assertEqual(allowed.exit_code, 0, allowed.output)
        self.assertIn("files remain quarantined", allowed.output)
        self.assertIn("restore explicitly", allowed.output)
        self.assertFalse(os.path.exists(original))
        entry = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(entry.actions.install, "allow")
        self.assertEqual(entry.actions.file, "")
        self.assertEqual(entry.actions.runtime, "")
        self.assertEqual(entry.source_path, os.path.realpath(original))
        self.assertEqual(
            self.records_for(name, "codex")[0].purpose,
            "runtime-isolation",
        )

        restored = self.invoke(["restore", name, "--connector", "codex"])
        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        restored_entry = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(restored_entry.actions.install, "allow")

    def test_scoped_allow_overrides_global_runtime_disable_for_restore(self) -> None:
        name = "scoped-allow-global-runtime"
        original = self.create_skill("codex", name)
        self.assertEqual(
            self.invoke(["disable", name, "--connector", "codex"]).exit_code,
            0,
        )
        pe = PolicyEngine(self.app.store)
        pe.disable("skill", name, "global runtime fixture")

        allowed = self.invoke(["allow", name, "--connector", "codex"])

        self.assertEqual(allowed.exit_code, 0, allowed.output)
        scoped = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(scoped.actions.install, "allow")
        self.assertEqual(scoped.actions.runtime, "enable")
        self.assertTrue(self.app.store.has_action(
            "skill", name, "runtime", "disable", "",
        ))
        self.assertFalse(
            __import__(
                "defenseclaw.commands.cmd_skill",
                fromlist=["_effective_skill_runtime_disabled"],
            )._effective_skill_runtime_disabled(self.app, name, "codex")
        )

        restored = self.invoke(["restore", name, "--connector", "codex"])
        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))

    @unittest.skipUnless(os.name == "nt", "Windows global identity casing")
    def test_bare_allow_removes_case_equivalent_global_runtime_state(self) -> None:
        canonical = "CanonicalAllowSkill"
        requested = canonical.lower()
        self.create_skill("codex", canonical)
        pe = PolicyEngine(self.app.store)
        pe.disable("skill", canonical, "global runtime fixture")

        allowed = self.invoke(["allow", requested])

        self.assertEqual(allowed.exit_code, 0, allowed.output)
        self.assertIsNone(self.app.store.get_action("skill", canonical))
        scoped = self.app.store.get_action("skill", canonical, "codex")
        self.assertIsNotNone(scoped)
        self.assertEqual(scoped.actions.install, "allow")
        self.assertEqual(scoped.actions.runtime, "")

    def test_runtime_restore_rejects_byte_identical_quarantine_replacement(self) -> None:
        name = "quarantine-identity-replacement"
        self.create_skill("codex", name)
        self.assertEqual(
            self.invoke(["disable", name, "--connector", "codex"]).exit_code,
            0,
        )
        self.assertEqual(
            self.invoke(["enable", name, "--connector", "codex"]).exit_code,
            0,
        )
        record = self.records_for(name, "codex")[0]
        shutil.rmtree(record.quarantine_path)
        os.makedirs(record.quarantine_path)
        with open(
            os.path.join(record.quarantine_path, "SKILL.md"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("test fixture\n")
        self.assertEqual(
            SkillEnforcer(self.app.cfg.quarantine_dir).content_hash(
                record.quarantine_path,
            ),
            record.content_hash,
        )

        restored = self.invoke(["restore", name, "--connector", "codex"])

        self.assertEqual(restored.exit_code, 1, restored.output)
        self.assertIn("identity check failed", restored.output)
        self.assertEqual(self.records_for(name, "codex")[0].state, "active")

    def test_runtime_restore_post_move_failure_is_retry_finalizable(self) -> None:
        name = "runtime-restore-reconcile"
        original = self.create_skill("codex", name)
        self.assertEqual(
            self.invoke(["disable", name, "--connector", "codex"]).exit_code,
            0,
        )
        self.assertEqual(
            self.invoke(["enable", name, "--connector", "codex"]).exit_code,
            0,
        )
        record = self.records_for(name, "codex")[0]
        real_verify = SkillEnforcer._verified_hash_identity

        def fail_restored_verification(path: str):
            if os.path.normcase(path) == os.path.normcase(original):
                return None
            return real_verify(path)

        with (
            patch.object(
                SkillEnforcer,
                "_verified_hash_identity",
                side_effect=fail_restored_verification,
            ),
            patch.object(
                SkillEnforcer,
                "_rollback_atomic_move",
                return_value=False,
            ),
        ):
            failed = self.invoke(["restore", name, "--connector", "codex"])

        self.assertEqual(failed.exit_code, 1, failed.output)
        self.assertIn("retry reconciliation", failed.output)
        self.assertFalse(os.path.exists(record.quarantine_path))
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        self.assertEqual(self.records_for(name, "codex")[0].state, "restoring")

        retried = self.invoke(["restore", name, "--connector", "codex"])
        self.assertEqual(retried.exit_code, 0, retried.output)
        self.assertIn("restore finalized", retried.output)
        self.assertEqual(self.records_for(name, "codex"), [])

    def test_codex_enable_then_unblock_then_restore_preserves_each_dimension(self) -> None:
        name = "runtime-lifecycle-skill"
        original = self.create_skill("codex", name)
        blocked = self.invoke(["block", name, "--connector", "codex"])
        self.assertEqual(blocked.exit_code, 0, blocked.output)
        disabled = self.invoke(["disable", name, "--connector", "codex"])
        self.assertEqual(disabled.exit_code, 0, disabled.output)
        record = self.records_for(name, "codex")[0]
        self.assertEqual(record.purpose, "runtime-isolation")

        refused = self.invoke(["restore", name, "--connector", "codex"])
        self.assertEqual(refused.exit_code, 1, refused.output)
        self.assertIn("remains runtime-disabled for Codex", refused.output)
        self.assertFalse(os.path.exists(original))
        self.assertTrue(os.path.isdir(record.quarantine_path))

        enabled = self.invoke(["enable", name, "--connector", "codex"])
        self.assertEqual(enabled.exit_code, 0, enabled.output)
        self.assertIn("files remain quarantined", enabled.output)
        self.assertIn("restore explicitly", enabled.output)
        entry = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(entry.actions.runtime, "")
        self.assertEqual(entry.actions.file, "quarantine")
        self.assertEqual(entry.actions.install, "block")
        self.assertEqual(entry.source_path, os.path.realpath(original))
        self.assertEqual(self.records_for(name, "codex")[0].original_path, os.path.realpath(original))

        unblocked = self.invoke(["unblock", name, "--connector", "codex"])
        self.assertEqual(unblocked.exit_code, 0, unblocked.output)
        self.assertIsNone(self.app.store.get_action("skill", name, "codex"))
        self.assertEqual(self.records_for(name, "codex")[0].original_path, os.path.realpath(original))

        restored = self.invoke(["restore", name, "--connector", "codex"])
        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        self.assertEqual(self.records_for(name, "codex"), [])
        restored_entry = self.app.store.get_action("skill", name, "codex")
        self.assertIsNotNone(restored_entry)
        self.assertTrue(restored_entry.actions.is_empty())
        self.assertEqual(restored_entry.source_path, os.path.realpath(original))

    def test_runtime_isolation_coexists_with_operator_record_and_preflights_restore(self) -> None:
        name = "coexisting-quarantine-purposes"
        original = self.create_skill("codex", name)
        operator = self.invoke(["quarantine", name, "--connector", "codex"])
        self.assertEqual(operator.exit_code, 0, operator.output)
        operator_record = self.records_for(name, "codex")[0]
        self.assertEqual(operator_record.purpose, "operator")

        self.create_skill("codex", name)
        disabled = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(disabled.exit_code, 0, disabled.output)
        records = self.records_for(name, "codex")
        self.assertEqual(
            {record.purpose for record in records},
            {"operator", "runtime-isolation"},
        )
        runtime_record = next(
            record for record in records if record.purpose == "runtime-isolation"
        )
        self.assertFalse(os.path.exists(original))
        self.assertTrue(os.path.isdir(operator_record.quarantine_path))
        self.assertTrue(os.path.isdir(runtime_record.quarantine_path))

        retried = self.invoke(["disable", name, "--connector", "codex"])
        self.assertEqual(retried.exit_code, 0, retried.output)
        self.assertEqual(len(self.records_for(name, "codex")), 2)

        refused = self.invoke(["restore", name, "--connector", "codex"])

        self.assertEqual(refused.exit_code, 1, refused.output)
        self.assertIn("remains runtime-disabled for Codex", refused.output)
        self.assertNotIn(" restored ", refused.output)
        self.assertFalse(os.path.exists(original))
        self.assertTrue(os.path.isdir(operator_record.quarantine_path))
        self.assertTrue(os.path.isdir(runtime_record.quarantine_path))
        self.assertEqual(len(self.records_for(name, "codex")), 2)

    def test_reintroduced_runtime_generations_restore_by_exact_record(self) -> None:
        name = "reintroduced-runtime-generation"
        original = self.create_skill("codex", name)
        first = self.invoke(["disable", name, "--connector", "codex"])
        self.assertEqual(first.exit_code, 0, first.output)
        first_record = self.records_for(name, "codex")[0]

        # A future/imported timestamp must not make post-move verification
        # select this older generation instead of the exact new journal.
        with self.app.store.db:
            self.app.store.db.execute(
                "UPDATE quarantine_records SET created_at = ? WHERE id = ?",
                ("9999-12-31T23:59:59+00:00", first_record.id),
            )

        recreated = self.create_skill("codex", name)
        with open(
            os.path.join(recreated, "generation.txt"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("second generation\n")
        second = self.invoke(["disable", name, "--connector", "codex"])

        self.assertEqual(second.exit_code, 0, second.output)
        records = self.records_for(name, "codex")
        self.assertEqual(len(records), 2)
        second_record = next(record for record in records if record.id != first_record.id)
        self.assertNotEqual(first_record.id, second_record.id)
        self.assertFalse(os.path.exists(original))
        self.assertTrue(os.path.isdir(first_record.quarantine_path))
        self.assertTrue(os.path.isdir(second_record.quarantine_path))
        retried = self.invoke(["disable", name, "--connector", "codex"])
        self.assertEqual(retried.exit_code, 0, retried.output)
        self.assertEqual(len(self.records_for(name, "codex")), 2)

        enabled = self.invoke(["enable", name, "--connector", "codex"])
        self.assertEqual(enabled.exit_code, 0, enabled.output)
        ambiguous = self.invoke(["restore", name, "--connector", "codex"])
        self.assertEqual(ambiguous.exit_code, 1, ambiguous.output)
        self.assertIn("multiple quarantine generations", ambiguous.output)
        self.assertFalse(os.path.exists(original))
        self.assertTrue(os.path.isdir(first_record.quarantine_path))
        self.assertTrue(os.path.isdir(second_record.quarantine_path))

        newest = self.invoke([
            "restore",
            name,
            "--connector",
            "codex",
            "--record-id",
            second_record.id,
        ])
        self.assertEqual(newest.exit_code, 0, newest.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "generation.txt")))
        self.assertTrue(os.path.isdir(first_record.quarantine_path))

        older_destination = os.path.join(self.codex_root, f"{name}-older")
        older = self.invoke([
            "restore",
            name,
            "--connector",
            "codex",
            "--record-id",
            first_record.id,
            "--path",
            older_destination,
        ])
        self.assertEqual(older.exit_code, 0, older.output)
        self.assertTrue(os.path.isfile(os.path.join(older_destination, "SKILL.md")))
        self.assertEqual(self.records_for(name, "codex"), [])

    def test_enable_write_failure_never_prints_success(self) -> None:
        name = "enable-write-failure"
        self.create_skill("codex", name)
        disabled = self.invoke(["disable", name, "--connector", "codex"])
        self.assertEqual(disabled.exit_code, 0, disabled.output)

        with patch.object(
            PolicyEngine,
            "enable_for_connector",
            side_effect=OSError("runtime policy database unavailable"),
        ):
            failed = self.invoke(["enable", name, "--connector", "codex"])

        self.assertEqual(failed.exit_code, 1, failed.output)
        self.assertIn("runtime enable persistence failed", failed.output)
        self.assertNotIn("runtime disable cleared", failed.output)
        self.assertNotIn("enabled for connector", failed.output)
        entry = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(entry.actions.runtime, "disable")

    def test_operator_quarantine_restore_is_not_owned_by_runtime_disable(self) -> None:
        name = "operator-quarantine-skill"
        original = self.create_skill("codex", name)
        quarantined = self.invoke([
            "quarantine", name, "--connector", "codex",
        ])
        self.assertEqual(quarantined.exit_code, 0, quarantined.output)
        record = self.records_for(name, "codex")[0]
        self.assertEqual(record.purpose, "operator")
        PolicyEngine(self.app.store).disable_for_connector(
            "skill", name, "codex", "independent runtime policy",
        )

        restored = self.invoke(["restore", name, "--connector", "codex"])

        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        self.assertEqual(self.records_for(name, "codex"), [])
        entry = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(entry.actions.file, "")
        self.assertEqual(entry.actions.runtime, "disable")
        self.assertEqual(entry.source_path, os.path.realpath(original))

    def test_watcher_quarantine_restore_preserves_independent_runtime_and_install(self) -> None:
        name = "watcher-quarantine-skill"
        original = self.create_skill("codex", name)
        enforcer = SkillEnforcer(self.app.cfg.quarantine_dir)
        content_hash = enforcer.content_hash(original)
        destination = enforcer.quarantine_path(name, "codex")
        record = self.app.store.create_quarantine_record(
            "skill",
            name,
            os.path.realpath(original),
            destination,
            content_hash,
            "watcher enforcement fixture",
            "codex",
            purpose="watcher-enforcement",
        )
        self.assertEqual(
            enforcer.quarantine(
                name, original, "codex", expected_hash=content_hash,
            ),
            destination,
        )
        self.app.store.update_quarantine_record_state(record.id, "active")
        pe = PolicyEngine(self.app.store)
        pe.quarantine_for_connector(
            "skill", name, "codex", "watcher enforcement fixture",
        )
        pe.set_source_path("skill", name, original, "codex")
        pe.disable_for_connector("skill", name, "codex", "independent runtime")
        pe.block_for_connector("skill", name, "codex", "independent install")

        restored = self.invoke([
            "restore",
            name,
            "--connector",
            "codex",
            "--record-id",
            record.id,
        ])

        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        entry = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(entry.actions.file, "")
        self.assertEqual(entry.actions.runtime, "disable")
        self.assertEqual(entry.actions.install, "block")
        self.assertEqual(self.records_for(name, "codex"), [])

        reused = self.invoke([
            "restore",
            name,
            "--connector",
            "codex",
            "--record-id",
            record.id,
        ])
        self.assertEqual(reused.exit_code, 1, reused.output)
        self.assertIn("does not match", reused.output)

    def test_exact_watcher_restore_ignores_peer_runtime_isolation_guard(self) -> None:
        name = "watcher-runtime-coexistence"
        original = self.create_skill("codex", name)
        enforcer = SkillEnforcer(self.app.cfg.quarantine_dir)
        content_hash = enforcer.content_hash(original)
        destination = enforcer.quarantine_path(name, "codex")
        watcher_record = self.app.store.create_quarantine_record(
            "skill",
            name,
            os.path.realpath(original),
            destination,
            content_hash,
            "watcher enforcement fixture",
            "codex",
            purpose="watcher-enforcement",
        )
        self.assertEqual(
            enforcer.quarantine(
                name, original, "codex", expected_hash=content_hash,
            ),
            destination,
        )
        self.app.store.update_quarantine_record_state(watcher_record.id, "active")

        self.create_skill("codex", name)
        disabled = self.invoke(["disable", name, "--connector", "codex"])
        self.assertEqual(disabled.exit_code, 0, disabled.output)
        PolicyEngine(self.app.store).block_for_connector(
            "skill", name, "codex", "independent install",
        )
        runtime_record = next(
            record
            for record in self.records_for(name, "codex")
            if record.purpose == "runtime-isolation"
        )

        inspected = self.invoke([
            "info", name, "--connector", "codex", "--json",
        ])
        self.assertEqual(inspected.exit_code, 0, inspected.output)
        advertised = json.loads(inspected.output)["quarantine_records"]
        advertised_watcher = next(
            record
            for record in advertised
            if record["purpose"] == "watcher-enforcement"
        )
        self.assertEqual(advertised_watcher["state"], "active")
        self.assertEqual(advertised_watcher["connectors"], ["codex"])

        restored = self.invoke([
            "restore",
            name,
            "--connector",
            "codex",
            "--record-id",
            advertised_watcher["id"],
        ])

        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        remaining = self.records_for(name, "codex")
        self.assertEqual([record.id for record in remaining], [runtime_record.id])
        entry = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(entry.actions.file, "quarantine")
        self.assertEqual(entry.actions.runtime, "disable")
        self.assertEqual(entry.actions.install, "block")
        self.assertEqual(entry.source_path, runtime_record.original_path)

        enabled = self.invoke(["enable", name, "--connector", "codex"])
        self.assertEqual(enabled.exit_code, 0, enabled.output)
        runtime_destination = os.path.join(self.codex_root, f"{name}-runtime")
        final = self.invoke([
            "restore",
            name,
            "--connector",
            "codex",
            "--record-id",
            runtime_record.id,
            "--path",
            runtime_destination,
        ])
        self.assertEqual(final.exit_code, 0, final.output)
        final_entry = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(final_entry.actions.file, "")
        self.assertEqual(final_entry.actions.runtime, "")
        self.assertEqual(final_entry.actions.install, "block")
        self.assertEqual(final_entry.source_path, os.path.realpath(runtime_destination))

    def test_scoped_enable_overrides_global_disable_before_runtime_restore(self) -> None:
        name = "global-runtime-override-skill"
        original = self.create_skill("codex", name)
        disabled = self.invoke(["disable", name, "--connector", "codex"])
        self.assertEqual(disabled.exit_code, 0, disabled.output)
        pe = PolicyEngine(self.app.store)
        pe.disable("skill", name, "global runtime policy")
        pe.enable_for_connector("skill", name, "codex")

        enabled = self.invoke(["enable", name, "--connector", "codex"])

        self.assertEqual(enabled.exit_code, 0, enabled.output)
        self.assertIn("global runtime disable remains", enabled.output)
        scoped = self.app.store.get_action("skill", name, "codex")
        self.assertEqual(scoped.actions.runtime, "enable")
        self.assertTrue(
            self.app.store.has_action(
                "skill", name, "runtime", "disable", "",
            )
        )

        restored = self.invoke(["restore", name, "--connector", "codex"])
        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))

    def test_codex_disable_is_visible_in_list_and_info_json(self) -> None:
        name = "runtime-visible-skill"
        self.create_skill("codex", name)
        disabled = self.invoke(["disable", name, "--connector", "codex"])
        self.assertEqual(disabled.exit_code, 0, disabled.output)

        listed = self.invoke(["list", "--json", "--connector", "codex"])
        self.assertEqual(listed.exit_code, 0, listed.output)
        list_payload = json.loads(listed.output)
        item = next(skill_item for skill_item in list_payload["skills"] if skill_item["name"] == name)
        self.assertEqual(item["connector"], "codex")
        self.assertEqual(item["actions"]["file"], "quarantine")
        self.assertEqual(item["actions"]["runtime"], "disable")
        self.assertEqual(item["verdict"], "quarantined")

        detailed = self.invoke(["info", name, "--json", "--connector", "codex"])
        self.assertEqual(detailed.exit_code, 0, detailed.output)
        info_payload = json.loads(detailed.output)
        self.assertEqual(info_payload["name"], name)
        self.assertEqual(info_payload["connector"], "codex")
        self.assertEqual(info_payload["actions"]["file"], "quarantine")
        self.assertEqual(info_payload["actions"]["runtime"], "disable")

    def test_codex_quarantine_unblock_restore_without_path_real_filesystem(self) -> None:
        original = self.create_skill("codex")

        quarantined = self.invoke(["quarantine", "dangerous", "--connector", "codex"])
        self.assertEqual(quarantined.exit_code, 0, quarantined.output)
        record = self.records("codex")[0]
        self.assertFalse(os.path.exists(original))
        self.assertTrue(os.path.isdir(record.quarantine_path))
        self.assertEqual(record.purpose, "operator")
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

    def test_operator_source_removal_failure_retains_verified_provenance(self) -> None:
        original = self.create_skill("codex")

        with patch.object(
            SkillEnforcer,
            "_remove_path",
            side_effect=PermissionError("simulated source removal denial"),
        ):
            result = self.invoke([
                "quarantine", "dangerous", "--connector", "codex",
            ])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertTrue(os.path.isfile(os.path.join(original, "SKILL.md")))
        records = self.records("codex")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].purpose, "operator")
        self.assertEqual(records[0].state, "pending")
        self.assertTrue(os.path.isfile(os.path.join(
            records[0].quarantine_path, "SKILL.md",
        )))

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
