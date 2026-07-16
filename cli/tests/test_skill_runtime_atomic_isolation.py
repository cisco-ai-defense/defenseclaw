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

"""WIN-AUD-070 atomic runtime-isolation filesystem regressions."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from defenseclaw.enforce.skill_enforcer import SkillEnforcer

from tests.environment import requires_symlink_privilege
from tests.permissions import grant_everyone


class TestSkillRuntimeAtomicIsolation(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temp_dir = temporary.name
        self.discovery_root = os.path.join(self.temp_dir, "skills")
        os.mkdir(self.discovery_root)
        self.enforcer = SkillEnforcer(os.path.join(self.temp_dir, "quarantine"))
        self.runtime_ownership: dict[str, str] = {}

    def create_skill(self, name: str = "benign-runtime-skill") -> str:
        path = os.path.join(self.discovery_root, name)
        os.mkdir(path)
        with open(os.path.join(path, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("harmless runtime-isolation fixture\n")
        return path

    def isolation_path(self, name: str = "benign-runtime-skill") -> str:
        path = self.enforcer.runtime_isolation_path(
            name,
            "codex",
            allowed_roots=[self.discovery_root],
        )
        self.assertIsNotNone(path)
        return str(path)

    def isolate(self, source: str, destination: str) -> bool:
        content_hash = self.enforcer.content_hash(source)
        self.assertIsNotNone(content_hash)
        ownership = self.enforcer.ownership_marker(source)
        isolated = self.enforcer.runtime_isolate(
            os.path.basename(source),
            source,
            "codex",
            quarantine_path=destination,
            expected_hash=str(content_hash),
            expected_ownership_json=ownership,
            allowed_roots=[self.discovery_root],
            isolation_roots=[self.discovery_root],
        )
        if isolated:
            combined = self.enforcer.runtime_ownership_marker(
                ownership, destination,
            )
            self.assertIsNotNone(combined)
            self.runtime_ownership[destination] = str(combined)
        return isolated

    def test_atomic_round_trip_preserves_identity_and_never_copies_or_removes(self) -> None:
        source = self.create_skill()
        source_identity = self.enforcer._path_identity(source)
        ownership = self.enforcer.ownership_marker(source)
        content_hash = self.enforcer.content_hash(source)
        destination = self.isolation_path()
        second_random_path = self.isolation_path()

        self.assertNotEqual(destination, second_random_path)
        self.assertFalse(
            self.enforcer._inside_one_root(
                destination,
                [os.path.realpath(self.discovery_root)],
            )
        )
        with (
            patch.object(
                SkillEnforcer,
                "_copy_path",
                side_effect=AssertionError("runtime isolation must not copy"),
            ),
            patch.object(
                SkillEnforcer,
                "_remove_path",
                side_effect=AssertionError("runtime isolation must not remove"),
            ),
        ):
            isolated = self.enforcer.runtime_isolate(
                "benign-runtime-skill",
                source,
                "codex",
                quarantine_path=destination,
                expected_hash=str(content_hash),
                expected_ownership_json=ownership,
                allowed_roots=[self.discovery_root],
                isolation_roots=[self.discovery_root],
            )
            combined_ownership = self.enforcer.runtime_ownership_marker(
                ownership, destination,
            )
            self.assertIsNotNone(combined_ownership)
            restored = self.enforcer.restore_runtime_isolation(
                "benign-runtime-skill",
                source,
                connector="codex",
                quarantine_path=destination,
                expected_hash=str(content_hash),
                expected_ownership_json=str(combined_ownership),
                allowed_roots=[self.discovery_root],
                isolation_roots=[self.discovery_root],
            )

        self.assertTrue(isolated)
        self.assertTrue(restored)
        self.assertTrue(os.path.isfile(os.path.join(source, "SKILL.md")))
        self.assertFalse(os.path.lexists(destination))
        self.assertEqual(self.enforcer._path_identity(source), source_identity)
        self.assertEqual(self.enforcer.ownership_marker(source), ownership)
        self.assertEqual(self.enforcer.content_hash(source), content_hash)

    def test_cross_device_identity_refuses_before_rename(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()

        with (
            patch.object(self.enforcer, "_same_filesystem", return_value=False),
            patch.object(self.enforcer, "_rename_no_replace") as rename,
        ):
            isolated = self.isolate(source, destination)

        self.assertFalse(isolated)
        self.assertTrue(os.path.isdir(source))
        self.assertFalse(os.path.lexists(destination))
        rename.assert_not_called()

    def test_macos_uses_exclusive_atomic_rename_primitive(self) -> None:
        rename_exclusive = unittest.mock.MagicMock(return_value=0)
        libc = unittest.mock.MagicMock(renameatx_np=rename_exclusive)
        source = os.path.join(self.temp_dir, "source-name")
        destination = os.path.join(self.temp_dir, "destination-name")

        with (
            patch.object(os, "name", "posix"),
            patch.object(sys, "platform", "darwin"),
            patch("ctypes.CDLL", return_value=libc),
        ):
            self.enforcer._rename_no_replace(source, destination, 3, 4)

        rename_exclusive.assert_called_once_with(
            3,
            os.fsencode("source-name"),
            4,
            os.fsencode("destination-name"),
            0x00000004,
        )

    def test_root_identity_mismatch_refuses_before_rename(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        original_matches = self.enforcer._identity_matches

        def mismatch_skill(path: str, expected) -> bool:
            if os.path.normcase(path) == os.path.normcase(source):
                return False
            return original_matches(path, expected)

        with (
            patch.object(
                self.enforcer,
                "_identity_matches",
                side_effect=mismatch_skill,
            ),
            patch.object(self.enforcer, "_rename_no_replace") as rename,
        ):
            isolated = self.isolate(source, destination)

        self.assertFalse(isolated)
        self.assertTrue(os.path.isdir(source))
        self.assertFalse(os.path.lexists(destination))
        rename.assert_not_called()

    def test_verified_snapshot_rejects_root_swap_during_capture(self) -> None:
        source = self.create_skill()
        displaced = os.path.join(self.temp_dir, "displaced-skill")
        real_marker = SkillEnforcer.ownership_marker

        def swap_before_marker(_path: str) -> str:
            os.rename(source, displaced)
            os.mkdir(source)
            with open(os.path.join(source, "SKILL.md"), "w", encoding="utf-8") as handle:
                handle.write("harmless runtime-isolation fixture\n")
            return real_marker(displaced)

        with patch.object(
            SkillEnforcer,
            "ownership_marker",
            side_effect=swap_before_marker,
        ):
            snapshot = self.enforcer.verified_snapshot(source)

        self.assertIsNone(snapshot)

    def test_ownership_match_compares_every_persisted_field(self) -> None:
        source = self.create_skill()
        marker = json.loads(self.enforcer.ownership_marker(source))
        marker["uid"] = int(marker.get("uid") or 0) + 1

        self.assertFalse(self.enforcer.matches_ownership_marker(
            source,
            json.dumps(marker, sort_keys=True, separators=(",", ":")),
        ))

    @unittest.skipUnless(os.name == "nt", "validates native Windows DACL integrity")
    def test_windows_acl_round_trip_and_tamper_detection(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        snapshot = self.enforcer.verified_snapshot(source)
        self.assertIsNotNone(snapshot)
        content_hash, _identity, ownership = snapshot
        self.assertTrue(self.enforcer.runtime_isolate(
            "benign-runtime-skill",
            source,
            "codex",
            quarantine_path=destination,
            expected_hash=content_hash,
            expected_ownership_json=ownership,
            allowed_roots=[self.discovery_root],
            isolation_roots=[self.discovery_root],
        ))
        combined = self.enforcer.runtime_ownership_marker(ownership, destination)
        self.assertIsNotNone(combined)
        self.assertTrue(self.enforcer.matches_runtime_ownership_marker(
            destination, str(combined), isolated=True,
        ))

        grant_everyone(destination, "R")

        self.assertFalse(self.enforcer.matches_runtime_ownership_marker(
            destination, str(combined), isolated=True,
        ))

    def test_source_mutation_after_hash_rolls_back_the_exact_entry(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        original_rename = self.enforcer._rename_no_replace

        def mutate_then_rename(
            old: str,
            new: str,
            old_parent_fd: int | None,
            new_parent_fd: int | None,
        ) -> None:
            with open(os.path.join(old, "SKILL.md"), "a", encoding="utf-8") as handle:
                handle.write("concurrent mutation\n")
            original_rename(old, new, old_parent_fd, new_parent_fd)

        with patch.object(
            self.enforcer,
            "_rename_no_replace",
            side_effect=mutate_then_rename,
        ):
            isolated = self.isolate(source, destination)

        self.assertFalse(isolated)
        self.assertTrue(os.path.isdir(source))
        self.assertFalse(os.path.lexists(destination))

    def test_existing_destination_is_refused_without_replacement(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        os.mkdir(destination)
        marker = os.path.join(destination, "owned-by-someone-else")
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("do not replace\n")

        isolated = self.isolate(source, destination)

        self.assertFalse(isolated)
        self.assertTrue(os.path.isdir(source))
        self.assertTrue(os.path.isfile(marker))

    def test_destination_creation_race_is_refused(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()

        def racing_destination(*_args) -> None:
            os.mkdir(destination)
            raise FileExistsError(destination)

        with patch.object(
            self.enforcer,
            "_rename_no_replace",
            side_effect=racing_destination,
        ):
            isolated = self.isolate(source, destination)

        self.assertFalse(isolated)
        self.assertTrue(os.path.isdir(source))
        self.assertTrue(os.path.isdir(destination))

    def test_foreign_destination_is_never_rolled_back_after_source_race(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        moved_source = os.path.join(self.temp_dir, "concurrently-moved-source")
        foreign_marker = os.path.join(destination, "foreign-owner")

        def race_source_and_destination(*_args) -> None:
            os.rename(source, moved_source)
            os.mkdir(destination)
            with open(foreign_marker, "w", encoding="utf-8") as handle:
                handle.write("must remain outside discovery\n")
            raise FileExistsError(destination)

        with patch.object(
            self.enforcer,
            "_rename_no_replace",
            side_effect=race_source_and_destination,
        ):
            isolated = self.isolate(source, destination)

        self.assertFalse(isolated)
        self.assertFalse(os.path.lexists(source))
        self.assertTrue(os.path.isfile(os.path.join(moved_source, "SKILL.md")))
        self.assertTrue(os.path.isfile(foreign_marker))

    def test_foreign_destination_swap_after_move_is_never_rolled_back(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        moved_source = os.path.join(self.temp_dir, "moved-before-destination-swap")
        foreign_marker = os.path.join(destination, "foreign-owner")
        original_rename = self.enforcer._rename_no_replace

        def move_then_swap_destination(
            old: str,
            new: str,
            old_parent_fd: int | None,
            new_parent_fd: int | None,
        ) -> None:
            original_rename(old, new, old_parent_fd, new_parent_fd)
            os.rename(new, moved_source)
            os.mkdir(new)
            with open(foreign_marker, "w", encoding="utf-8") as handle:
                handle.write("must remain outside discovery\n")

        with patch.object(
            self.enforcer,
            "_rename_no_replace",
            side_effect=move_then_swap_destination,
        ):
            isolated = self.isolate(source, destination)

        self.assertFalse(isolated)
        self.assertFalse(os.path.lexists(source))
        self.assertTrue(os.path.isfile(os.path.join(moved_source, "SKILL.md")))
        self.assertTrue(os.path.isfile(foreign_marker))

    def test_reparse_parent_chain_is_rejected(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        original_check = self.enforcer._is_link_or_reparse

        def simulated_reparse(path: str) -> bool:
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(
                self.discovery_root,
            ):
                return True
            return original_check(path)

        with (
            patch.object(
                SkillEnforcer,
                "_is_link_or_reparse",
                side_effect=simulated_reparse,
            ),
            patch.object(self.enforcer, "_rename_no_replace") as rename,
        ):
            isolated = self.isolate(source, destination)

        self.assertFalse(isolated)
        self.assertTrue(os.path.isdir(source))
        rename.assert_not_called()

    def test_move_refuses_nested_or_equal_peer_discovery_root(self) -> None:
        for relation in ("nested", "equal"):
            with self.subTest(relation=relation):
                source = self.create_skill(f"peer-root-{relation}")
                peer_root = source
                if relation == "nested":
                    peer_root = os.path.join(source, "peer-skills")
                    os.mkdir(peer_root)
                    peer_skill = os.path.join(peer_root, "peer-fixture")
                    os.mkdir(peer_skill)
                    with open(
                        os.path.join(peer_skill, "SKILL.md"),
                        "w",
                        encoding="utf-8",
                    ) as handle:
                        handle.write("peer connector fixture\n")
                destination = self.isolation_path(f"peer-root-{relation}")
                content_hash = self.enforcer.content_hash(source)
                ownership = self.enforcer.ownership_marker(source)

                isolated = self.enforcer.runtime_isolate(
                    f"peer-root-{relation}",
                    source,
                    "codex",
                    quarantine_path=destination,
                    expected_hash=str(content_hash),
                    expected_ownership_json=ownership,
                    allowed_roots=[self.discovery_root],
                    isolation_roots=[self.discovery_root, peer_root],
                )

                self.assertFalse(isolated)
                self.assertTrue(os.path.isfile(os.path.join(source, "SKILL.md")))
                self.assertFalse(os.path.lexists(destination))

    @requires_symlink_privilege
    def test_symlink_in_skill_tree_is_rejected(self) -> None:
        source = self.create_skill()
        outside = os.path.join(self.temp_dir, "outside.txt")
        with open(outside, "w", encoding="utf-8") as handle:
            handle.write("outside\n")
        os.symlink(outside, os.path.join(source, "linked.txt"))
        destination = self.isolation_path()

        with patch.object(self.enforcer, "_rename_no_replace") as rename:
            isolated = self.enforcer.runtime_isolate(
                "benign-runtime-skill",
                source,
                "codex",
                quarantine_path=destination,
                expected_hash="0" * 64,
                expected_ownership_json=self.enforcer.ownership_marker(source),
                allowed_roots=[self.discovery_root],
                isolation_roots=[self.discovery_root],
            )

        self.assertFalse(isolated)
        self.assertTrue(os.path.isdir(source))
        rename.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX physical-path canonicalization")
    def test_posix_symlink_ancestor_uses_canonical_held_paths(self) -> None:
        physical = os.path.join(self.temp_dir, "physical")
        alias = os.path.join(self.temp_dir, "alias")
        os.mkdir(physical)
        try:
            os.symlink(physical, alias, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"directory symlinks unavailable: {exc}")
        discovery = os.path.join(alias, "skills")
        os.mkdir(discovery)
        source = os.path.join(discovery, "alias-skill")
        os.mkdir(source)
        with open(os.path.join(source, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("harmless runtime-isolation fixture\n")
        enforcer = SkillEnforcer(os.path.join(alias, "quarantine"))
        snapshot = enforcer.verified_snapshot(os.path.realpath(source))
        self.assertIsNotNone(snapshot)
        content_hash, _identity, ownership = snapshot
        destination = enforcer.runtime_isolation_path(
            "alias-skill",
            "codex",
            allowed_roots=[discovery],
        )
        self.assertIsNotNone(destination)

        isolated = enforcer.runtime_isolate(
            "alias-skill",
            source,
            "codex",
            quarantine_path=str(destination),
            expected_hash=content_hash,
            expected_ownership_json=ownership,
            allowed_roots=[discovery],
            isolation_roots=[discovery],
        )

        self.assertTrue(isolated)

    def test_failed_post_move_validation_retains_fail_closed_target(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        original_verify = self.enforcer._verified_hash_identity

        def fail_destination_verification(path: str):
            if os.path.normcase(path) == os.path.normcase(destination):
                return None
            return original_verify(path)

        with (
            patch.object(
                self.enforcer,
                "_verified_hash_identity",
                side_effect=fail_destination_verification,
            ),
            patch.object(
                self.enforcer,
                "_rollback_atomic_move",
                return_value=False,
            ),
        ):
            isolated = self.isolate(source, destination)

        self.assertFalse(isolated)
        self.assertFalse(os.path.lexists(source))
        self.assertTrue(os.path.isdir(destination))

    def test_restore_hash_mismatch_never_moves_quarantine(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        content_hash = self.enforcer.content_hash(source)
        self.assertTrue(self.isolate(source, destination))
        with open(
            os.path.join(destination, "SKILL.md"),
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write("tampered while isolated\n")

        restored = self.enforcer.restore_runtime_isolation(
            "benign-runtime-skill",
            source,
            connector="codex",
            quarantine_path=destination,
            expected_hash=str(content_hash),
            expected_ownership_json=self.runtime_ownership[destination],
            allowed_roots=[self.discovery_root],
            isolation_roots=[self.discovery_root],
        )

        self.assertFalse(restored)
        self.assertFalse(os.path.lexists(source))
        self.assertTrue(os.path.isdir(destination))

    def test_restore_post_move_validation_rolls_back_to_quarantine(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        content_hash = self.enforcer.content_hash(source)
        self.assertTrue(self.isolate(source, destination))
        original_verify = self.enforcer._verified_hash_identity

        def fail_restored_verification(path: str):
            if os.path.normcase(path) == os.path.normcase(source):
                return None
            return original_verify(path)

        with patch.object(
            self.enforcer,
            "_verified_hash_identity",
            side_effect=fail_restored_verification,
        ):
            restored = self.enforcer.restore_runtime_isolation(
                "benign-runtime-skill",
                source,
                connector="codex",
                quarantine_path=destination,
                expected_hash=str(content_hash),
                expected_ownership_json=self.runtime_ownership[destination],
                allowed_roots=[self.discovery_root],
                isolation_roots=[self.discovery_root],
            )

        self.assertFalse(restored)
        self.assertFalse(os.path.lexists(source))
        self.assertTrue(os.path.isdir(destination))

    def test_restore_destination_parent_swap_signal_rolls_back(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        content_hash = self.enforcer.content_hash(source)
        self.assertTrue(self.isolate(source, destination))
        original_matches = self.enforcer._identity_matches
        destination_parent = os.path.dirname(source)
        parent_checks = 0

        def swap_after_move(path: str, expected) -> bool:
            nonlocal parent_checks
            if os.path.normcase(path) == os.path.normcase(destination_parent):
                parent_checks += 1
                if parent_checks > 1:
                    return False
            return original_matches(path, expected)

        with patch.object(
            self.enforcer,
            "_identity_matches",
            side_effect=swap_after_move,
        ):
            restored = self.enforcer.restore_runtime_isolation(
                "benign-runtime-skill",
                source,
                connector="codex",
                quarantine_path=destination,
                expected_hash=str(content_hash),
                expected_ownership_json=self.runtime_ownership[destination],
                allowed_roots=[self.discovery_root],
                isolation_roots=[self.discovery_root],
            )

        self.assertFalse(restored)
        self.assertFalse(os.path.lexists(source))
        self.assertTrue(os.path.isdir(destination))

    def test_restore_refuses_existing_destination_and_requires_recorded_path(self) -> None:
        source = self.create_skill()
        destination = self.isolation_path()
        content_hash = self.enforcer.content_hash(source)
        self.assertTrue(self.isolate(source, destination))
        os.mkdir(source)

        collision = self.enforcer.restore(
            "benign-runtime-skill",
            source,
            [self.discovery_root],
            "codex",
            expected_hash=str(content_hash),
            expected_ownership_json=self.runtime_ownership[destination],
            quarantine_path=destination,
            purpose="runtime-isolation",
            isolation_roots=[self.discovery_root],
        )
        missing_recorded_path = self.enforcer.restore(
            "benign-runtime-skill",
            source,
            [self.discovery_root],
            "codex",
            expected_hash=str(content_hash),
            expected_ownership_json=self.runtime_ownership[destination],
            quarantine_path="",
            purpose="runtime-isolation",
            isolation_roots=[self.discovery_root],
        )

        self.assertFalse(collision)
        self.assertFalse(missing_recorded_path)
        self.assertTrue(os.path.isdir(destination))


if __name__ == "__main__":
    unittest.main()
