# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import copy
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import prepare
from artifact_archive import ZipEvidence, sha


class FixedPreparationTests(unittest.TestCase):
    def test_missing_driver_review_refuses_before_files_or_api(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(prepare, "DRIVER_PROVENANCE_SHA", None):
            root = Path(directory) / "never-created"
            with self.assertRaises(ValueError):
                prepare.prepare(
                    root,
                    metadata_api=lambda _: self.fail("metadata reached"),
                    download=lambda _: self.fail("download reached"),
                )
            self.assertFalse(root.exists())

    def valid_actions(self):
        pin = prepare.PINS["driver"]
        run = {
            "id": pin["run"],
            "run_attempt": 1,
            "head_sha": pin["commit"],
            "repository": {"full_name": prepare.REPOSITORY},
            "head_repository": {"full_name": prepare.REPOSITORY},
            "status": "completed",
            "conclusion": "success",
            "path": pin["workflow"],
            "head_branch": pin["branch"],
            "event": pin["event"],
        }
        artifact = {
            "id": pin["artifact"],
            "expired": False,
            "digest": "sha256:" + pin["archive"],
            "name": pin["stem"] + pin["commit"],
            "workflow_run": {"id": pin["run"], "head_sha": pin["commit"]},
            "size_in_bytes": 100,
        }
        return pin, run, artifact

    def test_actions_route_source_and_digest_are_all_required(self):
        pin, run, artifact = self.valid_actions()
        prepare.check_actions(pin, run, artifact)
        for key in run:
            candidate = copy.deepcopy(run)
            candidate[key] = None
            with self.subTest(run=key), self.assertRaises(ValueError):
                prepare.check_actions(pin, candidate, artifact)
        for key in artifact:
            candidate = copy.deepcopy(artifact)
            candidate[key] = None
            with self.subTest(artifact=key), self.assertRaises(ValueError):
                prepare.check_actions(pin, run, candidate)

    def manifest_fixture(self, extra=False, omit=False):
        pin = dict(prepare.PINS["wrapper"])
        content = b"inert-public-fixture"
        value = {
            "repository": prepare.REPOSITORY,
            "workflow": pin["workflow"],
            "build_commit": pin["commit"],
            "run_id": pin["run"],
            "run_attempt": 1,
            "files": {"source/fixed.txt": {"sha256": sha(content), "size": len(content)}},
        }
        raw = (json.dumps(value) + "\n").encode()
        pin["provenance"] = sha(raw)
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("PROVENANCE.json", raw)
            if not omit:
                archive.writestr("source/fixed.txt", content)
            if extra:
                archive.writestr("undeclared.txt", b"public")
        return pin, ZipEvidence(target.getvalue())

    def test_full_manifest_rejects_missing_or_extra_members(self):
        pin, archive = self.manifest_fixture()
        prepare.flat_manifest(archive, pin)
        for kwargs in ({"extra": True}, {"omit": True}):
            pin, archive = self.manifest_fixture(**kwargs)
            with self.assertRaises(ValueError):
                prepare.flat_manifest(archive, pin)

    def test_provenance_and_member_pins_cannot_be_chosen_by_artifact(self):
        pin, archive = self.manifest_fixture()
        pin["provenance"] = "0" * 64
        with self.assertRaises(ValueError):
            prepare.flat_manifest(archive, pin)
        with self.assertRaises(ValueError):
            prepare.select(archive, "source/fixed.txt", "0" * 64)

    def test_compiled_combined_receipt_bytes_are_exact(self):
        raw = prepare.ordinary(Path(prepare.__file__).with_name("REVIEWED-ARTIFACTS.json"))
        self.assertEqual(sha(raw), prepare.RECEIPT_SHA)
        self.assertFalse(json.loads(raw)["execution_performed"])

    def test_fixture_collection_refuses_before_open_without_cleanup_or_binding(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                evidence = Path("live-evidence")
                evidence.mkdir()
                for complete, fixture, receipt in [
                    (False, "/tmp/dc-axis-native-peer-" + "a" * 32, prepare.RECEIPT_SHA),
                    (True, "/tmp/unrelated-private-directory", prepare.RECEIPT_SHA),
                    (True, "/tmp/dc-axis-native-peer-" + "a" * 32, "0" * 64),
                ]:
                    nested = {
                        "scope": "fixed_linux_native_peer_offline_contributor_v1",
                        "production_certification": False,
                        "synthetic_fixture": fixture,
                        "artifact_receipt_sha256": receipt,
                    }
                    result = {
                        "scope": "fixed_linux_native_peer_outer_driver_v1",
                        "whole_wrapper_namespace_cleanup_observed": complete,
                        "pending_driver_cleanup": 0,
                        "wrapper_stdout": json.dumps(nested),
                    }
                    (evidence / "DRIVER-RESULT.json").write_text(json.dumps(result))
                    with mock.patch.object(prepare.os, "open", side_effect=AssertionError("fixture open reached")):
                        prepare.collect()
                    record = json.loads((evidence / "COLLECTION.json").read_text())
                    self.assertFalse(record["fixture_copied"])
                    self.assertIn("error", record)
            finally:
                os.chdir(original)

    def test_tree_member_names_are_exact_and_only_in_work(self):
        expected = {
            "tree-parent.ready",
            "tree-child.ready",
            "tree-grandchild.ready",
            "tree-parent.heartbeat",
            "tree-child.heartbeat",
            "tree-grandchild.heartbeat",
        }
        self.assertEqual(prepare.TREE_FILES, expected)
        for name in expected:
            self.assertTrue(prepare.fixture_member_name(name, ("work",)))
            for relative in [(), ("home",), ("work", "nested")]:
                self.assertFalse(prepare.fixture_member_name(name, relative))
        for name in [
            "tree-other.ready",
            "tree-parent.ready.extra",
            ".ready",
            "../tree-parent.ready",
            "tree-parent/ready",
        ]:
            self.assertFalse(prepare.fixture_member_name(name, ("work",)))
        self.assertTrue(prepare.fixture_member_name("fixture-seal", ("work",)))
        with (
            mock.patch.object(prepare.os, "listdir", return_value=["tree-parent.ready"]),
            mock.patch.object(prepare.os, "open", side_effect=AssertionError("refused name reached native open")),
        ):
            with self.assertRaises(ValueError):
                prepare.copy_fixture(99, Path("unused"), 0, [0, 0])

    @unittest.skipUnless(__import__("os").name == "posix", "descriptor fixture copier is Linux-only")
    def test_tree_file_copy_keeps_existing_limits_and_refuses_directory_alias(self):
        import os

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            work = source / "work"
            work.mkdir()
            for name in prepare.TREE_FILES:
                (work / name).write_bytes(b"fixed-public\n")
            fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                budget = [0, 0]
                prepare.copy_fixture(fd, target, 0, budget)
                self.assertEqual(budget, [7, 78])
                self.assertEqual({path.name for path in (target / "work").iterdir()}, prepare.TREE_FILES)
                (work / "tree-parent.ready").unlink()
                (work / "tree-parent.ready").mkdir()
                second = root / "second"
                second.mkdir()
                with self.assertRaisesRegex(ValueError, "regular file"):
                    prepare.copy_fixture(fd, second, 0, [0, 0])
            finally:
                os.close(fd)

    @unittest.skipUnless(__import__("os").name == "posix", "descriptor fixture copier is Linux-only")
    def test_fixture_copy_rejects_links_and_preserves_owned_regular_data(self):
        import os

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            (source / "read-canary").write_bytes(b"fixed-public\n")
            fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                budget = [0, 0]
                prepare.copy_fixture(fd, target, 0, budget)
                self.assertEqual((target / "read-canary").read_bytes(), b"fixed-public\n")
                self.assertEqual(budget, [1, 13])
                (source / "read-canary").unlink()
                (source / "link").symlink_to(root / "outside-public-fixture")
                with self.assertRaises(OSError):
                    prepare.copy_fixture(fd, target, 0, [0, 0])
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
