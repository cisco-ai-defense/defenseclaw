# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Fixed synthetic verifier fixtures; no binaries or sandbox commands execute."""

from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path
from unittest import TestCase, mock

_SPEC = importlib.util.spec_from_file_location("mxc_verify_live", Path(__file__).with_name("verify_live_artifact.py"))
assert _SPEC is not None and _SPEC.loader is not None
verify = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verify)


class ArtifactVerificationTests(TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="dc-mxc-verifier-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.artifact = self.root / "artifact"
        self.checkout = self.root / "checkout"
        self.commit = "a" * 40
        self.run_id = "12345"
        self.combined_lock = b"synthetic combined lock fixture\n"
        self.upstream = {name: f"synthetic {name} lock fixture\n".encode() for name in ["axis", "mxc"]}
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(verify, "COMBINED_LOCK_SHA256", verify.sha256(self.combined_lock)).start()
        mock.patch.object(
            verify, "UPSTREAM_LOCK_SHA256", {name: verify.sha256(data) for name, data in self.upstream.items()}
        ).start()
        self.git = mock.patch.object(verify, "git_identity").start()
        for name in verify.FILES:
            path = self.artifact / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"synthetic non-executable {name}\n".encode())
        for name in verify.SOURCE_FILES:
            parent = "test/e2e/axis/patches" if name == "mxc-literal-argv.patch" else "test/e2e/axis/mxc-runner"
            path = self.checkout / parent / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((self.artifact / "source" / name).read_bytes())
        for base in [self.artifact / "source", self.checkout / "test/e2e/axis/mxc-runner"]:
            (base / "Cargo.lock").write_bytes(self.combined_lock)
        for name, data in self.upstream.items():
            (self.artifact / f"upstream/{name}-Cargo.lock").write_bytes(data)
        (self.artifact / "TOOLCHAIN.txt").write_bytes(b"rustc 1.95.0 (synthetic test fixture)\ncargo 1.95.0\n")
        mock.patch.object(
            verify,
            "LITERAL_PATCH_SHA256",
            verify.sha256((self.artifact / "source/mxc-literal-argv.patch").read_bytes()),
        ).start()
        self.provenance = {
            "schema": "defenseclaw-contributor-axis-mxc-probe-v1",
            "axis_commit": verify.AXIS_COMMIT,
            "mxc_commit": verify.MXC_COMMIT,
            "mxc_literal_patch_sha256": verify.LITERAL_PATCH_SHA256,
            "combined_lock_sha256": verify.COMBINED_LOCK_SHA256,
            "upstream_lock_sha256": verify.UPSTREAM_LOCK_SHA256,
            "build_mode": "build-locked",
            "probe_executed": False,
            "human_lock_review_required_before_live_execution": True,
            "locked_rebuild": True,
            "axis_patch_sha256": verify.sha256(
                (self.artifact / "source/patches/axis-offline-mxc-child.patch").read_bytes()
            ),
            "files": {name: verify.sha256((self.artifact / name).read_bytes()) for name in verify.FILES},
        }
        (self.artifact / "WORKFLOW.json").write_text(
            json.dumps(
                {
                    "repository": "cisco-ai-defense/defenseclaw",
                    "workflow_commit": self.commit,
                    "run_id": self.run_id,
                    "execution_performed": False,
                }
            ),
            encoding="utf-8",
        )
        self.write_provenance()

    def write_provenance(self) -> None:
        self.provenance_bytes = json.dumps(self.provenance).encode()
        (self.artifact / "PROVENANCE.json").write_bytes(self.provenance_bytes)

    def check(self) -> dict[str, object]:
        return verify.verify(
            self.artifact, self.checkout, verify.sha256(self.provenance_bytes), self.commit, self.run_id
        )

    def test_exact_locked_inventory_verified_without_execution(self) -> None:
        with mock.patch.object(verify.subprocess, "run") as command:
            result = self.check()
        command.assert_not_called()
        self.git.assert_called_once_with(self.checkout, self.commit)
        self.assertTrue(result["verified"])
        self.assertFalse(result["execution_performed"])
        self.assertEqual(result["verified_file_count"], 15)

    def test_independent_manifest_digest_required(self) -> None:
        with self.assertRaisesRegex(ValueError, "independently reviewed digest"):
            verify.verify(self.artifact, self.checkout, "0" * 64, self.commit, self.run_id)

    def test_shared_literal_patch_cannot_be_replaced_by_rehashed_manifest(self) -> None:
        changed = b"synthetic unreviewed literal patch\n"
        (self.artifact / "source/mxc-literal-argv.patch").write_bytes(changed)
        (self.checkout / "test/e2e/axis/patches/mxc-literal-argv.patch").write_bytes(changed)
        self.provenance["files"]["source/mxc-literal-argv.patch"] = verify.sha256(changed)
        self.write_provenance()
        with self.assertRaisesRegex(ValueError, "literal-argv patch content differs"):
            self.check()

    def test_generated_lock_build_cannot_be_admitted(self) -> None:
        self.provenance["build_mode"] = "generate-lock"
        self.provenance["locked_rebuild"] = False
        self.write_provenance()
        with self.assertRaisesRegex(ValueError, "locked build provenance"):
            self.check()

    def test_binary_tampering_refused(self) -> None:
        (self.artifact / verify.BINARY).write_bytes(b"different synthetic binary\n")
        with self.assertRaisesRegex(ValueError, "artifact content differs"):
            self.check()

    def test_unreviewed_additional_file_refused(self) -> None:
        (self.artifact / "extra-launcher").write_bytes(b"synthetic extra input\n")
        with self.assertRaisesRegex(ValueError, "unreviewed files"):
            self.check()

    def test_packaged_source_must_match_the_checked_out_commit(self) -> None:
        (self.checkout / "test/e2e/axis/mxc-runner/src/probe.rs").write_bytes(b"different synthetic source\n")
        with self.assertRaisesRegex(ValueError, "packaged source differs"):
            self.check()

    def test_boolean_execution_identity_cannot_be_replaced_by_zero(self) -> None:
        self.provenance["probe_executed"] = 0
        self.write_provenance()
        with self.assertRaisesRegex(ValueError, "probe_executed"):
            self.check()

    def test_no_path_outside_the_fixed_inventory_can_be_read(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside the fixed inventory"):
            verify.file_bytes(self.artifact, "../../outside")

    def test_build_run_attribution_must_match(self) -> None:
        with self.assertRaisesRegex(ValueError, "workflow attribution differs"):
            verify.verify(self.artifact, self.checkout, verify.sha256(self.provenance_bytes), self.commit, "54321")
