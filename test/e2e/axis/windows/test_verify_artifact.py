# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Offline supply-chain refusal cases; no AXIS executable is required."""

import hashlib
import json
import pathlib
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import verify_artifact as verifier


class VerificationRefusals(unittest.TestCase):
    def bundle(self, directory, variant, manifest, unsafe_member=None):
        platform = "windows" if variant == "baseline" else "windows-" + variant
        stem = f"axis-source-{platform}-x86_64-{verifier.AXIS}"
        archive = directory / (stem + ".zip")
        metadata = json.dumps(manifest).encode()
        inventory = hashlib.sha256(metadata).hexdigest() + "  BUILD.json\n"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(stem + "/BUILD.json", metadata)
            bundle.writestr(stem + "/SHA256SUMS", inventory)
            if unsafe_member:
                bundle.writestr(unsafe_member, "untrusted archive content")
        digest = verifier.sha(archive)
        (directory / (archive.name + ".sha256")).write_text(digest + "  " + archive.name)

    def manifest(self):
        return {
            "purpose": "contributor_source_build_only",
            "support_certification": False,
            "axis_source": {"commit": verifier.AXIS},
            "mxc_source": {"commit": verifier.MXC},
            "build": {"workflow_commit": "reviewed-workflow", "toolchain": "1.95.0"},
        }

    def test_archive_cannot_write_outside_fresh_extraction_root(self):
        with tempfile.TemporaryDirectory(prefix="defenseclaw-axis-verifier-") as temporary:
            root = pathlib.Path(temporary).resolve()
            self.bundle(root, "baseline", self.manifest(), "../outside.txt")
            with self.assertRaisesRegex(ValueError, "unsafe bundle path"):
                verifier.verify(root, root / "output", root / "axis", "reviewed-workflow")
            self.assertFalse((root / "outside.txt").exists())
            self.assertFalse((root / "output").exists())

    def test_overlaid_artifact_cannot_be_labeled_stock_baseline(self):
        with tempfile.TemporaryDirectory(prefix="defenseclaw-axis-verifier-") as temporary:
            root = pathlib.Path(temporary).resolve()
            manifest = self.manifest()
            manifest["axis_source"]["contributor_overlay"] = {"path": "unreviewed.patch"}
            self.bundle(root, "baseline", manifest)
            with patch.object(verifier.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")):
                with self.assertRaisesRegex(ValueError, "cannot be accepted as baseline"):
                    verifier.verify(root, root / "output", root / "axis", "reviewed-workflow")

    def test_relay_variant_requires_local_patch_review(self):
        with tempfile.TemporaryDirectory(prefix="defenseclaw-axis-verifier-") as temporary:
            root = pathlib.Path(temporary).resolve()
            manifest = self.manifest()
            manifest["variant"] = "inherited-console-relay"
            self.bundle(root, "inherited-console-relay", manifest)
            with patch.object(verifier.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")):
                with self.assertRaisesRegex(ValueError, "locally reviewed overlay is required"):
                    verifier.verify(
                        root, root / "output", root / "axis", "reviewed-workflow", "inherited-console-relay"
                    )


if __name__ == "__main__":
    unittest.main()
