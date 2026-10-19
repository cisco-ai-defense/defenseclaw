# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Synthetic admission tests; no executable, socket or network operation runs."""

import copy
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import run_headless
import verify_artifact


class ContributorAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory(prefix="defenseclaw-headless-admission-")
        self.addCleanup(self.private.cleanup)
        self.root = pathlib.Path(self.private.name).resolve()
        self.payload = self.root / "artifact"
        (self.payload / "bin").mkdir(parents=True)
        self.entries = []
        for name in sorted(verify_artifact.BINARIES):
            path = self.payload / "bin" / name
            path.write_bytes(("synthetic " + name).encode())
            self.entries.append(
                {"path": "bin/" + name, "sha256": run_headless.sha(path), "size_bytes": path.stat().st_size}
            )
        self.receipt = {
            "verified": True,
            "variant": "baseline",
            "axis_commit": verify_artifact.AXIS,
            "mxc_commit": verify_artifact.MXC,
            "workflow_commit": "a" * 40,
            "archive_sha256": "b" * 64,
            "contributor_overlay": None,
            "contributor_relay_overlays": None,
            "payload": str(self.payload),
            "binaries": self.entries,
        }
        self.verification_path = self.root / "verification.json"
        self.case_root = self.root / "uncreated-case"

    def save(self, value):
        self.verification_path.write_text(json.dumps(value), encoding="utf-8")

    def install_overlay(self, name, kind):
        source = run_headless.OVERLAY_ROOT / run_headless.REVIEWED_OVERLAYS[name]
        (self.payload / name).write_bytes(source.read_bytes())
        return {"path": name, "kind": kind, "sha256": run_headless.sha(source)}

    def assert_refused_before_effect(self, value):
        self.save(value)
        with (
            mock.patch.object(run_headless.subprocess, "Popen", side_effect=AssertionError("unexpected process")),
            mock.patch.object(run_headless.socket, "socket", side_effect=AssertionError("unexpected socket")),
            mock.patch.object(
                verify_artifact.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")
            ),
        ):
            with self.assertRaises(ValueError):
                run_headless.run(self.verification_path, self.root / "never-executed.exe", self.case_root, "boundary")
        self.assertFalse(self.case_root.exists(), "admission failure created a case directory")

    def test_exact_synthetic_baseline_inventory_is_admitted_without_execution(self):
        self.save(self.receipt)
        value, payload = run_headless.checked_bundle(self.verification_path)
        self.assertEqual(value["axis_commit"], verify_artifact.AXIS)
        self.assertEqual(payload, self.payload)
        legacy = copy.deepcopy(self.receipt)
        del legacy["variant"]
        self.save(legacy)
        self.assertEqual(run_headless.checked_bundle(self.verification_path)[1], self.payload)
        self.assertFalse(self.case_root.exists())

    def test_both_reviewed_console_variants_are_admitted_without_execution(self):
        overlay = self.install_overlay("AXIS_INHERITED_CONSOLE.patch", "windows_inherited_console_experiment")
        changed = copy.deepcopy(self.receipt)
        changed["variant"] = "inherited-console"
        changed["contributor_overlay"] = overlay
        self.save(changed)
        self.assertEqual(run_headless.checked_bundle(self.verification_path)[0]["variant"], "inherited-console")

        changed["variant"] = "inherited-console-relay"
        changed["contributor_relay_overlays"] = {
            "axis": self.install_overlay("AXIS_CONSOLE_CTRL_C_RELAY.patch", "windows_console_ctrl_c_relay_experiment"),
            "mxc": self.install_overlay("MXC_CONSOLE_CTRL_C_RELAY.patch", "windows_console_ctrl_c_relay_experiment"),
        }
        self.save(changed)
        self.assertEqual(run_headless.checked_bundle(self.verification_path)[0]["variant"], "inherited-console-relay")
        self.assertFalse(self.case_root.exists())

    def test_wrong_variant_commits_and_source_overlay_refuse_before_effect(self):
        for key, value in [
            ("verified", False),
            ("variant", "unreviewed-variant"),
            ("axis_commit", "0" * 40),
            ("mxc_commit", "0" * 40),
            ("workflow_commit", "unreviewed"),
            ("archive_sha256", "unreviewed"),
            ("contributor_overlay", {"path": "overlay.patch"}),
            ("payload", "relative-artifact"),
        ]:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.receipt)
                changed[key] = value
                self.assert_refused_before_effect(changed)

    def test_missing_or_changed_overlay_refuses_before_effect(self):
        inherited = copy.deepcopy(self.receipt)
        inherited["variant"] = "inherited-console"
        self.assert_refused_before_effect(inherited)

        inherited["contributor_overlay"] = self.install_overlay(
            "AXIS_INHERITED_CONSOLE.patch", "windows_inherited_console_experiment"
        )
        inherited["contributor_overlay"]["sha256"] = "0" * 64
        self.assert_refused_before_effect(inherited)

        inherited["contributor_overlay"]["sha256"] = run_headless.sha(
            run_headless.OVERLAY_ROOT / run_headless.REVIEWED_OVERLAYS["AXIS_INHERITED_CONSOLE.patch"]
        )
        inherited["variant"] = "inherited-console-relay"
        self.assert_refused_before_effect(inherited)

    def test_missing_duplicate_or_unlisted_binaries_refuse_before_effect(self):
        for mutation in ("missing", "duplicate", "unlisted", "unsafe-path"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(self.receipt)
                if mutation == "missing":
                    changed["binaries"].pop()
                elif mutation == "duplicate":
                    changed["binaries"].append(copy.deepcopy(changed["binaries"][0]))
                elif mutation == "unsafe-path":
                    changed["binaries"][0]["path"] = "../outside.exe"
                else:
                    extra = self.payload / "bin" / "unlisted.exe"
                    extra.write_bytes(b"synthetic unlisted file")
                    self.addCleanup(extra.unlink, missing_ok=True)
                self.assert_refused_before_effect(changed)
                if mutation == "unlisted":
                    extra.unlink()

    def test_changed_binary_refuses_before_case_creation(self):
        changed = self.payload / self.entries[0]["path"]
        changed.write_bytes(b"synthetic changed content")
        self.assert_refused_before_effect(self.receipt)


if __name__ == "__main__":
    unittest.main()
