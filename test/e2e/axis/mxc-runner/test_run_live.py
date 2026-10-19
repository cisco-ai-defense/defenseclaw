# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Failure-receipt regression tests; no contributor binary is executed."""

import contextlib
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase, mock

_SPEC = importlib.util.spec_from_file_location("mxc_run_live", Path(__file__).with_name("run_live.py"))
assert _SPEC is not None and _SPEC.loader is not None
live = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(live)


class FailureReceiptTests(TestCase):
    def test_rust_success_check_inventory_matches_driver_without_duplicates(self):
        source = Path(__file__).with_name("src").joinpath("probe.rs").read_text(encoding="utf-8")
        inventories = re.findall(r'"checks":\s*(\[[^\]]*\])', source)
        self.assertEqual(len(inventories), 1, "require one fixed Rust success-check inventory")
        checks = json.loads(inventories[0])
        self.assertTrue(all(isinstance(check, str) for check in checks))
        self.assertEqual(len(checks), len(set(checks)), "Rust success-check inventory has duplicates")
        self.assertEqual(set(checks), live.CHECKS)

    def run_case(self, *, timeout=False, checks=None, abi=3, groups=None):
        with tempfile.TemporaryDirectory(prefix="dc-live-receipt-unit-") as temporary:
            root = Path(temporary)
            artifact = root / "artifact"
            binary = artifact / "bin/defenseclaw-axis-mxc-probe"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"inert synthetic artifact; never executed")
            receipt = root / "verified.json"
            receipt.write_text(
                json.dumps(
                    {
                        "verified": True,
                        "execution_performed": False,
                        "binary": "bin/defenseclaw-axis-mxc-probe",
                        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    }
                )
            )
            evidence = root / "evidence"
            evidence.mkdir()
            payload = {
                "containment": "mxc_sdk_v1_bubblewrap",
                "axis_child_guards": "landlock_and_offline_seccomp",
                "filesystem": "hard_requirement",
                "network": "block",
                "landlock_abi": abi,
                "pty_groups": [
                    {"phase": phase, "isatty": 1, "foreground_pgrp": 7, "process_pgrp": 7}
                    for phase in ("initial", "resized", "continued")
                ]
                if groups is None
                else groups,
                "checks": sorted(live.CHECKS) if checks is None else checks,
                "production_or_claude_qualification": False,
                "proxy_or_descendant_cleanup_qualification": False,
            }

            def fixed_result(command, **kwargs):
                if timeout:
                    raise subprocess.TimeoutExpired(command, 75)
                kwargs["stdout"].write(json.dumps(payload).encode())
                return subprocess.CompletedProcess(command, 0)

            with (
                mock.patch.object(live.platform, "system", return_value="Linux"),
                mock.patch.object(live.platform, "machine", return_value="x86_64"),
                mock.patch.object(live.os, "geteuid", return_value=1000, create=True),
                mock.patch.object(live, "owned_processes", return_value=[]) as inspect,
                mock.patch.object(live.subprocess, "run", side_effect=fixed_result),
                mock.patch(
                    "sys.argv",
                    [
                        "run_live.py",
                        "--artifact",
                        str(artifact),
                        "--receipt",
                        str(receipt),
                        "--evidence",
                        str(evidence),
                    ],
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                try:
                    live.main()
                except SystemExit as error:
                    self.assertEqual(error.code, 1)
                self.assertEqual(inspect.call_count, 2)
            return json.loads((evidence / "live-result.json").read_text())

    def test_outer_timeout_still_records_failure_and_inspects_owned_processes(self):
        result = self.run_case(timeout=True)
        self.assertFalse(result["passed"])
        self.assertIsNone(result["exit_code"])
        self.assertEqual(result["errors"], ["TimeoutExpired"])
        self.assertEqual(result["remaining_matching_processes"], [])

    def test_unhashable_check_value_is_a_recorded_failed_result(self):
        result = self.run_case(checks=[{"invalid": "synthetic"}])
        self.assertFalse(result["passed"])

    def test_insufficient_landlock_abi_cannot_pass_wrapper(self):
        self.assertFalse(self.run_case(abi=2)["passed"])

    def test_complete_synthetic_result_admitted_without_executing_artifact(self):
        self.assertTrue(self.run_case()["passed"])

    def test_invalid_foreground_evidence_is_a_recorded_failure(self):
        for group in (0, -1, True, "7"):
            with self.subTest(group=group):
                groups = [
                    {"phase": phase, "isatty": 1, "foreground_pgrp": group, "process_pgrp": group}
                    for phase in ("initial", "resized", "continued")
                ]
                self.assertFalse(self.run_case(groups=groups)["passed"])

    def test_incomplete_or_reversed_foreground_evidence_is_refused(self):
        initial = {"phase": "initial", "isatty": 1, "foreground_pgrp": 7, "process_pgrp": 7}
        resized = dict(initial, phase="resized")
        continued = dict(initial, phase="continued")
        for groups in (
            [],
            [initial],
            [initial, resized],
            [resized, initial, continued],
            [initial, resized, resized],
            [initial, resized, continued, continued],
            [True, True, True],
        ):
            with self.subTest(groups=groups):
                self.assertFalse(self.run_case(groups=groups)["passed"])

    def test_pre_sigint_check_inventory_is_refused(self):
        checks = sorted(live.CHECKS - {"pty_sigint_ack_and_continued_input"})
        self.assertFalse(self.run_case(checks=checks)["passed"])
