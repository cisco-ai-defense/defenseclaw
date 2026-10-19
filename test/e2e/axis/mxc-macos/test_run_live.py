# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Synthetic live-runner guard tests; never start a contributor binary."""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath
from unittest import TestCase, mock

import run_live


class LiveRunnerGuardTests(TestCase):
    def test_rust_success_check_inventory_matches_driver_without_duplicates(self):
        source = Path(__file__).with_name("src").joinpath("probe.rs").read_text(encoding="utf-8")
        inventories = re.findall(r'"checks":\s*(\[[^\]]*\])', source)
        self.assertEqual(len(inventories), 1, "require one fixed Rust success-check inventory")
        checks = json.loads(inventories[0])
        self.assertTrue(all(isinstance(check, str) for check in checks))
        self.assertEqual(len(checks), len(set(checks)), "Rust success-check inventory has duplicates")
        self.assertEqual(set(checks), run_live.CHECKS)

    def test_matching_process_inspection_is_own_uid_and_exact_path(self) -> None:
        binary = PurePosixPath("/private/tmp/verified-probe")
        result = mock.Mock(
            stdout="\n".join(
                [
                    "101 501 /private/tmp/verified-probe --strict-fixed",
                    "102 501 /private/tmp/verified-probe-extra --strict-fixed",
                    "103 502 /private/tmp/verified-probe --strict-fixed",
                    "104 501 /bin/sh -c '/private/tmp/verified-probe'",
                    "999 501 /private/tmp/verified-probe --strict-fixed",
                ]
            )
        )
        with (
            mock.patch.object(run_live.subprocess, "run", return_value=result) as command,
            mock.patch.object(run_live.os, "geteuid", return_value=501, create=True),
            mock.patch.object(run_live.os, "getpid", return_value=999),
        ):
            matches = run_live.owned_processes(binary)
        self.assertEqual([item["pid"] for item in matches], [101, 104])
        command.assert_called_once()
        self.assertEqual(command.call_args.args[0], ["/bin/ps", "-ww", "-U", "501", "-o", "pid=,uid=,command="])

    def test_preflight_rejection_writes_failure_receipt_without_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dc-mxc-macos-runner-unit-") as temporary:
            root = Path(temporary)
            artifact = root / "artifact"
            evidence = root / "evidence"
            receipt = root / "receipt.json"
            artifact.mkdir()
            evidence.mkdir()
            receipt.write_text("{}", encoding="utf-8")
            argv = [
                "run_live.py",
                "--artifact",
                str(artifact),
                "--receipt",
                str(receipt),
                "--evidence",
                str(evidence),
                "--gtimeout",
                "/usr/local/bin/gtimeout",
                "--provenance-sha256",
                "0" * 64,
                "--build-commit",
                "a" * 40,
                "--build-run",
                "12345",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(run_live.platform, "system", return_value="Darwin"),
                mock.patch.object(run_live.platform, "machine", return_value="arm64"),
                mock.patch.object(run_live.os, "geteuid", return_value=501, create=True),
                mock.patch.object(run_live.subprocess, "run") as command,
                self.assertRaises(SystemExit) as failure,
            ):
                run_live.main()
            self.assertEqual(failure.exception.code, 1)
            command.assert_not_called()
            record = json.loads((evidence / "live-result.json").read_text(encoding="utf-8"))
            self.assertFalse(record["passed"])
            self.assertFalse(record["attempted"])
            self.assertIsNone(record["exit_code"])
            self.assertEqual(record["errors"], ["ValueError"])
