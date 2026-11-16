#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The package lane checks policy-view facts without a reboot exception."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).with_name("check_enterprise_lifecycle_result.py")


def result(errors, security_complete):
    return {
        "schema_version": 2,
        "ok": not errors,
        "action": "verify",
        "noop": False,
        "profile": "standalone",
        "platform": "linux",
        "product_version": "1.0.4",
        "installed_version": "1.0.4",
        "installed": True,
        "transaction_pending": False,
        "services": [],
        "readiness": {"gateway": True, "guardian": True, "enumerator": True, "sensor_helper": True},
        "inspection": {},
        "machine_policy": {},
        "enrollment": {},
        "coverage_complete": True,
        "security_complete": security_complete,
        "errors": [{"code": code, "message": code} for code in errors],
        "exit_code": 1 if errors else 0,
    }


class LifecycleResultTest(unittest.TestCase):
    def check_result(self, document, *flags):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.run(  # noqa: UP022 - capture_output is unavailable on Python 3.6
                [sys.executable, str(CHECKER), str(path), "--platform", "linux", *flags],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def test_retired_reboot_mode_is_rejected(self):
        completed = self.check_result(result([], True), "--reboot-pending")
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"unrecognized arguments: --reboot-pending", completed.stderr)

    def test_default_policy_view_status_matches_open_route_warnings(self):
        open_view = result([], False)
        open_view["warnings"] = [{"code": "unprivileged_user_namespaces", "message": "private view possible"}]
        flags = ("--policy-view-status", "--allow-warning", "unprivileged_user_namespaces")
        self.assertEqual(self.check_result(open_view, *flags).returncode, 0)
        open_view["warnings"] = []
        self.assertEqual(self.check_result(open_view, *flags).returncode, 1)
        open_view["security_complete"] = True
        self.assertEqual(self.check_result(open_view, *flags).returncode, 0)
        open_view["warnings"] = [{"code": "unprivileged_user_namespaces", "message": "private view possible"}]
        self.assertEqual(self.check_result(open_view, *flags).returncode, 1)

    def test_required_warning_must_be_reported_and_is_accepted(self):
        # The lanes predict the kernel's policy-view warnings from the host
        # settings they read: a predicted warning that is missing fails, a
        # reported one passes, and any other warning still fails.
        document = result([], False)
        document["warnings"] = [{"code": "unprivileged_ptrace", "message": "ptrace scope 1"}]
        flags = ("--security-incomplete", "--require-warning", "unprivileged_ptrace")
        self.assertEqual(self.check_result(document, *flags).returncode, 0)
        document["warnings"] = []
        missing = self.check_result(document, *flags)
        self.assertEqual(missing.returncode, 1)
        self.assertIn(b"warning unprivileged_ptrace was not reported", missing.stdout + missing.stderr)
        document["warnings"] = [
            {"code": "unprivileged_ptrace", "message": "ptrace scope 1"},
            {"code": "unprivileged_user_namespaces", "message": "private view possible"},
        ]
        extra = self.check_result(document, *flags)
        self.assertEqual(extra.returncode, 1)
        self.assertIn(b"unexpected warning unprivileged_user_namespaces", extra.stdout + extra.stderr)


if __name__ == "__main__":
    unittest.main()
