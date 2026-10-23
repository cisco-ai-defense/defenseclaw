#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The package lane must distinguish a pending reboot from a failed apply."""

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


class RebootResultTest(unittest.TestCase):
    def check_result(self, document, *flags):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(CHECKER), str(path), "--platform", "linux", *flags],
                capture_output=True,
                check=False,
            )

    def test_pending_reboot_requires_only_namespace_errors(self):
        flags = ("--reboot-pending", "--ready")
        pending_without_coverage = result(["unprivileged_user_namespaces"], False)
        pending_without_coverage["coverage_complete"] = False
        self.assertEqual(self.check_result(result(["unprivileged_user_namespaces"], False), *flags).returncode, 0)
        rolled_back = result(["unprivileged_user_namespaces"], False)
        rolled_back["warnings"] = [{"code": "rolled_back", "message": "restored the previous deployment"}]
        rollback_failed = result(["unprivileged_user_namespaces"], False)
        rollback_failed["warnings"] = [{"code": "rollback_failed", "message": ""}]
        for document in (rolled_back, rollback_failed):
            # Rejected even when the step allows the warning.
            allowed = ("--allow-warning", "rolled_back", "--allow-warning", "rollback_failed")
            self.assertEqual(self.check_result(document, *flags, *allowed).returncode, 1)
        for document in (
            result(["unprivileged_user_namespaces", "lifecycle_test_fault"], False),
            result(["unprivileged_user_namespaces"], True),
            result([], True),
            pending_without_coverage,
        ):
            self.assertEqual(self.check_result(document, *flags).returncode, 1)

    def test_reboot_transition_is_complete(self):
        self.assertEqual(self.check_result(result([], True), "--complete").returncode, 0)
        self.assertEqual(self.check_result(result(["unprivileged_user_namespaces"], False), "--complete").returncode, 1)

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


if __name__ == "__main__":
    unittest.main()
