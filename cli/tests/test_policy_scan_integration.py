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

"""Integration tests: create policy → activate → verify scan output drives correct action.

Tests that the policy YAML → config → severity action chain works end-to-end
without needing an actual scanner binary.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from datetime import datetime, timedelta, timezone

from click.testing import CliRunner
from defenseclaw.commands.cmd_policy import policy
from defenseclaw.models import Finding, ScanResult

from tests.helpers import cleanup_app, make_app_context


class PolicyScanIntegrationBase(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        os.makedirs(self.app.cfg.policy_dir, exist_ok=True)
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args: list[str]):
        return self.runner.invoke(policy, args, obj=self.app, catch_exceptions=False)

    def _make_scan_result(self, severity: str, num_findings: int = 1) -> ScanResult:
        findings = [
            Finding(
                id=f"plugin-{i+1}",
                severity=severity,
                title=f"Finding {i+1}",
                description=f"Test finding with {severity} severity",
                scanner="plugin-scanner",
            )
            for i in range(num_findings)
        ]
        return ScanResult(
            scanner="plugin-scanner",
            target="/tmp/test-plugin",
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            duration=timedelta(seconds=0.5),
        )


class TestDefaultPolicyScanActions(PolicyScanIntegrationBase):
    """Verify default policy: CRITICAL/HIGH → block+quarantine, MEDIUM/LOW → allow."""

    def test_critical_scan_triggers_quarantine(self):
        self.invoke(["activate", "default"])

        result = self._make_scan_result("CRITICAL")
        self.assertEqual(result.max_severity(), "CRITICAL")

        action = self.app.cfg.skill_actions.for_severity("CRITICAL")
        self.assertEqual(action.file, "quarantine")
        self.assertEqual(action.runtime, "disable")
        self.assertEqual(action.install, "block")

    def test_high_scan_triggers_quarantine(self):
        self.invoke(["activate", "default"])

        result = self._make_scan_result("HIGH")
        action = self.app.cfg.skill_actions.for_severity(result.max_severity())
        self.assertEqual(action.file, "quarantine")
        self.assertEqual(action.install, "block")

    def test_medium_scan_allows(self):
        self.invoke(["activate", "default"])

        result = self._make_scan_result("MEDIUM")
        action = self.app.cfg.skill_actions.for_severity(result.max_severity())
        self.assertEqual(action.file, "none")
        self.assertEqual(action.runtime, "enable")
        self.assertEqual(action.install, "none")

    def test_clean_scan(self):
        self.invoke(["activate", "default"])

        result = self._make_scan_result("INFO", 0)
        self.assertTrue(result.is_clean())


class TestStrictPolicyScanActions(PolicyScanIntegrationBase):
    """Verify strict policy: MEDIUM+ → block+quarantine."""

    def test_medium_scan_triggers_block(self):
        self.invoke(["activate", "strict"])

        result = self._make_scan_result("MEDIUM")
        action = self.app.cfg.skill_actions.for_severity(result.max_severity())
        self.assertEqual(action.file, "quarantine")
        self.assertEqual(action.runtime, "disable")
        self.assertEqual(action.install, "block")

    def test_low_scan_allows(self):
        self.invoke(["activate", "strict"])

        result = self._make_scan_result("LOW")
        action = self.app.cfg.skill_actions.for_severity(result.max_severity())
        self.assertEqual(action.file, "none")
        self.assertEqual(action.install, "none")


class TestPermissivePolicyScanActions(PolicyScanIntegrationBase):
    """Verify permissive policy: only CRITICAL → block+quarantine."""

    def test_high_scan_allows(self):
        self.invoke(["activate", "permissive"])

        result = self._make_scan_result("HIGH")
        action = self.app.cfg.skill_actions.for_severity(result.max_severity())
        self.assertEqual(action.file, "none")
        self.assertEqual(action.install, "none")

    def test_critical_still_blocked(self):
        self.invoke(["activate", "permissive"])

        result = self._make_scan_result("CRITICAL")
        action = self.app.cfg.skill_actions.for_severity(result.max_severity())
        self.assertEqual(action.file, "quarantine")
        self.assertEqual(action.install, "block")


class TestCustomPolicyScanActions(PolicyScanIntegrationBase):
    """Create custom policy → activate → verify scan actions."""

    def test_custom_block_medium(self):
        self.invoke([
            "create", "block-medium",
            "--critical-action", "block",
            "--high-action", "block",
            "--medium-action", "block",
        ])
        self.invoke(["activate", "block-medium"])

        result = self._make_scan_result("MEDIUM")
        action = self.app.cfg.skill_actions.for_severity(result.max_severity())
        self.assertEqual(action.file, "quarantine")
        self.assertEqual(action.install, "block")

    def test_custom_warn_all(self):
        self.invoke([
            "create", "warn-all",
            "--critical-action", "block",
            "--high-action", "warn",
            "--medium-action", "warn",
            "--low-action", "warn",
        ])
        self.invoke(["activate", "warn-all"])

        # HIGH should be warn (allow)
        result = self._make_scan_result("HIGH")
        action = self.app.cfg.skill_actions.for_severity(result.max_severity())
        self.assertEqual(action.file, "none")
        self.assertEqual(action.install, "none")

        # CRITICAL should still block
        result = self._make_scan_result("CRITICAL")
        action = self.app.cfg.skill_actions.for_severity(result.max_severity())
        self.assertEqual(action.file, "quarantine")
        self.assertEqual(action.install, "block")


class TestSameScanDifferentPolicies(PolicyScanIntegrationBase):
    """Same scan result → different verdicts when different policies are active."""

    def test_medium_findings_differ_by_policy(self):
        scan = self._make_scan_result("MEDIUM", 3)
        sev = scan.max_severity()

        # Default: MEDIUM → allow
        self.invoke(["activate", "default"])
        action = self.app.cfg.skill_actions.for_severity(sev)
        self.assertFalse(self.app.cfg.skill_actions.should_quarantine(sev))
        self.assertFalse(self.app.cfg.skill_actions.should_install_block(sev))

        # Strict: MEDIUM → block+quarantine
        self.invoke(["activate", "strict"])
        self.assertTrue(self.app.cfg.skill_actions.should_quarantine(sev))
        self.assertTrue(self.app.cfg.skill_actions.should_install_block(sev))

        # Permissive: MEDIUM → allow
        self.invoke(["activate", "permissive"])
        self.assertFalse(self.app.cfg.skill_actions.should_quarantine(sev))
        self.assertFalse(self.app.cfg.skill_actions.should_install_block(sev))


class TestPluginScannerOutputToActions(PolicyScanIntegrationBase):
    """Simulate plugin scanner JSON output → parse findings → check policy action."""

    def test_plugin_scanner_output_drives_quarantine(self):

        # Simulate what the TS plugin scanner outputs
        scanner_output = {
            "scanner": "defenseclaw-plugin-scanner",
            "target": "/tmp/test-plugin",
            "timestamp": "2026-03-24T12:00:00.000Z",
            "findings": [
                {
                    "id": "plugin-1",
                    "rule_id": "SRC-EVAL",
                    "severity": "CRITICAL",
                    "confidence": 0.95,
                    "title": "Dynamic code execution via eval()",
                    "description": "eval() can execute arbitrary code",
                    "evidence": "eval(userInput)",
                    "location": "src/index.ts:42",
                    "remediation": "Remove eval() usage",
                    "scanner": "defenseclaw-plugin-scanner",
                    "tags": ["code-execution"],
                    "occurrence_count": 1,
                    "suppressed": False,
                },
                {
                    "id": "plugin-2",
                    "rule_id": "PERM-DANGEROUS",
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "title": "Dangerous permission: fs:*",
                    "description": "Broad filesystem access",
                    "location": "package.json",
                    "scanner": "defenseclaw-plugin-scanner",
                    "tags": ["permissions"],
                    "suppressed": False,
                },
                {
                    "id": "plugin-3",
                    "severity": "MEDIUM",
                    "title": "Suppressed finding",
                    "description": "This is suppressed",
                    "scanner": "defenseclaw-plugin-scanner",
                    "suppressed": True,
                    "suppression_reason": "false positive",
                },
            ],
            "duration_ns": 150000000,
            "assessment": {"verdict": "malicious", "confidence": 0.95},
        }

        # Parse as the Python PluginScannerWrapper does
        data = scanner_output
        findings = []
        for f in data.get("findings", []):
            if f.get("suppressed", False):
                continue
            findings.append(Finding(
                id=f.get("id", ""),
                severity=f.get("severity", "INFO"),
                title=f.get("title", ""),
                description=f.get("description", ""),
                location=f.get("location", ""),
                remediation=f.get("remediation", ""),
                scanner="plugin-scanner",
                tags=f.get("tags", []),
            ))

        result = ScanResult(
            scanner="plugin-scanner",
            target="/tmp/test-plugin",
            timestamp=datetime.now(timezone.utc),
            findings=findings,
        )

        # Should have 2 findings (1 suppressed)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.max_severity(), "CRITICAL")
        self.assertFalse(result.is_clean())

        # Activate default policy and check action
        self.invoke(["activate", "default"])
        action = self.app.cfg.skill_actions.for_severity(result.max_severity())
        self.assertEqual(action.file, "quarantine")
        self.assertEqual(action.runtime, "disable")
        self.assertEqual(action.install, "block")

        # Switch to permissive: HIGH would be allowed, but CRITICAL still blocked
        self.invoke(["activate", "permissive"])
        action = self.app.cfg.skill_actions.for_severity(result.max_severity())
        self.assertEqual(action.file, "quarantine")
        self.assertEqual(action.install, "block")


if __name__ == "__main__":
    unittest.main()
