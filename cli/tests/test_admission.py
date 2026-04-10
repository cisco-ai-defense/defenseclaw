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

"""Tests for the centralized admission evaluation helpers."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import SeverityAction
from defenseclaw.enforce.admission import (
    AdmissionPolicyData,
    effective_action_for,
    evaluate_admission,
    load_admission_policy,
)
from defenseclaw.enforce.policy import PolicyEngine

from tests.helpers import make_temp_store


class _StoreTestBase(unittest.TestCase):
    def setUp(self):
        self.store, self.db_path = make_temp_store()
        self.pe = PolicyEngine(self.store)
        self.policy_dir = tempfile.mkdtemp(prefix="dclaw-policy-")
        rego_dir = os.path.join(self.policy_dir, "rego")
        os.makedirs(rego_dir, exist_ok=True)
        self._write_data_json(rego_dir, {
            "config": {
                "allow_list_bypass_scan": True,
                "scan_on_install": True,
            },
            "actions": {
                "CRITICAL": {"runtime": "block", "file": "quarantine", "install": "block"},
                "HIGH": {"runtime": "block", "file": "quarantine", "install": "block"},
                "MEDIUM": {"runtime": "allow", "file": "none", "install": "none"},
                "LOW": {"runtime": "allow", "file": "none", "install": "none"},
                "INFO": {"runtime": "allow", "file": "none", "install": "none"},
            },
            "first_party_allow_list": [
                {"target_type": "plugin", "target_name": "defenseclaw", "reason": "first-party"},
            ],
        })

    def _write_data_json(self, rego_dir, data):
        with open(os.path.join(rego_dir, "data.json"), "w") as f:
            json.dump(data, f)

    def tearDown(self):
        self.store.close()
        os.unlink(self.db_path)
        shutil.rmtree(self.policy_dir, ignore_errors=True)


class TestEvaluateAdmissionBlocked(_StoreTestBase):
    def test_blocked_item_returns_blocked(self):
        self.pe.block("skill", "evil", "malware")
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="skill", name="evil")
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "manual-block")

    def test_blocked_after_allow_then_block(self):
        """Block after allow should leave the item blocked (last-write wins)."""
        self.pe.allow("skill", "dual", "good")
        self.pe.block("skill", "dual", "bad")
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="skill", name="dual")
        self.assertEqual(d.verdict, "blocked")


class TestEvaluateAdmissionAllowed(_StoreTestBase):
    def test_explicit_allow_skips_scan(self):
        self.pe.allow("skill", "trusted", "vendor")
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="skill", name="trusted")
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "manual-allow")

    def test_first_party_allow_bypasses_scan(self):
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="plugin", name="defenseclaw")
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "policy-allow")


class TestEvaluateAdmissionFirstPartyProvenance(_StoreTestBase):
    def setUp(self):
        super().setUp()
        rego_dir = os.path.join(self.policy_dir, "rego")
        self._write_data_json(rego_dir, {
            "config": {
                "allow_list_bypass_scan": True,
                "scan_on_install": True,
            },
            "actions": {},
            "first_party_allow_list": [
                {
                    "target_type": "plugin",
                    "target_name": "defenseclaw",
                    "reason": "first-party",
                    "source_path_contains": [".defenseclaw", ".openclaw/extensions"],
                },
            ],
        })

    def test_matching_path_allows(self):
        d = evaluate_admission(
            self.pe, policy_dir=self.policy_dir,
            target_type="plugin", name="defenseclaw",
            source_path="/home/user/.openclaw/extensions/defenseclaw",
        )
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "policy-allow")

    def test_non_matching_path_falls_through(self):
        d = evaluate_admission(
            self.pe, policy_dir=self.policy_dir,
            target_type="plugin", name="defenseclaw",
            source_path="/home/user/random/plugins/something",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_temp_dir_falls_through(self):
        d = evaluate_admission(
            self.pe, policy_dir=self.policy_dir,
            target_type="plugin", name="defenseclaw",
            source_path="/tmp/dclaw-plugin-fetch-abc123/defenseclaw",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_empty_path_falls_through(self):
        d = evaluate_admission(
            self.pe, policy_dir=self.policy_dir,
            target_type="plugin", name="defenseclaw",
            source_path="",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_workspace_codeguard_path_allows(self):
        rego_dir = os.path.join(self.policy_dir, "rego")
        self._write_data_json(rego_dir, {
            "config": {
                "allow_list_bypass_scan": True,
                "scan_on_install": True,
            },
            "actions": {},
            "first_party_allow_list": [
                {
                    "target_type": "skill",
                    "target_name": "codeguard",
                    "reason": "first-party",
                    "source_path_contains": [".openclaw/workspace/skills", ".openclaw/skills"],
                },
            ],
        })
        d = evaluate_admission(
            self.pe, policy_dir=self.policy_dir,
            target_type="skill", name="codeguard",
            source_path="/home/user/.openclaw/workspace/skills/codeguard",
        )
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "policy-allow")


class TestEvaluateAdmissionFirstPartyNoBypass(_StoreTestBase):
    def setUp(self):
        super().setUp()
        rego_dir = os.path.join(self.policy_dir, "rego")
        self._write_data_json(rego_dir, {
            "config": {
                "allow_list_bypass_scan": False,
                "scan_on_install": True,
            },
            "actions": {},
            "first_party_allow_list": [
                {"target_type": "plugin", "target_name": "defenseclaw", "reason": "first-party"},
            ],
        })

    def test_first_party_requires_scan_when_bypass_disabled(self):
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="plugin", name="defenseclaw")
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")


class TestEvaluateAdmissionScanDisabled(_StoreTestBase):
    def setUp(self):
        super().setUp()
        rego_dir = os.path.join(self.policy_dir, "rego")
        self._write_data_json(rego_dir, {
            "config": {
                "allow_list_bypass_scan": True,
                "scan_on_install": False,
            },
            "actions": {},
        })

    def test_scan_disabled_allows_without_scan(self):
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="skill", name="new-skill")
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "scan-disabled")


class TestEvaluateAdmissionRequiresScan(_StoreTestBase):
    def test_no_scan_result_returns_scan_required(self):
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="skill", name="new-skill")
        self.assertEqual(d.verdict, "scan")


class TestEvaluateAdmissionWithScanResult(_StoreTestBase):
    def _make_scan_result(self, findings, max_severity):
        class FakeScanResult:
            def __init__(self, findings, sev):
                self.findings = findings
                self._sev = sev
            def max_severity(self):
                return self._sev
        return FakeScanResult(findings, max_severity)

    def test_clean_scan(self):
        result = self._make_scan_result([], "INFO")
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="skill", name="safe",
                               scan_result=result)
        self.assertEqual(d.verdict, "clean")
        self.assertEqual(d.source, "scan-clean")

    def test_high_severity_rejected(self):
        result = self._make_scan_result([{"severity": "HIGH"}], "HIGH")
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="skill", name="risky",
                               scan_result=result)
        self.assertEqual(d.verdict, "rejected")
        self.assertEqual(d.source, "scan-rejected")
        self.assertEqual(d.action.install, "block")
        self.assertEqual(d.action.runtime, "disable")

    def test_medium_severity_warning(self):
        result = self._make_scan_result([{"severity": "MEDIUM"}], "MEDIUM")
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="skill", name="iffy",
                               scan_result=result)
        self.assertEqual(d.verdict, "warning")
        self.assertEqual(d.source, "scan-warning")

    def test_install_block_alone_rejects(self):
        rego_dir = os.path.join(self.policy_dir, "rego")
        self._write_data_json(rego_dir, {
            "config": {"allow_list_bypass_scan": True, "scan_on_install": True},
            "actions": {
                "HIGH": {"runtime": "allow", "file": "none", "install": "block"},
            },
        })
        result = self._make_scan_result([{"severity": "HIGH"}], "HIGH")
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="skill", name="partial",
                               scan_result=result)
        self.assertEqual(d.verdict, "rejected")


class TestEvaluateAdmissionDictScanResult(_StoreTestBase):
    def test_dict_scan_result_clean(self):
        d = evaluate_admission(
            self.pe, policy_dir=self.policy_dir,
            target_type="skill", name="safe",
            scan_result={"total_findings": 0, "max_severity": "INFO"},
        )
        self.assertEqual(d.verdict, "clean")

    def test_dict_scan_result_with_findings(self):
        d = evaluate_admission(
            self.pe, policy_dir=self.policy_dir,
            target_type="skill", name="risky",
            scan_result={"total_findings": 2, "max_severity": "HIGH"},
        )
        self.assertEqual(d.verdict, "rejected")


class TestEvaluateAdmissionQuarantine(_StoreTestBase):
    def test_quarantined_item_rejected_when_flag_set(self):
        self.pe.quarantine("skill", "qskill", "scan findings")
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="skill", name="qskill",
                               include_quarantine=True)
        self.assertEqual(d.verdict, "rejected")
        self.assertEqual(d.source, "quarantine")

    def test_quarantined_item_not_checked_without_flag(self):
        self.pe.quarantine("skill", "qskill", "scan findings")
        d = evaluate_admission(self.pe, policy_dir=self.policy_dir,
                               target_type="skill", name="qskill")
        self.assertEqual(d.verdict, "scan")


class TestEffectiveActionFor(unittest.TestCase):
    def test_global_action(self):
        policy = AdmissionPolicyData(
            actions={"HIGH": SeverityAction(file="quarantine", runtime="disable", install="block")},
        )
        action = effective_action_for(policy, target_type="skill", severity="HIGH")
        self.assertEqual(action.install, "block")

    def test_scanner_override_takes_precedence(self):
        policy = AdmissionPolicyData(
            actions={"MEDIUM": SeverityAction(runtime="enable", install="none")},
            scanner_overrides={
                "mcp": {"MEDIUM": SeverityAction(runtime="disable", install="block")},
            },
        )
        action = effective_action_for(policy, target_type="mcp", severity="MEDIUM")
        self.assertEqual(action.install, "block")

        skill_action = effective_action_for(policy, target_type="skill", severity="MEDIUM")
        self.assertEqual(skill_action.install, "none")

    def test_unknown_severity_returns_default(self):
        policy = AdmissionPolicyData()
        action = effective_action_for(policy, target_type="skill", severity="UNKNOWN")
        self.assertEqual(action.install, "none")

    def test_fallback_actions_used(self):
        from defenseclaw.config import SkillActionsConfig
        policy = AdmissionPolicyData()
        fallback = SkillActionsConfig(
            high=SeverityAction(install="block", runtime="disable", file="quarantine"),
        )
        action = effective_action_for(policy, target_type="skill", severity="HIGH",
                                      fallback_actions=fallback)
        self.assertEqual(action.install, "block")


class TestLoadAdmissionPolicy(unittest.TestCase):
    def test_missing_dir_returns_defaults(self):
        policy = load_admission_policy("/nonexistent")
        self.assertTrue(policy.allow_list_bypass_scan)
        self.assertTrue(policy.scan_on_install)
        self.assertEqual(policy.actions["HIGH"].install, "block")
        self.assertEqual(policy.actions["HIGH"].runtime, "disable")
        self.assertEqual(policy.actions["MEDIUM"].install, "none")
        self.assertEqual(policy.scanner_overrides["mcp"]["MEDIUM"].install, "block")
        self.assertIn(("plugin", "defenseclaw"), policy.first_party_allow)
        self.assertIn(("skill", "codeguard"), policy.first_party_allow)

    def test_valid_data_json(self):
        tmp = tempfile.mkdtemp()
        rego_dir = os.path.join(tmp, "rego")
        os.makedirs(rego_dir)
        with open(os.path.join(rego_dir, "data.json"), "w") as f:
            json.dump({
                "config": {"allow_list_bypass_scan": False, "scan_on_install": False},
                "actions": {"MEDIUM": {"runtime": "block", "file": "quarantine", "install": "block"}},
                "first_party_allow_list": [
                    {"target_type": "skill", "target_name": "codeguard", "reason": "first-party"},
                ],
            }, f)
        policy = load_admission_policy(tmp)
        self.assertFalse(policy.allow_list_bypass_scan)
        self.assertFalse(policy.scan_on_install)
        self.assertIn("MEDIUM", policy.actions)
        self.assertEqual(policy.actions["MEDIUM"].runtime, "disable")
        self.assertIn(("skill", "codeguard"), policy.first_party_allow)

    def test_invalid_json_returns_defaults(self):
        tmp = tempfile.mkdtemp()
        rego_dir = os.path.join(tmp, "rego")
        os.makedirs(rego_dir)
        with open(os.path.join(rego_dir, "data.json"), "w") as f:
            f.write("{not json")
        policy = load_admission_policy(tmp)
        self.assertTrue(policy.allow_list_bypass_scan)


if __name__ == "__main__":
    unittest.main()
