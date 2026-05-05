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

"""Tests for 'defenseclaw policy' command group — create, list, show, activate, delete."""

import json
import os
import shutil
import tempfile
import unittest

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_policy import policy
from tests.helpers import make_app_context, cleanup_app


class PolicyCommandTestBase(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        os.makedirs(self.app.cfg.policy_dir, exist_ok=True)
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args: list[str]):
        return self.runner.invoke(policy, args, obj=self.app, catch_exceptions=False)


class TestPolicyCreate(PolicyCommandTestBase):
    def test_create_basic(self):
        result = self.invoke(["create", "my-policy"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("my-policy", result.output)
        self.assertIn("created", result.output)

        path = os.path.join(self.app.cfg.policy_dir, "my-policy.yaml")
        self.assertTrue(os.path.isfile(path))

    def test_create_with_description(self):
        result = self.invoke(["create", "desc-policy", "-d", "My custom description"])
        self.assertEqual(result.exit_code, 0, result.output)

        import yaml
        path = os.path.join(self.app.cfg.policy_dir, "desc-policy.yaml")
        with open(path) as f:
            data = yaml.safe_load(f)
        self.assertEqual(data["description"], "My custom description")

    def test_create_from_preset(self):
        result = self.invoke(["create", "from-strict", "--from-preset", "strict"])
        self.assertEqual(result.exit_code, 0, result.output)

        import yaml
        path = os.path.join(self.app.cfg.policy_dir, "from-strict.yaml")
        with open(path) as f:
            data = yaml.safe_load(f)
        self.assertEqual(data["name"], "from-strict")
        # Strict blocks medium
        self.assertEqual(data["skill_actions"]["medium"]["install"], "block")

    def test_create_with_severity_overrides(self):
        result = self.invoke([
            "create", "custom-sev",
            "--critical-action", "block",
            "--high-action", "block",
            "--medium-action", "warn",
            "--low-action", "allow",
        ])
        self.assertEqual(result.exit_code, 0, result.output)

        import yaml
        path = os.path.join(self.app.cfg.policy_dir, "custom-sev.yaml")
        with open(path) as f:
            data = yaml.safe_load(f)
        self.assertEqual(data["skill_actions"]["critical"]["install"], "block")
        self.assertEqual(data["skill_actions"]["critical"]["file"], "quarantine")
        self.assertEqual(data["skill_actions"]["medium"]["install"], "none")
        self.assertEqual(data["skill_actions"]["low"]["file"], "none")

    def test_create_refuses_builtin_name(self):
        result = self.invoke(["create", "default"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("cannot overwrite", result.output)

    def test_create_refuses_duplicate(self):
        self.invoke(["create", "dup-policy"])
        result = self.invoke(["create", "dup-policy"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("already exists", result.output)

    def test_create_no_scan_on_install(self):
        result = self.invoke(["create", "noscan", "--no-scan-on-install"])
        self.assertEqual(result.exit_code, 0, result.output)

        import yaml
        path = os.path.join(self.app.cfg.policy_dir, "noscan.yaml")
        with open(path) as f:
            data = yaml.safe_load(f)
        self.assertFalse(data["admission"]["scan_on_install"])

    def test_create_logs_action(self):
        self.invoke(["create", "logged-policy"])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "policy-create"]
        self.assertEqual(len(actions), 1)


class TestPolicyList(PolicyCommandTestBase):
    def test_list_shows_builtins(self):
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("default", result.output)
        self.assertIn("strict", result.output)
        self.assertIn("permissive", result.output)

    def test_list_shows_custom_policy(self):
        self.invoke(["create", "my-custom"])
        result = self.invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("my-custom", result.output)


class TestPolicyShow(PolicyCommandTestBase):
    def test_show_builtin(self):
        result = self.invoke(["show", "default"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("CRITICAL", result.output)
        self.assertIn("HIGH", result.output)
        self.assertIn("MEDIUM", result.output)

    def test_show_custom(self):
        self.invoke(["create", "show-me", "-d", "Test policy"])
        result = self.invoke(["show", "show-me"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("show-me", result.output)
        self.assertIn("Test policy", result.output)

    def test_show_nonexistent(self):
        result = self.invoke(["show", "does-not-exist"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not found", result.output)


class TestPolicyActivate(PolicyCommandTestBase):
    def test_activate_builtin(self):
        result = self.invoke(["activate", "strict"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("activated", result.output)

        # Check config was updated
        self.assertEqual(self.app.cfg.skill_actions.medium.install, "block")

    def test_activate_custom(self):
        self.invoke(["create", "my-active", "--medium-action", "block"])
        result = self.invoke(["activate", "my-active"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("activated", result.output)
        self.assertEqual(self.app.cfg.skill_actions.medium.install, "block")

    def test_activate_builtin_updates_watch_rescan_config(self):
        import yaml

        self.app.cfg.watch.rescan_enabled = False
        self.app.cfg.watch.rescan_interval_min = 120

        result = self.invoke(["activate", "strict"])
        self.assertEqual(result.exit_code, 0, result.output)

        self.assertTrue(self.app.cfg.watch.rescan_enabled)
        self.assertEqual(self.app.cfg.watch.rescan_interval_min, 30)

        with open(os.path.join(self.tmp_dir, "config.yaml")) as f:
            raw = yaml.safe_load(f)
        self.assertTrue(raw["watch"]["rescan_enabled"])
        self.assertEqual(raw["watch"]["rescan_interval_min"], 30)

    def test_activate_nonexistent(self):
        result = self.invoke(["activate", "ghost"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not found", result.output)

    def test_activate_logs_action(self):
        self.invoke(["activate", "default"])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "policy-activate"]
        self.assertEqual(len(actions), 1)


class TestPolicyDelete(PolicyCommandTestBase):
    def test_delete_custom(self):
        self.invoke(["create", "deletable"])
        result = self.invoke(["delete", "deletable"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("deleted", result.output)
        self.assertFalse(os.path.exists(
            os.path.join(self.app.cfg.policy_dir, "deletable.yaml")
        ))

    def test_delete_builtin_refused(self):
        result = self.invoke(["delete", "default"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("cannot delete", result.output)

    def test_delete_nonexistent(self):
        result = self.invoke(["delete", "nope"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not found", result.output)

    def test_delete_logs_action(self):
        self.invoke(["create", "to-delete"])
        self.invoke(["delete", "to-delete"])
        events = self.app.store.list_events(10)
        actions = [e for e in events if e.action == "policy-delete"]
        self.assertEqual(len(actions), 1)


class TestSyncOpaDataFirstParty(PolicyCommandTestBase):
    def test_sync_writes_guardrail_hilt(self):
        from defenseclaw.commands.cmd_policy import _sync_opa_data

        rego_dir = os.path.join(self.app.cfg.policy_dir, "rego")
        os.makedirs(rego_dir, exist_ok=True)
        data_json_path = os.path.join(rego_dir, "data.json")
        with open(data_json_path, "w") as f:
            json.dump({
                "config": {},
                "actions": {},
                "guardrail": {
                    "block_threshold": 4,
                    "alert_threshold": 2,
                    "hilt": {"enabled": False, "min_severity": "HIGH"},
                },
            }, f)

        policy_data = {
            "name": "test-sync",
            "guardrail": {
                "block_threshold": 4,
                "alert_threshold": 2,
                "hilt": {"enabled": True, "min_severity": "MEDIUM"},
            },
        }

        _sync_opa_data(self.app, policy_data)

        with open(data_json_path) as f:
            result = json.load(f)

        self.assertTrue(result["guardrail"]["hilt"]["enabled"])
        self.assertEqual(result["guardrail"]["hilt"]["min_severity"], "MEDIUM")

    def test_sync_writes_first_party_allow_list_with_provenance(self):
        from defenseclaw.commands.cmd_policy import _sync_opa_data

        rego_dir = os.path.join(self.app.cfg.policy_dir, "rego")
        os.makedirs(rego_dir, exist_ok=True)
        data_json_path = os.path.join(rego_dir, "data.json")
        with open(data_json_path, "w") as f:
            json.dump({
                "config": {},
                "actions": {},
                "first_party_allow_list": [
                    {
                        "target_type": "plugin",
                        "target_name": "defenseclaw",
                        "reason": "old reason",
                        "source_path_contains": [".defenseclaw"],
                    }
                ],
            }, f)

        policy_data = {
            "name": "test-sync",
            "first_party_allow_list": [
                {
                    "target_type": "plugin",
                    "target_name": "defenseclaw",
                    "reason": "first-party DefenseClaw plugin",
                    "source_path_contains": [".defenseclaw", ".openclaw/extensions"],
                },
                {
                    "target_type": "skill",
                    "target_name": "codeguard",
                    "reason": "first-party DefenseClaw skill",
                    "source_path_contains": [".defenseclaw", ".openclaw/skills"],
                },
            ],
        }

        _sync_opa_data(self.app, policy_data)

        with open(data_json_path) as f:
            result = json.load(f)

        fp_list = result.get("first_party_allow_list", [])
        self.assertEqual(len(fp_list), 2)

        plugin_entry = next(
            (e for e in fp_list if e["target_name"] == "defenseclaw"), None
        )
        self.assertIsNotNone(plugin_entry)
        self.assertIn(".openclaw/extensions", plugin_entry["source_path_contains"])
        self.assertEqual(plugin_entry["reason"], "first-party DefenseClaw plugin")

        skill_entry = next(
            (e for e in fp_list if e["target_name"] == "codeguard"), None
        )
        self.assertIsNotNone(skill_entry)
        self.assertIn(".openclaw/skills", skill_entry["source_path_contains"])


class TestPolicyLifecycle(PolicyCommandTestBase):
    def test_create_show_activate_delete(self):
        # Create
        result = self.invoke([
            "create", "lifecycle-test",
            "-d", "Lifecycle test policy",
            "--critical-action", "block",
            "--high-action", "block",
            "--medium-action", "block",
        ])
        self.assertEqual(result.exit_code, 0, result.output)

        # Show
        result = self.invoke(["show", "lifecycle-test"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("lifecycle-test", result.output)

        # List
        result = self.invoke(["list"])
        self.assertIn("lifecycle-test", result.output)

        # Activate
        result = self.invoke(["activate", "lifecycle-test"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.app.cfg.skill_actions.medium.install, "block")

        # Delete
        result = self.invoke(["delete", "lifecycle-test"])
        self.assertEqual(result.exit_code, 0, result.output)


if __name__ == "__main__":
    unittest.main()
