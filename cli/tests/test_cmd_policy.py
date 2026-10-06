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

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_policy import policy

from tests.helpers import cleanup_app, make_app_context


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

    # --- OTHER-3: tri-state --from-preset admission flags ---

    def _load_created(self, name: str) -> dict:
        import yaml
        with open(os.path.join(self.app.cfg.policy_dir, f"{name}.yaml")) as f:
            return yaml.safe_load(f)

    def test_create_from_preset_keeps_admission_when_no_flag(self):
        # strict ships allow_list_bypass_scan: false. Without the flag,
        # create must keep the preset's value (the OTHER-3 bug reset it
        # to the CLI default True).
        result = self.invoke(["create", "from-strict-keep", "--from-preset", "strict"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = self._load_created("from-strict-keep")
        self.assertFalse(data["admission"]["allow_list_bypass_scan"])
        self.assertTrue(data["admission"]["scan_on_install"])

    def test_create_from_preset_flag_overrides(self):
        # An explicit flag still overrides the preset value.
        result = self.invoke([
            "create", "from-strict-override", "--from-preset", "strict",
            "--allow-list-bypass",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        data = self._load_created("from-strict-override")
        self.assertTrue(data["admission"]["allow_list_bypass_scan"])

    def test_create_bare_defaults_scan_on_install_true(self):
        # No preset, no flag → historical default preserved.
        result = self.invoke(["create", "bare-default"])
        self.assertEqual(result.exit_code, 0, result.output)
        data = self._load_created("bare-default")
        self.assertTrue(data["admission"]["scan_on_install"])
        self.assertTrue(data["admission"]["allow_list_bypass_scan"])


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

    def test_show_names_guardrail_threshold_severities(self):
        # GAP-1228: "MEDIUM (2)", not a bare "2 (severity rank)".
        result = self.invoke(["show", "strict"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("(severity rank)", result.output)
        self.assertRegex(result.output, r"block_threshold:\s+(LOW|MEDIUM|HIGH|CRITICAL) \(\d\)")

    def test_show_nonexistent(self):
        result = self.invoke(["show", "does-not-exist"])
        self.assertEqual(result.exit_code, 1)
        # GAP-1818: CLI error style plus the valid names and the next step.
        self.assertIn("Error: policy 'does-not-exist' not found.", result.output)
        self.assertIn("Available policies:", result.output)
        self.assertIn("default", result.output)
        self.assertIn("defenseclaw policy list", result.output)


class TestPolicyActivate(PolicyCommandTestBase):
    def test_activate_builtin(self):
        result = self.invoke(["activate", "strict"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("activated", result.output)

        # The preset's actions become config admission defaults.
        self.assertEqual(self.app.cfg.admission.defaults.actions["medium"]["install"], "block")

    def test_activate_custom(self):
        self.invoke(["create", "my-active", "--medium-action", "block"])
        result = self.invoke(["activate", "my-active"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("activated", result.output)
        self.assertEqual(self.app.cfg.admission.defaults.actions["medium"]["install"], "block")

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
        self.assertTrue(raw.get("watch", {}).get("rescan_enabled", True))
        self.assertEqual(raw["watch"]["rescan_interval_min"], 30)

    def test_activate_nonexistent(self):
        result = self.invoke(["activate", "ghost"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not found", result.output)

    def test_activate_keeps_configured_webhooks(self):
        """GAP-1273: built-ins carry ``webhooks: []``; activation must keep the list."""
        import yaml
        from defenseclaw.config import WebhookConfig

        self.app.cfg.webhooks = [
            WebhookConfig(name="ops", url="https://hooks.example.com/ops", type="slack", enabled=True),
        ]
        self.app.cfg.save()
        for name in ("strict", "default"):
            result = self.invoke(["activate", name])
            self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual([w.name for w in self.app.cfg.webhooks], ["ops"])
        self.assertEqual(self.app.cfg.webhooks[0].type, "slack")
        with open(os.path.join(self.tmp_dir, "config.yaml")) as f:
            raw = yaml.safe_load(f)
        self.assertEqual([w.get("name") for w in raw.get("webhooks") or []], ["ops"])

    def test_activate_names_the_webhooks_it_added_and_skipped(self):
        """GAP-1585: activation says which policy webhooks it added or skipped."""
        import yaml
        from defenseclaw.config import WebhookConfig

        self.app.cfg.webhooks = [WebhookConfig(name="gen", url="https://hooks.example.com/gen", enabled=True)]
        self.app.cfg.save()
        self.assertEqual(self.invoke(["create", "whpol"]).exit_code, 0)
        path = os.path.join(self.app.cfg.policy_dir, "whpol.yaml")
        with open(path) as f:
            data = yaml.safe_load(f)
        data["webhooks"] = [
            {"name": "polwh", "url": "https://hooks.example.com/polwh", "enabled": True},
            {"name": "gen", "url": "https://hooks.example.com/other", "enabled": False},
        ]
        with open(path, "w") as f:
            yaml.safe_dump(data, f)
        result = self.invoke(["activate", "whpol"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Added webhook polwh from the policy", result.output)
        self.assertIn("Skipped webhook gen: a webhook with that name or URL is already configured", result.output)
        again = self.invoke(["activate", "whpol"])
        self.assertNotIn("Added webhook", again.output)
        self.assertNotIn("Skipped webhook polwh", again.output)

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

    def test_delete_reverts_an_edited_builtin(self):
        """GAP-1458: ``policy delete strict`` drops the user copy ``policy edit`` saved."""
        result = self.invoke(["edit", "guardrail", "-p", "strict", "--block-threshold", "3", "--no-reload"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("policy delete strict", result.output)
        user_copy = os.path.join(self.app.cfg.policy_dir, "strict.yaml")
        self.assertTrue(os.path.isfile(user_copy))
        self.assertIn("strict [built-in, edited]", self.invoke(["list"]).output)

        result = self.invoke(["delete", "strict"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("built-in version is back", result.output)
        self.assertFalse(os.path.exists(user_copy))
        listed = self.invoke(["list"]).output
        self.assertIn("strict [built-in]", listed)
        self.assertNotIn("edited", listed)
        # A second delete has nothing left to revert.
        self.assertNotEqual(self.invoke(["delete", "strict"]).exit_code, 0)

    def test_delete_asks_on_a_terminal_and_accepts_yes(self):
        # GAP-1887: a user-authored policy is removed for good, so confirm first.
        from unittest.mock import patch

        self.invoke(["create", "askme"])
        path = os.path.join(self.app.cfg.policy_dir, "askme.yaml")
        with patch("defenseclaw.commands.cmd_policy._stdin_is_tty", return_value=True):
            declined = self.runner.invoke(policy, ["delete", "askme"], obj=self.app, input="n\n")
            self.assertEqual(declined.exit_code, 1, declined.output)
            self.assertIn("Delete policy 'askme'", declined.output)
            self.assertTrue(os.path.exists(path))
            accepted = self.invoke(["delete", "askme", "--yes"])
        self.assertEqual(accepted.exit_code, 0, accepted.output)
        self.assertFalse(os.path.exists(path))

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


class TestPolicyActivateWritesConfig(PolicyCommandTestBase):
    def test_activate_writes_first_party_and_thresholds_to_config(self):
        result = self.invoke(["activate", "default", "--no-reload"])
        self.assertEqual(result.exit_code, 0, result.output)
        plugin = self.app.cfg.admission.plugin.first_party_allow_list
        self.assertEqual([e.name for e in plugin], ["defenseclaw"])
        self.assertIn(".openclaw/extensions/defenseclaw", plugin[0].source_path_contains)
        # The default preset's thresholds are the defaults, so the pack posture applies.
        self.assertEqual((self.app.cfg.guardrail.block_at, self.app.cfg.guardrail.alert_at), ("", ""))
        self.assertFalse(os.path.exists(os.path.join(self.app.cfg.policy_dir, "rego", "data.json")))

    def test_activate_compares_thresholds_with_the_selected_pack(self):
        # The permissive pack alerts at HIGH; the default preset alerts at
        # MEDIUM, so activating it must write alert_at (block CRITICAL matches).
        self.app.cfg.guardrail.rule_pack = "permissive"
        result = self.invoke(["activate", "default", "--no-reload"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual((self.app.cfg.guardrail.block_at, self.app.cfg.guardrail.alert_at), ("", "MEDIUM"))


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
        self.assertEqual(self.app.cfg.admission.defaults.actions["medium"]["install"], "block")

        # Delete — config.yaml keeps what the activation applied.
        result = self.invoke(["delete", "lifecycle-test"])
        self.assertEqual(result.exit_code, 0, result.output)


class TestPolicyEditLive(PolicyCommandTestBase):
    """Without -p an edit changes the live config.yaml policy."""

    def test_live_edit_writes_config_admission(self):
        result = self.invoke(["edit", "actions", "-s", "medium", "--install", "block", "--no-reload"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.app.cfg.admission.defaults.actions["medium"],
                         {"install": "block", "file": "none", "runtime": "enable"})
        # Skills resolve their scanner gate before the defaults, so the edit
        # is also theirs.
        from defenseclaw.enforce.admission import compile_admission

        self.assertEqual(compile_admission(self.app.cfg, "skill").actions["MEDIUM"][0].install, "block")


class TestPolicyEditCopyOnWrite(PolicyCommandTestBase):
    """OTHER-4: editing a built-in must not write into the bundled wheel dir."""

    def setUp(self):
        super().setUp()
        from defenseclaw.commands.cmd_policy import _bundled_policies_dir

        self._bundled_dir = _bundled_policies_dir()
        # Snapshot bundled built-ins so a regression that writes them in
        # place is both detected AND restored (never dirty the source tree).
        self._snapshots: dict[str, bytes] = {}
        for builtin in ("default", "strict"):
            p = os.path.join(self._bundled_dir, f"{builtin}.yaml")
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    self._snapshots[p] = f.read()

    def tearDown(self):
        for p, content in self._snapshots.items():
            with open(p, "rb") as f:
                current = f.read()
            if current != content:
                with open(p, "wb") as f:
                    f.write(content)
        super().tearDown()

    def _assert_bundled_unchanged(self):
        for p, content in self._snapshots.items():
            with open(p, "rb") as f:
                self.assertEqual(f.read(), content, f"bundled {p} was modified")

    def test_edit_active_builtin_copies_to_user_dir(self):
        import yaml

        self.assertEqual(self.invoke(["activate", "default"]).exit_code, 0)
        user_copy = os.path.join(self.app.cfg.policy_dir, "default.yaml")
        self.assertFalse(os.path.exists(user_copy))

        result = self.invoke(
            ["edit", "guardrail", "--block-threshold", "3", "-p", "default"]
        )
        self.assertEqual(result.exit_code, 0, result.output)

        # COW: user copy created with the change; bundled untouched.
        self.assertTrue(os.path.isfile(user_copy))
        with open(user_copy) as f:
            data = yaml.safe_load(f)
        self.assertEqual(data["guardrail"]["block_threshold"], 3)
        self._assert_bundled_unchanged()

    def test_edit_guardrail_threshold_takes_severity_names(self):
        """GAP-1724/GAP-1725: names like policy show prints; no plumbing lines."""
        import yaml

        activated = self.invoke(["activate", "default"])
        self.assertEqual(activated.exit_code, 0, activated.output)
        result = self.invoke(
            ["edit", "guardrail", "--block-threshold", "high", "--alert-threshold", "MEDIUM",
             "-p", "default", "--no-reload"]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("block_threshold=HIGH (3)", result.output)
        with open(os.path.join(self.app.cfg.policy_dir, "default.yaml")) as f:
            data = yaml.safe_load(f)
        self.assertEqual((data["guardrail"]["block_threshold"], data["guardrail"]["alert_threshold"]), (3, 2))
        for output in (activated.output, result.output):
            self.assertNotIn("data.json", output)
            self.assertNotIn("Config updated", output)

        bad = self.invoke(["edit", "guardrail", "--block-threshold", "5", "-p", "default", "--no-reload"])
        self.assertEqual(bad.exit_code, 2, bad.output)
        self.assertIn("Use LOW, MEDIUM, HIGH, CRITICAL or 1-4", bad.output)

    def test_edit_nonactive_builtin_copies_without_sync(self):
        import yaml

        self.assertEqual(self.invoke(["activate", "default"]).exit_code, 0)
        before = self.app.cfg.guardrail.block_at

        # strict is bundled: COW, and the live config is untouched.
        result = self.invoke(
            ["edit", "guardrail", "--block-threshold", "2", "-p", "strict"]
        )
        self.assertEqual(result.exit_code, 0, result.output)

        user_copy = os.path.join(self.app.cfg.policy_dir, "strict.yaml")
        self.assertTrue(os.path.isfile(user_copy))
        with open(user_copy) as f:
            data = yaml.safe_load(f)
        self.assertEqual(data["guardrail"]["block_threshold"], 2)
        self._assert_bundled_unchanged()

        self.assertEqual(self.app.cfg.guardrail.block_at, before)
        self.assertIn("Apply it with", result.output)


class TestPolicyDeleteKeepsConfig(PolicyCommandTestBase):
    """Deleting a policy file never changes what config.yaml enforces."""

    def test_delete_nonactive_unaffected(self):
        self.invoke(["create", "keep"])
        self.invoke(["create", "drop"])
        self.assertEqual(self.invoke(["activate", "keep"]).exit_code, 0)

        result = self.invoke(["delete", "drop"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(os.path.exists(
            os.path.join(self.app.cfg.policy_dir, "drop.yaml")
        ))


if __name__ == "__main__":
    unittest.main()
