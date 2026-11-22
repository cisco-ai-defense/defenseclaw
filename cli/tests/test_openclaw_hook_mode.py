# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import json
import os
import tempfile
import unittest
from types import SimpleNamespace

from defenseclaw.openclaw_plugin_config import (
    configured_openclaw_hook_mode,
    openclaw_hook_mode_detail,
    openclaw_install_policy_recorded_state,
    openclaw_install_policy_remediation,
    openclaw_install_policy_stale_remediation,
    openclaw_install_policy_stale_version,
    openclaw_install_policy_state,
)


class OpenClawHookModeTest(unittest.TestCase):
    def _cfg(self, entry_config):
        home = tempfile.mkdtemp()
        doc = {"plugins": {"entries": {"defenseclaw": {"enabled": True}}}}
        if entry_config is not None:
            doc["plugins"]["entries"]["defenseclaw"]["config"] = entry_config
        with open(os.path.join(home, "openclaw.json"), "w", encoding="utf-8") as f:
            json.dump(doc, f)
        return SimpleNamespace(claw=SimpleNamespace(home_dir=home, config_file=os.path.join(home, "openclaw.json")))

    def test_reads_the_mode_setup_wrote(self):
        self.assertEqual(configured_openclaw_hook_mode(self._cfg({"hookMode": "hybrid"})), "hybrid")
        self.assertEqual(configured_openclaw_hook_mode(self._cfg({"hookMode": "native"})), "native")

    def test_no_key_or_an_unknown_value_is_the_proxy_mode(self):
        self.assertEqual(configured_openclaw_hook_mode(self._cfg(None)), "proxy")
        self.assertEqual(configured_openclaw_hook_mode(self._cfg({"hookMode": "everything"})), "proxy")

    def test_missing_file_is_the_proxy_mode(self):
        cfg = SimpleNamespace(claw=SimpleNamespace(home_dir="/nonexistent-oc", config_file="/nonexistent-oc/openclaw.json"))
        self.assertEqual(configured_openclaw_hook_mode(cfg), "proxy")

    def test_detail_names_the_proxy(self):
        self.assertIn("no guardrail proxy", openclaw_hook_mode_detail("native"))
        self.assertIn("proxy", openclaw_hook_mode_detail("proxy"))


class OpenClawInstallPolicyStaleVersionTest(unittest.TestCase):
    # GAP-1198: setup registered the command under OpenClaw 2026.11.3, then
    # OpenClaw was reinstalled as 2026.8.35. The state file keeps the version
    # the policy was registered under; doctor and status compare it with the
    # cached one so a registered policy cannot read as fine while the version
    # is too old.
    def _cfg(self, cached, recorded):
        data_dir = tempfile.mkdtemp()
        with open(os.path.join(data_dir, "agent_discovery.json"), "w", encoding="utf-8") as f:
            json.dump({"agents": {"openclaw": {"version": cached}}} if cached else {"agents": {}}, f)
        if recorded is not None:
            with open(os.path.join(data_dir, "openclaw-install-policy-state.json"), "w", encoding="utf-8") as f:
                json.dump({"state": "registered", "openclaw_version": recorded}, f)
        return SimpleNamespace(data_dir=data_dir)

    def test_table(self):
        # (platform, cached, recorded, warns). A floor is crossed only when
        # recorded >= floor > cached; no record says nothing.
        table = [
            ("win32", "2026.8.35", "2026.11.3", True),  # the gap: registered under 11.3, reinstalled 8.35
            ("win32", "2026.7.1", "2026.11.3", True),  # below the hard floor too
            ("win32", "2026.7.1", "2026.8.35", True),
            ("linux", "2026.7.1", "2026.8.35", True),
            ("linux", "2026.8.35", "2026.11.3", False),  # 8.35 runs the command off Windows
            ("win32", "2026.9.1", "2026.8.35", False),  # both below 11.3: it passed the stricter rule
            ("win32", "2026.12.1", "2026.11.3", False),  # both at or above what Go accepts
            ("win32", "2026.11.3", "2026.11.3", False),
            ("win32", "2026.8.35", "2026.8.35", False),
            ("win32", "2026.8.35", None, False),  # never-written state: no permanent WARN
            ("linux", "2026.7.1", None, False),
            ("win32", "", "2026.11.3", False),  # cached version unknown
            ("win32", "garbage", "2026.11.3", False),
        ]
        for platform, cached, recorded, warns in table:
            with self.subTest(platform=platform, cached=cached, recorded=recorded):
                text, _certain = openclaw_install_policy_stale_version(self._cfg(cached, recorded), platform)
                self.assertEqual(bool(text), warns, text)

    def test_sentences(self):
        # GAP-1198 review: Python reads no folder ACLs, so the Windows rule
        # (only below a root with inherit-only entries) is "may be" until the
        # gateway re-checks it; below 2026.8.35 it is a hard warning anywhere.
        text, certain = openclaw_install_policy_stale_version(self._cfg("2026.8.35", "2026.11.3"), "win32")
        self.assertFalse(certain)
        self.assertIn("OpenClaw 2026.8.35 may be too old for strict install policy on Windows", text)
        self.assertIn("until the gateway re-checks it", text)
        self.assertNotIn("is too old", text)
        self.assertIn("needs 2026.11.3 or later", text)
        self.assertIn("registered under OpenClaw 2026.11.3", text)
        text, certain = openclaw_install_policy_stale_version(self._cfg("2026.7.1", "2026.11.3"), "win32")
        self.assertTrue(certain)
        self.assertIn("OpenClaw 2026.7.1 has no security.installPolicy (needs 2026.8.35 or later)", text)
        self.assertNotIn("may be", text)
        text, certain = openclaw_install_policy_stale_version(self._cfg("2026.7.1", "2026.8.35"), "linux")
        self.assertTrue(certain)
        self.assertIn("has no security.installPolicy (needs 2026.8.35 or later)", text)
        self.assertIn("registered under OpenClaw 2026.8.35", text)


class OpenClawInstallPolicyStatusRowTest(unittest.TestCase):
    # GAP-1198 follow-up: status says "may not be checked" for the Windows
    # rule the gateway settles and "not checked" for an OpenClaw below
    # 2026.8.35, from the real stale-version result, not from its wording.
    def _row(self, cached, recorded, platform):
        import shutil
        from unittest.mock import patch

        from defenseclaw.commands import cmd_status

        data_dir, home = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, data_dir, True)
        self.addCleanup(shutil.rmtree, home, True)
        with open(os.path.join(data_dir, "agent_discovery.json"), "w", encoding="utf-8") as f:
            json.dump({"agents": {"openclaw": {"version": cached}}}, f)
        with open(os.path.join(data_dir, "openclaw-install-policy-state.json"), "w", encoding="utf-8") as f:
            json.dump({"state": "registered", "openclaw_version": recorded}, f)
        policy = {
            "enabled": True,
            "exec": {"command": "defenseclaw-gateway", "args": ["connector", "openclaw", "install-policy"]},
        }
        with open(os.path.join(home, "openclaw.json"), "w", encoding="utf-8") as f:
            json.dump({"security": {"installPolicy": policy}}, f)
        cfg = SimpleNamespace(
            data_dir=data_dir, claw=SimpleNamespace(home_dir=home, config_file=os.path.join(home, "openclaw.json"))
        )
        with patch.object(cmd_status, "_status_row") as row:
            cmd_status._print_openclaw_install_admission(cfg, platform)
        self.assertEqual(row.call_count, 1)
        self.assertEqual(row.call_args.args[0], "OpenClaw installs")
        return row.call_args.args[1]

    def test_windows_rule_may_not_be_checked(self):
        text = self._row("2026.8.35", "2026.11.3", "win32")
        self.assertIn("OpenClaw version changed; may not be checked", text)

    def test_below_the_floor_is_not_checked(self):
        for platform in ("win32", "linux"):
            with self.subTest(platform=platform):
                text = self._row("2026.7.1", "2026.11.3", platform)
                self.assertIn("OpenClaw version changed; not checked", text)
                self.assertNotIn("may not be checked", text)

    def test_same_version_is_checked(self):
        self.assertIn("checked by DefenseClaw", self._row("2026.11.3", "2026.11.3", "win32"))


class OpenClawInstallPolicyStateTest(unittest.TestCase):
    def _cfg(self, security):
        home = tempfile.mkdtemp()
        doc = {"plugins": {}}
        if security is not None:
            doc["security"] = security
        with open(os.path.join(home, "openclaw.json"), "w", encoding="utf-8") as f:
            json.dump(doc, f)
        return SimpleNamespace(claw=SimpleNamespace(home_dir=home, config_file=os.path.join(home, "openclaw.json")))

    def test_states(self):
        ours = {"installPolicy": {"enabled": True, "exec": {"args": ["connector", "openclaw", "install-policy"]}}}
        other = {"installPolicy": {"enabled": True, "exec": {"args": ["--json"]}}}
        self.assertEqual(openclaw_install_policy_state(self._cfg(ours)), "ours")
        self.assertEqual(openclaw_install_policy_state(self._cfg(other)), "operator")
        self.assertEqual(openclaw_install_policy_state(self._cfg(None)), "none")
        self.assertEqual(openclaw_install_policy_state(self._cfg({"installPolicy": {"enabled": False}})), "none")


if __name__ == "__main__":
    unittest.main()


class OpenClawNativeFloorTest(unittest.TestCase):
    def test_floor(self):
        from defenseclaw.connector_contracts import openclaw_lacks_native_hooks

        self.assertTrue(openclaw_lacks_native_hooks("OpenClaw 2026.8.34 (abc)"))
        self.assertFalse(openclaw_lacks_native_hooks("2026.8.35"))
        self.assertFalse(openclaw_lacks_native_hooks(""))


class OpenClawOperatorAdminTest(unittest.TestCase):
    def _off(self, block):
        from unittest.mock import patch

        from defenseclaw.openclaw_plugin_config import openclaw_operator_admin_off

        home = tempfile.mkdtemp()
        path = os.path.join(home, "config.yaml")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"connectors": {"openclaw": block}}, f)
        with patch("defenseclaw.config.config_path", return_value=path):
            return openclaw_operator_admin_off()

    def test_only_an_explicit_false_turns_remediation_off(self):
        self.assertTrue(self._off({"operator_admin": False}))
        self.assertFalse(self._off({"operator_admin": True}))
        self.assertFalse(self._off({}))


class OpenClawExpectedHookModeTest(unittest.TestCase):
    # rel-1-0-10 GAP-0113: before the gateway writes the plugin entry, the
    # mode is the one setup will write, not "proxy".
    def _cfg(self, version):
        home = tempfile.mkdtemp()
        with open(os.path.join(home, "openclaw.json"), "w", encoding="utf-8") as f:
            json.dump({"plugins": {"entries": {}}}, f)
        with open(os.path.join(home, "agent_discovery.json"), "w", encoding="utf-8") as f:
            json.dump({"agents": {"openclaw": {"version": version}}}, f)
        claw = SimpleNamespace(home_dir=home, config_file=os.path.join(home, "openclaw.json"))
        return SimpleNamespace(claw=claw, data_dir=home)

    def _mode(self, version, os_name):
        from unittest.mock import patch

        missing = os.path.join(tempfile.mkdtemp(), "config.yaml")
        with (
            patch("defenseclaw.config.config_path", return_value=missing),
            patch("defenseclaw.platform_support.host_os", return_value=os_name),
        ):
            return configured_openclaw_hook_mode(self._cfg(version))

    def test_no_entry_yet_resolves_like_the_gateway(self):
        self.assertEqual(self._mode("OpenClaw 2026.8.35 (abc)", "linux"), "hybrid")
        self.assertEqual(self._mode("2026.3.24", "linux"), "proxy")
        self.assertEqual(self._mode("", "darwin"), "proxy")
        self.assertEqual(self._mode("2026.8.35", "windows"), "native")


class OpenClawCompatibilitySummaryTest(unittest.TestCase):
    # rel-1-0-10 GAP-0047: the doctor compatibility row names the hook mode.
    def test_summary_follows_os_and_version(self):
        from unittest.mock import patch

        from defenseclaw.doctor_health import _openclaw_compatibility_summary

        with patch("defenseclaw.platform_support.host_os", return_value="windows"):
            self.assertIn("native plugin hooks", _openclaw_compatibility_summary("openclaw", "2026.8.35"))
        with patch("defenseclaw.platform_support.host_os", return_value="linux"):
            self.assertIn("next to the proxy", _openclaw_compatibility_summary("openclaw", "2026.8.35"))
            self.assertIn("uses the guardrail proxy", _openclaw_compatibility_summary("openclaw", "2026.3.24"))


class OpenClawPluginEvidenceTest(unittest.TestCase):
    # rel-1-0-10 REVIEW-4 P1-1/P2-4: with the gateway up the mode counts only
    # once the plugin called in recently.
    def _cfg(self):
        home = tempfile.mkdtemp()
        with open(os.path.join(home, "openclaw.json"), "w", encoding="utf-8") as f:
            json.dump({"plugins": {"entries": {"defenseclaw": {"config": {"hookMode": "hybrid"}}}}}, f)
        claw = SimpleNamespace(home_dir=home, config_file=os.path.join(home, "openclaw.json"))
        return SimpleNamespace(claw=claw, data_dir=home)

    def _evidence(self, health):
        from unittest.mock import patch

        from defenseclaw.openclaw_plugin_config import openclaw_plugin_evidence

        missing = os.path.join(tempfile.mkdtemp(), "config.yaml")
        with patch("defenseclaw.config.config_path", return_value=missing):
            return openclaw_plugin_evidence(self._cfg(), health)

    def test_mode_needs_the_plugin_to_call_in(self):
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        self.assertEqual(self._evidence(None)[0], "hybrid")
        mode, detail, seen = self._evidence({})
        self.assertEqual((mode, seen), ("unverified", False))
        self.assertIn("expected hybrid", detail)
        fresh = {"openclaw_plugin": {"last_seen_at": now.isoformat(), "hook_mode": "hybrid"}}
        self.assertEqual(self._evidence(fresh)[:1] + (self._evidence(fresh)[2],), ("hybrid", True))
        stale = {"openclaw_plugin": {"last_seen_at": (now - timedelta(minutes=10)).isoformat(), "hook_mode": "hybrid"}}
        self.assertEqual(self._evidence(stale)[0], "unverified")


class OpenClawPluginEvidenceEdgeTest(OpenClawPluginEvidenceTest):
    # REVIEW-5 N4/N5: right after a gateway start the detail says so; a naive
    # timestamp does not crash.
    def test_fresh_gateway_and_naive_timestamp(self):
        from datetime import datetime

        mode, detail, _ = self._evidence({"uptime_ms": 5000})
        self.assertEqual(mode, "unverified")
        self.assertIn("started 5 s ago", detail)
        naive = {"openclaw_plugin": {"last_seen_at": datetime.utcnow().replace(microsecond=0).isoformat()}}
        self.assertEqual(self._evidence(naive)[0], "hybrid")


class OpenClawInstallPolicyRemediationTest(unittest.TestCase):
    # GAP-1139: the reason is in gateway.log (the gateway runs setup), and on
    # Windows doctor names the drive-root ACL that makes OpenClaw refuse the
    # command.
    def test_names_gateway_log_and_the_windows_drive_root(self):
        linux = openclaw_install_policy_remediation("none", "linux")
        self.assertIn("gateway.log", linux)
        self.assertNotIn("setup output", linux)
        self.assertNotIn("drive root", linux)
        windows = openclaw_install_policy_remediation("none", "win32")
        self.assertIn("drive root", windows)
        self.assertIn("C:\\", windows)

    def test_too_old_says_upgrade(self):
        text = openclaw_install_policy_remediation(
            "none", "win32", recorded="not registered: OpenClaw 2026.8.35 is too old for strict install policy on Windows"
        )
        self.assertIn("upgrade OpenClaw to 2026.11.3", text)
        # One remediation text for a too-old setup and a downgrade.
        self.assertEqual(text, openclaw_install_policy_stale_remediation())

    def test_operator_policy(self):
        self.assertIn("remove your own security.installPolicy", openclaw_install_policy_remediation("operator", "win32"))


class OpenClawInstallPolicyRecordedStateTest(unittest.TestCase):
    # GAP-1170: doctor and status read the reason the gateway recorded.
    def test_reads_the_gateway_state(self):
        data_dir = tempfile.mkdtemp()
        cfg = SimpleNamespace(data_dir=data_dir)
        self.assertEqual(openclaw_install_policy_recorded_state(cfg), "")
        reason = (
            "not registered: OpenClaw 2026.8.35 is too old for strict install policy on Windows "
            "(needs 2026.11.3 or later): it counts inherit-only entries"
        )
        with open(os.path.join(data_dir, "openclaw-install-policy-state.json"), "w", encoding="utf-8") as f:
            json.dump({"state": reason, "openclaw_version": "2026.8.35"}, f)
        self.assertEqual(openclaw_install_policy_recorded_state(cfg), reason)
        with open(os.path.join(data_dir, "openclaw-install-policy-state.json"), "w", encoding="utf-8") as f:
            f.write("{not json")
        self.assertEqual(openclaw_install_policy_recorded_state(cfg), "")
