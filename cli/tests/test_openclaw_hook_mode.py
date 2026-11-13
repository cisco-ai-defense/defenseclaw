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
