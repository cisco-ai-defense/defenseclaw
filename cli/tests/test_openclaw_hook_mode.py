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
