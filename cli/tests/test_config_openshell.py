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

"""Tests for the ``openshell:`` config section (Python twin of internal/config/openshell.go)."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import (
    DEFAULT_SANDBOX_HOME,
    OPENSHELL_LOCKABLE_KEYS,
    OPENSHELL_PROFILES,
    Config,
    GuardrailConfig,
    OpenShellAdminConfig,
    OpenShellConfig,
    OpenShellMCPConfig,
    OpenShellResourcesConfig,
    _merge_openshell,
    load,
)

_FULL_SECTION = {
    "enabled": True,
    "binary": "/usr/bin/openshell",
    "gateway": {"name": "openshell", "workspace": "team"},
    "egress_port": 19500,
    "pack": "balanced",
    "pack_dir": "/etc/defenseclaw/packs",
    "profile": "strict",
    "yolo": False,
    "workdir": {
        "mode": "copy",
        "masks": [".env*"],
        "unmask": [".env.example"],
        "max_upload_mb": 100,
        "git_depth": 50,
        "on_exit": "keep",
    },
    "egress": {
        "block": ["paste.example"],
        "allow": ["*.npmjs.org"],
        "ports": [443, 8443],
        "large_upload_mb": 10,
        "feed": "none",
    },
    "image": {"base": "registry.example/base@sha256:abc", "harness_versions": {"codex": "0.146.0"}},
    "approvals": {"debounce_ms": 1500, "agent_proposals": False},
    "resources": {"cpu": "2", "memory": "4Gi"},
    "harnesses": ["claude-code", "codex"],
    "wrappers": ["claudecode"],
    "mcp": {"import": False, "host_ports": [5432]},
    "upstream_telemetry": True,
    "token_delivery": "env",
    "middleware": {"enabled": True},
    "admin": {
        "required_pack": "strict",
        "min_profile": "balanced",
        "allow_yolo": False,
        "allow_mount": True,
        "allowed_harnesses": ["codex"],
        "egress_block": ["*.ngrok.io"],
        "egress_allow_only": ["*.corp.example"],
        "require_copy_for": ["/src/customer-*"],
        "max_resources": {"cpu": "500m", "memory": "8Gi"},
        "locked": ["profile", "yolo"],
    },
    # Legacy openshell-sandbox (0.0.x) keys stay accepted.
    "policy_dir": "/etc/openshell/policies",
    "version": "0.6.2",
    "auto_pair": True,
    "host_networking": True,
}


class TestOpenShellMerge(unittest.TestCase):
    def test_loader_defaults_mirror_go(self):
        oc = _merge_openshell(None, "/var/dc")
        self.assertFalse(oc.enabled)
        self.assertEqual(oc.binary, "openshell")
        self.assertEqual(oc.pack_dir, os.path.join("/var/dc", "policies", "sandbox"))
        self.assertEqual(oc.workdir.git_depth, 200)
        self.assertEqual(oc.workdir.on_exit, "ask")
        self.assertEqual(oc.approvals.debounce_ms, 3000)
        self.assertTrue(oc.approvals.agent_proposals_enabled())
        self.assertEqual(oc.token_delivery, "provider")
        self.assertEqual(oc.sandbox_home, DEFAULT_SANDBOX_HOME)
        # Pack-governed keys stay unset so the selected pack supplies them.
        self.assertEqual(oc.pack, "")
        self.assertEqual(oc.profile, "")
        self.assertIsNone(oc.yolo)
        self.assertEqual(oc.workdir.mode, "")
        self.assertEqual(oc.workdir.max_upload_mb, 0)
        self.assertEqual(oc.egress.ports, [])
        self.assertEqual(oc.egress.feed, "")
        self.assertIsNone(oc.mcp.import_)
        self.assertEqual(oc.admin, OpenShellAdminConfig())

    def test_full_section(self):
        oc = _merge_openshell(_FULL_SECTION, "/var/dc")
        self.assertTrue(oc.enabled)
        self.assertEqual(oc.binary, "/usr/bin/openshell")
        self.assertEqual(oc.gateway.workspace, "team")
        self.assertEqual(oc.ingress_port, 0)
        self.assertEqual(oc.egress_port, 19500)
        self.assertEqual(oc.pack, "balanced")
        self.assertEqual(oc.pack_dir, "/etc/defenseclaw/packs")
        self.assertEqual(oc.profile, "strict")
        self.assertIs(oc.yolo, False)
        self.assertEqual(oc.workdir.mode, "copy")
        self.assertEqual(oc.workdir.masks, [".env*"])
        self.assertEqual(oc.workdir.on_exit, "keep")
        self.assertEqual(oc.egress.ports, [443, 8443])
        self.assertEqual(oc.egress.feed, "none")
        self.assertEqual(oc.image.harness_versions, {"codex": "0.146.0"})
        self.assertFalse(oc.approvals.agent_proposals_enabled())
        self.assertEqual(oc.resources, OpenShellResourcesConfig(cpu="2", memory="4Gi"))
        self.assertEqual(oc.harnesses, ["claude-code", "codex"])
        self.assertIs(oc.mcp.import_, False)
        self.assertEqual(oc.mcp.host_ports, [5432])
        self.assertTrue(oc.upstream_telemetry)
        self.assertEqual(oc.token_delivery, "env")
        self.assertTrue(oc.middleware.enabled)
        self.assertEqual(oc.admin.required_pack, "strict")
        self.assertIs(oc.admin.allow_yolo, False)
        self.assertIs(oc.admin.allow_mount, True)
        self.assertIsNone(oc.admin.allow_unblock)
        self.assertEqual(oc.admin.max_resources, OpenShellResourcesConfig(cpu="500m", memory="8Gi"))
        self.assertEqual(oc.admin.locked, ["profile", "yolo"])
        self.assertFalse(hasattr(oc, "version"))
        self.assertFalse(hasattr(oc, "policy_dir"))

    def test_tolerates_malformed_values(self):
        oc = _merge_openshell(
            {
                "yolo": "false",
                "ingress_port": "not-a-port",
                "harnesses": "codex",
                "egress": {"ports": [443, "x", True, None]},
                "admin": {"allow_unblock": "no", "locked": None},
                "workdir": None,
            }
        )
        self.assertIs(oc.yolo, False)
        self.assertEqual(oc.ingress_port, 0)
        self.assertEqual(oc.harnesses, [])
        self.assertEqual(oc.egress.ports, [443])
        self.assertIs(oc.admin.allow_unblock, False)
        self.assertEqual(oc.admin.locked, [])
        self.assertEqual(oc.workdir.git_depth, 200)

    def test_effective_ports(self):
        oc = OpenShellConfig()
        self.assertEqual(oc.effective_ingress_port(18970), 18971)
        self.assertEqual(oc.effective_egress_port(0), 18972)
        oc.ingress_port = 20001
        self.assertEqual(oc.effective_ingress_port(18970), 20001)

    def test_constants_mirror_go(self):
        go = Path(__file__).resolve().parents[2] / "internal" / "config" / "openshell.go"
        source = go.read_text(encoding="utf-8")
        block = source.split("var OpenShellLockableKeys = []string{", 1)[1].split("}", 1)[0]
        go_keys = tuple(line.strip().strip(",").strip('"') for line in block.splitlines() if line.strip())
        self.assertEqual(go_keys, OPENSHELL_LOCKABLE_KEYS)
        self.assertEqual(OPENSHELL_PROFILES, ("open", "balanced", "strict"))


class TestPolicyConnectors(unittest.TestCase):
    def test_union_with_sandbox_harnesses(self):
        cfg = Config()
        cfg.claw.mode = ""
        self.assertEqual(cfg.policy_connectors(), [])
        cfg.openshell.harnesses = ["Codex", "claude-code", " "]
        self.assertEqual(cfg.policy_connectors(), ["claudecode", "codex"])
        cfg.guardrail = GuardrailConfig(connector="cursor")
        self.assertEqual(cfg.policy_connectors(), ["claudecode", "codex", "cursor"])
        self.assertEqual(cfg.active_connectors(), ["cursor"])


class TestOpenShellSave(unittest.TestCase):
    def _load(self, tmpdir: str) -> Config:
        with patch("defenseclaw.config.default_data_path") as mock_dp:
            mock_dp.return_value = Path(tmpdir)
            return load()

    def test_untouched_section_is_not_written(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.yaml")
            with open(path, "w") as f:
                yaml.safe_dump({"config_version": 8, "data_dir": tmpdir}, f)
            cfg = self._load(tmpdir)
            cfg.gateway.api_port = 19000
            cfg.save()
            with open(path) as f:
                raw = yaml.safe_load(f)
            self.assertNotIn("openshell", raw)

    def test_modeled_changes_round_trip_and_validate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.yaml")
            with open(path, "w") as f:
                yaml.safe_dump(
                    {
                        "config_version": 8,
                        "data_dir": tmpdir,
                        "openshell": {"mode": "standalone", "version": "0.6.2", "auto_pair": False},
                    },
                    f,
                )
            cfg = self._load(tmpdir)
            cfg.openshell.enabled = True
            cfg.openshell.profile = "balanced"
            cfg.openshell.yolo = False
            cfg.openshell.harnesses = ["codex"]
            cfg.openshell.mcp = OpenShellMCPConfig(import_=False, host_ports=[5432])
            cfg.openshell.admin.allow_unblock = False
            cfg.openshell.admin.locked = ["profile"]
            cfg.save()  # validates the merged document against the v8 schema

            with open(path) as f:
                raw = yaml.safe_load(f)
            section = raw["openshell"]
            self.assertIs(section["enabled"], True)
            self.assertEqual(section["profile"], "balanced")
            self.assertIs(section["yolo"], False)
            self.assertEqual(section["mcp"], {"import": False, "host_ports": [5432]})
            self.assertEqual(section["admin"], {"allow_unblock": False, "locked": ["profile"]})
            # Ignored legacy keys survive untouched; unset pack keys are not written.
            self.assertEqual(section["version"], "0.6.2")
            self.assertIs(section["auto_pair"], False)
            self.assertNotIn("workdir", section)
            self.assertNotIn("import_", section.get("mcp", {}))

            reloaded = self._load(tmpdir)
            self.assertIs(reloaded.openshell.mcp.import_, False)
            self.assertEqual(reloaded.openshell.admin.locked, ["profile"])
            self.assertEqual(reloaded.openshell.mode, "standalone")

            # Clearing a tri-state back to "inherit" writes null, which the
            # schema accepts and the loader reads as None.
            reloaded.openshell.yolo = None
            reloaded.save()
            self.assertIsNone(self._load(tmpdir).openshell.yolo)


if __name__ == "__main__":
    unittest.main()
