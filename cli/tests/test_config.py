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

"""Tests for defenseclaw.config — environment detection, load, save, claw-mode paths."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import (
    CiscoAIDefenseConfig,
    Config,
    ClawConfig,
    DEFAULT_OPENSHELL_VERSION,
    DEFAULT_SANDBOX_HOME,
    GatewayConfig,
    GatewayWatcherConfig,
    GatewayWatcherSkillConfig,
    InspectLLMConfig,
    MCPScannerConfig,
    GatewayWatcherPluginConfig,
    PluginActionsConfig,
    GuardrailConfig,
    OpenShellConfig,
    SeverityAction,
    SkillActionsConfig,
    SkillScannerConfig,
    WebhookConfig,
    WatchConfig,
    _dedup,
    _expand,
    _merge_cisco_ai_defense,
    _merge_gateway_watcher,
    _merge_inspect_llm,
    _merge_mcp_scanner,
    _merge_openshell,
    _merge_plugin_actions,
    _merge_guardrail,
    _merge_severity_action,
    _merge_skill_actions,
    _merge_webhooks,
    default_config,
    default_data_path,
    config_path,
    detect_environment,
    load,
)


class TestHelpers(unittest.TestCase):
    def test_expand_tilde(self):
        result = _expand("~/foo/bar")
        # On Windows os.path.expanduser uses backslashes
        self.assertTrue(result.endswith(os.path.join("foo", "bar")))
        self.assertFalse(result.startswith("~"))

    def test_expand_non_tilde(self):
        self.assertEqual(_expand("/abs/path"), "/abs/path")
        self.assertEqual(_expand("relative"), "relative")

    def test_dedup_preserves_order(self):
        self.assertEqual(_dedup(["a", "b", "a", "c", "b"]), ["a", "b", "c"])

    def test_dedup_empty(self):
        self.assertEqual(_dedup([]), [])


class TestPaths(unittest.TestCase):
    def test_default_data_path(self):
        dp = default_data_path()
        self.assertIsInstance(dp, Path)
        self.assertTrue(str(dp).endswith(".defenseclaw"))

    def test_config_path(self):
        cp = config_path()
        self.assertTrue(str(cp).endswith("config.yaml"))


class TestDetectEnvironment(unittest.TestCase):
    @patch("defenseclaw.config.platform.system", return_value="Darwin")
    def test_macos(self, _mock):
        self.assertEqual(detect_environment(), "macos")

    @patch("defenseclaw.config.platform.system", return_value="Linux")
    @patch("defenseclaw.config.Path.exists", return_value=True)
    def test_dgx_release_file(self, _mock_path, _mock_sys):
        self.assertEqual(detect_environment(), "dgx-spark")

    @patch("defenseclaw.config.platform.system", return_value="Linux")
    @patch("defenseclaw.config.Path.exists", return_value=False)
    @patch("defenseclaw.config.subprocess.check_output", side_effect=FileNotFoundError)
    def test_linux_fallback(self, _m1, _m2, _m3):
        self.assertEqual(detect_environment(), "linux")


class TestSeverityAction(unittest.TestCase):
    def test_defaults(self):
        sa = SeverityAction()
        self.assertEqual(sa.file, "none")
        self.assertEqual(sa.runtime, "enable")
        self.assertEqual(sa.install, "none")


class TestSkillActionsConfig(unittest.TestCase):
    def test_for_severity_known(self):
        cfg = SkillActionsConfig()
        self.assertEqual(cfg.for_severity("CRITICAL").install, "none")
        self.assertEqual(cfg.for_severity("HIGH").runtime, "enable")
        self.assertEqual(cfg.for_severity("MEDIUM").runtime, "enable")
        self.assertEqual(cfg.for_severity("LOW").file, "none")

    def test_for_severity_unknown_falls_to_info(self):
        cfg = SkillActionsConfig()
        action = cfg.for_severity("UNKNOWN")
        self.assertEqual(action.runtime, "enable")
        self.assertEqual(action.install, "none")

    def test_for_severity_case_insensitive(self):
        cfg = SkillActionsConfig()
        self.assertEqual(cfg.for_severity("critical").install, "none")

    def test_should_disable(self):
        cfg = SkillActionsConfig()
        self.assertFalse(cfg.should_disable("CRITICAL"))
        self.assertFalse(cfg.should_disable("HIGH"))
        self.assertFalse(cfg.should_disable("MEDIUM"))

    def test_should_quarantine(self):
        cfg = SkillActionsConfig()
        self.assertFalse(cfg.should_quarantine("CRITICAL"))
        self.assertFalse(cfg.should_quarantine("LOW"))

    def test_should_install_block(self):
        cfg = SkillActionsConfig()
        self.assertFalse(cfg.should_install_block("HIGH"))
        self.assertFalse(cfg.should_install_block("INFO"))


class TestMergeFunctions(unittest.TestCase):
    def test_merge_severity_action_none(self):
        sa = _merge_severity_action(None)
        self.assertEqual(sa.file, "none")

    def test_merge_severity_action_partial(self):
        sa = _merge_severity_action({"file": "quarantine"})
        self.assertEqual(sa.file, "quarantine")
        self.assertEqual(sa.runtime, "enable")

    def test_merge_skill_actions_none(self):
        sa = _merge_skill_actions(None)
        self.assertEqual(sa.critical.install, "none")

    def test_merge_skill_actions_override(self):
        sa = _merge_skill_actions({"critical": {"file": "quarantine", "runtime": "disable", "install": "block"}})
        self.assertEqual(sa.critical.install, "block")
        self.assertEqual(sa.high.install, "none")

    def test_merge_plugin_actions_none(self):
        pa = _merge_plugin_actions(None)
        self.assertEqual(pa.critical.file, "none")
        self.assertEqual(pa.critical.runtime, "enable")
        self.assertEqual(pa.critical.install, "none")
        self.assertEqual(pa.medium.file, "none")
        self.assertEqual(pa.medium.runtime, "enable")

    def test_merge_plugin_actions_override(self):
        pa = _merge_plugin_actions({"high": {"file": "quarantine", "runtime": "disable", "install": "block"}})
        self.assertEqual(pa.high.install, "block")
        self.assertEqual(pa.high.file, "quarantine")
        self.assertEqual(pa.critical.install, "none")

    def test_plugin_actions_for_severity(self):
        pa = PluginActionsConfig()
        self.assertEqual(pa.for_severity("CRITICAL").install, "none")
        self.assertFalse(pa.should_disable("HIGH"))
        self.assertFalse(pa.should_quarantine("CRITICAL"))
        self.assertFalse(pa.should_install_block("LOW"))
        self.assertEqual(pa.for_severity("BOGUS").runtime, "enable")

    def test_merge_gateway_watcher_none(self):
        gw = _merge_gateway_watcher(None)
        self.assertTrue(gw.enabled)
        self.assertTrue(gw.skill.enabled)
        self.assertFalse(gw.skill.take_action)

    def test_merge_gateway_watcher_with_data(self):
        gw = _merge_gateway_watcher({"enabled": True, "skill": {"enabled": False, "dirs": ["/tmp"]}})
        self.assertTrue(gw.enabled)
        self.assertFalse(gw.skill.enabled)
        self.assertEqual(gw.skill.dirs, ["/tmp"])

    def test_merge_gateway_watcher_with_plugin(self):
        gw = _merge_gateway_watcher(
            {
                "enabled": True,
                "plugin": {
                    "enabled": False,
                    "take_action": True,
                    "dirs": ["/opt/plugins"],
                },
            }
        )
        self.assertTrue(gw.enabled)
        self.assertFalse(gw.plugin.enabled)
        self.assertTrue(gw.plugin.take_action)
        self.assertEqual(gw.plugin.dirs, ["/opt/plugins"])

        gw_no_plugin = _merge_gateway_watcher({"enabled": True})
        self.assertEqual(gw_no_plugin.plugin, GatewayWatcherPluginConfig())


class TestDefaultConfig(unittest.TestCase):
    def test_default_config_structure(self):
        cfg = default_config()
        self.assertIsInstance(cfg, Config)
        self.assertTrue(cfg.data_dir.endswith(".defenseclaw"))
        self.assertTrue(cfg.audit_db.endswith("audit.db"))
        self.assertEqual(cfg.claw.mode, "openclaw")
        self.assertEqual(cfg.scanners.skill_scanner.binary, "skill-scanner")
        self.assertEqual(cfg.scanners.mcp_scanner.binary, "mcp-scanner")
        self.assertEqual(cfg.gateway.port, 18789)
        self.assertEqual(cfg.gateway.api_bind, "")
        self.assertEqual(cfg.gateway.api_port, 18970)
        self.assertTrue(cfg.gateway.watcher.enabled)
        self.assertTrue(cfg.gateway.watcher.skill.enabled)
        self.assertFalse(cfg.gateway.watcher.skill.take_action)

    def test_default_skill_scanner_config(self):
        cfg = default_config()
        sc = cfg.scanners.skill_scanner
        self.assertFalse(sc.use_llm)
        self.assertFalse(sc.use_behavioral)
        self.assertFalse(sc.enable_meta)
        self.assertFalse(sc.use_trigger)
        self.assertFalse(sc.use_virustotal)
        self.assertFalse(sc.use_aidefense)
        self.assertEqual(sc.llm_consensus_runs, 0)
        self.assertEqual(sc.policy, "permissive")
        self.assertTrue(sc.lenient)

    def test_default_mcp_scanner_config(self):
        cfg = default_config()
        mc = cfg.scanners.mcp_scanner
        self.assertEqual(mc.analyzers, "yara")
        self.assertFalse(mc.scan_prompts)
        self.assertFalse(mc.scan_resources)
        self.assertFalse(mc.scan_instructions)


class TestConfigLoadSave(unittest.TestCase):
    def test_load_missing_config_returns_defaults(self):
        with patch("defenseclaw.config.default_data_path") as mock_dp:
            mock_dp.return_value = Path(tempfile.mkdtemp()) / ".defenseclaw"
            cfg = load()
            self.assertIsInstance(cfg, Config)
            self.assertEqual(cfg.claw.mode, "openclaw")

    def test_save_and_reload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Config(
                data_dir=tmpdir,
                audit_db=os.path.join(tmpdir, "audit.db"),
                quarantine_dir=os.path.join(tmpdir, "quarantine"),
                plugin_dir=os.path.join(tmpdir, "plugins"),
                policy_dir=os.path.join(tmpdir, "policies"),
                environment="macos",
                gateway=GatewayConfig(api_bind="10.0.0.8"),
            )
            cfg.save()

            import yaml
            config_file = os.path.join(tmpdir, "config.yaml")
            self.assertTrue(os.path.exists(config_file))

            with open(config_file) as f:
                raw = yaml.safe_load(f)
            self.assertEqual(raw["environment"], "macos")
            self.assertEqual(raw["data_dir"], tmpdir)
            self.assertEqual(raw["gateway"]["api_bind"], "10.0.0.8")

    def test_save_and_reload_preserves_watch_rescan_fields(self):
        import yaml
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Config(
                data_dir=tmpdir,
                audit_db=os.path.join(tmpdir, "audit.db"),
                quarantine_dir=os.path.join(tmpdir, "quarantine"),
                plugin_dir=os.path.join(tmpdir, "plugins"),
                policy_dir=os.path.join(tmpdir, "policies"),
                environment="linux",
                watch=WatchConfig(
                    debounce_ms=750,
                    auto_block=False,
                    allow_list_bypass_scan=False,
                    rescan_enabled=False,
                    rescan_interval_min=15,
                ),
            )
            cfg.save()

            config_file = os.path.join(tmpdir, "config.yaml")
            with open(config_file) as f:
                raw = yaml.safe_load(f)

            self.assertFalse(raw["watch"]["rescan_enabled"])
            self.assertEqual(raw["watch"]["rescan_interval_min"], 15)

            with patch("defenseclaw.config.default_data_path") as mock_dp:
                mock_dp.return_value = Path(tmpdir)
                loaded = load()

            self.assertFalse(loaded.watch.rescan_enabled)
            self.assertEqual(loaded.watch.rescan_interval_min, 15)


class TestClawPaths(unittest.TestCase):
    def test_claw_home_dir_expands_tilde(self):
        cfg = Config(claw=ClawConfig(home_dir="~/.openclaw"))
        home = cfg.claw_home_dir()
        self.assertFalse(home.startswith("~"))
        self.assertTrue(home.endswith(".openclaw"))

    def test_mcp_servers_from_file(self):
        from defenseclaw.config import _read_mcp_servers_from_file
        with tempfile.TemporaryDirectory() as tmpdir:
            oc_data = {
                "mcp": {
                    "servers": {
                        "test-server": {"command": "npx", "args": ["-y", "test-srv"]},
                        "remote": {"url": "https://example.com/mcp"},
                    }
                }
            }
            oc_json = os.path.join(tmpdir, "openclaw.json")
            with open(oc_json, "w") as f:
                json.dump(oc_data, f)

            servers = _read_mcp_servers_from_file(oc_json)
            self.assertEqual(len(servers), 2)
            by_name = {s.name: s for s in servers}
            self.assertIn("test-server", by_name)
            self.assertEqual(by_name["test-server"].command, "npx")
            self.assertEqual(by_name["remote"].url, "https://example.com/mcp")

    def test_mcp_servers_no_mcp_block(self):
        from defenseclaw.config import _read_mcp_servers_from_file
        with tempfile.TemporaryDirectory() as tmpdir:
            oc_data = {"agents": {"defaults": {}}}
            oc_json = os.path.join(tmpdir, "openclaw.json")
            with open(oc_json, "w") as f:
                json.dump(oc_data, f)

            servers = _read_mcp_servers_from_file(oc_json)
            self.assertEqual(servers, [])

    def test_mcp_servers_missing_file(self):
        from defenseclaw.config import _read_mcp_servers_from_file
        servers = _read_mcp_servers_from_file("/tmp/nonexistent/openclaw.json")
        self.assertEqual(servers, [])

    def test_parse_mcp_servers_dict(self):
        from defenseclaw.config import _parse_mcp_servers_dict
        servers = _parse_mcp_servers_dict({
            "srv-a": {"command": "npx", "args": ["-y", "srv"]},
            "srv-b": {"url": "https://example.com", "transport": "sse"},
        })
        self.assertEqual(len(servers), 2)
        by_name = {s.name: s for s in servers}
        self.assertEqual(by_name["srv-b"].transport, "sse")

    def test_skill_dirs_no_openclaw_json(self):
        cfg = Config(claw=ClawConfig(
            home_dir="/tmp/nonexistent-oc",
            config_file="/tmp/nonexistent-oc/openclaw.json",
        ))
        dirs = cfg.skill_dirs()
        workspace = os.path.join("/tmp/nonexistent-oc", "workspace", "skills")
        expected = os.path.join("/tmp/nonexistent-oc", "skills")
        self.assertIn(workspace, dirs)
        self.assertIn(expected, dirs)

    def test_skill_dirs_with_openclaw_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = os.path.join(tmpdir, "project-workspace")
            oc_data = {
                "agents": {"defaults": {"workspace": workspace}},
                "skills": {"load": {"extraDirs": ["/tmp/extra-skills"]}},
            }
            oc_json = os.path.join(tmpdir, "openclaw.json")
            with open(oc_json, "w") as f:
                json.dump(oc_data, f)

            cfg = Config(claw=ClawConfig(
                home_dir=tmpdir,
                config_file=oc_json,
            ))
            dirs = cfg.skill_dirs()
            self.assertIn(os.path.join(workspace, "skills"), dirs)
            self.assertIn(os.path.join(tmpdir, "skills"), dirs)
            self.assertIn("/tmp/extra-skills", dirs)

    def test_plugin_dirs(self):
        cfg = Config(claw=ClawConfig(home_dir="/tmp/test-oc"))
        dirs = cfg.plugin_dirs()
        self.assertEqual(len(dirs), 1)
        self.assertEqual(dirs[0], os.path.join("/tmp/test-oc", "extensions"))

    def test_installed_skill_candidates(self):
        cfg = Config(claw=ClawConfig(
            home_dir="/tmp/test-oc",
            config_file="/tmp/nonexistent/openclaw.json",
        ))
        candidates = cfg.installed_skill_candidates("my-skill")
        self.assertTrue(all(c.endswith("my-skill") for c in candidates))

    def test_installed_skill_candidates_strips_prefix(self):
        cfg = Config(claw=ClawConfig(
            home_dir="/tmp/test-oc",
            config_file="/tmp/nonexistent/openclaw.json",
        ))
        candidates = cfg.installed_skill_candidates("@org/my-skill")
        self.assertTrue(all(c.endswith("my-skill") for c in candidates))


class TestInspectLLMConfig(unittest.TestCase):
    def test_defaults(self):
        llm = InspectLLMConfig()
        self.assertEqual(llm.provider, "")
        self.assertEqual(llm.model, "")
        self.assertEqual(llm.api_key, "")
        self.assertEqual(llm.api_key_env, "")
        self.assertEqual(llm.timeout, 30)
        self.assertEqual(llm.max_retries, 3)

    def test_resolved_api_key_direct(self):
        llm = InspectLLMConfig(api_key="direct-key")
        self.assertEqual(llm.resolved_api_key(), "direct-key")

    def test_resolved_api_key_from_env(self):
        llm = InspectLLMConfig(api_key="fallback", api_key_env="TEST_LLM_KEY_XYZ")
        os.environ["TEST_LLM_KEY_XYZ"] = "env-key"
        try:
            self.assertEqual(llm.resolved_api_key(), "env-key")
        finally:
            del os.environ["TEST_LLM_KEY_XYZ"]

    def test_resolved_api_key_env_takes_precedence(self):
        """When both api_key and api_key_env are set and the env var exists, env wins."""
        llm = InspectLLMConfig(api_key="direct", api_key_env="TEST_LLM_KEY_PREC")
        os.environ["TEST_LLM_KEY_PREC"] = "from-env"
        try:
            self.assertEqual(llm.resolved_api_key(), "from-env")
        finally:
            del os.environ["TEST_LLM_KEY_PREC"]

    def test_resolved_api_key_env_unset_falls_back(self):
        """When api_key_env is set but the env var doesn't exist, fall back to api_key."""
        llm = InspectLLMConfig(api_key="fallback", api_key_env="TEST_LLM_NONEXISTENT_XYZ")
        os.environ.pop("TEST_LLM_NONEXISTENT_XYZ", None)
        self.assertEqual(llm.resolved_api_key(), "fallback")

    def test_resolved_api_key_empty(self):
        llm = InspectLLMConfig()
        self.assertEqual(llm.resolved_api_key(), "")


class TestCiscoAIDefenseConfig(unittest.TestCase):
    def test_defaults(self):
        aid = CiscoAIDefenseConfig()
        self.assertEqual(aid.endpoint, "https://us.api.inspect.aidefense.security.cisco.com")
        self.assertEqual(aid.api_key, "")
        self.assertEqual(aid.api_key_env, "")
        self.assertEqual(aid.timeout_ms, 3000)
        self.assertEqual(aid.enabled_rules, [])

    def test_resolved_api_key_direct(self):
        aid = CiscoAIDefenseConfig(api_key="cisco-key", api_key_env="")
        self.assertEqual(aid.resolved_api_key(), "cisco-key")

    def test_resolved_api_key_from_env(self):
        aid = CiscoAIDefenseConfig(api_key="fallback", api_key_env="TEST_CISCO_KEY_XYZ")
        os.environ["TEST_CISCO_KEY_XYZ"] = "env-cisco-key"
        try:
            self.assertEqual(aid.resolved_api_key(), "env-cisco-key")
        finally:
            del os.environ["TEST_CISCO_KEY_XYZ"]

    def test_resolved_api_key_no_env_no_direct(self):
        aid = CiscoAIDefenseConfig(api_key_env="")
        self.assertEqual(aid.resolved_api_key(), "")


class TestMergeInspectLLM(unittest.TestCase):
    def test_none_returns_defaults(self):
        llm = _merge_inspect_llm(None)
        self.assertEqual(llm.provider, "")
        self.assertEqual(llm.timeout, 30)

    def test_partial_override(self):
        llm = _merge_inspect_llm({"provider": "openai", "model": "gpt-4o"})
        self.assertEqual(llm.provider, "openai")
        self.assertEqual(llm.model, "gpt-4o")
        self.assertEqual(llm.api_key, "")
        self.assertEqual(llm.timeout, 30)

    def test_full_override(self):
        llm = _merge_inspect_llm({
            "provider": "anthropic",
            "model": "claude-sonnet-4-20250514",
            "api_key": "sk-123",
            "api_key_env": "MY_KEY",
            "base_url": "https://custom.api",
            "timeout": 60,
            "max_retries": 5,
        })
        self.assertEqual(llm.provider, "anthropic")
        self.assertEqual(llm.api_key, "sk-123")
        self.assertEqual(llm.timeout, 60)
        self.assertEqual(llm.max_retries, 5)


class TestMergeCiscoAIDefense(unittest.TestCase):
    def test_none_returns_defaults(self):
        aid = _merge_cisco_ai_defense(None)
        self.assertIn("aidefense.security.cisco.com", aid.endpoint)
        self.assertEqual(aid.api_key_env, "")
        self.assertEqual(aid.timeout_ms, 3000)

    def test_override(self):
        aid = _merge_cisco_ai_defense({
            "endpoint": "https://eu.api.example.com",
            "api_key": "aid-key-123",
            "timeout_ms": 5000,
            "enabled_rules": ["rule1", "rule2"],
        })
        self.assertEqual(aid.endpoint, "https://eu.api.example.com")
        self.assertEqual(aid.api_key, "aid-key-123")
        self.assertEqual(aid.timeout_ms, 5000)
        self.assertEqual(aid.enabled_rules, ["rule1", "rule2"])


class TestMergeMCPScannerClean(unittest.TestCase):
    """Verify MCPScannerConfig no longer has LLM or AI Defense fields."""

    def test_no_llm_fields(self):
        cfg = MCPScannerConfig()
        self.assertFalse(hasattr(cfg, "llm_provider"))
        self.assertFalse(hasattr(cfg, "llm_api_key"))
        self.assertFalse(hasattr(cfg, "llm_model"))
        self.assertFalse(hasattr(cfg, "api_key"))
        self.assertFalse(hasattr(cfg, "endpoint_url"))

    def test_merge_mcp_scanner_ignores_old_fields(self):
        cfg = _merge_mcp_scanner({
            "binary": "mcp-scanner",
            "analyzers": "yara",
            "llm_provider": "openai",
            "api_key": "stale-key",
        })
        self.assertEqual(cfg.binary, "mcp-scanner")
        self.assertEqual(cfg.analyzers, "yara")
        self.assertFalse(hasattr(cfg, "llm_provider"))
        self.assertFalse(hasattr(cfg, "api_key"))


class TestSkillScannerConfigClean(unittest.TestCase):
    """Verify SkillScannerConfig no longer has LLM or AI Defense fields."""

    def test_no_llm_fields(self):
        cfg = SkillScannerConfig()
        self.assertFalse(hasattr(cfg, "llm_provider"))
        self.assertFalse(hasattr(cfg, "llm_model"))
        self.assertFalse(hasattr(cfg, "llm_api_key"))
        self.assertFalse(hasattr(cfg, "aidefense_api_key"))

    def test_scanner_specific_fields_remain(self):
        cfg = SkillScannerConfig(
            use_llm=True, use_behavioral=True,
            llm_consensus_runs=3, policy="strict",
            virustotal_api_key="vt-key",
        )
        self.assertTrue(cfg.use_llm)
        self.assertTrue(cfg.use_behavioral)
        self.assertEqual(cfg.llm_consensus_runs, 3)
        self.assertEqual(cfg.policy, "strict")
        self.assertEqual(cfg.virustotal_api_key, "vt-key")


class TestConfigTopLevelSections(unittest.TestCase):
    def test_default_config_has_inspect_llm(self):
        cfg = default_config()
        self.assertIsInstance(cfg.inspect_llm, InspectLLMConfig)
        self.assertEqual(cfg.inspect_llm.timeout, 30)

    def test_default_config_has_cisco_ai_defense(self):
        cfg = default_config()
        self.assertIsInstance(cfg.cisco_ai_defense, CiscoAIDefenseConfig)
        self.assertIn("aidefense.security.cisco.com", cfg.cisco_ai_defense.endpoint)

    def test_save_and_reload_preserves_new_sections(self):
        import yaml
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Config(
                data_dir=tmpdir,
                audit_db=os.path.join(tmpdir, "audit.db"),
                quarantine_dir=os.path.join(tmpdir, "quarantine"),
                plugin_dir=os.path.join(tmpdir, "plugins"),
                policy_dir=os.path.join(tmpdir, "policies"),
                environment="macos",
                inspect_llm=InspectLLMConfig(
                    provider="anthropic",
                    model="claude-sonnet-4-20250514",
                    api_key="sk-test-123",
                    timeout=45,
                ),
                cisco_ai_defense=CiscoAIDefenseConfig(
                    endpoint="https://eu.api.example.com",
                    api_key="aid-456",
                    timeout_ms=5000,
                ),
            )
            cfg.save()

            with open(os.path.join(tmpdir, "config.yaml")) as f:
                raw = yaml.safe_load(f)

            self.assertEqual(raw["inspect_llm"]["provider"], "anthropic")
            self.assertEqual(raw["inspect_llm"]["model"], "claude-sonnet-4-20250514")
            self.assertEqual(raw["inspect_llm"]["api_key"], "sk-test-123")
            self.assertEqual(raw["inspect_llm"]["timeout"], 45)

            self.assertEqual(raw["cisco_ai_defense"]["endpoint"], "https://eu.api.example.com")
            self.assertEqual(raw["cisco_ai_defense"]["api_key"], "aid-456")
            self.assertEqual(raw["cisco_ai_defense"]["timeout_ms"], 5000)

    def test_save_and_reload_guardrail_openshell(self):
        import yaml
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Config(
                data_dir=tmpdir,
                audit_db=os.path.join(tmpdir, "audit.db"),
                quarantine_dir=os.path.join(tmpdir, "quarantine"),
                plugin_dir=os.path.join(tmpdir, "plugins"),
                policy_dir=os.path.join(tmpdir, "policies"),
                environment="linux",
                guardrail=GuardrailConfig(host="10.200.0.1"),
                openshell=OpenShellConfig(mode="standalone"),
            )
            cfg.save()

            config_file = os.path.join(tmpdir, "config.yaml")
            with open(config_file) as f:
                raw = yaml.safe_load(f)
            self.assertEqual(raw["guardrail"]["host"], "10.200.0.1")
            self.assertEqual(raw["openshell"]["mode"], "standalone")

    def test_load_reads_new_sections(self):
        import yaml
        with tempfile.TemporaryDirectory() as tmpdir:
            config_data = {
                "data_dir": tmpdir,
                "inspect_llm": {
                    "provider": "openai",
                    "model": "gpt-4o",
                    "api_key": "sk-openai-key",
                    "timeout": 60,
                },
                "cisco_ai_defense": {
                    "endpoint": "https://custom.endpoint.com",
                    "api_key": "custom-cisco-key",
                    "timeout_ms": 10000,
                    "enabled_rules": ["rule-a"],
                },
            }
            with open(os.path.join(tmpdir, "config.yaml"), "w") as f:
                yaml.dump(config_data, f)

            with patch("defenseclaw.config.default_data_path") as mock_dp:
                mock_dp.return_value = Path(tmpdir)
                cfg = load()

            self.assertEqual(cfg.inspect_llm.provider, "openai")
            self.assertEqual(cfg.inspect_llm.model, "gpt-4o")
            self.assertEqual(cfg.inspect_llm.api_key, "sk-openai-key")
            self.assertEqual(cfg.inspect_llm.timeout, 60)

            self.assertEqual(cfg.cisco_ai_defense.endpoint, "https://custom.endpoint.com")
            self.assertEqual(cfg.cisco_ai_defense.api_key, "custom-cisco-key")
            self.assertEqual(cfg.cisco_ai_defense.timeout_ms, 10000)
            self.assertEqual(cfg.cisco_ai_defense.enabled_rules, ["rule-a"])

    def test_load_without_new_sections_uses_defaults(self):
        import yaml
        with tempfile.TemporaryDirectory() as tmpdir:
            config_data = {"data_dir": tmpdir, "environment": "linux"}
            with open(os.path.join(tmpdir, "config.yaml"), "w") as f:
                yaml.dump(config_data, f)

            with patch("defenseclaw.config.default_data_path") as mock_dp:
                mock_dp.return_value = Path(tmpdir)
                cfg = load()

            self.assertEqual(cfg.inspect_llm.provider, "")
            self.assertEqual(cfg.inspect_llm.timeout, 30)
            self.assertIn("aidefense.security.cisco.com", cfg.cisco_ai_defense.endpoint)

    def test_guardrail_config_has_no_cisco_ai_defense(self):
        """GuardrailConfig no longer nests CiscoAIDefenseConfig."""
        from defenseclaw.config import GuardrailConfig
        gc = GuardrailConfig()
        self.assertFalse(hasattr(gc, "cisco_ai_defense"))


class TestGatewayResolvedToken(unittest.TestCase):
    def test_empty_token_env_reads_openclaw_env(self):
        gw = GatewayConfig(token_env="", token="")
        with patch.dict(os.environ, {"OPENCLAW_GATEWAY_TOKEN": "t1"}, clear=False):
            self.assertEqual(gw.resolved_token(), "t1")

    def test_custom_token_env_takes_precedence(self):
        gw = GatewayConfig(token_env="MY_TOK", token="inline")
        env = {"MY_TOK": "from-env", "OPENCLAW_GATEWAY_TOKEN": "other"}
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(gw.resolved_token(), "from-env")

    def test_custom_token_env_empty_ignores_openclaw_env(self):
        gw = GatewayConfig(token_env="MY_TOK", token="fallback")
        env = {"OPENCLAW_GATEWAY_TOKEN": "other"}
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(gw.resolved_token(), "fallback")


class TestGuardrailHostField(unittest.TestCase):
    def test_default_guardrail_host(self):
        gc = GuardrailConfig()
        self.assertEqual(gc.host, "localhost")

    def test_merge_guardrail_host_from_yaml(self):
        gc = _merge_guardrail({"host": "10.200.0.1"}, "/tmp")
        self.assertEqual(gc.host, "10.200.0.1")

    def test_merge_guardrail_host_default(self):
        gc = _merge_guardrail({}, "/tmp")
        self.assertEqual(gc.host, "localhost")

    def test_merge_guardrail_none(self):
        gc = _merge_guardrail(None, "/tmp")
        self.assertEqual(gc.host, "localhost")


class TestOpenShellModeField(unittest.TestCase):
    def test_default_mode_empty(self):
        oc = OpenShellConfig()
        self.assertEqual(oc.mode, "")

    def test_mode_from_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            import yaml
            cfg_data = {
                "openshell": {"mode": "standalone"},
            }
            cfg_file = os.path.join(tmpdir, "config.yaml")
            with open(cfg_file, "w") as f:
                yaml.dump(cfg_data, f)

            with patch("defenseclaw.config.default_data_path") as mock_dp:
                mock_dp.return_value = Path(tmpdir)
                cfg = load()
                self.assertEqual(cfg.openshell.mode, "standalone")


class TestOpenShellSandboxFields(unittest.TestCase):
    def test_default_version(self):
        oc = OpenShellConfig()
        self.assertEqual(oc.version, DEFAULT_OPENSHELL_VERSION)
        self.assertEqual(oc.effective_version(), DEFAULT_OPENSHELL_VERSION)

    def test_custom_version(self):
        oc = OpenShellConfig(version="0.7.0")
        self.assertEqual(oc.effective_version(), "0.7.0")

    def test_default_sandbox_home(self):
        oc = OpenShellConfig()
        self.assertEqual(oc.sandbox_home, DEFAULT_SANDBOX_HOME)
        self.assertEqual(oc.effective_sandbox_home(), DEFAULT_SANDBOX_HOME)

    def test_custom_sandbox_home(self):
        oc = OpenShellConfig(sandbox_home="/opt/sandbox")
        self.assertEqual(oc.effective_sandbox_home(), "/opt/sandbox")

    def test_is_standalone(self):
        self.assertFalse(OpenShellConfig().is_standalone())
        self.assertTrue(OpenShellConfig(mode="standalone").is_standalone())
        self.assertFalse(OpenShellConfig(mode="cluster").is_standalone())

    def test_auto_pair_default(self):
        oc = OpenShellConfig()
        self.assertTrue(oc.should_auto_pair())

    def test_auto_pair_explicit_true(self):
        oc = OpenShellConfig(auto_pair=True)
        self.assertTrue(oc.should_auto_pair())

    def test_auto_pair_explicit_false(self):
        oc = OpenShellConfig(auto_pair=False)
        self.assertFalse(oc.should_auto_pair())

    def test_merge_openshell_none(self):
        oc = _merge_openshell(None)
        self.assertEqual(oc.version, DEFAULT_OPENSHELL_VERSION)
        self.assertEqual(oc.sandbox_home, DEFAULT_SANDBOX_HOME)
        self.assertIsNone(oc.auto_pair)

    def test_merge_openshell_with_data(self):
        oc = _merge_openshell({
            "mode": "standalone",
            "version": "0.7.0",
            "sandbox_home": "/opt/sandbox",
            "auto_pair": False,
        })
        self.assertEqual(oc.mode, "standalone")
        self.assertEqual(oc.version, "0.7.0")
        self.assertEqual(oc.sandbox_home, "/opt/sandbox")
        self.assertFalse(oc.auto_pair)

    def test_load_openshell_sandbox_fields(self):
        import yaml
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_data = {
                "openshell": {
                    "mode": "standalone",
                    "version": "0.7.0",
                    "sandbox_home": "/opt/sandbox",
                    "auto_pair": False,
                },
            }
            with open(os.path.join(tmpdir, "config.yaml"), "w") as f:
                yaml.dump(cfg_data, f)

            with patch("defenseclaw.config.default_data_path") as mock_dp:
                mock_dp.return_value = Path(tmpdir)
                cfg = load()
                self.assertEqual(cfg.openshell.mode, "standalone")
                self.assertEqual(cfg.openshell.version, "0.7.0")
                self.assertEqual(cfg.openshell.sandbox_home, "/opt/sandbox")
                self.assertFalse(cfg.openshell.auto_pair)


class TestWebhookConfig(unittest.TestCase):
    """Tests for WebhookConfig, _merge_webhooks, and resolved_secret."""

    def test_merge_valid_yaml(self):
        raw = [
            {
                "url": "https://hooks.slack.com/services/T/B/xxx",
                "type": "slack",
                "secret_env": "SLACK_TOKEN",
                "min_severity": "MEDIUM",
                "events": ["block", "drift"],
                "timeout_seconds": 15,
                "enabled": True,
            },
            {
                "url": "https://pd.example.com",
                "type": "pagerduty",
                "enabled": False,
            },
        ]
        result = _merge_webhooks(raw)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].url, "https://hooks.slack.com/services/T/B/xxx")
        self.assertEqual(result[0].type, "slack")
        self.assertEqual(result[0].min_severity, "MEDIUM")
        self.assertEqual(result[0].events, ["block", "drift"])
        self.assertEqual(result[0].timeout_seconds, 15)
        self.assertTrue(result[0].enabled)
        self.assertFalse(result[1].enabled)

    def test_merge_empty_and_none(self):
        self.assertEqual(_merge_webhooks(None), [])
        self.assertEqual(_merge_webhooks([]), [])

    def test_merge_skips_non_dict(self):
        result = _merge_webhooks(["not-a-dict", 42, None])
        self.assertEqual(result, [])

    def test_merge_defaults(self):
        result = _merge_webhooks([{}])
        self.assertEqual(len(result), 1)
        wh = result[0]
        self.assertEqual(wh.url, "")
        self.assertEqual(wh.type, "generic")
        self.assertEqual(wh.min_severity, "HIGH")
        self.assertEqual(wh.timeout_seconds, 10)
        self.assertEqual(wh.cooldown_seconds, 300)
        self.assertFalse(wh.enabled)

    def test_resolved_secret_from_env(self):
        wh = WebhookConfig(secret_env="TEST_WH_SECRET_42")
        with patch.dict(os.environ, {"TEST_WH_SECRET_42": "s3cret"}):
            self.assertEqual(wh.resolved_secret(), "s3cret")

    def test_resolved_secret_missing_env(self):
        wh = WebhookConfig(secret_env="NONEXISTENT_VAR_99")
        env = os.environ.copy()
        env.pop("NONEXISTENT_VAR_99", None)
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(wh.resolved_secret(), "")

    def test_resolved_secret_no_env_configured(self):
        wh = WebhookConfig()
        self.assertEqual(wh.resolved_secret(), "")

    def test_roundtrip_preservation(self):
        """Ensure load() preserves webhooks from YAML so init doesn't drop them."""
        import yaml

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_data = {
                "webhooks": [
                    {
                        "url": "https://hooks.example.com/abc",
                        "type": "generic",
                        "enabled": True,
                        "min_severity": "LOW",
                    }
                ],
            }
            with open(os.path.join(tmpdir, "config.yaml"), "w") as f:
                yaml.dump(cfg_data, f)

            with patch("defenseclaw.config.default_data_path") as mock_dp:
                mock_dp.return_value = Path(tmpdir)
                cfg = load()
                self.assertEqual(len(cfg.webhooks), 1)
                self.assertEqual(cfg.webhooks[0].url, "https://hooks.example.com/abc")
                self.assertTrue(cfg.webhooks[0].enabled)
                self.assertEqual(cfg.webhooks[0].min_severity, "LOW")


if __name__ == "__main__":
    unittest.main()
