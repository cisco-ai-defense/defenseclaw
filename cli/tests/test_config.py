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
    Config,
    ClawConfig,
    GatewayConfig,
    GatewayWatcherConfig,
    GatewayWatcherSkillConfig,
    SeverityAction,
    SkillActionsConfig,
    _dedup,
    _expand,
    _merge_gateway_watcher,
    _merge_severity_action,
    _merge_skill_actions,
    default_config,
    default_data_path,
    config_path,
    detect_environment,
    load,
)


class TestHelpers(unittest.TestCase):
    def test_expand_tilde(self):
        result = _expand("~/foo/bar")
        self.assertTrue(result.endswith("foo/bar"))
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
        self.assertEqual(cfg.for_severity("CRITICAL").install, "block")
        self.assertEqual(cfg.for_severity("HIGH").runtime, "disable")
        self.assertEqual(cfg.for_severity("MEDIUM").runtime, "enable")
        self.assertEqual(cfg.for_severity("LOW").file, "none")

    def test_for_severity_unknown_falls_to_info(self):
        cfg = SkillActionsConfig()
        action = cfg.for_severity("UNKNOWN")
        self.assertEqual(action.runtime, "enable")
        self.assertEqual(action.install, "none")

    def test_for_severity_case_insensitive(self):
        cfg = SkillActionsConfig()
        self.assertEqual(cfg.for_severity("critical").install, "block")

    def test_should_disable(self):
        cfg = SkillActionsConfig()
        self.assertTrue(cfg.should_disable("CRITICAL"))
        self.assertTrue(cfg.should_disable("HIGH"))
        self.assertFalse(cfg.should_disable("MEDIUM"))

    def test_should_quarantine(self):
        cfg = SkillActionsConfig()
        self.assertTrue(cfg.should_quarantine("CRITICAL"))
        self.assertFalse(cfg.should_quarantine("LOW"))

    def test_should_install_block(self):
        cfg = SkillActionsConfig()
        self.assertTrue(cfg.should_install_block("HIGH"))
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
        self.assertEqual(sa.critical.install, "block")

    def test_merge_skill_actions_override(self):
        sa = _merge_skill_actions({"critical": {"file": "none", "runtime": "enable", "install": "allow"}})
        self.assertEqual(sa.critical.install, "allow")
        self.assertEqual(sa.high.install, "block")

    def test_merge_gateway_watcher_none(self):
        gw = _merge_gateway_watcher(None)
        self.assertFalse(gw.enabled)
        self.assertTrue(gw.skill.enabled)

    def test_merge_gateway_watcher_with_data(self):
        gw = _merge_gateway_watcher({"enabled": True, "skill": {"enabled": False, "dirs": ["/tmp"]}})
        self.assertTrue(gw.enabled)
        self.assertFalse(gw.skill.enabled)
        self.assertEqual(gw.skill.dirs, ["/tmp"])


class TestDefaultConfig(unittest.TestCase):
    def test_default_config_structure(self):
        cfg = default_config()
        self.assertIsInstance(cfg, Config)
        self.assertTrue(cfg.data_dir.endswith(".defenseclaw"))
        self.assertTrue(cfg.audit_db.endswith("audit.db"))
        self.assertEqual(cfg.claw.mode, "openclaw")
        self.assertEqual(cfg.scanners.skill_scanner.binary, "skill-scanner")
        self.assertEqual(cfg.scanners.mcp_scanner, "mcp-scanner")
        self.assertEqual(cfg.gateway.port, 18789)


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
            )
            cfg.save()

            import yaml
            config_file = os.path.join(tmpdir, "config.yaml")
            self.assertTrue(os.path.exists(config_file))

            with open(config_file) as f:
                raw = yaml.safe_load(f)
            self.assertEqual(raw["environment"], "macos")
            self.assertEqual(raw["data_dir"], tmpdir)


class TestClawPaths(unittest.TestCase):
    def test_claw_home_dir_expands_tilde(self):
        cfg = Config(claw=ClawConfig(home_dir="~/.openclaw"))
        home = cfg.claw_home_dir()
        self.assertFalse(home.startswith("~"))
        self.assertTrue(home.endswith(".openclaw"))

    def test_mcp_dirs(self):
        cfg = Config(claw=ClawConfig(home_dir="/tmp/test-oc"))
        dirs = cfg.mcp_dirs()
        self.assertEqual(len(dirs), 2)
        self.assertIn("/tmp/test-oc/mcp-servers", dirs)
        self.assertIn("/tmp/test-oc/mcps", dirs)

    def test_skill_dirs_no_openclaw_json(self):
        cfg = Config(claw=ClawConfig(
            home_dir="/tmp/nonexistent-oc",
            config_file="/tmp/nonexistent-oc/openclaw.json",
        ))
        dirs = cfg.skill_dirs()
        self.assertIn("/tmp/nonexistent-oc/skills", dirs)

    def test_skill_dirs_with_openclaw_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            oc_data = {
                "agents": {"defaults": {"workspace": tmpdir}},
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
            self.assertIn(os.path.join(tmpdir, "skills"), dirs)
            self.assertIn("/tmp/extra-skills", dirs)
            self.assertIn(os.path.join(tmpdir, "skills"), dirs)

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


if __name__ == "__main__":
    unittest.main()
