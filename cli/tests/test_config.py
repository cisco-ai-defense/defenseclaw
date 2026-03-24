"""Tests for defenseclaw.config — defaults, environment detection, save/load, skill actions."""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import (
    Config,
    SkillActionsConfig,
    SkillScannerConfig,
    SeverityAction,
    default_config,
    detect_environment,
    load,
    _dedup,
)


class TestDetectEnvironment(unittest.TestCase):
    @patch("defenseclaw.config.platform.system", return_value="Darwin")
    def test_detects_macos(self, _mock):
        self.assertEqual(detect_environment(), "macos")

    @patch("defenseclaw.config.platform.system", return_value="Linux")
    @patch("defenseclaw.config.Path.exists", return_value=True)
    def test_detects_dgx_via_release_file(self, _path, _sys):
        self.assertEqual(detect_environment(), "dgx-spark")

    @patch("defenseclaw.config.platform.system", return_value="Linux")
    @patch("defenseclaw.config.Path.exists", return_value=False)
    @patch("defenseclaw.config.subprocess.check_output", side_effect=FileNotFoundError)
    def test_fallback_to_linux(self, _sub, _path, _sys):
        self.assertEqual(detect_environment(), "linux")


class TestDefaultConfig(unittest.TestCase):
    def test_has_expected_paths(self):
        cfg = default_config()
        self.assertTrue(cfg.data_dir.endswith(".defenseclaw"))
        self.assertTrue(cfg.audit_db.endswith("audit.db"))
        self.assertTrue(cfg.quarantine_dir.endswith("quarantine"))
        self.assertTrue(cfg.plugin_dir.endswith("plugins"))
        self.assertTrue(cfg.policy_dir.endswith("policies"))

    def test_claw_mode_defaults_to_openclaw(self):
        cfg = default_config()
        self.assertEqual(cfg.claw.mode, "openclaw")

    def test_scanners_have_defaults(self):
        cfg = default_config()
        self.assertEqual(cfg.scanners.skill_scanner.binary, "skill-scanner")
        self.assertEqual(cfg.scanners.mcp_scanner, "mcp-scanner")
        self.assertEqual(cfg.scanners.aibom, "cisco-aibom")


class TestConfigSaveLoad(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-cfg-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def test_save_then_load_roundtrip(self):
        cfg = default_config()
        cfg.data_dir = self.tmp_dir
        cfg.audit_db = os.path.join(self.tmp_dir, "audit.db")
        cfg.save()

        config_file = os.path.join(self.tmp_dir, "config.yaml")
        self.assertTrue(os.path.isfile(config_file))

        with patch("defenseclaw.config.default_data_path", return_value=type(os)("").__class__(self.tmp_dir)):
            from pathlib import Path
            with patch("defenseclaw.config.default_data_path", return_value=Path(self.tmp_dir)):
                loaded = load()
        self.assertEqual(loaded.data_dir, self.tmp_dir)
        self.assertEqual(loaded.claw.mode, "openclaw")


class TestSkillActionsConfig(unittest.TestCase):
    def test_critical_defaults_to_quarantine_and_block(self):
        sa = SkillActionsConfig()
        action = sa.for_severity("CRITICAL")
        self.assertEqual(action.file, "quarantine")
        self.assertEqual(action.runtime, "disable")
        self.assertEqual(action.install, "block")

    def test_high_defaults_to_quarantine_and_block(self):
        sa = SkillActionsConfig()
        action = sa.for_severity("HIGH")
        self.assertEqual(action.file, "quarantine")
        self.assertEqual(action.runtime, "disable")
        self.assertEqual(action.install, "block")

    def test_medium_defaults_to_none(self):
        sa = SkillActionsConfig()
        action = sa.for_severity("MEDIUM")
        self.assertEqual(action.file, "none")
        self.assertEqual(action.runtime, "enable")
        self.assertEqual(action.install, "none")

    def test_should_disable_critical(self):
        sa = SkillActionsConfig()
        self.assertTrue(sa.should_disable("CRITICAL"))
        self.assertTrue(sa.should_disable("HIGH"))
        self.assertFalse(sa.should_disable("MEDIUM"))
        self.assertFalse(sa.should_disable("LOW"))

    def test_should_quarantine(self):
        sa = SkillActionsConfig()
        self.assertTrue(sa.should_quarantine("CRITICAL"))
        self.assertTrue(sa.should_quarantine("HIGH"))
        self.assertFalse(sa.should_quarantine("MEDIUM"))

    def test_should_install_block(self):
        sa = SkillActionsConfig()
        self.assertTrue(sa.should_install_block("CRITICAL"))
        self.assertTrue(sa.should_install_block("HIGH"))
        self.assertFalse(sa.should_install_block("LOW"))

    def test_unknown_severity_falls_back_to_info(self):
        sa = SkillActionsConfig()
        action = sa.for_severity("UNKNOWN")
        self.assertEqual(action.file, "none")
        self.assertEqual(action.runtime, "enable")


class TestConfigPaths(unittest.TestCase):
    def test_installed_skill_candidates(self):
        cfg = default_config()
        candidates = cfg.installed_skill_candidates("my-skill")
        self.assertTrue(len(candidates) > 0)
        self.assertTrue(all("my-skill" in c for c in candidates))

    def test_installed_skill_candidates_strips_prefix(self):
        cfg = default_config()
        candidates = cfg.installed_skill_candidates("@org/my-skill")
        self.assertTrue(all("my-skill" in c for c in candidates))

    def test_mcp_dirs(self):
        cfg = default_config()
        dirs = cfg.mcp_dirs()
        self.assertEqual(len(dirs), 2)
        self.assertTrue(any("mcp-servers" in d for d in dirs))
        self.assertTrue(any("mcps" in d for d in dirs))


class TestHelpers(unittest.TestCase):
    def test_dedup_preserves_order(self):
        self.assertEqual(_dedup(["/a", "/b", "/a", "/c"]), ["/a", "/b", "/c"])

    def test_dedup_empty(self):
        self.assertEqual(_dedup([]), [])


if __name__ == "__main__":
    unittest.main()
