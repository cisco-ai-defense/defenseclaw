"""Tests for 'defenseclaw init' command."""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_init import init_cmd
from defenseclaw.context import AppContext


class TestInitCommand(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-test-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_help(self):
        result = self.runner.invoke(init_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Initialize DefenseClaw environment", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_skip_install_creates_dirs(self, mock_path, _mock_env, mock_scanners, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.assertIn("Environment:", result.output)
        self.assertIn("Directories: created", result.output)
        self.assertIn("Config:", result.output)
        self.assertIn("Audit DB:", result.output)

        # Verify config file was created
        config_file = os.path.join(self.tmp_dir, "config.yaml")
        self.assertTrue(os.path.isfile(config_file))

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_logs_action(self, mock_path, _mock_env, mock_scanners, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        # The DB should have at least one event (the init action)
        from defenseclaw.db import Store
        db_path = os.path.join(self.tmp_dir, "audit.db")
        store = Store(db_path)
        events = store.list_events(10)
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0].action, "init")
        store.close()

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_shows_openshell_macos_message(self, mock_path, _mock_env, mock_scanners, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.assertIn("not available on macOS", result.output)


class TestInstallScanners(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value="/usr/local/bin/uv")
    @patch("defenseclaw.commands.cmd_init._install_with_uv", return_value=True)
    def test_install_scanners_installs_missing(self, mock_install, mock_which):
        from defenseclaw.commands.cmd_init import _install_scanners
        from defenseclaw.config import default_config

        cfg = default_config()
        logger = MagicMock()

        def which_side_effect(binary):
            if binary == "uv":
                return "/usr/local/bin/uv"
            return None

        mock_which.side_effect = which_side_effect

        # Should not raise
        _install_scanners(cfg, logger, skip=False)
        self.assertTrue(mock_install.called)

    def test_install_scanners_skip(self):
        from defenseclaw.commands.cmd_init import _install_scanners
        from defenseclaw.config import default_config
        cfg = default_config()
        logger = MagicMock()

        # skip=True should print skip message without calling install
        _install_scanners(cfg, logger, skip=True)
        logger.log_action.assert_not_called()


if __name__ == "__main__":
    unittest.main()
