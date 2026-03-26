import os
import unittest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner


class CliSmokeTests(unittest.TestCase):
    def test_main_import_no_circular_dependency(self):
        import defenseclaw.main as main_mod
        self.assertTrue(hasattr(main_mod, "cli"))

    def test_top_level_help_works_without_init(self):
        from defenseclaw.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Usage:", result.output)
        self.assertIn("Commands:", result.output)
        self.assertIn("init", result.output)
        self.assertIn("skill", result.output)

    def test_init_help_works(self):
        from defenseclaw.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Initialize DefenseClaw environment", result.output)

    def test_setup_splunk_local_bootstraps_clean_home(self):
        from defenseclaw.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            data_dir = Path(os.getcwd()) / ".defenseclaw"
            with patch("defenseclaw.config.default_data_path", return_value=data_dir):
                result = runner.invoke(
                    cli,
                    ["setup", "splunk-local", "--non-interactive", "--no-bootstrap-bridge"],
                )
            config_exists = (data_dir / "config.yaml").is_file()
            audit_db_exists = (data_dir / "audit.db").is_file()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(config_exists)
        self.assertTrue(audit_db_exists)
        self.assertIn("Saved to ~/.defenseclaw/config.yaml", result.output)


if __name__ == "__main__":
    unittest.main()
