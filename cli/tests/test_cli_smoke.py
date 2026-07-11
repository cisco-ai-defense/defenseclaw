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

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def test_upgrade_recovers_before_config_load_then_reexecs_fresh_bridge(self):
        from defenseclaw.main import cli

        argv = ["defenseclaw", "upgrade", "--yes", "--version", "0.8.5"]
        runner = CliRunner()
        with (
            patch.object(sys, "argv", argv),
            patch(
                "defenseclaw.commands.cmd_upgrade._recover_interrupted_hard_cut",
                return_value=True,
            ) as recover,
            patch("defenseclaw.main.os.execve") as execve,
        ):
            result = runner.invoke(cli, argv[1:])

        self.assertNotEqual(result.exit_code, 0)
        recover.assert_called_once_with()
        execve.assert_called_once()
        executable, child_argv, child_env = execve.call_args.args
        self.assertEqual(executable, sys.executable)
        self.assertEqual(
            child_argv,
            [sys.executable, "-I", "-m", "defenseclaw.main", *argv[1:]],
        )
        self.assertNotIn("PYTHONHOME", child_env)
        self.assertNotIn("PYTHONPATH", child_env)

    def test_upgrade_help_never_triggers_interrupted_recovery(self):
        from defenseclaw.main import cli

        argv = ["defenseclaw", "upgrade", "--help"]
        runner = CliRunner()
        with (
            patch.object(sys, "argv", argv),
            patch(
                "defenseclaw.commands.cmd_upgrade._recover_interrupted_hard_cut"
            ) as recover,
        ):
            result = runner.invoke(cli, argv[1:])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Usage:", result.output)
        recover.assert_not_called()

    def test_upgrade_recovery_reexec_failure_is_controlled(self):
        from defenseclaw.main import cli

        argv = ["defenseclaw", "upgrade", "--yes", "--version", "0.8.5"]
        runner = CliRunner()
        with (
            patch.object(sys, "argv", argv),
            patch(
                "defenseclaw.commands.cmd_upgrade._recover_interrupted_hard_cut",
                return_value=True,
            ),
            patch("defenseclaw.main.os.execve", side_effect=OSError("injected exec failure")),
        ):
            result = runner.invoke(cli, argv[1:])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("Hard-cut recovery re-exec failed: injected exec failure", result.output)

    def test_setup_splunk_o11y_bootstraps_clean_home(self):
        from defenseclaw.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            data_dir = Path(os.getcwd()) / ".defenseclaw"
            with patch("defenseclaw.config.default_data_path", return_value=data_dir):
                runner.invoke(cli, ["init", "--skip-install"])
                result = runner.invoke(
                    cli,
                    ["setup", "splunk", "--o11y", "--access-token", "test-tok",
                     "--realm", "us1", "--non-interactive"],
                )
            config_exists = (data_dir / "config.yaml").is_file()
            audit_db_exists = (data_dir / "audit.db").is_file()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(config_exists)
        self.assertTrue(audit_db_exists)
        self.assertIn("Config saved to ~/.defenseclaw/config.yaml", result.output)


if __name__ == "__main__":
    unittest.main()
