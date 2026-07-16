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
from types import SimpleNamespace
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

    def test_direct_upgrade_refuses_active_recovery_and_points_to_resolver(self):
        from defenseclaw.main import cli

        for journal_name in ("phase-one-active.json", "phase-two-active.json"):
            with self.subTest(journal_name=journal_name):
                argv = ["defenseclaw", "upgrade", "--yes", "--version", "0.8.5"]
                runner = CliRunner()
                with runner.isolated_filesystem():
                    home = Path.cwd() / ".defenseclaw"
                    journal = home / ".upgrade-recovery" / journal_name
                    journal.parent.mkdir(parents=True)
                    journal.write_text("{}\n", encoding="utf-8")
                    before = {path.relative_to(home) for path in home.rglob("*")}
                    with patch.object(sys, "argv", argv), patch.dict(
                        os.environ,
                        {"DEFENSECLAW_HOME": str(home)},
                    ):
                        result = runner.invoke(cli, argv[1:])
                    self.assertEqual(journal.read_text(encoding="utf-8"), "{}\n")
                    self.assertEqual(
                        {path.relative_to(home) for path in home.rglob("*")},
                        before,
                    )

                self.assertEqual(result.exit_code, 1)
                self.assertIn("requires the release-owned resolver", result.output)
                self.assertIn("without --version/-Version", result.output)
                self.assertIn("mktemp -d", result.output)
                self.assertIn("cosign verify-blob", result.output)
                self.assertIn("releases/download/", result.output)
                self.assertIn("defenseclaw-upgrade.sh", result.output)
                self.assertIn("DefenseClaw upgrade resolver complete v1", result.output)
                self.assertIn("bash -n \"$d/defenseclaw-upgrade.sh\"", result.output)
                self.assertNotIn("upgrade.sh | bash", result.output)
                self.assertIn("[Guid]::NewGuid()", result.output)
                self.assertIn("-ErrorAction Stop", result.output)
                self.assertIn("finally", result.output)
                self.assertIn("& $r -Yes", result.output)
                self.assertIn("no recovery mutation was attempted", result.output)

    def test_upgrade_help_never_triggers_interrupted_recovery(self):
        from defenseclaw.main import cli

        argv = ["defenseclaw", "upgrade", "--help"]
        runner = CliRunner()
        with runner.isolated_filesystem():
            home = Path.cwd() / ".defenseclaw"
            journal = home / ".upgrade-recovery/phase-two-active.json"
            journal.parent.mkdir(parents=True)
            journal.write_text("{}\n", encoding="utf-8")
            before = {path.relative_to(home) for path in home.rglob("*")}
            with patch.object(sys, "argv", argv), patch.dict(
                os.environ,
                {"DEFENSECLAW_HOME": str(home)},
            ):
                result = runner.invoke(cli, argv[1:])
            self.assertEqual(journal.read_text(encoding="utf-8"), "{}\n")
            self.assertEqual(
                {path.relative_to(home) for path in home.rglob("*")},
                before,
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Usage:", result.output)

    def test_upgrade_preflight_does_not_initialize_audit_store(self):
        from defenseclaw.main import cli

        argv = ["defenseclaw", "upgrade", "--yes", "--version", "0.8.3"]
        runner = CliRunner()
        with runner.isolated_filesystem():
            home = Path.cwd() / ".defenseclaw"
            with (
                patch.object(sys, "argv", argv),
                patch.dict(
                    os.environ,
                    {"DEFENSECLAW_HOME": str(home), "HOME": str(Path.cwd())},
                ),
                patch("defenseclaw.config.load", return_value=object()) as load,
                patch("defenseclaw.db.Store") as store,
            ):
                result = runner.invoke(cli, argv[1:])

            self.assertFalse(home.exists())
            load.assert_called_once_with()
            store.assert_not_called()

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("Refusing to downgrade", result.output)
        self.assertIn("No changes were made", result.output)

    def test_setup_splunk_o11y_bootstraps_clean_home(self):
        from defenseclaw.commands.cmd_config import ValidationResult
        from defenseclaw.logger import Logger
        from defenseclaw.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            data_dir = Path(os.getcwd()) / ".defenseclaw"
            # The smoke test exercises CLI bootstrap/wiring, not the Go helper
            # binary (CI builds that in separate contract tests). Keep both
            # canonical validation seams successful and side-effect free.
            with (
                patch("defenseclaw.config.default_data_path", return_value=data_dir),
                patch(
                    "defenseclaw.commands.cmd_config.validate_config",
                    return_value=ValidationResult(),
                ),
                patch(
                    "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
                    return_value=SimpleNamespace(destinations=[]),
                ),
                patch.object(Logger, "from_config", return_value=Logger.no_runtime()),
                patch("defenseclaw.observability.v8_writer._validate_candidate"),
            ):
                runner.invoke(cli, ["init", "--skip-install"])
                result = runner.invoke(
                    cli,
                    ["setup", "splunk", "--o11y", "--access-token", "test-tok", "--realm", "us1", "--non-interactive"],
                )
            config_exists = (data_dir / "config.yaml").is_file()
            config_text = (data_dir / "config.yaml").read_text() if config_exists else ""
            audit_db_exists = (data_dir / "audit.db").is_file()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(config_exists)
        self.assertIn("config_version: 8", config_text)
        self.assertNotIn("emit_otel", config_text)
        self.assertTrue(audit_db_exists)
        self.assertIn("Config saved to ~/.defenseclaw/config.yaml", result.output)


if __name__ == "__main__":
    unittest.main()
