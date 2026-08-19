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

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import yaml
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

    def test_trusted_paths_add_bootstraps_exact_v8_config_before_init(self):
        from defenseclaw.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            home = Path.cwd() / ".defenseclaw"
            config_file = home / "config.yaml"
            runtime_root = Path.cwd() / "staged-runtime"
            runtime_root.mkdir()
            expected = str(runtime_root.resolve())
            with patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_HOME": str(home),
                    "DEFENSECLAW_CONFIG": str(config_file),
                    "DEFENSECLAW_TRUSTED_BIN_PREFIXES": "",
                },
            ):
                result = runner.invoke(
                    cli,
                    ["setup", "trusted-paths", "add", expected, "--json"],
                )

            self.assertEqual(result.exit_code, 0, result.output)
            payload = json.loads(result.output)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["path"], expected)
            document = yaml.safe_load(config_file.read_text(encoding="utf-8"))
            self.assertEqual(document["config_version"], 8)
            self.assertEqual(
                document["ai_discovery"]["trusted_binary_prefixes"],
                [expected],
            )
            self.assertFalse((home / "audit.db").exists())

    def test_trusted_path_bootstrap_survives_init_and_authorizes_codex_receipt(self):
        from defenseclaw.bootstrap import StepResult
        from defenseclaw.commands.cmd_config import ValidationResult
        from defenseclaw.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            home = Path.cwd() / ".defenseclaw"
            config_file = home / "config.yaml"
            runtime_root = Path.cwd() / "staged-runtime"
            runtime_root.mkdir()
            codex = runtime_root / "codex.exe"
            codex.write_bytes(b"synthetic approved Codex executable\n")
            codex.chmod(0o700)
            expected_root = str(runtime_root.resolve())
            expected_codex = str(codex.resolve())
            environment = {
                "DEFENSECLAW_HOME": str(home),
                "DEFENSECLAW_CONFIG": str(config_file),
                "DEFENSECLAW_TRUSTED_BIN_PREFIXES": expected_root,
            }
            with (
                patch.dict(os.environ, environment),
                patch(
                    "defenseclaw.commands.cmd_init.platform_support.host_os",
                    return_value="windows",
                ),
                patch(
                    "defenseclaw.inventory.agent_discovery._version_for_agent_binary",
                    return_value=("codex-cli 0.144.3", ""),
                ),
                patch(
                    "defenseclaw.inventory.agent_discovery._binary_candidates_for_agent",
                    return_value=(),
                ),
                patch(
                    "defenseclaw.agent_selection._builtin_setup_trusted_prefixes",
                    return_value=(),
                ),
                patch(
                    "defenseclaw.bootstrap._quiet_guardrail_setup",
                    return_value=StepResult("Guardrail", "pass", "fixture"),
                ),
                patch(
                    "defenseclaw.commands.cmd_config.validate_config",
                    return_value=ValidationResult(),
                ),
            ):
                added = runner.invoke(
                    cli,
                    ["setup", "trusted-paths", "add", expected_root, "--json"],
                )
                initialized = runner.invoke(
                    cli,
                    [
                        "init",
                        "--skip-install",
                        "--non-interactive",
                        "--yes",
                        "--connector",
                        "codex",
                        "--profile",
                        "observe",
                        "--no-start-gateway",
                        "--no-verify",
                        "--json-summary",
                    ],
                )
                # Check init succeeded FIRST. If it failed, the read below
                # would raise FileNotFoundError inside the context manager and
                # swallow the actual init.output — hiding the diagnostic and
                # preventing the exit-code assertions below from ever running.
                self.assertEqual(
                    initialized.exit_code, 0, initialized.output,
                )
                initialized_receipt = json.loads(
                    (home / "agent_selection.json").read_text()
                )
                configured = runner.invoke(
                    cli,
                    [
                        "setup",
                        "gateway",
                        "--api-port",
                        "19091",
                        "--non-interactive",
                        "--no-verify",
                    ],
                )
                shown = runner.invoke(
                    cli,
                    ["config", "show", "--source", "--format", "json"],
                )

            self.assertEqual(added.exit_code, 0, added.output)
            self.assertEqual(initialized.exit_code, 0, initialized.output)
            self.assertEqual(configured.exit_code, 0, configured.output)
            self.assertEqual(shown.exit_code, 0, shown.output)
            document = yaml.safe_load(config_file.read_text(encoding="utf-8"))
            self.assertEqual(
                document["ai_discovery"]["trusted_binary_prefixes"],
                [expected_root],
            )
            self.assertEqual(document["gateway"]["api_port"], 19091)
            self.assertEqual(json.loads(shown.output)["gateway"]["api_port"], 19091)
            initialized_selection = initialized_receipt["selections"]["codex"]
            self.assertEqual(initialized_selection["executable"], expected_codex)
            receipt = json.loads((home / "agent_selection.json").read_text())
            self.assertEqual(list(receipt["selections"]), ["codex"])
            selection = receipt["selections"]["codex"]
            self.assertEqual(selection["executable"], expected_codex)
            self.assertEqual(selection["raw_version"], "codex-cli 0.144.3")
            self.assertEqual(selection["normalized_version"], "0.144.3")
            self.assertEqual(len(selection["sha256"]), 64)

    def test_preinit_setup_rejects_non_trusted_paths_subcommand(self):
        from defenseclaw.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            home = Path.cwd() / ".defenseclaw"
            config_file = home / "config.yaml"
            with patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_HOME": str(home),
                    "DEFENSECLAW_CONFIG": str(config_file),
                },
            ):
                result = runner.invoke(cli, ["setup", "codex", "--yes"])

            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("DefenseClaw is not initialized", result.output)
            self.assertFalse(config_file.exists())
            self.assertFalse((home / "audit.db").exists())

    def test_preinit_trusted_paths_list_is_read_only_and_available(self):
        from defenseclaw.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            home = Path.cwd() / ".defenseclaw"
            config_file = home / "config.yaml"
            with patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_HOME": str(home),
                    "DEFENSECLAW_CONFIG": str(config_file),
                    "DEFENSECLAW_TRUSTED_BIN_PREFIXES": "",
                },
            ):
                result = runner.invoke(
                    cli,
                    ["setup", "trusted-paths", "list", "--json"],
                )

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIsInstance(json.loads(result.output), list)
            self.assertFalse(config_file.exists())
            self.assertFalse((home / "audit.db").exists())

    def test_preinit_trusted_paths_remove_is_available_without_creating_config(self):
        from defenseclaw.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            home = Path.cwd() / ".defenseclaw"
            config_file = home / "config.yaml"
            with patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_HOME": str(home),
                    "DEFENSECLAW_CONFIG": str(config_file),
                },
            ):
                result = runner.invoke(
                    cli,
                    ["setup", "trusted-paths", "remove", str(Path.cwd())],
                )

            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("not an operator-added trusted prefix", result.output)
            self.assertFalse(config_file.exists())
            self.assertFalse((home / "audit.db").exists())

    def test_offline_trusted_path_add_list_init_subprocess_preserves_config(self):
        cli_root = Path(__file__).resolve().parents[1]
        repository_root = Path(__file__).resolve().parents[2]
        gateway_name = (
            "defenseclaw-gateway.exe" if os.name == "nt" else "defenseclaw-gateway"
        )
        # Prefer an operator-supplied binary path (CI can stage one via
        # PYTEST_GATEWAY_BIN). Fall back to the repository-root
        # location. If neither exists but `go` is available, build the
        # gateway on demand so this smoke actually runs under CI Python
        # test jobs instead of silently skipping. When Go is also
        # unavailable, skip with a clear reason.
        fixture_env = os.environ.get("PYTEST_GATEWAY_BIN", "").strip()
        gateway: Path | None = None
        if fixture_env:
            candidate = Path(fixture_env)
            if candidate.is_file():
                gateway = candidate
        if gateway is None:
            candidate = repository_root / gateway_name
            if candidate.is_file():
                gateway = candidate
        if gateway is None:
            go_bin = shutil.which("go")
            if go_bin is None:
                self.skipTest(
                    "real gateway binary unavailable and `go` not on PATH; "
                    "set PYTEST_GATEWAY_BIN to skip building",
                )
            built = repository_root / gateway_name
            build = subprocess.run(
                [go_bin, "build", "-o", str(built), "./cmd/defenseclaw-gateway"],
                cwd=repository_root,
                capture_output=True,
                text=True,
                check=False,
            )
            # A skip here would report the trusted-path subprocess contract as
            # "not verified" when the real problem is a broken gateway build.
            # Only skip when Go itself is missing (handled above); a nonzero
            # `go build` exit or a missing output binary must fail loudly.
            if build.returncode != 0 or not built.is_file():
                self.fail(
                    "gateway build failed (go on PATH but produced no binary): "
                    + (build.stderr or build.stdout).strip(),
                )
            gateway = built

        runner = CliRunner()
        with runner.isolated_filesystem():
            root = Path.cwd()
            home = root / "profile"
            data_dir = home / ".defenseclaw"
            config_file = data_dir / "config.yaml"
            runtime_root = root / "staged-runtime"
            empty_path = root / "empty-path"
            runtime_root.mkdir()
            empty_path.mkdir()
            expected = str(runtime_root.resolve())
            environment = {
                "PATH": str(empty_path.resolve()),
                "HOME": str(home.resolve()),
                "USERPROFILE": str(home.resolve()),
                "APPDATA": str((home / "AppData" / "Roaming").resolve()),
                "LOCALAPPDATA": str((home / "AppData" / "Local").resolve()),
                "CODEX_HOME": str((home / ".codex").resolve()),
                "CLAUDE_CONFIG_DIR": str((home / ".claude").resolve()),
                "DEFENSECLAW_HOME": str(data_dir.resolve()),
                "DEFENSECLAW_CONFIG": str(config_file.resolve()),
                "DEFENSECLAW_TRUSTED_BIN_PREFIXES": "",
                "DEFENSECLAW_GATEWAY_BIN": str(gateway.resolve()),
                "PYTHONIOENCODING": "utf-8",
                "PYTHONPATH": str(cli_root.resolve()),
            }
            for name in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
                if value := os.environ.get(name):
                    environment[name] = value

            def invoke(
                *arguments: str,
                gateway_required: bool = False,
            ) -> subprocess.CompletedProcess[str]:
                child_environment = environment.copy()
                if not gateway_required:
                    child_environment.pop("DEFENSECLAW_GATEWAY_BIN", None)
                return subprocess.run(
                    [sys.executable, "-m", "defenseclaw.main", *arguments],
                    cwd=root,
                    env=child_environment,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=120,
                    check=False,
                )

            added = invoke("setup", "trusted-paths", "add", expected, "--json")
            before = invoke("setup", "trusted-paths", "list", "--json")
            initialized = invoke(
                "init",
                "--skip-install",
                "--non-interactive",
                "--yes",
                "--connector",
                "none",
                "--no-start-gateway",
                "--no-verify",
                "--json-summary",
                gateway_required=True,
            )
            after = invoke("setup", "trusted-paths", "list", "--json")

            self.assertEqual(added.returncode, 0, added.stderr + added.stdout)
            self.assertEqual(before.returncode, 0, before.stderr + before.stdout)
            self.assertEqual(initialized.returncode, 0, initialized.stderr + initialized.stdout)
            self.assertEqual(after.returncode, 0, after.stderr + after.stdout)
            before_rows = [row for row in json.loads(before.stdout) if row["source"] == "config"]
            after_rows = [row for row in json.loads(after.stdout) if row["source"] == "config"]
            self.assertEqual([row["resolved"] for row in before_rows], [expected])
            self.assertEqual([row["resolved"] for row in after_rows], [expected])
            document = yaml.safe_load(config_file.read_text(encoding="utf-8"))
            self.assertEqual(
                document["ai_discovery"]["trusted_binary_prefixes"],
                [expected],
            )
            self.assertFalse((data_dir / "agent_selection.json").exists())

    def test_trusted_paths_bootstrap_rejects_existing_legacy_config(self):
        from defenseclaw.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            home = Path.cwd() / ".defenseclaw"
            home.mkdir()
            config_file = home / "config.yaml"
            original = "config_version: 7\n"
            config_file.write_text(original, encoding="utf-8")
            runtime_root = Path.cwd() / "staged-runtime"
            runtime_root.mkdir()
            with patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_HOME": str(home),
                    "DEFENSECLAW_CONFIG": str(config_file),
                },
            ):
                result = runner.invoke(
                    cli,
                    [
                        "setup",
                        "trusted-paths",
                        "add",
                        str(runtime_root.resolve()),
                        "--json",
                    ],
                )

            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("Configuration schema v8 is required", result.output)
            self.assertEqual(config_file.read_text(encoding="utf-8"), original)
            self.assertFalse((home / "audit.db").exists())

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
                    with (
                        patch.object(sys, "argv", argv),
                        patch.dict(
                            os.environ,
                            {"DEFENSECLAW_HOME": str(home)},
                        ),
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
                self.assertIn(
                    '/bin/bash --noprofile --norc -p -n "$d/defenseclaw-upgrade.sh"',
                    result.output,
                )
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
            with (
                patch.object(sys, "argv", argv),
                patch.dict(
                    os.environ,
                    {"DEFENSECLAW_HOME": str(home)},
                ),
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
                patch.dict(
                    os.environ,
                    {"DEFENSECLAW_HOME": str(data_dir)},
                    clear=False,
                ),
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
