import os
import unittest
from contextlib import ExitStack
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from click.testing import CliRunner

from defenseclaw.commands.cmd_upgrade import (
    _api_bind_host,
    _create_backup,
    _install_wheel,
    upgrade,
)
from defenseclaw.config import Config, GatewayConfig, GuardrailConfig, OpenShellConfig
from defenseclaw.context import AppContext


class TestUpgradeAPIBindHost(unittest.TestCase):
    def test_defaults_to_loopback(self):
        cfg = Config()
        self.assertEqual(_api_bind_host(cfg), "127.0.0.1")

    def test_prefers_gateway_api_bind(self):
        cfg = Config(gateway=GatewayConfig(api_bind="10.0.0.8"))
        self.assertEqual(_api_bind_host(cfg), "10.0.0.8")

    def test_uses_guardrail_host_in_standalone_mode(self):
        cfg = Config(
            openshell=OpenShellConfig(mode="standalone"),
            guardrail=GuardrailConfig(host="192.168.65.2"),
        )
        self.assertEqual(_api_bind_host(cfg), "192.168.65.2")


class TestUpgradeBackup(unittest.TestCase):
    def test_create_backup_includes_managed_connector_backups(self):
        cfg = Config()
        with TemporaryDirectory() as data_dir:
            cfg.data_dir = data_dir
            managed = os.path.join(
                data_dir,
                "connector_backups",
                "codex",
                "config.toml.json",
            )
            os.makedirs(os.path.dirname(managed), exist_ok=True)
            with open(managed, "w") as f:
                f.write("{}")

            backup_dir = _create_backup(cfg)

            copied = os.path.join(
                backup_dir,
                "connector_backups",
                "codex",
                "config.toml.json",
            )
            self.assertTrue(os.path.isfile(copied))


class TestUpgradeWheelInstall(unittest.TestCase):
    def test_install_wheel_uses_managed_venv_python_after_creating_venv(self):
        with TemporaryDirectory() as home, patch.dict(os.environ, {"HOME": home}), \
             patch("shutil.which", return_value="/usr/bin/uv"), \
             patch("subprocess.run") as run_mock:
            venv_python = os.path.join(home, ".defenseclaw", ".venv", "bin", "python")

            def side_effect(args, **_kwargs):
                if args[:2] == ["/usr/bin/uv", "venv"]:
                    os.makedirs(os.path.dirname(venv_python), exist_ok=True)
                    with open(venv_python, "w") as f:
                        f.write("# python")
                return Mock(returncode=0)

            run_mock.side_effect = side_effect

            _install_wheel("/tmp/defenseclaw.whl")

        pip_call = run_mock.call_args_list[-1].args[0]
        self.assertEqual(pip_call[:4], ["/usr/bin/uv", "pip", "install", "--python"])
        self.assertEqual(pip_call[4], venv_python)


class TestUpgradeSameVersionRepair(unittest.TestCase):
    def test_same_version_reapplies_migrations(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "9.9.9"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._detect_platform",
                return_value=("darwin", "arm64"),
            ))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_gateway",
                return_value="/tmp/defenseclaw-gateway",
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_wheel",
                return_value="/tmp/defenseclaw.whl",
            ))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_gateway"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_wheel"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._create_backup",
                return_value="/tmp/backup",
            ))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._poll_health"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0),
            ))
            run_migrations = stack.enter_context(
                patch("defenseclaw.migrations.run_migrations", return_value=1)
            )
            result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)

        self.assertEqual(result.exit_code, 0, msg=result.output)
        run_migrations.assert_called_once()
