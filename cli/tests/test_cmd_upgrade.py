import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
import types
import unittest
import zipfile
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

import click
from click.testing import CliRunner
from defenseclaw.commands.cmd_upgrade import (
    _INSTALLED_HEALTH_SCRIPT,
    _INSTALLED_MIGRATION_SCRIPT,
    _acquire_bridge_rollback_artifacts,
    _api_bind_host,
    _assert_required_cli_migrations,
    _check_post_upgrade_drift,
    _create_backup,
    _detect_platform,
    _download_checksums,
    _download_file,
    _download_gateway,
    _download_upgrade_manifest,
    _enforce_upgrade_source_contract,
    _execute_hard_cut_rollback,
    _fetch_release_asset_digests,
    _fill_missing_checksums_from_release_assets,
    _gateway_archive_name,
    _handoff_to_installed_upgrade,
    _hold_phase_two_lease_for_command_lifetime,
    _install_gateway,
    _install_wheel,
    _load_hard_cut_recovery_journal,
    _normalize_target_version,
    _poll_health,
    _poll_installed_health,
    _preflight_check,
    _preflight_target_wheel_migrations,
    _preflight_wheel_install,
    _prepare_hard_cut_rollback_plan,
    _print_migration_cursor_summary,
    _recover_interrupted_hard_cut,
    _refresh_target_dotenv_environment,
    _release_download_base,
    _require_hard_cut_manifest_contract,
    _require_target_phase_two_mutator_wrapper,
    _run_installed_migrations,
    _run_phase_two_mutator,
    _run_silent,
    _start_and_verify_services,
    _target_migration_capabilities,
    _TargetMigrationCapabilities,
    _validate_staged_bridge_artifact_set,
    _validate_target_migration_capabilities,
    _validate_upgrade_manifest,
    _verify_checksums_sigstore,
    _verify_installed_gateway_version,
    _verify_sha256,
    _write_hard_cut_recovery_journal,
    upgrade,
)
from defenseclaw.config import Config, GatewayConfig, GuardrailConfig, OpenShellConfig
from defenseclaw.context import AppContext
from defenseclaw.upgrade_receipt import (
    UPGRADE_RECEIPT_DIRECTORY,
    begin_upgrade_receipt,
    load_upgrade_receipt,
)


def _write_migration_wheel(
    path: str,
    *,
    version: str,
    migration_versions: tuple[str, ...],
    supports_bundle_flag: bool,
    supported_config_versions: tuple[int, ...] | None,
) -> None:
    parameter = ", *, upgrade_handles_local_bundle=False" if supports_bundle_flag else ""
    supported = (
        f"SUPPORTED_CONFIG_VERSIONS = {supported_config_versions!r}\n" if supported_config_versions is not None else ""
    )
    rows = ",\n".join(f"    ({item!r}, 'migration', _migration)" for item in migration_versions)
    source = (
        "def _migration(_ctx):\n    return None\n\n"
        f"{supported}"
        f"MIGRATIONS = [\n{rows}\n]\n\n"
        f"def run_migrations(from_version, to_version, openclaw_home, data_dir=None{parameter}):\n"
        "    return 0\n"
    )
    metadata = f"Metadata-Version: 2.4\nName: defenseclaw\nVersion: {version}\n"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("defenseclaw/migrations.py", source)
        archive.writestr(
            "defenseclaw/phase_two_mutator.py",
            "raise SystemExit('fixture wrapper is not executed')\n",
        )
        archive.writestr(f"defenseclaw-{version}.dist-info/METADATA", metadata)


class TestUpgradeVersionValidation(unittest.TestCase):
    def test_accepts_plain_or_v_prefixed_semver(self):
        self.assertEqual(_normalize_target_version("9.9.9"), "9.9.9")
        self.assertEqual(_normalize_target_version("v9.9.9"), "9.9.9")

    def test_rejects_versions_that_would_be_unsafe_in_paths_or_urls(self):
        with self.assertRaises(SystemExit) as ctx:
            _normalize_target_version("../9.9.9")
        self.assertEqual(ctx.exception.code, 1)


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
            cfg.claw.home_dir = os.path.join(data_dir, "openclaw")
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

    @unittest.skipIf(os.name != "posix", "POSIX mode contract")
    def test_create_backup_tightens_legacy_root_and_makes_unique_private_directories(self):
        cfg = Config()
        with TemporaryDirectory() as data_dir:
            cfg.data_dir = data_dir
            cfg.claw.home_dir = os.path.join(data_dir, "openclaw")
            backup_root = os.path.join(data_dir, "backups")
            os.mkdir(backup_root, 0o755)
            os.chmod(backup_root, 0o755)

            first = _create_backup(cfg)
            second = _create_backup(cfg)

            self.assertNotEqual(first, second)
            self.assertEqual(stat.S_IMODE(os.stat(backup_root).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(first).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(second).st_mode), 0o700)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_create_backup_refuses_symlink_root(self):
        cfg = Config()
        with TemporaryDirectory() as data_dir, TemporaryDirectory() as target:
            cfg.data_dir = data_dir
            cfg.claw.home_dir = os.path.join(data_dir, "openclaw")
            os.symlink(target, os.path.join(data_dir, "backups"))

            with self.assertRaises(OSError):
                _create_backup(cfg)

            self.assertEqual(os.listdir(target), [])


class TestHardCutRollbackTransaction(unittest.TestCase):
    def _prepare_plan(
        self,
        root: str,
        *,
        active_gateway_payload: bytes | None = None,
        environment_payload: bytes | None = None,
    ):
        home = os.path.join(root, "home")
        data_dir = os.path.join(root, "data")
        staged = os.path.join(root, "staged-handoff")
        backup_root = os.path.join(data_dir, "backups")
        backup_dir = os.path.join(backup_root, "upgrade-test")
        os.makedirs(home)
        os.makedirs(data_dir)
        os.mkdir(staged, 0o700)
        os.mkdir(backup_root, 0o700)
        os.mkdir(backup_dir, 0o700)

        config_path = os.path.join(data_dir, "config.yaml")
        cursor_path = os.path.join(data_dir, ".migration_state.json")
        with open(config_path, "wb") as stream:
            stream.write(b"config_version: 7\ngateway:\n  api_port: 18970\n")
        with open(cursor_path, "wb") as stream:
            stream.write(b'{"schema":1,"applied":["0.8.4"]}\n')
        if environment_payload is not None:
            with open(os.path.join(data_dir, ".env"), "wb") as stream:
                stream.write(environment_payload)

        wheel_name = "defenseclaw-0.8.4-py3-none-any.whl"
        wheel_path = os.path.join(staged, wheel_name)
        _write_migration_wheel(
            wheel_path,
            version="0.8.4",
            migration_versions=("0.3.0",),
            supports_bundle_flag=True,
            supported_config_versions=(7,),
        )
        archive_name = "defenseclaw_0.8.4_linux_amd64.tar.gz"
        archive_path = os.path.join(staged, archive_name)
        gateway_payload = b"#!/bin/sh\necho 'defenseclaw-gateway version 0.8.4'\n"
        with tarfile.open(archive_path, "w:gz") as archive:
            member = tarfile.TarInfo("defenseclaw")
            member.size = len(gateway_payload)
            member.mode = 0o755
            archive.addfile(member, io.BytesIO(gateway_payload))
        active_gateway = os.path.join(home, ".local", "bin", "defenseclaw-gateway")
        os.makedirs(os.path.dirname(active_gateway), exist_ok=True)
        with open(active_gateway, "wb") as stream:
            stream.write(
                gateway_payload
                if active_gateway_payload is None
                else active_gateway_payload
            )
        os.chmod(active_gateway, 0o755)

        manifest_path = os.path.join(staged, "upgrade-manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as stream:
            json.dump(
                {
                    "schema_version": 1,
                    "release_version": "0.8.4",
                    "min_upgrade_protocol": 1,
                    "controller_upgrade_protocol": 2,
                    "migration_failure_policy": "warn",
                    "required_cli_migrations": [],
                },
                stream,
            )
        checksums_path = os.path.join(staged, "checksums.txt")
        with open(checksums_path, "w", encoding="utf-8") as stream:
            for filename in (wheel_name, archive_name, "upgrade-manifest.json"):
                with open(os.path.join(staged, filename), "rb") as artifact:
                    digest = hashlib.sha256(artifact.read()).hexdigest()
                stream.write(f"{digest}  {filename}\n")
        for filename in ("checksums.txt.sig", "checksums.txt.pem"):
            with open(os.path.join(staged, filename), "wb") as stream:
                stream.write(b"resolver-verified-test-asset")
        for filename in os.listdir(staged):
            os.chmod(os.path.join(staged, filename), 0o600)

        app = AppContext()
        app.cfg = Config()
        app.cfg.data_dir = data_dir
        app.cfg.claw.home_dir = os.path.join(root, "openclaw")
        with (
            patch.dict(os.environ, {"HOME": home, "DEFENSECLAW_CONFIG": config_path}),
            patch(
                "defenseclaw.commands.cmd_upgrade.shutil.which",
                return_value="/usr/bin/cosign",
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0),
            ),
        ):
            plan = _prepare_hard_cut_rollback_plan(
                app.cfg,
                backup_dir,
                source_version="0.8.4",
                os_name="linux",
                arch="amd64",
                staged_artifact_dir=staged,
            )
        return app, plan, config_path, cursor_path, gateway_payload, home

    def test_prepare_retains_exact_active_gateway_and_rejects_component_drift(self):
        with TemporaryDirectory() as root:
            _app, plan, _config_path, _cursor_path, gateway_payload, _home = self._prepare_plan(root)
            self.assertEqual(plan.gateway_snapshot.active_path, plan.active_gateway_path)
            self.assertEqual(plan.gateway_snapshot.backup_path, plan.rollback_gateway_path)
            with open(plan.rollback_gateway_path, "rb") as stream:
                self.assertEqual(stream.read(), gateway_payload)

        with TemporaryDirectory() as root, self.assertRaisesRegex(
            OSError,
            "does not match its authenticated rollback artifact",
        ):
            self._prepare_plan(root, active_gateway_payload=b"different bridge gateway")

    @unittest.skipUnless(os.name == "posix", "POSIX ownership/mode contract")
    def test_staged_bridge_root_must_be_owner_only(self):
        with TemporaryDirectory() as root:
            self._prepare_plan(root)
            staged = os.path.join(root, "staged-handoff")
            os.chmod(staged, 0o755)
            with self.assertRaisesRegex(OSError, "owner-only"):
                _validate_staged_bridge_artifact_set(staged, "0.8.4", "linux", "amd64")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_staged_bridge_rejects_symlinked_artifact(self):
        with TemporaryDirectory() as root:
            self._prepare_plan(root)
            staged = os.path.join(root, "staged-handoff")
            wheel = os.path.join(staged, "defenseclaw-0.8.4-py3-none-any.whl")
            replacement = os.path.join(root, "replacement.whl")
            os.replace(wheel, replacement)
            os.symlink(replacement, wheel)
            with self.assertRaisesRegex(OSError, "regular file"):
                _validate_staged_bridge_artifact_set(staged, "0.8.4", "linux", "amd64")

    def test_staged_bridge_rejects_missing_signature_digest_mismatch_and_bad_signature(self):
        with TemporaryDirectory() as root:
            self._prepare_plan(root)
            staged = os.path.join(root, "staged-handoff")
            signature = os.path.join(staged, "checksums.txt.sig")
            os.unlink(signature)
            with self.assertRaisesRegex(OSError, "unavailable"):
                _validate_staged_bridge_artifact_set(staged, "0.8.4", "linux", "amd64")

        with TemporaryDirectory() as root:
            self._prepare_plan(root)
            staged = os.path.join(root, "staged-handoff")
            wheel = os.path.join(staged, "defenseclaw-0.8.4-py3-none-any.whl")
            with open(wheel, "ab") as stream:
                stream.write(b"tampered")
            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade.shutil.which",
                    return_value="/usr/bin/cosign",
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(returncode=0),
                ),
                self.assertRaises(SystemExit),
            ):
                _validate_staged_bridge_artifact_set(staged, "0.8.4", "linux", "amd64")

    def test_staged_modern_bridge_requires_cosign_and_exact_workflow_identity(self):
        with TemporaryDirectory() as root:
            self._prepare_plan(root)
            staged = os.path.join(root, "staged-handoff")
            with (
                patch("defenseclaw.commands.cmd_upgrade.shutil.which", return_value=None),
                self.assertRaisesRegex(OSError, "requires cosign"),
            ):
                _validate_staged_bridge_artifact_set(staged, "0.8.4", "linux", "amd64")

            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade.shutil.which",
                    return_value="/usr/bin/cosign",
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(returncode=0),
                ) as run_mock,
            ):
                _validate_staged_bridge_artifact_set(staged, "0.8.4", "linux", "amd64")

            command = run_mock.call_args.args[0]
            self.assertNotIn("--certificate-identity-regexp", command)
            self.assertEqual(
                command[command.index("--certificate-identity") + 1],
                "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main",
            )

        with TemporaryDirectory() as root:
            self._prepare_plan(root)
            staged = os.path.join(root, "staged-handoff")
            with (
                patch("defenseclaw.commands.cmd_upgrade.shutil.which", return_value="/usr/bin/cosign"),
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(returncode=1),
                ),
                self.assertRaisesRegex(OSError, "signature verification failed"),
            ):
                _validate_staged_bridge_artifact_set(staged, "0.8.4", "linux", "amd64")

    def test_staged_bridge_manifest_must_remain_protocol_one_reachable(self):
        with TemporaryDirectory() as root:
            self._prepare_plan(root)
            staged = os.path.join(root, "staged-handoff")
            manifest_path = os.path.join(staged, "upgrade-manifest.json")
            with open(manifest_path, encoding="utf-8") as stream:
                manifest = json.load(stream)
            manifest["min_upgrade_protocol"] = 2
            with open(manifest_path, "w", encoding="utf-8") as stream:
                json.dump(manifest, stream)
            digest = hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest()
            checksums_path = os.path.join(staged, "checksums.txt")
            lines = Path(checksums_path).read_text(encoding="utf-8").splitlines()
            Path(checksums_path).write_text(
                "\n".join(
                    f"{digest}  upgrade-manifest.json"
                    if line.endswith("  upgrade-manifest.json")
                    else line
                    for line in lines
                )
                + "\n",
                encoding="utf-8",
            )
            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade.shutil.which",
                    return_value="/usr/bin/cosign",
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(returncode=0),
                ),
                self.assertRaisesRegex(OSError, "protocol-1 reachable"),
            ):
                _validate_staged_bridge_artifact_set(staged, "0.8.4", "linux", "amd64")

    def test_resolver_staged_artifacts_are_preferred_over_network_fallback(self):
        with TemporaryDirectory() as root:
            _app, _plan, _config_path, _cursor_path, _gateway_payload, _home = self._prepare_plan(root)
            staged = os.path.join(root, "staged-handoff")
            download_staging = os.path.join(root, "download-staging")
            os.mkdir(download_staging, 0o700)
            with (
                patch.dict(
                    os.environ,
                    {
                        "DEFENSECLAW_STAGED_UPGRADE": "1",
                        "DEFENSECLAW_STAGED_BRIDGE_VERSION": "0.8.4",
                        "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR": staged,
                    },
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.shutil.which",
                    return_value="/usr/bin/cosign",
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(returncode=0),
                ),
                patch("defenseclaw.commands.cmd_upgrade._download_checksums") as download_checksums,
            ):
                resolved = _acquire_bridge_rollback_artifacts(
                    "0.8.4",
                    "linux",
                    "amd64",
                    download_staging,
                )

            self.assertEqual(resolved, staged)
            download_checksums.assert_not_called()

    def test_ordinary_bridge_securely_fetches_rollback_set_before_backup(self):
        with TemporaryDirectory() as staging_dir:
            with (
                patch.dict(
                    os.environ,
                    {
                        "DEFENSECLAW_STAGED_UPGRADE": "",
                        "DEFENSECLAW_STAGED_BRIDGE_VERSION": "",
                        "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR": "",
                    },
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_checksums",
                    return_value={"artifact": "0" * 64},
                ) as checksums,
                patch("defenseclaw.commands.cmd_upgrade._download_upgrade_manifest") as manifest,
                patch("defenseclaw.commands.cmd_upgrade._download_wheel") as wheel,
                patch("defenseclaw.commands.cmd_upgrade._download_gateway") as gateway,
                patch("defenseclaw.commands.cmd_upgrade._validate_staged_bridge_artifact_set"),
            ):
                resolved = _acquire_bridge_rollback_artifacts(
                    "0.8.4",
                    "linux",
                    "amd64",
                    staging_dir,
                )

            self.assertTrue(resolved.startswith(staging_dir + os.sep))
            self.assertEqual(stat.S_IMODE(os.stat(resolved).st_mode), 0o700)
            self.assertFalse(checksums.call_args.kwargs["allow_unverified"])
            manifest.assert_called_once()
            wheel.assert_called_once()
            gateway.assert_called_once()

    def test_successful_rollback_restores_exact_state_and_records_outcome(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, cursor_path, gateway_payload, home = self._prepare_plan(root)
            with open(config_path, "wb") as stream:
                stream.write(b"config_version: 8\n")
            with open(cursor_path, "wb") as stream:
                stream.write(b'{"schema":1,"applied":["0.8.5"]}\n')
            environment_path = os.path.join(app.cfg.data_dir, ".env")
            with open(environment_path, "wb") as stream:
                stream.write(b"CREATED_BY_TARGET=yes\n")
            os.makedirs(os.path.dirname(plan.active_gateway_path), exist_ok=True)
            with open(plan.active_gateway_path, "wb") as stream:
                stream.write(b"target gateway")
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )

            with (
                patch.dict(os.environ, {"HOME": home, "DEFENSECLAW_CONFIG": config_path}),
                patch("defenseclaw.commands.cmd_upgrade._install_wheel") as install_wheel,
                patch("defenseclaw.commands.cmd_upgrade._verify_restored_bridge_artifacts"),
                patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
                patch(
                    "defenseclaw.commands.cmd_upgrade._poll_installed_health"
                ) as poll_health,
            ):
                restored = _execute_hard_cut_rollback(
                    plan,
                    app,
                    receipt_path,
                    failure_code="health_check_failed",
                    health_timeout=9,
                )

            self.assertTrue(restored)
            with open(config_path, "rb") as stream:
                self.assertEqual(stream.read(), b"config_version: 7\ngateway:\n  api_port: 18970\n")
            with open(cursor_path, "rb") as stream:
                self.assertEqual(stream.read(), b'{"schema":1,"applied":["0.8.4"]}\n')
            self.assertFalse(os.path.exists(environment_path))
            with open(plan.active_gateway_path, "rb") as stream:
                self.assertEqual(stream.read(), gateway_payload)
            install_wheel.assert_called_once_with(plan.rollback_wheel_path, "linux")
            poll_health.assert_called_once_with(
                app.cfg.data_dir,
                9,
                "0.8.4",
                os_name="linux",
            )
            receipt = load_upgrade_receipt(receipt_path)
            self.assertEqual(receipt.status, "rolled_back")
            self.assertEqual(receipt.failure_code, "health_check_failed")

    def test_rollback_discards_target_dotenv_value_before_loading_restored_bridge(self):
        env_name = "TEST_HARD_CUT_ROLLBACK_TOKEN"
        os.environ.pop(env_name, None)
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(
                root,
                environment_payload=f"{env_name}=bridge-value\n".encode(),
            )
            environment_path = os.path.join(app.cfg.data_dir, ".env")
            with open(environment_path, "w", encoding="utf-8") as stream:
                stream.write(f"{env_name}=target-value\n")
            os.environ[env_name] = "target-value"
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )

            def probe_restored(data_dir, timeout, expected_version, *, os_name):
                self.assertEqual(data_dir, app.cfg.data_dir)
                self.assertEqual(timeout, 1)
                self.assertEqual(expected_version, "0.8.4")
                self.assertEqual(os_name, "linux")
                self.assertNotIn(env_name, os.environ)
                self.assertEqual(
                    Path(data_dir, ".env").read_text(encoding="utf-8"),
                    f"{env_name}=bridge-value\n",
                )

            try:
                with (
                    patch.dict(os.environ, {"HOME": home, "DEFENSECLAW_CONFIG": config_path}),
                    patch("defenseclaw.commands.cmd_upgrade._install_wheel"),
                    patch("defenseclaw.commands.cmd_upgrade._verify_restored_bridge_artifacts"),
                    patch(
                        "defenseclaw.commands.cmd_upgrade._poll_installed_health",
                        side_effect=probe_restored,
                    ),
                    patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
                ):
                    restored = _execute_hard_cut_rollback(
                        plan,
                        app,
                        receipt_path,
                        failure_code="health_check_failed",
                        health_timeout=1,
                    )
                self.assertTrue(restored)
            finally:
                os.environ.pop(env_name, None)

    def test_rollback_refuses_to_restore_over_a_live_target_gateway(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(root)
            with open(os.path.join(app.cfg.data_dir, "gateway.pid"), "w", encoding="utf-8") as stream:
                stream.write("4242\n")
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )
            with (
                patch.dict(os.environ, {"HOME": home, "DEFENSECLAW_CONFIG": config_path}),
                patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
                patch("defenseclaw.process_liveness.read_pid_file", return_value=4242),
                patch("defenseclaw.process_liveness.pid_alive", return_value=True),
                patch("defenseclaw.process_liveness.process_is_gateway", return_value=True),
                patch("defenseclaw.commands.cmd_upgrade._restore_rollback_file") as restore_file,
            ):
                restored = _execute_hard_cut_rollback(
                    plan,
                    app,
                    receipt_path,
                    failure_code="install_failed",
                    health_timeout=1,
                )

            self.assertFalse(restored)
            restore_file.assert_not_called()
            receipt = load_upgrade_receipt(receipt_path)
            self.assertEqual(receipt.status, "failed")
            self.assertEqual(receipt.failure_code, "install_failed")

    def test_failed_restored_health_keeps_failed_receipt_and_returns_false(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(root)
            os.makedirs(os.path.dirname(plan.active_gateway_path), exist_ok=True)
            with open(plan.active_gateway_path, "wb") as stream:
                stream.write(b"target gateway")
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )

            with (
                patch.dict(os.environ, {"HOME": home, "DEFENSECLAW_CONFIG": config_path}),
                patch("defenseclaw.commands.cmd_upgrade._install_wheel"),
                patch("defenseclaw.commands.cmd_upgrade._verify_restored_bridge_artifacts"),
                patch(
                    "defenseclaw.commands.cmd_upgrade._poll_installed_health",
                    side_effect=SystemExit(1),
                ),
                patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
            ):
                restored = _execute_hard_cut_rollback(
                    plan,
                    app,
                    receipt_path,
                    failure_code="install_failed",
                    health_timeout=1,
                )

            self.assertFalse(restored)
            receipt = load_upgrade_receipt(receipt_path)
            self.assertEqual(receipt.status, "failed")
            self.assertEqual(receipt.failure_code, "install_failed")

    def test_recovery_journal_round_trips_private_secret_free_custody(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(
                root,
                environment_payload=b"BRIDGE_TOKEN=do-not-journal\n",
            )
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )
            with patch.dict(
                os.environ,
                {
                    "HOME": home,
                    "DEFENSECLAW_HOME": app.cfg.data_dir,
                    "DEFENSECLAW_CONFIG": config_path,
                    "BRIDGE_TOKEN": "do-not-journal",
                },
            ):
                journal = _write_hard_cut_recovery_journal(
                    plan,
                    receipt_path,
                    target_version="0.8.5",
                )
                loaded = _load_hard_cut_recovery_journal(app.cfg.data_dir)

            self.assertIsNotNone(loaded)
            assert loaded is not None
            loaded_path, loaded_plan, loaded_receipt, target_version = loaded
            self.assertEqual(loaded_path, journal)
            self.assertEqual(loaded_plan.source_version, plan.source_version)
            self.assertEqual(loaded_plan.rollback_wheel_sha256, plan.rollback_wheel_sha256)
            self.assertEqual(loaded_plan.rollback_gateway_sha256, plan.rollback_gateway_sha256)
            self.assertEqual(loaded_plan.state_files, plan.state_files)
            self.assertEqual(loaded_receipt, receipt_path)
            self.assertEqual(target_version, "0.8.5")
            self.assertNotIn(b"do-not-journal", journal.read_bytes())
            lease = journal.with_name("phase-two-mutator.lease")
            self.assertTrue(lease.is_file())
            self.assertEqual(lease.stat().st_size, 0)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(journal.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(lease.stat().st_mode), 0o600)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_recovery_journal_rejects_tampered_custody_and_symlink(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(root)
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )
            with patch.dict(
                os.environ,
                {
                    "HOME": home,
                    "DEFENSECLAW_HOME": app.cfg.data_dir,
                    "DEFENSECLAW_CONFIG": config_path,
                },
            ):
                journal = _write_hard_cut_recovery_journal(
                    plan,
                    receipt_path,
                    target_version="0.8.5",
                )
                with open(plan.rollback_wheel_path, "ab") as stream:
                    stream.write(b"tampered")
                with self.assertRaisesRegex(OSError, "digest changed"):
                    _load_hard_cut_recovery_journal(app.cfg.data_dir)

                real_journal = journal.with_name("phase-two-real.json")
                os.replace(journal, real_journal)
                os.symlink(real_journal, journal)
                with self.assertRaisesRegex(OSError, "regular file"):
                    _load_hard_cut_recovery_journal(app.cfg.data_dir)

    def test_journal_unlink_failure_keeps_receipt_pending_for_next_recovery(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(root)
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )
            with patch.dict(
                os.environ,
                {
                    "HOME": home,
                    "DEFENSECLAW_HOME": app.cfg.data_dir,
                    "DEFENSECLAW_CONFIG": config_path,
                },
            ):
                journal = _write_hard_cut_recovery_journal(
                    plan,
                    receipt_path,
                    target_version="0.8.5",
                )
                with (
                    patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
                    patch("defenseclaw.commands.cmd_upgrade._restore_rollback_file"),
                    patch("defenseclaw.commands.cmd_upgrade._restore_rollback_gateway"),
                    patch("defenseclaw.commands.cmd_upgrade._install_wheel"),
                    patch("defenseclaw.commands.cmd_upgrade._verify_restored_bridge_artifacts"),
                    patch("defenseclaw.commands.cmd_upgrade._poll_installed_health"),
                    patch(
                        "defenseclaw.commands.cmd_upgrade._remove_hard_cut_recovery_journal",
                        side_effect=OSError("injected unlink failure"),
                    ),
                ):
                    restored = _execute_hard_cut_rollback(
                        plan,
                        app,
                        receipt_path,
                        failure_code="interrupted",
                        health_timeout=1,
                        retain_pending_on_failure=True,
                        recovery_journal_path=journal,
                    )

            self.assertFalse(restored)
            self.assertTrue(journal.exists())
            self.assertEqual(load_upgrade_receipt(receipt_path).status, "pending")

    def test_leased_mutator_capture_uses_private_spool_without_pipe_hang(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(root)
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )
            with patch.dict(
                os.environ,
                {
                    "HOME": home,
                    "DEFENSECLAW_HOME": app.cfg.data_dir,
                    "DEFENSECLAW_CONFIG": config_path,
                },
            ):
                _write_hard_cut_recovery_journal(
                    plan,
                    receipt_path,
                    target_version="0.8.5",
                )
                completed = _run_phase_two_mutator(
                    [sys.executable, "-c", "print('leased-output')"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

            self.assertEqual(completed.stdout.strip(), "leased-output")
            self.assertEqual(completed.stderr, "")

    def test_command_lifetime_lease_covers_direct_mutation_gaps(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(root)
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )
            acquired = Path(root) / "second-controller-acquired"
            cli_root = str(Path(__file__).resolve().parents[1])
            environment = {
                **os.environ,
                "HOME": home,
                "DEFENSECLAW_HOME": app.cfg.data_dir,
                "DEFENSECLAW_CONFIG": config_path,
                "PYTHONPATH": cli_root,
            }
            with patch.dict(os.environ, environment, clear=True):
                _write_hard_cut_recovery_journal(
                    plan,
                    receipt_path,
                    target_version="0.8.5",
                )
                command_context = click.Context(click.Command("lease-test"))
                with command_context:
                    _hold_phase_two_lease_for_command_lifetime()
                    competitor = subprocess.Popen(
                        [
                            sys.executable,
                            "-c",
                            (
                                "import sys; from pathlib import Path; "
                                "from defenseclaw.commands.cmd_upgrade import "
                                "_hold_phase_two_recovery_lease; "
                                "manager=_hold_phase_two_recovery_lease(sys.argv[1]); "
                                "manager.__enter__(); Path(sys.argv[2]).touch(); "
                                "manager.__exit__(None,None,None)"
                            ),
                            app.cfg.data_dir,
                            str(acquired),
                        ],
                        env=environment,
                    )
                    time.sleep(0.25)
                    self.assertFalse(acquired.exists())
                    Path(config_path).write_text("config_version: 8\n", encoding="utf-8")

                self.assertEqual(competitor.wait(timeout=5), 0)
                self.assertTrue(acquired.exists())

    @unittest.skipUnless(hasattr(signal, "SIGKILL"), "SIGKILL unavailable")
    def test_sigkill_during_target_install_recovers_exact_bridge_and_bundle_state(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, cursor_path, gateway_payload, home = self._prepare_plan(root)
            data_dir = Path(app.cfg.data_dir)
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )
            stack = data_dir / "observability-stack"
            existing = stack / "managed/existing.yaml"
            created = stack / "managed/created.yaml"
            manifest = stack / ".defenseclaw-bundle-manifest.json"
            custom = stack / "grafana/dashboards/team-custom.json"
            for item in (existing, created, manifest, custom):
                item.parent.mkdir(parents=True, exist_ok=True)
            bridge_existing = b"bridge existing\n"
            bridge_manifest = b'{"bundle_version":"0.8.4"}\n'
            existing.write_bytes(bridge_existing)
            manifest.write_bytes(bridge_manifest)
            custom.write_bytes(b'{"uid":"team-custom"}\n')

            bundle_backup = Path(plan.backup_dir) / "local-observability-stack"
            managed_backup = bundle_backup / "managed"
            (managed_backup / "managed").mkdir(parents=True)
            (managed_backup / "managed/existing.yaml").write_bytes(bridge_existing)
            (managed_backup / ".defenseclaw-bundle-manifest.json").write_bytes(
                bridge_manifest
            )
            metadata = bundle_backup / "refresh-backup.json"
            metadata.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "existing_paths": [
                            ".defenseclaw-bundle-manifest.json",
                            "managed/existing.yaml",
                        ],
                        "old_sha256": {
                            ".defenseclaw-bundle-manifest.json": hashlib.sha256(
                                bridge_manifest
                            ).hexdigest(),
                            "managed/existing.yaml": hashlib.sha256(
                                bridge_existing
                            ).hexdigest(),
                        },
                        "old_modes": {
                            ".defenseclaw-bundle-manifest.json": 0o600,
                            "managed/existing.yaml": 0o640,
                        },
                        "managed_paths": [
                            ".defenseclaw-bundle-manifest.json",
                            "managed/created.yaml",
                            "managed/existing.yaml",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(metadata, 0o600)

            cli_marker = Path(home) / ".defenseclaw/.venv/site-packages/defenseclaw/main.py"
            cli_marker.parent.mkdir(parents=True)
            cli_marker.write_bytes(b"bridge controller\n")
            with patch.dict(
                os.environ,
                {
                    "HOME": home,
                    "DEFENSECLAW_HOME": app.cfg.data_dir,
                    "DEFENSECLAW_CONFIG": config_path,
                },
            ):
                journal = _write_hard_cut_recovery_journal(
                    plan,
                    receipt_path,
                    target_version="0.8.5",
                )

                killer = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import os,signal,sys; from pathlib import Path; "
                            "cfg,cursor,env,gateway,existing,created,manifest,cli=sys.argv[1:]; "
                            "Path(cfg).write_text('config_version: 8\\n'); "
                            "Path(cursor).write_text('{\"schema\":1,\"applied\":[\"0.8.5\"]}\\n'); "
                            "Path(env).write_text('TARGET_ONLY=yes\\n'); "
                            "Path(gateway).write_bytes(b'target gateway'); "
                            "Path(existing).write_bytes(b'target existing\\n'); "
                            "Path(created).write_bytes(b'target created\\n'); "
                            "Path(manifest).write_bytes(b'{\"bundle_version\":\"0.8.5\"}\\n'); "
                            "Path(cli).write_bytes(b'partial target wheel'); "
                            "os.kill(os.getpid(), signal.SIGKILL)"
                        ),
                        config_path,
                        cursor_path,
                        str(data_dir / ".env"),
                        plan.active_gateway_path,
                        str(existing),
                        str(created),
                        str(manifest),
                        str(cli_marker),
                    ],
                    check=False,
                )
                self.assertEqual(killer.returncode, -signal.SIGKILL)

                def reinstall_bridge(wheel_path: str, os_name: str) -> None:
                    self.assertEqual(wheel_path, plan.rollback_wheel_path)
                    self.assertEqual(os_name, "linux")
                    cli_marker.write_bytes(b"bridge controller\n")

                with (
                    patch(
                        "defenseclaw.commands.cmd_upgrade._install_wheel",
                        side_effect=reinstall_bridge,
                    ),
                    patch("defenseclaw.commands.cmd_upgrade._verify_restored_bridge_artifacts"),
                    patch("defenseclaw.commands.cmd_upgrade._poll_installed_health"),
                    patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
                ):
                    recovered = _recover_interrupted_hard_cut(app.cfg.data_dir)

            self.assertTrue(recovered)
            self.assertFalse(journal.exists())
            self.assertEqual(Path(config_path).read_bytes(), b"config_version: 7\ngateway:\n  api_port: 18970\n")
            self.assertEqual(
                Path(cursor_path).read_bytes(),
                b'{"schema":1,"applied":["0.8.4"]}\n',
            )
            self.assertFalse((data_dir / ".env").exists())
            self.assertEqual(Path(plan.active_gateway_path).read_bytes(), gateway_payload)
            self.assertEqual(cli_marker.read_bytes(), b"bridge controller\n")
            self.assertEqual(existing.read_bytes(), bridge_existing)
            self.assertFalse(created.exists())
            self.assertEqual(manifest.read_bytes(), bridge_manifest)
            self.assertEqual(custom.read_bytes(), b'{"uid":"team-custom"}\n')
            receipt = load_upgrade_receipt(receipt_path)
            self.assertEqual(receipt.status, "rolled_back")
            self.assertEqual(receipt.failure_code, "interrupted")

    @unittest.skipUnless(hasattr(signal, "SIGKILL"), "SIGKILL unavailable")
    def test_parent_only_sigkill_leaves_mutator_lease_until_child_finishes(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(root)
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )
            started = Path(root) / "mutator-started"
            release = Path(root) / "release-mutator"
            finished = Path(root) / "mutator-finished"
            cli_root = str(Path(__file__).resolve().parents[1])
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": home,
                    "DEFENSECLAW_HOME": app.cfg.data_dir,
                    "DEFENSECLAW_CONFIG": config_path,
                    "PYTHONPATH": cli_root,
                }
            )
            with patch.dict(os.environ, environment, clear=True):
                journal = _write_hard_cut_recovery_journal(
                    plan,
                    receipt_path,
                    target_version="0.8.5",
                )
                child_code = (
                    "import sys,time; from pathlib import Path; "
                    "started,release,finished,config=map(Path,sys.argv[1:]); "
                    "started.write_text('started'); "
                    "deadline=time.monotonic()+15; "
                    "exec(\"while not release.exists():\\n"
                    "    assert time.monotonic() < deadline\\n"
                    "    time.sleep(0.02)\"); "
                    "config.write_text('config_version: 8\\n'); "
                    "finished.write_text('finished')"
                )
                controller_code = (
                    "import sys; "
                    "from defenseclaw.commands.cmd_upgrade import _run_phase_two_mutator; "
                    "result=_run_phase_two_mutator("
                    "[sys.executable,'-c',sys.argv[1],*sys.argv[2:]],check=False); "
                    "raise SystemExit(result.returncode)"
                )
                controller = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        controller_code,
                        child_code,
                        str(started),
                        str(release),
                        str(finished),
                        config_path,
                    ],
                    env=environment,
                )
                deadline = time.monotonic() + 30
                while not started.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(started.exists(), "leased child did not start")
                os.kill(controller.pid, signal.SIGKILL)
                self.assertEqual(controller.wait(timeout=5), -signal.SIGKILL)

                recovered: list[bool] = []
                recovery_errors: list[BaseException] = []

                def recover() -> None:
                    try:
                        recovered.append(_recover_interrupted_hard_cut(app.cfg.data_dir))
                    except BaseException as exc:  # pragma: no cover - surfaced below
                        recovery_errors.append(exc)

                with (
                    patch("defenseclaw.commands.cmd_upgrade._install_wheel"),
                    patch("defenseclaw.commands.cmd_upgrade._verify_restored_bridge_artifacts"),
                    patch("defenseclaw.commands.cmd_upgrade._poll_installed_health"),
                    patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
                ):
                    recovery_thread = threading.Thread(target=recover, daemon=True)
                    recovery_thread.start()
                    time.sleep(0.25)
                    self.assertTrue(recovery_thread.is_alive())
                    self.assertEqual(recovered, [])
                    self.assertTrue(journal.exists())
                    release.write_text("release", encoding="utf-8")
                    recovery_thread.join(timeout=10)

                self.assertFalse(recovery_thread.is_alive())
                self.assertEqual(recovery_errors, [])
                self.assertEqual(recovered, [True])
                self.assertTrue(finished.exists())
                self.assertFalse(journal.exists())
                self.assertEqual(
                    Path(config_path).read_bytes(),
                    b"config_version: 7\ngateway:\n  api_port: 18970\n",
                )


class TestTargetWheelMigrationCapabilities(unittest.TestCase):
    def test_legacy_and_v8_wheels_are_distinguished_without_execution(self):
        with TemporaryDirectory() as directory:
            legacy_path = os.path.join(directory, "legacy.whl")
            _write_migration_wheel(
                legacy_path,
                version="0.8.3",
                migration_versions=("0.3.0", "0.4.0", "0.5.0"),
                supports_bundle_flag=False,
                supported_config_versions=None,
            )
            legacy = _target_migration_capabilities(legacy_path)
            self.assertEqual(legacy.package_version, "0.8.3")
            self.assertNotIn("upgrade_handles_local_bundle", legacy.run_migrations_parameters)
            self.assertEqual(legacy.supported_config_versions, frozenset())

            v8_path = os.path.join(directory, "v8.whl")
            _write_migration_wheel(
                v8_path,
                version="0.8.5",
                migration_versions=("0.3.0", "0.8.5"),
                supports_bundle_flag=True,
                supported_config_versions=(8,),
            )
            v8 = _target_migration_capabilities(v8_path)
            self.assertEqual(v8.package_version, "0.8.5")
            self.assertIn("upgrade_handles_local_bundle", v8.run_migrations_parameters)
            self.assertEqual(v8.supported_config_versions, frozenset({8}))
            self.assertIn("0.8.5", v8.migration_versions)

    def test_hard_cut_wheel_requires_crash_surviving_mutator_wrapper(self):
        with TemporaryDirectory() as directory:
            wheel = os.path.join(directory, "target.whl")
            _write_migration_wheel(
                wheel,
                version="0.8.5",
                migration_versions=("0.8.5",),
                supports_bundle_flag=True,
                supported_config_versions=(8,),
            )
            _require_target_phase_two_mutator_wrapper(wheel)

            without_wrapper = os.path.join(directory, "missing-wrapper.whl")
            with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(
                without_wrapper, "w"
            ) as destination:
                for item in source.infolist():
                    if item.filename != "defenseclaw/phase_two_mutator.py":
                        destination.writestr(item, source.read(item))
            with self.assertRaisesRegex(ValueError, "lacks"):
                _require_target_phase_two_mutator_wrapper(without_wrapper)

    def test_bridge_target_is_not_forced_to_claim_v8_config_capability(self):
        bridge = _TargetMigrationCapabilities(
            package_version="0.8.4",
            run_migrations_parameters=frozenset({"from_version", "to_version", "openclaw_home", "data_dir"}),
            migration_versions=frozenset({"0.3.0", "0.4.0", "0.5.0"}),
            supported_config_versions=frozenset(),
        )
        _validate_target_migration_capabilities(
            bridge,
            target_version="0.8.4",
            source_version=7,
            upgrade_manifest={"required_cli_migrations": []},
        )

        with self.assertRaisesRegex(ValueError, "does not support config_version: 8"):
            _validate_target_migration_capabilities(
                _TargetMigrationCapabilities(
                    package_version="0.8.5",
                    run_migrations_parameters=bridge.run_migrations_parameters,
                    migration_versions=bridge.migration_versions,
                    supported_config_versions=frozenset(),
                ),
                target_version="0.8.5",
                source_version=7,
                upgrade_manifest=None,
            )

    def test_real_v7_installation_can_preflight_protocol_one_bridge_wheel(self):
        with TemporaryDirectory() as directory:
            bridge_path = os.path.join(directory, "bridge.whl")
            _write_migration_wheel(
                bridge_path,
                version="0.8.4",
                migration_versions=("0.3.0", "0.4.0", "0.5.0"),
                supports_bundle_flag=False,
                supported_config_versions=None,
            )
            with patch("defenseclaw.config.source_config_version", return_value=7):
                capabilities = _preflight_target_wheel_migrations(
                    bridge_path,
                    "0.8.4",
                    {"required_cli_migrations": []},
                )

        self.assertEqual(capabilities.package_version, "0.8.4")
        self.assertEqual(capabilities.supported_config_versions, frozenset())

    def test_stamped_v8_target_covers_source_and_manifest_requirements(self):
        v8 = _TargetMigrationCapabilities(
            package_version="0.8.5",
            run_migrations_parameters=frozenset({"upgrade_handles_local_bundle"}),
            migration_versions=frozenset({"0.3.0", "0.8.5"}),
            supported_config_versions=frozenset({8}),
        )
        _validate_target_migration_capabilities(
            v8,
            target_version="0.8.5",
            source_version=0,
            upgrade_manifest={"required_cli_migrations": ["0.8.5"]},
        )
        with self.assertRaisesRegex(ValueError, "release-stamped artifacts"):
            _validate_target_migration_capabilities(
                v8,
                target_version="0.8.6",
                source_version=8,
                upgrade_manifest=None,
            )
        with self.assertRaisesRegex(ValueError, "release-required migration"):
            _validate_target_migration_capabilities(
                v8,
                target_version="0.8.5",
                source_version=8,
                upgrade_manifest={"required_cli_migrations": ["0.8.6"]},
            )

    def test_bridge_generic_validation_ignores_unrequired_future_migration(self):
        unstamped = _TargetMigrationCapabilities(
            package_version="0.8.0",
            run_migrations_parameters=frozenset({"upgrade_handles_local_bundle"}),
            migration_versions=frozenset({"0.3.0", "0.8.5"}),
            supported_config_versions=frozenset({8}),
        )
        _validate_target_migration_capabilities(
            unstamped,
            target_version="0.8.0",
            source_version=0,
            upgrade_manifest=None,
        )
        with self.assertRaisesRegex(ValueError, "cannot run release-required migration"):
            _validate_target_migration_capabilities(
                unstamped,
                target_version="0.8.0",
                source_version=None,
                upgrade_manifest={"required_cli_migrations": ["0.8.5"]},
            )

    def test_static_inspector_rejects_incompatible_runner_call_shape(self):
        with TemporaryDirectory() as directory:
            wheel_path = os.path.join(directory, "bad-runner.whl")
            with zipfile.ZipFile(wheel_path, "w") as archive:
                archive.writestr(
                    "defenseclaw/migrations.py",
                    "SUPPORTED_CONFIG_VERSIONS = (8,)\n"
                    "MIGRATIONS = [('0.8.4', 'migration', None)]\n"
                    "def run_migrations(from_version, to_version):\n    return 0\n",
                )
                archive.writestr(
                    "defenseclaw-0.8.4.dist-info/METADATA",
                    "Metadata-Version: 2.4\nName: defenseclaw\nVersion: 0.8.4\n",
                )
            with self.assertRaisesRegex(ValueError, "must declare positional parameters"):
                _target_migration_capabilities(wheel_path)

    def test_static_inspector_rejects_malformed_migration_row(self):
        with TemporaryDirectory() as directory:
            wheel_path = os.path.join(directory, "bad-registry.whl")
            with zipfile.ZipFile(wheel_path, "w") as archive:
                archive.writestr(
                    "defenseclaw/migrations.py",
                    "SUPPORTED_CONFIG_VERSIONS = (8,)\n"
                    "MIGRATIONS = [('0.8.4',)]\n"
                    "def run_migrations(from_version, to_version, openclaw_home, data_dir=None):\n"
                    "    return 0\n",
                )
                archive.writestr(
                    "defenseclaw-0.8.4.dist-info/METADATA",
                    "Metadata-Version: 2.4\nName: defenseclaw\nVersion: 0.8.4\n",
                )
            with self.assertRaisesRegex(ValueError, "MIGRATIONS contains an invalid row"):
                _target_migration_capabilities(wheel_path)

    def test_installed_runner_passes_bundle_flag_only_when_supported(self):
        calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

        def execute(run_migrations):
            fake = types.ModuleType("defenseclaw.migrations")
            fake.run_migrations = run_migrations
            with TemporaryDirectory() as directory:
                result_path = os.path.join(directory, "result.json")
                argv = ["migration-runner", "0.8.3", "0.8.4", "/openclaw", "/data", result_path]
                with patch.dict(sys.modules, {"defenseclaw.migrations": fake}), patch.object(sys, "argv", argv):
                    exec(_INSTALLED_MIGRATION_SCRIPT, {})
                with open(result_path, encoding="utf-8") as stream:
                    self.assertEqual(json.load(stream), {"count": 1})

        def legacy(*args):
            calls.append((args, {}))
            return 1

        def current(*args, upgrade_handles_local_bundle=False):
            calls.append((args, {"upgrade_handles_local_bundle": upgrade_handles_local_bundle}))
            return 1

        def positional_only(
            from_version,
            to_version,
            openclaw_home,
            data_dir,
            upgrade_handles_local_bundle=False,
            /,
        ):
            calls.append(
                (
                    (from_version, to_version, openclaw_home, data_dir),
                    {"upgrade_handles_local_bundle": upgrade_handles_local_bundle},
                )
            )
            return 1

        execute(legacy)
        execute(current)
        execute(positional_only)
        self.assertEqual(calls[0][1], {})
        self.assertEqual(calls[1][1], {"upgrade_handles_local_bundle": True})
        self.assertEqual(calls[2][1], {"upgrade_handles_local_bundle": False})

    def test_upgrade_rejects_hard_cut_wheel_without_v8_capability_before_mutation(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()
        with TemporaryDirectory() as directory, ExitStack() as stack:
            app.cfg.data_dir = directory
            app.cfg.claw.home_dir = directory
            config_path = os.path.join(directory, "config.yaml")
            with open(config_path, "w", encoding="utf-8") as stream:
                stream.write("config_version: 7\ngateway:\n  api_port: 18970\n")
            wheel_path = os.path.join(directory, "defenseclaw-0.8.5-py3-none-any.whl")
            _write_migration_wheel(
                wheel_path,
                version="0.8.5",
                migration_versions=("0.3.0", "0.8.5"),
                supports_bundle_flag=True,
                supported_config_versions=None,
            )
            stack.enter_context(patch.dict(os.environ, {"DEFENSECLAW_CONFIG": config_path}))
            stack.enter_context(patch("defenseclaw.__version__", "0.8.4"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("darwin", "arm64"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_checksums",
                    return_value={
                        "defenseclaw_0.8.5_darwin_arm64.tar.gz": "0" * 64,
                        "defenseclaw-0.8.5-py3-none-any.whl": "0" * 64,
                        "upgrade-manifest.json": "0" * 64,
                    },
                )
            )
            manifest = {
                "schema_version": 1,
                "release_version": "0.8.5",
                "min_upgrade_protocol": 2,
                "controller_upgrade_protocol": 2,
                "migration_failure_policy": "fail",
                "required_cli_migrations": ["0.8.5"],
                "minimum_source_version": "0.8.4",
                "required_bridge_version": "0.8.4",
                "auto_bridge_from": ["0.8.3"],
            }
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                    return_value=manifest,
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._acquire_bridge_rollback_artifacts",
                    return_value="/tmp/staged-bridge",
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_gateway",
                    return_value=("/tmp/gateway", "defenseclaw_0.8.5_darwin_arm64.tar.gz"),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_wheel",
                    return_value=(wheel_path, "defenseclaw-0.8.5-py3-none-any.whl"),
                )
            )
            backup = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._create_backup"))
            stop = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))
            gateway = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_gateway"))
            wheel = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_wheel"))

            result = runner.invoke(upgrade, ["--yes", "--version", "0.8.5"], obj=app)

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn("does not support config_version: 8", result.output)
        self.assertIn("No services were stopped", result.output)
        backup.assert_not_called()
        stop.assert_not_called()
        gateway.assert_not_called()
        wheel.assert_not_called()


class TestUpgradeWheelInstall(unittest.TestCase):
    def test_install_wheel_uses_managed_venv_python_after_creating_venv(self):
        with (
            TemporaryDirectory() as home,
            patch.dict(os.environ, {"HOME": home}),
            patch("shutil.which", return_value="/usr/bin/uv"),
            patch("subprocess.run") as run_mock,
        ):
            venv_python = os.path.join(home, ".defenseclaw", ".venv", "bin", "python")

            def side_effect(args, **_kwargs):
                if args[:3] == ["/usr/bin/uv", "--no-config", "venv"]:
                    os.makedirs(os.path.dirname(venv_python), exist_ok=True)
                    with open(venv_python, "w") as f:
                        f.write("# python")
                return Mock(returncode=0)

            run_mock.side_effect = side_effect

            _install_wheel("/tmp/defenseclaw.whl")

        pip_call = run_mock.call_args_list[-1].args[0]
        self.assertEqual(pip_call[:5], ["/usr/bin/uv", "--no-config", "pip", "install", "--python"])
        self.assertEqual(pip_call[5], venv_python)

    def test_preflight_wheel_install_uses_dry_run_without_managed_venv(self):
        with (
            TemporaryDirectory() as home,
            patch.dict(os.environ, {"HOME": home}),
            patch("shutil.which", return_value="/usr/bin/uv"),
            patch("subprocess.run") as run_mock,
        ):

            def side_effect(args, **_kwargs):
                if args[:3] == ["/usr/bin/uv", "--no-config", "venv"]:
                    venv_python = os.path.join(args[3], "bin", "python")
                    os.makedirs(os.path.dirname(venv_python), exist_ok=True)
                    with open(venv_python, "w") as f:
                        f.write("# python")
                return Mock(returncode=0)

            run_mock.side_effect = side_effect

            _preflight_wheel_install("/tmp/defenseclaw.whl", "darwin")

        calls = [call.args[0] for call in run_mock.call_args_list]
        self.assertEqual(calls[0][:3], ["/usr/bin/uv", "--no-config", "venv"])
        self.assertEqual(calls[1][:5], ["/usr/bin/uv", "--no-config", "pip", "install", "--python"])
        self.assertIn("--dry-run", calls[1])
        self.assertEqual(calls[1][-1], "/tmp/defenseclaw.whl")

    def test_run_installed_migrations_uses_managed_venv_python(self):
        with TemporaryDirectory() as home, patch.dict(os.environ, {"HOME": home}), patch("subprocess.run") as run_mock:
            venv_python = os.path.join(home, ".defenseclaw", ".venv", "bin", "python")
            os.makedirs(os.path.dirname(venv_python), exist_ok=True)
            with open(venv_python, "w") as f:
                f.write("# python")

            def side_effect(args, **_kwargs):
                result_path = args[-1]
                with open(result_path, "w", encoding="utf-8") as f:
                    json.dump({"count": 1}, f)
                return Mock(returncode=0)

            run_mock.side_effect = side_effect

            count = _run_installed_migrations(
                "0.7.0",
                "0.8.0",
                "/tmp/openclaw",
                "/tmp/defenseclaw",
                os_name="darwin",
            )

        self.assertEqual(count, 1)
        call = run_mock.call_args.args[0]
        self.assertEqual(call[0], venv_python)
        self.assertEqual(call[1:3], ["-I", "-c"])
        self.assertIn("inspect.signature(run_migrations).parameters", call[3])
        self.assertIn('kwargs["upgrade_handles_local_bundle"] = True', call[3])
        self.assertNotIn("upgrade_handles_local_bundle=True", call[3])
        self.assertEqual(call[4:8], ["0.7.0", "0.8.0", "/tmp/openclaw", "/tmp/defenseclaw"])


class TestUpgradeTestReleaseBase(unittest.TestCase):
    def test_loopback_release_base_requires_explicit_test_gate(self):
        base = "http://127.0.0.1:8765/releases/download/"
        with patch.dict(
            os.environ,
            {
                "DEFENSECLAW_UPGRADE_TEST_MODE": "1",
                "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL": base,
            },
        ):
            self.assertEqual(
                _release_download_base(),
                "http://127.0.0.1:8765/releases/download",
            )

        with (
            patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_UPGRADE_TEST_MODE": "",
                    "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL": base,
                },
            ),
            self.assertRaises(SystemExit),
        ):
            _release_download_base()

    def test_test_release_base_rejects_non_loopback_or_ambiguous_authority(self):
        unsafe = (
            "https://127.0.0.1:8765/releases/download",
            "http://example.com:8765/releases/download",
            "http://localhost:8765/releases/download",
            "http://127.0.0.1/releases/download",
            "http://user@127.0.0.1:8765/releases/download",
            "http://127.0.0.1:8765/releases/download?target=other",
        )
        for base in unsafe:
            with self.subTest(base=base), patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_UPGRADE_TEST_MODE": "1",
                    "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL": base,
                },
            ), self.assertRaises(SystemExit):
                _release_download_base()

    def test_preflight_uses_gated_loopback_base_for_candidate_assets(self):
        response = Mock(status_code=200)
        with (
            patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_UPGRADE_TEST_MODE": "1",
                    "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL": (
                        "http://127.0.0.1:8765/releases/download"
                    ),
                },
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade.requests.head",
                return_value=response,
            ) as head,
        ):
            _preflight_check("0.8.5", "linux", "amd64")

        self.assertEqual(
            [call.args[0] for call in head.call_args_list],
            [
                "http://127.0.0.1:8765/releases/download/0.8.5/defenseclaw_0.8.5_linux_amd64.tar.gz",
                "http://127.0.0.1:8765/releases/download/0.8.5/defenseclaw-0.8.5-py3-none-any.whl",
            ],
        )
        self.assertTrue(
            all(call.kwargs["allow_redirects"] is False for call in head.call_args_list)
        )

    def test_loopback_candidate_endpoint_cannot_redirect_to_remote_host(self):
        with (
            patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_UPGRADE_TEST_MODE": "1",
                    "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL": "http://127.0.0.1:8765",
                },
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade.requests.head",
                return_value=Mock(status_code=302, headers={"Location": "https://example.com"}),
            ) as head,
            self.assertRaises(SystemExit),
        ):
            _preflight_check("0.8.5", "linux", "amd64")

        self.assertFalse(head.call_args.kwargs["allow_redirects"])


class TestUpgradeFreshProcessHandoff(unittest.TestCase):
    def test_handoff_uses_isolated_installed_cli_and_propagates_argv_env_and_exit(self):
        with (
            TemporaryDirectory() as home,
            patch.dict(
                os.environ,
                {
                    "HOME": home,
                    "DEFENSECLAW_UPGRADE_FRESH_PROCESS": "",
                    "DEFENSECLAW_UPGRADE_TEST_MODE": "1",
                    "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL": (
                        "http://127.0.0.1:8765/releases/download"
                    ),
                    "HANDOFF_TEST_PRESERVED": "preserved",
                    "PYTHONHOME": "/poisoned/home",
                    "PYTHONPATH": "/poisoned/path",
                },
            ),
            patch("defenseclaw.commands.cmd_upgrade.os.path.isfile", return_value=True),
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=23),
            ) as run_mock,
            self.assertRaises(SystemExit) as raised,
        ):
            _handoff_to_installed_upgrade(
                "0.8.5",
                health_timeout=41,
                allow_unverified=True,
                os_name="linux",
            )

        self.assertEqual(raised.exception.code, 23)
        expected_python = os.path.join(home, ".defenseclaw", ".venv", "bin", "python")
        self.assertEqual(
            run_mock.call_args.args[0],
            [
                expected_python,
                "-I",
                "-m",
                "defenseclaw.main",
                "upgrade",
                "--yes",
                "--version",
                "0.8.5",
                "--health-timeout",
                "41",
                "--allow-unverified",
            ],
        )
        self.assertFalse(run_mock.call_args.kwargs["check"])
        child_env = run_mock.call_args.kwargs["env"]
        self.assertEqual(child_env["DEFENSECLAW_UPGRADE_FRESH_PROCESS"], "1")
        self.assertEqual(child_env["DEFENSECLAW_UPGRADE_TEST_MODE"], "1")
        self.assertEqual(
            child_env["DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL"],
            "http://127.0.0.1:8765/releases/download",
        )
        self.assertEqual(child_env["HANDOFF_TEST_PRESERVED"], "preserved")
        self.assertNotIn("PYTHONHOME", child_env)
        self.assertNotIn("PYTHONPATH", child_env)

    def test_handoff_never_returns_when_child_succeeds(self):
        with (
            patch.dict(os.environ, {"DEFENSECLAW_UPGRADE_FRESH_PROCESS": ""}),
            patch("defenseclaw.commands.cmd_upgrade.os.path.isfile", return_value=True),
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0),
            ),
            self.assertRaises(SystemExit) as raised,
        ):
            _handoff_to_installed_upgrade("0.8.5", health_timeout=60, os_name="windows")

        self.assertEqual(raised.exception.code, 0)

    def test_handoff_refuses_recursive_invocation(self):
        with (
            patch.dict(os.environ, {"DEFENSECLAW_UPGRADE_FRESH_PROCESS": "1"}),
            patch("defenseclaw.commands.cmd_upgrade.subprocess.run") as run_mock,
            self.assertRaises(SystemExit) as raised,
        ):
            _handoff_to_installed_upgrade("0.8.5", health_timeout=60, os_name="linux")

        self.assertEqual(raised.exception.code, 1)
        run_mock.assert_not_called()


class TestUpgradeSameVersionRepair(unittest.TestCase):
    def test_same_version_reapplies_migrations(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "9.9.9"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("darwin", "arm64"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._require_hard_cut_manifest_contract"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_checksums",
                    return_value={
                        "defenseclaw_9.9.9_darwin_arm64.tar.gz": "0" * 64,
                        "defenseclaw-9.9.9-py3-none-any.whl": "0" * 64,
                        "upgrade-manifest.json": "0" * 64,
                    },
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                    return_value=None,
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_gateway",
                    return_value=("/tmp/defenseclaw-gateway", "defenseclaw_9.9.9_darwin_arm64.tar.gz"),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_wheel",
                    return_value=("/tmp/defenseclaw.whl", "defenseclaw-9.9.9-py3-none-any.whl"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_wheel_install"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_gateway"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_wheel"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._verify_installed_gateway_version"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._check_post_upgrade_drift"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._create_backup",
                    return_value="/tmp/backup",
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._poll_health"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(returncode=0),
                )
            )
            run_migrations = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._run_installed_migrations", return_value=1)
            )
            result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)

            receipts = list((Path(data_dir) / UPGRADE_RECEIPT_DIRECTORY).glob("*.json"))
            self.assertEqual(len(receipts), 1)
            receipt = load_upgrade_receipt(receipts[0])
            self.assertEqual(receipt.status, "succeeded")
            self.assertEqual(receipt.migration_status, "completed")
            self.assertEqual(receipt.migration_count, 1)

        self.assertEqual(result.exit_code, 0, msg=result.output)
        run_migrations.assert_called_once()

    def test_required_migration_failure_leaves_target_services_stopped(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            backup_dir = os.path.join(data_dir, "backups", "upgrade")
            stack.enter_context(patch("defenseclaw.__version__", "9.9.8"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("darwin", "arm64"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._require_hard_cut_manifest_contract"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_checksums",
                    return_value={
                        "defenseclaw_9.9.9_darwin_arm64.tar.gz": "0" * 64,
                        "defenseclaw-9.9.9-py3-none-any.whl": "0" * 64,
                        "upgrade-manifest.json": "0" * 64,
                    },
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                    return_value={
                        "migration_failure_policy": "fail",
                        "required_cli_migrations": ["9.9.9"],
                    },
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_gateway",
                    return_value=(
                        "/tmp/defenseclaw-gateway",
                        "defenseclaw_9.9.9_darwin_arm64.tar.gz",
                    ),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_wheel",
                    return_value=(
                        "/tmp/defenseclaw.whl",
                        "defenseclaw-9.9.9-py3-none-any.whl",
                    ),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_wheel_install"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._install_gateway",
                    return_value="/tmp/installed-defenseclaw-gateway",
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_wheel"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._verify_installed_gateway_version"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._create_backup",
                    return_value=backup_dir,
                )
            )
            run_silent = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))
            poll_health = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._poll_health"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_installed_migrations", return_value=0))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._print_migration_cursor_summary"))
            result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)

            receipts = list((Path(data_dir) / UPGRADE_RECEIPT_DIRECTORY).glob("*.json"))
            self.assertEqual(len(receipts), 1)
            receipt = load_upgrade_receipt(receipts[0])
            self.assertEqual(receipt.status, "failed")
            self.assertEqual(receipt.failure_code, "required_migration_failed")

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn("Required migration failed; target services remain stopped", result.output)
        self.assertIn(f"Recovery backup: {backup_dir}", result.output)
        self.assertIn("Services Remain Stopped", result.output)
        self.assertNotIn("Upgrade Complete", result.output)
        self.assertEqual(run_silent.call_count, 1)
        self.assertEqual(run_silent.call_args.args[0], ["defenseclaw-gateway", "stop"])
        poll_health.assert_not_called()

    def test_upgrade_preflights_wheel_before_gateway_install(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()
        events: list[str] = []

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "9.9.9"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("darwin", "arm64"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._require_hard_cut_manifest_contract"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_checksums",
                    return_value={
                        "defenseclaw_9.9.9_darwin_arm64.tar.gz": "0" * 64,
                        "defenseclaw-9.9.9-py3-none-any.whl": "0" * 64,
                        "upgrade-manifest.json": "0" * 64,
                    },
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                    return_value=None,
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_gateway",
                    return_value=("/tmp/defenseclaw-gateway", "defenseclaw_9.9.9_darwin_arm64.tar.gz"),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_wheel",
                    return_value=("/tmp/defenseclaw.whl", "defenseclaw-9.9.9-py3-none-any.whl"),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._preflight_wheel_install",
                    side_effect=lambda *_args, **_kwargs: events.append("preflight"),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._install_gateway",
                    side_effect=lambda *_args, **_kwargs: events.append("gateway") or "/tmp/gateway",
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._install_wheel",
                    side_effect=lambda *_args: events.append("wheel"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._verify_installed_gateway_version"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._check_post_upgrade_drift"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._create_backup",
                    return_value="/tmp/backup",
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._poll_health"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_installed_migrations", return_value=0))
            result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertLess(events.index("preflight"), events.index("gateway"))
        self.assertLess(events.index("gateway"), events.index("wheel"))


class TestUpgradeServiceVerification(unittest.TestCase):
    def _invoke_upgrade(
        self,
        *,
        gateway_start_ok: bool = True,
        health_side_effect=None,
        install_side_effect=None,
        migration_side_effect=None,
        upgrade_manifest=None,
        rollback_plan=None,
        rollback_result: bool = True,
    ):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "9.9.8"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("darwin", "arm64"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._require_hard_cut_manifest_contract"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._acquire_bridge_rollback_artifacts",
                    return_value="/tmp/staged-bridge-artifacts",
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_checksums",
                    return_value={
                        "defenseclaw_9.9.9_darwin_arm64.tar.gz": "0" * 64,
                        "defenseclaw-9.9.9-py3-none-any.whl": "0" * 64,
                        "upgrade-manifest.json": "0" * 64,
                    },
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                    return_value=upgrade_manifest,
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_gateway",
                    return_value=(
                        "/tmp/defenseclaw-gateway",
                        "defenseclaw_9.9.9_darwin_arm64.tar.gz",
                    ),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_wheel",
                    return_value=(
                        "/tmp/defenseclaw.whl",
                        "defenseclaw-9.9.9-py3-none-any.whl",
                    ),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_wheel_install"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._install_gateway",
                    return_value="/tmp/installed-defenseclaw-gateway",
                    side_effect=install_side_effect,
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_wheel"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._verify_installed_gateway_version"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._create_backup",
                    return_value=os.path.join(data_dir, "backups", "upgrade"),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_installed_migrations",
                    return_value=0,
                    side_effect=migration_side_effect,
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._print_migration_cursor_summary"))
            self.assert_required_migrations = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._assert_required_cli_migrations")
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._check_post_upgrade_drift"))
            self.prepare_rollback = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._prepare_hard_cut_rollback_plan",
                    return_value=rollback_plan,
                )
            )
            self.write_recovery_journal = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._write_hard_cut_recovery_journal",
                    return_value=Path(data_dir) / ".upgrade-recovery/phase-two-active.json",
                )
            )
            self.hold_recovery_lease = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._hold_phase_two_lease_for_command_lifetime"
                )
            )
            self.remove_recovery_journal = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._remove_hard_cut_recovery_journal"
                )
            )
            self.execute_rollback = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._execute_hard_cut_rollback",
                    return_value=rollback_result,
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._reload_post_upgrade_config",
                    return_value=app.cfg,
                )
            )

            def run_silent(args, *_messages):
                if rollback_plan is not None:
                    self.write_recovery_journal.assert_called_once()
                if args == ["defenseclaw-gateway", "start"]:
                    return gateway_start_ok
                return True

            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_silent",
                    side_effect=run_silent,
                )
            )
            poll_health = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._poll_health",
                    side_effect=health_side_effect,
                )
            )

            result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)
            receipt_paths = list((Path(data_dir) / UPGRADE_RECEIPT_DIRECTORY).glob("*.json"))
            self.assertEqual(len(receipt_paths), 1)
            receipt = load_upgrade_receipt(receipt_paths[0])

        return result, receipt, poll_health

    def test_gateway_start_failure_is_fatal_and_records_failed_receipt(self):
        result, receipt, poll_health = self._invoke_upgrade(gateway_start_ok=False)

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertEqual(receipt.status, "failed")
        self.assertEqual(receipt.failure_code, "health_check_failed")
        self.assertIn("Gateway failed to start", result.output)
        self.assertNotIn("Upgrade Complete", result.output)
        poll_health.assert_not_called()

    def test_health_timeout_is_fatal_and_records_failed_receipt(self):
        result, receipt, poll_health = self._invoke_upgrade(health_side_effect=SystemExit(1))

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertEqual(receipt.status, "failed")
        self.assertEqual(receipt.failure_code, "health_check_failed")
        self.assertNotIn("Upgrade Complete", result.output)
        poll_health.assert_called_once()

    def test_healthy_gateway_still_completes_successfully(self):
        result, receipt, poll_health = self._invoke_upgrade()

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(receipt.status, "succeeded")
        self.assertEqual(receipt.failure_code, "")
        self.assertIn("Upgrade Complete", result.output)
        poll_health.assert_called_once()

    def test_restart_failure_does_not_mask_original_install_failure(self):
        result, receipt, poll_health = self._invoke_upgrade(
            gateway_start_ok=False,
            install_side_effect=RuntimeError("install exploded"),
        )

        self.assertIsInstance(result.exception, RuntimeError)
        self.assertEqual(str(result.exception), "install exploded")
        self.assertEqual(receipt.status, "failed")
        self.assertEqual(receipt.failure_code, "install_failed")
        self.assertIn("preserving the original upgrade error", result.output)
        self.assertNotIn("Upgrade Complete", result.output)
        poll_health.assert_not_called()

    def test_hard_cut_install_failure_invokes_rollback_transaction(self):
        manifest = {
            "minimum_source_version": "9.9.8",
            "required_bridge_version": "9.9.8",
            "auto_bridge_from": ["9.9.7"],
        }
        plan = Mock(name="rollback-plan")
        result, receipt, _poll_health = self._invoke_upgrade(
            install_side_effect=RuntimeError("target install failed"),
            upgrade_manifest=manifest,
            rollback_plan=plan,
        )

        self.assertIsInstance(result.exception, RuntimeError)
        self.prepare_rollback.assert_called_once()
        self.execute_rollback.assert_called_once()
        self.assertEqual(self.execute_rollback.call_args.args[0], plan)
        self.assertEqual(self.execute_rollback.call_args.kwargs["failure_code"], "install_failed")
        self.assertTrue(self.execute_rollback.call_args.kwargs["retain_pending_on_failure"])
        self.assertEqual(receipt.status, "pending")
        self.assertIn("Upgrade Rolled Back", result.output)
        self.assertNotIn("Upgrade Complete", result.output)

    def test_hard_cut_migration_subprocess_failure_rolls_back_even_if_cursor_was_written(self):
        manifest = {
            "minimum_source_version": "9.9.8",
            "required_bridge_version": "9.9.8",
            "auto_bridge_from": ["9.9.7"],
            "required_cli_migrations": ["0.8.5"],
            "migration_failure_policy": "fail",
        }
        plan = Mock(name="rollback-plan")

        def fail_after_cursor_write(_source, _target, _openclaw_home, data_dir, **_kwargs):
            Path(data_dir, ".migration_state.json").write_text(
                '{"schema":1,"applied":["0.8.5"]}\n',
                encoding="utf-8",
            )
            raise subprocess.CalledProcessError(17, ["installed-migration-runner"])

        result, receipt, poll_health = self._invoke_upgrade(
            migration_side_effect=fail_after_cursor_write,
            upgrade_manifest=manifest,
            rollback_plan=plan,
        )

        self.assertIsInstance(result.exception, subprocess.CalledProcessError)
        self.prepare_rollback.assert_called_once()
        self.execute_rollback.assert_called_once()
        self.assertEqual(self.execute_rollback.call_args.args[0], plan)
        self.assertEqual(
            self.execute_rollback.call_args.kwargs["failure_code"],
            "migration_failed",
        )
        self.assert_required_migrations.assert_not_called()
        poll_health.assert_not_called()
        self.assertEqual(receipt.status, "pending")
        self.assertIn("refusing partial target activation", result.output)
        self.assertNotIn("Upgrade Complete", result.output)

    def test_hard_cut_start_failure_invokes_rollback_transaction(self):
        manifest = {
            "minimum_source_version": "9.9.8",
            "required_bridge_version": "9.9.8",
            "auto_bridge_from": ["9.9.7"],
        }
        plan = Mock(name="rollback-plan")
        result, receipt, poll_health = self._invoke_upgrade(
            gateway_start_ok=False,
            upgrade_manifest=manifest,
            rollback_plan=plan,
        )

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.prepare_rollback.assert_called_once()
        self.execute_rollback.assert_called_once()
        self.assertEqual(self.execute_rollback.call_args.args[0], plan)
        self.assertEqual(self.execute_rollback.call_args.kwargs["failure_code"], "health_check_failed")
        self.assertEqual(receipt.status, "pending")
        self.assertIn("Upgrade Rolled Back", result.output)
        self.assertNotIn("Upgrade Complete", result.output)
        poll_health.assert_not_called()

    def test_incomplete_hard_cut_rollback_never_claims_rolled_back(self):
        manifest = {
            "minimum_source_version": "9.9.8",
            "required_bridge_version": "9.9.8",
            "auto_bridge_from": ["9.9.7"],
        }
        result, _receipt, _poll_health = self._invoke_upgrade(
            install_side_effect=RuntimeError("target install failed"),
            upgrade_manifest=manifest,
            rollback_plan=Mock(name="rollback-plan"),
            rollback_result=False,
        )

        self.assertIsInstance(result.exception, RuntimeError)
        self.assertIn("Rollback Incomplete", result.output)
        self.assertNotIn("Upgrade Rolled Back", result.output)
        self.assertNotIn("Upgrade Complete", result.output)

    def test_health_timeout_helper_raises_nonzero(self):
        with self.assertRaises(SystemExit) as raised:
            _poll_health(Config(), timeout_seconds=0)

        self.assertEqual(raised.exception.code, 1)

    def test_health_waits_for_expected_binary_provenance(self):
        client = Mock()
        client.health.side_effect = [
            {
                "gateway": {"state": "running"},
                "provenance": {"binary_version": "0.8.5"},
            },
            {
                "gateway": {"state": "running"},
                "provenance": {"binary_version": "0.8.4"},
            },
        ]
        with (
            patch("defenseclaw.gateway.OrchestratorClient", return_value=client),
            patch(
                "defenseclaw.commands.cmd_upgrade.time.monotonic",
                side_effect=[0.0, 0.0, 0.0],
            ),
            patch("defenseclaw.commands.cmd_upgrade.time.sleep"),
        ):
            _poll_health(
                Config(),
                timeout_seconds=1,
                expected_version="0.8.4",
            )

        self.assertEqual(client.health.call_count, 2)

    def test_restart_and_health_use_fresh_post_migration_config_and_dotenv(self):
        app = AppContext()
        app.cfg = Config(gateway=GatewayConfig(api_port=19001, token="stale-value"))
        # ``token_env`` accepts an operator-selected environment variable.
        # Keep this fixture outside the reserved ``DEFENSECLAW_*`` namespace:
        # those names are production API and must be declared in the shared
        # registry, while this value exists only for this isolated test.
        env_name = "TEST_UPGRADE_GATEWAY_TOKEN"

        with TemporaryDirectory() as data_dir:
            config_path = os.path.join(data_dir, "config.yaml")
            with open(config_path, "w", encoding="utf-8") as stream:
                stream.write(
                    "config_version: 8\n"
                    f"data_dir: {data_dir}\n"
                    "gateway:\n"
                    "  api_bind: 127.0.0.1\n"
                    "  api_port: 19002\n"
                    f"  token_env: {env_name}\n"
                )
            with open(os.path.join(data_dir, ".env"), "w", encoding="utf-8") as stream:
                stream.write(f"{env_name}=fresh-value\n")

            with (
                patch.dict(os.environ, {"DEFENSECLAW_CONFIG": config_path}),
                patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
                patch("defenseclaw.commands.cmd_upgrade._poll_health") as poll_health,
            ):
                os.environ.pop(env_name, None)
                _start_and_verify_services(app, 7, data_dir=data_dir)
                fresh_token = app.cfg.gateway.resolved_token()

            self.assertEqual(app.cfg.gateway.api_port, 19002)
            self.assertEqual(fresh_token, "fresh-value")
            poll_health.assert_called_once_with(app.cfg, 7, expected_version=None)

    def test_hard_cut_restart_never_imports_the_target_config_in_source_process(self):
        app = AppContext()
        app.cfg = Config()
        plan = Mock(os_name="linux")

        with (
            patch("defenseclaw.commands.cmd_upgrade._refresh_target_dotenv_environment") as refresh,
            patch("defenseclaw.commands.cmd_upgrade._reload_post_upgrade_config") as reload_config,
            patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
            patch("defenseclaw.commands.cmd_upgrade._poll_health") as in_process_health,
            patch("defenseclaw.commands.cmd_upgrade._poll_installed_health") as installed_health,
        ):
            _start_and_verify_services(
                app,
                13,
                data_dir="/private/bridge-data",
                expected_version="0.8.5",
                rollback_plan=plan,
            )

        refresh.assert_called_once_with(plan)
        reload_config.assert_not_called()
        in_process_health.assert_not_called()
        installed_health.assert_called_once_with(
            "/private/bridge-data",
            13,
            "0.8.5",
            os_name="linux",
        )

    def test_hard_cut_refresh_replaces_only_source_dotenv_values(self):
        with TemporaryDirectory() as data_dir:
            Path(data_dir, ".env").write_text(
                "SOURCE_VALUE=target\nAMBIENT_OVERRIDE=target\nTARGET_ONLY=created\n",
                encoding="utf-8",
            )
            plan = Mock(
                data_dir=data_dir,
                source_dotenv_values={
                    "SOURCE_VALUE": "source",
                    "AMBIENT_OVERRIDE": "source",
                },
            )
            with patch.dict(
                os.environ,
                {
                    "SOURCE_VALUE": "source",
                    "AMBIENT_OVERRIDE": "operator",
                },
                clear=True,
            ):
                _refresh_target_dotenv_environment(plan)
                self.assertEqual(os.environ["SOURCE_VALUE"], "target")
                self.assertEqual(os.environ["AMBIENT_OVERRIDE"], "operator")
                self.assertEqual(os.environ["TARGET_ONLY"], "created")

    def test_hard_cut_refresh_rejects_invalid_dotenv_keys(self):
        with TemporaryDirectory() as data_dir:
            Path(data_dir, ".env").write_text("NOT-AN-ENV-KEY=value\n", encoding="utf-8")
            plan = Mock(data_dir=data_dir, source_dotenv_values={})
            with self.assertRaisesRegex(OSError, "invalid environment entry"):
                _refresh_target_dotenv_environment(plan)

    def test_installed_health_uses_isolated_managed_interpreter(self):
        with TemporaryDirectory() as home:
            with (
                patch.dict(
                    os.environ,
                    {
                        "HOME": home,
                        "PYTHONHOME": "/poisoned/home",
                        "PYTHONPATH": "/poisoned/path",
                        "PRESERVED_FOR_HEALTH": "yes",
                    },
                ),
                patch("defenseclaw.commands.cmd_upgrade.os.path.isfile", return_value=True),
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(returncode=0),
                ) as run_mock,
            ):
                _poll_installed_health(
                    "/private/data",
                    19,
                    "0.8.5",
                    os_name="linux",
                )

        expected_python = os.path.join(home, ".defenseclaw", ".venv", "bin", "python")
        self.assertEqual(
            run_mock.call_args.args[0],
            [
                expected_python,
                "-I",
                "-c",
                _INSTALLED_HEALTH_SCRIPT,
                "/private/data",
                "19",
                "0.8.5",
            ],
        )
        child_env = run_mock.call_args.kwargs["env"]
        self.assertNotIn("PYTHONHOME", child_env)
        self.assertNotIn("PYTHONPATH", child_env)
        self.assertEqual(child_env["PRESERVED_FOR_HEALTH"], "yes")
        self.assertEqual(run_mock.call_args.kwargs["timeout"], 34)

    def test_installed_health_propagates_failed_fresh_probe(self):
        with (
            patch("defenseclaw.commands.cmd_upgrade.os.path.isfile", return_value=True),
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=17),
            ),
            self.assertRaises(SystemExit) as raised,
        ):
            _poll_installed_health("/private/data", 1, "0.8.4", os_name="windows")

        self.assertEqual(raised.exception.code, 17)


class TestUpgradeWithoutOpenClawCli(unittest.TestCase):
    """Regression: when the `openclaw` CLI is not installed, the post-restart
    hook used to crash with FileNotFoundError because subprocess.run() raises
    before check=False can take effect. The upgrade must instead degrade
    gracefully and exit 0."""

    def test_upgrade_succeeds_when_openclaw_cli_missing(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        def fake_run(args, **_kwargs):
            if args and args[0] == "openclaw":
                raise FileNotFoundError(2, "No such file or directory", "openclaw")
            return Mock(returncode=0)

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "9.9.9"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("darwin", "arm64"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._require_hard_cut_manifest_contract"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_checksums",
                    return_value={
                        "defenseclaw_9.9.9_darwin_arm64.tar.gz": "0" * 64,
                        "defenseclaw-9.9.9-py3-none-any.whl": "0" * 64,
                        "upgrade-manifest.json": "0" * 64,
                    },
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                    return_value=None,
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_gateway",
                    return_value=("/tmp/defenseclaw-gateway", "defenseclaw_9.9.9_darwin_arm64.tar.gz"),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_wheel",
                    return_value=("/tmp/defenseclaw.whl", "defenseclaw-9.9.9-py3-none-any.whl"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_wheel_install"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_gateway"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_wheel"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._verify_installed_gateway_version"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._check_post_upgrade_drift"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._create_backup",
                    return_value="/tmp/backup",
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._poll_health"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    side_effect=fake_run,
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_installed_migrations", return_value=0))
            result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Could not restart OpenClaw gateway automatically", result.output)
        self.assertIn("Run manually: openclaw gateway restart", result.output)


class TestChecksumVerification(unittest.TestCase):
    """Supply-chain: every artifact must match a published checksum or be
    refused. A successful checksum is silent; a mismatch aborts; an
    unknown filename in the manifest aborts. ``_download_checksums`` is
    network-bound so we patch ``requests.get`` directly."""

    def test_verify_sha256_passes_on_match(self):
        with TemporaryDirectory() as tmp:
            artifact = os.path.join(tmp, "release.tar.gz")
            payload = b"binary contents"
            with open(artifact, "wb") as f:
                f.write(payload)
            digest = hashlib.sha256(payload).hexdigest()
            checksums = {"release.tar.gz": digest}

            _verify_sha256(artifact, "release.tar.gz", checksums)

    def test_verify_sha256_aborts_on_mismatch(self):
        with TemporaryDirectory() as tmp:
            artifact = os.path.join(tmp, "release.tar.gz")
            with open(artifact, "wb") as f:
                f.write(b"tampered contents")
            checksums = {
                "release.tar.gz": hashlib.sha256(b"original contents").hexdigest(),
            }

            with self.assertRaises(SystemExit) as ctx:
                _verify_sha256(artifact, "release.tar.gz", checksums)
            self.assertEqual(ctx.exception.code, 1)

    def test_verify_sha256_aborts_when_filename_missing_from_manifest(self):
        """A novel filename never present in the manifest must NOT be
        treated as 'no checksum entry → trust' — that would let an
        attacker drop a new artifact next to legitimate ones."""
        with TemporaryDirectory() as tmp:
            artifact = os.path.join(tmp, "evil.tar.gz")
            with open(artifact, "wb") as f:
                f.write(b"surprise")

            with self.assertRaises(SystemExit) as ctx:
                _verify_sha256(artifact, "evil.tar.gz", {"other.tar.gz": "0" * 64})
            self.assertEqual(ctx.exception.code, 1)

    def test_download_checksums_parses_goreleaser_format(self):
        """goreleaser writes ``<sha256>  <filename>`` (two-space separator)."""
        with (
            TemporaryDirectory() as tmp,
            patch("defenseclaw.commands.cmd_upgrade.requests.get") as get_mock,
            patch("defenseclaw.commands.cmd_upgrade._verify_checksums_sigstore") as verify_sigstore,
        ):
            sha = "a" * 64
            body = f"{sha}  defenseclaw_9.9.9_darwin_arm64.tar.gz\n"
            get_mock.return_value = Mock(status_code=200, content=body.encode())

            result = _download_checksums("9.9.9", tmp)

            verify_sigstore.assert_called_once()
            self.assertEqual(
                result,
                {"defenseclaw_9.9.9_darwin_arm64.tar.gz": sha},
            )

    def test_download_checksums_normalizes_find_dot_prefix(self):
        """The Makefile-generated checksum manifest strips this now, but
        older local builds may contain ``./filename`` from ``find .``."""
        with (
            TemporaryDirectory() as tmp,
            patch("defenseclaw.commands.cmd_upgrade.requests.get") as get_mock,
            patch("defenseclaw.commands.cmd_upgrade._verify_checksums_sigstore"),
        ):
            sha = "c" * 64
            body = f"{sha}  ./upgrade-manifest.json\n"
            get_mock.return_value = Mock(status_code=200, content=body.encode())

            result = _download_checksums("9.9.9", tmp)

            self.assertEqual(result, {"upgrade-manifest.json": sha})

    def test_download_checksums_returns_none_on_404(self):
        """Old releases predate goreleaser checksum publication. Caller
        proceeds with a warning; callable must NOT raise."""
        with (
            TemporaryDirectory() as tmp,
            patch(
                "defenseclaw.commands.cmd_upgrade.requests.get",
                return_value=Mock(status_code=404, content=b""),
            ),
        ):
            self.assertIsNone(_download_checksums("9.9.9", tmp))

    def test_download_checksums_rejects_malformed_lines(self):
        """A 200 with garbage body must NOT parse as 'verified empty
        manifest' — the caller would silently skip checks."""
        with (
            TemporaryDirectory() as tmp,
            patch("defenseclaw.commands.cmd_upgrade.requests.get") as get_mock,
            patch("defenseclaw.commands.cmd_upgrade._verify_checksums_sigstore"),
        ):
            body = "not-a-checksum\nzzz  bad-hex\n"
            get_mock.return_value = Mock(status_code=200, content=body.encode())

            with self.assertRaises(SystemExit) as ctx:
                _download_checksums("9.9.9", tmp)
            self.assertEqual(ctx.exception.code, 1)

    def test_checksums_sigstore_verifies_signed_manifest(self):
        with TemporaryDirectory() as tmp:
            checksums = os.path.join(tmp, "checksums.txt")
            sig = os.path.join(tmp, "checksums.txt.sig")
            cert = os.path.join(tmp, "checksums.txt.pem")
            for path in (checksums, sig, cert):
                with open(path, "wb") as f:
                    f.write(b"release asset")

            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                    side_effect=[sig, cert],
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.shutil.which",
                    return_value="/usr/bin/cosign",
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(returncode=0, stdout="", stderr=""),
                ) as run_mock,
            ):
                _verify_checksums_sigstore("9.9.9", tmp, checksums)

        cmd = run_mock.call_args.args[0]
        self.assertEqual(cmd[0:2], ["/usr/bin/cosign", "verify-blob"])
        self.assertNotIn("--certificate-identity-regexp", cmd)
        self.assertEqual(
            cmd[cmd.index("--certificate-identity") + 1],
            "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main",
        )
        self.assertEqual(
            cmd[cmd.index("--certificate-oidc-issuer") + 1],
            "https://token.actions.githubusercontent.com",
        )
        self.assertEqual(cmd[-1], checksums)

    def test_checksums_sigstore_hard_fails_when_cosign_rejects_signature(self):
        with TemporaryDirectory() as tmp:
            checksums = os.path.join(tmp, "checksums.txt")
            sig = os.path.join(tmp, "checksums.txt.sig")
            cert = os.path.join(tmp, "checksums.txt.pem")
            for path in (checksums, sig, cert):
                with open(path, "wb") as f:
                    f.write(b"release asset")

            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                    side_effect=[sig, cert],
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.shutil.which",
                    return_value="/usr/bin/cosign",
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(returncode=1, stdout="", stderr="bad signature"),
                ),
                self.assertRaises(SystemExit) as ctx,
            ):
                _verify_checksums_sigstore("0.8.3", tmp, checksums)

        self.assertEqual(ctx.exception.code, 1)

    def test_checksums_sigstore_warns_without_cosign(self):
        """A release that ships Sigstore assets should still be upgradeable on
        hosts without cosign; checksum validation continues after a warning."""
        with TemporaryDirectory() as tmp:
            checksums = os.path.join(tmp, "checksums.txt")
            sig = os.path.join(tmp, "checksums.txt.sig")
            cert = os.path.join(tmp, "checksums.txt.pem")
            for path in (checksums, sig, cert):
                with open(path, "wb") as f:
                    f.write(b"release asset")

            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                    side_effect=[sig, cert],
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.shutil.which",
                    return_value=None,
                ),
                patch("defenseclaw.commands.cmd_upgrade.subprocess.run") as run_mock,
                patch("defenseclaw.commands.cmd_upgrade.ux.warn") as warn_mock,
            ):
                _verify_checksums_sigstore("0.8.3", tmp, checksums)

        run_mock.assert_not_called()
        warn_mock.assert_called_once()
        self.assertIn("continuing with checksum verification only", warn_mock.call_args.args[0])

    def test_download_checksums_accepts_signed_manifest_without_cosign(self):
        """Regression for 0.8.0 -> 0.8.1: signed release assets must not
        require cosign to be installed before checksum validation can proceed."""
        with TemporaryDirectory() as tmp:
            checksums = os.path.join(tmp, "checksums.txt")
            sig = os.path.join(tmp, "checksums.txt.sig")
            cert = os.path.join(tmp, "checksums.txt.pem")
            sha = "a" * 64
            with open(checksums, "w", encoding="utf-8") as f:
                f.write(f"{sha}  defenseclaw-0.8.3-py3-none-any.whl\n")
            for path in (sig, cert):
                with open(path, "wb") as f:
                    f.write(b"release asset")

            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                    side_effect=[checksums, sig, cert],
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.shutil.which",
                    return_value=None,
                ),
                patch("defenseclaw.commands.cmd_upgrade.subprocess.run") as run_mock,
                patch("defenseclaw.commands.cmd_upgrade.ux.warn") as warn_mock,
            ):
                result = _download_checksums("0.8.3", tmp)

        self.assertEqual(result, {"defenseclaw-0.8.3-py3-none-any.whl": sha})
        run_mock.assert_not_called()
        warn_mock.assert_called_once()

    def test_checksums_sigstore_allow_unverified_skips_cosign(self):
        """The explicit operator opt-in still permits the missing-cosign path."""
        with TemporaryDirectory() as tmp:
            checksums = os.path.join(tmp, "checksums.txt")
            sig = os.path.join(tmp, "checksums.txt.sig")
            cert = os.path.join(tmp, "checksums.txt.pem")
            for path in (checksums, sig, cert):
                with open(path, "wb") as f:
                    f.write(b"release asset")

            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                    side_effect=[sig, cert],
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.shutil.which",
                    return_value=None,
                ),
                patch("defenseclaw.commands.cmd_upgrade.subprocess.run") as run_mock,
            ):
                _verify_checksums_sigstore(
                    "0.8.3",
                    tmp,
                    checksums,
                    allow_unverified=True,
                )

        run_mock.assert_not_called()

    def test_modern_checksums_require_cosign_even_with_unsafe_override(self):
        with TemporaryDirectory() as tmp:
            checksums = os.path.join(tmp, "checksums.txt")
            sig = os.path.join(tmp, "checksums.txt.sig")
            cert = os.path.join(tmp, "checksums.txt.pem")
            for path in (checksums, sig, cert):
                with open(path, "wb") as stream:
                    stream.write(b"release asset")

            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                    side_effect=[sig, cert],
                ),
                patch("defenseclaw.commands.cmd_upgrade.shutil.which", return_value=None),
                patch("defenseclaw.commands.cmd_upgrade.subprocess.run") as run_mock,
                self.assertRaises(SystemExit) as raised,
            ):
                _verify_checksums_sigstore(
                    "0.8.4",
                    tmp,
                    checksums,
                    allow_unverified=True,
                )

        self.assertEqual(raised.exception.code, 1)
        run_mock.assert_not_called()

    def test_download_file_retries_transient_server_errors(self):
        ok_response = Mock(status_code=200)
        ok_response.iter_content = Mock(return_value=[b"downloaded"])
        with (
            TemporaryDirectory() as tmp,
            patch(
                "defenseclaw.commands.cmd_upgrade.requests.get",
                side_effect=[Mock(status_code=503), ok_response],
            ) as get_mock,
            patch("defenseclaw.commands.cmd_upgrade.time.sleep") as sleep_mock,
        ):
            dest = os.path.join(tmp, "artifact.bin")

            _download_file("https://example.invalid/artifact.bin", dest)

            with open(dest, "rb") as f:
                self.assertEqual(f.read(), b"downloaded")
            self.assertEqual(get_mock.call_count, 2)
            sleep_mock.assert_called_once_with(1)

    def test_fetch_release_asset_digests_parses_github_digest_field(self):
        with patch("defenseclaw.commands.cmd_upgrade.requests.get") as get_mock:
            sha = "b" * 64
            get_mock.return_value = Mock(
                json=Mock(
                    return_value={
                        "assets": [
                            {
                                "name": "defenseclaw-9.9.9-py3-none-any.whl",
                                "digest": f"sha256:{sha}",
                            },
                            {
                                "name": "checksums.txt",
                                "digest": "sha1:not-used",
                            },
                        ],
                    }
                ),
                raise_for_status=Mock(),
            )

            result = _fetch_release_asset_digests("9.9.9")

        self.assertEqual(result, {"defenseclaw-9.9.9-py3-none-any.whl": sha})

    def test_missing_manifest_entries_not_filled_from_unsigned_digests_by_default(self):
        """F-0582: a verified checksums.txt with a gap must NOT be silently
        topped up from unsigned GitHub asset digests — that would downgrade
        the artifact from signed to unsigned auth. Without --allow-unverified
        the gap is left in place (so _verify_sha256 fails closed)."""
        runner = CliRunner()
        checksums = {"defenseclaw_9.9.9_darwin_arm64.tar.gz": "a" * 64}
        with patch(
            "defenseclaw.commands.cmd_upgrade._fetch_release_asset_digests",
            return_value={"defenseclaw-9.9.9-py3-none-any.whl": "b" * 64},
        ) as fetch_mock:
            with runner.isolation() as (out, _err, _):
                _fill_missing_checksums_from_release_assets(
                    "9.9.9",
                    checksums,
                    [
                        "defenseclaw_9.9.9_darwin_arm64.tar.gz",
                        "defenseclaw-9.9.9-py3-none-any.whl",
                    ],
                )
                output = out.getvalue().decode()

        # Gap left untouched; the unsigned digest was never even fetched.
        self.assertNotIn("defenseclaw-9.9.9-py3-none-any.whl", checksums)
        fetch_mock.assert_not_called()
        self.assertIn("--allow-unverified", output)

    def test_missing_manifest_entries_filled_only_with_allow_unverified(self):
        """F-0582: the operator can still opt in to filling gaps from unsigned
        GitHub asset digests with --allow-unverified, but the downgraded
        artifact is named in a warning."""
        runner = CliRunner()
        checksums = {"defenseclaw_9.9.9_darwin_arm64.tar.gz": "a" * 64}
        with patch(
            "defenseclaw.commands.cmd_upgrade._fetch_release_asset_digests",
            return_value={"defenseclaw-9.9.9-py3-none-any.whl": "b" * 64},
        ):
            with runner.isolation() as (out, _err, _):
                _fill_missing_checksums_from_release_assets(
                    "9.9.9",
                    checksums,
                    [
                        "defenseclaw_9.9.9_darwin_arm64.tar.gz",
                        "defenseclaw-9.9.9-py3-none-any.whl",
                    ],
                    allow_unverified=True,
                )
                output = out.getvalue().decode()

        self.assertEqual(checksums["defenseclaw-9.9.9-py3-none-any.whl"], "b" * 64)
        self.assertIn("defenseclaw-9.9.9-py3-none-any.whl", output)
        self.assertIn("UNSIGNED", output)


class TestUpgradeManifest(unittest.TestCase):
    """Release-owned upgrade manifests let future versions declare upgrade
    policy even when the local upgrade script is older than the release."""

    @staticmethod
    def _hard_cut_manifest(**overrides):
        payload = {
            "schema_version": 1,
            "release_version": "0.8.5",
            "min_upgrade_protocol": 2,
            "controller_upgrade_protocol": 2,
            "migration_failure_policy": "fail",
            "required_cli_migrations": ["0.8.5"],
            "minimum_source_version": "0.8.4",
            "required_bridge_version": "0.8.4",
            "auto_bridge_from": ["0.8.3", "0.8.2", "0.7.2"],
        }
        payload.update(overrides)
        return payload

    def test_validate_accepts_complete_hard_cut_bridge_graph(self):
        manifest = _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5")

        self.assertEqual(manifest["minimum_source_version"], "0.8.4")
        self.assertEqual(manifest["required_bridge_version"], "0.8.4")
        self.assertEqual(manifest["auto_bridge_from"], ["0.8.3", "0.8.2", "0.7.2"])
        self.assertEqual(manifest["min_upgrade_protocol"], 2)
        self.assertEqual(manifest["controller_upgrade_protocol"], 2)
        _require_hard_cut_manifest_contract(manifest, target_version="0.8.5", required=True)

    def test_hard_cut_contract_is_mandatory_even_with_unsafe_override(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()
        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "0.8.4"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("linux", "amd64"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            checksums = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._download_checksums", return_value=None)
            )
            manifest = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._download_upgrade_manifest"))
            gateway = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._download_gateway"))
            backup = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._create_backup"))
            services = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))

            result = runner.invoke(
                upgrade,
                ["--yes", "--allow-unverified", "--version", "0.8.5"],
                obj=app,
            )

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn("--allow-unverified cannot override this gate", result.output)
        self.assertIn("No changes were made", result.output)
        self.assertFalse(checksums.call_args.kwargs["allow_unverified"])
        manifest.assert_not_called()
        gateway.assert_not_called()
        backup.assert_not_called()
        services.assert_not_called()

    def test_bridge_checksums_are_mandatory_even_with_unsafe_override(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()
        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "0.8.3"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("linux", "amd64"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            checksums = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._download_checksums", return_value=None)
            )
            manifest = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._download_upgrade_manifest")
            )
            gateway = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._download_gateway")
            )
            backup = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._create_backup")
            )
            services = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._run_silent")
            )

            result = runner.invoke(
                upgrade,
                ["--yes", "--allow-unverified", "--version", "0.8.4"],
                obj=app,
            )

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn("DefenseClaw 0.8.4 requires a trusted checksums.txt", result.output)
        self.assertIn("--allow-unverified cannot override this gate", result.output)
        self.assertFalse(checksums.call_args.kwargs["allow_unverified"])
        manifest.assert_not_called()
        gateway.assert_not_called()
        backup.assert_not_called()
        services.assert_not_called()

    def test_hard_cut_missing_manifest_cannot_bypass_policy(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()
        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "0.8.4"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("linux", "amd64"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_checksums",
                    return_value={
                        "defenseclaw_0.8.5_linux_amd64.tar.gz": "0" * 64,
                        "defenseclaw-0.8.5-py3-none-any.whl": "0" * 64,
                        "upgrade-manifest.json": "0" * 64,
                    },
                )
            )
            stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._download_upgrade_manifest", return_value=None)
            )
            gateway = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._download_gateway"))
            backup = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._create_backup"))
            services = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))

            result = runner.invoke(
                upgrade,
                ["--yes", "--allow-unverified", "--version", "0.8.5"],
                obj=app,
            )

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn("missing the mandatory hard-cut upgrade contract", result.output)
        self.assertIn("No changes were made", result.output)
        gateway.assert_not_called()
        backup.assert_not_called()
        services.assert_not_called()

    def test_validate_rejects_partial_or_noncanonical_bridge_graph(self):
        invalid_payloads = [
            self._hard_cut_manifest(required_bridge_version="v0.8.4"),
            self._hard_cut_manifest(required_bridge_version="00.8.4"),
            self._hard_cut_manifest(minimum_source_version="0.8"),
            self._hard_cut_manifest(auto_bridge_from="0.8.3"),
            self._hard_cut_manifest(auto_bridge_from=["v0.8.3"]),
            self._hard_cut_manifest(auto_bridge_from=["0.8.3", "0.8.3"]),
            self._hard_cut_manifest(auto_bridge_from=["0.8.4"]),
            self._hard_cut_manifest(minimum_source_version="0.9.0", required_bridge_version="0.9.0"),
        ]
        partial = self._hard_cut_manifest()
        del partial["required_bridge_version"]
        invalid_payloads.append(partial)

        for payload in invalid_payloads:
            with self.subTest(payload=payload), self.assertRaises(SystemExit) as raised:
                _validate_upgrade_manifest(payload, "0.8.5")
            self.assertEqual(raised.exception.code, 1)

    def test_bridge_source_can_proceed(self):
        _enforce_upgrade_source_contract(
            _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5"),
            source_version="0.8.4",
            target_version="0.8.5",
            explicit_target=True,
        )

    def test_explicit_hard_cut_from_supported_old_source_has_exact_bridge_guidance(self):
        runner = CliRunner()
        manifest = _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5")

        with runner.isolation() as (out, _err, _):
            with self.assertRaises(SystemExit) as raised:
                _enforce_upgrade_source_contract(
                    manifest,
                    source_version="0.8.3",
                    target_version="0.8.5",
                    explicit_target=True,
                )
            output = out.getvalue().decode()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("The explicit --version 0.8.5 request cannot skip the required bridge.", output)
        self.assertIn("Bridge first: defenseclaw upgrade --version 0.8.4", output)
        self.assertIn("Then retry:  defenseclaw upgrade --version 0.8.5", output)
        self.assertIn(
            "No changes were made: no services were stopped and no installed artifacts were changed.",
            output,
        )

    def test_unsupported_source_fails_closed_with_supported_path(self):
        runner = CliRunner()
        manifest = _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5")

        with runner.isolation() as (out, _err, _):
            with self.assertRaises(SystemExit) as raised:
                _enforce_upgrade_source_contract(
                    manifest,
                    source_version="0.3.0",
                    target_version="0.8.5",
                    explicit_target=False,
                )
            output = out.getvalue().decode()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("is not a supported source", output)
        self.assertIn("Supported automatic bridge sources: 0.8.3, 0.8.2, 0.7.2", output)
        self.assertIn("scripts/upgrade.sh --version 0.8.4", output)
        self.assertIn(r".\scripts\upgrade.ps1 -Version 0.8.4", output)
        self.assertIn("release-owned upgrade resolver for latest", output)
        self.assertNotIn("release-owned installer", output)
        self.assertIn("No changes were made", output)

    def test_protocol1_controller_only_refuses_and_points_to_release_resolver(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_upgrade._UPGRADE_PROTOCOL_VERSION", 1):
            with runner.isolation() as (out, _err, _):
                with self.assertRaises(SystemExit) as raised:
                    _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5")
                output = out.getvalue().decode()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("requires upgrade protocol 2, but this upgrader supports 1", output)
        self.assertIn("release-owned shell or PowerShell upgrade resolver", output)
        self.assertIn("/releases/tag/0.8.5", output)

    def test_command_enforces_bridge_before_download_backup_stop_or_install(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()
        manifest = _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5")

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "0.8.3"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("darwin", "arm64"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_checksums",
                    return_value={
                        "defenseclaw_0.8.5_darwin_arm64.tar.gz": "0" * 64,
                        "defenseclaw-0.8.5-py3-none-any.whl": "0" * 64,
                        "upgrade-manifest.json": "0" * 64,
                    },
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                    return_value=manifest,
                )
            )
            gateway_download = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._download_gateway")
            )
            wheel_download = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._download_wheel"))
            backup = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._create_backup"))
            services = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))
            install = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_gateway"))

            result = runner.invoke(upgrade, ["--yes", "--version", "0.8.5"], obj=app)

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn("Bridge first: defenseclaw upgrade --version 0.8.4", result.output)
        self.assertIn("No changes were made", result.output)
        gateway_download.assert_not_called()
        wheel_download.assert_not_called()
        backup.assert_not_called()
        services.assert_not_called()
        install.assert_not_called()

    def test_validate_rejects_newer_upgrade_protocol(self):
        payload = {
            "schema_version": 1,
            "release_version": "9.9.9",
            "min_upgrade_protocol": 999,
            "migration_failure_policy": "fail",
            "required_cli_migrations": ["9.9.9"],
        }

        with self.assertRaises(SystemExit) as ctx:
            _validate_upgrade_manifest(payload, "9.9.9")

        self.assertEqual(ctx.exception.code, 1)

    def test_validate_rejects_newer_manifest_schema(self):
        payload = {
            "schema_version": 2,
            "release_version": "9.9.9",
            "min_upgrade_protocol": 1,
            "migration_failure_policy": "warn",
            "required_cli_migrations": [],
        }

        with self.assertRaises(SystemExit) as ctx:
            _validate_upgrade_manifest(payload, "9.9.9")

        self.assertEqual(ctx.exception.code, 1)

    def test_download_manifest_verifies_checksum_and_parses_policy(self):
        payload = {
            "schema_version": 1,
            "release_version": "9.9.9",
            "min_upgrade_protocol": 1,
            "migration_failure_policy": "fail",
            "required_cli_migrations": ["9.9.9"],
        }
        body = json.dumps(payload).encode()
        digest = hashlib.sha256(body).hexdigest()
        with (
            TemporaryDirectory() as tmp,
            patch(
                "defenseclaw.commands.cmd_upgrade.requests.get",
                return_value=Mock(status_code=200, content=body),
            ),
        ):
            manifest = _download_upgrade_manifest(
                "9.9.9",
                tmp,
                {"upgrade-manifest.json": digest},
            )

        self.assertEqual(manifest["migration_failure_policy"], "fail")
        self.assertEqual(manifest["required_cli_migrations"], ["9.9.9"])

    def test_required_migration_check_fails_when_cursor_missing_entry(self):
        manifest = {
            "migration_failure_policy": "fail",
            "required_cli_migrations": ["9.9.9"],
        }

        with TemporaryDirectory() as data_dir, self.assertRaises(SystemExit) as ctx:
            _assert_required_cli_migrations(manifest, data_dir)

        self.assertEqual(ctx.exception.code, 1)

    def test_required_migration_check_warn_policy_does_not_fail(self):
        manifest = {
            "migration_failure_policy": "warn",
            "required_cli_migrations": ["9.9.9"],
        }

        with TemporaryDirectory() as data_dir:
            _assert_required_cli_migrations(manifest, data_dir)

    def test_required_migration_check_passes_when_cursor_records_entry(self):
        from defenseclaw import migration_state

        manifest = {
            "required_cli_migrations": ["9.9.9"],
        }
        with TemporaryDirectory() as data_dir:
            state = migration_state.MigrationState(
                package_version="9.9.9",
                applied=["9.9.9"],
                applied_at={"9.9.9": "2026-05-19T00:00:00Z"},
            )
            migration_state.save(data_dir, state)

            _assert_required_cli_migrations(manifest, data_dir)


class TestGatewayTarballExtraction(unittest.TestCase):
    """Gateway release tarballs are verified before extraction, but the
    extractor still refuses unsafe or malformed archive contents."""

    @staticmethod
    def _write_tarball(path, entries):
        with tarfile.open(path, "w:gz") as tar:
            for name, payload in entries.items():
                data = payload.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755
                tar.addfile(info, io.BytesIO(data))

    def test_download_gateway_extracts_expected_binary(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_tarball(dest, {"defenseclaw": "#!/bin/sh\n"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                binary, tarball_name = _download_gateway("9.9.9", "darwin", "arm64", tmp)

            self.assertEqual(tarball_name, "defenseclaw_9.9.9_darwin_arm64.tar.gz")
            self.assertTrue(os.path.isfile(binary))

    def test_download_gateway_rejects_path_traversal_tarball(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_tarball(dest, {"../evil": "nope"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                with self.assertRaises(SystemExit) as ctx:
                    _download_gateway("9.9.9", "darwin", "arm64", tmp)
            self.assertEqual(ctx.exception.code, 1)

    def test_download_gateway_rejects_tarball_without_binary(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_tarball(dest, {"README.md": "missing binary"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                with self.assertRaises(SystemExit) as ctx:
                    _download_gateway("9.9.9", "darwin", "arm64", tmp)
            self.assertEqual(ctx.exception.code, 1)


class TestGatewayWindowsArchive(unittest.TestCase):
    """Windows ships a .zip containing defenseclaw.exe; the upgrade path must
    download, validate, and extract it the same way it does the .tar.gz."""

    @staticmethod
    def _write_zip(path, entries):
        with zipfile.ZipFile(path, "w") as zf:
            for name, payload in entries.items():
                zf.writestr(name, payload)

    def test_archive_name_is_zip_on_windows_tarball_elsewhere(self):
        self.assertEqual(
            _gateway_archive_name("9.9.9", "windows", "amd64"),
            "defenseclaw_9.9.9_windows_amd64.zip",
        )
        self.assertEqual(
            _gateway_archive_name("9.9.9", "linux", "arm64"),
            "defenseclaw_9.9.9_linux_arm64.tar.gz",
        )

    def test_detect_platform_allows_windows(self):
        with patch("platform.system", return_value="Windows"), patch("platform.machine", return_value="AMD64"):
            self.assertEqual(_detect_platform(), ("windows", "amd64"))

    def test_download_gateway_extracts_exe_from_zip(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_zip(dest, {"defenseclaw.exe": "MZ\x00binary"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                binary, archive_name = _download_gateway("9.9.9", "windows", "amd64", tmp)

            self.assertEqual(archive_name, "defenseclaw_9.9.9_windows_amd64.zip")
            self.assertTrue(binary.endswith("defenseclaw.exe"))
            self.assertTrue(os.path.isfile(binary))

    def test_download_gateway_rejects_zip_without_exe(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_zip(dest, {"README.md": "missing binary"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                with self.assertRaises(SystemExit) as ctx:
                    _download_gateway("9.9.9", "windows", "amd64", tmp)
            self.assertEqual(ctx.exception.code, 1)

    def test_download_gateway_rejects_zip_path_traversal(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_zip(dest, {"../evil.exe": "nope"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                with self.assertRaises(SystemExit) as ctx:
                    _download_gateway("9.9.9", "windows", "amd64", tmp)
            self.assertEqual(ctx.exception.code, 1)


class TestInstallGatewaySnapshotsPrevious(unittest.TestCase):
    """Robustness: installing the new gateway must snapshot the old one
    so a failed health check has a documented rollback path."""

    def test_snapshot_created_when_previous_binary_exists(self):
        with (
            TemporaryDirectory() as fake_home,
            TemporaryDirectory() as backup_dir,
            patch.dict(os.environ, {"HOME": fake_home}),
        ):
            install_dir = os.path.join(fake_home, ".local", "bin")
            os.makedirs(install_dir)
            previous = os.path.join(install_dir, "defenseclaw-gateway")
            with open(previous, "wb") as f:
                f.write(b"#!/bin/sh\necho old\n")
            os.chmod(previous, 0o755)

            new_binary = os.path.join(fake_home, "defenseclaw")
            with open(new_binary, "wb") as f:
                f.write(b"#!/bin/sh\necho new\n")
            os.chmod(new_binary, 0o755)

            _install_gateway(new_binary, "linux", backup_dir=backup_dir)

            snapshot = os.path.join(backup_dir, "defenseclaw-gateway.previous")
            self.assertTrue(
                os.path.isfile(snapshot),
                msg="previous gateway should have been copied into backup_dir",
            )
            with open(snapshot, "rb") as f:
                self.assertEqual(f.read(), b"#!/bin/sh\necho old\n")
            with open(previous, "rb") as f:
                self.assertEqual(f.read(), b"#!/bin/sh\necho new\n")

    def test_no_snapshot_when_no_previous_binary(self):
        """A fresh install (no prior gateway) must not fail just because
        there's nothing to snapshot."""
        with (
            TemporaryDirectory() as fake_home,
            TemporaryDirectory() as backup_dir,
            patch.dict(os.environ, {"HOME": fake_home}),
        ):
            new_binary = os.path.join(fake_home, "defenseclaw")
            with open(new_binary, "wb") as f:
                f.write(b"#!/bin/sh\n")
            os.chmod(new_binary, 0o755)

            _install_gateway(new_binary, "linux", backup_dir=backup_dir)

            self.assertFalse(
                os.path.isfile(os.path.join(backup_dir, "defenseclaw-gateway.previous")),
            )

    def test_failed_candidate_copy_never_truncates_active_gateway(self):
        with TemporaryDirectory() as fake_home, patch.dict(os.environ, {"HOME": fake_home}):
            install_dir = Path(fake_home) / ".local/bin"
            install_dir.mkdir(parents=True)
            active = install_dir / "defenseclaw-gateway"
            candidate = Path(fake_home) / "candidate-gateway"
            active.write_bytes(b"complete bridge gateway")
            candidate.write_bytes(b"complete target gateway")

            def fail_partial_copy(_source, destination, **_kwargs):
                Path(destination).write_bytes(b"partial target")
                raise OSError("injected interrupted copy")

            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade.shutil.copy2",
                    side_effect=fail_partial_copy,
                ),
                self.assertRaisesRegex(OSError, "interrupted copy"),
            ):
                _install_gateway(str(candidate), "linux")

            self.assertEqual(active.read_bytes(), b"complete bridge gateway")


class TestPostInstallVersionVerification(unittest.TestCase):
    """The freshly-installed gateway must report the expected version, or
    the upgrade output must surface the discrepancy."""

    def test_warns_when_version_mismatches(self):
        """An unexpected version string warns but does not abort."""
        runner = CliRunner()
        with TemporaryDirectory() as tmp:
            gateway = os.path.join(tmp, "defenseclaw-gateway")
            with open(gateway, "w") as f:
                f.write("#!/bin/sh\n")
            with patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(
                    stdout="defenseclaw-gateway version 0.5.0 (commit=..., built=...)",
                    stderr="",
                ),
            ):
                with runner.isolation() as (out, _err, _):
                    _verify_installed_gateway_version(gateway, "9.9.9")
                    output = out.getvalue().decode()

        self.assertIn("Gateway version verification failed", output)
        self.assertIn("expected 9.9.9", output)

    def test_silent_success_when_version_matches(self):
        runner = CliRunner()
        with TemporaryDirectory() as tmp:
            gateway = os.path.join(tmp, "defenseclaw-gateway")
            with open(gateway, "w") as f:
                f.write("#!/bin/sh\n")
            with patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(
                    stdout="defenseclaw-gateway version 9.9.9 (commit=abc, built=2026-05-19)",
                    stderr="",
                ),
            ) as run_mock:
                with runner.isolation() as (out, _err, _):
                    _verify_installed_gateway_version(gateway, "9.9.9")
                    output = out.getvalue().decode()

        self.assertIn("Gateway binary verified", output)
        self.assertNotIn("verification failed", output)
        self.assertEqual(run_mock.call_args.args[0][0], gateway)

    def test_handles_missing_binary_gracefully(self):
        """Missing installed path warns and returns cleanly."""
        runner = CliRunner()
        with runner.isolation() as (out, _err, _):
            _verify_installed_gateway_version("/no/such/defenseclaw-gateway", "9.9.9")
            output = out.getvalue().decode()

        self.assertIn("Installed gateway binary is missing", output)


class TestRunSilentSurfaceErrors(unittest.TestCase):
    """When a command fails, the operator should see WHY without needing
    to re-run with --verbose. ``_run_silent`` is the workhorse for
    gateway start/stop/restart calls."""

    def test_success_path_silent(self):
        runner = CliRunner()
        with patch(
            "defenseclaw.commands.cmd_upgrade.subprocess.run",
            return_value=Mock(returncode=0, stderr="", stdout=""),
        ):
            with runner.isolation() as (out, _err, _):
                ok = _run_silent(["true"], "Started", "Did not start")
                output = out.getvalue().decode()

        self.assertTrue(ok)
        self.assertIn("Started", output)
        self.assertNotIn("Did not start", output)

    def test_non_zero_exit_surfaces_stderr(self):
        runner = CliRunner()
        with patch(
            "defenseclaw.commands.cmd_upgrade.subprocess.run",
            return_value=Mock(
                returncode=1,
                stderr="Error: port 18970 already in use\nrun: lsof -i :18970",
                stdout="",
            ),
        ):
            with runner.isolation() as (out, _err, _):
                ok = _run_silent(["start"], "Started", "Did not start")
                output = out.getvalue().decode()

        self.assertFalse(ok)
        self.assertIn("Did not start", output)
        self.assertIn("port 18970 already in use", output)

    def test_file_not_found_surfaces_exception_message(self):
        runner = CliRunner()
        with patch(
            "defenseclaw.commands.cmd_upgrade.subprocess.run",
            side_effect=FileNotFoundError(2, "No such file", "missing-bin"),
        ):
            with runner.isolation() as (out, _err, _):
                ok = _run_silent(["missing-bin"], "Started", "Did not start")
                output = out.getvalue().decode()

        self.assertFalse(ok)
        self.assertIn("Did not start", output)


class TestPostUpgradeDriftCheck(unittest.TestCase):
    """Drift check must surface mismatched component versions but never
    block the upgrade — it's an advisory at the end of the flow."""

    def test_drift_warns_with_actionable_message(self):
        runner = CliRunner()
        from defenseclaw.commands.cmd_version import Component

        with (
            patch(
                "defenseclaw.commands.cmd_version._cli_component",
                return_value=Component(
                    name="cli",
                    version="9.9.9",
                    origin="defenseclaw (python)",
                ),
            ),
            patch(
                "defenseclaw.commands.cmd_version._gateway_component",
                return_value=Component(
                    name="gateway",
                    version="9.9.9",
                    origin="/usr/local/bin",
                ),
            ),
            patch(
                "defenseclaw.commands.cmd_version._plugin_component",
                return_value=Component(
                    name="plugin",
                    version="0.5.0",
                    origin="~/.openclaw/...",
                ),
            ),
        ):
            with runner.isolation() as (out, _err, _):
                _check_post_upgrade_drift("9.9.9")
                output = out.getvalue().decode()

        self.assertIn("Component drift detected", output)
        self.assertIn("plugin", output)
        self.assertIn("9.9.9", output)

    def test_no_drift_means_no_output(self):
        runner = CliRunner()
        from defenseclaw.commands.cmd_version import Component

        with (
            patch(
                "defenseclaw.commands.cmd_version._cli_component",
                return_value=Component(
                    name="cli",
                    version="9.9.9",
                    origin="defenseclaw (python)",
                ),
            ),
            patch(
                "defenseclaw.commands.cmd_version._gateway_component",
                return_value=Component(
                    name="gateway",
                    version="9.9.9",
                    origin="/usr/local/bin",
                ),
            ),
            patch(
                "defenseclaw.commands.cmd_version._plugin_component",
                return_value=Component(
                    name="plugin",
                    version="9.9.9",
                    origin="~/.openclaw/...",
                ),
            ),
        ):
            with runner.isolation() as (out, _err, _):
                _check_post_upgrade_drift("9.9.9")
                output = out.getvalue().decode()

        self.assertNotIn("drift", output.lower())


class TestMigrationCursorSummary(unittest.TestCase):
    """The migration cursor is the source of truth for 'which migrations
    have observably executed.' Surface it in upgrade output so a partial-
    failure host is debuggable from a single log."""

    def test_summary_includes_applied_versions(self):
        runner = CliRunner()
        from defenseclaw import migration_state

        with TemporaryDirectory() as data_dir:
            state = migration_state.MigrationState(
                package_version="9.9.9",
                applied=["0.3.0", "0.4.0", "0.5.0"],
                applied_at={
                    "0.3.0": "2026-01-01T00:00:00Z",
                    "0.4.0": "2026-02-01T00:00:00Z",
                    "0.5.0": "2026-03-01T00:00:00Z",
                },
            )
            migration_state.save(data_dir, state)

            with runner.isolation() as (out, _err, _):
                _print_migration_cursor_summary(data_dir)
                output = out.getvalue().decode()

        self.assertIn("cursor:", output)
        self.assertIn("0.3.0", output)
        self.assertIn("0.4.0", output)
        self.assertIn("0.5.0", output)

    def test_summary_silent_when_cursor_absent(self):
        """Missing cursor file → silent. The caller already prints
        'No migrations needed' which is enough context."""
        runner = CliRunner()
        with TemporaryDirectory() as data_dir:
            with runner.isolation() as (out, _err, _):
                _print_migration_cursor_summary(data_dir)
                output = out.getvalue().decode()

        self.assertEqual(output.strip(), "")
