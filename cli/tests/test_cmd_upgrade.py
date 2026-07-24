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
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import ANY, Mock, patch

import click
import defenseclaw.commands.cmd_upgrade as cmd_upgrade_module
import pytest
import yaml
from click.testing import CliRunner
from defenseclaw.commands.cmd_upgrade import (
    _INSTALLED_HEALTH_SCRIPT,
    _INSTALLED_MIGRATION_SCRIPT,
    _MACOS_GATEWAY_CODESIGN_IDENTIFIER,
    _acquire_bridge_rollback_artifacts,
    _api_bind_host,
    _assert_gateway_quiesced,
    _assert_required_cli_migrations,
    _canonicalize_macos_gateway_for_coherence,
    _capture_rollback_file,
    _capture_source_gateway_running_state,
    _check_post_upgrade_drift,
    _cleanup_hard_cut_mutation_temporaries,
    _copy_distribution_metadata,
    _crash_bundle_rollback_result,
    _create_backup,
    _detect_platform,
    _download_bootstrap_cosign,
    _download_checksums,
    _download_file,
    _download_gateway,
    _download_release_provenance,
    _download_upgrade_manifest,
    _download_windows_setup,
    _enforce_upgrade_source_contract,
    _enforce_windows_self_update_policy,
    _execute_hard_cut_rollback,
    _expected_release_artifacts,
    _fetch_release_asset_digests,
    _fill_missing_checksums_from_release_assets,
    _fsync_hard_cut_recovery_custody,
    _gateway_archive_name,
    _handoff_hard_cut_recovery_to_source_controller,
    _handoff_to_installed_upgrade,
    _handoff_windows_setup_upgrade,
    _hard_cut_mutation_token,
    _hold_phase_two_lease_for_command_lifetime,
    _install_gateway,
    _install_wheel,
    _load_hard_cut_recovery_journal,
    _LocalBundleUpgradeInvocationError,
    _mark_hard_cut_bundle_mutation_intent,
    _materialize_bridge_source_wheel_for_preflight,
    _materialize_protected_artifact,
    _native_windows_install_state,
    _normalize_target_version,
    _parse_release_provenance,
    _poll_health,
    _poll_installed_health,
    _preflight_check,
    _preflight_hard_cut_observability_migration,
    _preflight_installed_source_coherence,
    _preflight_staged_target_controller_source,
    _preflight_target_wheel_migrations,
    _preflight_wheel_install,
    _prepare_hard_cut_rollback_plan,
    _print_migration_cursor_summary,
    _recover_interrupted_hard_cut,
    _refresh_target_dotenv_environment,
    _release_download_base,
    _require_bridge_checksums_provenance,
    _require_bridge_environment_accepts_target_wheel,
    _require_hard_cut_manifest_contract,
    _require_release_owned_hard_cut_handoff,
    _require_target_phase_two_mutator_wrapper,
    _resolve_upgrade_source_version,
    _restore_hard_cut_backup_root_contract,
    _restore_rollback_file,
    _restore_windows_rollback_file,
    _RollbackFileSnapshot,
    _run_installed_local_observability_operation,
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
    _verify_macos_rollback_gateway_signature,
    _verify_restored_bridge_artifacts,
    _verify_sha256,
    _verify_windows_setup_authenticode,
    _version_tuple,
    _write_hard_cut_recovery_journal,
    upgrade,
)
from defenseclaw.config import Config, GatewayConfig, GuardrailConfig, OpenShellConfig
from defenseclaw.context import AppContext
from defenseclaw.migrations import ObservabilityV8PreflightBinding, run_migrations
from defenseclaw.upgrade_receipt import (
    UPGRADE_RECEIPT_DIRECTORY,
    begin_upgrade_receipt,
    clear_local_bundle_restart_intent,
    load_local_bundle_restart_intent,
    load_upgrade_receipt,
    load_upgrade_receipt_supersession,
    record_local_bundle_restart_intent,
)


def _hard_cut_provenance_payload(
    bridge_checksums_sha256: str,
    *,
    target_version: str = "0.8.5",
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_version": target_version,
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "policy_commit": "3" * 40,
        "policy_tree": "4" * 40,
        "release_source_map_sha256": "5" * 64,
        "source_install_identity": {
            "schema_version": 1,
            "source_release": target_version,
            "source_install_compatibility_epoch": 2,
            "runtime_config_version": 8,
        },
        "bridge": {
            "version": "0.8.4",
            "commit": "6" * 40,
            "tree": "7" * 40,
            "checksums_sha256": bridge_checksums_sha256,
        },
    }


def _test_release_provenance(target_version: str = "0.8.5"):
    payload = _hard_cut_provenance_payload(
        "a" * 64,
        target_version=target_version,
    )
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    return _parse_release_provenance(
        payload,
        target_version=target_version,
        artifact_sha256=hashlib.sha256(raw).hexdigest(),
    )


@pytest.fixture(autouse=True)
def _authenticated_provenance_for_preexisting_upgrade_mocks(monkeypatch):
    """Supply the newly mandatory asset to older command-level mock graphs.

    Direct provenance/parser tests below retain the imported real functions;
    this only prevents unrelated upgrade tests from reaching the network for a
    release asset that did not exist when their mock graphs were authored.
    """

    def consume(version, _staging, _checksums, *, required):
        return _test_release_provenance(version) if required else None

    monkeypatch.setattr(cmd_upgrade_module, "_download_release_provenance", consume)
    monkeypatch.setattr(
        cmd_upgrade_module,
        "_require_bridge_checksums_provenance",
        lambda *_args, **_kwargs: None,
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
    wheel_path = path + ".materialized.whl" if path.endswith(".dcwheel") else path
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr("defenseclaw/migrations.py", source)
        archive.writestr(
            "defenseclaw/phase_two_mutator.py",
            "raise SystemExit('fixture wrapper is not executed')\n",
        )
        archive.writestr(f"defenseclaw-{version}.dist-info/METADATA", metadata)
    if wheel_path != path:
        payload = Path(wheel_path).read_bytes()
        Path(path).write_bytes(b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n" + bytes(value ^ 0xA5 for value in payload))
        Path(wheel_path).unlink()


class TestUpgradeVersionValidation(unittest.TestCase):
    def test_materializes_real_protected_bridge_wheel_for_hard_cut_preflight(self):
        with TemporaryDirectory() as root:
            protected = Path(root, "defenseclaw-0.8.4-2-py3-none-any.dcwheel")
            _write_migration_wheel(
                str(protected),
                version="0.8.4",
                migration_versions=(),
                supports_bundle_flag=True,
                supported_config_versions=(7,),
            )
            digest = hashlib.sha256(protected.read_bytes()).hexdigest()

            materialized = Path(
                _materialize_bridge_source_wheel_for_preflight(
                    root,
                    {protected.name: digest},
                    str(protected),
                )
            )

            self.assertEqual(
                materialized.name,
                "defenseclaw-0.8.4-2-py3-none-any.whl",
            )
            with zipfile.ZipFile(materialized) as archive:
                metadata = archive.read("defenseclaw-0.8.4.dist-info/METADATA").decode("utf-8")
            self.assertIn("Version: 0.8.4", metadata)

    def test_bridge_source_preflight_refuses_unprotected_or_unsigned_wheel(self):
        with TemporaryDirectory() as root:
            plain = Path(root, "defenseclaw-0.8.4-py3-none-any.whl")
            plain.write_bytes(b"PK\x03\x04")
            with self.assertRaisesRegex(OSError, "not a protected schema-2"):
                _materialize_bridge_source_wheel_for_preflight(root, {}, str(plain))

            protected = Path(root, "defenseclaw-0.8.4-2-py3-none-any.dcwheel")
            protected.write_bytes(b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n")
            with self.assertRaisesRegex(OSError, "authenticated outer digest"):
                _materialize_bridge_source_wheel_for_preflight(root, {}, str(protected))

    def test_protected_artifact_requires_magic_xor_decode_and_exclusive_destination(self):
        with TemporaryDirectory() as root:
            # Bare LF and DOS EOF catch accidental Windows CRT text-mode
            # translation while decoding the binary envelope.
            payload = b"PK\x03\x04private\nwheel\x1abytes"
            protected = Path(root, "artifact.dcwheel")
            destination = Path(root, "artifact.whl")
            protected.write_bytes(b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n" + bytes(value ^ 0xA5 for value in payload))
            protected_digest = hashlib.sha256(protected.read_bytes()).hexdigest()

            _materialize_protected_artifact(str(protected), str(destination), protected_digest)

            self.assertEqual(destination.read_bytes(), payload)
            with self.assertRaises(OSError):
                _materialize_protected_artifact(str(protected), str(destination), protected_digest)

            invalid = Path(root, "invalid.dcwheel")
            invalid.write_bytes(b"X" * 100)
            with self.assertRaisesRegex(OSError, "magic"):
                _materialize_protected_artifact(
                    str(invalid),
                    str(Path(root, "invalid.whl")),
                    hashlib.sha256(invalid.read_bytes()).hexdigest(),
                )

    def test_protected_artifact_binds_decoded_bytes_to_authenticated_outer_digest(self):
        with TemporaryDirectory() as root:
            magic = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
            source = Path(root, "artifact.dcwheel")
            destination = Path(root, "artifact.whl")
            original = b"original-wheel"
            substituted = b"malicious-data"
            self.assertEqual(len(original), len(substituted))
            source.write_bytes(magic + bytes(value ^ 0xA5 for value in original))
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            real_read = os.read
            mutated = False

            def mutate_after_magic(fd, size):
                nonlocal mutated
                chunk = real_read(fd, size)
                if not mutated and chunk == magic:
                    mutated = True
                    with source.open("r+b") as stream:
                        stream.seek(len(magic))
                        stream.write(bytes(value ^ 0xA5 for value in substituted))
                        stream.flush()
                return chunk

            with patch(
                "defenseclaw.commands.cmd_upgrade.os.read",
                side_effect=mutate_after_magic,
            ):
                with self.assertRaisesRegex(OSError, "changed after checksum"):
                    _materialize_protected_artifact(str(source), str(destination), expected)

            self.assertFalse(destination.exists())

    def test_accepts_plain_or_v_prefixed_semver(self):
        self.assertEqual(_normalize_target_version("9.9.9"), "9.9.9")
        self.assertEqual(_normalize_target_version("v9.9.9"), "9.9.9")

    def test_semver_tuple_orders_downgrades(self):
        self.assertLess(_version_tuple("1.9.9"), _version_tuple("2.0.0"))

    def test_rejects_versions_that_would_be_unsafe_in_paths_or_urls(self):
        with self.assertRaises(SystemExit) as ctx:
            _normalize_target_version("../9.9.9")
        self.assertEqual(ctx.exception.code, 1)

    def test_target_controller_source_override_requires_complete_exact_handoff(self):
        staged_artifact_dir = os.path.abspath(os.path.join(os.sep, "private", "custody"))
        legacy_environment = {
            "DEFENSECLAW_STAGED_UPGRADE": "1",
            "DEFENSECLAW_STAGED_BRIDGE_VERSION": "0.8.4",
            "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR": staged_artifact_dir,
        }
        with patch.dict(os.environ, legacy_environment, clear=True):
            self.assertEqual(
                _resolve_upgrade_source_version(
                    "0.8.5",
                    "0.8.5",
                    target_was_explicit=True,
                ),
                "0.8.5",
            )

        exact_environment = {
            **legacy_environment,
            "DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION": "0.8.5",
        }
        with patch.dict(os.environ, exact_environment, clear=True):
            self.assertEqual(
                _resolve_upgrade_source_version(
                    "0.8.5",
                    "0.8.5",
                    target_was_explicit=True,
                ),
                "0.8.4",
            )

        invalid_cases = (
            ({**exact_environment, "DEFENSECLAW_STAGED_UPGRADE": "0"}, True, "0.8.5"),
            (
                {
                    **exact_environment,
                    "DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION": "0.8.6",
                },
                True,
                "0.8.5",
            ),
            (
                {
                    **exact_environment,
                    "DEFENSECLAW_STAGED_BRIDGE_VERSION": "0.8.3",
                },
                True,
                "0.8.5",
            ),
            (
                {
                    **exact_environment,
                    "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR": "relative/custody",
                },
                True,
                "0.8.5",
            ),
            (exact_environment, False, "0.8.5"),
            (exact_environment, True, "0.8.6"),
        )
        for environment, target_was_explicit, target_version in invalid_cases:
            with (
                self.subTest(environment=environment, target=target_version),
                patch.dict(os.environ, environment, clear=True),
            ):
                with self.assertRaises(SystemExit):
                    _resolve_upgrade_source_version(
                        "0.8.5",
                        target_version,
                        target_was_explicit=target_was_explicit,
                    )

    @unittest.skipUnless(os.name == "posix", "POSIX target-controller custody")
    def test_target_controller_source_preflight_proves_private_controller_and_bridge(self):
        with TemporaryDirectory() as root:
            root_path = Path(root)
            home = root_path / "home"
            recovery_home = home / ".defenseclaw-recovery"
            installed_venv = recovery_home / ".venv"
            installed_cli = installed_venv / "bin" / "defenseclaw"
            launcher = home / ".local" / "bin" / "defenseclaw"
            target_venv = root_path / "target-controller-venv"
            staged = root_path / "bridge-handoff"
            installed_cli.parent.mkdir(parents=True)
            launcher.parent.mkdir(parents=True)
            target_venv.mkdir(mode=0o700)
            staged.mkdir(mode=0o700)
            installed_cli.write_text(
                "#!/bin/sh\necho 'DefenseClaw 0.8.4'\n",
                encoding="utf-8",
            )
            installed_cli.chmod(0o755)
            launcher.symlink_to(installed_cli)
            environment = {
                "HOME": str(home),
                "DEFENSECLAW_STAGED_UPGRADE": "1",
                "DEFENSECLAW_STAGED_BRIDGE_VERSION": "0.8.4",
                "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR": str(staged),
                "DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION": "0.8.5",
            }

            with (
                patch.dict(os.environ, environment, clear=True),
                patch.object(cmd_upgrade_module.sys, "prefix", str(target_venv)),
            ):
                _preflight_staged_target_controller_source(
                    source_version="0.8.4",
                    controller_version="0.8.5",
                    target_version="0.8.5",
                    recovery_home=str(recovery_home),
                )

            with (
                patch.dict(os.environ, environment, clear=True),
                patch.object(cmd_upgrade_module.sys, "prefix", str(installed_venv)),
            ):
                with self.assertRaises(SystemExit):
                    _preflight_staged_target_controller_source(
                        source_version="0.8.4",
                        controller_version="0.8.5",
                        target_version="0.8.5",
                        recovery_home=str(recovery_home),
                    )

    def test_hard_cut_accepts_coherent_bridge_self_custody_or_complete_resolver_handoff(self):
        provenance = Mock(release_version="0.8.5", bridge_version="0.8.4")
        with patch.dict(os.environ, {}, clear=True):
            _require_release_owned_hard_cut_handoff(
                source_version="0.8.4",
                target_version="0.8.5",
                provenance=provenance,
            )

        with patch.dict(
            os.environ,
            {
                "DEFENSECLAW_STAGED_UPGRADE": "1",
                "DEFENSECLAW_STAGED_BRIDGE_VERSION": "0.8.4",
                "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR": "/private/custody",
                "DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION": "0.8.5",
            },
            clear=True,
        ):
            _require_release_owned_hard_cut_handoff(
                source_version="0.8.4",
                target_version="0.8.5",
                provenance=provenance,
            )

    def test_hard_cut_refuses_partial_or_mismatched_resolver_handoff(self):
        provenance = Mock(release_version="0.8.5", bridge_version="0.8.4")
        environments = (
            {"DEFENSECLAW_STAGED_UPGRADE": "1"},
            {
                "DEFENSECLAW_STAGED_UPGRADE": "1",
                "DEFENSECLAW_STAGED_BRIDGE_VERSION": "0.8.3",
                "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR": "/private/custody",
            },
            {
                "DEFENSECLAW_STAGED_UPGRADE": "0",
                "DEFENSECLAW_STAGED_BRIDGE_VERSION": "0.8.4",
                "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR": "/private/custody",
            },
        )
        for environment in environments:
            with self.subTest(environment=environment), patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(SystemExit):
                    _require_release_owned_hard_cut_handoff(
                        source_version="0.8.4",
                        target_version="0.8.5",
                        provenance=provenance,
                    )

    def test_hard_cut_refuses_provenance_that_does_not_bind_bridge_and_target(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                _require_release_owned_hard_cut_handoff(
                    source_version="0.8.4",
                    target_version="0.8.5",
                    provenance=Mock(release_version="0.8.5", bridge_version="0.8.3"),
                )

    def test_hard_cut_refuses_missing_authenticated_provenance(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                OSError,
                "hard-cut release provenance was not authenticated",
            ):
                _require_release_owned_hard_cut_handoff(
                    source_version="0.8.4",
                    target_version="0.8.5",
                    provenance=None,
                )


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


class TestGatewayQuiescence(unittest.TestCase):
    def test_missing_pid_file_does_not_hide_live_exact_gateway_status(self):
        with (
            TemporaryDirectory() as data_dir,
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0),
            ) as run,
        ):
            with self.assertRaisesRegex(OSError, "still reports a live service"):
                _assert_gateway_quiesced(
                    data_dir,
                    gateway_path="/trusted/defenseclaw-gateway",
                )

        run.assert_called_once_with(
            ["/trusted/defenseclaw-gateway", "status"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env={**os.environ, "DEFENSECLAW_HOME": os.path.abspath(data_dir)},
        )

    def test_missing_pid_and_unreachable_exact_gateway_prove_quiescence(self):
        with (
            TemporaryDirectory() as data_dir,
            patch.dict(
                os.environ,
                {"DEFENSECLAW_HOME": "/ambient/wrong-home"},
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=1),
            ) as run,
        ):
            _assert_gateway_quiesced(
                data_dir,
                gateway_path="/trusted/defenseclaw-gateway",
            )

        self.assertEqual(
            run.call_args.kwargs["env"]["DEFENSECLAW_HOME"],
            os.path.abspath(data_dir),
        )

    def test_live_status_without_pid_identity_is_not_accepted_as_running(self):
        with (
            TemporaryDirectory() as data_dir,
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0),
            ),
        ):
            with self.assertRaisesRegex(OSError, "PID identity is unavailable"):
                _capture_source_gateway_running_state(
                    "/trusted/defenseclaw-gateway",
                    data_dir,
                )

    def test_live_status_and_verified_pid_identity_capture_running_state(self):
        with TemporaryDirectory() as data_dir:
            Path(data_dir, "gateway.pid").write_text("1234\n", encoding="utf-8")
            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(returncode=0),
                ) as run,
                patch(
                    "defenseclaw.process_liveness.read_pid_file",
                    return_value=1234,
                ),
                patch("defenseclaw.process_liveness.pid_alive", return_value=True),
                patch("defenseclaw.process_liveness.process_is_gateway", return_value=True),
            ):
                self.assertTrue(
                    _capture_source_gateway_running_state(
                        "/trusted/defenseclaw-gateway",
                        data_dir,
                    )
                )
                self.assertEqual(run.call_args.kwargs["timeout"], 20)


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
            try:
                os.symlink(target, os.path.join(data_dir, "backups"))
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows symlink privilege is unavailable")
                raise

            with self.assertRaises(OSError):
                _create_backup(cfg)

            self.assertEqual(os.listdir(target), [])


@unittest.skipIf(os.name == "nt", "POSIX hard-cut rollback fixture")
class TestHardCutRollbackTransaction(unittest.TestCase):
    def setUp(self) -> None:
        self._bridge_version = patch("defenseclaw.__version__", "0.8.4")
        self._bridge_version.start()

    def tearDown(self) -> None:
        self._bridge_version.stop()

    def _prepare_plan(
        self,
        root: str,
        *,
        config_payload: bytes | None = None,
        cursor_payload: bytes | None = None,
        active_gateway_payload: bytes | None = None,
        environment_payload: bytes | None = None,
        environment_lock_payload: bytes | None = None,
        preexisting_v8_recovery: bool = False,
        default_controller_config: bool = False,
        os_name: str = "linux",
        arch: str = "amd64",
    ):
        home = os.path.join(root, "home")
        data_dir = os.path.join(root, "data")
        staged = os.path.join(root, "staged-handoff")
        backup_root = os.path.join(data_dir, "backups")
        backup_dir = os.path.join(backup_root, "upgrade-test")
        os.makedirs(home)
        os.makedirs(os.path.join(home, ".defenseclaw"))
        os.makedirs(data_dir)
        os.mkdir(staged, 0o700)
        os.mkdir(backup_root, 0o700)
        os.mkdir(backup_dir, 0o700)
        if preexisting_v8_recovery:
            os.mkdir(os.path.join(backup_root, "observability-v8-" + "b" * 32), 0o700)

        config_path = (
            os.path.join(
                home,
                ".defenseclaw",
                "config.yaml",
            )
            if default_controller_config
            else os.path.join(data_dir, "config.yaml")
        )
        cursor_path = os.path.join(data_dir, ".migration_state.json")
        with open(config_path, "wb") as stream:
            stream.write(
                config_payload
                if config_payload is not None
                else (
                    f"config_version: 7\ndata_dir: {data_dir}\ngateway:\n  api_port: 18970\n"
                    if default_controller_config
                    else "config_version: 7\ngateway:\n  api_port: 18970\n"
                ).encode()
            )
        with open(cursor_path, "wb") as stream:
            stream.write(cursor_payload if cursor_payload is not None else b'{"schema":1,"applied":["0.8.4"]}\n')
        if environment_payload is not None:
            with open(os.path.join(data_dir, ".env"), "wb") as stream:
                stream.write(environment_payload)
        if environment_lock_payload is not None:
            with open(os.path.join(data_dir, ".env.lock"), "wb") as stream:
                stream.write(environment_lock_payload)
            os.chmod(os.path.join(data_dir, ".env.lock"), 0o644)

        release_artifacts = _expected_release_artifacts("0.8.4")
        wheel_name = release_artifacts["wheel"]
        wheel_path = os.path.join(staged, wheel_name)
        _write_migration_wheel(
            wheel_path,
            version="0.8.4",
            migration_versions=("0.3.0",),
            supports_bundle_flag=True,
            supported_config_versions=(7,),
        )
        archive_name = release_artifacts["gateways"][os_name][arch]
        archive_path = os.path.join(staged, archive_name)
        materialized_archive_path = archive_path + ".materialized.tar.gz"
        gateway_payload = (
            b"#!/bin/sh\nif [ \"${1:-}\" = status ]; then exit 1; fi\necho 'defenseclaw-gateway version 0.8.4'\n"
        )
        with tarfile.open(materialized_archive_path, "w:gz") as archive:
            member = tarfile.TarInfo("defenseclaw")
            member.size = len(gateway_payload)
            member.mode = 0o755
            archive.addfile(member, io.BytesIO(gateway_payload))
        archive_payload = Path(materialized_archive_path).read_bytes()
        Path(archive_path).write_bytes(
            b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n" + bytes(value ^ 0xA5 for value in archive_payload)
        )
        Path(materialized_archive_path).unlink()
        active_gateway = os.path.join(home, ".local", "bin", "defenseclaw-gateway")
        os.makedirs(os.path.dirname(active_gateway), exist_ok=True)
        with open(active_gateway, "wb") as stream:
            stream.write(gateway_payload if active_gateway_payload is None else active_gateway_payload)
        os.chmod(active_gateway, 0o755)

        manifest_path = os.path.join(staged, "upgrade-manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as stream:
            json.dump(
                {
                    "schema_version": 2,
                    "runtime_config_version": 7,
                    "release_version": "0.8.4",
                    "min_upgrade_protocol": 1,
                    "controller_upgrade_protocol": 2,
                    "migration_failure_policy": "warn",
                    "required_cli_migrations": [],
                    "tested_source_versions": ["0.8.3"],
                    "platform_tested_source_versions": {"windows": ["0.8.3"]},
                    "release_artifacts": release_artifacts,
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
        with open(checksums_path, "rb") as stream:
            bridge_checksums_sha256 = hashlib.sha256(stream.read()).hexdigest()
        provenance_payload = _hard_cut_provenance_payload(bridge_checksums_sha256)
        provenance_bytes = (json.dumps(provenance_payload, indent=2, sort_keys=True) + "\n").encode()
        release_provenance = _parse_release_provenance(
            provenance_payload,
            target_version="0.8.5",
            artifact_sha256=hashlib.sha256(provenance_bytes).hexdigest(),
        )

        app = AppContext()
        app.cfg = Config()
        app.cfg.data_dir = data_dir
        app.cfg.claw.home_dir = os.path.join(root, "openclaw")
        upgrade_environment = {"HOME": home}
        if not default_controller_config:
            upgrade_environment["DEFENSECLAW_CONFIG"] = config_path
        with (
            patch.dict(os.environ, upgrade_environment, clear=default_controller_config),
            patch(
                "defenseclaw.commands.cmd_upgrade.shutil.which",
                return_value="/usr/bin/cosign",
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0),
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade._capture_source_gateway_running_state",
                return_value=True,
            ),
        ):
            plan = _prepare_hard_cut_rollback_plan(
                app.cfg,
                backup_dir,
                source_version="0.8.4",
                os_name=os_name,
                arch=arch,
                staged_artifact_dir=staged,
                release_provenance=release_provenance,
            )
        return app, plan, config_path, cursor_path, gateway_payload, home

    def test_backup_root_contract_rejects_replaced_preexisting_recovery_entry(self):
        with TemporaryDirectory() as root:
            _app, plan, _config, _cursor, _gateway, _home = self._prepare_plan(
                root,
                preexisting_v8_recovery=True,
            )
            recovery = Path(plan.backup_dir).parent / ("observability-v8-" + "b" * 32)
            displaced = recovery.with_name("preexisting-recovery-displaced")
            recovery.rename(displaced)
            recovery.mkdir(mode=0o700)

            with self.assertRaisesRegex(OSError, "pre-existing .* disappeared"):
                _restore_hard_cut_backup_root_contract(plan)

    def test_default_controller_config_and_custom_data_dir_remain_distinct(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, cursor_path, _gateway, home = self._prepare_plan(
                root,
                default_controller_config=True,
            )

            self.assertEqual(plan.recovery_home, os.path.join(home, ".defenseclaw"))
            self.assertNotEqual(plan.recovery_home, plan.data_dir)
            self.assertEqual(plan.state_files[0].active_path, config_path)
            self.assertEqual(
                [snapshot.active_path for snapshot in plan.state_files],
                [
                    config_path,
                    config_path + ".pre-observability-migration.bak",
                    config_path + ".lock",
                    config_path + ".tmp-f3395",
                    os.path.join(app.cfg.data_dir, ".env"),
                    os.path.join(app.cfg.data_dir, ".env.lock"),
                    cursor_path,
                ],
            )

    def test_hard_cut_cleanup_removes_only_plan_owned_temporaries(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor, _gateway, _home = self._prepare_plan(root)
            token = _hard_cut_mutation_token(plan)
            owned = [
                Path(app.cfg.data_dir, f".migration_state.upgrade-{token}.abc.tmp"),
                Path(app.cfg.data_dir, f".tmp.upgrade-{token}.abc.env"),
                Path(
                    os.path.dirname(config_path),
                    f".{os.path.basename(config_path)}.upgrade-{token}.abc.tmp",
                ),
            ]
            unrelated = Path(app.cfg.data_dir, ".migration_state.preexisting.tmp")
            for path in (*owned, unrelated):
                path.write_bytes(b"temporary")

            _cleanup_hard_cut_mutation_temporaries(plan)

            self.assertTrue(unrelated.is_file())
            self.assertTrue(all(not path.exists() for path in owned))

    def test_wrong_version_recovery_reinstalls_and_execs_recorded_bridge_controller(self):
        class ExecveHandoffError(RuntimeError):
            pass

        with TemporaryDirectory() as root:
            _app, original_plan, config_path, _cursor, _gateway, _home = self._prepare_plan(
                root,
                default_controller_config=True,
            )
            plan = replace(
                original_plan,
                environment_snapshot={
                    "DEFENSECLAW_HOME": original_plan.recovery_home,
                    "DEFENSECLAW_CONFIG": config_path,
                    "KEEP_OPERATOR_OVERRIDE": "yes",
                    "PYTHONHOME": "target-python-home",
                    "PYTHONPATH": "target-python-path",
                },
            )
            expected_python = os.path.join(plan.recovery_home, ".venv", "bin", "python")

            with (
                patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True) as stop,
                patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced") as quiesced,
                patch("defenseclaw.commands.cmd_upgrade._install_wheel") as install,
                patch(
                    "defenseclaw.commands.cmd_upgrade.os.execve",
                    side_effect=ExecveHandoffError("execed bridge"),
                ) as execve,
                patch.object(sys, "argv", ["defenseclaw", "upgrade", "--yes"]),
                self.assertRaisesRegex(ExecveHandoffError, "execed bridge"),
            ):
                _handoff_hard_cut_recovery_to_source_controller(plan)

            stop.assert_called_once()
            stop_environment = stop.call_args.kwargs["env"]
            self.assertEqual(stop_environment["DEFENSECLAW_HOME"], plan.data_dir)
            self.assertEqual(stop_environment["DEFENSECLAW_CONFIG"], config_path)
            quiesced.assert_called_once_with(
                plan.data_dir,
                gateway_path=plan.active_gateway_path,
            )
            install.assert_called_once_with(
                plan.rollback_wheel_path,
                plan.os_name,
                exact_environment=True,
            )
            execve.assert_called_once()
            executable, arguments, child_environment = execve.call_args.args
            self.assertEqual(executable, expected_python)
            self.assertEqual(
                arguments,
                [expected_python, "-I", "-B", "-m", "defenseclaw.main", "upgrade", "--yes"],
            )
            self.assertEqual(child_environment["DEFENSECLAW_HOME"], plan.recovery_home)
            self.assertEqual(child_environment["DEFENSECLAW_CONFIG"], config_path)
            self.assertEqual(child_environment["KEEP_OPERATOR_OVERRIDE"], "yes")
            self.assertNotIn("PYTHONHOME", child_environment)
            self.assertNotIn("PYTHONPATH", child_environment)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX capture contract")
    def test_rollback_capture_rejects_symlink_source_without_creating_backup(self):
        with TemporaryDirectory() as root:
            real = Path(root, "real")
            active = Path(root, "active")
            backup = Path(root, "backup")
            real.write_bytes(b"bridge state")
            active.symlink_to(real)

            with self.assertRaisesRegex(OSError, "must be a regular file"):
                _capture_rollback_file(str(active), str(backup), required=True)

            self.assertFalse(backup.exists())

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX capture contract")
    def test_rollback_capture_detects_named_inode_swap_during_read(self):
        with TemporaryDirectory() as root:
            active = Path(root, "active")
            displaced = Path(root, "displaced")
            backup = Path(root, "backup")
            active.write_bytes(b"bridge state")
            real_read = os.read
            swapped = False

            def swap_after_first_read(descriptor: int, size: int) -> bytes:
                nonlocal swapped
                payload = real_read(descriptor, size)
                if payload and not swapped:
                    swapped = True
                    active.replace(displaced)
                    active.write_bytes(b"target replacement")
                return payload

            with (
                patch("defenseclaw.commands.cmd_upgrade.os.read", side_effect=swap_after_first_read),
                self.assertRaisesRegex(OSError, "changed while being read"),
            ):
                _capture_rollback_file(str(active), str(backup), required=True)

            self.assertFalse(backup.exists())
            self.assertEqual(active.read_bytes(), b"target replacement")

    def test_bundle_intent_without_metadata_is_prewrite_noop_after_lease(self):
        with TemporaryDirectory() as backup_dir:
            self.assertEqual(
                _crash_bundle_rollback_result(backup_dir, required=True),
                {"installed": False},
            )

    @unittest.skipUnless(os.name == "posix", "POSIX durability contract")
    def test_posix_state_restore_fsyncs_payload_before_publish_and_parent_after(self):
        with TemporaryDirectory() as root:
            active = Path(root, "config.yaml")
            backup = Path(root, "config.backup")
            active.write_bytes(b"target state")
            backup.write_bytes(b"bridge state")
            snapshot = _RollbackFileSnapshot(
                active_path=str(active),
                backup_path=str(backup),
                existed=True,
                sha256=hashlib.sha256(b"bridge state").hexdigest(),
                mode=0o600,
            )
            events: list[str] = []
            real_fsync = os.fsync
            real_replace = os.replace

            def tracking_fsync(descriptor):
                kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
                events.append(f"fsync:{kind}")
                real_fsync(descriptor)

            def tracking_replace(source, destination):
                events.append("replace")
                real_replace(source, destination)

            with (
                patch("defenseclaw.commands.cmd_upgrade.os.fsync", side_effect=tracking_fsync),
                patch("defenseclaw.commands.cmd_upgrade.os.replace", side_effect=tracking_replace),
            ):
                _restore_rollback_file(snapshot)

            self.assertEqual(active.read_bytes(), b"bridge state")
            self.assertEqual(events, ["fsync:file", "replace", "fsync:directory"])

    @unittest.skipUnless(os.name == "posix", "POSIX durability contract")
    def test_recovery_custody_fsyncs_full_directory_chain_before_journal(self):
        with TemporaryDirectory() as root:
            app, plan, _config_path, _cursor_path, _gateway_payload, _home = self._prepare_plan(root)
            descriptors: dict[int, str] = {}
            fsynced: list[str] = []

            def fake_open(path, _flags, *_args):
                descriptor = 1000 + len(descriptors)
                descriptors[descriptor] = os.path.abspath(os.fspath(path))
                return descriptor

            def fake_fsync(descriptor):
                fsynced.append(descriptors[descriptor])

            with (
                patch("defenseclaw.commands.cmd_upgrade.os.open", side_effect=fake_open),
                patch("defenseclaw.commands.cmd_upgrade.os.fsync", side_effect=fake_fsync),
                patch("defenseclaw.commands.cmd_upgrade.os.close"),
            ):
                _fsync_hard_cut_recovery_custody(plan)

            rollback_root = os.path.join(plan.backup_dir, "hard-cut-rollback")
            state_root = os.path.join(rollback_root, "state")
            backup_root = os.path.dirname(plan.backup_dir)
            for required in (
                state_root,
                rollback_root,
                plan.backup_dir,
                backup_root,
                app.cfg.data_dir,
            ):
                self.assertIn(os.path.abspath(required), fsynced)
            self.assertLess(fsynced.index(state_root), fsynced.index(rollback_root))
            self.assertLess(fsynced.index(rollback_root), fsynced.index(plan.backup_dir))
            self.assertLess(fsynced.index(plan.backup_dir), fsynced.index(backup_root))

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "symlink"), "POSIX symlink contract")
    def test_posix_state_restore_rejects_symlinked_backup_before_read(self):
        with TemporaryDirectory() as root:
            active = Path(root, "config.yaml")
            retained = Path(root, "retained.backup")
            backup = Path(root, "config.backup")
            active.write_bytes(b"target state")
            retained.write_bytes(b"bridge state")
            backup.symlink_to(retained)
            snapshot = _RollbackFileSnapshot(
                active_path=str(active),
                backup_path=str(backup),
                existed=True,
                sha256=hashlib.sha256(b"bridge state").hexdigest(),
                mode=0o600,
            )

            with self.assertRaisesRegex(OSError, "not a real regular file"):
                _restore_rollback_file(snapshot)

            self.assertEqual(active.read_bytes(), b"target state")
            self.assertEqual(retained.read_bytes(), b"bridge state")

    def test_windows_state_restore_rejects_reparse_backup_before_open(self):
        snapshot = _RollbackFileSnapshot(
            active_path="C:/DefenseClaw/config.yaml",
            backup_path="C:/DefenseClaw/config.backup",
            existed=True,
            sha256=hashlib.sha256(b"bridge state").hexdigest(),
            mode=None,
            windows_security=Mock(),
        )
        reparse = types.SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_file_attributes=0x00000400,
        )
        with (
            patch("defenseclaw.commands.cmd_upgrade.os.lstat", return_value=reparse),
            patch("defenseclaw.commands.cmd_upgrade.os.open") as secure_open,
            patch("defenseclaw.commands.cmd_upgrade._stage_windows_rollback_file") as stage,
            self.assertRaisesRegex(OSError, "not a real regular file"),
        ):
            _restore_windows_rollback_file(snapshot)

        secure_open.assert_not_called()
        stage.assert_not_called()

    def test_prepare_retains_exact_active_gateway_and_rejects_component_drift(self):
        with TemporaryDirectory() as root:
            _app, plan, _config_path, _cursor_path, gateway_payload, _home = self._prepare_plan(root)
            self.assertEqual(plan.gateway_snapshot.active_path, plan.active_gateway_path)
            self.assertEqual(plan.gateway_snapshot.backup_path, plan.rollback_gateway_path)
            with open(plan.rollback_gateway_path, "rb") as stream:
                self.assertEqual(stream.read(), gateway_payload)

        with (
            TemporaryDirectory() as root,
            self.assertRaisesRegex(
                OSError,
                "does not match its authenticated rollback artifact",
            ),
        ):
            self._prepare_plan(root, active_gateway_payload=b"different bridge gateway")

    @unittest.skipUnless(sys.platform == "darwin", "macOS codesign coherence contract")
    def test_macos_rollback_signature_accepts_authenticated_adhoc_fallback_identifier(self):
        with TemporaryDirectory() as root:
            gateway = Path(root, "published-unsigned-gateway")
            gateway.write_bytes(Path("/usr/bin/true").read_bytes())
            os.chmod(gateway, 0o755)
            subprocess.run(
                ["/usr/bin/codesign", "--remove-signature", str(gateway)],
                capture_output=True,
                text=True,
                check=True,
            )
            subprocess.run(
                [
                    "/usr/bin/codesign",
                    "--force",
                    "--sign",
                    "-",
                    "--identifier",
                    "a.out",
                    str(gateway),
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            _verify_macos_rollback_gateway_signature(str(gateway))

    def test_macos_rollback_signature_keeps_identifier_gate_for_non_adhoc_signatures(self):
        valid = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        signed_details = subprocess.CompletedProcess(
            [],
            0,
            stdout="",
            stderr="Signature size=9000\nAuthority=Developer ID Application: Example\nTeamIdentifier=TEAM123\n",
        )
        rejected = subprocess.CalledProcessError(3, ["/usr/bin/codesign"])
        with (
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                side_effect=(valid, signed_details, rejected),
            ) as run,
            self.assertRaisesRegex(OSError, "signature identifier is invalid"),
        ):
            _verify_macos_rollback_gateway_signature("/private/rollback/gateway")

        self.assertEqual(run.call_count, 3)
        self.assertIn("-R", run.call_args_list[-1].args[0])
        self.assertIn(_MACOS_GATEWAY_CODESIGN_IDENTIFIER, run.call_args_list[-1].args[0][-2])

    def test_macos_rollback_signature_rejects_ambiguous_adhoc_metadata(self):
        valid = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        ambiguous = subprocess.CompletedProcess(
            [],
            0,
            stdout="",
            stderr="Signature=adhoc\nAuthority=Unexpected\nTeamIdentifier=not set\n",
        )
        with (
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                side_effect=(valid, ambiguous),
            ),
            self.assertRaisesRegex(OSError, "ad-hoc signature metadata is invalid"),
        ):
            _verify_macos_rollback_gateway_signature("/private/rollback/gateway")

    @unittest.skipUnless(sys.platform == "darwin", "macOS codesign coherence contract")
    def test_macos_coherence_canonicalization_accepts_native_signature_layout(self):
        with TemporaryDirectory() as root:
            fixture = Path("/usr/bin/true").read_bytes()
            release_gateway = Path(root, "authenticated-release-gateway")
            native_gateway = Path(root, "native-app-gateway")
            release_gateway.write_bytes(fixture)
            native_gateway.write_bytes(fixture)
            os.chmod(release_gateway, 0o755)
            os.chmod(native_gateway, 0o755)
            subprocess.run(
                ["/usr/bin/codesign", "--remove-signature", str(release_gateway)],
                capture_output=True,
                text=True,
                check=True,
            )
            subprocess.run(
                [
                    "/usr/bin/codesign",
                    "--force",
                    "--options",
                    "runtime",
                    "--sign",
                    "-",
                    "--identifier",
                    "com.cisco.defenseclaw.gateway",
                    str(native_gateway),
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            _verify_macos_rollback_gateway_signature(str(native_gateway))
            _canonicalize_macos_gateway_for_coherence(str(release_gateway))
            _canonicalize_macos_gateway_for_coherence(str(native_gateway))

            self.assertEqual(release_gateway.read_bytes(), native_gateway.read_bytes())

    def test_macos_hard_cut_preserves_native_gateway_bytes_and_compares_code(self):
        release_gateway = (
            b"#!/bin/sh\nif [ \"${1:-}\" = status ]; then exit 1; fi\necho 'defenseclaw-gateway version 0.8.4'\n"
        )
        native_gateway = b"developer-id-signature-layout\n" + release_gateway
        canonical = b"same-host canonical release gateway"
        canonicalized: list[str] = []

        def canonicalize(path: str) -> None:
            payload = Path(path).read_bytes()
            canonicalized.append(path)
            if payload in (release_gateway, native_gateway):
                Path(path).write_bytes(canonical)

        with (
            TemporaryDirectory() as root,
            (
                patch(
                    "defenseclaw.commands.cmd_upgrade._canonicalize_macos_gateway_for_coherence",
                    side_effect=canonicalize,
                )
            ) as normalize,
            patch("defenseclaw.commands.cmd_upgrade._verify_macos_rollback_gateway_signature") as verify_signature,
        ):
            _app, plan, _config, _cursor, _gateway, _home = self._prepare_plan(
                root,
                active_gateway_payload=native_gateway,
                os_name="darwin",
                arch="arm64",
            )
            self.assertEqual(Path(plan.rollback_gateway_path).read_bytes(), native_gateway)
            self.assertEqual(
                plan.rollback_gateway_sha256,
                hashlib.sha256(native_gateway).hexdigest(),
            )
            verify_signature.assert_called_once_with(plan.rollback_gateway_path)
            self.assertEqual(normalize.call_count, 2)
            self.assertNotIn(plan.rollback_gateway_path, canonicalized)

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
            wheel = os.path.join(staged, "defenseclaw-0.8.4-2-py3-none-any.dcwheel")
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
            wheel = os.path.join(staged, "defenseclaw-0.8.4-2-py3-none-any.dcwheel")
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

    def test_staged_modern_bridge_bootstraps_cosign_and_uses_exact_workflow_identity(self):
        with TemporaryDirectory() as root:
            self._prepare_plan(root)
            staged = os.path.join(root, "staged-handoff")
            with (
                patch("defenseclaw.commands.cmd_upgrade.shutil.which", return_value=None),
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_bootstrap_cosign",
                    return_value="/tmp/authenticated-cosign",
                ) as bootstrap,
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(returncode=0),
                ) as bootstrap_run,
            ):
                _validate_staged_bridge_artifact_set(staged, "0.8.4", "linux", "amd64")

            bootstrap.assert_called_once()
            self.assertEqual(bootstrap_run.call_args.args[0][0], "/tmp/authenticated-cosign")

            with (
                patch("defenseclaw.commands.cmd_upgrade.shutil.which", return_value=None),
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_bootstrap_cosign",
                    side_effect=OSError("digest mismatch"),
                ),
                self.assertRaisesRegex(OSError, "signature verification failed"),
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
                    f"{digest}  upgrade-manifest.json" if line.endswith("  upgrade-manifest.json") else line
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

    def test_staged_bridge_rollback_names_must_come_from_signed_protected_policy(self):
        with TemporaryDirectory() as root:
            self._prepare_plan(root)
            staged = os.path.join(root, "staged-handoff")
            manifest_path = os.path.join(staged, "upgrade-manifest.json")
            with open(manifest_path, encoding="utf-8") as stream:
                manifest = json.load(stream)
            manifest["release_artifacts"]["wheel"] = "defenseclaw-0.8.4-py3-none-any.whl"
            with open(manifest_path, "w", encoding="utf-8") as stream:
                json.dump(manifest, stream)
            digest = hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest()
            checksums_path = os.path.join(staged, "checksums.txt")
            lines = Path(checksums_path).read_text(encoding="utf-8").splitlines()
            Path(checksums_path).write_text(
                "\n".join(
                    f"{digest}  upgrade-manifest.json" if line.endswith("  upgrade-manifest.json") else line
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
                self.assertRaises(SystemExit),
            ):
                _validate_staged_bridge_artifact_set(
                    staged,
                    "0.8.4",
                    "linux",
                    "amd64",
                )

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

    def test_post_migration_health_failure_restores_exact_bridge_state_and_records_outcome(self):
        with TemporaryDirectory() as root:
            root = os.path.realpath(root)
            bridge_config = (
                b"# operator upgrade note\nconfig_version: 7\ngateway:\n  api_port: 18970 # keep this port\n"
            )
            bridge_cursor = b'{"schema":1,"applied":["0.3.0","0.4.0","0.5.0","0.7.0","0.8.0"]}\n'
            app, plan, config_path, cursor_path, gateway_payload, home = self._prepare_plan(
                root,
                config_payload=bridge_config,
                cursor_payload=bridge_cursor,
                environment_lock_payload=b"bridge lock sentinel\n",
            )
            with open(config_path, "wb") as stream:
                stream.write(b"config_version: 8\n")
            with open(cursor_path, "wb") as stream:
                stream.write(b'{"schema":1,"applied":["0.8.5"]}\n')
            environment_path = os.path.join(app.cfg.data_dir, ".env")
            with open(environment_path, "wb") as stream:
                stream.write(b"CREATED_BY_TARGET=yes\n")
            environment_lock_path = os.path.join(app.cfg.data_dir, ".env.lock")
            with open(environment_lock_path, "wb") as stream:
                stream.write(b"target lock sentinel\n")
            os.chmod(environment_lock_path, 0o644)
            backup_root = Path(plan.backup_dir).parent
            os.chmod(backup_root, 0o755)
            target_recovery = backup_root / ("observability-v8-" + "a" * 32)
            target_recovery.mkdir(mode=0o700)
            (target_recovery / "config.source").write_bytes(b"config_version: 7\n")
            (target_recovery / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "observability-v8-activation",
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(target_recovery / "config.source", 0o600)
            os.chmod(target_recovery / "manifest.json", 0o600)
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
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_silent",
                    side_effect=[True, False, True],
                ) as run_silent,
                patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"),
                patch("defenseclaw.commands.cmd_upgrade._poll_installed_health") as poll_health,
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
                self.assertEqual(stream.read(), bridge_config)
            with open(cursor_path, "rb") as stream:
                self.assertEqual(stream.read(), bridge_cursor)
            self.assertFalse(os.path.exists(environment_path))
            self.assertEqual(Path(environment_lock_path).read_bytes(), b"bridge lock sentinel\n")
            self.assertEqual(stat.S_IMODE(os.stat(environment_lock_path).st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(backup_root.stat().st_mode), 0o700)
            self.assertTrue(target_recovery.is_dir())
            with open(plan.active_gateway_path, "rb") as stream:
                self.assertEqual(stream.read(), gateway_payload)
            install_wheel.assert_called_once_with(
                plan.rollback_wheel_path,
                "linux",
                exact_environment=True,
            )
            poll_health.assert_called_once_with(
                app.cfg.data_dir,
                9,
                "0.8.4",
                os_name="linux",
            )
            gateway_commands = [call.args[0] for call in run_silent.call_args_list]
            self.assertIn([plan.active_gateway_path, "stop"], gateway_commands)
            self.assertEqual(gateway_commands.count([plan.active_gateway_path, "start"]), 2)
            start_calls = [call for call in run_silent.call_args_list if call.args[0][-1] == "start"]
            self.assertTrue(all(call.kwargs["timeout_seconds"] == 90 for call in start_calls))

            # A later direct bridge-to-target retry must snapshot the restored,
            # comment-bearing bridge bytes, not a lossy phase-two derivative.
            retry_backup_dir = os.path.join(os.path.dirname(plan.backup_dir), "upgrade-retry")
            os.mkdir(retry_backup_dir, 0o700)
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
                patch(
                    "defenseclaw.commands.cmd_upgrade._capture_source_gateway_running_state",
                    return_value=True,
                ),
            ):
                retry_plan = _prepare_hard_cut_rollback_plan(
                    app.cfg,
                    retry_backup_dir,
                    source_version="0.8.4",
                    os_name="linux",
                    arch="amd64",
                    staged_artifact_dir=os.path.join(root, "staged-handoff"),
                    release_provenance=plan.release_provenance,
                )
            self.assertEqual(Path(retry_plan.state_files[0].backup_path).read_bytes(), bridge_config)

            with (
                patch("defenseclaw.__version__", "0.8.5"),
                patch(
                    "defenseclaw.migrations.inspect_v8_config",
                    return_value=types.SimpleNamespace(valid=True, config_version=8),
                ),
            ):
                applied = run_migrations(
                    "0.8.4",
                    "0.8.5",
                    app.cfg.claw.home_dir,
                    app.cfg.data_dir,
                    upgrade_handles_local_bundle=True,
                    controller_owns_local_bundle_transaction=True,
                )

            self.assertEqual(applied, 1)
            migrated = Path(config_path).read_text(encoding="utf-8")
            self.assertEqual(yaml.safe_load(migrated)["config_version"], 8)
            self.assertIn("# operator upgrade note", migrated)
            self.assertIn("# keep this port", migrated)
            self.assertIn("0.8.5", Path(cursor_path).read_text(encoding="utf-8"))
            self.assertNotIn(["defenseclaw-gateway", "stop"], gateway_commands)
            self.assertNotIn(["defenseclaw-gateway", "start"], gateway_commands)
            receipt = load_upgrade_receipt(receipt_path)
            self.assertEqual(receipt.status, "rolled_back")
            self.assertEqual(receipt.failure_code, "health_check_failed")

    def test_rollback_preserves_stopped_gateway_but_restarts_recorded_local_stack(self):
        with TemporaryDirectory() as root:
            app, running_plan, _config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(root)
            plan = replace(running_plan, source_gateway_was_running=False)
            bundle_backup = Path(plan.backup_dir) / "local-observability-stack"
            bundle_backup.mkdir(mode=0o700)
            restart_intent = bundle_backup / "restart-intent.json"
            restart_intent.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "target_manifest_sha256": "a" * 64,
                        "restart_required": True,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(restart_intent, 0o600)
            crash_bundle_result = _crash_bundle_rollback_result(
                plan.backup_dir,
                required=True,
            )
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )
            calls: list[list[str]] = []

            def run_silent(command, *_messages, **_kwargs):
                calls.append(command)
                return True

            with (
                patch.dict(os.environ, {"HOME": home}),
                patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced") as quiesced,
                patch("defenseclaw.commands.cmd_upgrade._install_wheel"),
                patch("defenseclaw.commands.cmd_upgrade._verify_restored_bridge_artifacts"),
                patch("defenseclaw.commands.cmd_upgrade._poll_installed_health") as health,
                patch("defenseclaw.commands.cmd_upgrade._run_silent", side_effect=run_silent),
                patch(
                    "defenseclaw.commands.cmd_upgrade._restart_restored_local_observability_stack",
                    return_value={"restarted": True, "degraded_errors": []},
                ) as restart_stack,
            ):
                restored = _execute_hard_cut_rollback(
                    plan,
                    app,
                    receipt_path,
                    failure_code="health_check_failed",
                    health_timeout=3,
                    local_bundle_upgrade=crash_bundle_result,
                )

            self.assertTrue(restored)
            self.assertNotIn([plan.active_gateway_path, "start"], calls)
            health.assert_not_called()
            quiesced.assert_called()
            restart_stack.assert_called_once_with(
                app.cfg.data_dir,
                health_timeout=3,
            )

    def test_crash_restart_failure_cannot_report_rollback_success(self):
        with TemporaryDirectory() as root:
            app, running_plan, _config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(root)
            plan = replace(running_plan, source_gateway_was_running=False)
            bundle_backup = Path(plan.backup_dir) / "local-observability-stack"
            bundle_backup.mkdir(mode=0o700)
            restart_intent = bundle_backup / "restart-intent.json"
            restart_intent.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "target_manifest_sha256": "b" * 64,
                        "restart_required": True,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(restart_intent, 0o600)
            crash_bundle_result = _crash_bundle_rollback_result(
                plan.backup_dir,
                required=True,
            )
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )

            with (
                patch.dict(os.environ, {"HOME": home}),
                patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"),
                patch("defenseclaw.commands.cmd_upgrade._install_wheel"),
                patch("defenseclaw.commands.cmd_upgrade._verify_restored_bridge_artifacts"),
                patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
                patch(
                    "defenseclaw.commands.cmd_upgrade._restart_restored_local_observability_stack",
                    return_value={
                        "restarted": False,
                        "degraded_errors": ["grafana_not_ready"],
                    },
                ) as restart_stack,
            ):
                restored = _execute_hard_cut_rollback(
                    plan,
                    app,
                    receipt_path,
                    failure_code="local_observability_failed",
                    health_timeout=3,
                    local_bundle_upgrade=crash_bundle_result,
                )

            self.assertFalse(restored)
            restart_stack.assert_called_once_with(
                app.cfg.data_dir,
                health_timeout=3,
            )
            receipt = load_upgrade_receipt(receipt_path)
            self.assertEqual(receipt.status, "failed")
            self.assertEqual(receipt.failure_code, "local_observability_failed")

    def test_rollback_restart_uses_durable_metadata_result_not_child_field(self):
        with TemporaryDirectory() as root:
            app, running_plan, _config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(root)
            plan = replace(running_plan, source_gateway_was_running=False)
            receipt_path = begin_upgrade_receipt(
                app.cfg.data_dir,
                from_version="0.8.4",
                target_version="0.8.5",
                artifacts_verified=True,
            )
            with (
                patch.dict(os.environ, {"HOME": home}),
                patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"),
                patch("defenseclaw.commands.cmd_upgrade._install_wheel"),
                patch("defenseclaw.commands.cmd_upgrade._verify_restored_bridge_artifacts"),
                patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
                patch(
                    "defenseclaw.commands.cmd_upgrade._restore_local_observability_upgrade_backup",
                    return_value=True,
                ) as restore_bundle,
                patch(
                    "defenseclaw.commands.cmd_upgrade._restart_restored_local_observability_stack",
                    return_value={"restarted": True, "degraded_errors": []},
                ) as restart_stack,
            ):
                restored = _execute_hard_cut_rollback(
                    plan,
                    app,
                    receipt_path,
                    failure_code="health_check_failed",
                    health_timeout=3,
                    local_bundle_upgrade={
                        "installed": True,
                        "restart_required": False,
                    },
                )

            self.assertTrue(restored)
            restore_bundle.assert_called_once_with(
                plan.data_dir,
                plan.backup_dir,
                {"installed": True, "restart_required": False},
            )
            restart_stack.assert_called_once_with(
                app.cfg.data_dir,
                health_timeout=3,
            )

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

    def test_rollback_retries_when_first_restored_health_probe_raises_oserror(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(root)
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
                patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"),
                patch(
                    "defenseclaw.commands.cmd_upgrade._poll_installed_health",
                    side_effect=[OSError("health probe could not start"), None],
                ) as poll_health,
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_silent",
                    return_value=True,
                ) as run_silent,
            ):
                restored = _execute_hard_cut_rollback(
                    plan,
                    app,
                    receipt_path,
                    failure_code="health_check_failed",
                    health_timeout=3,
                )

            self.assertTrue(restored)
            self.assertEqual(poll_health.call_count, 2)
            start_calls = [
                call for call in run_silent.call_args_list if call.args[0] == [plan.active_gateway_path, "start"]
            ]
            self.assertEqual(len(start_calls), 2)
            receipt = load_upgrade_receipt(receipt_path)
            self.assertEqual(receipt.status, "rolled_back")
            self.assertEqual(receipt.failure_code, "health_check_failed")

    def test_recovery_journal_round_trips_private_secret_free_custody(self):
        with TemporaryDirectory() as root:
            app, plan, config_path, _cursor_path, _gateway_payload, home = self._prepare_plan(
                root,
                environment_payload=b"BRIDGE_TOKEN=do-not-journal\n",
                preexisting_v8_recovery=True,
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
                    "DEFENSECLAW_HOME": plan.recovery_home,
                    "DEFENSECLAW_CONFIG": config_path,
                    "BRIDGE_TOKEN": "do-not-journal",
                },
            ):
                journal = _write_hard_cut_recovery_journal(
                    plan,
                    receipt_path,
                    target_version="0.8.5",
                )
                loaded = _load_hard_cut_recovery_journal(plan.recovery_home)

            with patch.dict(
                os.environ,
                {
                    "HOME": home,
                    "DEFENSECLAW_HOME": plan.recovery_home,
                    "DEFENSECLAW_CONFIG": os.path.join(root, "unrelated-config.yaml"),
                },
            ):
                loaded_with_changed_override = _load_hard_cut_recovery_journal(plan.recovery_home)

            self.assertIsNotNone(loaded)
            assert loaded is not None
            loaded_path, loaded_plan, loaded_receipt, target_version = loaded
            self.assertEqual(loaded_path, journal)
            self.assertEqual(loaded_plan.source_version, plan.source_version)
            self.assertNotEqual(loaded_plan.recovery_home, loaded_plan.data_dir)
            self.assertEqual(loaded_plan.recovery_home, plan.recovery_home)
            self.assertEqual(
                loaded_plan.environment_snapshot["DEFENSECLAW_HOME"],
                plan.recovery_home,
            )
            self.assertTrue(loaded_plan.source_gateway_was_running)
            self.assertFalse(loaded_plan.local_bundle_mutation_intent)
            self.assertEqual(loaded_plan.rollback_wheel_sha256, plan.rollback_wheel_sha256)
            self.assertEqual(loaded_plan.rollback_gateway_sha256, plan.rollback_gateway_sha256)
            self.assertEqual(loaded_plan.state_files, plan.state_files)
            self.assertEqual(loaded_plan.backup_root_snapshot, plan.backup_root_snapshot)
            self.assertIsNotNone(loaded_plan.release_provenance)
            assert loaded_plan.release_provenance is not None
            assert plan.release_provenance is not None
            self.assertEqual(
                loaded_plan.release_provenance.artifact_sha256,
                plan.release_provenance.artifact_sha256,
            )
            self.assertEqual(
                loaded_plan.release_provenance.bridge_checksums_sha256,
                plan.release_provenance.bridge_checksums_sha256,
            )
            self.assertEqual(loaded_receipt, receipt_path)
            self.assertEqual(target_version, "0.8.5")
            assert loaded_with_changed_override is not None
            self.assertEqual(
                loaded_with_changed_override[1].environment_snapshot["DEFENSECLAW_CONFIG"],
                config_path,
            )
            self.assertNotIn(b"do-not-journal", journal.read_bytes())
            lease = journal.with_name("phase-two-mutator.lease")
            self.assertTrue(lease.is_file())
            self.assertEqual(lease.stat().st_size, 0)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(journal.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(lease.stat().st_mode), 0o600)

    def test_recovery_journal_rejects_receipt_or_provenance_substitution(self):
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
                    "DEFENSECLAW_HOME": plan.recovery_home,
                    "DEFENSECLAW_CONFIG": config_path,
                },
            ):
                journal = _write_hard_cut_recovery_journal(
                    plan,
                    receipt_path,
                    target_version="0.8.5",
                )
                original = json.loads(journal.read_text(encoding="utf-8"))
                substitute_receipt = begin_upgrade_receipt(
                    app.cfg.data_dir,
                    from_version="0.8.4",
                    target_version="0.8.5",
                    artifacts_verified=True,
                )
                substituted = dict(original)
                substituted["receipt_path"] = str(substitute_receipt)
                journal.write_text(
                    json.dumps(substituted, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                os.chmod(journal, 0o600)
                with self.assertRaisesRegex(OSError, "receipt provenance binding changed"):
                    _load_hard_cut_recovery_journal(plan.recovery_home)

                tampered = dict(original)
                tampered_provenance = json.loads(json.dumps(original["release_provenance"]))
                tampered_provenance["source_tree"] = "9" * 40
                tampered["release_provenance"] = tampered_provenance
                journal.write_text(
                    json.dumps(tampered, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                os.chmod(journal, 0o600)
                with self.assertRaisesRegex(OSError, "bytes are not canonical or changed"):
                    _load_hard_cut_recovery_journal(plan.recovery_home)

    def test_bundle_mutation_intent_is_durable_before_target_child(self):
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
                    "DEFENSECLAW_HOME": plan.recovery_home,
                    "DEFENSECLAW_CONFIG": config_path,
                },
            ):
                journal = _write_hard_cut_recovery_journal(
                    plan,
                    receipt_path,
                    target_version="0.8.5",
                )
                _mark_hard_cut_bundle_mutation_intent(journal)
                loaded = _load_hard_cut_recovery_journal(plan.recovery_home)

            assert loaded is not None
            self.assertTrue(loaded[1].local_bundle_mutation_intent)

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
                    "DEFENSECLAW_HOME": plan.recovery_home,
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
                    _load_hard_cut_recovery_journal(plan.recovery_home)

                real_journal = journal.with_name("phase-two-real.json")
                os.replace(journal, real_journal)
                os.symlink(real_journal, journal)
                with self.assertRaisesRegex(OSError, "regular file"):
                    _load_hard_cut_recovery_journal(plan.recovery_home)

    def test_journal_unlink_failure_keeps_terminal_receipt_for_idempotent_cleanup(self):
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
                    "DEFENSECLAW_HOME": plan.recovery_home,
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

            self.assertTrue(restored)
            self.assertTrue(journal.exists())
            self.assertEqual(load_upgrade_receipt(receipt_path).status, "rolled_back")

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
                    "DEFENSECLAW_HOME": plan.recovery_home,
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
                "DEFENSECLAW_HOME": plan.recovery_home,
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
                            plan.recovery_home,
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
            created_backup = bundle_backup / "created"
            retired_backup = bundle_backup / "retired"
            (managed_backup / "managed").mkdir(parents=True)
            (created_backup / "managed").mkdir(parents=True)
            retired_backup.mkdir()
            (managed_backup / "managed/existing.yaml").write_bytes(bridge_existing)
            (managed_backup / ".defenseclaw-bundle-manifest.json").write_bytes(bridge_manifest)
            created_claim = created_backup / "managed/created.yaml"
            created_claim.write_bytes(b"target created\n")
            os.link(created_claim, created)
            metadata = bundle_backup / "refresh-backup.json"
            metadata.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "existing_paths": [
                            ".defenseclaw-bundle-manifest.json",
                            "managed/existing.yaml",
                        ],
                        "old_sha256": {
                            ".defenseclaw-bundle-manifest.json": hashlib.sha256(bridge_manifest).hexdigest(),
                            "managed/existing.yaml": hashlib.sha256(bridge_existing).hexdigest(),
                        },
                        "old_modes": {
                            ".defenseclaw-bundle-manifest.json": 0o600,
                            "managed/existing.yaml": 0o640,
                        },
                        "created_sha256": {
                            "managed/created.yaml": hashlib.sha256(b"target created\n").hexdigest(),
                        },
                        "old_windows_security": {},
                        "managed_paths": [
                            ".defenseclaw-bundle-manifest.json",
                            "managed/created.yaml",
                            "managed/existing.yaml",
                        ],
                        "restart_required": False,
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
                    "DEFENSECLAW_HOME": plan.recovery_home,
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
                            'Path(cursor).write_text(\'{"schema":1,"applied":["0.8.5"]}\\n\'); '
                            "Path(env).write_text('TARGET_ONLY=yes\\n'); "
                            "Path(gateway).write_bytes(b'target gateway'); "
                            "Path(existing).write_bytes(b'target existing\\n'); "
                            "Path(created).write_bytes(b'target created\\n'); "
                            'Path(manifest).write_bytes(b\'{"bundle_version":"0.8.5"}\\n\'); '
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

                def reinstall_bridge(
                    wheel_path: str,
                    os_name: str,
                    *,
                    exact_environment: bool,
                ) -> None:
                    self.assertEqual(wheel_path, plan.rollback_wheel_path)
                    self.assertEqual(os_name, "linux")
                    self.assertTrue(exact_environment)
                    cli_marker.write_bytes(b"bridge controller\n")

                with (
                    patch(
                        "defenseclaw.commands.cmd_upgrade._install_wheel",
                        side_effect=reinstall_bridge,
                    ),
                    patch("defenseclaw.commands.cmd_upgrade._verify_restored_bridge_artifacts"),
                    patch("defenseclaw.commands.cmd_upgrade._poll_installed_health"),
                    patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
                    patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"),
                ):
                    recovered = _recover_interrupted_hard_cut(plan.recovery_home)

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
                    "DEFENSECLAW_HOME": plan.recovery_home,
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
                    'exec("while not release.exists():\\n'
                    "    assert time.monotonic() < deadline\\n"
                    '    time.sleep(0.02)"); '
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
                        recovered.append(_recover_interrupted_hard_cut(plan.recovery_home))
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
            with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(without_wrapper, "w") as destination:
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

        def capable(
            *args,
            upgrade_handles_local_bundle=False,
            controller_owns_local_bundle_transaction=False,
        ):
            calls.append(
                (
                    args,
                    {
                        "upgrade_handles_local_bundle": upgrade_handles_local_bundle,
                        "controller_owns_local_bundle_transaction": controller_owns_local_bundle_transaction,
                    },
                )
            )
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
        execute(capable)
        execute(positional_only)
        self.assertEqual(calls[0][1], {})
        self.assertEqual(calls[1][1], {"upgrade_handles_local_bundle": True})
        self.assertEqual(
            calls[2][1],
            {
                "upgrade_handles_local_bundle": True,
                "controller_owns_local_bundle_transaction": True,
            },
        )
        self.assertEqual(calls[3][1], {"upgrade_handles_local_bundle": False})

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
            stack.enter_context(
                patch.dict(
                    os.environ,
                    {
                        "DEFENSECLAW_CONFIG": config_path,
                        "DEFENSECLAW_STAGED_UPGRADE": "1",
                        "DEFENSECLAW_STAGED_BRIDGE_VERSION": "0.8.4",
                        "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR": "/tmp/staged-bridge",
                    },
                )
            )
            stack.enter_context(patch("defenseclaw.__version__", "0.8.4"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_installed_source_coherence"))
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
                "schema_version": 2,
                "runtime_config_version": 8,
                "release_version": "0.8.5",
                "min_upgrade_protocol": 2,
                "controller_upgrade_protocol": 2,
                "migration_failure_policy": "fail",
                "required_cli_migrations": ["0.8.5"],
                "minimum_source_version": "0.8.4",
                "required_bridge_version": "0.8.4",
                "auto_bridge_from": ["0.8.3"],
                "tested_source_versions": ["0.8.4", "0.8.3"],
                "platform_tested_source_versions": {"windows": ["0.8.4", "0.8.3"]},
                "release_artifacts": _expected_release_artifacts("0.8.5"),
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
                    "defenseclaw.commands.cmd_upgrade._validate_staged_bridge_artifact_set",
                    return_value=(
                        {"bridge.dcwheel": "0" * 64},
                        "/tmp/bridge.dcwheel",
                        "/tmp/bridge.dcgateway",
                    ),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._materialize_bridge_source_wheel_for_preflight",
                    return_value="/tmp/bridge.whl",
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
    @unittest.skipIf(os.name == "nt", "POSIX managed-venv fixture")
    def test_install_wheel_uses_managed_venv_python_after_creating_venv(self):
        with (
            TemporaryDirectory() as home,
            patch.dict(
                os.environ,
                {
                    "HOME": home,
                    "DEFENSECLAW_HOME": os.path.join(home, "custom-defenseclaw"),
                    "DEFENSECLAW_OBSERVABILITY_V8_PREFLIGHT_BINDING": "stale-value",
                    "DEFENSECLAW_UPGRADE_MUTATION_TOKEN": "b" * 32,
                },
            ),
            patch("shutil.which", return_value="/usr/bin/uv"),
            patch("subprocess.run") as run_mock,
        ):
            custom_home = os.environ["DEFENSECLAW_HOME"]
            venv_python = os.path.join(custom_home, ".venv", "bin", "python")

            def side_effect(args, **_kwargs):
                if args[:3] == ["/usr/bin/uv", "--no-config", "venv"]:
                    os.makedirs(os.path.dirname(venv_python), exist_ok=True)
                    with open(venv_python, "w") as f:
                        f.write("# python")
                return Mock(returncode=0)

            run_mock.side_effect = side_effect

            _install_wheel("/tmp/defenseclaw.whl")

        pip_call = next(
            call.args[0]
            for call in run_mock.call_args_list
            if call.args[0][:4] == ["/usr/bin/uv", "--no-config", "pip", "install"]
        )
        self.assertEqual(pip_call[:5], ["/usr/bin/uv", "--no-config", "pip", "install", "--python"])
        self.assertEqual(pip_call[5], venv_python)

    @unittest.skipIf(os.name == "nt", "POSIX managed-venv fixture")
    def test_hard_cut_install_is_offline_and_never_mutates_dependencies(self):
        with (
            TemporaryDirectory() as home,
            patch.dict(os.environ, {"DEFENSECLAW_HOME": home}),
            patch("shutil.which", return_value="/usr/bin/uv"),
            patch("subprocess.run", return_value=Mock(returncode=0)) as run_mock,
        ):
            venv_python = os.path.join(home, ".venv", "bin", "python")
            os.makedirs(os.path.dirname(venv_python), exist_ok=True)
            Path(venv_python).write_text("# python\n", encoding="utf-8")
            _install_wheel(
                "/tmp/defenseclaw-0.8.5.whl",
                "linux",
                exact_environment=True,
            )

        args = next(
            call.args[0]
            for call in run_mock.call_args_list
            if call.args[0][:4] == ["/usr/bin/uv", "--no-config", "pip", "install"]
        )
        self.assertIn("--offline", args)
        self.assertIn("--no-deps", args)
        self.assertIn("--reinstall", args)
        self.assertEqual(args[-1], "/tmp/defenseclaw-0.8.5.whl")

    @staticmethod
    def _write_dependency_contract_wheel(
        path: Path,
        version: str,
        requirements: list[str],
    ) -> None:
        metadata = f"Metadata-Version: 2.4\nName: defenseclaw\nVersion: {version}\n"
        metadata += "".join(f"Requires-Dist: {requirement}\n" for requirement in requirements)
        dist_info = f"defenseclaw-{version}.dist-info"
        members = {
            "defenseclaw/__init__.py": f'__version__ = "{version}"\n',
            f"{dist_info}/METADATA": metadata,
            f"{dist_info}/WHEEL": (
                "Wheel-Version: 1.0\nGenerator: defenseclaw-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            ),
        }
        record = "".join(f"{name},,\n" for name in members)
        record += f"{dist_info}/RECORD,,\n"
        with zipfile.ZipFile(path, "w") as archive:
            for name, payload in members.items():
                archive.writestr(name, payload)
            archive.writestr(f"{dist_info}/RECORD", record)

    @unittest.skipUnless(cmd_upgrade_module.shutil.which("uv"), "uv required")
    def test_dynamic_hard_cut_contract_accepts_arbitrary_future_versions(self):
        uv = cmd_upgrade_module.shutil.which("uv") or ""
        os_name, _arch = _detect_platform()
        with TemporaryDirectory() as root:
            bridge_venv = Path(root, "bridge")
            subprocess.run(
                [uv, "--no-config", "venv", str(bridge_venv), "--python", sys.executable, "--offline", "--quiet"],
                check=True,
            )
            bridge_python = cmd_upgrade_module._venv_python_path(str(bridge_venv), os_name)
            site_packages = Path(cmd_upgrade_module._venv_site_package_directories(bridge_python)[0])
            runtime_info = site_packages / "runtime_support-3.7.0.dist-info"
            runtime_info.mkdir()
            (runtime_info / "METADATA").write_text(
                "Metadata-Version: 2.4\nName: runtime-support\nVersion: 3.7.0\n",
                encoding="utf-8",
            )
            (runtime_info / "WHEEL").write_text(
                "Wheel-Version: 1.0\nGenerator: defenseclaw-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                encoding="utf-8",
            )
            source = Path(root, "defenseclaw-0.8.4-py3-none-any.whl")
            self._write_dependency_contract_wheel(source, "0.8.4", ["runtime-support>=3"])
            for version in ("0.8.5", "0.8.6", "0.9.0", "1.0.0"):
                target = Path(root, f"defenseclaw-{version}-py3-none-any.whl")
                self._write_dependency_contract_wheel(target, version, ["runtime-support>=3.5"])
                with self.subTest(version=version):
                    _require_bridge_environment_accepts_target_wheel(
                        uv,
                        bridge_python,
                        str(source),
                        str(target),
                        os_name=os_name,
                    )

    @unittest.skipUnless(cmd_upgrade_module.shutil.which("uv"), "uv required")
    def test_dynamic_hard_cut_contract_rejects_missing_or_incompatible_requirements(self):
        uv = cmd_upgrade_module.shutil.which("uv") or ""
        os_name, _arch = _detect_platform()
        with TemporaryDirectory() as root:
            bridge_venv = Path(root, "bridge")
            subprocess.run(
                [uv, "--no-config", "venv", str(bridge_venv), "--python", sys.executable, "--offline", "--quiet"],
                check=True,
            )
            bridge_python = cmd_upgrade_module._venv_python_path(str(bridge_venv), os_name)
            site_packages = Path(cmd_upgrade_module._venv_site_package_directories(bridge_python)[0])
            runtime_info = site_packages / "runtime_support-3.7.0.dist-info"
            runtime_info.mkdir()
            (runtime_info / "METADATA").write_text(
                "Metadata-Version: 2.4\nName: runtime-support\nVersion: 3.7.0\n",
                encoding="utf-8",
            )
            (runtime_info / "WHEEL").write_text(
                "Wheel-Version: 1.0\nGenerator: defenseclaw-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                encoding="utf-8",
            )
            source = Path(root, "defenseclaw-0.8.4-py3-none-any.whl")
            self._write_dependency_contract_wheel(source, "0.8.4", ["runtime-support>=3"])
            cases = {
                "missing": ["runtime-support>=3", "future-runtime>=1"],
                "incompatible": ["runtime-support>=4"],
            }
            for name, requirements in cases.items():
                target = Path(root, f"defenseclaw-9.9.{len(requirements)}-py3-none-any.whl")
                self._write_dependency_contract_wheel(target, f"9.9.{len(requirements)}", requirements)
                with self.subTest(name=name), self.assertRaises(subprocess.CalledProcessError):
                    _require_bridge_environment_accepts_target_wheel(
                        uv,
                        bridge_python,
                        str(source),
                        str(target),
                        os_name=os_name,
                    )

    def test_distribution_metadata_copy_excludes_defenseclaw_and_rejects_duplicates(self):
        with TemporaryDirectory() as root:
            source = Path(root, "source")
            destination = Path(root, "destination")
            source.mkdir()
            destination.mkdir()

            def write_metadata(directory: str, name: str, version: str) -> None:
                info = source / directory
                info.mkdir()
                (info / "METADATA").write_text(
                    f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n",
                    encoding="utf-8",
                )
                (info / "WHEEL").write_text("Wheel-Version: 1.0\n", encoding="utf-8")

            write_metadata("defenseclaw-0.8.4.dist-info", "DefenseClaw", "0.8.4")
            write_metadata("runtime_support-3.7.dist-info", "runtime-support", "3.7")
            _copy_distribution_metadata((str(source),), str(destination))
            self.assertFalse((destination / "defenseclaw-0.8.4.dist-info").exists())
            self.assertTrue((destination / "runtime_support-3.7.dist-info/METADATA").is_file())

            write_metadata("runtime.support-3.7.dist-info", "runtime.support", "3.7")
            duplicate = Path(root, "duplicate")
            duplicate.mkdir()
            with self.assertRaisesRegex(ValueError, "duplicate packages"):
                _copy_distribution_metadata((str(source),), str(duplicate))

    def test_hard_cut_preflight_rejects_dynamic_contract_failure_before_mutation(self):
        with (
            TemporaryDirectory() as home,
            patch.dict(os.environ, {"DEFENSECLAW_HOME": home}),
            patch("shutil.which", return_value="/usr/bin/uv"),
            patch("os.path.isfile", return_value=True),
            patch("defenseclaw.commands.cmd_upgrade._preflight_target_wheel_migrations"),
            patch(
                "defenseclaw.commands.cmd_upgrade._require_bridge_environment_accepts_target_wheel",
                side_effect=ValueError("target dependency is absent"),
            ),
            patch("subprocess.run", return_value=Mock(returncode=0)) as run_mock,
        ):
            with self.assertRaises(SystemExit):
                _preflight_wheel_install(
                    "/tmp/target.whl",
                    "linux",
                    target_version="0.8.5",
                    hard_cut_source_wheel="/tmp/source.whl",
                    source_version="0.8.4",
                )

        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(run_mock.call_args.args[0][2:4], ["pip", "check"])
        self.assertEqual(
            run_mock.call_args.kwargs["timeout"],
            cmd_upgrade_module._DEPENDENCY_PREFLIGHT_TIMEOUT_SECONDS,
        )

    def test_hard_cut_preflight_reports_dynamic_contract_timeout(self):
        with (
            TemporaryDirectory() as home,
            patch.dict(os.environ, {"DEFENSECLAW_HOME": home}),
            patch("shutil.which", return_value="/usr/bin/uv"),
            patch("os.path.isfile", return_value=True),
            patch("defenseclaw.commands.cmd_upgrade._preflight_target_wheel_migrations"),
            patch(
                "defenseclaw.commands.cmd_upgrade._require_bridge_environment_accepts_target_wheel",
                side_effect=subprocess.TimeoutExpired(["bridge-python", "-I", "-B"], 10),
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade._fail_wheel_preflight",
                side_effect=SystemExit(1),
            ) as fail_mock,
            patch("subprocess.run", return_value=Mock(returncode=0)) as run_mock,
        ):
            with self.assertRaises(SystemExit):
                _preflight_wheel_install(
                    "/tmp/target.whl",
                    "linux",
                    target_version="0.8.5",
                    hard_cut_source_wheel="/tmp/source.whl",
                    source_version="0.8.4",
                )

        fail_mock.assert_called_once_with(
            "Hard-cut target cannot preserve the authenticated bridge dependency environment.",
            None,
        )
        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(
            run_mock.call_args.kwargs["timeout"],
            cmd_upgrade_module._DEPENDENCY_PREFLIGHT_TIMEOUT_SECONDS,
        )

    def test_restored_bridge_verifies_exact_package_metadata(self):
        with TemporaryDirectory() as root:
            wheel = Path(root, "bridge.whl")
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    "defenseclaw-0.8.4.dist-info/METADATA",
                    "Metadata-Version: 2.4\nName: defenseclaw\nVersion: 0.8.4\nRequires-Dist: requests>=2.32\n",
                )
            gateway = Path(root, "defenseclaw-gateway")
            gateway.write_bytes(b"gateway")
            venv_python = Path(root, "venv/bin/python")
            venv_python.parent.mkdir(parents=True)
            venv_python.write_bytes(b"python")
            plan = Mock(
                active_gateway_path=str(gateway),
                source_version="0.8.4",
                rollback_wheel_path=str(wheel),
                os_name="linux",
            )
            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade._managed_venv_path",
                    return_value=str(Path(root, "venv")),
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    side_effect=[
                        Mock(returncode=0, stdout="defenseclaw-gateway version 0.8.4\n", stderr=""),
                        Mock(
                            returncode=0,
                            stdout=json.dumps(
                                {
                                    "version": "0.8.4",
                                    "requires_dist": ["requests>=2.32"],
                                }
                            ),
                            stderr="",
                        ),
                    ],
                ),
            ):
                _verify_restored_bridge_artifacts(plan)

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
        for call in run_mock.call_args_list:
            self.assertEqual(
                call.kwargs["timeout"],
                cmd_upgrade_module._DEPENDENCY_PREFLIGHT_TIMEOUT_SECONDS,
            )

    def test_preflight_wheel_install_fails_closed_on_resolver_timeout(self):
        with (
            TemporaryDirectory() as home,
            patch.dict(os.environ, {"DEFENSECLAW_HOME": home}),
            patch("shutil.which", return_value="/usr/bin/uv"),
            patch(
                "defenseclaw.commands.cmd_upgrade._fail_wheel_preflight",
                side_effect=SystemExit(1),
            ) as fail_mock,
            patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(["uv", "pip", "install"], 120),
            ),
        ):
            venv_python = os.path.join(home, ".venv", "bin", "python")
            os.makedirs(os.path.dirname(venv_python), exist_ok=True)
            Path(venv_python).write_text("# python", encoding="utf-8")
            with self.assertRaises(SystemExit):
                _preflight_wheel_install("/tmp/defenseclaw.whl", "linux")

        fail_mock.assert_called_once_with(
            "Python CLI wheel dependencies are unsatisfiable.",
            None,
        )

    def test_preflight_wheel_install_fails_closed_on_venv_timeout(self):
        with (
            TemporaryDirectory() as home,
            patch.dict(os.environ, {"HOME": home}),
            patch("shutil.which", return_value="/usr/bin/uv"),
            patch(
                "defenseclaw.commands.cmd_upgrade._fail_wheel_preflight",
                side_effect=SystemExit(1),
            ) as fail_mock,
            patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(["uv", "venv"], 120),
            ),
        ):
            with self.assertRaises(SystemExit):
                _preflight_wheel_install("/tmp/defenseclaw.whl", "linux")

        fail_mock.assert_called_once_with(
            "Could not create Python CLI preflight environment.",
            None,
        )

    def test_run_installed_migrations_uses_managed_venv_python(self):
        with (
            TemporaryDirectory() as home,
            patch.dict(
                os.environ,
                {
                    "HOME": home,
                    "DEFENSECLAW_HOME": os.path.join(home, "custom-defenseclaw"),
                },
            ),
            patch("subprocess.run") as run_mock,
        ):
            venv_python = os.path.join(
                os.environ["DEFENSECLAW_HOME"],
                ".venv",
                "bin",
                "python",
            )
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
        self.assertEqual(call[1:4], ["-I", "-B", "-c"])
        self.assertIn("inspect.signature(run_migrations).parameters", call[4])
        self.assertIn('kwargs["upgrade_handles_local_bundle"] = True', call[4])
        self.assertIn('kwargs["controller_owns_local_bundle_transaction"] = True', call[4])
        self.assertNotIn("upgrade_handles_local_bundle=True", call[4])
        self.assertEqual(call[5:9], ["0.7.0", "0.8.0", "/tmp/openclaw", "/tmp/defenseclaw"])
        child_environment = run_mock.call_args.kwargs["env"]
        self.assertNotIn(
            "DEFENSECLAW_OBSERVABILITY_V8_PREFLIGHT_BINDING",
            child_environment,
        )
        self.assertNotIn("DEFENSECLAW_UPGRADE_MUTATION_TOKEN", child_environment)

    def test_run_installed_migrations_binds_hard_cut_token_and_preflight(self):
        binding = ObservabilityV8PreflightBinding(
            source_sha256="1" * 64,
            candidate_sha256="2" * 64,
            environment_file_present=True,
            environment_file_sha256="3" * 64,
            environment_dependencies_sha256="4" * 64,
            environment_edits_sha256="5" * 64,
        )
        with (
            TemporaryDirectory() as home,
            patch.dict(
                os.environ,
                {
                    "HOME": home,
                    "DEFENSECLAW_HOME": os.path.join(home, "custom-defenseclaw"),
                    "DEFENSECLAW_OBSERVABILITY_V8_PREFLIGHT_BINDING": "stale-value",
                },
                clear=True,
            ),
            patch("subprocess.run") as run_mock,
        ):
            venv_python = os.path.join(
                os.environ["DEFENSECLAW_HOME"],
                ".venv",
                "bin",
                "python",
            )
            os.makedirs(os.path.dirname(venv_python), exist_ok=True)
            Path(venv_python).write_text("# python", encoding="utf-8")

            def run_child(args, **_kwargs):
                Path(args[-1]).write_text(
                    json.dumps({"count": 1}),
                    encoding="utf-8",
                )
                return Mock(returncode=0)

            run_mock.side_effect = run_child
            count = _run_installed_migrations(
                "0.8.4",
                "0.8.5",
                "/tmp/openclaw",
                "/tmp/defenseclaw",
                os_name="darwin",
                mutation_token="a" * 32,
                observability_v8_preflight_binding=binding,
            )

        self.assertEqual(count, 1)
        child_environment = run_mock.call_args.kwargs["env"]
        self.assertEqual(
            child_environment["DEFENSECLAW_UPGRADE_MUTATION_TOKEN"],
            "a" * 32,
        )
        self.assertEqual(
            json.loads(child_environment["DEFENSECLAW_OBSERVABILITY_V8_PREFLIGHT_BINDING"]),
            binding.to_payload(),
        )

    def test_run_installed_migrations_rejects_unpaired_hard_cut_authority(self):
        binding = ObservabilityV8PreflightBinding(
            source_sha256="1" * 64,
            candidate_sha256="2" * 64,
            environment_file_present=False,
            environment_file_sha256="3" * 64,
            environment_dependencies_sha256="4" * 64,
            environment_edits_sha256="5" * 64,
        )
        with self.assertRaises(ValueError):
            _run_installed_migrations(
                "0.8.4",
                "0.8.5",
                "/tmp/openclaw",
                "/tmp/defenseclaw",
                observability_v8_preflight_binding=binding,
            )
        with self.assertRaises(ValueError):
            _run_installed_migrations(
                "0.8.4",
                "0.8.5",
                "/tmp/openclaw",
                "/tmp/defenseclaw",
                mutation_token="a" * 32,
            )

    def test_bundle_child_uses_custom_home_isolated_python_and_sanitized_environment(self):
        with TemporaryDirectory() as home:
            custom_home = os.path.join(home, "custom-defenseclaw")
            venv_python = os.path.join(custom_home, ".venv", "bin", "python")
            os.makedirs(os.path.dirname(venv_python), exist_ok=True)
            Path(venv_python).write_text("# python", encoding="utf-8")

            def run_child(args, **_kwargs):
                Path(args[-1]).write_text(
                    json.dumps({"ok": True, "result": {"installed": True}}),
                    encoding="utf-8",
                )
                return Mock(returncode=0)

            with (
                patch.dict(
                    os.environ,
                    {
                        "HOME": home,
                        "DEFENSECLAW_HOME": custom_home,
                        "PYTHONHOME": "/poisoned/home",
                        "PYTHONPATH": "/poisoned/path",
                        "BUNDLE_TEST_PRESERVED": "yes",
                    },
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_phase_two_mutator",
                    side_effect=run_child,
                ) as run_mock,
            ):
                result = _run_installed_local_observability_operation(
                    "refresh",
                    custom_home,
                    os.path.join(home, "backup"),
                    "0.8.5",
                    receipt_path=os.path.join(home, "receipt.json"),
                    os_name="linux",
                )

        self.assertTrue(result["installed"])
        argv = run_mock.call_args.args[0]
        self.assertEqual(argv[:4], [venv_python, "-I", "-B", "-c"])
        child_env = run_mock.call_args.kwargs["env"]
        self.assertNotIn("PYTHONHOME", child_env)
        self.assertNotIn("PYTHONPATH", child_env)
        self.assertEqual(child_env["BUNDLE_TEST_PRESERVED"], "yes")


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
            with (
                self.subTest(base=base),
                patch.dict(
                    os.environ,
                    {
                        "DEFENSECLAW_UPGRADE_TEST_MODE": "1",
                        "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL": base,
                    },
                ),
                self.assertRaises(SystemExit),
            ):
                _release_download_base()

    def test_preflight_uses_gated_loopback_base_for_candidate_assets(self):
        response = Mock(status_code=200)
        with (
            patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_UPGRADE_TEST_MODE": "1",
                    "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL": ("http://127.0.0.1:8765/releases/download"),
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
        self.assertTrue(all(call.kwargs["allow_redirects"] is False for call in head.call_args_list))

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
                    "DEFENSECLAW_HOME": os.path.join(home, "custom-defenseclaw"),
                    "DEFENSECLAW_UPGRADE_FRESH_PROCESS": "",
                    "DEFENSECLAW_UPGRADE_TEST_MODE": "1",
                    "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL": ("http://127.0.0.1:8765/releases/download"),
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
        expected_python = os.path.join(
            home,
            "custom-defenseclaw",
            ".venv",
            "bin",
            "python",
        )
        self.assertEqual(
            run_mock.call_args.args[0],
            [
                expected_python,
                "-I",
                "-B",
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
    def test_same_version_bundle_mismatch_requires_reconciliation(self):
        with patch(
            "defenseclaw.bundle_refresh.installed_local_observability_bundle_version",
            side_effect=[None, "9.9.9", "9.9.8", ""],
        ):
            self.assertFalse(
                cmd_upgrade_module._installed_local_observability_bundle_needs_reconciliation(
                    "/tmp/data",
                    "9.9.9",
                )
            )
            self.assertFalse(
                cmd_upgrade_module._installed_local_observability_bundle_needs_reconciliation(
                    "/tmp/data",
                    "9.9.9",
                )
            )
            self.assertTrue(
                cmd_upgrade_module._installed_local_observability_bundle_needs_reconciliation(
                    "/tmp/data",
                    "9.9.9",
                )
            )
            self.assertTrue(
                cmd_upgrade_module._installed_local_observability_bundle_needs_reconciliation(
                    "/tmp/data",
                    "9.9.9",
                )
            )

    def test_same_version_is_authenticated_noop(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "9.9.9"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_installed_source_coherence"))
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
            install_gateway = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_gateway"))
            install_wheel = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_wheel"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._verify_installed_gateway_version"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._check_post_upgrade_drift"))
            create_backup = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._create_backup",
                    return_value="/tmp/backup",
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"))
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
            recover_interrupted = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._recover_interrupted_same_version_upgrade")
            )
            result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)

            receipts = list((Path(data_dir) / UPGRADE_RECEIPT_DIRECTORY).glob("*.json"))
            self.assertEqual(receipts, [])
            self.assertFalse((Path(data_dir) / UPGRADE_RECEIPT_DIRECTORY).exists())
            recover_interrupted.assert_not_called()

            installed = begin_upgrade_receipt(
                data_dir,
                from_version="0.8.4",
                target_version="9.9.9",
                artifacts_verified=True,
            )
            cmd_upgrade_module.complete_upgrade_receipt(installed, status="succeeded")
            with patch(
                "defenseclaw.commands.cmd_upgrade._installed_local_observability_bundle_needs_reconciliation",
                return_value=True,
            ):
                installed_reconciliation_result = runner.invoke(
                    upgrade,
                    ["--yes", "--version", "9.9.9"],
                    obj=app,
                )
            recover_interrupted.assert_called_once()
            installed_recovery_receipt = recover_interrupted.call_args.kwargs["receipt_path"]
            installed_recovery = load_upgrade_receipt(installed_recovery_receipt)
            self.assertEqual(installed_recovery.from_version, "9.9.9")
            self.assertEqual(installed_recovery.target_version, "9.9.9")
            installed_recovery_receipt.unlink()
            recover_interrupted.reset_mock()

            pending = begin_upgrade_receipt(
                data_dir,
                from_version="9.9.8",
                target_version="9.9.9",
                artifacts_verified=True,
            )
            recovery_result = runner.invoke(
                upgrade,
                ["--yes", "--version", "9.9.9"],
                obj=app,
            )
            recover_interrupted.assert_called_once()
            self.assertEqual(
                recover_interrupted.call_args.kwargs["receipt_path"],
                pending,
            )

            record_local_bundle_restart_intent(pending, restart_required=True)
            cmd_upgrade_module.complete_upgrade_receipt(
                pending,
                status="failed",
                failure_code="local_observability_failed",
            )
            recover_interrupted.reset_mock()
            terminal_recovery_result = runner.invoke(
                upgrade,
                ["--yes", "--version", "9.9.9"],
                obj=app,
            )
            recover_interrupted.assert_called_once()
            terminal_recovery_receipt = recover_interrupted.call_args.kwargs["receipt_path"]
            self.assertNotEqual(terminal_recovery_receipt, pending)
            replacement = load_upgrade_receipt(terminal_recovery_receipt)
            self.assertEqual(replacement.status, "pending")
            self.assertEqual(replacement.from_version, "9.9.8")
            self.assertIs(load_local_bundle_restart_intent(terminal_recovery_receipt), True)

            recover_interrupted.reset_mock()
            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade.find_resumable_upgrade_receipt",
                    return_value=None,
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.find_verified_installed_upgrade_receipt",
                    return_value=None,
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade._installed_local_observability_bundle_needs_reconciliation",
                    return_value=True,
                ),
            ):
                unproven_bundle_result = runner.invoke(
                    upgrade,
                    ["--yes", "--version", "9.9.9"],
                    obj=app,
                )
            recover_interrupted.assert_not_called()

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Version Already Verified", result.output)
        self.assertIn("No backup, receipt, service stop", result.output)
        create_backup.assert_not_called()
        install_gateway.assert_not_called()
        install_wheel.assert_not_called()
        run_migrations.assert_not_called()
        self.assertEqual(
            installed_reconciliation_result.exit_code,
            0,
            msg=installed_reconciliation_result.output,
        )
        self.assertEqual(recovery_result.exit_code, 0, msg=recovery_result.output)
        self.assertIn("Found an incomplete target transaction", recovery_result.output)
        self.assertEqual(
            terminal_recovery_result.exit_code,
            0,
            msg=terminal_recovery_result.output,
        )
        self.assertEqual(unproven_bundle_result.exit_code, 1)
        self.assertIn("no verified target-install receipt exists", unproven_bundle_result.output)

    def test_interrupted_same_version_bundle_recovery_is_retryable(self):
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            Path(data_dir, "observability-stack").mkdir()
            receipt_path = begin_upgrade_receipt(
                data_dir,
                from_version="9.9.8",
                target_version="9.9.9",
                artifacts_verified=True,
            )
            cmd_upgrade_module.record_upgrade_migrations(
                receipt_path,
                migration_count=1,
                degraded=False,
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._create_backup",
                    return_value=os.path.join(data_dir, "backup"),
                )
            )
            refresh = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_installed_local_observability_bundle_upgrade",
                    side_effect=[
                        _LocalBundleUpgradeInvocationError("child_failed", "refresh"),
                        {"installed": True, "restart_required": False},
                    ],
                )
            )
            start = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._start_and_verify_services"))
            required = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._assert_required_cli_migrations"))
            run_migrations = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_installed_migrations"))

            with self.assertRaises(SystemExit):
                cmd_upgrade_module._recover_interrupted_same_version_upgrade(
                    app,
                    receipt_path=receipt_path,
                    data_dir=data_dir,
                    target_version="9.9.9",
                    os_name="darwin",
                    health_timeout=60,
                    config_path=os.path.join(data_dir, "config.yaml"),
                    recovery_home=data_dir,
                    upgrade_manifest={"required_cli_migrations": ["9.9.9"]},
                )
            self.assertEqual(load_upgrade_receipt(receipt_path).status, "pending")

            cmd_upgrade_module._recover_interrupted_same_version_upgrade(
                app,
                receipt_path=receipt_path,
                data_dir=data_dir,
                target_version="9.9.9",
                os_name="darwin",
                health_timeout=60,
                config_path=os.path.join(data_dir, "config.yaml"),
                recovery_home=data_dir,
                upgrade_manifest={"required_cli_migrations": ["9.9.9"]},
            )

            self.assertEqual(load_upgrade_receipt(receipt_path).status, "succeeded")
            self.assertEqual(
                list((Path(data_dir) / UPGRADE_RECEIPT_DIRECTORY).glob("*.json")),
                [receipt_path],
            )
            self.assertEqual(refresh.call_count, 2)
            run_migrations.assert_not_called()
            required.assert_called()
            start.assert_called_once()
            self.assertTrue(start.call_args.kwargs["strict_local_observability"])
            self.assertEqual(start.call_args.kwargs["expected_version"], "9.9.9")

    def test_terminal_restart_custody_is_superseded_before_replacement_success(self):
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            Path(data_dir, "observability-stack").mkdir()
            superseded = begin_upgrade_receipt(
                data_dir,
                from_version="9.9.8",
                target_version="9.9.9",
                artifacts_verified=True,
            )
            record_local_bundle_restart_intent(superseded, restart_required=True)
            cmd_upgrade_module.complete_upgrade_receipt(
                superseded,
                status="failed",
                failure_code="local_observability_failed",
            )
            replacement = begin_upgrade_receipt(
                data_dir,
                from_version="9.9.8",
                target_version="9.9.9",
                artifacts_verified=True,
            )
            cmd_upgrade_module.record_upgrade_migrations(
                replacement,
                migration_count=0,
                degraded=False,
            )
            record_local_bundle_restart_intent(replacement, restart_required=True)

            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._create_backup",
                    return_value=os.path.join(data_dir, "backup"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._assert_required_cli_migrations"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_installed_local_observability_bundle_upgrade",
                    return_value={
                        "installed": True,
                        "restart_required": True,
                        "_restart_intent_receipt": str(replacement),
                    },
                )
            )
            start_attempts = 0

            def start_then_recover(*_args, **_kwargs):
                nonlocal start_attempts
                start_attempts += 1
                if start_attempts == 1:
                    raise SystemExit(1)
                clear_local_bundle_restart_intent(replacement)

            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._start_and_verify_services",
                    side_effect=start_then_recover,
                )
            )
            original_complete = cmd_upgrade_module.complete_upgrade_receipt

            def complete_after_old_custody_is_superseded(path, **kwargs):
                marker = load_upgrade_receipt_supersession(superseded)
                self.assertIsNotNone(marker)
                self.assertTrue(marker.health_proven)
                self.assertEqual(
                    marker.superseded_by_receipt_id,
                    load_upgrade_receipt(replacement).receipt_id,
                )
                self.assertIs(load_local_bundle_restart_intent(superseded), True)
                return original_complete(path, **kwargs)

            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade.complete_upgrade_receipt",
                    side_effect=complete_after_old_custody_is_superseded,
                )
            )

            with self.assertRaises(SystemExit):
                cmd_upgrade_module._recover_interrupted_same_version_upgrade(
                    app,
                    receipt_path=replacement,
                    data_dir=data_dir,
                    target_version="9.9.9",
                    os_name="darwin",
                    health_timeout=60,
                    config_path=os.path.join(data_dir, "config.yaml"),
                    recovery_home=data_dir,
                    upgrade_manifest={"required_cli_migrations": ["9.9.9"]},
                )
            self.assertEqual(load_upgrade_receipt(replacement).status, "pending")
            self.assertIs(load_local_bundle_restart_intent(superseded), True)

            cmd_upgrade_module._recover_interrupted_same_version_upgrade(
                app,
                receipt_path=replacement,
                data_dir=data_dir,
                target_version="9.9.9",
                os_name="darwin",
                health_timeout=60,
                config_path=os.path.join(data_dir, "config.yaml"),
                recovery_home=data_dir,
                upgrade_manifest={"required_cli_migrations": ["9.9.9"]},
            )

            self.assertEqual(load_upgrade_receipt(replacement).status, "succeeded")
            self.assertIsNone(load_local_bundle_restart_intent(replacement))
            replacement.unlink()
            self.assertIsNone(
                cmd_upgrade_module.find_resumable_upgrade_receipt(
                    data_dir,
                    target_version="9.9.9",
                )
            )

    def test_same_version_recovery_rejects_pre_v8_bridge_receipt(self):
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            receipt_path = begin_upgrade_receipt(
                data_dir,
                from_version="0.8.4",
                target_version="9.9.9",
                artifacts_verified=True,
            )
            with (
                patch("defenseclaw.commands.cmd_upgrade._create_backup") as backup,
                self.assertRaises(SystemExit),
            ):
                cmd_upgrade_module._recover_interrupted_same_version_upgrade(
                    app,
                    receipt_path=receipt_path,
                    data_dir=data_dir,
                    target_version="9.9.9",
                    os_name="linux",
                    health_timeout=60,
                    config_path=os.path.join(data_dir, "config.yaml"),
                    recovery_home=data_dir,
                    upgrade_manifest={"required_cli_migrations": ["0.8.5"]},
                )

            backup.assert_not_called()
            self.assertEqual(load_upgrade_receipt(receipt_path).status, "pending")

    def test_interrupted_same_version_replays_pending_migrations_before_health(self):
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            receipt_path = begin_upgrade_receipt(
                data_dir,
                from_version="9.9.8",
                target_version="9.9.9",
                artifacts_verified=True,
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._create_backup",
                    return_value=os.path.join(data_dir, "backup"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True))
            quiesced = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"))
            run_migrations = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_installed_migrations",
                    return_value=2,
                )
            )
            required = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._assert_required_cli_migrations"))
            start = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._start_and_verify_services"))

            cmd_upgrade_module._recover_interrupted_same_version_upgrade(
                app,
                receipt_path=receipt_path,
                data_dir=data_dir,
                target_version="9.9.9",
                os_name="linux",
                health_timeout=60,
                config_path=os.path.join(data_dir, "config.yaml"),
                recovery_home=data_dir,
                upgrade_manifest={"required_cli_migrations": ["9.9.9"]},
            )

            receipt = load_upgrade_receipt(receipt_path)
            self.assertEqual(receipt.status, "succeeded")
            self.assertEqual(receipt.migration_status, "completed")
            self.assertEqual(receipt.migration_count, 2)
            run_migrations.assert_called_once()
            self.assertEqual(run_migrations.call_args.args[:2], ("9.9.8", "9.9.9"))
            quiesced.assert_called_once()
            required.assert_called_once()
            start.assert_called_once()
            self.assertIsNone(start.call_args.kwargs["local_bundle_upgrade"])

            degraded_path = begin_upgrade_receipt(
                data_dir,
                from_version="9.9.8",
                target_version="9.9.9",
                artifacts_verified=True,
            )
            cmd_upgrade_module.record_upgrade_migrations(
                degraded_path,
                migration_count=0,
                degraded=True,
            )
            run_migrations.reset_mock()
            required.reset_mock()
            start.reset_mock()
            cmd_upgrade_module._recover_interrupted_same_version_upgrade(
                app,
                receipt_path=degraded_path,
                data_dir=data_dir,
                target_version="9.9.9",
                os_name="linux",
                health_timeout=60,
                config_path=os.path.join(data_dir, "config.yaml"),
                recovery_home=data_dir,
                upgrade_manifest={"required_cli_migrations": ["9.9.9"]},
            )
            degraded = load_upgrade_receipt(degraded_path)
            self.assertEqual(degraded.status, "succeeded")
            self.assertEqual(degraded.migration_status, "completed")
            run_migrations.assert_called_once()
            required.assert_called_once()
            start.assert_called_once()

    def test_required_migration_assertion_failure_keeps_recovery_retryable(self):
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            receipt_path = begin_upgrade_receipt(
                data_dir,
                from_version="9.9.8",
                target_version="9.9.9",
                artifacts_verified=True,
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._create_backup",
                    return_value=os.path.join(data_dir, "backup"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"))
            run_migrations = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_installed_migrations",
                    return_value=1,
                )
            )
            required = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._assert_required_cli_migrations",
                    side_effect=[SystemExit(1), None],
                )
            )
            start = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._start_and_verify_services"))

            with self.assertRaises(SystemExit):
                cmd_upgrade_module._recover_interrupted_same_version_upgrade(
                    app,
                    receipt_path=receipt_path,
                    data_dir=data_dir,
                    target_version="9.9.9",
                    os_name="linux",
                    health_timeout=60,
                    config_path=os.path.join(data_dir, "config.yaml"),
                    recovery_home=data_dir,
                    upgrade_manifest={
                        "migration_failure_policy": "fail",
                        "required_cli_migrations": ["9.9.9"],
                    },
                )

            failed_attempt = load_upgrade_receipt(receipt_path)
            self.assertEqual(failed_attempt.status, "pending")
            self.assertEqual(failed_attempt.migration_status, "degraded")
            start.assert_not_called()

            cmd_upgrade_module._recover_interrupted_same_version_upgrade(
                app,
                receipt_path=receipt_path,
                data_dir=data_dir,
                target_version="9.9.9",
                os_name="linux",
                health_timeout=60,
                config_path=os.path.join(data_dir, "config.yaml"),
                recovery_home=data_dir,
                upgrade_manifest={
                    "migration_failure_policy": "fail",
                    "required_cli_migrations": ["9.9.9"],
                },
            )

            recovered = load_upgrade_receipt(receipt_path)
            self.assertEqual(recovered.status, "succeeded")
            self.assertEqual(recovered.migration_status, "completed")
            self.assertEqual(run_migrations.call_count, 2)
            self.assertEqual(required.call_count, 2)
            start.assert_called_once()

    @unittest.skipIf(os.name == "nt", "Darwin upgrade orchestration fixture")
    def test_required_migration_failure_leaves_target_services_stopped(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            backup_dir = os.path.join(data_dir, "backups", "upgrade")
            stack.enter_context(patch("defenseclaw.__version__", "9.9.8"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_installed_source_coherence"))
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
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"))
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
        self.assertEqual(
            run_silent.call_args.args[0],
            [os.path.expanduser("~/.local/bin/defenseclaw-gateway"), "stop"],
        )
        poll_health.assert_not_called()

    @unittest.skipIf(os.name == "nt", "Darwin upgrade orchestration fixture")
    def test_upgrade_preflights_wheel_before_gateway_install(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()
        events: list[str] = []

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "9.9.8"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_installed_source_coherence"))
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
                    side_effect=lambda *_args, **_kwargs: events.append("wheel"),
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
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"))
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
        preflight_binding_side_effect=None,
        recovery_journal_removal_side_effect=None,
        unset_config_data_dir: bool = False,
        controller_home_override: bool = False,
        installed_local_bundle: bool = False,
        bundle_refresh_side_effect=None,
    ):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            home = stack.enter_context(TemporaryDirectory())
            app.cfg.data_dir = "" if unset_config_data_dir else data_dir
            app.cfg.claw.home_dir = data_dir
            recovery_home = (
                data_dir
                if controller_home_override
                else os.path.join(
                    home,
                    ".defenseclaw",
                )
            )
            environment = {
                "HOME": home,
                "DEFENSECLAW_CONFIG": "",
                "DEFENSECLAW_HOME": recovery_home if controller_home_override else "",
                "DEFENSECLAW_STAGED_UPGRADE": "1",
                "DEFENSECLAW_STAGED_BRIDGE_VERSION": "9.9.8",
                "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR": "/tmp/staged-bridge-artifacts",
            }
            selected_data_dir = data_dir if not unset_config_data_dir else recovery_home
            if installed_local_bundle:
                os.makedirs(
                    os.path.join(selected_data_dir, "observability-stack"),
                    exist_ok=True,
                )
            self.invocation_data_dir = selected_data_dir
            self.invocation_recovery_home = recovery_home
            stack.enter_context(patch.dict(os.environ, environment))
            stack.enter_context(patch("defenseclaw.__version__", "9.9.8"))
            self.preflight_source = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._preflight_installed_source_coherence")
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("darwin", "arm64"),
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._require_hard_cut_manifest_contract"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._require_release_owned_hard_cut_handoff"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._acquire_bridge_rollback_artifacts",
                    return_value="/tmp/staged-bridge-artifacts",
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._validate_staged_bridge_artifact_set",
                    return_value=(
                        {"bridge.dcwheel": "0" * 64},
                        "/tmp/staged-bridge-artifacts/bridge.dcwheel",
                        "/tmp/staged-bridge-artifacts/gateway.dcgateway",
                    ),
                )
            )
            self.materialize_bridge_source = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._materialize_bridge_source_wheel_for_preflight",
                    return_value="/tmp/staged-bridge-artifacts/bridge.whl",
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"))
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
            self.read_migration_preflight = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._read_hard_cut_observability_preflight_binding",
                    return_value=None,
                    side_effect=preflight_binding_side_effect,
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._install_gateway",
                    return_value="/tmp/installed-defenseclaw-gateway",
                    side_effect=install_side_effect,
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_wheel"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._verify_installed_gateway_version"))
            self.create_backup = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._create_backup",
                    return_value=os.path.join(selected_data_dir, "backups", "upgrade"),
                )
            )
            self.run_installed_migrations = stack.enter_context(
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
            self.local_bundle_refresh = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_installed_local_observability_bundle_upgrade",
                    return_value={
                        "installed": True,
                        "refreshed": True,
                        "restart_required": False,
                        "changed_paths": ["docker-compose.yml"],
                    },
                    side_effect=bundle_refresh_side_effect,
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._check_post_upgrade_drift"))
            self.prepare_rollback = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._prepare_hard_cut_rollback_plan",
                    return_value=rollback_plan,
                )
            )
            self.require_stable_preflight_source = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._require_hard_cut_preflight_state_unchanged")
            )
            self.write_recovery_journal = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._write_hard_cut_recovery_journal",
                    return_value=Path(recovery_home) / ".upgrade-recovery/phase-two-active.json",
                )
            )
            self.hold_recovery_lease = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._hold_phase_two_lease_for_command_lifetime")
            )
            self.remove_recovery_journal = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._remove_hard_cut_recovery_journal",
                    side_effect=recovery_journal_removal_side_effect,
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

            def run_silent(args, *_messages, **_kwargs):
                if rollback_plan is not None:
                    self.write_recovery_journal.assert_called_once()
                if (
                    len(args) == 2
                    and args[1] == "start"
                    and (args[0] == "defenseclaw-gateway" or rollback_plan is not None)
                ):
                    return gateway_start_ok
                return True

            self.run_silent = stack.enter_context(
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
            receipt_paths = list((Path(selected_data_dir) / UPGRADE_RECEIPT_DIRECTORY).glob("*.json"))
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

    def test_verified_receipt_precedes_target_migrations_and_bundle_refresh(self):
        observed_receipts: list[Path] = []

        def assert_receipt_before_migration(*args, **_kwargs):
            data_dir = args[3]
            receipt_paths = list((Path(data_dir) / UPGRADE_RECEIPT_DIRECTORY).glob("*.json"))
            self.assertEqual(len(receipt_paths), 1)
            receipt = load_upgrade_receipt(receipt_paths[0])
            self.assertEqual(receipt.status, "pending")
            self.assertTrue(receipt.artifacts_verified)
            self.assertEqual(receipt.from_version, "9.9.8")
            self.assertEqual(receipt.target_version, "9.9.9")
            observed_receipts.append(receipt_paths[0])
            return 0

        result, receipt, _poll_health = self._invoke_upgrade(
            installed_local_bundle=True,
            migration_side_effect=assert_receipt_before_migration,
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(receipt.status, "succeeded")
        self.assertEqual(len(observed_receipts), 1)
        self.assertEqual(
            self.local_bundle_refresh.call_args.kwargs["receipt_path"],
            observed_receipts[0],
        )

    def test_normal_future_upgrade_refreshes_installed_bundle_without_rollback_plan(self):
        result, receipt, poll_health = self._invoke_upgrade(
            installed_local_bundle=True,
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(receipt.status, "succeeded")
        self.local_bundle_refresh.assert_called_once()
        call = self.local_bundle_refresh.call_args
        self.assertEqual(call.args[0], self.invocation_data_dir)
        self.assertEqual(call.args[2], "9.9.9")
        poll_health.assert_called_once()

    def test_normal_future_bundle_refresh_failure_prevents_target_restart(self):
        result, receipt, poll_health = self._invoke_upgrade(
            installed_local_bundle=True,
            bundle_refresh_side_effect=_LocalBundleUpgradeInvocationError(
                "activation_failed",
                "activate",
            ),
        )

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertEqual(receipt.status, "failed")
        self.assertIn("Local observability bundle refresh failed", result.output)
        poll_health.assert_not_called()
        gateway_starts = [
            call for call in self.run_silent.call_args_list if len(call.args[0]) == 2 and call.args[0][1] == "start"
        ]
        self.assertEqual(gateway_starts, [])

    def test_unset_config_data_dir_reuses_controller_override_for_all_phases(self):
        result, receipt, _poll_health = self._invoke_upgrade(
            unset_config_data_dir=True,
            controller_home_override=True,
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        selected = self.invocation_data_dir
        recovery_home = self.invocation_recovery_home
        self.assertEqual(selected, recovery_home)
        config_path = os.path.join(recovery_home, "config.yaml")
        self.preflight_source.assert_called_once_with(
            "9.9.8",
            "darwin",
            selected,
            config_path=config_path,
        )
        self.assertEqual(self.create_backup.call_args.kwargs["data_dir"], selected)
        migration_call = self.run_installed_migrations.call_args
        self.assertEqual(migration_call.args[3], selected)
        self.assertEqual(migration_call.kwargs["config_path"], config_path)
        self.assertEqual(migration_call.kwargs["recovery_home"], recovery_home)
        self.assert_required_migrations.assert_called_once_with(None, selected)
        gateway_environments = [call.kwargs["env"] for call in self.run_silent.call_args_list if "env" in call.kwargs]
        self.assertTrue(gateway_environments)
        self.assertTrue(all(environment["DEFENSECLAW_HOME"] == selected for environment in gateway_environments))
        self.assertEqual(receipt.status, "succeeded")

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

    def test_final_full_preflight_rejects_metadata_drift_before_service_stop(self):
        manifest = {
            "minimum_source_version": "9.9.8",
            "required_bridge_version": "9.9.8",
            "auto_bridge_from": ["9.9.7"],
        }
        plan = Mock(name="rollback-plan")
        result, receipt, poll_health = self._invoke_upgrade(
            upgrade_manifest=manifest,
            rollback_plan=plan,
            preflight_binding_side_effect=(
                None,
                None,
                OSError("fixture parent metadata changed after rollback capture"),
            ),
        )

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertEqual(self.read_migration_preflight.call_count, 3)
        self.write_recovery_journal.assert_called_once()
        self.remove_recovery_journal.assert_called_once()
        self.require_stable_preflight_source.assert_called_once()
        self.run_silent.assert_not_called()
        self.execute_rollback.assert_not_called()
        poll_health.assert_not_called()
        self.assertEqual(receipt.status, "failed")
        self.assertEqual(receipt.failure_code, "install_failed")
        self.assertIn("refusing to stop services", result.output)
        self.assertIn("No service stop, artifact install, or migration", result.output)
        self.assertNotIn("Stopping Services", result.output)

    def test_final_preflight_refusal_survives_recovery_journal_cleanup_failure(self):
        manifest = {
            "minimum_source_version": "9.9.8",
            "required_bridge_version": "9.9.8",
            "auto_bridge_from": ["9.9.7"],
        }
        plan = Mock(name="rollback-plan")
        result, receipt, poll_health = self._invoke_upgrade(
            upgrade_manifest=manifest,
            rollback_plan=plan,
            preflight_binding_side_effect=(
                None,
                None,
                OSError("fixture parent metadata changed after rollback capture"),
            ),
            recovery_journal_removal_side_effect=OSError("journal directory fsync failed"),
        )

        final_preflight_call = self.read_migration_preflight.call_args_list[-1]
        staging_dir = final_preflight_call.kwargs["candidate_directory"]
        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.remove_recovery_journal.assert_called_once()
        self.run_silent.assert_not_called()
        self.execute_rollback.assert_not_called()
        poll_health.assert_not_called()
        self.assertEqual(receipt.status, "failed")
        self.assertEqual(receipt.failure_code, "install_failed")
        self.assertFalse(os.path.exists(staging_dir))
        self.assertIn("stale recovery-journal cleanup was deferred", result.output)
        self.assertIn("refusing to stop services", result.output)
        self.assertIn("No service stop, artifact install, or migration", result.output)
        self.assertNotIn("Stopping Services", result.output)

    def test_surviving_timed_out_mutator_defers_rollback_and_retains_authority(self):
        manifest = {
            "minimum_source_version": "9.9.8",
            "required_bridge_version": "9.9.8",
            "auto_bridge_from": ["9.9.7"],
        }
        plan = Mock(name="rollback-plan")
        with patch(
            "defenseclaw.commands.cmd_upgrade._PHASE_TWO_MUTATOR_SURVIVED_TIMEOUT",
            True,
        ):
            result, receipt, _poll_health = self._invoke_upgrade(
                install_side_effect=subprocess.TimeoutExpired(["target-mutator"], 1),
                upgrade_manifest=manifest,
                rollback_plan=plan,
            )

        self.assertIsInstance(result.exception, subprocess.TimeoutExpired)
        self.execute_rollback.assert_not_called()
        self.remove_recovery_journal.assert_not_called()
        self.assertEqual(receipt.status, "pending")
        self.assertIn("automatic rollback is deferred", result.output)
        self.assertIn("release-owned resolver with no version override", result.output)
        self.assertNotIn("Upgrade Rolled Back", result.output)

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

    def test_health_accepts_disabled_fleet_only_with_expected_binary_provenance(self):
        client = Mock()
        client.health.side_effect = [
            {
                "gateway": {"state": "disabled"},
                "provenance": {},
            },
            {
                "gateway": {"state": "disabled"},
                "provenance": {"binary_version": "0.8.3"},
            },
            {
                "gateway": {"state": "disabled"},
                "provenance": {"binary_version": "0.8.4"},
            },
        ]
        with (
            patch("defenseclaw.gateway.OrchestratorClient", return_value=client),
            patch("defenseclaw.commands.cmd_upgrade.ux.ok") as ok,
            patch(
                "defenseclaw.commands.cmd_upgrade.time.monotonic",
                side_effect=[0.0, 0.0, 0.0, 0.0],
            ),
            patch("defenseclaw.commands.cmd_upgrade.time.sleep"),
        ):
            _poll_health(
                Config(),
                timeout_seconds=1,
                expected_version="0.8.4",
            )

        self.assertEqual(client.health.call_count, 3)
        ok.assert_called_once_with("Gateway API is healthy; fleet uplink is disabled by configuration")

    def test_gateway_start_timeout_contains_readiness_budget_and_preserves_other_defaults(self):
        app = AppContext()
        app.cfg = Config()
        gateway_environment = {"DEFENSECLAW_HOME": "/private/upgrade-data"}

        for health_timeout, expected_start_timeout in (
            (59, 90),
            (60, 90),
            (61, 91),
            (120, 150),
        ):
            with (
                self.subTest(health_timeout=health_timeout),
                patch(
                    "defenseclaw.commands.cmd_upgrade._reload_post_upgrade_config",
                    return_value=app.cfg,
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade._gateway_process_environment",
                    return_value=gateway_environment,
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_silent",
                    return_value=True,
                ) as run_silent,
                patch("defenseclaw.commands.cmd_upgrade._poll_health") as poll_health,
            ):
                _start_and_verify_services(
                    app,
                    health_timeout,
                    data_dir="/private/upgrade-data",
                )

            gateway_start, openclaw_restart = run_silent.call_args_list
            self.assertEqual(gateway_start.args[0], ["defenseclaw-gateway", "start"])
            self.assertEqual(gateway_start.kwargs["env"], gateway_environment)
            self.assertEqual(
                gateway_start.kwargs["timeout_seconds"],
                expected_start_timeout,
            )
            self.assertEqual(openclaw_restart.args[0], ["openclaw", "gateway", "restart"])
            self.assertNotIn("timeout_seconds", openclaw_restart.kwargs)
            poll_health.assert_called_once_with(
                app.cfg,
                health_timeout,
                expected_version=None,
            )

    def test_gateway_environment_preserves_fresh_process_readiness_handoff(self):
        data_dir = "/private/upgrade-data"
        config_path = "/private/controller/config.yaml"
        with patch.dict(
            os.environ,
            {
                "DEFENSECLAW_UPGRADE_FRESH_PROCESS": "1",
                "DEFENSECLAW_HOME": "/attacker/home",
                "DEFENSECLAW_CONFIG": "/attacker/config.yaml",
            },
            clear=True,
        ):
            environment = cmd_upgrade_module._gateway_process_environment(
                data_dir,
                config_path=config_path,
            )

        self.assertEqual(environment["DEFENSECLAW_UPGRADE_FRESH_PROCESS"], "1")
        self.assertEqual(environment["DEFENSECLAW_HOME"], os.path.abspath(data_dir))
        self.assertEqual(
            environment["DEFENSECLAW_CONFIG"],
            os.path.abspath(config_path),
        )

    def test_fresh_process_health_uses_current_strict_gateway_contract_once(self):
        cfg = Config()
        cfg.data_dir = "/private/upgrade-data"
        config_path = "/private/controller/config.yaml"

        with TemporaryDirectory() as install_dir:
            gateway_binary = Path(install_dir, "defenseclaw-gateway")
            gateway_binary.write_bytes(b"current-gateway")
            gateway_binary.chmod(0o700)
            completed = Mock(returncode=0)
            with (
                patch.dict(
                    os.environ,
                    {
                        "DEFENSECLAW_UPGRADE_FRESH_PROCESS": "1",
                        "DEFENSECLAW_GATEWAY_BIN": "/attacker/override",
                        "DEFENSECLAW_HOME": "/attacker/home",
                        "DEFENSECLAW_CONFIG": "/attacker/config.yaml",
                        "PATH": "/attacker/path",
                    },
                    clear=True,
                ),
                patch("defenseclaw.commands.cmd_upgrade.platform.system", return_value="Linux"),
                patch("defenseclaw.gateway.canonical_install_path", return_value=str(gateway_binary)),
                patch(
                    "defenseclaw.config.config_path",
                    return_value=Path(config_path),
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=completed,
                ) as run,
                patch("defenseclaw.gateway.OrchestratorClient") as legacy_client,
            ):
                _poll_health(cfg, timeout_seconds=60, expected_version="0.9.0")

        run.assert_called_once()
        self.assertEqual(
            run.call_args.args[0],
            [
                str(gateway_binary),
                "upgrade-wait-ready",
                "--timeout",
                "60s",
                "--expected-version",
                "0.9.0",
            ],
        )
        self.assertEqual(run.call_args.kwargs["timeout"], 65)
        self.assertFalse(run.call_args.kwargs["check"])
        self.assertEqual(
            run.call_args.kwargs["env"]["DEFENSECLAW_HOME"],
            os.path.abspath(cfg.data_dir),
        )
        self.assertEqual(
            run.call_args.kwargs["env"]["DEFENSECLAW_CONFIG"],
            os.path.abspath(config_path),
        )
        self.assertEqual(run.call_args.kwargs["env"]["DEFENSECLAW_UPGRADE_FRESH_PROCESS"], "1")
        legacy_client.assert_not_called()

    def test_fresh_process_health_requires_version_and_positive_shared_budget(self):
        cfg = Config()
        cfg.data_dir = "/private/upgrade-data"
        with (
            patch.dict(os.environ, {"DEFENSECLAW_UPGRADE_FRESH_PROCESS": "1"}, clear=True),
            patch("defenseclaw.commands.cmd_upgrade.subprocess.run") as run,
        ):
            for timeout, version in ((60, None), (0, "0.9.0")):
                with self.subTest(timeout=timeout, version=version), self.assertRaises(SystemExit):
                    _poll_health(cfg, timeout_seconds=timeout, expected_version=version)
        run.assert_not_called()

    def test_fresh_process_health_rejects_unmanaged_canonical_binary(self):
        cfg = Config()
        cfg.data_dir = "/private/upgrade-data"
        with TemporaryDirectory() as install_dir:
            target = Path(install_dir, "target")
            target.write_bytes(b"gateway")
            target.chmod(0o700)
            symlink = Path(install_dir, "defenseclaw-gateway")
            symlink.symlink_to(target)
            with (
                patch.dict(os.environ, {"DEFENSECLAW_UPGRADE_FRESH_PROCESS": "1"}, clear=True),
                patch("defenseclaw.commands.cmd_upgrade.platform.system", return_value="Linux"),
                patch("defenseclaw.gateway.canonical_install_path", return_value=str(symlink)),
                patch("defenseclaw.commands.cmd_upgrade.subprocess.run") as run,
                self.assertRaises(SystemExit),
            ):
                _poll_health(cfg, timeout_seconds=60, expected_version="0.9.0")
        run.assert_not_called()

    def test_fresh_process_health_propagates_strict_command_failure(self):
        cfg = Config()
        cfg.data_dir = "/private/upgrade-data"
        with TemporaryDirectory() as install_dir:
            gateway_binary = Path(install_dir, "defenseclaw-gateway")
            gateway_binary.write_bytes(b"current-gateway")
            gateway_binary.chmod(0o700)
            for outcome, expected_code in (
                (Mock(returncode=23), 23),
                (subprocess.TimeoutExpired([str(gateway_binary)], 65), 1),
            ):
                with (
                    self.subTest(outcome=type(outcome).__name__),
                    patch.dict(os.environ, {"DEFENSECLAW_UPGRADE_FRESH_PROCESS": "1"}, clear=True),
                    patch("defenseclaw.commands.cmd_upgrade.platform.system", return_value="Linux"),
                    patch("defenseclaw.gateway.canonical_install_path", return_value=str(gateway_binary)),
                    patch("defenseclaw.config.config_path", return_value=Path("/private/controller/config.yaml")),
                    patch("defenseclaw.commands.cmd_upgrade.subprocess.run") as run,
                    self.assertRaises(SystemExit) as raised,
                ):
                    if isinstance(outcome, BaseException):
                        run.side_effect = outcome
                    else:
                        run.return_value = outcome
                    _poll_health(cfg, timeout_seconds=60, expected_version="0.9.0")
                self.assertEqual(raised.exception.code, expected_code)

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

    def test_restart_config_reload_ignores_unrelated_default_home(self):
        app = AppContext()
        app.cfg = Config(gateway=GatewayConfig(api_port=19001))

        with TemporaryDirectory() as root:
            transaction_dir = Path(root, "transaction")
            unrelated_home = Path(root, "unrelated-home")
            transaction_dir.mkdir()
            unrelated_home.mkdir()
            Path(transaction_dir, "config.yaml").write_text(
                f"data_dir: {transaction_dir}\ngateway:\n  api_port: 19002\n",
                encoding="utf-8",
            )
            # This deliberately malformed shape reproduces the full-suite
            # contamination: an unscoped reload would read the other
            # installation and fail before restarting the gateway.
            Path(unrelated_home, "config.yaml").write_text(
                "scanners: []\n",
                encoding="utf-8",
            )

            with (
                patch.dict(os.environ, {"DEFENSECLAW_HOME": str(unrelated_home)}),
                patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
                patch("defenseclaw.commands.cmd_upgrade._poll_health") as poll_health,
            ):
                os.environ.pop("DEFENSECLAW_CONFIG", None)
                _start_and_verify_services(app, 7, data_dir=str(transaction_dir))

            self.assertEqual(app.cfg.data_dir, str(transaction_dir))
            self.assertEqual(app.cfg.gateway.api_port, 19002)
            poll_health.assert_called_once_with(app.cfg, 7, expected_version=None)

    def test_hard_cut_restart_never_imports_the_target_config_in_source_process(self):
        app = AppContext()
        app.cfg = Config()
        plan = Mock(os_name="linux")

        with (
            patch("defenseclaw.commands.cmd_upgrade._refresh_target_dotenv_environment") as refresh,
            patch("defenseclaw.commands.cmd_upgrade._reload_post_upgrade_config") as reload_config,
            patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True) as run_silent,
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
        self.assertEqual(
            run_silent.call_args_list[0].args[0],
            [plan.active_gateway_path, "start"],
        )
        self.assertEqual(
            run_silent.call_args_list[0].kwargs["timeout_seconds"],
            90,
        )
        installed_health.assert_called_once_with(
            "/private/bridge-data",
            13,
            "0.8.5",
            os_name="linux",
        )

    def test_hard_cut_local_stack_invocation_failure_is_fatal(self):
        app = AppContext()
        plan = Mock(os_name="linux", active_gateway_path="/exact/gateway")
        with (
            patch("defenseclaw.commands.cmd_upgrade._refresh_target_dotenv_environment"),
            patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
            patch("defenseclaw.commands.cmd_upgrade._poll_installed_health"),
            patch(
                "defenseclaw.commands.cmd_upgrade._run_installed_local_observability_bundle_restart",
                side_effect=_LocalBundleUpgradeInvocationError("restart_failed", "restart"),
            ),
            self.assertRaises(SystemExit),
        ):
            _start_and_verify_services(
                app,
                3,
                data_dir="/private/bridge-data",
                local_bundle_upgrade={"restart_required": True},
                expected_version="0.8.5",
                rollback_plan=plan,
            )

    def test_hard_cut_degraded_local_stack_readiness_is_fatal(self):
        app = AppContext()
        plan = Mock(os_name="linux", active_gateway_path="/exact/gateway")
        with (
            patch("defenseclaw.commands.cmd_upgrade._refresh_target_dotenv_environment"),
            patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
            patch("defenseclaw.commands.cmd_upgrade._poll_installed_health"),
            patch(
                "defenseclaw.commands.cmd_upgrade._run_installed_local_observability_bundle_restart",
                return_value={
                    "restarted": False,
                    "degraded_errors": ["grafana_not_ready"],
                },
            ),
            self.assertRaises(SystemExit),
        ):
            _start_and_verify_services(
                app,
                3,
                data_dir="/private/bridge-data",
                local_bundle_upgrade={"restart_required": True},
                expected_version="0.8.5",
                rollback_plan=plan,
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
                        "DEFENSECLAW_HOME": os.path.join(home, "custom-defenseclaw"),
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

        expected_python = os.path.join(
            home,
            "custom-defenseclaw",
            ".venv",
            "bin",
            "python",
        )
        self.assertEqual(
            run_mock.call_args.args[0],
            [
                expected_python,
                "-I",
                "-B",
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
            stack.enter_context(patch("defenseclaw.__version__", "9.9.8"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_installed_source_coherence"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced"))
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
            # ``cmd_upgrade.subprocess`` is the process-wide subprocess
            # module. The fake below intentionally replaces ``run`` to
            # exercise the missing OpenClaw CLI, which would otherwise also
            # intercept config.detect_environment() on Linux during the
            # post-install reload. Keep this unit test scoped to restart
            # behavior; dedicated reload tests cover the real loader.
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._reload_post_upgrade_config",
                    return_value=app.cfg,
                )
            )
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


@unittest.skipIf(os.name == "nt", "POSIX cosign custody fixture")
class TestCosignBootstrap(unittest.TestCase):
    def test_downloads_pinned_verifier_into_private_temporary_custody(self):
        payload = b"authenticated temporary cosign"
        response = Mock(
            status_code=200,
            headers={"content-length": str(len(payload))},
        )
        response.iter_content.return_value = [payload]
        expected = hashlib.sha256(payload).hexdigest()

        with (
            TemporaryDirectory() as root,
            patch(
                "defenseclaw.commands.cmd_upgrade._detect_platform",
                return_value=("linux", "amd64"),
            ),
            patch.dict(
                cmd_upgrade_module._COSIGN_BOOTSTRAP_SHA256,
                {("linux", "amd64"): expected},
                clear=True,
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade.requests.get",
                return_value=response,
            ) as get_mock,
        ):
            os.chmod(root, 0o700)
            real_chmod = os.chmod

            def linux_compatible_chmod(path, mode):
                # Linux rejects chmod(..., follow_symlinks=False).  Keep the
                # bootstrap test portable even when it runs on Darwin.
                return real_chmod(path, mode)

            with patch(
                "defenseclaw.commands.cmd_upgrade.os.chmod",
                side_effect=linux_compatible_chmod,
            ) as chmod_mock:
                verifier = _download_bootstrap_cosign(root)
            info = os.lstat(verifier)
            self.assertEqual(Path(verifier).read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
            self.assertEqual(info.st_uid, os.getuid())
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(chmod_mock.call_args.kwargs, {})

        get_mock.assert_called_once()
        self.assertFalse(get_mock.call_args.kwargs["allow_redirects"])

    def test_rejects_redirect_outside_pinned_github_host_set_before_following(self):
        response = Mock(
            status_code=302,
            headers={"location": "https://attacker.invalid/cosign"},
        )
        with (
            TemporaryDirectory() as root,
            patch(
                "defenseclaw.commands.cmd_upgrade._detect_platform",
                return_value=("linux", "amd64"),
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade.requests.get",
                return_value=response,
            ) as get_mock,
            self.assertRaisesRegex(OSError, "pinned HTTPS host set"),
        ):
            os.chmod(root, 0o700)
            _download_bootstrap_cosign(root)

        get_mock.assert_called_once()


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

    def test_download_checksums_forwards_native_embedded_verifier_requirement(self):
        with (
            TemporaryDirectory() as tmp,
            patch("defenseclaw.commands.cmd_upgrade.requests.get") as get_mock,
            patch("defenseclaw.commands.cmd_upgrade._verify_checksums_sigstore") as verify_sigstore,
        ):
            sha = "a" * 64
            get_mock.return_value = Mock(
                status_code=200,
                content=f"{sha}  DefenseClawSetup-x64.exe\n".encode(),
            )

            result = _download_checksums("9.9.9", tmp, require_sigstore=True)

            verify_sigstore.assert_called_once_with(
                "9.9.9",
                tmp,
                os.path.join(tmp, "checksums.txt"),
                allow_unverified=False,
                require_embedded_verifier=True,
            )
            self.assertEqual(result, {"DefenseClawSetup-x64.exe": sha})

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

    def test_native_setup_upgrade_requires_embedded_cosign(self):
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
                patch(
                    "defenseclaw.commands.cmd_upgrade._managed_cosign_path",
                    return_value=None,
                ),
                patch("defenseclaw.commands.cmd_upgrade.subprocess.run") as run_mock,
                self.assertRaises(SystemExit) as ctx,
            ):
                _verify_checksums_sigstore(
                    "9.9.9",
                    tmp,
                    checksums,
                    require_embedded_verifier=True,
                )

        self.assertEqual(ctx.exception.code, 1)
        run_mock.assert_not_called()

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

    def test_modern_checksums_bootstrap_failure_is_fatal_even_with_unsafe_override(self):
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
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_bootstrap_cosign",
                    side_effect=OSError("digest mismatch"),
                ),
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

    def test_hard_cut_release_provenance_is_checksum_covered_and_closed(self):
        with TemporaryDirectory() as tmp:
            payload = _hard_cut_provenance_payload("a" * 64)
            raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            path = os.path.join(tmp, "release-provenance.json")
            with open(path, "wb") as stream:
                stream.write(raw)
            checksums = {"release-provenance.json": hashlib.sha256(raw).hexdigest()}
            with patch(
                "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                return_value=path,
            ) as download:
                provenance = _download_release_provenance(
                    "0.8.5",
                    tmp,
                    checksums,
                    required=True,
                )

        self.assertIsNotNone(provenance)
        assert provenance is not None
        self.assertEqual(provenance.release_version, "0.8.5")
        self.assertEqual(provenance.bridge_version, "0.8.4")
        self.assertEqual(provenance.bridge_checksums_sha256, "a" * 64)
        download.assert_called_once_with(
            "0.8.5",
            "release-provenance.json",
            tmp,
            max_bytes=16 * 1024,
        )

    def test_hard_cut_release_provenance_missing_tampered_or_open_fails(self):
        with TemporaryDirectory() as tmp:
            payload = _hard_cut_provenance_payload("b" * 64)
            raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            path = os.path.join(tmp, "release-provenance.json")
            with open(path, "wb") as stream:
                stream.write(raw)
            digest = hashlib.sha256(raw).hexdigest()

            with (
                self.subTest("missing"),
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                    return_value=None,
                ),
                self.assertRaises(SystemExit),
            ):
                _download_release_provenance(
                    "0.8.5",
                    tmp,
                    {"release-provenance.json": digest},
                    required=True,
                )

            with (
                self.subTest("tampered"),
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                    return_value=path,
                ),
                self.assertRaises(SystemExit),
            ):
                _download_release_provenance(
                    "0.8.5",
                    tmp,
                    {"release-provenance.json": "c" * 64},
                    required=True,
                )

            payload["unreviewed"] = True
            open_raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            with open(path, "wb") as stream:
                stream.write(open_raw)
            with (
                self.subTest("open schema"),
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                    return_value=path,
                ),
                self.assertRaises(SystemExit),
            ):
                _download_release_provenance(
                    "0.8.5",
                    tmp,
                    {"release-provenance.json": hashlib.sha256(open_raw).hexdigest()},
                    required=True,
                )

    def test_bridge_checksums_are_bound_to_hard_cut_provenance(self):
        with TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o700)
            checksums_path = os.path.join(tmp, "checksums.txt")
            with open(checksums_path, "wb") as stream:
                stream.write(b"bridge checksums\n")
            os.chmod(checksums_path, 0o600)
            digest = hashlib.sha256(b"bridge checksums\n").hexdigest()
            payload = _hard_cut_provenance_payload(digest)
            raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            provenance = _parse_release_provenance(
                payload,
                target_version="0.8.5",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
            )

            _require_bridge_checksums_provenance(tmp, "0.8.4", provenance)
            with open(checksums_path, "ab") as stream:
                stream.write(b"changed\n")
            with self.assertRaisesRegex(OSError, "do not match hard-cut"):
                _require_bridge_checksums_provenance(tmp, "0.8.4", provenance)

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
            "schema_version": 2,
            "runtime_config_version": 8,
            "release_version": "0.8.5",
            "min_upgrade_protocol": 2,
            "controller_upgrade_protocol": 2,
            "migration_failure_policy": "fail",
            "required_cli_migrations": ["0.8.5"],
            "minimum_source_version": "0.8.4",
            "required_bridge_version": "0.8.4",
            "auto_bridge_from": ["0.8.3", "0.8.2", "0.7.2"],
            "tested_source_versions": [
                "0.8.4",
                "0.8.3",
                "0.8.2",
                "0.8.0",
                "0.7.2",
                "0.7.1",
                "0.6.6",
                "0.4.0",
            ],
            "platform_tested_source_versions": {"windows": []},
            "release_artifacts": _expected_release_artifacts("0.8.5"),
        }
        payload.update(overrides)
        return payload

    @staticmethod
    def _windows_installer_manifest() -> dict[str, object]:
        return {
            "windows_installer": {
                "asset": "DefenseClawSetup-x64.exe",
                "architectures": ["amd64"],
                "handoff_args": ["/upgrade", "/quiet", "/norestart", "INSTALLSCOPE=user"],
                "authenticode": {
                    "required": False,
                    "publisher": "Cisco Systems, Inc.",
                },
                "managed_policy": "respect",
            },
        }

    @staticmethod
    def _windows_setup_provenance(
        setup_sha256: str,
        *,
        unsigned: bool,
        source_commit: str = "a" * 40,
        version: str = "9.9.9",
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "artifact": "DefenseClawSetup-x64.exe",
            "artifact_sha256": setup_sha256,
            "version": version,
            "source_commit": source_commit,
            "distribution_flavor": "oss",
            "built_at_utc": "2026-07-23T00:00:00Z",
            "unsigned": unsigned,
            "authenticode": {},
            "inputs": {},
            "toolchain": {},
        }

    def test_validate_accepts_complete_hard_cut_bridge_graph(self):
        manifest = _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5")

        self.assertEqual(manifest["minimum_source_version"], "0.8.4")
        self.assertEqual(manifest["required_bridge_version"], "0.8.4")
        self.assertEqual(manifest["auto_bridge_from"], ["0.8.3", "0.8.2", "0.7.2"])
        self.assertEqual(manifest["min_upgrade_protocol"], 2)
        self.assertEqual(manifest["controller_upgrade_protocol"], 2)
        self.assertEqual(manifest["platform_tested_source_versions"], {"windows": []})
        _require_hard_cut_manifest_contract(manifest, target_version="0.8.5", required=True)

    def test_hard_cut_migration_preflight_failure_is_bounded_and_pre_stop(self):
        from defenseclaw.observability.v8_migration import V8MigrationError

        runner = CliRunner()
        failure = V8MigrationError(
            "invalid_endpoint",
            "$.otel.destinations[1].endpoint",
            "correct the endpoint and retry",
        )
        with runner.isolation() as (out, _err, _):
            with (
                patch(
                    "defenseclaw.migrations.preflight_observability_v8_upgrade",
                    side_effect=failure,
                ),
                self.assertRaises(SystemExit) as raised,
            ):
                _preflight_hard_cut_observability_migration(
                    data_dir="/active/data",
                    config_path="/active/config.yaml",
                    gateway_binary="/staged/defenseclaw-gateway",
                    candidate_directory="/staged",
                )
            output = out.getvalue().decode()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("$.otel.destinations[1].endpoint", output)
        self.assertIn("No backup, receipt, service stop, artifact install, or migration", output)

    def test_hard_cut_migration_preflight_forwards_authenticated_target(self):
        with patch("defenseclaw.migrations.preflight_observability_v8_upgrade") as preflight:
            _preflight_hard_cut_observability_migration(
                data_dir="/active/data",
                config_path="/active/config.yaml",
                gateway_binary="/staged/defenseclaw-gateway",
                candidate_directory="/staged",
                announce=False,
            )

        preflight.assert_called_once_with(
            data_dir="/active/data",
            config_path="/active/config.yaml",
            gateway_binary="/staged/defenseclaw-gateway",
            candidate_directory="/staged",
        )

    def test_hard_cut_migration_preflight_rejects_binding_drift_for_yes_path(self):
        initial = object()
        changed = object()
        runner = CliRunner()
        with runner.isolation() as (out, _err, _):
            with (
                patch(
                    "defenseclaw.migrations.preflight_observability_v8_upgrade",
                    return_value=changed,
                ),
                self.assertRaises(SystemExit) as raised,
            ):
                _preflight_hard_cut_observability_migration(
                    data_dir="/active/data",
                    config_path="/active/config.yaml",
                    gateway_binary="/staged/defenseclaw-gateway",
                    candidate_directory="/staged",
                    expected_binding=initial,
                    enforce_binding=True,
                    announce=False,
                )
            output = out.getvalue().decode()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("preflight_source_changed", output)
        self.assertIn("No backup, receipt, service stop, artifact install, or migration", output)

    def test_hard_cut_contract_is_mandatory_even_with_unsafe_override(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()
        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "0.8.4"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_installed_source_coherence"))
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
            manifest = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._download_upgrade_manifest"))
            gateway = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._download_gateway"))
            backup = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._create_backup"))
            services = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))

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
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_installed_source_coherence"))
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
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._download_upgrade_manifest", return_value=None))
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
            self._hard_cut_manifest(platform_tested_source_versions={"windows": ["0.8.3"]}),
        ]
        partial = self._hard_cut_manifest()
        del partial["required_bridge_version"]
        invalid_payloads.append(partial)

        for payload in invalid_payloads:
            with self.subTest(payload=payload), self.assertRaises(SystemExit) as raised:
                _validate_upgrade_manifest(payload, "0.8.5")
            self.assertEqual(raised.exception.code, 1)

    def test_validate_rejects_protocol_one_schema_two_manifest_without_bridge(self):
        runner = CliRunner()
        payload = self._hard_cut_manifest(min_upgrade_protocol=1)
        for key in (
            "minimum_source_version",
            "required_bridge_version",
            "auto_bridge_from",
        ):
            payload.pop(key)

        with runner.isolation() as (out, _err, _):
            with self.assertRaises(SystemExit) as raised:
                _validate_upgrade_manifest(payload, "0.8.5")
            output = out.getvalue().decode()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn(
            "hard-cut releases require upgrade protocol 2 and a complete bridge contract",
            output,
        )

    @unittest.skipIf(os.name == "nt", "POSIX installed-source fixture")
    def test_bridge_source_can_proceed(self):
        _enforce_upgrade_source_contract(
            _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5"),
            source_version="0.8.4",
            target_version="0.8.5",
            explicit_target=True,
        )

    def test_windows_hard_cut_without_published_bridge_fails_closed(self):
        runner = CliRunner()
        manifest = _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5")

        with runner.isolation() as (out, _err, _):
            with self.assertRaises(SystemExit) as raised:
                _enforce_upgrade_source_contract(
                    manifest,
                    source_version="0.8.3",
                    target_version="0.8.5",
                    explicit_target=False,
                    os_name="windows",
                )
            output = out.getvalue().decode()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("Windows upgrades to 0.8.5 are unsupported", output)
        self.assertIn("Required bridge 0.8.4 was not published for Windows", output)
        self.assertIn("No changes were made", output)

    @unittest.skipIf(os.name == "nt", "POSIX installed-source fixture")
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
        self.assertIn("Run the release-owned resolver with no version override", output)
        self.assertIn("scripts/upgrade.sh", output)
        self.assertIn("defenseclaw-upgrade.XXXXXX", output)
        self.assertIn("DefenseClaw upgrade resolver complete v1", output)
        self.assertIn("[Guid]::NewGuid()", output)
        self.assertIn("-ErrorAction Stop", output)
        self.assertNotIn("upgrade.sh | bash", output)
        self.assertNotIn("upgrade --version 0.8.4", output)
        self.assertIn(
            "No changes were made: no services were stopped and no installed artifacts were changed.",
            output,
        )

    @unittest.skipIf(os.name == "nt", "POSIX installed-source fixture")
    def test_unsupported_source_fails_closed_with_supported_path(self):
        runner = CliRunner()
        manifest = _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5")

        with runner.isolation() as (out, _err, _):
            with self.assertRaises(SystemExit) as raised:
                _enforce_upgrade_source_contract(
                    manifest,
                    source_version="0.7.0",
                    target_version="0.8.5",
                    explicit_target=False,
                )
            output = out.getvalue().decode()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("outside the signed published-baseline test matrix", output)
        self.assertIn("No tested in-place upgrade path exists", output)
        self.assertIn("Remain on the current version", output)
        self.assertNotIn("--version 0.7.1", output)
        self.assertIn("No changes were made", output)

    @unittest.skipIf(os.name == "nt", "POSIX installed-source fixture")
    def test_unsupported_source_does_not_invent_a_nearest_later_hop(self):
        runner = CliRunner()
        manifest = _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5")

        with runner.isolation() as (out, _err, _):
            with self.assertRaises(SystemExit):
                _enforce_upgrade_source_contract(
                    manifest,
                    source_version="0.7.3",
                    target_version="0.8.5",
                    explicit_target=False,
                )
            output = out.getvalue().decode()

        self.assertIn("No tested in-place upgrade path exists", output)
        self.assertNotIn("--version 0.8.0", output)
        self.assertNotIn("--version 0.4.0", output)

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
            gateway_download = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._download_gateway"))
            wheel_download = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._download_wheel"))
            backup = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._create_backup"))
            services = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))
            install = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_gateway"))

            result = runner.invoke(upgrade, ["--yes", "--version", "0.8.5"], obj=app)

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn("requires the 0.8.4 upgrade bridge", result.output)
        self.assertIn("release-owned resolver with no version override", result.output)
        self.assertNotIn("upgrade --version 0.8.4", result.output)
        self.assertIn("No changes were made", result.output)
        gateway_download.assert_not_called()
        wheel_download.assert_not_called()
        backup.assert_not_called()
        services.assert_not_called()
        install.assert_not_called()

    def test_coherent_bridge_without_handoff_acquires_authenticated_rollback_set_first(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()
        manifest = _validate_upgrade_manifest(self._hard_cut_manifest(), "0.8.5")
        provenance = Mock(release_version="0.8.5", bridge_version="0.8.4")

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(
                patch.dict(
                    os.environ,
                    {
                        "HOME": data_dir,
                        "DEFENSECLAW_CONFIG": "",
                    },
                    clear=True,
                )
            )
            stack.enter_context(patch("defenseclaw.__version__", "0.8.4"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_installed_source_coherence"))
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
                        "defenseclaw_0.8.5_protocol2_linux_amd64.dcgateway": "0" * 64,
                        "defenseclaw-0.8.5-2-py3-none-any.dcwheel": "0" * 64,
                        "upgrade-manifest.json": "0" * 64,
                        "release-provenance.json": "0" * 64,
                    },
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_release_provenance",
                    return_value=provenance,
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                    return_value=manifest,
                )
            )
            acquisition = stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._acquire_bridge_rollback_artifacts",
                    side_effect=RuntimeError("rollback acquisition reached"),
                )
            )
            gateway_download = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._download_gateway"))
            backup = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._create_backup"))
            services = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))

            result = runner.invoke(upgrade, ["--yes", "--version", "0.8.5"], obj=app)

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIsInstance(result.exception, RuntimeError)
        self.assertIn("rollback acquisition reached", str(result.exception))
        acquisition.assert_called_once_with("0.8.4", "linux", "amd64", ANY)
        gateway_download.assert_not_called()
        backup.assert_not_called()
        services.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX installed-source fixture")
    def test_component_drift_fails_before_target_network_backup_or_stop(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()
        with TemporaryDirectory() as root, ExitStack() as stack:
            home = Path(root) / "home"
            data_dir = home / ".defenseclaw"
            gateway = home / ".local/bin/defenseclaw-gateway"
            gateway.parent.mkdir(parents=True)
            data_dir.mkdir(parents=True)
            gateway.write_bytes(b"gateway")
            gateway.chmod(0o755)
            app.cfg.data_dir = str(data_dir)
            app.cfg.claw.home_dir = str(home / ".openclaw")
            stack.enter_context(patch.dict(os.environ, {"HOME": str(home)}))
            stack.enter_context(patch("defenseclaw.__version__", "0.8.4"))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade._detect_platform",
                    return_value=("linux", "amd64"),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_upgrade.subprocess.run",
                    return_value=Mock(
                        returncode=0,
                        stdout="defenseclaw version 0.8.3\n",
                        stderr="",
                    ),
                )
            )
            preflight = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            checksums = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._download_checksums"))
            backup = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._create_backup"))
            services = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))

            result = runner.invoke(
                upgrade,
                ["--yes", "--version", "0.8.5"],
                obj=app,
            )

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn("CLI=0.8.4, gateway=0.8.3", result.output)
        self.assertIn("no target artifacts were downloaded", result.output)
        preflight.assert_not_called()
        checksums.assert_not_called()
        backup.assert_not_called()
        services.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX installed-source fixture")
    def test_v8_installed_state_requires_config_and_cursor_coherence(self):
        runner = CliRunner()
        with (
            TemporaryDirectory() as root,
            patch.dict(os.environ, {"HOME": root}),
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(
                    returncode=0,
                    stdout="defenseclaw version 0.8.5\n",
                    stderr="",
                ),
            ),
        ):
            home = Path(root)
            gateway = home / ".local/bin/defenseclaw-gateway"
            gateway.parent.mkdir(parents=True)
            gateway.write_bytes(b"gateway")
            gateway.chmod(0o755)
            data_dir = home / ".defenseclaw"
            data_dir.mkdir()
            config = data_dir / "config.yaml"
            cursor = data_dir / ".migration_state.json"

            config.write_text("config_version: 7\n", encoding="utf-8")
            with runner.isolation() as (out, _err, _):
                with self.assertRaises(SystemExit):
                    _preflight_installed_source_coherence("0.8.5", "linux", str(data_dir))
                self.assertIn("requires config_version 8", out.getvalue().decode())

            config.write_text("config_version: 8\n", encoding="utf-8")
            with runner.isolation() as (out, _err, _):
                with self.assertRaises(SystemExit):
                    _preflight_installed_source_coherence("0.8.5", "linux", str(data_dir))
                self.assertIn("lacks the applied 0.8.5 migration cursor", out.getvalue().decode())

            cursor.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "package_version": "0.8.5",
                        "applied": ["0.8.5"],
                        "applied_at": {"0.8.5": "test"},
                    }
                ),
                encoding="utf-8",
            )
            _preflight_installed_source_coherence("0.8.5", "linux", str(data_dir))

    def test_downgrade_refusal_precedes_platform_network_and_mutation(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()
        with ExitStack() as stack:
            stack.enter_context(patch("defenseclaw.__version__", "0.8.5"))
            detect = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._detect_platform"))
            coherence = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._preflight_installed_source_coherence")
            )
            preflight = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            fetch = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._fetch_latest_version"))
            backup = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._create_backup"))
            services = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))
            result = runner.invoke(
                upgrade,
                ["--yes", "--version", "0.8.4"],
                obj=app,
            )

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn("Refusing to downgrade", result.output)
        self.assertIn("no network preflight ran", result.output)
        detect.assert_not_called()
        coherence.assert_not_called()
        preflight.assert_not_called()
        fetch.assert_not_called()
        backup.assert_not_called()
        services.assert_not_called()

    def test_validate_rejects_newer_upgrade_protocol(self):
        payload = {
            "schema_version": 2,
            "runtime_config_version": 8,
            "release_version": "9.9.9",
            "min_upgrade_protocol": 999,
            "migration_failure_policy": "fail",
            "required_cli_migrations": ["9.9.9"],
            "tested_source_versions": ["0.8.4"],
            "platform_tested_source_versions": {"windows": ["0.8.4"]},
            "release_artifacts": _expected_release_artifacts("9.9.9"),
        }

        with self.assertRaises(SystemExit) as ctx:
            _validate_upgrade_manifest(payload, "9.9.9")

        self.assertEqual(ctx.exception.code, 1)

    def test_validate_rejects_newer_manifest_schema(self):
        payload = {
            "schema_version": 3,
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
            "schema_version": 2,
            "runtime_config_version": 8,
            "release_version": "9.9.9",
            "min_upgrade_protocol": 2,
            "controller_upgrade_protocol": 2,
            "migration_failure_policy": "fail",
            "required_cli_migrations": ["9.9.9"],
            "minimum_source_version": "0.8.4",
            "required_bridge_version": "0.8.4",
            "auto_bridge_from": [],
            "tested_source_versions": ["0.8.4"],
            "platform_tested_source_versions": {"windows": ["0.8.4"]},
            "release_artifacts": _expected_release_artifacts("9.9.9"),
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

    def test_validate_accepts_windows_installer_policy(self):
        payload = {
            "schema_version": 2,
            "runtime_config_version": 8,
            "release_version": "9.9.9",
            "min_upgrade_protocol": 2,
            "controller_upgrade_protocol": 2,
            "migration_failure_policy": "fail",
            "required_cli_migrations": ["9.9.9"],
            "minimum_source_version": "0.8.4",
            "required_bridge_version": "0.8.4",
            "auto_bridge_from": [],
            "tested_source_versions": ["0.8.4"],
            "platform_tested_source_versions": {"windows": ["0.8.4"]},
            "release_artifacts": _expected_release_artifacts("9.9.9"),
            "windows_installer": {
                "asset": "DefenseClawSetup-x64.exe",
                "architectures": ["amd64"],
                "handoff_args": ["/upgrade", "/quiet", "/norestart", "INSTALLSCOPE=user"],
                "authenticode": {
                    "required": False,
                    "publisher": "Cisco Systems, Inc.",
                },
                "managed_policy": "respect",
            },
        }

        manifest = _validate_upgrade_manifest(payload, "9.9.9")

        self.assertEqual(manifest["windows_installer"]["asset"], "DefenseClawSetup-x64.exe")
        self.assertFalse(manifest["windows_installer"]["authenticode"]["required"])

    def test_validate_rejects_wrong_windows_installer_asset(self):
        payload = {
            "schema_version": 2,
            "runtime_config_version": 8,
            "release_version": "9.9.9",
            "min_upgrade_protocol": 2,
            "controller_upgrade_protocol": 2,
            "migration_failure_policy": "warn",
            "required_cli_migrations": [],
            "minimum_source_version": "0.8.4",
            "required_bridge_version": "0.8.4",
            "auto_bridge_from": [],
            "tested_source_versions": ["0.8.4"],
            "platform_tested_source_versions": {"windows": ["0.8.4"]},
            "release_artifacts": _expected_release_artifacts("9.9.9"),
            "windows_installer": {
                "asset": "DefenseClawSetup-latest.exe",
                "architectures": ["amd64"],
                "handoff_args": ["/upgrade", "/quiet", "/norestart", "INSTALLSCOPE=user"],
                "authenticode": {
                    "required": False,
                    "publisher": "Cisco Systems, Inc.",
                },
                "managed_policy": "respect",
            },
        }

        with self.assertRaises(SystemExit) as ctx:
            _validate_upgrade_manifest(payload, "9.9.9")

        self.assertEqual(ctx.exception.code, 1)

    def test_native_windows_install_state_reads_marker_and_normalizes_paths(self):
        with TemporaryDirectory() as temp:
            local_appdata = os.path.join(temp, "LocalAppData")
            profile = os.path.join(temp, "Profile")
            os.makedirs(local_appdata)
            os.makedirs(profile)
            root = os.path.join(local_appdata, "Programs", "DefenseClaw")
            installer = os.path.join(root, "installer")
            os.makedirs(installer)
            state = {
                "install_kind": "native-windows-exe",
                "connector": "codex",
                "mode": "action",
                "data_root": os.path.join(profile, ".defenseclaw"),
            }
            with open(os.path.join(installer, "install-state.json"), "w", encoding="utf-8") as stream:
                json.dump(state, stream)

            with patch(
                "defenseclaw.commands.cmd_upgrade._windows_known_folder",
                side_effect=[local_appdata, profile],
            ):
                loaded = _native_windows_install_state("windows")

        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["connector"], "codex")
        self.assertTrue(
            loaded["setup_path"].endswith(
                os.path.join("DefenseClaw", "InstallerCache", "DefenseClawSetup-x64.exe"),
            ),
        )

    def test_native_windows_install_state_ignores_environment_install_root(self):
        with TemporaryDirectory() as temp:
            local_appdata = os.path.join(temp, "LocalAppData")
            profile = os.path.join(temp, "Profile")
            installer = os.path.join(local_appdata, "Programs", "DefenseClaw", "installer")
            os.makedirs(installer)
            os.makedirs(profile)
            with open(os.path.join(installer, "install-state.json"), "w", encoding="utf-8") as stream:
                json.dump({"install_kind": "native-windows-exe"}, stream)

            with (
                patch.dict(os.environ, {"DEFENSECLAW_INSTALL_ROOT": os.path.join(temp, "Untrusted")}),
                patch(
                    "defenseclaw.commands.cmd_upgrade._windows_known_folder",
                    side_effect=[local_appdata, profile],
                ),
            ):
                loaded = _native_windows_install_state("windows")

        self.assertTrue(loaded["install_root"].startswith(os.path.realpath(local_appdata)))

    def test_native_windows_install_state_rejects_corrupt_marker(self):
        with TemporaryDirectory() as temp:
            local_appdata = os.path.join(temp, "LocalAppData")
            profile = os.path.join(temp, "Profile")
            installer = os.path.join(local_appdata, "Programs", "DefenseClaw", "installer")
            os.makedirs(installer)
            os.makedirs(profile)
            with open(os.path.join(installer, "install-state.json"), "w", encoding="utf-8") as stream:
                stream.write("not json")

            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade._windows_known_folder",
                    side_effect=[local_appdata, profile],
                ),
                self.assertRaises(SystemExit) as ctx,
            ):
                _native_windows_install_state("windows")

        self.assertEqual(ctx.exception.code, 1)

    def _download_windows_setup_fixture(
        self,
        staging_dir: str,
        *,
        provenance_unsigned: bool,
        observed_unsigned: bool,
        provenance_source_commit: str = "a" * 40,
        expected_source_commit: str = "a" * 40,
    ) -> tuple[str, str]:
        setup_bytes = b"authenticated native Setup fixture"
        setup_sha256 = hashlib.sha256(setup_bytes).hexdigest()
        provenance = self._windows_setup_provenance(
            setup_sha256,
            unsigned=provenance_unsigned,
            source_commit=provenance_source_commit,
        )
        provenance_bytes = json.dumps(provenance, sort_keys=True).encode("utf-8")
        checksums = {
            "DefenseClawSetup-x64.exe": setup_sha256,
            "DefenseClawSetup-x64.exe.provenance.json": hashlib.sha256(provenance_bytes).hexdigest(),
        }

        def download(_url: str, destination: str) -> None:
            name = os.path.basename(destination)
            payload = setup_bytes if name == "DefenseClawSetup-x64.exe" else provenance_bytes
            Path(destination).write_bytes(payload)

        with (
            patch(
                "defenseclaw.commands.cmd_upgrade._download_file",
                side_effect=download,
            ) as download_mock,
            patch(
                "defenseclaw.commands.cmd_upgrade._verify_windows_setup_authenticode",
                return_value=observed_unsigned,
            ),
        ):
            result = _download_windows_setup(
                "9.9.9",
                staging_dir,
                checksums,
                self._windows_installer_manifest(),
                expected_source_commit=expected_source_commit,
            )

        downloaded_names = {os.path.basename(call.args[1]) for call in download_mock.call_args_list}
        self.assertEqual(
            downloaded_names,
            {
                "DefenseClawSetup-x64.exe",
                "DefenseClawSetup-x64.exe.provenance.json",
            },
        )
        return result

    def test_windows_setup_download_accepts_matching_signed_and_unsigned_provenance(self):
        for unsigned in (False, True):
            with self.subTest(unsigned=unsigned), TemporaryDirectory() as staging:
                setup_path, setup_name = self._download_windows_setup_fixture(
                    staging,
                    provenance_unsigned=unsigned,
                    observed_unsigned=unsigned,
                )
                self.assertEqual(setup_name, "DefenseClawSetup-x64.exe")
                self.assertEqual(os.path.basename(setup_path), setup_name)

    def test_windows_setup_download_rejects_both_signing_state_mismatch_directions(self):
        for provenance_unsigned, observed_unsigned in (
            (False, True),
            (True, False),
        ):
            with (
                self.subTest(
                    provenance_unsigned=provenance_unsigned,
                    observed_unsigned=observed_unsigned,
                ),
                TemporaryDirectory() as staging,
                self.assertRaises(SystemExit) as ctx,
            ):
                self._download_windows_setup_fixture(
                    staging,
                    provenance_unsigned=provenance_unsigned,
                    observed_unsigned=observed_unsigned,
                )
            self.assertEqual(ctx.exception.code, 1)

    def test_windows_setup_download_binds_release_provenance_source_commit(self):
        with TemporaryDirectory() as staging, self.assertRaises(SystemExit) as ctx:
            self._download_windows_setup_fixture(
                staging,
                provenance_unsigned=True,
                observed_unsigned=True,
                provenance_source_commit="b" * 40,
                expected_source_commit="a" * 40,
            )
        self.assertEqual(ctx.exception.code, 1)

    def test_native_windows_authenticated_artifact_set_includes_setup_provenance(self):
        source = Path(cmd_upgrade_module.__file__).read_text(encoding="utf-8")
        start = source.index("artifact_names = [")
        end = source.index("if checksums is not None:", start)
        artifact_set = source[start:end]
        self.assertIn("_WINDOWS_SETUP_ASSET", artifact_set)
        self.assertIn("_WINDOWS_SETUP_PROVENANCE_ASSET", artifact_set)

    def test_authenticode_verification_requires_valid_publisher(self):
        installer = {
            "authenticode": {
                "required": False,
                "publisher": "Cisco Systems, Inc.",
            },
        }
        signed = json.dumps(
            {
                "Status": "Valid",
                "Publisher": "Cisco Systems, Inc.",
            }
        )
        with (
            patch(
                "defenseclaw.commands.cmd_upgrade._system_powershell_path",
                return_value="powershell.exe",
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0, stdout=signed, stderr=""),
            ),
        ):
            unsigned = _verify_windows_setup_authenticode("setup.exe", installer)
        self.assertFalse(unsigned)

    def test_authenticode_verification_accepts_explicitly_unverified_setup(self):
        installer = {
            "authenticode": {
                "required": False,
                "publisher": "Cisco Systems, Inc.",
            },
        }
        unsigned = json.dumps({"Status": "NotSigned", "Publisher": ""})
        with (
            patch(
                "defenseclaw.commands.cmd_upgrade._system_powershell_path",
                return_value="powershell.exe",
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0, stdout=unsigned, stderr=""),
            ),
        ):
            unsigned = _verify_windows_setup_authenticode("setup.exe", installer)
        self.assertTrue(unsigned)

    def test_authenticode_verification_rejects_publisher_lookalike(self):
        installer = {
            "authenticode": {
                "required": False,
                "publisher": "Cisco Systems, Inc.",
            },
        }
        signed = json.dumps(
            {
                "Status": "Valid",
                "Publisher": "Fake Cisco Systems, Inc.",
            }
        )
        with (
            patch(
                "defenseclaw.commands.cmd_upgrade._system_powershell_path",
                return_value="powershell.exe",
            ),
            patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0, stdout=signed, stderr=""),
            ),
            patch("defenseclaw.commands.cmd_upgrade.ux.subhead") as guidance,
            self.assertRaises(SystemExit) as ctx,
        ):
            _verify_windows_setup_authenticode("setup.exe", installer)

        self.assertEqual(ctx.exception.code, 1)
        self.assertIn(
            "unexpected signing state or untrusted signature",
            guidance.call_args.args[0],
        )

    def test_windows_setup_handoff_uses_silent_upgrade_shape(self):
        runner = CliRunner()
        manifest = {
            "windows_installer": {
                "asset": "DefenseClawSetup-x64.exe",
                "architectures": ["amd64"],
                "handoff_args": ["/upgrade", "/quiet", "/norestart", "INSTALLSCOPE=user"],
                "authenticode": {
                    "required": False,
                    "publisher": "Cisco Systems, Inc.",
                },
                "managed_policy": "respect",
            },
        }
        with TemporaryDirectory() as temp:
            source = os.path.join(temp, "download", "DefenseClawSetup-x64.exe")
            cache = os.path.join(temp, "cache", "DefenseClawSetup-x64.exe")
            os.makedirs(os.path.dirname(source))
            with open(source, "wb") as stream:
                stream.write(b"verified setup")
            state = {
                "connector": "claudecode",
                "mode": "action",
                "maintenance_path": cache,
            }
            with patch("defenseclaw.commands.cmd_upgrade.subprocess.Popen") as popen_mock:
                with runner.isolation():
                    _handoff_windows_setup_upgrade(
                        source,
                        "DefenseClawSetup-x64.exe",
                        "9.9.9",
                        state,
                        manifest,
                        yes=True,
                    )

        args = popen_mock.call_args.args[0]
        self.assertEqual(args[0], cache)
        self.assertIn("/upgrade", args)
        self.assertIn("/quiet", args)
        self.assertIn("/norestart", args)
        self.assertIn("INSTALLSCOPE=user", args)
        self.assertIn("CONNECTOR=claudecode", args)
        self.assertIn("MODE=action", args)
        self.assertTrue(any(arg.startswith("WAITPID=") for arg in args))

    def test_machine_install_self_update_is_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            _enforce_windows_self_update_policy({"install_scope": "machine"})
        self.assertEqual(ctx.exception.code, 1)

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
    """Windows ships gateway and no-console hook executables in one zip."""

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
                self._write_zip(
                    dest,
                    {
                        "defenseclaw.exe": "MZ\x00gateway",
                        "defenseclaw-hook.exe": "MZ\x00hook",
                    },
                )

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                binary, archive_name = _download_gateway("9.9.9", "windows", "amd64", tmp)

            self.assertEqual(archive_name, "defenseclaw_9.9.9_windows_amd64.zip")
            self.assertTrue(binary.endswith("defenseclaw.exe"))
            self.assertTrue(os.path.isfile(binary))
            self.assertTrue(os.path.isfile(os.path.join(tmp, "defenseclaw-hook.exe")))

    def test_download_gateway_rejects_zip_without_exe(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_zip(dest, {"README.md": "missing binary"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                with self.assertRaises(SystemExit) as ctx:
                    _download_gateway("9.9.9", "windows", "amd64", tmp)
            self.assertEqual(ctx.exception.code, 1)

    def test_download_gateway_rejects_zip_without_hook_launcher(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_zip(dest, {"defenseclaw.exe": "MZ\x00gateway"})

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

    @unittest.skipIf(os.name == "nt", "POSIX gateway snapshot fixture")
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

    @unittest.skipIf(os.name == "nt", "POSIX gateway snapshot fixture")
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

    def test_failed_macos_codesign_never_publishes_candidate_gateway(self):
        with TemporaryDirectory() as fake_home, patch.dict(os.environ, {"HOME": fake_home}):
            install_dir = Path(fake_home) / ".local/bin"
            install_dir.mkdir(parents=True)
            active = install_dir / "defenseclaw-gateway"
            candidate = Path(fake_home) / "candidate-gateway"
            active.write_bytes(b"signed bridge gateway")
            candidate.write_bytes(b"unsigned target gateway")

            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade._run_phase_two_mutator",
                    side_effect=subprocess.CalledProcessError(1, ["codesign"]),
                ) as codesign,
                self.assertRaises(subprocess.CalledProcessError),
            ):
                _install_gateway(str(candidate), "darwin")

            self.assertEqual(active.read_bytes(), b"signed bridge gateway")
            self.assertTrue(codesign.call_args.kwargs["check"])

    def test_windows_install_places_no_console_hook_next_to_gateway(self):
        with TemporaryDirectory() as staging, TemporaryDirectory() as fake_home:
            gateway = os.path.join(staging, "defenseclaw.exe")
            hook = os.path.join(staging, "defenseclaw-hook.exe")
            with open(gateway, "wb") as stream:
                stream.write(b"gateway")
            with open(hook, "wb") as stream:
                stream.write(b"hook")

            def fake_expanduser(path):
                return path.replace("~", fake_home, 1)

            with patch(
                "defenseclaw.commands.cmd_upgrade.os.path.expanduser",
                side_effect=fake_expanduser,
            ):
                target = _install_gateway(gateway, "windows")

            self.assertEqual(
                os.path.normpath(target),
                os.path.join(fake_home, ".local", "bin", "defenseclaw-gateway.exe"),
            )
            installed_hook = os.path.join(fake_home, ".local", "bin", "defenseclaw-hook.exe")
            with open(installed_hook, "rb") as stream:
                self.assertEqual(stream.read(), b"hook")

    def test_windows_install_rolls_back_hook_if_gateway_replace_fails(self):
        with TemporaryDirectory() as staging, TemporaryDirectory() as fake_home:
            install_dir = os.path.join(fake_home, ".local", "bin")
            os.makedirs(install_dir)
            gateway_target = os.path.join(install_dir, "defenseclaw-gateway.exe")
            hook_target = os.path.join(install_dir, "defenseclaw-hook.exe")
            with open(gateway_target, "wb") as stream:
                stream.write(b"old gateway")
            with open(hook_target, "wb") as stream:
                stream.write(b"old hook")

            gateway = os.path.join(staging, "defenseclaw.exe")
            hook = os.path.join(staging, "defenseclaw-hook.exe")
            with open(gateway, "wb") as stream:
                stream.write(b"new gateway")
            with open(hook, "wb") as stream:
                stream.write(b"new hook")

            real_replace = os.replace

            def fail_gateway_replace(source, destination):
                if os.path.normpath(destination) == os.path.normpath(gateway_target):
                    raise PermissionError("gateway is locked")
                return real_replace(source, destination)

            def fake_expanduser(path):
                return path.replace("~", fake_home, 1)

            with (
                patch(
                    "defenseclaw.commands.cmd_upgrade.os.path.expanduser",
                    side_effect=fake_expanduser,
                ),
                patch(
                    "defenseclaw.commands.cmd_upgrade.os.replace",
                    side_effect=fail_gateway_replace,
                ),
            ):
                with self.assertRaises(PermissionError):
                    _install_gateway(gateway, "windows")

            with open(gateway_target, "rb") as stream:
                self.assertEqual(stream.read(), b"old gateway")
            with open(hook_target, "rb") as stream:
                self.assertEqual(stream.read(), b"old hook")
            self.assertEqual(
                sorted(os.listdir(install_dir)),
                ["defenseclaw-gateway.exe", "defenseclaw-hook.exe"],
            )


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

    def test_default_timeout_remains_unchanged_for_unrelated_callers(self):
        runner = CliRunner()
        with patch(
            "defenseclaw.commands.cmd_upgrade._run_phase_two_mutator",
            return_value=Mock(returncode=0, stderr="", stdout=""),
        ) as run:
            with runner.isolation():
                ok = _run_silent(["other-command"], "Started", "Did not start")

        self.assertTrue(ok)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

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

    def test_zero_exit_with_declared_failure_marker_is_not_reported_as_success(self):
        runner = CliRunner()
        with patch(
            "defenseclaw.commands.cmd_upgrade.subprocess.run",
            return_value=Mock(
                returncode=0,
                stderr="",
                stdout="Gateway service disabled. Start with: openclaw gateway install\n",
            ),
        ):
            with runner.isolation() as (out, _err, _):
                ok = _run_silent(
                    ["openclaw", "gateway", "restart"],
                    "OpenClaw gateway restarted",
                    "Could not restart OpenClaw gateway automatically",
                    failure_output_markers=("gateway service disabled",),
                )
                output = out.getvalue().decode()

        self.assertFalse(ok)
        self.assertIn("Could not restart OpenClaw gateway automatically", output)
        self.assertIn("Gateway service disabled", output)
        self.assertNotIn("OpenClaw gateway restarted", output)

    def test_zero_exit_output_is_ignored_without_a_declared_failure_marker(self):
        runner = CliRunner()
        with patch(
            "defenseclaw.commands.cmd_upgrade.subprocess.run",
            return_value=Mock(
                returncode=0,
                stderr="",
                stdout="Gateway service disabled. Start with: openclaw gateway install\n",
            ),
        ):
            with runner.isolation() as (out, _err, _):
                ok = _run_silent(["other-command"], "Started", "Did not start")
                output = out.getvalue().decode()

        self.assertTrue(ok)
        self.assertIn("Started", output)
        self.assertNotIn("Did not start", output)

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
