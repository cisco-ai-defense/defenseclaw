"""Focused production wiring tests for the observability-v8 upgrade migration."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from defenseclaw import migration_state
from defenseclaw.config_inspect import ConfigInspectError
from defenseclaw.migrations import (
    MIGRATIONS,
    MigrationContext,
    ObservabilityV8UpgradeMigrationError,
    _allocate_observability_v8_bundle_backup,
    _migrate_observability_v8,
    _observability_v8_upgrade_environment,
    _preflight_observability_v8,
    _validate_observability_v8_candidate,
    preflight_required_migrations,
    run_migrations,
)
from defenseclaw.observability.v8_activation import V8ActivationError, V8CandidateValidationError


class TestObservabilityV8UpgradeMigration(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.TemporaryDirectory(prefix="defenseclaw-v8-upgrade-")
        self.data_dir = os.path.join(self.root.name, "active-data")
        os.makedirs(self.data_dir, mode=0o700)
        self.config_path = os.path.join(self.root.name, "operator-config.yaml")
        self.environment_path = os.path.join(self.data_dir, ".env")
        with open(self.config_path, "wb") as config_file:
            config_file.write(b"config_version: 7\ndata_dir: /legacy\n")
        with open(self.environment_path, "w", encoding="utf-8") as environment_file:
            environment_file.write("DOTENV_ONLY=dotenv-value\nSHARED=dotenv-loses\n")
        if os.name != "nt":
            os.chmod(self.config_path, 0o600)
            os.chmod(self.environment_path, 0o600)
        self.ctx = MigrationContext(
            openclaw_home=os.path.join(self.root.name, "openclaw"),
            data_dir=self.data_dir,
            from_version="0.8.4",
            to_version="0.8.5",
            config_path=self.config_path,
        )

    def tearDown(self) -> None:
        self.root.cleanup()

    def test_registry_runs_migration_only_at_forward_release_key(self) -> None:
        rows = [(version, fn) for version, _description, fn in MIGRATIONS if fn is _migrate_observability_v8]
        self.assertEqual(rows, [("0.8.5", _migrate_observability_v8)])

    def test_missing_config_is_an_unconfigured_installation_no_op(self) -> None:
        os.unlink(self.config_path)
        with (
            patch("defenseclaw.migrations.convert_v7_observability_to_v8") as convert,
            patch("defenseclaw.migrations.activate_v8_migration") as activate,
        ):
            _migrate_observability_v8(self.ctx)

        convert.assert_not_called()
        activate.assert_not_called()
        self.assertEqual(self.ctx.changes, [])

    def test_convert_validate_activate_order_and_exact_active_paths(self) -> None:
        calls: list[str] = []
        migration = object()
        inspected_candidate_paths: list[str] = []

        def convert(source, environment, **kwargs):
            calls.append("convert")
            self.assertEqual(source, b"config_version: 7\ndata_dir: /legacy\n")
            self.assertEqual(environment["DOTENV_ONLY"], "dotenv-value")
            self.assertEqual(environment["SHARED"], "ambient-wins")
            self.assertEqual(environment["AMBIENT_ONLY"], "ambient-value")
            self.assertEqual(kwargs["source_name"], os.path.abspath(self.config_path))
            self.assertEqual(kwargs["effective_data_dir"], os.path.abspath(self.data_dir))
            return migration

        def inspect(operation, **kwargs):
            calls.append("validate")
            candidate_path = kwargs["config_path"]
            inspected_candidate_paths.append(candidate_path)
            self.assertEqual(operation, "validate")
            self.assertEqual(kwargs["data_dir"], os.path.abspath(self.data_dir))
            self.assertEqual(kwargs["environment_overrides"]["DOTENV_ONLY"], "dotenv-value")
            self.assertEqual(kwargs["environment_overrides"]["MOVED_SECRET"], "protected-value")
            with open(candidate_path, "rb") as candidate_file:
                self.assertEqual(candidate_file.read(), b"config_version: 8\n")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(os.stat(candidate_path).st_mode), 0o600)
            return SimpleNamespace(valid=True, config_version=8)

        def activate(actual_migration, **kwargs):
            calls.append("activate")
            self.assertIs(actual_migration, migration)
            self.assertEqual(kwargs["data_dir"], os.path.abspath(self.data_dir))
            self.assertEqual(kwargs["config_path"], os.path.abspath(self.config_path))
            self.assertEqual(kwargs["environment_path"], os.path.abspath(self.environment_path))
            self.assertNotIn("backup_root", kwargs)
            self.assertIs(kwargs["tighten_legacy_backup_root"], True)
            self.assertNotIn("fault_injector", kwargs)
            kwargs["validator"](b"config_version: 8\n", {"MOVED_SECRET": "protected-value"})
            return SimpleNamespace(activated=True, already_v8=False)

        with (
            patch.dict(
                os.environ,
                {"SHARED": "ambient-wins", "AMBIENT_ONLY": "ambient-value"},
                clear=True,
            ),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", side_effect=convert),
            patch("defenseclaw.migrations.inspect_v8_config", side_effect=inspect),
            patch("defenseclaw.migrations.activate_v8_migration", side_effect=activate),
        ):
            _migrate_observability_v8(self.ctx)

        self.assertEqual(calls, ["convert", "activate", "validate"])
        self.assertEqual(self.ctx.changes, ["activated observability configuration schema v8"])
        self.assertEqual(len(inspected_candidate_paths), 1)
        self.assertFalse(os.path.exists(inspected_candidate_paths[0]))

    def test_already_v8_still_target_validates_and_is_idempotent(self) -> None:
        calls: list[str] = []
        migration = SimpleNamespace(changed=False, already_v8=True, candidate=b"config_version: 8\n")

        def convert(*_args, **_kwargs):
            calls.append("convert")
            return migration

        def inspect(*_args, **_kwargs):
            calls.append("validate")
            return SimpleNamespace(valid=True, config_version=8)

        def activate(actual_migration, **kwargs):
            calls.append("activate")
            self.assertIs(actual_migration, migration)
            kwargs["validator"](migration.candidate, {})
            return SimpleNamespace(activated=False, already_v8=True)

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", side_effect=convert),
            patch("defenseclaw.migrations.inspect_v8_config", side_effect=inspect),
            patch("defenseclaw.migrations.activate_v8_migration", side_effect=activate),
        ):
            _migrate_observability_v8(self.ctx)

        self.assertEqual(calls, ["convert", "activate", "validate"])
        self.assertEqual(self.ctx.changes, [])

    def test_target_helper_failure_is_value_safe_and_temp_is_removed(self) -> None:
        secret = "inline-secret-that-must-not-escape"
        migration = object()
        candidate_paths: list[str] = []

        def inspect(_operation, **kwargs):
            candidate_paths.append(kwargs["config_path"])
            self.assertNotIn(secret, kwargs["config_path"])
            self.assertNotIn(secret, kwargs["data_dir"])
            raise RuntimeError(secret)

        def activate(_migration, **kwargs):
            try:
                kwargs["validator"](b"config_version: 8\n", {"SECRET_ENV": secret})
            except Exception:
                raise V8ActivationError(
                    "candidate_validation_failed",
                    "target_go_validation",
                    target_path=kwargs["config_path"],
                ) from None
            self.fail("validator unexpectedly succeeded")

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", return_value=migration),
            patch("defenseclaw.migrations.inspect_v8_config", side_effect=inspect),
            patch("defenseclaw.migrations.activate_v8_migration", side_effect=activate),
        ):
            with self.assertRaises(V8ActivationError) as raised:
                _migrate_observability_v8(self.ctx)

        self.assertNotIn(secret, str(raised.exception))
        self.assertEqual(len(candidate_paths), 1)
        self.assertFalse(os.path.exists(candidate_paths[0]))

    def test_staged_preflight_validates_without_mutating_live_config_or_data(self) -> None:
        canonical_config = os.path.join(self.data_dir, "config.yaml")
        source = b"config_version: 7\nobservability:\n  enabled: true\n"
        with open(canonical_config, "wb") as config_file:
            config_file.write(source)
        with open(self.environment_path, "rb") as environment_file:
            before_environment = environment_file.read()
        scratch = os.path.join(self.root.name, "staged-runtime", "installer", ".migration-preflight")
        os.makedirs(scratch, mode=0o700)
        migration = SimpleNamespace(
            candidate=b"config_version: 8\nobservability: {}\n",
            environment_edits=(),
        )
        candidate_paths: list[str] = []

        def inspect(operation, **kwargs):
            self.assertEqual(operation, "validate")
            self.assertEqual(kwargs["data_dir"], os.path.abspath(self.data_dir))
            candidate_path = kwargs["config_path"]
            candidate_paths.append(candidate_path)
            self.assertEqual(os.path.commonpath((scratch, candidate_path)), scratch)
            with open(candidate_path, "rb") as candidate_file:
                self.assertEqual(candidate_file.read(), migration.candidate)
            return SimpleNamespace(valid=True, config_version=8)

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", return_value=migration),
            patch("defenseclaw.migrations.inspect_v8_config", side_effect=inspect),
            patch("defenseclaw.migrations.activate_v8_migration") as activate,
        ):
            count = preflight_required_migrations(
                "0.8.0",
                "0.8.6",
                self.ctx.openclaw_home,
                self.data_dir,
                ["0.8.5"],
                scratch,
            )

        self.assertEqual(count, 1)
        activate.assert_not_called()
        with open(canonical_config, "rb") as config_file:
            self.assertEqual(config_file.read(), source)
        with open(self.environment_path, "rb") as environment_file:
            self.assertEqual(environment_file.read(), before_environment)
        self.assertEqual(len(candidate_paths), 1)
        self.assertFalse(os.path.exists(candidate_paths[0]))
        self.assertEqual(os.listdir(scratch), [])

    def test_staged_preflight_rejects_config_path_escape_before_read(self) -> None:
        outside = os.path.join(self.root.name, "outside-config.yaml")
        with open(outside, "wb") as config_file:
            config_file.write(b"config_version: 7\n")
        scratch = os.path.join(self.root.name, "staged-runtime", "installer", ".migration-preflight")
        os.makedirs(scratch, mode=0o700)
        ctx = MigrationContext(
            openclaw_home=self.ctx.openclaw_home,
            data_dir=self.data_dir,
            from_version="0.8.0",
            to_version="0.8.6",
            config_path=outside,
        )

        with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
            _preflight_observability_v8(ctx, scratch)

        self.assertEqual(raised.exception.code, "preflight_path_escape")
        with open(outside, "rb") as config_file:
            self.assertEqual(config_file.read(), b"config_version: 7\n")
        self.assertEqual(os.listdir(scratch), [])

    def test_activation_failure_propagates_without_claiming_change(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", return_value=object()),
            patch(
                "defenseclaw.migrations.activate_v8_migration",
                side_effect=V8ActivationError("activation_failed", "config_write"),
            ),
        ):
            with self.assertRaises(V8ActivationError):
                _migrate_observability_v8(self.ctx)
        self.assertEqual(self.ctx.changes, [])

    def test_legacy_upgrader_refreshes_installed_bundle_in_target_interpreter(self) -> None:
        os.makedirs(os.path.join(self.data_dir, "observability-stack"))
        backup = os.path.join(self.data_dir, "backups", "observability-v8-test")
        activation = SimpleNamespace(
            activated=True,
            already_v8=False,
            backup_directory=backup,
        )
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", return_value=object()),
            patch("defenseclaw.migrations.activate_v8_migration", return_value=activation),
            patch(
                "defenseclaw.migrations._run_observability_v8_bundle_upgrade_in_target",
                return_value={"ok": True, "installed": True, "degraded_errors": []},
            ) as refresh,
        ):
            _migrate_observability_v8(self.ctx)

        refresh.assert_called_once_with(self.data_dir, backup, "0.8.5")
        self.assertEqual(
            self.ctx.changes,
            [
                "refreshed local observability bundle for the target release",
                "activated observability configuration schema v8",
            ],
        )

    def test_current_upgrader_owns_bundle_phase_without_migration_duplicate(self) -> None:
        os.makedirs(os.path.join(self.data_dir, "observability-stack"))
        self.ctx.upgrade_handles_local_bundle = True
        refresh = Mock()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", return_value=object()),
            patch(
                "defenseclaw.migrations.activate_v8_migration",
                return_value=SimpleNamespace(activated=False, already_v8=True, backup_directory=None),
            ),
            patch("defenseclaw.migrations._run_observability_v8_bundle_upgrade_in_target", refresh),
        ):
            _migrate_observability_v8(self.ctx)

        refresh.assert_not_called()

    @unittest.skipIf(os.name != "posix", "descriptor-relative backup creation is POSIX-only")
    def test_retry_allocates_private_bundle_backup_directory(self) -> None:
        backup_root = os.path.join(self.data_dir, "backups")
        os.mkdir(backup_root, 0o700)
        os.chmod(backup_root, 0o700)

        directory = _allocate_observability_v8_bundle_backup(self.data_dir)

        self.assertEqual(os.path.dirname(directory), backup_root)
        self.assertEqual(stat.S_IMODE(os.stat(directory).st_mode), 0o700)

    def _write_gateway_pid(self, value: str = "4242\n") -> str:
        path = os.path.join(self.data_dir, "gateway.pid")
        with open(path, "w", encoding="ascii") as pid_file:
            pid_file.write(value)
        return path

    def test_live_gateway_pid_rejects_before_conversion(self) -> None:
        self._write_gateway_pid()
        convert = Mock()
        with (
            patch("defenseclaw.migrations.read_pid_file", return_value=4242),
            patch("defenseclaw.migrations.pid_alive", return_value=True),
            patch("defenseclaw.migrations.process_argv0_basename", return_value="defenseclaw-gateway"),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", convert),
        ):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _migrate_observability_v8(self.ctx)
        self.assertEqual(raised.exception.code, "gateway_not_quiesced")
        convert.assert_not_called()

    def test_verified_foreign_live_pid_does_not_block_quiesced_runner(self) -> None:
        self._write_gateway_pid()
        with (
            patch("defenseclaw.migrations.read_pid_file", return_value=4242),
            patch("defenseclaw.migrations.pid_alive", return_value=True),
            patch("defenseclaw.migrations.process_argv0_basename", return_value="sleep"),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", return_value=object()),
            patch(
                "defenseclaw.migrations.activate_v8_migration",
                return_value=SimpleNamespace(activated=False, already_v8=True),
            ),
        ):
            _migrate_observability_v8(self.ctx)

    def test_dead_pid_does_not_block_quiesced_runner(self) -> None:
        self._write_gateway_pid()
        with (
            patch("defenseclaw.migrations.read_pid_file", return_value=4242),
            patch("defenseclaw.migrations.pid_alive", return_value=False),
            patch("defenseclaw.migrations.process_argv0_basename") as basename,
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", return_value=object()),
            patch(
                "defenseclaw.migrations.activate_v8_migration",
                return_value=SimpleNamespace(activated=False, already_v8=True),
            ),
        ):
            _migrate_observability_v8(self.ctx)
        basename.assert_not_called()

    def test_malformed_or_unreadable_pid_is_unknown(self) -> None:
        self._write_gateway_pid("not-a-pid\n")
        with self.assertRaises(ObservabilityV8UpgradeMigrationError) as malformed:
            _migrate_observability_v8(self.ctx)
        self.assertEqual(malformed.exception.code, "gateway_quiescence_unknown")

        self._write_gateway_pid()
        with patch("defenseclaw.migrations.read_pid_file", side_effect=OSError("secret-pid-error")):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as unreadable:
                _migrate_observability_v8(self.ctx)
        self.assertEqual(unreadable.exception.code, "gateway_quiescence_unknown")
        self.assertNotIn("secret-pid-error", str(unreadable.exception))

    def test_live_pid_with_unknown_identity_is_unknown(self) -> None:
        self._write_gateway_pid()
        with (
            patch("defenseclaw.migrations.read_pid_file", return_value=4242),
            patch("defenseclaw.migrations.pid_alive", return_value=True),
            patch("defenseclaw.migrations.process_argv0_basename", return_value=None),
        ):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _migrate_observability_v8(self.ctx)
        self.assertEqual(raised.exception.code, "gateway_quiescence_unknown")

    def test_pid_liveness_failure_is_unknown_without_exposing_detail(self) -> None:
        self._write_gateway_pid()
        with (
            patch("defenseclaw.migrations.read_pid_file", return_value=4242),
            patch(
                "defenseclaw.migrations.pid_alive",
                side_effect=OSError("secret-liveness-detail"),
            ),
        ):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _migrate_observability_v8(self.ctx)
        self.assertEqual(raised.exception.code, "gateway_quiescence_unknown")
        self.assertNotIn("secret-liveness-detail", str(raised.exception))

    def test_pid_identity_failure_is_unknown_without_exposing_detail(self) -> None:
        self._write_gateway_pid()
        with (
            patch("defenseclaw.migrations.read_pid_file", return_value=4242),
            patch("defenseclaw.migrations.pid_alive", return_value=True),
            patch(
                "defenseclaw.migrations.process_argv0_basename",
                side_effect=OSError("secret-identity-detail"),
            ),
        ):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _migrate_observability_v8(self.ctx)
        self.assertEqual(raised.exception.code, "gateway_quiescence_unknown")
        self.assertNotIn("secret-identity-detail", str(raised.exception))

    def test_missing_environment_uses_ambient_snapshot(self) -> None:
        os.remove(self.environment_path)
        with patch.dict(os.environ, {"AMBIENT_ONLY": "present"}, clear=True):
            snapshot = _observability_v8_upgrade_environment(self.environment_path)
        self.assertEqual(snapshot, {"AMBIENT_ONLY": "present"})

    def test_windows_ambient_names_outside_v8_grammar_are_ignored(self) -> None:
        with patch.dict(
            os.environ,
            {
                "AMBIENT_ONLY": "present",
                "PROGRAMFILES(X86)": r"C:\Program Files (x86)",
                "COMMONPROGRAMFILES(X86)": r"C:\Program Files (x86)\Common Files",
            },
            clear=True,
        ):
            snapshot = _observability_v8_upgrade_environment(self.environment_path)

        self.assertEqual(
            snapshot,
            {
                "AMBIENT_ONLY": "present",
                "DOTENV_ONLY": "dotenv-value",
                "SHARED": "dotenv-loses",
            },
        )

    def test_malformed_environment_fails_without_exposing_value(self) -> None:
        secret = "malformed-secret-value"
        with open(self.environment_path, "w", encoding="utf-8") as environment_file:
            environment_file.write(f"not an assignment {secret}\n")
        with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
            _observability_v8_upgrade_environment(self.environment_path)
        self.assertEqual(raised.exception.code, "environment_read_failed")
        self.assertNotIn(secret, str(raised.exception))

    def test_environment_read_error_fails_value_safely(self) -> None:
        secret = "filesystem-secret"
        with patch("defenseclaw.migrations.os.open", side_effect=PermissionError(secret)):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _observability_v8_upgrade_environment(self.environment_path)
        self.assertEqual(raised.exception.code, "environment_read_failed")
        self.assertNotIn(secret, str(raised.exception))

    def test_environment_path_swap_is_rejected(self) -> None:
        metadata = os.stat(self.environment_path)
        swapped = SimpleNamespace(
            st_mode=metadata.st_mode,
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino + 1,
        )
        with patch("defenseclaw.migrations.os.fstat", return_value=swapped):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _observability_v8_upgrade_environment(self.environment_path)
        self.assertEqual(raised.exception.code, "environment_read_failed")

    @unittest.skipIf(os.name == "nt", "symlink creation requires platform-specific privileges on Windows")
    def test_environment_symlink_is_rejected(self) -> None:
        target = os.path.join(self.root.name, "secret-env")
        with open(target, "w", encoding="utf-8") as target_file:
            target_file.write("SECRET=do-not-read\n")
        os.remove(self.environment_path)
        os.symlink(target, self.environment_path)
        with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
            _observability_v8_upgrade_environment(self.environment_path)
        self.assertEqual(raised.exception.code, "environment_read_failed")

    def test_cursor_marks_only_after_activation_success_and_retries_failure(self) -> None:
        cursor_dir = os.path.join(self.root.name, "cursor-data")
        os.makedirs(cursor_dir)
        with open(os.path.join(cursor_dir, "config.yaml"), "wb") as config_file:
            config_file.write(b"config_version: 7\n")
        activation = Mock(
            side_effect=[
                V8ActivationError("activation_failed", "config_write"),
                SimpleNamespace(activated=True, already_v8=False),
            ]
        )
        with (
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", return_value=object()),
            patch("defenseclaw.migrations.activate_v8_migration", activation),
        ):
            first = run_migrations("0.8.4", "0.8.5", self.ctx.openclaw_home, cursor_dir)
            first_state = migration_state.load(cursor_dir)
            second = run_migrations("0.8.4", "0.8.5", self.ctx.openclaw_home, cursor_dir)
            second_state = migration_state.load(cursor_dir)

        self.assertEqual(first, 0)
        self.assertIsNotNone(first_state)
        self.assertFalse(migration_state.is_applied(first_state, "0.8.5"))
        self.assertEqual(second, 1)
        self.assertIsNotNone(second_state)
        self.assertTrue(migration_state.is_applied(second_state, "0.8.5"))
        self.assertEqual(activation.call_count, 2)

    def test_strict_required_migration_preserves_refusal_and_does_not_mark_cursor(self) -> None:
        cursor_dir = os.path.join(self.root.name, "strict-cursor-data")
        os.makedirs(cursor_dir)
        with open(os.path.join(cursor_dir, "config.yaml"), "wb") as config_file:
            config_file.write(b"config_version: 7\n")
        refusal = V8ActivationError(
            "candidate_validation_failed",
            "target_go_validation",
            field_path="$.observability.destinations[0].protocol",
            reason="[config_schema_invalid] unsupported protocol",
        )
        with (
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", return_value=object()),
            patch("defenseclaw.migrations.activate_v8_migration", side_effect=refusal),
            self.assertRaises(V8ActivationError) as raised,
        ):
            run_migrations(
                "0.8.0",
                "0.8.6",
                self.ctx.openclaw_home,
                cursor_dir,
                strict_required=("0.8.5",),
            )
        self.assertIs(raised.exception, refusal)
        state = migration_state.load(cursor_dir)
        self.assertIsNone(state)
        self.assertFalse(os.path.exists(os.path.join(cursor_dir, ".migration_state.json")))

    def test_strict_required_refusal_preserves_existing_cursor_bytes(self) -> None:
        cursor_dir = os.path.join(self.root.name, "strict-existing-cursor-data")
        os.makedirs(cursor_dir)
        with open(os.path.join(cursor_dir, "config.yaml"), "wb") as config_file:
            config_file.write(b"config_version: 7\n")
        state = migration_state.bootstrap(
            None,
            from_version="0.8.0",
            package_version="0.8.0",
            registry_versions=[version for version, _description, _migration in MIGRATIONS],
        )
        migration_state.save(cursor_dir, state)
        cursor_path = migration_state.state_path(cursor_dir)
        with open(cursor_path, "rb") as cursor_file:
            before = cursor_file.read()
        refusal = V8ActivationError("candidate_validation_failed", "target_go_validation")

        with (
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", return_value=object()),
            patch("defenseclaw.migrations.activate_v8_migration", side_effect=refusal),
            self.assertRaises(V8ActivationError),
        ):
            run_migrations(
                "0.8.0",
                "0.8.6",
                self.ctx.openclaw_home,
                cursor_dir,
                strict_required=("0.8.5",),
            )

        with open(cursor_path, "rb") as cursor_file:
            self.assertEqual(cursor_file.read(), before)

    def test_strict_same_version_success_persists_deferred_bootstrap(self) -> None:
        cursor_dir = os.path.join(self.root.name, "strict-same-version-data")
        os.makedirs(cursor_dir)
        required = tuple(version for version, _description, _migration in MIGRATIONS)

        applied = run_migrations(
            "0.8.6",
            "0.8.6",
            self.ctx.openclaw_home,
            cursor_dir,
            strict_required=required,
        )

        state = migration_state.load(cursor_dir)
        self.assertEqual(applied, 0)
        self.assertIsNotNone(state)
        self.assertTrue(all(migration_state.is_applied(state, version) for version in required))

    def test_strict_missing_requirement_refuses_before_cursor_persistence(self) -> None:
        cursor_dir = os.path.join(self.root.name, "strict-missing-requirement-data")
        os.makedirs(cursor_dir)

        with self.assertRaisesRegex(RuntimeError, "required migrations are missing: 9.9.9"):
            run_migrations(
                "0.8.6",
                "0.8.6",
                self.ctx.openclaw_home,
                cursor_dir,
                strict_required=("9.9.9",),
            )

        self.assertFalse(os.path.exists(migration_state.state_path(cursor_dir)))

    def test_strict_deferred_bootstrap_save_failure_is_fatal(self) -> None:
        cursor_dir = os.path.join(self.root.name, "strict-bootstrap-save-failure-data")
        os.makedirs(cursor_dir)
        required = tuple(version for version, _description, _migration in MIGRATIONS)

        with (
            patch("defenseclaw.migration_state.save", side_effect=OSError("synthetic write refusal")),
            self.assertRaisesRegex(OSError, "synthetic write refusal"),
        ):
            run_migrations(
                "0.8.6",
                "0.8.6",
                self.ctx.openclaw_home,
                cursor_dir,
                strict_required=required,
            )

        self.assertFalse(os.path.exists(migration_state.state_path(cursor_dir)))


class TestObservabilityV8CandidateFile(unittest.TestCase):
    def test_owner_only_candidate_is_removed_after_success(self) -> None:
        with tempfile.TemporaryDirectory() as data_dir:
            seen: list[str] = []

            def inspect(operation, **kwargs):
                path = kwargs["config_path"]
                seen.append(path)
                self.assertEqual(operation, "validate")
                with open(path, "rb") as candidate_file:
                    self.assertEqual(candidate_file.read(), b"config_version: 8\n")
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
                return SimpleNamespace(valid=True, config_version=8)

            with patch("defenseclaw.migrations.inspect_v8_config", side_effect=inspect):
                _validate_observability_v8_candidate(
                    b"config_version: 8\n",
                    {"SECRET": "value"},
                    data_dir=data_dir,
                )

            self.assertEqual(len(seen), 1)
            self.assertFalse(os.path.exists(seen[0]))

    def test_cleanup_preserves_original_validator_exception(self) -> None:
        with tempfile.TemporaryDirectory() as data_dir:
            seen: list[str] = []
            original = RuntimeError("validator failed")

            def inspect(_operation, **kwargs):
                seen.append(kwargs["config_path"])
                raise original

            with patch("defenseclaw.migrations.inspect_v8_config", side_effect=inspect):
                with self.assertRaises(RuntimeError) as raised:
                    _validate_observability_v8_candidate(
                        b"config_version: 8\n",
                        {},
                        data_dir=data_dir,
                    )

            self.assertIs(raised.exception, original)
            self.assertEqual(len(seen), 1)
            self.assertFalse(os.path.exists(seen[0]))

    def test_structured_target_refusal_preserves_safe_path_and_reason(self) -> None:
        with tempfile.TemporaryDirectory() as data_dir:
            secret = "must-not-be-rendered"
            refusal = ConfigInspectError(
                "safe diagnostic",
                field_path="$.observability.destinations[0].protocol",
                reason="[config_schema_invalid] unsupported protocol",
            )
            with patch("defenseclaw.migrations.inspect_v8_config", side_effect=refusal):
                with self.assertRaises(V8CandidateValidationError) as raised:
                    _validate_observability_v8_candidate(
                        b"config_version: 8\n",
                        {"SECRET": secret},
                        data_dir=data_dir,
                    )
            self.assertEqual(raised.exception.field_path, refusal.field_path)
            self.assertEqual(raised.exception.reason, refusal.reason)
            self.assertNotIn(secret, str(raised.exception))

    def test_genuine_cleanup_failure_replaces_validator_exception_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as data_dir:
            seen: list[str] = []

            def inspect(_operation, **kwargs):
                seen.append(kwargs["config_path"])
                raise RuntimeError("validator detail")

            with (
                patch("defenseclaw.migrations.inspect_v8_config", side_effect=inspect),
                patch("defenseclaw.migrations.os.remove", side_effect=PermissionError("cleanup detail")),
            ):
                with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                    _validate_observability_v8_candidate(
                        b"config_version: 8\n",
                        {},
                        data_dir=data_dir,
                    )

            self.assertEqual(raised.exception.code, "candidate_cleanup_failed")
            self.assertNotIn("validator detail", str(raised.exception))
            self.assertNotIn("cleanup detail", str(raised.exception))
            self.assertEqual(len(seen), 1)
            os.remove(seen[0])


if __name__ == "__main__":
    unittest.main()
