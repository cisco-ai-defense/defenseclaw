"""Focused production wiring tests for the observability-v8 upgrade migration."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import ANY, Mock, patch

import defenseclaw.observability.v8_activation as activation_module
from defenseclaw import migration_state
from defenseclaw.config_inspect import ConfigInspectError
from defenseclaw.migrations import (
    MIGRATIONS,
    MigrationContext,
    ObservabilityV8PreflightBinding,
    ObservabilityV8UpgradeMigrationError,
    _allocate_observability_v8_bundle_backup,
    _migrate_observability_v8,
    _observability_v8_upgrade_environment,
    _preflight_observability_v8,
    _run_observability_v8_bundle_upgrade_in_target,
    _valid_upgrade_mutation_token,
    _validate_observability_v8_candidate,
    preflight_observability_v8_upgrade,
    preflight_required_migrations,
    run_migrations,
)
from defenseclaw.observability.v8_activation import V8ActivationError, V8CandidateValidationError
from defenseclaw.observability.v8_config import MAX_SOURCE_BYTES
from defenseclaw.observability.v8_migration import V8MigrationError
from defenseclaw.upgrade_receipt import begin_upgrade_receipt


class TestObservabilityV8UpgradeMigration(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.TemporaryDirectory(prefix="defenseclaw-v8-upgrade-")
        self.root_path = os.path.realpath(self.root.name)
        self.data_dir = os.path.join(self.root_path, "active-data")
        os.makedirs(self.data_dir, mode=0o700)
        self.config_path = os.path.join(self.root_path, "operator-config.yaml")
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

    def _begin_verified_upgrade_receipt(self, target_version: str = "9.9.9") -> str:
        return os.fspath(
            begin_upgrade_receipt(
                self.data_dir,
                from_version="0.8.5",
                target_version=target_version,
                artifacts_verified=True,
            )
        )

    def test_target_bundle_subprocess_uses_isolated_python(self) -> None:
        observed: list[str] = []

        def complete(
            command: list[str],
            **_kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            observed.extend(command)
            with open(command[-1], "w", encoding="utf-8") as result_file:
                json.dump({"ok": True, "installed": False}, result_file)
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("defenseclaw.migrations.subprocess.run", side_effect=complete):
            result = _run_observability_v8_bundle_upgrade_in_target(
                self.data_dir,
                os.path.join(self.data_dir, "backups", "bundle"),
                "9.9.9",
            )

        self.assertEqual(result, {"ok": True, "installed": False})
        self.assertEqual(observed[:4], [sys.executable, "-I", "-B", "-c"])

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

    def test_read_only_preflight_uses_downloaded_target_and_changes_nothing(self) -> None:
        config_before = open(self.config_path, "rb").read()
        environment_before = open(self.environment_path, "rb").read()
        candidate_paths: list[str] = []
        migration = SimpleNamespace(
            candidate=b"config_version: 8\n",
            source_sha256="1" * 64,
            candidate_sha256="2" * 64,
            environment_dependencies=(SimpleNamespace(name="DOTENV_ONLY", present=True, value_sha256="3" * 64),),
            environment_edits=(
                SimpleNamespace(
                    name="MOVED_SECRET",
                    value="protected-value",
                    value_sha256="4" * 64,
                    operation="set_if_absent",
                ),
            ),
        )

        def inspect(operation, **kwargs):
            candidate_paths.append(kwargs["config_path"])
            self.assertEqual(operation, "validate")
            self.assertEqual(kwargs["gateway_binary"], "/staged/0.8.5/defenseclaw-gateway")
            self.assertEqual(kwargs["data_dir"], os.path.abspath(self.data_dir))
            self.assertEqual(kwargs["environment_overrides"]["DOTENV_ONLY"], "dotenv-value")
            self.assertEqual(kwargs["environment_overrides"]["MOVED_SECRET"], "protected-value")
            self.assertEqual(os.path.dirname(kwargs["config_path"]), self.root.name)
            with open(kwargs["config_path"], "rb") as candidate_file:
                self.assertEqual(candidate_file.read(), migration.candidate)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(os.stat(kwargs["config_path"]).st_mode), 0o600)
            return SimpleNamespace(valid=True, config_version=8)

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", return_value=migration) as convert,
            patch("defenseclaw.migrations.inspect_v8_config", side_effect=inspect),
            patch("defenseclaw.migrations.preflight_v8_migration_activation") as activation_preflight,
            patch("defenseclaw.migrations.activate_v8_migration") as activate,
        ):
            binding = preflight_observability_v8_upgrade(
                data_dir=self.data_dir,
                config_path=self.config_path,
                gateway_binary="/staged/0.8.5/defenseclaw-gateway",
                candidate_directory=self.root.name,
            )

        convert.assert_called_once()
        activation_preflight.assert_called_once_with(
            migration,
            data_dir=os.path.abspath(self.data_dir),
            config_path=os.path.abspath(self.config_path),
            environment_path=os.path.abspath(self.environment_path),
            tighten_legacy_backup_root=True,
            environment=ANY,
        )
        activate.assert_not_called()
        self.assertIsNotNone(binding)
        self.assertEqual(binding.source_sha256, "1" * 64)
        self.assertEqual(binding.candidate_sha256, "2" * 64)
        self.assertEqual(open(self.config_path, "rb").read(), config_before)
        self.assertEqual(open(self.environment_path, "rb").read(), environment_before)
        self.assertEqual(len(candidate_paths), 1)
        self.assertFalse(os.path.exists(candidate_paths[0]))

    def test_preflight_binding_changes_when_source_changes(self) -> None:
        def convert(source, _environment, **_kwargs):
            source_digest = hashlib.sha256(source).hexdigest()
            return SimpleNamespace(
                candidate=b"config_version: 8\n",
                source_sha256=source_digest,
                candidate_sha256="2" * 64,
                environment_dependencies=(),
                environment_edits=(),
            )

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", side_effect=convert),
            patch(
                "defenseclaw.migrations.inspect_v8_config",
                return_value=SimpleNamespace(valid=True, config_version=8),
            ),
            patch("defenseclaw.migrations.preflight_v8_migration_activation"),
        ):
            before = preflight_observability_v8_upgrade(
                data_dir=self.data_dir,
                config_path=self.config_path,
                gateway_binary="/staged/0.8.5/defenseclaw-gateway",
                candidate_directory=self.root.name,
            )
            with open(self.config_path, "ab") as config_file:
                config_file.write(b"# concurrent operator edit\n")
            after = preflight_observability_v8_upgrade(
                data_dir=self.data_dir,
                config_path=self.config_path,
                gateway_binary="/staged/0.8.5/defenseclaw-gateway",
                candidate_directory=self.root.name,
            )

        self.assertNotEqual(before, after)

    def test_read_only_preflight_rejects_unmigratable_source_before_validation(self) -> None:
        config_before = open(self.config_path, "rb").read()
        environment_before = open(self.environment_path, "rb").read()
        failure = V8MigrationError(
            "invalid_endpoint",
            "$.otel.destinations[1].endpoint",
            "correct the endpoint and retry",
            source_name=self.config_path,
        )
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("defenseclaw.migrations.convert_v7_observability_to_v8", side_effect=failure),
            patch("defenseclaw.migrations.inspect_v8_config") as inspect,
        ):
            with self.assertRaises(V8MigrationError) as raised:
                preflight_observability_v8_upgrade(
                    data_dir=self.data_dir,
                    config_path=self.config_path,
                    gateway_binary="/staged/0.8.5/defenseclaw-gateway",
                    candidate_directory=self.root.name,
                )

        self.assertIs(raised.exception, failure)
        inspect.assert_not_called()
        self.assertEqual(open(self.config_path, "rb").read(), config_before)
        self.assertEqual(open(self.environment_path, "rb").read(), environment_before)

    def _real_preflight_binding(self) -> ObservabilityV8PreflightBinding:
        with open(self.config_path, "wb") as config_file:
            config_file.write(f"config_version: 7\ndata_dir: {self.data_dir}\n".encode())
        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "defenseclaw.migrations.inspect_v8_config",
                return_value=SimpleNamespace(valid=True, config_version=8),
            ),
        ):
            binding = preflight_observability_v8_upgrade(
                data_dir=self.data_dir,
                config_path=self.config_path,
                gateway_binary="/staged/0.8.5/defenseclaw-gateway",
                candidate_directory=self.root.name,
            )
        self.assertIsInstance(binding, ObservabilityV8PreflightBinding)
        return binding

    def _target_binding_environment(
        self,
        binding: ObservabilityV8PreflightBinding | None,
    ) -> dict[str, str]:
        return {
            "DEFENSECLAW_UPGRADE_MUTATION_TOKEN": "a" * 32,
            "DEFENSECLAW_OBSERVABILITY_V8_PREFLIGHT_BINDING": json.dumps(
                None if binding is None else binding.to_payload(),
                sort_keys=True,
                separators=(",", ":"),
            ),
        }

    def test_preflight_binding_payload_round_trip_and_strict_schema(self) -> None:
        binding = ObservabilityV8PreflightBinding(
            source_sha256="1" * 64,
            candidate_sha256="2" * 64,
            environment_file_present=True,
            environment_file_sha256="3" * 64,
            environment_dependencies_sha256="4" * 64,
            environment_edits_sha256="5" * 64,
        )
        payload = binding.to_payload()
        self.assertEqual(ObservabilityV8PreflightBinding.from_payload(payload), binding)

        malformed = (
            None,
            {**payload, "extra": "value"},
            {**payload, "schema_version": 2},
            {**payload, "environment_file_present": 1},
            {**payload, "source_sha256": "A" * 64},
            {**payload, "candidate_sha256": "2" * 63},
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate):
                with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                    ObservabilityV8PreflightBinding.from_payload(candidate)
                self.assertEqual(raised.exception.code, "preflight_binding_invalid")

    def test_target_accepts_exact_preflight_binding_before_activation(self) -> None:
        binding = self._real_preflight_binding()
        activate = Mock(return_value=SimpleNamespace(activated=True, already_v8=False))
        with (
            patch.dict(
                os.environ,
                self._target_binding_environment(binding),
                clear=True,
            ),
            patch("defenseclaw.migrations.activate_v8_migration", activate),
        ):
            _migrate_observability_v8(self.ctx)

        activate.assert_called_once()
        self.assertEqual(self.ctx.changes, ["activated observability configuration schema v8"])

    def test_target_rejects_config_drift_before_activation(self) -> None:
        binding = self._real_preflight_binding()
        with open(self.config_path, "ab") as config_file:
            config_file.write(b"# concurrent edit\n")
        activate = Mock()
        with (
            patch.dict(
                os.environ,
                self._target_binding_environment(binding),
                clear=True,
            ),
            patch("defenseclaw.migrations.activate_v8_migration", activate),
        ):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _migrate_observability_v8(self.ctx)

        self.assertEqual(raised.exception.code, "preflight_source_changed")
        activate.assert_not_called()

    def test_target_rejects_dotenv_byte_drift_before_activation(self) -> None:
        binding = self._real_preflight_binding()
        with open(self.environment_path, "ab") as environment_file:
            environment_file.write(b"# comment-only concurrent edit\n")
        activate = Mock()
        with (
            patch.dict(
                os.environ,
                self._target_binding_environment(binding),
                clear=True,
            ),
            patch("defenseclaw.migrations.activate_v8_migration", activate),
        ):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _migrate_observability_v8(self.ctx)

        self.assertEqual(raised.exception.code, "preflight_source_changed")
        activate.assert_not_called()

    def test_target_rejects_missing_to_present_config_drift(self) -> None:
        os.unlink(self.config_path)
        with patch.dict(os.environ, {}, clear=True):
            binding = preflight_observability_v8_upgrade(
                data_dir=self.data_dir,
                config_path=self.config_path,
                gateway_binary="/staged/0.8.5/defenseclaw-gateway",
                candidate_directory=self.root.name,
            )
        self.assertIsNone(binding)
        with open(self.config_path, "wb") as config_file:
            config_file.write(b"config_version: 7\n")
        activate = Mock()
        with (
            patch.dict(
                os.environ,
                self._target_binding_environment(binding),
                clear=True,
            ),
            patch("defenseclaw.migrations.activate_v8_migration", activate),
        ):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _migrate_observability_v8(self.ctx)
        self.assertEqual(raised.exception.code, "preflight_source_changed")
        activate.assert_not_called()

    def test_target_rejects_present_to_missing_config_drift(self) -> None:
        binding = self._real_preflight_binding()
        os.unlink(self.config_path)
        activate = Mock()
        with (
            patch.dict(
                os.environ,
                self._target_binding_environment(binding),
                clear=True,
            ),
            patch("defenseclaw.migrations.activate_v8_migration", activate),
        ):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _migrate_observability_v8(self.ctx)
        self.assertEqual(raised.exception.code, "preflight_source_changed")
        activate.assert_not_called()

    def test_target_mutation_token_requires_preflight_binding(self) -> None:
        activate = Mock()
        with (
            patch.dict(
                os.environ,
                {"DEFENSECLAW_UPGRADE_MUTATION_TOKEN": "a" * 32},
                clear=True,
            ),
            patch("defenseclaw.migrations.activate_v8_migration", activate),
        ):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _migrate_observability_v8(self.ctx)
        self.assertEqual(raised.exception.code, "preflight_binding_missing")
        activate.assert_not_called()

    def test_malformed_target_mutation_token_is_not_a_hard_cut_capability(self) -> None:
        for token in ("a" * 31, "A" * 32, "g" * 32):
            with (
                self.subTest(token=token),
                patch.dict(
                    os.environ,
                    {"DEFENSECLAW_UPGRADE_MUTATION_TOKEN": token},
                    clear=True,
                ),
            ):
                self.assertFalse(_valid_upgrade_mutation_token())

    @unittest.skipIf(os.name == "nt", "POSIX backup-root mode assertion")
    def test_target_rejects_config_changed_after_real_locks_before_any_activation_mutation(
        self,
    ) -> None:
        self._assert_post_lock_preflight_binding_refusal("config")

    @unittest.skipIf(os.name == "nt", "POSIX backup-root mode assertion")
    def test_target_rejects_dotenv_comment_changed_after_real_locks_before_any_activation_mutation(
        self,
    ) -> None:
        self._assert_post_lock_preflight_binding_refusal("dotenv-comment")

    @unittest.skipIf(os.name == "nt", "POSIX backup-root mode assertion")
    def test_target_rejects_dotenv_created_after_real_locks_before_any_activation_mutation(
        self,
    ) -> None:
        os.unlink(self.environment_path)
        self._assert_post_lock_preflight_binding_refusal("dotenv-create")

    def _assert_post_lock_preflight_binding_refusal(self, mutation: str) -> None:
        """Inject an uncooperative source write after both real locks exist."""

        backup_root = os.path.join(self.data_dir, "backups")
        os.mkdir(backup_root, mode=0o755)
        os.chmod(backup_root, 0o755)
        binding = self._real_preflight_binding()
        config_before = open(self.config_path, "rb").read()
        environment_before = open(self.environment_path, "rb").read() if os.path.exists(self.environment_path) else None
        config_mutation = b"# post-lock uncooperative config edit\n"
        environment_mutation = b"# post-lock comment-only dotenv edit\n"
        created_environment = b"POST_LOCK_CREATED=1\n"
        real_locks = activation_module._migration_update_locks

        @contextmanager
        def mutate_after_real_locks(active_config: str, active_environment: str):
            with real_locks(active_config, active_environment):
                if mutation == "config":
                    with open(active_config, "ab") as config_file:
                        config_file.write(config_mutation)
                elif mutation == "dotenv-comment":
                    with open(active_environment, "ab") as environment_file:
                        environment_file.write(environment_mutation)
                elif mutation == "dotenv-create":
                    with open(active_environment, "wb") as environment_file:
                        environment_file.write(created_environment)
                else:  # pragma: no cover - helper callers are fixed above.
                    raise AssertionError(f"unknown post-lock mutation: {mutation}")
                yield

        validator = Mock()
        with (
            patch.dict(
                os.environ,
                self._target_binding_environment(binding),
                clear=True,
            ),
            patch.object(
                activation_module,
                "_migration_update_locks",
                mutate_after_real_locks,
            ),
            patch(
                "defenseclaw.migrations._validate_observability_v8_candidate",
                validator,
            ),
            patch.object(
                activation_module,
                "_tighten_existing_backup_root",
                wraps=activation_module._tighten_existing_backup_root,
            ) as tighten_backup_root,
            patch.object(
                activation_module,
                "_create_recovery_backup",
                wraps=activation_module._create_recovery_backup,
            ) as create_backup,
            patch.object(
                activation_module,
                "_atomic_replace",
                wraps=activation_module._atomic_replace,
            ) as atomic_replace,
        ):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                _migrate_observability_v8(self.ctx)

        self.assertEqual(raised.exception.code, "preflight_source_changed")
        validator.assert_not_called()
        tighten_backup_root.assert_not_called()
        create_backup.assert_not_called()
        atomic_replace.assert_not_called()
        self.assertEqual(self.ctx.changes, [])
        self.assertEqual(stat.S_IMODE(os.stat(backup_root).st_mode), 0o755)
        self.assertEqual(os.listdir(backup_root), [])
        expected_config = config_before + (config_mutation if mutation == "config" else b"")
        self.assertEqual(open(self.config_path, "rb").read(), expected_config)
        if mutation == "dotenv-comment":
            assert environment_before is not None
            expected_environment = environment_before + environment_mutation
        elif mutation == "dotenv-create":
            expected_environment = created_environment
        else:
            expected_environment = environment_before
        self.assertEqual(open(self.environment_path, "rb").read(), expected_environment)

    @unittest.skipIf(os.name == "nt", "symlink creation requires platform-specific privileges")
    def test_preflight_rejects_symlink_config_without_reading_target(self) -> None:
        target = os.path.join(self.root.name, "sensitive-target")
        with open(target, "wb") as target_file:
            target_file.write(b"config_version: 7\nsecret: do-not-read\n")
        os.unlink(self.config_path)
        os.symlink(target, self.config_path)
        convert = Mock()
        with patch("defenseclaw.migrations.convert_v7_observability_to_v8", convert):
            with self.assertRaises(ObservabilityV8UpgradeMigrationError) as raised:
                preflight_observability_v8_upgrade(
                    data_dir=self.data_dir,
                    config_path=self.config_path,
                    gateway_binary="/staged/0.8.5/defenseclaw-gateway",
                    candidate_directory=self.root.name,
                )
        self.assertEqual(raised.exception.code, "source_read_failed")
        convert.assert_not_called()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is POSIX-only")
    def test_preflight_rejects_nonregular_config_without_blocking(self) -> None:
        os.unlink(self.config_path)
        os.mkfifo(self.config_path)
        probe = """
import sys
from unittest.mock import Mock, patch

from defenseclaw.migrations import (
    ObservabilityV8UpgradeMigrationError,
    preflight_observability_v8_upgrade,
)

convert = Mock()
try:
    with patch("defenseclaw.migrations.convert_v7_observability_to_v8", convert):
        preflight_observability_v8_upgrade(
            data_dir=sys.argv[1],
            config_path=sys.argv[2],
            gateway_binary="/staged/0.8.5/defenseclaw-gateway",
            candidate_directory=sys.argv[3],
        )
except ObservabilityV8UpgradeMigrationError as error:
    if error.code != "source_read_failed":
        raise AssertionError(f"unexpected error code: {error.code}") from error
else:
    raise AssertionError("non-regular config was accepted")
convert.assert_not_called()
"""
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    probe,
                    self.data_dir,
                    self.config_path,
                    self.root.name,
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.fail("preflight blocked while inspecting a FIFO config")
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"child preflight failed:\n{completed.stdout}\n{completed.stderr}",
        )

    def test_preflight_large_source_is_bounded_and_reports_source_limit(self) -> None:
        with open(self.config_path, "wb") as config_file:
            config_file.write(b"x" * (MAX_SOURCE_BYTES + 2))
        inspect = Mock()
        with patch("defenseclaw.migrations.inspect_v8_config", inspect):
            with self.assertRaises(V8MigrationError) as raised:
                preflight_observability_v8_upgrade(
                    data_dir=self.data_dir,
                    config_path=self.config_path,
                    gateway_binary="/staged/0.8.5/defenseclaw-gateway",
                    candidate_directory=self.root.name,
                )
        self.assertEqual(raised.exception.code, "source_too_large")
        inspect.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX permission-mode assertion")
    def test_preflight_rejects_world_readable_dotenv_before_any_mutation(self) -> None:
        secret = "pre-stop-secret-must-not-leak"
        source = f"""config_version: 7
data_dir: {self.data_dir}
audit_sinks:
  - name: splunk
    kind: splunk_hec
    enabled: true
    splunk_hec:
      endpoint: https://splunk.example.test/services/collector
      token: {secret}
""".encode()
        with open(self.config_path, "wb") as config_file:
            config_file.write(source)
        os.chmod(self.environment_path, 0o644)
        environment_before = open(self.environment_path, "rb").read()
        inspect = Mock(return_value=SimpleNamespace(valid=True, config_version=8))

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("defenseclaw.migrations.inspect_v8_config", inspect),
        ):
            with self.assertRaises(V8ActivationError) as raised:
                preflight_observability_v8_upgrade(
                    data_dir=self.data_dir,
                    config_path=self.config_path,
                    gateway_binary="/staged/0.8.5/defenseclaw-gateway",
                    candidate_directory=self.root.name,
                )

        self.assertEqual(raised.exception.code, "environment_permissions_unsafe")
        self.assertNotIn(secret, str(raised.exception))
        self.assertEqual(open(self.config_path, "rb").read(), source)
        self.assertEqual(open(self.environment_path, "rb").read(), environment_before)
        self.assertEqual(stat.S_IMODE(os.stat(self.environment_path).st_mode), 0o644)
        self.assertFalse(os.path.exists(os.path.join(self.data_dir, "backups")))

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
            self.assertNotIn("BASH_FUNC_which%%", environment)
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
                {
                    "SHARED": "ambient-wins",
                    "AMBIENT_ONLY": "ambient-value",
                    "BASH_FUNC_which%%": "() { :; }",
                },
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

        refresh.assert_called_once_with(
            self.data_dir,
            backup,
            "0.8.5",
            restart_intent_receipt=None,
        )
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

    def test_immutable_v8_controller_repairs_bundle_after_noop_future_upgrade(self) -> None:
        os.makedirs(os.path.join(self.data_dir, "observability-stack"))
        receipt_path = self._begin_verified_upgrade_receipt()
        with (
            patch.dict(
                os.environ,
                {"DEFENSECLAW_UPGRADE_MUTATION_TOKEN": ""},
                clear=True,
            ),
            patch(
                "defenseclaw.migrations._allocate_observability_v8_bundle_backup",
                return_value=os.path.join(self.data_dir, "backups", "bundle"),
            ),
            patch(
                "defenseclaw.migrations._run_observability_v8_bundle_upgrade_in_target",
                return_value={"installed": True, "degraded_errors": []},
            ) as refresh,
        ):
            count = run_migrations(
                "0.8.5",
                "9.9.9",
                self.ctx.openclaw_home,
                self.data_dir,
                upgrade_handles_local_bundle=True,
            )

        self.assertEqual(count, 0)
        refresh.assert_called_once()
        self.assertEqual(refresh.call_args.args[0], self.data_dir)
        self.assertEqual(refresh.call_args.args[2], "9.9.9")
        self.assertEqual(refresh.call_args.kwargs["restart_intent_receipt"], receipt_path)

    def test_immutable_v8_controller_requires_durable_bundle_recovery_authority(self) -> None:
        os.makedirs(os.path.join(self.data_dir, "observability-stack"))
        with (
            patch.dict(
                os.environ,
                {"DEFENSECLAW_UPGRADE_MUTATION_TOKEN": ""},
                clear=True,
            ),
            patch("defenseclaw.migrations._run_observability_v8_bundle_upgrade_in_target") as refresh,
            self.assertRaisesRegex(
                ObservabilityV8UpgradeMigrationError,
                "local_bundle_receipt_missing",
            ),
        ):
            run_migrations(
                "0.8.5",
                "9.9.9",
                self.ctx.openclaw_home,
                self.data_dir,
                upgrade_handles_local_bundle=True,
            )

        refresh.assert_not_called()

    def test_immutable_v8_controller_skips_receipt_when_no_bundle_is_installed(self) -> None:
        with (
            patch.dict(
                os.environ,
                {"DEFENSECLAW_UPGRADE_MUTATION_TOKEN": ""},
                clear=True,
            ),
            patch("defenseclaw.migrations._run_observability_v8_bundle_upgrade_in_target") as refresh,
        ):
            count = run_migrations(
                "0.8.5",
                "9.9.9",
                self.ctx.openclaw_home,
                self.data_dir,
                upgrade_handles_local_bundle=True,
            )

        self.assertEqual(count, 0)
        refresh.assert_not_called()

    def test_immutable_controller_defers_bundle_refresh_after_future_migration_failure(self) -> None:
        os.makedirs(os.path.join(self.data_dir, "observability-stack"))

        def fail_future_migration(_ctx: MigrationContext) -> None:
            raise RuntimeError("future migration failed")

        with (
            patch.dict(
                os.environ,
                {"DEFENSECLAW_UPGRADE_MUTATION_TOKEN": ""},
                clear=True,
            ),
            patch(
                "defenseclaw.migrations.MIGRATIONS",
                [("9.9.9", "future migration", fail_future_migration)],
            ),
            patch("defenseclaw.migrations._run_observability_v8_bundle_upgrade_in_target") as refresh,
        ):
            count = run_migrations(
                "0.8.5",
                "9.9.9",
                self.ctx.openclaw_home,
                self.data_dir,
                upgrade_handles_local_bundle=True,
            )

        self.assertEqual(count, 0)
        refresh.assert_not_called()

    def test_capable_controller_suppresses_target_bundle_fallback(self) -> None:
        os.makedirs(os.path.join(self.data_dir, "observability-stack"))
        with (
            patch.dict(
                os.environ,
                {"DEFENSECLAW_UPGRADE_MUTATION_TOKEN": ""},
                clear=True,
            ),
            patch("defenseclaw.migrations._run_observability_v8_bundle_upgrade_in_target") as refresh,
        ):
            count = run_migrations(
                "0.8.5",
                "9.9.9",
                self.ctx.openclaw_home,
                self.data_dir,
                upgrade_handles_local_bundle=True,
                controller_owns_local_bundle_transaction=True,
            )

        self.assertEqual(count, 0)
        refresh.assert_not_called()

    def test_controller_bundle_ownership_is_effective_migration_context_capability(self) -> None:
        observed: list[bool] = []

        def capture_context(ctx: MigrationContext) -> None:
            observed.append(ctx.upgrade_handles_local_bundle)

        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "defenseclaw.migrations.MIGRATIONS",
                [("9.9.9", "future migration", capture_context)],
            ),
            patch("defenseclaw.migrations._run_observability_v8_bundle_upgrade_in_target") as refresh,
        ):
            count = run_migrations(
                "0.8.5",
                "9.9.9",
                self.ctx.openclaw_home,
                self.data_dir,
                upgrade_handles_local_bundle=False,
                controller_owns_local_bundle_transaction=True,
            )

        self.assertEqual(count, 1)
        self.assertEqual(observed, [True])
        refresh.assert_not_called()

    def test_hard_cut_mutation_token_suppresses_target_bundle_fallback(self) -> None:
        os.makedirs(os.path.join(self.data_dir, "observability-stack"))
        with (
            patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_UPGRADE_MUTATION_TOKEN": "a" * 32,
                    "DEFENSECLAW_OBSERVABILITY_V8_PREFLIGHT_BINDING": "null",
                },
                clear=True,
            ),
            patch("defenseclaw.migrations._run_observability_v8_bundle_upgrade_in_target") as refresh,
        ):
            count = run_migrations(
                "0.8.5",
                "9.9.9",
                self.ctx.openclaw_home,
                self.data_dir,
                upgrade_handles_local_bundle=True,
            )

        self.assertEqual(count, 0)
        refresh.assert_not_called()

    def test_unpaired_ambient_mutation_token_does_not_suppress_bundle_repair(self) -> None:
        os.makedirs(os.path.join(self.data_dir, "observability-stack"))
        receipt_path = self._begin_verified_upgrade_receipt()
        with (
            patch.dict(
                os.environ,
                {"DEFENSECLAW_UPGRADE_MUTATION_TOKEN": "a" * 32},
                clear=True,
            ),
            patch(
                "defenseclaw.migrations._allocate_observability_v8_bundle_backup",
                return_value=os.path.join(self.data_dir, "backups", "bundle"),
            ),
            patch(
                "defenseclaw.migrations._run_observability_v8_bundle_upgrade_in_target",
                return_value={"installed": True, "degraded_errors": []},
            ) as refresh,
        ):
            count = run_migrations(
                "0.8.5",
                "9.9.9",
                self.ctx.openclaw_home,
                self.data_dir,
                upgrade_handles_local_bundle=True,
            )

        self.assertEqual(count, 0)
        refresh.assert_called_once()
        self.assertEqual(refresh.call_args.kwargs["restart_intent_receipt"], receipt_path)

    def test_malformed_hard_cut_binding_does_not_grant_bundle_custody(self) -> None:
        os.makedirs(os.path.join(self.data_dir, "observability-stack"))
        receipt_path = self._begin_verified_upgrade_receipt()
        with (
            patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_UPGRADE_MUTATION_TOKEN": "a" * 32,
                    "DEFENSECLAW_OBSERVABILITY_V8_PREFLIGHT_BINDING": "{}",
                },
                clear=True,
            ),
            patch(
                "defenseclaw.migrations._allocate_observability_v8_bundle_backup",
                return_value=os.path.join(self.data_dir, "backups", "bundle"),
            ),
            patch(
                "defenseclaw.migrations._run_observability_v8_bundle_upgrade_in_target",
                return_value={"installed": True, "degraded_errors": []},
            ) as refresh,
        ):
            count = run_migrations(
                "0.8.5",
                "9.9.9",
                self.ctx.openclaw_home,
                self.data_dir,
                upgrade_handles_local_bundle=True,
            )

        self.assertEqual(count, 0)
        refresh.assert_called_once()
        self.assertEqual(refresh.call_args.kwargs["restart_intent_receipt"], receipt_path)

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

    def test_ambient_snapshot_ignores_unreferenceable_shell_function_names(self) -> None:
        os.remove(self.environment_path)
        with patch.dict(
            os.environ,
            {
                "AMBIENT_ONLY": "present",
                "BASH_FUNC_which%%": "() { :; }",
            },
            clear=True,
        ):
            snapshot = _observability_v8_upgrade_environment(self.environment_path)
        self.assertEqual(snapshot, {"AMBIENT_ONLY": "present"})

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
