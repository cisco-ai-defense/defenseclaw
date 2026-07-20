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

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace
from typing import Any

import defenseclaw.observability.v8_activation as activation_module
import pytest
from defenseclaw import windows_acl
from defenseclaw.observability.v8_activation import (
    V8ActivationError,
    V8ActivationRollbackError,
    V8CandidateValidationError,
    activate_v8_migration,
    resolve_active_config_path,
)
from defenseclaw.observability.v8_migration import (
    EnvironmentDependency,
    EnvironmentEdit,
    EnvironmentReference,
    V8MigrationResult,
    V8MigrationSummary,
)

POSIX_PERMISSION_CONTRACT = pytest.mark.skipif(
    os.name == "nt",
    reason="POSIX uid/gid/mode contract; native Windows owner/DACL coverage lives in the Windows activation suites",
)
POSIX_TRANSACTION_INJECTION = pytest.mark.skipif(
    os.name == "nt",
    reason="injects the POSIX descriptor/rename transaction; native Windows transaction coverage is separate",
)


@pytest.fixture(autouse=True)
def _private_creation_umask() -> object:
    """Make success fixtures private independent of the host login umask.

    Tests that exercise unsafe parent/leaf permissions explicitly chmod their
    fixture after creation. Without this guard, a Linux host using umask 0002
    accidentally turns every ordinary success fixture into the unsafe-parent
    case before the intended assertion is reached.
    """

    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _summary(*, source_version: int = 7, destination_version: int = 8) -> V8MigrationSummary:
    return V8MigrationSummary(
        source_version=source_version,
        destination_version=destination_version,
        otlp_destinations=0,
        audit_destinations=0,
        local_destinations=0,
        environment_edits=0,
        redaction_intent="unchanged",
        judge_body_retention="unchanged",
        local_observability="unchanged",
    )


def _migration(
    source: bytes,
    candidate: bytes,
    *,
    edits: tuple[EnvironmentEdit, ...] = (),
    already_v8: bool = False,
    effective_data_dir: str = "/var/lib/defenseclaw",
) -> V8MigrationResult:
    return V8MigrationResult(
        candidate=candidate,
        source_sha256=_sha256(source),
        candidate_sha256=_sha256(candidate),
        changed=candidate != source or bool(edits),
        already_v8=already_v8,
        effective_data_dir=effective_data_dir,
        warnings=(),
        environment_edits=edits,
        summary=_summary(
            source_version=8 if already_v8 else 7,
            destination_version=8,
        ),
    )


def _edit(
    name: str,
    value: str,
    *,
    destination: str = "fixture-http",
    path: tuple[str, ...] = ("headers", "X-Fixture", "env"),
) -> EnvironmentEdit:
    return EnvironmentEdit(
        name=name,
        value=value,
        value_sha256=_sha256(value.encode("utf-8")),
        references=(EnvironmentReference(destination=destination, path=path),),
    )


def _candidate_with_header_reference(candidate: bytes, header: str, environment_name: str) -> bytes:
    marker = b"          env: DEFENSECLAW_MIGRATED_HEADER\r\n"
    addition = f"        {header}:\r\n          env: {environment_name}\r\n".encode()
    assert marker in candidate
    return candidate.replace(marker, marker + addition, 1)


def _fixture(tmp_path: Path, *, with_environment: bool = True) -> dict[str, Any]:
    data_dir = tmp_path / "data"
    config_dir = tmp_path / "managed config"
    data_dir.mkdir(parents=True)
    config_dir.mkdir(parents=True)
    config_path = config_dir / "custom.yaml"
    environment_path = data_dir / ".env"
    source = b"# operator guide\r\nconfig_version: 7\r\ncustom: keep\r\n"
    candidate = (
        b"# operator guide\r\nconfig_version: 8\r\ncustom: keep\r\n"
        b"observability:\r\n  destinations:\r\n    - name: fixture-http\r\n"
        b"      kind: http_jsonl\r\n      headers:\r\n        X-Fixture:\r\n"
        b"          env: DEFENSECLAW_MIGRATED_HEADER\r\n"
    )
    config_path.write_bytes(source)
    os.chmod(config_path, 0o640)
    environment = b"# curated\r\nEXISTING='keep me'\r\n" if with_environment else None
    if environment is not None:
        environment_path.write_bytes(environment)
        os.chmod(environment_path, 0o600)
    secret = "token with spaces # and ' quote"
    edit = _edit("DEFENSECLAW_MIGRATED_HEADER", secret)
    return {
        "data_dir": data_dir,
        "config_path": config_path,
        "environment_path": environment_path,
        "source": source,
        "candidate": candidate,
        "environment": environment,
        "secret": secret,
        "edit": edit,
        "migration": _migration(source, candidate, edits=(edit,), effective_data_dir=str(data_dir)),
    }


def _validator(expected_candidate: bytes, expected_secret: str):
    def validate(candidate: bytes, environment: object) -> None:
        assert candidate == expected_candidate
        assert repr(environment) == "<protected environment: 1 entries>"
        assert environment["DEFENSECLAW_MIGRATED_HEADER"] == expected_secret  # type: ignore[index]

    return validate


def test_resolve_active_source_honors_exact_config_override(tmp_path: Path) -> None:
    custom = tmp_path / "custom" / "defenseclaw.yaml"
    resolved = resolve_active_config_path(
        data_dir=tmp_path / "ignored",
        environment={"DEFENSECLAW_CONFIG": str(custom)},
    )
    assert resolved == str(custom)

    home = tmp_path / "home"
    resolved = resolve_active_config_path(environment={"DEFENSECLAW_HOME": str(home)})
    assert resolved == str(home / "config.yaml")


def test_explicit_environment_snapshot_preserves_sudo_invoking_user_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        import pwd
    except ImportError:
        pytest.skip("sudo home resolution is POSIX-only")
    invoking_home = tmp_path / "invoking-user"
    data_dir = invoking_home / ".defenseclaw"
    data_dir.mkdir(parents=True)
    (data_dir / "config.yaml").write_text("config_version: 7\n")
    monkeypatch.setattr(activation_module.os, "getuid", lambda: 0)
    monkeypatch.setattr(
        pwd,
        "getpwnam",
        lambda _user: SimpleNamespace(pw_dir=str(invoking_home)),
    )

    resolved = resolve_active_config_path(environment={"SUDO_USER": "invoking"})

    assert resolved == str(data_dir / "config.yaml")


def test_activation_preserves_custom_paths_modes_crlf_and_creates_private_backup(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    config_mode = stat.S_IMODE(fixture["config_path"].stat().st_mode)
    environment_mode = stat.S_IMODE(fixture["environment_path"].stat().st_mode)
    config_security = windows_acl.capture_path(str(fixture["config_path"])) if os.name == "nt" else None
    environment_security = (
        windows_acl.capture_path(str(fixture["environment_path"])) if os.name == "nt" else None
    )
    result = activate_v8_migration(
        fixture["migration"],
        validator=_validator(fixture["candidate"], fixture["secret"]),
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
    )

    assert result.activated
    assert not result.already_v8
    assert result.config_path == str(fixture["config_path"])
    assert result.environment_path == str(fixture["environment_path"])
    assert fixture["config_path"].read_bytes() == fixture["candidate"]
    assert stat.S_IMODE(fixture["config_path"].stat().st_mode) == config_mode
    environment = fixture["environment_path"].read_bytes()
    assert environment.startswith(fixture["environment"])
    assert b"\r\nDEFENSECLAW_MIGRATED_HEADER='" in environment
    assert environment.endswith(b"'\r\n")
    assert stat.S_IMODE(fixture["environment_path"].stat().st_mode) == environment_mode
    if os.name == "nt":
        assert windows_acl.capture_path(str(fixture["config_path"])) == config_security
        assert windows_acl.capture_path(str(fixture["environment_path"])) == environment_security

    backup = Path(result.backup_directory or "")
    assert backup.is_dir()
    if os.name == "nt":
        backup_security = windows_acl.capture_path(str(backup), directory=True)
        windows_acl.assert_not_broadly_readable(backup_security)
        windows_acl.assert_not_broadly_writable(backup_security)
    else:
        assert stat.S_IMODE(backup.stat().st_mode) == 0o700
    assert (backup / "config.source").read_bytes() == fixture["source"]
    assert (backup / "environment.source").read_bytes() == fixture["environment"]
    manifest_bytes = (backup / "manifest.json").read_bytes()
    assert fixture["secret"].encode() not in manifest_bytes
    manifest = json.loads(manifest_bytes)
    assert manifest["source_sha256"] == _sha256(fixture["source"])
    assert manifest["candidate_sha256"] == _sha256(fixture["candidate"])
    assert manifest["files"][0]["mode"] == f"{config_mode:04o}"
    assert manifest["files"][1]["mode"] == f"{environment_mode:04o}"
    assert manifest["files"][0]["target_path"] == str(fixture["config_path"])
    assert manifest["files"][1]["target_path"] == str(fixture["environment_path"])
    if hasattr(os, "getuid"):
        assert manifest["files"][0]["uid"] == os.getuid()
        assert manifest["files"][1]["uid"] == os.getuid()
        assert fixture["config_path"].stat().st_uid == os.getuid()
        assert fixture["environment_path"].stat().st_uid == os.getuid()


def test_activation_never_rewrites_connector_native_exporter_files(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    connector_files = {
        tmp_path / ".codex" / "config.toml": b'[otel]\nendpoint = "https://operator.example"\n',
        tmp_path / ".claude" / "settings.json": b'{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"https://operator.example"}}\n',
        tmp_path / ".gemini" / "settings.json": b'{"telemetry":{"target":"gcp"}}\n',
    }
    before: dict[Path, tuple[bytes, int, int]] = {}
    for path, payload in connector_files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        os.chmod(path, 0o640)
        before[path] = (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)

    result = activate_v8_migration(
        fixture["migration"],
        validator=_validator(fixture["candidate"], fixture["secret"]),
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
    )

    assert result.activated
    for path, expected in before.items():
        assert (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns) == expected


def test_absent_environment_is_created_private_and_manifest_records_absence(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, with_environment=False)
    result = activate_v8_migration(
        fixture["migration"],
        validator=_validator(fixture["candidate"], fixture["secret"]),
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
    )

    assert fixture["environment_path"].is_file()
    if os.name == "nt":
        environment_security = windows_acl.capture_path(str(fixture["environment_path"]))
        windows_acl.assert_not_broadly_readable(environment_security)
        windows_acl.assert_not_broadly_writable(environment_security)
    else:
        assert stat.S_IMODE(fixture["environment_path"].stat().st_mode) == 0o600
    assert fixture["environment_path"].read_bytes().startswith(b"DEFENSECLAW_MIGRATED_HEADER='")
    backup = Path(result.backup_directory or "")
    assert not (backup / "environment.source").exists()
    manifest = json.loads((backup / "manifest.json").read_text())
    assert manifest["files"][1]["role"] == "environment"
    assert manifest["files"][1]["existed"] is False
    assert manifest["files"][1]["sha256"] is None


def test_config_only_activation_preserves_absent_environment(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, with_environment=False)
    migration = _migration(
        fixture["source"],
        fixture["candidate"],
        effective_data_dir=str(fixture["data_dir"]),
    )

    result = activate_v8_migration(
        migration,
        validator=lambda _candidate, _environment: None,
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
    )

    assert result.activated
    assert result.environment_before_sha256 is None
    assert result.environment_after_sha256 is None
    assert not fixture["environment_path"].exists()


def test_already_v8_is_validated_without_backup_or_write(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config = data_dir / "config.yaml"
    source = b"config_version: 8\nobservability: {}\n"
    config.write_bytes(source)
    os.chmod(config, 0o640)
    original_mode = stat.S_IMODE(config.stat().st_mode)
    original_security = windows_acl.capture_path(str(config)) if os.name == "nt" else None
    migration = _migration(source, source, already_v8=True, effective_data_dir=str(data_dir))
    calls: list[bytes] = []

    result = activate_v8_migration(
        migration,
        validator=lambda candidate, _environment: calls.append(candidate),
        data_dir=data_dir,
    )

    assert calls == [source]
    assert not result.activated
    assert result.already_v8
    assert result.backup_directory is None
    assert config.read_bytes() == source
    assert stat.S_IMODE(config.stat().st_mode) == original_mode
    if os.name == "nt":
        assert windows_acl.capture_path(str(config)) == original_security
    assert not (data_dir / "backups").exists()


def test_already_v8_noop_does_not_tighten_backup_or_require_write_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config = data_dir / "config.yaml"
    source = b"config_version: 8\nobservability: {}\n"
    config.write_bytes(source)
    os.chmod(config, 0o640)
    backup_root = data_dir / "backups"
    backup_root.mkdir()
    os.chmod(backup_root, 0o755)
    original_mode = stat.S_IMODE(backup_root.stat().st_mode)
    original_security = (
        windows_acl.capture_path(str(backup_root), directory=True) if os.name == "nt" else None
    )
    migration = _migration(source, source, already_v8=True, effective_data_dir=str(data_dir))
    monkeypatch.setattr(activation_module, "_is_admin_process", lambda: False)

    result = activate_v8_migration(
        migration,
        validator=lambda _candidate, _environment: None,
        data_dir=data_dir,
        tighten_legacy_backup_root=True,
        environment={activation_module._DEPLOYMENT_MODE_ENV: "managed"},
    )

    assert result.already_v8 is True
    assert result.activated is False
    assert stat.S_IMODE(backup_root.stat().st_mode) == original_mode
    if os.name == "nt":
        assert windows_acl.capture_path(str(backup_root), directory=True) == original_security


def test_changed_false_non_v8_result_cannot_be_marked_as_successful(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config = data_dir / "config.yaml"
    source = b"config_version: 7\n"
    config.write_bytes(source)
    malformed = V8MigrationResult(
        candidate=source,
        source_sha256=_sha256(source),
        candidate_sha256=_sha256(source),
        changed=False,
        already_v8=False,
        effective_data_dir=str(data_dir),
        warnings=(),
        environment_edits=(),
        summary=_summary(),
    )

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            malformed,
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=data_dir,
        )

    assert captured.value.code == "invalid_result_state"
    assert config.read_bytes() == source


@pytest.mark.parametrize("target", ["config", "environment"])
@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_rejects_symlink_and_non_regular_targets(
    tmp_path: Path,
    target: str,
    kind: str,
) -> None:
    fixture = _fixture(tmp_path, with_environment=target != "environment")
    path = fixture["config_path"] if target == "config" else fixture["environment_path"]
    if path.exists():
        path.unlink()
    if kind == "symlink":
        outside = tmp_path / f"outside-{target}"
        outside.write_text("outside")
        try:
            path.symlink_to(outside)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                pytest.skip("Windows symlink creation requires Developer Mode or SeCreateSymbolicLinkPrivilege")
            raise
    else:
        path.mkdir()

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    expected = "symlink_forbidden" if kind == "symlink" else "regular_file_required"
    assert captured.value.code == expected
    if kind == "symlink":
        assert path.is_symlink()


def test_validator_failure_is_value_safe_and_does_not_create_backup(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    def reject(_candidate: bytes, environment: object) -> None:
        raise RuntimeError(f"rejected {environment!r} {fixture['secret']}")

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=reject,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "candidate_validation_failed"
    assert fixture["secret"] not in str(captured.value)
    assert fixture["secret"] not in repr(captured.value)
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    assert not (fixture["data_dir"] / "backups").exists()


def test_validator_safe_diagnostic_survives_activation_boundary(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    field_path = "$.observability.destinations[0].protocol"
    reason = "[config_schema_invalid] unsupported protocol"

    def reject(_candidate: bytes, _environment: object) -> None:
        raise V8CandidateValidationError(field_path, reason)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=reject,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "candidate_validation_failed"
    assert captured.value.field_path == field_path
    assert captured.value.reason == reason
    assert f"field={field_path}; reason={reason}" in str(captured.value)
    assert fixture["secret"] not in str(captured.value)
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    assert not (fixture["data_dir"] / "backups").exists()


def test_validator_concurrent_config_change_fails_cas_without_overwrite(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    concurrent = b"config_version: 7\nconcurrent: true\n"

    def mutate(_candidate: bytes, _environment: object) -> None:
        fixture["config_path"].write_bytes(concurrent)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=mutate,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "source_changed"
    assert fixture["config_path"].read_bytes() == concurrent
    assert fixture["environment_path"].read_bytes() == fixture["environment"]


def test_validator_concurrent_environment_change_fails_cas_without_overwrite(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    concurrent = b"CONCURRENT=preserve\n"

    def mutate(_candidate: bytes, _environment: object) -> None:
        fixture["environment_path"].write_bytes(concurrent)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=mutate,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "source_changed"
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == concurrent


def test_permission_preflight_failure_occurs_before_backup_or_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)

    def reject(_snapshot: object, *, default_mode: int) -> None:
        del default_mode
        raise PermissionError(fixture["secret"])

    monkeypatch.setattr(activation_module, "_preflight_atomic_replace", reject)
    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "permission_preflight_failed"
    assert fixture["secret"] not in str(captured.value)
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    assert not (fixture["data_dir"] / "backups").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission-mode assertion")
@pytest.mark.parametrize("legacy_mode", [0o500, 0o555])
def test_read_only_preflight_accepts_legacy_backup_root_target_can_tighten(
    tmp_path: Path,
    legacy_mode: int,
) -> None:
    fixture = _fixture(tmp_path)
    backup_root = fixture["data_dir"] / "backups"
    backup_root.mkdir()
    os.chmod(backup_root, legacy_mode)
    config_before = fixture["config_path"].read_bytes()
    environment_before = fixture["environment_path"].read_bytes()

    activation_module.preflight_v8_migration_activation(
        fixture["migration"],
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
        environment_path=fixture["environment_path"],
        tighten_legacy_backup_root=True,
        environment={},
    )

    assert stat.S_IMODE(backup_root.stat().st_mode) == legacy_mode
    assert fixture["config_path"].read_bytes() == config_before
    assert fixture["environment_path"].read_bytes() == environment_before
    assert list(backup_root.iterdir()) == []

    result = activate_v8_migration(
        fixture["migration"],
        validator=_validator(fixture["candidate"], fixture["secret"]),
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
        tighten_legacy_backup_root=True,
        environment={},
    )

    assert result.activated is True
    assert stat.S_IMODE(backup_root.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX advisory-lock mode semantics")
def test_read_only_preflight_rejects_unwritable_existing_lock_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    lock_path = Path(f"{fixture['config_path']}.lock")
    lock_path.write_bytes(b"")
    os.chmod(lock_path, 0o400)
    config_before = fixture["config_path"].read_bytes()
    environment_before = fixture["environment_path"].read_bytes()
    original_open = activation_module.os.open

    def deny_lock_update(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if os.fspath(path) == str(lock_path) and flags & os.O_RDWR:
            raise PermissionError(errno.EACCES, "fixture lock is read-only")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(activation_module.os, "open", deny_lock_update)
    with pytest.raises(V8ActivationError) as captured:
        activation_module.preflight_v8_migration_activation(
            fixture["migration"],
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment_path=fixture["environment_path"],
            tighten_legacy_backup_root=True,
            environment={},
        )

    assert captured.value.code == "lock_file_unwritable"
    assert fixture["config_path"].read_bytes() == config_before
    assert fixture["environment_path"].read_bytes() == environment_before
    assert lock_path.read_bytes() == b""
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o400
    assert not (fixture["data_dir"] / "backups").exists()


def test_held_update_lock_is_rejected_pre_stop_and_bounded_in_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    config_before = fixture["config_path"].read_bytes()
    environment_before = fixture["environment_path"].read_bytes()
    child_environment = dict(os.environ)
    child_environment["PYTHONPATH"] = os.pathsep.join(
        entry for entry in sys.path if isinstance(entry, str) and entry
    )
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import sys\n"
                "from defenseclaw.file_lock import locked_file_update\n"
                "with locked_file_update(sys.argv[1]):\n"
                "    print('locked', flush=True)\n"
                "    sys.stdin.read(1)\n"
            ),
            str(fixture["config_path"]),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=child_environment,
    )
    assert child.stdout is not None
    assert child.stdin is not None
    try:
        assert child.stdout.readline().strip() == "locked"
        with pytest.raises(V8ActivationError) as preflight_error:
            activation_module.preflight_v8_migration_activation(
                fixture["migration"],
                data_dir=fixture["data_dir"],
                config_path=fixture["config_path"],
                environment_path=fixture["environment_path"],
                tighten_legacy_backup_root=True,
                environment={},
            )
        assert preflight_error.value.code == "lock_file_busy"

        monkeypatch.setattr(activation_module, "_ACTIVATION_LOCK_TIMEOUT_SECONDS", 0.1)
        with pytest.raises(V8ActivationError) as activation_error:
            activate_v8_migration(
                fixture["migration"],
                validator=lambda _candidate, _environment: pytest.fail(
                    "validator must not run while the source lock is held"
                ),
                data_dir=fixture["data_dir"],
                config_path=fixture["config_path"],
                tighten_legacy_backup_root=True,
                environment={},
            )
        assert activation_error.value.code == "lock_unavailable"
        assert activation_error.value.stage == "acquire_update_lock"
    finally:
        try:
            child.stdin.write("x")
            child.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        try:
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=5)

    assert child.returncode == 0
    assert fixture["config_path"].read_bytes() == config_before
    assert fixture["environment_path"].read_bytes() == environment_before
    assert not (fixture["data_dir"] / "backups").exists()


def test_read_only_preflight_atomic_probe_failure_cleans_private_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    config_before = fixture["config_path"].read_bytes()
    environment_before = fixture["environment_path"].read_bytes()
    config_entries_before = set(fixture["config_path"].parent.iterdir())
    data_entries_before = set(fixture["data_dir"].iterdir())

    def reject_exchange(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.ENOTSUP, "fixture exchange unsupported")

    monkeypatch.setattr(activation_module, "_exchange_probe_entries", reject_exchange)
    with pytest.raises(V8ActivationError) as captured:
        activation_module.preflight_v8_migration_activation(
            fixture["migration"],
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment_path=fixture["environment_path"],
            tighten_legacy_backup_root=True,
            environment={},
        )

    assert captured.value.code == "permission_preflight_failed"
    assert fixture["config_path"].read_bytes() == config_before
    assert fixture["environment_path"].read_bytes() == environment_before
    assert set(fixture["config_path"].parent.iterdir()) == config_entries_before
    assert set(fixture["data_dir"].iterdir()) == data_entries_before
    assert not (fixture["data_dir"] / "backups").exists()


def test_read_only_preflight_rejects_promoted_secret_in_readable_environment(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    os.chmod(fixture["environment_path"], 0o644)
    config_before = fixture["config_path"].read_bytes()
    environment_before = fixture["environment_path"].read_bytes()

    with pytest.raises(V8ActivationError) as captured:
        activation_module.preflight_v8_migration_activation(
            fixture["migration"],
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment_path=fixture["environment_path"],
            tighten_legacy_backup_root=True,
            environment={},
        )

    assert captured.value.code == "environment_permissions_unsafe"
    assert fixture["config_path"].read_bytes() == config_before
    assert fixture["environment_path"].read_bytes() == environment_before
    assert stat.S_IMODE(fixture["environment_path"].stat().st_mode) == 0o644
    assert not (fixture["data_dir"] / "backups").exists()


@POSIX_PERMISSION_CONTRACT
def test_refuses_to_append_promoted_secret_to_world_readable_environment(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    os.chmod(fixture["environment_path"], 0o644)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "environment_permissions_unsafe"
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    assert stat.S_IMODE(fixture["environment_path"].stat().st_mode) == 0o644
    assert not (fixture["data_dir"] / "backups").exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACL semantics")
@pytest.mark.parametrize("timing", ["before_activation", "during_validation", "after_preflight"])
def test_inheritable_read_acl_cannot_expose_staged_or_backup_secrets(
    tmp_path: Path,
    timing: str,
) -> None:
    fixture = _fixture(tmp_path, with_environment=False)
    acl = "everyone allow read,file_inherit,directory_inherit"

    def add_acl() -> None:
        completed = subprocess.run(
            ["chmod", "+a", acl, str(fixture["data_dir"])],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            pytest.skip("test filesystem does not support inheritable ACLs")

    if timing == "before_activation":
        add_acl()

    def validator(_candidate: bytes, _environment: object) -> None:
        if timing == "during_validation":
            add_acl()

    def inject(stage: str) -> None:
        if timing == "after_preflight" and stage == "after_preflight":
            add_acl()

    try:
        with pytest.raises(V8ActivationError) as captured:
            activate_v8_migration(
                fixture["migration"],
                validator=validator,
                data_dir=fixture["data_dir"],
                config_path=fixture["config_path"],
                fault_injector=inject,
            )
    finally:
        subprocess.run(["chmod", "-N", str(fixture["data_dir"])], check=False, capture_output=True)

    assert captured.value.code in {"inheritable_read_acl_unsafe", "permission_preflight_failed", "backup_failed"}
    assert not fixture["environment_path"].exists()
    backup_root = fixture["data_dir"] / "backups"
    assert not backup_root.exists() or list(backup_root.iterdir()) == []
    assert fixture["config_path"].read_bytes() == fixture["source"]


@pytest.mark.parametrize("target", ["config", "environment"])
@POSIX_PERMISSION_CONTRACT
def test_untrusted_existing_leaf_uid_is_rejected_before_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    fixture = _fixture(tmp_path)
    target_path = fixture["config_path"] if target == "config" else fixture["environment_path"]
    original = activation_module._snapshot_regular_file

    def untrusted(path: str, *, required: bool):
        snapshot = original(path, required=required)
        if path == str(target_path):
            return replace(snapshot, uid=2_147_000_001)
        return snapshot

    monkeypatch.setattr(activation_module, "_snapshot_regular_file", untrusted)
    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "leaf_owner_untrusted"
    assert not (fixture["data_dir"] / "backups").exists()


@POSIX_PERMISSION_CONTRACT
def test_inherited_group_is_accepted_only_for_fully_private_trusted_uid() -> None:
    uid = os.getuid()
    gid = os.getgid()
    inherited_gid = gid + 2_147_000_001
    trusted = frozenset({(uid, gid)})

    assert activation_module._trusted_private_owner(uid, inherited_gid, 0o600, trusted)
    assert activation_module._trusted_private_owner(uid, inherited_gid, 0o700, trusted)
    assert not activation_module._trusted_private_owner(uid, inherited_gid, 0o640, trusted)
    assert not activation_module._trusted_private_owner(uid + 1, inherited_gid, 0o600, trusted)


@POSIX_PERMISSION_CONTRACT
def test_group_readable_leaf_with_inherited_group_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    os.chmod(fixture["config_path"], 0o640)
    original = activation_module._snapshot_regular_file

    def inherited_group(path: str, *, required: bool):
        snapshot = original(path, required=required)
        if path == str(fixture["config_path"]):
            return replace(snapshot, gid=(snapshot.gid or 0) + 2_147_000_001)
        return snapshot

    monkeypatch.setattr(activation_module, "_snapshot_regular_file", inherited_group)
    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "leaf_owner_untrusted"


@POSIX_PERMISSION_CONTRACT
def test_group_writable_config_is_rejected_before_validation(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    os.chmod(fixture["config_path"], 0o660)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "leaf_permissions_unsafe"
    assert not (fixture["data_dir"] / "backups").exists()


def test_new_environment_owner_follows_data_directory_not_sudo_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt":
        pytest.skip("POSIX ownership semantics")
    import pwd

    fixture = _fixture(tmp_path, with_environment=False)
    snapshot = activation_module._snapshot_regular_file(str(fixture["environment_path"]), required=False)
    account = pwd.getpwuid(os.getuid())
    environment = {
        "SUDO_USER": account.pw_name,
        "SUDO_UID": str(account.pw_uid),
        "SUDO_GID": str(account.pw_gid),
    }
    original_lstat = activation_module.os.lstat

    def root_owned(path):
        info = original_lstat(path)
        if os.fspath(path) == str(fixture["data_dir"]):
            return SimpleNamespace(st_uid=0, st_gid=0, st_mode=info.st_mode)
        return info

    monkeypatch.setattr(activation_module.os, "lstat", root_owned)
    metadata = activation_module._new_environment_metadata(snapshot, str(fixture["data_dir"]), environment)

    assert (metadata.uid, metadata.gid) == (0, 0)


def test_ambient_environment_precedence_conflict_fails_before_validation(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment={fixture["edit"].name: "different-secret"},
        )

    assert captured.value.code == "ambient_environment_conflict"
    assert fixture["secret"] not in str(captured.value)
    assert "different-secret" not in str(captured.value)
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    assert not (fixture["data_dir"] / "backups").exists()


def test_live_ambient_conflict_cannot_be_hidden_by_clean_supplied_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    monkeypatch.setenv(fixture["edit"].name, "live-conflicting-secret")

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment={},
        )

    assert captured.value.code == "ambient_environment_conflict"
    assert "live-conflicting-secret" not in str(captured.value)
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]


def test_changed_activation_fails_closed_when_windows_acl_api_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    monkeypatch.setattr(activation_module, "_is_windows", lambda: True)
    monkeypatch.setattr(
        activation_module.windows_acl,
        "capture_path",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(activation_module.windows_acl.WindowsAclError("unavailable")),
    )

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "parent_acl_unsafe"
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]


def test_managed_write_policy_is_enforced_before_backup_or_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)

    def reject(_path: str, _environment: object) -> None:
        raise PermissionError(fixture["secret"])

    monkeypatch.setattr(activation_module, "_assert_config_write_allowed", reject)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "config_write_forbidden"
    assert fixture["secret"] not in str(captured.value)
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    assert not (fixture["data_dir"] / "backups").exists()


def test_supplied_managed_mode_requires_admin_before_backup_or_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    monkeypatch.setattr(activation_module, "_is_admin_process", lambda: False)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment={activation_module._DEPLOYMENT_MODE_ENV: "managed"},
        )

    assert captured.value.code == "config_write_forbidden"
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    assert not (fixture["data_dir"] / "backups").exists()


def test_live_managed_mode_cannot_be_hidden_by_clean_supplied_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    monkeypatch.setattr(activation_module, "_is_admin_process", lambda: False)
    monkeypatch.setenv(activation_module._DEPLOYMENT_MODE_ENV, "managed_enterprise")

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment={},
        )

    assert captured.value.code == "config_write_forbidden"
    assert not (fixture["data_dir"] / "backups").exists()


@pytest.mark.parametrize(
    "stage",
    [
        "before_validator",
        "after_validator",
        "after_backup",
        "before_environment_write",
        "after_environment_write",
        "before_config_write",
        "after_config_write",
        "after_activation",
    ],
)
@pytest.mark.parametrize("environment_exists", [False, True])
def test_fault_boundaries_restore_exact_originals(
    tmp_path: Path,
    stage: str,
    environment_exists: bool,
) -> None:
    fixture = _fixture(tmp_path, with_environment=environment_exists)
    original_config_mode = stat.S_IMODE(fixture["config_path"].stat().st_mode)
    original_env_mode = stat.S_IMODE(fixture["environment_path"].stat().st_mode) if environment_exists else None

    def inject(current: str) -> None:
        if current == stage:
            raise RuntimeError(fixture["secret"])

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            fault_injector=inject,
        )

    assert fixture["secret"] not in str(captured.value)
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert stat.S_IMODE(fixture["config_path"].stat().st_mode) == original_config_mode
    if environment_exists:
        assert fixture["environment_path"].read_bytes() == fixture["environment"]
        assert stat.S_IMODE(fixture["environment_path"].stat().st_mode) == original_env_mode
    else:
        assert not fixture["environment_path"].exists()


@pytest.mark.parametrize(
    "stage",
    ["after_environment_write", "after_config_write", "after_activation"],
)
def test_keyboard_interrupt_rolls_back_partial_activation(
    tmp_path: Path,
    stage: str,
) -> None:
    fixture = _fixture(tmp_path)

    def interrupt(current: str) -> None:
        if current == stage:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            fault_injector=interrupt,
        )

    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]


def test_injected_second_write_failure_restores_environment_and_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    original_replace = activation_module._atomic_replace
    failed = False

    def fail_config(
        snapshot: object,
        payload: bytes,
        *,
        default_mode: int,
        metadata: object | None = None,
    ) -> None:
        nonlocal failed
        if not failed and snapshot.path == str(fixture["config_path"]):  # type: ignore[attr-defined]
            failed = True
            raise OSError("secret-bearing low-level error " + fixture["secret"])
        original_replace(snapshot, payload, default_mode=default_mode, metadata=metadata)

    monkeypatch.setattr(activation_module, "_atomic_replace", fail_config)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "activation_failed"
    assert fixture["secret"] not in str(captured.value)
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]


def test_rollback_failure_is_explicit_and_keeps_recovery_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)

    def inject(stage: str) -> None:
        if stage == "after_environment_write":
            raise RuntimeError(fixture["secret"])

    monkeypatch.setattr(
        activation_module,
        "_restore_snapshot",
        lambda _snapshot, **_kwargs: (_ for _ in ()).throw(OSError(fixture["secret"])),
    )

    with pytest.raises(V8ActivationRollbackError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            fault_injector=inject,
        )

    assert captured.value.code == "rollback_incomplete"
    assert fixture["secret"] not in str(captured.value)
    backup = Path(captured.value.backup_directory or "")
    assert backup.is_dir()
    assert (backup / "config.source").read_bytes() == fixture["source"]
    assert (backup / "environment.source").read_bytes() == fixture["environment"]


def test_rollback_continues_after_keyboard_interrupt_in_first_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    restored: list[str] = []

    def interrupt_first(snapshot: object, **_kwargs: object) -> None:
        restored.append(snapshot.path)  # type: ignore[attr-defined]
        if len(restored) == 1:
            raise KeyboardInterrupt

    def inject(stage: str) -> None:
        if stage == "after_environment_write":
            raise RuntimeError(fixture["secret"])

    monkeypatch.setattr(activation_module, "_restore_snapshot", interrupt_first)

    with pytest.raises(V8ActivationRollbackError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            fault_injector=inject,
        )

    assert captured.value.code == "rollback_incomplete"
    assert restored == [str(fixture["config_path"]), str(fixture["environment_path"])]


def test_rollback_refuses_to_clobber_an_external_post_activation_change(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    external = b"EXTERNAL=must-survive\n"

    def inject(stage: str) -> None:
        if stage == "after_config_write":
            fixture["environment_path"].write_bytes(external)
            raise RuntimeError(fixture["secret"])

    with pytest.raises(V8ActivationRollbackError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            fault_injector=inject,
        )

    assert captured.value.code == "rollback_incomplete"
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == external


@POSIX_PERMISSION_CONTRACT
def test_rollback_refuses_to_clobber_an_external_metadata_only_change(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)

    def inject(stage: str) -> None:
        if stage == "after_config_write":
            os.chmod(fixture["environment_path"], 0o640)
            raise RuntimeError(fixture["secret"])

    with pytest.raises(V8ActivationRollbackError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            fault_injector=inject,
        )

    assert captured.value.code == "rollback_incomplete"
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["secret"].encode() in fixture["environment_path"].read_bytes()
    assert stat.S_IMODE(fixture["environment_path"].stat().st_mode) == 0o640


@pytest.mark.parametrize("target", ["config", "environment"])
@POSIX_PERMISSION_CONTRACT
def test_final_verification_rejects_metadata_drift(
    tmp_path: Path,
    target: str,
) -> None:
    fixture = _fixture(tmp_path)
    path = fixture["config_path"] if target == "config" else fixture["environment_path"]
    changed_mode = 0o600 if target == "config" else 0o640

    def mutate_without_raising(stage: str) -> None:
        if stage == "after_config_write":
            os.chmod(path, changed_mode)

    with pytest.raises(V8ActivationRollbackError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            fault_injector=mutate_without_raising,
        )

    assert captured.value.code == "rollback_incomplete"
    assert stat.S_IMODE(path.stat().st_mode) == changed_mode


@POSIX_TRANSACTION_INJECTION
def test_partial_backup_failure_is_cleaned_without_mutating_live_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)

    def reject_backup(*_args: object, **_kwargs: object) -> None:
        raise OSError(fixture["secret"])

    monkeypatch.setattr(activation_module, "_write_backup_snapshot_at", reject_backup)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "backup_failed"
    assert fixture["secret"] not in str(captured.value)
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    backup_root = fixture["data_dir"] / "backups"
    assert backup_root.is_dir()
    assert list(backup_root.iterdir()) == []


@POSIX_TRANSACTION_INJECTION
def test_keyboard_interrupt_cleans_partial_backup_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)

    def interrupt_backup(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(activation_module, "_write_backup_snapshot_at", interrupt_backup)

    with pytest.raises(KeyboardInterrupt):
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture["candidate"], fixture["secret"]),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    backup_root = fixture["data_dir"] / "backups"
    assert backup_root.is_dir()
    assert list(backup_root.iterdir()) == []


def test_environment_conflict_and_duplicate_are_rejected_without_values(
    tmp_path: Path,
) -> None:
    for body in (
        b"DEFENSECLAW_MIGRATED_HEADER=other\n",
        b"DEFENSECLAW_MIGRATED_HEADER=first\nDEFENSECLAW_MIGRATED_HEADER=second\n",
    ):
        fixture = _fixture(tmp_path / _sha256(body)[:8])
        fixture["environment_path"].write_bytes(body)
        with pytest.raises(V8ActivationError) as captured:
            activate_v8_migration(
                fixture["migration"],
                validator=lambda _candidate, _environment: None,
                data_dir=fixture["data_dir"],
                config_path=fixture["config_path"],
            )
        assert captured.value.code in {
            "environment_entry_conflict",
            "environment_entry_ambiguous",
        }
        assert fixture["secret"] not in str(captured.value)
        assert fixture["config_path"].read_bytes() == fixture["source"]
        assert fixture["environment_path"].read_bytes() == body


def test_matching_environment_edit_is_idempotent_and_not_duplicated(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    existing = fixture["environment"] + b"DEFENSECLAW_MIGRATED_HEADER='" + fixture["secret"].encode() + b"'\r\n"
    fixture["environment_path"].write_bytes(existing)

    result = activate_v8_migration(
        fixture["migration"],
        validator=_validator(fixture["candidate"], fixture["secret"]),
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
    )

    assert result.activated
    assert fixture["environment_path"].read_bytes() == existing
    assert fixture["environment_path"].read_bytes().count(b"DEFENSECLAW_MIGRATED_HEADER=") == 1


@POSIX_PERMISSION_CONTRACT
def test_matching_environment_edit_still_requires_private_dotenv_permissions(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    existing = fixture["environment"] + b"DEFENSECLAW_MIGRATED_HEADER='" + fixture["secret"].encode() + b"'\r\n"
    fixture["environment_path"].write_bytes(existing)
    os.chmod(fixture["environment_path"], 0o644)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "environment_permissions_unsafe"
    assert fixture["environment_path"].read_bytes() == existing


def test_rejects_bound_data_dir_and_environment_path_mismatches(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    other = tmp_path / "other"
    other.mkdir()

    with pytest.raises(V8ActivationError) as data_error:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: None,
            data_dir=other,
            config_path=fixture["config_path"],
        )
    assert data_error.value.code == "effective_data_dir_mismatch"

    with pytest.raises(V8ActivationError) as environment_error:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment_path=other / ".env",
        )
    assert environment_error.value.code == "environment_path_mismatch"


def test_backup_root_cannot_alias_absent_environment_file(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, with_environment=False)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            backup_root=fixture["environment_path"],
        )

    assert captured.value.code == "path_alias"
    assert not fixture["environment_path"].exists()


def test_consulted_environment_change_fails_cas_before_validation(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    dependency = EnvironmentDependency(
        name="DEFENSECLAW_JSONL_DISABLE",
        present=True,
        value_sha256=_sha256(b"true"),
    )
    migration = V8MigrationResult(
        candidate=fixture["migration"].candidate,
        source_sha256=fixture["migration"].source_sha256,
        candidate_sha256=fixture["migration"].candidate_sha256,
        changed=True,
        already_v8=False,
        effective_data_dir=str(fixture["data_dir"]),
        warnings=(),
        environment_edits=fixture["migration"].environment_edits,
        summary=fixture["migration"].summary,
        environment_dependencies=(dependency,),
    )

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            migration,
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment={"DEFENSECLAW_JSONL_DISABLE": "false"},
        )

    assert captured.value.code == "environment_dependency_changed"
    assert fixture["config_path"].read_bytes() == fixture["source"]


def test_live_ambient_dependency_cannot_shadow_clean_supplied_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    dependency = EnvironmentDependency(
        name="DEPENDENCY_CANARY",
        present=True,
        value_sha256=_sha256(b"before"),
    )
    migration = replace(fixture["migration"], environment_dependencies=(dependency,))
    monkeypatch.setenv("DEPENDENCY_CANARY", "after")

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            migration,
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment={"DEPENDENCY_CANARY": "before"},
        )

    assert captured.value.code == "environment_dependency_changed"
    assert fixture["config_path"].read_bytes() == fixture["source"]


def test_live_ambient_dependency_cannot_shadow_expected_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    dependency = EnvironmentDependency(
        name="DEPENDENCY_CANARY",
        present=False,
        value_sha256=_sha256(b""),
    )
    migration = replace(fixture["migration"], environment_dependencies=(dependency,))
    monkeypatch.setenv("DEPENDENCY_CANARY", "surprise")

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            migration,
            validator=lambda _candidate, _environment: pytest.fail("validator must not run"),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment={},
        )

    assert captured.value.code == "environment_dependency_changed"


@pytest.mark.parametrize("stage", ["after_environment_write", "after_config_write"])
def test_environment_dependency_change_during_commit_rolls_back_both_files(
    tmp_path: Path,
    stage: str,
) -> None:
    fixture = _fixture(tmp_path)
    environment = {"DEPENDENCY_CANARY": "before"}
    dependency = EnvironmentDependency(
        name="DEPENDENCY_CANARY",
        present=True,
        value_sha256=_sha256(b"before"),
    )
    migration = replace(fixture["migration"], environment_dependencies=(dependency,))
    seen: list[str] = []

    def mutate(current_stage: str) -> None:
        seen.append(current_stage)
        if current_stage == stage:
            environment["DEPENDENCY_CANARY"] = "after"

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            migration,
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            environment=environment,
            fault_injector=mutate,
        )

    assert captured.value.code == "environment_dependency_changed"
    assert stage in seen
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]


@POSIX_TRANSACTION_INJECTION
def test_cooperative_cas_rejects_stale_config_without_candidate_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    concurrent = b"config_version: 7\nconcurrent: final-window\n"
    original = activation_module._publish_checked_under_lock
    original_replace = activation_module.os.replace
    config_replacements: list[str] = []

    def race(expected, candidate, **kwargs) -> None:
        if expected.path == str(fixture["config_path"]):
            fixture["config_path"].write_bytes(concurrent)
        original(expected, candidate, **kwargs)

    def track_replace(source, destination, *args, **kwargs) -> None:
        if os.fspath(destination) == fixture["config_path"].name:
            config_replacements.append(os.fspath(source))
        original_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(activation_module, "_publish_checked_under_lock", race)
    monkeypatch.setattr(activation_module.os, "replace", track_replace)
    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "rollback_incomplete"
    assert fixture["config_path"].read_bytes() == concurrent
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    assert config_replacements == []


@POSIX_TRANSACTION_INJECTION
def test_stale_environment_cas_never_publishes_secret_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    concurrent = b"CONCURRENT=must-survive\n"
    original = activation_module._publish_checked_under_lock
    original_replace = activation_module.os.replace
    environment_replacements: list[str] = []

    def race(expected, candidate, **kwargs) -> None:
        if expected.path == str(fixture["environment_path"]):
            fixture["environment_path"].write_bytes(concurrent)
        original(expected, candidate, **kwargs)

    def track_replace(source, destination, *args, **kwargs) -> None:
        if os.fspath(destination) == fixture["environment_path"].name:
            environment_replacements.append(os.fspath(source))
        original_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(activation_module, "_publish_checked_under_lock", race)
    monkeypatch.setattr(activation_module.os, "replace", track_replace)
    with pytest.raises(V8ActivationRollbackError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "rollback_incomplete"
    assert fixture["environment_path"].read_bytes() == concurrent
    assert fixture["secret"].encode() not in concurrent
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert environment_replacements == []


@POSIX_TRANSACTION_INJECTION
def test_parent_directory_swap_is_detected_without_writing_replacement_tree(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    displaced = tmp_path / "displaced-data"

    def swap_parent(stage: str) -> None:
        if stage == "before_environment_write":
            fixture["data_dir"].rename(displaced)
            fixture["data_dir"].mkdir(mode=0o700)

    with pytest.raises(V8ActivationRollbackError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            fault_injector=swap_parent,
        )

    assert captured.value.code == "rollback_incomplete"
    assert not fixture["environment_path"].exists()
    assert (displaced / ".env").read_bytes() == fixture["environment"]
    assert fixture["config_path"].read_bytes() == fixture["source"]


def test_shared_dotenv_lock_serializes_setup_writer_without_lost_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv

    fixture = _fixture(tmp_path)
    activation_holds_lock = Event()
    release_activation = Event()
    writer_done = Event()
    errors: list[BaseException] = []

    def pause(stage: str) -> None:
        if stage == "before_validator":
            activation_holds_lock.set()
            if not release_activation.wait(5):
                raise TimeoutError("test did not release activation")

    def run_activation() -> None:
        try:
            activate_v8_migration(
                fixture["migration"],
                validator=lambda _candidate, _environment: None,
                data_dir=fixture["data_dir"],
                config_path=fixture["config_path"],
                fault_injector=pause,
            )
        except BaseException as error:
            errors.append(error)

    def run_writer() -> None:
        try:
            _save_secret_to_dotenv("DEFENSECLAW_CONCURRENT_SECRET", "writer-value", str(fixture["data_dir"]))
        except BaseException as error:
            errors.append(error)
        finally:
            writer_done.set()

    monkeypatch.delenv("DEFENSECLAW_CONCURRENT_SECRET", raising=False)
    activation_thread = Thread(target=run_activation)
    activation_thread.start()
    assert activation_holds_lock.wait(5)
    writer_thread = Thread(target=run_writer)
    writer_thread.start()
    assert not writer_done.wait(0.2)
    release_activation.set()
    activation_thread.join(5)
    writer_thread.join(5)

    assert not activation_thread.is_alive()
    assert not writer_thread.is_alive()
    assert errors == []
    body = fixture["environment_path"].read_bytes()
    assert b"DEFENSECLAW_MIGRATED_HEADER=" in body
    assert b"DEFENSECLAW_CONCURRENT_SECRET=writer-value" in body


@pytest.mark.parametrize(
    ("destination", "path"),
    [("other-http", ("headers", "X-Fixture", "env")), ("fixture-http", ("token_env",))],
)
def test_environment_edit_requires_its_exact_candidate_reference_path(
    tmp_path: Path,
    destination: str,
    path: tuple[str, ...],
) -> None:
    fixture = _fixture(tmp_path)
    mismatched = _edit(
        fixture["edit"].name,
        fixture["secret"],
        destination=destination,
        path=path,
    )
    migration = _migration(
        fixture["source"],
        fixture["candidate"],
        edits=(mismatched,),
        effective_data_dir=str(fixture["data_dir"]),
    )

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            migration,
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "environment_reference_missing"
    assert fixture["config_path"].read_bytes() == fixture["source"]


def test_environment_edit_rejects_undeclared_second_destination_use(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    candidate = _candidate_with_header_reference(
        fixture["candidate"],
        "X-Undeclared",
        fixture["edit"].name,
    )
    migration = _migration(
        fixture["source"],
        candidate,
        edits=(fixture["edit"],),
        effective_data_dir=str(fixture["data_dir"]),
    )

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            migration,
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "environment_reference_provenance_mismatch"
    assert fixture["config_path"].read_bytes() == fixture["source"]


def test_replacement_preserves_exact_extended_attributes(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    attribute = "com.cisco.defenseclaw.test" if sys.platform == "darwin" else "user.defenseclaw.test"
    try:
        if hasattr(os, "setxattr"):
            os.setxattr(fixture["config_path"], attribute, b"config-metadata")
            os.setxattr(fixture["environment_path"], attribute, b"environment-metadata")
        elif sys.platform == "darwin":
            for path, value in (
                (fixture["config_path"], b"config-metadata"),
                (fixture["environment_path"], b"environment-metadata"),
            ):
                descriptor = os.open(path, os.O_RDONLY)
                try:
                    activation_module._set_darwin_xattrs(descriptor, ((attribute, value),))
                finally:
                    os.close(descriptor)
        else:
            pytest.skip("extended attributes are unavailable")
    except OSError:
        pytest.skip("test filesystem does not support user extended attributes")

    activate_v8_migration(
        fixture["migration"],
        validator=lambda _candidate, _environment: None,
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
    )

    config = activation_module._snapshot_regular_file(str(fixture["config_path"]), required=True)
    environment = activation_module._snapshot_regular_file(str(fixture["environment_path"]), required=True)
    assert dict(config.xattrs)[attribute] == b"config-metadata"
    assert dict(environment.xattrs)[attribute] == b"environment-metadata"


@POSIX_PERMISSION_CONTRACT
def test_existing_backup_root_must_be_private(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    backup_root = fixture["data_dir"] / "backups"
    backup_root.mkdir()
    os.chmod(backup_root, 0o755)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "backup_failed"
    assert fixture["config_path"].read_bytes() == fixture["source"]


@POSIX_PERMISSION_CONTRACT
def test_upgrade_may_tighten_trusted_legacy_backup_root(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    backup_root = fixture["data_dir"] / "backups"
    backup_root.mkdir()
    os.chmod(backup_root, 0o755)

    result = activate_v8_migration(
        fixture["migration"],
        validator=lambda _candidate, _environment: None,
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
        tighten_legacy_backup_root=True,
    )

    assert result.activated is True
    assert stat.S_IMODE(backup_root.stat().st_mode) == 0o700
    assert Path(result.backup_directory or "").parent == backup_root


@POSIX_PERMISSION_CONTRACT
def test_upgrade_never_tightens_writable_legacy_backup_root(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    backup_root = fixture["data_dir"] / "backups"
    backup_root.mkdir()
    os.chmod(backup_root, 0o775)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            tighten_legacy_backup_root=True,
        )

    assert captured.value.code == "parent_permissions_unsafe"
    assert stat.S_IMODE(backup_root.stat().st_mode) == 0o775
    assert fixture["config_path"].read_bytes() == fixture["source"]


@pytest.mark.parametrize("tamper", ["source", "candidate", "edit"])
def test_rejects_tampered_result_digests(tmp_path: Path, tamper: str) -> None:
    fixture = _fixture(tmp_path)
    migration = fixture["migration"]
    if tamper == "source":
        migration = V8MigrationResult(
            candidate=migration.candidate,
            source_sha256="0" * 64,
            candidate_sha256=migration.candidate_sha256,
            changed=True,
            already_v8=False,
            effective_data_dir=migration.effective_data_dir,
            warnings=(),
            environment_edits=migration.environment_edits,
            summary=migration.summary,
        )
        expected = "source_digest_mismatch"
    elif tamper == "candidate":
        migration = V8MigrationResult(
            candidate=migration.candidate,
            source_sha256=migration.source_sha256,
            candidate_sha256="0" * 64,
            changed=True,
            already_v8=False,
            effective_data_dir=migration.effective_data_dir,
            warnings=(),
            environment_edits=migration.environment_edits,
            summary=migration.summary,
        )
        expected = "candidate_digest_mismatch"
    else:
        bad_edit = EnvironmentEdit(
            name=fixture["edit"].name,
            value=fixture["secret"],
            value_sha256="0" * 64,
            references=fixture["edit"].references,
        )
        migration = _migration(
            fixture["source"],
            fixture["candidate"],
            edits=(bad_edit,),
            effective_data_dir=str(fixture["data_dir"]),
        )
        expected = "environment_edit_digest_mismatch"

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            migration,
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == expected
    assert fixture["config_path"].read_bytes() == fixture["source"]


def test_low_entropy_promoted_value_is_not_rejected_by_raw_substring_match(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    short_edit = _edit(
        "DEFENSECLAW_MIGRATED_SHORT",
        "8",
        path=("headers", "X-Short", "env"),
    )
    candidate = _candidate_with_header_reference(
        fixture["candidate"],
        "X-Short",
        short_edit.name,
    )
    migration = _migration(
        fixture["source"],
        candidate,
        edits=(short_edit,),
        effective_data_dir=str(fixture["data_dir"]),
    )

    result = activate_v8_migration(
        migration,
        validator=lambda _candidate, _environment: None,
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
    )

    assert result.activated
    assert b"config_version: 8" in fixture["config_path"].read_bytes()
    assert b"DEFENSECLAW_MIGRATED_SHORT='8'" in fixture["environment_path"].read_bytes()
    assert "8" not in repr(short_edit)


def test_high_entropy_promoted_value_cannot_remain_verbatim_in_candidate(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    candidate = fixture["candidate"] + b"token: " + fixture["secret"].encode() + b"\r\n"
    migration = _migration(
        fixture["source"],
        candidate,
        edits=(fixture["edit"],),
        effective_data_dir=str(fixture["data_dir"]),
    )

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            migration,
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "secret_in_candidate"
    assert fixture["secret"] not in repr(migration)
    assert fixture["secret"] not in repr(fixture["edit"])
    assert fixture["secret"] not in str(captured.value)


def test_low_entropy_promoted_value_cannot_remain_as_string_scalar(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    short_edit = _edit(
        "DEFENSECLAW_MIGRATED_SHORT",
        "abc",
        path=("headers", "X-Short", "env"),
    )
    candidate = (
        _candidate_with_header_reference(
            fixture["candidate"],
            "X-Short",
            short_edit.name,
        )
        + b"static_header: 'abc'\r\n"
    )
    migration = _migration(
        fixture["source"],
        candidate,
        edits=(short_edit,),
        effective_data_dir=str(fixture["data_dir"]),
    )

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            migration,
            validator=lambda _candidate, _environment: None,
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
        )

    assert captured.value.code == "secret_in_candidate"


def test_backup_directories_are_collision_safe(tmp_path: Path) -> None:
    shared_backup = tmp_path / "backups"
    results = []
    for suffix in ("one", "two"):
        fixture = _fixture(tmp_path / suffix)
        results.append(
            activate_v8_migration(
                fixture["migration"],
                validator=_validator(fixture["candidate"], fixture["secret"]),
                data_dir=fixture["data_dir"],
                config_path=fixture["config_path"],
                backup_root=shared_backup,
            )
        )

    directories = {result.backup_directory for result in results}
    assert len(directories) == 2
    assert all(Path(path or "").is_dir() for path in directories)


def test_first_backup_root_creation_uses_private_durable_hierarchy(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    config_snapshot = activation_module._snapshot_regular_file(
        str(fixture["config_path"]),
        required=True,
    )
    environment_snapshot = activation_module._snapshot_regular_file(
        str(fixture["environment_path"]),
        required=True,
    )
    backup_root = fixture["data_dir"] / "new-backups"
    directory = activation_module._create_recovery_backup(
        str(backup_root),
        config_snapshot,
        environment_snapshot,
        fixture["migration"],
        _sha256(fixture["environment"]),
    )

    assert Path(directory).parent == backup_root
    if os.name == "nt":
        for path, is_directory in (
            (backup_root, True),
            (Path(directory), True),
            (Path(directory) / "manifest.json", False),
        ):
            security = windows_acl.capture_path(str(path), directory=is_directory)
            windows_acl.assert_not_broadly_readable(security)
            windows_acl.assert_not_broadly_writable(security)
    else:
        assert stat.S_IMODE(backup_root.stat().st_mode) == 0o700
        assert stat.S_IMODE(Path(directory).stat().st_mode) == 0o700
        assert stat.S_IMODE((Path(directory) / "manifest.json").stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX exchange recovery regression")
def test_private_file_post_exchange_snapshot_failure_retains_exact_original(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private"
    external = tmp_path / "external"
    original = b"ORIGINAL\n"
    target.write_bytes(original)
    external.write_bytes(b"EXTERNAL\n")
    os.chmod(target, 0o600)
    os.chmod(external, 0o600)
    real_exchange = activation_module._exchange_entries

    def replace_published_with_symlink(parent_descriptor, first, second, target_path):
        real_exchange(parent_descriptor, first, second, target_path)
        os.unlink(second, dir_fd=parent_descriptor)
        os.symlink(external.name, second, dir_fd=parent_descriptor)

    monkeypatch.setattr(activation_module, "_exchange_entries", replace_published_with_symlink)

    with pytest.raises(V8ActivationRollbackError) as captured:
        activation_module.update_private_file(
            target,
            owner_directory=tmp_path,
            transform=lambda _source: b"UPDATED\n",
        )

    recovery = Path(captured.value.backup_directory or "")
    assert captured.value.code == "rollback_incomplete"
    assert target.is_symlink()
    assert target.read_bytes() == b"EXTERNAL\n"
    assert recovery.parent == tmp_path
    assert recovery.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="POSIX exchange durability regression")
def test_private_file_publish_fsync_failure_never_requires_reconstruction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private"
    original = b"ORIGINAL\n"
    updated = b"UPDATED\n"
    target.write_bytes(original)
    os.chmod(target, 0o600)
    real_fsync = activation_module.os.fsync
    real_create = activation_module._create_staged_file
    failed_publish_fsync = False
    candidate_calls = 0

    def fail_publish_fsync(descriptor: int) -> None:
        nonlocal failed_publish_fsync
        if not failed_publish_fsync and stat.S_ISDIR(os.fstat(descriptor).st_mode) and target.read_bytes() == updated:
            failed_publish_fsync = True
            raise OSError(errno.EIO, "injected publication fsync failure")
        real_fsync(descriptor)

    def fail_reconstruction(parent_descriptor: int, basename: str, purpose: str):
        nonlocal candidate_calls
        if purpose == "candidate":
            candidate_calls += 1
            if candidate_calls == 2:
                raise OSError(errno.EIO, "injected reconstruction staging failure")
        return real_create(parent_descriptor, basename, purpose)

    monkeypatch.setattr(activation_module.os, "fsync", fail_publish_fsync)
    monkeypatch.setattr(activation_module, "_create_staged_file", fail_reconstruction)

    with pytest.raises(V8ActivationRollbackError) as captured:
        activation_module.update_private_file(
            target,
            owner_directory=tmp_path,
            transform=lambda _source: updated,
        )

    recovery = Path(captured.value.backup_directory or "")
    assert captured.value.code == "rollback_incomplete"
    assert failed_publish_fsync
    assert candidate_calls == 1
    assert target.read_bytes() == updated
    assert recovery.parent == tmp_path
    assert recovery.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="POSIX absent-target rollback regression")
def test_private_file_absent_rollback_retains_raced_writers_without_unlinking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private"
    external = tmp_path / "external"
    external_payload = b"EXTERNAL\n"
    later_payload = b"LATER\n"
    external.write_bytes(external_payload)
    os.chmod(external, 0o600)
    real_rename = activation_module._rename_entry_no_replace
    rename_calls = 0

    def race_rollback(parent_descriptor, source, destination, target_path):
        nonlocal rename_calls
        rename_calls += 1
        if rename_calls == 1:
            os.replace(
                external.name,
                target.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
        elif rename_calls == 2:
            descriptor = os.open(
                target.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_descriptor,
            )
            try:
                os.write(descriptor, later_payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        real_rename(parent_descriptor, source, destination, target_path)

    monkeypatch.setattr(activation_module, "_rename_entry_no_replace", race_rollback)
    monkeypatch.setattr(
        activation_module,
        "_assert_expected_file_state",
        lambda path, _expected: (_ for _ in ()).throw(
            V8ActivationError("injected_post_publish_failure", "activation_verification", target_path=path)
        ),
    )

    with pytest.raises(V8ActivationRollbackError) as captured:
        activation_module.update_private_file(
            target,
            owner_directory=tmp_path,
            transform=lambda _source: b"CANDIDATE\n",
        )

    recovery = Path(captured.value.backup_directory or "")
    assert captured.value.code == "rollback_incomplete"
    assert rename_calls == 2
    assert target.read_bytes() == later_payload
    assert recovery.parent == tmp_path
    assert recovery.read_bytes() == external_payload


@pytest.mark.skipif(os.name == "nt", reason="POSIX absent-target cleanup regression")
def test_absent_rollback_does_not_report_deleted_recovery_after_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private"
    target.write_bytes(b"CANDIDATE\n")
    os.chmod(target, 0o600)
    snapshot = activation_module._snapshot_regular_file(str(target), required=True)
    parent_descriptor = activation_module._open_pinned_parent(snapshot)
    real_fsync = activation_module.os.fsync
    directory_fsyncs = 0

    def fail_if_cleanup_fsyncs(descriptor: int) -> None:
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs > 1:
                raise OSError(errno.EIO, "injected post-cleanup fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(activation_module.os, "fsync", fail_if_cleanup_fsyncs)
    try:
        activation_module._restore_absent_posix_target(
            snapshot,
            parent_descriptor=parent_descriptor,
            parent=str(tmp_path),
        )
    finally:
        os.close(parent_descriptor)

    assert directory_fsyncs == 1
    assert not target.exists()
    assert not list(tmp_path.glob(".private.observability-v8-rollback-*.tmp"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX exchange preflight regression")
def test_private_file_preflight_exercises_exchange_before_candidate_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private"
    original = b"ORIGINAL\n"
    target.write_bytes(original)
    os.chmod(target, 0o600)
    real_create = activation_module._create_staged_file
    purposes: list[str] = []

    def record_create(parent_descriptor: int, basename: str, purpose: str):
        purposes.append(purpose)
        return real_create(parent_descriptor, basename, purpose)

    def reject_exchange(*_args, **_kwargs) -> None:
        raise V8ActivationError("atomic_exchange_failed", "locked_publish_check", target_path=str(target))

    monkeypatch.setattr(activation_module, "_create_staged_file", record_create)
    monkeypatch.setattr(activation_module, "_exchange_probe_entries", reject_exchange)

    with pytest.raises(V8ActivationError) as captured:
        activation_module.update_private_file(
            target,
            owner_directory=tmp_path,
            transform=lambda _source: b"SECRET-CANDIDATE\n",
        )

    assert captured.value.code == "atomic_exchange_failed"
    assert purposes == ["preflight", "exchange"]
    assert target.read_bytes() == original
    assert not list(tmp_path.glob(".private.observability-v8-*.tmp"))
