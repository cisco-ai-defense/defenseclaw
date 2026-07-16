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

import hashlib
import os
import struct
import sys
from pathlib import Path
from typing import Any

import defenseclaw.observability.v8_activation as activation
import pytest
from defenseclaw.observability.v8_activation import V8ActivationError, activate_v8_migration
from defenseclaw.observability.v8_migration import (
    EnvironmentEdit,
    EnvironmentReference,
    V8MigrationResult,
    V8MigrationSummary,
)
from defenseclaw.windows_acl import WindowsAclError, WindowsFileSecurity

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX-hosted mocked Win32 transaction tests")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sid(*subauthorities: int, authority: int = 5) -> bytes:
    return (
        bytes((1, len(subauthorities)))
        + authority.to_bytes(6, "big")
        + b"".join(struct.pack("<I", value) for value in subauthorities)
    )


def _dacl(*aces: tuple[int, int, int, bytes]) -> bytes:
    payload = b""
    for ace_type, ace_flags, access_mask, sid in aces:
        size = 8 + len(sid)
        payload += struct.pack("<BBHI", ace_type, ace_flags, size, access_mask) + sid
    return struct.pack("<BBHHH", 2, 0, 8 + len(payload), len(aces), 0) + payload


OWNER = _sid(21, 101, 202, 303, 1001)
SYSTEM = _sid(18)
ADMINISTRATORS = _sid(32, 544)
USERS = _sid(32, 545)
CONFIG_SECURITY = WindowsFileSecurity(OWNER, _dacl((0, 0, 0x001F01FF, OWNER)), False)
ENVIRONMENT_SECURITY = WindowsFileSecurity(
    OWNER,
    _dacl((0, 0, 0x001F01FF, OWNER), (0, 0, 0x001F01FF, SYSTEM)),
    True,
)
PRIVATE_SECURITY = WindowsFileSecurity(
    OWNER,
    _dacl(
        (0, 0, 0x001F01FF, OWNER),
        (0, 0, 0x001F01FF, SYSTEM),
        (0, 0, 0x001F01FF, ADMINISTRATORS),
    ),
    True,
)
UNPROTECTED_PRIVATE_SECURITY = WindowsFileSecurity(
    PRIVATE_SECURITY.owner,
    PRIVATE_SECURITY.dacl,
    False,
)
HIGH_MANDATORY_LABEL = _dacl(
    (0x11, 0, 0x00000003, _sid(0x3000, authority=16)),
)
LABELED_ENVIRONMENT_SECURITY = WindowsFileSecurity(
    ENVIRONMENT_SECURITY.owner,
    ENVIRONMENT_SECURITY.dacl,
    ENVIRONMENT_SECURITY.dacl_protected,
    HIGH_MANDATORY_LABEL,
    True,
)
BROAD_DIRECTORY_SECURITY = WindowsFileSecurity(
    OWNER,
    _dacl((0, 0, 0x001F01FF, USERS)),
    False,
)


class _MockWindowsAcl:
    """Path-backed Win32 API model used while pytest itself runs on POSIX."""

    def __init__(self) -> None:
        self.security: dict[str, WindowsFileSecurity] = {}
        self.claimed_fds: dict[int, str] = {}
        self.flushes: list[str] = []
        self.tamper_publish_name: str | None = None
        self.tampered = False
        self.drop_dacl_protection_name: str | None = None
        self.dropped_dacl_protection = 0
        self.security_repairs: list[str] = []
        self.mismatches: list[tuple[Any, Any]] = []

    @staticmethod
    def _key(path: str | os.PathLike[str]) -> str:
        return os.path.abspath(os.fspath(path))

    def register(self, path: Path, security: WindowsFileSecurity) -> None:
        self.security[self._key(path)] = security

    @staticmethod
    def _fd_path(descriptor: int) -> str:
        if sys.platform == "darwin":
            import fcntl

            return fcntl.fcntl(descriptor, 50, b"\0" * 1024).split(b"\0", 1)[0].decode()
        return os.readlink(f"/proc/self/fd/{descriptor}")

    def capture_fd(self, descriptor: int) -> WindowsFileSecurity:
        return self.security[self._key(self._fd_path(descriptor))]

    def capture_path(self, path: str, *, directory: bool = False) -> WindowsFileSecurity:
        key = self._key(path)
        return self.security.get(key, PRIVATE_SECURITY)

    def apply_path(self, path: str, security: WindowsFileSecurity, *, directory: bool = False) -> None:
        self.security[self._key(path)] = security

    def private_security_for_directory(self, path: str) -> WindowsFileSecurity:
        return PRIVATE_SECURITY

    def write_new_file(self, path: str, payload: bytes, security: WindowsFileSecurity) -> None:
        key = self._key(path)
        if os.path.lexists(key):
            raise WindowsAclError("CREATE_NEW target exists")
        with open(key, "xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        self.security[key] = security.staging_copy()

    def open_regular_mutation_fd(self, path: str) -> int:
        key = self._key(path)
        descriptor = os.open(key, os.O_RDONLY)
        self.claimed_fds[descriptor] = key
        return descriptor

    def open_regular_security_mutation_fd(self, path: str) -> int:
        key = self._key(path)
        descriptor = os.open(key, os.O_RDWR)
        self.claimed_fds[descriptor] = key
        return descriptor

    def apply_fd(self, descriptor: int, security: WindowsFileSecurity) -> None:
        key = self.claimed_fds[descriptor]
        self.security[key] = security
        self.security_repairs.append(key)

    def flush_fd(self, descriptor: int) -> None:
        os.fsync(descriptor)
        self.flushes.append(self.claimed_fds[descriptor])

    def move_regular_fd_no_replace(self, descriptor: int, target: str) -> None:
        source_key = self._key(self._fd_path(descriptor))
        target_key = self._key(target)
        if os.path.lexists(target_key):
            raise WindowsAclError("handle-bound move target exists")
        os.replace(source_key, target_key)
        self.security[target_key] = self.security.pop(source_key)
        self.claimed_fds[descriptor] = target_key

    def delete_regular_fd(self, descriptor: int) -> None:
        source_key = self._key(self._fd_path(descriptor))
        os.unlink(source_key)
        self.security.pop(source_key, None)

    def flush_path(self, path: str) -> None:
        self.flushes.append(self._key(path))

    def external_replace(self, path: Path, payload: bytes, security: WindowsFileSecurity) -> None:
        key = self._key(path)
        for descriptor, claimed in self.claimed_fds.items():
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            if claimed == key:
                raise WindowsAclError("sharing violation")
        path.write_bytes(payload)
        self.security[key] = security

    def replace_file(self, target: str, replacement: str, backup: str) -> None:
        target_key = self._key(target)
        replacement_key = self._key(replacement)
        backup_key = self._key(backup)
        if os.path.lexists(backup_key):
            raise WindowsAclError("ReplaceFile backup exists")
        target_security = self.security[target_key]
        replacement_security = self.security[replacement_key]
        os.replace(target_key, backup_key)
        self.security[backup_key] = target_security
        os.replace(replacement_key, target_key)
        self.security.pop(replacement_key, None)
        result = WindowsFileSecurity(
            replacement_security.owner,
            target_security.dacl,
            target_security.dacl_protected,
            replacement_security.mandatory_label,
            replacement_security.sacl_protected,
        )
        if (
            self.tamper_publish_name == os.path.basename(target_key)
            and not self.tampered
            and ".observability-v8-" not in os.path.basename(target_key)
        ):
            result = WindowsFileSecurity(result.owner, _dacl((0, 0, 0x001F01FF, USERS)), False)
            self.tampered = True
        if (
            self.drop_dacl_protection_name is not None
            and self.drop_dacl_protection_name in os.path.basename(target_key)
            and result.dacl_protected
        ):
            result = WindowsFileSecurity(
                result.owner,
                result.dacl,
                False,
                result.mandatory_label,
                result.sacl_protected,
            )
            self.dropped_dacl_protection += 1
        self.security[target_key] = result

    def move_file_no_replace(self, source: str, target: str) -> None:
        source_key = self._key(source)
        target_key = self._key(target)
        if os.path.lexists(target_key):
            raise WindowsAclError("MoveFile target exists")
        os.replace(source_key, target_key)
        self.security[target_key] = self.security.pop(source_key)

    @staticmethod
    def assert_trusted_owner(_security: WindowsFileSecurity) -> None:
        return

    @staticmethod
    def assert_not_broadly_writable(_security: WindowsFileSecurity) -> None:
        return

    @staticmethod
    def assert_not_broadly_readable(_security: WindowsFileSecurity) -> None:
        return


def _fixture(tmp_path: Path, *, environment_exists: bool) -> dict[str, Any]:
    data_dir = tmp_path / "data"
    config_dir = tmp_path / "config"
    data_dir.mkdir()
    config_dir.mkdir()
    config_path = config_dir / "custom.yaml"
    environment_path = data_dir / ".env"
    source = b"config_version: 7\ncustom: keep\n"
    candidate = (
        b"config_version: 8\ncustom: keep\nobservability:\n  destinations:\n"
        b"    - name: fixture-http\n      kind: http_jsonl\n      headers:\n"
        b"        X-Fixture:\n          env: MIGRATED_HEADER_TEST_SECRET\n"
    )
    config_path.write_bytes(source)
    environment = b"EXISTING='keep'\n" if environment_exists else None
    if environment is not None:
        environment_path.write_bytes(environment)
    secret = "private token value"
    edit = EnvironmentEdit(
        name="MIGRATED_HEADER_TEST_SECRET",
        value=secret,
        value_sha256=_sha256(secret.encode()),
        references=(EnvironmentReference("fixture-http", ("headers", "X-Fixture", "env")),),
    )
    summary = V8MigrationSummary(7, 8, 0, 0, 0, 1, "unchanged", "unchanged", "unchanged")
    migration = V8MigrationResult(
        candidate=candidate,
        source_sha256=_sha256(source),
        candidate_sha256=_sha256(candidate),
        changed=True,
        already_v8=False,
        effective_data_dir=str(data_dir),
        warnings=(),
        environment_edits=(edit,),
        summary=summary,
    )
    return {
        "data_dir": data_dir,
        "config_path": config_path,
        "environment_path": environment_path,
        "source": source,
        "candidate": candidate,
        "environment": environment,
        "secret": secret,
        "migration": migration,
    }


def _install_mock(monkeypatch: pytest.MonkeyPatch, fixture: dict[str, Any]) -> _MockWindowsAcl:
    mock = _MockWindowsAcl()
    mock.register(fixture["config_path"], CONFIG_SECURITY)
    if fixture["environment"] is not None:
        mock.register(fixture["environment_path"], ENVIRONMENT_SECURITY)
    monkeypatch.setattr(activation, "_is_windows", lambda: True)
    monkeypatch.setattr(activation, "_read_xattrs", lambda _descriptor, _path: ())
    for name in (
        "capture_fd",
        "capture_path",
        "apply_fd",
        "apply_path",
        "flush_fd",
        "private_security_for_directory",
        "write_new_file",
        "open_regular_mutation_fd",
        "open_regular_security_mutation_fd",
        "move_regular_fd_no_replace",
        "delete_regular_fd",
        "flush_path",
        "replace_file",
        "move_file_no_replace",
        "assert_trusted_owner",
        "assert_not_broadly_writable",
        "assert_not_broadly_readable",
    ):
        monkeypatch.setattr(activation.windows_acl, name, getattr(mock, name))
    original_matches = activation._matches_expected_state

    def track_matches(current, expected):
        result = original_matches(current, expected)
        if not result:
            mock.mismatches.append((current, expected))
        return result

    monkeypatch.setattr(activation, "_matches_expected_state", track_matches)
    return mock


def _validator(fixture: dict[str, Any]):
    def validate(candidate: bytes, environment: Any) -> None:
        assert candidate == fixture["candidate"]
        assert environment["MIGRATED_HEADER_TEST_SECRET"] == fixture["secret"]

    return validate


@pytest.mark.parametrize("environment_exists", [False, True])
def test_windows_activation_preserves_exact_existing_owner_and_dacl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    environment_exists: bool,
) -> None:
    fixture = _fixture(tmp_path, environment_exists=environment_exists)
    mock = _install_mock(monkeypatch, fixture)
    if not environment_exists:
        monkeypatch.setattr(
            activation.windows_acl,
            "private_security_for_directory",
            lambda _path: UNPROTECTED_PRIVATE_SECURITY,
        )

    result = activate_v8_migration(
        fixture["migration"],
        validator=_validator(fixture),
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
        tighten_legacy_backup_root=True,
        environment={},
    )

    assert result.activated is True
    assert fixture["config_path"].read_bytes() == fixture["candidate"]
    assert mock.security[mock._key(fixture["config_path"])] == CONFIG_SECURITY
    assert fixture["secret"].encode() in fixture["environment_path"].read_bytes()
    expected_environment_security = (
        ENVIRONMENT_SECURITY if environment_exists else UNPROTECTED_PRIVATE_SECURITY.staging_copy()
    )
    assert mock.security[mock._key(fixture["environment_path"])] == expected_environment_security


def test_windows_fault_after_both_publications_restores_exact_owner_dacl_and_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, environment_exists=True)
    mock = _install_mock(monkeypatch, fixture)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            tighten_legacy_backup_root=True,
            environment={},
            fault_injector=lambda stage: (
                (_ for _ in ()).throw(RuntimeError("fault")) if stage == "after_config_write" else None
            ),
        )

    assert captured.value.code == "injected_failure"
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    assert mock.security[mock._key(fixture["config_path"])] == CONFIG_SECURITY
    assert mock.security[mock._key(fixture["environment_path"])] == ENVIRONMENT_SECURITY


def test_windows_replace_dacl_protection_drift_is_repaired_on_exact_published_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, environment_exists=True)
    mock = _install_mock(monkeypatch, fixture)
    mock.register(fixture["config_path"], PRIVATE_SECURITY)
    mock.drop_dacl_protection_name = fixture["config_path"].name

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            tighten_legacy_backup_root=True,
            environment={},
            fault_injector=lambda stage: (
                (_ for _ in ()).throw(RuntimeError("fault")) if stage == "after_config_write" else None
            ),
        )

    config_key = mock._key(fixture["config_path"])
    assert captured.value.code == "injected_failure"
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert mock.security[config_key] == PRIVATE_SECURITY
    assert mock.dropped_dacl_protection == 3
    assert mock.security_repairs.count(config_key) == 2


def test_post_publish_dacl_drift_preserves_live_state_and_retained_original(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, environment_exists=True)
    mock = _install_mock(monkeypatch, fixture)
    mock.tamper_publish_name = fixture["config_path"].name

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            tighten_legacy_backup_root=True,
            environment={},
        )

    assert captured.value.code == "rollback_incomplete"
    assert mock.tampered is True
    assert fixture["config_path"].read_bytes() == fixture["candidate"]
    assert fixture["secret"].encode() in fixture["environment_path"].read_bytes()
    assert mock.security[mock._key(fixture["config_path"])] != CONFIG_SECURITY
    recovery = Path(captured.value.backup_directory or "")
    assert recovery.exists()
    assert recovery.read_bytes() == fixture["source"]
    assert mock.security[mock._key(recovery)] == CONFIG_SECURITY
    recovery.unlink()


def test_windows_private_file_cas_restores_concurrent_pre_replace_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, environment_exists=True)
    mock = _install_mock(monkeypatch, fixture)
    target = fixture["environment_path"]
    concurrent = b"EXTERNAL_ROTATION=preserve\n"
    concurrent_security = WindowsFileSecurity(
        OWNER,
        _dacl((0, 0, 0x001F01FF, OWNER), (0, 0, 0x80000000, SYSTEM)),
        True,
    )
    real_replace = mock.replace_file
    raced = False

    def race_before_replace(target_path: str, replacement: str, backup: str) -> None:
        nonlocal raced
        if mock._key(target_path) == mock._key(target) and not raced:
            raced = True
            Path(target_path).write_bytes(concurrent)
            mock.security[mock._key(target_path)] = concurrent_security
        real_replace(target_path, replacement, backup)

    monkeypatch.setattr(activation.windows_acl, "replace_file", race_before_replace)

    with pytest.raises(V8ActivationError) as captured:
        activation.update_private_file(
            target,
            owner_directory=fixture["data_dir"],
            transform=lambda _payload: b"UPDATED=ours\n",
            environment={},
        )

    assert captured.value.code == "source_changed"
    assert raced
    assert target.read_bytes() == concurrent
    assert mock.security[mock._key(target)] == concurrent_security
    assert not list(fixture["data_dir"].glob("..env.observability-v8-*.tmp"))


def test_windows_private_file_post_replace_external_target_is_never_clobbered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, environment_exists=True)
    mock = _install_mock(monkeypatch, fixture)
    target = fixture["environment_path"]
    original = target.read_bytes()
    external = b"EXTERNAL_AFTER_REPLACE=authoritative\n"
    external_security = WindowsFileSecurity(
        OWNER,
        _dacl((0, 0, 0x001F01FF, OWNER), (0, 0, 0x80000000, SYSTEM)),
        True,
    )
    real_replace = mock.replace_file
    raced = False

    def race_after_replace(target_path: str, replacement: str, backup: str) -> None:
        nonlocal raced
        real_replace(target_path, replacement, backup)
        if mock._key(target_path) == mock._key(target) and not raced:
            raced = True
            Path(target_path).write_bytes(external)
            mock.security[mock._key(target_path)] = external_security

    monkeypatch.setattr(activation.windows_acl, "replace_file", race_after_replace)

    with pytest.raises(activation.V8ActivationRollbackError) as captured:
        activation.update_private_file(
            target,
            owner_directory=fixture["data_dir"],
            transform=lambda _payload: b"UPDATED=ours\n",
            environment={},
        )

    recovery = Path(captured.value.backup_directory or "")
    assert captured.value.code == "rollback_incomplete"
    assert raced
    assert target.read_bytes() == external
    assert mock.security[mock._key(target)] == external_security
    assert recovery.exists()
    assert recovery.read_bytes() == original
    assert mock.security[mock._key(recovery)] == ENVIRONMENT_SECURITY
    recovery.unlink()


def test_windows_private_file_restore_claim_blocks_later_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, environment_exists=True)
    mock = _install_mock(monkeypatch, fixture)
    target = fixture["environment_path"]
    first = b"EXTERNAL_FIRST=preserve\n"
    later = b"EXTERNAL_LATER=must-remain-live\n"
    real_replace = mock.replace_file
    real_move = mock.move_regular_fd_no_replace
    raced = False
    blocked = False

    def race_before_replace(target_path: str, replacement: str, backup: str) -> None:
        nonlocal raced
        if mock._key(target_path) == mock._key(target) and not raced:
            raced = True
            mock.external_replace(target, first, ENVIRONMENT_SECURITY)
        real_replace(target_path, replacement, backup)

    def race_during_restore(descriptor: int, destination: str) -> None:
        nonlocal blocked
        claimed = mock.claimed_fds.get(descriptor)
        if claimed == mock._key(target) and "discard-" in os.path.basename(destination):
            with pytest.raises(WindowsAclError, match="sharing violation"):
                mock.external_replace(target, later, CONFIG_SECURITY)
            blocked = True
        real_move(descriptor, destination)

    monkeypatch.setattr(activation.windows_acl, "replace_file", race_before_replace)
    monkeypatch.setattr(activation.windows_acl, "move_regular_fd_no_replace", race_during_restore)

    with pytest.raises(V8ActivationError) as captured:
        activation.update_private_file(
            target,
            owner_directory=fixture["data_dir"],
            transform=lambda _payload: b"UPDATED=ours\n",
            environment={},
        )

    assert captured.value.code == "source_changed"
    assert raced and blocked
    assert target.read_bytes() == first
    mock.external_replace(target, later, CONFIG_SECURITY)
    assert target.read_bytes() == later
    assert mock.security[mock._key(target)] == CONFIG_SECURITY


def test_windows_private_file_incomplete_restore_reports_every_recovery_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, environment_exists=True)
    mock = _install_mock(monkeypatch, fixture)
    target = fixture["environment_path"]
    external = b"EXTERNAL_ROTATION=recover-me\n"
    real_replace = mock.replace_file
    raced = False

    def race_before_replace(target_path: str, replacement: str, backup: str) -> None:
        nonlocal raced
        if mock._key(target_path) == mock._key(target) and not raced:
            raced = True
            mock.external_replace(target, external, ENVIRONMENT_SECURITY)
        real_replace(target_path, replacement, backup)

    def fail_restore(_descriptor: int, _destination: str) -> None:
        raise WindowsAclError("injected handle-bound restore failure")

    monkeypatch.setattr(activation.windows_acl, "replace_file", race_before_replace)
    monkeypatch.setattr(activation.windows_acl, "move_regular_fd_no_replace", fail_restore)

    with pytest.raises(activation.V8ActivationRollbackError) as captured:
        activation.update_private_file(
            target,
            owner_directory=fixture["data_dir"],
            transform=lambda _payload: b"UPDATED=ours\n",
            environment={},
        )

    recovery_paths = tuple(Path(path) for path in captured.value.recovery_paths)
    assert captured.value.code == "rollback_incomplete"
    assert captured.value.backup_directory is not None
    assert Path(captured.value.backup_directory) in recovery_paths
    assert target in recovery_paths
    assert target.read_bytes() == b"UPDATED=ours\n"
    assert any(path.exists() and path.read_bytes() == external for path in recovery_paths)
    for path in recovery_paths:
        if path != target and path.exists():
            path.unlink()


def test_windows_private_file_preserves_mandatory_label_and_flushes_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, environment_exists=True)
    mock = _install_mock(monkeypatch, fixture)
    target = fixture["environment_path"]
    mock.register(target, LABELED_ENVIRONMENT_SECURITY)

    changed = activation.update_private_file(
        target,
        owner_directory=fixture["data_dir"],
        transform=lambda _payload: b"UPDATED=with-label\n",
        environment={},
    )

    assert changed is True
    assert target.read_bytes() == b"UPDATED=with-label\n"
    assert mock.security[mock._key(target)] == LABELED_ENVIRONMENT_SECURITY
    assert mock.flushes[-1] == mock._key(target)


def test_windows_absent_target_rollback_claim_blocks_concurrent_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, environment_exists=False)
    mock = _install_mock(monkeypatch, fixture)
    target = fixture["environment_path"]
    external = b"EXTERNAL_CREATE=after-rollback\n"
    real_delete = mock.delete_regular_fd
    blocked = False

    def fail_flush(path: str) -> None:
        if mock._key(path) == mock._key(target):
            raise WindowsAclError("injected publication flush failure")
        mock.flush_path(path)

    def race_delete(descriptor: int) -> None:
        nonlocal blocked
        with pytest.raises(WindowsAclError, match="sharing violation"):
            mock.external_replace(target, external, CONFIG_SECURITY)
        blocked = True
        real_delete(descriptor)

    monkeypatch.setattr(activation.windows_acl, "flush_path", fail_flush)
    monkeypatch.setattr(activation.windows_acl, "delete_regular_fd", race_delete)

    with pytest.raises(WindowsAclError, match="flush failure"):
        activation.update_private_file(
            target,
            owner_directory=fixture["data_dir"],
            transform=lambda _payload: b"UPDATED=ours\n",
            environment={},
        )

    assert blocked
    assert not target.exists()
    mock.external_replace(target, external, CONFIG_SECURITY)
    assert target.read_bytes() == external


def test_windows_private_file_parent_acl_drift_cannot_return_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, environment_exists=True)
    mock = _install_mock(monkeypatch, fixture)
    target = fixture["environment_path"]
    before = target.read_bytes()
    real_capture = mock.capture_path
    real_replace = mock.replace_file
    drifted = False

    def capture_path(path: str, *, directory: bool = False) -> WindowsFileSecurity:
        if drifted and directory and mock._key(path) == mock._key(fixture["data_dir"]):
            return BROAD_DIRECTORY_SECURITY
        return real_capture(path, directory=directory)

    def assert_not_broadly_writable(security: WindowsFileSecurity) -> None:
        if security == BROAD_DIRECTORY_SECURITY:
            raise WindowsAclError("broad parent write access")

    def drift_after_publish(target_path: str, replacement: str, backup: str) -> None:
        nonlocal drifted
        real_replace(target_path, replacement, backup)
        if mock._key(target_path) == mock._key(target):
            drifted = True

    monkeypatch.setattr(activation.windows_acl, "capture_path", capture_path)
    monkeypatch.setattr(
        activation.windows_acl,
        "assert_not_broadly_writable",
        assert_not_broadly_writable,
    )
    monkeypatch.setattr(activation.windows_acl, "replace_file", drift_after_publish)

    with pytest.raises(V8ActivationError) as captured:
        activation.update_private_file(
            target,
            owner_directory=fixture["data_dir"],
            transform=lambda _payload: b"UPDATED=ours\n",
            environment={},
        )

    assert captured.value.code == "parent_acl_unsafe"
    assert drifted
    assert target.read_bytes() == before
