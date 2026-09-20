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
import stat
from pathlib import Path
from typing import Any

import defenseclaw.observability.v8_activation as activation_module
import pytest
from defenseclaw import windows_acl
from defenseclaw.observability import v8_activation as activation
from defenseclaw.observability.v8_activation import (
    V8ActivationError,
    activate_v8_migration,
    update_private_file,
)
from defenseclaw.observability.v8_migration import (
    EnvironmentEdit,
    EnvironmentReference,
    V8MigrationResult,
    V8MigrationSummary,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires native Windows owner/DACL APIs")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fixture(tmp_path: Path) -> dict[str, Any]:
    data_dir = tmp_path / "data"
    config_dir = tmp_path / "config"
    data_dir.mkdir()
    config_dir.mkdir()

    # The transaction validates direct-parent DACLs. Protect both fixture
    # directories explicitly so the test is independent of runner inheritance.
    inherited = windows_acl.private_security_for_directory(str(tmp_path))
    windows_acl.apply_path(str(data_dir), inherited, directory=True)
    windows_acl.apply_path(str(config_dir), inherited, directory=True)

    config_path = config_dir / "custom.yaml"
    environment_path = data_dir / ".env"
    source = b"config_version: 7\r\ncustom: keep\r\n"
    candidate = (
        b"config_version: 8\r\ncustom: keep\r\nobservability:\r\n  destinations:\r\n"
        b"    - name: fixture-http\r\n      kind: http_jsonl\r\n      headers:\r\n"
        b"        X-Fixture:\r\n          env: MIGRATED_HEADER_TEST_SECRET\r\n"
    )
    config_path.write_bytes(source)
    environment = b"EXISTING='keep'\r\n"
    environment_path.write_bytes(environment)
    windows_acl.apply_path(str(config_path), inherited)
    windows_acl.apply_path(str(environment_path), inherited)
    config_security = windows_acl.capture_path(str(config_path))
    environment_security = windows_acl.capture_path(str(environment_path))

    secret = "native private token"
    edit = EnvironmentEdit(
        name="MIGRATED_HEADER_TEST_SECRET",
        value=secret,
        value_sha256=_sha256(secret.encode()),
        references=(EnvironmentReference("fixture-http", ("headers", "X-Fixture", "env")),),
    )
    migration = V8MigrationResult(
        candidate=candidate,
        source_sha256=_sha256(source),
        candidate_sha256=_sha256(candidate),
        changed=True,
        already_v8=False,
        effective_data_dir=str(data_dir),
        warnings=(),
        environment_edits=(edit,),
        summary=V8MigrationSummary(7, 8, 0, 0, 0, 1, "unchanged", "unchanged", "unchanged"),
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
        "config_security": config_security,
        "environment_security": environment_security,
    }


def _validator(fixture: dict[str, Any]):
    def validate(candidate: bytes, environment: Any) -> None:
        assert candidate == fixture["candidate"]
        assert environment["MIGRATED_HEADER_TEST_SECRET"] == fixture["secret"]

    return validate


def test_native_windows_snapshot_preserves_raw_crlf_bytes_and_digest(tmp_path: Path) -> None:
    path = tmp_path / "raw-crlf.yaml"
    payload = b"config_version: 7\r\ncustom: keep\r\n"
    path.write_bytes(payload)

    snapshot = activation_module._snapshot_regular_file(str(path), required=True)

    assert snapshot.payload == payload
    assert snapshot.sha256 == _sha256(payload)


def test_native_windows_activation_preserves_exact_owner_and_dacl(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

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
    assert fixture["secret"].encode() in fixture["environment_path"].read_bytes()
    assert windows_acl.capture_path(str(fixture["config_path"])) == fixture["config_security"]
    assert windows_acl.capture_path(str(fixture["environment_path"])) == fixture["environment_security"]


def test_native_windows_new_environment_is_private_before_secret_publish(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture["environment_path"].unlink()
    expected = windows_acl.private_security_for_directory(str(fixture["data_dir"]))

    result = activate_v8_migration(
        fixture["migration"],
        validator=_validator(fixture),
        data_dir=fixture["data_dir"],
        config_path=fixture["config_path"],
        tighten_legacy_backup_root=True,
        environment={},
    )

    assert result.activated is True
    assert fixture["secret"].encode() in fixture["environment_path"].read_bytes()
    actual = windows_acl.capture_path(str(fixture["environment_path"]))
    assert actual == expected.staging_copy()
    windows_acl.assert_not_broadly_readable(actual)


def test_native_windows_rollback_removes_new_environment_and_restores_config(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture["environment_path"].unlink()

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            tighten_legacy_backup_root=True,
            environment={},
            fault_injector=lambda stage: (
                (_ for _ in ()).throw(RuntimeError("native fault")) if stage == "after_config_write" else None
            ),
        )

    assert captured.value.code == "injected_failure"
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert not fixture["environment_path"].exists()
    assert windows_acl.capture_path(str(fixture["config_path"])) == fixture["config_security"]


def test_native_windows_rollback_restores_exact_owner_dacl_and_bytes(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            tighten_legacy_backup_root=True,
            environment={},
            fault_injector=lambda stage: (
                (_ for _ in ()).throw(RuntimeError("native fault")) if stage == "after_config_write" else None
            ),
        )

    assert captured.value.code == "injected_failure"
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    assert windows_acl.capture_path(str(fixture["config_path"])) == fixture["config_security"]
    assert windows_acl.capture_path(str(fixture["environment_path"])) == fixture["environment_security"]


def test_native_windows_repairs_replacefile_dacl_protection_drift_on_exact_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    real_replace = windows_acl.replace_file
    dropped = 0

    def replace_then_drop_protection(target: str, replacement: str, backup: str) -> None:
        nonlocal dropped
        real_replace(target, replacement, backup)
        current = windows_acl.capture_path(target)
        if fixture["config_path"].name in Path(target).name and current.dacl_protected:
            windows_acl.apply_path(
                target,
                windows_acl.WindowsFileSecurity(
                    current.owner,
                    current.dacl,
                    False,
                    current.mandatory_label,
                    current.sacl_protected,
                ),
            )
            dropped += 1

    monkeypatch.setattr(windows_acl, "replace_file", replace_then_drop_protection)

    with pytest.raises(V8ActivationError) as captured:
        activate_v8_migration(
            fixture["migration"],
            validator=_validator(fixture),
            data_dir=fixture["data_dir"],
            config_path=fixture["config_path"],
            tighten_legacy_backup_root=True,
            environment={},
            fault_injector=lambda stage: (
                (_ for _ in ()).throw(RuntimeError("native fault")) if stage == "after_config_write" else None
            ),
        )

    assert captured.value.code == "injected_failure"
    assert dropped == 3
    assert fixture["config_path"].read_bytes() == fixture["source"]
    assert fixture["environment_path"].read_bytes() == fixture["environment"]
    assert windows_acl.capture_path(str(fixture["config_path"])) == fixture["config_security"]
    assert windows_acl.capture_path(str(fixture["environment_path"])) == fixture["environment_security"]


def test_native_windows_same_inode_arbitrary_dacl_drift_remains_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    real_replace = windows_acl.replace_file
    original_security = fixture["config_security"]
    dacl_header = original_security.dacl[:8]
    aces: list[bytes] = []
    cursor = 8
    while cursor < len(original_security.dacl):
        ace_size = int.from_bytes(original_security.dacl[cursor + 2 : cursor + 4], "little")
        aces.append(original_security.dacl[cursor : cursor + ace_size])
        cursor += ace_size
    assert len(aces) >= 3
    drifted_security = windows_acl.WindowsFileSecurity(
        original_security.owner,
        dacl_header + aces[0] + aces[2] + aces[1] + b"".join(aces[3:]),
        original_security.dacl_protected,
        original_security.mandatory_label,
        original_security.sacl_protected,
    )
    assert drifted_security.dacl != fixture["config_security"].dacl
    drifted = False

    def replace_then_drift_dacl(target: str, replacement: str, backup: str) -> None:
        nonlocal drifted
        real_replace(target, replacement, backup)
        if Path(target).name == fixture["config_path"].name and not drifted:
            windows_acl.apply_path(target, drifted_security)
            drifted = True

    monkeypatch.setattr(windows_acl, "replace_file", replace_then_drift_dacl)

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
    assert drifted
    assert fixture["config_path"].read_bytes() == fixture["candidate"]
    assert windows_acl.capture_path(str(fixture["config_path"])) == drifted_security
    recovery = Path(captured.value.backup_directory or "")
    assert recovery.exists()
    assert recovery.read_bytes() == fixture["source"]
    assert windows_acl.capture_path(str(recovery)) == fixture["config_security"]


@pytest.mark.parametrize("mutation", ["readonly", "write_time"])
def test_native_windows_publication_rejects_attribute_or_write_time_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    path = tmp_path / "published.env"
    security = windows_acl.private_security_for_directory(str(tmp_path))
    windows_acl.write_new_file(str(path), b"EXACT=payload\r\n", security)
    staged = activation._snapshot_regular_file(str(path), required=True)
    assert staged.windows_security is not None
    expected = activation._ExpectedFileState(
        existed=True,
        sha256=staged.sha256,
        mode=None,
        uid=None,
        gid=None,
        windows_security=staged.windows_security,
    )
    real_flush = windows_acl.flush_fd

    def flush_then_mutate(descriptor: int) -> None:
        real_flush(descriptor)
        if mutation == "readonly":
            os.chmod(path, stat.S_IREAD)
        else:
            current = path.stat()
            os.utime(
                path,
                ns=(current.st_atime_ns, current.st_mtime_ns + 2_000_000_000),
            )

    monkeypatch.setattr(windows_acl, "flush_fd", flush_then_mutate)
    try:
        with pytest.raises(activation._WindowsPublicationVerificationError):
            activation._repair_and_verify_windows_publication(str(path), staged, expected)
    finally:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def test_native_windows_private_file_update_preserves_exact_security(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    environment_path = fixture["environment_path"]

    changed = update_private_file(
        environment_path,
        owner_directory=fixture["data_dir"],
        transform=lambda payload: payload + b"NATIVE_UPDATE='yes'\r\n",
        environment={},
    )

    assert changed is True
    assert environment_path.read_bytes().endswith(b"NATIVE_UPDATE='yes'\r\n")
    assert windows_acl.capture_path(str(environment_path)) == fixture["environment_security"]


def test_native_windows_private_file_update_creates_private_file(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    environment_path = fixture["environment_path"]
    environment_path.unlink()
    expected = windows_acl.private_security_for_directory(str(fixture["data_dir"]))

    changed = update_private_file(
        environment_path,
        owner_directory=fixture["data_dir"],
        transform=lambda _payload: b"NATIVE_NEW='yes'\r\n",
        environment={},
    )

    assert changed is True
    assert environment_path.read_bytes() == b"NATIVE_NEW='yes'\r\n"
    actual = windows_acl.capture_path(str(environment_path))
    assert actual == expected.staging_copy()
    windows_acl.assert_not_broadly_readable(actual)
