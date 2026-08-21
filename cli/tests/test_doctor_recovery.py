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

"""Focused custody and continuity tests for Doctor recovery planning."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ntpath
import os
import posixpath
import sqlite3
import stat
import subprocess
import sys
from contextlib import closing, nullcontext
from pathlib import Path

import pytest
from defenseclaw import doctor_recovery as recovery
from defenseclaw.doctor_recovery import (
    AuditDBHealthStatus,
    CustodySnapshot,
    DeviceKeyHealthStatus,
    RecoveryApplyStatus,
    RecoveryDisposition,
    RecoveryPublicationError,
    RecoveryRefusedError,
    WindowsDirectoryIdentity,
    apply_audit_db_recovery,
    apply_device_key_recovery,
    inspect_audit_db,
    inspect_device_key,
    plan_missing_audit_db,
    plan_missing_device_key,
)


def _private_data_dir(tmp_path: Path) -> Path:
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o700)
    from defenseclaw.file_permissions import make_private_directory

    make_private_directory(data_dir)
    return data_dir


def test_audit_db_plan_is_read_only_and_requires_explicit_approval(tmp_path: Path) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "audit.db"
    before = tuple(data_dir.iterdir())

    plan = plan_missing_audit_db(target, data_dir=data_dir)

    assert plan.disposition is RecoveryDisposition.READY
    assert plan.reason_code == "missing-target-safe-to-create"
    assert plan.unattended_allowed is True
    assert plan.custody is not None
    assert tuple(data_dir.iterdir()) == before
    assert not target.exists()

    with pytest.raises(RecoveryRefusedError) as exc:
        apply_audit_db_recovery(plan, approved=False)
    assert exc.value.code == "recovery-approval-required"
    assert not target.exists()


def test_recovery_refuses_a_filesystem_root_as_data_dir(tmp_path: Path) -> None:
    root = Path(tmp_path.anchor)
    plan = plan_missing_audit_db(root / "audit.db", data_dir=root)

    assert plan.disposition is RecoveryDisposition.BLOCKED
    assert plan.reason_code == "data-dir-too-broad"


@pytest.mark.parametrize(
    ("path", "path_module", "expected"),
    (
        ("/", posixpath, True),
        ("/var/lib/defenseclaw", posixpath, False),
        ("C:\\", ntpath, True),
        ("D:\\", ntpath, True),
        ("C:\\defenseclaw", ntpath, False),
        ("\\\\server\\share\\", ntpath, True),
        ("\\\\server\\share\\defenseclaw", ntpath, False),
    ),
)
def test_filesystem_root_predicate_covers_windows_drive_and_unc_roots(
    path,
    path_module,
    expected,
) -> None:
    assert (
        recovery._path_is_filesystem_root(  # noqa: SLF001 - pure policy seam.
            path,
            path_module=path_module,
        )
        is expected
    )


def test_audit_db_inspection_distinguishes_missing_invalid_and_valid_state(
    tmp_path: Path,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "audit.db"

    missing = inspect_audit_db(target, data_dir=data_dir)
    assert missing.status is AuditDBHealthStatus.MISSING

    target.write_bytes(b"not sqlite")
    os.chmod(target, 0o600)
    corrupt = inspect_audit_db(target, data_dir=data_dir)
    assert corrupt.status is AuditDBHealthStatus.INVALID
    assert corrupt.reason_code == "audit-db-integrity-unavailable"

    target.unlink()
    with closing(sqlite3.connect(target)) as connection:
        connection.execute("CREATE TABLE audit_events (id INTEGER)")
        connection.commit()
    os.chmod(target, 0o600)
    incomplete = inspect_audit_db(target, data_dir=data_dir)
    assert incomplete.status is AuditDBHealthStatus.INVALID
    assert incomplete.reason_code == "audit-db-schema-incomplete"

    target.unlink()
    plan = plan_missing_audit_db(target, data_dir=data_dir)
    result = apply_audit_db_recovery(plan, approved=True, unattended=True)
    assert result.status is RecoveryApplyStatus.CREATED
    assert inspect_audit_db(target, data_dir=data_dir).status is AuditDBHealthStatus.VALID


def test_audit_db_apply_creates_verified_private_schema(tmp_path: Path) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "audit.db"
    plan = plan_missing_audit_db(target, data_dir=data_dir)

    result = apply_audit_db_recovery(plan, approved=True, unattended=True)

    assert result.status is RecoveryApplyStatus.CREATED
    assert result.created_artifacts == ("audit-db",)
    if os.name == "nt":
        from defenseclaw.windows_acl import (
            assert_not_broadly_readable,
            assert_not_broadly_writable,
            assert_trusted_owner,
            capture_path,
        )

        security = capture_path(target)
        assert_trusted_owner(security)
        assert_not_broadly_writable(security)
        assert_not_broadly_readable(security)
    else:
        assert stat.S_IMODE(os.lstat(target).st_mode) == 0o600
    assert not Path(os.fspath(target) + "-wal").exists()
    assert not Path(os.fspath(target) + "-shm").exists()
    with sqlite3.connect(target) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name IN ('audit_events', 'scan_results', 'findings')"
            )
        }
        assert tables == {"audit_events", "scan_results", "findings"}
    assert plan_missing_audit_db(target, data_dir=data_dir).disposition is RecoveryDisposition.NOT_NEEDED
    assert not any(item.name.startswith(".doctor-audit-db.") for item in data_dir.iterdir())


@pytest.mark.parametrize("suffix", ("-wal", "-shm", "-journal"))
def test_orphaned_sqlite_continuity_blocks_empty_db_creation(
    tmp_path: Path,
    suffix: str,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "audit.db"
    Path(os.fspath(target) + suffix).write_bytes(b"prior-state")

    plan = plan_missing_audit_db(target, data_dir=data_dir)

    assert plan.disposition is RecoveryDisposition.BLOCKED
    assert plan.reason_code == "continuity-evidence-present"
    with pytest.raises(RecoveryRefusedError) as exc:
        apply_audit_db_recovery(plan, approved=True)
    assert exc.value.code == "recovery-plan-not-ready"
    assert not target.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode and symlink custody")
def test_recovery_rejects_writable_or_indirect_custody(tmp_path: Path) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "audit.db"
    os.chmod(data_dir, 0o777)
    try:
        writable = plan_missing_audit_db(target, data_dir=data_dir)
    finally:
        os.chmod(data_dir, 0o700)

    assert writable.disposition is RecoveryDisposition.BLOCKED
    assert writable.reason_code == "directory-chain-is-writable-by-others"

    outside = tmp_path / "outside"
    outside.mkdir()
    linked_parent = data_dir / "linked"
    linked_parent.symlink_to(outside, target_is_directory=True)
    indirect = plan_missing_audit_db(linked_parent / "audit.db", data_dir=data_dir)
    assert indirect.disposition is RecoveryDisposition.BLOCKED
    assert indirect.reason_code == "directory-chain-is-not-regular"


def test_stale_plan_never_overwrites_a_concurrently_created_target(tmp_path: Path) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "audit.db"
    plan = plan_missing_audit_db(target, data_dir=data_dir)
    target.write_bytes(b"preserve-concurrent-file")

    with pytest.raises(RecoveryRefusedError) as exc:
        apply_audit_db_recovery(plan, approved=True)
    assert exc.value.code == "recovery-plan-stale"
    assert target.read_bytes() == b"preserve-concurrent-file"


def test_device_key_continuity_markers_fail_closed(tmp_path: Path) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "device.key"
    provenance = Path(os.fspath(target) + ".provenance")
    provenance.write_text("prior identity", encoding="utf-8")

    plan = plan_missing_device_key(target, data_dir=data_dir)

    assert plan.disposition is RecoveryDisposition.BLOCKED
    assert plan.reason_code == "continuity-evidence-present"
    assert not target.exists()

    provenance.unlink()
    custom_marker = data_dir / "paired-device.receipt"
    custom_marker.write_text("prior pairing", encoding="utf-8")
    custom = plan_missing_device_key(
        target,
        data_dir=data_dir,
        continuity_paths=(custom_marker,),
    )
    assert custom.disposition is RecoveryDisposition.BLOCKED
    assert custom.reason_code == "continuity-evidence-present"


@pytest.mark.parametrize(
    ("relative_target", "reason_code"),
    (
        ("device.provenance.secret", "identity-artifact-alias"),
        (
            os.path.join("device.provenance.secret", "nested", "device.key"),
            "reserved-provenance-secret-path",
        ),
        ("DEVICE.PROVENANCE.SECRET", "identity-artifact-alias"),
        (
            os.path.join("DEVICE.PROVENANCE.SECRET", "nested", "device.key"),
            "reserved-provenance-secret-path",
        ),
    ),
)
def test_device_key_plan_blocks_reserved_artifact_paths_without_mutation(
    tmp_path: Path,
    relative_target: str,
    reason_code: str,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / relative_target
    before = tuple(data_dir.iterdir())

    plan = plan_missing_device_key(target, data_dir=data_dir)

    assert plan.disposition is RecoveryDisposition.BLOCKED
    assert plan.reason_code == reason_code
    with pytest.raises(RecoveryRefusedError) as exc:
        apply_device_key_recovery(plan, approved=True)
    assert exc.value.code == "recovery-plan-not-ready"
    assert tuple(data_dir.iterdir()) == before
    assert not target.exists()


def test_device_key_plan_blocks_relative_and_root_data_dirs_without_mutation(
    tmp_path: Path,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    before = tuple(data_dir.iterdir())

    relative = plan_missing_device_key("device.key", data_dir=data_dir)
    root = Path(tmp_path.anchor)
    broad = plan_missing_device_key(root / "device.key", data_dir=root)

    assert relative.disposition is RecoveryDisposition.BLOCKED
    assert relative.reason_code == "invalid-recovery-path"
    assert broad.disposition is RecoveryDisposition.BLOCKED
    assert broad.reason_code == "data-dir-too-broad"
    assert tuple(data_dir.iterdir()) == before


@pytest.mark.parametrize(
    ("path", "expected"),
    (
        (r"C:\DefenseClaw\device.key", False),
        (r"\\server\share\DefenseClaw\device.key", False),
        (r"\\?\C:\DefenseClaw\device.key", False),
        (r"\\?\UNC\server\share\DefenseClaw\device.key", False),
        (
            r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\DefenseClaw\device.key",
            False,
        ),
        (r"C:\DefenseClaw\device.key:stream", True),
        (r"C:\DefenseClaw:identity\device.key", True),
        (r"C:\DefenseClaw\device.provenance.secret:KEY", True),
        (r"\\server\share\DefenseClaw\device.key:stream", True),
        (r"\\?\C:\DefenseClaw\DEVICE.PROVENANCE.SECRET:key", True),
    ),
)
def test_windows_ads_path_classifier(path: str, expected: bool) -> None:
    assert recovery._windows_path_has_alternate_data_stream(path) is expected


@pytest.mark.skipif(os.name != "nt", reason="native Windows ADS regression")
def test_device_key_plan_blocks_ads_before_custody_or_publication(tmp_path: Path) -> None:
    data_dir = _private_data_dir(tmp_path)
    variants = (
        data_dir / "device.key:stream",
        data_dir / "device.provenance.secret:key",
        data_dir / "DEVICE.PROVENANCE.SECRET:KEY",
        data_dir / "missing" / "device.key:stream",
    )
    for target in variants:
        plan = plan_missing_device_key(target, data_dir=data_dir)
        assert plan.disposition is RecoveryDisposition.BLOCKED
        assert plan.reason_code == "windows-alternate-data-stream-path"
        with pytest.raises(RecoveryRefusedError) as exc:
            apply_device_key_recovery(plan, approved=True)
        assert exc.value.code == "recovery-plan-not-ready"
    assert tuple(data_dir.iterdir()) == ()

    stream_data_dir = Path(os.fspath(data_dir) + ":identity")
    plan = plan_missing_device_key(
        stream_data_dir / "device.key",
        data_dir=stream_data_dir,
    )
    assert plan.disposition is RecoveryDisposition.BLOCKED
    assert plan.reason_code == "windows-alternate-data-stream-path"
    assert tuple(data_dir.iterdir()) == ()

    base = data_dir / "existing-holder"
    base.write_bytes(b"base-preserved")
    stream = Path(os.fspath(base) + ":device-key")
    stream.write_bytes(b"existing-stream")
    plan = plan_missing_device_key(stream, data_dir=data_dir)
    assert plan.disposition is RecoveryDisposition.BLOCKED
    assert plan.reason_code == "windows-alternate-data-stream-path"
    assert base.read_bytes() == b"base-preserved"
    assert not Path(os.fspath(stream) + ".provenance").exists()


def test_device_key_recovery_is_attended_and_provenance_bound(tmp_path: Path) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "device.key"
    plan = plan_missing_device_key(target, data_dir=data_dir)
    assert plan.disposition is RecoveryDisposition.READY
    assert plan.unattended_allowed is False

    with pytest.raises(RecoveryRefusedError) as exc:
        apply_device_key_recovery(plan, approved=True, unattended=True)
    assert exc.value.code == "unattended-recovery-refused"
    assert not target.exists()

    result = apply_device_key_recovery(plan, approved=True)

    assert result.status is RecoveryApplyStatus.CREATED
    assert result.created_artifacts == (
        "device-provenance-secret",
        "device-provenance",
        "device-key",
    )
    provenance = Path(os.fspath(target) + ".provenance")
    secret_path = data_dir / "device.provenance.secret"
    for path in (target, provenance, secret_path):
        if os.name == "nt":
            from defenseclaw.windows_acl import (
                assert_not_broadly_readable,
                assert_not_broadly_writable,
                assert_trusted_owner,
                capture_path,
            )

            security = capture_path(path)
            assert_trusted_owner(security)
            assert_not_broadly_writable(security)
            assert_not_broadly_readable(security)
        else:
            assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600

    key_data = target.read_bytes()
    secret = secret_path.read_bytes()
    prefix = b"defenseclaw-device-provenance-v1:"
    claimed = provenance.read_bytes().strip()[len(prefix) :]
    assert hmac.compare_digest(
        claimed,
        hmac.new(secret, key_data, hashlib.sha256).hexdigest().encode("ascii"),
    )

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    encoded_seed = key_data.strip().splitlines()[1]
    assert Ed25519PrivateKey.from_private_bytes(base64.b64decode(encoded_seed)) is not None
    assert plan_missing_device_key(target, data_dir=data_dir).disposition is RecoveryDisposition.NOT_NEEDED
    assert inspect_device_key(target, data_dir=data_dir).status is DeviceKeyHealthStatus.VALID
    assert not any(item.name.startswith(".doctor-device-") for item in data_dir.iterdir())


def test_device_key_recovery_revalidates_custody_before_each_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "device.key"
    plan = plan_missing_device_key(target, data_dir=data_dir)
    original = recovery._revalidate_directory_custody
    calls = 0

    def counted_revalidation(candidate) -> None:
        nonlocal calls
        calls += 1
        original(candidate)

    monkeypatch.setattr(recovery, "_revalidate_directory_custody", counted_revalidation)

    result = apply_device_key_recovery(plan, approved=True)

    assert result.status is RecoveryApplyStatus.CREATED
    assert calls == 3


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink replacement regression")
def test_device_key_recovery_blocks_replaced_nested_parent_before_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    target_parent = data_dir / "nested"
    target_parent.mkdir(mode=0o700)
    target = target_parent / "device.key"
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    parked = data_dir / "parked"
    plan = plan_missing_device_key(target, data_dir=data_dir)
    original = recovery._revalidate_directory_custody
    calls = 0

    def replace_before_second_publication(candidate) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            target_parent.rename(parked)
            target_parent.symlink_to(outside, target_is_directory=True)
        original(candidate)

    monkeypatch.setattr(
        recovery,
        "_revalidate_directory_custody",
        replace_before_second_publication,
    )

    with pytest.raises(RecoveryRefusedError) as exc:
        apply_device_key_recovery(plan, approved=True)

    assert exc.value.code == "recovery-plan-stale"
    assert calls == 2
    assert not target.exists()
    assert not Path(os.fspath(target) + ".provenance").exists()
    assert tuple(outside.iterdir()) == ()


def test_device_key_inspection_distinguishes_missing_legacy_and_invalid_state(
    tmp_path: Path,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "device.key"

    missing = inspect_device_key(target, data_dir=data_dir)
    assert missing.status is DeviceKeyHealthStatus.MISSING

    target.write_bytes(recovery._new_device_key_pem())
    os.chmod(target, 0o600)
    legacy = inspect_device_key(target, data_dir=data_dir)
    assert legacy.status is DeviceKeyHealthStatus.LEGACY_UNPROVENANCED
    assert legacy.reason_code == "device-key-provenance-absent"

    provenance = Path(os.fspath(target) + ".provenance")
    provenance.write_bytes(b"# DefenseClaw device.key provenance sentinel\nsource=gateway-existing-load\n")
    os.chmod(provenance, 0o600)
    legacy_sentinel = inspect_device_key(target, data_dir=data_dir)
    assert legacy_sentinel.status is DeviceKeyHealthStatus.LEGACY_UNPROVENANCED
    assert legacy_sentinel.reason_code == "device-key-legacy-provenance"

    provenance.write_text("untrusted sentinel", encoding="utf-8")
    invalid = inspect_device_key(target, data_dir=data_dir)
    assert invalid.status is DeviceKeyHealthStatus.INVALID
    assert invalid.reason_code == "device-key-provenance-incomplete"


def test_device_key_provenance_secret_without_key_blocks_regeneration(tmp_path: Path) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "device.key"
    secret = data_dir / "device.provenance.secret"
    secret.write_bytes(os.urandom(32))
    os.chmod(secret, 0o600)

    plan = plan_missing_device_key(target, data_dir=data_dir)

    assert plan.disposition is RecoveryDisposition.BLOCKED
    assert plan.reason_code == "continuity-evidence-present"
    assert not target.exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL regression")
def test_device_key_plan_rejects_read_acl_before_staging_or_publication(
    tmp_path: Path,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "device.key"
    entry = "everyone allow read,readattr,readextattr,file_inherit,directory_inherit"
    command = ["/bin/chmod", "+a", entry, os.fspath(data_dir)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        pytest.skip(f"macOS ACL fixture command unavailable: {exc}")
    if result.returncode != 0:
        message = (result.stdout + result.stderr).lower()
        if "not supported" in message or "invalid argument" in message:
            pytest.skip(f"macOS ACL fixture unavailable: {message.strip()}")
        pytest.fail(f"could not add macOS ACL fixture: {message.strip()}")
    try:
        before = tuple(data_dir.iterdir())
        plan = plan_missing_device_key(target, data_dir=data_dir)

        assert plan.disposition is RecoveryDisposition.BLOCKED
        assert plan.reason_code == "directory-chain-has-untrusted-reader"
        with pytest.raises(RecoveryRefusedError) as exc:
            apply_device_key_recovery(plan, approved=True)
        assert exc.value.code == "recovery-plan-not-ready"
        assert tuple(data_dir.iterdir()) == before
        assert not target.exists()
        assert not Path(os.fspath(target) + ".provenance").exists()
        assert not (data_dir / "device.provenance.secret").exists()
        assert not any(item.name.startswith(".doctor-device-") for item in data_dir.iterdir())
    finally:
        subprocess.run(
            ["/bin/chmod", "-N", os.fspath(data_dir)],
            capture_output=True,
            check=False,
        )


def _inject_windows_backend(monkeypatch: pytest.MonkeyPatch):
    writes: list[tuple[str, bytes, bool]] = []

    def fake_custody(data_dir: str, parent: str):
        identities = []
        for path in recovery._controlled_directory_paths(data_dir, parent):
            info = os.lstat(path)
            identities.append(
                WindowsDirectoryIdentity(
                    path=path,
                    device=int(info.st_dev),
                    inode=int(info.st_ino),
                    security=("private-windows-dacl", path),
                )
            )
        return tuple(identities)

    def fake_write_new(
        path: str,
        payload: bytes,
        custody,
        *,
        confidential: bool,
    ) -> None:
        assert custody.platform == "windows"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                assert written > 0
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        writes.append((path, payload, confidential))

    def fake_private_postconditions(path: str, *, confidential: bool) -> bool:
        info = os.lstat(path)
        # Windows ignores the POSIX mode passed to os.open; the real backend
        # proves confidentiality through the DACL captured above.
        return confidential and stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)

    monkeypatch.setattr(recovery, "_platform_name", lambda: "windows")
    monkeypatch.setattr(recovery, "_windows_directory_custody", fake_custody)
    monkeypatch.setattr(recovery, "_windows_write_new_private_file", fake_write_new)
    monkeypatch.setattr(
        recovery,
        "_windows_private_file_postconditions",
        fake_private_postconditions,
    )
    monkeypatch.setattr(
        recovery,
        "_publish_no_replace",
        lambda *_args, **_kwargs: pytest.fail("Windows recovery used POSIX hard-link publication"),
    )
    return writes


@pytest.mark.skipif(
    os.name == "nt",
    reason="injected Windows backend is for non-Windows hosts; native recovery tests cover Windows",
)
def test_injected_windows_audit_backend_uses_create_new_payload_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    writes = _inject_windows_backend(monkeypatch)
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "audit.db"
    plan = plan_missing_audit_db(target, data_dir=data_dir)

    assert plan.disposition is RecoveryDisposition.READY
    assert plan.custody is not None
    assert plan.custody.platform == "windows"

    result = apply_audit_db_recovery(plan, approved=True, unattended=True)

    assert result.status is RecoveryApplyStatus.CREATED
    assert [Path(path).name for path, _payload, _private in writes] == ["audit.db"]
    assert writes[0][2] is True
    assert writes[0][1].startswith(b"SQLite format 3\x00")


@pytest.mark.skipif(
    os.name == "nt",
    reason="injected Windows backend is for non-Windows hosts; native recovery tests cover Windows",
)
def test_injected_windows_device_backend_uses_three_private_create_new_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    writes = _inject_windows_backend(monkeypatch)
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "device.key"
    plan = plan_missing_device_key(target, data_dir=data_dir)

    result = apply_device_key_recovery(plan, approved=True)

    assert result.status is RecoveryApplyStatus.CREATED
    assert [Path(path).name for path, _payload, _private in writes] == [
        "device.provenance.secret",
        "device.key.provenance",
        "device.key",
    ]
    assert all(private for _path, _payload, private in writes)


def test_windows_publication_adapter_uses_native_create_new_and_security_checks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from defenseclaw import file_permissions, windows_acl

    parent = os.fspath(tmp_path)
    target = os.fspath(tmp_path / "new-private-file")
    parent_security = object()
    written_security = object()
    calls: list[str] = []
    custody = CustodySnapshot(
        platform="windows",
        windows_directories=(
            WindowsDirectoryIdentity(
                path=parent,
                device=int(os.lstat(parent).st_dev),
                inode=int(os.lstat(parent).st_ino),
                security=parent_security,
            ),
        ),
    )

    def capture(path: str, *, directory: bool = False):
        calls.append("capture-directory" if directory else "capture-file")
        return parent_security if directory else written_security

    def write_new(path: str, payload: bytes, security):
        assert path == target
        assert payload == b"private-payload"
        assert security is parent_security
        calls.append("write-new")
        return written_security

    monkeypatch.setattr(windows_acl, "hold_directory_chain", lambda _path: nullcontext())
    monkeypatch.setattr(windows_acl, "capture_path", capture)
    monkeypatch.setattr(windows_acl, "private_security_for_directory", lambda _path: parent_security)
    monkeypatch.setattr(windows_acl, "write_new_file", write_new)
    monkeypatch.setattr(
        windows_acl,
        "assert_trusted_owner",
        lambda _security: calls.append("trusted-owner"),
    )
    monkeypatch.setattr(
        windows_acl,
        "assert_not_broadly_writable",
        lambda _security: calls.append("not-broadly-writable"),
    )
    monkeypatch.setattr(
        windows_acl,
        "assert_not_broadly_readable",
        lambda _security: calls.append("not-broadly-readable"),
    )
    monkeypatch.setattr(
        file_permissions,
        "windows_acl_custody_write_error",
        lambda *_args, **_kwargs: None,
    )

    recovery._windows_write_new_private_file(
        target,
        b"private-payload",
        custody,
        confidential=True,
    )

    assert calls == [
        "capture-directory",
        "trusted-owner",
        "not-broadly-writable",
        "write-new",
        "capture-file",
        "trusted-owner",
        "not-broadly-writable",
        "not-broadly-readable",
    ]


def test_windows_publication_refuses_changed_parent_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from defenseclaw import file_permissions, windows_acl

    parent = os.fspath(tmp_path)
    target = os.fspath(tmp_path / "new-private-file")
    parent_security = object()
    info = os.lstat(parent)
    custody = CustodySnapshot(
        platform="windows",
        windows_directories=(
            WindowsDirectoryIdentity(
                path=parent,
                device=int(info.st_dev),
                inode=int(info.st_ino) + 1,
                security=parent_security,
            ),
        ),
    )
    monkeypatch.setattr(windows_acl, "hold_directory_chain", lambda _path: nullcontext())
    monkeypatch.setattr(windows_acl, "capture_path", lambda *_args, **_kwargs: parent_security)
    monkeypatch.setattr(
        windows_acl,
        "write_new_file",
        lambda *_args, **_kwargs: pytest.fail("changed parent identity was used"),
    )
    monkeypatch.setattr(
        file_permissions,
        "windows_acl_custody_write_error",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(RecoveryRefusedError) as exc:
        recovery._windows_write_new_private_file(
            target,
            b"private-payload",
            custody,
            confidential=True,
        )
    assert exc.value.code == "recovery-plan-stale"
    assert not os.path.exists(target)


def test_windows_publication_conservatively_reports_post_create_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from defenseclaw import file_permissions, windows_acl

    parent = os.fspath(tmp_path)
    target = os.fspath(tmp_path / "new-private-file")
    parent_security = object()
    info = os.lstat(parent)
    custody = CustodySnapshot(
        platform="windows",
        windows_directories=(
            WindowsDirectoryIdentity(
                path=parent,
                device=int(info.st_dev),
                inode=int(info.st_ino),
                security=parent_security,
            ),
        ),
    )
    monkeypatch.setattr(windows_acl, "hold_directory_chain", lambda _path: nullcontext())
    monkeypatch.setattr(windows_acl, "capture_path", lambda *_args, **_kwargs: parent_security)
    monkeypatch.setattr(windows_acl, "assert_trusted_owner", lambda _security: None)
    monkeypatch.setattr(windows_acl, "assert_not_broadly_writable", lambda _security: None)
    monkeypatch.setattr(
        windows_acl,
        "private_security_for_directory",
        lambda _path: parent_security,
    )
    monkeypatch.setattr(
        windows_acl,
        "write_new_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(windows_acl.WindowsAclError("flush failed after CREATE_NEW")),
    )
    monkeypatch.setattr(
        file_permissions,
        "windows_acl_custody_write_error",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(RecoveryPublicationError) as exc:
        recovery._windows_write_new_private_file(
            target,
            b"private-payload",
            custody,
            confidential=True,
        )
    assert exc.value.created is True


def test_injected_windows_create_new_never_overwrites_a_last_moment_racer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _inject_windows_backend(monkeypatch)
    data_dir = _private_data_dir(tmp_path)
    target = data_dir / "audit.db"
    plan = plan_missing_audit_db(target, data_dir=data_dir)
    original_revalidate = recovery._revalidate_plan
    calls = 0

    def revalidate_then_race(candidate) -> None:
        nonlocal calls
        original_revalidate(candidate)
        calls += 1
        if calls == 2:
            target.write_bytes(b"last-moment-racer")

    monkeypatch.setattr(recovery, "_revalidate_plan", revalidate_then_race)

    result = apply_audit_db_recovery(plan, approved=True, unattended=True)

    assert result.status is RecoveryApplyStatus.FAILED
    assert result.created_artifacts == ()
    assert target.read_bytes() == b"last-moment-racer"
