# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Bridge-side replay of the target wheel's bundle rollback metadata."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw.commands.cmd_upgrade import _restore_local_observability_upgrade_backup


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_backup(
    backup_dir: Path,
    files: dict[str, tuple[bytes, int]],
) -> None:
    root = backup_dir / "local-observability-stack"
    managed = root / "managed"
    managed.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    os.chmod(managed, 0o700)
    old_sha256: dict[str, str] = {}
    old_modes: dict[str, int] = {}
    for relative, (payload, mode) in files.items():
        path = managed / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        path.write_bytes(payload)
        os.chmod(path, 0o600)
        old_sha256[relative] = _sha256(payload)
        old_modes[relative] = mode
    (root / "refresh-backup.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "existing_paths": sorted(files),
                "old_sha256": old_sha256,
                "old_modes": old_modes,
            }
        ),
        encoding="utf-8",
    )


def test_bridge_restores_exact_managed_bundle_files_and_preserves_custom_files(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backup"
    stack = data_dir / "observability-stack"
    existing = stack / "managed/existing.yaml"
    created = stack / "managed/created.yaml"
    manifest = stack / ".defenseclaw-bundle-manifest.json"
    custom = stack / "grafana/dashboards/team-custom.json"
    for path in (existing, created, manifest, custom):
        path.parent.mkdir(parents=True, exist_ok=True)
    existing.write_bytes(b"target existing\n")
    created.write_bytes(b"target created\n")
    manifest.write_bytes(b'{"bundle_version":"0.8.5"}\n')
    custom.write_bytes(b'{"uid":"team-custom"}\n')

    old_existing = b"bridge existing\n"
    old_manifest = b'{"bundle_version":"0.8.4"}\n'
    _write_backup(
        backup_dir,
        {
            "managed/existing.yaml": (old_existing, 0o640),
            ".defenseclaw-bundle-manifest.json": (old_manifest, 0o600),
        },
    )

    _restore_local_observability_upgrade_backup(
        str(data_dir),
        str(backup_dir),
        {
            "installed": True,
            "managed_paths": ["managed/existing.yaml", "managed/created.yaml"],
            "changed_paths": ["managed/existing.yaml", "managed/created.yaml"],
        },
    )

    assert existing.read_bytes() == old_existing
    if os.name == "posix":
        assert stat.S_IMODE(existing.stat().st_mode) == 0o640
    assert not created.exists()
    assert manifest.read_bytes() == old_manifest
    if os.name == "posix":
        assert stat.S_IMODE(manifest.stat().st_mode) == 0o600
    assert custom.read_bytes() == b'{"uid":"team-custom"}\n'


def test_bridge_rejects_unsafe_or_incomplete_bundle_rollback_inventory(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backup"
    destination = data_dir / "observability-stack/managed/existing.yaml"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"target\n")
    _write_backup(
        backup_dir,
        {"managed/existing.yaml": (b"bridge\n", 0o600)},
    )

    with pytest.raises(OSError, match="unsafe path"):
        _restore_local_observability_upgrade_backup(
            str(data_dir),
            str(backup_dir),
            {
                "installed": True,
                "managed_paths": ["../escape"],
                "changed_paths": [],
            },
        )
    assert destination.read_bytes() == b"target\n"

    metadata = backup_dir / "local-observability-stack/refresh-backup.json"
    document = json.loads(metadata.read_text(encoding="utf-8"))
    document["old_sha256"] = {}
    metadata.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(OSError, match="inventory is inconsistent"):
        _restore_local_observability_upgrade_backup(
            str(data_dir),
            str(backup_dir),
            {
                "installed": True,
                "managed_paths": ["managed/existing.yaml"],
                "changed_paths": [],
            },
        )
    assert destination.read_bytes() == b"target\n"


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative rollback is POSIX-only")
@pytest.mark.parametrize("restore_existing", [True, False])
def test_bridge_rollback_never_follows_destination_ancestor_symlinks(
    tmp_path: Path,
    restore_existing: bool,
) -> None:
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backup"
    stack = data_dir / "observability-stack"
    outside = tmp_path / "outside"
    stack.mkdir(parents=True)
    outside.mkdir()
    outside_file = outside / "member.yaml"
    outside_file.write_bytes(b"outside must survive\n")
    (stack / "managed").symlink_to(outside, target_is_directory=True)
    _write_backup(
        backup_dir,
        {"managed/member.yaml": (b"bridge state\n", 0o600)} if restore_existing else {},
    )

    with pytest.raises(OSError, match="unsafe .* destination ancestor"):
        _restore_local_observability_upgrade_backup(
            str(data_dir),
            str(backup_dir),
            {
                "installed": True,
                "managed_paths": ["managed/member.yaml"],
                "changed_paths": [],
            },
        )

    assert outside_file.read_bytes() == b"outside must survive\n"
    assert (stack / "managed").is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="directory fsync is POSIX-only")
def test_bridge_rollback_verifies_before_durable_publish(
    tmp_path: Path,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backup"
    destination = data_dir / "observability-stack/managed/member.yaml"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"target state\n")
    bridge_state = b"bridge state\n"
    _write_backup(
        backup_dir,
        {"managed/member.yaml": (bridge_state, 0o640)},
    )

    events: list[str] = []
    real_fsync = bundle_refresh.os.fsync
    real_digest = bundle_refresh._sha256_descriptor
    real_replace = bundle_refresh.os.replace

    def record_fsync(descriptor: int) -> None:
        kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
        events.append(f"fsync-{kind}")
        real_fsync(descriptor)

    def record_digest(descriptor: int) -> str:
        events.append("digest")
        return real_digest(descriptor)

    def record_replace(*args, **kwargs):
        events.append("replace")
        return real_replace(*args, **kwargs)

    with (
        patch.object(bundle_refresh.os, "fsync", side_effect=record_fsync),
        patch.object(bundle_refresh, "_sha256_descriptor", side_effect=record_digest),
        patch.object(bundle_refresh.os, "replace", side_effect=record_replace),
    ):
        _restore_local_observability_upgrade_backup(
            str(data_dir),
            str(backup_dir),
            {
                "installed": True,
                "managed_paths": ["managed/member.yaml"],
                "changed_paths": [],
            },
        )

    assert destination.read_bytes() == bridge_state
    assert events[-4:] == ["digest", "fsync-file", "replace", "fsync-directory"]


@pytest.mark.skipif(os.name != "posix", reason="directory fsync is POSIX-only")
def test_bridge_rollback_durability_failure_prevents_success(tmp_path: Path) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backup"
    destination = data_dir / "observability-stack/managed/member.yaml"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"target state\n")
    _write_backup(
        backup_dir,
        {"managed/member.yaml": (b"bridge state\n", 0o600)},
    )
    real_fsync = bundle_refresh.os.fsync

    def fail_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("simulated directory durability failure")
        real_fsync(descriptor)

    with (
        patch.object(bundle_refresh.os, "fsync", side_effect=fail_directory_fsync),
        pytest.raises(OSError, match="simulated directory durability failure"),
    ):
        _restore_local_observability_upgrade_backup(
            str(data_dir),
            str(backup_dir),
            {
                "installed": True,
                "managed_paths": ["managed/member.yaml"],
                "changed_paths": [],
            },
        )


@pytest.mark.parametrize("restore_existing", [True, False])
def test_non_posix_fallback_rejects_symlinked_destination_ancestors(
    tmp_path: Path,
    restore_existing: bool,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    stack = tmp_path / "observability-stack"
    outside = tmp_path / "outside"
    backup_dir = tmp_path / "backup"
    stack.mkdir()
    outside.mkdir()
    outside_file = outside / "member.yaml"
    outside_file.write_bytes(b"outside must survive\n")
    try:
        (stack / "managed").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    bridge_state = b"bridge state\n"
    _write_backup(
        backup_dir,
        {"managed/member.yaml": (bridge_state, 0o600)} if restore_existing else {},
    )
    existing = {"managed/member.yaml"} if restore_existing else set()

    with pytest.raises(OSError, match="unsafe .* destination ancestor"):
        bundle_refresh._restore_local_observability_backup_by_path(
            stack,
            backup_dir / "local-observability-stack/managed",
            {"managed/member.yaml"},
            existing,
            {"managed/member.yaml": _sha256(bridge_state)} if restore_existing else {},
            {"managed/member.yaml": 0o600} if restore_existing else {},
        )

    assert outside_file.read_bytes() == b"outside must survive\n"
    assert (stack / "managed").is_symlink()


@pytest.mark.parametrize("reparse_component", ["root", "ancestor", "managed_file"])
def test_non_posix_fallback_rejects_mocked_windows_reparse_points(
    tmp_path: Path,
    reparse_component: str,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    stack = tmp_path / "observability-stack"
    managed = stack / "managed"
    backup_dir = tmp_path / "backup"
    managed.mkdir(parents=True)
    managed_file = managed / "member.yaml"
    managed_file.write_bytes(b"target state\n")
    _write_backup(backup_dir, {})
    reparse_path = {
        "root": stack,
        "ancestor": managed,
        "managed_file": managed_file,
    }[reparse_component]
    real_lstat = bundle_refresh.os.lstat

    def mocked_lstat(path: str | os.PathLike[str]):
        info = real_lstat(path)
        if os.path.normcase(os.path.abspath(path)) == os.path.normcase(os.path.abspath(reparse_path)):
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
                st_file_attributes=0x00000400,
            )
        return info

    with (
        patch.object(bundle_refresh.os, "lstat", side_effect=mocked_lstat),
        pytest.raises(OSError, match="unsafe .* rollback"),
    ):
        bundle_refresh._restore_local_observability_backup_by_path(
            stack,
            backup_dir / "local-observability-stack/managed",
            {"managed/member.yaml"},
            set(),
            {},
            {},
        )


def test_non_posix_fallback_restores_and_deletes_real_files(tmp_path: Path) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    stack = tmp_path / "observability-stack"
    backup_dir = tmp_path / "backup"
    existing = stack / "managed/existing.yaml"
    created = stack / "managed/created.yaml"
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"target state\n")
    created.write_bytes(b"target-created state\n")
    bridge_state = b"bridge state\n"
    _write_backup(
        backup_dir,
        {"managed/existing.yaml": (bridge_state, 0o600)},
    )

    bundle_refresh._restore_local_observability_backup_by_path(
        stack,
        backup_dir / "local-observability-stack/managed",
        {"managed/existing.yaml", "managed/created.yaml"},
        {"managed/existing.yaml"},
        {"managed/existing.yaml": _sha256(bridge_state)},
        {"managed/existing.yaml": 0o600},
    )

    assert existing.read_bytes() == bridge_state
    assert not created.exists()


def test_non_posix_fallback_revalidates_ancestors_after_copy(tmp_path: Path) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    stack = tmp_path / "observability-stack"
    managed = stack / "managed"
    outside = tmp_path / "outside"
    backup_dir = tmp_path / "backup"
    managed.mkdir(parents=True)
    outside.mkdir()
    bridge_state = b"bridge state\n"
    _write_backup(
        backup_dir,
        {"managed/member.yaml": (bridge_state, 0o600)},
    )
    real_info = bundle_refresh._rollback_file_info
    swapped = False

    def inspect_then_swap_parent(path: Path, *, missing_ok: bool):
        nonlocal swapped
        result = real_info(path, missing_ok=missing_ok)
        if path.name.startswith(".rollback-") and not swapped:
            swapped = True
            managed.rename(stack / "managed-original")
            try:
                managed.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                pytest.skip(f"directory symlink unavailable: {exc}")
        return result

    with (
        patch.object(bundle_refresh, "_rollback_file_info", side_effect=inspect_then_swap_parent),
        pytest.raises(OSError, match="destination ancestor"),
    ):
        bundle_refresh._restore_local_observability_backup_by_path(
            stack,
            backup_dir / "local-observability-stack/managed",
            {"managed/member.yaml"},
            {"managed/member.yaml"},
            {"managed/member.yaml": _sha256(bridge_state)},
            {"managed/member.yaml": 0o600},
        )

    assert not (outside / "member.yaml").exists()


def _assert_destination_snapshot(path: Path, snapshot: tuple[bytes, int, int]) -> None:
    payload, inode, mode = snapshot
    assert path.read_bytes() == payload
    assert path.stat().st_ino == inode
    assert stat.S_IMODE(path.stat().st_mode) == mode


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative rollback is POSIX-only")
@pytest.mark.parametrize("mutation", ["digest-mismatch", "source-race"])
def test_posix_rollback_authenticates_backup_before_destination_publish(
    tmp_path: Path,
    mutation: str,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    destination_root = tmp_path / "observability-stack"
    destination = destination_root / "managed/member.yaml"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"target state must survive\n")
    os.chmod(destination, 0o640)
    before = (destination.read_bytes(), destination.stat().st_ino, stat.S_IMODE(destination.stat().st_mode))
    backup_dir = tmp_path / "backup"
    expected = b"bridge state\n"
    backup_payload = b"corrupt backup\n" if mutation == "digest-mismatch" else expected
    _write_backup(backup_dir, {"managed/member.yaml": (backup_payload, 0o600)})
    backup = backup_dir / "local-observability-stack/managed/managed/member.yaml"
    expected_error = "digest mismatch" if mutation == "digest-mismatch" else "changed during restore"

    if mutation == "source-race":
        real_read = bundle_refresh.os.read
        raced = False

        def read_then_race(descriptor: int, size: int) -> bytes:
            nonlocal raced
            block = real_read(descriptor, size)
            if block and not raced:
                raced = True
                backup.write_bytes(b"raced backup bytes with a different size\n")
            return block

        read_patch = patch.object(bundle_refresh.os, "read", side_effect=read_then_race)
    else:
        read_patch = nullcontext()

    with read_patch, pytest.raises(OSError, match=expected_error):
        bundle_refresh._restore_local_observability_backup(
            destination_root,
            backup_dir / "local-observability-stack/managed",
            {"managed/member.yaml"},
            {"managed/member.yaml"},
            {"managed/member.yaml": _sha256(expected)},
            {"managed/member.yaml": 0o600},
        )

    _assert_destination_snapshot(destination, before)
    assert not list(destination.parent.glob(".rollback-*"))


@pytest.mark.parametrize("mutation", ["digest-mismatch", "source-race"])
def test_fallback_rollback_authenticates_backup_before_destination_publish(
    tmp_path: Path,
    mutation: str,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    destination_root = tmp_path / "observability-stack"
    destination = destination_root / "managed/member.yaml"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"target state must survive\n")
    os.chmod(destination, 0o640)
    before = (destination.read_bytes(), destination.stat().st_ino, stat.S_IMODE(destination.stat().st_mode))
    backup_dir = tmp_path / "backup"
    expected = b"bridge state\n"
    backup_payload = b"corrupt backup\n" if mutation == "digest-mismatch" else expected
    _write_backup(backup_dir, {"managed/member.yaml": (backup_payload, 0o600)})
    backup = backup_dir / "local-observability-stack/managed/managed/member.yaml"
    expected_error = "digest mismatch" if mutation == "digest-mismatch" else "changed during restore"

    if mutation == "source-race":
        real_read = bundle_refresh.os.read
        raced = False

        def read_then_race(descriptor: int, size: int) -> bytes:
            nonlocal raced
            block = real_read(descriptor, size)
            if block and not raced:
                raced = True
                backup.write_bytes(b"raced backup bytes with a different size\n")
            return block

        read_patch = patch.object(bundle_refresh.os, "read", side_effect=read_then_race)
    else:
        read_patch = nullcontext()

    with read_patch, pytest.raises(OSError, match=expected_error):
        bundle_refresh._restore_local_observability_backup_by_path(
            destination_root,
            backup_dir / "local-observability-stack/managed",
            {"managed/member.yaml"},
            {"managed/member.yaml"},
            {"managed/member.yaml": _sha256(expected)},
            {"managed/member.yaml": 0o600},
        )

    _assert_destination_snapshot(destination, before)
    assert not list(destination.parent.glob(".rollback-*"))


@pytest.mark.parametrize("mutation", ["valid", "digest-mismatch", "source-race"])
def test_windows_fallback_authenticates_before_private_staging_and_publish(
    tmp_path: Path,
    mutation: str,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh
    from defenseclaw import windows_acl

    destination_root = tmp_path / "observability-stack"
    destination = destination_root / "managed/member.yaml"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"target state must survive\n")
    os.chmod(destination, 0o640)
    before = (destination.read_bytes(), destination.stat().st_ino, stat.S_IMODE(destination.stat().st_mode))
    backup_dir = tmp_path / "backup"
    expected = b"bridge state\n"
    backup_payload = b"corrupt backup\n" if mutation == "digest-mismatch" else expected
    _write_backup(backup_dir, {"managed/member.yaml": (backup_payload, 0o600)})
    backup = backup_dir / "local-observability-stack/managed/managed/member.yaml"
    security = object()
    events: list[str] = []
    held: list[str] = []

    @contextmanager
    def hold(path: str):
        events.append(f"lease-enter:{path}")
        held.append(path)
        try:
            yield
        finally:
            assert held.pop() == path
            events.append(f"lease-exit:{path}")

    def write_private(path: str, payload: bytes, observed_security: object) -> None:
        assert observed_security is security
        assert held
        _assert_destination_snapshot(destination, before)
        events.append("private-write")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def replace_by_handle(source: str, target: str) -> None:
        assert held
        events.append("handle-replace")
        os.replace(source, target)

    if mutation == "source-race":
        real_read = bundle_refresh.os.read
        raced = False

        def read_then_race(descriptor: int, size: int) -> bytes:
            nonlocal raced
            block = real_read(descriptor, size)
            if block and not raced:
                raced = True
                backup.write_bytes(b"raced backup bytes with a different size\n")
            return block

        read_patch = patch.object(bundle_refresh.os, "read", side_effect=read_then_race)
    else:
        read_patch = nullcontext()

    with (
        read_patch,
        patch.object(bundle_refresh.os, "name", "nt"),
        patch.object(windows_acl, "hold_directory_chain", side_effect=hold),
        patch.object(windows_acl, "hold_directory", side_effect=hold),
        patch.object(windows_acl, "private_security_for_directory", return_value=security),
        patch.object(windows_acl, "write_new_file", side_effect=write_private) as private_write,
        patch.object(windows_acl, "replace_regular_file_by_handle", side_effect=replace_by_handle),
        patch.object(windows_acl, "delete_regular_file_by_handle"),
    ):
        if mutation == "valid":
            bundle_refresh._restore_local_observability_backup_by_path(
                destination_root,
                backup_dir / "local-observability-stack/managed",
                {"managed/member.yaml"},
                {"managed/member.yaml"},
                {"managed/member.yaml": _sha256(expected)},
                {"managed/member.yaml": 0o600},
            )
        else:
            expected_error = "digest mismatch" if mutation == "digest-mismatch" else "changed during restore"
            with pytest.raises(OSError, match=expected_error):
                bundle_refresh._restore_local_observability_backup_by_path(
                    destination_root,
                    backup_dir / "local-observability-stack/managed",
                    {"managed/member.yaml"},
                    {"managed/member.yaml"},
                    {"managed/member.yaml": _sha256(expected)},
                    {"managed/member.yaml": 0o600},
                )

    if mutation == "valid":
        assert events.index("private-write") < events.index("handle-replace")
        assert destination.read_bytes() == expected
        private_write.assert_called_once()
    else:
        _assert_destination_snapshot(destination, before)
        private_write.assert_not_called()
    assert not list(destination.parent.glob(".rollback-*"))


def test_windows_rollback_holds_parent_chain_across_mkdir_and_delete(
    tmp_path: Path,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh
    from defenseclaw import windows_acl

    destination_root = tmp_path / "observability-stack"
    destination_root.mkdir()
    backup_dir = tmp_path / "backup"
    _write_backup(backup_dir, {})
    retired = destination_root / "managed/retired.yaml"
    retired.parent.mkdir()
    retired.write_bytes(b"target-created state\n")
    created_parent = destination_root / "new-parent"
    expected = b"bridge state\n"
    _write_backup(backup_dir, {"new-parent/restored.yaml": (expected, 0o600)})

    events: list[str] = []
    held: list[str] = []
    real_mkdir = bundle_refresh.os.mkdir

    @contextmanager
    def hold(path: str):
        events.append(f"lease-enter:{path}")
        held.append(path)
        try:
            yield
        finally:
            assert held.pop() == path
            events.append(f"lease-exit:{path}")

    def locked_mkdir(path: str | os.PathLike[str], mode: int = 0o777) -> None:
        assert held
        events.append("mkdir")
        real_mkdir(path, mode)

    def write_private(path: str, payload: bytes, _security: object) -> None:
        assert held
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, payload)
        finally:
            os.close(descriptor)

    def replace_by_handle(source: str, target: str) -> None:
        assert held
        events.append("handle-replace")
        os.replace(source, target)

    def delete_by_handle(path: str, *, missing_ok: bool = False) -> bool:
        assert held
        events.append("handle-delete")
        try:
            os.unlink(path)
        except FileNotFoundError:
            if missing_ok:
                return False
            raise
        return True

    with (
        patch.object(bundle_refresh.os, "name", "nt"),
        patch.object(bundle_refresh.os, "mkdir", side_effect=locked_mkdir),
        patch.object(windows_acl, "hold_directory_chain", side_effect=hold),
        patch.object(windows_acl, "hold_directory", side_effect=hold),
        patch.object(windows_acl, "private_security_for_directory", return_value=object()),
        patch.object(windows_acl, "write_new_file", side_effect=write_private),
        patch.object(windows_acl, "replace_regular_file_by_handle", side_effect=replace_by_handle),
        patch.object(windows_acl, "delete_regular_file_by_handle", side_effect=delete_by_handle),
    ):
        bundle_refresh._restore_local_observability_backup_by_path(
            destination_root,
            backup_dir / "local-observability-stack/managed",
            {"managed/retired.yaml", "new-parent/restored.yaml"},
            {"new-parent/restored.yaml"},
            {"new-parent/restored.yaml": _sha256(expected)},
            {"new-parent/restored.yaml": 0o600},
        )

    assert created_parent.joinpath("restored.yaml").read_bytes() == expected
    assert not retired.exists()
    assert events.index("mkdir") < events.index("handle-replace")
    assert events.index("handle-delete") < max(
        index for index, event in enumerate(events) if event.startswith("lease-exit:")
    )
