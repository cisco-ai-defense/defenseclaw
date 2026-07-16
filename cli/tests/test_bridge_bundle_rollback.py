# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Bridge-side replay of the target wheel's bundle rollback metadata."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw import windows_acl
from defenseclaw.commands import cmd_upgrade
from defenseclaw.commands.cmd_upgrade import (
    _parse_bundle_rollback_metadata,
    _restore_local_observability_upgrade_backup,
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def test_fsync_claimed_file_rejects_named_reparse_point(tmp_path: Path) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    regular = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_dev=1,
        st_ino=2,
        st_size=3,
        st_mtime_ns=4,
        st_ctime_ns=5,
        st_file_attributes=0,
    )
    reparse = SimpleNamespace(**vars(regular))
    reparse.st_file_attributes = 0x00000400

    with (
        patch.object(bundle_refresh.os, "fstat", return_value=regular),
        patch.object(bundle_refresh.os, "lstat", return_value=reparse),
        patch.object(bundle_refresh.os, "fsync") as fsync,
    ):
        with pytest.raises(OSError, match="changed while syncing"):
            bundle_refresh._fsync_claimed_file(17, tmp_path / "member")

    fsync.assert_not_called()


@pytest.mark.parametrize(
    ("platform", "windows_exclusive_lease", "rejects_skew"),
    [("nt", True, False), ("nt", False, True), ("posix", False, True)],
)
def test_fsync_claimed_file_tolerates_only_exclusive_windows_ctime_flush_skew(
    tmp_path: Path,
    platform: str,
    windows_exclusive_lease: bool,
    rejects_skew: bool,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    before = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_dev=1,
        st_ino=2,
        st_size=3,
        st_mtime_ns=4,
        st_ctime_ns=5,
        st_file_attributes=0,
    )
    after = SimpleNamespace(**vars(before))
    after.st_ctime_ns += 1
    path = tmp_path / "member"
    outcome = pytest.raises(OSError, match="changed while syncing") if rejects_skew else nullcontext()
    security = object()

    with (
        patch.object(bundle_refresh.os, "name", platform),
        patch.object(bundle_refresh.os, "fstat", side_effect=[before, after]),
        patch.object(bundle_refresh.os, "lstat", side_effect=[before, after]),
        patch.object(bundle_refresh.os, "fsync") as fsync,
        patch.object(windows_acl, "capture_fd", side_effect=[security, security]) as capture_fd,
        outcome,
    ):
        bundle_refresh._fsync_claimed_file(
            17,
            path,
            windows_exclusive_lease=windows_exclusive_lease,
        )

    fsync.assert_called_once_with(17)
    assert capture_fd.call_count == (2 if windows_exclusive_lease else 0)


def test_fsync_claimed_file_rejects_windows_security_change(tmp_path: Path) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    unchanged = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_dev=1,
        st_ino=2,
        st_size=3,
        st_mtime_ns=4,
        st_ctime_ns=5,
        st_file_attributes=0,
    )

    with (
        patch.object(bundle_refresh.os, "name", "nt"),
        patch.object(bundle_refresh.os, "fstat", return_value=unchanged),
        patch.object(bundle_refresh.os, "lstat", return_value=unchanged),
        patch.object(bundle_refresh.os, "fsync") as fsync,
        patch.object(windows_acl, "capture_fd", side_effect=[object(), object()]),
        pytest.raises(OSError, match="changed while syncing"),
    ):
        bundle_refresh._fsync_claimed_file(
            17,
            tmp_path / "member",
            windows_exclusive_lease=True,
        )

    fsync.assert_called_once_with(17)


def _write_restart_intent(backup_dir: Path, *, restart_required: bool) -> Path:
    root = backup_dir / "local-observability-stack"
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    path = root / "restart-intent.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target_manifest_sha256": "a" * 64,
                "restart_required": restart_required,
            }
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return path


def _write_backup(
    backup_dir: Path,
    files: dict[str, tuple[bytes, int]],
    *,
    created_paths: dict[str, Path] | None = None,
    schema_version: int = 2,
) -> None:
    root = backup_dir / "local-observability-stack"
    managed = root / "managed"
    created = root / "created"
    retired = root / "retired"
    managed.mkdir(parents=True, exist_ok=True)
    if schema_version == 2:
        created.mkdir(parents=True, exist_ok=True)
        retired.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    os.chmod(managed, 0o700)
    if created.exists():
        os.chmod(created, 0o700)
    if retired.exists():
        os.chmod(retired, 0o700)
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
    target_created = dict(created_paths or {})
    manifest_relative = ".defenseclaw-bundle-manifest.json"
    if (
        schema_version == 2
        and manifest_relative not in files
        and manifest_relative not in target_created
    ):
        claim = created / manifest_relative
        claim.write_bytes(b'{"bundle_version":"0.8.5"}\n')
        target_created[manifest_relative] = claim
    created_sha256: dict[str, str] = {}
    if schema_version == 2:
        for relative, canonical in target_created.items():
            claim = created / relative
            claim.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(claim.parent, 0o700)
            if claim != canonical:
                os.link(canonical, claim)
            created_sha256[relative] = _sha256(claim.read_bytes())
    metadata = {
        "schema_version": schema_version,
        "managed_paths": sorted(set(files) | set(target_created)),
        "existing_paths": sorted(files),
        "old_sha256": old_sha256,
        "old_modes": old_modes,
        "restart_required": False,
    }
    if schema_version == 2:
        old_windows_security: dict[str, object] = {}
        if os.name == "nt":
            from defenseclaw import windows_acl

            old_windows_security = {
                relative: cmd_upgrade._windows_security_to_recovery_json(
                    windows_acl.capture_path(str(managed / relative))
                )
                for relative in files
            }
        metadata["created_sha256"] = created_sha256
        metadata["old_windows_security"] = old_windows_security
    metadata_path = root / "refresh-backup.json"
    metadata_path.write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )
    os.chmod(metadata_path, 0o600)


def test_prepublication_crash_uses_durable_restart_intent_without_file_replay(
    tmp_path: Path,
) -> None:
    backup_dir = tmp_path / "backup"
    _write_restart_intent(backup_dir, restart_required=True)

    recovered = cmd_upgrade._crash_bundle_rollback_result(
        str(backup_dir),
        required=True,
    )

    assert recovered == {
        "installed": False,
        "restart_required": True,
    }
    assert _restore_local_observability_upgrade_backup(
        str(tmp_path / "data"),
        str(backup_dir),
        recovered,
    ) is True


@pytest.mark.parametrize(
    "mutation",
    [
        {"restart_required": "yes"},
        {"target_manifest_sha256": "not-a-digest"},
        {"unexpected": True},
    ],
)
def test_prepublication_crash_rejects_ambiguous_restart_intent(
    tmp_path: Path,
    mutation: dict[str, object],
) -> None:
    backup_dir = tmp_path / "backup"
    path = _write_restart_intent(backup_dir, restart_required=True)
    document = json.loads(path.read_text(encoding="utf-8"))
    document.update(mutation)
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(OSError, match="restart intent is invalid"):
        cmd_upgrade._crash_bundle_rollback_result(str(backup_dir), required=True)


def test_full_descriptor_cannot_contradict_pre_stop_restart_intent(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backup"
    _write_backup(backup_dir, {})
    _write_restart_intent(backup_dir, restart_required=True)

    with pytest.raises(OSError, match="restart state is inconsistent"):
        cmd_upgrade._crash_bundle_rollback_result(str(backup_dir), required=True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX metadata mode and symlink policy")
@pytest.mark.parametrize("mutation", ["symlink", "broad-mode"])
def test_bundle_rollback_metadata_refuses_untrusted_path_before_restore(
    tmp_path: Path,
    mutation: str,
) -> None:
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backup"
    destination = data_dir / "observability-stack/managed/member.yaml"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"target must survive\n")
    before = destination.read_bytes()
    _write_backup(
        backup_dir,
        {"managed/member.yaml": (b"bridge bytes\n", 0o600)},
    )
    metadata = backup_dir / "local-observability-stack/refresh-backup.json"
    if mutation == "symlink":
        external = tmp_path / "attacker-metadata.json"
        external.write_bytes(metadata.read_bytes())
        metadata.unlink()
        metadata.symlink_to(external)
        expected = "bounded regular file"
    else:
        os.chmod(metadata, 0o644)
        expected = "owner-only"

    with pytest.raises(OSError, match=expected):
        _restore_local_observability_upgrade_backup(
            str(data_dir),
            str(backup_dir),
            {
                "installed": True,
                "managed_paths": ["managed/member.yaml"],
                "changed_paths": [],
                "restart_required": False,
            },
        )

    assert destination.read_bytes() == before


def test_bundle_rollback_metadata_reader_rejects_leaf_swap_while_opening(
    tmp_path: Path,
) -> None:
    metadata = tmp_path / "refresh-backup.json"
    replacement = tmp_path / "replacement.json"
    displaced = tmp_path / "original.json"
    metadata.write_text('{"authority":"original"}', encoding="utf-8")
    replacement.write_text('{"authority":"attacker"}', encoding="utf-8")
    os.chmod(metadata, 0o600)
    os.chmod(replacement, 0o600)
    real_open = cmd_upgrade.os.open
    swapped = False

    def swap_before_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if os.fspath(path) == os.fspath(metadata) and not swapped:
            swapped = True
            metadata.rename(displaced)
            replacement.rename(metadata)
        return real_open(path, flags, *args, **kwargs)

    with (
        patch.object(cmd_upgrade.os, "open", side_effect=swap_before_open),
        pytest.raises(OSError, match="changed while opening"),
    ):
        cmd_upgrade._read_bounded_bundle_rollback_json(metadata)

    assert swapped


def test_bundle_rollback_metadata_reader_rejects_in_place_write_while_reading(
    tmp_path: Path,
) -> None:
    metadata = tmp_path / "refresh-backup.json"
    metadata.write_text('{"authority":"original"}', encoding="utf-8")
    os.chmod(metadata, 0o600)
    real_read = cmd_upgrade.os.read
    mutated = False

    def mutate_after_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        block = real_read(descriptor, size)
        if block and not mutated:
            mutated = True
            metadata.write_text('{"authority":"attacker-expanded"}', encoding="utf-8")
        return block

    with (
        patch.object(cmd_upgrade.os, "read", side_effect=mutate_after_read),
        pytest.raises(OSError, match="changed while reading"),
    ):
        cmd_upgrade._read_bounded_bundle_rollback_json(metadata)

    assert mutated


def test_bundle_rollback_metadata_reader_revalidates_windows_security(
    tmp_path: Path,
) -> None:
    from defenseclaw import windows_acl

    metadata = tmp_path / "refresh-backup.json"
    metadata.write_text('{"authority":"bridge"}', encoding="utf-8")
    os.chmod(metadata, 0o600)
    security = object()
    with (
        patch.object(cmd_upgrade.os, "name", "nt"),
        patch.object(windows_acl, "capture_fd", side_effect=[security, security]) as capture,
        patch.object(windows_acl, "assert_trusted_owner") as trusted,
        patch.object(windows_acl, "assert_not_broadly_writable") as private,
    ):
        assert cmd_upgrade._read_bounded_bundle_rollback_json(metadata) == {
            "authority": "bridge"
        }
    assert capture.call_count == 2
    assert trusted.call_count == 2
    assert private.call_count == 2

    with (
        patch.object(cmd_upgrade.os, "name", "nt"),
        patch.object(windows_acl, "capture_fd", side_effect=[object(), object()]),
        patch.object(windows_acl, "assert_trusted_owner"),
        patch.object(windows_acl, "assert_not_broadly_writable"),
        pytest.raises(OSError, match="security changed"),
    ):
        cmd_upgrade._read_bounded_bundle_rollback_json(metadata)


@pytest.mark.parametrize("size", [0, 4 * 1024 * 1024 + 1])
def test_bundle_rollback_metadata_reader_enforces_serialized_size_bound(
    tmp_path: Path,
    size: int,
) -> None:
    metadata = tmp_path / "refresh-backup.json"
    with metadata.open("wb") as stream:
        stream.truncate(size)
    os.chmod(metadata, 0o600)

    with pytest.raises(OSError, match="bounded regular file"):
        cmd_upgrade._read_bounded_bundle_rollback_json(metadata)


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
        created_paths={"managed/created.yaml": created},
    )

    _restore_local_observability_upgrade_backup(
        str(data_dir),
        str(backup_dir),
        {
            "installed": True,
            "managed_paths": ["managed/existing.yaml", "managed/created.yaml"],
            "changed_paths": ["managed/existing.yaml", "managed/created.yaml"],
            "restart_required": False,
        },
    )

    assert existing.read_bytes() == old_existing
    if os.name == "posix":
        assert stat.S_IMODE(existing.stat().st_mode) == 0o640
    assert not created.exists()
    if os.name == "posix":
        retired_created = (
            backup_dir / "local-observability-stack/retired/managed/created.yaml"
        )
        claim_created = backup_dir / "local-observability-stack/created/managed/created.yaml"
        assert os.path.samefile(retired_created, claim_created)
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
                "restart_required": False,
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
                "restart_required": False,
            },
        )
    assert destination.read_bytes() == b"target\n"


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("schema_version", True, "metadata is invalid"),
        ("schema_version", "2", "metadata is invalid"),
        ("schema_version", 2.0, "metadata is invalid"),
        ("restart_required", None, "lacks boolean restart state"),
        ("restart_required", 0, "lacks boolean restart state"),
        ("managed_paths", ["managed/nul\x00member"], "unsafe path"),
        ("managed_paths", ["x" * 256], "unsafe path"),
        ("managed_paths", ["/".join(["x" * 250] * 17)], "unsafe path"),
        ("managed_paths", ["/".join(["x"] * 65)], "unsafe path"),
        ("managed_paths", ["managed/config.yaml:alternate"], "Windows-unsafe path"),
        ("managed_paths", ["managed/name."], "Windows-unsafe path"),
        ("managed_paths", ["managed/name "], "Windows-unsafe path"),
        ("managed_paths", ["managed/CON"], "Windows-unsafe path"),
        ("managed_paths", ["managed/CONIN$"], "Windows-unsafe path"),
        ("managed_paths", ["managed/conout$.log"], "Windows-unsafe path"),
        ("managed_paths", ["managed/aux.txt"], "Windows-unsafe path"),
        ("managed_paths", ["managed/control\n"], "Windows-unsafe path"),
        (
            "managed_paths",
            ["managed/Config.yaml", "managed/config.yaml"],
            "Windows path alias collision",
        ),
    ],
)
def test_schema_two_metadata_rejects_type_and_path_ambiguity(
    field: str,
    value: object,
    expected: str,
) -> None:
    metadata: dict[str, object] = {
        "schema_version": 2,
        "managed_paths": [],
        "existing_paths": [],
        "old_sha256": {},
        "old_modes": {},
        "created_sha256": {},
        "old_windows_security": {},
        "restart_required": False,
    }
    metadata[field] = value
    with pytest.raises(OSError, match=expected):
        _parse_bundle_rollback_metadata(metadata)


def _schema_two_existing_metadata() -> dict[str, object]:
    payload = b"bridge bytes\n"
    return {
        "schema_version": 2,
        "managed_paths": ["managed/member.yaml"],
        "existing_paths": ["managed/member.yaml"],
        "old_sha256": {"managed/member.yaml": _sha256(payload)},
        "old_modes": {"managed/member.yaml": 0o600},
        "created_sha256": {},
        "old_windows_security": {
            "managed/member.yaml": {
                "owner": "AQEBAQEBAQEBAQEB",
                "dacl": "AgICAgICAgI=",
                "dacl_protected": False,
            }
        },
        "restart_required": False,
    }


def test_schema_two_windows_security_inventory_round_trips_exact_native_bytes() -> None:
    from defenseclaw.windows_acl import WindowsFileSecurity

    metadata = _schema_two_existing_metadata()
    with patch.object(cmd_upgrade.os, "name", "nt"):
        parsed = _parse_bundle_rollback_metadata(metadata)

    security = parsed[5]["managed/member.yaml"]
    assert security == WindowsFileSecurity(b"\x01" * 12, b"\x02" * 8, False)


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda metadata: metadata["old_windows_security"].clear(),
            "security inventory is inconsistent",
        ),
        (
            lambda metadata: metadata["old_windows_security"].__setitem__(
                "managed/extra.yaml",
                metadata["old_windows_security"]["managed/member.yaml"],
            ),
            "security inventory is inconsistent",
        ),
        (
            lambda metadata: metadata["old_windows_security"]["managed/member.yaml"].update(
                {"extra": True}
            ),
            "security row is invalid",
        ),
        (
            lambda metadata: metadata["old_windows_security"]["managed/member.yaml"].update(
                {"owner": "not base64!"}
            ),
            "security row is invalid",
        ),
        (
            lambda metadata: metadata["old_windows_security"]["managed/member.yaml"].update(
                {"dacl": "Ag=="}
            ),
            "security row is invalid",
        ),
        (
            lambda metadata: metadata["old_windows_security"]["managed/member.yaml"].update(
                {"owner": base64.b64encode(b"x" * 69).decode("ascii")}
            ),
            "security row is invalid",
        ),
        (
            lambda metadata: metadata["old_windows_security"]["managed/member.yaml"].update(
                {"dacl": base64.b64encode(b"x" * 65_536).decode("ascii")}
            ),
            "security row is invalid",
        ),
    ],
)
def test_schema_two_windows_security_inventory_fails_closed(
    mutate,
    expected: str,
) -> None:
    metadata = _schema_two_existing_metadata()
    mutate(metadata)
    with (
        patch.object(cmd_upgrade.os, "name", "nt"),
        pytest.raises(OSError, match=expected),
    ):
        _parse_bundle_rollback_metadata(metadata)


def test_schema_one_windows_existing_inventory_refuses_without_native_security() -> None:
    metadata = _schema_two_existing_metadata()
    metadata["schema_version"] = 1
    metadata.pop("created_sha256")
    metadata.pop("old_windows_security")
    with (
        patch.object(cmd_upgrade.os, "name", "nt"),
        pytest.raises(OSError, match="lacks exact Windows security"),
    ):
        _parse_bundle_rollback_metadata(metadata)


def test_normal_rollback_requires_child_restart_state_to_match_durable_metadata(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backup"
    manifest = data_dir / "observability-stack/.defenseclaw-bundle-manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_bytes(b"target manifest\n")
    _write_backup(
        backup_dir,
        {".defenseclaw-bundle-manifest.json": (b"bridge manifest\n", 0o600)},
    )

    with pytest.raises(OSError, match="restart state is inconsistent"):
        _restore_local_observability_upgrade_backup(
            str(data_dir),
            str(backup_dir),
            {
                "installed": True,
                "managed_paths": [],
                "changed_paths": [],
                "restart_required": True,
            },
        )
    assert manifest.read_bytes() == b"target manifest\n"

    durable_restart = _restore_local_observability_upgrade_backup(
        str(data_dir),
        str(backup_dir),
        {
            "installed": True,
            "managed_paths": [],
            "changed_paths": [],
            "restart_required": False,
        },
    )
    assert durable_restart is False
    assert manifest.read_bytes() == b"bridge manifest\n"


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
    target_claim = tmp_path / "target-claim.yaml"
    target_claim.write_bytes(b"target state\n")
    _write_backup(
        backup_dir,
        {"managed/member.yaml": (b"bridge state\n", 0o600)} if restore_existing else {},
        created_paths=None if restore_existing else {"managed/member.yaml": target_claim},
    )

    with pytest.raises(OSError, match="unsafe .* destination ancestor"):
        _restore_local_observability_upgrade_backup(
            str(data_dir),
            str(backup_dir),
            {
                "installed": True,
                "managed_paths": ["managed/member.yaml"],
                "changed_paths": [],
                "restart_required": False,
            },
        )

    assert outside_file.read_bytes() == b"outside must survive\n"
    assert (stack / "managed").is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative rollback is POSIX-only")
@pytest.mark.parametrize("entry_kind", ["symlink", "fifo"])
def test_retire_rollback_file_at_refuses_real_special_entries(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    parent = tmp_path / "managed"
    retired = tmp_path / "retired"
    parent.mkdir()
    retired.mkdir()
    destination = parent / "created.yaml"
    outside = tmp_path / "outside.yaml"
    outside.write_bytes(b"must survive\n")
    if entry_kind == "symlink":
        destination.symlink_to(outside)
    else:
        os.mkfifo(destination)
    claim = parent / "created.claim"
    claim.write_bytes(b"target-created state\n")

    parent_descriptor = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    claim_descriptor = os.open(claim, os.O_RDONLY)
    retired_descriptor = os.open(retired, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with pytest.raises(OSError, match="unsafe|changed and was preserved"):
            bundle_refresh._retire_rollback_file_at(
                parent_descriptor,
                destination.name,
                retired_descriptor,
                destination.name,
                claim_descriptor,
                _sha256(claim.read_bytes()),
            )
    finally:
        os.close(retired_descriptor)
        os.close(claim_descriptor)
        os.close(parent_descriptor)

    assert os.path.lexists(destination)
    assert outside.read_bytes() == b"must survive\n"


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative rollback is POSIX-only")
@pytest.mark.parametrize(
    "special_mode",
    [stat.S_IFCHR, stat.S_IFBLK, stat.S_IFSOCK],
    ids=["character-device", "block-device", "socket"],
)
def test_retire_rollback_file_at_refuses_device_and_socket_modes_before_rename(
    tmp_path: Path,
    special_mode: int,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    parent = tmp_path / "managed"
    retired = tmp_path / "retired"
    parent.mkdir()
    retired.mkdir()
    destination = parent / "created.yaml"
    destination.write_bytes(b"target-created state\n")
    claim = parent / "created.claim"
    os.link(destination, claim)
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    claim_descriptor = os.open(claim, os.O_RDONLY)
    retired_descriptor = os.open(retired, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with (
            patch.object(
                bundle_refresh.os,
                "stat",
                return_value=SimpleNamespace(st_mode=special_mode),
            ) as stat_call,
            patch.object(bundle_refresh, "_rename_no_replace_at") as rename_call,
            pytest.raises(OSError, match="unsafe .* preserved"),
        ):
            bundle_refresh._retire_rollback_file_at(
                parent_descriptor,
                "created.yaml",
                retired_descriptor,
                "created.yaml",
                claim_descriptor,
                _sha256(claim.read_bytes()),
            )
        stat_call.assert_called_once_with(
            "created.yaml",
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        rename_call.assert_not_called()
    finally:
        os.close(retired_descriptor)
        os.close(claim_descriptor)
        os.close(parent_descriptor)


@pytest.mark.skipif(os.name != "posix", reason="atomic retirement is POSIX-only")
def test_target_created_retirement_restores_same_byte_replacement_raced_at_rename(
    tmp_path: Path,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    parent = tmp_path / "managed"
    retired = tmp_path / "retired"
    parent.mkdir()
    retired.mkdir()
    destination = parent / "created.yaml"
    claim = parent / "created.claim"
    replacement = parent / "replacement"
    payload = b"identical target bytes\n"
    destination.write_bytes(payload)
    os.link(destination, claim)
    replacement.write_bytes(payload)
    replacement_identity = replacement.stat().st_dev, replacement.stat().st_ino

    parent_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    retired_descriptor = os.open(retired, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    claim_descriptor = os.open(claim, os.O_RDONLY)
    real_rename = bundle_refresh._rename_no_replace_at
    substituted = False

    def substitute_after_authentication(
        source_parent_fd: int,
        source_name: str,
        retired_parent_fd: int,
        retired_name: str,
    ) -> None:
        nonlocal substituted
        if source_parent_fd == parent_descriptor and not substituted:
            substituted = True
            os.unlink(destination.name, dir_fd=source_parent_fd)
            os.rename(
                replacement.name,
                destination.name,
                src_dir_fd=source_parent_fd,
                dst_dir_fd=source_parent_fd,
            )
        real_rename(
            source_parent_fd,
            source_name,
            retired_parent_fd,
            retired_name,
        )

    try:
        with (
            patch.object(
                bundle_refresh,
                "_rename_no_replace_at",
                side_effect=substitute_after_authentication,
            ),
            pytest.raises(OSError, match="raced .* restored and preserved"),
        ):
            bundle_refresh._retire_rollback_file_at(
                parent_descriptor,
                destination.name,
                retired_descriptor,
                destination.name,
                claim_descriptor,
                _sha256(payload),
            )
    finally:
        os.close(claim_descriptor)
        os.close(retired_descriptor)
        os.close(parent_descriptor)

    assert substituted
    assert destination.read_bytes() == payload
    assert (destination.stat().st_dev, destination.stat().st_ino) == replacement_identity
    assert claim.read_bytes() == payload
    assert not (retired / destination.name).exists()


@pytest.mark.skipif(os.name != "posix", reason="atomic retirement is POSIX-only")
def test_target_created_retirement_retry_completes_after_kill_post_rename(
    tmp_path: Path,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    parent = tmp_path / "managed"
    retired = tmp_path / "retired"
    parent.mkdir()
    retired.mkdir()
    destination = parent / "created.yaml"
    claim = tmp_path / "created.claim"
    payload = b"target bytes\n"
    destination.write_bytes(payload)
    os.link(destination, claim)
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    retired_fd = os.open(retired, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    claim_fd = os.open(claim, os.O_RDONLY)
    real_rename = bundle_refresh._rename_no_replace_at
    killed = False

    def kill_after_rename(*args) -> None:
        nonlocal killed
        real_rename(*args)
        if not killed:
            killed = True
            raise RuntimeError("simulated kill after retirement rename")

    try:
        with (
            patch.object(bundle_refresh, "_rename_no_replace_at", side_effect=kill_after_rename),
            pytest.raises(RuntimeError, match="simulated kill"),
        ):
            bundle_refresh._retire_rollback_file_at(
                parent_fd,
                destination.name,
                retired_fd,
                destination.name,
                claim_fd,
                _sha256(payload),
            )
        assert not destination.exists()
        assert os.path.samefile(retired / destination.name, claim)

        fsynced: list[int] = []
        real_fsync = bundle_refresh.os.fsync

        def record_fsync(descriptor: int) -> None:
            fsynced.append(descriptor)
            real_fsync(descriptor)

        with patch.object(bundle_refresh.os, "fsync", side_effect=record_fsync):
            bundle_refresh._retire_rollback_file_at(
                parent_fd,
                destination.name,
                retired_fd,
                destination.name,
                claim_fd,
                _sha256(payload),
            )
        assert retired_fd in fsynced
        assert parent_fd in fsynced
    finally:
        os.close(claim_fd)
        os.close(retired_fd)
        os.close(parent_fd)


@pytest.mark.skipif(os.name != "posix", reason="atomic retirement is POSIX-only")
def test_target_created_retirement_retry_restores_foreign_retired_leaf(
    tmp_path: Path,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    parent = tmp_path / "managed"
    retired = tmp_path / "retired"
    parent.mkdir()
    retired.mkdir()
    destination = parent / "created.yaml"
    claim = tmp_path / "created.claim"
    claim.write_bytes(b"target bytes\n")
    foreign = retired / destination.name
    foreign.write_bytes(b"foreign bytes\n")
    foreign_identity = foreign.stat().st_dev, foreign.stat().st_ino
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    retired_fd = os.open(retired, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    claim_fd = os.open(claim, os.O_RDONLY)
    fsync_events: list[str] = []
    real_fsync = bundle_refresh.os.fsync

    def record_fsync(descriptor: int) -> None:
        if descriptor == retired_fd:
            fsync_events.append("retired-directory")
        elif descriptor == parent_fd:
            fsync_events.append("source-directory")
        else:
            assert stat.S_ISREG(os.fstat(descriptor).st_mode)
            fsync_events.append("restored-file")
        real_fsync(descriptor)

    try:
        with (
            patch.object(bundle_refresh.os, "fsync", side_effect=record_fsync),
            pytest.raises(OSError, match="raced .* restored and preserved"),
        ):
            bundle_refresh._retire_rollback_file_at(
                parent_fd,
                destination.name,
                retired_fd,
                destination.name,
                claim_fd,
                _sha256(claim.read_bytes()),
            )
    finally:
        os.close(claim_fd)
        os.close(retired_fd)
        os.close(parent_fd)

    assert (destination.stat().st_dev, destination.stat().st_ino) == foreign_identity
    assert destination.read_bytes() == b"foreign bytes\n"
    assert not foreign.exists()
    assert fsync_events == [
        "restored-file",
        "retired-directory",
        "source-directory",
    ]


@pytest.mark.skipif(os.name != "posix", reason="atomic retirement is POSIX-only")
def test_target_created_retirement_detects_in_place_write_during_foreign_restore_fsync(
    tmp_path: Path,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    parent = tmp_path / "managed"
    retired = tmp_path / "retired"
    parent.mkdir()
    retired.mkdir()
    destination = parent / "created.yaml"
    claim = tmp_path / "created.claim"
    claim.write_bytes(b"target bytes\n")
    foreign = retired / destination.name
    foreign.write_bytes(b"foreign bytes\n")
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    retired_fd = os.open(retired, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    claim_fd = os.open(claim, os.O_RDONLY)
    real_fsync = bundle_refresh.os.fsync
    mutated = False

    def mutate_restored_file(descriptor: int) -> None:
        nonlocal mutated
        if descriptor not in {parent_fd, retired_fd} and not mutated:
            mutated = True
            destination.write_bytes(b"foreign bytes changed during fsync\n")
        real_fsync(descriptor)

    try:
        with (
            patch.object(bundle_refresh.os, "fsync", side_effect=mutate_restored_file),
            pytest.raises(OSError, match="changed during restore"),
        ):
            bundle_refresh._retire_rollback_file_at(
                parent_fd,
                destination.name,
                retired_fd,
                destination.name,
                claim_fd,
                _sha256(claim.read_bytes()),
            )
    finally:
        os.close(claim_fd)
        os.close(retired_fd)
        os.close(parent_fd)

    assert mutated
    assert destination.read_bytes() == b"foreign bytes changed during fsync\n"
    assert not foreign.exists()


@pytest.mark.skipif(os.name != "posix", reason="atomic retirement is POSIX-only")
def test_target_created_retirement_kill_while_restoring_foreign_leaf_is_idempotent(
    tmp_path: Path,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    parent = tmp_path / "managed"
    retired = tmp_path / "retired"
    parent.mkdir()
    retired.mkdir()
    destination = parent / "created.yaml"
    claim = tmp_path / "created.claim"
    claim.write_bytes(b"target bytes\n")
    foreign = retired / destination.name
    foreign.write_bytes(b"foreign bytes\n")
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    retired_fd = os.open(retired, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    claim_fd = os.open(claim, os.O_RDONLY)
    real_rename = bundle_refresh._rename_no_replace_at

    def kill_after_restore(*args) -> None:
        real_rename(*args)
        raise RuntimeError("simulated kill after foreign restore")

    try:
        with (
            patch.object(bundle_refresh, "_rename_no_replace_at", side_effect=kill_after_restore),
            pytest.raises(RuntimeError, match="simulated kill"),
        ):
            bundle_refresh._retire_rollback_file_at(
                parent_fd,
                destination.name,
                retired_fd,
                destination.name,
                claim_fd,
                _sha256(claim.read_bytes()),
            )
        assert destination.read_bytes() == b"foreign bytes\n"
        assert not foreign.exists()
        with pytest.raises(OSError, match="changed and was preserved"):
            bundle_refresh._retire_rollback_file_at(
                parent_fd,
                destination.name,
                retired_fd,
                destination.name,
                claim_fd,
                _sha256(claim.read_bytes()),
            )
    finally:
        os.close(claim_fd)
        os.close(retired_fd)
        os.close(parent_fd)


@pytest.mark.skipif(os.name != "posix", reason="atomic retirement is POSIX-only")
def test_target_created_retirement_preserves_late_canonical_replacement(
    tmp_path: Path,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    parent = tmp_path / "managed"
    retired = tmp_path / "retired"
    parent.mkdir()
    retired.mkdir()
    destination = parent / "created.yaml"
    claim = tmp_path / "created.claim"
    replacement = tmp_path / "replacement"
    payload = b"identical target bytes\n"
    destination.write_bytes(payload)
    os.link(destination, claim)
    replacement.write_bytes(payload)
    replacement_identity = replacement.stat().st_dev, replacement.stat().st_ino
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    retired_fd = os.open(retired, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    claim_fd = os.open(claim, os.O_RDONLY)
    real_rename = bundle_refresh._rename_no_replace_at
    injected = False

    def replace_after_retirement(*args) -> None:
        nonlocal injected
        real_rename(*args)
        if not injected:
            injected = True
            os.rename(replacement, destination)

    try:
        with (
            patch.object(bundle_refresh, "_rename_no_replace_at", side_effect=replace_after_retirement),
            pytest.raises(OSError, match="canonical path reappeared"),
        ):
            bundle_refresh._retire_rollback_file_at(
                parent_fd,
                destination.name,
                retired_fd,
                destination.name,
                claim_fd,
                _sha256(payload),
            )
    finally:
        os.close(claim_fd)
        os.close(retired_fd)
        os.close(parent_fd)

    assert (destination.stat().st_dev, destination.stat().st_ino) == replacement_identity
    assert os.path.samefile(retired / destination.name, claim)


@pytest.mark.skipif(os.name != "posix", reason="atomic retirement is POSIX-only")
def test_target_created_retirement_classifies_both_absent_and_collision(
    tmp_path: Path,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    parent = tmp_path / "managed"
    retired = tmp_path / "retired"
    parent.mkdir()
    retired.mkdir()
    claim = tmp_path / "created.claim"
    claim.write_bytes(b"target bytes\n")
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    retired_fd = os.open(retired, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    claim_fd = os.open(claim, os.O_RDONLY)
    try:
        bundle_refresh._retire_rollback_file_at(
            parent_fd,
            "created.yaml",
            retired_fd,
            "created.yaml",
            claim_fd,
            _sha256(claim.read_bytes()),
        )

        canonical = parent / "created.yaml"
        os.link(claim, canonical)
        collision = retired / "created.yaml"
        collision.write_bytes(b"foreign collision\n")
        with pytest.raises(OSError, match="collision was preserved"):
            bundle_refresh._retire_rollback_file_at(
                parent_fd,
                canonical.name,
                retired_fd,
                collision.name,
                claim_fd,
                _sha256(claim.read_bytes()),
            )
    finally:
        os.close(claim_fd)
        os.close(retired_fd)
        os.close(parent_fd)

    assert os.path.samefile(canonical, claim)
    assert collision.read_bytes() == b"foreign collision\n"


@pytest.mark.skipif(os.name != "posix", reason="hardlink custody is POSIX-only")
def test_completed_target_created_retirement_rejects_escaped_claim_hardlink(
    tmp_path: Path,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh

    parent = tmp_path / "managed"
    retired = tmp_path / "retired"
    parent.mkdir()
    retired.mkdir()
    claim = tmp_path / "created.claim"
    escaped = tmp_path / "escaped.claim"
    claim.write_bytes(b"target bytes\n")
    os.link(claim, escaped)
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    retired_fd = os.open(retired, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    claim_fd = os.open(claim, os.O_RDONLY)
    expected_digest = _sha256(claim.read_bytes())
    try:
        with pytest.raises(OSError, match="escaped deterministic custody"):
            bundle_refresh._retire_rollback_file_at(
                parent_fd,
                "created.yaml",
                retired_fd,
                "created.yaml",
                claim_fd,
                expected_digest,
            )

        assert os.path.samefile(claim, escaped)
        escaped.unlink()
        bundle_refresh._retire_rollback_file_at(
            parent_fd,
            "created.yaml",
            retired_fd,
            "created.yaml",
            claim_fd,
            expected_digest,
        )
    finally:
        os.close(claim_fd)
        os.close(retired_fd)
        os.close(parent_fd)

    assert claim.read_bytes() == b"target bytes\n"
    assert not (parent / "created.yaml").exists()
    assert not (retired / "created.yaml").exists()


def test_schema_one_target_created_inventory_fails_before_deleting_anything(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backup"
    stack = data_dir / "observability-stack"
    manifest = stack / ".defenseclaw-bundle-manifest.json"
    created = stack / "managed/created.yaml"
    for path in (manifest, created):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"target bytes\n")
    _write_backup(
        backup_dir,
        {".defenseclaw-bundle-manifest.json": (b"bridge manifest\n", 0o600)},
        created_paths={"managed/created.yaml": created},
        schema_version=1,
    )

    with pytest.raises(OSError, match="schema 1 lacks retained target-created claims"):
        _restore_local_observability_upgrade_backup(
            str(data_dir),
            str(backup_dir),
            {
                "installed": True,
                "managed_paths": ["managed/created.yaml"],
                "changed_paths": ["managed/created.yaml"],
                "restart_required": False,
            },
        )

    assert created.read_bytes() == b"target bytes\n"
    assert manifest.read_bytes() == b"target bytes\n"


@pytest.mark.skipif(
    os.name == "nt",
    reason="schema 1 intentionally lacks exact Windows owner/DACL rollback state",
)
def test_schema_one_without_target_created_paths_remains_rollback_compatible(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backup"
    manifest = data_dir / "observability-stack/.defenseclaw-bundle-manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_bytes(b"target manifest\n")
    _write_backup(
        backup_dir,
        {".defenseclaw-bundle-manifest.json": (b"bridge manifest\n", 0o600)},
        schema_version=1,
    )

    _restore_local_observability_upgrade_backup(
        str(data_dir),
        str(backup_dir),
        {
            "installed": True,
            "managed_paths": [],
            "changed_paths": [],
            "restart_required": False,
        },
    )

    assert manifest.read_bytes() == b"bridge manifest\n"


def test_retained_claim_preserves_preexisting_same_byte_substitution(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backup"
    destination = data_dir / "observability-stack/managed/created.yaml"
    destination.parent.mkdir(parents=True)
    payload = b"identical target bytes\n"
    destination.write_bytes(payload)
    _write_backup(
        backup_dir,
        {},
        created_paths={"managed/created.yaml": destination},
    )
    destination.unlink()
    destination.write_bytes(payload)
    replacement_identity = destination.stat().st_dev, destination.stat().st_ino

    with pytest.raises(OSError, match="changed and was preserved"):
        _restore_local_observability_upgrade_backup(
            str(data_dir),
            str(backup_dir),
            {
                "installed": True,
                "managed_paths": ["managed/created.yaml"],
                "changed_paths": ["managed/created.yaml"],
                "restart_required": False,
            },
        )

    assert destination.read_bytes() == payload
    assert (destination.stat().st_dev, destination.stat().st_ino) == replacement_identity


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
                "restart_required": False,
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
                "restart_required": False,
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
            backup_dir / "local-observability-stack/created",
            backup_dir / "local-observability-stack/retired",
            {"managed/member.yaml"},
            existing,
            {"managed/member.yaml": _sha256(bridge_state)} if restore_existing else {},
            {"managed/member.yaml": 0o600} if restore_existing else {},
            {},
            {},
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
    _write_backup(
        backup_dir,
        {},
        created_paths={"managed/member.yaml": managed_file},
    )
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
            backup_dir / "local-observability-stack/created",
            backup_dir / "local-observability-stack/retired",
            {"managed/member.yaml"},
            set(),
            {},
            {},
            {"managed/member.yaml": _sha256(b"target state\n")},
            {},
        )


@pytest.mark.skipif(os.name == "nt", reason="exercises the generic non-Windows path fallback")
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
        created_paths={"managed/created.yaml": created},
    )

    bundle_refresh._restore_local_observability_backup_by_path(
        stack,
        backup_dir / "local-observability-stack/managed",
        backup_dir / "local-observability-stack/created",
        backup_dir / "local-observability-stack/retired",
        {"managed/existing.yaml", "managed/created.yaml"},
        {"managed/existing.yaml"},
        {"managed/existing.yaml": _sha256(bridge_state)},
        {"managed/existing.yaml": 0o600},
        {"managed/created.yaml": _sha256(created.read_bytes())},
        {},
    )

    assert existing.read_bytes() == bridge_state
    assert not created.exists()


@pytest.mark.skipif(os.name == "nt", reason="exercises the generic non-Windows path fallback")
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
            backup_dir / "local-observability-stack/created",
            backup_dir / "local-observability-stack/retired",
            {"managed/member.yaml"},
            {"managed/member.yaml"},
            {"managed/member.yaml": _sha256(bridge_state)},
            {"managed/member.yaml": 0o600},
            {},
            {},
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
            backup_dir / "local-observability-stack/created",
            backup_dir / "local-observability-stack/retired",
            {"managed/member.yaml"},
            {"managed/member.yaml"},
            {"managed/member.yaml": _sha256(expected)},
            {"managed/member.yaml": 0o600},
            {},
            {},
        )

    _assert_destination_snapshot(destination, before)
    assert not list(destination.parent.glob(".rollback-*"))


@pytest.mark.skipif(os.name == "nt", reason="exercises the generic non-Windows path fallback")
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
            backup_dir / "local-observability-stack/created",
            backup_dir / "local-observability-stack/retired",
            {"managed/member.yaml"},
            {"managed/member.yaml"},
            {"managed/member.yaml": _sha256(expected)},
            {"managed/member.yaml": 0o600},
            {},
            {},
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
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
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

    def apply_exact(path: str, observed_security: object) -> None:
        assert os.path.exists(path)
        assert observed_security is security
        events.append("apply-security")

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
        patch.object(windows_acl, "write_new_file", side_effect=write_private) as private_write,
        patch.object(windows_acl, "apply_path", side_effect=apply_exact) as apply_security,
        patch.object(windows_acl, "capture_path", return_value=security),
        patch.object(windows_acl, "capture_fd", return_value=security),
        patch.object(windows_acl, "replace_regular_file_by_handle", side_effect=replace_by_handle),
        patch.object(windows_acl, "delete_regular_file_by_handle"),
    ):
        if mutation == "valid":
            bundle_refresh._restore_local_observability_backup_by_path(
                destination_root,
                backup_dir / "local-observability-stack/managed",
                backup_dir / "local-observability-stack/created",
                backup_dir / "local-observability-stack/retired",
                {"managed/member.yaml"},
                {"managed/member.yaml"},
                {"managed/member.yaml": _sha256(expected)},
                {"managed/member.yaml": 0o600},
                {},
                {"managed/member.yaml": security},
            )
        else:
            expected_error = "digest mismatch" if mutation == "digest-mismatch" else "changed during restore"
            with pytest.raises(OSError, match=expected_error):
                bundle_refresh._restore_local_observability_backup_by_path(
                    destination_root,
                    backup_dir / "local-observability-stack/managed",
                    backup_dir / "local-observability-stack/created",
                    backup_dir / "local-observability-stack/retired",
                    {"managed/member.yaml"},
                    {"managed/member.yaml"},
                    {"managed/member.yaml": _sha256(expected)},
                    {"managed/member.yaml": 0o600},
                    {},
                    {"managed/member.yaml": security},
                )

    if mutation == "valid":
        assert events.index("private-write") < events.index("apply-security")
        assert events.index("apply-security") < events.index("handle-replace")
        assert events.index("private-write") < events.index("handle-replace")
        assert destination.read_bytes() == expected
        private_write.assert_called_once()
        apply_security.assert_called_once()
    else:
        _assert_destination_snapshot(destination, before)
        private_write.assert_not_called()
        apply_security.assert_not_called()
    assert not list(destination.parent.glob(".rollback-*"))


def test_windows_rollback_holds_parent_chain_across_mkdir_and_delete(
    tmp_path: Path,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh
    from defenseclaw import windows_acl

    destination_root = tmp_path / "observability-stack"
    destination_root.mkdir()
    backup_dir = tmp_path / "backup"
    retired = destination_root / "managed/retired.yaml"
    retired.parent.mkdir()
    retired.write_bytes(b"target-created state\n")
    created_parent = destination_root / "new-parent"
    expected = b"bridge state\n"
    _write_backup(
        backup_dir,
        {"new-parent/restored.yaml": (expected, 0o600)},
        created_paths={"managed/retired.yaml": retired},
    )

    events: list[str] = []
    held: list[str] = []
    security = object()
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

    def write_private(path: str, payload: bytes, observed_security: object) -> None:
        assert held
        assert observed_security is security
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            os.write(descriptor, payload)
        finally:
            os.close(descriptor)

    def replace_by_handle(source: str, target: str) -> None:
        assert held
        events.append("handle-replace")
        os.replace(source, target)

    def delete_exact(
        path: Path,
        _parent_chain,
        claim: Path,
        _claim_chain,
        expected_digest: str,
    ) -> None:
        assert held
        events.append("handle-delete")
        assert os.path.samefile(path, claim)
        assert _sha256(claim.read_bytes()) == expected_digest
        path.unlink()

    with (
        patch.object(bundle_refresh.os, "name", "nt"),
        patch.object(bundle_refresh.os, "mkdir", side_effect=locked_mkdir),
        patch.object(windows_acl, "hold_directory_chain", side_effect=hold),
        patch.object(windows_acl, "hold_directory", side_effect=hold),
        patch.object(windows_acl, "write_new_file", side_effect=write_private),
        patch.object(windows_acl, "apply_path"),
        patch.object(windows_acl, "capture_path", return_value=security),
        patch.object(windows_acl, "capture_fd", return_value=security),
        patch.object(
            windows_acl,
            "open_regular_read_fd_shared_delete",
            side_effect=lambda path: os.open(path, os.O_RDONLY),
        ),
        patch.object(windows_acl, "replace_regular_file_by_handle", side_effect=replace_by_handle),
        patch.object(
            bundle_refresh,
            "_remove_windows_rollback_file_by_path",
            side_effect=delete_exact,
        ),
    ):
        bundle_refresh._restore_local_observability_backup_by_path(
            destination_root,
            backup_dir / "local-observability-stack/managed",
            backup_dir / "local-observability-stack/created",
            backup_dir / "local-observability-stack/retired",
            {"managed/retired.yaml", "new-parent/restored.yaml"},
            {"new-parent/restored.yaml"},
            {"new-parent/restored.yaml": _sha256(expected)},
            {"new-parent/restored.yaml": 0o600},
            {"managed/retired.yaml": _sha256(b"target-created state\n")},
            {"new-parent/restored.yaml": security},
        )

    assert created_parent.joinpath("restored.yaml").read_bytes() == expected
    assert not retired.exists()
    assert events.index("mkdir") < events.index("handle-replace")
    assert events.index("handle-delete") < max(
        index for index, event in enumerate(events) if event.startswith("lease-exit:")
    )


@pytest.mark.parametrize("substituted", [False, True])
def test_windows_exact_delete_authenticates_claim_before_same_handle_disposition(
    tmp_path: Path,
    substituted: bool,
) -> None:
    import defenseclaw.bundle_refresh as bundle_refresh
    from defenseclaw import windows_acl

    destination_parent = tmp_path / "observability-stack/managed"
    claim_parent = tmp_path / "backup/created/managed"
    destination_parent.mkdir(parents=True)
    claim_parent.mkdir(parents=True)
    destination = destination_parent / "created.yaml"
    claim = claim_parent / "created.yaml"
    payload = b"identical target bytes\n"
    claim.write_bytes(payload)
    if substituted:
        destination.write_bytes(payload)
    else:
        os.link(claim, destination)

    class FakeApi:
        def __init__(self) -> None:
            self.opened: list[tuple[int, str]] = []
            self.closed: list[int] = []

        def _open_regular_mutator(self, path: str) -> int:
            events.append("destination-open")
            os.fstat(claim_descriptor)
            handle = 37
            self.opened.append((handle, path))
            return handle

        def close_handle(self, handle: int) -> None:
            events.append("destination-close")
            self.closed.append(handle)

    api = FakeApi()
    disposed: list[int] = []
    events: list[str] = []
    real_close = os.close
    claim_descriptor = os.open(claim, os.O_RDONLY)
    claim_is_open = True

    def open_claim(path: str) -> int:
        assert path == str(claim)
        events.append("claim-native-open")
        return claim_descriptor

    def close_descriptor(descriptor: int) -> None:
        nonlocal claim_is_open
        if descriptor == claim_descriptor and claim_is_open:
            events.append("claim-close")
            claim_is_open = False
        real_close(descriptor)

    def dispose(_api: FakeApi, handle: int) -> None:
        assert _api is api
        events.append("disposition")
        disposed.append(handle)
        destination.unlink()

    destination_chain = [
        (destination_parent, bundle_refresh._rollback_directory_info(destination_parent))
    ]
    claim_chain = [(claim_parent, bundle_refresh._rollback_directory_info(claim_parent))]
    with (
        patch.object(bundle_refresh.os, "name", "nt"),
        patch.object(windows_acl, "_get_api", return_value=api),
        patch.object(
            windows_acl,
            "open_regular_read_fd_shared_delete",
            side_effect=open_claim,
        ) as native_open,
        patch.object(bundle_refresh.os, "close", side_effect=close_descriptor),
        patch.object(bundle_refresh, "_mark_windows_handle_for_delete", side_effect=dispose),
    ):
        if substituted:
            with pytest.raises(OSError, match="changed and was preserved"):
                bundle_refresh._remove_windows_rollback_file_by_path(
                    destination,
                    destination_chain,
                    claim,
                    claim_chain,
                    _sha256(payload),
                )
        else:
            bundle_refresh._remove_windows_rollback_file_by_path(
                destination,
                destination_chain,
                claim,
                claim_chain,
                _sha256(payload),
            )

    native_open.assert_called_once_with(str(claim))
    assert api.opened == [(37, str(destination))]
    assert api.closed == [37]
    assert disposed == ([] if substituted else [37])
    assert events == (
        ["claim-native-open", "destination-open", "destination-close", "claim-close"]
        if substituted
        else [
            "claim-native-open",
            "destination-open",
            "disposition",
            "destination-close",
            "claim-close",
        ]
    )
    with pytest.raises(OSError):
        os.fstat(claim_descriptor)
    assert destination.exists() is substituted
    assert claim.read_bytes() == payload
