# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Bridge-side replay of the target wheel's bundle rollback metadata."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

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
    old_sha256: dict[str, str] = {}
    old_modes: dict[str, int] = {}
    for relative, (payload, mode) in files.items():
        path = managed / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        os.chmod(path, mode)
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
