# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from defenseclaw.upgrade_receipt import (
    UPGRADE_RECEIPT_DIRECTORY,
    begin_upgrade_receipt,
    complete_upgrade_receipt,
    finalize_interrupted_upgrade_receipts,
    load_upgrade_receipt,
    record_upgrade_migrations,
)


def test_receipt_is_private_atomic_and_contains_only_bounded_facts(tmp_path: Path) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    receipt = load_upgrade_receipt(path)

    assert path.parent == tmp_path / UPGRADE_RECEIPT_DIRECTORY
    assert receipt.status == "pending"
    assert receipt.completed_at is None
    assert receipt.from_version == "7.9.0"
    assert receipt.target_version == "8.0.0"
    assert set(json.loads(path.read_text(encoding="utf-8"))) == {
        "schema_version",
        "receipt_id",
        "created_at",
        "completed_at",
        "from_version",
        "target_version",
        "status",
        "migration_status",
        "migration_count",
        "artifacts_verified",
        "failure_code",
    }
    assert "secret" not in path.read_text(encoding="utf-8").lower()
    if os.name == "posix":
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_progress_then_success_is_terminal_and_idempotent(tmp_path: Path) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    progress = record_upgrade_migrations(path, migration_count=3, degraded=False)
    assert progress.migration_status == "completed"
    assert progress.migration_count == 3

    completed = complete_upgrade_receipt(path, status="succeeded")
    assert completed.status == "succeeded"
    assert completed.completed_at
    assert complete_upgrade_receipt(path, status="succeeded") == completed
    with pytest.raises(ValueError, match="terminal"):
        complete_upgrade_receipt(path, status="failed", failure_code="interrupted")
    with pytest.raises(ValueError, match="terminal"):
        record_upgrade_migrations(path, migration_count=4, degraded=False)


def test_retry_does_not_infer_rollback_from_version_equality_alone(tmp_path: Path) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    assert finalize_interrupted_upgrade_receipts(str(tmp_path), current_version="7.9.0") == 1
    receipt = load_upgrade_receipt(path)
    assert receipt.status == "failed"
    assert receipt.failure_code == "interrupted"


def test_retry_never_promotes_an_abandoned_attempt_to_success(tmp_path: Path) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=False,
    )
    assert finalize_interrupted_upgrade_receipts(str(tmp_path), current_version="8.0.0") == 1
    receipt = load_upgrade_receipt(path)
    assert receipt.status == "failed"
    assert receipt.failure_code == "interrupted"
    assert receipt.artifacts_verified is False


def test_unknown_fields_and_symlink_receipts_are_rejected(tmp_path: Path) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["raw_config"] = "token=do-not-persist"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="fields"):
        load_upgrade_receipt(path)

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    symlink = path.parent / "00000000-0000-0000-0000-000000000000.json"
    if hasattr(os, "symlink"):
        symlink.symlink_to(target)
        with pytest.raises(ValueError, match="regular"):
            load_upgrade_receipt(symlink)
