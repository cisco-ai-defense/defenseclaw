# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

import pytest
from defenseclaw import upgrade_receipt as upgrade_receipt_module
from defenseclaw.upgrade_receipt import (
    MAX_UPGRADE_RECEIPTS,
    UPGRADE_RECEIPT_DIRECTORY,
    begin_upgrade_receipt,
    clear_local_bundle_restart_intent,
    complete_upgrade_receipt,
    delegate_prior_upgrade_receipts,
    finalize_interrupted_upgrade_receipts,
    find_resumable_upgrade_receipt,
    find_verified_installed_upgrade_receipt,
    load_local_bundle_restart_intent,
    load_upgrade_receipt,
    load_upgrade_receipt_supersession,
    record_local_bundle_restart_intent,
    record_upgrade_migrations,
    record_upgrade_receipt_supersession,
    supersede_prior_upgrade_receipts,
)


def _symlink_or_skip(
    link: Path,
    target: Path,
    *,
    target_is_directory: bool = False,
) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")


def test_python_and_go_recoverable_failure_codes_match() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    go_source = (repository_root / "internal/gateway/upgrade_receipt.go").read_text(encoding="utf-8")
    function_marker = "func upgradeReceiptRecoverableFailure("
    authority_marker = "\nfunc upgradeReceiptRecoveryAuthority"
    assert function_marker in go_source, "Go recovery failure-code function is missing"
    function_start = go_source.index(function_marker)
    assert authority_marker in go_source[function_start:], "Go recovery-authority function is missing"
    function_end = go_source.index(authority_marker, function_start)
    function_source = go_source[function_start:function_end]
    switch_body = re.search(
        r"switch receipt\.FailureCode \{(?P<body>.*?)\n\tdefault:",
        function_source,
        flags=re.DOTALL,
    )

    assert switch_body is not None, "Go recoverable failure-code switch is missing"
    case_labels = re.findall(
        r'(?m)^\s*case\s+("[a-z_]+"(?:\s*,\s*"[a-z_]+")*)\s*:',
        switch_body.group("body"),
    )
    assert case_labels, "Go recoverable failure-code case labels are missing"
    go_failure_codes = frozenset(code for labels in case_labels for code in re.findall(r'"([a-z_]+)"', labels))
    assert go_failure_codes == upgrade_receipt_module._RECOVERABLE_TARGET_FAILURE_CODES


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


def test_resumable_lookup_is_read_only_and_requires_one_verified_target(tmp_path: Path) -> None:
    receipt_dir = tmp_path / UPGRADE_RECEIPT_DIRECTORY
    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") is None
    assert not receipt_dir.exists()

    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") == path
    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.1.0") is None


def test_resumable_lookup_refuses_unverified_or_ambiguous_target(tmp_path: Path) -> None:
    begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=False,
    )
    with pytest.raises(ValueError, match="did not authenticate"):
        find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0")

    other = tmp_path / "other"
    begin_upgrade_receipt(
        str(other),
        from_version="7.8.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    begin_upgrade_receipt(
        str(other),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    with pytest.raises(ValueError, match="multiple pending"):
        find_resumable_upgrade_receipt(str(other), target_version="8.0.0")


def test_resumable_lookup_uses_failed_target_until_health_proven_success(tmp_path: Path) -> None:
    failed = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    record_upgrade_migrations(failed, migration_count=1, degraded=False)
    complete_upgrade_receipt(
        failed,
        status="failed",
        failure_code="local_observability_failed",
    )
    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") == failed

    succeeded = begin_upgrade_receipt(
        str(tmp_path),
        from_version="8.0.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    record_upgrade_migrations(succeeded, migration_count=0, degraded=False)
    record_upgrade_receipt_supersession(
        failed,
        replacement_path=succeeded,
        health_proven=True,
    )
    complete_upgrade_receipt(succeeded, status="succeeded")
    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") is None
    assert find_verified_installed_upgrade_receipt(str(tmp_path), target_version="8.0.0") == succeeded


def test_installed_authority_requires_verified_terminal_success(tmp_path: Path) -> None:
    unverified = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=False,
    )
    record_upgrade_migrations(unverified, migration_count=1, degraded=False)
    complete_upgrade_receipt(unverified, status="succeeded")
    assert find_verified_installed_upgrade_receipt(str(tmp_path), target_version="8.0.0") is None

    verified = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    record_upgrade_migrations(verified, migration_count=1, degraded=True)
    complete_upgrade_receipt(verified, status="partial")
    assert find_verified_installed_upgrade_receipt(str(tmp_path), target_version="8.0.0") == verified


def test_installed_authority_orders_mixed_iso_timestamps_chronologically(tmp_path: Path) -> None:
    receipts: list[tuple[Path, str]] = []
    for created_at in (
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00.500000Z",
    ):
        path = begin_upgrade_receipt(
            str(tmp_path),
            from_version="7.9.0",
            target_version="8.0.0",
            artifacts_verified=True,
        )
        record_upgrade_migrations(path, migration_count=1, degraded=False)
        complete_upgrade_receipt(path, status="succeeded")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["created_at"] = created_at
        payload["completed_at"] = created_at
        path.write_text(json.dumps(payload), encoding="utf-8")
        if os.name == "posix":
            os.chmod(path, 0o600)
        receipts.append((path, created_at))

    assert find_verified_installed_upgrade_receipt(str(tmp_path), target_version="8.0.0") == receipts[1][0]


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode contract")
def test_recovery_lookup_rejects_replaceable_or_malformed_queue_entries(tmp_path: Path) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    os.chmod(path.parent, 0o755)
    with pytest.raises(OSError, match="accessible to other accounts"):
        find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0")

    os.chmod(path.parent, 0o700)
    path.write_text("not-json", encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ValueError, match="invalid entry"):
        find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0")


def test_recovery_lookup_rejects_symlinked_queue_or_record(tmp_path: Path) -> None:
    actual_root = tmp_path / "actual"
    begin_upgrade_receipt(
        str(actual_root),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    linked_root = tmp_path / "linked"
    linked_root.mkdir()
    _symlink_or_skip(
        linked_root / UPGRADE_RECEIPT_DIRECTORY,
        actual_root / UPGRADE_RECEIPT_DIRECTORY,
        target_is_directory=True,
    )
    with pytest.raises(OSError, match="private directory"):
        find_resumable_upgrade_receipt(str(linked_root), target_version="8.0.0")

    receipt_dir = actual_root / UPGRADE_RECEIPT_DIRECTORY
    target = next(receipt_dir.glob("*.json"))
    symlink = receipt_dir / "00000000-0000-0000-0000-000000000000.json"
    _symlink_or_skip(symlink, target)
    with pytest.raises(ValueError, match="unsafe entry"):
        find_resumable_upgrade_receipt(str(actual_root), target_version="8.0.0")


def test_recovery_lookup_enforces_receipt_queue_bound(tmp_path: Path) -> None:
    receipt_dir = tmp_path / UPGRADE_RECEIPT_DIRECTORY
    receipt_dir.mkdir(mode=0o700)
    for index in range(MAX_UPGRADE_RECEIPTS + 1):
        path = receipt_dir / f"{index:064x}.json"
        path.write_text("{}", encoding="utf-8")
        if os.name == "posix":
            os.chmod(path, 0o600)
    with pytest.raises(OSError, match="exceeds its bound"):
        find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0")


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
    _symlink_or_skip(symlink, target)
    with pytest.raises(ValueError, match="regular"):
        load_upgrade_receipt(symlink)


@pytest.mark.parametrize("writer", ["receipt", "metadata"])
def test_atomic_writers_do_not_close_transferred_descriptor_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    writer: str,
) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    original_mkstemp = upgrade_receipt_module.tempfile.mkstemp
    original_close = upgrade_receipt_module.os.close
    descriptors: list[int] = []
    explicit_closes: list[int] = []

    def tracked_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        descriptor, temporary = original_mkstemp(*args, **kwargs)
        explicit_closes.clear()
        descriptors.append(descriptor)
        return descriptor, temporary

    def tracked_close(descriptor: int) -> None:
        explicit_closes.append(descriptor)
        original_close(descriptor)

    def fail_replace(_source: object, _target: object) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(upgrade_receipt_module.tempfile, "mkstemp", tracked_mkstemp)
    monkeypatch.setattr(upgrade_receipt_module.os, "close", tracked_close)
    monkeypatch.setattr(upgrade_receipt_module.os, "replace", fail_replace)

    with pytest.raises(OSError, match="injected replace failure"):
        if writer == "receipt":
            record_upgrade_migrations(path, migration_count=1, degraded=False)
        else:
            record_local_bundle_restart_intent(path, restart_required=True)

    assert len(descriptors) == 1
    assert descriptors[0] not in explicit_closes


def test_local_bundle_restart_intent_is_private_monotonic_and_receipt_bound(
    tmp_path: Path,
) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    assert load_local_bundle_restart_intent(path) is None
    assert record_local_bundle_restart_intent(path, restart_required=False) is False
    assert record_local_bundle_restart_intent(path, restart_required=True) is True
    assert record_local_bundle_restart_intent(path, restart_required=False) is True
    assert load_local_bundle_restart_intent(path) is True

    intent_path = next(path.parent.glob("*.local-bundle-intent"))
    if os.name == "posix":
        assert stat.S_IMODE(intent_path.stat().st_mode) == 0o600
    complete_upgrade_receipt(
        path,
        status="failed",
        failure_code="local_observability_failed",
    )
    assert load_local_bundle_restart_intent(path) is True


def test_cleared_local_bundle_restart_intent_stays_absent_after_success(
    tmp_path: Path,
) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    record_local_bundle_restart_intent(path, restart_required=True)
    intent_path = next(path.parent.glob("*.local-bundle-intent"))
    clear_local_bundle_restart_intent(path)
    complete_upgrade_receipt(path, status="succeeded")
    assert not intent_path.exists()


def test_clear_local_bundle_restart_intent_preserves_unlink_errors(
    tmp_path: Path,
) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    record_local_bundle_restart_intent(path, restart_required=True)

    def fail_unlink(*_args: object, **_kwargs: object) -> None:
        raise PermissionError

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Path, "unlink", fail_unlink)
        with pytest.raises(PermissionError):
            clear_local_bundle_restart_intent(path)


def test_clear_local_bundle_restart_intent_tolerates_missing_file_race(
    tmp_path: Path,
) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    record_local_bundle_restart_intent(path, restart_required=True)
    intent_path = next(path.parent.glob("*.local-bundle-intent"))
    original_unlink = Path.unlink

    def race_unlink(candidate: Path, *, missing_ok: bool = False) -> None:
        original_unlink(candidate, missing_ok=missing_ok)
        raise FileNotFoundError(candidate)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Path, "unlink", race_unlink)
        clear_local_bundle_restart_intent(path)

    assert not intent_path.exists()


def test_old_controller_terminal_intent_authorizes_one_strict_recovery(tmp_path: Path) -> None:
    old = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    record_local_bundle_restart_intent(old, restart_required=True)
    payload = json.loads(old.read_text(encoding="utf-8"))
    payload.update(
        {
            "status": "partial",
            "migration_status": "degraded",
            "migration_count": 0,
            "completed_at": payload["created_at"],
        }
    )
    old.write_text(json.dumps(payload), encoding="utf-8")
    if os.name == "posix":
        os.chmod(old, 0o600)

    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") == old

    recovered = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    record_local_bundle_restart_intent(recovered, restart_required=True)
    clear_local_bundle_restart_intent(recovered)
    assert supersede_prior_upgrade_receipts(recovered) == 1
    complete_upgrade_receipt(recovered, status="succeeded")
    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") is None
    assert load_local_bundle_restart_intent(old) is True


def test_health_proven_supersession_survives_success_acknowledgement(tmp_path: Path) -> None:
    failed = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    complete_upgrade_receipt(
        failed,
        status="failed",
        failure_code="health_check_failed",
    )
    replacement = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )

    assert (
        record_upgrade_receipt_supersession(
            failed,
            replacement_path=replacement,
            health_proven=True,
        )
        == load_upgrade_receipt(replacement).receipt_id
    )
    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") == replacement

    complete_upgrade_receipt(replacement, status="succeeded")
    replacement.unlink()
    assert load_upgrade_receipt_supersession(failed) is not None
    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") is None


def test_retry_delegation_keeps_one_authority_across_repeated_failures(tmp_path: Path) -> None:
    first = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    complete_upgrade_receipt(first, status="failed", failure_code="interrupted")
    second = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    assert delegate_prior_upgrade_receipts(second) == 1
    complete_upgrade_receipt(second, status="failed", failure_code="migration_failed")
    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") == second

    third = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    assert delegate_prior_upgrade_receipts(third) == 2
    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") == third
    assert supersede_prior_upgrade_receipts(third) == 2
    complete_upgrade_receipt(third, status="succeeded")
    third.unlink()

    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") is None


def test_nonrecoverable_replacement_restores_delegated_authority(tmp_path: Path) -> None:
    prior = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    complete_upgrade_receipt(prior, status="failed", failure_code="interrupted")
    replacement = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    assert delegate_prior_upgrade_receipts(replacement) == 1
    complete_upgrade_receipt(replacement, status="failed", failure_code="install_failed")

    assert find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0") == prior


def test_supersession_metadata_fails_closed_when_identity_is_changed(tmp_path: Path) -> None:
    failed = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    complete_upgrade_receipt(
        failed,
        status="failed",
        failure_code="health_check_failed",
    )
    replacement = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    record_upgrade_receipt_supersession(
        failed,
        replacement_path=replacement,
        health_proven=True,
    )
    marker = next(failed.parent.glob("*.superseded-by"))
    payload = json.loads(marker.read_text(encoding="utf-8"))
    payload["target_version"] = "8.1.0"
    marker.write_text(json.dumps(payload), encoding="utf-8")
    if os.name == "posix":
        os.chmod(marker, 0o600)

    with pytest.raises(ValueError, match="supersession is invalid"):
        find_resumable_upgrade_receipt(str(tmp_path), target_version="8.0.0")


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode contract")
def test_local_bundle_restart_intent_rejects_replaceable_metadata(tmp_path: Path) -> None:
    path = begin_upgrade_receipt(
        str(tmp_path),
        from_version="7.9.0",
        target_version="8.0.0",
        artifacts_verified=True,
    )
    record_local_bundle_restart_intent(path, restart_required=True)
    intent_path = next(path.parent.glob("*.local-bundle-intent"))
    os.chmod(intent_path, 0o644)
    with pytest.raises(OSError, match="accessible to other accounts"):
        load_local_bundle_restart_intent(path)
