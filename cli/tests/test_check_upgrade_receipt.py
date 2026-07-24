# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

import pytest
import yaml

import scripts.check_upgrade_receipt as receipt_check
from scripts.check_upgrade_receipt import ReceiptCheckError, _queued_receipts, check_upgrade_receipt


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    data_dir = tmp_path / "data"
    database = data_dir / "state" / "audit.db"
    database.parent.mkdir(parents=True)
    (data_dir / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "config_version": 8,
                "observability": {"local": {"path": str(database)}},
            }
        ),
        encoding="utf-8",
    )
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            """CREATE TABLE audit_events (
                id TEXT PRIMARY KEY,
                action TEXT,
                bucket TEXT,
                signal TEXT,
                event_name TEXT,
                source TEXT,
                mandatory INTEGER,
                structured_json TEXT,
                projected_record_json TEXT
            )"""
        )
        connection.commit()
    finally:
        connection.close()
    return data_dir, database


def _facts(receipt_id: str, **overrides: object) -> dict[str, object]:
    facts: dict[str, object] = {
        "receipt_id": receipt_id,
        "from_version": "0.8.4",
        "target_version": "0.8.5",
        "status": "succeeded",
        "migration_status": "completed",
        "migration_count": 1,
        "artifacts_verified": True,
        "failure_code": "",
    }
    facts.update(overrides)
    return facts


def _insert(database: Path, facts: dict[str, object], *, outcome: str = "applied") -> None:
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            """INSERT INTO audit_events
               (id, action, bucket, signal, event_name, source, mandatory,
                structured_json, projected_record_json)
               VALUES (?, 'upgrade', 'compliance.activity', 'logs',
                       'legacy.audit.upgrade', 'cli', 1, ?, ?)""",
            (
                facts["receipt_id"],
                json.dumps(facts),
                json.dumps({"outcome": outcome}),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _queue(data_dir: Path, facts: dict[str, object]) -> Path:
    root = data_dir / ".upgrade-receipts"
    root.mkdir()
    path = root / f"{facts['receipt_id']}.json"
    path.write_text(json.dumps(facts), encoding="utf-8")
    return path


def _check(data_dir: Path, *, timeout: float = 0.2) -> None:
    check_upgrade_receipt(
        data_dir,
        source="0.8.4",
        target="0.8.5",
        timeout_seconds=timeout,
    )


def test_accepts_canonical_receipt_after_gateway_acknowledges_queue(tmp_path: Path) -> None:
    data_dir, database = _fixture(tmp_path)
    receipt = _facts(str(uuid.uuid4()))
    _insert(database, receipt)

    _check(data_dir)


def test_accepts_success_after_prior_canonical_rollback(tmp_path: Path) -> None:
    data_dir, database = _fixture(tmp_path)
    rolled_back = _facts(
        str(uuid.uuid4()),
        status="rolled_back",
        migration_status="degraded",
        failure_code="health_check_failed",
    )
    _insert(database, rolled_back, outcome="revoked")
    _insert(database, _facts(str(uuid.uuid4())))

    _check(data_dir)


def test_ignores_prior_canonical_rollback_from_another_source(tmp_path: Path) -> None:
    data_dir, database = _fixture(tmp_path)
    rolled_back = _facts(
        str(uuid.uuid4()),
        from_version="0.8.3",
        status="rolled_back",
        migration_status="degraded",
        failure_code="health_check_failed",
    )
    _insert(database, rolled_back, outcome="revoked")
    _insert(database, _facts(str(uuid.uuid4())))

    _check(data_dir)


def test_waits_for_acknowledgement_when_same_receipt_is_briefly_queued(tmp_path: Path) -> None:
    data_dir, database = _fixture(tmp_path)
    receipt = _facts(str(uuid.uuid4()))
    _insert(database, receipt)
    queued = _queue(data_dir, receipt)
    timer = threading.Timer(0.05, queued.unlink)
    timer.start()
    try:
        _check(data_dir, timeout=1)
    finally:
        timer.join()


def test_waits_for_prior_rollback_queue_acknowledgement(tmp_path: Path) -> None:
    data_dir, database = _fixture(tmp_path)
    rolled_back = _facts(
        str(uuid.uuid4()),
        status="rolled_back",
        migration_status="degraded",
        failure_code="health_check_failed",
    )
    _insert(database, rolled_back, outcome="revoked")
    _insert(database, _facts(str(uuid.uuid4())))
    queued = _queue(data_dir, rolled_back)
    timer = threading.Timer(0.05, queued.unlink)
    timer.start()
    try:
        _check(data_dir, timeout=1)
    finally:
        timer.join()


def test_queue_scan_tolerates_gateway_acknowledgement_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir, _ = _fixture(tmp_path)
    queued = _queue(data_dir, _facts(str(uuid.uuid4())))
    real_lstat = Path.lstat

    def unlink_during_lstat(path: Path):
        if path == queued:
            path.unlink()
            raise FileNotFoundError(path)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", unlink_during_lstat)

    assert _queued_receipts(data_dir) == []


def test_locked_database_respects_short_caller_deadline(tmp_path: Path) -> None:
    data_dir, database = _fixture(tmp_path)
    lock = sqlite3.connect(database, timeout=0)
    lock.execute("BEGIN EXCLUSIVE")
    started = time.monotonic()
    try:
        with pytest.raises(ReceiptCheckError, match="canonical=0 queued=0"):
            _check(data_dir, timeout=0.05)
    finally:
        elapsed = time.monotonic() - started
        lock.rollback()
        lock.close()

    assert elapsed < 0.2


def test_canonical_reads_leave_retry_budget_to_outer_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir, _ = _fixture(tmp_path)
    real_connect = sqlite3.connect
    observed_timeouts: list[object] = []

    def recording_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        observed_timeouts.append(kwargs.get("timeout"))
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(receipt_check.sqlite3, "connect", recording_connect)

    with pytest.raises(ReceiptCheckError, match="canonical=0 queued=0"):
        _check(data_dir, timeout=0.01)

    assert observed_timeouts
    assert set(observed_timeouts) == {0.0}


def test_slow_canonical_read_cannot_succeed_after_caller_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir, database = _fixture(tmp_path)
    _insert(database, _facts(str(uuid.uuid4())))
    now = [100.0]
    real_canonical_receipts = receipt_check._canonical_receipts

    def slow_canonical_receipts(*args: object, **kwargs: object):
        rows = real_canonical_receipts(*args, **kwargs)
        now[0] = 100.1
        return rows

    monkeypatch.setattr(receipt_check.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(receipt_check, "_canonical_receipts", slow_canonical_receipts)

    with pytest.raises(ReceiptCheckError, match="canonical=1 queued=0"):
        _check(data_dir, timeout=0.05)


def test_rejects_duplicate_canonical_target_receipts(tmp_path: Path) -> None:
    data_dir, database = _fixture(tmp_path)
    _insert(database, _facts(str(uuid.uuid4())))
    _insert(database, _facts(str(uuid.uuid4())))

    with pytest.raises(ReceiptCheckError, match="duplicate"):
        _check(data_dir)


@pytest.mark.parametrize(
    "overrides",
    [
        {"from_version": "0.8.3"},
        {"status": "partial"},
        {"migration_status": "degraded"},
        {"artifacts_verified": False},
        {"failure_code": "migration_failed"},
    ],
)
def test_rejects_invalid_canonical_terminal_facts(
    tmp_path: Path,
    overrides: dict[str, object],
) -> None:
    data_dir, database = _fixture(tmp_path)
    _insert(database, _facts(str(uuid.uuid4()), **overrides))

    with pytest.raises(ReceiptCheckError):
        _check(data_dir)


def test_rejects_nonterminal_queue_even_when_canonical_receipt_exists(tmp_path: Path) -> None:
    data_dir, database = _fixture(tmp_path)
    terminal = _facts(str(uuid.uuid4()))
    _insert(database, terminal)
    _queue(data_dir, _facts(str(uuid.uuid4()), status="pending"))

    with pytest.raises(ReceiptCheckError, match="pending or partial"):
        _check(data_dir)


def test_rejects_queue_file_without_canonical_admission(tmp_path: Path) -> None:
    data_dir, _ = _fixture(tmp_path)
    _queue(data_dir, _facts(str(uuid.uuid4())))

    with pytest.raises(ReceiptCheckError, match="canonical=0 queued=1"):
        _check(data_dir, timeout=0.05)


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), 0.0, -1.0])
def test_rejects_nonfinite_or_nonpositive_timeout(tmp_path: Path, timeout: float) -> None:
    data_dir, _ = _fixture(tmp_path)

    with pytest.raises(ReceiptCheckError, match="finite and positive"):
        _check(data_dir, timeout=timeout)
