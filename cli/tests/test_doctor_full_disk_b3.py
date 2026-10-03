# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert doctor b3: plain full-disk cache note (GAP-2015), freed audit
disk no longer FAILs (GAP-2016), old real drops do not turn by-design skips
into data loss (GAP-2035)."""

from __future__ import annotations

import errno
import json
import sqlite3
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _check_observability_v8_status, _DoctorResult
from defenseclaw.observability.custody_status import inspect_connector_custody, summarize_native_delivery
from defenseclaw.observability.v8_status import V8BucketStatus, V8DestinationStatus, V8OperatorStatus

_Usage = namedtuple("_Usage", "total used free")
_FULL = _Usage(1 << 30, 1 << 30, 32 * 1024 * 1024)  # a full APFS volume still reports ~32 MiB
_FREED = _Usage(2 << 30, 1 << 30, 754 * 1024 * 1024)
_HEALTH = {
    "telemetry": {
        "state": "error",
        "details": {"event_history_failure": "sqlite_write_failed", "event_history_last_sqlite_class": "full"},
    }
}


def test_full_disk_cache_write_is_one_plain_line(tmp_path: Path, capsys) -> None:
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    full = OSError(errno.ENOSPC, "No space left on device")
    with mock.patch.object(cmd_doctor, "atomic_write_private_bytes", side_effect=full):
        cmd_doctor._write_doctor_cache(cfg, _DoctorResult())
    err = capsys.readouterr().err
    assert "Errno" not in err and "doctor_cache.json" not in err
    assert f"doctor results were not cached: the disk holding {tmp_path} is full" in err


def _status(db_path: str) -> V8OperatorStatus:
    return V8OperatorStatus(
        source="/tmp/config.yaml",
        data_dir="/tmp",
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=7,
        local_path=db_path,
        judge_bodies_path="",
        destinations=(
            V8DestinationStatus(
                name="local-sqlite",
                kind="sqlite",
                enabled=True,
                generated=True,
                capabilities=("logs",),
                selected_signals=("logs",),
                policy_form="implicit_local",
                endpoint=db_path,
                route_count=1,
                buckets=("compliance.activity",),
                redaction_profiles=("none",),
            ),
        ),
        buckets=(V8BucketStatus("compliance.activity", ("logs",), "none"),),
        warnings=(),
    )


def test_freed_audit_disk_warns_that_it_clears_with_the_next_event(tmp_path: Path) -> None:
    db_path = str(tmp_path / "audit.db")
    for usage, status, phrase in ((_FULL, "fail", "is full"), (_FREED, "warn", "has room again")):
        result = _DoctorResult()
        with mock.patch("shutil.disk_usage", return_value=usage):
            _check_observability_v8_status(_status(db_path), result, live_health=_HEALTH, audit_db=db_path)
            reason = cmd_doctor._telemetry_error_reason(_HEALTH["telemetry"]["details"], db_path)
        checks = {item["label"]: item for item in result.checks}
        for label in ("Local SQLite", "Destination: local-sqlite"):
            assert checks[label]["status"] == status, (usage, label)
            assert phrase in checks[label]["detail"]
        assert phrase in reason
    assert "clears with the next audit event" in reason
    assert checks["Local SQLite"]["remediation"] == ""


def _record(signal: str, count: int, reason: str = "") -> str:
    body = {"defenseclaw.telemetry.signal": signal, "defenseclaw.telemetry.record_count": count}
    if reason:
        body["defenseclaw.telemetry.rejection_reason_class"] = reason
    return json.dumps({"body": body})


def _custody_db(path: Path, old_real_drops: int) -> None:
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE correlation_connector_instances (
            connector_instance_id TEXT PRIMARY KEY, connector TEXT NOT NULL, export_custody TEXT NOT NULL,
            profile_version TEXT NOT NULL, managed_config_digest TEXT, is_default INTEGER NOT NULL,
            created_time_unix_nano INTEGER NOT NULL, updated_time_unix_nano INTEGER NOT NULL);
        CREATE TABLE audit_events (
            id TEXT PRIMARY KEY, timestamp DATETIME NOT NULL, event_name TEXT, source TEXT,
            connector TEXT, request_id TEXT, projected_record_json TEXT);
        """
    )
    db.execute(
        "INSERT INTO correlation_connector_instances VALUES (?, 'codex', 'defenseclaw', 'codex-v1', NULL, 1, 1, 1)",
        ("019b0000-0000-7000-8000-000000000001",),
    )

    def event(rid: str, name: str, request: str, projected: str, when: str) -> None:
        db.execute(
            "INSERT INTO audit_events VALUES (?, ?, ?, 'otlp_receiver', 'codex', ?, ?)",
            (rid, when, name, request, projected),
        )

    batches = [(f"old-{i}", "invalid_mapped_field", f"2026-10-02T05:0{i}:00Z") for i in range(old_real_drops)]
    batches += [(f"new-{i}", "unsupported_identity", "2026-10-03T00:30:00Z") for i in range(20)]
    batches += [(f"ok-{i}", "", "2026-10-03T00:40:00Z") for i in range(10)]
    for request, reason, when in batches:
        event(f"n-{request}", "telemetry.batch.normalized", request, _record("logs", 2), when)
        if reason:
            event(f"d-{request}", "telemetry.records.dropped", request, _record("logs", 2, reason), when)
    db.commit()
    db.close()


def test_old_real_drops_do_not_count_by_design_skips_as_loss(tmp_path: Path) -> None:
    now = datetime(2026, 10, 3, 1, 0, tzinfo=timezone.utc)
    for old, state in ((5, "partial_drop_only"), (0, "accepted")):
        db_path = tmp_path / f"audit-{old}.db"
        _custody_db(db_path, old)
        (row,) = summarize_native_delivery(inspect_connector_custody(db_path, tmp_path, now=now)).connectors
        assert row.state == state, row.detail
    detail = (
        summarize_native_delivery(inspect_connector_custody(tmp_path / "audit-5.db", tmp_path, now=now))
        .connectors[0]
        .detail
    )
    assert "5/35 batches dropped whole" in detail
    assert "reason: invalid mapped field;" in detail and "unsupported identity" not in detail
    assert "last at 2026-10-02T05:04:00Z" in detail
    assert "20 more held only records DefenseClaw does not map, skipped by design" in detail
