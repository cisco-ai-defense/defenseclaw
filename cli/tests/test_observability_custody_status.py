# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from defenseclaw.commands.cmd_doctor import _check_connector_export_custody, _DoctorResult
from defenseclaw.observability.custody_status import (
    ConnectorCustodyReport,
    ConnectorCustodyStatus,
    inspect_connector_custody,
)

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)


def _database(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE correlation_connector_instances (
            connector_instance_id TEXT PRIMARY KEY,
            connector TEXT NOT NULL,
            export_custody TEXT NOT NULL,
            profile_version TEXT NOT NULL,
            managed_config_digest TEXT,
            is_default INTEGER NOT NULL,
            created_time_unix_nano INTEGER NOT NULL,
            updated_time_unix_nano INTEGER NOT NULL
        );
        CREATE TABLE audit_events (
            id TEXT PRIMARY KEY,
            timestamp DATETIME NOT NULL,
            event_name TEXT,
            source TEXT,
            connector TEXT,
            request_id TEXT,
            projected_record_json TEXT
        );
        """
    )
    return db


def _instance(
    db: sqlite3.Connection,
    connector_id: str,
    connector: str,
    custody: str,
    *,
    default: bool = True,
) -> None:
    db.execute(
        "INSERT INTO correlation_connector_instances VALUES (?, ?, ?, ?, NULL, ?, 1, 1)",
        (connector_id, connector, custody, f"{connector}-correlation-v1", int(default)),
    )


def _record(signal: str, count: int) -> str:
    return json.dumps(
        {
            "body": {
                "defenseclaw.telemetry.signal": signal,
                "defenseclaw.telemetry.record_count": count,
            }
        }
    )


def _event(
    db: sqlite3.Connection,
    record_id: str,
    event_name: str,
    source: str,
    request_id: str,
    projected: str,
    *,
    timestamp: str = "2026-07-14T11:55:00Z",
) -> None:
    db.execute(
        "INSERT INTO audit_events VALUES (?, ?, ?, 'otlp_receiver', ?, ?, ?)",
        (record_id, timestamp, event_name, source, request_id, projected),
    )


def _managed_backup(data_dir: Path, connector: str, target: Path) -> None:
    directory = data_dir / "connector_backups" / connector
    directory.mkdir(parents=True)
    content = target.read_bytes()
    (directory / "config.json").write_text(
        json.dumps(
            {
                "version": 1,
                "connector": connector,
                "logical_name": "config",
                "path": str(target),
                "existed": True,
                "pristine_sha256": "0" * 64,
                "post_sha256": hashlib.sha256(content).hexdigest(),
                "pristine_bytes": "operator-secret-must-not-render",
                "captured_at": "2026-07-14T10:00:00Z",
            }
        )
    )


def test_custody_status_is_read_only_and_reports_per_instance_evidence(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    db = _database(db_path)
    _instance(db, "019b0000-0000-7000-8000-000000000001", "codex", "defenseclaw")
    _instance(
        db,
        "019b0000-0000-7000-8000-000000000002",
        "codex",
        "defenseclaw",
        default=False,
    )
    _instance(db, "019b0000-0000-7000-8000-000000000003", "claudecode", "external")
    _instance(db, "019b0000-0000-7000-8000-000000000004", "cursor", "hook_only")
    _event(db, "normalized", "telemetry.batch.normalized", "codex", "request-1", _record("logs", 2))
    _event(db, "dropped", "telemetry.records.dropped", "codex", "request-1", _record("logs", 2))
    _event(db, "auth", "telemetry.authentication.failed", "codex", "request-2", _record("logs", 0))
    _event(db, "unknown-auth", "telemetry.authentication.failed", "unknown", "request-3", _record("logs", 0))
    db.commit()
    db.close()

    target = tmp_path / "codex-config.toml"
    target.write_text("[otel]\nmanaged=true\n")
    _managed_backup(tmp_path, "codex", target)
    external_file = tmp_path / "claude-settings.json"
    external_file.write_text('{"operator":"owned"}\n')
    before = external_file.read_bytes()
    before_mtime = external_file.stat().st_mtime_ns

    report = inspect_connector_custody(db_path, tmp_path, now=NOW)

    assert report.state == "available"
    by_id = {item.connector_instance_id: item for item in report.instances}
    codex = by_id["019b0000-0000-7000-8000-000000000001"]
    assert codex.custody == "defenseclaw"
    assert codex.managed_config_state == "verified"
    assert codex.normalized_batches == 1
    assert codex.drop_only_batches == 1
    assert codex.authentication_failures == 1
    assert codex.credential_state == "invalid"
    explicit = by_id["019b0000-0000-7000-8000-000000000002"]
    assert not explicit.default
    assert explicit.normalized_batches == 0
    assert explicit.authentication_failures == 0
    assert by_id["019b0000-0000-7000-8000-000000000003"].custody == "external"
    assert by_id["019b0000-0000-7000-8000-000000000004"].custody == "hook_only"
    assert report.unattributed_authentication_failures == 1
    assert "operator-secret" not in repr(report)
    assert external_file.read_bytes() == before
    assert external_file.stat().st_mtime_ns == before_mtime


def test_custody_status_detects_managed_exporter_drift_without_repair(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    db = _database(db_path)
    _instance(db, "019b0000-0000-7000-8000-000000000001", "codex", "defenseclaw")
    db.commit()
    db.close()
    target = tmp_path / "codex-config.toml"
    target.write_text("managed-v1")
    _managed_backup(tmp_path, "codex", target)
    target.write_text("operator-drift")
    before = target.read_bytes()

    report = inspect_connector_custody(db_path, tmp_path, now=NOW)

    assert report.instances[0].managed_config_state == "drifted"
    assert target.read_bytes() == before


def test_custody_status_missing_ledger_is_bounded_and_does_not_initialize(tmp_path: Path) -> None:
    missing = tmp_path / "missing.db"
    report = inspect_connector_custody(missing, tmp_path, now=NOW)
    assert report.state == "unavailable"
    assert report.reason == "database_missing"
    assert not missing.exists()

    legacy = tmp_path / "legacy.db"
    sqlite3.connect(legacy).close()
    report = inspect_connector_custody(legacy, tmp_path, now=NOW)
    assert report.reason == "ledger_unavailable"
    with sqlite3.connect(legacy) as db:
        assert db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0] == 0


def test_custody_status_fails_closed_on_a_fourth_custody_state(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    db = _database(db_path)
    _instance(db, "019b0000-0000-7000-8000-000000000001", "codex", "unsupported")
    db.commit()
    db.close()

    report = inspect_connector_custody(db_path, tmp_path, now=NOW)

    assert report.state == "unavailable"
    assert report.reason == "invalid_ledger"
    assert not report.instances


def test_custody_status_bounds_a_corrupt_database(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    db_path.write_bytes(b"not-a-sqlite-database")

    report = inspect_connector_custody(db_path, tmp_path, now=NOW)

    assert report.state == "unavailable"
    assert report.reason == "database_unreadable"


def test_doctor_reports_external_invalid_drop_only_and_managed_drift() -> None:
    report = ConnectorCustodyReport(
        state="available",
        reason="",
        observation_window_hours=24,
        instances=(
            ConnectorCustodyStatus(
                connector_instance_id="019b0000-0000-7000-8000-000000000001",
                connector="claudecode",
                custody="external",
                profile_version="claude-v1",
                default=True,
                normalized_batches=1,
                drop_only_batches=1,
                authentication_failures=1,
                credential_state="invalid",
            ),
            ConnectorCustodyStatus(
                connector_instance_id="019b0000-0000-7000-8000-000000000002",
                connector="cursor",
                custody="hook_only",
                profile_version="cursor-v1",
                default=True,
            ),
            ConnectorCustodyStatus(
                connector_instance_id="019b0000-0000-7000-8000-000000000003",
                connector="codex",
                custody="defenseclaw",
                profile_version="codex-v1",
                default=True,
                managed_config_state="drifted",
                normalized_batches=2,
                drop_only_batches=2,
                authentication_failures=3,
                credential_state="invalid",
            ),
        ),
        unattributed_authentication_failures=1,
        last_unattributed_authentication_failure="2026-07-14T11:55:00Z",
    )
    result = _DoctorResult()

    _check_connector_export_custody(report, result)

    checks = {item["label"]: item for item in result.checks}
    external = checks["Connector OTLP: claudecode"]
    assert external["status"] == "fail"
    assert "migration left its endpoint and credentials untouched" in external["detail"]
    assert "invalid credentials" in external["detail"]
    assert "drop-only native stream" in external["detail"]
    assert checks["Connector OTLP: cursor"]["status"] == "pass"
    codex = checks["Connector OTLP: codex"]
    assert codex["status"] == "fail"
    assert "managed-exporter drift" in codex["detail"]
    assert "invalid credentials" in codex["detail"]
    assert "drop-only native stream" in codex["detail"]
    assert checks["Native OTLP credentials"]["status"] == "warn"
