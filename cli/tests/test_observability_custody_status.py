# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
from defenseclaw.commands.cmd_doctor import (
    _check_connector_export_custody,
    _claude_exporter_reaches_gateway,
    _DoctorResult,
    _emit_unattributed_otlp_credentials,
)
from defenseclaw.commands.cmd_status import _print_native_delivery_status
from defenseclaw.observability.custody_status import (
    ConnectorCustodyReport,
    ConnectorCustodyStatus,
    inspect_connector_custody,
    summarize_native_delivery,
)

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)


def test_claude_exporter_at_own_gateway_is_not_external(tmp_path, monkeypatch) -> None:
    from defenseclaw import connector_paths

    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"env": {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:18970"}}))
    monkeypatch.setattr(connector_paths, "claude_settings_paths", lambda: [str(settings)])
    assert _claude_exporter_reaches_gateway("127.0.0.1:18970")
    assert not _claude_exporter_reaches_gateway("127.0.0.1:18971")


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
    assert codex.authentication_failures == 0
    assert codex.credential_state == "no_recent_failure"
    explicit = by_id["019b0000-0000-7000-8000-000000000002"]
    assert not explicit.default
    assert explicit.normalized_batches == 0
    assert explicit.authentication_failures == 0
    assert by_id["019b0000-0000-7000-8000-000000000003"].custody == "external"
    assert by_id["019b0000-0000-7000-8000-000000000004"].custody == "hook_only"
    assert report.unattributed_authentication_failures == 2
    assert "operator-secret" not in repr(report)
    assert external_file.read_bytes() == before
    assert external_file.stat().st_mtime_ns == before_mtime


@pytest.mark.parametrize("accepted_delivery", [False, True])
def test_untrusted_otlp_probe_does_not_fail_a_verified_exporter(tmp_path: Path, accepted_delivery: bool) -> None:
    """A route name on a rejected request is a claim, not exporter identity."""
    db_path = tmp_path / "audit.db"
    db = _database(db_path)
    _instance(db, "019b0000-0000-7000-8000-000000000001", "codex", "defenseclaw")
    if accepted_delivery:
        _event(db, "accepted", "telemetry.batch.normalized", "codex", "accepted-1", _record("logs", 2))
    _event(
        db,
        "peer-probe", "telemetry.authentication.failed", "codex", "rejected-1", _record("logs", 0),
        timestamp="2026-07-14T11:56:00Z",
    )
    db.commit()
    db.close()
    target = tmp_path / "codex-config.toml"
    target.write_text("[otel]\nmanaged=true\n")
    _managed_backup(tmp_path, "codex", target)

    report = inspect_connector_custody(db_path, tmp_path, now=NOW)
    (codex,) = report.instances
    assert codex.managed_config_state == "verified"
    assert codex.credential_state == "no_recent_failure"
    assert report.unattributed_authentication_failures == 1

    result = _DoctorResult()
    _check_connector_export_custody(report, result)
    rows = {row["label"]: row for row in result.checks}
    assert rows["Connector OTLP: codex"]["status"] == "pass"
    if accepted_delivery:
        assert "accepted native delivery observed" in rows["Connector OTLP: codex"]["detail"]
    assert rows["Native OTLP credentials"]["status"] == "warn"
    assert "defenseclaw setup" not in rows["Native OTLP credentials"]["remediation"]
    recent = _DoctorResult()
    _emit_unattributed_otlp_credentials(report, recent, now=NOW)
    assert "re-run 'defenseclaw setup" not in recent.checks[0]["remediation"]


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


def test_codex_folder_trust_write_is_not_exporter_drift(tmp_path: Path) -> None:
    # GAP-1330: Codex appends [projects."<dir>"] after setup; the managed
    # [otel] exporters are unchanged, so this is not drift.
    db_path = tmp_path / "audit.db"
    db = _database(db_path)
    _instance(db, "019b0000-0000-7000-8000-000000000001", "codex", "defenseclaw")
    db.commit()
    db.close()
    managed = _codex_otel_block()
    target = tmp_path / "config.toml"
    target.write_text(managed)
    _managed_backup(tmp_path, "codex", target)
    target.write_text(managed + '\n[projects."/home/u/work"]\ntrust_level = "trusted"\n')
    assert inspect_connector_custody(db_path, tmp_path, now=NOW).instances[0].managed_config_state == "verified"
    state = inspect_connector_custody(db_path, tmp_path, now=NOW, api_addr="127.0.0.1:18970")
    assert state.instances[0].managed_config_state == "verified"

    target.write_text('[projects."/home/u/work"]\ntrust_level = "trusted"\n')
    assert inspect_connector_custody(db_path, tmp_path, now=NOW).instances[0].managed_config_state == "drifted"


@pytest.mark.parametrize("edit", ["ordinary", "managed", "absent", "helper", "missing-key", "missing-snapshot", "corrupt-snapshot"])
def test_claude_settings_drift_checks_the_exact_managed_environment(tmp_path: Path, edit: str) -> None:
    db_path = tmp_path / "audit.db"
    db = _database(db_path)
    _instance(db, "019b0000-0000-7000-8000-000000000001", "claudecode", "defenseclaw")
    db.commit()
    db.close()
    managed = {
        "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
        "OTEL_LOGS_EXPORTER": "otlp",
        "OTEL_METRICS_EXPORTER": "otlp",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:18970",
        "OTEL_EXPORTER_OTLP_HEADERS": "x-defenseclaw-source=claudecode",
    }
    target = tmp_path / "settings.json"
    settings = {"env": dict(managed), "otelHeadersHelper": "managed credential helper"}
    target.write_text(json.dumps(settings))
    _managed_backup(tmp_path, "claudecode", target)
    snapshot = tmp_path / "claudecode_backup.json"
    snapshot.write_text(json.dumps({"env_backup_captured": True, "managed_env": managed,
                                    "managed_absent_env": ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"],
                                    "otlp_headers_helper_captured": True,
                                    "managed_otlp_headers_helper": "managed credential helper"}))
    settings["model"] = "operator-model"
    settings["env"]["UNRELATED_SETTING"] = "retained"
    if edit == "managed":
        settings["env"]["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://127.0.0.1:19999"
    elif edit == "absent":
        settings["env"]["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] = "http://127.0.0.1:19999"
    elif edit == "helper":
        settings["otelHeadersHelper"] = "operator changed helper"
    elif edit == "missing-key":
        del settings["env"]["OTEL_EXPORTER_OTLP_HEADERS"]
    elif edit == "missing-snapshot":
        snapshot.unlink()
    elif edit == "corrupt-snapshot":
        snapshot.write_text("null")
    target.write_text(json.dumps(settings))
    before = target.read_bytes()
    state = inspect_connector_custody(db_path, tmp_path, now=NOW, api_addr="127.0.0.1:18970")
    assert state.instances[0].managed_config_state == ("verified" if edit == "ordinary" else "drifted")
    assert target.read_bytes() == before


def _codex_otel_block(port: int = 18970, trace_port: int | None = None) -> str:
    headers = '{ x-defenseclaw-source = "codex", x-defenseclaw-client = "codex-otel/1.0" }'
    return "".join(
        f'[otel.{name}.otlp-http]\nendpoint = "http://127.0.0.1:{trace_port if name == "trace_exporter" and trace_port else port}'
        f'/v1/{signal}"\nprotocol = "binary"\nheaders = {headers}\n'
        for name, signal in (("exporter", "logs"), ("trace_exporter", "traces"), ("metrics_exporter", "metrics"))
    )


def test_codex_exporter_endpoint_edit_is_drift(tmp_path: Path) -> None:
    # GAP-2345: a managed exporter repointed to another port must not pass
    # the GAP-1330 folder-trust fallback as "managed-exporter verified".
    db_path = tmp_path / "audit.db"
    db = _database(db_path)
    _instance(db, "019b0000-0000-7000-8000-000000000001", "codex", "defenseclaw")
    db.commit()
    db.close()
    target = tmp_path / "config.toml"
    target.write_text(_codex_otel_block())
    _managed_backup(tmp_path, "codex", target)

    target.write_text(_codex_otel_block(trace_port=19999))
    assert inspect_connector_custody(db_path, tmp_path, now=NOW).instances[0].managed_config_state == "drifted"

    target.write_text(_codex_otel_block(port=19999))
    assert inspect_connector_custody(db_path, tmp_path, now=NOW).instances[0].managed_config_state == "verified"
    state = inspect_connector_custody(db_path, tmp_path, now=NOW, api_addr="127.0.0.1:18970")
    assert state.instances[0].managed_config_state == "drifted"


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


def test_doctor_drop_only_stream_at_own_gateway_fails(tmp_path, monkeypatch) -> None:
    # A fresh install (exporter at this gateway, custody not yet confirmed)
    # gets the same verdict as an upgraded managed one (GAP-1229).
    from defenseclaw import connector_paths

    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"env": {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:18970"}}))
    monkeypatch.setattr(connector_paths, "claude_settings_paths", lambda: [str(settings)])
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
                normalized_batches=4,
                drop_only_batches=4,
                drop_only_signals=("logs", "metrics"),
                drop_only_reasons=("invalid_mapped_field", "unsupported_identity"),
            ),
        ),
    )
    result = _DoctorResult()

    _check_connector_export_custody(report, result, gateway_addr="127.0.0.1:18970")

    row = {item["label"]: item for item in result.checks}["Connector OTLP: claudecode"]
    assert row["status"] == "fail"
    assert "drop-only native stream (4/4 batches)" in row["detail"]


def test_doctor_managed_exporter_drift_alone_warns_with_next_step() -> None:
    report = ConnectorCustodyReport(
        state="available",
        reason="",
        observation_window_hours=24,
        instances=(
            ConnectorCustodyStatus(
                connector_instance_id="019b0000-0000-7000-8000-000000000003",
                connector="codex",
                custody="defenseclaw",
                profile_version="codex-v1",
                default=True,
                managed_config_state="drifted",
            ),
        ),
    )
    result = _DoctorResult()

    _check_connector_export_custody(report, result)

    codex = {item["label"]: item for item in result.checks}["Connector OTLP: codex"]
    assert codex["status"] == "warn"
    assert codex["remediation"] == "run 'defenseclaw setup codex' to re-apply"


def test_native_delivery_summary_covers_all_states_and_doctor_status_parity(capsys) -> None:
    report = ConnectorCustodyReport(
        state="available",
        reason="",
        observation_window_hours=24,
        instances=(
            ConnectorCustodyStatus(
                connector_instance_id="019b0000-0000-7000-8000-000000000001",
                connector="codex",
                custody="defenseclaw",
                profile_version="codex-v1",
                default=True,
                normalized_batches=2,
                drop_only_batches=2,
            ),
            ConnectorCustodyStatus(
                connector_instance_id="019b0000-0000-7000-8000-000000000002",
                connector="claudecode",
                custody="external",
                profile_version="claude-v1",
                default=True,
                normalized_batches=3,
                drop_only_batches=1,
            ),
            ConnectorCustodyStatus(
                connector_instance_id="019b0000-0000-7000-8000-000000000003",
                connector="opencode",
                custody="defenseclaw",
                profile_version="opencode-v1",
                default=True,
                normalized_batches=4,
            ),
            ConnectorCustodyStatus(
                connector_instance_id="019b0000-0000-7000-8000-000000000004",
                connector="copilot",
                custody="defenseclaw",
                profile_version="copilot-v1",
                default=True,
            ),
            ConnectorCustodyStatus(
                connector_instance_id="019b0000-0000-7000-8000-000000000005",
                connector="cursor",
                custody="hook_only",
                profile_version="cursor-v1",
                default=True,
            ),
        ),
        event_rows_truncated=True,
    )

    summary = summarize_native_delivery(report)

    assert summary.evidence_scope == "truncated"
    assert [row.state for row in summary.connectors] == [
        "all_drop_only",
        "partial_drop_only",
        "accepted",
        "no_evidence",
    ]
    assert [row.connector for row in summary.connectors] == [
        "codex",
        "claudecode",
        "opencode",
        "copilot",
    ]
    serialized = json.dumps(summary.as_json(), sort_keys=True)
    assert "019b0000" not in serialized
    assert "profile" not in serialized
    assert "path" not in serialized
    assert "token" not in serialized

    _print_native_delivery_status(summary)
    status_output = capsys.readouterr().out
    assert "collector/runtime health does not prove accepted delivery" in status_output
    assert "bounded 24h, newest 4096 events" in status_output
    # The detail names the state once; no "accepted — accepted ..." (GAP-2549).
    for row in summary.connectors:
        assert f"{row.connector}  {row.detail[:24]}" in status_output
    assert "partial-drop-only" not in status_output

    result = _DoctorResult()
    _check_connector_export_custody(report, result)
    doctor = {item["label"]: item["detail"] for item in result.checks}
    for row in summary.connectors:
        assert row.detail in doctor[f"Connector OTLP: {row.connector}"]
    # GAP-2555: the read cap on a busy install is a sample note, not a warning.
    cap = next(item for item in result.checks if item["label"] == "Connector OTLP evidence")
    assert cap["status"] == "pass"
    assert "newest 4096 events of the last 24 h; nothing to do" in cap["detail"]
    assert "bounded read limit" not in cap["detail"]


def test_native_delivery_missing_evidence_is_bounded_not_failed(capsys) -> None:
    summary = summarize_native_delivery(ConnectorCustodyReport("unavailable", "database_missing", 24))

    assert summary.state == "no_evidence"
    assert summary.connectors == ()
    _print_native_delivery_status(summary)
    output = capsys.readouterr().out
    assert "no evidence" in output
    assert "database missing" in output
    assert "fail" not in output.lower()
